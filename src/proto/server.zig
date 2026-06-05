//! # identityd Protocol Server
//!
//! Single-threaded Unix socket server. Accepts one client at a time
//! (CLI tool pattern — not a concurrent service). Reads frames, dispatches
//! to the appropriate store, writes response frames.
//!
//! For MVP, this is synchronous and blocking. Post-MVP: kqueue event loop
//! with multiple client slots (same pattern as xmppd-auth).

const std = @import("std");
const protocol = @import("protocol");
const backend_mod = @import("backend");
const identity_store_mod = @import("identity_store");
const group_store_mod = @import("group_store");
const edge_store_mod = @import("edge_store");
const cbor = @import("cbor");

const log = std.log.scoped(.server);

pub fn Server(comptime Backend: type) type {
    const IdentityStore = identity_store_mod.IdentityStore(Backend);
    const GroupStore = group_store_mod.GroupStore(Backend);
    const EdgeStore = edge_store_mod.EdgeStore(Backend);

    return struct {
        const Self = @This();

        identity_store: IdentityStore,
        group_store: GroupStore,
        edge_store: EdgeStore,
        allocator: std.mem.Allocator,
        socket_path: []const u8,
        listener: ?std.posix.socket_t,
        running: bool,

        pub fn init(
            allocator: std.mem.Allocator,
            db: *Backend,
            socket_path: []const u8,
        ) Self {
            return .{
                .identity_store = IdentityStore.init(db),
                .group_store = GroupStore.init(db),
                .edge_store = EdgeStore.init(db),
                .allocator = allocator,
                .socket_path = socket_path,
                .listener = null,
                .running = false,
            };
        }

        pub fn listen(self: *Self) !void {
            // Remove stale socket
            std.fs.cwd().deleteFile(self.socket_path) catch {};

            const addr = try std.net.Address.initUnix(self.socket_path);
            const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
            errdefer std.posix.close(sock);

            try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
            try std.posix.listen(sock, 5);

            self.listener = sock;
            self.running = true;
            log.info("listening on {s}", .{self.socket_path});
        }

        pub fn serve(self: *Self) !void {
            const listener = self.listener orelse return error.NotListening;

            while (self.running) {
                const conn = std.posix.accept(listener, null, null, 0) catch |err| {
                    if (!self.running) break;
                    log.err("accept error: {}", .{err});
                    continue;
                };
                defer std.posix.close(conn);

                self.handleConnection(conn) catch |err| {
                    log.err("connection error: {}", .{err});
                };
            }
        }

        pub fn stop(self: *Self) void {
            self.running = false;
            if (self.listener) |sock| {
                std.posix.close(sock);
                self.listener = null;
            }
            std.fs.cwd().deleteFile(self.socket_path) catch {};
        }

        fn handleConnection(self: *Self, conn: std.posix.socket_t) !void {
            while (true) {
                var frame = (try protocol.readFrameFd(self.allocator, conn)) orelse break;
                defer frame.deinit(self.allocator);

                const response = self.dispatch(frame.tag, frame.payload) catch |err| {
                    const err_payload = protocol.buildError(
                        self.allocator,
                        .internal,
                        @errorName(err),
                    ) catch break;
                    defer self.allocator.free(err_payload);
                    protocol.writeFrameFd(conn, .err, err_payload) catch break;
                    continue;
                };
                defer if (response.payload.len > 0) self.allocator.free(response.payload);
                protocol.writeFrameFd(conn, response.tag, response.payload) catch break;
            }
        }

        const Response = struct {
            tag: protocol.Tag,
            payload: []const u8,
        };

        fn dispatch(self: *Self, tag: protocol.Tag, payload: []const u8) !Response {
            return switch (tag) {
                .create_identity => try self.handleCreateIdentity(payload),
                .get_identity => try self.handleGetIdentity(payload),
                .delete_identity => try self.handleDeleteIdentity(payload),
                .lookup_by_email => try self.handleLookupByEmail(payload),
                .create_group => try self.handleCreateGroup(payload),
                .get_group => try self.handleGetGroup(payload),
                .delete_group => try self.handleDeleteGroup(payload),
                .lookup_by_name => try self.handleLookupByName(payload),
                .add_edge => try self.handleAddEdge(payload),
                .remove_edge => try self.handleRemoveEdge(payload),
                .has_edge => try self.handleHasEdge(payload),
                .get_edge => try self.handleGetEdge(payload),
                .has_path => try self.handleHasPath(payload),
                .reachable => try self.handleReachable(payload),
                else => blk: {
                    const err_payload = try protocol.buildError(self.allocator, .invalid_request, "unknown tag");
                    break :blk .{ .tag = .err, .payload = err_payload };
                },
            };
        }

        // -- Identity handlers --

        fn handleCreateIdentity(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const id = try dec.readStr();
            const display_name = try dec.readStr();
            const email = try dec.readOptionalStr();
            const identity_type = try dec.readU8();
            const status = try dec.readU8();
            const created_at = try dec.readU64();
            const updated_at = try dec.readU64();

            const identity = identity_store_mod.Identity{
                .id = id,
                .display_name = display_name,
                .email = email,
                .identity_type = @enumFromInt(identity_type),
                .status = @enumFromInt(status),
                .created_at = created_at,
                .updated_at = updated_at,
                .attributes = &.{},
            };

            self.identity_store.create(self.allocator, identity) catch |err| {
                const code: protocol.ErrorCode = switch (err) {
                    error.IdentityAlreadyExists, error.EmailAlreadyExists => .already_exists,
                    else => .internal,
                };
                const p = try protocol.buildError(self.allocator, code, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            return .{ .tag = .ok, .payload = "" };
        }

        fn handleGetIdentity(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const id = try dec.readStr();

            const identity = self.identity_store.lookup(self.allocator, id) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            if (identity == null) {
                const p = try protocol.buildError(self.allocator, .not_found, "identity not found");
                return .{ .tag = .err, .payload = p };
            }

            defer identity_store_mod.freeIdentity(self.allocator, identity.?);
            const resp = try self.encodeIdentityResponse(identity.?);
            return .{ .tag = .identity_result, .payload = resp };
        }

        fn handleDeleteIdentity(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const id = try dec.readStr();

            self.identity_store.remove(self.allocator, id) catch |err| {
                const code: protocol.ErrorCode = switch (err) {
                    error.IdentityNotFound => .not_found,
                    else => .internal,
                };
                const p = try protocol.buildError(self.allocator, code, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            return .{ .tag = .ok, .payload = "" };
        }

        fn handleLookupByEmail(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const email = try dec.readStr();

            const id = self.identity_store.lookupByEmail(self.allocator, email) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            if (id == null) {
                const p = try protocol.buildError(self.allocator, .not_found, "email not found");
                return .{ .tag = .err, .payload = p };
            }
            defer self.allocator.free(id.?);

            const ids = [_][]const u8{id.?};
            const resp = try protocol.buildIdList(self.allocator, &ids);
            return .{ .tag = .id_list_result, .payload = resp };
        }

        // -- Group handlers --

        fn handleCreateGroup(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const id = try dec.readStr();
            const name = try dec.readStr();
            const description = try dec.readOptionalStr();
            const group_type = try dec.readU8();
            const created_at = try dec.readU64();
            const updated_at = try dec.readU64();

            const group = group_store_mod.Group{
                .id = id,
                .name = name,
                .description = description,
                .group_type = @enumFromInt(group_type),
                .created_at = created_at,
                .updated_at = updated_at,
                .attributes = &.{},
            };

            self.group_store.create(self.allocator, group) catch |err| {
                const code: protocol.ErrorCode = switch (err) {
                    error.GroupAlreadyExists, error.NameAlreadyExists => .already_exists,
                    else => .internal,
                };
                const p = try protocol.buildError(self.allocator, code, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            return .{ .tag = .ok, .payload = "" };
        }

        fn handleGetGroup(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const id = try dec.readStr();

            const group = self.group_store.lookup(self.allocator, id) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            if (group == null) {
                const p = try protocol.buildError(self.allocator, .not_found, "group not found");
                return .{ .tag = .err, .payload = p };
            }

            defer group_store_mod.freeGroup(self.allocator, group.?);
            const resp = try self.encodeGroupResponse(group.?);
            return .{ .tag = .group_result, .payload = resp };
        }

        fn handleDeleteGroup(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const id = try dec.readStr();

            self.group_store.remove(self.allocator, id) catch |err| {
                const code: protocol.ErrorCode = switch (err) {
                    error.GroupNotFound => .not_found,
                    else => .internal,
                };
                const p = try protocol.buildError(self.allocator, code, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            return .{ .tag = .ok, .payload = "" };
        }

        fn handleLookupByName(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const name = try dec.readStr();

            const id = self.group_store.lookupByName(self.allocator, name) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            if (id == null) {
                const p = try protocol.buildError(self.allocator, .not_found, "name not found");
                return .{ .tag = .err, .payload = p };
            }
            defer self.allocator.free(id.?);

            const ids = [_][]const u8{id.?};
            const resp = try protocol.buildIdList(self.allocator, &ids);
            return .{ .tag = .id_list_result, .payload = resp };
        }

        // -- Edge handlers --

        fn handleAddEdge(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const from = try dec.readStr();
            const edge_type = try dec.readStr();
            const to = try dec.readStr();
            const data = try dec.readStr();

            self.edge_store.addEdge(from, edge_type, to, data) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            return .{ .tag = .ok, .payload = "" };
        }

        fn handleRemoveEdge(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const from = try dec.readStr();
            const edge_type = try dec.readStr();
            const to = try dec.readStr();

            self.edge_store.removeEdge(from, edge_type, to) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            return .{ .tag = .ok, .payload = "" };
        }

        fn handleHasEdge(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const from = try dec.readStr();
            const edge_type = try dec.readStr();
            const to = try dec.readStr();

            const exists = self.edge_store.hasEdge(self.allocator, from, edge_type, to) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            const resp = try protocol.buildBoolResult(self.allocator, exists);
            return .{ .tag = .bool_result, .payload = resp };
        }

        fn handleGetEdge(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const from = try dec.readStr();
            const edge_type = try dec.readStr();
            const to = try dec.readStr();

            const data = self.edge_store.getEdge(self.allocator, from, edge_type, to) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            if (data == null) {
                const p = try protocol.buildError(self.allocator, .not_found, "edge not found");
                return .{ .tag = .err, .payload = p };
            }
            defer self.allocator.free(data.?);

            var enc = protocol.FieldEncoder.init(self.allocator);
            defer enc.deinit();
            try enc.writeStr(data.?);
            const resp = try enc.toOwnedSlice();
            return .{ .tag = .edge_data_result, .payload = resp };
        }

        // -- Graph query handlers --

        fn handleHasPath(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const start = try dec.readStr();
            const target = try dec.readStr();
            const edge_type = try dec.readStr();
            const max_depth = try dec.readU8();

            const found = self.edge_store.hasPath(start, target, edge_type, max_depth) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            const resp = try protocol.buildBoolResult(self.allocator, found);
            return .{ .tag = .bool_result, .payload = resp };
        }

        fn handleReachable(self: *Self, payload: []const u8) !Response {
            var dec = protocol.FieldDecoder.init(payload);
            const start = try dec.readStr();
            const edge_type = try dec.readStr();
            const max_depth = try dec.readU8();

            const result = self.edge_store.reachable(start, edge_type, max_depth) catch |err| {
                const p = try protocol.buildError(self.allocator, .internal, @errorName(err));
                return .{ .tag = .err, .payload = p };
            };

            const resp = try protocol.buildIdList(self.allocator, result.items());
            return .{ .tag = .id_list_result, .payload = resp };
        }

        // -- Response encoding --

        fn encodeIdentityResponse(self: *Self, identity: identity_store_mod.Identity) ![]u8 {
            var enc = protocol.FieldEncoder.init(self.allocator);
            defer enc.deinit();
            try enc.writeStr(identity.id);
            try enc.writeStr(identity.display_name);
            try enc.writeOptionalStr(identity.email);
            try enc.writeU8(@intFromEnum(identity.identity_type));
            try enc.writeU8(@intFromEnum(identity.status));
            try enc.writeU64(identity.created_at);
            try enc.writeU64(identity.updated_at);
            return try enc.toOwnedSlice();
        }

        fn encodeGroupResponse(self: *Self, group: group_store_mod.Group) ![]u8 {
            var enc = protocol.FieldEncoder.init(self.allocator);
            defer enc.deinit();
            try enc.writeStr(group.id);
            try enc.writeStr(group.name);
            try enc.writeOptionalStr(group.description);
            try enc.writeU8(@intFromEnum(group.group_type));
            try enc.writeU64(group.created_at);
            try enc.writeU64(group.updated_at);
            return try enc.toOwnedSlice();
        }
    };
}

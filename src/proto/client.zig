//! # identityd Protocol Client
//!
//! Connects to identityd via Unix socket and provides typed request methods.
//! Used by idctl and any future gateway service.

const std = @import("std");
const protocol = @import("protocol");

pub const ClientError = error{
    ConnectionFailed,
    ServerError,
    NotFound,
    AlreadyExists,
    InvalidResponse,
    UnexpectedEof,
    FrameTooLarge,
    OutOfMemory,
};

pub const Client = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,

    pub fn connect(allocator: std.mem.Allocator, socket_path: []const u8) !Client {
        const addr = try std.net.Address.initUnix(socket_path);
        const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
        errdefer std.posix.close(sock);
        try std.posix.connect(sock, &addr.any, addr.getOsSockLen());

        return .{
            .fd = sock,
            .allocator = allocator,
        };
    }

    pub fn close(self: *Client) void {
        std.posix.close(self.fd);
    }

    // -- Identity operations --

    pub fn createIdentity(
        self: *Client,
        id: []const u8,
        display_name: []const u8,
        email: ?[]const u8,
        identity_type: u8,
        status: u8,
        created_at: u64,
        updated_at: u64,
    ) !void {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(id);
        try enc.writeStr(display_name);
        try enc.writeOptionalStr(email);
        try enc.writeU8(identity_type);
        try enc.writeU8(status);
        try enc.writeU64(created_at);
        try enc.writeU64(updated_at);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try self.sendAndExpectOk(.create_identity, payload);
    }

    pub fn getIdentity(self: *Client, id: []const u8) !?IdentityResult {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(id);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try protocol.writeFrameFd(self.fd, .get_identity, payload);
        var frame = (try protocol.readFrameFd(self.allocator, self.fd)) orelse return error.UnexpectedEof;
        defer frame.deinit(self.allocator);

        if (frame.tag == .err) return handleError(frame.payload);
        if (frame.tag != .identity_result) return error.InvalidResponse;

        return try decodeIdentityResult(self.allocator, frame.payload);
    }

    pub fn deleteIdentity(self: *Client, id: []const u8) !void {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(id);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try self.sendAndExpectOk(.delete_identity, payload);
    }

    pub fn lookupByEmail(self: *Client, email: []const u8) !?[]const u8 {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(email);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try protocol.writeFrameFd(self.fd, .lookup_by_email, payload);
        var frame = (try protocol.readFrameFd(self.allocator, self.fd)) orelse return error.UnexpectedEof;
        defer frame.deinit(self.allocator);

        if (frame.tag == .err) return try handleErrorOrNull(frame.payload);
        if (frame.tag != .id_list_result) return error.InvalidResponse;

        // Read first ID from list
        if (frame.payload.len < 2) return null;
        const count = std.mem.readInt(u16, frame.payload[0..2], .little);
        if (count == 0) return null;
        var dec = protocol.FieldDecoder.init(frame.payload[2..]);
        const id_str = try dec.readStr();
        return try self.allocator.dupe(u8, id_str);
    }

    // -- Group operations --

    pub fn createGroup(
        self: *Client,
        id: []const u8,
        name: []const u8,
        description: ?[]const u8,
        group_type: u8,
        created_at: u64,
        updated_at: u64,
    ) !void {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(id);
        try enc.writeStr(name);
        try enc.writeOptionalStr(description);
        try enc.writeU8(group_type);
        try enc.writeU64(created_at);
        try enc.writeU64(updated_at);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try self.sendAndExpectOk(.create_group, payload);
    }

    pub fn deleteGroup(self: *Client, id: []const u8) !void {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(id);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try self.sendAndExpectOk(.delete_group, payload);
    }

    // -- Edge operations --

    pub fn addEdge(self: *Client, from: []const u8, edge_type: []const u8, to: []const u8, data: []const u8) !void {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(from);
        try enc.writeStr(edge_type);
        try enc.writeStr(to);
        try enc.writeStr(data);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try self.sendAndExpectOk(.add_edge, payload);
    }

    pub fn removeEdge(self: *Client, from: []const u8, edge_type: []const u8, to: []const u8) !void {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(from);
        try enc.writeStr(edge_type);
        try enc.writeStr(to);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try self.sendAndExpectOk(.remove_edge, payload);
    }

    pub fn hasEdge(self: *Client, from: []const u8, edge_type: []const u8, to: []const u8) !bool {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(from);
        try enc.writeStr(edge_type);
        try enc.writeStr(to);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try protocol.writeFrameFd(self.fd, .has_edge, payload);
        var frame = (try protocol.readFrameFd(self.allocator, self.fd)) orelse return error.UnexpectedEof;
        defer frame.deinit(self.allocator);

        if (frame.tag == .err) return handleError(frame.payload);
        if (frame.tag != .bool_result) return error.InvalidResponse;
        if (frame.payload.len < 1) return error.InvalidResponse;
        return frame.payload[0] != 0;
    }

    // -- Graph queries --

    pub fn hasPath(self: *Client, start: []const u8, target: []const u8, edge_type: []const u8, max_depth: u8) !bool {
        var enc = protocol.FieldEncoder.init(self.allocator);
        defer enc.deinit();
        try enc.writeStr(start);
        try enc.writeStr(target);
        try enc.writeStr(edge_type);
        try enc.writeU8(max_depth);
        const payload = try enc.toOwnedSlice();
        defer self.allocator.free(payload);

        try protocol.writeFrameFd(self.fd, .has_path, payload);
        var frame = (try protocol.readFrameFd(self.allocator, self.fd)) orelse return error.UnexpectedEof;
        defer frame.deinit(self.allocator);

        if (frame.tag == .err) return handleError(frame.payload);
        if (frame.tag != .bool_result) return error.InvalidResponse;
        if (frame.payload.len < 1) return error.InvalidResponse;
        return frame.payload[0] != 0;
    }

    // -- Internal helpers --

    fn sendAndExpectOk(self: *Client, tag: protocol.Tag, payload: []const u8) !void {
        try protocol.writeFrameFd(self.fd, tag, payload);
        var frame = (try protocol.readFrameFd(self.allocator, self.fd)) orelse return error.UnexpectedEof;
        defer frame.deinit(self.allocator);

        if (frame.tag == .err) return handleError(frame.payload);
        if (frame.tag != .ok) return error.InvalidResponse;
    }

    fn handleError(payload: []const u8) ClientError {
        if (payload.len < 1) return error.ServerError;
        const code: protocol.ErrorCode = @enumFromInt(payload[0]);
        return switch (code) {
            .not_found => error.NotFound,
            .already_exists => error.AlreadyExists,
            else => error.ServerError,
        };
    }

    fn handleErrorOrNull(payload: []const u8) ClientError!?[]const u8 {
        if (payload.len < 1) return error.ServerError;
        const code: protocol.ErrorCode = @enumFromInt(payload[0]);
        if (code == .not_found) return null;
        return error.ServerError;
    }
};

pub const IdentityResult = struct {
    id: []const u8,
    display_name: []const u8,
    email: ?[]const u8,
    identity_type: u8,
    status: u8,
    created_at: u64,
    updated_at: u64,

    pub fn deinit(self: *const IdentityResult, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.display_name);
        if (self.email) |e| allocator.free(e);
    }
};

fn decodeIdentityResult(allocator: std.mem.Allocator, payload: []const u8) !IdentityResult {
    var dec = protocol.FieldDecoder.init(payload);
    const id = try allocator.dupe(u8, try dec.readStr());
    errdefer allocator.free(id);
    const display_name = try allocator.dupe(u8, try dec.readStr());
    errdefer allocator.free(display_name);
    const raw_email = try dec.readOptionalStr();
    const email = if (raw_email) |e| try allocator.dupe(u8, e) else null;
    errdefer if (email) |e| allocator.free(e);
    return .{
        .id = id,
        .display_name = display_name,
        .email = email,
        .identity_type = try dec.readU8(),
        .status = try dec.readU8(),
        .created_at = try dec.readU64(),
        .updated_at = try dec.readU64(),
    };
}

//! # Group Store
//!
//! Document store for groups (groups, roles, organizational units).
//! Generic over a StorageBackend.
//!
//! ## Namespaces
//!
//! - `groups` — primary documents, key = group ID
//! - `group_idx` — secondary indexes
//!
//! ## Index layout
//!
//! Unique indexes (value = primary key):
//!   `name\x00{name}` → group_id
//!
//! Non-unique indexes (value = empty):
//!   `type\x00{type_byte}\x00{group_id}` → ""
//!
//! ## CBOR document format (map with integer keys)
//!
//!   0: name (text)
//!   1: description (text or null)
//!   2: type (uint: 0=group, 1=role, 2=ou)
//!   3: created_at (uint, unix seconds)
//!   4: updated_at (uint, unix seconds)
//!   5: attributes (map of text → bytes) — extensible

const std = @import("std");
const backend_mod = @import("backend");
const cbor = @import("cbor");

const NS_GROUPS = "groups";
const NS_INDEX = "group_idx";

pub const GroupType = enum(u8) {
    group = 0,
    role = 1,
    ou = 2,
};

pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
};

pub const Group = struct {
    id: []const u8,
    name: []const u8,
    description: ?[]const u8,
    group_type: GroupType,
    created_at: u64,
    updated_at: u64,
    attributes: []const Attribute,
};

pub fn GroupStore(comptime Backend: type) type {
    backend_mod.assertBackend(Backend);

    return struct {
        const Self = @This();
        db: *Backend,

        pub fn init(db: *Backend) Self {
            return .{ .db = db };
        }

        /// Create a new group. Fails if ID or name already exists.
        pub fn create(self: *Self, allocator: std.mem.Allocator, group: Group) !void {
            // Check for duplicate ID
            const existing = try self.db.get(allocator, NS_GROUPS, group.id);
            if (existing) |e| {
                allocator.free(e);
                return error.GroupAlreadyExists;
            }

            // Check unique name index
            if (try self.lookupByName(allocator, group.name)) |gid| {
                allocator.free(gid);
                return error.NameAlreadyExists;
            }

            // Encode document
            const encoded = try encodeGroup(allocator, group);
            defer allocator.free(encoded);

            // Atomic write: document + indexes
            var batch = try self.db.writeBatch();
            errdefer batch.abort();

            try batch.put(NS_GROUPS, group.id, encoded);
            try self.writeIndexes(&batch, group);
            try batch.commit();
        }

        /// Get a group by ID. Caller owns returned memory.
        pub fn lookup(self: *Self, allocator: std.mem.Allocator, id: []const u8) !?Group {
            const data = try self.db.get(allocator, NS_GROUPS, id);
            if (data) |d| {
                defer allocator.free(d);
                return try decodeGroup(allocator, id, d);
            }
            return null;
        }

        /// Look up a group ID by name (unique index).
        pub fn lookupByName(self: *Self, allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
            var key_buf: [512]u8 = undefined;
            const key = buildUniqueIndexKey(&key_buf, "name", name) orelse return error.KeyTooLong;
            return try self.db.get(allocator, NS_INDEX, key);
        }

        /// List group IDs matching a given type.
        pub fn listByType(self: *Self, group_type: GroupType) !Backend.Iterator {
            var prefix_buf: [64]u8 = undefined;
            const prefix = buildNonUniquePrefix(&prefix_buf, "type", &[_]u8{@intFromEnum(group_type)});
            return try self.db.iterator(NS_INDEX, prefix);
        }

        /// Update an existing group. Maintains index consistency.
        pub fn update(self: *Self, allocator: std.mem.Allocator, group: Group) !void {
            // Load old document for index cleanup
            const old_data = try self.db.get(allocator, NS_GROUPS, group.id);
            if (old_data == null) return error.GroupNotFound;
            defer allocator.free(old_data.?);

            const old = try decodeGroup(allocator, group.id, old_data.?);
            defer freeGroup(allocator, old);

            // If name changed, check uniqueness of new name
            if (!std.mem.eql(u8, old.name, group.name)) {
                if (try self.lookupByName(allocator, group.name)) |gid| {
                    allocator.free(gid);
                    return error.NameAlreadyExists;
                }
            }

            // Encode new document
            const encoded = try encodeGroup(allocator, group);
            defer allocator.free(encoded);

            // Atomic: remove old indexes, write new doc + new indexes
            var batch = try self.db.writeBatch();
            errdefer batch.abort();

            try self.deleteIndexes(&batch, old);
            try batch.put(NS_GROUPS, group.id, encoded);
            try self.writeIndexes(&batch, group);
            try batch.commit();
        }

        /// Delete a group and its indexes.
        pub fn remove(self: *Self, allocator: std.mem.Allocator, id: []const u8) !void {
            const data = try self.db.get(allocator, NS_GROUPS, id);
            if (data == null) return error.GroupNotFound;
            defer allocator.free(data.?);

            const group = try decodeGroup(allocator, id, data.?);
            defer freeGroup(allocator, group);

            var batch = try self.db.writeBatch();
            errdefer batch.abort();

            try batch.delete(NS_GROUPS, id);
            try self.deleteIndexes(&batch, group);
            try batch.commit();
        }

        /// List all group IDs.
        pub fn listAll(self: *Self) !Backend.Iterator {
            return try self.db.iterator(NS_GROUPS, "");
        }

        // -- Index helpers --

        fn writeIndexes(self: *Self, batch: *Backend.WriteBatch, group: Group) !void {
            _ = self;

            // Unique: name
            {
                var key_buf: [512]u8 = undefined;
                const key = buildUniqueIndexKey(&key_buf, "name", group.name) orelse return error.KeyTooLong;
                try batch.put(NS_INDEX, key, group.id);
            }

            // Non-unique: type
            {
                var key_buf: [256]u8 = undefined;
                const key = buildNonUniqueKey(&key_buf, "type", &[_]u8{@intFromEnum(group.group_type)}, group.id) orelse return error.KeyTooLong;
                try batch.put(NS_INDEX, key, "");
            }
        }

        fn deleteIndexes(self: *Self, batch: *Backend.WriteBatch, group: Group) !void {
            _ = self;

            {
                var key_buf: [512]u8 = undefined;
                const key = buildUniqueIndexKey(&key_buf, "name", group.name) orelse return error.KeyTooLong;
                try batch.delete(NS_INDEX, key);
            }

            {
                var key_buf: [256]u8 = undefined;
                const key = buildNonUniqueKey(&key_buf, "type", &[_]u8{@intFromEnum(group.group_type)}, group.id) orelse return error.KeyTooLong;
                try batch.delete(NS_INDEX, key);
            }
        }
    };
}

// ============================================================================
// Index key builders
// ============================================================================

fn buildUniqueIndexKey(buf: []u8, field: []const u8, value: []const u8) ?[]const u8 {
    const needed = field.len + 1 + value.len;
    if (needed > buf.len) return null;
    @memcpy(buf[0..field.len], field);
    buf[field.len] = 0;
    @memcpy(buf[field.len + 1 ..][0..value.len], value);
    return buf[0..needed];
}

fn buildNonUniqueKey(buf: []u8, field: []const u8, value: []const u8, id: []const u8) ?[]const u8 {
    const needed = field.len + 1 + value.len + 1 + id.len;
    if (needed > buf.len) return null;
    var pos: usize = 0;
    @memcpy(buf[pos..][0..field.len], field);
    pos += field.len;
    buf[pos] = 0;
    pos += 1;
    @memcpy(buf[pos..][0..value.len], value);
    pos += value.len;
    buf[pos] = 0;
    pos += 1;
    @memcpy(buf[pos..][0..id.len], id);
    pos += id.len;
    return buf[0..pos];
}

fn buildNonUniquePrefix(buf: []u8, field: []const u8, value: []const u8) []const u8 {
    var pos: usize = 0;
    @memcpy(buf[pos..][0..field.len], field);
    pos += field.len;
    buf[pos] = 0;
    pos += 1;
    @memcpy(buf[pos..][0..value.len], value);
    pos += value.len;
    buf[pos] = 0;
    pos += 1;
    return buf[0..pos];
}

// ============================================================================
// CBOR encode/decode for Group documents
// ============================================================================

fn encodeGroup(allocator: std.mem.Allocator, group: Group) ![]u8 {
    var enc = cbor.Encoder.init(allocator);
    defer enc.deinit();

    const attr_count = group.attributes.len;
    const map_len: usize = 5 + (if (attr_count > 0) @as(usize, 1) else 0);
    try enc.writeMapHeader(map_len);

    // 0: name
    try enc.writeUint(0);
    try enc.writeText(group.name);

    // 1: description
    try enc.writeUint(1);
    try enc.writeOptionalText(group.description);

    // 2: type
    try enc.writeUint(2);
    try enc.writeUint(@intFromEnum(group.group_type));

    // 3: created_at
    try enc.writeUint(3);
    try enc.writeUint(group.created_at);

    // 4: updated_at
    try enc.writeUint(4);
    try enc.writeUint(group.updated_at);

    // 5: attributes
    if (attr_count > 0) {
        try enc.writeUint(5);
        try enc.writeMapHeader(attr_count);
        for (group.attributes) |attr| {
            try enc.writeText(attr.key);
            try enc.writeBytes(attr.value);
        }
    }

    return try enc.toOwnedSlice();
}

fn decodeGroup(allocator: std.mem.Allocator, id: []const u8, data: []const u8) !Group {
    var dec = cbor.Decoder.init(data);
    const root = try dec.decode(allocator);

    if (root != .map) return error.InvalidCbor;
    const entries = root.map;
    defer allocator.free(@constCast(entries));

    const name_val = cbor.mapGetUintKey(entries, 0) orelse return error.InvalidCbor;
    const desc_val = cbor.mapGetUintKey(entries, 1) orelse return error.InvalidCbor;
    const type_val = cbor.mapGetUintKey(entries, 2) orelse return error.InvalidCbor;
    const created_val = cbor.mapGetUintKey(entries, 3) orelse return error.InvalidCbor;
    const updated_val = cbor.mapGetUintKey(entries, 4) orelse return error.InvalidCbor;

    const name = switch (name_val) {
        .text => |t| try allocator.dupe(u8, t),
        else => return error.InvalidCbor,
    };
    errdefer allocator.free(name);

    const description: ?[]const u8 = switch (desc_val) {
        .text => |t| try allocator.dupe(u8, t),
        .null_value => null,
        else => return error.InvalidCbor,
    };
    errdefer if (description) |d| allocator.free(d);

    const group_type: GroupType = switch (type_val) {
        .unsigned => |v| @enumFromInt(@as(u8, @intCast(v))),
        else => return error.InvalidCbor,
    };

    const created_at: u64 = switch (created_val) {
        .unsigned => |v| v,
        else => return error.InvalidCbor,
    };

    const updated_at: u64 = switch (updated_val) {
        .unsigned => |v| v,
        else => return error.InvalidCbor,
    };

    // Decode attributes
    var attrs: []Attribute = &.{};
    if (cbor.mapGetUintKey(entries, 5)) |attr_val| {
        switch (attr_val) {
            .map => |attr_entries| {
                attrs = try allocator.alloc(Attribute, attr_entries.len);
                for (attr_entries, 0..) |ae, i| {
                    const k = switch (ae.key) {
                        .text => |t| try allocator.dupe(u8, t),
                        else => return error.InvalidCbor,
                    };
                    const v = switch (ae.value) {
                        .bytes => |b| try allocator.dupe(u8, b),
                        else => return error.InvalidCbor,
                    };
                    attrs[i] = .{ .key = k, .value = v };
                }
                allocator.free(@constCast(attr_entries));
            },
            else => return error.InvalidCbor,
        }
    }

    return .{
        .id = try allocator.dupe(u8, id),
        .name = name,
        .description = description,
        .group_type = group_type,
        .created_at = created_at,
        .updated_at = updated_at,
        .attributes = attrs,
    };
}

/// Free all allocator-owned memory in a Group.
pub fn freeGroup(allocator: std.mem.Allocator, group: Group) void {
    allocator.free(group.id);
    allocator.free(group.name);
    if (group.description) |d| allocator.free(d);
    for (group.attributes) |attr| {
        allocator.free(attr.key);
        allocator.free(attr.value);
    }
    if (group.attributes.len > 0) allocator.free(group.attributes);
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;

test "GroupStore: create and lookup" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const admins = Group{
        .id = "admins",
        .name = "Administrators",
        .description = "Full system access",
        .group_type = .role,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, admins);

    const found = try store.lookup(allocator, "admins");
    try std.testing.expect(found != null);
    defer freeGroup(allocator, found.?);

    try std.testing.expectEqualStrings("Administrators", found.?.name);
    try std.testing.expectEqualStrings("Full system access", found.?.description.?);
    try std.testing.expectEqual(GroupType.role, found.?.group_type);
}

test "GroupStore: duplicate ID rejected" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const grp = Group{
        .id = "devs",
        .name = "Developers",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, grp);
    const result = store.create(allocator, grp);
    try std.testing.expectError(error.GroupAlreadyExists, result);
}

test "GroupStore: duplicate name rejected" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const grp1 = Group{
        .id = "eng-1",
        .name = "Engineering",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    const grp2 = Group{
        .id = "eng-2",
        .name = "Engineering",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, grp1);
    const result = store.create(allocator, grp2);
    try std.testing.expectError(error.NameAlreadyExists, result);
}

test "GroupStore: lookup by name" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const grp = Group{
        .id = "ops-team",
        .name = "Operations",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, grp);

    const id = try store.lookupByName(allocator, "Operations");
    try std.testing.expect(id != null);
    defer allocator.free(id.?);
    try std.testing.expectEqualStrings("ops-team", id.?);
}

test "GroupStore: update changes document and indexes" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const grp = Group{
        .id = "devs",
        .name = "Developers",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, grp);

    const updated = Group{
        .id = "devs",
        .name = "Software Engineers",
        .description = "All engineering staff",
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717100000,
        .attributes = &.{},
    };

    try store.update(allocator, updated);

    // Old name should not resolve
    const old_lookup = try store.lookupByName(allocator, "Developers");
    try std.testing.expect(old_lookup == null);

    // New name resolves
    const new_lookup = try store.lookupByName(allocator, "Software Engineers");
    try std.testing.expect(new_lookup != null);
    defer allocator.free(new_lookup.?);
    try std.testing.expectEqualStrings("devs", new_lookup.?);

    // Document updated
    const found = try store.lookup(allocator, "devs");
    defer freeGroup(allocator, found.?);
    try std.testing.expectEqualStrings("All engineering staff", found.?.description.?);
}

test "GroupStore: remove deletes document and indexes" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const grp = Group{
        .id = "old-team",
        .name = "Legacy Team",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, grp);
    try store.remove(allocator, "old-team");

    const found = try store.lookup(allocator, "old-team");
    try std.testing.expect(found == null);

    const name_lookup = try store.lookupByName(allocator, "Legacy Team");
    try std.testing.expect(name_lookup == null);
}

test "GroupStore: null description" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const ou = Group{
        .id = "hq",
        .name = "Headquarters",
        .description = null,
        .group_type = .ou,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, ou);

    const found = try store.lookup(allocator, "hq");
    try std.testing.expect(found != null);
    defer freeGroup(allocator, found.?);
    try std.testing.expect(found.?.description == null);
    try std.testing.expectEqual(GroupType.ou, found.?.group_type);
}

test "GroupStore: create with attributes" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const attrs = [_]Attribute{
        .{ .key = "max_members", .value = "50" },
    };

    const grp = Group{
        .id = "limited",
        .name = "Limited Group",
        .description = null,
        .group_type = .group,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &attrs,
    };

    try store.create(allocator, grp);

    const found = try store.lookup(allocator, "limited");
    try std.testing.expect(found != null);
    defer freeGroup(allocator, found.?);

    try std.testing.expectEqual(@as(usize, 1), found.?.attributes.len);
    try std.testing.expectEqualStrings("max_members", found.?.attributes[0].key);
    try std.testing.expectEqualStrings("50", found.?.attributes[0].value);
}

test "GroupStore: remove nonexistent returns error" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = GroupStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const result = store.remove(allocator, "ghost");
    try std.testing.expectError(error.GroupNotFound, result);
}

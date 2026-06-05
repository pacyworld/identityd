//! # Identity Store
//!
//! Document store for identity records (users, service accounts, bots).
//! Generic over a StorageBackend — works with LMDB, MemoryBackend, etc.
//!
//! ## Namespaces
//!
//! - `identities` — primary documents, key = identity ID
//! - `identity_idx` — secondary indexes
//!
//! ## Index layout
//!
//! Unique indexes (value = primary key):
//!   `email\x00{email}` → identity_id
//!
//! Non-unique indexes (value = empty, key encodes the FK):
//!   `type\x00{type_byte}\x00{identity_id}` → ""
//!   `status\x00{status_byte}\x00{identity_id}` → ""
//!
//! ## CBOR document format (map with integer keys)
//!
//!   0: display_name (text)
//!   1: email (text or null)
//!   2: type (uint: 0=user, 1=service_account, 2=bot)
//!   3: status (uint: 0=active, 1=suspended, 2=locked, 3=deleted)
//!   4: created_at (uint, unix seconds)
//!   5: updated_at (uint, unix seconds)
//!   6: attributes (map of text → bytes) — extensible

const std = @import("std");
const backend_mod = @import("backend");
const cbor = @import("cbor");

const NS_IDENTITIES = "identities";
const NS_INDEX = "identity_idx";

pub const IdentityType = enum(u8) {
    user = 0,
    service_account = 1,
    bot = 2,
};

pub const IdentityStatus = enum(u8) {
    active = 0,
    suspended = 1,
    locked = 2,
    deleted = 3,
};

pub const Attribute = struct {
    key: []const u8,
    value: []const u8,
};

pub const Identity = struct {
    id: []const u8,
    display_name: []const u8,
    email: ?[]const u8,
    identity_type: IdentityType,
    status: IdentityStatus,
    created_at: u64,
    updated_at: u64,
    attributes: []const Attribute,
};

pub fn IdentityStore(comptime Backend: type) type {
    backend_mod.assertBackend(Backend);

    return struct {
        const Self = @This();
        db: *Backend,

        pub fn init(db: *Backend) Self {
            return .{ .db = db };
        }

        /// Create a new identity. Fails if ID or email already exists.
        pub fn create(self: *Self, allocator: std.mem.Allocator, identity: Identity) !void {
            // Check for duplicate ID
            const existing = try self.db.get(allocator, NS_IDENTITIES, identity.id);
            if (existing) |e| {
                allocator.free(e);
                return error.IdentityAlreadyExists;
            }

            // Check unique email index
            if (identity.email) |email| {
                if (try self.lookupByEmail(allocator, email)) |eid| {
                    allocator.free(eid);
                    return error.EmailAlreadyExists;
                }
            }

            // Encode document
            const encoded = try encodeIdentity(allocator, identity);
            defer allocator.free(encoded);

            // Atomic write: document + indexes
            var batch = try self.db.writeBatch();
            errdefer batch.abort();

            try batch.put(NS_IDENTITIES, identity.id, encoded);
            try self.writeIndexes(&batch, identity);
            try batch.commit();
        }

        /// Get an identity by ID. Caller owns returned memory.
        pub fn lookup(self: *Self, allocator: std.mem.Allocator, id: []const u8) !?Identity {
            const data = try self.db.get(allocator, NS_IDENTITIES, id);
            if (data) |d| {
                defer allocator.free(d);
                return try decodeIdentity(allocator, id, d);
            }
            return null;
        }

        /// Look up an identity ID by email (unique index).
        pub fn lookupByEmail(self: *Self, allocator: std.mem.Allocator, email: []const u8) !?[]u8 {
            var key_buf: [512]u8 = undefined;
            const key = buildUniqueIndexKey(&key_buf, "email", email) orelse return error.KeyTooLong;
            return try self.db.get(allocator, NS_INDEX, key);
        }

        /// List identity IDs matching a given type.
        pub fn listByType(self: *Self, identity_type: IdentityType) !Backend.Iterator {
            var prefix_buf: [64]u8 = undefined;
            const prefix = buildNonUniquePrefix(&prefix_buf, "type", &[_]u8{@intFromEnum(identity_type)});
            return try self.db.iterator(NS_INDEX, prefix);
        }

        /// List identity IDs matching a given status.
        pub fn listByStatus(self: *Self, status: IdentityStatus) !Backend.Iterator {
            var prefix_buf: [64]u8 = undefined;
            const prefix = buildNonUniquePrefix(&prefix_buf, "status", &[_]u8{@intFromEnum(status)});
            return try self.db.iterator(NS_INDEX, prefix);
        }

        /// Update an existing identity. Maintains index consistency.
        pub fn update(self: *Self, allocator: std.mem.Allocator, identity: Identity) !void {
            // Load old document for index cleanup
            const old_data = try self.db.get(allocator, NS_IDENTITIES, identity.id);
            if (old_data == null) return error.IdentityNotFound;
            defer allocator.free(old_data.?);

            const old = try decodeIdentity(allocator, identity.id, old_data.?);
            defer freeIdentity(allocator, old);

            // If email changed, check uniqueness of new email
            if (identity.email) |new_email| {
                const email_changed = if (old.email) |oe| !std.mem.eql(u8, oe, new_email) else true;
                if (email_changed) {
                    if (try self.lookupByEmail(allocator, new_email)) |eid| {
                        allocator.free(eid);
                        return error.EmailAlreadyExists;
                    }
                }
            }

            // Encode new document
            const encoded = try encodeIdentity(allocator, identity);
            defer allocator.free(encoded);

            // Atomic: remove old indexes, write new doc + new indexes
            var batch = try self.db.writeBatch();
            errdefer batch.abort();

            try self.deleteIndexes(&batch, old);
            try batch.put(NS_IDENTITIES, identity.id, encoded);
            try self.writeIndexes(&batch, identity);
            try batch.commit();
        }

        /// Delete an identity and its indexes.
        pub fn remove(self: *Self, allocator: std.mem.Allocator, id: []const u8) !void {
            const data = try self.db.get(allocator, NS_IDENTITIES, id);
            if (data == null) return error.IdentityNotFound;
            defer allocator.free(data.?);

            const identity = try decodeIdentity(allocator, id, data.?);
            defer freeIdentity(allocator, identity);

            var batch = try self.db.writeBatch();
            errdefer batch.abort();

            try batch.delete(NS_IDENTITIES, id);
            try self.deleteIndexes(&batch, identity);
            try batch.commit();
        }

        /// List all identity IDs (prefix scan on empty prefix).
        pub fn listAll(self: *Self) !Backend.Iterator {
            return try self.db.iterator(NS_IDENTITIES, "");
        }

        // -- Index helpers --

        fn writeIndexes(self: *Self, batch: *Backend.WriteBatch, identity: Identity) !void {
            _ = self;

            // Unique: email
            if (identity.email) |email| {
                var key_buf: [512]u8 = undefined;
                const key = buildUniqueIndexKey(&key_buf, "email", email) orelse return error.KeyTooLong;
                try batch.put(NS_INDEX, key, identity.id);
            }

            // Non-unique: type
            {
                var key_buf: [256]u8 = undefined;
                const key = buildNonUniqueKey(&key_buf, "type", &[_]u8{@intFromEnum(identity.identity_type)}, identity.id) orelse return error.KeyTooLong;
                try batch.put(NS_INDEX, key, "");
            }

            // Non-unique: status
            {
                var key_buf: [256]u8 = undefined;
                const key = buildNonUniqueKey(&key_buf, "status", &[_]u8{@intFromEnum(identity.status)}, identity.id) orelse return error.KeyTooLong;
                try batch.put(NS_INDEX, key, "");
            }
        }

        fn deleteIndexes(self: *Self, batch: *Backend.WriteBatch, identity: Identity) !void {
            _ = self;

            if (identity.email) |email| {
                var key_buf: [512]u8 = undefined;
                const key = buildUniqueIndexKey(&key_buf, "email", email) orelse return error.KeyTooLong;
                try batch.delete(NS_INDEX, key);
            }

            {
                var key_buf: [256]u8 = undefined;
                const key = buildNonUniqueKey(&key_buf, "type", &[_]u8{@intFromEnum(identity.identity_type)}, identity.id) orelse return error.KeyTooLong;
                try batch.delete(NS_INDEX, key);
            }

            {
                var key_buf: [256]u8 = undefined;
                const key = buildNonUniqueKey(&key_buf, "status", &[_]u8{@intFromEnum(identity.status)}, identity.id) orelse return error.KeyTooLong;
                try batch.delete(NS_INDEX, key);
            }
        }
    };
}

// ============================================================================
// Index key builders
// ============================================================================

/// Build a unique index key: `{field}\x00{value}`
fn buildUniqueIndexKey(buf: []u8, field: []const u8, value: []const u8) ?[]const u8 {
    const needed = field.len + 1 + value.len;
    if (needed > buf.len) return null;
    @memcpy(buf[0..field.len], field);
    buf[field.len] = 0;
    @memcpy(buf[field.len + 1 ..][0..value.len], value);
    return buf[0..needed];
}

/// Build a non-unique index key: `{field}\x00{value}\x00{id}`
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

/// Build a non-unique index prefix: `{field}\x00{value}\x00`
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
// CBOR encode/decode for Identity documents
// ============================================================================

fn encodeIdentity(allocator: std.mem.Allocator, identity: Identity) ![]u8 {
    var enc = cbor.Encoder.init(allocator);
    defer enc.deinit();

    // Count map entries: always 6 base fields + attributes if non-empty
    const attr_count = identity.attributes.len;
    const map_len: usize = 6 + (if (attr_count > 0) @as(usize, 1) else 0);
    try enc.writeMapHeader(map_len);

    // 0: display_name
    try enc.writeUint(0);
    try enc.writeText(identity.display_name);

    // 1: email
    try enc.writeUint(1);
    try enc.writeOptionalText(identity.email);

    // 2: type
    try enc.writeUint(2);
    try enc.writeUint(@intFromEnum(identity.identity_type));

    // 3: status
    try enc.writeUint(3);
    try enc.writeUint(@intFromEnum(identity.status));

    // 4: created_at
    try enc.writeUint(4);
    try enc.writeUint(identity.created_at);

    // 5: updated_at
    try enc.writeUint(5);
    try enc.writeUint(identity.updated_at);

    // 6: attributes (only if present)
    if (attr_count > 0) {
        try enc.writeUint(6);
        try enc.writeMapHeader(attr_count);
        for (identity.attributes) |attr| {
            try enc.writeText(attr.key);
            try enc.writeBytes(attr.value);
        }
    }

    return try enc.toOwnedSlice();
}

fn decodeIdentity(allocator: std.mem.Allocator, id: []const u8, data: []const u8) !Identity {
    var dec = cbor.Decoder.init(data);
    const root = try dec.decode(allocator);

    if (root != .map) return error.InvalidCbor;
    const entries = root.map;
    defer allocator.free(@constCast(entries));

    const display_name_val = cbor.mapGetUintKey(entries, 0) orelse return error.InvalidCbor;
    const email_val = cbor.mapGetUintKey(entries, 1) orelse return error.InvalidCbor;
    const type_val = cbor.mapGetUintKey(entries, 2) orelse return error.InvalidCbor;
    const status_val = cbor.mapGetUintKey(entries, 3) orelse return error.InvalidCbor;
    const created_val = cbor.mapGetUintKey(entries, 4) orelse return error.InvalidCbor;
    const updated_val = cbor.mapGetUintKey(entries, 5) orelse return error.InvalidCbor;

    const display_name = switch (display_name_val) {
        .text => |t| try allocator.dupe(u8, t),
        else => return error.InvalidCbor,
    };
    errdefer allocator.free(display_name);

    const email: ?[]const u8 = switch (email_val) {
        .text => |t| try allocator.dupe(u8, t),
        .null_value => null,
        else => return error.InvalidCbor,
    };
    errdefer if (email) |e| allocator.free(e);

    const identity_type: IdentityType = switch (type_val) {
        .unsigned => |v| @enumFromInt(@as(u8, @intCast(v))),
        else => return error.InvalidCbor,
    };

    const status: IdentityStatus = switch (status_val) {
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
    if (cbor.mapGetUintKey(entries, 6)) |attr_val| {
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
        .display_name = display_name,
        .email = email,
        .identity_type = identity_type,
        .status = status,
        .created_at = created_at,
        .updated_at = updated_at,
        .attributes = attrs,
    };
}

/// Free all allocator-owned memory in an Identity.
pub fn freeIdentity(allocator: std.mem.Allocator, identity: Identity) void {
    allocator.free(identity.id);
    allocator.free(identity.display_name);
    if (identity.email) |e| allocator.free(e);
    for (identity.attributes) |attr| {
        allocator.free(attr.key);
        allocator.free(attr.value);
    }
    if (identity.attributes.len > 0) allocator.free(identity.attributes);
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;

test "IdentityStore: create and lookup" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice Smith",
        .email = "alice@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, alice);

    const found = try store.lookup(allocator, "alice");
    try std.testing.expect(found != null);
    defer freeIdentity(allocator, found.?);

    try std.testing.expectEqualStrings("Alice Smith", found.?.display_name);
    try std.testing.expectEqualStrings("alice@example.com", found.?.email.?);
    try std.testing.expectEqual(IdentityType.user, found.?.identity_type);
    try std.testing.expectEqual(IdentityStatus.active, found.?.status);
    try std.testing.expectEqual(@as(u64, 1717000000), found.?.created_at);
}

test "IdentityStore: duplicate ID rejected" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice",
        .email = null,
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, alice);
    const result = store.create(allocator, alice);
    try std.testing.expectError(error.IdentityAlreadyExists, result);
}

test "IdentityStore: duplicate email rejected" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice",
        .email = "shared@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    const bob = Identity{
        .id = "bob",
        .display_name = "Bob",
        .email = "shared@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, alice);
    const result = store.create(allocator, bob);
    try std.testing.expectError(error.EmailAlreadyExists, result);
}

test "IdentityStore: lookup by email" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice",
        .email = "alice@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, alice);

    const id = try store.lookupByEmail(allocator, "alice@example.com");
    try std.testing.expect(id != null);
    defer allocator.free(id.?);
    try std.testing.expectEqualStrings("alice", id.?);

    const missing = try store.lookupByEmail(allocator, "nobody@example.com");
    try std.testing.expect(missing == null);
}

test "IdentityStore: update changes document and indexes" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice",
        .email = "alice@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, alice);

    // Update email and status
    const updated = Identity{
        .id = "alice",
        .display_name = "Alice Smith",
        .email = "newalice@example.com",
        .identity_type = .user,
        .status = .suspended,
        .created_at = 1717000000,
        .updated_at = 1717100000,
        .attributes = &.{},
    };

    try store.update(allocator, updated);

    // Old email should not resolve
    const old_lookup = try store.lookupByEmail(allocator, "alice@example.com");
    try std.testing.expect(old_lookup == null);

    // New email resolves
    const new_lookup = try store.lookupByEmail(allocator, "newalice@example.com");
    try std.testing.expect(new_lookup != null);
    defer allocator.free(new_lookup.?);
    try std.testing.expectEqualStrings("alice", new_lookup.?);

    // Document updated
    const found = try store.lookup(allocator, "alice");
    defer freeIdentity(allocator, found.?);
    try std.testing.expectEqualStrings("Alice Smith", found.?.display_name);
    try std.testing.expectEqual(IdentityStatus.suspended, found.?.status);
}

test "IdentityStore: remove deletes document and indexes" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice",
        .email = "alice@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, alice);
    try store.remove(allocator, "alice");

    const found = try store.lookup(allocator, "alice");
    try std.testing.expect(found == null);

    const email_lookup = try store.lookupByEmail(allocator, "alice@example.com");
    try std.testing.expect(email_lookup == null);
}

test "IdentityStore: create with attributes" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const attrs = [_]Attribute{
        .{ .key = "department", .value = "engineering" },
        .{ .key = "title", .value = "SRE" },
    };

    const alice = Identity{
        .id = "alice",
        .display_name = "Alice",
        .email = "alice@example.com",
        .identity_type = .user,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &attrs,
    };

    try store.create(allocator, alice);

    const found = try store.lookup(allocator, "alice");
    try std.testing.expect(found != null);
    defer freeIdentity(allocator, found.?);

    try std.testing.expectEqual(@as(usize, 2), found.?.attributes.len);
    try std.testing.expectEqualStrings("department", found.?.attributes[0].key);
    try std.testing.expectEqualStrings("engineering", found.?.attributes[0].value);
    try std.testing.expectEqualStrings("title", found.?.attributes[1].key);
    try std.testing.expectEqualStrings("SRE", found.?.attributes[1].value);
}

test "IdentityStore: null email identity" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const svc = Identity{
        .id = "svc-deploy",
        .display_name = "Deploy Bot",
        .email = null,
        .identity_type = .service_account,
        .status = .active,
        .created_at = 1717000000,
        .updated_at = 1717000000,
        .attributes = &.{},
    };

    try store.create(allocator, svc);

    const found = try store.lookup(allocator, "svc-deploy");
    try std.testing.expect(found != null);
    defer freeIdentity(allocator, found.?);

    try std.testing.expect(found.?.email == null);
    try std.testing.expectEqual(IdentityType.service_account, found.?.identity_type);
}

test "IdentityStore: remove nonexistent returns error" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = IdentityStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const result = store.remove(allocator, "nobody");
    try std.testing.expectError(error.IdentityNotFound, result);
}

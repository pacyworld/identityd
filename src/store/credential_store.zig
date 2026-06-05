//! # Credential Store
//!
//! Stores authentication credentials per identity. Generic over Backend.
//! Supports multiple credential types per identity (password + TOTP + WebAuthn).
//!
//! ## Namespaces
//!
//! - `credentials` — key = `{identity_id}\x00{cred_type}`, value = type-specific binary
//!
//! ## Credential types
//!
//! - password (0x01): 100-byte SCRAM-SHA-256 credential
//! - totp (0x02): 20-byte TOTP secret
//! - webauthn (0x03): credential_id(2B len + data) + public_key(2B len + data)
//!
//! ## Key format
//!
//! `{identity_id}\x00{type_byte}` — allows prefix scan for all credentials of an identity.

const std = @import("std");
const backend_mod = @import("backend");
const crypto = @import("crypto");

const NS_CREDENTIALS = "credentials";

pub const CredentialType = enum(u8) {
    password = 0x01,
    totp = 0x02,
    webauthn = 0x03,
};

pub fn CredentialStore(comptime Backend: type) type {
    backend_mod.assertBackend(Backend);

    return struct {
        const Self = @This();
        db: *Backend,

        pub fn init(db: *Backend) Self {
            return .{ .db = db };
        }

        // ================================================================
        // Password (SCRAM-SHA-256)
        // ================================================================

        /// Set password credential for an identity. Overwrites existing.
        pub fn setPassword(self: *Self, identity_id: []const u8, password: []const u8) !void {
            const cred = crypto.generateCredential(password, crypto.DEFAULT_ITERATIONS);
            const bytes = cred.toBytes();
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .password) orelse return error.KeyTooLong;
            try self.db.put(NS_CREDENTIALS, key, &bytes);
        }

        /// Set password with explicit iteration count.
        pub fn setPasswordWithIterations(self: *Self, identity_id: []const u8, password: []const u8, iterations: u32) !void {
            const cred = crypto.generateCredential(password, iterations);
            const bytes = cred.toBytes();
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .password) orelse return error.KeyTooLong;
            try self.db.put(NS_CREDENTIALS, key, &bytes);
        }

        /// Verify a password against the stored credential.
        /// Returns true if valid, false if wrong, null if no credential.
        pub fn verifyPassword(self: *Self, allocator: std.mem.Allocator, identity_id: []const u8, password: []const u8) !?bool {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .password) orelse return error.KeyTooLong;
            const data = try self.db.get(allocator, NS_CREDENTIALS, key);
            if (data == null) return null;
            defer allocator.free(data.?);

            if (data.?.len != crypto.CREDENTIAL_LEN) return false;
            const cred = crypto.ScramCredential.fromBytes(data.?[0..crypto.CREDENTIAL_LEN]);
            return crypto.verifyPassword(password, &cred);
        }

        /// Get the raw SCRAM credential (for SASL auth flows).
        pub fn getScramCredential(self: *Self, allocator: std.mem.Allocator, identity_id: []const u8) !?crypto.ScramCredential {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .password) orelse return error.KeyTooLong;
            const data = try self.db.get(allocator, NS_CREDENTIALS, key);
            if (data == null) return null;
            defer allocator.free(data.?);

            if (data.?.len != crypto.CREDENTIAL_LEN) return null;
            return crypto.ScramCredential.fromBytes(data.?[0..crypto.CREDENTIAL_LEN]);
        }

        /// Remove password credential.
        pub fn removePassword(self: *Self, identity_id: []const u8) !void {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .password) orelse return error.KeyTooLong;
            try self.db.delete(NS_CREDENTIALS, key);
        }

        // ================================================================
        // TOTP
        // ================================================================

        /// Set TOTP secret for an identity. Generates a new random secret.
        /// Returns the secret (caller should display as base32 to user).
        pub fn setTotp(self: *Self, identity_id: []const u8) ![crypto.TOTP_SECRET_LEN]u8 {
            const secret = crypto.generateTotpSecret();
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .totp) orelse return error.KeyTooLong;
            try self.db.put(NS_CREDENTIALS, key, &secret);
            return secret;
        }

        /// Set TOTP with an explicit secret (for import/migration).
        pub fn setTotpSecret(self: *Self, identity_id: []const u8, secret: []const u8) !void {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .totp) orelse return error.KeyTooLong;
            try self.db.put(NS_CREDENTIALS, key, secret);
        }

        /// Verify a TOTP code. Returns true if valid, null if no TOTP configured.
        pub fn verifyTotp(self: *Self, allocator: std.mem.Allocator, identity_id: []const u8, code: u32, time: u64) !?bool {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .totp) orelse return error.KeyTooLong;
            const data = try self.db.get(allocator, NS_CREDENTIALS, key);
            if (data == null) return null;
            defer allocator.free(data.?);

            return crypto.totpVerify(data.?, code, time);
        }

        /// Remove TOTP credential.
        pub fn removeTotp(self: *Self, identity_id: []const u8) !void {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .totp) orelse return error.KeyTooLong;
            try self.db.delete(NS_CREDENTIALS, key);
        }

        /// Check if TOTP is configured for an identity.
        pub fn hasTotp(self: *Self, allocator: std.mem.Allocator, identity_id: []const u8) !bool {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .totp) orelse return error.KeyTooLong;
            const data = try self.db.get(allocator, NS_CREDENTIALS, key);
            if (data) |d| {
                allocator.free(d);
                return true;
            }
            return false;
        }

        // ================================================================
        // WebAuthn (public key storage)
        // ================================================================

        /// Store a WebAuthn public key credential.
        /// Value format: credential_id_len(2B LE) + credential_id + pubkey_len(2B LE) + pubkey
        pub fn setWebAuthn(self: *Self, identity_id: []const u8, credential_id: []const u8, public_key: []const u8) !void {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .webauthn) orelse return error.KeyTooLong;

            // Encode value
            const val_len = 2 + credential_id.len + 2 + public_key.len;
            if (val_len > 4096) return error.KeyTooLong;
            var val_buf: [4096]u8 = undefined;
            var pos: usize = 0;
            std.mem.writeInt(u16, val_buf[pos..][0..2], @intCast(credential_id.len), .little);
            pos += 2;
            @memcpy(val_buf[pos..][0..credential_id.len], credential_id);
            pos += credential_id.len;
            std.mem.writeInt(u16, val_buf[pos..][0..2], @intCast(public_key.len), .little);
            pos += 2;
            @memcpy(val_buf[pos..][0..public_key.len], public_key);
            pos += public_key.len;

            try self.db.put(NS_CREDENTIALS, key, val_buf[0..pos]);
        }

        /// Get WebAuthn credential_id and public_key for an identity.
        pub const WebAuthnCredential = struct {
            credential_id: []const u8,
            public_key: []const u8,
        };

        pub fn getWebAuthn(self: *Self, allocator: std.mem.Allocator, identity_id: []const u8) !?WebAuthnData {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .webauthn) orelse return error.KeyTooLong;
            const data = try self.db.get(allocator, NS_CREDENTIALS, key);
            if (data == null) return null;

            return .{ .raw = data.?, .allocator = allocator };
        }

        /// Remove WebAuthn credential.
        pub fn removeWebAuthn(self: *Self, identity_id: []const u8) !void {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .webauthn) orelse return error.KeyTooLong;
            try self.db.delete(NS_CREDENTIALS, key);
        }

        // ================================================================
        // Bulk operations
        // ================================================================

        /// Remove all credentials for an identity.
        pub fn removeAll(self: *Self, identity_id: []const u8) !void {
            try self.removePassword(identity_id);
            try self.removeTotp(identity_id);
            try self.removeWebAuthn(identity_id);
        }

        /// Check if an identity has any password credential set.
        pub fn hasPassword(self: *Self, allocator: std.mem.Allocator, identity_id: []const u8) !bool {
            var key_buf: [256]u8 = undefined;
            const key = buildKey(&key_buf, identity_id, .password) orelse return error.KeyTooLong;
            const data = try self.db.get(allocator, NS_CREDENTIALS, key);
            if (data) |d| {
                allocator.free(d);
                return true;
            }
            return false;
        }
    };
}

/// Parsed WebAuthn data with deferred free.
pub const WebAuthnData = struct {
    raw: []u8,
    allocator: std.mem.Allocator,

    pub fn credentialId(self: *const WebAuthnData) ?[]const u8 {
        if (self.raw.len < 2) return null;
        const id_len = std.mem.readInt(u16, self.raw[0..2], .little);
        if (2 + id_len > self.raw.len) return null;
        return self.raw[2..][0..id_len];
    }

    pub fn publicKey(self: *const WebAuthnData) ?[]const u8 {
        if (self.raw.len < 2) return null;
        const id_len = std.mem.readInt(u16, self.raw[0..2], .little);
        const pk_offset = 2 + id_len;
        if (pk_offset + 2 > self.raw.len) return null;
        const pk_len = std.mem.readInt(u16, self.raw[pk_offset..][0..2], .little);
        if (pk_offset + 2 + pk_len > self.raw.len) return null;
        return self.raw[pk_offset + 2 ..][0..pk_len];
    }

    pub fn deinit(self: *WebAuthnData) void {
        self.allocator.free(self.raw);
    }
};

// ============================================================================
// Key builders
// ============================================================================

fn buildKey(buf: []u8, identity_id: []const u8, cred_type: CredentialType) ?[]const u8 {
    const needed = identity_id.len + 1 + 1;
    if (needed > buf.len) return null;
    @memcpy(buf[0..identity_id.len], identity_id);
    buf[identity_id.len] = 0;
    buf[identity_id.len + 1] = @intFromEnum(cred_type);
    return buf[0..needed];
}

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;

test "CredentialStore: set and verify password" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.setPassword("alice", "secret123");

    const result = try store.verifyPassword(allocator, "alice", "secret123");
    try std.testing.expect(result != null);
    try std.testing.expect(result.? == true);

    const wrong = try store.verifyPassword(allocator, "alice", "wrong");
    try std.testing.expect(wrong != null);
    try std.testing.expect(wrong.? == false);
}

test "CredentialStore: verify nonexistent returns null" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const result = try store.verifyPassword(allocator, "nobody", "pass");
    try std.testing.expect(result == null);
}

test "CredentialStore: change password" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.setPassword("alice", "old_pass");
    try store.setPassword("alice", "new_pass");

    const old_check = try store.verifyPassword(allocator, "alice", "old_pass");
    try std.testing.expect(old_check.? == false);

    const new_check = try store.verifyPassword(allocator, "alice", "new_pass");
    try std.testing.expect(new_check.? == true);
}

test "CredentialStore: remove password" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.setPassword("alice", "secret");
    try store.removePassword("alice");

    const result = try store.verifyPassword(allocator, "alice", "secret");
    try std.testing.expect(result == null);
}

test "CredentialStore: hasPassword" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try std.testing.expect(!try store.hasPassword(allocator, "alice"));
    try store.setPassword("alice", "secret");
    try std.testing.expect(try store.hasPassword(allocator, "alice"));
}

test "CredentialStore: TOTP set and verify" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const secret = try store.setTotp("alice");
    const time: u64 = 1717000000;
    const code = crypto.totpGenerate(&secret, time);

    const result = try store.verifyTotp(allocator, "alice", code, time);
    try std.testing.expect(result != null);
    try std.testing.expect(result.? == true);

    // Wrong code
    const wrong = try store.verifyTotp(allocator, "alice", 999999, time);
    try std.testing.expect(wrong.? == false);
}

test "CredentialStore: TOTP not configured returns null" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const result = try store.verifyTotp(allocator, "bob", 123456, 1717000000);
    try std.testing.expect(result == null);
}

test "CredentialStore: hasTotp" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try std.testing.expect(!try store.hasTotp(allocator, "alice"));
    _ = try store.setTotp("alice");
    try std.testing.expect(try store.hasTotp(allocator, "alice"));
}

test "CredentialStore: WebAuthn set and get" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const cred_id = "credential-abc-123";
    const pubkey = "fake-public-key-bytes-here";

    try store.setWebAuthn("alice", cred_id, pubkey);

    var wa = (try store.getWebAuthn(allocator, "alice")).?;
    defer wa.deinit();

    try std.testing.expectEqualStrings(cred_id, wa.credentialId().?);
    try std.testing.expectEqualStrings(pubkey, wa.publicKey().?);
}

test "CredentialStore: WebAuthn not configured returns null" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    const result = try store.getWebAuthn(allocator, "nobody");
    try std.testing.expect(result == null);
}

test "CredentialStore: removeAll" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.setPassword("alice", "pass");
    _ = try store.setTotp("alice");
    try store.setWebAuthn("alice", "cred", "key");

    try store.removeAll("alice");

    try std.testing.expect(!try store.hasPassword(allocator, "alice"));
    try std.testing.expect(!try store.hasTotp(allocator, "alice"));
    const wa = try store.getWebAuthn(allocator, "alice");
    try std.testing.expect(wa == null);
}

test "CredentialStore: getScramCredential" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.setPasswordWithIterations("alice", "mypassword", 2000);

    const cred = (try store.getScramCredential(allocator, "alice")).?;
    try std.testing.expectEqual(@as(u32, 2000), cred.iteration_count);
    try std.testing.expect(crypto.verifyPassword("mypassword", &cred));
}

test "CredentialStore: separate identities" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = CredentialStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.setPassword("alice", "alice_pass");
    try store.setPassword("bob", "bob_pass");

    try std.testing.expect((try store.verifyPassword(allocator, "alice", "alice_pass")).? == true);
    try std.testing.expect((try store.verifyPassword(allocator, "alice", "bob_pass")).? == false);
    try std.testing.expect((try store.verifyPassword(allocator, "bob", "bob_pass")).? == true);
}

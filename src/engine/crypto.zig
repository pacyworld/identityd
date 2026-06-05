//! # Cryptographic Primitives
//!
//! SCRAM-SHA-256 credential generation, TOTP (RFC 6238), and helpers.
//! Uses Zig's std.crypto for all underlying operations.
//!
//! ## SCRAM-SHA-256 (RFC 5802)
//!
//! Credential format (100 bytes):
//!   salt(32) | stored_key(32) | server_key(32) | iteration_count_be(4)
//!
//! Generation:
//!   SaltedPassword = PBKDF2-SHA256(password, salt, iterations)
//!   ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
//!   StoredKey = SHA256(ClientKey)
//!   ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")
//!
//! Verification:
//!   Recompute StoredKey from supplied password + stored salt/iterations,
//!   compare against stored StoredKey.
//!
//! ## TOTP (RFC 6238)
//!
//! 6-digit HMAC-SHA1 codes with 30-second period.
//! Accepts ±1 window for clock skew tolerance.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SALT_LEN = 32;
pub const KEY_LEN = 32; // SHA-256 output
pub const CREDENTIAL_LEN = SALT_LEN + KEY_LEN + KEY_LEN + 4; // 100 bytes
pub const DEFAULT_ITERATIONS: u32 = 4096;

pub const TOTP_SECRET_LEN = 20; // 160-bit TOTP secret (RFC 4226 recommends 160)
pub const TOTP_PERIOD: u64 = 30;
pub const TOTP_DIGITS: u8 = 6;

/// SCRAM-SHA-256 stored credential.
pub const ScramCredential = struct {
    salt: [SALT_LEN]u8,
    stored_key: [KEY_LEN]u8,
    server_key: [KEY_LEN]u8,
    iteration_count: u32,

    /// Serialize to 100-byte binary format.
    pub fn toBytes(self: *const ScramCredential) [CREDENTIAL_LEN]u8 {
        var buf: [CREDENTIAL_LEN]u8 = undefined;
        @memcpy(buf[0..SALT_LEN], &self.salt);
        @memcpy(buf[SALT_LEN..][0..KEY_LEN], &self.stored_key);
        @memcpy(buf[SALT_LEN + KEY_LEN ..][0..KEY_LEN], &self.server_key);
        std.mem.writeInt(u32, buf[SALT_LEN + KEY_LEN + KEY_LEN ..][0..4], self.iteration_count, .big);
        return buf;
    }

    /// Deserialize from 100-byte binary format.
    pub fn fromBytes(data: *const [CREDENTIAL_LEN]u8) ScramCredential {
        var cred: ScramCredential = undefined;
        @memcpy(&cred.salt, data[0..SALT_LEN]);
        @memcpy(&cred.stored_key, data[SALT_LEN..][0..KEY_LEN]);
        @memcpy(&cred.server_key, data[SALT_LEN + KEY_LEN ..][0..KEY_LEN]);
        cred.iteration_count = std.mem.readInt(u32, data[SALT_LEN + KEY_LEN + KEY_LEN ..][0..4], .big);
        return cred;
    }
};

/// Generate a SCRAM-SHA-256 credential from a password.
/// Uses OS random for salt generation.
pub fn generateCredential(password: []const u8, iterations: u32) ScramCredential {
    var salt: [SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);
    return generateCredentialWithSalt(password, &salt, iterations);
}

/// Generate a SCRAM-SHA-256 credential with an explicit salt (for testing).
pub fn generateCredentialWithSalt(password: []const u8, salt: *const [SALT_LEN]u8, iterations: u32) ScramCredential {
    // SaltedPassword = Hi(password, salt, iterations)
    var salted_password: [KEY_LEN]u8 = undefined;
    pbkdf2Sha256(password, salt, iterations, &salted_password);

    // ClientKey = HMAC(SaltedPassword, "Client Key")
    var client_key: [KEY_LEN]u8 = undefined;
    HmacSha256.create(&client_key, "Client Key", &salted_password);

    // StoredKey = SHA256(ClientKey)
    var stored_key: [KEY_LEN]u8 = undefined;
    Sha256.hash(&client_key, &stored_key, .{});

    // ServerKey = HMAC(SaltedPassword, "Server Key")
    var server_key: [KEY_LEN]u8 = undefined;
    HmacSha256.create(&server_key, "Server Key", &salted_password);

    return .{
        .salt = salt.*,
        .stored_key = stored_key,
        .server_key = server_key,
        .iteration_count = iterations,
    };
}

/// Verify a password against a stored SCRAM credential.
/// Returns true if the password matches.
pub fn verifyPassword(password: []const u8, credential: *const ScramCredential) bool {
    const recomputed = generateCredentialWithSalt(
        password,
        &credential.salt,
        credential.iteration_count,
    );
    return std.mem.eql(u8, &recomputed.stored_key, &credential.stored_key);
}

/// PBKDF2-HMAC-SHA256 (RFC 2898).
fn pbkdf2Sha256(password: []const u8, salt: []const u8, iterations: u32, out: *[KEY_LEN]u8) void {
    // For SCRAM, we only need block 1 (dk_len == hash_len)
    // U1 = HMAC(password, salt || INT32BE(1))
    var salt_block: [SALT_LEN + 4]u8 = undefined;
    @memcpy(salt_block[0..salt.len], salt);
    std.mem.writeInt(u32, salt_block[salt.len..][0..4], 1, .big);

    var u: [KEY_LEN]u8 = undefined;
    HmacSha256.create(&u, salt_block[0 .. salt.len + 4], password);

    var result: [KEY_LEN]u8 = u;

    // U2..Un
    var i: u32 = 1;
    while (i < iterations) : (i += 1) {
        var next: [KEY_LEN]u8 = undefined;
        HmacSha256.create(&next, &u, password);
        u = next;
        for (&result, next) |*r, n| r.* ^= n;
    }

    out.* = result;
}

// ============================================================================
// TOTP (RFC 6238)
// ============================================================================

/// Generate a TOTP code for the given secret and time.
pub fn totpGenerate(secret: []const u8, time: u64) u32 {
    const counter = time / TOTP_PERIOD;
    return hotpGenerate(secret, counter);
}

/// Verify a TOTP code with ±1 window tolerance.
pub fn totpVerify(secret: []const u8, code: u32, time: u64) bool {
    const counter = time / TOTP_PERIOD;

    // Check current, previous, and next windows
    if (counter > 0 and hotpGenerate(secret, counter - 1) == code) return true;
    if (hotpGenerate(secret, counter) == code) return true;
    if (hotpGenerate(secret, counter + 1) == code) return true;
    return false;
}

/// HOTP (RFC 4226) — base algorithm for TOTP.
fn hotpGenerate(secret: []const u8, counter: u64) u32 {
    // HMAC-SHA1(secret, counter_be)
    const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_bytes, counter, .big);

    var hash: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&hash, &counter_bytes, secret);

    // Dynamic truncation (RFC 4226 Section 5.4)
    const offset: u4 = @intCast(hash[19] & 0x0f);
    const code_bytes = hash[offset..][0..4];
    const raw: u32 = (std.mem.readInt(u32, code_bytes, .big)) & 0x7fffffff;

    // Modulo 10^digits
    const modulus: u32 = 1000000; // 10^6 for 6 digits
    return raw % modulus;
}

/// Generate a random TOTP secret.
pub fn generateTotpSecret() [TOTP_SECRET_LEN]u8 {
    var secret: [TOTP_SECRET_LEN]u8 = undefined;
    std.crypto.random.bytes(&secret);
    return secret;
}

// ============================================================================
// Tests
// ============================================================================

test "SCRAM credential: generate and verify" {
    const password = "correct horse battery staple";
    const cred = generateCredential(password, DEFAULT_ITERATIONS);

    try std.testing.expect(verifyPassword(password, &cred));
    try std.testing.expect(!verifyPassword("wrong password", &cred));
}

test "SCRAM credential: serialize roundtrip" {
    const password = "test123";
    const cred = generateCredential(password, 1000);
    const bytes = cred.toBytes();
    const restored = ScramCredential.fromBytes(&bytes);

    try std.testing.expectEqualSlices(u8, &cred.salt, &restored.salt);
    try std.testing.expectEqualSlices(u8, &cred.stored_key, &restored.stored_key);
    try std.testing.expectEqualSlices(u8, &cred.server_key, &restored.server_key);
    try std.testing.expectEqual(cred.iteration_count, restored.iteration_count);
}

test "SCRAM credential: deterministic with same salt" {
    const password = "hello";
    var salt: [SALT_LEN]u8 = undefined;
    @memset(&salt, 0xAB);

    const cred1 = generateCredentialWithSalt(password, &salt, 1000);
    const cred2 = generateCredentialWithSalt(password, &salt, 1000);

    try std.testing.expectEqualSlices(u8, &cred1.stored_key, &cred2.stored_key);
    try std.testing.expectEqualSlices(u8, &cred1.server_key, &cred2.server_key);
}

test "SCRAM credential: different salt produces different keys" {
    const password = "hello";
    var salt1: [SALT_LEN]u8 = undefined;
    @memset(&salt1, 0x01);
    var salt2: [SALT_LEN]u8 = undefined;
    @memset(&salt2, 0x02);

    const cred1 = generateCredentialWithSalt(password, &salt1, 1000);
    const cred2 = generateCredentialWithSalt(password, &salt2, 1000);

    try std.testing.expect(!std.mem.eql(u8, &cred1.stored_key, &cred2.stored_key));
}

test "PBKDF2-SHA256: consistency via SCRAM roundtrip" {
    // Verify PBKDF2 produces consistent results by generating
    // two credentials with the same inputs and comparing
    var salt: [SALT_LEN]u8 = undefined;
    @memset(&salt, 0x42);
    const cred1 = generateCredentialWithSalt("password", &salt, 100);
    const cred2 = generateCredentialWithSalt("password", &salt, 100);
    try std.testing.expectEqualSlices(u8, &cred1.stored_key, &cred2.stored_key);
    try std.testing.expectEqualSlices(u8, &cred1.server_key, &cred2.server_key);
}

test "TOTP: generate and verify" {
    var secret: [TOTP_SECRET_LEN]u8 = undefined;
    @memset(&secret, 0x42);

    const time: u64 = 1717000000;
    const code = totpGenerate(&secret, time);

    // Same time should verify
    try std.testing.expect(totpVerify(&secret, code, time));

    // ±30s should still verify (window tolerance)
    try std.testing.expect(totpVerify(&secret, code, time + 15));

    // Far future should NOT verify
    try std.testing.expect(!totpVerify(&secret, code, time + 120));
}

test "TOTP: different secrets produce different codes" {
    var secret1: [TOTP_SECRET_LEN]u8 = undefined;
    @memset(&secret1, 0x01);
    var secret2: [TOTP_SECRET_LEN]u8 = undefined;
    @memset(&secret2, 0x02);

    const time: u64 = 1717000000;
    const code1 = totpGenerate(&secret1, time);
    const code2 = totpGenerate(&secret2, time);

    try std.testing.expect(code1 != code2);
}

test "TOTP: code is 6 digits" {
    var secret: [TOTP_SECRET_LEN]u8 = undefined;
    @memset(&secret, 0xFF);

    const code = totpGenerate(&secret, 1717000000);
    try std.testing.expect(code < 1000000);
}

test "HOTP: deterministic" {
    var secret: [TOTP_SECRET_LEN]u8 = undefined;
    @memset(&secret, 0x31);

    const code1 = hotpGenerate(&secret, 100);
    const code2 = hotpGenerate(&secret, 100);
    try std.testing.expectEqual(code1, code2);

    // Different counter produces different code
    const code3 = hotpGenerate(&secret, 101);
    try std.testing.expect(code1 != code3);
}

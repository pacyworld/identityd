//! # Wire Protocol
//!
//! Binary request-response protocol for identityd. Same framing as xmppd IPC:
//! 4-byte LE length prefix + 1-byte tag + variable fields.
//!
//! ## Frame layout
//!
//! ```
//! ┌──────────┬─────┬────────────────┐
//! │ len (4B) │ tag │ payload (N-1B) │
//! └──────────┴─────┴────────────────┘
//! ```
//!
//! `len` is the total size of tag + payload (does NOT include the 4-byte length itself).
//!
//! ## Field encoding
//!
//! Fields use a simple length-prefixed format:
//! - Strings/bytes: 2B LE length + data
//! - u64: 8 bytes LE
//! - u8: 1 byte
//! - bool: 1 byte (0x00 = false, 0x01 = true)
//! - Optional string: 1B present flag + (if present: 2B LE length + data)
//!
//! ## Request tags (client → server)
//!
//! Identity operations:   0x01–0x06
//! Group operations:      0x10–0x15
//! Edge operations:       0x20–0x25
//! Graph queries:         0x30–0x31
//!
//! ## Response tags (server → client)
//!
//! 0x80: OK (empty or payload follows)
//! 0x81: Error (1B error code + string message)
//! 0x82: Bool result
//! 0x83: Single identity document
//! 0x84: Single group document
//! 0x85: List of IDs
//! 0x86: Edge data

const std = @import("std");

// ============================================================================
// Tags
// ============================================================================

pub const Tag = enum(u8) {
    // Identity
    create_identity = 0x01,
    get_identity = 0x02,
    update_identity = 0x03,
    delete_identity = 0x04,
    list_identities = 0x05,
    lookup_by_email = 0x06,

    // Group
    create_group = 0x10,
    get_group = 0x11,
    update_group = 0x12,
    delete_group = 0x13,
    list_groups = 0x14,
    lookup_by_name = 0x15,

    // Edge
    add_edge = 0x20,
    remove_edge = 0x21,
    has_edge = 0x22,
    get_edge = 0x23,
    list_edges_from = 0x24,
    list_edges_to = 0x25,

    // Graph queries
    has_path = 0x30,
    reachable = 0x31,

    // Responses
    ok = 0x80,
    err = 0x81,
    bool_result = 0x82,
    identity_result = 0x83,
    group_result = 0x84,
    id_list_result = 0x85,
    edge_data_result = 0x86,

    _,
};

pub const ErrorCode = enum(u8) {
    unknown = 0,
    not_found = 1,
    already_exists = 2,
    invalid_request = 3,
    internal = 4,
    key_too_long = 5,
};

// ============================================================================
// Frame reader/writer
// ============================================================================

pub const HEADER_LEN = 4;
pub const MAX_FRAME_LEN = 64 * 1024; // 64KB max frame

/// Read a complete frame from a socket fd. Returns tag + payload.
/// Caller owns the returned payload slice.
pub fn readFrameFd(allocator: std.mem.Allocator, fd: std.posix.fd_t) !?Frame {
    var hdr: [HEADER_LEN]u8 = undefined;
    if (!readExact(fd, &hdr)) return null;

    const len = std.mem.readInt(u32, &hdr, .little);
    if (len == 0) return null;
    if (len > MAX_FRAME_LEN) return error.FrameTooLarge;

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    if (!readExact(fd, buf)) {
        allocator.free(buf);
        return null;
    }

    return .{
        .tag = @enumFromInt(buf[0]),
        .payload = buf[1..],
        .raw = buf,
    };
}

/// Write a frame to a socket fd.
pub fn writeFrameFd(fd: std.posix.fd_t, tag: Tag, payload: []const u8) !void {
    const len: u32 = @intCast(1 + payload.len);
    var hdr: [HEADER_LEN]u8 = undefined;
    std.mem.writeInt(u32, &hdr, len, .little);
    try writeAll(fd, &hdr);
    try writeAll(fd, &[_]u8{@intFromEnum(tag)});
    if (payload.len > 0) {
        try writeAll(fd, payload);
    }
}

/// Read a complete frame from any reader (for tests with fixedBufferStream).
pub fn readFrame(allocator: std.mem.Allocator, reader: anytype) !?Frame {
    var hdr: [HEADER_LEN]u8 = undefined;
    const hdr_read = reader.readAll(&hdr) catch return null;
    if (hdr_read < HEADER_LEN) return null;

    const len = std.mem.readInt(u32, &hdr, .little);
    if (len == 0) return null;
    if (len > MAX_FRAME_LEN) return error.FrameTooLarge;

    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    const n = reader.readAll(buf) catch {
        allocator.free(buf);
        return null;
    };
    if (n < len) {
        allocator.free(buf);
        return null;
    }

    return .{
        .tag = @enumFromInt(buf[0]),
        .payload = buf[1..],
        .raw = buf,
    };
}

/// Write a frame to any writer (for tests with fixedBufferStream).
pub fn writeFrame(writer: anytype, tag: Tag, payload: []const u8) !void {
    const len: u32 = @intCast(1 + payload.len);
    var hdr: [HEADER_LEN]u8 = undefined;
    std.mem.writeInt(u32, &hdr, len, .little);
    try writer.writeAll(&hdr);
    try writer.writeAll(&[_]u8{@intFromEnum(tag)});
    if (payload.len > 0) {
        try writer.writeAll(payload);
    }
}

// -- Low-level I/O helpers --

fn readExact(fd: std.posix.fd_t, buf: []u8) bool {
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch return false;
        if (n == 0) return false;
        total += n;
    }
    return true;
}

fn writeAll(fd: std.posix.fd_t, data: []const u8) !void {
    var total: usize = 0;
    while (total < data.len) {
        const n = std.posix.write(fd, data[total..]) catch return error.BrokenPipe;
        total += n;
    }
}

pub const Frame = struct {
    tag: Tag,
    payload: []const u8,
    raw: []u8, // full allocation (tag byte + payload)

    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
    }
};

// ============================================================================
// Field encoder
// ============================================================================

pub const FieldEncoder = struct {
    buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) FieldEncoder {
        return .{ .buf = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *FieldEncoder) void {
        self.buf.deinit(self.allocator);
    }

    pub fn toOwnedSlice(self: *FieldEncoder) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    pub fn writeStr(self: *FieldEncoder, s: []const u8) !void {
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(s.len), .little);
        try self.buf.appendSlice(self.allocator, &len_buf);
        try self.buf.appendSlice(self.allocator, s);
    }

    pub fn writeOptionalStr(self: *FieldEncoder, s: ?[]const u8) !void {
        if (s) |str| {
            try self.buf.append(self.allocator, 1);
            try self.writeStr(str);
        } else {
            try self.buf.append(self.allocator, 0);
        }
    }

    pub fn writeU64(self: *FieldEncoder, val: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, val, .little);
        try self.buf.appendSlice(self.allocator, &buf);
    }

    pub fn writeU8(self: *FieldEncoder, val: u8) !void {
        try self.buf.append(self.allocator, val);
    }

    pub fn writeBool(self: *FieldEncoder, val: bool) !void {
        try self.buf.append(self.allocator, if (val) @as(u8, 1) else @as(u8, 0));
    }
};

// ============================================================================
// Field decoder
// ============================================================================

pub const FieldDecoder = struct {
    data: []const u8,
    pos: usize,

    pub fn init(data: []const u8) FieldDecoder {
        return .{ .data = data, .pos = 0 };
    }

    pub fn readStr(self: *FieldDecoder) ![]const u8 {
        if (self.pos + 2 > self.data.len) return error.UnexpectedEof;
        const len = std.mem.readInt(u16, self.data[self.pos..][0..2], .little);
        self.pos += 2;
        if (self.pos + len > self.data.len) return error.UnexpectedEof;
        const s = self.data[self.pos..][0..len];
        self.pos += len;
        return s;
    }

    pub fn readOptionalStr(self: *FieldDecoder) !?[]const u8 {
        if (self.pos >= self.data.len) return error.UnexpectedEof;
        const present = self.data[self.pos];
        self.pos += 1;
        if (present == 0) return null;
        return try self.readStr();
    }

    pub fn readU64(self: *FieldDecoder) !u64 {
        if (self.pos + 8 > self.data.len) return error.UnexpectedEof;
        const val = std.mem.readInt(u64, self.data[self.pos..][0..8], .little);
        self.pos += 8;
        return val;
    }

    pub fn readU8(self: *FieldDecoder) !u8 {
        if (self.pos >= self.data.len) return error.UnexpectedEof;
        const val = self.data[self.pos];
        self.pos += 1;
        return val;
    }

    pub fn readBool(self: *FieldDecoder) !bool {
        return (try self.readU8()) != 0;
    }

    pub fn remaining(self: *const FieldDecoder) []const u8 {
        return self.data[self.pos..];
    }
};

// ============================================================================
// Response builders
// ============================================================================

/// Build an OK response with no payload.
pub fn buildOk(allocator: std.mem.Allocator) ![]u8 {
    _ = allocator;
    return &.{};
}

/// Build an error response.
pub fn buildError(allocator: std.mem.Allocator, code: ErrorCode, msg: []const u8) ![]u8 {
    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    try enc.writeU8(@intFromEnum(code));
    try enc.writeStr(msg);
    return try enc.toOwnedSlice();
}

/// Build a bool result.
pub fn buildBoolResult(allocator: std.mem.Allocator, val: bool) ![]u8 {
    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    try enc.writeBool(val);
    return try enc.toOwnedSlice();
}

/// Build an ID list result from an iterator.
pub fn buildIdList(allocator: std.mem.Allocator, ids: []const []const u8) ![]u8 {
    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    var count_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &count_buf, @intCast(ids.len), .little);
    try enc.buf.appendSlice(allocator, &count_buf);
    for (ids) |id| {
        try enc.writeStr(id);
    }
    return try enc.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "FieldEncoder/FieldDecoder roundtrip: strings" {
    const allocator = std.testing.allocator;

    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    try enc.writeStr("hello");
    try enc.writeStr("world");
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = FieldDecoder.init(data);
    const s1 = try dec.readStr();
    try std.testing.expectEqualStrings("hello", s1);
    const s2 = try dec.readStr();
    try std.testing.expectEqualStrings("world", s2);
}

test "FieldEncoder/FieldDecoder roundtrip: u64" {
    const allocator = std.testing.allocator;

    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    try enc.writeU64(1717000000);
    try enc.writeU64(0);
    try enc.writeU64(std.math.maxInt(u64));
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = FieldDecoder.init(data);
    try std.testing.expectEqual(@as(u64, 1717000000), try dec.readU64());
    try std.testing.expectEqual(@as(u64, 0), try dec.readU64());
    try std.testing.expectEqual(std.math.maxInt(u64), try dec.readU64());
}

test "FieldEncoder/FieldDecoder roundtrip: optional strings" {
    const allocator = std.testing.allocator;

    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    try enc.writeOptionalStr("present");
    try enc.writeOptionalStr(null);
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = FieldDecoder.init(data);
    const s1 = try dec.readOptionalStr();
    try std.testing.expectEqualStrings("present", s1.?);
    const s2 = try dec.readOptionalStr();
    try std.testing.expect(s2 == null);
}

test "FieldEncoder/FieldDecoder roundtrip: bool and u8" {
    const allocator = std.testing.allocator;

    var enc = FieldEncoder.init(allocator);
    defer enc.deinit();
    try enc.writeBool(true);
    try enc.writeBool(false);
    try enc.writeU8(42);
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = FieldDecoder.init(data);
    try std.testing.expect(try dec.readBool() == true);
    try std.testing.expect(try dec.readBool() == false);
    try std.testing.expectEqual(@as(u8, 42), try dec.readU8());
}

test "writeFrame/readFrame roundtrip" {
    const allocator = std.testing.allocator;

    var out_buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out_buf);
    const writer = fbs.writer();

    try writeFrame(writer, .create_identity, "test_payload");

    // Read it back
    fbs.pos = 0;
    const reader = fbs.reader();
    var frame = (try readFrame(allocator, reader)).?;
    defer frame.deinit(allocator);

    try std.testing.expectEqual(Tag.create_identity, frame.tag);
    try std.testing.expectEqualStrings("test_payload", frame.payload);
}

test "readFrame: incomplete header returns null" {
    const allocator = std.testing.allocator;

    var buf = [_]u8{ 0x01, 0x00 }; // Only 2 bytes, need 4
    var fbs = std.io.fixedBufferStream(&buf);
    const result = try readFrame(allocator, fbs.reader());
    try std.testing.expect(result == null);
}

test "buildError" {
    const allocator = std.testing.allocator;

    const payload = try buildError(allocator, .not_found, "identity not found");
    defer allocator.free(payload);

    var dec = FieldDecoder.init(payload);
    const code = try dec.readU8();
    try std.testing.expectEqual(@as(u8, 1), code);
    const msg = try dec.readStr();
    try std.testing.expectEqualStrings("identity not found", msg);
}

test "buildBoolResult" {
    const allocator = std.testing.allocator;

    const payload = try buildBoolResult(allocator, true);
    defer allocator.free(payload);

    var dec = FieldDecoder.init(payload);
    try std.testing.expect(try dec.readBool() == true);
}

test "buildIdList" {
    const allocator = std.testing.allocator;

    const ids = [_][]const u8{ "alice", "bob", "charlie" };
    const payload = try buildIdList(allocator, &ids);
    defer allocator.free(payload);

    var dec = FieldDecoder.init(payload);
    const count = std.mem.readInt(u16, payload[0..2], .little);
    try std.testing.expectEqual(@as(u16, 3), count);
    dec.pos = 2;
    try std.testing.expectEqualStrings("alice", try dec.readStr());
    try std.testing.expectEqualStrings("bob", try dec.readStr());
    try std.testing.expectEqualStrings("charlie", try dec.readStr());
}

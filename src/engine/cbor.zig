//! # CBOR Codec
//!
//! Minimal CBOR (RFC 8949) encoder/decoder for identity document attributes.
//! Supports the subset needed for structured identity data:
//!
//! - Unsigned integers (major type 0)
//! - Byte strings (major type 2)
//! - Text strings (major type 3)
//! - Arrays (major type 4)
//! - Maps (major type 5)
//! - Simple values: null, true, false (major type 7)
//!
//! Documents are encoded as CBOR maps with integer keys (compact).
//! Attribute maps use text string keys for extensibility.

const std = @import("std");

/// CBOR value type for decoding.
pub const Value = union(enum) {
    unsigned: u64,
    bytes: []const u8,
    text: []const u8,
    array: []const Value,
    map: []const MapEntry,
    boolean: bool,
    null_value: void,
};

pub const MapEntry = struct {
    key: Value,
    value: Value,
};

// ============================================================================
// Encoder
// ============================================================================

pub const Encoder = struct {
    buf: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Encoder {
        return .{ .buf = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *Encoder) void {
        self.buf.deinit(self.allocator);
    }

    pub fn toOwnedSlice(self: *Encoder) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    /// Encode an unsigned integer (major type 0).
    pub fn writeUint(self: *Encoder, val: u64) !void {
        try self.writeHead(0, val);
    }

    /// Encode a byte string (major type 2).
    pub fn writeBytes(self: *Encoder, data: []const u8) !void {
        try self.writeHead(2, data.len);
        try self.buf.appendSlice(self.allocator, data);
    }

    /// Encode a text string (major type 3).
    pub fn writeText(self: *Encoder, text: []const u8) !void {
        try self.writeHead(3, text.len);
        try self.buf.appendSlice(self.allocator, text);
    }

    /// Begin an array of known length (major type 4).
    pub fn writeArrayHeader(self: *Encoder, len: usize) !void {
        try self.writeHead(4, len);
    }

    /// Begin a map of known length (major type 5).
    pub fn writeMapHeader(self: *Encoder, len: usize) !void {
        try self.writeHead(5, len);
    }

    /// Encode null (major type 7, value 22).
    pub fn writeNull(self: *Encoder) !void {
        try self.buf.append(self.allocator, 0xf6);
    }

    /// Encode a boolean (major type 7, values 20/21).
    pub fn writeBool(self: *Encoder, val: bool) !void {
        try self.buf.append(self.allocator, if (val) @as(u8, 0xf5) else @as(u8, 0xf4));
    }

    /// Encode an optional text string — writes text or null.
    pub fn writeOptionalText(self: *Encoder, text: ?[]const u8) !void {
        if (text) |t| {
            try self.writeText(t);
        } else {
            try self.writeNull();
        }
    }

    fn writeHead(self: *Encoder, major: u3, val: u64) !void {
        const mt: u8 = @as(u8, major) << 5;
        if (val < 24) {
            try self.buf.append(self.allocator, mt | @as(u8, @intCast(val)));
        } else if (val <= 0xFF) {
            try self.buf.append(self.allocator, mt | 24);
            try self.buf.append(self.allocator, @intCast(val));
        } else if (val <= 0xFFFF) {
            try self.buf.append(self.allocator, mt | 25);
            const v16: u16 = @intCast(val);
            const be = std.mem.nativeToBig(u16, v16);
            try self.buf.appendSlice(self.allocator, &std.mem.toBytes(be));
        } else if (val <= 0xFFFFFFFF) {
            try self.buf.append(self.allocator, mt | 26);
            const v32: u32 = @intCast(val);
            const be = std.mem.nativeToBig(u32, v32);
            try self.buf.appendSlice(self.allocator, &std.mem.toBytes(be));
        } else {
            try self.buf.append(self.allocator, mt | 27);
            const be = std.mem.nativeToBig(u64, val);
            try self.buf.appendSlice(self.allocator, &std.mem.toBytes(be));
        }
    }
};

// ============================================================================
// Decoder
// ============================================================================

pub const DecodeError = error{
    UnexpectedEof,
    UnsupportedType,
    InvalidCbor,
    OutOfMemory,
};

pub const Decoder = struct {
    data: []const u8,
    pos: usize,

    pub fn init(data: []const u8) Decoder {
        return .{ .data = data, .pos = 0 };
    }

    /// Decode the next value. Returned slices point into the input data
    /// (zero-copy for bytes/text). Arrays and maps are allocated with the
    /// provided allocator — caller owns.
    pub fn decode(self: *Decoder, allocator: std.mem.Allocator) DecodeError!Value {
        if (self.pos >= self.data.len) return error.UnexpectedEof;

        const initial = self.data[self.pos];
        const major: u3 = @intCast(initial >> 5);
        const additional: u5 = @intCast(initial & 0x1f);
        self.pos += 1;

        switch (major) {
            0 => {
                // Unsigned integer
                const val = try self.readArgument(additional);
                return .{ .unsigned = val };
            },
            2 => {
                // Byte string
                const len = try self.readArgument(additional);
                if (self.pos + len > self.data.len) return error.UnexpectedEof;
                const slice = self.data[self.pos..][0..len];
                self.pos += len;
                return .{ .bytes = slice };
            },
            3 => {
                // Text string
                const len = try self.readArgument(additional);
                if (self.pos + len > self.data.len) return error.UnexpectedEof;
                const slice = self.data[self.pos..][0..len];
                self.pos += len;
                return .{ .text = slice };
            },
            4 => {
                // Array
                const len = try self.readArgument(additional);
                const items = try allocator.alloc(Value, len);
                for (items) |*item| {
                    item.* = try self.decode(allocator);
                }
                return .{ .array = items };
            },
            5 => {
                // Map
                const len = try self.readArgument(additional);
                const entries = try allocator.alloc(MapEntry, len);
                for (entries) |*entry| {
                    entry.key = try self.decode(allocator);
                    entry.value = try self.decode(allocator);
                }
                return .{ .map = entries };
            },
            7 => {
                // Simple values
                return switch (additional) {
                    20 => .{ .boolean = false },
                    21 => .{ .boolean = true },
                    22 => .{ .null_value = {} },
                    else => error.UnsupportedType,
                };
            },
            else => return error.UnsupportedType,
        }
    }

    /// Read a uint argument following the initial byte.
    fn readArgument(self: *Decoder, additional: u5) DecodeError!u64 {
        if (additional < 24) return @as(u64, additional);

        switch (additional) {
            24 => {
                if (self.pos >= self.data.len) return error.UnexpectedEof;
                const val = self.data[self.pos];
                self.pos += 1;
                return @as(u64, val);
            },
            25 => {
                if (self.pos + 2 > self.data.len) return error.UnexpectedEof;
                const val = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
                self.pos += 2;
                return @as(u64, val);
            },
            26 => {
                if (self.pos + 4 > self.data.len) return error.UnexpectedEof;
                const val = std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
                self.pos += 4;
                return @as(u64, val);
            },
            27 => {
                if (self.pos + 8 > self.data.len) return error.UnexpectedEof;
                const val = std.mem.readInt(u64, self.data[self.pos..][0..8], .big);
                self.pos += 8;
                return @as(u64, val);
            },
            else => return error.InvalidCbor,
        }
    }

    /// Decode a uint, returning null if the value is null.
    pub fn decodeOptionalUint(self: *Decoder, allocator: std.mem.Allocator) DecodeError!?u64 {
        const val = try self.decode(allocator);
        return switch (val) {
            .unsigned => |u| u,
            .null_value => null,
            else => error.InvalidCbor,
        };
    }

    /// Decode a text string, returning null if the value is null.
    pub fn decodeOptionalText(self: *Decoder, allocator: std.mem.Allocator) DecodeError!?[]const u8 {
        const val = try self.decode(allocator);
        return switch (val) {
            .text => |t| t,
            .null_value => null,
            else => error.InvalidCbor,
        };
    }
};

// ============================================================================
// Helper: decode map by integer key
// ============================================================================

/// Look up a value in a decoded CBOR map by integer key.
pub fn mapGetUintKey(entries: []const MapEntry, key: u64) ?Value {
    for (entries) |entry| {
        switch (entry.key) {
            .unsigned => |k| if (k == key) return entry.value,
            else => {},
        }
    }
    return null;
}

/// Look up a value in a decoded CBOR map by text key.
pub fn mapGetTextKey(entries: []const MapEntry, key: []const u8) ?Value {
    for (entries) |entry| {
        switch (entry.key) {
            .text => |k| if (std.mem.eql(u8, k, key)) return entry.value,
            else => {},
        }
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "encode and decode unsigned integers" {
    const allocator = std.testing.allocator;

    // Small integer (< 24)
    {
        var enc = Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeUint(7);
        const data = try enc.toOwnedSlice();
        defer allocator.free(data);

        var dec = Decoder.init(data);
        const val = try dec.decode(allocator);
        try std.testing.expectEqual(@as(u64, 7), val.unsigned);
    }

    // 1-byte integer
    {
        var enc = Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeUint(200);
        const data = try enc.toOwnedSlice();
        defer allocator.free(data);

        var dec = Decoder.init(data);
        const val = try dec.decode(allocator);
        try std.testing.expectEqual(@as(u64, 200), val.unsigned);
    }

    // 2-byte integer
    {
        var enc = Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeUint(1000);
        const data = try enc.toOwnedSlice();
        defer allocator.free(data);

        var dec = Decoder.init(data);
        const val = try dec.decode(allocator);
        try std.testing.expectEqual(@as(u64, 1000), val.unsigned);
    }

    // 4-byte integer
    {
        var enc = Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeUint(100000);
        const data = try enc.toOwnedSlice();
        defer allocator.free(data);

        var dec = Decoder.init(data);
        const val = try dec.decode(allocator);
        try std.testing.expectEqual(@as(u64, 100000), val.unsigned);
    }

    // 8-byte integer
    {
        var enc = Encoder.init(allocator);
        defer enc.deinit();
        try enc.writeUint(5_000_000_000);
        const data = try enc.toOwnedSlice();
        defer allocator.free(data);

        var dec = Decoder.init(data);
        const val = try dec.decode(allocator);
        try std.testing.expectEqual(@as(u64, 5_000_000_000), val.unsigned);
    }
}

test "encode and decode text strings" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeText("hello world");
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const val = try dec.decode(allocator);
    try std.testing.expectEqualStrings("hello world", val.text);
}

test "encode and decode byte strings" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeBytes(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const val = try dec.decode(allocator);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, val.bytes);
}

test "encode and decode null" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeNull();
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const val = try dec.decode(allocator);
    try std.testing.expect(val == .null_value);
}

test "encode and decode booleans" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeBool(true);
    try enc.writeBool(false);
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const t = try dec.decode(allocator);
    try std.testing.expect(t.boolean == true);
    const f = try dec.decode(allocator);
    try std.testing.expect(f.boolean == false);
}

test "encode and decode map" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeMapHeader(2);
    try enc.writeUint(0);
    try enc.writeText("Alice");
    try enc.writeUint(1);
    try enc.writeUint(42);
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const val = try dec.decode(allocator);
    defer allocator.free(@constCast(val.map));

    try std.testing.expectEqual(@as(usize, 2), val.map.len);

    const name = mapGetUintKey(val.map, 0).?;
    try std.testing.expectEqualStrings("Alice", name.text);

    const age = mapGetUintKey(val.map, 1).?;
    try std.testing.expectEqual(@as(u64, 42), age.unsigned);
}

test "encode and decode array" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeArrayHeader(3);
    try enc.writeText("a");
    try enc.writeText("b");
    try enc.writeText("c");
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const val = try dec.decode(allocator);
    defer allocator.free(@constCast(val.array));

    try std.testing.expectEqual(@as(usize, 3), val.array.len);
    try std.testing.expectEqualStrings("a", val.array[0].text);
    try std.testing.expectEqualStrings("b", val.array[1].text);
    try std.testing.expectEqualStrings("c", val.array[2].text);
}

test "encode and decode nested map with attributes" {
    const allocator = std.testing.allocator;

    // Simulate an identity document:
    // { 0: "Alice", 1: "alice@example.com", 2: 0, 3: 0, 4: 1717000000 }
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeMapHeader(5);
    try enc.writeUint(0);
    try enc.writeText("Alice");
    try enc.writeUint(1);
    try enc.writeText("alice@example.com");
    try enc.writeUint(2);
    try enc.writeUint(0); // type: user
    try enc.writeUint(3);
    try enc.writeUint(0); // status: active
    try enc.writeUint(4);
    try enc.writeUint(1717000000); // created_at
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const val = try dec.decode(allocator);
    defer allocator.free(@constCast(val.map));

    const display = mapGetUintKey(val.map, 0).?;
    try std.testing.expectEqualStrings("Alice", display.text);

    const email = mapGetUintKey(val.map, 1).?;
    try std.testing.expectEqualStrings("alice@example.com", email.text);

    const identity_type = mapGetUintKey(val.map, 2).?;
    try std.testing.expectEqual(@as(u64, 0), identity_type.unsigned);
}

test "optional text encode/decode" {
    const allocator = std.testing.allocator;

    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.writeOptionalText("present");
    try enc.writeOptionalText(null);
    const data = try enc.toOwnedSlice();
    defer allocator.free(data);

    var dec = Decoder.init(data);
    const t = try dec.decodeOptionalText(allocator);
    try std.testing.expectEqualStrings("present", t.?);
    const n = try dec.decodeOptionalText(allocator);
    try std.testing.expect(n == null);
}

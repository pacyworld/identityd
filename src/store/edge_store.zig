//! # Edge Store (Graph Engine)
//!
//! Directed labeled graph engine for identity relationships. Generic over a
//! StorageBackend — works with LMDB, MemoryBackend, etc.
//!
//! ## Namespaces
//!
//! - `edges` — forward edges, key = `{from}\x00{edge_type}\x00{to}`
//! - `edges_rev` — reverse edges, key = `{to}\x00{edge_type}\x00{from}`
//!
//! Both namespaces are maintained atomically via WriteBatch on every
//! mutation. The reverse index enables efficient "who points to X?" queries
//! without a full scan.
//!
//! ## Edge data
//!
//! Each edge carries an optional byte-string payload (metadata like
//! granted_at, granted_by, role weight, etc.). Empty slice for edges
//! that need no metadata.
//!
//! ## Traversal
//!
//! Bounded BFS for transitive queries (e.g., "is alice transitively in
//! admins via member_of?"). Max depth prevents infinite loops in cyclic
//! graphs. Fixed-size visited set avoids heap allocation during traversal.
//!
//! ## Composite key layout
//!
//! ```
//! Forward: from \x00 edge_type \x00 to   →  data
//! Reverse: to   \x00 edge_type \x00 from →  data
//! ```
//!
//! Prefix scans:
//! - `{from}\x00{edge_type}\x00` → all targets of `from` via `edge_type`
//! - `{from}\x00` → all edges from `from` (any type)

const std = @import("std");
const backend_mod = @import("backend");

const NS_EDGES = "edges";
const NS_EDGES_REV = "edges_rev";

const MAX_KEY_LEN = 512;

/// Maximum nodes tracked during BFS traversal.
const MAX_VISITED = 256;

/// Maximum BFS depth.
const MAX_DEPTH = 16;

/// An edge with parsed components.
pub const Edge = struct {
    from: []const u8,
    edge_type: []const u8,
    to: []const u8,
    data: []const u8,
};

pub fn EdgeStore(comptime Backend: type) type {
    backend_mod.assertBackend(Backend);

    return struct {
        const Self = @This();
        db: *Backend,

        pub fn init(db: *Backend) Self {
            return .{ .db = db };
        }

        /// Add a directed edge. Atomically writes forward + reverse.
        /// Overwrites if the edge already exists.
        pub fn addEdge(self: *Self, from: []const u8, edge_type: []const u8, to: []const u8, data: []const u8) !void {
            var fwd_buf: [MAX_KEY_LEN]u8 = undefined;
            var rev_buf: [MAX_KEY_LEN]u8 = undefined;
            const fwd_key = buildEdgeKey(&fwd_buf, from, edge_type, to) orelse return error.KeyTooLong;
            const rev_key = buildEdgeKey(&rev_buf, to, edge_type, from) orelse return error.KeyTooLong;

            var batch = try self.db.writeBatch();
            errdefer batch.abort();
            try batch.put(NS_EDGES, fwd_key, data);
            try batch.put(NS_EDGES_REV, rev_key, data);
            try batch.commit();
        }

        /// Remove a directed edge. Atomically deletes forward + reverse.
        /// No error if the edge doesn't exist.
        pub fn removeEdge(self: *Self, from: []const u8, edge_type: []const u8, to: []const u8) !void {
            var fwd_buf: [MAX_KEY_LEN]u8 = undefined;
            var rev_buf: [MAX_KEY_LEN]u8 = undefined;
            const fwd_key = buildEdgeKey(&fwd_buf, from, edge_type, to) orelse return error.KeyTooLong;
            const rev_key = buildEdgeKey(&rev_buf, to, edge_type, from) orelse return error.KeyTooLong;

            var batch = try self.db.writeBatch();
            errdefer batch.abort();
            try batch.delete(NS_EDGES, fwd_key);
            try batch.delete(NS_EDGES_REV, rev_key);
            try batch.commit();
        }

        /// Check if a specific edge exists.
        pub fn hasEdge(self: *Self, allocator: std.mem.Allocator, from: []const u8, edge_type: []const u8, to: []const u8) !bool {
            var buf: [MAX_KEY_LEN]u8 = undefined;
            const key = buildEdgeKey(&buf, from, edge_type, to) orelse return error.KeyTooLong;
            const val = try self.db.get(allocator, NS_EDGES, key);
            if (val) |v| {
                allocator.free(v);
                return true;
            }
            return false;
        }

        /// Get the data payload of a specific edge. Caller owns returned memory.
        pub fn getEdge(self: *Self, allocator: std.mem.Allocator, from: []const u8, edge_type: []const u8, to: []const u8) !?[]u8 {
            var buf: [MAX_KEY_LEN]u8 = undefined;
            const key = buildEdgeKey(&buf, from, edge_type, to) orelse return error.KeyTooLong;
            return try self.db.get(allocator, NS_EDGES, key);
        }

        /// Iterate all targets reachable from `from` via `edge_type`.
        /// Iterator yields Entry where key = full composite key, value = edge data.
        /// Use `parseEdgeKey()` to extract components.
        pub fn iterEdgesFrom(self: *Self, from: []const u8, edge_type: []const u8) !Backend.Iterator {
            var prefix_buf: [MAX_KEY_LEN]u8 = undefined;
            const prefix = buildEdgePrefix(&prefix_buf, from, edge_type) orelse return error.KeyTooLong;
            return try self.db.iterator(NS_EDGES, prefix);
        }

        /// Iterate all sources pointing to `to` via `edge_type` (reverse lookup).
        /// Use `parseEdgeKey()` on the returned key — note the components are
        /// (to, edge_type, from) since this is the reverse namespace.
        pub fn iterEdgesTo(self: *Self, to: []const u8, edge_type: []const u8) !Backend.Iterator {
            var prefix_buf: [MAX_KEY_LEN]u8 = undefined;
            const prefix = buildEdgePrefix(&prefix_buf, to, edge_type) orelse return error.KeyTooLong;
            return try self.db.iterator(NS_EDGES_REV, prefix);
        }

        /// Iterate ALL edges from `from` (any edge type).
        pub fn iterAllEdgesFrom(self: *Self, from: []const u8) !Backend.Iterator {
            var prefix_buf: [MAX_KEY_LEN]u8 = undefined;
            const len = from.len + 1;
            if (len > prefix_buf.len) return error.KeyTooLong;
            @memcpy(prefix_buf[0..from.len], from);
            prefix_buf[from.len] = 0;
            return try self.db.iterator(NS_EDGES, prefix_buf[0..len]);
        }

        /// Remove all edges originating from `from` (any type, any target).
        /// Useful for cascade delete when removing an identity.
        pub fn removeAllEdgesFrom(self: *Self, allocator: std.mem.Allocator, from: []const u8) !void {
            // Collect forward edges, then delete each one.
            // Must collect first because iterator is invalidated by writes.
            var keys_list: [MAX_VISITED]EdgeComponents = undefined;
            var count: usize = 0;

            {
                var iter = try self.iterAllEdgesFrom(from);
                defer iter.deinit();

                while (iter.next()) |entry| {
                    if (count >= MAX_VISITED) break;
                    const parsed = parseEdgeKey(entry.key) orelse continue;
                    // Copy the components we need (iterator memory is transient)
                    keys_list[count] = .{
                        .a = try allocator.dupe(u8, parsed.a),
                        .b = try allocator.dupe(u8, parsed.b),
                        .c = try allocator.dupe(u8, parsed.c),
                    };
                    count += 1;
                }
            }
            defer for (keys_list[0..count]) |*k| {
                allocator.free(k.a);
                allocator.free(k.b);
                allocator.free(k.c);
            };

            for (keys_list[0..count]) |k| {
                try self.removeEdge(k.a, k.b, k.c);
            }
        }

        /// Remove all edges pointing to `to` (any type, any source).
        /// Useful for cascade delete when removing a group.
        pub fn removeAllEdgesTo(self: *Self, allocator: std.mem.Allocator, to: []const u8) !void {
            var keys_list: [MAX_VISITED]EdgeComponents = undefined;
            var count: usize = 0;

            {
                var prefix_buf: [MAX_KEY_LEN]u8 = undefined;
                const len = to.len + 1;
                if (len > prefix_buf.len) return error.KeyTooLong;
                @memcpy(prefix_buf[0..to.len], to);
                prefix_buf[to.len] = 0;

                var iter = try self.db.iterator(NS_EDGES_REV, prefix_buf[0..len]);
                defer iter.deinit();

                while (iter.next()) |entry| {
                    if (count >= MAX_VISITED) break;
                    // Reverse key: to\x00type\x00from
                    const parsed = parseEdgeKey(entry.key) orelse continue;
                    keys_list[count] = .{
                        .a = try allocator.dupe(u8, parsed.c), // from (third component of reverse key)
                        .b = try allocator.dupe(u8, parsed.b), // edge_type
                        .c = try allocator.dupe(u8, parsed.a), // to (first component of reverse key)
                    };
                    count += 1;
                }
            }
            defer for (keys_list[0..count]) |*k| {
                allocator.free(k.a);
                allocator.free(k.b);
                allocator.free(k.c);
            };

            for (keys_list[0..count]) |k| {
                try self.removeEdge(k.a, k.b, k.c);
            }
        }

        // ================================================================
        // Bounded BFS Traversal
        // ================================================================

        /// Check if `target` is reachable from `start` via edges of `edge_type`
        /// within `max_depth` hops. Follows forward edges.
        pub fn hasPath(self: *Self, start: []const u8, target: []const u8, edge_type: []const u8, max_depth: u8) !bool {
            if (std.mem.eql(u8, start, target)) return true;
            if (max_depth == 0) return false;

            const depth = @min(max_depth, MAX_DEPTH);
            var visited = VisitedSet{};

            visited.add(start);

            // BFS using two alternating queue layers (current depth / next depth)
            var current = QueueLayer{};
            current.add(start);

            var d: u8 = 0;
            while (d < depth) : (d += 1) {
                var next = QueueLayer{};

                for (current.items()) |node| {
                    var iter = try self.iterEdgesFrom(node, edge_type);
                    defer iter.deinit();

                    while (iter.next()) |entry| {
                        const parsed = parseEdgeKey(entry.key) orelse continue;
                        const neighbor = parsed.c; // 'to' component

                        if (std.mem.eql(u8, neighbor, target)) return true;

                        if (!visited.contains(neighbor)) {
                            visited.add(neighbor);
                            next.add(neighbor);
                        }
                    }
                }

                if (next.count == 0) return false;
                current = next;
            }
            return false;
        }

        /// Return all nodes reachable from `start` via `edge_type` within
        /// `max_depth` hops. Returns a list of node IDs (pointers into
        /// the visited set — valid until the caller's scope ends).
        /// Caller does NOT own the returned slice memory.
        pub fn reachable(self: *Self, start: []const u8, edge_type: []const u8, max_depth: u8) !ReachableResult {
            const depth = @min(max_depth, MAX_DEPTH);
            var result = ReachableResult{};

            var visited = VisitedSet{};
            visited.add(start);

            var current = QueueLayer{};
            current.add(start);

            var d: u8 = 0;
            while (d < depth) : (d += 1) {
                var next = QueueLayer{};

                for (current.items()) |node| {
                    var iter = try self.iterEdgesFrom(node, edge_type);
                    defer iter.deinit();

                    while (iter.next()) |entry| {
                        const parsed = parseEdgeKey(entry.key) orelse continue;
                        const neighbor = parsed.c;

                        if (!visited.contains(neighbor)) {
                            visited.add(neighbor);
                            next.add(neighbor);
                            result.add(neighbor);
                        }
                    }
                }

                if (next.count == 0) break;
                current = next;
            }

            return result;
        }
    };
}

// ============================================================================
// Composite key builders
// ============================================================================

/// Build a composite edge key: `{a}\x00{b}\x00{c}`
fn buildEdgeKey(buf: []u8, a: []const u8, b: []const u8, c: []const u8) ?[]const u8 {
    const needed = a.len + 1 + b.len + 1 + c.len;
    if (needed > buf.len) return null;
    var pos: usize = 0;
    @memcpy(buf[pos..][0..a.len], a);
    pos += a.len;
    buf[pos] = 0;
    pos += 1;
    @memcpy(buf[pos..][0..b.len], b);
    pos += b.len;
    buf[pos] = 0;
    pos += 1;
    @memcpy(buf[pos..][0..c.len], c);
    pos += c.len;
    return buf[0..pos];
}

/// Build a prefix for scanning: `{a}\x00{b}\x00`
fn buildEdgePrefix(buf: []u8, a: []const u8, b: []const u8) ?[]const u8 {
    const needed = a.len + 1 + b.len + 1;
    if (needed > buf.len) return null;
    var pos: usize = 0;
    @memcpy(buf[pos..][0..a.len], a);
    pos += a.len;
    buf[pos] = 0;
    pos += 1;
    @memcpy(buf[pos..][0..b.len], b);
    pos += b.len;
    buf[pos] = 0;
    pos += 1;
    return buf[0..pos];
}

const EdgeComponents = struct {
    a: []const u8,
    b: []const u8,
    c: []const u8,
};

/// Parse a composite key `{a}\x00{b}\x00{c}` into its three components.
pub fn parseEdgeKey(key: []const u8) ?EdgeComponents {
    // Find first separator
    const sep1 = std.mem.indexOfScalar(u8, key, 0) orelse return null;
    const rest = key[sep1 + 1 ..];
    // Find second separator
    const sep2 = std.mem.indexOfScalar(u8, rest, 0) orelse return null;

    return .{
        .a = key[0..sep1],
        .b = rest[0..sep2],
        .c = rest[sep2 + 1 ..],
    };
}

// ============================================================================
// BFS data structures (fixed-size, no heap allocation)
// ============================================================================

/// Fixed-size set tracking visited node IDs during BFS.
/// Stores pointers to iterator-returned strings (valid for current depth).
/// Uses linear scan — fine for MAX_VISITED ≤ 256.
const VisitedSet = struct {
    entries: [MAX_VISITED][]const u8 = undefined,
    count: usize = 0,

    fn add(self: *VisitedSet, id: []const u8) void {
        if (self.count < MAX_VISITED) {
            self.entries[self.count] = id;
            self.count += 1;
        }
    }

    fn contains(self: *const VisitedSet, id: []const u8) bool {
        for (self.entries[0..self.count]) |e| {
            if (std.mem.eql(u8, e, id)) return true;
        }
        return false;
    }
};

/// Fixed-size queue layer for BFS (nodes at current depth).
const QueueLayer = struct {
    entries: [MAX_VISITED][]const u8 = undefined,
    count: usize = 0,

    fn add(self: *QueueLayer, id: []const u8) void {
        if (self.count < MAX_VISITED) {
            self.entries[self.count] = id;
            self.count += 1;
        }
    }

    fn items(self: *const QueueLayer) []const []const u8 {
        return self.entries[0..self.count];
    }
};

/// Result of a reachable() query.
pub const ReachableResult = struct {
    nodes: [MAX_VISITED][]const u8 = undefined,
    count: usize = 0,

    fn add(self: *ReachableResult, id: []const u8) void {
        if (self.count < MAX_VISITED) {
            self.nodes[self.count] = id;
            self.count += 1;
        }
    }

    pub fn items(self: *const ReachableResult) []const []const u8 {
        return self.nodes[0..self.count];
    }

    pub fn contains(self: *const ReachableResult, id: []const u8) bool {
        for (self.nodes[0..self.count]) |n| {
            if (std.mem.eql(u8, n, id)) return true;
        }
        return false;
    }
};

// ============================================================================
// Tests
// ============================================================================

const MemoryBackend = backend_mod.MemoryBackend;

test "EdgeStore: add and check edge" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.addEdge("alice", "member_of", "admins", "");

    try std.testing.expect(try store.hasEdge(allocator, "alice", "member_of", "admins"));
    try std.testing.expect(!try store.hasEdge(allocator, "alice", "member_of", "users"));
    try std.testing.expect(!try store.hasEdge(allocator, "bob", "member_of", "admins"));
}

test "EdgeStore: add edge with data" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.addEdge("alice", "has_role", "editor", "granted_by=admin");

    const data = try store.getEdge(allocator, "alice", "has_role", "editor");
    try std.testing.expect(data != null);
    defer allocator.free(data.?);
    try std.testing.expectEqualStrings("granted_by=admin", data.?);
}

test "EdgeStore: remove edge" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.addEdge("alice", "member_of", "admins", "");
    try store.removeEdge("alice", "member_of", "admins");

    try std.testing.expect(!try store.hasEdge(allocator, "alice", "member_of", "admins"));
}

test "EdgeStore: remove nonexistent edge is silent" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // Should not error
    try store.removeEdge("nobody", "member_of", "nothing");
}

test "EdgeStore: iterate edges from" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    try store.addEdge("alice", "member_of", "admins", "");
    try store.addEdge("alice", "member_of", "devs", "");
    try store.addEdge("bob", "member_of", "devs", "");

    var iter = try store.iterEdgesFrom("alice", "member_of");
    defer iter.deinit();

    var count: usize = 0;
    while (iter.next()) |entry| {
        const parsed = parseEdgeKey(entry.key).?;
        try std.testing.expectEqualStrings("alice", parsed.a);
        try std.testing.expectEqualStrings("member_of", parsed.b);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "EdgeStore: iterate edges to (reverse)" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    try store.addEdge("alice", "member_of", "devs", "");
    try store.addEdge("bob", "member_of", "devs", "");
    try store.addEdge("charlie", "member_of", "ops", "");

    // Who is in devs?
    var iter = try store.iterEdgesTo("devs", "member_of");
    defer iter.deinit();

    var count: usize = 0;
    while (iter.next()) |entry| {
        const parsed = parseEdgeKey(entry.key).?;
        // Reverse key: to=devs, type=member_of, from=alice|bob
        try std.testing.expectEqualStrings("devs", parsed.a);
        try std.testing.expectEqualStrings("member_of", parsed.b);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "EdgeStore: overwrite edge data" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.addEdge("alice", "has_role", "editor", "v1");
    try store.addEdge("alice", "has_role", "editor", "v2");

    const data = try store.getEdge(allocator, "alice", "has_role", "editor");
    try std.testing.expect(data != null);
    defer allocator.free(data.?);
    try std.testing.expectEqualStrings("v2", data.?);
}

test "EdgeStore: removeAllEdgesFrom" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.addEdge("alice", "member_of", "admins", "");
    try store.addEdge("alice", "member_of", "devs", "");
    try store.addEdge("alice", "has_role", "editor", "");
    try store.addEdge("bob", "member_of", "devs", "");

    try store.removeAllEdgesFrom(allocator, "alice");

    // Alice's edges gone
    try std.testing.expect(!try store.hasEdge(allocator, "alice", "member_of", "admins"));
    try std.testing.expect(!try store.hasEdge(allocator, "alice", "member_of", "devs"));
    try std.testing.expect(!try store.hasEdge(allocator, "alice", "has_role", "editor"));

    // Bob's edge untouched
    try std.testing.expect(try store.hasEdge(allocator, "bob", "member_of", "devs"));
}

test "EdgeStore: removeAllEdgesTo" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);
    const allocator = std.testing.allocator;

    try store.addEdge("alice", "member_of", "devs", "");
    try store.addEdge("bob", "member_of", "devs", "");
    try store.addEdge("charlie", "member_of", "ops", "");

    try store.removeAllEdgesTo(allocator, "devs");

    // devs edges gone
    try std.testing.expect(!try store.hasEdge(allocator, "alice", "member_of", "devs"));
    try std.testing.expect(!try store.hasEdge(allocator, "bob", "member_of", "devs"));

    // ops edge untouched
    try std.testing.expect(try store.hasEdge(allocator, "charlie", "member_of", "ops"));
}

test "EdgeStore: hasPath direct" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    try store.addEdge("alice", "member_of", "admins", "");

    try std.testing.expect(try store.hasPath("alice", "admins", "member_of", 3));
    try std.testing.expect(!try store.hasPath("alice", "ops", "member_of", 3));
}

test "EdgeStore: hasPath transitive" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // alice -> devs -> engineering -> all-staff
    try store.addEdge("alice", "member_of", "devs", "");
    try store.addEdge("devs", "member_of", "engineering", "");
    try store.addEdge("engineering", "member_of", "all-staff", "");

    // Depth 3 should find it
    try std.testing.expect(try store.hasPath("alice", "all-staff", "member_of", 3));

    // Depth 2 should NOT (3 hops needed)
    try std.testing.expect(!try store.hasPath("alice", "all-staff", "member_of", 2));

    // Depth 1 only finds direct
    try std.testing.expect(try store.hasPath("alice", "devs", "member_of", 1));
    try std.testing.expect(!try store.hasPath("alice", "engineering", "member_of", 1));
}

test "EdgeStore: hasPath self" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // start == target should always be true
    try std.testing.expect(try store.hasPath("alice", "alice", "member_of", 0));
}

test "EdgeStore: hasPath cycle detection" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // Create a cycle: a -> b -> c -> a
    try store.addEdge("a", "link", "b", "");
    try store.addEdge("b", "link", "c", "");
    try store.addEdge("c", "link", "a", "");

    // Should find b and c from a, but NOT loop forever
    try std.testing.expect(try store.hasPath("a", "c", "link", 10));
    try std.testing.expect(try store.hasPath("a", "b", "link", 10));

    // d is unreachable
    try std.testing.expect(!try store.hasPath("a", "d", "link", 10));
}

test "EdgeStore: reachable" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // alice -> devs -> engineering
    // alice -> ops
    try store.addEdge("alice", "member_of", "devs", "");
    try store.addEdge("alice", "member_of", "ops", "");
    try store.addEdge("devs", "member_of", "engineering", "");

    const result = try store.reachable("alice", "member_of", 5);

    try std.testing.expect(result.contains("devs"));
    try std.testing.expect(result.contains("ops"));
    try std.testing.expect(result.contains("engineering"));
    try std.testing.expect(!result.contains("alice")); // start is excluded
    try std.testing.expectEqual(@as(usize, 3), result.count);
}

test "EdgeStore: reachable with depth limit" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // chain: a -> b -> c -> d
    try store.addEdge("a", "link", "b", "");
    try store.addEdge("b", "link", "c", "");
    try store.addEdge("c", "link", "d", "");

    const r1 = try store.reachable("a", "link", 1);
    try std.testing.expectEqual(@as(usize, 1), r1.count);
    try std.testing.expect(r1.contains("b"));

    const r2 = try store.reachable("a", "link", 2);
    try std.testing.expectEqual(@as(usize, 2), r2.count);

    const r3 = try store.reachable("a", "link", 3);
    try std.testing.expectEqual(@as(usize, 3), r3.count);
}

test "EdgeStore: reachable cycle" {
    var db = try MemoryBackend.open("", .{});
    defer db.close();

    var store = EdgeStore(MemoryBackend).init(&db);

    // Cycle: a -> b -> c -> a
    try store.addEdge("a", "link", "b", "");
    try store.addEdge("b", "link", "c", "");
    try store.addEdge("c", "link", "a", "");

    const result = try store.reachable("a", "link", 10);
    try std.testing.expectEqual(@as(usize, 2), result.count);
    try std.testing.expect(result.contains("b"));
    try std.testing.expect(result.contains("c"));
}

test "parseEdgeKey" {
    const key = "alice\x00member_of\x00admins";
    const parsed = parseEdgeKey(key).?;
    try std.testing.expectEqualStrings("alice", parsed.a);
    try std.testing.expectEqualStrings("member_of", parsed.b);
    try std.testing.expectEqualStrings("admins", parsed.c);
}

test "parseEdgeKey invalid" {
    try std.testing.expect(parseEdgeKey("no_separators") == null);
    try std.testing.expect(parseEdgeKey("one\x00separator") == null);
}

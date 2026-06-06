//! # idctl — Identity Database Control Tool
//!
//! CLI management tool for identityd. Connects via Unix socket.
//!
//! Commands:
//!   idctl adduser <id> <display_name> [--email <email>]
//!   idctl deluser <id>
//!   idctl getuser <id>
//!   idctl addgroup <id> <name> [--description <desc>] [--type group|role|ou]
//!   idctl delgroup <id>
//!   idctl getgroup <id>
//!   idctl addedge <from> <edge_type> <to> [--data <data>]
//!   idctl deledge <from> <edge_type> <to>
//!   idctl hasedge <from> <edge_type> <to>
//!   idctl haspath <start> <target> <edge_type> [--depth <N>]
//!   idctl members <group_id> <edge_type>

const std = @import("std");
const protocol = @import("protocol");
const client_mod = @import("client");

const Client = client_mod.Client;

const DEFAULT_SOCKET_PATH = "/var/run/identityd.sock";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    // Find --socket option and command (first non-option arg)
    var socket_path: []const u8 = DEFAULT_SOCKET_PATH;
    var cmd_index: ?usize = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--socket") and i + 1 < args.len) {
            socket_path = args[i + 1];
            i += 1;
        } else if (args[i].len > 0 and args[i][0] == '-') {
            // Other global options (--help, -h) handled below
            if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
                printUsage();
                return;
            }
        } else {
            if (cmd_index == null) cmd_index = i;
        }
    }

    if (cmd_index == null) {
        printUsage();
        std.process.exit(1);
    }

    const cmd = args[cmd_index.?];

    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        printUsage();
        return;
    }

    var client = Client.connect(allocator, socket_path) catch {
        fatal("cannot connect to identityd (is it running?)");
    };
    defer client.close();

    const cmd_args = args[cmd_index.? + 1 ..];

    if (std.mem.eql(u8, cmd, "adduser")) {
        try cmdAddUser(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "deluser")) {
        try cmdDelUser(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "getuser")) {
        try cmdGetUser(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "addgroup")) {
        try cmdAddGroup(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "delgroup")) {
        try cmdDelGroup(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "addedge")) {
        try cmdAddEdge(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "deledge")) {
        try cmdDelEdge(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "hasedge")) {
        try cmdHasEdge(allocator, &client, cmd_args);
    } else if (std.mem.eql(u8, cmd, "haspath")) {
        try cmdHasPath(allocator, &client, cmd_args);
    } else {
        std.log.err("unknown command: {s}", .{cmd});
        printUsage();
        std.process.exit(1);
    }
}

fn cmdAddUser(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 2) fatal("usage: idctl adduser <id> <display_name> [--email <email>]");

    const id = args[0];
    const display_name = args[1];
    var email: ?[]const u8 = null;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--email") and i + 1 < args.len) {
            email = args[i + 1];
            i += 1;
        }
    }

    const now = @as(u64, @intCast(std.time.timestamp()));
    client.createIdentity(id, display_name, email, 0, 0, now, now) catch |err| {
        return handleClientError(err, "create identity");
    };
    printOut("created identity: {s}\n", .{id});
}

fn cmdDelUser(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 1) fatal("usage: idctl deluser <id>");
    client.deleteIdentity(args[0]) catch |err| return handleClientError(err, "delete identity");
    printOut("deleted identity: {s}\n", .{args[0]});
}

fn cmdGetUser(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 1) fatal("usage: idctl getuser <id>");
    const result = client.getIdentity(args[0]) catch |err| {
        return handleClientError(err, "get identity");
    };
    if (result) |r| {
        printOut("id:           {s}\n", .{r.id});
        printOut("display_name: {s}\n", .{r.display_name});
        if (r.email) |e| {
            printOut("email:        {s}\n", .{e});
        } else {
            printOut("email:        (none)\n", .{});
        }
        printOut("type:         {d}\n", .{r.identity_type});
        printOut("status:       {d}\n", .{r.status});
    } else {
        printOut("identity not found: {s}\n", .{args[0]});
    }
}

fn cmdAddGroup(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 2) fatal("usage: idctl addgroup <id> <name> [--description <desc>] [--type group|role|ou]");

    const id = args[0];
    const name = args[1];
    var description: ?[]const u8 = null;
    var group_type: u8 = 0;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--description") and i + 1 < args.len) {
            description = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--type") and i + 1 < args.len) {
            i += 1;
            if (std.mem.eql(u8, args[i], "role")) {
                group_type = 1;
            } else if (std.mem.eql(u8, args[i], "ou")) {
                group_type = 2;
            }
        }
    }

    const now = @as(u64, @intCast(std.time.timestamp()));
    client.createGroup(id, name, description, group_type, now, now) catch |err| {
        return handleClientError(err, "create group");
    };
    printOut("created group: {s}\n", .{id});
}

fn cmdDelGroup(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 1) fatal("usage: idctl delgroup <id>");
    client.deleteGroup(args[0]) catch |err| return handleClientError(err, "delete group");
    printOut("deleted group: {s}\n", .{args[0]});
}

fn cmdAddEdge(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 3) fatal("usage: idctl addedge <from> <edge_type> <to> [--data <data>]");

    const from = args[0];
    const edge_type = args[1];
    const to = args[2];
    var data: []const u8 = "";

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--data") and i + 1 < args.len) {
            data = args[i + 1];
            i += 1;
        }
    }

    client.addEdge(from, edge_type, to, data) catch |err| {
        return handleClientError(err, "add edge");
    };
    printOut("added edge: {s} --[{s}]--> {s}\n", .{ from, edge_type, to });
}

fn cmdDelEdge(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 3) fatal("usage: idctl deledge <from> <edge_type> <to>");
    client.removeEdge(args[0], args[1], args[2]) catch |err| {
        return handleClientError(err, "remove edge");
    };
    printOut("removed edge: {s} --[{s}]--> {s}\n", .{ args[0], args[1], args[2] });
}

fn cmdHasEdge(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 3) fatal("usage: idctl hasedge <from> <edge_type> <to>");
    const exists = client.hasEdge(args[0], args[1], args[2]) catch |err| {
        return handleClientError(err, "has edge");
    };
    printOut("{s}\n", .{if (exists) "true" else "false"});
}

fn cmdHasPath(_: std.mem.Allocator, client: *Client, args: []const []const u8) !void {
    if (args.len < 3) fatal("usage: idctl haspath <start> <target> <edge_type> [--depth <N>]");

    const start = args[0];
    const target = args[1];
    const edge_type = args[2];
    var max_depth: u8 = 8;

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--depth") and i + 1 < args.len) {
            i += 1;
            max_depth = std.fmt.parseInt(u8, args[i], 10) catch 8;
        }
    }

    const found = client.hasPath(start, target, edge_type, max_depth) catch |err| {
        return handleClientError(err, "has path");
    };
    printOut("{s}\n", .{if (found) "true" else "false"});
}

fn handleClientError(err: anytype, context: []const u8) void {
    switch (err) {
        error.NotFound => printErr("error: not found ({s})\n", .{context}),
        error.AlreadyExists => printErr("error: already exists ({s})\n", .{context}),
        error.ConnectionFailed => printErr("error: connection failed\n", .{}),
        else => printErr("error: {s} ({s})\n", .{ @errorName(err), context }),
    }
    std.process.exit(1);
}

fn printOut(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(1, msg) catch {};
}

fn printErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(2, msg) catch {};
}

fn fatal(msg: []const u8) noreturn {
    printErr("{s}\n", .{msg});
    std.process.exit(1);
}

fn printUsage() void {
    printOut(
        \\idctl — Identity Database Control Tool
        \\
        \\Usage: idctl <command> [options]
        \\
        \\Commands:
        \\  adduser <id> <display_name> [--email <email>]
        \\  deluser <id>
        \\  getuser <id>
        \\  addgroup <id> <name> [--description <desc>] [--type group|role|ou]
        \\  delgroup <id>
        \\  addedge <from> <edge_type> <to> [--data <data>]
        \\  deledge <from> <edge_type> <to>
        \\  hasedge <from> <edge_type> <to>
        \\  haspath <start> <target> <edge_type> [--depth <N>]
        \\
        \\Global options:
        \\  --socket <path>   Unix socket path (default: /var/run/identityd.sock)
        \\  --help, -h        Show this help
        \\
    , .{});
}

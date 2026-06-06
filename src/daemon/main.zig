//! # identityd — Identity Database Daemon
//!
//! Opens an LMDB database and listens on a Unix socket for protocol requests.
//! Single-threaded, synchronous, one client at a time (MVP).
//!
//! Usage:
//!   identityd --db /var/db/identityd --socket /var/run/identityd.sock
//!
//! Defaults:
//!   --db      /var/db/identityd
//!   --socket  /var/run/identityd.sock

const std = @import("std");
const lmdb_mod = @import("lmdb_backend");
const server_mod = @import("server");

const LmdbBackend = lmdb_mod.LmdbBackend;
const Server = server_mod.Server(LmdbBackend);

const DEFAULT_DB_PATH = "/var/db/identityd";
const DEFAULT_SOCKET_PATH = "/var/run/identityd.sock";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse args
    var db_path: []const u8 = DEFAULT_DB_PATH;
    var socket_path: []const u8 = DEFAULT_SOCKET_PATH;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--db")) {
            i += 1;
            if (i >= args.len) fatal("--db requires an argument");
            db_path = args[i];
        } else if (std.mem.eql(u8, arg, "--socket")) {
            i += 1;
            if (i >= args.len) fatal("--socket requires an argument");
            socket_path = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else {
            std.log.err("unknown argument: {s}", .{arg});
            fatal("use --help for usage");
        }
    }

    // Open LMDB
    std.log.info("opening database at {s}", .{db_path});
    var db = try LmdbBackend.open(db_path, .{
        .max_namespaces = 16,
        .map_size = 256 * 1024 * 1024, // 256MB
        .create = true,
    });
    defer db.close();

    // Start server
    var srv = Server.init(allocator, &db, socket_path);
    defer srv.stop();

    try srv.listen();

    // Install signal handler for clean shutdown
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    std.log.info("identityd ready, accepting connections", .{});
    srv.serve() catch |err| {
        std.log.err("server error: {}", .{err});
    };
    std.log.info("identityd shutting down", .{});
}

fn handleSignal(_: c_int) callconv(.c) void {
    // Zig's std.posix.accept retries EINTR and treats EBADF as unreachable,
    // so there's no clean way to unblock the blocking accept loop from a
    // signal handler in the prototype. Just exit. The OS cleans up fds.
    std.posix.exit(0);
}

fn fatal(msg: []const u8) noreturn {
    std.log.err("{s}", .{msg});
    std.process.exit(1);
}

fn printUsage() void {
    _ = std.posix.write(1,
        \\identityd — Identity Database Daemon
        \\
        \\Usage: identityd [options]
        \\
        \\Options:
        \\  --db <path>       Database directory (default: /var/db/identityd)
        \\  --socket <path>   Unix socket path (default: /var/run/identityd.sock)
        \\  --help, -h        Show this help
        \\
    ) catch {};
}

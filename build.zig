const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Dependencies ---

    const lmdb_dep = b.dependency("lmdb", .{ .target = target, .optimize = optimize });

    // --- Backend module (trait + MemoryBackend) ---

    const backend_mod = b.createModule(.{
        .root_source_file = b.path("src/engine/backend.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- CBOR module ---

    const cbor_mod = b.createModule(.{
        .root_source_file = b.path("src/engine/cbor.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- LMDB backend module ---

    const lmdb_backend_mod = b.createModule(.{
        .root_source_file = b.path("src/engine/lmdb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lmdb_backend_mod.addImport("lmdb", lmdb_dep.module("lmdb"));
    lmdb_backend_mod.addImport("backend", backend_mod);

    // --- Identity Store module ---

    const identity_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/identity_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    identity_store_mod.addImport("backend", backend_mod);
    identity_store_mod.addImport("cbor", cbor_mod);

    // --- Group Store module ---

    const group_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/group_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    group_store_mod.addImport("backend", backend_mod);
    group_store_mod.addImport("cbor", cbor_mod);

    // --- Edge Store module ---

    const edge_store_mod = b.createModule(.{
        .root_source_file = b.path("src/store/edge_store.zig"),
        .target = target,
        .optimize = optimize,
    });
    edge_store_mod.addImport("backend", backend_mod);

    // --- Protocol module ---

    const protocol_mod = b.createModule(.{
        .root_source_file = b.path("src/proto/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Client module ---

    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/proto/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("protocol", protocol_mod);

    // --- Server module ---

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/proto/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("protocol", protocol_mod);
    server_mod.addImport("backend", backend_mod);
    server_mod.addImport("identity_store", identity_store_mod);
    server_mod.addImport("group_store", group_store_mod);
    server_mod.addImport("edge_store", edge_store_mod);
    server_mod.addImport("cbor", cbor_mod);

    // --- identityd executable ---

    const daemon_mod = b.createModule(.{
        .root_source_file = b.path("src/daemon/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    daemon_mod.addImport("lmdb_backend", lmdb_backend_mod);
    daemon_mod.addImport("server", server_mod);

    const daemon_exe = b.addExecutable(.{
        .name = "identityd",
        .root_module = daemon_mod,
    });
    b.installArtifact(daemon_exe);

    // --- idctl executable ---

    const ctl_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    ctl_mod.addImport("protocol", protocol_mod);
    ctl_mod.addImport("client", client_mod);

    const ctl_exe = b.addExecutable(.{
        .name = "idctl",
        .root_module = ctl_mod,
    });
    b.installArtifact(ctl_exe);

    // --- Tests ---

    const backend_tests = b.addTest(.{
        .name = "backend-tests",
        .root_module = backend_mod,
    });
    const run_backend_tests = b.addRunArtifact(backend_tests);

    const cbor_tests = b.addTest(.{
        .name = "cbor-tests",
        .root_module = cbor_mod,
    });
    const run_cbor_tests = b.addRunArtifact(cbor_tests);

    const lmdb_tests = b.addTest(.{
        .name = "lmdb-backend-tests",
        .root_module = lmdb_backend_mod,
    });
    const run_lmdb_tests = b.addRunArtifact(lmdb_tests);

    const identity_store_tests = b.addTest(.{
        .name = "identity-store-tests",
        .root_module = identity_store_mod,
    });
    const run_identity_store_tests = b.addRunArtifact(identity_store_tests);

    const group_store_tests = b.addTest(.{
        .name = "group-store-tests",
        .root_module = group_store_mod,
    });
    const run_group_store_tests = b.addRunArtifact(group_store_tests);

    const edge_store_tests = b.addTest(.{
        .name = "edge-store-tests",
        .root_module = edge_store_mod,
    });
    const run_edge_store_tests = b.addRunArtifact(edge_store_tests);

    const protocol_tests = b.addTest(.{
        .name = "protocol-tests",
        .root_module = protocol_mod,
    });
    const run_protocol_tests = b.addRunArtifact(protocol_tests);

    // --- Test step ---

    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_backend_tests.step);
    test_step.dependOn(&run_cbor_tests.step);
    test_step.dependOn(&run_lmdb_tests.step);
    test_step.dependOn(&run_identity_store_tests.step);
    test_step.dependOn(&run_group_store_tests.step);
    test_step.dependOn(&run_edge_store_tests.step);
    test_step.dependOn(&run_protocol_tests.step);
}

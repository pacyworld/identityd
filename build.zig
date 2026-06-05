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

    // --- Test step ---

    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_backend_tests.step);
    test_step.dependOn(&run_cbor_tests.step);
    test_step.dependOn(&run_lmdb_tests.step);
    test_step.dependOn(&run_identity_store_tests.step);
    test_step.dependOn(&run_group_store_tests.step);
}

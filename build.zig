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

    // --- LMDB backend module ---

    const lmdb_backend_mod = b.createModule(.{
        .root_source_file = b.path("src/engine/lmdb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lmdb_backend_mod.addImport("lmdb", lmdb_dep.module("lmdb"));
    lmdb_backend_mod.addImport("backend", backend_mod);

    // --- Tests ---

    const backend_tests = b.addTest(.{
        .name = "backend-tests",
        .root_module = backend_mod,
    });
    const run_backend_tests = b.addRunArtifact(backend_tests);

    const lmdb_tests = b.addTest(.{
        .name = "lmdb-backend-tests",
        .root_module = lmdb_backend_mod,
    });
    const run_lmdb_tests = b.addRunArtifact(lmdb_tests);

    // --- Test step ---

    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_backend_tests.step);
    test_step.dependOn(&run_lmdb_tests.step);
}

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Spice parallelism — can be disabled by parent builds to avoid diamond dep conflicts
    const enable_spice = b.option(bool, "spice", "Enable spice parallelism") orelse true;
    const spice_mod: ?*std.Build.Module = if (enable_spice) blk: {
        const spice_dep = b.dependency("spice", .{});
        break :blk spice_dep.module("spice");
    } else null;

    // Helper to conditionally add spice import
    const addSpice = struct {
        fn f(mod: *std.Build.Module, sm: ?*std.Build.Module) void {
            if (sm) |s| mod.addImport("spice", s);
        }
    }.f;

    // Build zlib from upstream source
    const zlib_dep = b.dependency("zlib", .{});
    const zlib_lib = b.addLibrary(.{
        .name = "z",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    // Add zlib C source files
    const zlib_sources = [_][]const u8{
        "adler32.c",
        "compress.c",
        "crc32.c",
        "deflate.c",
        "gzclose.c",
        "gzlib.c",
        "gzread.c",
        "gzwrite.c",
        "inflate.c",
        "infback.c",
        "inftrees.c",
        "inffast.c",
        "trees.c",
        "uncompr.c",
        "zutil.c",
    };

    for (zlib_sources) |src| {
        const src_path = zlib_dep.path(src);
        zlib_lib.root_module.addCSourceFile(.{
            .file = src_path,
            .flags = &[_][]const u8{
                "-DHAVE_SYS_TYPES_H",
                "-DHAVE_STDINT_H",
                "-DHAVE_STDDEF_H",
                "-DZ_HAVE_UNISTD_H",
                "-fno-sanitize=undefined",
            },
        });
    }

    zlib_lib.root_module.link_libc = true;
    zlib_lib.installHeadersDirectory(
        zlib_dep.path("."),
        ".",
        .{ .include_extensions = &[_][]const u8{ ".h" } },
    );

    // Server module (for internal use and library export)
    const server_mod = b.addModule("grpc-server", .{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSpice(server_mod, spice_mod);
    server_mod.linkLibrary(zlib_lib);

    // Client module (for internal use and library export)
    const client_mod = b.addModule("grpc-client", .{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSpice(client_mod, spice_mod);
    client_mod.linkLibrary(zlib_lib);

    // Benchmark executable
    const benchmark = b.addExecutable(.{
        .name = "grpc-benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/benchmark.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    addSpice(benchmark.root_module, spice_mod);
    benchmark.root_module.linkLibrary(zlib_lib);
    b.installArtifact(benchmark);

    // Benchmark step with automatic server management
    const benchmark_step = b.step("benchmark", "Run benchmarks (starts server automatically)");

    // Create a system command to run server in background, benchmark, then cleanup
    const benchmark_cmd = b.addSystemCommand(&[_][]const u8{
        "sh",
        "-c",
        "trap 'kill $SERVER_PID 2>/dev/null' EXIT; " ++
        "./zig-out/bin/grpc-server-example & SERVER_PID=$!; " ++
        "sleep 2; " ++
        "./zig-out/bin/grpc-benchmark --host localhost --port 50051 --requests 10 --clients 1 --size 512 --output text; " ++
        "kill $SERVER_PID 2>/dev/null || true",
    });
    benchmark_cmd.step.dependOn(b.getInstallStep());
    benchmark_step.dependOn(&benchmark_cmd.step);

    // Also keep the standalone benchmark executable for manual testing
    const run_benchmark_manual = b.addRunArtifact(benchmark);
    run_benchmark_manual.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_benchmark_manual.addArgs(args);
    }
    const benchmark_manual_step = b.step("benchmark-manual", "Run benchmark manually (requires server running)");
    benchmark_manual_step.dependOn(&run_benchmark_manual.step);

    // Example executables
    const server_example = b.addExecutable(.{
        .name = "grpc-server-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_server.zig"),
            .target = target,
            .optimize = optimize,

        }),
    });
    addSpice(server_example.root_module, spice_mod);
    server_example.root_module.addImport("grpc", server_mod);
    server_example.root_module.linkLibrary(zlib_lib);
    b.installArtifact(server_example);

    const client_example = b.addExecutable(.{
        .name = "grpc-client-example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_client.zig"),
            .target = target,
            .optimize = optimize,

        }),
    });
    addSpice(client_example.root_module, spice_mod);
    client_example.root_module.addImport("grpcclient", client_mod);
    client_example.root_module.linkLibrary(zlib_lib);
    b.installArtifact(client_example);

    // Tests
    const tests = b.addTest(.{
        .name = "tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    addSpice(tests.root_module, spice_mod);
    tests.root_module.linkLibrary(zlib_lib);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    // Integration test server
    const integration_test_mod = b.createModule(.{
        .root_source_file = b.path("integration_test/proto.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSpice(integration_test_mod, spice_mod);

    const integration_test_server = b.addExecutable(.{
        .name = "grpc-test-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("integration_test/test_server.zig"),
            .target = target,
            .optimize = optimize,

        }),
    });
    addSpice(integration_test_server.root_module, spice_mod);
    integration_test_server.root_module.addImport("grpc", server_mod);
    integration_test_server.root_module.addImport("proto", integration_test_mod);
    integration_test_server.root_module.linkLibrary(zlib_lib);

    const install_integration_test = b.addInstallArtifact(integration_test_server, .{});
    const integration_test_step = b.step("integration_test", "Build integration test server");
    integration_test_step.dependOn(&install_integration_test.step);
}

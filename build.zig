const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
        .{ .include_extensions = &[_][]const u8{".h"} },
    );

    // Server module (for internal use and library export)
    const server_mod = b.addModule("grpc-server", .{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.linkLibrary(zlib_lib);

    // Client module (for internal use and library export)
    const client_mod = b.addModule("grpc-client", .{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });
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
    tests.root_module.linkLibrary(zlib_lib);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    // Endstream wire-bytes tests for `Transport.endStreamWithStatus`.
    // Lives in its own file so we can drive it without bringing in zlib /
    // protobuf — the helper is pure HPACK + frame header generation.
    const endstream_tests = b.addTest(.{
        .name = "transport-endstream-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transport_endstream_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    endstream_tests.root_module.linkLibrary(zlib_lib);
    const run_endstream_tests = b.addRunArtifact(endstream_tests);
    test_step.dependOn(&run_endstream_tests.step);

    // JWT/Auth tests for `features/auth.zig`.
    const auth_tests = b.addTest(.{
        .name = "auth-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/auth_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    auth_tests.root_module.linkLibrary(zlib_lib);
    const run_auth_tests = b.addRunArtifact(auth_tests);
    test_step.dependOn(&run_auth_tests.step);

    // `check` step: compile everything (lib modules + test binary) without
    // running the tests. CI uses this for fast type/compile checks separate
    // from the full test execution.
    const check_step = b.step("check", "Compile lib + tests without running");
    check_step.dependOn(&tests.step);
    check_step.dependOn(&endstream_tests.step);
    check_step.dependOn(&auth_tests.step);

    // Integration test server
    const integration_test_mod = b.createModule(.{
        .root_source_file = b.path("integration_test/proto.zig"),
        .target = target,
        .optimize = optimize,
    });
    const integration_test_server = b.addExecutable(.{
        .name = "grpc-test-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("integration_test/test_server.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    integration_test_server.root_module.addImport("grpc", server_mod);
    integration_test_server.root_module.addImport("proto", integration_test_mod);
    integration_test_server.root_module.linkLibrary(zlib_lib);

    const install_integration_test = b.addInstallArtifact(integration_test_server, .{});
    const integration_test_step = b.step("integration_test", "Build integration test server");
    integration_test_step.dependOn(&install_integration_test.step);

    // In-process loopback smoke test (server + client in same process).
    // Run with a process-level timeout to catch deadlocks:
    //   `timeout 10 ./zig-out/bin/grpc-loopback-test`
    //
    // Imports server.zig and client.zig via relative paths so they live in a
    // single compile-unit (avoids the "file in two modules" error that occurs
    // when both grpc and grpcclient modules are imported together).
    const loopback_test = b.addExecutable(.{
        .name = "grpc-loopback-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/loopback_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    loopback_test.root_module.linkLibrary(zlib_lib);

    const install_loopback_test = b.addInstallArtifact(loopback_test, .{});
    const loopback_test_step = b.step("loopback-test", "Build the in-process loopback smoke test");
    loopback_test_step.dependOn(&install_loopback_test.step);

    // Path-based handler dispatch test (closes GAP-0003 / #4). Two
    // handlers registered with distinct names; the test verifies each is
    // routed correctly by `:path` and that an unregistered path returns a
    // gRPC trailer with status 12 (UNIMPLEMENTED).
    const dispatch_test = b.addExecutable(.{
        .name = "grpc-dispatch-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dispatch_test_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    dispatch_test.root_module.linkLibrary(zlib_lib);
    const install_dispatch_test = b.addInstallArtifact(dispatch_test, .{});
    const dispatch_test_step = b.step("dispatch-test", "Build the path-based dispatch test");
    dispatch_test_step.dependOn(&install_dispatch_test.step);

    // Interop wire-codec unit tests.
    const interop_codec_tests = b.addTest(.{
        .name = "interop-codec-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interop/zig/harness_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_interop_codec_tests = b.addRunArtifact(interop_codec_tests);
    const interop_codec_test_step = b.step("interop-codec-test", "Run the interop wire-codec unit tests");
    interop_codec_test_step.dependOn(&run_interop_codec_tests.step);

    // Failing reproduction test for the client request HEADERS bug.
    // See src/transport_request_headers_test.zig — this asserts that
    // `transport.writeRequestHeaders` emits request-shaped HPACK bytes
    // (`:method POST` / `:scheme http` / `:path` / `:authority` / etc.)
    // instead of the response-shaped HEADERS the buggy `writeMessage`
    // path currently produces.
    const request_headers_tests = b.addTest(.{
        .name = "request-headers-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transport_request_headers_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    request_headers_tests.root_module.linkLibrary(zlib_lib);
    const run_request_headers_tests = b.addRunArtifact(request_headers_tests);
    const request_headers_test_step = b.step("request-headers-test", "Run the client request-HEADERS reproduction test");
    request_headers_test_step.dependOn(&run_request_headers_tests.step);

    // Zig interop server: uses a named import for grpc-server so src/ files
    // are reachable from interop/zig/ without escaping the module boundary.
    // Transport is accessed via grpc_server.Transport (re-exported by server.zig).
    const interop_server = b.addExecutable(.{
        .name = "grpc-interop-zig-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interop/zig/server_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    interop_server.root_module.linkLibrary(zlib_lib);
    interop_server.root_module.addImport("grpc-server", server_mod);
    const install_interop_server = b.addInstallArtifact(interop_server, .{});
    const interop_server_step = b.step("interop-server", "Build the Zig interop server binary");
    interop_server_step.dependOn(&install_interop_server.step);

    const interop_client = b.addExecutable(.{
        .name = "grpc-interop-zig-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interop/zig/client_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    interop_client.root_module.linkLibrary(zlib_lib);
    interop_client.root_module.addImport("grpc-client", client_mod);
    const install_interop_client = b.addInstallArtifact(interop_client, .{});
    const interop_client_step = b.step("interop-client", "Build the Zig interop client binary");
    interop_client_step.dependOn(&install_interop_client.step);
}

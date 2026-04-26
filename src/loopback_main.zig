//! In-process loopback coverage for the gRPC-zig HTTP/2 stack. Spawns a
//! `GrpcServer` on a thread and drives it with `GrpcClient` from the main
//! thread (and worker threads, for the concurrent-connections scenario).
//!
//! Scenarios:
//!   1. Sequential single-call round-trips (smoke test).
//!   2. Large payload (256 KB request, byte-perfect echo).
//!   3. Compression in loopback (.gzip, .deflate) with a passthrough handler
//!      so client-side compress/decompress round-trips through unchanged
//!      server bytes.
//!   4. Server streaming (handler emits N messages then endStream; client
//!      reads them all via streamCall).
//!   5. Concurrent connections (N client threads, each with its own
//!      GrpcClient/connection, all calling at once).
//!   6. Concurrent in-flight calls on ONE connection via `ClientMux`
//!      (per-call stream id, reader thread demultiplexes responses,
//!      multi-frame writes serialized by the transport's write_mutex).
//!
//! Run via `zig build loopback-test && timeout 30 ./zig-out/bin/grpc-loopback-test`.

const std = @import("std");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const client_mux_mod = @import("client_mux.zig");

const GrpcServer = server_mod.GrpcServer;
const GrpcClient = client_mod.GrpcClient;
const ClientMux = client_mux_mod.ClientMux;

const PORT: u16 = 50100;
const STREAM_PREFIX = "STREAM:";

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

const ServerArgs = struct { server: *GrpcServer };

fn serverThread(args: ServerArgs) void {
    args.server.start() catch |err| {
        std.log.err("server crashed: {}", .{err});
    };
}

/// Single dispatcher handler: passthrough echoes the request bytes verbatim,
/// except when the request begins with STREAM_PREFIX, in which case the
/// remainder is parsed as the streaming chunk count and the handler emits
/// `count` messages then ends the stream.
fn dispatchHandler(
    request: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    _: std.mem.Allocator,
) anyerror!void {
    if (request.len >= STREAM_PREFIX.len and std.mem.eql(u8, request[0..STREAM_PREFIX.len], STREAM_PREFIX)) {
        const tail = request[STREAM_PREFIX.len..];
        const count = std.fmt.parseInt(u32, tail, 10) catch 3;

        var i: u32 = 0;
        while (i < count) : (i += 1) {
            var buf: [32]u8 = undefined;
            const msg = try std.fmt.bufPrint(&buf, "frame-{d}", .{i});
            try trans.writeStreamMessage(msg, i == 0);
        }
        try trans.endStream();
        return;
    }

    // Passthrough: echo the request bytes back verbatim. Lets us test large
    // payloads and end-to-end compression without the handler interpreting
    // the bytes.
    try trans.writeMessage(request);
}

fn scenarioSequential(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[1/6] sequential calls", .{});
    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT);
    defer client.deinit();

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        var buf: [16]u8 = undefined;
        const req = std.fmt.bufPrint(&buf, "ping{d}", .{i}) catch unreachable;
        const resp = try client.call("/Echo", req, .none);
        defer allocator.free(resp);
        if (!std.mem.eql(u8, resp, req)) fatal("seq[{d}]: got '{s}' want '{s}'", .{ i, resp, req });
    }
    std.log.info("    ok ({d} calls)", .{i});
}

fn scenarioLargePayload(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[2/6] large payload (256 KB)", .{});
    const size: usize = 256 * 1024;
    const req = try allocator.alloc(u8, size);
    defer allocator.free(req);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    prng.random().bytes(req);

    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT);
    defer client.deinit();

    const resp = try client.call("/Passthrough", req, .none);
    defer allocator.free(resp);

    if (!std.mem.eql(u8, resp, req)) fatal("large: round-trip differs (sent {d}, got {d})", .{ req.len, resp.len });
    std.log.info("    ok ({d} bytes round-trip)", .{resp.len});
}

fn scenarioCompression(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[3/6] compression in loopback (gzip, deflate)", .{});

    const algorithms = [_]compression.Compression.Algorithm{ .gzip, .deflate };
    for (algorithms) |alg| {
        // Use a payload long and repetitive enough that compression actually
        // does something — exercises the codec in both directions.
        const original = "the quick brown fox jumps over the lazy dog. " ** 64;

        var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT);
        defer client.deinit();

        const resp = try client.call("/Passthrough", original, alg);
        defer allocator.free(resp);

        if (!std.mem.eql(u8, resp, original)) {
            fatal("compression {s}: round-trip differs", .{@tagName(alg)});
        }
        std.log.info("    ok ({s})", .{@tagName(alg)});
    }
}

fn scenarioServerStreaming(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[4/6] server streaming (3 messages)", .{});
    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT);
    defer client.deinit();

    var frames: std.ArrayList([]u8) = .empty;
    defer {
        for (frames.items) |f| allocator.free(f);
        frames.deinit(allocator);
    }

    try client.streamCall("/Stream", STREAM_PREFIX ++ "3", .none, &frames);

    if (frames.items.len != 3) fatal("stream: got {d} frames want 3", .{frames.items.len});
    const expected = [_][]const u8{ "frame-0", "frame-1", "frame-2" };
    for (frames.items, 0..) |f, i| {
        if (!std.mem.eql(u8, f, expected[i])) fatal("stream[{d}]: got '{s}' want '{s}'", .{ i, f, expected[i] });
    }
    std.log.info("    ok ({d} streamed messages)", .{frames.items.len});
}

const ConcurrentArgs = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    id: u32,
    err: ?anyerror,
};

fn concurrentClientThread(args: *ConcurrentArgs) void {
    args.err = null;
    runConcurrentClient(args) catch |err| {
        args.err = err;
    };
}

fn runConcurrentClient(args: *ConcurrentArgs) !void {
    var client = try GrpcClient.init(args.allocator, args.io, "127.0.0.1", PORT);
    defer client.deinit();

    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        var buf: [32]u8 = undefined;
        const req = std.fmt.bufPrint(&buf, "c{d}-r{d}", .{ args.id, i }) catch unreachable;
        const resp = try client.call("/Echo", req, .none);
        defer args.allocator.free(resp);
        if (!std.mem.eql(u8, resp, req)) return error.RoundTripMismatch;
    }
}

fn scenarioConcurrentConnections(allocator: std.mem.Allocator, io: std.Io) !void {
    const N: u32 = 4;
    std.log.info("[5/6] concurrent connections (N={d}, each 4 calls)", .{N});

    var args_list: [N]ConcurrentArgs = undefined;
    var threads: [N]std.Thread = undefined;

    for (0..N) |i| {
        args_list[i] = .{ .allocator = allocator, .io = io, .id = @intCast(i), .err = null };
        threads[i] = try std.Thread.spawn(.{}, concurrentClientThread, .{&args_list[i]});
    }
    for (0..N) |i| threads[i].join();

    var any_err: ?anyerror = null;
    for (args_list) |a| if (a.err) |e| {
        any_err = e;
        std.log.err("concurrent client {d}: {}", .{ a.id, e });
    };
    if (any_err) |e| return e;
    std.log.info("    ok (N={d}, total {d} calls across {d} connections)", .{ N, N * 4, N });
}

const MuxArgs = struct {
    mux: *ClientMux,
    allocator: std.mem.Allocator,
    id: u32,
    err: ?anyerror = null,
};

fn muxClientThread(args: *MuxArgs) void {
    runMuxClient(args) catch |err| {
        args.err = err;
    };
}

fn runMuxClient(args: *MuxArgs) !void {
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        var buf: [32]u8 = undefined;
        const req = std.fmt.bufPrint(&buf, "mux-c{d}-r{d}", .{ args.id, i }) catch unreachable;
        const resp = try args.mux.call("/loopback.Mux/Echo", req, .none);
        defer args.allocator.free(resp);
        if (!std.mem.eql(u8, resp, req)) return error.RoundTripMismatch;
    }
}

fn scenarioConcurrentInFlight(allocator: std.mem.Allocator, io: std.Io) !void {
    const N: u32 = 8;
    std.log.info("[6/6] concurrent in-flight on ONE connection (N={d}, each 16 calls)", .{N});

    const mux = try ClientMux.init(allocator, io, "127.0.0.1", PORT);
    defer mux.deinit();

    var args_list: [N]MuxArgs = undefined;
    var threads: [N]std.Thread = undefined;

    for (0..N) |i| {
        args_list[i] = .{ .mux = mux, .allocator = allocator, .id = @intCast(i) };
        threads[i] = try std.Thread.spawn(.{}, muxClientThread, .{&args_list[i]});
    }
    for (0..N) |i| threads[i].join();

    var any_err: ?anyerror = null;
    for (args_list) |a| if (a.err) |e| {
        any_err = e;
        std.log.err("mux client {d}: {}", .{ a.id, e });
    };
    if (any_err) |e| return e;
    std.log.info("    ok (N={d}, total {d} calls multiplexed on 1 connection)", .{ N, N * 16 });
}

pub fn main(init: std.process.Init) !void {
    // The server thread is detached and runs `accept()` forever, so we cannot
    // join it cleanly before tearing down the allocator. Use the C allocator
    // (no leak detection) to avoid a teardown race; allocator hygiene is
    // covered by `zig build test`.
    const allocator = std.heap.c_allocator;
    const io = init.io;

    std.log.info("starting loopback server on 127.0.0.1:{d}", .{PORT});

    var server = try GrpcServer.init(allocator, io, PORT, "loopback-key");
    defer server.deinit();

    try server.handlers.append(allocator, .{ .name = "Dispatch", .handler_fn = dispatchHandler });

    const thread = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = &server }});
    thread.detach();

    // Give the server thread time to bind / listen / accept.
    try io.sleep(.fromMilliseconds(100), .awake);

    try scenarioSequential(allocator, io);
    try scenarioLargePayload(allocator, io);
    try scenarioCompression(allocator, io);
    try scenarioServerStreaming(allocator, io);
    try scenarioConcurrentConnections(allocator, io);
    try scenarioConcurrentInFlight(allocator, io);

    std.log.info("ALL SCENARIOS PASSED", .{});

    // Detached server thread never returns; exit explicitly to avoid getting
    // torn down mid-flight by main's implicit cleanup.
    std.process.exit(0);
}

// Multi-stream multiplexing on one connection (scenario 6) lands via
// `client_mux.zig`. The single-call `GrpcClient.call` path remains for
// clients that don't need it.

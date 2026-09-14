//! SONNY-1560 regression coverage for the per-connection reader thread.
//!
//! Before the fix, `GrpcServer.handleConnection` ran the HTTP/2 read loop on
//! the SAME thread as the handler. While a handler wrote a response nobody
//! drained the socket, so the peer's WINDOW_UPDATE frames were never
//! processed: once the peer's 1 MiB initial send window was consumed, the
//! writer parked in `Transport.reserveSendCredit` until
//! `flow_credit_timeout_ns` (30 s by default) expired. Geode saw this as a
//! ~5632-row (~1 MiB) push followed by a 30 s stall.
//!
//! Scenarios (each FAILs loudly and exits non-zero):
//!
//!   1. RED-before-fix: a server-streaming handler writes 4x the peer's
//!      initial window (4 MiB) to an in-process `GrpcClient` that credits
//!      normally. It must COMPLETE well inside `flow_credit_timeout_ns`
//!      (bound: 10 s against the default 30 s timeout). Pre-fix this stalls
//!      for a full 30 s per window and the client sees a truncated stream.
//!
//!   2. A raw client that never credits the STALLED stream makes the
//!      handler's write fail with the credit timeout (grpc-status 2 /
//!      "FlowControlTimeout" trailer + RST_STREAM(FLOW_CONTROL_ERROR)),
//!      while the connection stays alive: a PING sent mid-stall is ACKed by
//!      the reader thread BEFORE the stalled stream closes (impossible
//!      pre-fix — the single thread was parked in the writer), and a
//!      request opened on a second stream during the stall is still served.
//!
//!   3. A client that disappears mid-response tears the connection down
//!      deterministically. The server under test is capped at ONE concurrent
//!      connection (`conn_sem.permits = 1`), and that permit is only posted
//!      when `connectionThread` returns — which cannot happen until
//!      `handleConnection` has JOINED the reader thread. A second connection
//!      being accepted and served afterwards therefore proves the reader
//!      exited and no thread was leaked.
//!
//! Run: `zig build test-flow-control-reader` (builds AND runs), or
//! `timeout 120 ./zig-out/bin/grpc-flow-control-reader-test`.

const std = @import("std");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const transport = @import("transport.zig");
const net = std.Io.net;
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

const GrpcServer = server_mod.GrpcServer;
const GrpcClient = client_mod.GrpcClient;

/// Server A: default (30 s) credit timeout — scenario 1.
const PORT_A: u16 = 50611;
/// Server B: short (2 s) credit timeout — scenario 2.
const PORT_B: u16 = 50612;
/// Server C: one connection permit — scenario 3.
const PORT_C: u16 = 50613;

/// Peer initial window advertised by our own client SETTINGS.
const WINDOW: usize = @intCast(transport.ADVERTISED_INITIAL_WINDOW_SIZE);
const CHUNK_BYTES: usize = 64 * 1024;
/// 4x the initial window.
const CHUNKS: usize = (4 * WINDOW) / CHUNK_BYTES;

const SHORT_TIMEOUT_NS: u64 = 2 * std.time.ns_per_s;

/// Milliseconds on the `awake` clock. Zig 0.16 has no `std.time.milliTimestamp`;
/// clock reads go through `std.Io`.
fn nowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err("FAIL: " ++ fmt, args);
    std.process.exit(1);
}

// ---------------------------------------------------------------- handlers

fn bigStreamHandler(
    _: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    allocator: std.mem.Allocator,
) anyerror!void {
    const chunk = try allocator.alloc(u8, CHUNK_BYTES);
    defer allocator.free(chunk);
    @memset(chunk, 'x');
    var i: usize = 0;
    while (i < CHUNKS) : (i += 1) {
        try trans.writeStreamMessage(chunk, i == 0);
    }
    try trans.endStream();
}

fn echoHandler(
    request: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    _: std.mem.Allocator,
) anyerror!void {
    try trans.writeMessage(request);
}

const ServerArgs = struct { server: *GrpcServer };

fn serverThread(args: ServerArgs) void {
    args.server.start() catch |err| {
        std.log.err("server crashed: {}", .{err});
    };
}

fn registerHandlers(allocator: std.mem.Allocator, server: *GrpcServer) !void {
    try server.handlers.append(allocator, .{ .name = "/Big", .handler_fn = bigStreamHandler });
    try server.handlers.append(allocator, .{ .name = "/Echo", .handler_fn = echoHandler });
}

/// Hard bound on the whole run so a regression HANGS the test into a
/// failure instead of into a wedged CI job.
fn watchdog(io: std.Io) void {
    io.sleep(.fromSeconds(120), .awake) catch return;
    std.log.err("FAIL: watchdog fired — the test did not finish in 120 s", .{});
    std.process.exit(1);
}

// ------------------------------------------------------------- scenario 1

fn scenarioCreditedStreamCompletes(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[1/3] {d} x {d} B ({d} MiB = 4x initial window) to a crediting client", .{
        CHUNKS,
        CHUNK_BYTES,
        (CHUNKS * CHUNK_BYTES) / (1024 * 1024),
    });

    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT_A);
    defer client.deinit();

    var frames: std.ArrayList([]u8) = .empty;
    defer {
        for (frames.items) |f| allocator.free(f);
        frames.deinit(allocator);
    }

    const started = nowMs(io);
    try client.streamCall("/Big", "go", .none, &frames);
    const elapsed_ms = nowMs(io) - started;

    if (frames.items.len != CHUNKS) {
        fail("streamed {d} messages, want {d}", .{ frames.items.len, CHUNKS });
    }
    for (frames.items, 0..) |f, i| {
        if (f.len != CHUNK_BYTES) fail("message {d} is {d} B, want {d}", .{ i, f.len, CHUNK_BYTES });
    }
    // The server's flow_credit_timeout_ns here is the 30 s default; "well
    // under" it is the whole point of the fix.
    if (elapsed_ms >= 10_000) {
        fail("4 MiB stream took {d} ms — credit is not being processed during the response", .{elapsed_ms});
    }
    std.log.info("    ok ({d} messages, {d} ms)", .{ frames.items.len, elapsed_ms });
}

// ------------------------------------------------------------- scenario 2

/// Emit a WINDOW_UPDATE for `stream_id` with `increment` octets.
fn sendWindowUpdate(t: *transport.Transport, stream_id: u31, increment: u32) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment & 0x7FFF_FFFF, .big);
    try t.writeFrame(.WINDOW_UPDATE, 0, stream_id, &payload);
}

fn scenarioStalledStreamDoesNotWedgeConnection(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[2/3] stalled stream times out; connection keeps serving", .{});

    const address = try net.IpAddress.parseIp4("127.0.0.1", PORT_B);
    const conn = try address.connect(io, .{ .mode = .stream });
    transport.setRpcSocketOptions(conn.socket.handle);
    var t = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
    defer t.deinit();

    const FT = http2.frame.FrameType;
    const FF = http2.frame.FrameFlags;

    // Stream 1: the stall. We deliberately never credit THIS stream's
    // receive window, so the server's writer runs out of send credit.
    const stall_sid: u31 = try t.nextClientStreamId();
    try t.writeRequestOnStream(stall_sid, "go", "/Big");

    const echo_sid: u31 = try t.nextClientStreamId();

    var data_seen: usize = 0;
    var ping_sent = false;
    var ping_acked = false;
    var echo_sent = false;
    var stall_closed = false;
    var saw_rst = false;
    var saw_timeout_trailer = false;
    var echo_payload_bytes: usize = 0;
    var echo_closed = false;
    var ping_ack_before_stall_close = false;

    const started = nowMs(io);
    while (!echo_closed) {
        const frame = try t.readFrame();
        defer allocator.free(frame.payload);

        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                if (frame.stream_id == stall_sid) {
                    data_seen += frame.payload.len;
                    // Mid-stall: prove the reader thread is still alive by
                    // demanding a PING ACK, open a second stream, and credit
                    // the CONNECTION window (never the stalled stream's) so
                    // the second stream can actually be answered.
                    if (!ping_sent and data_seen >= WINDOW / 2) {
                        const ping_payload = [_]u8{ 'S', 'O', 'N', 'N', 'Y', '1', '5', '6' };
                        try t.writeFrame(.PING, 0, 0, &ping_payload);
                        ping_sent = true;
                        try sendWindowUpdate(&t, 0, 4 * @as(u32, @intCast(WINDOW)));
                        try t.writeRequestOnStream(echo_sid, "hello", "/Echo");
                        echo_sent = true;
                    }
                } else if (frame.stream_id == echo_sid) {
                    echo_payload_bytes += frame.payload.len;
                }
            },
            @intFromEnum(FT.PING) => {
                if ((frame.flags & 0x1) != 0) {
                    ping_acked = true;
                    if (!stall_closed) ping_ack_before_stall_close = true;
                }
            },
            @intFromEnum(FT.HEADERS) => {
                if (std.mem.indexOf(u8, frame.payload, "FlowControlTimeout") != null) {
                    saw_timeout_trailer = true;
                }
                if ((frame.flags & FF.END_STREAM) != 0) {
                    if (frame.stream_id == stall_sid) stall_closed = true;
                    if (frame.stream_id == echo_sid) echo_closed = true;
                }
            },
            @intFromEnum(FT.RST_STREAM) => {
                if (frame.stream_id == stall_sid) {
                    saw_rst = true;
                    stall_closed = true;
                }
            },
            @intFromEnum(FT.SETTINGS) => {
                if ((frame.flags & 0x1) == 0) {
                    t.applyPeerSettings(frame.payload);
                    try t.writeFrame(.SETTINGS, 0x1, 0, &.{});
                }
            },
            @intFromEnum(FT.WINDOW_UPDATE) => t.processWindowUpdate(frame.stream_id, frame.payload),
            @intFromEnum(FT.GOAWAY) => fail("server sent GOAWAY; connection was torn down", .{}),
            else => {},
        }
    }
    const elapsed_ms = nowMs(io) - started;

    if (!echo_sent) fail("never reached the mid-stall checkpoint (saw {d} B)", .{data_seen});
    if (!ping_acked) fail("no PING ACK — the reader thread is not draining during a handler write", .{});
    if (!ping_ack_before_stall_close) {
        fail("PING was only ACKed after the stalled stream closed — reader is still behind the writer", .{});
    }
    if (!stall_closed) fail("stalled stream never closed", .{});
    if (!saw_rst and !saw_timeout_trailer) {
        fail("stalled stream closed without RST_STREAM or a FlowControlTimeout trailer", .{});
    }
    if (echo_payload_bytes == 0) fail("second stream got no response payload — connection was wedged", .{});
    std.log.info(
        "    ok (stalled after {d} B, PING ACK mid-stall, second stream served, {d} ms)",
        .{ data_seen, elapsed_ms },
    );
}

// ------------------------------------------------------------- scenario 3

fn scenarioReaderExitsOnClientClose(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[3/3] client disappears mid-response; reader thread is joined", .{});

    {
        const address = try net.IpAddress.parseIp4("127.0.0.1", PORT_C);
        const conn = try address.connect(io, .{ .mode = .stream });
        transport.setRpcSocketOptions(conn.socket.handle);
        var t = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
        // NOTE: deliberately no `defer` — we close mid-response, below.
        const sid: u31 = try t.nextClientStreamId();
        try t.writeRequestOnStream(sid, "go", "/Big");

        // Read a little of the response, then vanish.
        var got: usize = 0;
        while (got < CHUNK_BYTES) {
            const frame = try t.readFrame();
            defer allocator.free(frame.payload);
            if (frame.frame_type == @intFromEnum(http2.frame.FrameType.DATA)) got += frame.payload.len;
        }
        t.deinit();
    }

    // Server C has exactly ONE connection permit. It is posted only when
    // `connectionThread` returns, and `handleConnection` cannot return
    // without joining its reader thread — so being served here proves the
    // reader exited and nothing leaked.
    const started = nowMs(io);
    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT_C);
    defer client.deinit();
    const resp = try client.call("/Echo", "after-abrupt-close", .none);
    defer allocator.free(resp);
    const elapsed_ms = nowMs(io) - started;

    if (!std.mem.eql(u8, resp, "after-abrupt-close")) {
        fail("second connection echoed '{s}'", .{resp});
    }
    if (elapsed_ms >= 30_000) {
        fail("second connection waited {d} ms for the admission permit", .{elapsed_ms});
    }
    std.log.info("    ok (permit returned, new connection served in {d} ms)", .{elapsed_ms});
}

// ------------------------------------------------------------------- main

pub fn main(init: std.process.Init) !void {
    // The accept loops run on detached threads that never return, so use the
    // C allocator here (no leak detection at teardown); allocator hygiene is
    // covered by `zig build test`.
    const allocator = std.heap.c_allocator;
    const io = init.io;

    const wd = try std.Thread.spawn(.{}, watchdog, .{io});
    wd.detach();

    var server_a = try GrpcServer.init(allocator, io, PORT_A, "flow-reader-key");
    defer server_a.deinit();
    try registerHandlers(allocator, &server_a);

    var server_b = try GrpcServer.init(allocator, io, PORT_B, "flow-reader-key");
    defer server_b.deinit();
    try registerHandlers(allocator, &server_b);
    server_b.flow_credit_timeout_ns = SHORT_TIMEOUT_NS;

    var server_c = try GrpcServer.init(allocator, io, PORT_C, "flow-reader-key");
    defer server_c.deinit();
    try registerHandlers(allocator, &server_c);
    // One connection at a time — see scenario 3.
    server_c.conn_sem = .{ .permits = 1 };

    inline for (.{ &server_a, &server_b, &server_c }) |srv| {
        const th = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = srv }});
        th.detach();
    }
    try io.sleep(.fromMilliseconds(150), .awake);

    try scenarioCreditedStreamCompletes(allocator, io);
    try scenarioStalledStreamDoesNotWedgeConnection(allocator, io);
    try scenarioReaderExitsOnClientClose(allocator, io);

    std.log.info("FLOW-CONTROL READER TEST PASSED", .{});
    std.process.exit(0);
}

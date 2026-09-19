//! SONNY-1838 regression coverage: an inbound RST_STREAM is a STREAM error,
//! not a connection teardown (HTTP/2 §5.4.2).
//!
//! Before the fix, `GrpcServer`'s per-connection reader treated RST_STREAM
//! exactly like GOAWAY: it returned `TransportError.ConnectionClosed`, which
//! made `connectionReader` call `markPeerGone` (releasing EVERY writer parked
//! in `reserveSendCredit` with `error.PeerGone`) and close the request queue.
//! So one stream's RST tore down the whole connection reader and dropped
//! every other in-flight / queued RPC sharing that TCP connection.
//!
//! After the fix the reader RESETS ONLY THE NAMED STREAM (its parked handler
//! is released with the stream-scoped `error.StreamReset`) and KEEPS READING,
//! so sibling RPCs on the same connection survive. GOAWAY / real connection
//! loss still trip `markPeerGone`.
//!
//! Scenario (FAILs loudly and exits non-zero on regression):
//!
//!   Stream A opens `/Big` and is deliberately never credited, so its handler
//!   parks in `reserveSendCredit`. A sibling request B (`/Echo`) is pipelined
//!   on the SAME connection, the CONNECTION window is credited so B can be
//!   answered, and then the client sends RST_STREAM(CANCEL) for stream A.
//!   Assertions:
//!     * stream A's handler unwinds with EXACTLY `error.StreamReset` — its
//!       own RPC was failed, promptly and stream-scoped;
//!     * sibling stream B's `/Echo` RPC still completes with grpc-status 0
//!       and its payload — the connection was NOT torn down;
//!     * the server never sends GOAWAY.
//!
//!   Pre-fix, RST(A) tears the connection down: A unwinds via `error.PeerGone`
//!   (not `StreamReset`), the queue is closed so B is never served, and the
//!   socket is closed under the client (its next `readFrame` errors). Any of
//!   those makes this test exit non-zero.
//!
//! Run: `zig build test-rst-stream-isolation` (builds AND runs), or
//! `timeout 60 ./zig-out/bin/grpc-rst-stream-isolation-test`.

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

const PORT: u16 = 50616;

/// Peer initial window advertised by our own client SETTINGS.
const WINDOW: usize = @intCast(transport.ADVERTISED_INITIAL_WINDOW_SIZE);
const CHUNK_BYTES: usize = 64 * 1024;
/// 4x the initial window — well past what one window can deliver, so the
/// handler is guaranteed to run out of send credit and park.
const CHUNKS: usize = (4 * WINDOW) / CHUNK_BYTES;

/// Wire size of one `/Big` message (5-byte gRPC prefix + payload); the whole
/// amount is charged to `reserveSendCredit` per `writeStreamMessage`.
const GRPC_FRAME_LEN: usize = 5 + CHUNK_BYTES;

/// Greatest number of response bytes the client can observe before the
/// server's NEXT `reserveSendCredit` call MUST park (see the flow-control
/// reader test for the arithmetic). Reading this many guarantees stream A's
/// handler is parked, not merely about to park, when we send its RST.
const DELIVERABLE_BEFORE_PARK: usize = (WINDOW / GRPC_FRAME_LEN) * GRPC_FRAME_LEN;

/// HTTP/2 RST_STREAM error code CANCEL (§7).
const HTTP2_CANCEL: u32 = 0x8;

/// `@intFromError` of stream A's handler outcome, published when the handler
/// returns. 0 is "unset" (Zig error values are never 0), so the scenario can
/// assert the handler actually unwound via `error.StreamReset`.
var big_handler_result: std.atomic.Value(u16) = .init(0);

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

/// Records stream A's terminal error so the scenario can assert it is
/// exactly `error.StreamReset`.
fn bigStreamHandlerRecordErr(
    request: []const u8,
    path: []const u8,
    trans: *transport.Transport,
    allocator: std.mem.Allocator,
) anyerror!void {
    bigStreamHandler(request, path, trans, allocator) catch |err| {
        big_handler_result.store(@intFromError(err), .release);
        return err;
    };
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

/// Hard bound: a regression that wedges (rather than exits) still fails.
fn watchdog(io: std.Io) void {
    io.sleep(.fromSeconds(60), .awake) catch return;
    std.log.err("FAIL: watchdog fired — the test did not finish in 60 s", .{});
    std.process.exit(1);
}

/// Emit a WINDOW_UPDATE for `stream_id` with `increment` octets.
fn sendWindowUpdate(t: *transport.Transport, stream_id: u31, increment: u32) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment & 0x7FFF_FFFF, .big);
    try t.writeFrame(.WINDOW_UPDATE, 0, stream_id, &payload);
}

/// Emit an RST_STREAM for `stream_id` with `error_code`.
fn sendRstStream(t: *transport.Transport, stream_id: u31, error_code: u32) !void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, error_code, .big);
    try t.writeFrame(.RST_STREAM, 0, stream_id, &payload);
}

fn scenarioRstIsolatesStream(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[1/1] RST_STREAM on one stream fails only that stream; sibling survives", .{});
    big_handler_result.store(0, .release);

    const address = try net.IpAddress.parseIp4("127.0.0.1", PORT);
    const conn = try address.connect(io, .{ .mode = .stream });
    transport.setRpcSocketOptions(conn.socket.handle);
    var t = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
    defer t.deinit();

    const FT = http2.frame.FrameType;
    const FF = http2.frame.FrameFlags;

    // Stream A: the victim. We deliberately never credit its receive window,
    // so the server's handler runs out of send credit and parks.
    const a_sid: u31 = try t.nextClientStreamId();
    try t.writeRequestOnStream(a_sid, "go", "/Big");

    // Drain stream A's DATA until the handler MUST be parked (arithmetic, not
    // a race). Handle the SETTINGS handshake and any WINDOW_UPDATE inline.
    var got: usize = 0;
    while (got < DELIVERABLE_BEFORE_PARK) {
        const frame = try t.readFrame();
        defer allocator.free(frame.payload);
        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                if (frame.stream_id == a_sid) got += frame.payload.len;
            },
            @intFromEnum(FT.SETTINGS) => {
                if ((frame.flags & 0x1) == 0) {
                    t.applyPeerSettings(frame.payload);
                    try t.writeFrame(.SETTINGS, 0x1, 0, &.{});
                }
            },
            @intFromEnum(FT.WINDOW_UPDATE) => t.processWindowUpdate(frame.stream_id, frame.payload),
            @intFromEnum(FT.GOAWAY) => fail("server sent GOAWAY while streaming stream A", .{}),
            else => {},
        }
    }

    // Stream A's handler is now parked in `reserveSendCredit` (its stream
    // window is exhausted and we never credit it). Credit the CONNECTION
    // window so a sibling stream can be answered, pipeline sibling B, then
    // reset A. A stays parked across the connection-window credit because its
    // per-stream window is still zero — only the RST releases it.
    try sendWindowUpdate(&t, 0, 4 * @as(u32, @intCast(WINDOW)));
    const b_sid: u31 = try t.nextClientStreamId();
    try t.writeRequestOnStream(b_sid, "hello", "/Echo");
    try sendRstStream(&t, a_sid, HTTP2_CANCEL);

    // Sibling B must complete with grpc-status 0 and its echo payload while
    // the connection stays alive.
    var b_payload_bytes: usize = 0;
    var b_closed = false;
    var b_status_ok = false;
    while (!b_closed) {
        const frame = try t.readFrame();
        defer allocator.free(frame.payload);
        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                if (frame.stream_id == b_sid) b_payload_bytes += frame.payload.len;
            },
            @intFromEnum(FT.HEADERS) => {
                if (frame.stream_id == b_sid and (frame.flags & FF.END_STREAM) != 0) {
                    b_status_ok = std.mem.indexOf(u8, frame.payload, "grpc-status") != null and
                        hasGrpcStatus(frame.payload, "0");
                    b_closed = true;
                }
            },
            @intFromEnum(FT.SETTINGS) => {
                if ((frame.flags & 0x1) == 0) {
                    t.applyPeerSettings(frame.payload);
                    try t.writeFrame(.SETTINGS, 0x1, 0, &.{});
                }
            },
            @intFromEnum(FT.WINDOW_UPDATE) => t.processWindowUpdate(frame.stream_id, frame.payload),
            @intFromEnum(FT.GOAWAY) => fail("server sent GOAWAY after RST_STREAM — connection was torn down", .{}),
            else => {},
        }
    }

    if (b_payload_bytes == 0) {
        fail("sibling stream B got no response payload — the connection was wedged by the RST", .{});
    }
    if (!b_status_ok) fail("sibling stream B did not end with grpc-status 0", .{});

    // Stream A's handler unwound before B could be popped (single sequential
    // handler thread), so this load observes A's recorded outcome. It MUST be
    // the stream-scoped `error.StreamReset`, not the connection-scoped
    // `error.PeerGone` the pre-fix teardown produced.
    const raw_err = big_handler_result.load(.acquire);
    const want_err = @intFromError(error.StreamReset);
    if (raw_err != want_err) {
        fail(
            "stream A's handler recorded error code {d}, want error.StreamReset ({d}) — RST did not fail the stream stream-scoped (error.PeerGone is {d})",
            .{ raw_err, want_err, @intFromError(error.PeerGone) },
        );
    }

    std.log.info("    ok (stream A reset with error.StreamReset, sibling B served {d} B @ status 0)", .{b_payload_bytes});
}

/// True when a trailer HEADERS payload carries `grpc-status: <want>`. The
/// server encodes trailers as plain literal-name HPACK, so the bytes are
/// searchable as-is (mirrors the flow-control reader test helper).
fn hasGrpcStatus(payload: []const u8, want: []const u8) bool {
    const idx = std.mem.indexOf(u8, payload, "grpc-status") orelse return false;
    const vlen_at = idx + "grpc-status".len;
    if (vlen_at >= payload.len) return false;
    const vlen: usize = payload[vlen_at];
    const val_at = vlen_at + 1;
    if (val_at + vlen > payload.len) return false;
    return std.mem.eql(u8, payload[val_at .. val_at + vlen], want);
}

// ------------------------------------------------------------------- main

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    const wd = try std.Thread.spawn(.{}, watchdog, .{io});
    wd.detach();

    var server = try GrpcServer.init(allocator, io, PORT, "rst-isolation-key");
    defer server.deinit();
    try server.handlers.append(allocator, .{ .name = "/Big", .handler_fn = bigStreamHandlerRecordErr });
    try server.handlers.append(allocator, .{ .name = "/Echo", .handler_fn = echoHandler });
    // A moderate credit timeout: the fix releases stream A via RST at once, so
    // this timeout should never fire; it only bounds a regression where the
    // handler parks with nobody to wake it.
    server.flow_credit_timeout_ns = 10 * std.time.ns_per_s;

    const th = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = &server }});
    th.detach();
    try io.sleep(.fromMilliseconds(150), .awake);

    try scenarioRstIsolatesStream(allocator, io);

    std.log.info("RST-STREAM ISOLATION TEST PASSED", .{});
    std.process.exit(0);
}

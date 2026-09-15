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
//!      exited and no thread was leaked. The server's credit timeout is
//!      SHORT here so the assertion is about the JOIN happening inside a few
//!      seconds, never about which error (socket vs credit) wins the race —
//!      that race is what made an earlier revision of this scenario flaky
//!      under load.
//!
//!   4. SONNY-1568: a handler PARKED on send credit is released when the peer
//!      vanishes. The server under test keeps the DEFAULT 30 s
//!      `flow_credit_timeout_ns` and one connection permit; a client asks for
//!      the 4 MiB stream, reads part of it without ever crediting, then
//!      vanishes. The reader's exit must set `peer_gone` and wake the parked
//!      writer, so the permit comes back in seconds. Without that wake the
//!      writer sleeps the full 30 s and this scenario fails on its bound.
//!
//!   5. Queue-overflow refusal: with the single handler thread held inside a
//!      gated handler, more than `MAX_PENDING_REQUESTS` requests are
//!      pipelined on ONE connection. Exactly the overflow gets
//!      `grpc-status: 8` (RESOURCE_EXHAUSTED), every queued request is served
//!      once the gate opens, and the connection keeps serving afterwards. The
//!      round runs twice against a leak-checking server allocator
//!      (`std.heap.DebugAllocator` with `enable_memory_limit`), measured at
//!      the same point each time, so a refused request that leaked its 4 KiB
//!      payload shows up as tens of KiB of heap growth.
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
/// Server C: one connection permit, short credit timeout — scenario 3.
const PORT_C: u16 = 50613;
/// Server D: one connection permit, DEFAULT (30 s) credit timeout —
/// scenario 4 (the peer-vanished wake must beat that timeout by an order of
/// magnitude, which is what makes the scenario a regression test).
const PORT_D: u16 = 50614;
/// Server E: one connection permit, leak-checking allocator — scenario 5.
const PORT_E: u16 = 50615;

/// Peer initial window advertised by our own client SETTINGS.
const WINDOW: usize = @intCast(transport.ADVERTISED_INITIAL_WINDOW_SIZE);
const CHUNK_BYTES: usize = 64 * 1024;
/// 4x the initial window.
const CHUNKS: usize = (4 * WINDOW) / CHUNK_BYTES;

/// Wire size of one `/Big` message: the 5-byte gRPC length-prefix plus the
/// chunk payload. `reserveSendCredit` is charged this whole amount per
/// `writeStreamMessage` call, not just the payload.
const GRPC_FRAME_LEN: usize = 5 + CHUNK_BYTES;

/// SONNY-1568c: the largest number of response bytes a client can EVER
/// observe without crediting anything back, i.e. the greatest multiple of
/// `GRPC_FRAME_LEN` that fits inside one advertised window. `WINDOW` itself
/// overcounts by the framing overhead (16 messages need 16 * 5 = 80 bytes
/// more than `WINDOW` provides), so a client that waited for `got >=
/// WINDOW` would hang forever: the server parks on the 16th message and
/// never sends the remaining 80 bytes. Reading exactly this many bytes
/// guarantees the server's NEXT `reserveSendCredit` call has strictly less
/// than `GRPC_FRAME_LEN` remaining and MUST park — deterministically, by
/// arithmetic, not by a timing race.
const DELIVERABLE_BEFORE_PARK: usize = (WINDOW / GRPC_FRAME_LEN) * GRPC_FRAME_LEN;

const SHORT_TIMEOUT_NS: u64 = 2 * std.time.ns_per_s;

/// Upper bound on "the reader thread was joined and the admission permit
/// came back". Scenarios 3 and 4 both assert against it. Comfortably above
/// any scheduler noise, and far below the 30 s default credit timeout whose
/// absence it is proving.
const JOIN_BOUND_MS: i64 = 10_000;

/// How many requests scenario 5 pipelines PAST `MAX_PENDING_REQUESTS`.
const OVERFLOW_EXTRA: usize = 8;

/// Body size of every pipelined request in scenario 5. Deliberately large:
/// the leak assertion compares the server's live heap between two identical
/// rounds, and a fixed per-connection residue of a few dozen bytes is always
/// present. At 4 KiB per request, LEAKING the refused payloads would show up
/// as `OVERFLOW_EXTRA * 4 KiB` = 32 KiB of growth, two orders of magnitude
/// above that residue — so the tolerance below (one payload) separates a
/// real leak from noise without hand-tuning.
const OVERFLOW_BODY_BYTES: usize = 4096;

/// Leak-checking allocator for server E. `enable_memory_limit` makes
/// `total_requested_bytes` track currently-live requested bytes, which is
/// the cheapest honest leak signal available while the accept loop is still
/// running (a `detectLeaks()` sweep would flag the server's own live state).
const LeakGpa = std.heap.DebugAllocator(.{ .enable_memory_limit = true });
var server_e_gpa: LeakGpa = LeakGpa.init;

/// Gate used by `/Block` (scenario 5) to hold the single handler thread
/// until the test has finished pipelining. A condition variable, not a
/// sleep: the handler blocks until the test explicitly releases it.
const Gate = struct {
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    open: bool = false,

    fn reset(self: *Gate, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.open = false;
    }

    fn wait(self: *Gate, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (!self.open) self.cond.waitUncancelable(io, &self.mutex);
    }

    fn release(self: *Gate, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.open = true;
        self.cond.broadcast(io);
    }
};

var overflow_gate: Gate = .{};

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

/// SONNY-1568c: `@intFromError` of the handler's terminal error, for
/// scenario 4 (server D's `/Big`). 0 is "unset" — Zig error values are
/// never 0 — so the scenario can assert the handler's OUTCOME
/// (`error.PeerGone`), not just that the join happened inside the bound.
/// A stale value from an earlier run can't leak into the assertion: this
/// is the only handler registered for `/Big` on server D, and scenario 4
/// resets it before making its request.
var big_handler_result: std.atomic.Value(u16) = .init(0);

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

/// Scenario 5: occupies the connection's single handler thread. Writes a
/// "started" marker FIRST so the test knows the request has been popped off
/// the queue (making the later overflow count exact, not racy), then blocks
/// on the gate, then ends the stream.
fn blockHandler(
    _: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    _: std.mem.Allocator,
) anyerror!void {
    try trans.writeStreamMessage("started", true);
    overflow_gate.wait(trans.io);
    try trans.endStream();
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
    try server.handlers.append(allocator, .{ .name = "/Block", .handler_fn = blockHandler });
}

/// Server D only: same as `registerHandlers` but `/Big` records its
/// terminal error (SONNY-1568c) so scenario 4 can assert it's exactly
/// `error.PeerGone`.
fn registerHandlersD(allocator: std.mem.Allocator, server: *GrpcServer) !void {
    try server.handlers.append(allocator, .{ .name = "/Big", .handler_fn = bigStreamHandlerRecordErr });
    try server.handlers.append(allocator, .{ .name = "/Echo", .handler_fn = echoHandler });
    try server.handlers.append(allocator, .{ .name = "/Block", .handler_fn = blockHandler });
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
    std.log.info("[1/5] {d} x {d} B ({d} MiB = 4x initial window) to a crediting client", .{
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
    std.log.info("[2/5] stalled stream times out; connection keeps serving", .{});

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
    std.log.info("[3/5] client disappears mid-response; reader thread is joined", .{});

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
    //
    // The assertion is deliberately about the JOIN, not about which error
    // wins the teardown race. The vanished peer can surface either as a
    // socket error on the handler's next write or as the credit wait
    // ending; server C's credit timeout is SHORT (`SHORT_TIMEOUT_NS`) so
    // BOTH outcomes land inside `JOIN_BOUND_MS`. An earlier revision gave
    // server C the 30 s default and asserted `< 30_000 ms`, which made the
    // scenario a coin flip under load (observed FAIL at load ~12.7).
    const started = nowMs(io);
    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT_C);
    defer client.deinit();
    const resp = try client.call("/Echo", "after-abrupt-close", .none);
    defer allocator.free(resp);
    const elapsed_ms = nowMs(io) - started;

    if (!std.mem.eql(u8, resp, "after-abrupt-close")) {
        fail("second connection echoed '{s}'", .{resp});
    }
    if (elapsed_ms >= JOIN_BOUND_MS) {
        fail(
            "reader was not joined promptly: second connection waited {d} ms for the admission permit (bound {d} ms)",
            .{ elapsed_ms, JOIN_BOUND_MS },
        );
    }
    std.log.info("    ok (permit returned, new connection served in {d} ms)", .{elapsed_ms});
}

// ------------------------------------------------------------- scenario 4

/// SONNY-1568: a handler PARKED in `Transport.reserveSendCredit` must be
/// released when the peer vanishes, not when `flow_credit_timeout_ns`
/// expires.
///
/// Server D keeps the DEFAULT 30 s credit timeout and one connection permit.
/// The client requests the 4 MiB stream, reads part of it while NEVER
/// emitting a WINDOW_UPDATE — so the server burns through its send window
/// and the handler parks — then vanishes. The reader thread's exit sets
/// `peer_gone` and wakes the writer with `error.PeerGone`; the handler
/// unwinds, `handleConnection` joins the reader, and the permit comes back.
///
/// Three orderings are possible (handler already parked / parking right now
/// / still writing) and the fix covers all three: the parked writer is woken,
/// a writer that parks after the flag is set takes the on-entry check, and a
/// writer still in `ioWriteLocked` fails on the dead socket. The bound is
/// what distinguishes the fix from the bug — 30 s of parked writer cannot
/// hide inside `JOIN_BOUND_MS`.
///
/// SONNY-1568c: the client reads exactly `DELIVERABLE_BEFORE_PARK` bytes —
/// not `WINDOW / 2` — before vanishing. Reading only half the window left
/// the handler with credit still in hand, so it was never actually parked
/// when the client vanished: the observed error was `error.SocketUnconnected`
/// off the handler's next (unparked) write, and the scenario passed even
/// with `markPeerGone`'s call reverted — it was only ever checking the JOIN
/// bound, which the socket-error path satisfies on its own. Reading up to
/// `DELIVERABLE_BEFORE_PARK` is the exact byte count after which the
/// server's next `reserveSendCredit` call has too little credit to proceed —
/// arithmetic, not a race — so the handler MUST be parked (or arrive at the
/// park a moment later) when the client vanishes. The assertion below
/// checks the handler's recorded outcome, not just the bound, so a future
/// regression that makes the wake path silently no-op can't hide behind a
/// coincidentally-fast socket error again.
fn scenarioPeerVanishReleasesParkedWriter(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info("[4/5] handler parked on send credit is released when the peer vanishes", .{});
    big_handler_result.store(0, .release);

    {
        const address = try net.IpAddress.parseIp4("127.0.0.1", PORT_D);
        const conn = try address.connect(io, .{ .mode = .stream });
        transport.setRpcSocketOptions(conn.socket.handle);
        var t = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
        // NOTE: deliberately no `defer` — we vanish mid-response, below.
        const sid: u31 = try t.nextClientStreamId();
        try t.writeRequestOnStream(sid, "go", "/Big");

        // Consume every byte the server can EVER send without credit back
        // WITHOUT ever crediting it. Beyond `DELIVERABLE_BEFORE_PARK` the
        // handler cannot have sent anything more — it parked — so by the
        // time this loop ends the handler IS parked in `reserveSendCredit`,
        // not merely "microseconds from parking". Bounded: every iteration
        // reads a frame the server has already sent or is sending, no
        // sleeps.
        var got: usize = 0;
        while (got < DELIVERABLE_BEFORE_PARK) {
            const frame = try t.readFrame();
            defer allocator.free(frame.payload);
            if (frame.frame_type == @intFromEnum(http2.frame.FrameType.DATA)) got += frame.payload.len;
        }
        t.deinit();
    }

    const started = nowMs(io);
    var client = try GrpcClient.init(allocator, io, "127.0.0.1", PORT_D);
    defer client.deinit();
    const resp = try client.call("/Echo", "after-vanish", .none);
    defer allocator.free(resp);
    const elapsed_ms = nowMs(io) - started;

    if (!std.mem.eql(u8, resp, "after-vanish")) fail("second connection echoed '{s}'", .{resp});
    if (elapsed_ms >= JOIN_BOUND_MS) {
        fail(
            "parked writer was not released by the peer's disappearance: permit took {d} ms (bound {d} ms; the credit timeout here is 30 s)",
            .{ elapsed_ms, JOIN_BOUND_MS },
        );
    }

    // The permit coming back happens-after the handler's dispatch (server.zig
    // pops the next queue item / posts `conn_sem` only once `handleConnection`
    // returns, which happens after `handler_fn` returns), so this load is
    // guaranteed to observe the store `bigStreamHandlerRecordErr` made.
    const raw_err = big_handler_result.load(.acquire);
    const want_err = @intFromError(error.PeerGone);
    if (raw_err != want_err) {
        fail(
            "handler's recorded outcome was error code {d}, want error.PeerGone ({d}) — the join happened inside the bound, but the handler did not actually unwind via the peer-gone wake path",
            .{ raw_err, want_err },
        );
    }
    std.log.info("    ok (parked writer released with error.PeerGone, permit returned in {d} ms)", .{elapsed_ms});
}

// ------------------------------------------------------------- scenario 5

/// True when a trailer HEADERS payload carries `grpc-status: 8`. The server
/// encodes trailers as plain literal-name HPACK (`0x40, len, name, len,
/// value`), so the bytes are searchable as-is.
fn hasGrpcStatus(payload: []const u8, want: []const u8) bool {
    const idx = std.mem.indexOf(u8, payload, "grpc-status") orelse return false;
    const vlen_at = idx + "grpc-status".len;
    if (vlen_at >= payload.len) return false;
    const vlen: usize = payload[vlen_at];
    const val_at = vlen_at + 1;
    if (val_at + vlen > payload.len) return false;
    return std.mem.eql(u8, payload[val_at .. val_at + vlen], want);
}

/// One queue-overflow round on a fresh connection. Runs twice so scenario 5
/// can compare the server's live heap at identical points.
fn overflowRound(allocator: std.mem.Allocator, io: std.Io) !void {
    overflow_gate.reset(io);

    const address = try net.IpAddress.parseIp4("127.0.0.1", PORT_E);
    const conn = try address.connect(io, .{ .mode = .stream });
    transport.setRpcSocketOptions(conn.socket.handle);
    var t = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
    defer t.deinit();

    const FT = http2.frame.FrameType;
    const FF = http2.frame.FrameFlags;

    // 1. Pin the single handler thread inside `/Block`. Its "started"
    //    marker proves the request was POPPED, so the queue is empty again
    //    and the overflow arithmetic below is exact rather than racy.
    const block_sid: u31 = try t.nextClientStreamId();
    try t.writeRequestOnStream(block_sid, "block", "/Block");
    var block_started = false;
    while (!block_started) {
        const frame = try t.readFrame();
        defer allocator.free(frame.payload);
        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                if (frame.stream_id == block_sid) block_started = true;
            },
            @intFromEnum(FT.SETTINGS) => {
                if ((frame.flags & 0x1) == 0) {
                    t.applyPeerSettings(frame.payload);
                    try t.writeFrame(.SETTINGS, 0x1, 0, &.{});
                }
            },
            @intFromEnum(FT.WINDOW_UPDATE) => t.processWindowUpdate(frame.stream_id, frame.payload),
            @intFromEnum(FT.GOAWAY) => fail("server sent GOAWAY while pinning the handler", .{}),
            else => {},
        }
    }

    // 2. Pipeline MAX_PENDING_REQUESTS + OVERFLOW_EXTRA requests. The first
    //    MAX_PENDING_REQUESTS fill the queue; the rest must be refused.
    const PIPELINED = server_mod.MAX_PENDING_REQUESTS + OVERFLOW_EXTRA;
    const body = try allocator.alloc(u8, OVERFLOW_BODY_BYTES);
    defer allocator.free(body);
    @memset(body, 'p');
    var echo_sids: [PIPELINED]u31 = undefined;
    for (&echo_sids) |*sid| {
        sid.* = try t.nextClientStreamId();
        try t.writeRequestOnStream(sid.*, body, "/Echo");
    }

    // 3. Collect exactly OVERFLOW_EXTRA refusals. The reader emits them as
    //    it parses, without waiting for the (still-blocked) handler.
    var refused: usize = 0;
    var bad_status: usize = 0;
    var served: usize = 0;
    var served_payload_bytes: usize = 0;
    var block_closed = false;
    var gate_released = false;

    while (!(gate_released and served == server_mod.MAX_PENDING_REQUESTS and block_closed)) {
        const frame = try t.readFrame();
        defer allocator.free(frame.payload);
        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                if (frame.stream_id != block_sid) served_payload_bytes += frame.payload.len;
            },
            @intFromEnum(FT.HEADERS) => {
                if ((frame.flags & FF.END_STREAM) == 0) continue;
                if (frame.stream_id == block_sid) {
                    block_closed = true;
                } else if (std.mem.indexOf(u8, frame.payload, "server request queue full") != null) {
                    refused += 1;
                    if (!hasGrpcStatus(frame.payload, "8")) bad_status += 1;
                } else {
                    served += 1;
                    if (!hasGrpcStatus(frame.payload, "0")) {
                        fail("pipelined request on stream {d} ended with a non-OK status", .{frame.stream_id});
                    }
                }
            },
            @intFromEnum(FT.SETTINGS) => {
                if ((frame.flags & 0x1) == 0) {
                    t.applyPeerSettings(frame.payload);
                    try t.writeFrame(.SETTINGS, 0x1, 0, &.{});
                }
            },
            @intFromEnum(FT.WINDOW_UPDATE) => t.processWindowUpdate(frame.stream_id, frame.payload),
            @intFromEnum(FT.RST_STREAM) => fail("server RST a pipelined stream", .{}),
            @intFromEnum(FT.GOAWAY) => fail("server sent GOAWAY on queue overflow; connection was torn down", .{}),
            else => {},
        }

        // Every refusal is in hand — let the handler drain the queue.
        if (!gate_released and refused == OVERFLOW_EXTRA) {
            overflow_gate.release(io);
            gate_released = true;
        }
    }

    if (refused != OVERFLOW_EXTRA) {
        fail("{d} requests refused, want exactly {d}", .{ refused, OVERFLOW_EXTRA });
    }
    if (bad_status != 0) {
        fail("{d} refusals carried a status other than 8 (RESOURCE_EXHAUSTED)", .{bad_status});
    }
    if (served != server_mod.MAX_PENDING_REQUESTS) {
        fail("{d} queued requests served, want {d}", .{ served, server_mod.MAX_PENDING_REQUESTS });
    }
    if (served_payload_bytes == 0) fail("queued requests produced no response payload", .{});

    // 4. The connection must keep serving after the overflow.
    const tail_sid: u31 = try t.nextClientStreamId();
    try t.writeRequestOnStream(tail_sid, "after-overflow", "/Echo");
    var tail_closed = false;
    var tail_bytes: usize = 0;
    while (!tail_closed) {
        const frame = try t.readFrame();
        defer allocator.free(frame.payload);
        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                if (frame.stream_id == tail_sid) tail_bytes += frame.payload.len;
            },
            @intFromEnum(FT.HEADERS) => {
                if (frame.stream_id == tail_sid and (frame.flags & FF.END_STREAM) != 0) {
                    if (!hasGrpcStatus(frame.payload, "0")) {
                        fail("post-overflow request did not end with grpc-status 0", .{});
                    }
                    tail_closed = true;
                }
            },
            @intFromEnum(FT.WINDOW_UPDATE) => t.processWindowUpdate(frame.stream_id, frame.payload),
            @intFromEnum(FT.GOAWAY) => fail("server sent GOAWAY after the overflow", .{}),
            else => {},
        }
    }
    if (tail_bytes == 0) fail("post-overflow request got no response payload", .{});
}

fn scenarioQueueOverflowRefused(allocator: std.mem.Allocator, io: std.Io) !void {
    std.log.info(
        "[5/5] >{d} pipelined requests: overflow refused with grpc-status 8, connection keeps serving",
        .{server_mod.MAX_PENDING_REQUESTS},
    );

    // Two identical rounds. Server E has ONE connection permit, so the probe
    // connection below can only be admitted after the round's connection has
    // been fully torn down (`handleConnection` returned, transport freed).
    // Both snapshots are therefore taken with exactly one live connection —
    // the live state cancels and only a genuine leak (e.g. a refused
    // request's payload never freed) shows up as growth.
    var live_bytes: [2]usize = .{ 0, 0 };
    var round: usize = 0;
    while (round < 2) : (round += 1) {
        try overflowRound(allocator, io);

        var probe = try GrpcClient.init(allocator, io, "127.0.0.1", PORT_E);
        const resp = try probe.call("/Echo", "still-serving", .none);
        if (!std.mem.eql(u8, resp, "still-serving")) {
            fail("probe connection echoed '{s}'", .{resp});
        }
        allocator.free(resp);

        // SONNY-1568c: `total_requested_bytes` is mutated by server E's
        // reader/handler threads under `server_e_gpa.mutex` (DebugAllocator's
        // own internal lock, since `LeakGpa` is `thread_safe`); reading the
        // field directly from this test thread was a data race against
        // whichever server thread is still touching the live probe
        // connection's allocations at that instant. Taking the SAME mutex
        // for the read gives a synchronized, torn-free snapshot instead —
        // the field itself is untouched, so the tolerance below is
        // unaffected.
        server_e_gpa.mutex.lockUncancelable(io);
        live_bytes[round] = server_e_gpa.total_requested_bytes;
        server_e_gpa.mutex.unlock(io);
        probe.deinit();
    }

    const growth = if (live_bytes[1] > live_bytes[0]) live_bytes[1] - live_bytes[0] else 0;
    if (growth >= OVERFLOW_BODY_BYTES) {
        fail(
            "server heap grew {d} B across two identical overflow rounds ({d} -> {d}) — refused requests leak (tolerance {d} B = one request body; {d} leaked refusals would be {d} B)",
            .{ growth, live_bytes[0], live_bytes[1], OVERFLOW_BODY_BYTES, OVERFLOW_EXTRA, OVERFLOW_EXTRA * OVERFLOW_BODY_BYTES },
        );
    }
    std.log.info(
        "    ok ({d} x {d} B refused with status 8, {d} served, connection healthy, live heap {d} -> {d} B)",
        .{ OVERFLOW_EXTRA, OVERFLOW_BODY_BYTES, server_mod.MAX_PENDING_REQUESTS, live_bytes[0], live_bytes[1] },
    );
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
    // Short credit timeout so scenario 3's assertion is about the JOIN and
    // not about whether the socket error or the credit wait wins the race.
    server_c.flow_credit_timeout_ns = SHORT_TIMEOUT_NS;

    // Scenario 4 keeps the DEFAULT 30 s credit timeout on purpose: the wake
    // on `peer_gone` is only proven by finishing far inside it.
    var server_d = try GrpcServer.init(allocator, io, PORT_D, "flow-reader-key");
    defer server_d.deinit();
    try registerHandlersD(allocator, &server_d);
    server_d.conn_sem = .{ .permits = 1 };

    // Scenario 5 runs on a leak-checking allocator (see `LeakGpa`).
    const leak_allocator = server_e_gpa.allocator();
    var server_e = try GrpcServer.init(leak_allocator, io, PORT_E, "flow-reader-key");
    defer server_e.deinit();
    try registerHandlers(leak_allocator, &server_e);
    server_e.conn_sem = .{ .permits = 1 };

    inline for (.{ &server_a, &server_b, &server_c, &server_d, &server_e }) |srv| {
        const th = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = srv }});
        th.detach();
    }
    try io.sleep(.fromMilliseconds(150), .awake);

    try scenarioCreditedStreamCompletes(allocator, io);
    try scenarioStalledStreamDoesNotWedgeConnection(allocator, io);
    try scenarioReaderExitsOnClientClose(allocator, io);
    try scenarioPeerVanishReleasesParkedWriter(allocator, io);
    try scenarioQueueOverflowRefused(allocator, io);

    std.log.info("FLOW-CONTROL READER TEST PASSED", .{});
    std.process.exit(0);
}

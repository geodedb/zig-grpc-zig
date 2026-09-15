const std = @import("std");
const testing = std.testing;
const client_mux = @import("client_mux.zig");
const transport = @import("transport.zig");
const compat = @import("compat.zig");
const net = std.Io.net;
const http2f = @import("http2/frame.zig");

// deliverData is the pure core of readerLoop's DATA handling: it appends
// a validated gRPC message into the slot and ALWAYS signals end_stream
// (with err set) on any failure so the waiting caller never deadlocks
// (closes quality R2 / #57).

test "R2: allocation failure sets err AND end_stream (no deadlock)" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);

    const payload = [_]u8{ 0, 0, 0, 0, 2, 'h', 'i' }; // prefix(5) + "hi"
    client_mux.deliverData(&slot, failing.allocator(), &payload, false, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);

    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream); // MUST be set or the caller hangs
}

test "deliverData appends message bytes on success" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    const payload = [_]u8{ 0, 0, 0, 0, 2, 'h', 'i' };
    client_mux.deliverData(&slot, testing.allocator, &payload, true, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
    try testing.expect(slot.err == null);
    try testing.expect(slot.end_stream);
    try testing.expectEqualSlices(u8, "hi", slot.data.items);
}

test "deliverData rejects invalid gRPC prefix (I6)" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    const payload = [_]u8{ 0xFF, 0, 0, 0, 1, 'x' };
    client_mux.deliverData(&slot, testing.allocator, &payload, false, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream);
}

test "NEW-1 client side: accumulated response beyond cap errors out" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    // Cap of 4 bytes; deliver a 3-byte message twice -> second must fail.
    const payload = [_]u8{ 0, 0, 0, 0, 3, 'a', 'b', 'c' };
    client_mux.deliverData(&slot, testing.allocator, &payload, false, 4);
    try testing.expect(slot.err == null);
    client_mux.deliverData(&slot, testing.allocator, &payload, false, 4);
    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream);
}

test "M2: nextStreamId detects u31 wraparound" {
    try testing.expectEqual(@as(u31, 5), try client_mux.nextStreamId(3));
    const last_odd: u31 = std.math.maxInt(u31); // 0x7FFFFFFF, odd
    try testing.expectError(error.StreamIdExhausted, client_mux.nextStreamId(last_odd));
    try testing.expectError(error.StreamIdExhausted, client_mux.nextStreamId(last_odd - 1));
}

// ------------------------------------------------------------------------
// SONNY-1568c: `readerLoop`'s exit must release a caller parked in
// `Transport.reserveSendCredit` (via `writeRequestOnStreamWithMetadata`),
// not just callers blocked on a `StreamSlot.cond` — see `client_mux.zig`'s
// `readerLoop` doc comment. A real `GrpcServer` can't be used to exercise
// this: its reader thread ALWAYS auto-credits inbound DATA (that is the
// whole point of SONNY-1560), so it can never be made to withhold send
// credit from a writer. Instead these tests play a minimal, fully
// hand-rolled HTTP/2 peer over a real loopback socket: just enough of the
// server side of the handshake for `ClientMux.init` to succeed, advertising
// a ZERO initial window so the very next stream is starved from birth, then
// going silent and closing to simulate the peer vanishing mid-park.

fn rawWrite(io: std.Io, stream: net.Stream, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const trailing = [_][]const u8{data[sent..]};
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, "", &trailing, 1);
        if (n == 0) return error.WriteFailed;
        sent += n;
    }
}

fn sendRawFrame(
    io: std.Io,
    stream: net.Stream,
    frame_type: http2f.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    var header: [9]u8 = undefined;
    const length: u24 = @intCast(payload.len);
    header[0] = @intCast((length >> 16) & 0xFF);
    header[1] = @intCast((length >> 8) & 0xFF);
    header[2] = @intCast(length & 0xFF);
    header[3] = @intFromEnum(frame_type);
    header[4] = flags;
    header[5] = @intCast((@as(u32, stream_id) >> 24) & 0x7F);
    header[6] = @intCast((@as(u32, stream_id) >> 16) & 0xFF);
    header[7] = @intCast((@as(u32, stream_id) >> 8) & 0xFF);
    header[8] = @intCast(@as(u32, stream_id) & 0xFF);
    try rawWrite(io, stream, &header);
    if (payload.len > 0) try rawWrite(io, stream, payload);
}

const FakeServerCtx = struct {
    server: *net.Server,
    io: std.Io,
};

/// Accepts exactly one connection, sends just enough of the server side of
/// the HTTP/2 handshake for `Transport.initClient`'s
/// `consumeInitialServerFrames` to return (a SETTINGS advertising a ZERO
/// initial window, its ACK, and a connection WINDOW_UPDATE so the loop's
/// "saw all three" exit condition is met rather than blocking on a fourth
/// read that never arrives), then sleeps briefly — giving the writer thread
/// time to actually park in `reserveSendCredit` rather than merely take the
/// on-entry check — and closes. Never reads anything from the client: the
/// whole point of `reserveSendCreditOrRst` is that it parks BEFORE writing
/// any bytes for the stream, so there is nothing to read, and the ~100
/// bytes of preface/SETTINGS/WINDOW_UPDATE the client sends comfortably fit
/// in the loopback socket buffer unread.
fn fakeVanishingServer(ctx: FakeServerCtx) void {
    const conn = ctx.server.accept(ctx.io) catch return;
    defer conn.close(ctx.io);

    var settings_payload: [6]u8 = undefined;
    settings_payload[0] = @intCast((transport.SETTINGS_INITIAL_WINDOW_SIZE >> 8) & 0xFF);
    settings_payload[1] = @intCast(transport.SETTINGS_INITIAL_WINDOW_SIZE & 0xFF);
    @memset(settings_payload[2..6], 0); // INITIAL_WINDOW_SIZE = 0

    sendRawFrame(ctx.io, conn, .SETTINGS, 0, 0, &settings_payload) catch return;
    sendRawFrame(ctx.io, conn, .SETTINGS, 0x1, 0, &.{}) catch return; // ACK
    const wu_payload = [_]u8{ 0, 0, 0, 1 };
    sendRawFrame(ctx.io, conn, .WINDOW_UPDATE, 0, 0, &wu_payload) catch return;

    ctx.io.sleep(.fromMilliseconds(500), .awake) catch {};
    // `conn.close` (deferred above) simulates the peer vanishing.
}

test "SONNY-1568c: readerLoop exit releases a writer parked on send credit" {
    const allocator = testing.allocator;
    const io = std.testing.io;

    const listen_addr = try net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const server_thread = try std.Thread.spawn(.{}, fakeVanishingServer, .{FakeServerCtx{ .server = &server, .io = io }});
    defer server_thread.join();

    // `ClientMux.init` blocks in `Transport.initClient` ->
    // `consumeInitialServerFrames` until the fake server's three handshake
    // frames arrive, so by the time this returns the per-stream send window
    // is already zero.
    const mux = try client_mux.ClientMux.init(allocator, io, "127.0.0.1", port);
    defer mux.deinit();

    const start_ns = compat.nanoTimestamp();
    const result = mux.call("/Echo", "x", .none);
    const elapsed_ns = compat.nanoTimestamp() - start_ns;

    if (result) |bytes| {
        allocator.free(bytes);
        return error.TestUnexpectedResult; // the write should never succeed
    } else |err| {
        try testing.expectEqual(error.PeerGone, err);
    }
    // Orders of magnitude below the 30 s default `flow_credit_timeout_ns`
    // this write would otherwise sleep out before `client_mux.zig`'s fix
    // (a `defer self.transport.markPeerGone()` covering every `readerLoop`
    // exit path).
    try testing.expect(elapsed_ns < 15 * std.time.ns_per_s);
}

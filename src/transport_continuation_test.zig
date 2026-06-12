const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "I5: header fragments accumulate up to the bound" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "abc", 8);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "defgh", 8);
    try testing.expectEqualSlices(u8, "abcdefgh", buf.items);
}

test "I5: over-bound header block is a protocol error" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "abcd", 8);
    try testing.expectError(
        transport.TransportError.HeaderBlockTooLarge,
        transport.Transport.appendHeaderFragment(&buf, testing.allocator, "efghi", 8),
    );
}

test "I5: MAX_HEADER_BLOCK_BYTES matches advertised MAX_HEADER_LIST_SIZE" {
    try testing.expectEqual(@as(usize, 8192), transport.MAX_HEADER_BLOCK_BYTES);
}

// --- Integration tests: drive readMessage end-to-end through a fake
// socket under testing.allocator so the leak detector enforces the
// per-exit-path free discipline of the CONTINUATION reassembly code. ---

const FakeStream = struct {
    read_buf: []const u8,
    read_pos: usize = 0,
    write_buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn read(ctx: *anyopaque, dst: []u8) anyerror!usize {
        const self: *FakeStream = @ptrCast(@alignCast(ctx));
        if (self.read_pos >= self.read_buf.len) return 0;
        const remaining = self.read_buf.len - self.read_pos;
        const n = @min(dst.len, remaining);
        @memcpy(dst[0..n], self.read_buf[self.read_pos .. self.read_pos + n]);
        self.read_pos += n;
        return n;
    }
    fn write(ctx: *anyopaque, src: []const u8) anyerror!usize {
        const self: *FakeStream = @ptrCast(@alignCast(ctx));
        try self.write_buf.appendSlice(self.allocator, src);
        return src.len;
    }
    fn close(ctx: *anyopaque) void {
        _ = ctx;
    }
};

/// Append a 9-byte HTTP/2 frame header + payload to `out`.
fn pushFrame(out: *std.ArrayList(u8), allocator: std.mem.Allocator, ftype: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
    const len: u24 = @intCast(payload.len);
    var hdr: [9]u8 = undefined;
    hdr[0] = @intCast((len >> 16) & 0xFF);
    hdr[1] = @intCast((len >> 8) & 0xFF);
    hdr[2] = @intCast(len & 0xFF);
    hdr[3] = ftype;
    hdr[4] = flags;
    hdr[5] = @intCast((@as(u32, stream_id) >> 24) & 0x7F);
    hdr[6] = @intCast((@as(u32, stream_id) >> 16) & 0xFF);
    hdr[7] = @intCast((@as(u32, stream_id) >> 8) & 0xFF);
    hdr[8] = @intCast(@as(u32, stream_id) & 0xFF);
    try out.appendSlice(allocator, &hdr);
    try out.appendSlice(allocator, payload);
}

/// Build a Transport wired to a FakeStream, with the minimal fields
/// readMessage touches initialized. Reads go through the fake; writes
/// (e.g. GOAWAY on error paths) are captured in fake.write_buf.
fn fakeTransport(fake: *FakeStream) transport.Transport {
    var t: transport.Transport = undefined;
    t.allocator = testing.allocator;
    t.io = std.testing.io;
    t.tls_io = .{
        .ctx = fake,
        .read_fn = FakeStream.read,
        .write_fn = FakeStream.write,
        .close_fn = FakeStream.close,
    };
    t.write_mutex = .init;
    t.max_frame_size = transport.DEFAULT_MAX_FRAME_SIZE;
    t.max_recv_message_bytes = transport.DEFAULT_MAX_RECV_MESSAGE_BYTES;
    t.conn_recv_window = transport.ADVERTISED_INITIAL_WINDOW_SIZE;
    t.stream_recv_windows = &[_]i32{};
    t.last_stream_id = 0;
    t.last_method_len = 0;
    t.last_authorization_len = 0;
    t.hpack_dyn_count = 0;
    t.hpack_dyn_head = 0;
    return t;
}

test "I5 integration: HEADERS(no END_HEADERS)+CONTINUATION(END_HEADERS)+DATA reassembles, no leak" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    // HEADERS, empty payload, NO END_HEADERS, stream 1
    try pushFrame(&script, alloc, 0x1, 0x0, 1, &.{});
    // CONTINUATION, empty payload, END_HEADERS (0x4), stream 1
    try pushFrame(&script, alloc, 0x9, 0x4, 1, &.{});
    // DATA, gRPC framed "hi": prefix(0,0,0,0,2)+"hi", stream 1
    try pushFrame(&script, alloc, 0x0, 0x0, 1, &[_]u8{ 0, 0, 0, 0, 2, 'h', 'i' });

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    const msg = try t.readMessage();
    defer alloc.free(msg);
    try testing.expectEqualSlices(u8, "hi", msg);
}

test "I5 integration: non-CONTINUATION frame mid-block is ProtocolError, no leak" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    // HEADERS, empty payload, NO END_HEADERS, stream 1
    try pushFrame(&script, alloc, 0x1, 0x0, 1, &.{});
    // A DATA frame where a CONTINUATION was required -> PROTOCOL_ERROR
    try pushFrame(&script, alloc, 0x0, 0x0, 1, &[_]u8{ 0, 0, 0, 0, 2, 'h', 'i' });

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    try testing.expectError(transport.TransportError.ProtocolError, t.readMessage());
}

test "I5 integration: over-8192-byte header block is HeaderBlockTooLarge, no leak" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    const big = [_]u8{0} ** 8000;
    const more = [_]u8{0} ** 300; // 8000 + 300 = 8300 > 8192
    // HEADERS, 8000-byte payload, NO END_HEADERS, stream 1
    try pushFrame(&script, alloc, 0x1, 0x0, 1, &big);
    // CONTINUATION, 300-byte payload, END_HEADERS, stream 1 -> over bound
    try pushFrame(&script, alloc, 0x9, 0x4, 1, &more);

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    try testing.expectError(transport.TransportError.HeaderBlockTooLarge, t.readMessage());
}

// --- Iter2-C: stream-id-filtered client read (readMessageOnStream) ---
//
// These exercise the exact failure modes the single-call client hit:
//   (a) a trailer-only error response (lone HEADERS(END_STREAM)) must NOT
//       loop forever — it surfaces error.StreamEndedWithoutMessage;
//   (b) a stale stream-1 trailer left in the buffer by call N-1 must be
//       SKIPPED by call N (which reads on a fresh sid) before its real
//       response is parsed — the precise loopback regression;
//   (c) a normal HEADERS(no END_STREAM)+DATA on the expected stream still
//       returns the message.

test "Iter2-C: trailer-only HEADERS(END_STREAM) yields StreamEndedWithoutMessage (no hang)" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    // Lone HEADERS with END_STREAM|END_HEADERS, empty payload, stream 1.
    // This is a gRPC trailer-only error status (e.g. UNIMPLEMENTED).
    try pushFrame(&script, alloc, 0x1, 0x1 | 0x4, 1, &.{});

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    try testing.expectError(
        transport.TransportError.StreamEndedWithoutMessage,
        t.readMessageOnStream(1),
    );
}

test "Iter2-C: readMessageOnStream(3) skips stale stream-1 trailer then returns message" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    // Stale trailer left by the PREVIOUS call: HEADERS(END_STREAM|END_HEADERS)
    // on stream 1. Must be skipped because we read on stream 3.
    try pushFrame(&script, alloc, 0x1, 0x1 | 0x4, 1, &.{});
    // Current call's real response on stream 3: HEADERS(END_HEADERS, no
    // END_STREAM) then DATA carrying gRPC framed "hi".
    try pushFrame(&script, alloc, 0x1, 0x4, 3, &.{});
    try pushFrame(&script, alloc, 0x0, 0x0, 3, &[_]u8{ 0, 0, 0, 0, 2, 'h', 'i' });

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    const msg = try t.readMessageOnStream(3);
    defer alloc.free(msg);
    try testing.expectEqualSlices(u8, "hi", msg);
}

test "Iter2-C: readMessageOnStream(1) returns message on normal HEADERS+DATA" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    // Normal unary response on stream 1: HEADERS(END_HEADERS, no END_STREAM)
    // then DATA carrying gRPC framed "hi".
    try pushFrame(&script, alloc, 0x1, 0x4, 1, &.{});
    try pushFrame(&script, alloc, 0x0, 0x0, 1, &[_]u8{ 0, 0, 0, 0, 2, 'h', 'i' });

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    const msg = try t.readMessageOnStream(1);
    defer alloc.free(msg);
    try testing.expectEqualSlices(u8, "hi", msg);
}

// --- Iter2-D: stream-id-filtered streaming client read
// (readStreamFrameOnStream) ---
//
// The latent bug: after a unary `call` reads via `readMessageOnStream` it
// intentionally leaves its own HEADERS(END_STREAM) trailer UNREAD in the
// buffer. A subsequent `streamCall` on the SAME client that read via the
// unfiltered `readStreamFrame` would misread that stale trailer as its own
// end-of-stream and abandon its real response. `readStreamFrameOnStream`
// skips the stale trailer and reads its own stream's message + end.

test "Iter2-D: readStreamFrameOnStream skips stale trailer from a completed stream" {
    const alloc = testing.allocator;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(alloc);
    // Stale unary trailer from stream 1 (HEADERS END_STREAM|END_HEADERS),
    // left unread by a prior `call`:
    try pushFrame(&script, alloc, 0x1, 0x1 | 0x4, 1, &.{});
    // This streamCall's response on stream 3: HEADERS(END_HEADERS, no
    // END_STREAM) then DATA(END_STREAM) carrying gRPC framed "hi" — so the
    // streamed message and end arrive together.
    try pushFrame(&script, alloc, 0x1, 0x4, 3, &.{});
    try pushFrame(&script, alloc, 0x0, 0x1, 3, &[_]u8{ 0, 0, 0, 0, 2, 'h', 'i' });

    var fake = FakeStream{ .read_buf = script.items, .allocator = alloc };
    defer fake.write_buf.deinit(alloc);
    var t = fakeTransport(&fake);

    const sf = try t.readStreamFrameOnStream(3);
    defer if (sf.data) |d| alloc.free(d);
    try testing.expect(sf.data != null);
    try testing.expectEqualSlices(u8, "hi", sf.data.?);
    try testing.expect(sf.end_stream);
}

// --- Iter2-C: nextClientStreamId allocator (odd, monotonic, exhaustion) ---

test "Iter2-C: nextClientStreamId yields 1,3,5 from last_stream_id=1" {
    var t: transport.Transport = undefined;
    t.last_stream_id = 1;
    try testing.expectEqual(@as(u31, 1), try t.nextClientStreamId());
    try testing.expectEqual(@as(u31, 3), try t.nextClientStreamId());
    try testing.expectEqual(@as(u31, 5), try t.nextClientStreamId());
}

test "Iter2-C: nextClientStreamId near max returns StreamIdExhausted" {
    var t: transport.Transport = undefined;
    // maxInt(u31) is odd; one below the wrap threshold still works, then exhausts.
    t.last_stream_id = std.math.maxInt(u31) - 1; // even-ish boundary; > max-2 triggers exhaustion
    try testing.expectError(error.StreamIdExhausted, t.nextClientStreamId());
}

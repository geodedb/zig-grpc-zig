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

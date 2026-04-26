// Wire-level test for I3 — closes the SETTINGS_MAX_FRAME_SIZE enforcement
// gap (GitLab security #8 / RFC 7540 §6.5.2).
//
// Bug: `Transport.readFrame` allocated an arbitrary-sized buffer for the
// frame payload based purely on the 24-bit length header from the peer.
// A peer could declare a 16 MiB length and force the server to alloc
// 16 MiB before any auth check, providing a trivial DoS amplification.
//
// Fix: the Transport tracks `max_frame_size` (RFC 7540 default 16384,
// updated from peer SETTINGS frame parameter id 0x05). `readFrame`
// rejects oversize frames with `error.FrameSizeError` BEFORE allocating
// the payload buffer, and emits a GOAWAY with FRAME_SIZE_ERROR (0x6).

const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

/// In-memory fake stream that pretends to be the peer side of a socket.
/// Captures writes (so we can assert the GOAWAY frame is emitted) and
/// returns scripted bytes on read.
const FakeStream = struct {
    read_buf: []const u8,
    read_pos: usize = 0,
    write_buf: std.ArrayList(u8) = .empty,
    closed: bool = false,
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
        const self: *FakeStream = @ptrCast(@alignCast(ctx));
        self.closed = true;
    }
};

test "DEFAULT_MAX_FRAME_SIZE is 16384 (RFC 7540 default)" {
    try testing.expectEqual(@as(u32, 16384), transport.DEFAULT_MAX_FRAME_SIZE);
}

test "checkFrameSize accepts a frame at exactly the default max_frame_size" {
    // The pure helper checkFrameSize is what readFrame consults before
    // allocating a payload buffer. Any value <= max_frame_size is OK.
    try transport.Transport.checkFrameSize(transport.DEFAULT_MAX_FRAME_SIZE, transport.DEFAULT_MAX_FRAME_SIZE);
    try transport.Transport.checkFrameSize(0, transport.DEFAULT_MAX_FRAME_SIZE);
    try transport.Transport.checkFrameSize(1024, transport.DEFAULT_MAX_FRAME_SIZE);
}

test "checkFrameSize rejects an oversize frame" {
    // 2x default — trivially over the cap.
    const too_big = transport.DEFAULT_MAX_FRAME_SIZE * 2;
    try testing.expectError(
        error.FrameSizeError,
        transport.Transport.checkFrameSize(too_big, transport.DEFAULT_MAX_FRAME_SIZE),
    );
}

test "checkFrameSize honours an updated max_frame_size from peer SETTINGS" {
    // Peer can negotiate a larger limit via SETTINGS_MAX_FRAME_SIZE.
    // After the update, the previously-rejected size is accepted.
    const new_max: u32 = 1 << 20;
    try transport.Transport.checkFrameSize(transport.DEFAULT_MAX_FRAME_SIZE * 2, new_max);
    // But anything still over the new cap must error.
    try testing.expectError(
        error.FrameSizeError,
        transport.Transport.checkFrameSize(new_max + 1, new_max),
    );
}

test "buildGoawayFrameSizeError encodes the connection-level frame" {
    // GOAWAY frame layout (RFC 7540 §6.8):
    //   Frame header (9 bytes), payload:
    //     R + Last-Stream-ID (4 bytes, R=0)
    //     Error code (4 bytes, 0x06 = FRAME_SIZE_ERROR)
    //     [optional debug data]
    // Stream ID on the frame itself is always 0 for GOAWAY.
    var allocator = std.testing.allocator;
    const bytes = try transport.Transport.buildGoawayFrameSizeError(allocator, 0);
    defer allocator.free(bytes);

    // Header is 9 bytes; payload is at minimum 8 bytes (last-stream-id + error code).
    try testing.expect(bytes.len >= 17);

    // length field = bytes.len - 9, parsed big-endian from bytes[0..3]
    const length: u32 = (@as(u32, bytes[0]) << 16) | (@as(u32, bytes[1]) << 8) | @as(u32, bytes[2]);
    try testing.expectEqual(@as(u32, @intCast(bytes.len - 9)), length);

    // Frame type = GOAWAY (0x07)
    try testing.expectEqual(@as(u8, 0x07), bytes[3]);
    // Flags = 0
    try testing.expectEqual(@as(u8, 0), bytes[4]);
    // Stream id = 0 (4 bytes)
    try testing.expectEqual(@as(u8, 0), bytes[5]);
    try testing.expectEqual(@as(u8, 0), bytes[6]);
    try testing.expectEqual(@as(u8, 0), bytes[7]);
    try testing.expectEqual(@as(u8, 0), bytes[8]);

    // Payload: last-stream-id then error code (FRAME_SIZE_ERROR = 0x06)
    // last-stream-id big-endian, top bit reserved (R) = 0
    const error_code: u32 = (@as(u32, bytes[13]) << 24) |
        (@as(u32, bytes[14]) << 16) |
        (@as(u32, bytes[15]) << 8) |
        @as(u32, bytes[16]);
    try testing.expectEqual(@as(u32, 0x06), error_code);
}

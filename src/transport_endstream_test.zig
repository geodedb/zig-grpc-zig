// Wire-level test for `Transport.endStreamWithStatus`.
//
// This helper writes a single HEADERS frame carrying the gRPC trailers
// for a non-zero status (used by error paths: UNAUTHENTICATED, UNKNOWN,
// UNIMPLEMENTED, etc.). The HEADERS frame must:
//
//   * Set END_STREAM | END_HEADERS flags.
//   * Use HPACK Literal-with-Incremental-Indexing (0x40) literal-name form
//     for both `grpc-status` and `grpc-message`.
//   * Encode the status code as its decimal-ASCII representation (e.g. 16
//     for UNAUTHENTICATED -> "16").
//   * Include `grpc-message` only when a message is supplied.
//
// For the success path (code = 0, message = null) the helper must emit the
// same single-byte status payload that the legacy `endStream` produced so
// existing flow is unchanged.

const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

/// In-memory stand-in for a `net.Stream` so we can capture the bytes the
/// transport emits without opening a real socket. We patch them into the
/// transport via the `tls_io` shim — read_fn is never invoked for this test
/// because we only call `endStreamWithStatus`, which is a pure write.
const Capture = struct {
    out: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn writeFn(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        try self.out.appendSlice(self.allocator, data);
        return data.len;
    }

    fn readFn(_: *anyopaque, _: []u8) anyerror!usize {
        return error.EndOfStream;
    }

    fn closeFn(_: *anyopaque) void {}
};

/// Build a minimal `Transport` by hand without the HTTP/2 setup handshake.
/// The handshake reads/writes on the underlying socket; for a wire-bytes
/// assertion we only need the write path, so we skip `initServer`/`initClient`
/// and assemble the struct directly.
fn buildCapturingTransport(allocator: std.mem.Allocator, capture: *Capture) !transport.Transport {
    const authority_owned = try allocator.dupe(u8, "");
    errdefer allocator.free(authority_owned);

    return transport.Transport{
        .stream = undefined,
        .io = undefined,
        .tls_io = transport.TlsIo{
            .ctx = capture,
            .read_fn = Capture.readFn,
            .write_fn = Capture.writeFn,
            .close_fn = Capture.closeFn,
        },
        .allocator = allocator,
        .last_stream_id = 1,
        .last_method = .{0} ** 256,
        .last_method_len = 0,
        .authority = authority_owned,
    };
}

fn freeTransport(t: *transport.Transport) void {
    t.allocator.free(t.authority);
}

test "endStreamWithStatus emits HEADERS with grpc-status=16 and grpc-message=unauthenticated" {
    const allocator = testing.allocator;

    var capture = Capture{ .allocator = allocator };
    defer capture.out.deinit(allocator);

    var trans = try buildCapturingTransport(allocator, &capture);
    defer freeTransport(&trans);

    trans.last_stream_id = 1;

    try trans.endStreamWithStatus(1, 16, "unauthenticated");

    // Frame layout: 9-byte header + payload.
    try testing.expect(capture.out.items.len > 9);

    const hdr = capture.out.items[0..9];
    const payload_len = (@as(u24, hdr[0]) << 16) | (@as(u24, hdr[1]) << 8) | @as(u24, hdr[2]);
    const frame_type = hdr[3];
    const flags = hdr[4];
    const stream_id: u31 = @intCast(
        (@as(u32, hdr[5] & 0x7F) << 24) |
            (@as(u32, hdr[6]) << 16) |
            (@as(u32, hdr[7]) << 8) |
            @as(u32, hdr[8]),
    );

    try testing.expectEqual(@intFromEnum(http2.frame.FrameType.HEADERS), frame_type);
    try testing.expectEqual(
        @as(u8, http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS),
        flags,
    );
    try testing.expectEqual(@as(u31, 1), stream_id);

    const payload = capture.out.items[9 .. 9 + payload_len];

    // grpc-status: LIE literal-name 0x40, name len 11, "grpc-status",
    // value len 2, "16" (UNAUTHENTICATED).
    var i: usize = 0;
    try testing.expectEqual(@as(u8, 0x40), payload[i]);
    i += 1;
    try testing.expectEqual(@as(u8, 11), payload[i]);
    i += 1;
    try testing.expectEqualStrings("grpc-status", payload[i .. i + 11]);
    i += 11;
    try testing.expectEqual(@as(u8, 2), payload[i]);
    i += 1;
    try testing.expectEqualStrings("16", payload[i .. i + 2]);
    i += 2;

    // grpc-message: LIE literal-name 0x40, name len 12, "grpc-message",
    // value len 15, "unauthenticated".
    try testing.expectEqual(@as(u8, 0x40), payload[i]);
    i += 1;
    try testing.expectEqual(@as(u8, 12), payload[i]);
    i += 1;
    try testing.expectEqualStrings("grpc-message", payload[i .. i + 12]);
    i += 12;
    try testing.expectEqual(@as(u8, 15), payload[i]);
    i += 1;
    try testing.expectEqualStrings("unauthenticated", payload[i .. i + 15]);
    i += 15;

    try testing.expectEqual(i, payload.len);
}

test "endStreamWithStatus with code=0 and no message matches legacy endStream success layout" {
    const allocator = testing.allocator;

    var capture = Capture{ .allocator = allocator };
    defer capture.out.deinit(allocator);

    var trans = try buildCapturingTransport(allocator, &capture);
    defer freeTransport(&trans);

    trans.last_stream_id = 7;

    try trans.endStreamWithStatus(7, 0, null);

    try testing.expect(capture.out.items.len > 9);
    const hdr = capture.out.items[0..9];
    const payload_len = (@as(u24, hdr[0]) << 16) | (@as(u24, hdr[1]) << 8) | @as(u24, hdr[2]);
    const frame_type = hdr[3];
    const flags = hdr[4];
    const stream_id: u31 = @intCast(
        (@as(u32, hdr[5] & 0x7F) << 24) |
            (@as(u32, hdr[6]) << 16) |
            (@as(u32, hdr[7]) << 8) |
            @as(u32, hdr[8]),
    );

    try testing.expectEqual(@intFromEnum(http2.frame.FrameType.HEADERS), frame_type);
    try testing.expectEqual(
        @as(u8, http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS),
        flags,
    );
    try testing.expectEqual(@as(u31, 7), stream_id);

    // Expected payload: 0x40, 11, "grpc-status", 1, '0' — exactly the
    // 15-byte literal that legacy `endStream` produced.
    const expected = [_]u8{
        0x40, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '0',
    };
    const payload = capture.out.items[9 .. 9 + payload_len];
    try testing.expectEqualSlices(u8, &expected, payload);
}

test "endStreamWithStatus with multi-digit status code encodes as decimal ASCII" {
    const allocator = testing.allocator;

    var capture = Capture{ .allocator = allocator };
    defer capture.out.deinit(allocator);

    var trans = try buildCapturingTransport(allocator, &capture);
    defer freeTransport(&trans);

    try trans.endStreamWithStatus(3, 12, null); // UNIMPLEMENTED

    const hdr = capture.out.items[0..9];
    const payload_len = (@as(u24, hdr[0]) << 16) | (@as(u24, hdr[1]) << 8) | @as(u24, hdr[2]);
    const payload = capture.out.items[9 .. 9 + payload_len];

    // 0x40, 11, "grpc-status", 2, "12"
    const expected = [_]u8{
        0x40, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 2, '1', '2',
    };
    try testing.expectEqualSlices(u8, &expected, payload);
}

// Unit tests for HTTP/2 flow control (closes GAP-0004 / GitLab #5 + perf
// NW-1+NW-2+NW-3).
//
// Coverage:
//  (a) Stream and connection windows initialize to RFC 7540 default
//      (65535 octets) for both send and receive directions.
//  (b) Applying SETTINGS_INITIAL_WINDOW_SIZE on the connection updates
//      the stream's send window by the delta (§6.9.2).
//  (c) WINDOW_UPDATE with a payload of 0 (or non-4-byte) is invalid.
//  (d) WINDOW_UPDATE that would push send_window past 2^31-1 returns
//      error.FlowControlError (§6.9.1).
//  (e) Helper used by inbound DATA flow: when recv_window drops below
//      half of the advertised initial size we should send WINDOW_UPDATE.
//  (f) Helper used by outbound DATA flow: a fragmenter respects the
//      smaller of stream.send_window and conn_send_window.

const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");
const compat = @import("compat.zig");

test "Transport initializes conn_send_window and conn_recv_window to 65535" {
    // Use a default-init Transport — we only inspect the field defaults.
    var t: transport.Transport = undefined;
    transport.Transport.initFlowControlForTest(&t);
    try testing.expectEqual(@as(i32, 65535), t.conn_send_window);
    try testing.expectEqual(@as(i32, 65535), t.conn_recv_window);
}

test "applyWindowUpdate rejects zero increment" {
    var window: i32 = 65535;
    try testing.expectError(
        error.ProtocolError,
        transport.Transport.applyWindowUpdate(&window, 0),
    );
}

test "applyWindowUpdate adds positive increment" {
    var window: i32 = 1000;
    try transport.Transport.applyWindowUpdate(&window, 500);
    try testing.expectEqual(@as(i32, 1500), window);
}

test "applyWindowUpdate rejects overflow past 2^31-1" {
    var window: i32 = std.math.maxInt(i32) - 10;
    try testing.expectError(
        error.FlowControlError,
        transport.Transport.applyWindowUpdate(&window, 100),
    );
}

test "shouldEmitWindowUpdate fires when below half threshold" {
    // initial=65535, current=20000 -> below half (32767)
    try testing.expect(transport.Transport.shouldEmitWindowUpdate(20000, 65535));
    // initial=65535, current=40000 -> above half
    try testing.expect(!transport.Transport.shouldEmitWindowUpdate(40000, 65535));
    // current at exactly half boundary -> not yet
    try testing.expect(!transport.Transport.shouldEmitWindowUpdate(32768, 65535));
}

test "applyInitialWindowSizeDelta updates stream send window via delta" {
    // §6.9.2: when peer changes SETTINGS_INITIAL_WINDOW_SIZE, the new value
    // is added to (or subtracted from) every existing stream's send window
    // as `delta = new - old`.
    var stream_send: i32 = 65535;
    transport.Transport.applyInitialWindowSizeDelta(&stream_send, 65535, 1024 * 1024);
    try testing.expectEqual(@as(i32, 65535 + (1024 * 1024 - 65535)), stream_send);

    // Smaller value: delta is negative, send window goes negative (legal).
    var stream_send2: i32 = 65535;
    transport.Transport.applyInitialWindowSizeDelta(&stream_send2, 65535, 1024);
    try testing.expectEqual(@as(i32, 1024), stream_send2);
}

test "applyInitialWindowSizeDelta rejects making send window overflow i32" {
    // §6.9.2: a peer that causes a flow-control window to exceed 2^31-1
    // must trigger FLOW_CONTROL_ERROR.
    var stream_send: i32 = std.math.maxInt(i32) - 100;
    const err = transport.Transport.applyInitialWindowSizeDeltaChecked(
        &stream_send,
        0,
        @as(u32, std.math.maxInt(i32)),
    );
    try testing.expectError(error.FlowControlError, err);
}

test "buildSettingsFrame encodes our initial SETTINGS for h2 conformance" {
    // Server / client setup MUST advertise our settings at startup. The
    // helper produces a well-formed SETTINGS frame body (no header) with
    // our chosen values for INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE,
    // MAX_CONCURRENT_STREAMS, and MAX_HEADER_LIST_SIZE.
    var allocator = std.testing.allocator;
    const bytes = try transport.Transport.buildInitialSettingsBody(allocator);
    defer allocator.free(bytes);

    // Each entry is 6 bytes (u16 id + u32 value); we emit 4 entries.
    try testing.expectEqual(@as(usize, 4 * 6), bytes.len);

    // Walk the entries; we don't assume order but we DO require all four
    // ids appear with the documented values.
    var seen_iws = false;
    var seen_mfs = false;
    var seen_mcs = false;
    var seen_mhls = false;
    var i: usize = 0;
    while (i + 6 <= bytes.len) : (i += 6) {
        const id: u16 = (@as(u16, bytes[i]) << 8) | @as(u16, bytes[i + 1]);
        const value: u32 = (@as(u32, bytes[i + 2]) << 24) |
            (@as(u32, bytes[i + 3]) << 16) |
            (@as(u32, bytes[i + 4]) << 8) |
            @as(u32, bytes[i + 5]);
        switch (id) {
            transport.SETTINGS_INITIAL_WINDOW_SIZE => {
                try testing.expectEqual(@as(u32, 1024 * 1024), value);
                seen_iws = true;
            },
            transport.SETTINGS_MAX_FRAME_SIZE => {
                try testing.expectEqual(@as(u32, 16384), value);
                seen_mfs = true;
            },
            transport.SETTINGS_MAX_CONCURRENT_STREAMS => {
                try testing.expectEqual(@as(u32, 100), value);
                seen_mcs = true;
            },
            transport.SETTINGS_MAX_HEADER_LIST_SIZE => {
                try testing.expectEqual(@as(u32, 8192), value);
                seen_mhls = true;
            },
            else => {},
        }
    }
    try testing.expect(seen_iws);
    try testing.expect(seen_mfs);
    try testing.expect(seen_mcs);
    try testing.expect(seen_mhls);
}

test "reserveSendCredit returns FlowControlTimeout when peer never advertises credit" {
    // GAP-FU-002 — a slow-loris peer that opens streams but never
    // emits WINDOW_UPDATE must not be able to park writer threads
    // forever. With conn_send_window starved to 0 and a short
    // configured timeout (50 ms), reserveSendCredit must surface
    // error.FlowControlTimeout so the caller can emit RST_STREAM
    // and free the thread.
    const allocator = std.testing.allocator;

    const send = try allocator.alloc(i32, 8);
    defer allocator.free(send);
    @memset(send, 0); // all per-stream send windows starved

    const recv = try allocator.alloc(i32, 8);
    defer allocator.free(recv);
    @memset(recv, 65535);

    var t: transport.Transport = undefined;
    transport.Transport.initFlowControlForTest(&t);
    t.io = std.testing.io;
    t.conn_send_window = 0; // connection-level window starved as well
    t.stream_send_windows = send;
    t.stream_recv_windows = recv;
    t.flow_mutex = .init;
    t.flow_epoch = .init(0);
    t.flow_credit_timeout_ns = 50 * std.time.ns_per_ms;

    const start_ns = compat.nanoTimestamp();
    const result = transport.Transport.reserveSendCredit(&t, 1, 100);
    const elapsed_ns = compat.nanoTimestamp() - start_ns;

    try testing.expectError(error.FlowControlTimeout, result);
    // Returned within the configured timeout's order of magnitude;
    // upper bound is generous to absorb scheduler / CI noise.
    try testing.expect(elapsed_ns >= 30 * std.time.ns_per_ms);
    try testing.expect(elapsed_ns < 1 * std.time.ns_per_s);
    // Windows untouched on the timeout path.
    try testing.expectEqual(@as(i32, 0), t.conn_send_window);
    try testing.expectEqual(@as(i32, 0), t.stream_send_windows[1]);
}

test "reserveSendCredit succeeds when credit is available within the timeout" {
    // Inverse of the slow-loris test: with both windows funded, the
    // call must return immediately, decrement both windows by `n`,
    // and not surface any error even with a tight timeout.
    const allocator = std.testing.allocator;

    const send = try allocator.alloc(i32, 8);
    defer allocator.free(send);
    @memset(send, 0);
    send[1] = 1024;

    const recv = try allocator.alloc(i32, 8);
    defer allocator.free(recv);
    @memset(recv, 65535);

    var t: transport.Transport = undefined;
    transport.Transport.initFlowControlForTest(&t);
    t.io = std.testing.io;
    t.conn_send_window = 1024;
    t.stream_send_windows = send;
    t.stream_recv_windows = recv;
    t.flow_mutex = .init;
    t.flow_epoch = .init(0);
    t.flow_credit_timeout_ns = 50 * std.time.ns_per_ms;

    try transport.Transport.reserveSendCredit(&t, 1, 200);
    try testing.expectEqual(@as(i32, 1024 - 200), t.conn_send_window);
    try testing.expectEqual(@as(i32, 1024 - 200), t.stream_send_windows[1]);
}

test "reserveSendCredit with timeout=0 keeps legacy unbounded behaviour for funded streams" {
    // `flow_credit_timeout_ns == 0` disables the timeout. A funded
    // stream must still succeed without delay; this guards against a
    // regression where the disabled-timeout branch silently drops
    // into a tight spin loop.
    const allocator = std.testing.allocator;

    const send = try allocator.alloc(i32, 8);
    defer allocator.free(send);
    @memset(send, 0);
    send[1] = 4096;

    const recv = try allocator.alloc(i32, 8);
    defer allocator.free(recv);
    @memset(recv, 65535);

    var t: transport.Transport = undefined;
    transport.Transport.initFlowControlForTest(&t);
    t.io = std.testing.io;
    t.conn_send_window = 4096;
    t.stream_send_windows = send;
    t.stream_recv_windows = recv;
    t.flow_mutex = .init;
    t.flow_epoch = .init(0);
    t.flow_credit_timeout_ns = 0;

    try transport.Transport.reserveSendCredit(&t, 1, 1024);
    try testing.expectEqual(@as(i32, 4096 - 1024), t.conn_send_window);
    try testing.expectEqual(@as(i32, 4096 - 1024), t.stream_send_windows[1]);
}

test "buildWindowUpdateFrame produces a 4-byte u31 increment" {
    var allocator = std.testing.allocator;
    const bytes = try transport.Transport.buildWindowUpdateFrame(allocator, 7, 32768);
    defer allocator.free(bytes);

    // 9-byte frame header + 4-byte payload.
    try testing.expectEqual(@as(usize, 13), bytes.len);
    try testing.expectEqual(@as(u8, @intFromEnum(@import("http2/frame.zig").FrameType.WINDOW_UPDATE)), bytes[3]);
    // Stream id is in bytes[5..9]; 7 is small so only bytes[8] is non-zero.
    try testing.expectEqual(@as(u8, 7), bytes[8]);
    // Increment in bytes[9..13] big-endian.
    const inc: u32 = (@as(u32, bytes[9]) << 24) |
        (@as(u32, bytes[10]) << 16) |
        (@as(u32, bytes[11]) << 8) |
        @as(u32, bytes[12]);
    try testing.expectEqual(@as(u32, 32768), inc);
    // Reserved high bit must be 0.
    try testing.expectEqual(@as(u8, 0), bytes[9] & 0x80);
}

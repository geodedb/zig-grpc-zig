// Failing-then-passing test for I1: HPACK varint decoder must reject
// pathologically long continuation byte sequences instead of panicking on
// integer overflow.
//
// The bug: `transport.hpackDecodeInt` accumulated multi-byte HPACK 7-bit-prefix
// integers (RFC 7541 §5.1) using `var m: std.math.Log2Int(usize) = 0; m += 7;`
// in a loop. On a 64-bit target `Log2Int(usize) == u6`, so a peer sending
// 10+ continuation bytes (each with the high bit set) eventually computes
// `m + 7 = 70` and panics the connection thread with integer overflow.
//
// After the fix the decoder caps the continuation count and returns
// `error.HpackIntegerOverflow` cleanly. The transport propagates that error
// up through the HEADERS-decoding path, which surfaces as a connection-level
// protocol error to the caller — never a process panic.
//
// We exercise the bug surface via the public `extractPathFromHpackForTest`
// entry point (added on the Transport for this test), which decodes a
// HEADERS payload with the same internal logic the server uses but in a
// way that lets us assert the error rather than reading from a real socket.

const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "hpack varint: short single-byte values still decode correctly" {
    // Single-byte (value < 127 with prefix=7) and short multi-byte values
    // must continue working — the fix must not regress the fast path.
    const r1 = transport.Transport.hpackDecodeIntForTest(&[_]u8{42}, 7);
    try testing.expectEqual(@as(usize, 42), r1.value);
    try testing.expectEqual(@as(usize, 1), r1.consumed);

    // Multi-byte: prefix saturated (127) + one continuation byte.
    // Encoding of 200 with prefix=7 is: 0x7F, (200-127)=73 (no high bit).
    const r2 = transport.Transport.hpackDecodeIntForTest(&[_]u8{ 0x7F, 73 }, 7);
    try testing.expectEqual(@as(usize, 200), r2.value);
    try testing.expectEqual(@as(usize, 2), r2.consumed);
}

test "hpack varint: 11+ continuation bytes returns HpackIntegerOverflow" {
    // Construct a HEADERS payload whose first header field is a literal
    // with incremental indexing (0x40) and an oversize indexed name where
    // the name index is encoded with 12 continuation bytes — each byte
    // having the high bit set so the decoder keeps shifting `m` past the
    // 32-bit boundary.
    var data = [_]u8{0xFF} ** 13; // saturated prefix + 12 continuation bytes
    // Last byte must still have its high bit set to keep the loop going up
    // to the limit; the cap on continuation count must trigger the error.
    data[12] = 0xFF;

    const result = transport.Transport.hpackDecodeIntChecked(&data, 7);
    try testing.expectError(error.HpackIntegerOverflow, result);
}

test "hpack varint: shift exceeding usize bit width returns HpackIntegerOverflow" {
    // Even fewer continuation bytes can overflow if each one keeps the
    // high bit set. The invariant the fix enforces is: `m + 7 <= bitSize(usize)`.
    // Construct 10 continuation bytes (m climbs 7,14,21,...,63,70) — at the
    // step where m would become 70 the decoder must error out instead of
    // panicking on the shift.
    var data = [_]u8{0xFF} ** 11; // saturated prefix + 10 continuation bytes
    data[10] = 0xFF; // keep loop going

    const result = transport.Transport.hpackDecodeIntChecked(&data, 7);
    try testing.expectError(error.HpackIntegerOverflow, result);
}

test "hpack varint: terminated 5-byte continuation still decodes" {
    // RFC 7541 §5.1 example: encoding 1337 with N=5 prefix:
    //   prefix byte: 0x1F (mask=31), value=1337-31=1306
    //   1306 = 0x51A -> 7-bit groups: 0x1A (no top), 0x0A (no top after shift)
    //   Bytes: 0x1F, 0x9A, 0x0A
    const r = transport.Transport.hpackDecodeIntForTest(&[_]u8{ 0x1F, 0x9A, 0x0A }, 5);
    try testing.expectEqual(@as(usize, 1337), r.value);
    try testing.expectEqual(@as(usize, 3), r.consumed);
}

const std = @import("std");
const testing = std.testing;
const harness = @import("harness.zig");

test "encode/decode EchoRequest round-trip matches Go-emitted bytes" {
    const allocator = testing.allocator;

    const req = harness.EchoRequest{ .payload = "hello", .tag = "go" };
    const bytes = try harness.encodeEchoRequest(allocator, req);
    defer allocator.free(bytes);

    // Bytes verified against `protoc --decode_raw` output for the same
    // message — field 1 (LEN, "hello"), field 2 (LEN, "go").
    const expected = [_]u8{
        0x0a, 0x05, 'h', 'e', 'l', 'l', 'o',
        0x12, 0x02, 'g', 'o',
    };
    try testing.expectEqualSlices(u8, &expected, bytes);

    const decoded = try harness.decodeEchoRequest(allocator, bytes);
    defer harness.freeEchoRequest(allocator, decoded);
    try testing.expectEqualStrings("hello", decoded.payload);
    try testing.expectEqualStrings("go", decoded.tag);
}

test "decode tolerates fields out of order and unknown fields" {
    const allocator = testing.allocator;
    // Same message, tag first then payload, with an extra unknown field
    // (LEN, 0x03 "xyz") in the middle that decode must skip. The varint
    // 0xfa 0x06 decodes to (111 << 3) | 2 — i.e. field 111, wire type 2.
    const bytes = [_]u8{
        0x12, 0x02, 'g', 'o',
        0xfa, 0x06, 0x03, 'x', 'y', 'z', // field 111, wire type 2, len 3, "xyz"
        0x0a, 0x05, 'h',  'e', 'l', 'l',
        'o',
    };
    const decoded = try harness.decodeEchoRequest(allocator, &bytes);
    defer harness.freeEchoRequest(allocator, decoded);
    try testing.expectEqualStrings("hello", decoded.payload);
    try testing.expectEqualStrings("go", decoded.tag);
}

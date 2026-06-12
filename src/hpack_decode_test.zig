const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

// RFC 7541 §C.4 / §C.6 Huffman-coded literal values. The existing
// printable-ASCII group table must decode all of these exactly.

test "RFC 7541 C.4.1: huffman 'www.example.com'" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "www.example.com", out[0..n]);
}

test "RFC 7541 C.4.2: huffman 'no-cache'" {
    const encoded = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "no-cache", out[0..n]);
}

test "RFC 7541 C.6.1: huffman date 'Mon, 21 Oct 2013 20:13:21 GMT'" {
    const encoded = [_]u8{
        0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95,
        0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
    };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "Mon, 21 Oct 2013 20:13:21 GMT", out[0..n]);
}

test "RFC 7541 C.6.1: huffman 'https://www.example.com'" {
    const encoded = [_]u8{
        0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9,
        0xae, 0x82, 0xae, 0x43, 0xd3,
    };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "https://www.example.com", out[0..n]);
}

test "I2: EOS symbol / all-ones run in body is a decode error" {
    const encoded = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    var out: [16]u8 = undefined;
    try testing.expectError(
        transport.TransportError.HuffmanDecodeError,
        transport.Transport.huffmanDecodeChecked(&encoded, &out),
    );
}

test "I2: valid trailing padding (all-ones partial byte) is accepted" {
    // 'o' = code 0x07 @ 5 bits -> 0b00111 then 3 padding one-bits = 0x3f.
    const encoded = [_]u8{0x3f};
    var out: [4]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "o", out[0..n]);
}

test "I2: output-buffer overflow is a decode error, not silent truncation" {
    // 'www.example.com' needs 15 bytes; give a 4-byte out buffer.
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [4]u8 = undefined;
    try testing.expectError(
        transport.TransportError.HuffmanDecodeError,
        transport.Transport.huffmanDecodeChecked(&encoded, &out),
    );
}

test "T1: hpack dynamic table push/get roundtrip" {
    var t: transport.Transport = undefined;
    t.hpack_dyn_count = 0;
    t.hpack_dyn_head = 0;
    t.hpack_dyn = [_]transport.Transport.HpackDynEntryForTest{.{}} ** 128;
    t.last_method = .{0} ** 256;
    @memcpy(t.last_method[0..5], "/a.B/");
    t.last_method_len = 5;
    t.hpackDynPushForTest(true);
    const e = t.hpackDynGetForTest(0).?;
    try testing.expect(e.is_path);
    try testing.expectEqualSlices(u8, "/a.B/", e.path[0..e.path_len]);
}

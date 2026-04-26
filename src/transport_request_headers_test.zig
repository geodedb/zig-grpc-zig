// Failing reproduction test for the client request HEADERS bug.
//
// Bug: `Transport.writeMessage` and `Transport.writeMessageOnStream` in
// `src/transport.zig` emit SERVER-RESPONSE-shaped HPACK HEADERS
// (`:status: 200`, `content-type: application/grpc`) regardless of caller.
// When the client write path uses these functions to start an outbound
// request, a real gRPC server (e.g. the `go × zig` interop pair) rejects
// the response-shaped HEADERS and the connection is torn down with
// `error.ConnectionClosed`.
//
// The fix introduces an encoder-only API (planned name:
// `transport.writeRequestHeaders(allocator, method_path, authority) ![]u8`)
// that emits a request-shaped HEADERS payload:
//
//   :method   POST                 -> 0x83        (HPACK static index 3, indexed)
//   :scheme   http                 -> 0x86        (HPACK static index 6, indexed)
//   :path     <method_path>        -> 0x44 <vlen> <bytes>  (LIE name index 4)
//   :authority <authority>         -> 0x41 <vlen> <bytes>  (LIE name index 1)
//   content-type application/grpc -> 0x5f <vlen> <bytes>  (LIE name index 31)
//   te        trailers             -> 0x40 0x02 't' 'e' 0x08 'trailers'
//
// This test asserts the byte-level structure of the encoder output. It
// MUST fail before the fix (with "no member named writeRequestHeaders"
// or equivalent) and pass after.

const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "writeRequestHeaders emits request-shaped HPACK for echo call" {
    const allocator = testing.allocator;

    const method_path = "/interop.Interop/Echo";
    const authority = "127.0.0.1:50064";

    const bytes = try transport.writeRequestHeaders(allocator, method_path, authority);
    defer allocator.free(bytes);

    var i: usize = 0;

    // (1) :method POST -> indexed static index 3 -> 0x80 | 3 = 0x83
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x83), bytes[i]);
    i += 1;

    // (2) :scheme http -> indexed static index 6 -> 0x80 | 6 = 0x86
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x86), bytes[i]);
    i += 1;

    // (3) :path <method_path> -> Literal-with-Incremental-Indexing,
    //     name index 4 -> 0x40 | 4 = 0x44, then varint length,
    //     then literal value bytes (no Huffman).
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x44), bytes[i]);
    i += 1;

    try testing.expect(bytes.len > i);
    // method_path.len = 21 which fits in a 7-bit prefix varint -> 0x15
    try testing.expectEqual(@as(u8, @intCast(method_path.len)), bytes[i]);
    i += 1;

    try testing.expect(bytes.len >= i + method_path.len);
    try testing.expectEqualStrings(method_path, bytes[i .. i + method_path.len]);
    i += method_path.len;

    // (4) :authority <authority> -> LIE name index 1 -> 0x40 | 1 = 0x41
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x41), bytes[i]);
    i += 1;

    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, @intCast(authority.len)), bytes[i]);
    i += 1;

    try testing.expect(bytes.len >= i + authority.len);
    try testing.expectEqualStrings(authority, bytes[i .. i + authority.len]);
    i += authority.len;

    // (5) content-type application/grpc -> LIE name index 31 -> 0x40 | 31 = 0x5f
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x5f), bytes[i]);
    i += 1;

    const ctype_value = "application/grpc";
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, @intCast(ctype_value.len)), bytes[i]);
    i += 1;

    try testing.expect(bytes.len >= i + ctype_value.len);
    try testing.expectEqualStrings(ctype_value, bytes[i .. i + ctype_value.len]);
    i += ctype_value.len;

    // (6) te trailers -> LIE with literal name (name-index 0): 0x40,
    //     then name "te" (len 2), then value "trailers" (len 8).
    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x40), bytes[i]);
    i += 1;

    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x02), bytes[i]);
    i += 1;

    try testing.expect(bytes.len >= i + 2);
    try testing.expectEqualStrings("te", bytes[i .. i + 2]);
    i += 2;

    try testing.expect(bytes.len > i);
    try testing.expectEqual(@as(u8, 0x08), bytes[i]);
    i += 1;

    try testing.expect(bytes.len >= i + 8);
    try testing.expectEqualStrings("trailers", bytes[i .. i + 8]);
    i += 8;

    // Encoder must emit EXACTLY this header set, nothing more.
    try testing.expectEqual(i, bytes.len);
}

test "writeRequestHeaders does not emit response-shaped :status or response content-type prefix" {
    // Regression guard: the old (buggy) code path emitted 0x88 (`:status 200`,
    // static index 8) as the very first byte. Make sure that byte never
    // appears in the request-shaped output.
    const allocator = testing.allocator;
    const bytes = try transport.writeRequestHeaders(
        allocator,
        "/interop.Interop/Echo",
        "127.0.0.1:50064",
    );
    defer allocator.free(bytes);

    try testing.expect(bytes.len > 0);
    try testing.expect(bytes[0] != 0x88);
}

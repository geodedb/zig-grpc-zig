const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "encodeGrpcPrefix writes flag 0 and big-endian length" {
    var buf: [5]u8 = undefined;
    transport.encodeGrpcPrefix(&buf, 0x01020304);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0x01, 0x02, 0x03, 0x04 }, &buf);
}

test "decodeGrpcPrefix roundtrips" {
    var buf: [5]u8 = undefined;
    transport.encodeGrpcPrefix(&buf, 42);
    const p = try transport.decodeGrpcPrefix(&buf);
    try testing.expectEqual(@as(u32, 42), p.msg_len);
    try testing.expectEqual(false, p.compressed);
}

test "decodeGrpcPrefix accepts compressed flag 1" {
    const buf = [_]u8{ 1, 0, 0, 0, 7 };
    const p = try transport.decodeGrpcPrefix(&buf);
    try testing.expectEqual(@as(u32, 7), p.msg_len);
    try testing.expectEqual(true, p.compressed);
}

test "decodeGrpcPrefix rejects invalid compression flag (I6)" {
    const buf = [_]u8{ 0xFF, 0, 0, 0, 1 };
    try testing.expectError(error.InvalidGrpcPrefix, transport.decodeGrpcPrefix(&buf));
}

test "decodeGrpcPrefix rejects short input" {
    const buf = [_]u8{ 0, 0 };
    try testing.expectError(error.InvalidGrpcPrefix, transport.decodeGrpcPrefix(&buf));
}

test "OK_TRAILERS_BYTES encodes grpc-status 0" {
    try testing.expectEqual(@as(usize, 15), transport.OK_TRAILERS_BYTES.len);
    try testing.expectEqual(@as(u8, 0x40), transport.OK_TRAILERS_BYTES[0]);
    try testing.expectEqualSlices(u8, "grpc-status", transport.OK_TRAILERS_BYTES[2..13]);
    try testing.expectEqual(@as(u8, '0'), transport.OK_TRAILERS_BYTES[14]);
}

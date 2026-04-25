//! Minimal proto3 wire codec for the interop EchoRequest/EchoResponse
//! messages. Only handles wire type 2 (LEN) for `bytes` and `string`
//! fields 1 and 2. Unknown fields are skipped on decode.

const std = @import("std");

pub const EchoRequest = struct {
    payload: []const u8 = "",
    tag: []const u8 = "",
};

pub const EchoResponse = struct {
    payload: []const u8 = "",
    tag: []const u8 = "",
};

const FIELD_PAYLOAD = 1;
const FIELD_TAG = 2;

const WIRE_VARINT = 0;
const WIRE_FIXED64 = 1;
const WIRE_LEN = 2;
const WIRE_FIXED32 = 5;

fn writeVarint(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try buf.append(allocator, @as(u8, @intCast(v & 0x7f)) | 0x80);
        v >>= 7;
    }
    try buf.append(allocator, @as(u8, @intCast(v)));
}

fn writeLenField(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, field_no: u32, data: []const u8) !void {
    const tag: u64 = (@as(u64, field_no) << 3) | WIRE_LEN;
    try writeVarint(buf, allocator, tag);
    try writeVarint(buf, allocator, @intCast(data.len));
    try buf.appendSlice(allocator, data);
}

pub fn encodeEchoRequest(allocator: std.mem.Allocator, req: EchoRequest) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    if (req.payload.len > 0) try writeLenField(&buf, allocator, FIELD_PAYLOAD, req.payload);
    if (req.tag.len > 0) try writeLenField(&buf, allocator, FIELD_TAG, req.tag);
    return buf.toOwnedSlice(allocator);
}

pub fn encodeEchoResponse(allocator: std.mem.Allocator, resp: EchoResponse) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    if (resp.payload.len > 0) try writeLenField(&buf, allocator, FIELD_PAYLOAD, resp.payload);
    if (resp.tag.len > 0) try writeLenField(&buf, allocator, FIELD_TAG, resp.tag);
    return buf.toOwnedSlice(allocator);
}

const DecodeError = error{ Truncated, UnsupportedWireType };

fn readVarint(bytes: []const u8, pos: *usize) !u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < bytes.len) {
        const b = bytes[pos.*];
        pos.* += 1;
        v |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return v;
        shift += 7;
        if (shift >= 64) return DecodeError.Truncated;
    }
    return DecodeError.Truncated;
}

fn skipField(bytes: []const u8, pos: *usize, wire_type: u3) !void {
    switch (wire_type) {
        WIRE_VARINT => _ = try readVarint(bytes, pos),
        WIRE_FIXED64 => {
            if (pos.* + 8 > bytes.len) return DecodeError.Truncated;
            pos.* += 8;
        },
        WIRE_LEN => {
            const len = try readVarint(bytes, pos);
            if (pos.* + len > bytes.len) return DecodeError.Truncated;
            pos.* += @intCast(len);
        },
        WIRE_FIXED32 => {
            if (pos.* + 4 > bytes.len) return DecodeError.Truncated;
            pos.* += 4;
        },
        else => return DecodeError.UnsupportedWireType,
    }
}

fn decodeEchoFields(allocator: std.mem.Allocator, bytes: []const u8, payload: *[]const u8, tag: *[]const u8) !void {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const tag_v = try readVarint(bytes, &pos);
        const field_no: u32 = @intCast(tag_v >> 3);
        const wire_type: u3 = @intCast(tag_v & 0x7);
        if (wire_type != WIRE_LEN or (field_no != FIELD_PAYLOAD and field_no != FIELD_TAG)) {
            try skipField(bytes, &pos, wire_type);
            continue;
        }
        const len = try readVarint(bytes, &pos);
        if (pos + len > bytes.len) return DecodeError.Truncated;
        const slice = try allocator.dupe(u8, bytes[pos .. pos + @as(usize, @intCast(len))]);
        pos += @intCast(len);
        switch (field_no) {
            FIELD_PAYLOAD => payload.* = slice,
            FIELD_TAG => tag.* = slice,
            else => unreachable,
        }
    }
}

pub fn decodeEchoRequest(allocator: std.mem.Allocator, bytes: []const u8) !EchoRequest {
    var payload: []const u8 = "";
    var tag: []const u8 = "";
    try decodeEchoFields(allocator, bytes, &payload, &tag);
    return .{ .payload = payload, .tag = tag };
}

pub fn decodeEchoResponse(allocator: std.mem.Allocator, bytes: []const u8) !EchoResponse {
    var payload: []const u8 = "";
    var tag: []const u8 = "";
    try decodeEchoFields(allocator, bytes, &payload, &tag);
    return .{ .payload = payload, .tag = tag };
}

pub fn freeEchoRequest(allocator: std.mem.Allocator, req: EchoRequest) void {
    if (req.payload.len > 0) allocator.free(req.payload);
    if (req.tag.len > 0) allocator.free(req.tag);
}

pub fn freeEchoResponse(allocator: std.mem.Allocator, resp: EchoResponse) void {
    if (resp.payload.len > 0) allocator.free(resp.payload);
    if (resp.tag.len > 0) allocator.free(resp.tag);
}

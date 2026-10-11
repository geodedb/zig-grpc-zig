//! Full RFC 7541 HPACK header-block decoder for the server's inbound
//! request path.
//!
//! `Transport.extractPathFromHpack` only scrapes `:path` / `authorization`
//! and keeps a placeholder dynamic table, so it cannot tell a malformed
//! request from a valid one. The server reader needs every field, with the
//! dynamic table tracked byte-for-byte, to apply the RFC 7540 §8.1.2 request
//! checks (pseudo-header rules, connection-specific headers, uppercase names,
//! content-length). Any decoding failure is a connection error of type
//! COMPRESSION_ERROR (RFC 7540 §4.3), surfaced as `error.CompressionError`.

const std = @import("std");
const transport = @import("transport.zig");

pub const Error = error{ CompressionError, OutOfMemory };

/// A decoded header field. `name` and `value` are owned by the allocator
/// passed to `Decoder.decode` (use an arena and free it in one go).
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

const StaticEntry = struct { name: []const u8, value: []const u8 };

/// RFC 7541 Appendix A.
const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// SETTINGS_HEADER_TABLE_SIZE we accept (we never advertise another value,
/// so the RFC default applies).
pub const DEFAULT_TABLE_SIZE: usize = 4096;

/// Cap on a single decoded string. Header blocks are already bounded by
/// `MAX_HEADER_BLOCK_BYTES`; this stops a Huffman string from expanding
/// past what any sane header could need.
const MAX_STRING_LEN: usize = 64 * 1024;

const DynEntry = struct {
    name: []u8,
    value: []u8,

    fn size(self: DynEntry) usize {
        return self.name.len + self.value.len + 32;
    }
};

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    /// Dynamic table, oldest first (index 62 is the LAST element).
    entries: std.ArrayList(DynEntry) = .empty,
    size: usize = 0,
    /// Current table size limit (set by dynamic table size updates).
    max_size: usize = DEFAULT_TABLE_SIZE,
    /// Upper bound the encoder may set via a size update — our
    /// SETTINGS_HEADER_TABLE_SIZE.
    settings_max_size: usize = DEFAULT_TABLE_SIZE,

    pub fn init(allocator: std.mem.Allocator) Decoder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Decoder) void {
        for (self.entries.items) |e| {
            self.allocator.free(e.name);
            self.allocator.free(e.value);
        }
        self.entries.deinit(self.allocator);
    }

    fn evictTo(self: *Decoder, limit: usize) void {
        while (self.size > limit and self.entries.items.len > 0) {
            const e = self.entries.orderedRemove(0);
            self.size -= e.size();
            self.allocator.free(e.name);
            self.allocator.free(e.value);
        }
    }

    fn add(self: *Decoder, name: []const u8, value: []const u8) Error!void {
        const entry_size = name.len + value.len + 32;
        if (entry_size > self.max_size) {
            // RFC 7541 §4.4: an entry larger than the table empties it.
            self.evictTo(0);
            return;
        }
        self.evictTo(self.max_size - entry_size);
        const n = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(n);
        const v = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(v);
        try self.entries.append(self.allocator, .{ .name = n, .value = v });
        self.size += entry_size;
    }

    fn lookup(self: *const Decoder, index: usize) Error!StaticEntry {
        if (index == 0) return error.CompressionError;
        if (index <= static_table.len) return static_table[index - 1];
        const dyn_idx = index - static_table.len - 1;
        if (dyn_idx >= self.entries.items.len) return error.CompressionError;
        const e = self.entries.items[self.entries.items.len - 1 - dyn_idx];
        return .{ .name = e.name, .value = e.value };
    }

    /// Decode a complete header block, appending fields to `out`. Field
    /// strings are allocated from `arena`.
    pub fn decode(
        self: *Decoder,
        block: []const u8,
        arena: std.mem.Allocator,
        out: *std.ArrayList(Field),
    ) Error!void {
        var pos: usize = 0;
        var seen_field = false;
        while (pos < block.len) {
            const b = block[pos];
            if (b & 0x80 != 0) {
                // §6.1 indexed header field.
                const idx = try decodeInt(block, &pos, 7);
                const e = try self.lookup(idx);
                try out.append(arena, .{ .name = try arena.dupe(u8, e.name), .value = try arena.dupe(u8, e.value) });
                seen_field = true;
            } else if (b & 0xC0 == 0x40) {
                // §6.2.1 literal with incremental indexing.
                const f = try self.decodeLiteral(block, &pos, 6, arena);
                try self.add(f.name, f.value);
                try out.append(arena, f);
                seen_field = true;
            } else if (b & 0xE0 == 0x20) {
                // §6.3 dynamic table size update: only at the start of a
                // block (§4.2) and never above our SETTINGS value.
                if (seen_field) return error.CompressionError;
                const new_size = try decodeInt(block, &pos, 5);
                if (new_size > self.settings_max_size) return error.CompressionError;
                self.max_size = new_size;
                self.evictTo(new_size);
            } else {
                // §6.2.2 without indexing (0000) / §6.2.3 never indexed (0001).
                const f = try self.decodeLiteral(block, &pos, 4, arena);
                try out.append(arena, f);
                seen_field = true;
            }
        }
    }

    fn decodeLiteral(
        self: *Decoder,
        block: []const u8,
        pos: *usize,
        comptime prefix: u4,
        arena: std.mem.Allocator,
    ) Error!Field {
        const name_idx = try decodeInt(block, pos, prefix);
        const name: []const u8 = if (name_idx == 0)
            try decodeString(block, pos, arena)
        else
            try arena.dupe(u8, (try self.lookup(name_idx)).name);
        const value = try decodeString(block, pos, arena);
        return .{ .name = name, .value = value };
    }
};

/// RFC 7541 §5.1 integer. Rejects truncated input and values that do not
/// fit comfortably in 32 bits.
fn decodeInt(block: []const u8, pos: *usize, comptime prefix: u4) Error!usize {
    if (pos.* >= block.len) return error.CompressionError;
    const mask: u8 = @intCast((@as(u16, 1) << prefix) - 1);
    var value: usize = block[pos.*] & mask;
    pos.* += 1;
    if (value < mask) return value;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= block.len) return error.CompressionError;
        if (shift > 28) return error.CompressionError;
        const b = block[pos.*];
        pos.* += 1;
        value += @as(usize, b & 0x7F) << shift;
        if (b & 0x80 == 0) break;
        shift += 7;
    }
    if (value > std.math.maxInt(u32)) return error.CompressionError;
    return value;
}

/// RFC 7541 §5.2 string literal (plain or Huffman).
fn decodeString(block: []const u8, pos: *usize, arena: std.mem.Allocator) Error![]const u8 {
    if (pos.* >= block.len) return error.CompressionError;
    const huffman = block[pos.*] & 0x80 != 0;
    const len = try decodeInt(block, pos, 7);
    if (len > MAX_STRING_LEN or len > block.len - pos.*) return error.CompressionError;
    const raw = block[pos.* .. pos.* + len];
    pos.* += len;
    if (!huffman) return arena.dupe(u8, raw);
    // The shortest Huffman code is 5 bits, so the output is at most
    // len * 8 / 5 bytes.
    const out = try arena.alloc(u8, (len * 8) / 5 + 1);
    const n = transport.Transport.huffmanDecodeChecked(raw, out) catch return error.CompressionError;
    return out[0..n];
}

test "hpack decoder: RFC 7541 C.3 requests without Huffman" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();

    // C.3.1
    const r1 = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x0f } ++ "www.example.com".*;
    var f1: std.ArrayList(Field) = .empty;
    try dec.decode(&r1, arena, &f1);
    try std.testing.expectEqual(@as(usize, 4), f1.items.len);
    try std.testing.expectEqualStrings(":method", f1.items[0].name);
    try std.testing.expectEqualStrings("GET", f1.items[0].value);
    try std.testing.expectEqualStrings(":authority", f1.items[3].name);
    try std.testing.expectEqualStrings("www.example.com", f1.items[3].value);
    try std.testing.expectEqual(@as(usize, 57), dec.size);

    // C.3.2 references the dynamic entry added above (index 62).
    const r2 = [_]u8{ 0x82, 0x86, 0x84, 0xbe, 0x58, 0x08 } ++ "no-cache".*;
    var f2: std.ArrayList(Field) = .empty;
    try dec.decode(&r2, arena, &f2);
    try std.testing.expectEqual(@as(usize, 5), f2.items.len);
    try std.testing.expectEqualStrings("www.example.com", f2.items[3].value);
    try std.testing.expectEqualStrings("cache-control", f2.items[4].name);
    try std.testing.expectEqual(@as(usize, 110), dec.size);
}

test "hpack decoder: RFC 7541 C.4.1 Huffman request" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();
    const r = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var f: std.ArrayList(Field) = .empty;
    try dec.decode(&r, arena_state.allocator(), &f);
    try std.testing.expectEqualStrings("www.example.com", f.items[3].value);
}

test "hpack decoder: invalid blocks are COMPRESSION_ERROR" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var dec = Decoder.init(std.testing.allocator);
    defer dec.deinit();
    var f: std.ArrayList(Field) = .empty;
    // Index 0 is never valid.
    try std.testing.expectError(error.CompressionError, dec.decode(&[_]u8{0x80}, arena_state.allocator(), &f));
    // Dynamic index that does not exist.
    try std.testing.expectError(error.CompressionError, dec.decode(&[_]u8{0xbe}, arena_state.allocator(), &f));
    // Truncated string literal.
    try std.testing.expectError(error.CompressionError, dec.decode(&[_]u8{ 0x40, 0x05, 'a' }, arena_state.allocator(), &f));
    // Table size update above SETTINGS_HEADER_TABLE_SIZE.
    try std.testing.expectError(error.CompressionError, dec.decode(&[_]u8{ 0x3f, 0xe2, 0x1f }, arena_state.allocator(), &f));
    // Table size update after a header field.
    try std.testing.expectError(error.CompressionError, dec.decode(&[_]u8{ 0x82, 0x20 }, arena_state.allocator(), &f));
}

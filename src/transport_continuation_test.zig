const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "I5: header fragments accumulate up to the bound" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "abc", 8);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "defgh", 8);
    try testing.expectEqualSlices(u8, "abcdefgh", buf.items);
}

test "I5: over-bound header block is a protocol error" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "abcd", 8);
    try testing.expectError(
        transport.TransportError.HeaderBlockTooLarge,
        transport.Transport.appendHeaderFragment(&buf, testing.allocator, "efghi", 8),
    );
}

test "I5: MAX_HEADER_BLOCK_BYTES matches advertised MAX_HEADER_LIST_SIZE" {
    try testing.expectEqual(@as(usize, 8192), transport.MAX_HEADER_BLOCK_BYTES);
}

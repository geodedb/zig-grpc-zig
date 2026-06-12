const std = @import("std");
const testing = std.testing;
const client_mux = @import("client_mux.zig");
const transport = @import("transport.zig");

// deliverData is the pure core of readerLoop's DATA handling: it appends
// a validated gRPC message into the slot and ALWAYS signals end_stream
// (with err set) on any failure so the waiting caller never deadlocks
// (closes quality R2 / #57).

test "R2: allocation failure sets err AND end_stream (no deadlock)" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);

    const payload = [_]u8{ 0, 0, 0, 0, 2, 'h', 'i' }; // prefix(5) + "hi"
    client_mux.deliverData(&slot, failing.allocator(), &payload, false, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);

    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream); // MUST be set or the caller hangs
}

test "deliverData appends message bytes on success" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    const payload = [_]u8{ 0, 0, 0, 0, 2, 'h', 'i' };
    client_mux.deliverData(&slot, testing.allocator, &payload, true, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
    try testing.expect(slot.err == null);
    try testing.expect(slot.end_stream);
    try testing.expectEqualSlices(u8, "hi", slot.data.items);
}

test "deliverData rejects invalid gRPC prefix (I6)" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    const payload = [_]u8{ 0xFF, 0, 0, 0, 1, 'x' };
    client_mux.deliverData(&slot, testing.allocator, &payload, false, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream);
}

test "NEW-1 client side: accumulated response beyond cap errors out" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    // Cap of 4 bytes; deliver a 3-byte message twice -> second must fail.
    const payload = [_]u8{ 0, 0, 0, 0, 3, 'a', 'b', 'c' };
    client_mux.deliverData(&slot, testing.allocator, &payload, false, 4);
    try testing.expect(slot.err == null);
    client_mux.deliverData(&slot, testing.allocator, &payload, false, 4);
    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream);
}

test "M2: nextStreamId detects u31 wraparound" {
    try testing.expectEqual(@as(u31, 5), try client_mux.nextStreamId(3));
    const last_odd: u31 = std.math.maxInt(u31); // 0x7FFFFFFF, odd
    try testing.expectError(error.StreamIdExhausted, client_mux.nextStreamId(last_odd));
    try testing.expectError(error.StreamIdExhausted, client_mux.nextStreamId(last_odd - 1));
}

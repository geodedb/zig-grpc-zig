const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "NEW-1: checkRecvMessageSize rejects msg_len above cap" {
    try testing.expectError(
        transport.TransportError.MessageTooLarge,
        transport.Transport.checkRecvMessageSize(
            transport.DEFAULT_MAX_RECV_MESSAGE_BYTES + 1,
            transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
        ),
    );
}

test "NEW-1: checkRecvMessageSize accepts msg_len at cap" {
    try transport.Transport.checkRecvMessageSize(
        transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
        transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
    );
}

test "NEW-1: default cap is 4 MiB (gRPC convention)" {
    try testing.expectEqual(@as(u32, 4 * 1024 * 1024), transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
}

test "NEW-1: cumulative buffer check rejects unbounded accumulation" {
    try testing.expectError(
        transport.TransportError.MessageTooLarge,
        transport.Transport.checkRecvBufferSize(
            @as(usize, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES) + 6,
            transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
        ),
    );
    try transport.Transport.checkRecvBufferSize(
        @as(usize, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES) + 5,
        transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
    );
}

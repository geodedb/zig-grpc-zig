const std = @import("std");
const transport = @import("transport.zig");
const net = std.Io.net;

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a TCP connection
    const address = try net.IpAddress.resolve(init.io, "localhost", 50051);
    const stream = try address.connect(init.io, .{ .mode = .stream });
    defer stream.close(init.io);

    // Initialize transport with HTTP/2
    var trans = try transport.Transport.initClient(allocator, init.io, stream, "localhost:50051");
    defer trans.deinit();

    // Send a message
    const message = "Hello over HTTP/2";
    try trans.writeMessage(message);

    // Read response
    const response = try trans.readMessage();
    defer allocator.free(response);

    std.debug.print("Received: {s}\n", .{response});
}

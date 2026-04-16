const std = @import("std");
const GrpcServer = @import("grpc").GrpcServer;
const proto = @import("proto.zig");

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const port = 50052; // Use different port to avoid conflicts
    var server = try GrpcServer.init(allocator, init.io, port, "test-secret-key");
    defer server.deinit();

    std.log.info("Integration test server starting on port {d}", .{port});

    // Register test handlers
    try server.handlers.append(
        allocator,
        .{
            .name = "Echo",
            .handler_fn = echoHandler,
        },
    );

    try server.handlers.append(
        allocator,
        .{
            .name = "CompressedEcho",
            .handler_fn = compressedEchoHandler,
        },
    );

    try server.handlers.append(
        allocator,
        .{
            .name = "HealthCheck",
            .handler_fn = healthCheckHandler,
        },
    );

    try server.handlers.append(
        allocator,
        .{
            .name = "SecureEcho",
            .handler_fn = secureEchoHandler,
        },
    );

    std.log.info("Test server ready with handlers: Echo, CompressedEcho, HealthCheck, SecureEcho", .{});

    try server.start();
}

fn getTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

fn echoHandler(request: []const u8, _: []const u8, trans: *@import("grpc").Transport, allocator: std.mem.Allocator) anyerror!void {
    const timestamp = getTimestamp();
    const response = try std.fmt.allocPrint(
        allocator,
        "Echo: {s} | Server: gRPC-zig | Time: {d}",
        .{ request, timestamp },
    );
    defer allocator.free(response);
    try trans.writeMessage(response);
}

fn compressedEchoHandler(request: []const u8, _: []const u8, trans: *@import("grpc").Transport, allocator: std.mem.Allocator) anyerror!void {
    const timestamp = getTimestamp();
    const response = try std.fmt.allocPrint(
        allocator,
        "CompressedEcho: {s} | Server: gRPC-zig | Time: {d}",
        .{ request, timestamp },
    );
    defer allocator.free(response);
    try trans.writeMessage(response);
}

fn healthCheckHandler(_: []const u8, _: []const u8, trans: *@import("grpc").Transport, _: std.mem.Allocator) anyerror!void {
    try trans.writeMessage("SERVING");
}

fn secureEchoHandler(request: []const u8, _: []const u8, trans: *@import("grpc").Transport, allocator: std.mem.Allocator) anyerror!void {
    const timestamp = getTimestamp();
    const response = try std.fmt.allocPrint(
        allocator,
        "SecureEcho: {s} | Server: gRPC-zig (authenticated) | Time: {d}",
        .{ request, timestamp },
    );
    defer allocator.free(response);
    try trans.writeMessage(response);
}

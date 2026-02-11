const std = @import("std");
const grpc = @import("grpc");
const GrpcServer = grpc.GrpcServer;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try GrpcServer.init(allocator, 50051, "secret-key");
    defer server.deinit();

    // Register handlers
    try server.handlers.append(
        allocator,
        .{
            .name = "SayHello",
            .handler_fn = sayHello,
        },
    );

    // Register benchmark handler
    try server.handlers.append(
        allocator,
        .{
            .name = "Benchmark",
            .handler_fn = benchmarkHandler,
        },
    );

    try server.start();
}

fn sayHello(_: []const u8, _: []const u8, trans: *grpc.Transport, _: std.mem.Allocator) anyerror!void {
    try trans.writeMessage("Hello from gRPC!");
}

fn benchmarkHandler(request: []const u8, _: []const u8, trans: *grpc.Transport, allocator: std.mem.Allocator) anyerror!void {
    const response = try std.fmt.allocPrint(allocator, "Echo: {s} (processed at {d})", .{ request, std.time.milliTimestamp() });
    defer allocator.free(response);
    try trans.writeMessage(response);
}

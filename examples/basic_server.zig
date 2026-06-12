const std = @import("std");
const grpc = @import("grpc");
const GrpcServer = grpc.GrpcServer;

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try GrpcServer.init(allocator, init.io, 50051, "secret-key");
    defer server.deinit();

    // Register handlers
    try server.handlers.append(
        allocator,
        .{
            .name = "/grpc.example/SayHello",
            .handler_fn = sayHello,
        },
    );

    // Register benchmark handler
    try server.handlers.append(
        allocator,
        .{
            .name = "/grpc.benchmark/Benchmark",
            .handler_fn = benchmarkHandler,
        },
    );

    try server.start();
}

fn sayHello(_: []const u8, _: []const u8, trans: *grpc.Transport, _: std.mem.Allocator) anyerror!void {
    try trans.writeMessage("Hello from gRPC!");
}

fn benchmarkHandler(request: []const u8, _: []const u8, trans: *grpc.Transport, allocator: std.mem.Allocator) anyerror!void {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    const millis = @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
    const response = try std.fmt.allocPrint(allocator, "Echo: {s} (processed at {d})", .{ request, millis });
    defer allocator.free(response);
    try trans.writeMessage(response);
}

//! Zig interop server. Registers a handler that decodes EchoRequest,
//! mirrors payload+tag back as EchoResponse, and writes via the
//! existing GrpcServer.

const std = @import("std");
const grpc_server = @import("grpc-server");
const harness = @import("harness.zig");

const GrpcServer = grpc_server.GrpcServer;
const Transport = grpc_server.Transport;

fn echoHandler(
    request: []const u8,
    _: []const u8,
    trans: *Transport,
    allocator: std.mem.Allocator,
) anyerror!void {
    const decoded = harness.decodeEchoRequest(allocator, request) catch |err| {
        std.log.err("decode EchoRequest: {}", .{err});
        return err;
    };
    defer harness.freeEchoRequest(allocator, decoded);

    const resp = harness.EchoResponse{
        .payload = decoded.payload,
        .tag = decoded.tag,
    };
    const out = try harness.encodeEchoResponse(allocator, resp);
    defer allocator.free(out);
    try trans.writeMessage(out);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    var port: u16 = 50062;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // program name
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--port")) {
            const v = args.next() orelse return error.MissingPortValue;
            port = try std.fmt.parseInt(u16, v, 10);
        }
    }

    std.log.info("interop-zig-server listening on 127.0.0.1:{d}", .{port});

    var server = try GrpcServer.init(allocator, io, port, "interop");
    defer server.deinit();
    try server.handlers.append(allocator, .{ .name = "Echo", .handler_fn = echoHandler });

    try server.start();
}

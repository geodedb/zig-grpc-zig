//! Zig interop client. Encodes EchoRequest, fires it via GrpcClient,
//! decodes the response, and reports OK/FAIL like the Go client.

const std = @import("std");
const grpc_client = @import("grpc-client");
const harness = @import("harness.zig");

const GrpcClient = grpc_client.GrpcClient;

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("FAIL: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    var host: []const u8 = "127.0.0.1";
    var port: u16 = 50062;
    var message: []const u8 = "ping";
    var tag: []const u8 = "zig-client";

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--target")) {
            const v = args.next() orelse fail("--target requires value", .{});
            const colon = std.mem.indexOfScalar(u8, v, ':') orelse fail("--target must be host:port", .{});
            host = v[0..colon];
            port = std.fmt.parseInt(u16, v[colon + 1 ..], 10) catch |err| fail("bad port: {}", .{err});
        } else if (std.mem.eql(u8, a, "--message")) {
            message = args.next() orelse fail("--message requires value", .{});
        } else if (std.mem.eql(u8, a, "--tag")) {
            tag = args.next() orelse fail("--tag requires value", .{});
        }
    }

    var client = GrpcClient.init(allocator, io, host, port) catch |err| fail("dial: {}", .{err});
    defer client.deinit();

    const req_bytes = try harness.encodeEchoRequest(allocator, .{ .payload = message, .tag = tag });
    defer allocator.free(req_bytes);

    const resp_bytes = client.call("/interop.Interop/Echo", req_bytes, .none) catch |err| fail("call: {}", .{err});
    defer allocator.free(resp_bytes);

    const resp = harness.decodeEchoResponse(allocator, resp_bytes) catch |err| fail("decode: {}", .{err});
    defer harness.freeEchoResponse(allocator, resp);

    if (!std.mem.eql(u8, resp.payload, message)) {
        fail("payload mismatch: got '{s}' want '{s}'", .{ resp.payload, message });
    }
    std.log.info("OK payload='{s}' tag='{s}'", .{ resp.payload, resp.tag });
}

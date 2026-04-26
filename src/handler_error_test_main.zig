//! End-to-end test for handler-error trailer propagation (closes R1).
//!
//! Before the fix, when a handler returned an error the server logged
//! the error and silently continued. The client, blocked in
//! `readStreamFrame`/`readMessage`, hung indefinitely because no
//! TRAILERS frame ever arrived. This test runs a server with a handler
//! that intentionally returns `error.IntentionalFailure` and asserts:
//!
//!   1. The client receives a HEADERS frame with END_STREAM (a trailer).
//!   2. The trailer encodes `grpc-status: 2` (UNKNOWN).
//!   3. The trailer's `grpc-message` value is `IntentionalFailure`.
//!
//! Before the fix the test should hang up to the timeout in `doCall`
//! and exit with a non-zero status. After the fix it passes immediately.

const std = @import("std");
const server_mod = @import("server.zig");
const transport = @import("transport.zig");
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

const PORT: u16 = 50155;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

fn failingHandler(
    _: []const u8,
    _: []const u8,
    _: *transport.Transport,
    _: std.mem.Allocator,
) anyerror!void {
    return error.IntentionalFailure;
}

const ServerArgs = struct { server: *server_mod.GrpcServer };
fn serverThread(args: ServerArgs) void {
    args.server.start() catch |err| {
        std.log.err("server crashed: {}", .{err});
    };
}

const Outcome = struct {
    grpc_status: ?u32 = null,
    grpc_message: ?[]u8 = null,
};

fn parseTrailers(allocator: std.mem.Allocator, payload: []const u8) !Outcome {
    var out: Outcome = .{};
    var i: usize = 0;
    while (i < payload.len) {
        const b = payload[i];
        if (b == 0x40) {
            i += 1;
            if (i >= payload.len) break;
            const name_len = payload[i];
            i += 1;
            if (i + name_len > payload.len) break;
            const name = payload[i .. i + name_len];
            i += name_len;
            if (i >= payload.len) break;
            const value_len = payload[i];
            i += 1;
            if (i + value_len > payload.len) break;
            const value = payload[i .. i + value_len];
            i += value_len;
            if (std.mem.eql(u8, name, "grpc-status")) {
                out.grpc_status = std.fmt.parseInt(u32, value, 10) catch null;
            } else if (std.mem.eql(u8, name, "grpc-message")) {
                out.grpc_message = try allocator.dupe(u8, value);
            }
        } else {
            break;
        }
    }
    return out;
}

fn doCall(allocator: std.mem.Allocator, io: std.Io) !Outcome {
    const net = std.Io.net;
    const address = try net.IpAddress.resolve(io, "127.0.0.1", PORT);
    const conn = try address.connect(io, .{ .mode = .stream });

    var trans = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
    defer trans.deinit();

    try trans.writeRequestOnStream(1, "x", "/svc/Boom");

    var iter: u32 = 0;
    while (iter < 20) : (iter += 1) {
        const frame = try trans.readFrame();
        defer allocator.free(frame.payload);

        const FT = http2.frame.FrameType;
        switch (@as(FT, @enumFromInt(frame.frame_type))) {
            .HEADERS => {
                const FF = http2.frame.FrameFlags;
                if ((frame.flags & FF.END_STREAM) != 0) {
                    return parseTrailers(allocator, frame.payload);
                }
            },
            .RST_STREAM, .GOAWAY => return Outcome{},
            else => {},
        }
    }
    return Outcome{};
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    std.log.info("starting handler-error-test server on 127.0.0.1:{d}", .{PORT});

    var server = try server_mod.GrpcServer.init(allocator, io, PORT, "ignored-key");
    defer server.deinit();

    try server.handlers.append(allocator, .{ .name = "/svc/Boom", .handler_fn = failingHandler });

    const thread = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = &server }});
    thread.detach();

    try io.sleep(.fromMilliseconds(100), .awake);

    const out = try doCall(allocator, io);
    defer if (out.grpc_message) |m| allocator.free(m);

    if (out.grpc_status == null) fatal("no trailer received (server hung after handler error)", .{});
    if (out.grpc_status.? != 2) {
        fatal("got grpc-status {d} want 2", .{out.grpc_status.?});
    }
    if (out.grpc_message == null) fatal("no grpc-message in trailer", .{});
    if (!std.mem.eql(u8, out.grpc_message.?, "IntentionalFailure")) {
        fatal("got grpc-message '{s}' want 'IntentionalFailure'", .{out.grpc_message.?});
    }

    std.log.info("    ok handler error -> grpc-status 2 grpc-message IntentionalFailure", .{});
    std.log.info("ALL HANDLER-ERROR SCENARIOS PASSED", .{});
    std.process.exit(0);
}

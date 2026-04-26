//! End-to-end test for path-based handler dispatch (closes GAP-0003 / #4).
//!
//! The legacy server unconditionally invoked `handlers.items[0]` for every
//! request, ignoring `:path`. This test wires up a real server with TWO
//! distinct handlers and verifies:
//!
//!   1. A request to `/svc.A/Foo` is routed to handler A (returns "A:<req>").
//!   2. A request to `/svc.B/Bar` is routed to handler B (returns "B:<req>").
//!   3. A request to an unregistered `/svc.X/Unknown` receives a gRPC
//!      trailer with `grpc-status: 12` (UNIMPLEMENTED) instead of hanging.
//!
//! Before the fix this test must FAIL: the unknown-path call hangs (server
//! returns nothing because the dispatch loop did `continue` on missing
//! handler) and/or the registered handlers are mis-matched.

const std = @import("std");
const server_mod = @import("server.zig");
const transport = @import("transport.zig");
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

const PORT: u16 = 50133;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

fn handlerA(
    request: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    allocator: std.mem.Allocator,
) anyerror!void {
    const resp = try std.fmt.allocPrint(allocator, "A:{s}", .{request});
    defer allocator.free(resp);
    try trans.writeMessage(resp);
}

fn handlerB(
    request: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    allocator: std.mem.Allocator,
) anyerror!void {
    const resp = try std.fmt.allocPrint(allocator, "B:{s}", .{request});
    defer allocator.free(resp);
    try trans.writeMessage(resp);
}

const ServerArgs = struct { server: *server_mod.GrpcServer };
fn serverThread(args: ServerArgs) void {
    args.server.start() catch |err| {
        std.log.err("server crashed: {}", .{err});
    };
}

/// Send a request manually via raw `Transport.writeRequestOnStream` and
/// read frames until we see either a DATA frame (success) or a trailers-only
/// HEADERS frame with END_STREAM (status code in HPACK payload).
const Outcome = struct {
    response: ?[]u8 = null,
    grpc_status: ?u32 = null, // populated when trailers-only frame arrives.
};

/// Decode the very first HPACK literal field in `payload` if it is the
/// LIE-literal-name form (0x40, 11, "grpc-status", n, "<digits>").
/// Returns the parsed status code.
fn parseGrpcStatusFromTrailers(payload: []const u8) ?u32 {
    var i: usize = 0;
    while (i < payload.len) {
        const b = payload[i];
        if (b == 0x40) {
            // LIE literal-name. Read name length.
            i += 1;
            if (i >= payload.len) return null;
            const name_len = payload[i];
            i += 1;
            if (i + name_len > payload.len) return null;
            const name = payload[i .. i + name_len];
            i += name_len;
            if (i >= payload.len) return null;
            const value_len = payload[i];
            i += 1;
            if (i + value_len > payload.len) return null;
            const value = payload[i .. i + value_len];
            i += value_len;
            if (std.mem.eql(u8, name, "grpc-status")) {
                return std.fmt.parseInt(u32, value, 10) catch null;
            }
        } else {
            // Skip unknown form — for this test we only generate LIE-literal.
            return null;
        }
    }
    return null;
}

fn doCall(
    allocator: std.mem.Allocator,
    io: std.Io,
    method_path: []const u8,
    body: []const u8,
) !Outcome {
    const net = std.Io.net;
    const address = try net.IpAddress.resolve(io, "127.0.0.1", PORT);
    const conn = try address.connect(io, .{ .mode = .stream });

    var trans = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
    defer trans.deinit();

    try trans.writeRequestOnStream(1, body, method_path);

    var outcome: Outcome = .{};

    // Read up to ~10 frames looking for the response. We stop as soon as we
    // see a HEADERS frame with END_STREAM (trailers) or a DATA frame.
    var iter: u32 = 0;
    while (iter < 20) : (iter += 1) {
        const frame = try trans.readFrame();
        defer allocator.free(frame.payload);

        const FT = http2.frame.FrameType;
        switch (@as(FT, @enumFromInt(frame.frame_type))) {
            .DATA => {
                if (frame.payload.len >= 5) {
                    const msg_len = (@as(u32, frame.payload[1]) << 24) |
                        (@as(u32, frame.payload[2]) << 16) |
                        (@as(u32, frame.payload[3]) << 8) |
                        @as(u32, frame.payload[4]);
                    if (frame.payload.len >= 5 + msg_len) {
                        outcome.response = try allocator.dupe(u8, frame.payload[5 .. 5 + msg_len]);
                    }
                }
            },
            .HEADERS => {
                const FF = http2.frame.FrameFlags;
                if ((frame.flags & FF.END_STREAM) != 0) {
                    // Trailers — try parsing grpc-status.
                    outcome.grpc_status = parseGrpcStatusFromTrailers(frame.payload);
                    return outcome;
                }
                // Initial response HEADERS (no END_STREAM) — keep reading.
            },
            .RST_STREAM, .GOAWAY => return outcome,
            else => {},
        }
    }
    return outcome;
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    std.log.info("starting dispatch-test server on 127.0.0.1:{d}", .{PORT});

    var server = try server_mod.GrpcServer.init(allocator, io, PORT, "dispatch-key");
    defer server.deinit();

    try server.handlers.append(allocator, .{ .name = "/svc.A/Foo", .handler_fn = handlerA });
    try server.handlers.append(allocator, .{ .name = "/svc.B/Bar", .handler_fn = handlerB });

    const thread = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = &server }});
    thread.detach();

    try io.sleep(.fromMilliseconds(100), .awake);

    // (1) /svc.A/Foo -> handler A
    {
        const out = try doCall(allocator, io, "/svc.A/Foo", "hello");
        defer if (out.response) |r| allocator.free(r);
        if (out.response == null) fatal("A: no response", .{});
        if (!std.mem.eql(u8, out.response.?, "A:hello")) {
            fatal("A: got '{s}' want 'A:hello'", .{out.response.?});
        }
        std.log.info("    ok /svc.A/Foo -> {s}", .{out.response.?});
    }

    // (2) /svc.B/Bar -> handler B
    {
        const out = try doCall(allocator, io, "/svc.B/Bar", "world");
        defer if (out.response) |r| allocator.free(r);
        if (out.response == null) fatal("B: no response", .{});
        if (!std.mem.eql(u8, out.response.?, "B:world")) {
            fatal("B: got '{s}' want 'B:world'", .{out.response.?});
        }
        std.log.info("    ok /svc.B/Bar -> {s}", .{out.response.?});
    }

    // (3) /svc.X/Unknown -> grpc-status 12 trailer (UNIMPLEMENTED)
    {
        const out = try doCall(allocator, io, "/svc.X/Unknown", "x");
        defer if (out.response) |r| allocator.free(r);
        if (out.grpc_status == null) fatal("unknown: no trailer received", .{});
        if (out.grpc_status.? != 12) {
            fatal("unknown: got status {d} want 12", .{out.grpc_status.?});
        }
        std.log.info("    ok /svc.X/Unknown -> grpc-status 12", .{});
    }

    std.log.info("ALL DISPATCH SCENARIOS PASSED", .{});
    std.process.exit(0);
}

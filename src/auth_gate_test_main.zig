//! End-to-end test for the server-side auth gate (closes GAP-0001 / #2).
//!
//! Wires up a real `GrpcServer` with `requireAuth = true` and verifies
//! three scenarios:
//!
//!   1. A request bearing a valid JWT (signed with the server's secret)
//!      reaches the handler and gets a normal response.
//!   2. A request with NO `authorization` header receives a `grpc-status:
//!      16` (UNAUTHENTICATED) trailer.
//!   3. A request with a tampered token receives a `grpc-status: 16`
//!      trailer.
//!
//! Before the fix this test FAILS because the server did not consult
//! `auth.verifyToken` and dispatched every request unconditionally.

const std = @import("std");
const server_mod = @import("server.zig");
const transport = @import("transport.zig");
const auth = @import("features/auth.zig");
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

const PORT: u16 = 50144;
const SECRET = "auth-gate-test-secret-very-long";

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

fn echoHandler(
    request: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    _: std.mem.Allocator,
) anyerror!void {
    try trans.writeMessage(request);
}

const ServerArgs = struct { server: *server_mod.GrpcServer };
fn serverThread(args: ServerArgs) void {
    args.server.start() catch |err| {
        std.log.err("server crashed: {}", .{err});
    };
}

const Outcome = struct {
    response: ?[]u8 = null,
    grpc_status: ?u32 = null,
};

fn parseGrpcStatusFromTrailers(payload: []const u8) ?u32 {
    var i: usize = 0;
    while (i < payload.len) {
        const b = payload[i];
        if (b == 0x40) {
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
            return null;
        }
    }
    return null;
}

fn doCallWithAuth(
    allocator: std.mem.Allocator,
    io: std.Io,
    method_path: []const u8,
    body: []const u8,
    auth_value: ?[]const u8,
) !Outcome {
    const net = std.Io.net;
    const address = try net.IpAddress.resolve(io, "127.0.0.1", PORT);
    const conn = try address.connect(io, .{ .mode = .stream });

    var trans = try transport.Transport.initClient(allocator, io, conn, "127.0.0.1");
    defer trans.deinit();

    var meta: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer meta.deinit(allocator);
    if (auth_value) |v| try meta.put(allocator, "authorization", v);

    try trans.writeRequestOnStreamWithMetadata(
        1,
        body,
        method_path,
        if (meta.count() == 0) null else &meta,
    );

    var outcome: Outcome = .{};

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
                    outcome.grpc_status = parseGrpcStatusFromTrailers(frame.payload);
                    return outcome;
                }
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

    std.log.info("starting auth-gate-test server on 127.0.0.1:{d}", .{PORT});

    var server = try server_mod.GrpcServer.init(allocator, io, PORT, SECRET);
    defer server.deinit();
    server.require_auth = true;

    try server.handlers.append(allocator, .{ .name = "/svc/Echo", .handler_fn = echoHandler });

    const thread = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = &server }});
    thread.detach();

    try io.sleep(.fromMilliseconds(100), .awake);

    // (1) Valid token — handler runs.
    {
        var signer = auth.Auth.init(allocator, SECRET);
        const token = try signer.generateToken("alice", 3600);
        defer allocator.free(token);

        const out = try doCallWithAuth(allocator, io, "/svc/Echo", "hi", token);
        defer if (out.response) |r| allocator.free(r);
        if (out.response == null) fatal("valid: no response (status={?d})", .{out.grpc_status});
        if (!std.mem.eql(u8, out.response.?, "hi")) {
            fatal("valid: got '{s}' want 'hi'", .{out.response.?});
        }
        std.log.info("    ok valid token -> echoed", .{});
    }

    // (2) No authorization header — UNAUTHENTICATED (16).
    {
        const out = try doCallWithAuth(allocator, io, "/svc/Echo", "hi", null);
        defer if (out.response) |r| allocator.free(r);
        if (out.grpc_status == null) fatal("missing-auth: no trailer", .{});
        if (out.grpc_status.? != 16) {
            fatal("missing-auth: got status {d} want 16", .{out.grpc_status.?});
        }
        std.log.info("    ok missing auth -> grpc-status 16", .{});
    }

    // (3) Tampered token — UNAUTHENTICATED.
    {
        var signer = auth.Auth.init(allocator, SECRET);
        const token = try signer.generateToken("alice", 3600);
        defer allocator.free(token);

        const tampered = try allocator.dupe(u8, token);
        defer allocator.free(tampered);
        // Tamper a byte in the payload segment.
        const first_dot = std.mem.indexOfScalar(u8, tampered, '.') orelse return error.TestFailed;
        const second_dot = std.mem.indexOfScalarPos(u8, tampered, first_dot + 1, '.') orelse return error.TestFailed;
        const tamper_at = first_dot + 1 + (second_dot - first_dot - 1) / 2;
        tampered[tamper_at] = if (tampered[tamper_at] == 'A') 'B' else 'A';

        const out = try doCallWithAuth(allocator, io, "/svc/Echo", "hi", tampered);
        defer if (out.response) |r| allocator.free(r);
        if (out.grpc_status == null) fatal("tampered: no trailer", .{});
        if (out.grpc_status.? != 16) {
            fatal("tampered: got status {d} want 16", .{out.grpc_status.?});
        }
        std.log.info("    ok tampered token -> grpc-status 16", .{});
    }

    std.log.info("ALL AUTH-GATE SCENARIOS PASSED", .{});
    std.process.exit(0);
}

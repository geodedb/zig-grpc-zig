//! In-process reproduction for the connection-thread stack-overflow segfault
//! (GAP-0018 — remote DoS). See `src/server.zig`'s `DEFAULT_CONN_STACK_SIZE` /
//! `connStackSizeFromEnv` and the CC-4 comment in `start()`.
//!
//! ## What this reproduces
//!
//! Each accepted connection is served on a dedicated OS thread. The "CC-4"
//! memory optimization originally capped that thread's stack at 512 KiB. On
//! the FIRST heap allocation the connection thread performs —
//! `Transport.initServer` -> `allocStreamWindows` — a stack-trace-capturing
//! allocator runs the DWARF self-unwinder, which allocates large CFI
//! register-rule state ON THE STACK. The shipped `examples/basic_server.zig`
//! uses `std.heap.DebugAllocator(.{})`, which is exactly such an allocator.
//! 512 KiB overflows into the guard page -> SIGSEGV, on the FIRST accepted TCP
//! connection, BEFORE auth and BEFORE dispatch. A single unauthenticated
//! `connect()` crashes the connection thread.
//!
//! ## Harness
//!
//! 1. The SERVER uses `std.heap.DebugAllocator(.{})` (the trigger) — NOT
//!    `c_allocator`. This is the only allocator that exercises the unwinder
//!    path on every allocation.
//! 2. The server runs `start()` on a background thread.
//! 3. The main thread opens a raw TCP connection and writes the HTTP/2
//!    connection preface + an empty SETTINGS frame, which forces the server's
//!    `initServer` (and thus `allocStreamWindows`) to run under the capturing
//!    allocator on the freshly-spawned connection thread.
//! 4. After giving the connection thread time to accept + init, the harness
//!    asserts the server is STILL ALIVE by opening a SECOND connection and
//!    completing its preface. If the server thread crashed, the listen socket
//!    is gone (or the whole process took the SIGSEGV) and the second connect
//!    or the liveness flag fails.
//!
//! Before the fix (512 KiB stack) this binary crashes / exits non-zero. After
//! the fix (configurable stack with a safe default) it prints
//! "CONN STACK TEST PASSED" and exits 0.
//!
//! Run via:
//!   `zig build conn-stack-test && timeout 30 ./zig-out/bin/grpc-conn-stack-test`

const std = @import("std");
const server_mod = @import("server.zig");
const transport = @import("transport.zig");

const net = std.Io.net;

const PORT: u16 = 50166;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(1);
}

const ServerArgs = struct { server: *server_mod.GrpcServer };

fn serverThread(args: ServerArgs) void {
    // If the connection thread overflows its stack, the SIGSEGV takes down
    // the whole process — control never returns here. If instead `start()`
    // itself returns an error (e.g. accept fails after a crash), we log it so
    // the failure is visible.
    args.server.start() catch |err| {
        std.log.err("server crashed: {}", .{err});
    };
}

/// Write all of `data` to a raw socket handle via the low-level Io vtable.
/// `net.Stream` itself only exposes buffered Reader/Writer adapters; for a
/// fixed self-contained chunk (preface, one frame) the direct vtable call is
/// simplest and mirrors how `transport.zig` writes the HTTP/2 preface.
fn writeAllRaw(io: std.Io, handle: net.Socket.Handle, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const trailing = [_][]const u8{data[off..]};
        const n = try io.vtable.netWrite(io.userdata, handle, "", &trailing, 1);
        if (n == 0) return error.WriteZero;
        off += n;
    }
}

/// Open a raw TCP connection and push the HTTP/2 client preface + an empty
/// SETTINGS frame. This is enough to make the server accept the connection,
/// spawn the connection thread, and run `Transport.initServer` ->
/// `allocStreamWindows` under the (capturing) server allocator — which is the
/// faulting path. We deliberately do NOT use `GrpcClient` here: a raw socket
/// is simpler and more reliable for triggering the server-side init, and it
/// keeps the repro free of client-side handshake timing.
fn pokeServer(io: std.Io) !void {
    const address = try net.IpAddress.resolve(io, "127.0.0.1", PORT);
    const conn = try address.connect(io, .{ .mode = .stream });
    defer conn.close(io);
    const handle = conn.socket.handle;

    // HTTP/2 connection preface (RFC 7540 §3.5).
    try writeAllRaw(io, handle, transport.HTTP2_PREFACE);

    // Empty SETTINGS frame: 9-byte header (length=0, type=0x4 SETTINGS,
    // flags=0, stream id=0), no payload. Completing the preface lets the
    // server-side handshake proceed past the point where `allocStreamWindows`
    // has already run, so the crash (if any) has definitely occurred by the
    // time this returns.
    const settings_frame = [_]u8{
        0x00, 0x00, 0x00, // length = 0
        0x04, // type = SETTINGS
        0x00, // flags
        0x00, 0x00, 0x00, 0x00, // stream id = 0
    };
    try writeAllRaw(io, handle, &settings_frame);

    // Best-effort: read whatever the server sends back (its own SETTINGS), but
    // don't require it — for the repro all that matters is that the server's
    // connection thread ran `initServer` without faulting.
    var scratch: [256]u8 = undefined;
    var dest = [_][]u8{&scratch};
    _ = io.vtable.netRead(io.userdata, handle, &dest) catch {};
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // CRITICAL: the server MUST use a stack-trace-capturing allocator to
    // exercise the unwinder path. This mirrors `examples/basic_server.zig`.
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("starting conn-stack-test server on 127.0.0.1:{d} (DebugAllocator)", .{PORT});

    var server = try server_mod.GrpcServer.init(allocator, io, PORT, "conn-stack-key");
    defer server.deinit();

    const thread = try std.Thread.spawn(.{}, serverThread, .{ServerArgs{ .server = &server }});
    thread.detach();

    // Give the server thread time to bind / listen / accept.
    try io.sleep(.fromMilliseconds(150), .awake);

    // (1) First connection — this is the one that historically crashed the
    // connection thread (and, via SIGSEGV, the whole process) during
    // `initServer` -> `allocStreamWindows` under the DebugAllocator.
    std.log.info("[1/2] first connection (triggers initServer under capturing allocator)", .{});
    pokeServer(io) catch |err| fatal("first connection failed: {}", .{err});

    // Let the connection thread finish its init + handshake. If it overflowed
    // its stack, the process is already dead and we never reach the next line.
    try io.sleep(.fromMilliseconds(250), .awake);

    // (2) Liveness check: open a SECOND connection. If the server thread (or
    // process) died from the first connection, the listen backlog is gone /
    // the process is dead, so this connect (or its preface write) fails — or
    // we never get here at all because of the SIGSEGV.
    std.log.info("[2/2] second connection (liveness — server must still accept)", .{});
    pokeServer(io) catch |err| fatal("second connection failed (server appears dead): {}", .{err});

    try io.sleep(.fromMilliseconds(100), .awake);

    std.log.info("CONN STACK TEST PASSED", .{});

    // Detached server thread never returns; exit explicitly so main's implicit
    // cleanup doesn't tear us down mid-flight.
    std.process.exit(0);
}

const std = @import("std");
const proto = @import("proto/service.zig");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const auth = @import("features/auth.zig");
const streaming = @import("features/streaming.zig");
const health = @import("features/health.zig");
const net = std.Io.net;
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

pub const Transport = transport.Transport;
pub const TlsIo = transport.TlsIo;

/// Public otel seam re-export. When `-Dwith_otel=false` (default),
/// `observability.enabled` is `false` and every span call is a
/// comptime-known no-op. When `-Dwith_otel=true`, callers can install
/// providers via `observability_init.Otel`.
pub const observability = @import("observability.zig");

/// Otel bootstrap helper, only present when `-Dwith_otel=true`. End
/// consumers parking a real `Otel` value in their `main()` call
/// `observability_init.Otel.init` then `installGlobals()` to publish
/// Tracer/Meter handles to the seam. Under the disabled build this is
/// an empty struct so the import never resolves the otel namespace.
pub const observability_init = if (observability.enabled)
    @import("observability_init.zig")
else
    struct {};

pub const Handler = struct {
    name: []const u8,
    /// Handler receives: request bytes, method path, transport (for streaming writes), allocator.
    /// For unary RPCs, call trans.writeMessage(). For streaming, use writeStreamMessage()+endStream().
    handler_fn: *const fn ([]const u8, []const u8, *transport.Transport, std.mem.Allocator) anyerror!void,
};

/// gRPC server over HTTP/2.
///
/// THREADING MODEL (per accepted connection)
/// -----------------------------------------
/// Every accepted connection owns exactly TWO threads for its whole life:
///
///   * the **reader thread** (`connectionReader`) is the ONLY thread that
///     calls `Transport.readFrame`. It owns inbound frame parsing and the
///     HPACK decoder state, answers connection-level control frames
///     inline (SETTINGS ACK, PING ACK, WINDOW_UPDATE credit, RST_STREAM /
///     GOAWAY teardown), refills our receive windows, assembles inbound
///     DATA into complete gRPC messages, and hands each finished request
///     to the handler thread through a bounded `RequestQueue`.
///
///   * the **handler thread** is the connection thread spawned by
///     `start()` (`connectionThread` -> `handleConnection`). After
///     spawning the reader it does nothing but pop requests off the queue
///     and run the auth gate + dispatch + response writes, exactly as
///     before. Requests are still served strictly one at a time per
///     connection, so handler-visible ordering is unchanged.
///
/// WHY (SONNY-1560): before this split, the same thread read frames AND
/// ran the handler. While a handler was writing a large response nobody
/// drained the socket, so the peer's WINDOW_UPDATE frames were never
/// processed; once the peer's initial send window (1 MiB) was consumed the
/// writer parked in `Transport.reserveSendCredit` until
/// `flow_credit_timeout_ns` (30 s) expired. Flow control itself was always
/// correct — it simply never got fed. With a dedicated reader the credit
/// keeps flowing while the handler writes.
///
/// SHARED STATE AND THE LOCK THAT GUARDS IT
/// ----------------------------------------
///   * socket writes                 -> `Transport.write_mutex`. Both
///     threads write (reader: SETTINGS/PING ACK, WINDOW_UPDATE, RST_STREAM,
///     GOAWAY; handler: HEADERS/DATA/TRAILERS). Every multi-frame sequence
///     takes the mutex once, so frames can never interleave on the wire.
///   * send windows + `flow_epoch`   -> `Transport.flow_mutex` (unchanged).
///     The reader credits them via `processWindowUpdate` /
///     `applyPeerSettings`; the handler consumes them via
///     `reserveSendCredit`.
///   * the request queue             -> `RequestQueue.mutex` + `.cond`.
///   * receive windows, HPACK dynamic table, `last_method`,
///     `last_authorization` -> single-writer: the READER thread only.
///     Handlers must use the `path` argument passed to `handler_fn`, NOT
///     `Transport.lastMethod()` / `lastAuthorization()`, which now describe
///     whatever HEADERS frame the reader saw most recently. The per-request
///     values are snapshotted into the queued `PendingRequest`.
///   * `Transport.last_stream_id`    -> single-writer: the HANDLER thread
///     only. It is set from the popped request before dispatch, so
///     `writeMessage` / `writeStreamMessage` / `endStream` keep targeting
///     the stream being served.
///
/// TEARDOWN is deterministic: the reader exits on EOF/error/GOAWAY and
/// closes the queue (carrying any fatal error); the handler drains what is
/// already queued, leaves the loop, shuts the socket down and JOINS the
/// reader before `Transport.deinit()` closes the fd. No connection thread
/// is ever left behind.
pub const GrpcServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: net.IpAddress,
    server: net.Server,
    handlers: std.ArrayList(Handler),
    compression: compression.Compression,
    auth: auth.Auth,
    health_check: health.HealthCheck,
    on_tls_accept: ?*const fn (net.Stream) anyerror!transport.TlsIo = null,
    /// When true, every incoming request must carry a valid `authorization`
    /// header that `Auth.verifyToken` accepts. Closes GAP-0001:
    ///   * Missing or empty header        -> grpc-status 16 (UNAUTHENTICATED)
    ///   * Token rejected by verifyToken  -> grpc-status 16 with @errorName
    /// When false (default), the server is unauthenticated and dispatches
    /// every request directly — the legacy behaviour, kept for tests and
    /// for endpoints that don't need an auth gate.
    require_auth: bool = false,
    /// Counting semaphore that bounds the number of concurrent
    /// connection threads (closes CC-1 + MW-4). The accept loop
    /// `wait`s for a permit before spawning, and `connectionThread`
    /// `post`s on exit. Sized from the `GRPC_ZIG_MAX_CONNS` env var,
    /// falling back to `DEFAULT_MAX_CONNS = 1024`.
    conn_sem: std.Io.Semaphore = .{ .permits = DEFAULT_MAX_CONNS },
    /// Per-stream send-credit timeout in nanoseconds, applied to every
    /// accepted connection's Transport. A slow-loris peer that opens
    /// streams but never advertises send-window credit can otherwise
    /// pin up to MAX_CONNS writer threads in `reserveSendCredit`. On
    /// timeout the writer emits `RST_STREAM(FLOW_CONTROL_ERROR)` for
    /// the offending stream and frees the thread. Sized from the
    /// `GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS` env var (milliseconds);
    /// `0` disables the timeout (legacy behaviour: park forever).
    /// Defaults to `DEFAULT_FLOW_CREDIT_TIMEOUT_MS = 30_000` (30 s).
    /// Closes GAP-FU-002.
    flow_credit_timeout_ns: u64 = DEFAULT_FLOW_CREDIT_TIMEOUT_MS * std.time.ns_per_ms,
    /// Monotonic count of connections that terminated with an error
    /// (anything other than a clean peer disconnect). Exposed so
    /// embedders can alert on error spikes without an otel build
    /// (closes quality R3 / #58).
    conn_error_count: std.atomic.Value(u64) = .init(0),
    /// Stack size (bytes) for each spawned connection thread (CC-4).
    /// Sized from the `GRPC_ZIG_CONN_STACK_SIZE` env var, falling back to
    /// `DEFAULT_CONN_STACK_SIZE`. The default is deliberately larger than
    /// the original 512 KiB CC-4 value because a stack-trace-capturing
    /// allocator (e.g. Zig 0.16's `std.heap.DebugAllocator`, used by the
    /// shipped `examples/basic_server.zig`) runs the DWARF self-unwinder
    /// on its FIRST allocation inside `Transport.initServer` ->
    /// `allocStreamWindows`. The unwinder allocates large CFI register-rule
    /// state on the stack; 512 KiB overflowed into the guard page and
    /// SIGSEGV-ed the connection thread on the first accepted, still
    /// unauthenticated TCP connection (GAP-0018, remote DoS). Operators
    /// running a non-capturing allocator (`c_allocator`, arena, etc.) can
    /// reclaim memory by lowering this via the env var. Closes GAP-0018.
    conn_stack_size: usize = DEFAULT_CONN_STACK_SIZE,

    /// Default cap on concurrent accepted connections when
    /// `GRPC_ZIG_MAX_CONNS` is unset.
    pub const DEFAULT_MAX_CONNS: usize = 1024;
    /// Default per-stream send-credit timeout (milliseconds) when
    /// `GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS` is unset.
    pub const DEFAULT_FLOW_CREDIT_TIMEOUT_MS: u64 = 30_000;

    /// Default connection-thread stack size (bytes) when
    /// `GRPC_ZIG_CONN_STACK_SIZE` is unset. 8 MiB — matches the glibc
    /// default pthread stack.
    ///
    /// WHY 8 MiB (not the old CC-4 value of 512 KiB): a stack-trace-
    /// capturing allocator (Zig 0.16's `std.heap.DebugAllocator`, which
    /// the shipped `examples/basic_server.zig` uses) runs the DWARF
    /// self-unwinder on its FIRST allocation. The unwinder
    /// (`Dwarf.SelfUnwinder.computeRules`) materializes large CFI
    /// register-rule state on the stack. Measured against the
    /// `conn-stack-test` reproduction under the DebugAllocator
    /// (`src/conn_stack_test_main.zig`): 512 KiB SIGSEGVs 8/8 runs on the
    /// first accepted connection inside `Transport.initServer` ->
    /// `allocStreamWindows`; 544 KiB and up pass reliably (544 KiB / 768 KiB
    /// / 1 MiB / 2 MiB / 4 MiB / 8 MiB each passed every run). The smallest
    /// reliably-passing measured value is ~544 KiB; doubling that for margin
    /// lands near 1.1 MiB. We deliberately set the DEFAULT higher — the
    /// glibc default of 8 MiB — so the safe default exactly matches what
    /// every connection thread got BEFORE the CC-4 optimization was
    /// introduced (zero regression risk for capturing allocators, and the
    /// guard page still backstops genuine runaway recursion). Operators
    /// using a non-capturing allocator (`c_allocator`, arena, etc.) can
    /// reclaim idle-connection memory by lowering this via
    /// `GRPC_ZIG_CONN_STACK_SIZE`. Closes GAP-0018.
    pub const DEFAULT_CONN_STACK_SIZE: usize = 8 * 1024 * 1024;

    /// Lower bound (bytes) accepted for `GRPC_ZIG_CONN_STACK_SIZE`. 64 KiB.
    /// The empirical DebugAllocator crash floor is just above 512 KiB, so
    /// 64 KiB is NOT a safety guarantee for capturing allocators — it is a
    /// sanity guard that stops an operator from reintroducing the crash
    /// class with an absurdly small value (e.g. 4096) that can't even hold
    /// the transport's own frames. Operators who KNOW they run a
    /// non-capturing allocator can legitimately set values below the
    /// DebugAllocator floor down to this minimum.
    pub const MIN_CONN_STACK_SIZE: usize = 64 * 1024;

    /// Default bind interface. Loopback-by-default (closes O1 / #53):
    /// binding every interface in cleartext h2c was a hostile-network
    /// footgun. Opt into a public bind explicitly via `initWithBind` or
    /// the `GRPC_ZIG_BIND_ADDR` env var (e.g. "0.0.0.0").
    pub const DEFAULT_BIND_ADDRESS: []const u8 = "127.0.0.1";

    /// Read GRPC_ZIG_BIND_ADDR via libc getenv (same rationale as
    /// `maxConnsFromEnv`); falls back to DEFAULT_BIND_ADDRESS. The
    /// returned slice is libc-owned (env path) or a static string
    /// (default) — callers must NOT free it.
    pub fn bindAddressFromEnv() []const u8 {
        const raw_ptr = std.c.getenv("GRPC_ZIG_BIND_ADDR") orelse return DEFAULT_BIND_ADDRESS;
        const raw = std.mem.span(raw_ptr);
        if (raw.len == 0) return DEFAULT_BIND_ADDRESS;
        return raw;
    }

    /// Read GRPC_ZIG_MAX_CONNS via libc `getenv`; return
    /// DEFAULT_MAX_CONNS when missing, or propagate
    /// `error.InvalidMaxConns` for malformed values.
    /// Public so `init` and unit tests can both reach it.
    ///
    /// We use `std.c.getenv` directly rather than going through
    /// `std.process.Environ`. The Environ-based API in Zig 0.16
    /// requires access to a process-level Environ instance (passed
    /// via the `Init` argument to `main`), which the existing
    /// `GrpcServer.init` signature doesn't have a path to. Since
    /// the gRPC server module already links libc transitively for
    /// zlib, libc's `getenv` is available everywhere we ship.
    pub fn maxConnsFromEnv(allocator: std.mem.Allocator) !usize {
        _ = allocator; // libc owns the returned buffer
        const raw_ptr = std.c.getenv("GRPC_ZIG_MAX_CONNS") orelse return DEFAULT_MAX_CONNS;
        const raw = std.mem.span(raw_ptr);
        return parseMaxConnsValue(raw);
    }

    /// Test-only alias.
    pub fn maxConnsFromEnvForTest(allocator: std.mem.Allocator) !usize {
        return maxConnsFromEnv(allocator);
    }

    /// Parse a GRPC_ZIG_MAX_CONNS value into a usable cap. Rejects 0
    /// (would deadlock the accept loop) and any non-digit input.
    pub fn parseMaxConnsValue(raw: []const u8) !usize {
        if (raw.len == 0) return error.InvalidMaxConns;
        const n = std.fmt.parseInt(usize, raw, 10) catch return error.InvalidMaxConns;
        if (n == 0) return error.InvalidMaxConns;
        return n;
    }

    /// Read GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS via libc `getenv`; return
    /// the default when missing. `0` is a valid value here (disables
    /// the timeout entirely). Malformed values fall back to the
    /// default rather than refusing to boot. Closes GAP-FU-002.
    pub fn flowCreditTimeoutNsFromEnv() u64 {
        const raw_ptr = std.c.getenv("GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS") orelse
            return DEFAULT_FLOW_CREDIT_TIMEOUT_MS * std.time.ns_per_ms;
        const raw = std.mem.span(raw_ptr);
        const ms = parseFlowCreditTimeoutMs(raw) catch
            return DEFAULT_FLOW_CREDIT_TIMEOUT_MS * std.time.ns_per_ms;
        return ms * std.time.ns_per_ms;
    }

    /// Parse a GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS value. Unlike
    /// `parseMaxConnsValue`, `0` IS a valid input (disables the
    /// timeout). Empty or non-digit input is rejected. Public for
    /// unit tests.
    pub fn parseFlowCreditTimeoutMs(raw: []const u8) !u64 {
        if (raw.len == 0) return error.InvalidFlowCreditTimeout;
        return std.fmt.parseInt(u64, raw, 10) catch error.InvalidFlowCreditTimeout;
    }

    /// Read GRPC_ZIG_CONN_STACK_SIZE (bytes) via libc `getenv`; return
    /// `DEFAULT_CONN_STACK_SIZE` when missing. Malformed or out-of-range
    /// values fall back to the default rather than refusing to boot — the
    /// safe default is always recoverable, and silently shrinking the
    /// stack on a typo would reintroduce the GAP-0018 crash class. Closes
    /// GAP-0018.
    pub fn connStackSizeFromEnv() usize {
        const raw_ptr = std.c.getenv("GRPC_ZIG_CONN_STACK_SIZE") orelse
            return DEFAULT_CONN_STACK_SIZE;
        const raw = std.mem.span(raw_ptr);
        return parseConnStackSize(raw) catch DEFAULT_CONN_STACK_SIZE;
    }

    /// Parse a GRPC_ZIG_CONN_STACK_SIZE value (bytes). Rejects 0,
    /// non-digit input, and anything below `MIN_CONN_STACK_SIZE` (64 KiB)
    /// so an operator can't reintroduce the GAP-0018 crash class with an
    /// absurdly small stack. Public for unit tests. Mirrors
    /// `parseMaxConnsValue`'s shape with an added lower-bound floor.
    pub fn parseConnStackSize(raw: []const u8) !usize {
        if (raw.len == 0) return error.InvalidConnStackSize;
        const n = std.fmt.parseInt(usize, raw, 10) catch return error.InvalidConnStackSize;
        if (n == 0) return error.InvalidConnStackSize;
        if (n < MIN_CONN_STACK_SIZE) return error.InvalidConnStackSize;
        return n;
    }

    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16, secret_key: []const u8) !GrpcServer {
        return initWithBind(allocator, io, bindAddressFromEnv(), port, secret_key);
    }

    /// Like `init` but binds the given interface (e.g. "0.0.0.0" for a
    /// deliberate public bind). Closes O1 (#53).
    pub fn initWithBind(allocator: std.mem.Allocator, io: std.Io, bind_address: []const u8, port: u16, secret_key: []const u8) !GrpcServer {
        const address = try net.IpAddress.parseIp4(bind_address, port);
        const server = try address.listen(io, .{ .reuse_address = true });
        // Resolve the admission cap. Fall back silently to the default
        // on any malformed env value rather than refusing to boot.
        const max_conns = maxConnsFromEnv(allocator) catch DEFAULT_MAX_CONNS;
        return GrpcServer{
            .allocator = allocator,
            .io = io,
            .address = address,
            .server = server,
            .handlers = try std.ArrayList(Handler).initCapacity(allocator, 1),
            .compression = compression.Compression.init(allocator),
            .auth = auth.Auth.init(allocator, secret_key),
            .health_check = health.HealthCheck.init(allocator),
            .conn_sem = .{ .permits = max_conns },
            .flow_credit_timeout_ns = flowCreditTimeoutNsFromEnv(),
            .conn_stack_size = connStackSizeFromEnv(),
        };
    }

    /// Read the connection-error counter (R3 / #58).
    pub fn connErrorCount(self: *const GrpcServer) u64 {
        return self.conn_error_count.load(.monotonic);
    }

    pub fn deinit(self: *GrpcServer) void {
        self.handlers.deinit(self.allocator);
        self.server.deinit(self.io);
        self.health_check.deinit();
    }

    pub fn start(self: *GrpcServer) !void {
        try self.health_check.setStatus("grpc.health.v1.Health", .SERVING);

        while (true) {
            const stream_ = try self.server.accept(self.io);
            transport.setRpcSocketOptions(stream_.socket.handle);
            // CC-1 + MW-4 — bound concurrent connections. Acquire a
            // semaphore permit BEFORE spawning so a hostile or buggy
            // client cannot exhaust system memory by opening 100k
            // sockets. The accept loop blocks here until a thread
            // exits and posts a permit, applying back-pressure all the
            // way up to the kernel listen queue.
            self.conn_sem.waitUncancelable(self.io);

            // Daemon per connection: handleConnection serves the connection
            // for its entire lifetime (while-true readMessage loop). Not a
            // thread-pool candidate — a bounded pool would starve under
            // long-lived or streaming RPCs, and a blocked readMessage has no
            // cooperative reschedule. Dedicated OS thread + detach is the
            // correct primitive for this shape.
            //
            // CC-4 — size the per-connection pthread stack from
            // `self.conn_stack_size` (env: `GRPC_ZIG_CONN_STACK_SIZE`,
            // default `DEFAULT_CONN_STACK_SIZE` = 8 MiB).
            //
            // The handler stack frames in this codebase are small (one
            // allocator, a couple ArrayLists, and HPACK fixed-size
            // buffers), so the ORIGINAL CC-4 optimization capped this at
            // 512 KiB to cut idle-connection memory ~16x. That value is
            // unsafe when the embedder uses a stack-trace-capturing
            // allocator: the connection thread's FIRST allocation
            // (`Transport.initServer` -> `allocStreamWindows`) runs the
            // DWARF self-unwinder, which materializes large CFI
            // register-rule state on the stack and overflowed 512 KiB into
            // the guard page -> SIGSEGV on the first unauthenticated
            // connection (GAP-0018, remote DoS). The DEFAULT is now 8 MiB
            // (the glibc default; the measured DebugAllocator crash floor
            // is just above 512 KiB, so this is a large verified margin).
            // Operators running a non-capturing
            // allocator can reclaim that memory by lowering
            // `GRPC_ZIG_CONN_STACK_SIZE` (floor `MIN_CONN_STACK_SIZE`,
            // 64 KiB). The memory optimization is preserved — just no
            // longer the unsafe default.
            const thread = std.Thread.spawn(.{ .stack_size = self.conn_stack_size }, connectionThread, .{ self, stream_ }) catch |err| {
                std.log.err("Failed to spawn connection thread: {}", .{err});
                stream_.close(self.io);
                // Spawn failed — return the permit we reserved.
                self.conn_sem.post(self.io);
                continue;
            };
            thread.detach();
        }
    }

    fn connectionThread(self: *GrpcServer, stream_: net.Stream) void {
        // Always release the admission permit on thread exit, no
        // matter how handleConnection returned.
        defer self.conn_sem.post(self.io);
        self.handleConnection(stream_) catch |err| {
            _ = self.conn_error_count.fetchAdd(1, .monotonic);
            std.log.err("Connection handling failed: {}", .{err});
        };
    }

    fn handleConnection(self: *GrpcServer, stream_: net.Stream) !void {
        var trans = if (self.on_tls_accept) |accept_fn| blk: {
            const tls_io = accept_fn(stream_) catch |err| {
                // TLS accept failed — close the stream before returning
                stream_.close(self.io);
                return err;
            };
            break :blk transport.Transport.initServerTls(self.allocator, self.io, stream_, tls_io) catch |err| {
                // initServerTls already cleans up tls_io via errdefer —
                // only close the underlying stream here to avoid double-free.
                stream_.close(self.io);
                return err;
            };
        } else transport.Transport.initServer(self.allocator, self.io, stream_) catch |err| {
            stream_.close(self.io);
            return err;
        };
        defer trans.deinit();

        // Propagate the server-level flow-control credit timeout to the
        // per-connection transport. Closes GAP-FU-002.
        trans.flow_credit_timeout_ns = self.flow_credit_timeout_ns;

        // Setup streaming
        var message_stream = streaming.MessageStream.init(self.allocator, 1024);
        defer message_stream.deinit();

        // SONNY-1560: hand inbound frame parsing to a dedicated reader
        // thread so connection-level control frames (above all
        // WINDOW_UPDATE) keep being processed while a handler is writing
        // a response. See the `GrpcServer` doc comment for the model.
        var queue = RequestQueue{ .allocator = self.allocator, .io = self.io };
        defer queue.deinit();

        var reader_ctx = ConnReader{ .server = self, .trans = &trans, .queue = &queue };
        // Same stack sizing rationale as the connection thread (GAP-0018):
        // the reader is the thread that allocates frame payloads, so it is
        // the one that runs a capturing allocator's DWARF self-unwinder.
        const reader_thread = std.Thread.spawn(
            .{ .stack_size = self.conn_stack_size },
            connectionReader,
            .{&reader_ctx},
        ) catch |err| {
            std.log.err("Failed to spawn connection reader thread: {}", .{err});
            return err;
        };
        // Deterministic teardown: unblock the reader's in-flight read and
        // JOIN it before `trans.deinit()` (declared earlier, so it runs
        // later) closes the socket. Nothing may touch `trans` afterwards.
        defer {
            reader_ctx.shutdown.store(true, .release);
            // POSIX `close()` on one thread does not wake another blocked in
            // `read()` on the same fd; `shutdown(SHUT_RDWR)` does. Mirrors
            // `ClientMux.deinit`. Best-effort — the fd is closed next anyway.
            //
            // SONNY-1568: done UNCONDITIONALLY, including for TLS. The old
            // `if (trans.tls_io == null)` guard meant that when the handler
            // loop left early on a TLS connection (a fatal dispatch error,
            // say) while the reader was blocked inside a TLS read, nothing
            // unblocked it and `join()` hung forever. `shutdown()` acts on
            // the underlying fd, which the TLS layer reads through, so it
            // wakes the reader for TLS exactly as it does for plaintext;
            // the TLS read then surfaces as a TLS/EOF error the reader
            // already classifies as a clean disconnect.
            _ = std.c.shutdown(trans.stream.socket.handle, 2);
            reader_thread.join();
        }

        while (queue.pop()) |request| {
            const message = request.payload;
            defer self.allocator.free(message);

            const compression_alg = compression.Compression.Algorithm.none;
            const decompressed = try self.compression.decompress(message, compression_alg);
            defer self.allocator.free(decompressed);

            // Route to handler by matching the request `:path` against the
            // registered handler's `name`. Closes GAP-0003 (#4): the legacy
            // path unconditionally invoked `handlers.items[0]`, which made
            // multi-method services impossible (every method got the first
            // handler). On no match we send an UNIMPLEMENTED (12) trailer
            // so the client gets a definitive answer instead of hanging.
            //
            // `method` / `stream_id` come from the queued request rather
            // than `trans.lastMethod()` / `trans.last_stream_id`: the reader
            // thread may already have parsed a LATER request's HEADERS.
            const method = request.method();
            const stream_id = request.stream_id;
            // The handler thread is the only writer of `last_stream_id`, so
            // `writeMessage` / `writeStreamMessage` / `endStream` (which all
            // default to it) keep targeting the stream we are serving.
            trans.last_stream_id = stream_id;

            // Observability seam (Task 1.5). One server span per inbound
            // request iteration. Status updates flow from the dispatch
            // outcome below: 0 (OK) on handler success, gRPC UNKNOWN (2)
            // on handler error, UNAUTHENTICATED (16) on auth failure,
            // UNIMPLEMENTED (12) on no-match. Comptime no-op when
            // `-Dwith_otel=false`.
            var __obs_span = observability.startServerSpan(.{
                .method = "POST",
                .route = method,
                .url = method,
            });
            // Default to gRPC INTERNAL (13); the success/error sites below
            // overwrite via `endServerSpan` before the defer fires.
            // `defer span.end(null)` is the lifecycle close; callers may
            // attach the gRPC status via `endServerSpan` BEFORE the defer
            // — when the seam is enabled the second `end` is idempotent.
            defer __obs_span.end(null);
            // I-1 fix: make lifecycle symmetric with the client. If any
            // `try` between here and the explicit grpc-status sites below
            // (lines for OK/UNKNOWN/UNIMPLEMENTED/UNAUTHENTICATED) bails
            // out, the span ends with status 13 (gRPC INTERNAL) instead
            // of silently with no status attached.
            errdefer observability.endServerSpan(__obs_span, 13);

            // Auth gate (closes GAP-0001 / #2). When `require_auth` is set
            // we must verify the `authorization` header before dispatching;
            // any failure produces a `grpc-status: 16` (UNAUTHENTICATED)
            // trailer with `@errorName(err)` as the message and we skip
            // dispatch entirely. Ordering is unchanged: the gate still runs
            // before handler lookup and before any handler runs.
            if (self.require_auth) {
                const auth_value = request.authorization();
                if (auth_value.len == 0) {
                    std.log.warn("auth gate: missing 'authorization' for {s}", .{method});
                    trans.endStreamWithStatus(stream_id, 16, "missing authorization") catch |err| {
                        std.log.err("auth gate: failed to emit UNAUTHENTICATED trailer: {}", .{err});
                    };
                    observability.endServerSpan(__obs_span, 16); // gRPC UNAUTHENTICATED
                    continue;
                }
                const claims = self.auth.verifyToken(auth_value) catch |err| {
                    std.log.warn("auth gate: rejected {s}: {s}", .{ method, @errorName(err) });
                    trans.endStreamWithStatus(stream_id, 16, @errorName(err)) catch |trailer_err| {
                        std.log.err("auth gate: failed to emit UNAUTHENTICATED trailer: {}", .{trailer_err});
                    };
                    observability.endServerSpan(__obs_span, 16); // gRPC UNAUTHENTICATED
                    continue;
                };
                // Free the duped subject — we don't surface it to handlers
                // yet (future work). The successful auth implies the token
                // claims are valid; tearing the slice down here is safe.
                self.allocator.free(claims.sub);
            }

            var matched: ?Handler = null;
            for (self.handlers.items) |h| {
                if (std.mem.eql(u8, h.name, method)) {
                    matched = h;
                    break;
                }
            }
            if (matched) |handler| {
                handler.handler_fn(decompressed, method, &trans, self.allocator) catch |err| {
                    // R1: surface handler errors to the client as a
                    // grpc-status: 2 (UNKNOWN) trailer. The legacy code
                    // logged the error and silently continued; clients
                    // hung indefinitely waiting for trailers that never
                    // came. Now we emit a proper trailer-only HEADERS
                    // frame with the error name so the client sees a
                    // definite end-of-stream and a meaningful status.
                    std.log.err("Handler error: {}", .{err});
                    trans.endStreamWithStatus(stream_id, 2, @errorName(err)) catch |trailer_err| {
                        std.log.err("Failed to emit error trailer: {}", .{trailer_err});
                    };
                    observability.endServerSpan(__obs_span, 2); // gRPC UNKNOWN
                    continue;
                };
                observability.endServerSpan(__obs_span, 0); // gRPC OK
            } else {
                std.log.warn("No handler for method '{s}' (stream {d})", .{ method, stream_id });
                trans.endStreamWithStatus(stream_id, 12, "method not found") catch |err| {
                    std.log.err("Failed to emit UNIMPLEMENTED trailer: {}", .{err});
                };
                observability.endServerSpan(__obs_span, 12); // gRPC UNIMPLEMENTED
                continue;
            }
        }

        // The reader closed the queue. A fatal (non peer-disconnect) frame
        // error is propagated exactly as the pre-split `readMessage` loop
        // propagated it, so `connectionThread` still counts it in
        // `conn_error_count`.
        if (queue.fatalError()) |err| return err;
    }
};

/// Upper bound on fully-assembled inbound requests a single connection may
/// have waiting for its handler thread (SONNY-1560).
///
/// The reader thread must NEVER block on the handler — if it did, a handler
/// parked in `reserveSendCredit` could not be rescued by the WINDOW_UPDATE
/// the reader is supposed to deliver, which is exactly the deadlock this
/// change removes. So the queue is bounded and overflow is rejected rather
/// than waited on: a peer that pipelines more than this many requests
/// without letting the server drain gets `grpc-status: 8`
/// (RESOURCE_EXHAUSTED) on the overflowing stream and the connection stays
/// healthy. 64 is far above anything a well-behaved client produces against
/// a server that serves one request at a time per connection.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// gRPC status 8 — RESOURCE_EXHAUSTED.
const GRPC_STATUS_RESOURCE_EXHAUSTED: u8 = 8;

/// One fully-assembled inbound request, handed from a connection's reader
/// thread to its handler thread.
///
/// `method` / `authorization` are snapshotted (by value) at HEADERS-parse
/// time rather than read back from the `Transport` at dispatch time: the
/// reader may already have parsed a later request's HEADERS by then, which
/// would make `Transport.lastMethod()` describe the wrong request.
const PendingRequest = struct {
    stream_id: u31,
    method_buf: [256]u8 = .{0} ** 256,
    method_len: usize = 0,
    auth_buf: [1024]u8 = .{0} ** 1024,
    auth_len: usize = 0,
    /// Owned gRPC message bytes (gRPC 5-byte prefix already stripped).
    /// Freed by whoever takes the request off the queue.
    payload: []u8,

    fn method(self: *const PendingRequest) []const u8 {
        return self.method_buf[0..self.method_len];
    }

    fn authorization(self: *const PendingRequest) []const u8 {
        return self.auth_buf[0..self.auth_len];
    }
};

/// Bounded FIFO handoff between a connection's reader thread (single
/// producer) and its handler thread (single consumer).
///
/// `mutex` guards `items`, `closed` and `fatal`; `cond` wakes the consumer.
/// `close` is idempotent and always broadcasts, so the consumer can never
/// be left parked after the reader exits.
const RequestQueue = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    items: std.ArrayList(PendingRequest) = .empty,
    closed: bool = false,
    fatal: ?anyerror = null,

    /// Free anything still queued. Call only after the reader thread has
    /// been joined.
    fn deinit(self: *RequestQueue) void {
        for (self.items.items) |item| self.allocator.free(item.payload);
        self.items.deinit(self.allocator);
    }

    /// Producer side. Returns false when the queue is closed or already at
    /// `MAX_PENDING_REQUESTS`; the caller still owns `request.payload` then.
    /// Never blocks.
    fn push(self: *RequestQueue, request: PendingRequest) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) return false;
        if (self.items.items.len >= MAX_PENDING_REQUESTS) return false;
        self.items.append(self.allocator, request) catch return false;
        self.cond.signal(self.io);
        return true;
    }

    /// Consumer side. Blocks until a request is available; returns null once
    /// the queue is closed AND drained. The caller owns `payload`.
    fn pop(self: *RequestQueue) ?PendingRequest {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (true) {
            if (self.items.items.len > 0) return self.items.orderedRemove(0);
            if (self.closed) return null;
            self.cond.waitUncancelable(self.io, &self.mutex);
        }
    }

    /// Close the queue, recording an optional fatal error for the consumer
    /// to propagate. Idempotent; the first error recorded wins.
    fn close(self: *RequestQueue, err: ?anyerror) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (!self.closed) {
            self.closed = true;
            self.fatal = err;
        }
        self.cond.broadcast(self.io);
    }

    fn fatalError(self: *RequestQueue) ?anyerror {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.fatal;
    }
};

/// Everything the per-connection reader thread needs. Lives on the handler
/// thread's stack for the lifetime of the connection; the handler joins the
/// reader before this goes out of scope.
const ConnReader = struct {
    server: *GrpcServer,
    trans: *transport.Transport,
    queue: *RequestQueue,
    /// Set by the handler thread to ask the reader to stop. The reader also
    /// stops on EOF/error, which is the usual path.
    shutdown: std.atomic.Value(bool) = .init(false),
};

/// Reader-thread entry point. Runs `readFrames` and translates its exit
/// into a queue close, using exactly the error classification the pre-split
/// `handleConnection` read loop applied to `Transport.readMessage`.
fn connectionReader(ctx: *ConnReader) void {
    var fatal: ?anyerror = null;
    readFrames(ctx) catch |err| switch (err) {
        // Treat all "client went away" signals as a clean shutdown.
        // The kernel surfaces a peer-side close as ConnectionClosed
        // when the read returns 0 bytes, but it can also surface as
        // ConnectionResetByPeer or EndOfStream depending on whether
        // the peer sent FIN cleanly or RST. Logging these as errors
        // produces noise on every legitimate disconnect.
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.BrokenPipe,
        => {},
        // TLS errors indicate the connection is gone — treat like
        // ConnectionClosed to avoid propagating the error which could
        // cause cleanup issues (double-free on aarch64).
        error.TlsReadFailed,
        error.TlsWriteFailed,
        error.TlsHandshakeFailed,
        error.TlsNotInitialized,
        => std.log.warn("TLS connection error; closing: {}", .{err}),
        error.MessageTooLarge => std.log.warn(
            "closing connection: inbound gRPC message exceeded max_recv_message_bytes",
            .{},
        ),
        error.ProtocolError, error.HeaderBlockTooLarge => std.log.warn(
            "closing connection: HTTP/2 protocol violation in header block",
            .{},
        ),
        else => fatal = err,
    };
    // SONNY-1568: the reader owns the read side of the socket, so its exit
    // is this connection's death certificate. Publish that BEFORE closing
    // the queue.
    //
    // Closing the queue only wakes a handler blocked in `RequestQueue.pop`.
    // A handler that is mid-response is instead parked in
    // `Transport.reserveSendCredit` (a futex on `flow_epoch`) waiting for a
    // WINDOW_UPDATE that can never arrive now — it would sleep out the full
    // `flow_credit_timeout_ns` (30 s by default) still holding its
    // admission-control permit, and `handleConnection` could not join us
    // until it did. `markPeerGone` sets the flag under `flow_mutex` and
    // wakes every credit waiter, which returns `error.PeerGone` at once.
    ctx.trans.markPeerGone();
    ctx.queue.close(fatal);
}

/// The connection's inbound frame loop. This is the ONLY caller of
/// `Transport.readFrame` for a server connection, and it keeps running
/// while handlers write — that is the whole point of SONNY-1560.
///
/// Frame handling mirrors `Transport.readMessageCore(null)` (the server /
/// legacy path) one-for-one; the only difference is that a completed gRPC
/// message is pushed onto the dispatch queue instead of being returned.
///
/// HAZARD — the reader can be stalled by a peer that stops reading TCP
/// (SONNY-1568, minor): three things this loop does take
/// `Transport.write_mutex` — the SETTINGS ACK, the PING ACK, and the
/// receive-window refills inside `Transport.maybeRefillRecvWindow`. If a
/// handler is at that moment inside `ioWriteLocked` on a socket whose send
/// buffer the peer has stopped draining, that handler holds `write_mutex`
/// until the kernel accepts the bytes, and the reader blocks on the mutex
/// and stops reading. The SONNY-1560 fix itself survives this — the
/// WINDOW_UPDATE path (`Transport.processWindowUpdate`) needs only
/// `flow_mutex`, never `write_mutex`, so credit keeps flowing and a stuck
/// writer still makes progress the instant the peer credits it — but a peer
/// that both withholds credit and refuses to read can wedge both threads
/// until `flow_credit_timeout_ns` fires. Mitigations, neither taken here
/// because both are bigger than this change:
///   * a bounded write deadline on the socket (`SO_SNDTIMEO`, or a
///     deadline threaded through `ioWriteLocked`) so no writer can hold
///     `write_mutex` longer than that bound. `Transport` has no such
///     deadline today — `setRpcSocketOptions` sets only `TCP_NODELAY` and
///     `SO_KEEPALIVE` — so there is nothing cheap to apply to the ACK and
///     refill writes below;
///   * a dedicated writer thread with an outbound frame queue, so control
///     frames never contend with response bytes for the socket at all.
///
/// INVARIANT — cross-stream DATA accumulation: `grpc_buf` is a SINGLE
/// assembly buffer for the whole connection and the completed message is
/// attributed to `pending`, i.e. to the most recent HEADERS seen, not to
/// `frame.stream_id`. Interleaving DATA from two streams would therefore
/// splice their payloads together. That is safe against this repo's peers
/// and is inherited verbatim from `Transport.readMessageCore`: `ClientMux`
/// (and `Transport.writeRequestOnStream`) emit a request's HEADERS and its
/// DATA under one acquisition of `write_mutex`, so a request's frames
/// cannot be split by another stream's frames on the wire. `loopback-test`
/// scenario 6 covers the concurrent case (8 in-flight ClientMux streams ×
/// 16 messages). A general-purpose peer that fragments a large request
/// across streams would need per-stream assembly buffers keyed by
/// `frame.stream_id`; the `pending` snapshot is the seam for that.
fn readFrames(ctx: *ConnReader) !void {
    const self = ctx.server;
    const trans = ctx.trans;
    const allocator = self.allocator;
    const FT = http2.frame.FrameType;
    const FF = http2.frame.FrameFlags;

    // Inbound gRPC message assembly buffer. As in `readMessageCore`, DATA
    // from any stream is accumulated and anything past the completed
    // message is discarded.
    var grpc_buf: std.ArrayList(u8) = .empty;
    defer grpc_buf.deinit(allocator);

    // Most recent request HEADERS seen, snapshotted for the next completed
    // message (the server learns the stream id and `:path` from HEADERS).
    var pending: PendingRequest = .{ .stream_id = trans.last_stream_id, .payload = undefined };

    while (!ctx.shutdown.load(.acquire)) {
        const frame = try trans.readFrame();
        const payload = frame.payload;

        switch (frame.frame_type) {
            @intFromEnum(FT.DATA) => {
                const data_len: u32 = @intCast(payload.len);
                grpc_buf.appendSlice(allocator, payload) catch {
                    allocator.free(payload);
                    return error.OutOfMemory;
                };
                allocator.free(payload);
                // Refill receive windows now that the bytes have been
                // consumed (NW-2).
                trans.maybeRefillRecvWindow(frame.stream_id, data_len);

                // NEW-1 (#43): bound the assembly buffer BEFORE parsing.
                transport.Transport.checkRecvBufferSize(grpc_buf.items.len, trans.max_recv_message_bytes) catch |err| {
                    trans.writeRstStream(frame.stream_id, transport.HTTP2_ERROR_FLOW_CONTROL_ERROR);
                    return err;
                };

                if (grpc_buf.items.len < 5) continue;
                const prefix = transport.decodeGrpcPrefix(grpc_buf.items) catch
                    return transport.TransportError.Http2Error;
                const msg_len = prefix.msg_len;
                transport.Transport.checkRecvMessageSize(msg_len, trans.max_recv_message_bytes) catch |err| {
                    trans.writeRstStream(frame.stream_id, transport.HTTP2_ERROR_FLOW_CONTROL_ERROR);
                    return err;
                };
                const need: usize = 5 + @as(usize, msg_len);
                if (grpc_buf.items.len < need) continue;

                const message = try allocator.alloc(u8, msg_len);
                @memcpy(message, grpc_buf.items[5..need]);
                grpc_buf.clearRetainingCapacity();

                var request = pending;
                request.payload = message;
                if (!ctx.queue.push(request)) {
                    // Queue full (or already closed): refuse this stream
                    // rather than blocking the reader — see
                    // MAX_PENDING_REQUESTS.
                    std.log.warn(
                        "connection request queue full ({d}); refusing stream {d}",
                        .{ MAX_PENDING_REQUESTS, request.stream_id },
                    );
                    trans.endStreamWithStatus(
                        request.stream_id,
                        GRPC_STATUS_RESOURCE_EXHAUSTED,
                        "server request queue full",
                    ) catch {};
                    allocator.free(message);
                }
                continue;
            },
            @intFromEnum(FT.HEADERS) => {
                const end_headers = (frame.flags & FF.END_HEADERS) != 0;
                if (end_headers) {
                    trans.extractPathFromHpack(payload);
                    allocator.free(payload);
                } else {
                    // I5 (#48): reassemble CONTINUATION fragments.
                    const block = trans.collectContinuations(frame.stream_id, payload) catch |err| {
                        allocator.free(payload);
                        return err;
                    };
                    allocator.free(payload);
                    trans.extractPathFromHpack(block);
                    allocator.free(block);
                }
                // Snapshot the per-request metadata for the message that
                // this HEADERS frame opens.
                pending.stream_id = frame.stream_id;
                const m = trans.lastMethod();
                pending.method_len = @min(m.len, pending.method_buf.len);
                @memcpy(pending.method_buf[0..pending.method_len], m[0..pending.method_len]);
                const a = trans.lastAuthorization();
                pending.auth_len = @min(a.len, pending.auth_buf.len);
                @memcpy(pending.auth_buf[0..pending.auth_len], a[0..pending.auth_len]);
                continue;
            },
            @intFromEnum(FT.SETTINGS) => {
                const is_ack = (frame.flags & 0x1) != 0;
                if (!is_ack) {
                    // Apply peer settings (e.g. SETTINGS_MAX_FRAME_SIZE and
                    // SETTINGS_INITIAL_WINDOW_SIZE) before ACKing.
                    trans.applyPeerSettings(payload);
                    allocator.free(payload);
                    try trans.writeFrame(.SETTINGS, 0x1, 0, &.{});
                } else {
                    allocator.free(payload);
                }
                continue;
            },
            @intFromEnum(FT.WINDOW_UPDATE) => {
                // THE fix (SONNY-1560): this now runs even while a handler
                // is parked in `reserveSendCredit` writing a response.
                trans.processWindowUpdate(frame.stream_id, payload);
                allocator.free(payload);
                continue;
            },
            @intFromEnum(FT.PING) => {
                const is_ack = (frame.flags & 0x1) != 0;
                if (!is_ack) {
                    var ping_data: [8]u8 = .{0} ** 8;
                    const copy_len = @min(payload.len, 8);
                    @memcpy(ping_data[0..copy_len], payload[0..copy_len]);
                    allocator.free(payload);
                    try trans.writeFrame(.PING, 0x1, 0, ping_data[0..copy_len]);
                } else {
                    allocator.free(payload);
                }
                continue;
            },
            @intFromEnum(FT.RST_STREAM), @intFromEnum(FT.GOAWAY) => {
                allocator.free(payload);
                return transport.TransportError.ConnectionClosed;
            },
            @intFromEnum(FT.CONTINUATION) => {
                // §6.10: a CONTINUATION with no preceding open header block
                // is a connection error (PROTOCOL_ERROR).
                allocator.free(payload);
                trans.emitGoawayProtocolError();
                return transport.TransportError.ProtocolError;
            },
            else => {
                // Unknown frame type — skip
                allocator.free(payload);
                continue;
            },
        }
    }
}

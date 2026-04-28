const std = @import("std");
const proto = @import("proto/service.zig");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const auth = @import("features/auth.zig");
const streaming = @import("features/streaming.zig");
const health = @import("features/health.zig");
const net = std.Io.net;

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

    /// Default cap on concurrent accepted connections when
    /// `GRPC_ZIG_MAX_CONNS` is unset.
    pub const DEFAULT_MAX_CONNS: usize = 1024;
    /// Default per-stream send-credit timeout (milliseconds) when
    /// `GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS` is unset.
    pub const DEFAULT_FLOW_CREDIT_TIMEOUT_MS: u64 = 30_000;

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

    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16, secret_key: []const u8) !GrpcServer {
        const address = try net.IpAddress.parseIp4("0.0.0.0", port);
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
        };
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
            // CC-4 — cap the pthread stack at 512 KiB instead of the
            // glibc default of 8 MiB. The handler stack frames in this
            // codebase are small (one allocator, a couple ArrayLists,
            // and HPACK fixed-size buffers) so 512 KiB is comfortable
            // headroom; this drops idle-connection memory from ~8 MiB
            // to ~512 KiB, ~16x reduction at fleet steady state.
            const thread = std.Thread.spawn(.{ .stack_size = 512 * 1024 }, connectionThread, .{ self, stream_ }) catch |err| {
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

        while (true) {
            const message = trans.readMessage() catch |err| switch (err) {
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
                => break,
                // TLS errors indicate the connection is gone — treat like
                // ConnectionClosed to avoid propagating the error which could
                // cause cleanup issues (double-free on aarch64).
                error.TlsReadFailed,
                error.TlsWriteFailed,
                error.TlsHandshakeFailed,
                error.TlsNotInitialized,
                => break,
                else => return err,
            };
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
            const method = trans.lastMethod();
            const stream_id = trans.last_stream_id;

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

            // Auth gate (closes GAP-0001 / #2). When `require_auth` is set
            // we must verify the `authorization` header before dispatching;
            // any failure produces a `grpc-status: 16` (UNAUTHENTICATED)
            // trailer with `@errorName(err)` as the message and we skip
            // dispatch entirely.
            if (self.require_auth) {
                const auth_value = trans.lastAuthorization();
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
    }
};

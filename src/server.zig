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

    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16, secret_key: []const u8) !GrpcServer {
        const address = try net.IpAddress.parseIp4("0.0.0.0", port);
        const server = try address.listen(io, .{ .reuse_address = true });
        return GrpcServer{
            .allocator = allocator,
            .io = io,
            .address = address,
            .server = server,
            .handlers = try std.ArrayList(Handler).initCapacity(allocator, 1),
            .compression = compression.Compression.init(allocator),
            .auth = auth.Auth.init(allocator, secret_key),
            .health_check = health.HealthCheck.init(allocator),
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
                continue;
            };
            thread.detach();
        }
    }

    fn connectionThread(self: *GrpcServer, stream_: net.Stream) void {
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
                    continue;
                }
                const claims = self.auth.verifyToken(auth_value) catch |err| {
                    std.log.warn("auth gate: rejected {s}: {s}", .{ method, @errorName(err) });
                    trans.endStreamWithStatus(stream_id, 16, @errorName(err)) catch |trailer_err| {
                        std.log.err("auth gate: failed to emit UNAUTHENTICATED trailer: {}", .{trailer_err});
                    };
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
                    continue;
                };
            } else {
                std.log.warn("No handler for method '{s}' (stream {d})", .{ method, stream_id });
                trans.endStreamWithStatus(stream_id, 12, "method not found") catch |err| {
                    std.log.err("Failed to emit UNIMPLEMENTED trailer: {}", .{err});
                };
                continue;
            }
        }
    }
};

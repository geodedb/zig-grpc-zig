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
            const thread = std.Thread.spawn(.{}, connectionThread, .{ self, stream_ }) catch |err| {
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
                error.ConnectionClosed => break,
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

            // Route to handler, passing the method path and transport
            const method = trans.lastMethod();
            if (self.handlers.items.len > 0) {
                const handler = self.handlers.items[0];
                handler.handler_fn(decompressed, method, &trans, self.allocator) catch |err| {
                    std.log.err("Handler error: {}", .{err});
                    continue;
                };
            }
        }
    }
};

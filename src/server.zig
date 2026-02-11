const std = @import("std");
const spice = @import("spice");
const proto = @import("proto/service.zig");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const auth = @import("features/auth.zig");
const streaming = @import("features/streaming.zig");
const health = @import("features/health.zig");

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
    address: std.net.Address,
    server: std.net.Server,
    handlers: std.ArrayList(Handler),
    compression: compression.Compression,
    auth: auth.Auth,
    health_check: health.HealthCheck,
    on_tls_accept: ?*const fn (std.net.Stream) anyerror!transport.TlsIo = null,

    pub fn init(allocator: std.mem.Allocator, port: u16, secret_key: []const u8) !GrpcServer {
        const address = try std.net.Address.parseIp("0.0.0.0", port);
        const server = try address.listen(.{ .reuse_address = true });
        return GrpcServer{
            .allocator = allocator,
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
        self.server.deinit();
        self.health_check.deinit();
    }

    pub fn start(self: *GrpcServer) !void {
        try self.health_check.setStatus("grpc.health.v1.Health", .SERVING);

        while (true) {
            const connection = try self.server.accept();
            // Spawn a thread per connection for concurrent handling
            const thread = std.Thread.spawn(.{}, connectionThread, .{ self, connection }) catch |err| {
                std.log.err("Failed to spawn connection thread: {}", .{err});
                connection.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn connectionThread(self: *GrpcServer, conn: std.net.Server.Connection) void {
        self.handleConnection(conn) catch |err| {
            std.log.err("Connection handling failed: {}", .{err});
        };
    }

    fn handleConnection(self: *GrpcServer, conn: std.net.Server.Connection) !void {
        var trans = if (self.on_tls_accept) |accept_fn| blk: {
            const tls_io = accept_fn(conn.stream) catch |err| {
                // TLS accept failed — close the stream before returning
                conn.stream.close();
                return err;
            };
            break :blk transport.Transport.initServerTls(self.allocator, conn.stream, tls_io) catch |err| {
                // initServerTls already cleans up tls_io via errdefer —
                // only close the underlying stream here to avoid double-free.
                conn.stream.close();
                return err;
            };
        } else transport.Transport.initServer(self.allocator, conn.stream) catch |err| {
            conn.stream.close();
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

const std = @import("std");
const proto = @import("proto/service.zig");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const auth = @import("features/auth.zig");
const streaming = @import("features/streaming.zig");
const health = @import("features/health.zig");
const net = std.Io.net;

pub const GrpcClient = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: transport.Transport,
    compression: compression.Compression,
    auth: ?auth.Auth,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) !GrpcClient {
        const address = try net.IpAddress.resolve(io, host, port);
        const connection = try address.connect(io, .{ .mode = .stream });

        const authority = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        defer allocator.free(authority);

        return GrpcClient{
            .allocator = allocator,
            .io = io,
            .transport = try transport.Transport.initClient(allocator, io, connection, authority),
            .compression = compression.Compression.init(allocator),
            .auth = null,
        };
    }

    pub fn deinit(self: *GrpcClient) void {
        self.transport.deinit();
    }

    pub fn setAuth(self: *GrpcClient, secret_key: []const u8) !void {
        self.auth = auth.Auth.init(self.allocator, secret_key);
    }

    pub fn checkHealth(_: *GrpcClient, _: []const u8) !health.HealthStatus {
        // Health check requires JSON serialization; return unknown for now
        return .UNKNOWN;
    }

    /// Server-streaming RPC: send a single request, then read messages until
    /// the server signals END_STREAM. Each message is appended to `out`,
    /// allocated by `self.allocator`. On return, the caller owns every slice
    /// in `out` and must free them (and clear the list) before reuse.
    ///
    /// `compression_alg` is applied symmetrically: the request is compressed
    /// outbound and each response message is decompressed inbound. The server
    /// must echo the algorithm or use a passthrough handler that does not
    /// transform the bytes — see notes in `Compression`.
    pub fn streamCall(
        self: *GrpcClient,
        method_path: []const u8,
        request: []const u8,
        compression_alg: compression.Compression.Algorithm,
        out: *std.ArrayList([]u8),
    ) !void {
        const compressed = try self.compression.compress(request, compression_alg);
        defer self.allocator.free(compressed);

        try self.transport.writeRequest(compressed, method_path);

        while (true) {
            const sf = try self.transport.readStreamFrame();
            if (sf.data) |raw| {
                const decompressed = self.compression.decompress(raw, compression_alg) catch |err| {
                    self.allocator.free(raw);
                    return err;
                };
                self.allocator.free(raw);
                try out.append(self.allocator, decompressed);
            }
            if (sf.end_stream) break;
        }
    }

    pub fn call(self: *GrpcClient, method_path: []const u8, request: []const u8, compression_alg: compression.Compression.Algorithm) ![]u8 {
        // Add auth token if available
        var headers = std.StringHashMap([]const u8).init(self.allocator);
        defer headers.deinit();

        if (self.auth) |*auth_client| {
            const token = try auth_client.generateToken("client", 3600);
            defer self.allocator.free(token);
            try headers.put("authorization", token);
        }

        // Compress request
        const compressed = try self.compression.compress(request, compression_alg);
        defer self.allocator.free(compressed);

        try self.transport.writeRequest(compressed, method_path);
        const response_bytes = try self.transport.readMessage();
        defer self.allocator.free(response_bytes);

        // Decompress response
        return self.compression.decompress(response_bytes, compression_alg);
    }
};

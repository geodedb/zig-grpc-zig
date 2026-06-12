const std = @import("std");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const auth = @import("features/auth.zig");
const streaming = @import("features/streaming.zig");
const net = std.Io.net;

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

pub const GrpcClient = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: transport.Transport,
    compression: compression.Compression,
    auth: ?auth.Auth,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) !GrpcClient {
        const address = try net.IpAddress.resolve(io, host, port);
        const connection = try address.connect(io, .{ .mode = .stream });
        transport.setRpcSocketOptions(connection.socket.handle);

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
        // Observability seam (Task 1.5). gRPC IS HTTP/2, so we use the
        // otel HTTP helper directly with a synthesized URL. The seam is
        // a comptime-known no-op when `-Dwith_otel=false`.
        //
        // Lifecycle: `startClientSpan` returns a `Span` value owned by
        // the caller. We close it explicitly on the success path with
        // gRPC status 0 and via `errdefer` with gRPC INTERNAL (13) on
        // any error. The defer span.end(null) below is the
        // belt-and-suspenders fallback the recipe requires — when the
        // seam is enabled, both `endClientSpan` and `span.end` are
        // idempotent for status reporting (only the first attribute
        // write wins; the second `end` is a redundant no-op). When the
        // seam is disabled the entire block compiles out.
        var __obs_url_buf: [256]u8 = undefined;
        const __obs_url = std.fmt.bufPrint(
            __obs_url_buf[0..],
            "grpc://{s}/{s}",
            .{ self.transport.authority, method_path },
        ) catch method_path;
        var __obs_span = observability.startClientSpan(.{
            .method = "POST",
            .route = method_path,
            .url = __obs_url,
        });
        defer __obs_span.end(null);
        errdefer observability.endClientSpan(__obs_span, 13); // gRPC INTERNAL

        // Add auth token if available. Closes GAP-0002: the headers map
        // is now passed through to the transport instead of being thrown
        // away after construction. Token bytes are owned by `headers`
        // until after writeRequestWithMetadata returns.
        var headers: std.StringHashMapUnmanaged([]const u8) = .empty;
        defer headers.deinit(self.allocator);

        var token_owned: ?[]u8 = null;
        defer if (token_owned) |t| self.allocator.free(t);

        if (self.auth) |*auth_client| {
            const token = try auth_client.generateToken("client", 3600);
            token_owned = token;
            try headers.put(self.allocator, "authorization", token);
        }

        // Compress request
        const compressed = try self.compression.compress(request, compression_alg);
        defer self.allocator.free(compressed);

        try self.transport.writeRequestWithMetadata(
            compressed,
            method_path,
            if (headers.count() == 0) null else &headers,
        );
        const response_bytes = try self.transport.readMessage();
        defer self.allocator.free(response_bytes);

        // Decompress response
        const result = try self.compression.decompress(response_bytes, compression_alg);
        observability.endClientSpan(__obs_span, 0); // gRPC OK
        return result;
    }
};

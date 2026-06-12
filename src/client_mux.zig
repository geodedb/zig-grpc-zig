//! `ClientMux` — multiplexed gRPC-over-HTTP/2 client.
//!
//! Wraps a single `Transport` connection and lets multiple threads issue
//! `call()` invocations concurrently. Each call gets a fresh odd-numbered
//! stream id; a dedicated reader thread demultiplexes incoming frames by
//! stream id into per-call completion slots.
//!
//! The single-call `GrpcClient` API in `client.zig` remains for simple
//! request/response use; `ClientMux` is what you reach for when you need
//! N concurrent in-flight RPCs on a single connection.

const std = @import("std");
const transport = @import("transport.zig");
const compression = @import("features/compression.zig");
const observability = @import("observability.zig");
const net = std.Io.net;
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

const Allocator = std.mem.Allocator;

/// Per-stream completion slot. The owning call() thread allocates this on
/// its stack, registers it with the mux, writes its request, then blocks on
/// `cond` until the reader thread sets `end_stream` (or `err`).
pub const StreamSlot = struct {
    /// Concatenated DATA-frame payloads for this stream, gRPC 5-byte prefix
    /// stripped. Built up by the reader thread; consumed by the caller after
    /// `end_stream` is signaled.
    data: std.ArrayList(u8) = .empty,
    end_stream: bool = false,
    err: ?anyerror = null,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,

    pub fn deinit(self: *StreamSlot, allocator: Allocator) void {
        self.data.deinit(allocator);
    }
};

/// Core of readerLoop's DATA handling, extracted for unit testing
/// (closes quality R2 / #57). Caller MUST hold `slot.mutex` and is
/// responsible for calling `slot.cond.broadcast` after this returns
/// whenever `slot.end_stream` is true.
///
/// Invariant: on ANY failure (bad prefix, over-cap, OOM) this sets
/// BOTH `slot.err` and `slot.end_stream` — never just `err` — so a
/// caller blocked on `while (!slot.end_stream)` always wakes.
pub fn deliverData(
    slot: *StreamSlot,
    allocator: Allocator,
    payload: []const u8,
    end: bool,
    max_recv_message_bytes: u32,
) void {
    if (payload.len >= 5) {
        if (transport.decodeGrpcPrefix(payload)) |prefix| {
            const msg_len = prefix.msg_len;
            const over_cap = msg_len > max_recv_message_bytes or
                slot.data.items.len + msg_len > max_recv_message_bytes;
            if (over_cap) {
                slot.err = transport.TransportError.MessageTooLarge;
                slot.end_stream = true;
                return;
            }
            if (payload.len >= 5 + msg_len) {
                slot.data.appendSlice(allocator, payload[5 .. 5 + msg_len]) catch |e| {
                    slot.err = e;
                    slot.end_stream = true;
                    return;
                };
            }
        } else |e| {
            slot.err = e;
            slot.end_stream = true;
            return;
        }
    }
    if (end) slot.end_stream = true;
}

pub const ClientMux = struct {
    allocator: Allocator,
    io: std.Io,
    transport: transport.Transport,
    compression: compression.Compression,
    /// Hostname provided at init time, owned by this struct (heap allocated
    /// via `allocator.dupe`). Combined with the port to form the
    /// `:authority` header for outgoing requests.
    host: []const u8,

    streams: std.AutoHashMap(u31, *StreamSlot) = undefined,
    streams_mutex: std.Io.Mutex = .init,

    /// Next outgoing stream id. Client-initiated streams must be odd
    /// (RFC 7540 §5.1.1) and monotonically increasing. We reserve id 1 for
    /// the legacy single-call code path that lives in `Transport`, so the
    /// mux starts allocating at 3.
    next_stream_id: u31 = 3,

    reader_thread: std.Thread = undefined,
    reader_started: bool = false,
    shutdown: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: Allocator, io: std.Io, host: []const u8, port: u16) !*ClientMux {
        const self = try allocator.create(ClientMux);
        errdefer allocator.destroy(self);

        const address = try net.IpAddress.resolve(io, host, port);
        const conn = try address.connect(io, .{ .mode = .stream });

        const host_owned = try allocator.dupe(u8, host);
        errdefer allocator.free(host_owned);

        const authority = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        defer allocator.free(authority);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .transport = try transport.Transport.initClient(allocator, io, conn, authority),
            .compression = compression.Compression.init(allocator),
            .host = host_owned,
            .streams = std.AutoHashMap(u31, *StreamSlot).init(allocator),
        };
        errdefer self.transport.deinit();
        errdefer self.streams.deinit();

        self.reader_thread = try std.Thread.spawn(.{}, readerLoop, .{self});
        self.reader_started = true;

        return self;
    }

    pub fn deinit(self: *ClientMux) void {
        self.shutdown.store(true, .release);

        // POSIX `close()` on one thread does not wake another thread blocked
        // in `read()` on the same fd; we need `shutdown(SHUT_RDWR, fd)` to
        // make the in-flight read return EOF/error so the reader thread can
        // exit. Best-effort: ignore failure (e.g. NotConnected if peer
        // already closed) since we'll close the fd next anyway.
        // SHUT_RDWR == 2 (POSIX).
        if (self.transport.tls_io == null) {
            _ = std.c.shutdown(self.transport.stream.socket.handle, 2);
        }

        if (self.reader_started) {
            self.reader_thread.join();
        }

        self.transport.deinit();
        self.streams.deinit();
        self.allocator.free(self.host);
        self.allocator.destroy(self);
    }

    fn allocStreamId(self: *ClientMux) u31 {
        self.streams_mutex.lockUncancelable(self.io);
        defer self.streams_mutex.unlock(self.io);
        const sid = self.next_stream_id;
        self.next_stream_id +%= 2;
        return sid;
    }

    fn registerStream(self: *ClientMux, sid: u31, slot: *StreamSlot) !void {
        self.streams_mutex.lockUncancelable(self.io);
        defer self.streams_mutex.unlock(self.io);
        try self.streams.put(sid, slot);
    }

    fn unregisterStream(self: *ClientMux, sid: u31) void {
        self.streams_mutex.lockUncancelable(self.io);
        defer self.streams_mutex.unlock(self.io);
        _ = self.streams.remove(sid);
    }

    fn findStream(self: *ClientMux, sid: u31) ?*StreamSlot {
        self.streams_mutex.lockUncancelable(self.io);
        defer self.streams_mutex.unlock(self.io);
        return self.streams.get(sid);
    }

    /// Wake every waiting call() with the same error. Used when the reader
    /// thread can no longer make progress (socket closed, GOAWAY, etc.) so
    /// nobody waits forever.
    fn broadcastError(self: *ClientMux, err: anyerror) void {
        self.streams_mutex.lockUncancelable(self.io);
        defer self.streams_mutex.unlock(self.io);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const slot = entry.value_ptr.*;
            slot.mutex.lockUncancelable(self.io);
            slot.err = err;
            slot.end_stream = true;
            slot.cond.broadcast(self.io);
            slot.mutex.unlock(self.io);
        }
    }

    /// Issue a unary RPC. Thread-safe — multiple threads can call this
    /// concurrently on the same `ClientMux`. Each call gets a fresh stream
    /// id and waits on its own completion slot.
    ///
    /// NOTE: deviation from template — instrumentation lives only in the
    /// inner `callWithMetadata` implementation. `call` is a one-line
    /// forwarder, so adding a second `__obs_span` here would emit TWO
    /// spans for one logical RPC. Both entry points still emit exactly
    /// one client span via the forwarded call.
    pub fn call(
        self: *ClientMux,
        method_path: []const u8,
        request: []const u8,
        compression_alg: compression.Compression.Algorithm,
    ) ![]u8 {
        return self.callWithMetadata(method_path, request, compression_alg, null);
    }

    /// Variant of `call` that emits per-RPC metadata (e.g. `authorization`)
    /// in the HEADERS frame. Closes GAP-0002 for the multiplexed path.
    pub fn callWithMetadata(
        self: *ClientMux,
        method_path: []const u8,
        request: []const u8,
        compression_alg: compression.Compression.Algorithm,
        metadata: ?*const std.StringHashMapUnmanaged([]const u8),
    ) ![]u8 {
        // Observability seam (C-1 fix). Mirrors the established pattern
        // from `client.zig:117-155`: synthesize a `grpc://authority/path`
        // url, open a client span, close it with gRPC OK on the success
        // path, gRPC INTERNAL (13) via `errdefer` on any propagated
        // error. `defer span.end(null)` is the lifecycle close; the
        // explicit `endClientSpan` calls attach the gRPC status before
        // the defer fires (idempotent under enabled builds, comptime
        // no-op under `-Dwith_otel=false`).
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

        const compressed = try self.compression.compress(request, compression_alg);
        defer self.allocator.free(compressed);

        const sid = self.allocStreamId();

        var slot: StreamSlot = .{};
        defer slot.deinit(self.allocator);

        try self.registerStream(sid, &slot);
        defer self.unregisterStream(sid);

        try self.transport.writeRequestOnStreamWithMetadata(sid, compressed, method_path, metadata);

        // Block until the reader thread signals end-of-stream or an error.
        slot.mutex.lockUncancelable(self.io);
        defer slot.mutex.unlock(self.io);
        while (!slot.end_stream) {
            slot.cond.waitUncancelable(self.io, &slot.mutex);
        }
        if (slot.err) |e| return e;

        // Decompress and hand back to caller as an owned slice.
        const result = try self.compression.decompress(slot.data.items, compression_alg);
        observability.endClientSpan(__obs_span, 0); // gRPC OK
        return result;
    }
};

fn readerLoop(self: *ClientMux) void {
    while (!self.shutdown.load(.acquire)) {
        const frame = self.transport.readFrame() catch |err| {
            self.broadcastError(err);
            return;
        };
        const ftype = frame.frame_type;
        const flags = frame.flags;
        const sid = frame.stream_id;
        const payload = frame.payload;

        const FT = http2.frame.FrameType;
        const FF = http2.frame.FrameFlags;

        switch (@as(FT, @enumFromInt(ftype))) {
            .DATA => {
                const end = (flags & FF.END_STREAM) != 0;
                const data_len: u32 = @intCast(payload.len);
                if (self.findStream(sid)) |slot| {
                    slot.mutex.lockUncancelable(self.io);
                    deliverData(slot, self.allocator, payload, end, self.transport.max_recv_message_bytes);
                    if (slot.end_stream) slot.cond.broadcast(self.io);
                    slot.mutex.unlock(self.io);
                }
                self.allocator.free(payload);
                // Refill receive window so the server keeps sending
                // (NW-2). Without this the connection-level recv window
                // shrinks every DATA and never gets replenished, which
                // eventually deadlocks the peer.
                self.transport.maybeRefillRecvWindow(sid, data_len);
            },
            .HEADERS => {
                const end = (flags & FF.END_STREAM) != 0;
                if (end) {
                    if (self.findStream(sid)) |slot| {
                        slot.mutex.lockUncancelable(self.io);
                        defer slot.mutex.unlock(self.io);
                        slot.end_stream = true;
                        slot.cond.broadcast(self.io);
                    }
                }
                self.allocator.free(payload);
            },
            .SETTINGS => {
                const is_ack = (flags & 0x1) != 0;
                if (!is_ack) {
                    // Apply peer settings (INITIAL_WINDOW_SIZE,
                    // MAX_FRAME_SIZE, etc.) before ACKing.
                    self.transport.applyPeerSettings(payload);
                    self.allocator.free(payload);
                    self.transport.writeFrame(.SETTINGS, 0x1, 0, &.{}) catch |err| {
                        self.broadcastError(err);
                        return;
                    };
                } else {
                    self.allocator.free(payload);
                }
            },
            .WINDOW_UPDATE => {
                // Credit the relevant send-window so the per-call
                // writers in callWithMetadata can wake up and continue
                // emitting DATA (NW-3).
                self.transport.processWindowUpdate(sid, payload);
                self.allocator.free(payload);
            },
            .PING => {
                const is_ack = (flags & 0x1) != 0;
                if (!is_ack) {
                    var ping_data: [8]u8 = .{0} ** 8;
                    const copy_len = @min(payload.len, 8);
                    @memcpy(ping_data[0..copy_len], payload[0..copy_len]);
                    self.allocator.free(payload);
                    self.transport.writeFrame(.PING, 0x1, 0, ping_data[0..copy_len]) catch |err| {
                        self.broadcastError(err);
                        return;
                    };
                } else {
                    self.allocator.free(payload);
                }
            },
            .RST_STREAM => {
                if (self.findStream(sid)) |slot| {
                    slot.mutex.lockUncancelable(self.io);
                    defer slot.mutex.unlock(self.io);
                    slot.err = error.StreamReset;
                    slot.end_stream = true;
                    slot.cond.broadcast(self.io);
                }
                self.allocator.free(payload);
            },
            .GOAWAY => {
                self.allocator.free(payload);
                self.broadcastError(error.GoAway);
                return;
            },
            else => {
                self.allocator.free(payload);
            },
        }
    }
}

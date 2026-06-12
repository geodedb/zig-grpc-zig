const std = @import("std");
const net = std.Io.net;
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

/// HTTP/2 client connection preface (RFC 7540 §3.5).
pub const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const TransportError = error{
    ConnectionClosed,
    InvalidHeader,
    PayloadTooLarge,
    CompressionNotSupported,
    Http2Error,
    MethodPathTooLong,
    AuthorityTooLong,
    /// Peer announced a DATA/HEADERS/etc. frame whose length exceeds the
    /// negotiated SETTINGS_MAX_FRAME_SIZE (RFC 7540 §6.5.2 / §4.2). The
    /// reader rejects the frame BEFORE allocating its payload buffer to
    /// avoid an unauthenticated memory amplification (closes I3).
    FrameSizeError,
};

/// Default SETTINGS_MAX_FRAME_SIZE per RFC 7540 §6.5.2 — every HTTP/2
/// implementation MUST accept frames at least this large; we apply it as
/// the inbound cap until the peer negotiates a larger value via SETTINGS.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// HTTP/2 SETTINGS parameter ids (RFC 7540 §6.5.2).
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x01;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x02;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x03;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x04;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x05;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x06;

/// HTTP/2 connection error codes (RFC 7540 §7).
pub const HTTP2_ERROR_NO_ERROR: u32 = 0x00;
pub const HTTP2_ERROR_PROTOCOL_ERROR: u32 = 0x01;
pub const HTTP2_ERROR_FRAME_SIZE_ERROR: u32 = 0x06;
pub const HTTP2_ERROR_FLOW_CONTROL_ERROR: u32 = 0x03;

/// RFC 7540 §6.9.2 default initial window size for both connection and
/// new streams. Until the peer sends SETTINGS we assume this value.
pub const INITIAL_WINDOW_SIZE_DEFAULT: i32 = 65535;

/// What we ourselves advertise as SETTINGS_INITIAL_WINDOW_SIZE on
/// startup — gives streams a 1 MiB receive credit by default so a
/// well-behaved peer doesn't have to wait every 64 KiB for a
/// WINDOW_UPDATE round-trip.
pub const ADVERTISED_INITIAL_WINDOW_SIZE: i32 = 1024 * 1024;

/// Cap on the per-Transport flow-control table size. Stream ids above
/// this fall through to connection-window-only accounting; in practice
/// no real gRPC client opens >1024 concurrent streams on one TCP
/// connection.
pub const MAX_TRACKED_STREAMS: usize = 1024;

/// Build the HPACK-encoded HEADERS payload for a CLIENT request. The
/// caller owns the returned slice and must free it with `allocator`.
///
/// Header order (RFC 7541 + gRPC over HTTP/2):
///   :method POST                  -> indexed static idx 3      (0x83)
///   :scheme http                  -> indexed static idx 6      (0x86)
///   :path <method_path>           -> LIE name idx 4 (0x44) + literal
///   :authority <authority>        -> LIE name idx 1 (0x41) + literal
///   content-type application/grpc -> LIE name idx 31 (0x5f) + literal
///   te trailers                   -> LIE literal name (0x40) + "te" + "trailers"
///
/// Phase 1: paths and authorities are short, so we only encode 7-bit-prefix
/// varints (length < 128). Longer values yield error.MethodPathTooLong /
/// error.AuthorityTooLong rather than silently mis-encoding.
pub fn writeRequestHeaders(
    allocator: std.mem.Allocator,
    method_path: []const u8,
    authority: []const u8,
) ![]u8 {
    return writeRequestHeadersWithMetadata(allocator, method_path, authority, null);
}

/// Number of bytes needed to encode `value` as an HPACK 7-bit-prefix
/// integer (RFC 7541 §5.1) starting at the prefix byte. Used to size
/// length fields for HPACK string literals (the prefix is the H-bit +
/// 7-bit length form).
fn hpackInt7Len(value: usize) usize {
    if (value < 127) return 1;
    var n = value - 127;
    var bytes: usize = 2; // prefix byte + at least one continuation
    while (n >= 128) : (n >>= 7) bytes += 1;
    return bytes;
}

/// Encode `value` as an HPACK 7-bit-prefix integer into `out`. Returns
/// the number of bytes written. Caller must pass `prefix_high_bits`
/// (the bits ORed into the first byte's top, e.g. 0x00 for plain string
/// length, since the H-bit-clear form is the only one we emit).
fn hpackInt7Encode(out: []u8, prefix_high_bits: u8, value: usize) usize {
    if (value < 127) {
        out[0] = prefix_high_bits | @as(u8, @intCast(value));
        return 1;
    }
    out[0] = prefix_high_bits | 0x7F; // 7-bit prefix saturated
    var n = value - 127;
    var i: usize = 1;
    while (n >= 128) : (n >>= 7) {
        out[i] = @as(u8, @intCast((n & 0x7F) | 0x80));
        i += 1;
    }
    out[i] = @as(u8, @intCast(n));
    i += 1;
    return i;
}

/// Like `writeRequestHeaders` but also encodes per-RPC metadata after the
/// canonical request headers. Each metadata entry is emitted as an HPACK
/// Literal-with-Incremental-Indexing header with a literal name (0x40
/// prefix, length-prefixed name, length-prefixed value).
///
/// Closes GAP-0002: prior to this helper the legacy `GrpcClient.call`
/// constructed a `headers` map but threw it away — `authorization` and
/// any other client-supplied metadata never reached the wire.
///
/// Names and values longer than 126 bytes are encoded with multi-byte
/// HPACK 7-bit-prefix varints (RFC 7541 §5.1). This is required for JWT
/// authorization values, which are typically ~150+ bytes.
///
/// Caller owns the returned slice.
pub fn writeRequestHeadersWithMetadata(
    allocator: std.mem.Allocator,
    method_path: []const u8,
    authority: []const u8,
    metadata: ?*const std.StringHashMapUnmanaged([]const u8),
) ![]u8 {
    if (method_path.len > 126) return TransportError.MethodPathTooLong;
    if (authority.len > 126) return TransportError.AuthorityTooLong;

    const ctype_value = "application/grpc";

    // Compute final size up-front to allocate exactly once.
    //   2 (indexed :method, :scheme) + 2 (LIE :path header byte + len) + path
    //   + 2 (:authority) + authority + 2 (content-type) + ctype
    //   + 13 (te trailers fixed bytes)
    var total: usize = 2 + (2 + method_path.len) + (2 + authority.len) + (2 + ctype_value.len) + 13;
    if (metadata) |m| {
        var it = m.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            total += 1 // 0x40 prefix
                + hpackInt7Len(name.len) + name.len + hpackInt7Len(value.len) + value.len;
        }
    }

    var out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    var i: usize = 0;

    // :method POST -> indexed static index 3 (0x80 | 3)
    out[i] = 0x83;
    i += 1;
    // :scheme http -> indexed static index 6 (0x80 | 6)
    out[i] = 0x86;
    i += 1;

    // :path -> LIE name idx 4 (0x40 | 4)
    out[i] = 0x44;
    i += 1;
    out[i] = @intCast(method_path.len);
    i += 1;
    @memcpy(out[i .. i + method_path.len], method_path);
    i += method_path.len;

    // :authority -> LIE name idx 1 (0x40 | 1)
    out[i] = 0x41;
    i += 1;
    out[i] = @intCast(authority.len);
    i += 1;
    @memcpy(out[i .. i + authority.len], authority);
    i += authority.len;

    // content-type -> LIE name idx 31 (0x40 | 31)
    out[i] = 0x5f;
    i += 1;
    out[i] = @intCast(ctype_value.len);
    i += 1;
    @memcpy(out[i .. i + ctype_value.len], ctype_value);
    i += ctype_value.len;

    // te trailers -> LIE literal name (0x40), name "te", value "trailers"
    out[i] = 0x40;
    i += 1;
    out[i] = 0x02;
    i += 1;
    out[i] = 't';
    out[i + 1] = 'e';
    i += 2;
    out[i] = 0x08;
    i += 1;
    @memcpy(out[i .. i + 8], "trailers");
    i += 8;

    // Append per-RPC metadata as LIE literal-name headers.
    if (metadata) |m| {
        var it = m.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            out[i] = 0x40; // LIE, literal name (name index 0)
            i += 1;
            i += hpackInt7Encode(out[i..], 0x00, name.len);
            @memcpy(out[i .. i + name.len], name);
            i += name.len;
            i += hpackInt7Encode(out[i..], 0x00, value.len);
            @memcpy(out[i .. i + value.len], value);
            i += value.len;
        }
    }

    std.debug.assert(i == total);
    return out;
}

/// HPACK dynamic table entry for tracking :path values across requests.
const HpackDynEntry = struct {
    is_path: bool = false,
    path: [128]u8 = .{0} ** 128,
    path_len: usize = 0,
};

const HPACK_DYN_MAX = 128;

/// I/O abstraction for TLS-wrapped connections.
/// The caller provides opaque context and function pointers for read/write/close.
pub const TlsIo = struct {
    ctx: *anyopaque,
    read_fn: *const fn (*anyopaque, []u8) anyerror!usize,
    write_fn: *const fn (*anyopaque, []const u8) anyerror!usize,
    close_fn: *const fn (*anyopaque) void,
};

/// Pre-encoded HPACK payload for the gRPC server response HEADERS:
///   :status: 200                           (static index 8 -> 0x88)
///   content-type: application/grpc         (LIE name index 31 -> 0x5f, len 16)
///
/// Hoisted out of the duplicated literals previously embedded in
/// `writeStreamMessage` and `writeMessageOnStream` (closes M1 partially —
/// see GAP_ANALYSIS.md). Both call sites now reference this constant so a
/// future change to the response header set has exactly one site to update.
pub const RESPONSE_HEADERS_BYTES = [_]u8{
    0x88, // :status: 200
    0x40 | 31, // content-type LIE name index 31
    16, // value length
    'a',
    'p',
    'p',
    'l',
    'i',
    'c',
    'a',
    't',
    'i',
    'o',
    'n',
    '/',
    'g',
    'r',
    'p',
    'c',
};

/// Pre-encoded HPACK trailer payload for a successful gRPC response:
///   grpc-status: 0   (LIE literal-name 0x40, name "grpc-status", value "0")
/// Hoisted from the duplicated literals in `endStream` and
/// `writeMessageOnStream` (closes quality M2).
pub const OK_TRAILERS_BYTES = [_]u8{
    0x40, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '0',
};

/// Decoded gRPC 5-byte message prefix (compression flag + u32 length).
pub const GrpcPrefix = struct { compressed: bool, msg_len: u32 };

/// Encode the gRPC length prefix (flag byte 0 = uncompressed) into
/// `out[0..5]`. Single definition for the three write paths (closes M3).
pub fn encodeGrpcPrefix(out: *[5]u8, msg_len: u32) void {
    out[0] = 0;
    out[1] = @intCast((msg_len >> 24) & 0xFF);
    out[2] = @intCast((msg_len >> 16) & 0xFF);
    out[3] = @intCast((msg_len >> 8) & 0xFF);
    out[4] = @intCast(msg_len & 0xFF);
}

/// Decode and validate a gRPC 5-byte message prefix. The compression
/// flag byte MUST be 0 or 1 (gRPC over HTTP/2 spec); anything else is
/// a framing error (closes I6 / #49). Closes M4: single definition for
/// the three read paths.
pub fn decodeGrpcPrefix(buf: []const u8) error{InvalidGrpcPrefix}!GrpcPrefix {
    if (buf.len < 5) return error.InvalidGrpcPrefix;
    if (buf[0] > 1) return error.InvalidGrpcPrefix;
    const msg_len = (@as(u32, buf[1]) << 24) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 8) |
        @as(u32, buf[4]);
    return .{ .compressed = buf[0] == 1, .msg_len = msg_len };
}

pub const Transport = struct {
    stream: net.Stream,
    io: std.Io,
    tls_io: ?TlsIo = null,
    allocator: std.mem.Allocator,
    /// Track the stream ID from the client's HEADERS frame for responses
    last_stream_id: u31,
    /// HTTP/2 `:authority` header value used by client write paths.
    /// Heap-allocated via `allocator.dupe`; freed in `deinit`. For server
    /// transports this is an empty slice and unused.
    authority: []const u8 = "",
    /// The gRPC method path extracted from the last HEADERS frame (e.g. "/geode.GeodeService/Handshake")
    last_method: [256]u8 = .{0} ** 256,
    last_method_len: usize = 0,
    /// The `authorization` header value extracted from the last HEADERS
    /// frame. Empty when absent. Bounded buffer — values longer than
    /// `last_authorization.len` are truncated; the auth gate then rejects
    /// the truncated form on signature mismatch (still safe). Closes
    /// GAP-0001 when consumed by the server's auth gate.
    last_authorization: [1024]u8 = .{0} ** 1024,
    last_authorization_len: usize = 0,
    /// HPACK dynamic table (ring buffer, newest entry at hpack_dyn_head)
    hpack_dyn: [HPACK_DYN_MAX]HpackDynEntry = [_]HpackDynEntry{.{}} ** HPACK_DYN_MAX,
    hpack_dyn_count: usize = 0,
    hpack_dyn_head: usize = 0,
    /// Serializes byte-level writes to the socket. Multi-frame sequences
    /// (HEADERS+DATA+TRAILERS) acquire this once for the whole sequence so
    /// frames from different threads cannot interleave on the wire. The
    /// reader-thread side of `ClientMux` also acquires this briefly when
    /// sending control-frame ACKs (SETTINGS, PING).
    ///
    /// Uses `std.Io.Mutex` (Zig 0.16's IO-aware primitive) and the
    /// `*Uncancelable` variants because cancelling a half-written frame on
    /// the wire would desynchronize the peer.
    write_mutex: std.Io.Mutex = .init,
    /// Largest frame length WE accept from the peer on inbound reads.
    /// This is OUR advertised SETTINGS_MAX_FRAME_SIZE and is never
    /// modified by peer SETTINGS — per RFC 7540 §6.5.2 the peer's value
    /// governs what the PEER accepts, not what we must accept.
    /// Closes NEW-2 (#44): previously the peer could raise this to
    /// 16 MiB and amplify per-frame allocations ~1000x. (Also closes I3.)
    max_frame_size: u32 = DEFAULT_MAX_FRAME_SIZE,
    /// Largest frame length the PEER accepts (their advertised
    /// SETTINGS_MAX_FRAME_SIZE). Used only to size outbound DATA
    /// fragmentation in `writeDataFragmentedLocked`.
    peer_max_frame_size: u32 = DEFAULT_MAX_FRAME_SIZE,
    /// Connection-level send window. Decremented when we transmit DATA;
    /// incremented when peer sends WINDOW_UPDATE on stream 0 (§6.9).
    conn_send_window: i32 = INITIAL_WINDOW_SIZE_DEFAULT,
    /// Connection-level receive window. Decremented as we consume
    /// inbound DATA; we restore credit by emitting WINDOW_UPDATE on
    /// stream 0 once it falls below threshold.
    conn_recv_window: i32 = INITIAL_WINDOW_SIZE_DEFAULT,
    /// Currently advertised initial window size for new streams. We
    /// announce ADVERTISED_INITIAL_WINDOW_SIZE in our SETTINGS so peers
    /// know they can send us up to that many octets per stream before a
    /// WINDOW_UPDATE.
    our_initial_window_size: i32 = ADVERTISED_INITIAL_WINDOW_SIZE,
    /// The peer-advertised SETTINGS_INITIAL_WINDOW_SIZE value last seen.
    /// Used to compute the §6.9.2 delta when peer sends a fresh SETTINGS.
    peer_initial_window_size: i32 = INITIAL_WINDOW_SIZE_DEFAULT,
    /// Per-stream send and receive windows. Tracked here (rather than on
    /// the legacy stream.Stream) so flow-control state is reachable from
    /// the Transport's read/write loops without a parallel hash map per
    /// connection. Heap-allocated to keep the Transport struct itself
    /// small enough for a 512 KiB pthread stack (CC-4). Bounded at
    /// MAX_TRACKED_STREAMS; stream ids beyond that fall back to the
    /// connection window only (a safe over-estimate for short-lived
    /// calls).
    stream_send_windows: []i32 = &[_]i32{},
    stream_recv_windows: []i32 = &[_]i32{},
    /// Coordinates blocking writers waiting for additional send-window
    /// credit (peer sent WINDOW_UPDATE) without busy-spinning.
    ///
    /// Implemented as a futex over `flow_epoch` (incremented on every
    /// credit) rather than `std.Io.Condition` because Zig 0.16's
    /// Condition does not expose a timed-wait variant, and we need a
    /// bounded wait to mitigate a slow-loris peer that opens streams
    /// but never advertises credit (closes GAP-FU-002). The writer
    /// side reads `flow_epoch` under `flow_mutex`, releases the mutex,
    /// then `futexWaitTimeout`s on `flow_epoch` for the configured
    /// timeout (`flow_credit_timeout_ns`). The credit side bumps
    /// `flow_epoch` (under the same mutex) and `futexWake`s every
    /// blocked writer.
    flow_mutex: std.Io.Mutex = .init,
    flow_epoch: std.atomic.Value(u32) = .init(0),
    /// Maximum time a writer thread will park in `reserveSendCredit`
    /// waiting for the peer to advertise send-window credit before
    /// giving up with `error.FlowControlTimeout`. On timeout the writer
    /// emits `RST_STREAM (FLOW_CONTROL_ERROR)` for the offending
    /// stream and propagates the error to its caller. A value of `0`
    /// disables the timeout entirely (legacy behaviour: park forever).
    /// Default 30s -- long enough that legitimate large unary calls
    /// and server-streaming responses on a healthy peer complete
    /// without false positives, short enough that a deliberate slow-
    /// loris peer can't pin a writer thread for the lifetime of the
    /// process. Closes GAP-FU-002.
    flow_credit_timeout_ns: u64 = 30 * std.time.ns_per_s,

    /// Allocate the per-stream flow-control arrays on the heap. Used by
    /// every init path so the embedded slices are non-empty and indexable.
    fn allocStreamWindows(allocator: std.mem.Allocator) !struct { send: []i32, recv: []i32 } {
        const send = try allocator.alloc(i32, MAX_TRACKED_STREAMS);
        errdefer allocator.free(send);
        const recv = try allocator.alloc(i32, MAX_TRACKED_STREAMS);
        errdefer allocator.free(recv);
        @memset(send, INITIAL_WINDOW_SIZE_DEFAULT);
        @memset(recv, INITIAL_WINDOW_SIZE_DEFAULT);
        return .{ .send = send, .recv = recv };
    }

    pub fn initClient(allocator: std.mem.Allocator, io: std.Io, stream_: net.Stream, authority: []const u8) !Transport {
        const authority_owned = try allocator.dupe(u8, authority);
        errdefer allocator.free(authority_owned);
        const windows = try allocStreamWindows(allocator);
        errdefer allocator.free(windows.send);
        errdefer allocator.free(windows.recv);

        var trans = Transport{
            .stream = stream_,
            .io = io,
            .allocator = allocator,
            .last_stream_id = 1,
            .last_method = .{0} ** 256,
            .last_method_len = 0,
            .authority = authority_owned,
            .stream_send_windows = windows.send,
            .stream_recv_windows = windows.recv,
        };

        try trans.setupHttp2Client();

        return trans;
    }

    pub fn initServer(allocator: std.mem.Allocator, io: std.Io, stream_: net.Stream) !Transport {
        const authority_owned = try allocator.dupe(u8, "");
        errdefer allocator.free(authority_owned);
        const windows = try allocStreamWindows(allocator);
        errdefer allocator.free(windows.send);
        errdefer allocator.free(windows.recv);

        var trans = Transport{
            .stream = stream_,
            .io = io,
            .allocator = allocator,
            .last_stream_id = 1,
            .last_method = .{0} ** 256,
            .last_method_len = 0,
            .authority = authority_owned,
            .stream_send_windows = windows.send,
            .stream_recv_windows = windows.recv,
        };

        try trans.setupHttp2Server();

        return trans;
    }

    pub fn initServerTls(allocator: std.mem.Allocator, io: std.Io, stream_: net.Stream, tls_io_: TlsIo) !Transport {
        const authority_owned = try allocator.dupe(u8, "");
        errdefer allocator.free(authority_owned);
        const windows = try allocStreamWindows(allocator);
        errdefer allocator.free(windows.send);
        errdefer allocator.free(windows.recv);

        var trans = Transport{
            .stream = stream_,
            .io = io,
            .tls_io = tls_io_,
            .allocator = allocator,
            .last_stream_id = 1,
            .last_method = .{0} ** 256,
            .last_method_len = 0,
            .authority = authority_owned,
            .stream_send_windows = windows.send,
            .stream_recv_windows = windows.recv,
        };
        // If setup fails, close the TLS connection to avoid leaking the
        // SSL object and SslConn allocation.
        errdefer tls_io_.close_fn(tls_io_.ctx);

        try trans.setupHttp2Server();

        return trans;
    }

    fn ioRead(self: *Transport, buf: []u8) !usize {
        if (self.tls_io) |tio| return tio.read_fn(tio.ctx, buf);
        var bufs = [_][]u8{buf};
        return self.io.vtable.netRead(self.io.userdata, self.stream.socket.handle, &bufs);
    }

    /// Low-level socket write. Caller MUST hold `write_mutex`.
    fn ioWriteLocked(self: *Transport, data: []const u8) !usize {
        if (self.tls_io) |tio| return tio.write_fn(tio.ctx, data);
        // `std.Io.Threaded.netWritePosix` indexes `data[data.len - 1]`
        // unconditionally, so passing `&.{}` as the additional-buffers
        // slice triggers an integer underflow panic. Pass `data` itself
        // as the trailing pattern with splat=1; the function then writes
        // the empty header followed by `data` exactly once, which is the
        // semantics this method needs.
        const trailing = [_][]const u8{data};
        return self.io.vtable.netWrite(self.io.userdata, self.stream.socket.handle, "", &trailing, 1);
    }

    /// Single-shot socket write, takes the write_mutex internally. Used by
    /// callers that emit a single self-contained chunk (the HTTP/2 preface,
    /// for example) where atomicity with surrounding frames isn't required.
    fn ioWrite(self: *Transport, data: []const u8) !usize {
        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);
        return self.ioWriteLocked(data);
    }

    fn ioClose(self: *Transport) void {
        if (self.tls_io) |tio| tio.close_fn(tio.ctx);
        self.stream.close(self.io);
    }

    pub fn deinit(self: *Transport) void {
        self.allocator.free(self.authority);
        if (self.stream_send_windows.len > 0) self.allocator.free(self.stream_send_windows);
        if (self.stream_recv_windows.len > 0) self.allocator.free(self.stream_recv_windows);
        self.ioClose();
    }

    fn setupHttp2Client(self: *Transport) !void {
        // Client sends HTTP/2 connection preface
        _ = try self.ioWrite(HTTP2_PREFACE);

        // Send initial SETTINGS frame advertising our non-default values
        // (INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_CONCURRENT_STREAMS,
        // MAX_HEADER_LIST_SIZE) — closes GAP-0004 / NW-1.
        const body = try buildInitialSettingsBody(self.allocator);
        defer self.allocator.free(body);
        try self.writeFrame(.SETTINGS, 0, 0, body);

        // Immediately credit the connection-level recv window from the
        // RFC default (65535) up to ADVERTISED_INITIAL_WINDOW_SIZE so a
        // single big request doesn't have to interleave WINDOW_UPDATE
        // round-trips with the application's write→read pattern. This
        // is what mainline implementations (grpc-go, h2load, nghttp2)
        // do at startup.
        try self.bumpConnectionRecvWindow();

        // Drain server's initial control frames (SETTINGS, ACK,
        // WINDOW_UPDATE) before returning. The single-threaded
        // GrpcClient writes the entire request before reading any
        // response, so we MUST seed conn_send_window from the server's
        // bump WINDOW_UPDATE before the first DATA write blocks. The
        // legacy multiplexed ClientMux already runs a reader thread
        // and would have processed these asynchronously.
        try self.consumeInitialServerFrames();
    }

    /// Best-effort drain of the server's initial control frames after
    /// the SETTINGS exchange. We need to consume:
    ///   * server SETTINGS (non-ACK)  — applies INITIAL_WINDOW_SIZE etc.
    ///   * SETTINGS ACK                — for our SETTINGS
    ///   * server WINDOW_UPDATE        — credits our conn_send_window
    ///
    /// The relative ordering of ACK vs. the server's own non-ACK
    /// SETTINGS / WINDOW_UPDATE isn't guaranteed: a server might emit
    /// its SETTINGS, then ACK ours, then send WINDOW_UPDATE — so we
    /// can't stop on the ACK or we lose the credit. Track all three
    /// expected frames and exit when all have been observed (or when
    /// our small budget is exhausted, leaving any remaining work for
    /// the application's read loop).
    fn consumeInitialServerFrames(self: *Transport) !void {
        var got_ack = false;
        var got_settings = false;
        var got_window_update = false;
        var max_frames: u8 = 16;
        while (max_frames > 0 and !(got_ack and got_settings and got_window_update)) : (max_frames -= 1) {
            const frame = try self.readFrame();
            defer self.allocator.free(frame.payload);
            switch (frame.frame_type) {
                @intFromEnum(http2.frame.FrameType.SETTINGS) => {
                    const is_ack = (frame.flags & 0x1) != 0;
                    if (is_ack) {
                        got_ack = true;
                    } else {
                        got_settings = true;
                        self.applyPeerSettings(frame.payload);
                        // ACK the server's SETTINGS.
                        try self.writeFrame(.SETTINGS, 0x1, 0, &.{});
                    }
                },
                @intFromEnum(http2.frame.FrameType.WINDOW_UPDATE) => {
                    got_window_update = true;
                    self.processWindowUpdate(frame.stream_id, frame.payload);
                },
                @intFromEnum(http2.frame.FrameType.PING) => {
                    const is_ack = (frame.flags & 0x1) != 0;
                    if (!is_ack) {
                        var ping_data: [8]u8 = .{0} ** 8;
                        const copy_len = @min(frame.payload.len, 8);
                        @memcpy(ping_data[0..copy_len], frame.payload[0..copy_len]);
                        try self.writeFrame(.PING, 0x1, 0, ping_data[0..copy_len]);
                    }
                },
                else => {
                    // Unexpected frame this early; let the application
                    // handle it on the next read.
                    break;
                },
            }
        }
    }

    /// Read exactly `buf.len` bytes from the stream, handling partial reads.
    fn readExact(self: *Transport, buf: []u8) !void {
        var total: usize = 0;
        while (total < buf.len) {
            const n = try self.ioRead(buf[total..]);
            if (n == 0) return TransportError.ConnectionClosed;
            total += n;
        }
    }

    /// Decoded HTTP/2 frame header + owned payload. The `payload` slice is
    /// allocated via the Transport's allocator and the caller is responsible
    /// for freeing it when finished.
    pub const RawFrame = struct {
        frame_type: u8,
        flags: u8,
        stream_id: u31,
        payload: []u8,
    };

    /// Pure size-check used by `readFrame` before allocating the payload
    /// buffer. Public for unit tests (`transport_max_frame_size_test.zig`).
    /// Returns `error.FrameSizeError` when the peer-declared length exceeds
    /// the negotiated max — closes I3.
    pub fn checkFrameSize(length: u32, max: u32) TransportError!void {
        if (length > max) return TransportError.FrameSizeError;
    }

    /// Initialize the flow-control fields of an arbitrary Transport
    /// pointer in-place. Used only by unit tests that don't want to
    /// stand up a full Transport (no socket / allocator). Sets exactly
    /// the fields the flow-control unit tests inspect.
    pub fn initFlowControlForTest(t: *Transport) void {
        t.conn_send_window = INITIAL_WINDOW_SIZE_DEFAULT;
        t.conn_recv_window = INITIAL_WINDOW_SIZE_DEFAULT;
        t.our_initial_window_size = ADVERTISED_INITIAL_WINDOW_SIZE;
        t.peer_initial_window_size = INITIAL_WINDOW_SIZE_DEFAULT;
        // Tests don't allocate the per-stream arrays — leave them empty
        // and rely on per-stream code paths' MAX_TRACKED_STREAMS bounds
        // check (idx >= MAX_TRACKED_STREAMS short-circuits).
        t.stream_send_windows = &[_]i32{};
        t.stream_recv_windows = &[_]i32{};
    }

    /// Apply a WINDOW_UPDATE increment to a flow-control window pointer.
    /// RFC 7540 §6.9.1:
    ///   * Increment of 0 is a PROTOCOL_ERROR.
    ///   * Resulting window must not exceed 2^31-1; otherwise
    ///     FLOW_CONTROL_ERROR.
    pub fn applyWindowUpdate(window: *i32, increment: u32) error{ ProtocolError, FlowControlError }!void {
        if (increment == 0) return error.ProtocolError;
        // The increment is a 31-bit unsigned per spec (top bit reserved),
        // so it fits in i64 without truncation.
        const new_val: i64 = @as(i64, window.*) + @as(i64, @intCast(increment));
        if (new_val > std.math.maxInt(i32)) return error.FlowControlError;
        window.* = @intCast(new_val);
    }

    /// Should we proactively emit a WINDOW_UPDATE for this side? We do
    /// so once `current` falls below half of the advertised initial
    /// window — strikes a balance between credit-restore round-trips
    /// and giving the peer enough headroom to keep streaming.
    pub fn shouldEmitWindowUpdate(current: i32, initial: i32) bool {
        return current < @divFloor(initial, 2);
    }

    /// §6.9.2 stream window adjustment when peer changes
    /// SETTINGS_INITIAL_WINDOW_SIZE: each existing stream's send window
    /// is shifted by `new - old`. May leave the window negative.
    pub fn applyInitialWindowSizeDelta(send_window: *i32, old_initial: i32, new_initial: i32) void {
        const delta: i64 = @as(i64, new_initial) - @as(i64, old_initial);
        const new_val: i64 = @as(i64, send_window.*) + delta;
        // Clamp at i32 bounds (callers that need to reject overflow use
        // applyInitialWindowSizeDeltaChecked instead).
        if (new_val > std.math.maxInt(i32)) {
            send_window.* = std.math.maxInt(i32);
        } else if (new_val < std.math.minInt(i32)) {
            send_window.* = std.math.minInt(i32);
        } else {
            send_window.* = @intCast(new_val);
        }
    }

    /// Same as `applyInitialWindowSizeDelta` but rejects overflow with
    /// FLOW_CONTROL_ERROR per §6.9.2.
    pub fn applyInitialWindowSizeDeltaChecked(
        send_window: *i32,
        old_initial: i32,
        new_initial: u32,
    ) error{FlowControlError}!void {
        if (new_initial > @as(u32, std.math.maxInt(i32))) return error.FlowControlError;
        const new_signed: i32 = @intCast(new_initial);
        const delta: i64 = @as(i64, new_signed) - @as(i64, old_initial);
        const new_val: i64 = @as(i64, send_window.*) + delta;
        if (new_val > std.math.maxInt(i32)) return error.FlowControlError;
        if (new_val < std.math.minInt(i32)) return error.FlowControlError;
        send_window.* = @intCast(new_val);
    }

    /// Build the body (no frame header) of our initial SETTINGS frame.
    /// We advertise four non-default values:
    ///   INITIAL_WINDOW_SIZE        = 1 MiB
    ///   MAX_FRAME_SIZE             = 16384  (RFC default; explicit for
    ///                                        peers that don't assume
    ///                                        the default)
    ///   MAX_CONCURRENT_STREAMS     = 100
    ///   MAX_HEADER_LIST_SIZE       = 8192
    pub fn buildInitialSettingsBody(allocator: std.mem.Allocator) ![]u8 {
        const entries = [_]struct { id: u16, value: u32 }{
            .{ .id = SETTINGS_INITIAL_WINDOW_SIZE, .value = @intCast(ADVERTISED_INITIAL_WINDOW_SIZE) },
            .{ .id = SETTINGS_MAX_FRAME_SIZE, .value = DEFAULT_MAX_FRAME_SIZE },
            .{ .id = SETTINGS_MAX_CONCURRENT_STREAMS, .value = 100 },
            .{ .id = SETTINGS_MAX_HEADER_LIST_SIZE, .value = 8192 },
        };
        var bytes = try allocator.alloc(u8, entries.len * 6);
        errdefer allocator.free(bytes);
        var i: usize = 0;
        for (entries) |e| {
            bytes[i] = @intCast((e.id >> 8) & 0xFF);
            bytes[i + 1] = @intCast(e.id & 0xFF);
            bytes[i + 2] = @intCast((e.value >> 24) & 0xFF);
            bytes[i + 3] = @intCast((e.value >> 16) & 0xFF);
            bytes[i + 4] = @intCast((e.value >> 8) & 0xFF);
            bytes[i + 5] = @intCast(e.value & 0xFF);
            i += 6;
        }
        return bytes;
    }

    /// Build a complete WINDOW_UPDATE frame (header + 4-byte payload).
    /// `stream_id` of 0 credits the connection-level window; non-zero
    /// credits a specific stream.
    pub fn buildWindowUpdateFrame(allocator: std.mem.Allocator, stream_id: u31, increment: u32) ![]u8 {
        var bytes = try allocator.alloc(u8, 13);
        errdefer allocator.free(bytes);
        // Header
        bytes[0] = 0;
        bytes[1] = 0;
        bytes[2] = 4; // payload length
        bytes[3] = @intFromEnum(http2.frame.FrameType.WINDOW_UPDATE);
        bytes[4] = 0; // flags
        const sid: u32 = @intCast(stream_id);
        bytes[5] = @intCast((sid >> 24) & 0x7F);
        bytes[6] = @intCast((sid >> 16) & 0xFF);
        bytes[7] = @intCast((sid >> 8) & 0xFF);
        bytes[8] = @intCast(sid & 0xFF);
        // Payload: 31-bit increment, top bit reserved (R) = 0
        bytes[9] = @intCast((increment >> 24) & 0x7F);
        bytes[10] = @intCast((increment >> 16) & 0xFF);
        bytes[11] = @intCast((increment >> 8) & 0xFF);
        bytes[12] = @intCast(increment & 0xFF);
        return bytes;
    }

    /// Build the bytes for a connection-level GOAWAY frame announcing
    /// FRAME_SIZE_ERROR. Caller owns the returned slice. Used by
    /// `readFrame` after rejecting an oversize peer frame so the peer
    /// learns why the connection is closing.
    pub fn buildGoawayFrameSizeError(allocator: std.mem.Allocator, last_stream_id: u31) ![]u8 {
        // Layout: 9-byte frame header + 8-byte payload.
        //   header: length(3) | type(1=GOAWAY=0x07) | flags(1=0) | stream_id(4=0)
        //   payload: R + last-stream-id (4 bytes) | error code (4 bytes)
        const payload_len: u32 = 8;
        var bytes = try allocator.alloc(u8, 9 + payload_len);
        errdefer allocator.free(bytes);
        // Header
        bytes[0] = @intCast((payload_len >> 16) & 0xFF);
        bytes[1] = @intCast((payload_len >> 8) & 0xFF);
        bytes[2] = @intCast(payload_len & 0xFF);
        bytes[3] = @intFromEnum(http2.frame.FrameType.GOAWAY);
        bytes[4] = 0; // flags
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = 0;
        bytes[8] = 0; // stream id 0
        // Payload
        const lsid: u32 = @intCast(last_stream_id);
        bytes[9] = @intCast((lsid >> 24) & 0x7F); // R bit clear
        bytes[10] = @intCast((lsid >> 16) & 0xFF);
        bytes[11] = @intCast((lsid >> 8) & 0xFF);
        bytes[12] = @intCast(lsid & 0xFF);
        bytes[13] = @intCast((HTTP2_ERROR_FRAME_SIZE_ERROR >> 24) & 0xFF);
        bytes[14] = @intCast((HTTP2_ERROR_FRAME_SIZE_ERROR >> 16) & 0xFF);
        bytes[15] = @intCast((HTTP2_ERROR_FRAME_SIZE_ERROR >> 8) & 0xFF);
        bytes[16] = @intCast(HTTP2_ERROR_FRAME_SIZE_ERROR & 0xFF);
        return bytes;
    }

    /// Process a peer WINDOW_UPDATE frame. The 4-byte payload is a
    /// 31-bit increment (top bit reserved). Stream id 0 credits the
    /// connection-level send window; non-zero credits a specific stream.
    /// On any decoding / overflow error we log and drop the increment
    /// rather than tearing the connection down — strict-mode peers can
    /// always observe the missing credit and recover.
    pub fn processWindowUpdate(self: *Transport, stream_id: u31, payload: []const u8) void {
        if (payload.len != 4) return;
        const increment: u32 = ((@as(u32, payload[0]) & 0x7F) << 24) |
            (@as(u32, payload[1]) << 16) |
            (@as(u32, payload[2]) << 8) |
            @as(u32, payload[3]);
        // Hold flow_mutex while updating the window AND bumping the
        // epoch: a writer that observed the predicate as false and is
        // about to read `flow_epoch` (still under the same lock) must
        // see either (a) the new credit, in which case it skips the
        // wait, or (b) the old credit but a new epoch, in which case
        // its futex wait returns immediately. Doing the bump under
        // the lock closes the lost-wakeup race.
        self.flow_mutex.lockUncancelable(self.io);
        defer self.flow_mutex.unlock(self.io);
        if (stream_id == 0) {
            applyWindowUpdate(&self.conn_send_window, increment) catch return;
        } else {
            const idx: usize = @intCast(stream_id);
            if (idx >= self.stream_send_windows.len) return;
            applyWindowUpdate(&self.stream_send_windows[idx], increment) catch return;
        }
        // Wake any writers blocked on send credit.
        self.wakeFlowWaiters();
    }

    /// Credit our connection-level receive window (and optionally a
    /// stream's window) by emitting WINDOW_UPDATE frame(s) when below
    /// threshold. Used after we consume an inbound DATA frame.
    pub fn maybeRefillRecvWindow(self: *Transport, stream_id: u31, consumed: u32) void {
        // Always shrink first, even if we don't end up emitting credit
        // (so the cumulative consumed == cumulative credit eventually).
        self.conn_recv_window -|= @intCast(consumed);
        if (shouldEmitWindowUpdate(self.conn_recv_window, ADVERTISED_INITIAL_WINDOW_SIZE)) {
            const credit: u32 = @intCast(@as(i64, ADVERTISED_INITIAL_WINDOW_SIZE) - @as(i64, self.conn_recv_window));
            if (credit > 0) {
                const bytes = buildWindowUpdateFrame(self.allocator, 0, credit) catch return;
                defer self.allocator.free(bytes);
                _ = self.ioWrite(bytes) catch return;
                self.conn_recv_window = ADVERTISED_INITIAL_WINDOW_SIZE;
            }
        }

        if (stream_id == 0) return;
        const idx: usize = @intCast(stream_id);
        if (idx >= self.stream_recv_windows.len) return;
        self.stream_recv_windows[idx] -|= @intCast(consumed);
        if (shouldEmitWindowUpdate(self.stream_recv_windows[idx], ADVERTISED_INITIAL_WINDOW_SIZE)) {
            const credit: u32 = @intCast(@as(i64, ADVERTISED_INITIAL_WINDOW_SIZE) - @as(i64, self.stream_recv_windows[idx]));
            if (credit > 0) {
                const bytes = buildWindowUpdateFrame(self.allocator, stream_id, credit) catch return;
                defer self.allocator.free(bytes);
                _ = self.ioWrite(bytes) catch return;
                self.stream_recv_windows[idx] = ADVERTISED_INITIAL_WINDOW_SIZE;
            }
        }
    }

    /// Wake every writer thread blocked in `reserveSendCredit`. Called
    /// after the caller has updated send-window state under
    /// `flow_mutex`. The epoch bump (release order) plus the
    /// `futexWake` together close the lost-wakeup race: a waiter that
    /// observed the old epoch will see the bump (and wake), and a
    /// waiter that hasn't yet entered the futex will skip the wait
    /// because its `epoch` argument no longer matches the current
    /// value (futex returns `EAGAIN`).
    fn wakeFlowWaiters(self: *Transport) void {
        _ = self.flow_epoch.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.flow_epoch.raw, std.math.maxInt(u32));
    }

    /// Reserve `n` octets of send-window credit, blocking until both
    /// the connection and per-stream send windows have enough headroom
    /// or the configured `flow_credit_timeout_ns` elapses (whichever
    /// comes first). On success decrements both windows by `n` and
    /// returns. On timeout returns `error.FlowControlTimeout` without
    /// touching the windows. Caller must NOT hold flow_mutex.
    ///
    /// The bounded wait closes GAP-FU-002: a slow-loris peer that
    /// opens streams but never advertises credit can no longer pin
    /// `MAX_CONNS` writer threads forever. When `flow_credit_timeout_ns`
    /// is `0` the wait is unbounded (legacy behaviour).
    pub fn reserveSendCredit(self: *Transport, stream_id: u31, n: u32) error{FlowControlTimeout}!void {
        if (n == 0) return;
        const idx: ?usize = blk: {
            if (stream_id == 0) break :blk null;
            const i: usize = @intCast(stream_id);
            if (i >= self.stream_send_windows.len) break :blk null;
            break :blk i;
        };

        // Compute the deadline once, before entering the loop, so
        // spurious wake-ups + partial-credit advances cannot extend
        // the cumulative wait past `flow_credit_timeout_ns`.
        const deadline: ?std.Io.Clock.Timestamp = blk: {
            const ns = self.flow_credit_timeout_ns;
            if (ns == 0) break :blk null;
            const dur = std.Io.Clock.Duration{
                .clock = .awake,
                .raw = std.Io.Duration.fromNanoseconds(@as(i96, @intCast(ns))),
            };
            break :blk std.Io.Clock.Timestamp.fromNow(self.io, dur);
        };

        self.flow_mutex.lockUncancelable(self.io);
        defer self.flow_mutex.unlock(self.io);

        while (true) {
            const conn_avail = self.conn_send_window;
            const stream_avail: i32 = if (idx) |i| self.stream_send_windows[i] else std.math.maxInt(i32);
            const avail = @min(conn_avail, stream_avail);
            if (avail >= @as(i32, @intCast(n))) {
                self.conn_send_window -= @as(i32, @intCast(n));
                if (idx) |i| self.stream_send_windows[i] -= @as(i32, @intCast(n));
                return;
            }

            // Past the deadline? `std.Io.futexWaitTimeout` does NOT
            // return `error.Timeout` -- it surfaces a deadline
            // expiry as a successful (spurious-style) wake-up. We
            // therefore check the deadline ourselves before sleeping
            // again, and bail with `error.FlowControlTimeout` if it
            // has elapsed.
            if (deadline) |d| {
                const remaining = d.durationFromNow(self.io);
                if (remaining.raw.nanoseconds <= 0) return error.FlowControlTimeout;
            }

            // Snapshot the epoch BEFORE releasing the mutex. The
            // credit side bumps the epoch under `flow_mutex`, so any
            // bump that happens after this load will produce
            // `EAGAIN` on the futex (epoch mismatch) and the wait
            // returns immediately; any bump that happens before this
            // load already implies an updated window, which we just
            // failed to find -- so the writer side must have changed
            // it in between, which is fine: we'll loop, observe the
            // new credit, and proceed.
            const epoch = self.flow_epoch.load(.acquire);
            self.flow_mutex.unlock(self.io);

            const wait_result = if (deadline) |d|
                self.io.futexWaitTimeout(u32, &self.flow_epoch.raw, epoch, .{ .deadline = d })
            else
                self.io.futexWaitTimeout(u32, &self.flow_epoch.raw, epoch, .none);

            self.flow_mutex.lockUncancelable(self.io);

            wait_result catch |err| switch (err) {
                // grpc-zig's connection threads are detached and not
                // wired to the cancelation surface; treat a cancel
                // signal as equivalent to a timeout so callers still
                // emit RST_STREAM and tear the stream down cleanly.
                error.Canceled => return error.FlowControlTimeout,
            };
            // Successful return from the futex covers all of: real
            // wakeup, spurious wakeup, AND deadline expiry. Loop back
            // to the top: the predicate-then-deadline checks above
            // will decide whether we proceed, retry, or time out.
        }
    }

    /// Wrapper around `reserveSendCredit` that, on timeout, emits an
    /// HTTP/2 `RST_STREAM` frame with `FLOW_CONTROL_ERROR` (0x03) for
    /// the offending stream and propagates the error. Used by every
    /// outbound DATA write path. Closes GAP-FU-002.
    fn reserveSendCreditOrRst(self: *Transport, stream_id: u31, n: u32) error{FlowControlTimeout}!void {
        self.reserveSendCredit(stream_id, n) catch |err| switch (err) {
            error.FlowControlTimeout => {
                std.log.warn(
                    "flow-control credit timeout on stream {d}; sending RST_STREAM(FLOW_CONTROL_ERROR)",
                    .{stream_id},
                );
                self.writeRstStream(stream_id, HTTP2_ERROR_FLOW_CONTROL_ERROR);
                return err;
            },
        };
    }

    /// Best-effort RST_STREAM emit. The 4-byte payload is the HTTP/2
    /// error code (RFC 7540 §7) in big-endian. Ignores any write
    /// error: callers reach this on an already-failing path and a
    /// failed RST simply means the connection is gone, which the next
    /// read will surface anyway.
    fn writeRstStream(self: *Transport, stream_id: u31, error_code: u32) void {
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, error_code, .big);
        self.writeFrame(.RST_STREAM, 0, stream_id, &payload) catch {};
    }

    /// Send a GOAWAY frame with FRAME_SIZE_ERROR. Best-effort: ignores
    /// any write failure since we are about to tear the connection down.
    fn emitGoawayFrameSizeError(self: *Transport) void {
        const bytes = buildGoawayFrameSizeError(self.allocator, self.last_stream_id) catch return;
        defer self.allocator.free(bytes);
        _ = self.ioWrite(bytes) catch {};
    }

    /// Apply the parameters in a peer SETTINGS frame payload. Each entry
    /// is a 6-byte big-endian (id:u16, value:u32) tuple per RFC 7540
    /// §6.5.1. Unknown ids are ignored. We honour:
    ///   * SETTINGS_MAX_FRAME_SIZE (0x05): clamp to spec range and apply
    ///     to `peer_max_frame_size` (our OUTBOUND fragmentation cap). Our
    ///     inbound acceptance cap `max_frame_size` is never moved by the
    ///     peer — RFC 7540 §6.5.2 governs only what the PEER accepts.
    ///   * SETTINGS_INITIAL_WINDOW_SIZE (0x04): §6.9.2 — adjust every
    ///     existing stream's send window by `new - old`, clamping at
    ///     i32 bounds (a strict implementation would emit
    ///     FLOW_CONTROL_ERROR on overflow; we clamp for resilience).
    pub fn applyPeerSettings(self: *Transport, payload: []const u8) void {
        var i: usize = 0;
        while (i + 6 <= payload.len) : (i += 6) {
            const id: u16 = (@as(u16, payload[i]) << 8) | @as(u16, payload[i + 1]);
            const value: u32 = (@as(u32, payload[i + 2]) << 24) |
                (@as(u32, payload[i + 3]) << 16) |
                (@as(u32, payload[i + 4]) << 8) |
                @as(u32, payload[i + 5]);
            switch (id) {
                SETTINGS_MAX_FRAME_SIZE => {
                    // RFC 7540 §6.5.2: this advertises what the PEER accepts,
                    // so it updates `peer_max_frame_size` (our OUTBOUND DATA
                    // fragmentation cap), NOT our inbound acceptance cap
                    // `max_frame_size`. Peer values <16384 are invalid; we
                    // clamp to the default. The spec maximum is
                    // 2^24-1 = 16,777,215.
                    if (value < DEFAULT_MAX_FRAME_SIZE) {
                        self.peer_max_frame_size = DEFAULT_MAX_FRAME_SIZE;
                    } else if (value > 0xFFFFFF) {
                        self.peer_max_frame_size = 0xFFFFFF;
                    } else {
                        self.peer_max_frame_size = value;
                    }
                },
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    // §6.9.2: clamp to i32 range (top bit reserved). Apply
                    // delta to every existing stream's send window.
                    const new_initial: i32 = if (value > @as(u32, std.math.maxInt(i32)))
                        std.math.maxInt(i32)
                    else
                        @intCast(value);
                    const old_initial = self.peer_initial_window_size;
                    if (new_initial != old_initial) {
                        // See processWindowUpdate: hold flow_mutex while
                        // updating + bumping flow_epoch to avoid the
                        // lost-wakeup race with reserveSendCredit.
                        self.flow_mutex.lockUncancelable(self.io);
                        defer self.flow_mutex.unlock(self.io);
                        for (self.stream_send_windows) |*sw| {
                            applyInitialWindowSizeDelta(sw, old_initial, new_initial);
                        }
                        self.peer_initial_window_size = new_initial;
                        self.wakeFlowWaiters();
                    }
                },
                else => {},
            }
        }
    }

    /// Read a single HTTP/2 frame header and payload. Public so a
    /// multiplexing reader (`ClientMux`) can drive its own dispatch loop.
    ///
    /// I3 — closes the SETTINGS_MAX_FRAME_SIZE enforcement gap: we now
    /// reject frames whose declared length exceeds `max_frame_size` BEFORE
    /// allocating the payload buffer, and emit a GOAWAY with
    /// FRAME_SIZE_ERROR (0x06) so the peer learns why we are closing.
    pub fn readFrame(self: *Transport) !RawFrame {
        var header: [9]u8 = undefined;
        try self.readExact(&header);

        const length: u24 = (@as(u24, header[0]) << 16) | (@as(u24, header[1]) << 8) | @as(u24, header[2]);
        const frame_type = header[3];
        const flags = header[4];
        const stream_id: u31 = @intCast(
            (@as(u32, header[5] & 0x7F) << 24) |
                (@as(u32, header[6]) << 16) |
                (@as(u32, header[7]) << 8) |
                @as(u32, header[8]),
        );

        // I3: enforce SETTINGS_MAX_FRAME_SIZE before allocating. A
        // malicious or buggy peer must never be able to force the server
        // to allocate up to 16 MiB based on a 24-bit length field.
        checkFrameSize(@intCast(length), self.max_frame_size) catch |err| {
            self.emitGoawayFrameSizeError();
            return err;
        };

        const payload = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(payload);

        if (length > 0) {
            try self.readExact(payload);
        }

        return .{ .frame_type = frame_type, .flags = flags, .stream_id = stream_id, .payload = payload };
    }

    /// Write an HTTP/2 frame; takes `write_mutex` for the header+payload
    /// pair so they can't interleave with another writer. Public so the
    /// `ClientMux` reader thread can send connection-level ACKs.
    pub fn writeFrame(self: *Transport, frame_type: http2.frame.FrameType, flags: u8, stream_id: u31, payload: []const u8) !void {
        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);
        try self.writeFrameLocked(frame_type, flags, stream_id, payload);
    }

    /// Write an HTTP/2 frame; caller MUST hold `write_mutex`. Used inside
    /// multi-frame sequences (e.g. HEADERS+DATA+TRAILERS in `writeMessage`)
    /// so the whole sequence is atomic on the wire.
    fn writeFrameLocked(self: *Transport, frame_type: http2.frame.FrameType, flags: u8, stream_id: u31, payload: []const u8) !void {
        const length: u24 = @intCast(payload.len);
        var header: [9]u8 = undefined;
        header[0] = @intCast((length >> 16) & 0xFF);
        header[1] = @intCast((length >> 8) & 0xFF);
        header[2] = @intCast(length & 0xFF);
        header[3] = @intFromEnum(frame_type);
        header[4] = flags;
        header[5] = @intCast((@as(u32, stream_id) >> 24) & 0x7F);
        header[6] = @intCast((@as(u32, stream_id) >> 16) & 0xFF);
        header[7] = @intCast((@as(u32, stream_id) >> 8) & 0xFF);
        header[8] = @intCast(@as(u32, stream_id) & 0xFF);

        _ = try self.ioWriteLocked(&header);
        if (payload.len > 0) {
            _ = try self.ioWriteLocked(payload);
        }
    }

    /// Write a DATA frame, fragmenting across multiple HTTP/2 DATA frames
    /// when `payload` exceeds `max_frame_size`. The caller-supplied
    /// flags are applied to the LAST fragment; intermediate fragments
    /// carry no flags. Caller MUST hold `write_mutex` AND have already
    /// reserved enough send-window credit via `reserveSendCredit` (or
    /// equivalent) for the entire payload — this fn does NOT block.
    fn writeDataFragmentedLocked(
        self: *Transport,
        stream_id: u31,
        flags: u8,
        payload: []const u8,
    ) !void {
        const max: usize = @intCast(self.peer_max_frame_size);
        if (payload.len == 0) {
            try self.writeFrameLocked(.DATA, flags, stream_id, payload);
            return;
        }
        var offset: usize = 0;
        while (offset < payload.len) {
            const remaining = payload.len - offset;
            const chunk_len = @min(remaining, max);
            const is_last = (offset + chunk_len == payload.len);
            const chunk_flags: u8 = if (is_last) flags else 0;
            try self.writeFrameLocked(.DATA, chunk_flags, stream_id, payload[offset .. offset + chunk_len]);
            offset += chunk_len;
        }
    }

    fn setupHttp2Server(self: *Transport) !void {
        // Server receives and validates HTTP/2 connection preface
        var preface_buf: [24]u8 = undefined;
        try self.readExact(&preface_buf);

        // Validate preface
        if (!std.mem.eql(u8, &preface_buf, HTTP2_PREFACE)) {
            return TransportError.Http2Error;
        }

        // Read client's initial SETTINGS frame
        const frame = try self.readFrame();
        defer self.allocator.free(frame.payload);

        if (frame.frame_type != @intFromEnum(http2.frame.FrameType.SETTINGS)) {
            return TransportError.Http2Error;
        }

        // Apply peer settings (e.g. SETTINGS_MAX_FRAME_SIZE) so subsequent
        // readFrame() calls honour the negotiated cap.
        self.applyPeerSettings(frame.payload);

        // Send server's SETTINGS frame advertising our non-default values
        // (INITIAL_WINDOW_SIZE = 1 MiB, MAX_FRAME_SIZE = 16384, etc.) —
        // closes GAP-0004 / NW-1.
        const body = try buildInitialSettingsBody(self.allocator);
        defer self.allocator.free(body);
        try self.writeFrame(.SETTINGS, 0, 0, body);

        // Send SETTINGS ACK for client's settings
        try self.writeFrame(.SETTINGS, 0x1, 0, &.{});

        // Immediately credit our connection-level recv window from the
        // RFC default (65535) up to ADVERTISED_INITIAL_WINDOW_SIZE — see
        // setupHttp2Client comment.
        try self.bumpConnectionRecvWindow();
    }

    /// Emit a WINDOW_UPDATE on stream 0 to credit our connection-level
    /// receive window from the RFC default (65535) up to
    /// ADVERTISED_INITIAL_WINDOW_SIZE. Called once during HTTP/2 setup.
    fn bumpConnectionRecvWindow(self: *Transport) !void {
        const credit_i64: i64 = @as(i64, ADVERTISED_INITIAL_WINDOW_SIZE) - @as(i64, INITIAL_WINDOW_SIZE_DEFAULT);
        if (credit_i64 <= 0) return;
        const credit: u32 = @intCast(credit_i64);
        const bytes = try buildWindowUpdateFrame(self.allocator, 0, credit);
        defer self.allocator.free(bytes);
        _ = try self.ioWrite(bytes);
        self.conn_recv_window = ADVERTISED_INITIAL_WINDOW_SIZE;
    }

    /// Read the next gRPC message from the connection.
    /// Handles standard gRPC framing: skips HEADERS, SETTINGS, WINDOW_UPDATE,
    /// PING frames, and extracts the protobuf payload from DATA frames by
    /// stripping the 5-byte gRPC length-prefixed message header.
    ///
    /// I3 — a single gRPC message may span multiple HTTP/2 DATA frames
    /// because we honour SETTINGS_MAX_FRAME_SIZE on outbound (and so do
    /// well-behaved peers). We accumulate DATA frames into a per-call
    /// buffer until we have the full gRPC message indicated by the
    /// length-prefix in the first 5 bytes.
    pub fn readMessage(self: *Transport) ![]const u8 {
        var grpc_buf: std.ArrayList(u8) = .empty;
        defer grpc_buf.deinit(self.allocator);
        while (true) {
            const frame = try self.readFrame();
            const frame_type = frame.frame_type;
            const payload = frame.payload;

            switch (frame_type) {
                @intFromEnum(http2.frame.FrameType.DATA) => {
                    // Append this fragment; the gRPC message may have
                    // been split across multiple HTTP/2 DATA frames.
                    const data_len: u32 = @intCast(payload.len);
                    grpc_buf.appendSlice(self.allocator, payload) catch {
                        self.allocator.free(payload);
                        return error.OutOfMemory;
                    };
                    self.allocator.free(payload);
                    // Refill receive windows now that the bytes have
                    // been consumed (NW-2: emit WINDOW_UPDATE when
                    // either window dips below half its initial size).
                    self.maybeRefillRecvWindow(frame.stream_id, data_len);

                    // Try to parse a complete gRPC message from the
                    // accumulated bytes.
                    if (grpc_buf.items.len < 5) continue;
                    const prefix = decodeGrpcPrefix(grpc_buf.items) catch
                        return TransportError.Http2Error;
                    const msg_len = prefix.msg_len;
                    if (grpc_buf.items.len < 5 + msg_len) continue;

                    const result = self.allocator.alloc(u8, msg_len) catch
                        return error.OutOfMemory;
                    @memcpy(result, grpc_buf.items[5 .. 5 + msg_len]);
                    return result;
                },
                @intFromEnum(http2.frame.FrameType.HEADERS) => {
                    // Standard gRPC sends HEADERS before DATA. Remember the
                    // stream ID so we can respond on the same stream.
                    self.last_stream_id = frame.stream_id;
                    // Extract :path from HPACK-encoded headers
                    self.extractPathFromHpack(payload);
                    self.allocator.free(payload);
                    // Continue reading to get the DATA frame
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.SETTINGS) => {
                    // Could be client's SETTINGS ACK or new SETTINGS
                    const is_ack = (frame.flags & 0x1) != 0;
                    if (!is_ack) {
                        // Apply peer settings (e.g. SETTINGS_MAX_FRAME_SIZE)
                        // before ACKing so subsequent reads honour the
                        // negotiated cap.
                        self.applyPeerSettings(payload);
                        // ACK the client's settings -- free payload before try
                        // to avoid leak if writeFrame fails
                        self.allocator.free(payload);
                        try self.writeFrame(.SETTINGS, 0x1, 0, &.{});
                    } else {
                        self.allocator.free(payload);
                    }
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.WINDOW_UPDATE) => {
                    // Credit the relevant send-window so blocked writers
                    // can wake up and emit DATA (NW-3).
                    self.processWindowUpdate(frame.stream_id, payload);
                    self.allocator.free(payload);
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.PING) => {
                    // Respond with PONG (PING with ACK flag)
                    // Copy payload data before freeing, since writeFrame
                    // needs the data and payload must be freed to avoid leaks
                    const is_ack = (frame.flags & 0x1) != 0;
                    if (!is_ack) {
                        var ping_data: [8]u8 = .{0} ** 8;
                        const copy_len = @min(payload.len, 8);
                        @memcpy(ping_data[0..copy_len], payload[0..copy_len]);
                        self.allocator.free(payload);
                        try self.writeFrame(.PING, 0x1, 0, ping_data[0..copy_len]);
                    } else {
                        self.allocator.free(payload);
                    }
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.RST_STREAM) => {
                    self.allocator.free(payload);
                    return TransportError.ConnectionClosed;
                },
                @intFromEnum(http2.frame.FrameType.GOAWAY) => {
                    self.allocator.free(payload);
                    return TransportError.ConnectionClosed;
                },
                else => {
                    // Unknown frame type — skip
                    self.allocator.free(payload);
                    continue;
                },
            }
        }
    }

    /// One frame in a server-streaming response sequence.
    /// `data` is non-null for DATA frames carrying a gRPC message (caller
    /// owns and must free). `end_stream` is true when the peer has signaled
    /// that no further frames will arrive on this stream — either via a
    /// DATA frame with the END_STREAM flag, or via a trailing HEADERS
    /// frame with END_STREAM (the standard gRPC trailers form).
    pub const StreamFrame = struct {
        data: ?[]u8,
        end_stream: bool,
    };

    /// Read the next gRPC message in a server-streaming response, with an
    /// explicit end-of-stream signal. Has the same connection-level frame
    /// handling as `readMessage` (SETTINGS, PING, WINDOW_UPDATE, etc.) but
    /// surfaces END_STREAM to the caller so it knows when the server is
    /// done sending. Returns `{ data: null, end_stream: true }` for the
    /// trailers frame that ends a streaming response with no payload.
    pub fn readStreamFrame(self: *Transport) !StreamFrame {
        var grpc_buf: std.ArrayList(u8) = .empty;
        defer grpc_buf.deinit(self.allocator);
        var saw_end: bool = false;
        while (true) {
            const frame = try self.readFrame();
            const frame_type = frame.frame_type;
            const flags = frame.flags;
            const payload = frame.payload;

            switch (frame_type) {
                @intFromEnum(http2.frame.FrameType.DATA) => {
                    const end = (flags & http2.frame.FrameFlags.END_STREAM) != 0;
                    if (end) saw_end = true;
                    const data_len: u32 = @intCast(payload.len);
                    grpc_buf.appendSlice(self.allocator, payload) catch {
                        self.allocator.free(payload);
                        return error.OutOfMemory;
                    };
                    self.allocator.free(payload);
                    self.maybeRefillRecvWindow(frame.stream_id, data_len);
                    if (grpc_buf.items.len < 5) {
                        if (saw_end) return .{ .data = null, .end_stream = true };
                        continue;
                    }
                    const prefix = decodeGrpcPrefix(grpc_buf.items) catch
                        return TransportError.Http2Error;
                    const msg_len = prefix.msg_len;
                    if (grpc_buf.items.len < 5 + msg_len) {
                        if (saw_end) return .{ .data = null, .end_stream = true };
                        continue;
                    }
                    const result = self.allocator.alloc(u8, msg_len) catch
                        return error.OutOfMemory;
                    @memcpy(result, grpc_buf.items[5 .. 5 + msg_len]);
                    return .{ .data = result, .end_stream = saw_end };
                },
                @intFromEnum(http2.frame.FrameType.HEADERS) => {
                    const end = (flags & http2.frame.FrameFlags.END_STREAM) != 0;
                    self.last_stream_id = frame.stream_id;
                    self.extractPathFromHpack(payload);
                    self.allocator.free(payload);
                    if (end) return .{ .data = null, .end_stream = true };
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.SETTINGS) => {
                    const is_ack = (flags & 0x1) != 0;
                    if (!is_ack) {
                        self.applyPeerSettings(payload);
                        self.allocator.free(payload);
                        try self.writeFrame(.SETTINGS, 0x1, 0, &.{});
                    } else {
                        self.allocator.free(payload);
                    }
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.WINDOW_UPDATE) => {
                    self.processWindowUpdate(frame.stream_id, payload);
                    self.allocator.free(payload);
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.PING) => {
                    const is_ack = (flags & 0x1) != 0;
                    if (!is_ack) {
                        var ping_data: [8]u8 = .{0} ** 8;
                        const copy_len = @min(payload.len, 8);
                        @memcpy(ping_data[0..copy_len], payload[0..copy_len]);
                        self.allocator.free(payload);
                        try self.writeFrame(.PING, 0x1, 0, ping_data[0..copy_len]);
                    } else {
                        self.allocator.free(payload);
                    }
                    continue;
                },
                @intFromEnum(http2.frame.FrameType.RST_STREAM),
                @intFromEnum(http2.frame.FrameType.GOAWAY),
                => {
                    self.allocator.free(payload);
                    return TransportError.ConnectionClosed;
                },
                else => {
                    self.allocator.free(payload);
                    continue;
                },
            }
        }
    }

    /// Return the gRPC method path extracted from the last HEADERS frame.
    pub fn lastMethod(self: *Transport) []const u8 {
        return self.last_method[0..self.last_method_len];
    }

    /// Push a new entry to the front of the HPACK dynamic table.
    fn hpackDynPush(self: *Transport, is_path: bool) void {
        // Move head backward (ring buffer)
        if (self.hpack_dyn_count == 0) {
            self.hpack_dyn_head = 0;
        } else {
            self.hpack_dyn_head = if (self.hpack_dyn_head == 0) HPACK_DYN_MAX - 1 else self.hpack_dyn_head - 1;
        }
        self.hpack_dyn[self.hpack_dyn_head] = .{};
        if (is_path) {
            const len = @min(self.last_method_len, 128);
            @memcpy(self.hpack_dyn[self.hpack_dyn_head].path[0..len], self.last_method[0..len]);
            self.hpack_dyn[self.hpack_dyn_head].path_len = len;
            self.hpack_dyn[self.hpack_dyn_head].is_path = true;
        }
        if (self.hpack_dyn_count < HPACK_DYN_MAX) {
            self.hpack_dyn_count += 1;
        }
    }

    /// Look up a dynamic table entry by index (0 = newest).
    fn hpackDynGet(self: *Transport, dyn_idx: usize) ?*const HpackDynEntry {
        if (dyn_idx >= self.hpack_dyn_count) return null;
        const actual = (self.hpack_dyn_head + dyn_idx) % HPACK_DYN_MAX;
        return &self.hpack_dyn[actual];
    }

    /// Look up an HPACK indexed reference and set last_method if it's a :path entry.
    fn hpackLookupIndex(self: *Transport, index: usize) void {
        if (index <= 61) return; // Static table — :path entries 4,5 are "/" and "/index.html"
        const dyn_idx = index - 62;
        if (self.hpackDynGet(dyn_idx)) |entry| {
            if (entry.is_path) {
                const len = @min(entry.path_len, self.last_method.len);
                @memcpy(self.last_method[0..len], entry.path[0..len]);
                self.last_method_len = len;
            }
        }
    }

    // RFC 7541 Appendix B Huffman decode table, organized by code bit-length.
    // Each group: codes [first_code .. first_code+syms.len) map to syms[] in order.
    // Symbols are sorted by value within each group (canonical Huffman assignment).
    const HuffGroup = struct { bits: u8, first_code: u32, syms: []const u8 };
    const huff_groups = [_]HuffGroup{
        .{ .bits = 5, .first_code = 0x00, .syms = &[_]u8{ '0', '1', '2', 'a', 'c', 'e', 'i', 'o', 's', 't' } },
        .{ .bits = 6, .first_code = 0x14, .syms = &[_]u8{ ' ', '%', '-', '.', '/', '3', '4', '5', '6', '7', '8', '9', '=', 'A', '_', 'b', 'd', 'f', 'g', 'h', 'l', 'm', 'n', 'p', 'r', 'u' } },
        .{ .bits = 7, .first_code = 0x5c, .syms = &[_]u8{ ':', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Y', 'j', 'k', 'q', 'v', 'w', 'x', 'y', 'z' } },
        .{ .bits = 8, .first_code = 0xf8, .syms = &[_]u8{ '&', '*', ',', ';', 'X', 'Z' } },
        .{ .bits = 10, .first_code = 0x3f8, .syms = &[_]u8{ '!', '"', '(', ')', '?' } },
        .{ .bits = 11, .first_code = 0x7fa, .syms = &[_]u8{ '\'', '+', '|' } },
        .{ .bits = 12, .first_code = 0xffa, .syms = &[_]u8{ '#', '>' } },
        .{ .bits = 13, .first_code = 0x1ff8, .syms = &[_]u8{ 0, '$', '@', '[', ']', '~' } },
        .{ .bits = 14, .first_code = 0x3ffc, .syms = &[_]u8{ '^', '}' } },
        .{ .bits = 15, .first_code = 0x7ffc, .syms = &[_]u8{ '<', '`' } },
        .{ .bits = 19, .first_code = 0x7fff0, .syms = &[_]u8{ '\\', '{' } },
    };

    /// Decode an RFC 7541 HPACK Huffman-encoded byte string into plaintext.
    /// Returns the number of decoded bytes written to `out`.
    fn huffmanDecode(encoded: []const u8, out: []u8) usize {
        var out_pos: usize = 0;
        var acc: u32 = 0; // bit accumulator
        var acc_bits: u8 = 0; // number of valid bits in acc

        for (encoded) |byte| {
            // Process each bit from MSB to LSB
            var b: u8 = byte;
            var bit_i: u4 = 0;
            while (bit_i < 8) : (bit_i += 1) {
                acc = (acc << 1) | ((b >> 7) & 1);
                acc_bits += 1;
                b <<= 1;

                // Try to match accumulated bits against each group
                for (huff_groups) |grp| {
                    if (acc_bits == grp.bits) {
                        if (acc >= grp.first_code and acc < grp.first_code + grp.syms.len) {
                            if (out_pos < out.len) {
                                out[out_pos] = grp.syms[acc - grp.first_code];
                                out_pos += 1;
                            }
                            acc = 0;
                            acc_bits = 0;
                            break;
                        }
                    }
                }

                // If we've accumulated too many bits without a match, stop
                // (would only happen for control chars / high bytes not in table)
                if (acc_bits > 19) return out_pos;
            }
        }
        return out_pos;
    }

    /// Decode an HPACK integer with the given prefix size (RFC 7541 §5.1).
    ///
    /// I1 (closes GitLab #6 / security GAP):
    ///   The legacy implementation kept a `std.math.Log2Int(usize)` shift
    ///   counter (u6 on 64-bit targets) and unconditionally added 7 each
    ///   continuation byte. A peer feeding HEADERS with 10+ continuation
    ///   bytes (each with the high bit set) drove that counter past 63 and
    ///   panicked the connection thread on integer overflow. We now:
    ///     * widen the shift counter to u32 so the addition itself is safe,
    ///     * reject before-the-shift if `m + 7 > @bitSizeOf(usize)`, and
    ///     * cap continuation bytes at MAX_HPACK_VARINT_CONTINUATIONS (5),
    ///       enough for any 32-bit value field RFC 7541 admits.
    /// On overflow we return `error.HpackIntegerOverflow` instead of
    /// panicking; the connection thread surfaces this as a protocol error.
    const MAX_HPACK_VARINT_CONTINUATIONS: u32 = 5;

    /// Result of decoding an HPACK varint. `value` holds the decoded
    /// integer; `consumed` is the number of input bytes read.
    pub const HpackVarint = struct { value: usize, consumed: usize };

    fn hpackDecodeInt(
        data: []const u8,
        comptime prefix_bits: u4,
    ) error{HpackIntegerOverflow}!HpackVarint {
        if (data.len == 0) return .{ .value = 0, .consumed = 0 };
        const mask: u8 = (@as(u8, 1) << @as(u3, @intCast(prefix_bits))) - 1;
        var value: usize = data[0] & mask;
        if (value < mask) return .{ .value = value, .consumed = 1 };
        // Multi-byte integer.
        var pos: usize = 1;
        var m: u32 = 0;
        var continuations: u32 = 0;
        while (pos < data.len) {
            // RFC 7541 admits values up to 2^N-1 + 127*2^N for prefix N,
            // but 32-bit is more than enough for any sane HPACK field; cap
            // continuations to MAX_HPACK_VARINT_CONTINUATIONS to defang
            // peers attempting overflow-driven panics.
            if (continuations >= MAX_HPACK_VARINT_CONTINUATIONS) {
                return error.HpackIntegerOverflow;
            }
            // Pre-check the shift width: the next addend is `(b & 0x7F) << m`,
            // which Zig will panic on if m >= @bitSizeOf(usize).
            if (m >= @bitSizeOf(usize)) {
                return error.HpackIntegerOverflow;
            }
            const b = data[pos];
            value += @as(usize, b & 0x7F) << @as(std.math.Log2Int(usize), @intCast(m));
            pos += 1;
            if (b & 0x80 == 0) break;
            // Guard the next iteration's shift: m is about to become m+7.
            if (m + 7 > @bitSizeOf(usize)) {
                return error.HpackIntegerOverflow;
            }
            m += 7;
            continuations += 1;
        }
        return .{ .value = value, .consumed = pos };
    }

    /// Public test entry: returns the same struct as `hpackDecodeInt` but
    /// panics on overflow (only used for valid-input regression tests).
    pub fn hpackDecodeIntForTest(
        data: []const u8,
        comptime prefix_bits: u4,
    ) HpackVarint {
        return hpackDecodeInt(data, prefix_bits) catch unreachable;
    }

    /// Public test entry: returns the error union directly so overflow
    /// tests can assert `error.HpackIntegerOverflow`.
    pub fn hpackDecodeIntChecked(
        data: []const u8,
        comptime prefix_bits: u4,
    ) error{HpackIntegerOverflow}!HpackVarint {
        return hpackDecodeInt(data, prefix_bits);
    }

    /// Skip an HPACK string (returns bytes consumed). Returns 0 on overflow
    /// of the embedded length varint; callers in the bounded-loop parser
    /// treat 0 as "give up" which is safer than propagating up an error
    /// path that would still need to discard the rest of the payload.
    fn hpackSkipString(data: []const u8) usize {
        if (data.len == 0) return 0;
        const int_result = hpackDecodeInt(data, 7) catch return 0;
        return int_result.consumed + int_result.value;
    }

    /// Check if an HPACK string (plain-text, not Huffman) matches `expected`.
    fn hpackStringIs(data: []const u8, expected: []const u8) bool {
        if (data.len == 0) return false;
        const is_huffman = (data[0] & 0x80) != 0;
        if (is_huffman) return false; // only match plain-text names
        const r = hpackDecodeInt(data, 7) catch return false;
        if (r.value != expected.len) return false;
        if (r.consumed + r.value > data.len) return false;
        return std.mem.eql(u8, data[r.consumed .. r.consumed + r.value], expected);
    }

    /// Extract the :path and `authorization` headers from an HPACK-encoded
    /// HEADERS payload.
    ///
    /// `:path` is stored in `last_method` / `last_method_len`.
    /// `authorization` is stored in `last_authorization` / `last_authorization_len`.
    /// `last_authorization_len` is reset to 0 every time a new HEADERS
    /// frame is parsed, so a request without `authorization` produces an
    /// empty value (the auth gate then rejects it as MalformedToken).
    ///
    /// Tracks the HPACK dynamic table so indexed references to :path work
    /// across requests on the same connection.
    fn extractPathFromHpack(self: *Transport, payload: []const u8) void {
        // Reset authorization on every request so a previous request's
        // value can't leak into a new one on the same connection.
        self.last_authorization_len = 0;

        var pos: usize = 0;
        var found_path = false;
        while (pos < payload.len) {
            const byte = payload[pos];

            if (byte & 0x80 != 0) {
                // Indexed header field (1xxxxxxx) — look up in dynamic table
                const r = hpackDecodeInt(payload[pos..], 7) catch return;
                pos += r.consumed;
                if (!found_path) {
                    self.hpackLookupIndex(r.value);
                    if (r.value > 61) {
                        // Check if we found a :path entry
                        const dyn_idx = r.value - 62;
                        if (self.hpackDynGet(dyn_idx)) |entry| {
                            if (entry.is_path) found_path = true;
                        }
                    }
                }
            } else if (byte & 0xC0 == 0x40) {
                // Literal with incremental indexing (01xxxxxx) — adds to dynamic table
                const r = hpackDecodeInt(payload[pos..], 6) catch return;
                pos += r.consumed;
                const name_idx = r.value;
                var is_path_header = (name_idx == 4 or name_idx == 5);
                // HPACK static table index 23 is `authorization` (RFC 7541
                // Appendix A). We also recognise the LIE-literal-name form.
                var is_auth_header = (name_idx == 23);
                if (name_idx == 0) {
                    // Literal name — check if it's ":path" or "authorization" before skipping
                    if (!is_path_header and !is_auth_header) {
                        is_path_header = hpackStringIs(payload[pos..], ":path");
                        is_auth_header = hpackStringIs(payload[pos..], "authorization");
                    }
                    pos += hpackSkipString(payload[pos..]);
                }
                // Read value
                if (pos >= payload.len) {
                    // Still add a non-path entry to keep table in sync
                    self.hpackDynPush(false);
                    break;
                }
                if (is_path_header) {
                    // This is :path — decode and add to dynamic table
                    self.setPathFromHpackString(payload[pos..]);
                    pos += hpackSkipString(payload[pos..]);
                    self.hpackDynPush(true);
                    found_path = true;
                } else if (is_auth_header) {
                    self.setAuthorizationFromHpackString(payload[pos..]);
                    pos += hpackSkipString(payload[pos..]);
                    self.hpackDynPush(false);
                } else {
                    pos += hpackSkipString(payload[pos..]);
                    self.hpackDynPush(false);
                }
            } else if (byte & 0xF0 == 0x00 or byte & 0xF0 == 0x10) {
                // Literal without indexing (0000xxxx) or never indexed (0001xxxx)
                // Does NOT add to dynamic table
                const r = hpackDecodeInt(payload[pos..], 4) catch return;
                pos += r.consumed;
                const name_idx = r.value;
                var is_path_hdr = (name_idx == 4 or name_idx == 5);
                var is_auth_hdr = (name_idx == 23);
                if (name_idx == 0) {
                    if (!is_path_hdr and !is_auth_hdr) {
                        is_path_hdr = hpackStringIs(payload[pos..], ":path");
                        is_auth_hdr = hpackStringIs(payload[pos..], "authorization");
                    }
                    pos += hpackSkipString(payload[pos..]);
                }
                if (pos >= payload.len) break;
                if (is_path_hdr) {
                    self.setPathFromHpackString(payload[pos..]);
                    found_path = true;
                } else if (is_auth_hdr) {
                    self.setAuthorizationFromHpackString(payload[pos..]);
                }
                pos += hpackSkipString(payload[pos..]);
            } else if (byte & 0xE0 == 0x20) {
                // Dynamic table size update (001xxxxx) — skip
                const r = hpackDecodeInt(payload[pos..], 5) catch return;
                pos += r.consumed;
            } else {
                pos += 1; // unknown — skip byte
            }
        }
    }

    /// Read an HPACK string at position and set last_method from it.
    /// Handles both Huffman and non-Huffman encoded strings.
    fn setPathFromHpackString(self: *Transport, data: []const u8) void {
        if (data.len == 0) return;
        const is_huffman = (data[0] & 0x80) != 0;
        const r = hpackDecodeInt(data, 7) catch return;
        const str_start = r.consumed;
        const str_len = r.value;
        if (str_start + str_len > data.len) return;
        const str_bytes = data[str_start .. str_start + str_len];

        if (!is_huffman) {
            // Plain text — copy directly
            const copy_len = @min(str_len, self.last_method.len);
            @memcpy(self.last_method[0..copy_len], str_bytes[0..copy_len]);
            self.last_method_len = copy_len;
        } else {
            // Huffman encoded — decode using RFC 7541 table
            self.last_method_len = huffmanDecode(str_bytes, &self.last_method);
        }
    }

    /// Read an HPACK string at position and copy it into `last_authorization`.
    /// Mirror of setPathFromHpackString — used by the GAP-0001 auth gate.
    fn setAuthorizationFromHpackString(self: *Transport, data: []const u8) void {
        if (data.len == 0) return;
        const is_huffman = (data[0] & 0x80) != 0;
        const r = hpackDecodeInt(data, 7) catch return;
        const str_start = r.consumed;
        const str_len = r.value;
        if (str_start + str_len > data.len) return;
        const str_bytes = data[str_start .. str_start + str_len];

        if (!is_huffman) {
            const copy_len = @min(str_len, self.last_authorization.len);
            @memcpy(self.last_authorization[0..copy_len], str_bytes[0..copy_len]);
            self.last_authorization_len = copy_len;
        } else {
            self.last_authorization_len = huffmanDecode(str_bytes, &self.last_authorization);
        }
    }

    /// Return the `authorization` header value extracted from the last
    /// HEADERS frame, or an empty slice if none was present.
    pub fn lastAuthorization(self: *Transport) []const u8 {
        return self.last_authorization[0..self.last_authorization_len];
    }

    /// Write a single gRPC response message in a server stream.
    /// Sends HEADERS (if first message) + DATA, but no TRAILERS — the stream stays open.
    pub fn writeStreamMessage(self: *Transport, message: []const u8, is_first: bool) !void {
        const sid = self.last_stream_id;

        const grpc_frame = try self.allocator.alloc(u8, 5 + message.len);
        defer self.allocator.free(grpc_frame);
        encodeGrpcPrefix(grpc_frame[0..5], @intCast(message.len));
        @memcpy(grpc_frame[5..], message);

        // Reserve send-window credit BEFORE acquiring write_mutex so we
        // never block (waiting for peer WINDOW_UPDATE) while holding it.
        // On `error.FlowControlTimeout` the wrapper has already emitted
        // RST_STREAM(FLOW_CONTROL_ERROR); propagate so the caller drops
        // the stream.
        try self.reserveSendCreditOrRst(sid, @intCast(grpc_frame.len));

        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);

        if (is_first) {
            try self.writeFrameLocked(.HEADERS, http2.frame.FrameFlags.END_HEADERS, sid, &RESPONSE_HEADERS_BYTES);
        }
        try self.writeDataFragmentedLocked(sid, 0, grpc_frame);
    }

    /// End a gRPC server stream by sending TRAILERS with grpc-status: 0.
    pub fn endStream(self: *Transport) !void {
        const sid = self.last_stream_id;
        try self.writeFrame(.HEADERS, http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS, sid, &OK_TRAILERS_BYTES);
    }

    /// End a gRPC stream with a non-zero (or zero) status code and an
    /// optional `grpc-message`. Emits a single trailer-only HEADERS frame
    /// with END_STREAM | END_HEADERS, encoding `grpc-status` as decimal-ASCII
    /// and (if provided) `grpc-message` as a literal value.
    ///
    /// Status codes per the gRPC core spec
    /// (https://grpc.io/docs/guides/status-codes/):
    ///   0  OK              2  UNKNOWN          12 UNIMPLEMENTED
    ///   16 UNAUTHENTICATED 7  PERMISSION_DENIED ...
    ///
    /// Used by error paths (handler errors, missing/invalid auth, unknown
    /// method) to give the client a definitive trailer instead of a closed
    /// connection. `message` MUST fit in a 7-bit-prefix HPACK length (<128
    /// bytes after any necessary truncation by the caller); longer messages
    /// are truncated to 127 bytes to stay within that prefix.
    pub fn endStreamWithStatus(self: *Transport, stream_id: u31, code: u8, message: ?[]const u8) !void {
        // grpc-status decimal-ASCII (max 3 chars: 0..255).
        var code_buf: [3]u8 = undefined;
        const code_str = std.fmt.bufPrint(&code_buf, "{d}", .{code}) catch unreachable;

        // Compute payload size up-front so we can allocate a single buffer
        // and emit one frame.
        // Layout:
        //   0x40, 11, "grpc-status",  <code_len>, <code_bytes>
        //   [optional] 0x40, 12, "grpc-message", <msg_len>, <msg_bytes>
        const status_overhead: usize = 1 + 1 + 11 + 1; // type + name_len + name + value_len
        var msg_slice: ?[]const u8 = null;
        if (message) |m| {
            // Truncate to 127 to fit a 7-bit varint length prefix.
            msg_slice = if (m.len > 127) m[0..127] else m;
        }
        var total: usize = status_overhead + code_str.len;
        if (msg_slice) |m| {
            total += 1 + 1 + 12 + 1 + m.len; // type + name_len + name + value_len + value
        }

        const payload = try self.allocator.alloc(u8, total);
        defer self.allocator.free(payload);

        var i: usize = 0;
        payload[i] = 0x40; // LIE literal-name
        i += 1;
        payload[i] = 11; // "grpc-status".len
        i += 1;
        @memcpy(payload[i .. i + 11], "grpc-status");
        i += 11;
        payload[i] = @intCast(code_str.len);
        i += 1;
        @memcpy(payload[i .. i + code_str.len], code_str);
        i += code_str.len;

        if (msg_slice) |m| {
            payload[i] = 0x40;
            i += 1;
            payload[i] = 12; // "grpc-message".len
            i += 1;
            @memcpy(payload[i .. i + 12], "grpc-message");
            i += 12;
            payload[i] = @intCast(m.len);
            i += 1;
            @memcpy(payload[i .. i + m.len], m);
            i += m.len;
        }

        std.debug.assert(i == total);

        try self.writeFrame(
            .HEADERS,
            http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS,
            stream_id,
            payload,
        );
    }

    /// Write a gRPC response message.
    /// Sends proper gRPC framing: HEADERS frame, then DATA frame with
    /// 5-byte gRPC prefix, then TRAILERS with grpc-status: 0.
    pub fn writeMessage(self: *Transport, message: []const u8) !void {
        return self.writeMessageOnStream(self.last_stream_id, message);
    }

    /// Write a gRPC message on a specific HTTP/2 stream id. Holds the
    /// `write_mutex` for the entire HEADERS+DATA+TRAILERS sequence so
    /// concurrent writers (multiple in-flight client calls) can't
    /// interleave their frames on the wire.
    pub fn writeMessageOnStream(self: *Transport, stream_id: u31, message: []const u8) !void {
        const grpc_frame = try self.allocator.alloc(u8, 5 + message.len);
        defer self.allocator.free(grpc_frame);
        encodeGrpcPrefix(grpc_frame[0..5], @intCast(message.len));
        @memcpy(grpc_frame[5..], message);

        // Reserve send-window credit BEFORE acquiring write_mutex.
        // The wrapper emits RST_STREAM(FLOW_CONTROL_ERROR) on timeout.
        try self.reserveSendCreditOrRst(stream_id, @intCast(grpc_frame.len));

        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);

        try self.writeFrameLocked(.HEADERS, http2.frame.FrameFlags.END_HEADERS, stream_id, &RESPONSE_HEADERS_BYTES);
        try self.writeDataFragmentedLocked(stream_id, 0, grpc_frame);

        try self.writeFrameLocked(.HEADERS, http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS, stream_id, &OK_TRAILERS_BYTES);
    }

    /// Write a CLIENT request: HEADERS (request-shaped) + DATA with
    /// END_STREAM. Uses `self.last_stream_id` for the legacy single-call
    /// path. Holds `write_mutex` for the whole sequence.
    pub fn writeRequest(self: *Transport, message: []const u8, method_path: []const u8) !void {
        return self.writeRequestOnStream(self.last_stream_id, message, method_path);
    }

    /// Variant of `writeRequest` that includes per-RPC metadata in the
    /// HPACK HEADERS payload (e.g. `authorization: Bearer ...`).
    /// Closes GAP-0002.
    pub fn writeRequestWithMetadata(
        self: *Transport,
        message: []const u8,
        method_path: []const u8,
        metadata: ?*const std.StringHashMapUnmanaged([]const u8),
    ) !void {
        return self.writeRequestOnStreamWithMetadata(
            self.last_stream_id,
            message,
            method_path,
            metadata,
        );
    }

    /// Write a CLIENT request on the given stream id. Emits request-shaped
    /// HPACK HEADERS (`:method POST`, `:scheme http`, `:path`, `:authority`,
    /// `content-type`, `te trailers`) followed by a single gRPC-framed DATA
    /// frame with END_STREAM. Holds `write_mutex` for the whole sequence so
    /// HEADERS+DATA cannot interleave with another writer.
    pub fn writeRequestOnStream(self: *Transport, stream_id: u31, message: []const u8, method_path: []const u8) !void {
        return self.writeRequestOnStreamWithMetadata(stream_id, message, method_path, null);
    }

    /// Variant of `writeRequestOnStream` that emits per-RPC metadata as
    /// trailing HPACK headers in the HEADERS frame. Closes GAP-0002.
    pub fn writeRequestOnStreamWithMetadata(
        self: *Transport,
        stream_id: u31,
        message: []const u8,
        method_path: []const u8,
        metadata: ?*const std.StringHashMapUnmanaged([]const u8),
    ) !void {
        const headers_bytes = try writeRequestHeadersWithMetadata(
            self.allocator,
            method_path,
            self.authority,
            metadata,
        );
        defer self.allocator.free(headers_bytes);

        const grpc_frame = try self.allocator.alloc(u8, 5 + message.len);
        defer self.allocator.free(grpc_frame);
        encodeGrpcPrefix(grpc_frame[0..5], @intCast(message.len));
        @memcpy(grpc_frame[5..], message);

        // Reserve send-window credit BEFORE acquiring write_mutex.
        // The wrapper emits RST_STREAM(FLOW_CONTROL_ERROR) on timeout.
        try self.reserveSendCreditOrRst(stream_id, @intCast(grpc_frame.len));

        self.write_mutex.lockUncancelable(self.io);
        defer self.write_mutex.unlock(self.io);

        try self.writeFrameLocked(.HEADERS, http2.frame.FrameFlags.END_HEADERS, stream_id, headers_bytes);
        try self.writeDataFragmentedLocked(stream_id, http2.frame.FrameFlags.END_STREAM, grpc_frame);
    }
};

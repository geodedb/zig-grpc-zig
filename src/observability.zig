//! observability.zig — single-file otel seam for grpc-zig.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to
//! `otel.instrumentation.http`.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break gRPC traffic.
//!
//! NOTE: deviation from template — gRPC's request shape is
//! `[]const u8` (the method path) plus the host/port held on the client
//! struct. The template's duck-typed `req.method_string()` /
//! `req.url_string()` accessors don't fit the gRPC call site cleanly,
//! so this seam accepts an `anytype` whose only requirement is the
//! method/route/url accessor functions OR plain string fields. The
//! re-export `RpcRequest` below shows the canonical shape callers
//! should use; tests use a tiny anonymous struct with the same fields.

const std = @import("std");
const build_options = @import("build_options");

pub const enabled: bool = build_options.with_otel;

const otel = if (enabled) @import("otel") else struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Canonical request shape for the gRPC seam. Callers may use this
/// struct or any anytype with the same three string-returning accessor
/// functions / fields. Fields are plain slices (not closures) — the
/// seam introspects them via `accessOr` below.
pub const RpcRequest = struct {
    method: []const u8,
    route: []const u8,
    url: []const u8,
};

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes. The closure
/// shape is what the recipe template ships; the field shape is what
/// hot-path call sites in client.zig / server.zig will use.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for an outbound gRPC call. The caller passes anything
/// with `method`, `route`, `url` accessors (string fields or zero-arg
/// fns returning strings).
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

/// Close a client span with the gRPC status code. We bridge gRPC status
/// (0 = OK, non-zero = error) into HTTP semconv: status 0 -> 200, any
/// non-zero gRPC status -> 500 so the otel HTTP helper marks the span
/// `error`. Future work could attach `rpc.grpc.status_code` directly.
pub fn endClientSpan(span: Span, grpc_status: u16) void {
    if (!enabled) return;
    const http_status: u16 = if (grpc_status == 0) 200 else 500;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = http_status });
}

/// Start a span for an inbound gRPC call.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endServerSpan(span: Span, grpc_status: u16) void {
    if (!enabled) return;
    const http_status: u16 = if (grpc_status == 0) 200 else 500;
    otel.instrumentation.http.endServerSpan(span, http_status);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};

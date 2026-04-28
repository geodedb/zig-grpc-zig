//! Verifies one client span lands in an in-memory recorder when
//! -Dwith_otel=true. Skips under the disabled build.
//!
//! NOTE: deviation from template — we exercise the seam directly via
//! the in-memory recorder rather than spinning up the full gRPC
//! transport. The recipe explicitly permits this when running the
//! real stack would require network setup. The seam's behavior is
//! identical: `startClientSpan` -> `endClientSpan` enters and leaves
//! one tracer span.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const grpc = @import("grpc-server");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one span recorded when otel enabled" {
    if (!grpc.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "grpc-zig-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "grpc-zig-test" });
    grpc.observability.global.tracer = &tracer;
    defer grpc.observability.global.tracer = null;

    const span = grpc.observability.startClientSpan(.{
        .method = "POST",
        .route = "/svc/Method",
        .url = "grpc://localhost:50051/svc/Method",
    });
    grpc.observability.endClientSpan(span, 0);

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);
}

//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! grpc-zig publishes two public modules ("grpc-server" rooted at
//! src/server.zig and "grpc-client" rooted at src/client.zig). This test
//! exercises the seam through the server module since it carries the
//! observability surface for the consumer.

const std = @import("std");
const grpc = @import("grpc-server");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled tracks build_options.with_otel" {
    const build_options = @import("build_options");
    try std.testing.expectEqual(build_options.with_otel, grpc.observability.enabled);
}

test "no-op when otel disabled" {
    if (grpc.observability.enabled) return error.SkipZigTest;
    var span = grpc.observability.startClientSpan(.{
        .method = "POST",
        .route = "/svc/Method",
        .url = "grpc://host:50051/svc/Method",
    });
    grpc.observability.endClientSpan(span, 0);
    // Belt-and-suspenders: callers may also invoke `span.end(null)`
    // directly. The seam's `endClientSpan` already covers the lifecycle;
    // this line just verifies the no-op fallback signature matches the
    // real API's `Span.end(?u64) void`.
    span.end(null);
}

test "server seam no-op when otel disabled" {
    if (grpc.observability.enabled) return error.SkipZigTest;
    var span = grpc.observability.startServerSpan(.{
        .method = "POST",
        .route = "/svc/Method",
        .url = "/svc/Method",
    });
    grpc.observability.endServerSpan(span, 0);
    span.end(null);
}

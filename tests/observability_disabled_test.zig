//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! grpc-zig publishes two public modules ("grpc-server" rooted at
//! src/server.zig and "grpc-client" rooted at src/client.zig). This test
//! exercises the seam through the server module since it carries the
//! observability surface for the consumer.
//!
//! Task 1.2 introduces only the `build_options.with_otel` assertion.
//! Task 1.4 extends this file with the seam-level no-op tests once
//! `observability.zig` exists.

const std = @import("std");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

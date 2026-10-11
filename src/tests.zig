const std = @import("std");
const testing = std.testing;
const benchmark = @import("benchmark.zig");

test "benchmark handler" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const request = "test_request";
    const response = try benchmark.benchmarkHandler(request, allocator);
    defer allocator.free(response);

    // Verify response contains the request
    try testing.expect(std.mem.indexOf(u8, response, request) != null);
    // Verify response contains timestamp
    try testing.expect(std.mem.indexOf(u8, response, "processed at") != null);
}

test "compression - gzip" {
    const compression = @import("features/compression.zig");

    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var comp = compression.Compression.init(allocator);

    // Test data
    const original = "Hello, World! This is a test of gzip compression. " ** 10;

    // Compress
    const compressed = try comp.compress(original, .gzip);
    defer allocator.free(compressed);

    // Compressed should be smaller than original
    try testing.expect(compressed.len < original.len);

    // Decompress
    const decompressed = try comp.decompress(compressed, .gzip);
    defer allocator.free(decompressed);

    // Should match original
    try testing.expectEqualStrings(original, decompressed);
}

test "compression - deflate" {
    const compression = @import("features/compression.zig");

    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var comp = compression.Compression.init(allocator);

    // Test data
    const original = "Deflate compression test data. " ** 20;

    // Compress
    const compressed = try comp.compress(original, .deflate);
    defer allocator.free(compressed);

    // Compressed should be smaller
    try testing.expect(compressed.len < original.len);

    // Decompress
    const decompressed = try comp.decompress(compressed, .deflate);
    defer allocator.free(decompressed);

    // Should match original
    try testing.expectEqualStrings(original, decompressed);
}

test "health check - setStatus does not leak duped keys" {
    const health = @import("features/health.zig");

    var gpa = std.heap.DebugAllocator(.{}).init;
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("HealthCheck leaked memory");
    const allocator = gpa.allocator();

    var hc = health.HealthCheck.init(allocator);
    defer hc.deinit();

    // Insert and update repeatedly: each set must not leak its key, and the
    // dedup path on update must not leak either.
    try hc.setStatus("svc.a", .SERVING);
    try hc.setStatus("svc.b", .SERVING);
    try hc.setStatus("svc.a", .NOT_SERVING); // update — must reuse existing key
    try hc.setStatus("svc.c", .SERVING);

    try testing.expectEqual(health.HealthStatus.NOT_SERVING, hc.getStatus("svc.a"));
    try testing.expectEqual(health.HealthStatus.SERVING, hc.getStatus("svc.b"));
    try testing.expectEqual(health.HealthStatus.SERVING, hc.getStatus("svc.c"));
}

test "compression - none algorithm" {
    const compression = @import("features/compression.zig");

    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var comp = compression.Compression.init(allocator);

    const original = "No compression test";

    // Compress with none
    const compressed = try comp.compress(original, .none);
    defer allocator.free(compressed);

    // Should be same length
    try testing.expectEqual(original.len, compressed.len);
    try testing.expectEqualStrings(original, compressed);

    // Decompress
    const decompressed = try comp.decompress(compressed, .none);
    defer allocator.free(decompressed);

    try testing.expectEqualStrings(original, decompressed);
}

test {
    // Full HPACK decoder used by the server reader (h2spec gate).
    _ = @import("hpack_decoder.zig");
}

// Bounded admission control tests (closes CC-1 + MW-4 / GitLab #20 + #18).
//
// The server's accept loop now requires a slot from a counting semaphore
// before spawning a connection thread. The semaphore is sized from the
// `GRPC_ZIG_MAX_CONNS` env var, falling back to 1024.
//
// These tests cover the static helpers in isolation; the full
// integration test (3 concurrent connects with max=2 on the live
// accept loop) lives in the loopback binary because it requires
// running an actual server.

const std = @import("std");
const testing = std.testing;
const server_mod = @import("server.zig");

test "maxConnsFromEnv falls back to default when env var missing" {
    // We don't set the env var here — std.process.getEnvVarOwned
    // returns error.EnvironmentVariableNotFound, which the helper
    // converts to the default fallback (1024).
    const allocator = std.testing.allocator;
    const got = try server_mod.GrpcServer.maxConnsFromEnvForTest(allocator);
    try testing.expectEqual(@as(usize, 1024), got);
}

test "parseMaxConnsValue accepts a positive integer" {
    try testing.expectEqual(@as(usize, 256), try server_mod.GrpcServer.parseMaxConnsValue("256"));
    try testing.expectEqual(@as(usize, 1), try server_mod.GrpcServer.parseMaxConnsValue("1"));
    try testing.expectEqual(@as(usize, 65536), try server_mod.GrpcServer.parseMaxConnsValue("65536"));
}

test "parseMaxConnsValue rejects zero (would deadlock the accept loop)" {
    try testing.expectError(error.InvalidMaxConns, server_mod.GrpcServer.parseMaxConnsValue("0"));
}

test "parseMaxConnsValue rejects non-integer text" {
    try testing.expectError(error.InvalidMaxConns, server_mod.GrpcServer.parseMaxConnsValue("foo"));
    try testing.expectError(error.InvalidMaxConns, server_mod.GrpcServer.parseMaxConnsValue(""));
    try testing.expectError(error.InvalidMaxConns, server_mod.GrpcServer.parseMaxConnsValue("-5"));
}

test "GrpcServer.DEFAULT_MAX_CONNS is 1024" {
    try testing.expectEqual(@as(usize, 1024), server_mod.GrpcServer.DEFAULT_MAX_CONNS);
}

test "parseFlowCreditTimeoutMs accepts non-negative integers including 0 (disable)" {
    // GAP-FU-002 — unlike GRPC_ZIG_MAX_CONNS, a value of 0 is valid
    // here (disables the per-stream credit timeout entirely). Empty
    // and non-digit input is still rejected.
    try testing.expectEqual(@as(u64, 0), try server_mod.GrpcServer.parseFlowCreditTimeoutMs("0"));
    try testing.expectEqual(@as(u64, 30000), try server_mod.GrpcServer.parseFlowCreditTimeoutMs("30000"));
    try testing.expectEqual(@as(u64, 1), try server_mod.GrpcServer.parseFlowCreditTimeoutMs("1"));
}

test "parseFlowCreditTimeoutMs rejects empty and non-numeric input" {
    try testing.expectError(error.InvalidFlowCreditTimeout, server_mod.GrpcServer.parseFlowCreditTimeoutMs(""));
    try testing.expectError(error.InvalidFlowCreditTimeout, server_mod.GrpcServer.parseFlowCreditTimeoutMs("forever"));
    try testing.expectError(error.InvalidFlowCreditTimeout, server_mod.GrpcServer.parseFlowCreditTimeoutMs("-1"));
}

test "GrpcServer.DEFAULT_FLOW_CREDIT_TIMEOUT_MS is 30_000 (30 s)" {
    try testing.expectEqual(@as(u64, 30_000), server_mod.GrpcServer.DEFAULT_FLOW_CREDIT_TIMEOUT_MS);
}

test "Semaphore wait then post does not block" {
    // Smoke test that the std.Io.Semaphore primitive we depend on
    // behaves as expected: with 2 permits, two waits return without
    // blocking, and posts top the count back up.
    const io = std.testing.io;
    var sem: std.Io.Semaphore = .{ .permits = 2 };
    sem.waitUncancelable(io);
    sem.waitUncancelable(io);
    sem.post(io);
    sem.post(io);
    // Two more should still pass (we posted what we waited for).
    sem.waitUncancelable(io);
    sem.waitUncancelable(io);
    sem.post(io);
    sem.post(io);
}

test "O1: DEFAULT_BIND_ADDRESS is loopback" {
    try testing.expectEqualStrings("127.0.0.1", server_mod.GrpcServer.DEFAULT_BIND_ADDRESS);
}

test "O1: bindAddressFromEnv falls back to default when unset" {
    // GRPC_ZIG_BIND_ADDR is not set in the test environment.
    try testing.expectEqualStrings("127.0.0.1", server_mod.GrpcServer.bindAddressFromEnv());
}

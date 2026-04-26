//! Tests for the JWT-based `Auth` feature.
//!
//! Closes A3 + M3:
//!   * A3 — replace placeholder dot-separated string with full RFC 7519
//!     JWT: base64url(header).base64url(payload).base64url(hmac_sha256).
//!   * M3 — verify HMAC with `std.crypto.timing_safe.eql` instead of
//!     `std.mem.eql` so signature comparison runs in constant time.
//!
//! Each test exercises a distinct branch:
//!   1. `generateToken` -> `verifyToken` round-trip succeeds.
//!   2. Tampered payload (re-signed with a wrong key) is rejected.
//!   3. Expired token is rejected with `error.TokenExpired`.
//!   4. Constant-time compare smoke test: signatures equal byte-by-byte
//!      compare equal under `timing_safe.eql` and unequal otherwise.
//!   5. Malformed (non-three-segment) token returns `error.MalformedToken`.

const std = @import("std");
const testing = std.testing;
const auth = @import("features/auth.zig");
const crypto = std.crypto;

test "generateToken / verifyToken round-trip succeeds" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var a = auth.Auth.init(allocator, "test-secret-key-1234567890");
    const token = try a.generateToken("alice", 3600);
    defer allocator.free(token);

    // RFC 7519 token must have exactly two '.' separators.
    var dot_count: usize = 0;
    for (token) |c| if (c == '.') {
        dot_count += 1;
    };
    try testing.expectEqual(@as(usize, 2), dot_count);

    // Verify must succeed and return the parsed claims.
    const claims = try a.verifyToken(token);
    defer allocator.free(claims.sub);
    try testing.expectEqualStrings("alice", claims.sub);
    try testing.expect(claims.exp > claims.iat);
}

test "tampered payload is rejected" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var a = auth.Auth.init(allocator, "test-secret-key-1234567890");
    const token = try a.generateToken("alice", 3600);
    defer allocator.free(token);

    // Flip a single byte in the payload segment (between the two dots) and
    // expect verification to fail with InvalidSignature.
    const buf = try allocator.dupe(u8, token);
    defer allocator.free(buf);

    // Find the second segment.
    const first_dot = std.mem.indexOfScalar(u8, buf, '.') orelse return error.TestFailed;
    const second_dot = std.mem.indexOfScalarPos(u8, buf, first_dot + 1, '.') orelse return error.TestFailed;
    // Tamper a byte in the middle of the payload segment.
    const tamper_at = first_dot + 1 + (second_dot - first_dot - 1) / 2;
    // Pick a different valid base64url char.
    buf[tamper_at] = if (buf[tamper_at] == 'A') 'B' else 'A';

    const result = a.verifyToken(buf);
    try testing.expectError(auth.AuthError.InvalidSignature, result);
}

test "expired token is rejected" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var a = auth.Auth.init(allocator, "test-secret-key-1234567890");

    // Generate with negative TTL — token's `exp` lies in the past.
    const token = try a.generateToken("bob", -10);
    defer allocator.free(token);

    const result = a.verifyToken(token);
    try testing.expectError(auth.AuthError.TokenExpired, result);
}

test "malformed token (missing segments) is rejected" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var a = auth.Auth.init(allocator, "test-secret-key-1234567890");

    const cases = [_][]const u8{
        "",
        "header.payload",
        "no-dots-here",
        ".",
        "..",
        "x.y.z.extra",
    };
    for (cases) |t| {
        const result = a.verifyToken(t);
        try testing.expectError(auth.AuthError.MalformedToken, result);
    }
}

test "wrong secret key is rejected as InvalidSignature" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create with key A.
    var signer = auth.Auth.init(allocator, "secret-A");
    const token = try signer.generateToken("alice", 3600);
    defer allocator.free(token);

    // Verify with key B — should reject.
    var verifier = auth.Auth.init(allocator, "secret-B-different-key");
    const result = verifier.verifyToken(token);
    try testing.expectError(auth.AuthError.InvalidSignature, result);
}

test "constant-time compare smoke test" {
    // Direct check that std.crypto.timing_safe.eql behaves as expected for
    // 32-byte HMAC outputs. This is a sanity check — the actual auth path
    // calls it inside verifyToken.
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    @memset(&a, 0xAA);
    @memset(&b, 0xAA);
    try testing.expect(crypto.timing_safe.eql([32]u8, a, b));

    b[31] ^= 0x01;
    try testing.expect(!crypto.timing_safe.eql([32]u8, a, b));
}

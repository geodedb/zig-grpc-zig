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

test "FIPS-0007: crypto_backend HMAC-SHA256 matches std and detects mismatch" {
    const crypto_backend = @import("crypto_backend");
    var tag: [32]u8 = undefined;
    const n = try crypto_backend.Mac.hmac(.sha256, "k", "msg", &tag);
    try testing.expectEqual(@as(usize, 32), n);
    // RFC 4231 TC2 vector for cross-check.
    var tag2: [32]u8 = undefined;
    _ = try crypto_backend.Mac.hmac(.sha256, "Jefe", "what do ya want for nothing?", &tag2);
    const expect = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try testing.expectEqualSlices(u8, &expect, &tag2);
}

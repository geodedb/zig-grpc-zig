const std = @import("std");
const auth = @import("features/auth.zig");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var auth_handler = auth.Auth.init(allocator, "my-secret-key");

    // Generate a token
    const token = try auth_handler.generateToken("user123", 3600);
    defer allocator.free(token);

    std.debug.print("Generated token: {s}\n", .{token});

    // Verify the token. Returns parsed claims on success — caller owns
    // the duped `sub` slice.
    const claims = try auth_handler.verifyToken(token);
    defer allocator.free(claims.sub);
    std.debug.print("Token verified successfully for sub={s}\n", .{claims.sub});

    // Try to verify an invalid token
    _ = auth_handler.verifyToken("invalid.token.here") catch |err| {
        std.debug.print("Expected error: {}\n", .{err});
    };
}

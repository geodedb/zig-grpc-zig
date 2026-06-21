// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const crypto_backend = @import("crypto_backend");

test "grpc-zig crypto_backend seam resolves Mac (HMAC-SHA256)" {
    var tag: [32]u8 = undefined;
    const n = try crypto_backend.Mac.hmac(.sha256, "Jefe", "what do ya want for nothing?", &tag);
    try std.testing.expectEqual(@as(usize, 32), n);
    crypto_backend.assertActive();
}

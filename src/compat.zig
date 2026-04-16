/// Zig 0.16.0 compatibility helpers for time functions.
/// In 0.16.0, std.time.timestamp/nanoTimestamp/milliTimestamp were removed.
/// These helpers provide equivalent functionality using libc clock_gettime.
const std = @import("std");

/// Returns seconds since Unix epoch (equivalent to old std.time.timestamp).
pub fn timestamp() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// Returns milliseconds since Unix epoch (equivalent to old std.time.milliTimestamp).
pub fn milliTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    const sec_ms: i64 = @as(i64, @intCast(ts.sec)) * 1000;
    const nsec_ms: i64 = @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
    return sec_ms + nsec_ms;
}

/// Returns nanoseconds from monotonic clock (equivalent to old std.time.nanoTimestamp).
pub fn nanoTimestamp() i128 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

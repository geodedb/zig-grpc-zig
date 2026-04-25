/// Zig 0.16.0 compatibility helpers for time functions.
/// In 0.16.0, std.time.timestamp/nanoTimestamp/milliTimestamp were removed.
/// The new portable API is `std.Io.Clock.now(io)`, but threading an `Io`
/// through every call site is impractical for these utility helpers, so
/// we drop to the OS directly here.
const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

const win = if (is_windows) struct {
    extern "kernel32" fn GetSystemTimePreciseAsFileTime(*std.os.windows.FILETIME) callconv(.winapi) void;
    extern "kernel32" fn QueryPerformanceCounter(*i64) callconv(.winapi) i32;
    extern "kernel32" fn QueryPerformanceFrequency(*i64) callconv(.winapi) i32;

    /// FILETIME is 100-ns intervals since 1601-01-01 UTC; convert to
    /// nanoseconds since 1970-01-01 UTC (the POSIX epoch).
    fn nowUnixNs() i128 {
        var ft: std.os.windows.FILETIME = undefined;
        GetSystemTimePreciseAsFileTime(&ft);
        const t100ns: u64 = (@as(u64, ft.dwHighDateTime) << 32) | @as(u64, ft.dwLowDateTime);
        // 11_644_473_600 seconds between 1601-01-01 and 1970-01-01.
        const epoch_offset_100ns: u64 = 11_644_473_600 * 10_000_000;
        const unix_100ns: u64 = t100ns - epoch_offset_100ns;
        return @as(i128, unix_100ns) * 100;
    }

    fn monotonicNs() i128 {
        var freq: i64 = 0;
        var counter: i64 = 0;
        _ = QueryPerformanceFrequency(&freq);
        _ = QueryPerformanceCounter(&counter);
        return @divTrunc(@as(i128, counter) * std.time.ns_per_s, @as(i128, freq));
    }
} else struct {};

/// Returns seconds since Unix epoch (equivalent to old std.time.timestamp).
pub fn timestamp() i64 {
    if (is_windows) {
        return @intCast(@divTrunc(win.nowUnixNs(), std.time.ns_per_s));
    }
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// Returns milliseconds since Unix epoch (equivalent to old std.time.milliTimestamp).
pub fn milliTimestamp() i64 {
    if (is_windows) {
        return @intCast(@divTrunc(win.nowUnixNs(), std.time.ns_per_ms));
    }
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    const sec_ms: i64 = @as(i64, @intCast(ts.sec)) * 1000;
    const nsec_ms: i64 = @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
    return sec_ms + nsec_ms;
}

/// Returns nanoseconds from monotonic clock (equivalent to old std.time.nanoTimestamp).
pub fn nanoTimestamp() i128 {
    if (is_windows) return win.monotonicNs();
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

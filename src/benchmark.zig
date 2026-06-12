const std = @import("std");
const GrpcClient = @import("client.zig").GrpcClient;
const GrpcServer = @import("server.zig").GrpcServer;
const json = std.json;
const compat = @import("compat.zig");

// Benchmark configuration
const BenchmarkConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 50051,
    num_requests: u32 = 1000,
    concurrent_clients: u32 = 10,
    request_size_bytes: u32 = 1024,
    warmup_requests: u32 = 100,
    secret_key: ?[]const u8 = null,
};

// Benchmark results structure
const BenchmarkResults = struct {
    total_requests: u32,
    successful_requests: u32,
    failed_requests: u32,
    total_duration_ms: f64,
    requests_per_second: f64,
    latency_stats: LatencyStats,
    error_rate: f64,
    timestamp: i64,

    const LatencyStats = struct {
        min_ms: f64,
        max_ms: f64,
        avg_ms: f64,
        p95_ms: f64,
        p99_ms: f64,
    };
};

// Simple benchmarking timer
const Timer = struct {
    start_time: i128,

    fn start() Timer {
        return Timer{
            .start_time = compat.nanoTimestamp(),
        };
    }

    fn elapsed_ms(self: Timer) f64 {
        const end_time = compat.nanoTimestamp();
        return @as(f64, @floatFromInt(end_time - self.start_time)) / 1_000_000.0;
    }
};

// Test client worker
const ClientWorker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: BenchmarkConfig,
    results: std.ArrayList(f64),

    fn init(allocator: std.mem.Allocator, io: std.Io, config: BenchmarkConfig) ClientWorker {
        return ClientWorker{
            .allocator = allocator,
            .io = io,
            .config = config,
            .results = .empty,
        };
    }

    fn deinit(self: *ClientWorker) void {
        self.results.deinit(self.allocator);
    }

    fn runBenchmark(self: *ClientWorker) !void {
        var client = try GrpcClient.init(self.allocator, self.io, self.config.host, self.config.port);
        defer client.deinit();

        if (self.config.secret_key) |key| {
            try client.setAuth(key);
        }

        // Generate test payload
        const payload = try self.generatePayload();
        defer self.allocator.free(payload);

        // Warmup requests
        for (0..self.config.warmup_requests) |_| {
            if (client.call("/grpc.benchmark/Benchmark", payload, .none)) |warmup_response| {
                self.allocator.free(warmup_response);
            } else |_| {
                // Ignore warmup errors
                continue;
            }
        }

        // Actual benchmark requests
        for (0..self.config.num_requests) |_| {
            const timer = Timer.start();

            const response = client.call("/grpc.benchmark/Benchmark", payload, .none) catch |err| {
                std.log.warn("Request failed: {}", .{err});
                continue;
            };

            const elapsed = timer.elapsed_ms();
            try self.results.append(self.allocator, elapsed);

            self.allocator.free(response);
        }
    }

    fn generatePayload(self: *ClientWorker) ![]u8 {
        const payload = try self.allocator.alloc(u8, self.config.request_size_bytes);
        var prng = std.Random.DefaultPrng.init(@as(u64, @intCast(compat.milliTimestamp())));
        const random = prng.random();

        for (payload) |*byte| {
            byte.* = random.int(u8);
        }

        return payload;
    }
};

fn calculateLatencyStats(latencies: []f64) BenchmarkResults.LatencyStats {
    if (latencies.len == 0) {
        return BenchmarkResults.LatencyStats{
            .min_ms = 0,
            .max_ms = 0,
            .avg_ms = 0,
            .p95_ms = 0,
            .p99_ms = 0,
        };
    }

    // Sort latencies for percentile calculations
    std.sort.heap(f64, latencies, {}, comptime std.sort.asc(f64));

    var sum: f64 = 0;
    for (latencies) |lat| {
        sum += lat;
    }

    const p95_index = @as(usize, @intFromFloat(@as(f64, @floatFromInt(latencies.len)) * 0.95));
    const p99_index = @as(usize, @intFromFloat(@as(f64, @floatFromInt(latencies.len)) * 0.99));

    return BenchmarkResults.LatencyStats{
        .min_ms = latencies[0],
        .max_ms = latencies[latencies.len - 1],
        .avg_ms = sum / @as(f64, @floatFromInt(latencies.len)),
        .p95_ms = latencies[@min(p95_index, latencies.len - 1)],
        .p99_ms = latencies[@min(p99_index, latencies.len - 1)],
    };
}

fn workerMain(worker: *ClientWorker) void {
    worker.runBenchmark() catch |err| {
        std.log.warn("Worker failed: {}", .{err});
        // A worker that died early simply has fewer results; the
        // aggregation loop accounts for the shortfall as failures.
    };
}

fn runBenchmark(allocator: std.mem.Allocator, io: std.Io, config: BenchmarkConfig) !BenchmarkResults {
    std.log.info("Starting benchmark with {} concurrent clients, {} requests each", .{ config.concurrent_clients, config.num_requests });

    var all_latencies = try std.ArrayList(f64).initCapacity(allocator, config.concurrent_clients);
    defer all_latencies.deinit(allocator);

    const overall_timer = Timer.start();

    // Create and run client workers concurrently
    var workers = try std.ArrayList(ClientWorker).initCapacity(allocator, config.concurrent_clients);
    defer {
        for (workers.items) |*worker| {
            worker.deinit();
        }
        workers.deinit(allocator);
    }

    // Initialize workers
    for (0..config.concurrent_clients) |_| {
        const worker = ClientWorker.init(allocator, io, config);
        workers.appendAssumeCapacity(worker);
    }

    // Run workers concurrently — one OS thread per configured client
    // (closes BH-1 / #22: the loop previously ran workers serially, so
    // --clients N measured sequential throughput, not concurrency).
    var threads = try std.ArrayList(std.Thread).initCapacity(allocator, config.concurrent_clients);
    defer threads.deinit(allocator);
    for (workers.items) |*worker| {
        threads.appendAssumeCapacity(try std.Thread.spawn(.{}, workerMain, .{worker}));
    }
    for (threads.items) |t| t.join();

    var total_successful: u32 = 0;
    var total_failed: u32 = 0;
    for (workers.items) |*worker| {
        for (worker.results.items) |latency| {
            try all_latencies.append(allocator, latency);
        }
        total_successful += @as(u32, @intCast(worker.results.items.len));
        total_failed += config.num_requests - @as(u32, @intCast(worker.results.items.len));
    }

    const total_duration = overall_timer.elapsed_ms();
    const total_requests = config.concurrent_clients * config.num_requests;
    const requests_per_second = @as(f64, @floatFromInt(total_successful)) / (total_duration / 1000.0);

    return BenchmarkResults{
        .total_requests = total_requests,
        .successful_requests = total_successful,
        .failed_requests = total_failed,
        .total_duration_ms = total_duration,
        .requests_per_second = requests_per_second,
        .latency_stats = calculateLatencyStats(all_latencies.items),
        .error_rate = @as(f64, @floatFromInt(total_failed)) / @as(f64, @floatFromInt(total_requests)),
        .timestamp = compat.timestamp(),
    };
}

fn outputResults(allocator: std.mem.Allocator, io: std.Io, results: BenchmarkResults, format: Format) !void {
    switch (format) {
        .json => {
            const doc = try std.fmt.allocPrint(allocator,
                \\{{
                \\  "total_requests": {d},
                \\  "successful_requests": {d},
                \\  "failed_requests": {d},
                \\  "total_duration_ms": {d:.2},
                \\  "requests_per_second": {d:.2},
                \\  "latency_stats": {{
                \\    "min_ms": {d:.2},
                \\    "max_ms": {d:.2},
                \\    "avg_ms": {d:.2},
                \\    "p95_ms": {d:.2},
                \\    "p99_ms": {d:.2}
                \\  }},
                \\  "error_rate": {d:.4},
                \\  "timestamp": {d}
                \\}}
                \\
            , .{
                results.total_requests,       results.successful_requests,
                results.failed_requests,      results.total_duration_ms,
                results.requests_per_second,  results.latency_stats.min_ms,
                results.latency_stats.max_ms, results.latency_stats.avg_ms,
                results.latency_stats.p95_ms, results.latency_stats.p99_ms,
                results.error_rate,           results.timestamp,
            });
            defer allocator.free(doc);
            // Write to STDOUT; std.debug.print goes to stderr, which
            // broke `--output json > file.json` (BH-4 / #23).
            try std.Io.File.stdout().writeStreamingAll(io, doc);
        },
        .text => {
            std.debug.print("Benchmark Results:\n", .{});
            std.debug.print("==================\n", .{});
            std.debug.print("Total Requests: {}\n", .{results.total_requests});
            std.debug.print("Successful: {}\n", .{results.successful_requests});
            std.debug.print("Failed: {}\n", .{results.failed_requests});
            std.debug.print("Error Rate: {d:.2}%\n", .{results.error_rate * 100});
            std.debug.print("Total Duration: {d:.2}ms\n", .{results.total_duration_ms});
            std.debug.print("Requests/sec: {d:.2}\n", .{results.requests_per_second});
            std.debug.print("Latency Stats:\n", .{});
            std.debug.print("  Min: {d:.2}ms\n", .{results.latency_stats.min_ms});
            std.debug.print("  Max: {d:.2}ms\n", .{results.latency_stats.max_ms});
            std.debug.print("  Avg: {d:.2}ms\n", .{results.latency_stats.avg_ms});
            std.debug.print("  P95: {d:.2}ms\n", .{results.latency_stats.p95_ms});
            std.debug.print("  P99: {d:.2}ms\n", .{results.latency_stats.p99_ms});
        },
    }
}

pub const Format = enum { json, text };

fn parseArgs(allocator: std.mem.Allocator, args_raw: std.process.Args) !struct { config: BenchmarkConfig, output_format: Format, secret_owned: bool } {
    var config = BenchmarkConfig{};
    var format: Format = .text;
    var secret_owned = false;
    var args_iter = std.process.Args.Iterator.init(args_raw);

    // Skip program name
    _ = args_iter.next();

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            if (args_iter.next()) |val| {
                config.host = try allocator.dupe(u8, val);
            }
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (args_iter.next()) |val| {
                config.port = try std.fmt.parseInt(u16, val, 10);
            }
        } else if (std.mem.eql(u8, arg, "--requests")) {
            if (args_iter.next()) |val| {
                config.num_requests = try std.fmt.parseInt(u32, val, 10);
            }
        } else if (std.mem.eql(u8, arg, "--clients")) {
            if (args_iter.next()) |val| {
                config.concurrent_clients = try std.fmt.parseInt(u32, val, 10);
            }
        } else if (std.mem.eql(u8, arg, "--size")) {
            if (args_iter.next()) |val| {
                config.request_size_bytes = try std.fmt.parseInt(u32, val, 10);
            }
        } else if (std.mem.eql(u8, arg, "--secret")) {
            if (args_iter.next()) |val| {
                config.secret_key = try allocator.dupe(u8, val);
                secret_owned = true;
            }
        } else if (std.mem.eql(u8, arg, "--output")) {
            if (args_iter.next()) |val| {
                if (std.mem.eql(u8, val, "json")) {
                    format = .json;
                } else if (std.mem.eql(u8, val, "text")) {
                    format = .text;
                }
            }
        } else if (std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        }
    }

    if (config.secret_key == null) {
        if (std.c.getenv("GRPC_ZIG_BENCH_SECRET")) |raw_ptr| {
            config.secret_key = std.mem.span(raw_ptr);
        }
    }

    return .{ .config = config, .output_format = format, .secret_owned = secret_owned };
}

fn printUsage() void {
    std.debug.print("gRPC-zig Benchmark Tool\n", .{});
    std.debug.print("Usage: benchmark [options]\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("Options:\n", .{});
    std.debug.print("  --host <host>       Server host (default: localhost)\n", .{});
    std.debug.print("  --port <port>       Server port (default: 50051)\n", .{});
    std.debug.print("  --requests <n>      Number of requests per client (default: 1000)\n", .{});
    std.debug.print("  --clients <n>       Number of concurrent clients (default: 10)\n", .{});
    std.debug.print("  --size <bytes>      Request payload size (default: 1024)\n", .{});
    std.debug.print("  --output <format>   Output format: text|json (default: text)\n", .{});
    std.debug.print("  --secret <key>      Auth secret (default: none; env GRPC_ZIG_BENCH_SECRET)\n", .{});
    std.debug.print("  --help              Show this help message\n", .{});
}

// Simple benchmark handler for testing
pub fn benchmarkHandler(request: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Echo the request back with a timestamp
    const response = try std.fmt.allocPrint(allocator, "Echo: {s} (processed at {})", .{ request, compat.milliTimestamp() });
    return response;
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const parsed = try parseArgs(allocator, init.minimal.args);
    const config = parsed.config;
    const output_format = parsed.output_format;
    // Free the duplicated host string at the end
    defer if (config.host.ptr != "localhost".ptr) allocator.free(config.host);
    defer if (parsed.secret_owned) {
        if (config.secret_key) |s| allocator.free(s);
    };

    std.debug.print("gRPC-zig Benchmark Tool\n", .{});
    std.debug.print("Configuration:\n", .{});
    std.debug.print("  Host: {s}:{}\n", .{ config.host, config.port });
    std.debug.print("  Requests per client: {}\n", .{config.num_requests});
    std.debug.print("  Concurrent clients: {}\n", .{config.concurrent_clients});
    std.debug.print("  Request size: {} bytes\n", .{config.request_size_bytes});
    std.debug.print("  Output format: {}\n", .{output_format});

    const results = try runBenchmark(allocator, init.io, config);
    try outputResults(allocator, init.io, results, output_format);
}

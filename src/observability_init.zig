//! observability_init.zig — bootstrap helper. Only compiled when
//! `build_options.with_otel == true` (gated at the importer site by
//! `if (@import("build_options").with_otel) @import("observability_init.zig")`).
//!
//! Reads OTEL_* env vars via otel.sdk.config.resolve; builds a
//! TracerProvider, MeterProvider, and LoggerProvider with sane
//! production defaults; exposes Tracer/Meter handles to
//! observability.zig's `global`. On any init failure, log to
//! `std.log.err` and leave globals as null — the seam's
//! `catch return Span{}` paths then yield no-op behaviour.
//!
//! API contract used here matches otel HEAD:
//!   - otel.sdk.config.resolve(allocator, ?Config) !Config
//!   - otel.sdk.trace.TracerProvider.initFromConfig(alloc, *const Config) !TP
//!   - otel.sdk.metrics.MeterProvider.initFromConfig(alloc, *const Config) !MP
//!   - otel.sdk.logs.LoggerProvider.initFromConfig(alloc, *const Config) !LP

const std = @import("std");
const otel = @import("otel");
const observability = @import("observability.zig");

pub const Otel = struct {
    allocator: std.mem.Allocator,
    /// Captured at `init` time so `installGlobals` can re-derive the
    /// instrumentation scope after the value has been moved into its
    /// final storage location.
    service_name: []const u8,
    cfg: otel.sdk.config.Config,
    tracer_provider: otel.sdk.trace.TracerProvider,
    meter_provider: otel.sdk.metrics.MeterProvider,
    logger_provider: otel.sdk.logs.LoggerProvider,
    // Tracer / Meter handles are owned by-value here so the address we
    // hand to `observability.global` stays valid for the lifetime of
    // the Otel struct.
    tracer: otel.api.trace.Tracer,
    meter: otel.api.metrics.Meter,

    /// Build the providers and return the value. The caller is
    /// responsible for parking the returned Otel at a STABLE address
    /// and then calling `installGlobals()` from THAT address.
    pub fn init(
        allocator: std.mem.Allocator,
        service_name_default: []const u8,
    ) !@This() {
        var cfg = try otel.sdk.config.resolve(allocator, null);
        errdefer cfg.deinit(allocator);
        if (cfg.service_name.len == 0) {
            cfg.service_name = service_name_default;
            cfg.service_name_owned = false;
        }

        var tp = try otel.sdk.trace.TracerProvider.initFromConfig(allocator, &cfg);
        errdefer tp.deinit();

        var mp = try otel.sdk.metrics.MeterProvider.initFromConfig(allocator, &cfg);
        errdefer mp.deinit();

        var lp = try otel.sdk.logs.LoggerProvider.initFromConfig(allocator, &cfg);
        errdefer lp.deinit();

        return .{
            .allocator = allocator,
            .service_name = service_name_default,
            .cfg = cfg,
            .tracer_provider = tp,
            .meter_provider = mp,
            .logger_provider = lp,
            .tracer = undefined,
            .meter = undefined,
        };
    }

    /// Materialise the Tracer + Meter handles into struct-owned fields
    /// and publish their addresses to `observability.global`. MUST be
    /// called against a `*@This()` whose backing storage outlives every
    /// span site.
    pub fn installGlobals(self: *@This()) void {
        self.tracer = self.tracer_provider.tracer(.{ .name = self.service_name });
        self.meter = self.meter_provider.meter(.{ .name = self.service_name });
        observability.global.tracer = &self.tracer;
        observability.global.meter = &self.meter;
    }

    pub fn deinit(self: *@This()) void {
        observability.global.tracer = null;
        observability.global.meter = null;
        self.tracer_provider.forceFlush(2_000) catch {};
        self.meter_provider.forceFlush(2_000) catch {};
        self.logger_provider.forceFlush(2_000) catch {};
        self.tracer_provider.deinit();
        self.meter_provider.deinit();
        self.logger_provider.deinit();
        self.cfg.deinit(self.allocator);
    }
};

const std = @import("std");

pub const HealthStatus = enum {
    UNKNOWN,
    SERVING,
    NOT_SERVING,
    SERVICE_UNKNOWN,
};

pub const HealthCheck = struct {
    status: std.StringHashMap(HealthStatus),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HealthCheck {
        return .{
            .status = std.StringHashMap(HealthStatus).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HealthCheck) void {
        var it = self.status.keyIterator();
        while (it.next()) |key_ptr| self.allocator.free(key_ptr.*);
        self.status.deinit();
    }

    pub fn setStatus(self: *HealthCheck, service: []const u8, status: HealthStatus) !void {
        // If the key already exists, replace the value without re-duplicating
        // the key string. Otherwise, dup once and insert; on insert failure
        // free the dup to avoid leaking it.
        if (self.status.getEntry(service)) |entry| {
            entry.value_ptr.* = status;
            return;
        }
        const service_key = try self.allocator.dupe(u8, service);
        errdefer self.allocator.free(service_key);
        try self.status.put(service_key, status);
    }

    pub fn getStatus(self: *HealthCheck, service: []const u8) HealthStatus {
        return self.status.get(service) orelse .UNKNOWN;
    }

    pub fn check(self: *HealthCheck, service: []const u8) !HealthStatus {
        // Perform actual health check logic here
        const current_status = self.getStatus(service);
        if (current_status == .UNKNOWN) {
            return error.ServiceNotFound;
        }
        return current_status;
    }
};

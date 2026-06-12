# Audit Fixes Iteration 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the actionable findings from the 2026-06-11 appsec review (`docs/APPSEC_REVIEW_2026-06-11.md`) and codepros audit: the pre-auth memory-DoS (NEW-1/#43), frame-cap erosion (NEW-2/#44), client-mux OOM deadlock (#57), dead-code attack surface (#64/#50), codec/doc/benchmark quality items, and secure defaults.

**Architecture:** All protocol fixes land in `src/transport.zig` (the single transport module — the planned M7 split is deferred to iteration 2, so edits follow the existing in-file conventions). Client-mux fixes land in `src/client_mux.zig` with a new testable `deliverData` helper. Benchmark, server-default, and documentation fixes are independent. New regression tests follow the existing pattern: small dedicated `src/*_test.zig` root files wired into the `test` step in `build.zig`.

**Tech Stack:** Zig 0.16.0, `zig build test` (8 existing test steps), `zig fmt`, GitLab CI (h2spec interop gate exercises the HTTP/2 server).

**Verification commands (used by every task):**

- Format: `zig fmt src/ build.zig tests/ examples/`
- Compile: `zig build check`
- Test: `zig build test`
- Smoke (optional, end-to-end): `zig build loopback-test && timeout 60 ./zig-out/bin/grpc-loopback-test`

**Conventions:**

- Commit after every task, message style: `fix(scope): summary (closes #NN / FINDING-ID)`.
- Zig 0.16 idioms: `std.ArrayList(u8) = .empty` + allocator-passing methods; `std.Io.Mutex`/`.lockUncancelable(io)`; tests use `std.testing`.
- Never weaken an existing test. If a step's expected output differs, STOP and re-read the code — do not force it.

---

## Task 1: Delete dead `src/http2/` modules (I7/#50, M5/M6/#64, M12/#72-part)

The stub HPACK decoder in `src/http2/hpack.zig:86-101` has out-of-bounds reads and is dead code; `src/http2/connection.zig` and `src/http2/stream.zig` are orphaned state machines. Only two things from `src/http2/` are actually live: `frame.zig` (FrameType/FrameFlags, used everywhere) and the `PREFACE` constant from `connection.zig` (used at `transport.zig:495` and `transport.zig:1128`).

**Files:**

- Delete: `src/http2/connection.zig`, `src/http2/hpack.zig`, `src/http2/stream.zig`
- Modify: `src/transport.zig:1-7` (imports), `src/transport.zig:495`, `src/transport.zig:1128` (PREFACE uses)
- Modify: `src/client.zig:2` (remove unused `proto` import)
- Keep: `src/http2/frame.zig` (live)

- [ ] **Step 1: Verify the only live uses**

Run: `grep -rn "http2/connection\|http2/hpack\|http2/stream\|connection.Connection\|proto/service" src/ examples/ integration_test/ interop/zig/ tests/`
Expected: hits only in `src/transport.zig` (import block + 2 PREFACE uses), `src/http2/connection.zig` itself, `src/client.zig:2`, `src/tests.zig:3`, and `integration_test/`/`interop` files that import their OWN proto module (leave those alone). If anything else references the dead modules, STOP and report.

- [ ] **Step 2: Inline the preface constant in transport.zig**

In `src/transport.zig`, replace the import block at lines 1-7:

```zig
const std = @import("std");
const net = std.Io.net;
const http2 = struct {
    pub const frame = @import("http2/frame.zig");
};

/// HTTP/2 client connection preface (RFC 7540 §3.5).
pub const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
```

Then replace both uses:

- Line ~495: `_ = try self.ioWrite(http2.connection.Connection.PREFACE);` → `_ = try self.ioWrite(HTTP2_PREFACE);`
- Line ~1128: `if (!std.mem.eql(u8, &preface_buf, http2.connection.Connection.PREFACE)) {` → `if (!std.mem.eql(u8, &preface_buf, HTTP2_PREFACE)) {`

- [ ] **Step 3: Delete the dead files and the unused client import**

```bash
git rm src/http2/connection.zig src/http2/hpack.zig src/http2/stream.zig
```

In `src/client.zig`, delete line 2 (`const proto = @import("proto/service.zig");`). Do NOT touch `src/tests.zig`'s proto import yet (Task 11 removes it together with the commented tests that reference it).

Check `src/tests.zig:3`: `const proto = @import("proto/service.zig");` — if `zig build test` fails with "unused" on it after this task, it was already unused; remove it here instead of in Task 11.

- [ ] **Step 4: Verify build and tests**

Run: `zig fmt src/ && zig build check && zig build test`
Expected: all pass. If `zig build check` complains about `src/proto/service.zig` no longer being referenced anywhere, that's fine (it's still referenced by `src/tests.zig` until Task 11).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(http2): delete dead connection/hpack/stream modules (closes #64, #50; I7/M5/M6)"
```

---

## Task 2: Extract gRPC length-prefix helpers + OK trailers constant (M3/M4/#61, M2/#62, I6/#49)

The 5-byte gRPC message prefix is encoded inline at 3 sites (`transport.zig:1752-1759`, `:1873-1880`, `:1963-1970`) and decoded inline at 3 sites (`transport.zig:1209-1212`, `:1329-1332`, `client_mux.zig:259-262`). The OK trailer literal is duplicated (`transport.zig:1780-1782` and `:1892-1908`). The decoder never validates the compression-flag byte (I6).

**Files:**

- Modify: `src/transport.zig` (add helpers near `RESPONSE_HEADERS_BYTES` at ~line 250; replace the 6 inline sites + 2 trailer literals)
- Modify: `src/client_mux.zig` (use decode helper)
- Create: `src/grpc_framing_test.zig`
- Modify: `build.zig` (wire new test file into `test` step)

- [ ] **Step 1: Write the failing test**

Create `src/grpc_framing_test.zig`:

```zig
const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "encodeGrpcPrefix writes flag 0 and big-endian length" {
    var buf: [5]u8 = undefined;
    transport.encodeGrpcPrefix(&buf, 0x01020304);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0x01, 0x02, 0x03, 0x04 }, &buf);
}

test "decodeGrpcPrefix roundtrips" {
    var buf: [5]u8 = undefined;
    transport.encodeGrpcPrefix(&buf, 42);
    const p = try transport.decodeGrpcPrefix(&buf);
    try testing.expectEqual(@as(u32, 42), p.msg_len);
    try testing.expectEqual(false, p.compressed);
}

test "decodeGrpcPrefix accepts compressed flag 1" {
    const buf = [_]u8{ 1, 0, 0, 0, 7 };
    const p = try transport.decodeGrpcPrefix(&buf);
    try testing.expectEqual(@as(u32, 7), p.msg_len);
    try testing.expectEqual(true, p.compressed);
}

test "decodeGrpcPrefix rejects invalid compression flag (I6)" {
    const buf = [_]u8{ 0xFF, 0, 0, 0, 1 };
    try testing.expectError(error.InvalidGrpcPrefix, transport.decodeGrpcPrefix(&buf));
}

test "decodeGrpcPrefix rejects short input" {
    const buf = [_]u8{ 0, 0 };
    try testing.expectError(error.InvalidGrpcPrefix, transport.decodeGrpcPrefix(&buf));
}

test "OK_TRAILERS_BYTES encodes grpc-status 0" {
    // 0x40 LIE literal-name, len 11, "grpc-status", len 1, '0'
    try testing.expectEqual(@as(usize, 15), transport.OK_TRAILERS_BYTES.len);
    try testing.expectEqual(@as(u8, 0x40), transport.OK_TRAILERS_BYTES[0]);
    try testing.expectEqualSlices(u8, "grpc-status", transport.OK_TRAILERS_BYTES[2..13]);
    try testing.expectEqual(@as(u8, '0'), transport.OK_TRAILERS_BYTES[14]);
}
```

Wire into `build.zig`: copy the exact pattern of the `hpack_varint_tests` block (build.zig:219-229), renaming to `grpc_framing_tests` with `.root_source_file = b.path("src/grpc_framing_test.zig")` and a step name `"grpc-framing-tests"`, then `test_step.dependOn(&run_grpc_framing_tests.step);`.

- [ ] **Step 2: Run test to verify it fails**

Run: `zig build test`
Expected: FAIL — `transport` has no member `encodeGrpcPrefix` / `decodeGrpcPrefix` / `OK_TRAILERS_BYTES`.

- [ ] **Step 3: Implement the helpers in transport.zig**

Add after the `RESPONSE_HEADERS_BYTES` constant (around line 270), at module level (NOT inside the `Transport` struct):

```zig
/// Pre-encoded HPACK trailer payload for a successful gRPC response:
///   grpc-status: 0   (LIE literal-name 0x40, name "grpc-status", value "0")
/// Hoisted from the duplicated literals in `endStream` and
/// `writeMessageOnStream` (closes quality M2).
pub const OK_TRAILERS_BYTES = [_]u8{
    0x40, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '0',
};

/// Decoded gRPC 5-byte message prefix (compression flag + u32 length).
pub const GrpcPrefix = struct { compressed: bool, msg_len: u32 };

/// Encode the gRPC length prefix (flag byte 0 = uncompressed) into
/// `out[0..5]`. Single definition for the three write paths (closes M3).
pub fn encodeGrpcPrefix(out: *[5]u8, msg_len: u32) void {
    out[0] = 0;
    out[1] = @intCast((msg_len >> 24) & 0xFF);
    out[2] = @intCast((msg_len >> 16) & 0xFF);
    out[3] = @intCast((msg_len >> 8) & 0xFF);
    out[4] = @intCast(msg_len & 0xFF);
}

/// Decode and validate a gRPC 5-byte message prefix. The compression
/// flag byte MUST be 0 or 1 (gRPC over HTTP/2 spec); anything else is
/// a framing error (closes I6 / #49). Closes M4: single definition for
/// the three read paths.
pub fn decodeGrpcPrefix(buf: []const u8) error{InvalidGrpcPrefix}!GrpcPrefix {
    if (buf.len < 5) return error.InvalidGrpcPrefix;
    if (buf[0] > 1) return error.InvalidGrpcPrefix;
    const msg_len = (@as(u32, buf[1]) << 24) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 8) |
        @as(u32, buf[4]);
    return .{ .compressed = buf[0] == 1, .msg_len = msg_len };
}
```

- [ ] **Step 4: Replace the six inline sites and two trailer literals**

Encode sites — in `writeStreamMessage` (~:1748), `writeMessageOnStream` (~:1871), `writeRequestOnStreamWithMetadata` (~:1947), replace the five `grpc_frame[N] = ...` lines with:

```zig
        const grpc_frame = try self.allocator.alloc(u8, 5 + message.len);
        defer self.allocator.free(grpc_frame);
        encodeGrpcPrefix(grpc_frame[0..5], @intCast(message.len));
        @memcpy(grpc_frame[5..], message);
```

(delete the now-unused `const grpc_msg_len: u32 = @intCast(message.len);` line at each site).

Decode sites — in `readMessage` (~:1208-1213) replace:

```zig
                    if (grpc_buf.items.len < 5) continue;
                    const prefix = decodeGrpcPrefix(grpc_buf.items) catch
                        return TransportError.Http2Error;
                    const msg_len = prefix.msg_len;
                    if (grpc_buf.items.len < 5 + msg_len) continue;
```

In `readStreamFrame` (~:1325-1336) the same substitution, preserving the `if (saw_end) return .{ .data = null, .end_stream = true };` short-circuits exactly as they are.

In `client_mux.zig` `readerLoop` `.DATA` arm (~:258-263), replace the inline decode:

```zig
                    if (payload.len >= 5) {
                        if (transport.decodeGrpcPrefix(payload)) |prefix| {
                            const msg_len = prefix.msg_len;
                            if (payload.len >= 5 + msg_len) {
                                slot.data.appendSlice(self.allocator, payload[5 .. 5 + msg_len]) catch |e| {
                                    slot.err = e;
                                };
                            }
                        } else |e| {
                            slot.err = e;
                        }
                    }
```

(Task 5 restructures this block further; make this minimal substitution now so each task stays reviewable.)

Trailer literals — in `endStream` (~:1778-1783) replace the local `trailers` array:

```zig
    pub fn endStream(self: *Transport) !void {
        const sid = self.last_stream_id;
        try self.writeFrame(.HEADERS, http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS, sid, &OK_TRAILERS_BYTES);
    }
```

In `writeMessageOnStream` (~:1892-1909) replace the 15-element `trailers` array and its write with:

```zig
        try self.writeFrameLocked(.HEADERS, http2.frame.FrameFlags.END_STREAM | http2.frame.FrameFlags.END_HEADERS, stream_id, &OK_TRAILERS_BYTES);
```

- [ ] **Step 5: Run tests**

Run: `zig fmt src/ build.zig && zig build test`
Expected: PASS (all steps including new `grpc-framing-tests`).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(transport): extract gRPC prefix helpers + OK trailers constant; validate compression flag (closes #61, #62, #49)"
```

---

## Task 3: Decouple inbound frame-size cap from peer SETTINGS_MAX_FRAME_SIZE (NEW-2/#44)

Per RFC 7540 §6.5.2, the peer's `SETTINGS_MAX_FRAME_SIZE` advertises what the *peer* accepts (governs our outbound fragmentation). Today `applyPeerSettings` (`transport.zig:986-996`) overwrites `self.max_frame_size`, which `readFrame` (`:1048`) uses as the *inbound* cap — so a peer can raise our acceptance cap to 16 MiB.

**Files:**

- Modify: `src/transport.zig` (field + `applyPeerSettings` + `writeDataFragmentedLocked`)
- Modify: `src/transport_max_frame_size_test.zig` (add regression tests)

- [ ] **Step 1: Write the failing tests**

Append to `src/transport_max_frame_size_test.zig` (read the file first to match its import style):

```zig
test "NEW-2: peer SETTINGS_MAX_FRAME_SIZE does not raise our inbound cap" {
    var t: transport.Transport = undefined;
    t.max_frame_size = transport.DEFAULT_MAX_FRAME_SIZE;
    t.peer_max_frame_size = transport.DEFAULT_MAX_FRAME_SIZE;
    // SETTINGS payload: id 0x05 (MAX_FRAME_SIZE), value 0xFFFFFF
    const payload = [_]u8{ 0x00, 0x05, 0x00, 0xFF, 0xFF, 0xFF };
    t.applyPeerSettings(&payload);
    // Outbound fragmentation limit follows the peer...
    try std.testing.expectEqual(@as(u32, 0xFFFFFF), t.peer_max_frame_size);
    // ...but our inbound acceptance cap must NOT move.
    try std.testing.expectEqual(transport.DEFAULT_MAX_FRAME_SIZE, t.max_frame_size);
    // And readFrame's check still rejects an oversize inbound frame.
    try std.testing.expectError(
        transport.TransportError.FrameSizeError,
        transport.Transport.checkFrameSize(16385, t.max_frame_size),
    );
}

test "NEW-2: peer values below RFC minimum clamp to default" {
    var t: transport.Transport = undefined;
    t.max_frame_size = transport.DEFAULT_MAX_FRAME_SIZE;
    t.peer_max_frame_size = transport.DEFAULT_MAX_FRAME_SIZE;
    const payload = [_]u8{ 0x00, 0x05, 0x00, 0x00, 0x00, 0x01 };
    t.applyPeerSettings(&payload);
    try std.testing.expectEqual(transport.DEFAULT_MAX_FRAME_SIZE, t.peer_max_frame_size);
}
```

NOTE: `applyPeerSettings` only touches `flow_mutex`/`io` in its `SETTINGS_INITIAL_WINDOW_SIZE` branch; these payloads contain only id 0x05, so an `undefined` Transport is safe here. If the test panics on undefined fields, initialize via `transport.Transport.initFlowControlForTest(&t)` first and set the two frame-size fields after.

- [ ] **Step 2: Run tests to verify failure**

Run: `zig build test`
Expected: FAIL — no field `peer_max_frame_size`.

- [ ] **Step 3: Implement the split**

In `src/transport.zig`:

(a) After the `max_frame_size` field (~line 311), update its doc-comment and add the new field:

```zig
    /// Largest frame length WE accept from the peer on inbound reads.
    /// This is OUR advertised SETTINGS_MAX_FRAME_SIZE and is never
    /// modified by peer SETTINGS — per RFC 7540 §6.5.2 the peer's value
    /// governs what the PEER accepts, not what we must accept.
    /// Closes NEW-2 (#44): previously the peer could raise this to
    /// 16 MiB and amplify per-frame allocations ~1000x.
    max_frame_size: u32 = DEFAULT_MAX_FRAME_SIZE,
    /// Largest frame length the PEER accepts (their advertised
    /// SETTINGS_MAX_FRAME_SIZE). Used only to size outbound DATA
    /// fragmentation in `writeDataFragmentedLocked`.
    peer_max_frame_size: u32 = DEFAULT_MAX_FRAME_SIZE,
```

(b) In `applyPeerSettings` (~:986-996), change the three assignments in the `SETTINGS_MAX_FRAME_SIZE` arm from `self.max_frame_size = ...` to `self.peer_max_frame_size = ...`.

(c) In `writeDataFragmentedLocked` (~:1106), change `const max: usize = @intCast(self.max_frame_size);` to `const max: usize = @intCast(self.peer_max_frame_size);`.

(d) `readFrame`'s check (`checkFrameSize(@intCast(length), self.max_frame_size)`) stays exactly as is — it now enforces a value the peer can no longer raise.

- [ ] **Step 4: Run tests**

Run: `zig fmt src/ && zig build test`
Expected: PASS. Also run the loopback smoke: `zig build loopback-test && timeout 60 ./zig-out/bin/grpc-loopback-test` — expected exit 0 (both sides advertise the default, so behavior is unchanged for well-behaved peers).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fix(transport): never let peer SETTINGS raise our inbound frame cap (closes #44; NEW-2)"
```

---

## Task 4: Cap inbound gRPC message assembly (NEW-1/#43 — High)

`readMessage` (`transport.zig:1183`) and `readStreamFrame` (`:1304`) accumulate DATA into `grpc_buf` with no upper bound; the declared `msg_len` (u32, attacker-controlled) is trusted. An unauthenticated peer declaring a 4 GiB message OOMs the server (auth runs only after `readMessage` returns).

**Files:**

- Modify: `src/transport.zig` (constant, field, error, checks in both read fns)
- Create: `src/transport_recv_limit_test.zig`
- Modify: `build.zig` (wire test)

- [ ] **Step 1: Write the failing test**

Create `src/transport_recv_limit_test.zig`:

```zig
const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

test "NEW-1: checkRecvMessageSize rejects msg_len above cap" {
    try testing.expectError(
        transport.TransportError.MessageTooLarge,
        transport.Transport.checkRecvMessageSize(
            transport.DEFAULT_MAX_RECV_MESSAGE_BYTES + 1,
            transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
        ),
    );
}

test "NEW-1: checkRecvMessageSize accepts msg_len at cap" {
    try transport.Transport.checkRecvMessageSize(
        transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
        transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
    );
}

test "NEW-1: default cap is 4 MiB (gRPC convention)" {
    try testing.expectEqual(@as(u32, 4 * 1024 * 1024), transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
}

test "NEW-1: cumulative buffer check rejects unbounded accumulation" {
    // Even before a complete 5-byte prefix is parseable, accumulated
    // bytes beyond cap+5 must be rejected.
    try testing.expectError(
        transport.TransportError.MessageTooLarge,
        transport.Transport.checkRecvBufferSize(
            @as(usize, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES) + 6,
            transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
        ),
    );
    try transport.Transport.checkRecvBufferSize(
        @as(usize, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES) + 5,
        transport.DEFAULT_MAX_RECV_MESSAGE_BYTES,
    );
}
```

Wire into `build.zig` following the same pattern as Task 2 (step name `"transport-recv-limit-tests"`), `test_step.dependOn(...)`.

- [ ] **Step 2: Run tests to verify failure**

Run: `zig build test`
Expected: FAIL — `MessageTooLarge`, `DEFAULT_MAX_RECV_MESSAGE_BYTES`, `checkRecvMessageSize`, `checkRecvBufferSize` undefined.

- [ ] **Step 3: Implement the cap**

In `src/transport.zig`:

(a) Add to `TransportError` (after `FrameSizeError`):

```zig
    /// Peer declared (or streamed) a gRPC message larger than
    /// `max_recv_message_bytes`. Rejected BEFORE buffering the payload
    /// to prevent an unauthenticated memory-exhaustion DoS (closes
    /// NEW-1 / #43).
    MessageTooLarge,
```

(b) Add module-level constant after `DEFAULT_MAX_FRAME_SIZE`:

```zig
/// Default cap on a single inbound gRPC message (the de-facto gRPC
/// default, e.g. grpc-go's MaxRecvMsgSize). Closes NEW-1 (#43).
pub const DEFAULT_MAX_RECV_MESSAGE_BYTES: u32 = 4 * 1024 * 1024;
```

(c) Add a Transport field after `max_frame_size`/`peer_max_frame_size`:

```zig
    /// Largest single gRPC message we will assemble from inbound DATA
    /// frames. Embedders may raise this per-transport before serving.
    max_recv_message_bytes: u32 = DEFAULT_MAX_RECV_MESSAGE_BYTES,
```

(d) Add pure check helpers inside `Transport` (next to `checkFrameSize`):

```zig
    /// Pure check: declared gRPC message length vs the configured cap.
    /// Public for unit tests (`transport_recv_limit_test.zig`).
    pub fn checkRecvMessageSize(msg_len: u32, max: u32) TransportError!void {
        if (msg_len > max) return TransportError.MessageTooLarge;
    }

    /// Pure check: cumulative assembly-buffer length (message + 5-byte
    /// prefix) vs the configured cap. Guards the case where a peer
    /// streams unbounded DATA without ever completing a message.
    pub fn checkRecvBufferSize(buf_len: usize, max: u32) TransportError!void {
        if (buf_len > @as(usize, max) + 5) return TransportError.MessageTooLarge;
    }
```

(e) In `readMessage`'s `.DATA` arm, right after `self.maybeRefillRecvWindow(frame.stream_id, data_len);` and before the `if (grpc_buf.items.len < 5) continue;` line, insert:

```zig
                    // NEW-1 (#43): bound the assembly buffer and the
                    // declared message length BEFORE buffering more.
                    // On violation, RST the stream and tear down — the
                    // peer is malicious or misconfigured.
                    Transport.checkRecvBufferSize(grpc_buf.items.len, self.max_recv_message_bytes) catch |err| {
                        self.writeRstStream(frame.stream_id, HTTP2_ERROR_FLOW_CONTROL_ERROR);
                        return err;
                    };
```

and right after the `const msg_len = prefix.msg_len;` line (from Task 2), insert:

```zig
                    Transport.checkRecvMessageSize(msg_len, self.max_recv_message_bytes) catch |err| {
                        self.writeRstStream(frame.stream_id, HTTP2_ERROR_FLOW_CONTROL_ERROR);
                        return err;
                    };
```

(f) Apply the identical two checks at the identical points in `readStreamFrame`'s `.DATA` arm.

(g) In `src/server.zig` `handleConnection`, the `readMessage() catch |err| switch (err)` arm list (~:241-254): add `error.MessageTooLarge => break,`? **No** — treat it as a real error so the connection tears down AND gets logged: add a dedicated arm:

```zig
                error.MessageTooLarge => {
                    std.log.warn("closing connection: inbound gRPC message exceeded max_recv_message_bytes", .{});
                    break;
                },
```

- [ ] **Step 4: Run tests**

Run: `zig fmt src/ && zig build test && zig build loopback-test && timeout 60 ./zig-out/bin/grpc-loopback-test`
Expected: all PASS (loopback messages are far below 4 MiB).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fix(transport): cap inbound gRPC message assembly at max_recv_message_bytes (closes #43; NEW-1 pre-auth memory DoS)"
```

---

## Task 5: Fix client-mux OOM deadlock + bound response accumulation (Q-R2/#57, NEW-1 client side)

In `readerLoop`'s `.DATA` arm (`client_mux.zig:252-280`), an `appendSlice` failure sets `slot.err` but `broadcast()` only fires in the separate `if (end)` branch — when OOM hits a non-terminal DATA frame, the caller in `callWithMetadata` (`:225`) waits forever on `while (!slot.end_stream)`. Also `slot.data` grows without bound across a streaming response.

**Files:**

- Modify: `src/client_mux.zig` (extract testable `deliverData`, fix broadcast, add cap)
- Create: `src/client_mux_test.zig`
- Modify: `build.zig` (wire test)

- [ ] **Step 1: Write the failing tests**

Create `src/client_mux_test.zig`:

```zig
const std = @import("std");
const testing = std.testing;
const client_mux = @import("client_mux.zig");
const transport = @import("transport.zig");

// deliverData is the pure-ish core of readerLoop's DATA handling:
// it appends a validated gRPC message into the slot and ALWAYS
// signals end_stream (with err set) on any failure so the waiting
// caller can never deadlock (closes quality R2 / #57).

test "R2: allocation failure sets err AND end_stream (no deadlock)" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);

    // gRPC frame: prefix(5) + payload "hi"
    const payload = [_]u8{ 0, 0, 0, 0, 2, 'h', 'i' };
    client_mux.deliverData(&slot, failing.allocator(), &payload, false, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);

    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream); // MUST be set or the caller hangs
}

test "deliverData appends message bytes on success" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    const payload = [_]u8{ 0, 0, 0, 0, 2, 'h', 'i' };
    client_mux.deliverData(&slot, testing.allocator, &payload, true, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
    try testing.expect(slot.err == null);
    try testing.expect(slot.end_stream);
    try testing.expectEqualSlices(u8, "hi", slot.data.items);
}

test "deliverData rejects invalid gRPC prefix (I6)" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    const payload = [_]u8{ 0xFF, 0, 0, 0, 1, 'x' };
    client_mux.deliverData(&slot, testing.allocator, &payload, false, transport.DEFAULT_MAX_RECV_MESSAGE_BYTES);
    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream);
}

test "NEW-1 client side: accumulated response beyond cap errors out" {
    var slot: client_mux.StreamSlot = .{};
    defer slot.deinit(testing.allocator);
    // Cap of 4 bytes; deliver a 3-byte message twice -> second must fail.
    const payload = [_]u8{ 0, 0, 0, 0, 3, 'a', 'b', 'c' };
    client_mux.deliverData(&slot, testing.allocator, &payload, false, 4);
    try testing.expect(slot.err == null);
    client_mux.deliverData(&slot, testing.allocator, &payload, false, 4);
    try testing.expect(slot.err != null);
    try testing.expect(slot.end_stream);
}
```

NOTE: these tests do not touch `slot.mutex`/`slot.cond` (no `std.Io` available in unit tests) — `deliverData` must therefore take the LOCKED slot and NOT do its own locking/signaling of the condition variable; the caller (readerLoop) holds the mutex and broadcasts after. The "MUST be set" assertion is on `end_stream`, which is what the waiter's predicate checks. Wire the test file into `build.zig` (step name `"client-mux-tests"`).

- [ ] **Step 2: Run tests to verify failure**

Run: `zig build test`
Expected: FAIL — `client_mux` has no public `StreamSlot`/`deliverData`.

- [ ] **Step 3: Implement deliverData and rewire readerLoop**

In `src/client_mux.zig`:

(a) Make `StreamSlot` public: change `const StreamSlot = struct {` to `pub const StreamSlot = struct {`.

(b) Add after the `StreamSlot` definition:

```zig
/// Core of readerLoop's DATA handling, extracted for unit testing
/// (closes quality R2 / #57). Caller MUST hold `slot.mutex` and is
/// responsible for `slot.cond.broadcast` after this returns whenever
/// `slot.end_stream` is true.
///
/// Invariant: on ANY failure (bad prefix, over-cap, OOM) this sets
/// BOTH `slot.err` and `slot.end_stream` — never just `err` — so the
/// caller blocked on `while (!slot.end_stream)` always wakes.
pub fn deliverData(
    slot: *StreamSlot,
    allocator: Allocator,
    payload: []const u8,
    end: bool,
    max_recv_message_bytes: u32,
) void {
    if (payload.len >= 5) {
        if (transport.decodeGrpcPrefix(payload)) |prefix| {
            const msg_len = prefix.msg_len;
            const over_cap = msg_len > max_recv_message_bytes or
                slot.data.items.len + msg_len > max_recv_message_bytes;
            if (over_cap) {
                slot.err = transport.TransportError.MessageTooLarge;
                slot.end_stream = true;
                return;
            }
            if (payload.len >= 5 + msg_len) {
                slot.data.appendSlice(allocator, payload[5 .. 5 + msg_len]) catch |e| {
                    slot.err = e;
                    slot.end_stream = true;
                    return;
                };
            }
        } else |e| {
            slot.err = e;
            slot.end_stream = true;
            return;
        }
    }
    if (end) slot.end_stream = true;
}
```

(c) Rewrite `readerLoop`'s `.DATA` arm to use it:

```zig
            .DATA => {
                const end = (flags & FF.END_STREAM) != 0;
                const data_len: u32 = @intCast(payload.len);
                if (self.findStream(sid)) |slot| {
                    slot.mutex.lockUncancelable(self.io);
                    deliverData(slot, self.allocator, payload, end, self.transport.max_recv_message_bytes);
                    if (slot.end_stream) slot.cond.broadcast(self.io);
                    slot.mutex.unlock(self.io);
                }
                self.allocator.free(payload);
                self.transport.maybeRefillRecvWindow(sid, data_len);
            },
```

(keep the existing comment about refilling the receive window above the `maybeRefillRecvWindow` call).

- [ ] **Step 4: Run tests**

Run: `zig fmt src/ build.zig && zig build test`
Expected: PASS, including the four new client-mux tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fix(client_mux): always signal end_stream on delivery failure; cap response accumulation (closes #57; R2, NEW-1 client side)"
```

---

## Task 6: Detect stream-id wraparound in ClientMux (M2-sec/#51)

`allocStreamId` (`client_mux.zig:117-123`) does `self.next_stream_id +%= 2`, silently wrapping after ~2^30 calls and colliding with live stream ids.

**Files:**

- Modify: `src/client_mux.zig` (`allocStreamId` + its one caller in `callWithMetadata`)
- Modify: `src/client_mux_test.zig`

- [ ] **Step 1: Write the failing test**

Append to `src/client_mux_test.zig` — `allocStreamId` needs a ClientMux (socket); instead extract the arithmetic as a pure function and test that:

```zig
test "M2: nextStreamId detects u31 wraparound" {
    try testing.expectEqual(@as(u31, 5), try client_mux.nextStreamId(3));
    const last_odd: u31 = std.math.maxInt(u31); // 0x7FFFFFFF, odd
    try testing.expectError(error.StreamIdExhausted, client_mux.nextStreamId(last_odd));
    try testing.expectError(error.StreamIdExhausted, client_mux.nextStreamId(last_odd - 1));
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `zig build test`
Expected: FAIL — no `nextStreamId`.

- [ ] **Step 3: Implement**

In `src/client_mux.zig`, add above `ClientMux`:

```zig
/// Compute the successor of a client-initiated stream id (odd,
/// monotonically increasing per RFC 7540 §5.1.1). Returns
/// `error.StreamIdExhausted` instead of wrapping — a wrapped id would
/// collide with a live stream in `streams` and corrupt demux
/// (closes security M2 / #51). Callers should open a fresh connection.
pub fn nextStreamId(current: u31) error{StreamIdExhausted}!u31 {
    if (current > std.math.maxInt(u31) - 2) return error.StreamIdExhausted;
    return current + 2;
}
```

Change `allocStreamId` to:

```zig
    fn allocStreamId(self: *ClientMux) error{StreamIdExhausted}!u31 {
        self.streams_mutex.lockUncancelable(self.io);
        defer self.streams_mutex.unlock(self.io);
        const sid = self.next_stream_id;
        self.next_stream_id = try nextStreamId(sid);
        return sid;
    }
```

And the caller in `callWithMetadata` (~:212): `const sid = self.allocStreamId();` → `const sid = try self.allocStreamId();`.

- [ ] **Step 4: Run tests**

Run: `zig fmt src/ && zig build test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fix(client_mux): error on stream-id exhaustion instead of wrapping (closes #51; M2)"
```

---

## Task 7: Handle CONTINUATION frames per RFC 7540 §6.10 (I5/#48)

HEADERS without END_HEADERS followed by CONTINUATION frames is currently mishandled: CONTINUATION falls into the `else → free + skip` arm in `readMessage`/`readStreamFrame`, silently dropping header bytes. Fix: reassemble bounded header blocks; reject protocol violations with GOAWAY(PROTOCOL_ERROR).

**Files:**

- Modify: `src/transport.zig` (new `collectHeaderBlock` helper + HEADERS/CONTINUATION arms in `readMessage` and `readStreamFrame`; GOAWAY helper generalization)
- Modify: `src/client_mux.zig` (readerLoop: treat unexpected CONTINUATION as fatal)
- Create: `src/transport_continuation_test.zig`
- Modify: `build.zig` (wire test)

- [ ] **Step 1: Generalize the GOAWAY builder**

In `src/transport.zig`, `buildGoawayFrameSizeError` (~:735) hardcodes the error code. Replace it with a parameterized version and keep a thin wrapper for the existing test surface:

```zig
    /// Build the bytes for a connection-level GOAWAY frame with the
    /// given HTTP/2 error code. Caller owns the returned slice.
    pub fn buildGoawayFrame(allocator: std.mem.Allocator, last_stream_id: u31, error_code: u32) ![]u8 {
        const payload_len: u32 = 8;
        var bytes = try allocator.alloc(u8, 9 + payload_len);
        errdefer allocator.free(bytes);
        bytes[0] = @intCast((payload_len >> 16) & 0xFF);
        bytes[1] = @intCast((payload_len >> 8) & 0xFF);
        bytes[2] = @intCast(payload_len & 0xFF);
        bytes[3] = @intFromEnum(http2.frame.FrameType.GOAWAY);
        bytes[4] = 0;
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = 0;
        bytes[8] = 0;
        const lsid: u32 = @intCast(last_stream_id);
        bytes[9] = @intCast((lsid >> 24) & 0x7F);
        bytes[10] = @intCast((lsid >> 16) & 0xFF);
        bytes[11] = @intCast((lsid >> 8) & 0xFF);
        bytes[12] = @intCast(lsid & 0xFF);
        bytes[13] = @intCast((error_code >> 24) & 0xFF);
        bytes[14] = @intCast((error_code >> 16) & 0xFF);
        bytes[15] = @intCast((error_code >> 8) & 0xFF);
        bytes[16] = @intCast(error_code & 0xFF);
        return bytes;
    }

    /// Back-compat wrapper used by `transport_max_frame_size_test.zig`.
    pub fn buildGoawayFrameSizeError(allocator: std.mem.Allocator, last_stream_id: u31) ![]u8 {
        return buildGoawayFrame(allocator, last_stream_id, HTTP2_ERROR_FRAME_SIZE_ERROR);
    }
```

Add a sibling of `emitGoawayFrameSizeError`:

```zig
    /// Send a GOAWAY with PROTOCOL_ERROR. Best-effort (see
    /// emitGoawayFrameSizeError).
    fn emitGoawayProtocolError(self: *Transport) void {
        const bytes = buildGoawayFrame(self.allocator, self.last_stream_id, HTTP2_ERROR_PROTOCOL_ERROR) catch return;
        defer self.allocator.free(bytes);
        _ = self.ioWrite(bytes) catch {};
    }
```

- [ ] **Step 2: Write the failing tests**

Create `src/transport_continuation_test.zig`. The reassembly core must be a pure function so it's testable without a socket; test that contract:

```zig
const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

// appendHeaderFragment(buf, allocator, fragment, max_len) appends a
// HEADERS/CONTINUATION fragment to the reassembly buffer, enforcing
// the bound. Closes I5 (#48).

test "I5: header fragments accumulate up to the bound" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "abc", 8);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "defgh", 8);
    try testing.expectEqualSlices(u8, "abcdefgh", buf.items);
}

test "I5: over-bound header block is a protocol error" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try transport.Transport.appendHeaderFragment(&buf, testing.allocator, "abcd", 8);
    try testing.expectError(
        transport.TransportError.HeaderBlockTooLarge,
        transport.Transport.appendHeaderFragment(&buf, testing.allocator, "efghi", 8),
    );
}

test "I5: MAX_HEADER_BLOCK_BYTES matches advertised MAX_HEADER_LIST_SIZE" {
    try testing.expectEqual(@as(usize, 8192), transport.MAX_HEADER_BLOCK_BYTES);
}
```

Wire into `build.zig` (step name `"transport-continuation-tests"`).

- [ ] **Step 3: Run tests to verify failure**

Run: `zig build test`
Expected: FAIL — `appendHeaderFragment`, `HeaderBlockTooLarge`, `MAX_HEADER_BLOCK_BYTES` undefined.

- [ ] **Step 4: Implement reassembly**

In `src/transport.zig`:

(a) Add to `TransportError`:

```zig
    /// A header block (HEADERS + CONTINUATION fragments) exceeded
    /// MAX_HEADER_BLOCK_BYTES, or CONTINUATION sequencing violated
    /// RFC 7540 §6.10. Closes I5 (#48).
    HeaderBlockTooLarge,
    ProtocolError,
```

(NOTE: if `error.ProtocolError` already conflicts with the standalone `error{ProtocolError}` sets used by `applyWindowUpdate`, that's fine — Zig merges identically-named errors.)

(b) Add module-level constant after `DEFAULT_MAX_RECV_MESSAGE_BYTES`:

```zig
/// Cap on a reassembled header block (HEADERS + CONTINUATIONs). Matches
/// the SETTINGS_MAX_HEADER_LIST_SIZE we advertise (8192) — peers that
/// honour our SETTINGS never hit this.
pub const MAX_HEADER_BLOCK_BYTES: usize = 8192;
```

(c) Add inside `Transport` (near `checkFrameSize`):

```zig
    /// Append one HEADERS/CONTINUATION fragment to a reassembly buffer,
    /// enforcing MAX_HEADER_BLOCK_BYTES (or a caller-supplied bound for
    /// tests). Public for unit tests.
    pub fn appendHeaderFragment(
        buf: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        fragment: []const u8,
        max_len: usize,
    ) (TransportError || error{OutOfMemory})!void {
        if (buf.items.len + fragment.len > max_len) return TransportError.HeaderBlockTooLarge;
        try buf.appendSlice(allocator, fragment);
    }

    /// Reassemble a complete header block starting from a HEADERS frame
    /// that did NOT carry END_HEADERS: read CONTINUATION frames (which
    /// MUST be contiguous and on the same stream — RFC 7540 §6.10) until
    /// one carries END_HEADERS. Returns the owned, assembled block
    /// (caller frees). `first_payload` is consumed (appended, not freed —
    /// caller still owns/frees it as before).
    fn collectContinuations(self: *Transport, stream_id: u31, first_payload: []const u8) ![]u8 {
        var block: std.ArrayList(u8) = .empty;
        errdefer block.deinit(self.allocator);
        try appendHeaderFragment(&block, self.allocator, first_payload, MAX_HEADER_BLOCK_BYTES);
        while (true) {
            const cont = try self.readFrame();
            const is_continuation = cont.frame_type == @intFromEnum(http2.frame.FrameType.CONTINUATION);
            const same_stream = cont.stream_id == stream_id;
            if (!is_continuation or !same_stream) {
                // §6.10: anything other than a CONTINUATION on the same
                // stream is a connection error of type PROTOCOL_ERROR.
                self.allocator.free(cont.payload);
                self.emitGoawayProtocolError();
                return TransportError.ProtocolError;
            }
            const end_headers = (cont.flags & http2.frame.FrameFlags.END_HEADERS) != 0;
            appendHeaderFragment(&block, self.allocator, cont.payload, MAX_HEADER_BLOCK_BYTES) catch |err| {
                self.allocator.free(cont.payload);
                self.emitGoawayProtocolError();
                return err;
            };
            self.allocator.free(cont.payload);
            if (end_headers) break;
        }
        return block.toOwnedSlice(self.allocator);
    }
```

(d) In `readMessage`'s `.HEADERS` arm (~:1220-1229), replace the body with END_HEADERS awareness:

```zig
                @intFromEnum(http2.frame.FrameType.HEADERS) => {
                    // Standard gRPC sends HEADERS before DATA. Remember the
                    // stream ID so we can respond on the same stream.
                    self.last_stream_id = frame.stream_id;
                    const end_headers = (frame.flags & http2.frame.FrameFlags.END_HEADERS) != 0;
                    if (end_headers) {
                        self.extractPathFromHpack(payload);
                        self.allocator.free(payload);
                    } else {
                        // I5 (#48): reassemble CONTINUATION fragments.
                        const block = self.collectContinuations(frame.stream_id, payload) catch |err| {
                            self.allocator.free(payload);
                            return err;
                        };
                        self.allocator.free(payload);
                        self.extractPathFromHpack(block);
                        self.allocator.free(block);
                    }
                    continue;
                },
```

(e) Add an explicit CONTINUATION arm before the `else` in `readMessage`'s switch:

```zig
                @intFromEnum(http2.frame.FrameType.CONTINUATION) => {
                    // §6.10: CONTINUATION without a preceding open header
                    // block is a connection error (PROTOCOL_ERROR). The
                    // in-block case is consumed by collectContinuations.
                    self.allocator.free(payload);
                    self.emitGoawayProtocolError();
                    return TransportError.ProtocolError;
                },
```

(f) Apply (d)-style and (e)-style changes identically in `readStreamFrame` — its `.HEADERS` arm additionally checks END_STREAM; preserve that logic exactly:

```zig
                @intFromEnum(http2.frame.FrameType.HEADERS) => {
                    const end = (flags & http2.frame.FrameFlags.END_STREAM) != 0;
                    self.last_stream_id = frame.stream_id;
                    const end_headers = (flags & http2.frame.FrameFlags.END_HEADERS) != 0;
                    if (end_headers) {
                        self.extractPathFromHpack(payload);
                        self.allocator.free(payload);
                    } else {
                        const block = self.collectContinuations(frame.stream_id, payload) catch |err| {
                            self.allocator.free(payload);
                            return err;
                        };
                        self.allocator.free(payload);
                        self.extractPathFromHpack(block);
                        self.allocator.free(block);
                    }
                    if (end) return .{ .data = null, .end_stream = true };
                    continue;
                },
```

(g) In `src/server.zig`'s `handleConnection` error switch, add graceful teardown arms:

```zig
                error.ProtocolError, error.HeaderBlockTooLarge => {
                    std.log.warn("closing connection: HTTP/2 protocol violation in header block", .{});
                    break;
                },
```

(h) In `src/client_mux.zig` `readerLoop`, add an explicit arm before `else`:

```zig
            .CONTINUATION => {
                // We never expect fragmented response headers from the
                // small trailer sets gRPC servers emit; treat as fatal
                // rather than silently dropping header bytes (I5/#48).
                self.allocator.free(payload);
                self.broadcastError(error.ProtocolError);
                return;
            },
```

- [ ] **Step 5: Run tests + h2spec sanity**

Run: `zig fmt src/ build.zig && zig build test && zig build loopback-test && timeout 60 ./zig-out/bin/grpc-loopback-test`
Expected: PASS.
If `h2spec` is installed locally (`command -v h2spec`), also run the interop server + `h2spec http2 -p <port>` per `.gitlab-ci.yml`'s interop-h2spec job; otherwise note in the task report that CI's h2spec gate will verify §6.10 conformance.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "fix(transport): reassemble CONTINUATION header blocks; reject §6.10 violations with PROTOCOL_ERROR (closes #48; I5)"
```

---

## Task 8: Complete the HPACK Huffman decoder + HPACK unit tests (I2/#47, T1/#63)

The Huffman table (`transport.zig:1442-1454`) covers only printable ASCII groups (≤19 bits); `huffmanDecode` (`:1458-1493`) silently truncates on unmapped symbols and never validates EOS/padding. Complete the table per RFC 7541 Appendix B, make decode failures explicit, and add the missing HPACK unit tests.

**Files:**

- Modify: `src/transport.zig` (full `huff_groups` table; `huffmanDecode` → error-returning; the two call sites)
- Create: `src/hpack_decode_test.zig`
- Modify: `build.zig` (wire test)

- [ ] **Step 1: Obtain the authoritative table**

Fetch RFC 7541 Appendix B (e.g. `curl -s https://www.rfc-editor.org/rfc/rfc7541.txt` or use the local copy if the network is unavailable — the table is also embedded in many local sources; `grep -r "ffffea" /usr/include 2>/dev/null` style shortcuts are unreliable, prefer the RFC text). Transcribe ALL 256 symbol codes plus EOS (code 0x3fffffff, 30 bits) into the existing `HuffGroup` group format: for each bit-length present in the table, one group `{ .bits = N, .first_code = <code of first symbol at N bits>, .syms = &[_]u8{ <symbols in code order> } }`. The existing 11 groups for printable ASCII are correct and stay; ADD the missing groups (bit lengths 19-28 covering control chars and high bytes — note 19 bits already has a partial group; extend it with the additional 19-bit symbols in code order). The §C test vectors in Step 2 are the correctness oracle: if any group is mistranscribed, those tests fail.

- [ ] **Step 2: Write the failing tests**

Create `src/hpack_decode_test.zig`:

```zig
const std = @import("std");
const testing = std.testing;
const transport = @import("transport.zig");

// RFC 7541 §C.4 request examples — Huffman-coded literal values.

test "RFC 7541 C.4.1: huffman 'www.example.com'" {
    // f1e3 c2e5 f23a 6ba0 ab90 f4ff
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "www.example.com", out[0..n]);
}

test "RFC 7541 C.4.2: huffman 'no-cache'" {
    // a8eb 1064 9cbf
    const encoded = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "no-cache", out[0..n]);
}

test "RFC 7541 C.6.1: huffman 'Mon, 21 Oct 2013 20:13:21 GMT'" {
    // d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff
    const encoded = [_]u8{
        0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95,
        0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff,
    };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "Mon, 21 Oct 2013 20:13:21 GMT", out[0..n]);
}

test "RFC 7541 C.6.1: huffman 'https://www.example.com'" {
    // 9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3
    const encoded = [_]u8{
        0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9,
        0xae, 0x82, 0xae, 0x43, 0xd3,
    };
    var out: [64]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "https://www.example.com", out[0..n]);
}

test "I2: EOS symbol in body is a decode error" {
    // 30 one-bits = the EOS code with 2 trailing padding bits; a peer
    // MUST NOT encode EOS in the body (RFC 7541 §5.2).
    const encoded = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    var out: [16]u8 = undefined;
    try testing.expectError(
        transport.TransportError.HuffmanDecodeError,
        transport.Transport.huffmanDecodeChecked(&encoded, &out),
    );
}

test "I2: valid padding (all-ones partial byte) is accepted" {
    // 'o' = 0x07 @5 bits -> byte 0b00111_111 with 3 bits of EOS-prefix padding.
    const encoded = [_]u8{0x3f};
    var out: [4]u8 = undefined;
    const n = try transport.Transport.huffmanDecodeChecked(&encoded, &out);
    try testing.expectEqualSlices(u8, "o", out[0..n]);
}

test "T1: hpack dynamic table push/get roundtrip" {
    var t: transport.Transport = undefined;
    t.hpack_dyn_count = 0;
    t.hpack_dyn_head = 0;
    t.hpack_dyn = [_]transport.Transport.HpackDynEntryForTest{.{}} ** 128;
    t.last_method = .{0} ** 256;
    @memcpy(t.last_method[0..5], "/a.B/");
    t.last_method_len = 5;
    t.hpackDynPushForTest(true);
    const e = t.hpackDynGetForTest(0).?;
    try testing.expect(e.is_path);
    try testing.expectEqualSlices(u8, "/a.B/", e.path[0..e.path_len]);
}
```

NOTE on the last test: `hpackDynPush`/`hpackDynGet`/`HpackDynEntry` are private. Expose minimal public test shims in `Transport`:

```zig
    /// Test-only aliases for the private dynamic-table internals
    /// (T1 / #63). Do not use outside tests.
    pub const HpackDynEntryForTest = HpackDynEntry;
    pub fn hpackDynPushForTest(self: *Transport, is_path: bool) void {
        self.hpackDynPush(is_path);
    }
    pub fn hpackDynGetForTest(self: *Transport, dyn_idx: usize) ?*const HpackDynEntry {
        return self.hpackDynGet(dyn_idx);
    }
```

(`HpackDynEntry` is declared at module scope, so the test can also spell it via the alias.) Wire the test file into `build.zig` (step name `"hpack-decode-tests"`).

- [ ] **Step 3: Run tests to verify failure**

Run: `zig build test`
Expected: FAIL — `huffmanDecodeChecked` undefined (and likely C.6.1 vectors would fail on the old table anyway).

- [ ] **Step 4: Implement the complete decoder**

In `src/transport.zig`:

(a) Add to `TransportError`:

```zig
    /// Huffman-coded HPACK string contained the EOS symbol, an
    /// unmapped code, or invalid padding (RFC 7541 §5.2). Closes I2.
    HuffmanDecodeError,
```

(b) Extend `huff_groups` with the missing Appendix B groups (transcribed in Step 1). Keep the existing groups; the complete set covers bit lengths {5,6,7,8,10,11,12,13,14,15,19,20,21,22,23,24,25,26,27,28} (EOS at 30 bits is handled as an error, not a table entry). The 19-bit group gains the control-char symbols that share that length with `\\` and `{` — order all symbols within a group by ascending code.

(c) Replace `huffmanDecode` with a checked version + compatibility behavior at call sites:

```zig
    /// Decode an RFC 7541 Huffman-coded byte string. Returns the number
    /// of decoded bytes written to `out`, or HuffmanDecodeError when the
    /// input contains EOS, an unmapped code, or invalid padding (must be
    /// the most-significant bits of EOS, i.e. all ones, and shorter than
    /// 8 bits). Public for unit tests. Closes I2 (#47).
    pub fn huffmanDecodeChecked(encoded: []const u8, out: []u8) TransportError!usize {
        var out_pos: usize = 0;
        var acc: u32 = 0;
        var acc_bits: u8 = 0;

        for (encoded) |byte| {
            var b: u8 = byte;
            var bit_i: u4 = 0;
            while (bit_i < 8) : (bit_i += 1) {
                acc = (acc << 1) | ((b >> 7) & 1);
                acc_bits += 1;
                b <<= 1;

                var matched = false;
                for (huff_groups) |grp| {
                    if (acc_bits == grp.bits) {
                        if (acc >= grp.first_code and acc < grp.first_code + grp.syms.len) {
                            if (out_pos < out.len) {
                                out[out_pos] = grp.syms[acc - grp.first_code];
                                out_pos += 1;
                            } else {
                                // Output truncation is a decode error,
                                // not silent data loss.
                                return TransportError.HuffmanDecodeError;
                            }
                            acc = 0;
                            acc_bits = 0;
                            matched = true;
                            break;
                        }
                    }
                }
                _ = matched;

                // 30 bits with no match means the EOS code or garbage.
                if (acc_bits >= 30) return TransportError.HuffmanDecodeError;
            }
        }
        // §5.2: leftover bits must be < 8 and all ones (EOS prefix).
        if (acc_bits >= 8) return TransportError.HuffmanDecodeError;
        if (acc_bits > 0) {
            const ones: u32 = (@as(u32, 1) << @as(u5, @intCast(acc_bits))) - 1;
            if (acc != ones) return TransportError.HuffmanDecodeError;
        }
        return out_pos;
    }
```

Delete the old `huffmanDecode`.

(d) Update the two call sites to fail closed (empty value) on decode error:

In `setPathFromHpackString` (~:1714-1717):

```zig
        } else {
            // Huffman encoded — decode using the full RFC 7541 table.
            // On decode error leave the method empty: the dispatcher
            // then returns UNIMPLEMENTED rather than acting on a
            // truncated path (fail closed — I2).
            self.last_method_len = huffmanDecodeChecked(str_bytes, &self.last_method) catch 0;
        }
```

In `setAuthorizationFromHpackString` (~:1735-1737):

```zig
        } else {
            // Fail closed: an undecodable authorization is treated as
            // absent and rejected by the auth gate (I2).
            self.last_authorization_len = huffmanDecodeChecked(str_bytes, &self.last_authorization) catch 0;
        }
```

- [ ] **Step 5: Run tests**

Run: `zig fmt src/ build.zig && zig build test`
Expected: PASS — every §C vector decodes exactly. If a vector fails, the table transcription is wrong: decode the failing vector by hand against the RFC table and fix the group.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "fix(transport): complete RFC 7541 Huffman table with EOS/padding validation; add HPACK unit tests (closes #47, #63; I2, T1)"
```

---

## Task 9: Secure server defaults + socket options + error visibility (O1/#53, NW-5/#32, R3/#58, R4/#59)

**Files:**

- Modify: `src/server.zig` (bind address param/env, error counter, TLS-error logging, TCP_NODELAY)
- Modify: `src/client.zig`, `src/client_mux.zig` (TCP_NODELAY on connect)
- Modify: `src/admission_control_test.zig` (bind-address parse tests — read it first and follow its existing test style)
- Modify: `examples/basic_server.zig` ONLY IF its init call breaks (it shouldn't — `init` keeps its signature)

- [ ] **Step 1: Write the failing tests**

Append to `src/admission_control_test.zig` (it already tests `GrpcServer` env parsing — match its imports):

```zig
test "O1: default bind address is loopback" {
    try std.testing.expectEqualStrings("127.0.0.1", server_mod.GrpcServer.DEFAULT_BIND_ADDRESS);
}

test "O1: bindAddressFromEnv falls back to default" {
    // GRPC_ZIG_BIND_ADDR unset in the test environment.
    const addr = server_mod.GrpcServer.bindAddressFromEnv();
    try std.testing.expectEqualStrings("127.0.0.1", addr);
}
```

(`server_mod` = whatever alias the file already uses for `@import("server.zig")` — read the file and reuse it.)

- [ ] **Step 2: Run tests to verify failure**

Run: `zig build test`
Expected: FAIL — `DEFAULT_BIND_ADDRESS` undefined.

- [ ] **Step 3: Implement bind-address control**

In `src/server.zig`:

(a) Add near `DEFAULT_MAX_CONNS`:

```zig
    /// Default bind interface. Loopback-by-default (closes O1 / #53):
    /// binding every interface in cleartext h2c was a hostile-network
    /// footgun. Opt into public binds explicitly via `initWithBind`
    /// or the `GRPC_ZIG_BIND_ADDR` env var (e.g. "0.0.0.0").
    pub const DEFAULT_BIND_ADDRESS: []const u8 = "127.0.0.1";

    /// Read GRPC_ZIG_BIND_ADDR via libc getenv (same rationale as
    /// maxConnsFromEnv); falls back to DEFAULT_BIND_ADDRESS.
    pub fn bindAddressFromEnv() []const u8 {
        const raw_ptr = std.c.getenv("GRPC_ZIG_BIND_ADDR") orelse return DEFAULT_BIND_ADDRESS;
        const raw = std.mem.span(raw_ptr);
        if (raw.len == 0) return DEFAULT_BIND_ADDRESS;
        return raw;
    }
```

(b) Change `init` to use it and add an explicit-bind variant:

```zig
    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16, secret_key: []const u8) !GrpcServer {
        return initWithBind(allocator, io, bindAddressFromEnv(), port, secret_key);
    }

    /// Like `init` but binds the given interface (e.g. "0.0.0.0" for
    /// a deliberate public bind). Closes O1 (#53).
    pub fn initWithBind(allocator: std.mem.Allocator, io: std.Io, bind_address: []const u8, port: u16, secret_key: []const u8) !GrpcServer {
        const address = try net.IpAddress.parseIp4(bind_address, port);
        // ... (move the entire existing init body here, replacing the
        //      hardcoded "0.0.0.0" parseIp4 line with the one above)
    }
```

(c) Check every in-repo caller still works: `grep -rn "GrpcServer.init\|\.init(" examples/ integration_test/ interop/zig/ src/loopback_main.zig src/dispatch_test_main.zig src/auth_gate_test_main.zig src/handler_error_test_main.zig | grep -i server`. Callers connect to `localhost`/`127.0.0.1`, so the loopback default is compatible. The interop scripts (`interop/scripts/run-pair.sh`) and CI run client+server on the same host — verify with `grep -n "host\|addr" interop/scripts/*.sh integration_test/run_tests.sh`. If any harness connects to a non-loopback address of the same host, set `GRPC_ZIG_BIND_ADDR=0.0.0.0` in that harness script rather than reverting the default.

- [ ] **Step 4: Add TCP_NODELAY + SO_KEEPALIVE (NW-5/#32)**

In `src/server.zig` `start()`, right after `const stream_ = try self.server.accept(self.io);`:

```zig
            // NW-5 (#32): disable Nagle for RPC latency; enable
            // keepalive so dead peers are eventually reaped.
            setRpcSocketOptions(stream_.socket.handle);
```

Add the helper (module level, in server.zig):

```zig
/// Best-effort socket tuning for RPC traffic (TCP_NODELAY +
/// SO_KEEPALIVE). Failures are ignored: these are optimizations, not
/// correctness requirements, and not every platform/socket supports
/// them. Closes NW-5 (#32).
pub fn setRpcSocketOptions(handle: anytype) void {
    const one = std.mem.toBytes(@as(c_int, 1));
    std.posix.setsockopt(handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, &one) catch {};
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, &one) catch {};
}
```

(If `std.posix.TCP.NODELAY` doesn't exist under that name in Zig 0.16, find the right one: `grep -rn "NODELAY" "$(dirname "$(which zig)")/lib/std/"` — it is `std.posix.TCP.NODELAY` or `std.os.linux.TCP.NODELAY`; use whichever compiles for the POSIX path. If Windows compilation of this call is a problem, guard with `if (@import("builtin").os.tag != .windows)`.)

In `src/client.zig` `init` after `const connection = try address.connect(...)`, and in `src/client_mux.zig` `init` after `const conn = try address.connect(...)`:

```zig
        @import("server.zig").setRpcSocketOptions(connection.socket.handle);
```

WAIT — `client.zig` importing `server.zig` would be an ugly dependency. Instead put `setRpcSocketOptions` in `src/transport.zig` (module level, exported `pub`), and have server.zig/client.zig/client_mux.zig all call `transport.setRpcSocketOptions(...)`. transport.zig is already imported by all three.

- [ ] **Step 5: Error visibility (R3/#58, R4/#59)**

In `src/server.zig`:

(a) Add a counter field to `GrpcServer` (after `flow_credit_timeout_ns`):

```zig
    /// Monotonic count of connections that terminated with an error
    /// (anything other than clean peer disconnect). Exposed so
    /// embedders can alert on error spikes without an otel build
    /// (closes quality R3 / #58).
    conn_error_count: std.atomic.Value(u64) = .init(0),
```

with a getter:

```zig
    /// Read the connection-error counter (R3 / #58).
    pub fn connErrorCount(self: *const GrpcServer) u64 {
        return self.conn_error_count.load(.monotonic);
    }
```

(b) In `connectionThread`, bump it:

```zig
    fn connectionThread(self: *GrpcServer, stream_: net.Stream) void {
        defer self.conn_sem.post(self.io);
        self.handleConnection(stream_) catch |err| {
            _ = self.conn_error_count.fetchAdd(1, .monotonic);
            std.log.err("Connection handling failed: {}", .{err});
        };
    }
```

(c) R4: in `handleConnection`'s read-error switch, the TLS arm currently `=> break,` silently. Change to:

```zig
                error.TlsReadFailed,
                error.TlsWriteFailed,
                error.TlsHandshakeFailed,
                error.TlsNotInitialized,
                => {
                    // R4 (#59): TLS failures are worth a log line — they
                    // can indicate misconfigured certs or active MitM,
                    // not just a vanished peer.
                    std.log.warn("TLS connection error; closing: {}", .{err});
                    break;
                },
```

NOTE: the `err` capture is already in scope from `catch |err| switch (err)`.

- [ ] **Step 6: Run tests**

Run: `zig fmt src/ && zig build check && zig build test && zig build loopback-test && timeout 60 ./zig-out/bin/grpc-loopback-test`
Expected: all PASS (loopback connects to 127.0.0.1, so the new default is exercised end-to-end).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "fix(server): loopback-by-default bind, TCP_NODELAY/keepalive, error counter, TLS error logging (closes #53, #32, #58, #59)"
```

---

## Task 10: Benchmark harness fixes (A5/#46, BH-1/#22, BH-4/#23, BH-5/#42, AG-5/#41)

Four independent benchmark defects plus a transport cleanup: hardcoded secret default, sequential "concurrent" workers, JSON on stderr, usage text without newlines, and redundant `last_method` re-initialization in the three Transport init paths.

**Files:**

- Modify: `src/benchmark.zig`
- Modify: `src/transport.zig` (AG-5: delete `.last_method = .{0} ** 256, .last_method_len = 0,` from the struct literals in `initClient` (~:389-390), `initServer` (~:413-414), `initServerTls` (~:438-439) — the field defaults already zero them)
- Modify: `scripts/run_benchmark.sh` and `build.zig` benchmark step IF they pass a secret (check with `grep -n secret scripts/run_benchmark.sh build.zig`)

- [ ] **Step 1: Remove the hardcoded secret (A5/#46)**

In `src/benchmark.zig`:

(a) `BenchmarkConfig.secret_key` becomes optional with no default:

```zig
    secret_key: ?[]const u8 = null,
```

(b) In `ClientWorker.runBenchmark`, replace `try client.setAuth(self.config.secret_key);` with:

```zig
        if (self.config.secret_key) |key| {
            try client.setAuth(key);
        }
```

(c) In `parseArgs`, add a `--secret` flag (after the `--size` branch):

```zig
        } else if (std.mem.eql(u8, arg, "--secret")) {
            if (args_iter.next()) |val| {
                config.secret_key = try allocator.dupe(u8, val);
            }
```

and also read `GRPC_ZIG_BENCH_SECRET` from the env at the end of `parseArgs` (before `return`):

```zig
    if (config.secret_key == null) {
        if (std.c.getenv("GRPC_ZIG_BENCH_SECRET")) |raw_ptr| {
            config.secret_key = std.mem.span(raw_ptr);
        }
    }
```

(d) In `main`, the host-free defer pattern also applies to the duped secret; add:

```zig
    defer if (parsed.secret_owned) allocator.free(config.secret_key.?);
```

— to keep it simple, have `parseArgs` return an extra `secret_owned: bool` set true only on the `--secret` path (env path returns libc-owned memory; do not free). Update the return struct accordingly:

```zig
fn parseArgs(...) !struct { config: BenchmarkConfig, output_format: Format, secret_owned: bool } {
```

- [ ] **Step 2: Parallel workers (BH-1/#22)**

Replace the sequential worker loop in `runBenchmark` (`benchmark.zig:177-194`) with real threads:

```zig
    // Run workers concurrently — one OS thread per configured client
    // (closes BH-1 / #22: the loop previously ran workers serially, so
    // --clients N measured sequential throughput).
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
```

with a top-level thread entry:

```zig
fn workerMain(worker: *ClientWorker) void {
    worker.runBenchmark() catch |err| {
        std.log.warn("Worker failed: {}", .{err});
        // Remaining requests count as failures via the results-length
        // accounting in runBenchmark's aggregation loop.
    };
}
```

CAUTION: `workers.items` pointers must be stable while threads run — `workers` is fully populated (appendAssumeCapacity within initCapacity) before any spawn, so no reallocation occurs. Keep it that way.

- [ ] **Step 3: JSON to stdout + usage newlines (BH-4/#23, BH-5/#42)**

In `outputResults`, the `.json` arm must write to STDOUT so `benchmark --output json > results.json` works. Build the document with `std.fmt.allocPrint` and write it via the file API:

```zig
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
                results.total_requests,        results.successful_requests,
                results.failed_requests,       results.total_duration_ms,
                results.requests_per_second,   results.latency_stats.min_ms,
                results.latency_stats.max_ms,  results.latency_stats.avg_ms,
                results.latency_stats.p95_ms,  results.latency_stats.p99_ms,
                results.error_rate,            results.timestamp,
            });
            defer allocator.free(doc);
            // Write to STDOUT (fd 1) — std.debug.print goes to stderr,
            // which broke `--output json > file.json` (BH-4 / #23).
            var remaining: []const u8 = doc;
            while (remaining.len > 0) {
                const n = std.posix.write(std.posix.STDOUT_FILENO, remaining) catch break;
                remaining = remaining[n..];
            }
        },
```

(`outputResults`'s allocator parameter is currently discarded `_:` — rename it back to `allocator: std.mem.Allocator`.)

If `std.posix.write`/`STDOUT_FILENO` don't resolve under Zig 0.16, use `std.fs.File.stdout()` + `writeAll` instead — check with a quick compile; whichever resolves, keep ONE mechanism.

For BH-5/#42: append `\n` to every `std.debug.print` string in `printUsage` (12 lines) and the startup `Configuration:` block in `main` (7 lines).

- [ ] **Step 4: AG-5 transport init cleanup (#41)**

In `src/transport.zig`, delete these two lines from each of the three struct literals (`initClient` ~:389-390, `initServer` ~:413-414, `initServerTls` ~:438-439):

```zig
            .last_method = .{0} ** 256,
            .last_method_len = 0,
```

(the field declarations at :284-285 already default them).

- [ ] **Step 5: Verify**

Run: `zig fmt src/ && zig build check && zig build test`
Expected: PASS.
Then smoke the benchmark end-to-end: `grep -n "secret\|benchmark" build.zig | head -20` — the `zig build benchmark` step (build.zig:120) starts a server and runs `--requests 10 --clients 1`; run `zig build benchmark` and confirm it completes and prints results (auth is now off by default for the bench — the example server doesn't require auth, so this works).
Then: `./zig-out/bin/grpc-benchmark --help 2>&1 | head -5` — expected: each option on its own line.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "fix(benchmark): remove hardcoded secret, parallelize workers, JSON to stdout, usage newlines (closes #46, #22, #23, #42, #41)"
```

---

## Task 11: Test scaffolding + stub cleanup (T3/#69, M11/#72)

**Files:**

- Modify: `src/tests.zig` (delete commented TODO blocks + now-unused proto import)
- Modify: `src/client.zig` (remove `checkHealth` stub)
- Check: `grep -rn "checkHealth" examples/ integration_test/ interop/ src/` — update any caller

- [ ] **Step 1: Remove dead test scaffolding**

In `src/tests.zig`, delete lines 3 (`const proto = ...` — if not already removed in Task 1) and 6-28 (the two commented-out `TODO` test blocks). The real protobuf round-trip coverage lives in `interop/zig/harness_test.zig` and `integration_test/`; tracking for a general proto3 codec is GAP-0006 (#7).

- [ ] **Step 2: Remove the checkHealth stub**

`grep -rn "checkHealth" src/ examples/ integration_test/ interop/` — expected: only the definition at `src/client.zig:57-60` and possibly `examples/health.zig`. Delete the method:

```zig
    pub fn checkHealth(_: *GrpcClient, _: []const u8) !health.HealthStatus {
        // Health check requires JSON serialization; return unknown for now
        return .UNKNOWN;
    }
```

If `examples/health.zig` calls it, rewrite that example to use the server-side `health.HealthCheck` API directly (read the example first; it likely already demos `HealthCheck.setStatus/getStatus`). The wire-level health protocol is tracked as GAP-0008 (#9) — do NOT attempt to implement it here.

If removing the method leaves `src/client.zig`'s `health` import unused, remove the import too.

- [ ] **Step 3: Verify and commit**

Run: `zig fmt src/ examples/ && zig build check && zig build test`
Expected: PASS.

```bash
git add -A
git commit -m "chore: remove dead test scaffolding and checkHealth stub (closes #69, #72; T3, M11/M12)"
```

---

## Task 12: Documentation truth pass (NEW-3/#45, D1/D2/#70, D3/#71)

**Files:**

- Modify: `README.md` (security claims, wrong URLs, bind/auth defaults)
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Modify: `integration_test/README.md` (Zig version drift)

- [ ] **Step 1: Fix README security claims and URLs**

In `README.md`:

(a) Line 12: replace

```markdown
- 🔐 **Full Security**: Built-in JWT authentication and TLS support
```

with

```markdown
- 🔐 **Auth**: Built-in JWT (HS256) authentication; TLS is bring-your-own via the `on_tls_accept` callback (no built-in TLS engine — see SECURITY.md)
```

(b) Lines 112 and 147 reference `github.com/ziglana/gRPC-zig`; replace with the actual upstream `https://gitlab.com/devnw/zig/grpc-zig` (line 112: `zig fetch --save git+https://gitlab.com/devnw/zig/grpc-zig#main`; line 147: `.url = "https://gitlab.com/devnw/zig/grpc-zig/-/archive/main/grpc-zig-main.tar.gz"`).

(c) Add a `## Security posture` section (place it after the features list / before installation):

```markdown
## Security posture

grpc-zig is an **experimental v0.1.x library**. Read this before exposing a server:

- **Transport is plaintext h2c by default.** There is no built-in TLS engine,
  ALPN, or certificate handling; production deployments must either terminate
  TLS in front (reverse proxy / mTLS sidecar) or supply their own TLS via the
  `on_tls_accept` callback. Tracking: GAP-0009.
- **Authentication is off by default.** Set `server.require_auth = true` and
  provide a real secret to enforce the JWT gate.
- **Bind address defaults to `127.0.0.1`.** Opt into public binds explicitly
  with `GrpcServer.initWithBind(..., "0.0.0.0", ...)` or
  `GRPC_ZIG_BIND_ADDR=0.0.0.0`.
- **Resource limits:** inbound messages are capped at 4 MiB
  (`max_recv_message_bytes`), frames at 16 KiB, concurrent connections at 1024
  (`GRPC_ZIG_MAX_CONNS`).
- Vulnerability reports: see [SECURITY.md](SECURITY.md).
```

(d) Sweep the rest of the README for stale claims with fresh eyes: `grep -n "TLS\|secure\|Security" README.md` — every remaining claim must be true at HEAD.

- [ ] **Step 2: Create SECURITY.md**

```markdown
# Security Policy

## Supported versions

grpc-zig is pre-1.0; only the latest tagged `v0.1.x` release receives fixes.

## Deployment guidance

- Do **not** expose a grpc-zig server directly to untrusted networks.
  The transport is plaintext h2c unless you supply TLS via `on_tls_accept`;
  deploy behind TLS/mTLS termination.
- Enable the auth gate (`require_auth = true`) with a strong, rotated secret.
- The server binds `127.0.0.1` by default; public binds are an explicit opt-in.
- Resource limits (message size, frame size, connection count, flow-credit
  timeout) are enforced by default — review `GRPC_ZIG_*` env vars before
  raising them.

## Reporting a vulnerability

Open a **confidential issue** at
<https://gitlab.com/devnw/zig/grpc-zig/-/issues/new> (mark it confidential),
or email benji@vester.by. Please include a reproduction. You should receive a
response within 7 days.

## Known limitations

Tracked openly in `docs/SECURITY_GAP_ANALYSIS.md` and the issue tracker
(label `type::security`).
```

- [ ] **Step 3: Create CONTRIBUTING.md**

```markdown
# Contributing

## Toolchain

- Zig **0.16.0** (`scripts/install-zig.sh` installs the pinned version).
- Pre-commit: `pre-commit install` (zig fmt, shellcheck, ruff, markdownlint,
  commitizen commit messages, diamond-dep check).

## Workflow

1. Branch from `main`; commits follow Conventional Commits (`feat:`, `fix:`,
   `refactor:`, `chore:`...) — enforced by commitizen.
2. `zig build test` must pass locally (8+ test steps), plus
   `zig fmt --check src/ build.zig tests/ examples/`.
3. For transport/protocol changes, also run the loopback smoke:
   `zig build loopback-test && ./zig-out/bin/grpc-loopback-test`.
4. Open a merge request; CI runs unit tests under 4 optimize modes, the
   Go↔Zig interop matrix, and h2spec conformance — all are required gates.

## Tests

New protocol behavior needs a dedicated `src/*_test.zig` regression test wired
into the `test` step in `build.zig` (see `hpack_varint_test.zig` for the
pattern). Bug fixes follow TDD: failing test first.

## Security

See [SECURITY.md](SECURITY.md). Do not include real secrets in code, tests,
or benchmarks — CI runs gitleaks and will block the pipeline.
```

- [ ] **Step 4: Fix the Zig version drift (D1)**

`grep -rn "0\.15" integration_test/README.md README.md docs/` — update `integration_test/README.md:28` ("Zig 0.15.2") to `0.16.0`, and any other stale version strings found.

- [ ] **Step 5: Verify and commit**

Run: `npx markdownlint-cli README.md SECURITY.md CONTRIBUTING.md 2>/dev/null || true` (pre-commit runs it anyway); `zig build check` (no code changed, sanity only).

```bash
git add -A
git commit -m "docs: truthful security posture, SECURITY.md, CONTRIBUTING.md, fix stale URLs/versions (closes #45, #70, #71; NEW-3, D1-D3)"
```

---

## Task 13: Full verification + tracker sync

**Files:**

- Modify: `docs/SECURITY_GAP_ANALYSIS.md`, `docs/QUALITY_GAP_ANALYSIS.md`, `docs/PERF_GAP_ANALYSIS.md`, `docs/GAP_ANALYSIS_RESOLVED.md`
- GitLab: close resolved issues with evidence comments

- [ ] **Step 1: Full local gate**

Run, in order, and capture output:

```bash
zig fmt --check src/ build.zig tests/ examples/
zig build check
zig build test
zig build loopback-test && timeout 60 ./zig-out/bin/grpc-loopback-test
zig build benchmark
```

Expected: every command exits 0. If anything fails, STOP and fix before any tracker updates.

- [ ] **Step 2: Pre-commit gate**

Run: `pre-commit run --all-files`
Expected: pass (or only auto-fixes that you then commit).

- [ ] **Step 3: Close GitLab issues with evidence**

For each issue closed by Tasks 1-12 — #22, #23, #41, #42, #43, #44, #46, #47, #48, #49, #50, #51, #53 (partially: bind default landed, doc'd), #57, #58, #59, #61, #62, #63 (partially: HPACK tests landed; broader T1 scope note), #64, #69, #70, #71, #72, #45, #32 — use `glab issue close <n> --comment "Fixed in <commit sha>: <one-line summary>. Verification: zig build test green at <sha>."`. For partial closures (#53 needs README cross-check, #63 broader coverage) leave the issue open with a progress comment instead. For #40 (AG-3 early-exit): comment-and-close as **won't-fix** with rationale: "early exit would desynchronize the HPACK dynamic table — LIE entries after :path must still be pushed; full iteration is required for correctness" and apply it.

- [ ] **Step 4: Update the gap-analysis docs**

- `docs/SECURITY_GAP_ANALYSIS.md`: move NEW-1/NEW-2/NEW-3/A5/I2/I5/I6/I7/M2/O1 to a "Closed in 2026-06-11 pass" block (matching the existing closed-block format at the top), with commit SHAs. Leave O2 (TLS engine — GAP-0009), R2 (#52), S1, S3, M1 (downgraded, recheck) open.
- `docs/QUALITY_GAP_ANALYSIS.md`: update the Tracker Mapping table to reference issues #57-#73; mark R2, M3, M4, M2, M5, M6, M11, M12, T3, D1, D2, D3 closed with SHAs; R3/R4 closed; T1 partial; M7/M8/M9/M10/T2/D4 still open.
- `docs/PERF_GAP_ANALYSIS.md`: mark BH-1, BH-4, BH-5, AG-5, NW-5 closed; AG-3 won't-fix with the rationale above; BH-7 closed (verified monotonic clock).
- `docs/GAP_ANALYSIS_RESOLVED.md`: append entries for everything closed this pass.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "docs(trackers): sync gap analyses with 2026-06-11 audit-fix pass"
```

---

## Deferred to iteration 2 (tracked, intentionally NOT in this plan)

- **#52 R2-sec**: enforce advertised MAX_CONCURRENT_STREAMS (low risk while dispatch is serial).
- **#66 M7**: split `transport.zig` (~2k LOC) into hpack/frame_io/grpc_framing modules — large refactor, do it as its own plan after this pass stabilizes.
- **#67 M10 / #73 D4**: full magic-number/named-constant + RFC-citation sweep (partially improved here).
- **#68 T2**: fake-IO injection tests for `readFrame`/`readMessage`/`readerLoop`.
- **#27-#31, #36-#38 AL/CC/AG/MW perf cluster**: scratch-buffer reuse, writev, Huffman LUT, full static table, byte-bounded dyn table — needs the bench harness fixed first (this plan fixes it) to measure wins.
- **#26, #6 GAP-0005**: full HPACK static table + general metadata surface.
- **#35 BH-9**: CI perf regression gate (needs baseline JSON from the now-fixed harness).
- **#55/#56 S1/S3**: CI catalog `allow_failure` audit + branch-protection verification (GitLab settings, not repo code).
- Feature gaps #7-#19 (proto3 codec, streaming breadth, health-on-wire, TLS engine, gzip path, interop breadth, observability surface).

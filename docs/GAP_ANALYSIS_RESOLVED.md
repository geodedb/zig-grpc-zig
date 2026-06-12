# Gap Analysis -- Resolved

Repository: `devnw/zig/grpc-zig`
Last sync: 2026-04-26 (gap-close pass)
Companion files:

- `docs/GAP_ANALYSIS.md` (open functional/feature gaps)
- `docs/QUALITY_GAP_ANALYSIS.md` (open quality findings)
- `docs/PERF_GAP_ANALYSIS.md` (open performance findings)
- `docs/SECURITY_GAP_ANALYSIS.md` (open security findings)

Resolved or invalidated gaps are recorded here for historical traceability.

---

## Functional / Feature Gap Resolutions

### GAP-0017: "Zero dependencies" claim verified [RESOLVED]

- **Issue:** none (resolved at gap-detection time; no platform issue created)
- **Category:** Docs
- **Source tag:** G-DOC-01
- **Resolution:** Phase 3 gap-detector verified the README's "zero dependencies" claim by inspecting `build.zig.zon` and `build.zig`. No third-party package declarations were found beyond Zig standard library usage.
- **Evidence:**
  - `build.zig.zon` -- no `.dependencies` entries.
  - `build.zig` -- no `b.dependency(...)` calls.
  - README.md -- "Zero dependencies" claim confirmed accurate.
- **Resolved date:** 2026-04-26

---

### GAP-0001: Server accepts every RPC unauthenticated despite advertising JWT auth [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/2> (closed)
- **Category:** Security (Critical)
- **Resolution commit:** `51a5924` -- *fix(security): close GAP-0001 - reject requests with missing or invalid authorization*
- **Resolution summary:** Added `GrpcServer.require_auth` (default off for back-compat). When enabled, the dispatch loop reads `trans.lastAuthorization()` and calls `auth.verifyToken`; missing or invalid token short-circuits with `endStreamWithStatus(stream_id, 16, @errorName(err))` (UNAUTHENTICATED). Transport now captures the `authorization` header into a 1024-byte bounded buffer during HPACK extraction (handles LIE-with-incremental-indexing, Literal-Without-Indexing, static-table index 23, plain-text and Huffman strings). Multi-byte HPACK 7-bit-prefix integer encoding (`hpackInt7Encode`) added so JWT values >127 bytes round-trip.
- **Evidence:**
  - `src/server.zig` -- new `require_auth` field + verify-then-dispatch flow.
  - `src/transport.zig` -- `last_authorization`, `lastAuthorization()`, `setAuthorizationFromHpackString`.
  - `src/auth_gate_test_main.zig` -- end-to-end test: valid token (handler runs), missing header (status 16), tampered token (status 16). Wired via `zig build auth-gate-test`.
- **Resolved date:** 2026-04-26

### GAP-0002: Per-RPC authorization metadata silently dropped on the wire [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/3> (closed)
- **Category:** Correctness / Security (Critical)
- **Resolution commit:** `cc2d9b7` -- *fix: close GAP-0002 - transmit per-RPC metadata in HEADERS*
- **Resolution summary:** Introduced `writeRequestHeadersWithMetadata` which appends each metadata entry as an HPACK Literal-with-Incremental-Indexing header after the canonical pseudo-headers. `GrpcClient.call` now plumbs the headers map (and JWT, when `auth` is set) through `writeRequestWithMetadata` instead of dropping it. Existing `writeRequestHeaders` is a null-metadata wrapper, so byte-for-byte output is unchanged for metadata-free callers.
- **Evidence:**
  - `src/transport.zig` -- `writeRequestHeadersWithMetadata`, `writeRequestWithMetadata`, `writeRequestOnStreamWithMetadata`.
  - `src/client.zig` -- `call` now forwards metadata + JWT.
  - `src/client_mux.zig` -- `callWithMetadata` for the multiplexed path.
  - `src/transport_request_headers_test.zig` -- wire-bytes assertions for `authorization: Bearer xyz123` LIE signature and byte-identical null-metadata output.
- **Resolved date:** 2026-04-26

### GAP-0003: Server always invokes handlers.items[0] regardless of :path [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/4> (closed)
- **Category:** Correctness (Critical)
- **Resolution commit:** `bf55446` -- *fix: close GAP-0003 - dispatch by :path instead of handlers[0]*
- **Resolution summary:** Server dispatch now linear-scans `self.handlers` for a name == method match. On miss, emits `grpc-status: 12` (UNIMPLEMENTED) trailer-only HEADERS via `endStreamWithStatus` and continues. Loopback scenarios now register one handler per `:path` (`/Echo`, `/Passthrough`, `/Stream`, `/loopback.Mux/Echo`).
- **Evidence:**
  - `src/server.zig` -- new dispatch loop + UNIMPLEMENTED fallback.
  - `src/dispatch_test_main.zig` -- end-to-end: `/svc.A/Foo` to A, `/svc.B/Bar` to B, unregistered path returns status 12.
- **Resolved date:** 2026-04-26

### GAP-0004: Flow control window never decremented; large streams stall [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/5> (closed); also closes perf #13 (NW-1+NW-2+NW-3)
- **Category:** Correctness / HTTP/2 protocol (High)
- **Resolution commit:** `efd9ef6` -- *fix: close GAP-0004 - track and honor HTTP/2 flow control + h2spec CI*
- **Resolution summary:** Full HTTP/2 flow-control state machine. Server and client now advertise non-default SETTINGS (INITIAL_WINDOW_SIZE 1 MiB, MAX_FRAME_SIZE 16384, MAX_CONCURRENT_STREAMS 100, MAX_HEADER_LIST_SIZE 8192). Per-stream and connection windows tracked as `i32 send_window` / `i32 recv_window`. `processWindowUpdate` validates non-zero and rejects overflow past 2^31-1 with FLOW_CONTROL_ERROR. `reserveSendCredit` uses `flow_cv` to block writers; `maybeRefillRecvWindow` emits WINDOW_UPDATE below the half-threshold. `applyPeerSettings` honours SETTINGS_INITIAL_WINDOW_SIZE per RFC 7540 §6.9.2. Outbound DATA fragmenter fragments a gRPC-framed buffer into max_frame_size-sized DATA frames; reassembly accumulates into a per-call ArrayList until the gRPC length-prefix indicates a complete message. CI now runs h2spec generic + http2 conformance suites against the Zig interop server.
- **Evidence:**
  - `src/http2/stream.zig` -- `i32 send_window`, `i32 recv_window`.
  - `src/transport.zig` -- `conn_send_window`, `conn_recv_window`, `flow_mutex`, `flow_cv`, `reserveSendCredit`, `maybeRefillRecvWindow`, `applyPeerSettings`, `processWindowUpdate`.
  - `src/client_mux.zig` -- reader loop honours peer SETTINGS + WINDOW_UPDATE.
  - `src/flow_control_test.zig` -- 8 unit tests cover initial windows, WINDOW_UPDATE validation/overflow, half-threshold refill, §6.9.2 delta math + i32-overflow rejection, SETTINGS-frame builder, WINDOW_UPDATE-frame builder.
  - `.gitlab-ci.yml` -- `interop-h2spec` job (h2spec v2.6.0).
- **Resolved date:** 2026-04-26

---

## Verifier Follow-Up Resolutions

### GAP-FU-002: Per-stream send-credit timeout in flow control [RESOLVED]

- **Issue:** none filed (filed under `security`, severity::medium / `reliability`)
- **Category:** Security / Reliability (slow-loris class, Medium)
- **Source:** Verifier pass on commit `efd9ef6` (2026-04-26).
- **Resolution summary:** Replaced the unbounded `flow_cv.waitUncancelable` in `Transport.reserveSendCredit` with a futex-based bounded wait. The transport now owns a `flow_epoch: std.atomic.Value(u32)` (incremented under `flow_mutex` whenever credit is granted) plus a configurable `flow_credit_timeout_ns`. The reserve loop computes the deadline once at entry, releases the mutex, and calls `std.Io.futexWaitTimeout(&flow_epoch.raw, snapshot, .{ .deadline = d })`. Because `futexWaitTimeout` surfaces deadline expiry as a successful (spurious-style) wake, the loop checks the deadline manually each iteration; on expiry it returns `error.FlowControlTimeout`. A new wrapper `reserveSendCreditOrRst` emits `RST_STREAM(FLOW_CONTROL_ERROR=0x03)` for the offending stream (best-effort, via a new `writeRstStream` helper) before propagating the error to its caller. Wired into `writeStreamMessage`, `writeMessageOnStream`, and `writeRequestOnStreamWithMetadata`. The timeout is plumbed end-to-end: `GrpcServer.flow_credit_timeout_ns` (default 30 s; `0` disables) is read from `GRPC_ZIG_FLOW_CREDIT_TIMEOUT_MS` and copied onto each accepted Transport in `handleConnection`.
- **Evidence:**
  - `src/transport.zig` -- `flow_epoch` + `flow_credit_timeout_ns` fields replacing `flow_cv`; new `wakeFlowWaiters`, `reserveSendCredit` (returns `error{FlowControlTimeout}!void`), `reserveSendCreditOrRst`, `writeRstStream`. Broadcast sites in `processWindowUpdate` and `applyPeerSettings` updated.
  - `src/server.zig` -- `GrpcServer.flow_credit_timeout_ns`, `DEFAULT_FLOW_CREDIT_TIMEOUT_MS`, `flowCreditTimeoutNsFromEnv`, `parseFlowCreditTimeoutMs`; `handleConnection` propagates the timeout onto the new Transport.
  - `src/flow_control_test.zig` -- 3 new tests:
    - `reserveSendCredit returns FlowControlTimeout when peer never advertises credit` (slow-loris fault injection: starves both windows, sets a 50 ms timeout, asserts timeout fires within (~30 ms, 1 s)).
    - `reserveSendCredit succeeds when credit is available within the timeout` (no false positive on funded streams).
    - `reserveSendCredit with timeout=0 keeps legacy unbounded behaviour for funded streams`.
  - `src/admission_control_test.zig` -- 3 new tests for `parseFlowCreditTimeoutMs` (accepts `0`, rejects empty / non-numeric / negative; default constant pinned to `30_000`).
  - `zig build test` -- 45/45 unit tests pass; `zig build loopback-test` ALL SCENARIOS PASSED including the multiplexed 128-calls-on-1-connection scenario which exercises the flow-control fast path on legitimate, funded streams.
- **Resolved date:** 2026-04-26

### GAP-FU-001: R1 acceptance text references RST_STREAM; impl emits gRPC-canonical trailer-only HEADERS [RESOLVED]

- **Issue:** none filed (filed under `quality-finding`, severity::low)
- **Category:** Docs / api-contract (Low)
- **Source:** Verifier pass on commit `0993e5e` (2026-04-26).
- **Resolution summary:** Updated `docs/QUALITY_GAP_ANALYSIS.md` R1 narrative + stack-ranked-row text to remove the misleading "or `RST_STREAM`" alternative and cross-reference the gRPC core spec ([gRPC over HTTP/2](https://grpc.io/docs/guides/wire-format/)) which mandates a trailer-only HEADERS|END_STREAM frame carrying `grpc-status` (and optionally `grpc-message`). `RST_STREAM` aborts a stream WITHOUT delivering a status and is therefore not a substitute. Landed implementation is correct; only the criterion wording was stale.
- **Evidence:**
  - `docs/QUALITY_GAP_ANALYSIS.md` -- header banner, R1 narrative (#1), and stack-ranked-row finding text now reference only the trailer-only HEADERS|END_STREAM close-out.
  - `docs/GAP_ANALYSIS_RESOLVED.md:Q-R1` -- note clarifies that the canonical close-out shape is mandatory and `RST_STREAM` is NOT a substitute.
- **Resolved date:** 2026-04-26

---

## Quality Domain Resolutions

### Q-R1: Server swallows handler errors -- wire-contract breach [RESOLVED]

- **Issue:** none filed (quality findings tracker creation deferred)
- **Category:** Reliability / api-contract (Critical, PriorityScore 200)
- **Resolution commits:** `19fcf38` (precursor: `endStreamWithStatus` helper) + `0993e5e` (R1 fix)
- **Resolution summary:** Handler-error path in `src/server.zig` now calls `endStreamWithStatus(stream_id, 2, @errorName(err))`, emitting a trailer-only HEADERS frame with `grpc-status: 2` (UNKNOWN) and `grpc-message=<err>`. Failing client no longer hangs until deadline.
- **Note:** Implementation emits the gRPC-canonical trailer-only HEADERS|END_STREAM frame carrying `grpc-status` (and optionally `grpc-message`) -- the only spec-compliant way to terminate a stream with a status. `RST_STREAM` aborts the stream without delivering a status and is therefore NOT a substitute. The earlier wording listing `RST_STREAM` as an allowable signal has been corrected in `docs/QUALITY_GAP_ANALYSIS.md` (closes follow-up `GAP-FU-001`).
- **Evidence:**
  - `src/server.zig` -- handler-error catch arm.
  - `src/transport.zig:875-882` -- `endStreamWithStatus` helper (also closes Q-A1).
  - `src/handler_error_test_main.zig` -- handler returns `error.IntentionalFailure`; client observes `grpc-status: 2`, `grpc-message: "IntentionalFailure"`. Wired via `zig build handler-error-test`.
- **Resolved date:** 2026-04-26

### Q-A1: gRPC error contract not modelled -- no `endStreamWithStatus(code, message)` helper [RESOLVED]

- **Issue:** none filed
- **Category:** api-contract (High, PriorityScore 112.5)
- **Resolution commit:** `19fcf38` -- *feat(transport): add endStreamWithStatus helper for non-zero gRPC status*
- **Resolution summary:** New helper `Transport.endStreamWithStatus(stream_id, code, message)` builds a wire-correct trailer-only HEADERS frame containing `grpc-status: <code>` and `grpc-message: <message>`, with END_STREAM. Consumed by R1, GAP-0001, GAP-0003.
- **Evidence:**
  - `src/transport.zig` -- `endStreamWithStatus`.
  - `src/transport_endstream_test.zig` -- wire-bytes test.
- **Resolved date:** 2026-04-26

---

## Security Domain Resolutions

### S-A1: AuthN never invoked on dispatch path [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/2> (same as GAP-0001; closed)
- **Category:** Authentication (Critical, Risk 30, CWE-306 / OWASP A07:2021)
- **Resolution commit:** `51a5924`
- **Resolution summary:** See GAP-0001.
- **Resolved date:** 2026-04-26

### S-A2: Client never serializes `authorization` metadata [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/3> (same as GAP-0002; closed)
- **Category:** Authentication (Critical, Risk 24, CWE-287 / OWASP A07:2021)
- **Resolution commit:** `cc2d9b7`
- **Resolution summary:** See GAP-0002.
- **Resolved date:** 2026-04-26

### S-A3: `generateToken` emits no signature; `verifyToken` compares HMAC bytes to decimal `iat` [RESOLVED]

- **Issue:** none filed (held back per disclosure policy until fix landed)
- **Category:** Authentication / Cryptography (Critical, Risk 30, CWE-347 / OWASP A02:2021)
- **Resolution commit:** `5ec22b8` -- *fix(security): close A3 - implement RFC 7519 JWT with constant-time HMAC compare* (also closes M3)
- **Resolution summary:** Full rewrite of `src/features/auth.zig`. `generateToken` now produces a true RFC 7519 JWT: `base64url(json_header).base64url(json_payload).base64url(hmac_sha256)` with header `{"alg":"HS256","typ":"JWT"}` and payload `{sub, iat, exp}`. `verifyToken` decodes, asserts `alg==HS256` and `typ==JWT`, recomputes HMAC-SHA256 over the literal `<header_b64>.<payload_b64>` prefix, and compares with `std.crypto.timing_safe.eql([32]u8, ...)` (closes M3 timing oracle). Signature verified BEFORE payload claim parsing so a forged token can't reveal anything via parse-error timing. Distinct error variants: `MalformedToken`, `InvalidToken`, `InvalidSignature`, `TokenExpired`, `TokenNotYetValid`.
- **Evidence:**
  - `src/features/auth.zig` -- new `generateToken` / `verifyToken` / `Claims`.
  - `src/auth_test.zig` -- round-trip success, payload tamper, expired (negative TTL), wrong key, malformed segments, `timing_safe.eql` smoke.
- **Resolved date:** 2026-04-26

### S-M3: Non-constant-time `std.mem.eql` for HMAC compare [RESOLVED]

- **Issue:** none filed
- **Category:** Memory safety / timing (Medium, CWE-208)
- **Resolution commit:** `5ec22b8` (folded into S-A3 fix)
- **Evidence:** `src/features/auth.zig` now uses `std.crypto.timing_safe.eql([32]u8, ...)`.
- **Resolved date:** 2026-04-26

### S-I1: HPACK `hpackDecodeInt` shift-counter overflow [RESOLVED]

- **Issue:** none filed (held back per disclosure policy)
- **Category:** Input parsing (Critical, Risk 18, CWE-190)
- **Resolution commit:** `9322f96` -- *fix(security): close I1 - cap HPACK varint shift to prevent overflow*
- **Resolution summary:** `hpackDecodeInt` now uses a u32 shift counter (so the addition itself is safe), rejects before each shift if `m + 7 > @bitSizeOf(usize)` returning `error.HpackIntegerOverflow`, and caps continuation bytes at `MAX_HPACK_VARINT_CONTINUATIONS = 5`. All callers (`hpackStringIs`, `setPathFromHpackString`, `setAuthorizationFromHpackString`, `extractPathFromHpack`) propagate or catch the new error so a malicious peer triggers a protocol error instead of panicking the connection thread. Pre-auth single-packet DoS path closed.
- **Evidence:**
  - `src/transport.zig` -- `hpackDecodeInt` guard + `MAX_HPACK_VARINT_CONTINUATIONS`.
  - `src/hpack_varint_test.zig` -- regression coverage. Wired via `zig build hpack-varint-tests` and the `check` step.
- **Resolved date:** 2026-04-26

### S-I3: `SETTINGS_MAX_FRAME_SIZE` not enforced [RESOLVED]

- **Issue:** none filed (held back per disclosure policy)
- **Category:** Resource exhaustion (High, Risk 18, CWE-770)
- **Resolution commit:** `8919308` -- *fix(security): close I3 - enforce SETTINGS_MAX_FRAME_SIZE on inbound frames*
- **Resolution summary:** `Transport.max_frame_size` (default `DEFAULT_MAX_FRAME_SIZE = 16384` per RFC 7540 §6.5.2) is consulted in `readFrame` before allocating the payload buffer. Oversize frames return `error.FrameSizeError` and emit a connection-level GOAWAY with `FRAME_SIZE_ERROR (0x06)`. `applyPeerSettings` parses (id, value) tuples and updates `max_frame_size` on parameter id 0x05, clamping to `[16384, 2^24-1]`. Required correctness fallout: outbound DATA fragmenter (`writeDataFragmentedLocked`) and multi-frame gRPC reassembly added so `readMessage`/`readStreamFrame` accumulate until the gRPC length-prefix indicates a complete message. Pre-auth memory-amplification DoS closed.
- **Evidence:**
  - `src/transport.zig` -- `DEFAULT_MAX_FRAME_SIZE`, `max_frame_size`, `checkFrameSize`, `applyPeerSettings`, `writeDataFragmentedLocked`, multi-frame reassembly.
  - `src/transport_max_frame_size_test.zig` -- 4 tests: cap value, accept-at-cap/reject-above, peer-SETTINGS update, GOAWAY wire bytes.
- **Resolved date:** 2026-04-26

---

## Performance Domain Resolutions

### P-MW-1 + P-MW-2: Unused 64 KiB read_buf + write_buf per Transport [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/24> (closed)
- **Category:** Memory (P1, Score 20)
- **Resolution commit:** `3238c26` -- *perf: close MW-1/2/3 - remove unused per-Transport buffers and dead http2_conn*
- **Resolution summary:** Deleted `read_buf` and `write_buf` fields and their alloc/free in `initClient`, `initServer`, `initServerTls`, `deinit`. No code path ever read from or wrote to either slice -- every byte movement went through stack buffers in `readExact` / `ioWriteLocked`. -128 KiB per connection.
- **Evidence:** `src/transport.zig` (deletions); existing endstream/loopback/flow-control tests still pass.
- **Resolved date:** 2026-04-26

### P-MW-3: Dead `http2_conn` Connection field; `sendFrame` is a no-op [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/25> (closed)
- **Category:** Memory / cleanup (P1, Score 15)
- **Resolution commit:** `3238c26`
- **Resolution summary:** Removed `http2_conn` field plus matching alloc/free; deleted the no-op `sendFrame` stub in `src/http2/connection.zig`. Saves a per-connection HPACK encoder/decoder + AutoHashMap allocation pair.
- **Evidence:** `src/http2/connection.zig`, `src/transport.zig`, `src/transport_endstream_test.zig`.
- **Resolved date:** 2026-04-26

### P-MW-4: ~131 KiB heap + 8 MiB stack/conn -- ~8 GiB at 1k conns [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/18> (closed)
- **Category:** Memory umbrella (P0, Score 16)
- **Resolution commits:** `3238c26` (MW-1/2/3) + `0fd05ac` (CC-4) + `ac7f771` (CC-1 + admission cap) collectively
- **Resolution summary:** With MW-1/2/3 deletions (-128 KiB heap/conn), CC-4 stack cap (8 MiB to 512 KiB stack/conn), and CC-1 admission cap (default 1024 conns), the combined resident-memory ceiling drops from ~8 GiB to well under 600 MiB at the cap. Further gating now happens at admission rather than after thread spawn.
- **Evidence:** see MW-1/2/3, CC-4, CC-1 entries.
- **Resolved date:** 2026-04-26
- **⚠ Note 2026-06-12:** the CC-4 portion of this ceiling changed — the connection-thread stack default reverted from 512 KiB to 8 MiB to fix the GAP-0018 segfault (see P-CC-4). Because thread stacks are demand-paged, idle-connection *RSS* is still dominated by heap state, not the stack reservation; the 8 MiB figure is virtual address space, lowerable via `GRPC_ZIG_CONN_STACK_SIZE` under non-capturing allocators. The heap-side reductions (MW-1/2/3) and the CC-1 admission cap are unchanged.

### P-CC-1: Unbounded thread-per-connection accept loop [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/20> (closed)
- **Category:** Concurrency / admission control (P0, Score 32)
- **Resolution commit:** `ac7f771` -- *perf(server): close CC-1 + MW-4 - bound concurrent connections*
- **Resolution summary:** Bounded admission control. `GRPC_ZIG_MAX_CONNS` env var (default 1024) caps live connection count; exceeded limit gates accept via a counting semaphore. Outstanding accept counter decremented on connection-thread exit. Combined with CC-4 stack cap, this puts a hard ceiling under the per-conn memory cost.
- **Evidence:**
  - `src/server.zig` -- accept gate + counter.
  - `src/admission_control_test.zig` -- exercises cap behaviour.
- **Resolved date:** 2026-04-26

### P-CC-4: 8 MiB pthread stack per connection [RESOLVED]

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/21> (closed)
- **Category:** Concurrency / memory (P0, Score 32)
- **Resolution commit:** `0fd05ac` -- *perf: close CC-4 - cap connection-thread stack at 512 KiB*
- **Resolution summary:** `SpawnConfig.stack_size = 512 * 1024` for the per-connection thread. ~16x reduction in idle-connection memory; combined with the CC-1 admission cap, saves ~7.5 GiB at fleet steady state vs the glibc default.
- **Evidence:** `src/server.zig` -- `SpawnConfig.stack_size`.
- **Resolved date:** 2026-04-26
- **⚠ Superseded 2026-06-12 (GAP-0018):** the fixed 512 KiB cap was found UNSAFE under any stack-trace-capturing allocator (Zig 0.16's `std.heap.DebugAllocator`, which the shipped example uses): the DWARF self-unwinder allocates large CFI state on the stack during the connection thread's first allocation (`Transport.initServer` → `allocStreamWindows`), overflowing the 512 KiB stack and SIGSEGV-ing on the first accepted connection — a pre-auth remote DoS. Fixed in `77ed8d4`: the connection-thread stack size is now **configurable** via `GRPC_ZIG_CONN_STACK_SIZE` (64 KiB floor) with a **safe 8 MiB default**. Note thread stacks are demand-paged, so the 8 MiB reservation does not cost 8 MiB of RSS per idle connection — actual resident memory tracks pages touched (a few KiB for an idle/handshaked connection). Operators running a non-capturing allocator (e.g. `c_allocator`, release builds) may lower the value via the env var to reclaim virtual address space. Regression-gated by `zig build conn-stack-test` (CI).

---

## 2026-06-11 audit-fix pass

Closed on branch `fix/audit-2026-06-11` (on top of `e060433`). Verification for every item: `zig build test` green + loopback ALL SCENARIOS PASSED at HEAD. Each line is `Gap-ID — GitLab issue — commit — summary`.

### Security domain

- **NEW-1 (High, pre-auth memory DoS)** — #43 — `16ce41c` — cap inbound gRPC message assembly (`max_recv_message_bytes` 4 MiB).
- **NEW-2 (Medium)** — #44 — `721eda3` — peer SETTINGS can no longer raise the inbound frame-size cap (preserves I3).
- **NEW-3 (Medium)** — #45 — `e3f1594` — truthful README security posture; added SECURITY.md; removed Full-Security/built-in-TLS overclaim.
- **A5 (High)** — #46 — `5a03dc4` — removed hardcoded `benchmark-secret-key` from `src/`.
- **I2 (High)** — #47 — `b2e8c4e` — HPACK Huffman decode fails closed; RFC 7541 vector tests added.
- **I5 (High)** — #48 — `98d1c7b` / `b2071c8` — CONTINUATION reassembly (no longer dropped) + leak-detecting tests.
- **I6 (High)** — #49 — `1d27136` — gRPC length-prefix / compression flag validated against DATA frame boundaries.
- **I7 (Medium-latent)** — #50 — `21136ef` — deleted dead stub HPACK decoder with latent OOB reads.
- **M2-sec (Medium)** — #51 — `61e2f15` — error on stream-id exhaustion instead of silently wrapping `next_stream_id`.
- **O1 (High)** — #53 — `7b810a4` — loopback-default bind with `bind_address` option (no hardcoded `0.0.0.0`).

### Quality domain

- **R2 (Critical)** — #57 — `8c79e2e` — client_mux always signals end_stream on delivery failure; caps response accumulation (fixes OOM deadlock).
- **M3 / M4 (High)** — #61 — `1d27136` — shared 5-byte gRPC length-prefix encoder/decoder helpers.
- **M1 / M2-dup (High)** — #62 — `1d27136` — deduplicated response-headers HPACK literal + gRPC trailer literal (OK trailers).
- **M5 / M6 (High/Medium)** — #64 — `21136ef` — deleted dead `http2/connection.zig` and `http2/{hpack,stream}.zig`.
- **R3 (High)** — #58 — `7b810a4` — connection error counter instead of silently discarding errors.
- **R4 (High)** — #59 — `7b810a4` — TLS read failures log a warning before break.
- **T3 (Medium)** — #69 — `a43e991` — removed commented-out HelloRequest/HelloResponse test scaffolding.
- **M11 / M12 (Low)** — #72 — `a43e991` — removed dead `checkHealth` stub and unused `proto/service.zig` import.
- **D1 / D2 (Medium)** — #70 — `e3f1594` — reconciled Zig version drift and corrected the upstream URL.

### Performance domain

- **BH-1 (P0)** — #22 — `5a03dc4` — benchmark workers run in parallel honoring `concurrent_clients`.
- **BH-4 (P0)** — #23 — `5a03dc4` — benchmark JSON output to stdout instead of stderr.
- **BH-5 (P3)** — #42 — `5a03dc4` — printUsage emits trailing newlines.
- **AG-5 (P3)** — #41 — `5a03dc4` — dropped redundant 256-byte `last_method` memset on every Transport init.
- **NW-5 (P1)** — #32 — `7b810a4` — TCP_NODELAY/keepalive on listener and accepted sockets.
- **BH-7 (P1)** — #34 — verified `compat.nanoTimestamp` is monotonic ns-grade; no code change required.

### Won't-fix

- **AG-3 (P3)** — #40 — won't-fix. Early exit from `extractPathFromHpack` would desynchronize the HPACK dynamic table — literal-with-incremental-indexing entries appearing after `:path` must still be pushed to keep the dynamic table consistent across requests, so full iteration is required for correctness. Cost is bounded (one HEADERS frame, ≤8 KiB).

### Partial (issues remain OPEN)

- **T1 (High)** — #63 — `b2e8c4e` — HPACK Huffman/dynamic-table tests landed; `extractPathFromHpack` end-to-end coverage and fuzzing remain. Issue left open.
- **D3 (Medium)** — #71 — `e3f1594` — SECURITY.md and CONTRIBUTING.md added; CODEOWNERS and `docs/ADRS/ADR-0001` remain. Issue left open.

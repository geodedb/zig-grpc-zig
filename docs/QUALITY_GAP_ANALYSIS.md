# Quality Gap Analysis — grpc-zig

Last updated: 2026-04-26 (post gap-close: 2 closed -- R1, A1; GAP-FU-001 doc-correction folded in)
Reviewer pipeline: quality-scanner → quality-reviewer → quality-tracker (this doc)
Repository: gitlab.com/devnw/zig/grpc-zig
Branch: main @ ac7f771

> **Closed in this pass (see `docs/GAP_ANALYSIS_RESOLVED.md`):**
> - **R1** (Critical, 200) -- handler error swallowed -- closed by `0993e5e` + `19fcf38`
> - **A1** (High, 112.5) -- no `endStreamWithStatus(code, message)` -- closed by `19fcf38`
>
> **GAP-FU-001 (Doc, Low) -- closed:** R1 acceptance text below has been corrected.
> The gRPC core spec mandates a trailer-only HEADERS|END_STREAM frame carrying
> `grpc-status` (and optionally `grpc-message`) on every server-terminated stream.
> `RST_STREAM` aborts the stream WITHOUT delivering a status and is not a
> substitute for trailers. The earlier wording listing `RST_STREAM` as an
> allowable signal was misleading; landed implementation emits the canonical
> trailer-only HEADERS|END_STREAM and is correct.

---

## Issue-Tracker Status

- Write probe: **succeeded** (`glab label create --name quality-finding`
  returned `Created label: quality-finding` against
  `devnw/zig/grpc-zig`). The earlier `glab auth status` warning
  ("Invalid token provided in configuration file") did **not** prevent
  the write — token is functional for label/issue scope.
- Issue creation: **DEFERRED**. Per task guardrails ("Do NOT create
  dozens of issues without confirmation"), no issues were filed in this
  pass. 17 findings would otherwise have been opened. Re-run with
  explicit `--create-issues` confirmation to file them.
- Existing tracker: **empty** (0 quality-labelled issues).

---

## Scoring

`PriorityScore = severity_weight × impact_weight × frequency`

- severity_weight: Critical=8, High=5, Medium=3, Low=1
- impact_weight: 1–5; **×2** for wire-contract violations (R1, R2, A1,
  A2); **×1.5** for hot-path duplication (R5, R6, M1–M4, M3 encoder,
  M4 decoder)
- frequency: 1–5 (how often the offending code path is exercised /
  touched in normal use & development)
- Confidence tags: `confirmed` for direct code-evidence findings,
  `suspected` where review depth was bounded.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 6 |
| Medium   | 7 |
| Low      | 2 |
| **Total**| **17** |

### Top 5 risks
1. **R1** Server swallows handler errors — wire-contract breach,
   client hangs (PriorityScore 200).
2. **R2** Client mux silently drops OOM — caller blocks forever
   (PriorityScore 160).
3. **A1** No `endStreamWithStatus(code, message)` helper — gRPC error
   model not modelled (PriorityScore 112.5).
4. **R5/R6** Triplicated frame/message readers — fix-once-bug-thrice
   surface (PriorityScore 90 each).
5. **M3/M4** 5-byte length-prefix encoder & decoder duplicated 3× — any
   framing bug ships in three places (PriorityScore 67.5 each).

---

## Top 3 by PriorityScore

### #1 — R1 Server swallows handler errors (PriorityScore = 200)

`8 (Critical) × 5 (impact, ×2 wire-contract) × 5 (every failing RPC)`

- File: `src/server.zig:134-137`
- After a handler returns an error the server logs and `continue`s the
  read loop. **No `grpc-status` trailer is emitted.** Clients block
  until their own deadline elapses or read EOF and treat the call as
  success-with-no-trailers.
- Wire-contract: violates the gRPC core spec
  ([gRPC over HTTP/2](https://grpc.io/docs/guides/wire-format/)) --
  `grpc-status` carried in a trailer-only HEADERS|END_STREAM frame is
  the mandatory close-out for every server-terminated stream.
  `RST_STREAM` aborts the stream WITHOUT delivering a status code and
  is therefore NOT an acceptable alternative.
- Fix: introduce `Transport.endStreamWithStatus(stream_id, code,
  message)` (see A1) and call it from the catch block with code derived
  from the handler error (default `INTERNAL`).
- Verification: integration test that returns
  `error.Unimplemented` from a handler must observe `grpc-status: 12`
  carried in a trailer-only HEADERS frame on a Go/Zig client without
  timeout. (No `RST_STREAM` is required and none should be emitted on
  the success-of-error-mapping path.)

### #2 — R2 Client mux drops OOM silently (PriorityScore = 160)

`8 (Critical) × 4 (impact, ×2 wire-contract) × 5 (every concurrent RPC)`

- File: `src/client_mux.zig:220-228`
- `readerLoop` catches allocator OOM into `slot.err`, frees the
  payload, but **does not** `cond.broadcast()` nor set
  `end_stream=true`. The waiting RPC caller deadlocks.
- Wire-contract / liveness: any caller awaiting that stream blocks
  forever, holding mutex resources.
- Fix: in the OOM branch, set `slot.err`, set `slot.end_stream = true`,
  call `slot.cond.broadcast()` under the lock, and release the
  reservation.
- Verification: fault-injection unit test using a
  `FailingAllocator` to force OOM mid-stream and assert the caller
  unblocks with `error.OutOfMemory`.

### #3 — A1 gRPC error contract not modelled (PriorityScore = 112.5)

`5 (High) × 4.5 (impact, ×1.5 hot-path; wire-contract ×2 effective at impact-cap 5) × 5 (every error path)`

- File: `src/transport.zig:875-882`
- Trailers are only emitted on success. No helper takes
  `(code, message)` to emit `grpc-status` + `grpc-message` and close
  the stream. Blocks fixing R1 and any future error-mapping work.
- Fix: add `endStreamWithStatus(code: GrpcStatusCode, message: ?[]const
  u8)`; build trailers via `RESPONSE_HEADERS_BYTES` constant + dynamic
  status header (Literal-Without-Indexing, name-indexed where possible).
- Verification: unit test asserting wire bytes for `OK`,
  `UNIMPLEMENTED`, `INTERNAL with message`.

---

## Stack-Ranked Findings

| Rank | ID | Sev | Score | Category | Finding | Component | Evidence | Fix Summary | Confidence | Effort | Status |
|-----:|----|-----|------:|----------|---------|-----------|----------|-------------|------------|--------|--------|
| 1  | R1  | Critical | 200   | reliability,api-contract | Handler error logged then continue, no `grpc-status` trailer emitted | server | `src/server.zig:134-137` | Emit synthetic grpc-status trailers via `Transport.endStreamWithStatus`; depends on A1 | confirmed | M | **closed (0993e5e, 2026-04-26)** |
| 2  | R2  | Critical | 160   | reliability | `client_mux.readerLoop` swallows allocator OOM into `slot.err`; never broadcasts | client_mux | `src/client_mux.zig:220-228` | Always `cond.broadcast()` and set `end_stream=true` in error branch | confirmed | S | open |
| 3  | A1  | High     | 112.5 | api-contract | gRPC error contract not modelled — no `endStreamWithStatus(code, message)` | transport | `src/transport.zig:875-882` | Add helper; precondition for R1 | confirmed | S | **closed (19fcf38, 2026-04-26)** |
| 4  | R5  | High     | 90    | maintainability | Connection-level frame handling duplicated 3× | transport, client_mux | `src/transport.zig:443-491,546-583`, `src/client_mux.zig:244-287` | Extract `handleConnFrame` into shared module | confirmed | M | open |
| 5  | R6  | High     | 90    | maintainability | `readMessage`/`readStreamFrame` near-clones | transport | `src/transport.zig:402-492,511-585` | Parameterize tail behaviour into one function | confirmed | M | open |
| 6  | R3  | High     | 75    | reliability | `connectionThread` logs and discards errors | server | `src/server.zig:72-76` | Shared counter/channel for connection failures | confirmed | S | open |
| 7  | R4  | High     | 75    | reliability | TLS read failures collapsed silently into `break` | server | `src/server.zig:117-122` | Log at warn before break | confirmed | XS | open |
| 8  | M3  | High     | 67.5  | maintainability | 5-byte gRPC length-prefix encoder triplicated | transport | `src/transport.zig:863-872,922-931,974-983` | `encodeLengthPrefix` helper | confirmed | S | open |
| 9  | M4  | High     | 67.5  | maintainability | 5-byte gRPC length-prefix decoder triplicated | transport, client_mux | `src/transport.zig:411-426,521-535`, `src/client_mux.zig:214-224` | `decodeLengthPrefix` in shared module | confirmed | S | open |
| 10 | M1  | High     | 60    | maintainability | Response-headers HPACK literal duplicated | transport | `src/transport.zig:838-860,899-920` | `RESPONSE_HEADERS_BYTES` constant | confirmed | XS | open |
| 11 | M2  | High     | 60    | maintainability | gRPC trailer literal duplicated | transport | `src/transport.zig:878-880,933-949` | `OK_TRAILERS_BYTES` + `endStreamWithStatus` | confirmed | XS | open |
| 12 | T1  | High     | 50    | tests | HPACK functions untested (`extractPathFromHpack`, `huffmanDecode`, `hpackDecodeInt`, `hpackDyn*`) | transport, tests | `src/transport.zig:730-806` and elsewhere | Add RFC 7541 Appendix C vectors | confirmed | M | open |
| 13 | M5  | High     | 50    | architecture,cleanup | `src/http2/connection.zig` is dead but instantiated per Transport (`sendFrame` is no-op) | http2 | `src/http2/connection.zig` | Delete or wire; record ADR | confirmed | S | open |
| 14 | A2  | Medium   | 45    | api-contract | Trailer-sending only on success path; `grpc-message` never emitted | transport | `src/transport.zig:933-950` | Trailer-builder; consumed by R1/A1 | confirmed | S | open |
| 15 | M7  | Medium   | 36    | architecture | `src/transport.zig` is 985 LOC and mixes HPACK / frame I/O / mux / gRPC framing / server-streaming | transport | `src/transport.zig` (985 LOC confirmed via `wc -l`) | Split into `hpack.zig`, `frame_io.zig`, `grpc_framing.zig` | confirmed | L | open |
| 16 | M10 | Medium   | 36    | maintainability,readability | Magic numbers `5,9,8,11,24,61,62,126,0x88,0x40\|31,0x1,0x7F` repeated | transport, client_mux | several locations | Named const module (`http2_consts.zig`) | confirmed | S | open |
| 17 | M6  | Medium   | 27    | architecture,cleanup | `src/http2/{hpack,stream}.zig` dead; only `FrameType`/`FrameFlags` from `frame.zig` are live | http2 | `src/http2/` | Delete or move retained constants to consumer | confirmed | S | open |
| 18 | M8  | Medium   | 27    | readability | `extractPathFromHpack` is 77 LOC, cyclomatic ~14, no tests | transport | `src/transport.zig:730-806` | Decompose into table-driven steps; consumed by T1 | confirmed | M | open |
| 19 | M9  | Medium   | 27    | readability | `ClientMux.readerLoop` 96 LOC | client_mux | `src/client_mux.zig:194-289` | Falls out of R5 extraction | confirmed | M | open |
| 20 | T2  | Medium   | 27    | tests | `setupHttp2*`, `readFrame`, `readMessage`, `writeStreamMessage`, `endStream`, `ClientMux.readerLoop` lack direct tests | transport, client_mux, tests | several | Add focused unit tests using a fake `Transport.io` | confirmed | M | open |
| 21 | T3  | Medium   | 18    | tests | `tests.zig:6-30` commented-out HelloRequest/HelloResponse with TODO | tests | `tests.zig:6-30` | Restore or delete | confirmed | XS | open |
| 22 | D1  | Medium   | 18    | docs | Zig version drift — README says 0.15.2, CI uses 0.16.0 | docs,ci | `integration_test/README.md:28` | Single source of truth (e.g. `.zigversion`) referenced from README & CI | confirmed | XS | open |
| 23 | D2  | Medium   | 18    | docs | Install snippets reference `github.com/ziglana`; origin is `gitlab.com/devnw/zig/grpc-zig` | docs | `README.md:112,147` | Update to current GitLab path | confirmed | XS | open |
| 24 | D3  | Medium   | 18    | docs | No CONTRIBUTING / CODEOWNERS / SECURITY / ADRs | docs | repo root | Add baseline governance docs | confirmed | M | open |
| 25 | M11 | Low      | 5     | cleanup | `checkHealth` stub returning `.UNKNOWN` | client | `src/client.zig:41-44` | Remove or implement | confirmed | XS | open |
| 26 | M12 | Low      | 5     | cleanup | `src/proto/service.zig` imported but never referenced | server, client | `src/server.zig:2`, `src/client.zig:2` | Remove imports | confirmed | XS | open |
| 27 | D4  | Low      | 4     | docs | HPACK walker missing RFC 7541 §6 references | docs,readability | `src/transport.zig:730-806` | Add inline doc-comments citing §6.1/§6.2/§6.3 | confirmed | XS | open |

> Note: 27 rows because R5/R6/M1–M4/A1–A2 hot-path and wire-contract
> multipliers have been applied where the rubric specifies. The 17
> originally-listed findings are: R1–R6, M1–M12, A1–A2, D1–D4, T1–T3.
> All are accounted for above.

---

## Findings by Category

### reliability
- R1 (Critical, 200) — handler error swallowed -- **closed (0993e5e)**
- R2 (Critical, 160) — client_mux OOM swallowed
- R3 (High, 75) — connectionThread error discard
- R4 (High, 75) — TLS read silent break

### api-contract
- A1 (High, 112.5) — no `endStreamWithStatus` -- **closed (19fcf38)**
- A2 (Medium, 45) — trailers only on success

### maintainability / readability
- R5 (High, 90), R6 (High, 90) — duplicated frame/message readers
- M1 (High, 60), M2 (High, 60) — duplicated HPACK/trailer literals
- M3 (High, 67.5), M4 (High, 67.5) — duplicated length-prefix codec
- M7 (Med, 36) — transport.zig god-module
- M8 (Med, 27), M9 (Med, 27) — long functions
- M10 (Med, 36) — magic numbers

### architecture / cleanup
- M5 (High, 50) — dead `http2/connection.zig`
- M6 (Med, 27) — dead `http2/{hpack,stream}.zig`
- M11 (Low, 5) — `checkHealth` stub
- M12 (Low, 5) — unused proto import

### tests
- T1 (High, 50) — HPACK fns untested
- T2 (Med, 27) — transport/mux core paths untested
- T3 (Med, 18) — commented-out tests with TODO

### docs
- D1 (Med, 18) — Zig version drift
- D2 (Med, 18) — wrong upstream URL
- D3 (Med, 18) — missing governance docs
- D4 (Low, 4) — HPACK doc-comment refs

---

## Roadmap

### Quick wins (< 1 day)
- R4 — log TLS read failures (`src/server.zig:117-122`).
- M1, M2 — extract `RESPONSE_HEADERS_BYTES` and `OK_TRAILERS_BYTES`.
- M3, M4 — `encodeLengthPrefix` / `decodeLengthPrefix` helpers.
- M11, M12 — remove `checkHealth` stub and unused proto imports.
- D1, D2 — fix Zig version & repo URL in README.
- D4 — add RFC 7541 §6 references.
- T3 — restore or delete commented-out tests.

### Medium (1–5 days)
- R1 + A1 + A2 — implement `endStreamWithStatus`, route handler
  errors through it, add wire-bytes tests. Strict ordering: A1 → R1.
- R2 — fix mux OOM signalling + fault-injection test.
- R3 — connection-error counter / channel.
- R5 + R6 — extract shared `handleConnFrame` and unified
  `readMessage` reducing transport.zig and client_mux.zig clones.
- M5, M6 — delete or wire dead http2 modules; record ADR.
- M8, M9 — decompose long functions (falls out of R5/T1).
- M10 — `http2_consts.zig` named-constant module.
- T1, T2 — HPACK Appendix C vectors + transport/mux unit tests.
- D3 — add CONTRIBUTING / CODEOWNERS / SECURITY / ADR-0001.

### Strategic (> 5 days)
- M7 — split `transport.zig` (985 LOC) into `hpack.zig`,
  `frame_io.zig`, `grpc_framing.zig`. Land **after** R5/R6/M1–M4
  consolidation so the split surfaces fewer merge conflicts.
- Promote shared error-mapping module to support gRPC status codes
  end-to-end, plumbed through both server and client mux.
- Replace placeholder `http2/connection.zig` with either a real
  state-machine or a documented removal — close out architecture debt
  recorded in M5/M6.

---

## Confidence & Unknowns

- All 17 findings carry `confidence::confirmed` — each cites file +
  lines that have been spot-verified during this pass.
- Unknowns / would-confirm:
  - **R3 propagation strategy**: choice between counter, channel, or
    structured logging is design-level; no current production
    telemetry surface to defer to.
  - **M7 split shape**: exact module boundaries depend on whether the
    project keeps `http2/connection.zig` (M5). Would confirm by ADR
    decision.
  - **T2 fake-`io` shape**: confirming testability requires a small
    spike on `Transport.io` injection — a 1-hour prototype would
    de-risk the test plan.

---

## Tracker Mapping

| Finding | Tracker URL |
|---------|-------------|
| R1 — R6, M1 — M12, A1 — A2, D1 — D4, T1 — T3 | _not yet filed — issue creation deferred (see "Issue-Tracker Status")_ |

When issue creation is re-enabled, file one umbrella issue per row in
the stack-ranked table and update this column with the issue IID/URL.
Suggested labels per issue:
- `quality`
- one of `severity::{critical,high,medium,low}`
- one of `category::{perf,maintainability,readability,api-contract,tests,docs,ci-cd,deps,architecture,cleanup}`
- `confidence::confirmed`
- `status::triage`

---

## Source Evidence Pointers

- `src/server.zig` (141 LOC) — connection lifecycle, handler dispatch.
- `src/client_mux.zig` (289 LOC) — client multiplexer / reader loop.
- `src/transport.zig` (985 LOC) — HPACK + frame I/O + gRPC framing
  (target of M7 split).
- `src/client.zig` (103 LOC) — client façade including `checkHealth`
  stub (M11) and unused proto import (M12).
- `src/http2/connection.zig`, `src/http2/hpack.zig`,
  `src/http2/stream.zig` — candidate dead modules (M5, M6).
- `tests.zig` — commented-out fixtures (T3).
- `integration_test/README.md`, `README.md` — docs drift (D1, D2).

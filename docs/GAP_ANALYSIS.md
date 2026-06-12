# Gap Analysis

Repository: `devnw/zig/grpc-zig`
Last sync: 2026-04-26 (gap-close pass)
Source of truth: GitLab issue tracker (`https://gitlab.com/devnw/zig/grpc-zig/-/issues`). This file mirrors open gaps; resolved entries live in `docs/GAP_ANALYSIS_RESOLVED.md`.

## Theme Summary

After the 2026-04-26 gap-close pass, four blockers have been retired (auth bypass, dropped metadata, single-handler dispatch, broken flow control). The remaining open gaps cluster on:

1. **HPACK / codec depth.** Static-table coverage and dynamic-table byte-bounded eviction still incomplete (GAP-0005). Knock-on effects on metadata-heavy traces and conformance fuzzing (GAP-0015).
2. **Feature surface advertised but not shipped.** Bidi streaming + interop coverage (GAP-0007, GAP-0014), health on the wire (GAP-0008), built-in TLS + ALPN (GAP-0009), gzip/encoding (GAP-0011), generic proto3 codec (GAP-0006), interop matrix breadth (GAP-0012), CI perf gating (GAP-0013), observability surface (GAP-0016).
3. **Verifier follow-ups from gap-close.** Both 2026-04-26 verifier carry-overs (`GAP-FU-001`, `GAP-FU-002`) are now closed; resolutions live in `docs/GAP_ANALYSIS_RESOLVED.md`.
4. **GAP-0018 RESOLVED (2026-06-12).** The benchmark single-call path failure was triaged and fixed as a cluster: a connection-thread stack overflow (segfault / remote DoS), a `readMessage` hang on trailer-only responses, single-call stream-id reuse, a `streamCall` stale-trailer bug, example handler-path mismatches, and a `--host localhost` DNS-parse failure. See `docs/GAP_ANALYSIS_RESOLVED.md`. A residual hostname-resolution limitation is now tracked as GAP-0019.

## Blockers for Phase 4 issue creation

- The GitLab tracker is now active (issues #2..#42 created during the audit; #2/#3/#4/#5/#13/#18/#20/#21/#24/#25 closed by this gap-close pass). All open gaps below mirror an open GitLab issue.
- `glab auth status` reported "Invalid token provided in configuration file" but write operations succeed -- treat the warning as cosmetic.
- 15 labels (`gap`, `type::*`, `category::*`) are present.

## Open Gaps

### GAP-0005: HPACK only parses :path; dynamic-table state shaky

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/6>
- **Category:** Correctness (HTTP/2 protocol)
- **Severity:** High
- **Requirement source:** RFC 7541; downstream of GAP-0010 / GAP-0015.
- **Current state (evidence):**
  - `src/http2/hpack.zig:10,15,21,25` -- `dynamic_table` exists but minimally populated.
  - `src/transport.zig` -- header parsing extracts only `:path` and (post GAP-0001) `authorization`.
  - No RFC 7541 §C vectors found in repo.
- **Why this is a gap:** Server still cannot read `grpc-timeout` or arbitrary custom metadata.
- **Impact/Risk:** Blocks general metadata flow (deadlines, tracing, custom headers).
- **Recommended fix:** Persist dynamic table per connection with byte-bounded eviction (also closes perf #31 / MW-6); implement static table lookup, dynamic insertion/eviction with size accounting, and Huffman coder. Validate against RFC 7541 §C.
- **Acceptance criteria:** All §C vectors decode; encoder/decoder roundtrip random sets; server exposes parsed metadata to handlers; ties into GAP-0015 fuzz harness.

### GAP-0006: No general proto3 codec

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/7>
- **Category:** Feature (codec)
- **Severity:** High
- **Requirement source:** Implicit in shipping a gRPC library.
- **Current state (evidence):**
  - `src/proto/service.zig` -- single-purpose plumbing only.
  - `grep -rn 'encodeVarint\|writeVarint\|zigzag' src/` -- no codec primitives.
- **Why this is a gap:** Users cannot define arbitrary `.proto` messages.
- **Impact/Risk:** Cross-stack interop with non-trivial schemas is impossible.
- **Recommended fix:** Implement varint, zigzag, fixed32/64, length-delimited reader/writer, and packed repeated encoding. Optional: codegen from `.proto`.
- **Acceptance criteria:** Encode/decode int32/int64/sint*/fixed*/string/bytes/repeated/message; round-trip random messages against Go reference; tests cover unknown-field preservation.

### GAP-0007: Streaming RPCs only partially work; CI exercises only unary

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/8>
- **Category:** Feature
- **Severity:** High
- **Requirement source:** README.md:14 ("Efficient bi-directional streaming").
- **Current state (evidence):**
  - `src/features/streaming.zig` -- only `MessageStream` buffer abstraction; no orchestrators.
  - `interop/scripts/run-matrix.sh` -- only unary `--message hello` pair.
  - `grep -n 'client_stream\|bidi\|server_stream' src/features/streaming.zig` -- no matches.
- **Why this is a gap:** README advertises bi-directional streaming; only server-streaming is partially present and untested in CI.
- **Impact/Risk:** Real-world services cannot ship; streaming bugs undetected.
- **Recommended fix:** Implement client-streaming and bidi orchestration with concurrent send/recv loops; wire into interop scripts (depends on GAP-0014).
- **Acceptance criteria:** Client-stream and bidi roundtrip against Go server; cancellation propagates; interop matrix exercises all four modes.

### GAP-0008: Health service unreachable over the wire

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/9>
- **Category:** Feature
- **Severity:** High
- **Requirement source:** README.md:16 ("Built-in health checking system").
- **Current state (evidence):**
  - `src/features/health.zig` -- service definition exists.
  - Now-fixed dispatch (GAP-0003 closed by `bf55446`) admits multi-handler registration; the health service still has no auto-registration path.
- **Why this is a gap:** Health service exists in code but is not auto-wired.
- **Impact/Risk:** Liveness probes via `grpc-health-probe` will fail by default.
- **Recommended fix:** With GAP-0003 done, add `Server.enableHealth()` that registers `grpc.health.v1.Health/Check` and `Watch`; expose API to set per-service serving status.
- **Acceptance criteria:** `grpc-health-probe -addr=...` succeeds; status changes reflected in `Watch` responses.

### GAP-0009: TLS BYO only; no built-in engine, ALPN, or cert pinning

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/10>
- **Category:** Feature (TLS)
- **Severity:** High
- **Requirement source:** README.md:12 ("Built-in JWT authentication and TLS support").
- **Current state (evidence):** No built-in TLS engine in `src/`; only abstract reader/writer surface; no h2 ALPN code.
- **Why this is a gap:** README claims built-in TLS but only a BYO surface ships.
- **Impact/Risk:** Production TLS deployments require custom glue; the marketing claim is overstated.
- **Recommended fix:** Provide default TLS implementation (`std.crypto.tls` if viable for target Zig version, or BoringSSL bindings); negotiate `h2` ALPN; document BYO surface as fallback.
- **Acceptance criteria:** Server accepts cert+key paths; client connects to `grpcs://` and verifies identity; ALPN negotiates `h2`; integration test with self-signed cert.

### GAP-0010: Hard-coded request headers; no custom metadata possible

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/11>
- **Category:** Correctness (codec)
- **Severity:** High
- **Requirement source:** gRPC spec for client-side metadata.
- **Current state (evidence):**
  - Partially closed by GAP-0002 (`cc2d9b7`): `writeRequestHeadersWithMetadata` now appends LIE-encoded metadata.
  - Still missing: name validation per gRPC spec (lowercase, ASCII or `-bin`); `grpc-timeout` plumbing into deadline machinery; base64-encode `-bin` headers.
- **Why this is a gap:** Encoder accepts arbitrary metadata, but the public API does not yet enforce gRPC name/value rules and deadlines are not honoured server-side.
- **Recommended fix:** Layer name validation on `writeRequestHeadersWithMetadata`; recognise `grpc-timeout` and propagate to handler context; auto-base64 `-bin` keys.
- **Acceptance criteria:** `grpc-timeout: 5S` round-trips and is honored server-side; `-bin` headers base64-encoded; metadata visible to handlers; invalid names rejected client-side.

### GAP-0011: Server hardcodes Algorithm.none; never decompresses gzip

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/12>
- **Category:** Correctness
- **Severity:** High
- **Requirement source:** gRPC spec for `grpc-encoding` / `grpc-accept-encoding`.
- **Current state (evidence):**
  - `src/server.zig` -- `compression_alg = .none` hard-coded.
  - `grep -rn 'grpc-encoding\|grpc-accept-encoding' src/` -- advertised, never honored.
- **Why this is a gap:** Server ignores wire-stated encoding.
- **Impact/Risk:** Cross-stack clients defaulting to gzip will deliver corrupted bodies.
- **Recommended fix:** Parse `grpc-encoding` from inbound HEADERS; decompress before handler dispatch; compress response per `grpc-accept-encoding`; set `grpc-encoding` response header.
- **Acceptance criteria:** Gzip request decompressed; gzip response emitted when supported; unsupported encoding returns UNIMPLEMENTED.

### GAP-0012: Cross-stack interop matrix only Go x Zig

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/14>
- **Category:** Feature (interop)
- **Severity:** Medium
- **Requirement source:** Implicit in shipping a cross-language protocol implementation.
- **Current state (evidence):**
  - `interop/scripts/run-matrix.sh:11-16` -- pairs limited to `go` and `zig`.
  - `interop/zig/`, `interop/go/` -- only two stacks present.
- **Why this is a gap:** Real-world clients run tonic, grpcio, grpc-java, etc.
- **Impact/Risk:** Subtle compatibility regressions with other implementations are undetected.
- **Recommended fix:** Add Rust (tonic) and Python (grpcio) interop containers; update `run-matrix.sh`; cap matrix runtime; mark expensive combinations as nightly.
- **Acceptance criteria:** Rust and Python pairs pass; CI required gating on at least one cross-pair.

### GAP-0013: Benchmark not wired to CI; harness sequential despite --clients

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/15>
- **Category:** Feature (observability)
- **Severity:** Medium
- **Requirement source:** Implicit in publishing benchmarks.
- **Current state (evidence):**
  - `scripts/run_benchmark.sh` -- present but no CI references.
  - `src/benchmark.zig` -- single-threaded loop despite `--clients` parsing.
- **Why this is a gap:** Numbers are unrepresentative; regressions land without notice.
- **Impact/Risk:** No perf gating in CI.
- **Recommended fix:** Parallelize harness; persist per-run JSON artifacts; add a perf-gate job comparing to a rolling baseline.
- **Acceptance criteria:** `--clients` scales under load; CI publishes JSON artifact; regression threshold enforced.

### GAP-0014: Streaming not exercised in interop matrix

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/16>
- **Category:** Test (interop)
- **Severity:** Medium
- **Requirement source:** gRPC interop test suite.
- **Current state (evidence):**
  - `interop/scripts/run-pair.sh` invoked with `--message hello` only.
  - `interop/scripts/run-matrix.sh` -- no streaming flag.
  - `interop/zig/client_main.zig` -- streaming flow not invoked.
- **Why this is a gap:** Once GAP-0007 lands, regressions in streaming will not be caught by CI.
- **Impact/Risk:** Streaming correctness regressions invisible.
- **Recommended fix:** Extend interop client/server to support `--mode unary|server|client|bidi`; iterate modes per pair in `run-matrix.sh`.
- **Acceptance criteria:** Matrix runs all four modes; CI summary reports per-mode results.

### GAP-0015: No HPACK/Huffman fuzz or RFC 7541 conformance tests

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/17>
- **Category:** Test (correctness)
- **Severity:** Medium
- **Requirement source:** RFC 7541 §C.
- **Current state (evidence):**
  - `src/hpack_varint_test.zig` -- focussed regression for I1 only (added by `9322f96`); not a §C suite.
  - No `std.testing.fuzz` harness yet.
  - `src/http2/hpack.zig` -- stub-quality dynamic-table handling (see GAP-0005).
- **Why this is a gap:** HPACK is the gateway for all metadata yet has no formal verification.
- **Impact/Risk:** Subtle bugs corrupt metadata; potential security implications (oversized integers, table-size attacks).
- **Recommended fix:** Add RFC 7541 §C deterministic tests; add `std.testing.fuzz` harness with adversarial corpus.
- **Acceptance criteria:** All §C vectors pass; fuzz harness runs in CI; adversarial inputs rejected without panic.

### GAP-0016: Only ad-hoc std.log; no metrics/traces surface

- **Issue:** <https://gitlab.com/devnw/zig/grpc-zig/-/issues/19>
- **Category:** Feature (observability)
- **Severity:** Low
- **Requirement source:** Operational requirement for production deployment.
- **Current state (evidence):**
  - `grep -rn 'std.log\.' src/` -- many sites, no abstraction.
  - No metrics or trace types in `src/`.
- **Why this is a gap:** SRE teams cannot wire to Prometheus/OpenTelemetry without forking.
- **Impact/Risk:** Production usability is poor.
- **Recommended fix:** Define `Logger` interface (vtable); minimal metrics surface (counter/histogram); optional tracing span API; default impl backed by `std.log` and counters.
- **Acceptance criteria:** Custom logger injectable; per-RPC metrics emitted; documented in README.

### GAP-0019: Client cannot connect by hostname (no DNS resolution) [NEW finding 2026-06-12]

- **Issue:** _not yet filed_ (recorded here for the next audit iteration)
- **Category:** Feature gap (client / transport)
- **Severity:** Medium
- **Requirement source:** Observed during GAP-0018 triage: `zig build benchmark --host localhost` failed in `GrpcClient.init` with `error.ParseFailed` before any request.
- **Current state (evidence):**
  - `GrpcClient.init`/`ClientMux.init` resolve the target via `std.Io.net.IpAddress.resolve`, which parses literal IPv4/IPv6 addresses only -- it does NOT perform DNS resolution. Passing a hostname (e.g. `localhost`, `example.com`) returns `error.ParseFailed`.
  - Verified: `--host 127.0.0.1` succeeds (5/5), `--host localhost` fails (5/5 ParseFailed). The `zig build benchmark` invocation was changed to `127.0.0.1` as a workaround (commit db78b15).
- **Why this is a gap:** The README and examples imply hostname connectivity ("localhost"); clients can currently only dial literal IPs. Real deployments target DNS names.
- **Recommended fix:** Add a resolver step (getaddrinfo / `std.net` name resolution) in the client connect path, or document the literal-IP-only limitation explicitly and provide a helper. Decide whether DNS belongs in the library or is the embedder's responsibility.
- **Acceptance criteria:** `GrpcClient.init(allocator, io, "localhost", port)` connects successfully, OR the limitation is explicitly documented with a sanctioned resolution helper; a test covers the chosen behavior.

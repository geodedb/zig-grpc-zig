# AppSec Review — grpc-zig @ e060433 (2026-06-11)

## 1. Scope & Assumptions

**Reviewed (first-party, HEAD `e060433`, working tree clean):**

- `src/` — `server.zig`, `client.zig`, `client_mux.zig`, `transport.zig` (1982 lines, the core), `compat.zig`, `observability.zig`, `observability_init.zig`, `benchmark.zig`
- `src/http2/` — `connection.zig`, `frame.zig`, `hpack.zig`, `stream.zig`
- `src/features/` — `auth.zig` (JWT HS256), `compression.zig`, `health.zig`, `streaming.zig`
- `build.zig`, `build.zig.zon`, `.gitlab-ci.yml`, `.pre-commit-config.yaml`, `scripts/detect_diamond_deps.py`, `scripts/install-zig.sh`, `README.md`, `docs/SECURITY_GAP_ANALYSIS.md`, `docs/GAP_ANALYSIS.md`
- Diff `ac7f771..HEAD` reviewed via `git log --stat` and full read of the changed modules (flow control, admission control, observability, client_mux, diamond-dep detector).

**Excluded:** vendored `zig-pkg/` zlib 1.3.1 source (per contract — supply-chain note only); Go/Python interop *clients* reviewed only for shell/network/secret hazards, not full audit.

**Trust model applied:** every byte off the socket is untrusted and **pre-authentication** — the gRPC auth gate (`server.zig:300`) runs only *after* `Transport.readMessage()` has fully parsed frames, decoded HPACK, and assembled a complete gRPC message. Therefore all of frame parsing, HPACK decode, flow-control accounting, and message assembly is reachable by an unauthenticated remote attacker speaking HTTP/2 (plaintext h2c; no TLS). Default bind is `0.0.0.0`.

**Assumptions:** the embedder runs the server as documented (no reverse-proxy/mTLS sidecar unless they add one). gRPC/HTTP/2 semantics per RFC 7540/7541 and the gRPC-over-HTTP/2 spec. The server was not executed or fuzzed; all findings are by code reading with `file:line` evidence.

## 2. Executive Summary

- **Q1 — Did any previously-closed finding (A1/A2/A3/M3/I1/I3) regress at HEAD? No.** All six fixes are intact and were re-read line-by-line: the server auth gate is wired into dispatch (`server.zig:300-322`), the client serializes `authorization` metadata (`client.zig:135-149` → `transport.zig:204-218`), JWT is a real RFC 7519 HS256 token with `timing_safe.eql` signature compare (`auth.zig:104-115, 178-192`), the HPACK varint decoder caps continuations and pre-checks shift width (`transport.zig:1515-1552`), and `SETTINGS_MAX_FRAME_SIZE` is enforced *before* payload allocation (`transport.zig:1048-1053`). Confidence: **High.**

- **Q2 — Are the open items still accurate, and are there NEW issues the prior review missed? Yes to both.** The prior open items (A5, I2, I5, I6, I7, M2, R2, O1, O2, S1, S3) remain accurate at `e060433`; M1 is now largely mitigated by i64-intermediate arithmetic and should be downgraded. **The most significant new finding is an unauthenticated memory-exhaustion DoS via unbounded inbound gRPC message assembly** (`transport.zig:1183-1218`): there is no maximum-message-size cap anywhere in the codebase, and the receive-side flow-control window is decremented-then-immediately-refilled (`transport.zig:800-827`) without ever *rejecting* DATA — so a peer that declares a 4 GiB gRPC length prefix and streams DATA frames drives `grpc_buf` to OOM. The prior review's R2 covered stream *count*, not message *size* — this is genuinely new. Two secondary new issues: a malicious peer can *raise* the inbound frame cap to 16 MiB via `SETTINGS_MAX_FRAME_SIZE` (`transport.zig:986-996`), partially eroding the I3 protection; and the README markets "Full Security … Built-in JWT authentication and TLS support" (`README.md:12`) which overstates the actual posture (no built-in TLS, plaintext default, `0.0.0.0` bind).

- **Q3 — Safe to ship as v0.1.x given documented limitations? Conditionally, with caveats.** The auth/crypto subsystem is now sound and the criticals from the prior review are genuinely closed. However, the library is **not safe to expose directly to untrusted networks** in its current form: no TLS, `0.0.0.0` default bind, and at least one unauthenticated pre-auth memory-DoS (NEW-1) plus a single-packet panic surface that is *mostly* closed but has residual gaps (I2/I5/I6). Shipping as a `0.1.x` *experimental* library is defensible **only if** the README's security claims are corrected and an explicit "deploy behind TLS/mTLS, do not expose h2c to the public internet" warning is added. See §7.

- **Overall risk:** no Critical confirmed at HEAD. One **High** (NEW-1 pre-auth memory DoS), several **Medium** (frame-cap raise, benchmark secret, HPACK/framing soundness gaps, bind/TLS defaults, misleading security marketing), and the usual Low/Info hardening items. Overall confidence **High** for the reviewed first-party scope.

## 3. Findings Table

| ID | Title | Severity | OWASP / CWE | Location | Status |
|----|-------|:--------:|-------------|----------|--------|
| NEW-1 | Unbounded inbound gRPC message assembly — no max-message cap, recv window never rejects | **High** | A10 / CWE-770, CWE-789 | `transport.zig:1183-1218`, `:800-827`, `:1305-1340` | Confirmed |
| NEW-2 | Peer can raise inbound `MAX_FRAME_SIZE` to 16 MiB, eroding I3 | **Medium** | A10 / CWE-770 | `transport.zig:986-996`, `:1048-1053` | Confirmed |
| NEW-3 | README overclaims "Full Security … built-in TLS"; no `SECURITY.md` | **Medium** | A06 / CWE-1059, CWE-319 | `README.md:12` | Confirmed |
| A5 | Hardcoded shared secret `"benchmark-secret-key"` ships in `src/` | **Medium** | A02 / CWE-798 | `benchmark.zig:15`, used `:78` | Confirmed (open) |
| I2 | HPACK Huffman table incomplete; missing groups + no EOS-in-body rejection | **Medium** | A05 / CWE-20 | `transport.zig:1442-1454`, `:1458-1493` | Confirmed (open) |
| I5 | `CONTINUATION` frames not reassembled; fall to `else→skip` | **Medium** | A10 / CWE-444 | `transport.zig:1278-1282` | Confirmed (open) |
| I6 | gRPC length-prefix vs DATA payload not validated against frame boundaries | **Low** | A10 / CWE-130 | `transport.zig:1208-1218`, `client_mux.zig:258-268` | Confirmed (open) |
| I7 | Stub HPACK decoder has OOB reads — latent (dead code) | **Low** | A05 / CWE-125 | `src/http2/hpack.zig:86-101` | Confirmed (latent) |
| M2 | `next_stream_id +%= 2` silently wraps → stream-id collision | **Low** | A10 / CWE-190 | `client_mux.zig:121` | Confirmed (open) |
| R2 | Advertised `MAX_CONCURRENT_STREAMS=100` never enforced | **Low** | A10 / CWE-770 | `transport.zig:688`; no enforcement | Confirmed (open) |
| O1 | Hardcoded `0.0.0.0` bind; no `bind_address` option | **Medium** | A05 / CWE-1327 | `server.zig:135` | Confirmed (open) |
| O2 | No built-in TLS / ALPN / cert pinning; BYO callback only | **Medium** | A04 / CWE-319 | `server.zig:45, 207-218` | Confirmed (open) |
| M1 | `@intCast` on attacker lengths | **Info** (downgraded) | A10 / CWE-681 | `transport.zig` (various) | Mitigated |
| S1 | CI security components' `allow_failure` default unverified | **Low** | A03 / CWE-1395 | `.gitlab-ci.yml:43-50` | Needs-verification |
| S3 | `main` branch protection not verifiable from repo | **Low** | A08 / CWE-353 | GitLab settings | Needs-verification |
| OBS-1 | Observability seam hardcoded `enabled=false` → no runtime security telemetry | **Info** | A09 / CWE-778 | `observability.zig:29`, `build.zig:11` | Confirmed (by design) |

## 4. Finding Details

### NEW-1 — Unbounded inbound gRPC message assembly (pre-auth memory DoS) — High

**Evidence.** `Transport.readMessage` (`transport.zig:1183-1218`) loops reading DATA frames and appends each payload into a heap `grpc_buf` (`:1196`). It reads the declared gRPC message length from the 5-byte prefix as a full `u32` (`:1209-1212`) and only returns once `grpc_buf.items.len >= 5 + msg_len` (`:1213`). There is **no upper bound** on `msg_len` and **no cap** on how large `grpc_buf` may grow — confirmed by `grep` finding no `max_message`/`4194304`/recv-size constant anywhere in `src/`. The receive-side flow-control accounting that should bound this is non-enforcing: `maybeRefillRecvWindow` (`:800-827`) does `conn_recv_window -|= consumed` (saturating, so it floors at 0 and cannot go negative) and then *immediately emits a WINDOW_UPDATE to refill back to 1 MiB* whenever it dips below half (`:804-811`). `readFrame` (`:1031-1061`) checks only the per-frame `max_frame_size`, never the cumulative connection window, before `allocator.alloc(u8, length)` (`:1053`). `readStreamFrame` (`:1305-1340`) has the identical pattern. The same unbounded `slot.data.appendSlice` exists client-side in `client_mux.zig:258-268`.

**Attack scenario (non-destructive).** An unauthenticated client completes the HTTP/2 preface + SETTINGS exchange, sends HEADERS, then sends a DATA frame whose first 5 bytes encode `msg_len = 0xFFFFFFFF` (~4 GiB), followed by a steady stream of `max_frame_size`-sized DATA frames. The server appends every frame to `grpc_buf`, auto-refilling the receive window after each, and never returns from `readMessage` until 4 GiB is buffered — exhausting memory and OOM-killing the process. Because the auth gate runs only *after* `readMessage` returns (`server.zig:234, 300`), `require_auth` provides no protection. With the admission cap defaulting to 1024 connections (`server.zig:74`), even a single connection per attacker is enough.

**Impact.** Unauthenticated remote memory-exhaustion DoS of any embedder's server. Single connection, low effort.

**Root cause.** Receive-side flow control is implemented for *liveness* (keep the peer sending) but not for *back-pressure/limits*; no application-level max-message size; the 5-byte gRPC length prefix is trusted without bound.

**Remediation.** (1) Add a `max_recv_message_bytes` config (gRPC's de-facto default is 4 MiB) and reject in `readMessage`/`readStreamFrame` when `msg_len` or `grpc_buf.items.len` exceeds it — emit `RST_STREAM(FLOW_CONTROL_ERROR)` or `endStreamWithStatus(…, 8 /*RESOURCE_EXHAUSTED*/)` and stop accumulating. (2) Make the receive window *enforcing*: do not auto-refill past a hard ceiling; if a stream/connection exceeds its credited window, treat it as `FLOW_CONTROL_ERROR` per RFC 7540 §6.9 instead of silently re-crediting. (3) Cap `grpc_buf` capacity up-front.

**Regression tests.** Add a transport test that feeds a DATA frame declaring `msg_len` above the cap and asserts the call returns `error.ResourceExhausted` (not OOM); a test that streams more bytes than the receive window credits and asserts a `FLOW_CONTROL_ERROR`/reject rather than continued buffering.

**References.** RFC 7540 §6.9 (flow control), gRPC `grpc.max_receive_message_length`, CWE-770, CWE-789, OWASP A10:2025.

---

### NEW-2 — Peer can raise inbound `MAX_FRAME_SIZE` to 16 MiB — Medium

**Evidence.** `applyPeerSettings` (`transport.zig:986-996`) accepts the peer's `SETTINGS_MAX_FRAME_SIZE` and stores it in `self.max_frame_size`, clamping only to the RFC range `[16384, 0xFFFFFF]`. `readFrame` enforces `checkFrameSize(length, self.max_frame_size)` (`:1048`) — i.e. the *inbound* allocation cap is the value the **peer** chose. So a malicious peer sends `SETTINGS_MAX_FRAME_SIZE = 0xFFFFFF` and the server will then `alloc(u8, length)` up to 16 MiB per frame (`:1053`).

**Attack scenario.** Peer raises the cap to 16 MiB, then sends a few 16 MiB DATA/HEADERS frames across the 1024 permitted connections → ~16 GiB of transient allocations. This is the exact amplification I3 was meant to prevent; the fix bounded it to the *default* 16384, but the setting is attacker-tunable upward. Combined with NEW-1 it compounds.

**Impact.** Pre-auth memory amplification (16384 → 16 MiB per frame, ~1000×).

**Root cause.** `SETTINGS_MAX_FRAME_SIZE` semantics were applied symmetrically (it governs frames *we send to the peer*, i.e. our outbound fragmentation), but here the same field is also used as our *inbound* acceptance cap. Per RFC 7540 §4.2/§6.5.2 the peer's `MAX_FRAME_SIZE` advertises what *the peer* will accept, not what *we* must accept; our inbound cap should be a value *we* choose and advertise, independent of the peer's.

**Remediation.** Separate the two: keep an `our_max_frame_size` (what we advertise and enforce on inbound, e.g. fixed 16384 or an embedder config) distinct from `peer_max_frame_size` (used only to size outbound fragments). Enforce `readFrame` against `our_max_frame_size`, never the peer's.

**Regression tests.** Send a peer SETTINGS raising MAX_FRAME_SIZE to 0xFFFFFF, then a 17 KiB frame; assert `FrameSizeError`/GOAWAY.

**References.** RFC 7540 §4.2, §6.5.2; CWE-770.

---

### NEW-3 — README overstates security posture; no `SECURITY.md` — Medium

**Evidence.** `README.md:12`: "🔐 **Full Security**: Built-in JWT authentication and TLS support." There is **no built-in TLS** — `server.zig:45` exposes only an optional `on_tls_accept: ?*const fn(...)` BYO callback and the default path is plaintext (`initServer`, `server.zig:219`). Default bind is `0.0.0.0` (`server.zig:135`). `grep` found no `SECURITY.md` at repo root. The README has no bind-interface, plaintext-h2c, or "do not expose to untrusted networks" warning.

**Impact.** Embedders who take "Full Security / TLS support" at face value will deploy an unauthenticated-by-default (`require_auth` defaults to `false`, `server.zig:53`), plaintext, public-bound server. This is a misconfiguration multiplier for every other finding here.

**Root cause.** Marketing copy ahead of implemented controls (GAP-0009 TLS is open).

**Remediation.** Correct the README to state TLS is *bring-your-own via callback* (no built-in engine/ALPN/pinning), document the `0.0.0.0` default and how to restrict it, document that `require_auth` defaults off, and add a `SECURITY.md` with the supported deployment posture and reporting process.

**References.** OWASP A06:2025; CIS Controls v8.1.2 (secure-design, documentation).

---

### A5 — Hardcoded secret `"benchmark-secret-key"` ships in `src/` — Medium (open)

**Evidence.** `benchmark.zig:15` `secret_key: []const u8 = "benchmark-secret-key"`, consumed at `:78` `client.setAuth(self.config.secret_key)`. `build.zig:107-117` builds and `installArtifact`s `grpc-benchmark`; `build.zig.zon:11-19` lists `src` in `.paths`, so the literal ships in the published package. The local `.pre-commit-config.yaml` has `detect-private-key` (`:39`) but no gitleaks hook (gitleaks runs in CI only, `.gitlab-ci.yml:46`), so the literal is not blocked pre-commit.

**Impact.** Any JWT ever signed with this key is forgeable by anyone reading the public repo. Low operational blast radius (it is a *benchmark* default, not wired into the server), but it is a real hardcoded credential in shipped library-package source.

**Remediation.** Remove the default; require an explicit `--secret`/env var for the benchmark; add a gitleaks/`*-secret-key` rule to the local pre-commit so regressions are caught before CI. Treat the string as compromised.

**References.** CWE-798; OWASP A02:2025.

---

### I2 / I5 / I6 — HPACK Huffman + framing soundness gaps — Medium / Medium / Low (open)

**Evidence.** The Huffman table (`transport.zig:1442-1454`) covers groups up to 19-bit only; `huffmanDecode` (`:1458-1493`) silently stops at `acc_bits > 19` (`:1489`) and never treats an EOS or unmapped symbol as an error — it just truncates output. `CONTINUATION` (frame type 0x9) is not handled in `readMessage`/`readStreamFrame`; it falls into the `else → free + continue` arm (`:1278-1282`), so a HEADERS block split across CONTINUATION frames is silently dropped rather than reassembled or rejected with `PROTOCOL_ERROR` (RFC 7540 §6.10). The gRPC 5-byte length prefix is read from `grpc_buf` (`:1209-1212`) without validating the compression-flag byte or that the prefix is consistent with frame boundaries; `client_mux.zig:258-268` simply drops messages where `payload.len < 5 + msg_len` (single-frame assumption).

**Impact.** I2: malformed/Huffman-encoded `:path`/`authorization` headers can be silently truncated, which—because the auth gate compares the *truncated* `authorization` against the HMAC—fails closed (safe) but can mis-route `:path` (correctness, and a theoretical authz-confusion surface if handlers ever trust a truncated path). I5: HEADERS bombs split across CONTINUATION are mishandled (smuggling/confusion class). I6: framing-confusion / message drop. None is a confirmed memory-safety break (the bounded scanner uses `@min` and `str_start + str_len > data.len` guards at `:1706, 1728`), so these are integrity/robustness issues, not OOB.

**Remediation.** Complete the RFC 7541 Appendix B Huffman table incl. EOS handling (EOS in body = decode error); implement CONTINUATION reassembly with the "must be contiguous on the same stream, END_HEADERS terminates" rule, else `PROTOCOL_ERROR`; validate the gRPC prefix (compression flag ∈ {0,1}, length consistency). Tie into the GAP-0015 fuzz harness.

**References.** RFC 7541 Appendix B; RFC 7540 §6.10; CWE-20, CWE-444, CWE-130.

---

### I7 — Stub HPACK decoder OOB reads (latent / dead code) — Low

**Evidence.** `src/http2/hpack.zig:86-101` (`decodeField`) indexes `encoded[1]`, `encoded[2 + name_len]`, `encoded[3 + name_len .. 3 + name_len + value_len]` with no length checks → OOB read on a short/crafted buffer. **Confirmed dead on the wire:** the only importer is `connection.zig:4`, and `http2.connection.Connection` is referenced live *only for its `PREFACE` constant* (`transport.zig:495, 1128`); the `Connection` struct (which owns the `hpack.Decoder`) is never instantiated in the server/client path — the live HPACK work is the bespoke scanner in `transport.zig`. So I7 is latent, not reachable today.

**Impact.** None today; a footgun if a future caller wires this decoder to untrusted input.

**Remediation.** Delete the stub `Encoder`/`Decoder` in `src/http2/hpack.zig` (and the `connection.zig` import of it), or add length guards. Removing dead parsing code shrinks the attack surface.

**References.** CWE-125.

---

### M2 / R2 — Stream-id wrap & unenforced concurrent-stream cap — Low (open)

**Evidence.** `client_mux.zig:121` `self.next_stream_id +%= 2` wraps silently after ~2³⁰ streams, after which a new call can collide with a live stream id in `self.streams` (`put` overwrites the slot). `transport.zig:688` advertises `MAX_CONCURRENT_STREAMS = 100` but nothing tracks or enforces an active-stream count on accept. (On the *server* the serial `readMessage` loop processes one stream at a time, so concurrent-stream exhaustion is naturally bounded to ~1 in-flight per connection — which is why R2 stays Low — but the advertised limit is cosmetic and a future concurrent dispatch would expose it.)

**Remediation.** M2: use `@addWithOverflow`/`+%=`-with-detection in `allocStreamId` and return an error (or open a fresh connection) on wrap. R2: track active streams per connection and refuse beyond the advertised cap with `REFUSED_STREAM`.

**References.** CWE-190, CWE-770.

---

### O1 / O2 — `0.0.0.0` default bind; no built-in TLS — Medium (open)

**Evidence.** `server.zig:135` `net.IpAddress.parseIp4("0.0.0.0", port)` unconditionally; no `bind_address` parameter on `init`. TLS is BYO only via `on_tls_accept` (`server.zig:45, 207-218`); no built-in engine/ALPN/cert-pinning (GAP-0009). Default transport is plaintext h2c.

**Impact.** Out-of-the-box the server is reachable on every interface, in cleartext, unauthenticated (`require_auth=false`). Trivially exploitable by deployment misconfiguration; combined with NEW-1/NEW-2 it means a public-facing default install is DoS-able and eavesdroppable.

**Remediation.** Add a `ServerConfig{ bind_address = "127.0.0.1", … }` and require an explicit opt-in for public binds; ship or document a vetted TLS path with ALPN `h2`. Until then, document loudly (see NEW-3).

**References.** CWE-1327, CWE-319; OWASP A04/A05:2025.

---

### M1 — `@intCast` truncations — Info (downgraded from prior High)

The prior review's M1 sites have been refactored: window arithmetic now uses `i64`/`i96` intermediates with explicit `maxInt`/`minInt` checks (`transport.zig:626-674`), the request-header length casts at `:169/177/185` are guarded by `len > 126` rejects (`:134-135`), and `@intCast(length)` at `:1048` is a widening `u24→u32`. No attacker-controlled narrowing `@intCast` that can be evidenced as exploitable remains. Recommend re-validating during the NEW-1 fix and then closing M1.

---

### S1 / S3 — CI gate & branch protection — Low (needs-verification)

`.gitlab-ci.yml:43-50` includes SAST, dependency-scanning, secret-detection, gitleaks, and SBOM components pinned at `@v1.7.1`, plus `release-semantic@v1.7.1`. Whether those catalog jobs default to `allow_failure: true` (which would make the security gates non-blocking) is **not determinable from this repo** — it lives in `gitlab.com/devnw/ci-catalog`. Branch protection on `main` is a GitLab project setting, also not in-repo. Both remain needs-verification. *Positive:* `scripts/install-zig.sh:45-46` verifies the Zig tarball with `sha256sum --check --strict` against the official `index.json`; `build.zig.zon:8` pins zlib by hash; `scripts/detect_diamond_deps.py` contains no `subprocess`/`eval`/network.

---

### OBS-1 — Observability seam permanently disabled — Info

`observability.zig:29` `pub const enabled: bool = false` and `build.zig:11` `with_otel = false` are both hardcoded (to work around a Zig 0.16 module-dedup diamond). Every span call (`server.zig:277-353`, `client.zig:117-155`, `client_mux.zig:201-232`) is a comptime no-op. Net security effect: no telemetry-leak risk, but also **no runtime security logging/alerting surface** (A09) beyond ad-hoc `std.log` — auth failures are logged (`server.zig:303, 311`) but there is no metrics/alerting path. Acceptable for a `0.1.x` library; note for operators.

## 5. Secure Design Notes (done well)

- **JWT/auth subsystem is now correct.** `auth.zig` implements a real RFC 7519 HS256 token (`:104-115`), verifies the signature with constant-time `crypto.timing_safe.eql` (`:190`) *before* parsing claims or checking time windows (`:174-219`) — a deliberate and correct ordering that avoids leaking "would-have-been-valid" through pre-signature errors. `alg`/`typ` are pinned to `HS256`/`JWT` (`:167-172`), defusing `alg:none` confusion. Length is checked before `@memcpy` of the provided signature (`:185-189`).
- **I3 fix is structurally sound** — the size check precedes allocation (`transport.zig:1048-1053`) and emits a GOAWAY with `FRAME_SIZE_ERROR`. (NEW-2 is about *which* limit is used, not the check itself.)
- **I1 fix is thorough** — continuation cap (`:1532`), pre-shift width check (`:1537, 1545`), `u32` shift counter, error return instead of panic, with dedicated regression tests (`build.zig:219-229`).
- **Admission control (R1)** — bounded `conn_sem` semaphore acquired before thread spawn with correct permit return on spawn-failure and on thread exit (`server.zig:171, 190, 200`); 512 KiB capped stacks reduce idle memory.
- **Flow-control credit timeout (GAP-FU-002)** — the `reserveSendCredit` futex wait has a real deadline and emits `RST_STREAM(FLOW_CONTROL_ERROR)` on timeout (`transport.zig:853-947`), defusing the slow-loris-pins-a-writer-thread case; the lost-wakeup race is handled by bumping `flow_epoch` under `flow_mutex`.
- **Allocator hygiene on error paths** is careful — `errdefer` on the window arrays and authority dup in every `init*` (`transport.zig:377-451`), explicit `free(payload)` before each `try writeFrame` in the frame handlers to avoid leak-on-error, and `errdefer tls_io.close_fn` to avoid leaking the TLS object (`:446`).
- **Supply chain:** zlib hash-pinned; Zig toolchain sha256-verified; CI runs SAST + dep-scan + gitleaks + SBOM; diamond-dep detector added; no dangerous shell in scripts.

## 6. Coverage Gaps & Questions

- **Not executed/fuzzed.** Findings are by code reading. NEW-1 and I2/I5/I6 would benefit from an HPACK/framing fuzz harness (GAP-0015) and a `wrk`-style OOM repro; recommended before relying on the NEW-1 fix.
- **CI catalog internals (S1).** Need to read `gitlab.com/devnw/ci-catalog/security-*@v1.7.1` to confirm the security jobs are blocking (`allow_failure: false`). Cannot determine from this repo.
- **Branch protection / signed commits (S3).** GitLab project settings — verify `main` requires MR + green pipeline, no force-push.
- **zlib 1.3.1 (excluded).** No known critical CVE in 1.3.1 as of the knowledge cutoff, but no advisory lookup was run against the live feed; recommend a `trivy`/OSV check in CI (the SBOM-scan component may already do this — tie to S1).
- **Interop Go/Python harnesses** were scanned only for shell/secret/network hazards, not fully audited; they are test-only and not shipped in the package `.paths`.
- **`maybeRefillRecvWindow` arithmetic** assumes `consumed ≤ max_frame_size`; once NEW-1/NEW-2 are fixed, re-confirm the `@intCast(consumed)` at `:803/817` cannot be driven negative.

## 7. Prioritized Next Actions

1. **Fix NEW-1 (High):** add a `max_recv_message_bytes` cap (default 4 MiB) enforced in `readMessage`/`readStreamFrame`/`client_mux` DATA handling, and make the receive window *enforcing* (reject, don't auto-refill past a ceiling). Add the two regression tests in §4. This is the gating item for "safe to expose."
2. **Fix NEW-2 (Medium):** decouple inbound frame-size enforcement from the peer-advertised `MAX_FRAME_SIZE`; enforce `readFrame` against an `our_max_frame_size` we control.
3. **Correct NEW-3 (Medium):** rewrite the README security section (TLS is BYO, plaintext default, `0.0.0.0` default, `require_auth` defaults off), add `SECURITY.md`. Cheap, high-leverage — stops misconfiguration.
4. **Close A5 (Medium):** remove the hardcoded benchmark secret; add a local gitleaks pre-commit hook.
5. **Harden defaults (O1/O2):** add `bind_address` config defaulting to `127.0.0.1`; document/ship a vetted TLS path.
6. **Codec soundness (I2/I5/I6) + delete dead stub (I7):** complete Huffman/EOS handling, implement/reject CONTINUATION, validate the gRPC prefix; remove `src/http2/hpack.zig`'s unreachable decoder. Build the GAP-0015 fuzz harness to lock these.
7. **Robustness (M2/R2):** wrap-detect stream ids; enforce the advertised concurrent-stream cap.
8. **Verify CI/governance (S1/S3):** confirm security jobs are blocking and `main` is protected; re-validate M1 closed after the NEW-1 work.

**Shipping recommendation (Q3):** acceptable to tag `v0.1.x` as an **experimental** library *after* items 1–3, provided the package is documented as "not for direct exposure to untrusted networks; deploy behind TLS/mTLS termination." Do not market it as production-ready transport security until O2 (built-in TLS) and the codec-soundness items land.

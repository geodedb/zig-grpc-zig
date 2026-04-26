# Security Gap Analysis — grpc-zig

> Last updated: 2026-04-26 (post gap-close: 5 closed -- A1, A2, A3, M3, I1, I3)
> Scope: full repository (`src/`, `build.zig`, `.gitlab-ci.yml`) at HEAD `ac7f771`.

> **Closed in this pass (see `docs/GAP_ANALYSIS_RESOLVED.md`):**
> - **A1** (Critical, 30) -- AuthN never invoked on dispatch -- `51a5924` -- closed GitLab #2
> - **A2** (Critical, 24) -- Client never serializes authorization metadata -- `cc2d9b7` -- closed GitLab #3
> - **A3** (Critical, 30) -- broken JWT generate/verify -- `5ec22b8` (also closes M3)
> - **M3** (Medium, 6) -- non-constant-time HMAC compare -- `5ec22b8`
> - **I1** (Critical, 18) -- HPACK varint shift overflow -- `9322f96`
> - **I3** (High, 18) -- SETTINGS_MAX_FRAME_SIZE not enforced -- `8919308`
> Source: Phase 3 adversarial security review (auth, transport/HPACK, memory, resource, ops, supply-chain).
> Audience: maintainers and embedders. Treat as security-sensitive material until criticals are patched.

---

## 0. Immediate Action Items (READ FIRST)

These are gating actions. Each one assumes that the released `main` branch is in scope for any consumer who depends on this library today.

1. **Treat `"benchmark-secret-key"` as compromised.** The string lives in *library* code at `src/benchmark.zig:15` (default field of `BenchmarkConfig.secret_key`), not in an example/demo file. Anything that ever signed JWTs with that key is forgeable by anyone who has read the source — which, since the repo is public on GitLab, is "everyone." Rotate any operational secret that may have collided with it; never re-use that string. Recommended fix: remove the default (require an explicit secret), and document key sourcing.

2. **Publish a security advisory: `Authentication.requireAuth` does not enforce auth on the wire.** Three independent failure modes compound to a total auth bypass on any released version:
   - Server dispatch never invokes `auth.verifyToken` (`src/server.zig:55-140`, dispatch at `:132-138`);
   - Client never serializes `authorization` metadata into HEADERS (`src/client.zig:81-96`, transport HEADERS builder at `src/transport.zig:33-96`);
   - Even if both wired up, `verifyToken` is broken: it compares the raw `signature` segment to the binary HMAC bytes with `std.mem.eql`, but `generateToken` produces no signature segment at all — the format is `"HS256.JWT.{sub}.{exp}.{iat}"`, so `parts.next()` for "signature" returns the decimal `iat` string. Recommend embedders gate at a reverse proxy / mTLS sidecar until fixed.

3. **Yank or pin any tagged release that ships `Server` with `requireAuth`/`Auth.init`.** The README markets JWT auth as "built-in"; consumers who took that at face value are unauthenticated in production. If no release tags exist yet, add a `SECURITY.md` warning in the README before tagging.

4. **Stop binding `0.0.0.0` by default.** `src/server.zig:32` calls `net.IpAddress.parseIp4("0.0.0.0", port)` unconditionally. Minimum: document this loudly in the README (current README does not mention the bind interface). Ideal: accept a bind-address parameter on `GrpcServer.init`, default to `127.0.0.1`, and require a deliberate opt-in for public binds.

---

## 1. Stats

| Severity | Count | SLA |
|---------:|:-----:|:----|
| Critical | 4     | 7 days  |
| High     | 6     | 30 days |
| Medium   | 5     | 90 days |
| Low      | 3     | 180 days |
| **Total** | **18** | |

Open GitLab issues already filed (public — see "Tracker State" §6): 3.

---

## 2. Top 5 by Risk Score (with Exploit Sketch)

`Risk = likelihood × impact × auth_required_factor`
likelihood: Unauth-external=4, Authenticated=3, Network-MitM=2, Operator=1
auth_required_factor: 1.5 if no auth needed, 1.0 otherwise

| Rank | ID | Finding | L | I | Factor | Risk | Exploit Sketch |
|------|----|---------|---|---|--------|------|----------------|
| 1 | A1 | AuthN never invoked on dispatch path | 4 | 5 | 1.5 | **30** | `nc server 50051` → speak HTTP/2 preface → send any HEADERS+DATA → handler runs. No token presented, no token checked. |
| 2 | A3 | `generateToken` produces no signature; `verifyToken` compares HMAC bytes to decimal `iat` | 4 | 5 | 1.5 | **30** | Even *if* A1 were fixed, attacker crafts `"HS256.JWT.alice.9999999999.1700000000"` — `parts.next()` for "signature" yields `"1700000000"`. `std.mem.eql(u8, "1700000000", &<32-byte HMAC>)` is always false; the only "valid" path is to brute-force a collision with the binary HMAC, which any attacker-chosen iat trivially fails — meaning **all tokens are rejected** as well. The auth subsystem is unusable in either direction; the server-side check is decorative. |
| 3 | A2 | Client never sends `authorization` metadata | 4 | 4 | 1.5 | **24** | Even when a caller calls `client.setAuth(...)`, `transport.writeRequestHeaders` accepts no metadata parameter. The token built at `client.zig:87` is dropped on the floor. |
| 4 | I1 | HPACK `hpackDecodeInt` shift-counter overflow | 4 | 3 | 1.5 | **18** | Send a HEADERS frame whose first integer field has 11+ continuation bytes (each 0x80 plus a final non-continuation). After ~9 iterations `m` reaches its max for `Log2Int(usize)` (u6 on 64-bit) and `m += 7` panics in safe builds → connection thread crash → DoS. Pre-auth, single packet. |
| 5 | I3 | `SETTINGS_MAX_FRAME_SIZE` not enforced | 4 | 3 | 1.5 | **18** | Send a 16 MiB DATA frame. Server reads `length` from frame header (`u24`, up to 16 777 215) and unconditionally `self.allocator.alloc(u8, length)` at `src/transport.zig:332`. A handful of connections from one attacker exhausts memory; per-connection dedicated thread (R1) compounds it. |

---

## 3. Full Findings by Category

### 3.1 Authentication (5)

| ID  | Sev | Risk | Finding | Evidence | CWE / OWASP | Status |
|-----|:---:|:----:|---------|----------|-------------|--------|
| A1 | Critical | 30 | AuthN never invoked on dispatch path | `src/server.zig:55-140`, dispatch at `:132-138` | CWE-306 / OWASP A07:2021 | **closed (51a5924, 2026-04-26)** |
| A2 | Critical | 24 | Client never serializes `authorization` metadata | `src/client.zig:81-96`, `src/transport.zig:33-96` | CWE-287 / OWASP A07:2021 | **closed (cc2d9b7, 2026-04-26)** |
| A3 | Critical | 30 | `generateToken` emits no signature; `verifyToken` compares HMAC bytes to decimal `iat` | `src/features/auth.zig:33-66` | CWE-347 / OWASP A02:2021 | **closed (5ec22b8, 2026-04-26)** |
| A4 | High     | 12 | Single-handler dispatch — `:path` ignored, `handlers.items[0]` always | `src/server.zig:131-138`; `getMethodPath` exists at `src/transport.zig:587` but is unread | CWE-863 | **closed (bf55446, 2026-04-26)** |
| A5 | High     | 18 | Hardcoded shared secret in library code | `src/benchmark.zig:15` (`secret_key: []const u8 = "benchmark-secret-key"`) | CWE-798 | open |

### 3.2 Input Parsing / HTTP-2 / HPACK (7)

| ID  | Sev | Risk | Finding | Evidence | CWE / OWASP | Status |
|-----|:---:|:----:|---------|----------|-------------|--------|
| I1 | Critical | 18 | HPACK integer-decoder shift-counter overflow | `src/transport.zig:691-707` (`m: std.math.Log2Int(usize)` += 7 unbounded) | CWE-190 | **closed (9322f96, 2026-04-26)** |
| I2 | High | 12 | Huffman table missing 20-, 21-, 22-, 23-, 24-, 25-, 26-, 27-, 28-bit, 30-bit, and EOS groups | `src/transport.zig:652-687` | CWE-117 | open |
| I3 | High | 18 | `SETTINGS_MAX_FRAME_SIZE` not enforced; `payload = alloc(u8, length)` at u24 width | `src/transport.zig:332`, settings handler `:443-455` is no-op | CWE-770 | **closed (8919308, 2026-04-26)** |
| I4 | High | 12 | `WINDOW_UPDATE` accepted but never honored — no flow control | `src/transport.zig:456-460` | CWE-770 | **closed (efd9ef6, 2026-04-26)** |
| I5 | High | 12 | `CONTINUATION` frames silently fall to the `else→skip` arm; no header reassembly | `src/transport.zig:485-489` | CWE-444 | open |
| I6 | High | 12 | Truncated DATA payloads return the buffer including the 5-byte gRPC prefix as message — fallback at `:429-431` | `src/transport.zig:418-431` | CWE-130 | open |
| I7 | Medium-latent | 6 | `hpack.zig` stub OOB on `encoded[1]`/`encoded[2+name_len]` if length under-runs; only safe today because that decoder is dead code | `src/http2/hpack.zig:86-101` | CWE-125 | open |

### 3.3 Memory Safety (3)

| ID  | Sev | Risk | Finding | Evidence | CWE | Status |
|-----|:---:|:----:|---------|----------|-----|--------|
| M1 | High | 12 | `@intCast` truncations on attacker-controlled lengths/offsets | `src/transport.zig:355, 863, 922, 974` | CWE-681 | open |
| M2 | Medium | 6 | `next_stream_id: u31` advanced by `+%= 2` — silently wraps after ~1.07 B streams; subsequent stream IDs collide with live ones | `src/client_mux.zig:120` | CWE-190 / CWE-694 | open |
| M3 | Medium | 6 | Non-constant-time `std.mem.eql` for HMAC compare (theoretical until A3 is fixed) | `src/features/auth.zig:49` | CWE-208 | **closed (5ec22b8 via timing_safe.eql, 2026-04-26)** |

### 3.4 Resource Exhaustion (2)

| ID  | Sev | Risk | Finding | Evidence | CWE | Status |
|-----|:---:|:----:|---------|----------|-----|--------|
| R1 | High | 18 | Thread-per-connection unbounded; no rate-limit, no max-conns | `src/server.zig:55-69` | CWE-770 | **closed (ac7f771 admission cap, 2026-04-26)** |
| R2 | Medium | 6 | No per-connection stream cap (advertised `MAX_CONCURRENT_STREAMS` not enforced) | `src/transport.zig:443-455`, server-side | CWE-770 | open (server now advertises 100 via efd9ef6 but doesn't enforce on accept) |

### 3.5 Operational Defaults (3)

| ID  | Sev | Risk | Finding | Evidence | CWE |
|-----|:---:|:----:|---------|----------|-----|
| O1 | High | 18 | Hardcoded `0.0.0.0` bind in server constructor — no opt-in | `src/server.zig:32` | CWE-1327 |
| O2 | Medium | 6 | TLS optional via `on_tls_accept` callback only — no built-in TLS, no ALPN, no cert pinning, no docs | `src/server.zig:29, 79-94` | CWE-319 |
| O3 | Low | 2 | `-fno-sanitize=undefined` scoped to vendored zlib — *acceptable*; flagged for transparency, no action required | `build.zig:46` | — |

### 3.6 Supply Chain / CI (3)

| ID  | Sev | Risk | Finding | Evidence | Notes |
|-----|:---:|:----:|---------|----------|-------|
| S1 | Medium | 6 | SAST/dep-scan/SBOM components from `gitlab.com/devnw/ci-catalog` may internally `allow_failure: true` (catalog default) — *unverified* | `.gitlab-ci.yml:43-50` | Need to inspect catalog v1.7.1 source to confirm; if true, security gates do not block MR. |
| S2 | Low | 2 | Dependency pinning unverified | `build.zig.zon` | Confirm hashes are pinned and `--system-package-mode` constraints are documented. |
| S3 | Low | 2 | Branch protection on `main` not verified | GitLab settings | Confirm push, force-push, and direct-merge are restricted; require MR + pipeline pass. |

---

## 4. Prioritized Fix Order (8 steps)

The order minimizes blast radius first, then closes wire-level vulnerabilities, then resource and ops hardening.

1. **Auth bus end-to-end** (closes A1, A2, A3, A4 partially)
   - Plumb a `metadata: std.StringHashMapUnmanaged([]const u8)` parameter through `transport.writeRequestHeaders` and into HPACK encoding.
   - Server-side: extract `authorization` from inbound HEADERS via the existing `extractPathFromHpack` path generalized to capture all literal headers; pass into a new `Authenticator` interceptor that runs *before* `handler.handler_fn`.
   - Rewrite `generateToken` to emit a true `header.payload.signature` JWT (HS256 over base64url(header) + "." + base64url(payload)); rewrite `verifyToken` to base64url-decode the signature segment, recompute, and compare with `std.crypto.utils.timingSafeEql` (closes M3 too).
   - Add table-driven roundtrip tests: missing token → status 16; invalid token → status 16; valid token → handler invoked.

2. **Method dispatch by `:path`** (closes A4)
   - Replace `handlers: ArrayList(Handler)` with `handlers: StringHashMapUnmanaged(Handler)` keyed on `/Service/Method`.
   - Unknown method → trailers with `grpc-status: 12 UNIMPLEMENTED`.
   - Tests: register two services, assert each routes to its own handler; bogus path returns 12.

3. **Remove the hardcoded benchmark secret** (closes A5)
   - Drop the `secret_key` default from `BenchmarkConfig`. Make it required at the call site; document key sourcing (env var, file, vault). Add a CI gitleaks rule (already pulled in via `security-secrets` component) to fail on any literal that matches `*-secret-key`.

4. **HPACK decoder hardening** (closes I1, I2, I7)
   - In `hpackDecodeInt`, cap `m` at `@bitSizeOf(usize) - 7` and return error on overflow rather than wrapping/panicking.
   - Backfill the Huffman groups in `huff_groups` to cover the full RFC 7541 Appendix B table (20-30 bit and EOS); EOS in body must be a decode error.
   - Replace the stub decoder in `src/http2/hpack.zig` or remove it; if removed, ensure no module imports it.

5. **Frame size + flow control** (closes I3, I4, I5, I6, R2)
   - Track and enforce peer-advertised `SETTINGS_MAX_FRAME_SIZE`; reject frames with `FRAME_SIZE_ERROR` (HTTP/2 §6.5.2).
   - Implement `WINDOW_UPDATE` accounting; refuse to send more than the advertised window; surface `FLOW_CONTROL_ERROR` on overrun.
   - Implement `CONTINUATION` reassembly (HEADERS+CONTINUATION must be contiguous on the same stream); reject otherwise with `PROTOCOL_ERROR`.
   - Validate the gRPC 5-byte length prefix against payload length; on mismatch, return `INTERNAL` rather than the payload-as-message fallback.
   - Enforce server-advertised `MAX_CONCURRENT_STREAMS`; refuse new streams beyond the limit.

6. **Bounded concurrency + bind discipline** (closes R1, O1)
   - Introduce a `ServerConfig` with `bind_address` (default `"127.0.0.1"`), `max_connections`, `max_concurrent_streams_per_conn`, `accept_timeout_ms`.
   - Replace the unbounded accept loop with a semaphore on `max_connections`; reject new connections with TCP RST when full.
   - Document the public-bind opt-in path in README.

7. **Memory-safety audit pass** (closes M1, M2)
   - Replace each `@intCast` of an attacker-controlled length with a checked `std.math.cast` (return error on overflow).
   - In `client_mux.allocStreamId`, use `+%=` to detect wrap and return an error (or open a new connection); never silently reuse.

8. **CI/supply-chain verification** (closes S1, S2, S3)
   - Inspect `gitlab.com/devnw/ci-catalog/security-*@v1.7.1` to confirm whether jobs `allow_failure: true` by default. If yes, override locally (`allow_failure: false`) and surface security-job results as required pipeline status.
   - Verify `build.zig.zon` lockfile pins each dependency by SHA-256.
   - Verify branch-protection on `main`: no force push, MR required, pipeline-success gate, signed commits encouraged.

---

## 5. Tracker State

### 5.1 Existing GitLab issues (already public)

| Issue | Title | Maps to | Notes |
|-------|-------|---------|-------|
| [#2](https://gitlab.com/devnw/zig/grpc-zig/-/issues/2)  | GAP-0001: Server accepts every RPC unauthenticated | A1 | Public. No `confidential` flag. |
| [#3](https://gitlab.com/devnw/zig/grpc-zig/-/issues/3)  | GAP-0002: Per-RPC authorization metadata silently dropped | A2 | Public. |
| [#4](https://gitlab.com/devnw/zig/grpc-zig/-/issues/4)  | GAP-0003: Server always invokes `handlers.items[0]` | A4 | Public. |

These three already disclose the high-level auth-bypass shape publicly. Marking subsequent issues confidential would not undo that disclosure. Fix-and-release is the only effective control.

### 5.2 Findings NOT filed as issues (deliberate)

The following Critical/High findings are **not** filed as new issues, per the Phase 1 strategy ("do NOT create open issues that broadcast unpatched vulnerabilities") combined with the Phase 1 caveat that the GitLab tracker's confidential-issue policy is unverified for this project:

| ID | Severity | Rationale for doc-only |
|----|:--------:|------------------------|
| A3 | Critical | Exact exploit path (HMAC-vs-iat compare) is novel detail beyond what #2/#3 disclose; keep private until fix lands. |
| A5 | High     | Secret value would be reflected in issue text; rotation/revocation note here is the safer surface. |
| I1 | Critical | Pre-auth, single-packet panic-DoS — lowest-effort exploit on the list; keep details private. |
| I2 | High     | Truncates HPACK soundness; pairs with I1 to widen attack surface. |
| I3 | High     | Pre-auth memory-DoS; pairs with R1. |
| I4 | High     | Wire-level protocol gap. |
| I5 | High     | Wire-level protocol gap. |
| I6 | High     | Decode-confusion path. |
| M1 | High     | Memory-safety footguns. |
| O1 | High     | Trivially exploitable via deployment misconfiguration. |
| R1 | High     | Trivial DoS. |

All remaining Medium/Low items (I7, M2, M3, R2, O2, O3, S1, S2, S3) are tracker-eligible but withheld here as a single batch — recommend the maintainer file them after the Critical/High fixes land, so they do not bury the urgent work.

### 5.3 Operational note on glab access

`glab auth status` reports `Logged in to gitlab.com as benjiv` but also `Invalid token provided in configuration file`. Read APIs (issue/label list, `repo view`) work; write was not exercised for new issues by this audit. If the maintainer wants the Medium/Low items filed automatically, refresh the glab token first (`glab auth login --hostname gitlab.com`) and re-run the tracking phase.

---

## 6. Blockers for Phase 4 (Tracking)

Two blockers prevent automated issue creation for the Critical/High items:

1. **glab write-token validity** — `glab auth status` flags an invalid token. Read works; write must be probed before bulk creation. Action: `glab auth login` to refresh, then `glab issue create --title "test-probe" --description "delete me" --confidential` and immediately delete; only proceed if the round-trip succeeds.

2. **Confidential-issue policy unverified** — GitLab supports `--confidential` per-issue (the flag exists in `glab issue create`), but project-level confidentiality is on the `Owner/Maintainer` group permission set. Confirm that:
   - non-members cannot view confidential issues on this public project (default GitLab behavior, but the Reporter role *can* see confidential issues — verify the Reporter membership of the `devnw` group is acceptable);
   - the existing public issues (#2, #3, #4) are intentionally public, not an oversight (consider converting them to confidential if the threat model permits — but note that prior cache/RSS may have already mirrored them).

3. **Disclosure decision** — for each Critical finding documented here, the maintainer should choose:
   - silently fix, then publish a CVE/advisory after release;
   - file a confidential issue immediately, fix, then disclose;
   - or coordinate with downstream embedders before broadcasting.

This document defaults to *silently fix* for items not already in the public tracker.

---

## 7. CWE / OWASP Reference Index

- CWE-117 Improper Output Neutralization for Logs — I2
- CWE-125 Out-of-bounds Read — I7
- CWE-130 Improper Handling of Length Parameter Inconsistency — I6
- CWE-190 Integer Overflow — I1, M2
- CWE-208 Observable Timing Discrepancy — M3
- CWE-287 Improper Authentication — A2
- CWE-306 Missing Authentication for Critical Function — A1
- CWE-319 Cleartext Transmission — O2
- CWE-347 Improper Verification of Cryptographic Signature — A3
- CWE-444 HTTP Request Smuggling / Frame Confusion — I5
- CWE-681 Incorrect Conversion between Numeric Types — M1
- CWE-694 Use of Multiple Resources with Duplicate Identifier — M2
- CWE-770 Allocation of Resources Without Limits or Throttling — I3, I4, R1, R2
- CWE-798 Use of Hard-coded Credentials — A5
- CWE-863 Incorrect Authorization — A4
- CWE-1327 Binding to an Unrestricted IP Address — O1
- OWASP A02:2021 Cryptographic Failures — A3
- OWASP A07:2021 Identification & Authentication Failures — A1, A2

---

## Appendix A: Risk-Score Worksheet

| ID | likelihood | impact | factor | risk |
|----|:----------:|:------:|:------:|:----:|
| A1 | 4 | 5 | 1.5 | 30 |
| A2 | 4 | 4 | 1.5 | 24 |
| A3 | 4 | 5 | 1.5 | 30 |
| A4 | 3 | 4 | 1.0 | 12 |
| A5 | 4 | 3 | 1.5 | 18 |
| I1 | 4 | 3 | 1.5 | 18 |
| I2 | 3 | 4 | 1.0 | 12 |
| I3 | 4 | 3 | 1.5 | 18 |
| I4 | 3 | 4 | 1.0 | 12 |
| I5 | 3 | 4 | 1.0 | 12 |
| I6 | 3 | 4 | 1.0 | 12 |
| I7 | 2 | 3 | 1.0 |  6 |
| M1 | 3 | 4 | 1.0 | 12 |
| M2 | 2 | 3 | 1.0 |  6 |
| M3 | 2 | 3 | 1.0 |  6 |
| R1 | 4 | 3 | 1.5 | 18 |
| R2 | 2 | 3 | 1.0 |  6 |
| O1 | 4 | 3 | 1.5 | 18 |
| O2 | 2 | 3 | 1.0 |  6 |
| O3 | 1 | 2 | 1.0 |  2 |
| S1 | 2 | 3 | 1.0 |  6 |
| S2 | 1 | 2 | 1.0 |  2 |
| S3 | 1 | 2 | 1.0 |  2 |

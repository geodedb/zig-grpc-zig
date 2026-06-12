# Performance Gap Analysis — grpc-zig

Last updated: 2026-06-11 (audit-fix pass: BH-1, BH-4, BH-5, AG-5, NW-5, BH-7 closed; AG-3 won't-fix)
Branch: main @ ac7f771 (closures landed on `fix/audit-2026-06-11`)

> **Closed in 2026-06-11 audit-fix pass (branch `fix/audit-2026-06-11`; see `docs/GAP_ANALYSIS_RESOLVED.md`):**
>
> - **BH-1 (P0, 24)** -- bench workers run sequentially; now parallel -- `5a03dc4` -- closed GitLab #22
> - **BH-4 (P0, 32)** -- bench JSON to stderr; now stdout -- `5a03dc4` -- closed GitLab #23
> - **BH-5 (P3, 4)** -- printUsage missing trailing newlines -- `5a03dc4` -- closed GitLab #42
> - **AG-5 (P3, 4)** -- redundant 256-byte last_method memset; field dropped -- `5a03dc4` -- closed GitLab #41
> - **NW-5 (P1, 20)** -- TCP_NODELAY/keepalive on accepted sockets -- `7b810a4` -- closed GitLab #32
> - **BH-7 (P1, 15)** -- compat.nanoTimestamp verified monotonic ns-grade -- no code needed -- closed GitLab #34
> - **AG-3 (P3, 4)** -- extractPathFromHpack iterates past `:path` -- **won't-fix** (full iteration required to keep HPACK dynamic table consistent) -- closed GitLab #40
>
> **Closed in the 2026-04-26 gap-close pass (see `docs/GAP_ANALYSIS_RESOLVED.md`):**
>
> - **NW-1+NW-2+NW-3 (P0, 64)** -- HTTP/2 flow control -- `efd9ef6` -- closed GitLab #13
> - **CC-1 (P0, 32)** -- unbounded thread-per-conn -- `ac7f771` -- closed GitLab #20
> - **CC-4 (P0, 32)** -- 8 MiB pthread stack -- `0fd05ac` -- closed GitLab #21
> - **MW-4 (P0, 16)** -- per-conn memory umbrella -- `3238c26` + `0fd05ac` + `ac7f771` -- closed GitLab #18
> - **MW-1+MW-2 (P1, 20)** -- unused 64 KiB read_buf+write_buf -- `3238c26` -- closed GitLab #24
> - **MW-3 (P1, 15)** -- dead http2_conn / sendFrame stub -- `3238c26` -- closed GitLab #25

This document captures the prioritized performance findings from the Phase 3 perf-reviewer pass against `src/transport.zig`, `src/server.zig`, `src/http2/*.zig`, and `src/benchmark.zig`. Every finding is tracked as a GitLab issue; URLs appear in the table below. PerfScore is computed as
`severity_weight × effort_inverse × impact_weight` where:

- severity_weight: P0=8, P1=5, P2=3, P3=1
- effort_inverse: XS=4, S=3, M=2, L=1
- impact_weight: 2x for throughput-cliff or correctness-shaped, 1x for pure waste

## Summary

### Counts by severity

| Severity | Count |
|----------|-------|
| P0       | 7     |
| P1       | 14    |
| P2       | 4     |
| P3       | 3     |
| Info     | 0     |
| **Total**| **28**|

Closed to date: 13 of the tracked findings. The 2026-04-26 pass closed NW-1/2/3 (#13), CC-1 (#20), CC-4 (#21), MW-4 (#18), MW-1/2 (#24), MW-3 (#25). The 2026-06-11 audit-fix pass closed BH-1 (#22), BH-4 (#23), BH-5 (#42), AG-5 (#41), NW-5 (#32), BH-7 (#34, verified-only), and resolved AG-3 (#40) as won't-fix. Still open: the allocation cluster AL-1/AL-2/AL-3/AL-4 (#27/#28/#29/#37), CC-3+NW-6 (#30), AG-1 (#36), AG-2 (#26), MW-5 (#37)/MW-6 (#31), BH-8 (#33), BH-9 (#35), BH-3 (#38/#39), and the P1 timer/gate items.

### Top 5 risks (by PerfScore)

1. **NW-1+NW-2+NW-3 — HTTP/2 flow control broken** (Score 64+, P0). Server SETTINGS empty, peer windows untracked, default 65,535-byte initial window; large bodies stall because WINDOW_UPDATE is drained-and-discarded. Correctness-shaped throughput cliff. Unblocks every other perf measurement. Issue [#13](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/13).
2. **CC-1 + MW-4 + CC-4 — per-conn memory ceiling** (combined Score 32+32+32, P0). Unbounded thread-per-conn × 8 MiB pthread stack × 131 KiB heap → ~8 GiB at 1k idle conns and trivial DoS. Issues [#18](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/18), [#20](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/20), [#21](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/21).
3. **BH-1 — bench workers run sequentially** (Score 24, P0). `concurrent_clients` is a fiction; current bench numbers are single-threaded. Issue [#22](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/22).
4. **BH-4 — bench JSON to stderr** (Score 32, P0). `std.debug.print` writes to stderr; CI cannot consume the JSON. Blocks BH-9 regression gate. Issue [#23](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/23).
5. **AL-1 + AL-2 + AL-3 — per-frame allocs on hot path** (Score 15+20+15, P1). Every readFrame heap-allocs payload, every DATA->handler memcpy strips prefix via alloc+copy, every writeMessage allocates `5 + len`. Once flow control lands, this dominates the steady-state hot path. Issues [#27](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/27), [#28](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/28), [#29](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/29).

## Stack-ranked findings

| Rank | Sev | Score | Finding | Component | Evidence (file:line) | Measurement | Issue | Fix Summary | Owner | SLA | Status |
|------|-----|-------|---------|-----------|----------------------|-------------|-------|-------------|-------|-----|--------|
| 1  | P0 | 64 | NW-1+2+3 HTTP/2 flow control broken (umbrella) | transport / http2 | transport.zig:286-293, 391-392, 456-460, 556-559; stream.zig:17,25 | h2spec + 1 MiB body bench: pre-fix hangs, post-fix completes <100ms | [#13](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/13) | Advertise SETTINGS (MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE>=1MiB, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE); track conn+stream send windows; honor incoming WINDOW_UPDATE | transport | within 1 sprint | **closed (efd9ef6, 2026-04-26)** |
| 2  | P0 | 32 | CC-1 unbounded thread-per-conn / no admission control | server | server.zig:55-69 | 5k concurrent connect: pre OOM, post plateau | [#20](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/20) | Bounded thread pool or counting-semaphore gating accept | server | within 1 sprint | **closed (ac7f771, 2026-04-26)** |
| 3  | P0 | 32 | CC-4 8 MiB pthread stack per conn | server | server.zig:63 (default SpawnConfig) | pmap stack region size 8192K → 512K | [#21](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/21) | `SpawnConfig.stack_size = 512 * 1024` | server | same sprint as #18/#20 | **closed (0fd05ac, 2026-04-26)** |
| 4  | P0 | 32 | BH-4 bench JSON written to stderr | bench/ci | benchmark.zig:212-220 | `zig build bench -- --format json \| jq -e .` returns valid | [#23](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/23) | Replace `std.debug.print` with stdout writer + flush | bench/ci | XS, before BH-9 | **closed (5a03dc4, 2026-06-11)** -- #23 |
| 5  | P0 | 24 | BH-1 bench workers run sequentially | bench/ci | benchmark.zig:181-194 | top -H shows 10 active threads; total_duration ~= max(per-worker) | [#22](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/22) | Spawn N threads or use std.Thread.Pool; merge results on join | bench/ci | before any perf gate | **closed (5a03dc4, 2026-06-11)** -- #22 |
| 6  | P0 | 16 | MW-4 ~131 KiB heap + 8 MiB stack/conn → ~8 GiB at 1k conns | server / transport | transport.zig:120-280; server.zig:63 | VmRSS at 1k idle conns ≤ 600 MiB | [#18](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/18) | Apply MW-1/2/3 + CC-4 + CC-1 in concert | server/transport | within 1 sprint | **closed (3238c26+0fd05ac+ac7f771, 2026-04-26)** |
| 7  | P1 | 20 | MW-1+MW-2 unused 64 KiB read_buf+write_buf per Transport | transport | transport.zig:120-121,149-151,178-180,207-209,276-277 | `grep` confirms no use; -128 KiB/conn | [#24](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/24) | Delete fields, allocs, frees | transport | XS quick win | **closed (3238c26, 2026-04-26)** |
| 8  | P1 | 20 | AL-2 DATA→handler memcpy strips prefix via alloc+copy | transport | transport.zig:418-426, 526-534 | perf record: __memcpy disappears for big-msg bench | [#28](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/28) | Borrow `payload[5..5+msg_len]` (after AL-1) | transport | XS, after AL-1 | triage |
| 9  | P1 | 20 | NW-5 no TCP_NODELAY/keepalive on accepted sockets | server | server.zig:31-69 | tcpdump confirms no Nagle gaps; `ss -tio` shows keepalive | [#32](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/32) | setsockopt TCP_NODELAY, SO_KEEPALIVE; optional SO_REUSEPORT | server | XS quick win | **closed (7b810a4, 2026-06-11)** -- #32 (issue number corrected from stale #31) |
| 10 | P1 | 15 | AG-2 HPACK static-table only handles indices 4/5 as :path | transport | transport.zig:619-630 | unit-test indexed `:method` decode succeeds | [#26](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/26) | Comptime full 61-entry static table; lookup by name=":path" | transport | within 1 sprint | triage |
| 11 | P1 | 15 | MW-3 dead http2_conn Connection field, sendFrame is no-op | transport | transport.zig:170,199,232; connection.zig:73-77 | grep zero call sites of http2_conn.* | [#25](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/25) | Delete field + init + deinit; consider deleting Connection module | transport | S quick win | **closed (3238c26, 2026-04-26)** |
| 12 | P1 | 15 | MW-6 HPACK dyn table count-bounded not byte-bounded | transport | transport.zig:97-105, 593-610 | h2spec HPACK section passes; RFC C.6 vectors pass | [#32](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/32) | Track byte-size sum, evict on overflow, honor SETTINGS_HEADER_TABLE_SIZE | transport | after AG-2 | triage |
| 13 | P1 | 15 | AL-1 per-frame readFrame heap alloc | transport | transport.zig:332 | bench tracks 1 alloc/RPC for response only | [#27](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/27) | Per-conn read scratch ArrayList; borrow returns | transport | after NW cluster | triage |
| 14 | P1 | 15 | AL-3 writeMessage* allocates 5+len buffer at 3 sites | transport | transport.zig:864-872, 923-931, 975-983 | strace shows single writev per DATA; perf shows no memcpy | [#29](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/29) | iovec-based writeFrameLocked; stack [5]u8 grpc header | transport | bundle with NW-6/CC-3 | triage |
| 15 | P1 | 15 | CC-3+NW-6 write_mutex held across 2 socket writes per frame | transport | transport.zig:367-370 | `strace -c -e trace=write,writev` shows writev | [#30](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/30) | netWrite vectored; combine with AL-3 | transport | bundle | triage |
| 16 | P1 | 15 | BH-7 compat.nanoTimestamp resolution unverified | bench/ci | benchmark.zig:39-52; compat.zig (audit) | unit test asserts monotonic non-decreasing | [#34](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/34) | Audit; switch to std.time.Instant if wall-clock-based | bench/ci | S effort | **closed (verified monotonic, 2026-06-11)** -- no code change needed (clock confirmed monotonic ns-grade) |
| 17 | P1 | 15 | BH-8 bench dials fresh GrpcClient per worker | bench/ci | benchmark.zig:74-108 | ss -t shows N stable conns, no TIME_WAIT churn | [#33](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/33) | Reuse client per worker, possibly across workers | bench/ci | after BH-1 | open -- #33 (deferred; BH-1 sequential-workers fixed in 5a03dc4, per-worker client lifecycle remains) |
| 18 | P1 | 10 | CC-2 no backpressure on accept | server | server.zig:31-44 | covered by CC-1 stress test | [#20](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/20) | Coupled with CC-1 | server | with CC-1 | triage |
| 19 | P1 | 10 | BH-9 no SLO/regression gate | ci | .gitlab-ci.yml | failing PR with intentional regression breaks pipeline | [#34](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/34) | New `bench:perf` job + perf_compare script + bench-baseline.json | ci | after BH-1/4/7/8 | triage |
| 20 | P2 | 12 | AL-4 writeRequestHeaders heap-allocates per request | transport | transport.zig:33-96, 956-983 | bench: 0 allocs for headers per call | [#37](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/37) | Stack [512]u8 buf; refactor to fill caller-provided slice | transport | XS | triage |
| 21 | P2 | 9 | MW-5 last_method+hpack_dyn always resident (~17.8 KiB) | transport | transport.zig:131-136 | VmRSS at 1k idle conns drops ~17.8 MiB | [#36](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/36) | Lazy alloc on first HEADERS / first dynamic-table push | transport | S | triage |
| 22 | P2 | 9 | BH-3 bench JSON schema mismatches docs | bench/ci | benchmark.zig:19-36; docs/benchmarking.md | smoke parse via std.json.parseFromSlice | [#38](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/38) | Reconcile schema; commit fixture sample | bench/ci | S | triage |
| 23 | P2 | 6 | AG-1 HPACK Huffman bit-serial O(bits×groups) | transport | transport.zig:657-684 | microbench 1 KiB blob: 1-3 µs → 100-300 ns | [#35](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/35) | 8-bit prefix LUT (two-stage) | transport | M, after NW+AL | triage |
| 24 | P3 | 4 | AG-3 extractPathFromHpack continues after :path found | transport | transport.zig (extractPathFromHpack) | code-review only | [#40](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/40) | Document or short-circuit | transport | XS | **won't-fix (2026-06-11)** -- #40 closed. Early exit would desync the HPACK dynamic table; LIE entries after `:path` must still be pushed for cross-request consistency, so full iteration is required for correctness. Cost is bounded (one HEADERS frame, ≤8 KiB). |
| 25 | P3 | 4 | AG-5 redundant 256B last_method memset on init | transport | transport.zig:131,164,193,223 | code-review only | [#41](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/41) | Drop redundant explicit zero-fills (or remove field via MW-5) | transport | XS, bundle with MW-5 | **closed (5a03dc4, 2026-06-11)** -- #41 (issue number corrected from stale #40) |
| 26 | P3 | 4 | BH-5 printUsage missing trailing newlines | bench/ci | benchmark.zig (printUsage) | visual `--help` check | [#42](https://gitlab.com/devnw/zig/grpc-zig/-/work_items/42) | Add `\n` | bench/ci | XS | **closed (5a03dc4, 2026-06-11)** -- #42 (issue number corrected from stale #41) |

## Findings by area

### area::app (transport, server)

P0: NW-1/2/3 (#13) **closed**, MW-4 (#18) **closed**, CC-1+CC-2 (#20) **closed**, CC-4 (#21) **closed**.
P1: MW-1/2 (#24) **closed**, MW-3 (#25) **closed**, NW-5 (#32) **closed (7b810a4)**, AG-2 (#26), AL-1 (#27), AL-2 (#28), AL-3 (#29), CC-3+NW-6 (#30), MW-6 (#31).
P2: AG-1 (#36), MW-5 (#37), AL-4 (#37/headers).
P3: AG-3 (#40) **won't-fix**, AG-5 (#41) **closed (5a03dc4)**.

> Note: earlier revisions of this doc carried stale GitLab issue numbers for some `area::app` rows (e.g. NW-5 as #31, MW-6 as #32). The live tracker is authoritative: NW-5=#32, MW-6=#31, AG-1=#36, MW-5=#37, BH-9=#35, BH-7=#34, AG-3=#40, AG-5=#41, BH-5=#42. Rows touched this pass have been corrected; untouched rows are left as-is for the next perf pass to reconcile.

### area::ci (bench, gitlab-ci)

P0: BH-1 (#22) **closed (5a03dc4)**, BH-4 (#23) **closed (5a03dc4)**.
P1: BH-7 (#34) **closed (verified monotonic)**, BH-8 (#33), BH-9 (#35).
P2: BH-3 (#38/#39).
P3: BH-5 (#42) **closed (5a03dc4)**.

### area::db, area::infra

No findings in this pass. (No DB; infra concerns only via thread/socket primitives, captured under area::app.)

## Roadmap

### Quick wins (< 1 day)

- BH-4 stdout (#23) — XS.
- CC-4 stack size (#21) — XS.
- MW-1/2 delete read_buf/write_buf (#24) — XS.
- NW-5 setsockopt (#31) — XS.
- AL-4 stack-allocate request headers (#37) — XS.
- AG-5 drop redundant memset (#40) — XS.
- BH-5 newlines (#41) — XS.

### Medium (1-5 days)

- NW-1 advertise SETTINGS (#13 part 1).
- MW-3 delete dead Connection field (#25).
- AG-2 full HPACK static table (#26).
- AL-1 per-conn read scratch (#27) + AL-2 borrow (#28).
- AL-3 + CC-3 + NW-6 iovec writeFrameLocked (#29, #30).
- CC-1 + CC-2 bounded pool / accept gating (#20).
- BH-1 real concurrency in bench (#22).
- BH-7 timer audit (#33).
- BH-8 bench client reuse (#33 pair).
- BH-3 schema reconcile (#38).
- MW-5 lazy HPACK state (#36).
- MW-6 byte-bounded HPACK dyn table (#32).

### Strategic (> 5 days)

- NW-2 + NW-3 send-window state machine + WINDOW_UPDATE handling (#13 main work).
- MW-4 combined per-conn memory ceiling enforcement (#18 — depends on MW-1/2/3 + CC-1/4 landing).
- AG-1 Huffman LUT (#35).
- BH-9 perf regression gate in CI (#34).

## Sequencing Plan

The sequencing intentionally unblocks measurement before optimization, fixes the throughput cliff before any micro-opt, then puts a memory ceiling under the system before chasing CPU.

1. **Unblock measurement** — BH-4 (#23) → BH-1 (#22) → BH-7 (#33) → BH-8 (#33 pair). Without trustworthy bench output and a real concurrent harness, every "10% faster" claim is noise.
2. **Flow control (the cliff)** — NW-1+NW-2+NW-3 (#13). Without this, larger payloads simply do not complete. All other transport work is invisible until this lands.
3. **Memory ceiling** — MW-1/2 (#24), MW-3 (#25), CC-4 (#21), MW-5 (#36), CC-1+CC-2 (#20). Combined effect captured in MW-4 (#18). Drives per-conn cost from ~8 MiB to ~530 KiB.
4. **Hot-path allocs / writev** — AL-1 (#27), AL-2 (#28), AL-3 (#29), CC-3+NW-6 (#30), AL-4 (#37). After steps 2-3, this is the next visible cost. Goal: zero-alloc steady-state per RPC on the read+write hot path.
5. **Admission control hardening** — sized pool from CC-1, NW-5 socket options (#31). At this point the server is shaped for production load.
6. **HPACK perf** — AG-2 (#26), MW-6 (#32), AG-1 (#35). Now that the rest is fast, header decode is the next bottleneck on header-heavy traces.
7. **CI gate** — BH-9 (#34) once steps 1-6 have produced a meaningful baseline, lock in non-regression.

## Notes / Unknowns / Blockers

- **BH-7 / compat.zig**: `compat.nanoTimestamp` source not yet audited. If it's already CLOCK_MONOTONIC-based, BH-7 reduces to documenting the contract. Confirm via `Read src/compat.zig` before scheduling.
- **AL-2 ownership audit**: callers in `src/client.zig` and `src/client_mux.zig` not yet reviewed for ownership of returned message slices. Borrowed-slice flip needs a sweep across both.
- **NW-2 deadlock risk**: writer waiting on WINDOW_UPDATE requires a per-conn condvar / event woken by the reader. Wiring through `std.Io` correctly is the highest-risk piece of #13. Consider unit-testing the window arithmetic in isolation first.
- **MW-3 / connection.zig**: `Connection.sendHeaders` and `Connection.createStream` may be referenced from tests or examples not yet checked. Verify with `grep -rn 'http2_conn\.\|Connection\.sendHeaders\|Connection\.createStream' .` before deletion.
- **GitLab work-item URLs**: created against the `work_items` (group-level) endpoint; some glab versions display them as `/issues/N` instead. Both forms point at the same record.

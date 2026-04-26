# Interop Findings

Running log of cross-stack interop failures and their fix paths.
Each entry: date, pair (server × client), symptom, root cause, fix
plan / fix commit.

## 2026-04-25 — initial Phase 1 sweep

### go-server × zig-client — RESOLVED 2026-04-26 (commit `a9adadd`)

**Symptom (was):** `FAIL: call: error.ConnectionClosed`
(server log showed only `interop-go-server listening on 127.0.0.1:50063` — the Go server
closed the connection immediately without producing any RPC response.)

**Root cause:** grpc-zig `Transport.writeMessage` emitted HPACK
HEADERS containing `:status: 200` and `content-type: application/grpc`,
which is the shape of a SERVER response. A request must instead
carry `:method: POST`, `:scheme: http`, `:path: /interop.Interop/Echo`,
`:authority: <host>`, `content-type: application/grpc`, `te: trailers`.

**Fix (commit `a9adadd`):**
- Added `Transport.writeRequestHeaders(allocator, method_path, authority)`,
  `Transport.writeRequest(message, method_path)`, and
  `Transport.writeRequestOnStream(stream_id, message, method_path)` that
  emit a proper request-shaped HPACK block with `:method: POST`,
  `:scheme: http`, `:path: <method_path>`, `:authority: <host>:<port>`,
  `content-type: application/grpc`, `te: trailers`.
- `GrpcClient` now plumbs `host:port` through to `Transport.initClient`
  as the `:authority` value; `call` and `streamCall` thread the
  `method_path` through to `writeRequest`.
- `ClientMux.call` grew a `method_path` parameter and forwards it to
  `writeRequestOnStream`.
- Server-side `writeMessage` / `writeMessageOnStream` /
  `writeStreamMessage` / `endStream` are unchanged — they still emit
  the response-shaped HEADERS the server needs.
- Verified: `interop/scripts/run-matrix.sh` exits 0 (4/4 PASS) locally;
  the `interop-cross` CI job is no longer `allow_failure`.

### zig-server × go-client

**Symptom:** (unexpected pass — keep watching)
`2026/04/25 23:36:40 OK payload="hello" tag="zig-go"` — the Go client
successfully received the Echo response from the Zig server.

**Root cause:** The originally-anticipated bug (incomplete
`extractPathFromHpack` failing to parse a real Go client's HEADERS
block) was not triggered in this scenario. The Go client's HPACK
encoding happened to be simple enough (or the grpc-zig decoder
happened to cover the specific indexed/literal encodings used for
`:path`) that path extraction succeeded and the handler dispatched
correctly.

**Fix path (separate plan):**
- Replace `extractPathFromHpack` with a complete RFC 7541 decoder
  that maintains the full dynamic table state across requests and
  exposes every header to the dispatch layer (not just `:path`).
- Add HPACK fixture tests using HEADERS blocks captured from
  grpc-go's debug logs so the decoder is verified against real
  client output.
- The pass here should not be taken as proof of correctness; more
  complex Go clients or different method paths may still fail.

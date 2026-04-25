# Interop Findings

Running log of cross-stack interop failures and their fix paths.
Each entry: date, pair (server × client), symptom, root cause, fix
plan / fix commit.

## 2026-04-25 — initial Phase 1 sweep

### go-server × zig-client

**Symptom:** `FAIL: call: error.ConnectionClosed`
(server log shows only `interop-go-server listening on 127.0.0.1:50063` — the Go server
closed the connection immediately without producing any RPC response.)

**Root cause:** grpc-zig `Transport.writeMessage` emits HPACK
HEADERS containing `:status: 200` and `content-type: application/grpc`,
which is the shape of a SERVER response. A request must instead
carry `:method: POST`, `:scheme: http`, `:path: /interop.Interop/Echo`,
`:authority: <host>`, `content-type: application/grpc`, `te: trailers`.

**Fix path (separate plan):**
- Split `writeMessage` into a server-side `writeResponse` and a new
  client-side `writeRequest(method_path)` that emits proper request
  headers.
- Update `GrpcClient.call` and `ClientMux.call` to take the method
  path and pass it to `writeRequest`.
- Update `loopback_main.zig` and the existing tests (loopback already
  passes a path string, so the API change is internal-only).

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

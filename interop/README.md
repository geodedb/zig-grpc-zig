# grpc-zig Interop Tests

Cross-stack interop harness. Each supported language has a reference
gRPC server and client using its canonical library; grpc-zig has its
own server/client wrappers using `src/server.zig` and `src/client.zig`.
The runner pairs every server with every client and prints a result
matrix.

## Layout

- `proto/` — shared `.proto` file. Regenerate stubs with `make gen`.
- `go/` — Go reference impl (`google.golang.org/grpc`).
- `zig/` — Zig harness using grpc-zig.
- `scripts/run-matrix.sh` — runs all pairs.

## Running locally

    cd interop
    ./scripts/run-matrix.sh

## Adding a language

1. Generate stubs from `proto/interop.proto` using the language's
   gRPC plugin.
2. Implement an Echo passthrough server that accepts `--port`.
3. Implement a client that accepts `--target` and `--message` and
   exits 0 on success / non-zero with `FAIL: <reason>` on failure.
4. Add the language's `(server, client)` pair to `run-matrix.sh`.

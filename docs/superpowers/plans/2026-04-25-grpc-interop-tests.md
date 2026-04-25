# gRPC Interop Tests — Phase 1: Go ↔ Zig Echo RPC

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a real gRPC reference implementation in Go and prove that grpc-zig (as both server and client) can interoperate with it for the unary `Echo` RPC. Surface every protocol gap as a documented failure with a fix path.

**Architecture:** A new `interop/` directory holds a shared proto file, a Go reference server + client (vanilla `grpc-go` + `protoc-gen-go-grpc`), Zig harnesses that wrap the existing `GrpcServer` / `GrpcClient` for the same proto, and a shell-based runner that pairs servers with clients across the four combinations. The harness runs in subprocesses (each side as its own binary) on localhost.

**Tech Stack:** Go 1.22+, `google.golang.org/grpc`, `protoc-gen-go-grpc` v1.5+, protoc 25+, Zig 0.16, existing grpc-zig (`src/server.zig`, `src/client.zig`, `src/transport.zig`).

**Why scope is limited to Go + Echo for this plan:** the spec asked for Go, Rust, and Python interop. Each language is a non-trivial sub-project (toolchain setup, codegen, server/client code) and grpc-zig has known protocol gaps that real gRPC clients will reject — fixing those is itself a sub-project. Doing all three languages plus protocol fixes in one plan would create a spec too large to review. This plan delivers Go-only interop end-to-end, which is the smallest viable surface for finding the protocol gaps. Follow-on plans (sketched at the bottom) cover Rust, Python, larger scenarios, and the actual protocol fixes.

---

## File Structure

**New files:**

- `interop/README.md` — what this directory is, how to run the matrix locally, where findings go.
- `interop/proto/interop.proto` — `package interop; service Interop { rpc Echo(EchoRequest) returns (EchoResponse); }`. Keep the message types minimal (one `bytes payload`, one `string trailer`) so the protobuf wire codec stays trivial.
- `interop/go/go.mod` — module `gitlab.com/devnw/zig/grpc-zig/interop/go`, Go 1.22.
- `interop/go/gen.go` — `//go:generate protoc ...` directive driving codegen into `interop/go/genproto/`.
- `interop/go/genproto/interop.pb.go`, `interop/go/genproto/interop_grpc.pb.go` — generated, committed (so CI doesn't need protoc).
- `interop/go/server/main.go` — Go reference server, listens on `--port`, implements `Echo` as passthrough.
- `interop/go/client/main.go` — Go reference client, takes `--target`, `--message`, prints decoded response or `FAIL: <err>` and exits non-zero.
- `interop/zig/harness.zig` — shared helpers: minimal proto3 wire encode/decode for `EchoRequest`/`EchoResponse` (two fields each, all scalar/bytes types).
- `interop/zig/server_main.zig` — Zig interop server (uses `GrpcServer`, dispatches Echo via `harness.zig`).
- `interop/zig/client_main.zig` — Zig interop client (uses `GrpcClient`, encodes request, decodes response, prints/exits like the Go client).
- `interop/scripts/run-pair.sh` — spawn one server, wait for listen, run one client, kill server, propagate exit code.
- `interop/scripts/run-matrix.sh` — call `run-pair.sh` for every (server-stack × client-stack) pair, collect results, print summary table.
- `docs/interop/findings.md` — running log of failures discovered, with fix candidates.

**Modified files:**

- `build.zig` — add `interop-server` and `interop-client` build steps producing `zig-out/bin/grpc-interop-server` and `grpc-interop-client`.
- `.gitlab-ci.yml` — add an `interop` stage with two jobs: `interop-go-go` (control, must pass) and `interop-cross` (allow_failure: true until protocol fixes land).

**Why this layout:**
- Each language sits under its own directory with its own toolchain manifest. The Go module is self-contained so `go build` works without affecting the parent project.
- The Zig harness imports server.zig/client.zig with relative paths the same way `src/loopback_main.zig` does — avoids the "file in two modules" build error.
- Generated proto code is committed so CI doesn't need protoc; the regen step is documented in `interop/README.md` for when the proto changes.
- `interop/scripts/` is shell because the orchestration is just "spawn process, wait, run other process, kill" — using the test runners' built-in subprocess support per language would multiply complexity without buying anything.

---

## Task 1: Create the proto definition and the directory layout

**Files:**
- Create: `interop/README.md`
- Create: `interop/proto/interop.proto`
- Create: `docs/interop/findings.md`

- [ ] **Step 1.1: Create the proto file**

```proto
// interop/proto/interop.proto
syntax = "proto3";

package interop;

option go_package = "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto;genproto";

// Minimal service for cross-stack interop: unary echo only.
// Keep the message shape small so the hand-written Zig wire codec
// stays trivial — bytes + string covers fields 1 (length-delimited
// LEN wire type 2) and proves end-to-end framing works.
service Interop {
  rpc Echo(EchoRequest) returns (EchoResponse);
}

message EchoRequest {
  bytes payload = 1;
  string tag    = 2;
}

message EchoResponse {
  bytes payload = 1;
  string tag    = 2;
}
```

- [ ] **Step 1.2: Create the README**

```markdown
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
```

- [ ] **Step 1.3: Create the findings doc skeleton**

```markdown
# Interop Findings

Running log of cross-stack interop failures and their fix paths.
Each entry: date, pair (server × client), symptom, root cause, fix
plan / fix commit.

## 2026-04-25 — initial Phase 1 sweep

(Entries added as Tasks 9-10 surface failures.)
```

- [ ] **Step 1.4: Commit**

```bash
git add interop/README.md interop/proto/interop.proto docs/interop/findings.md
git commit -m "interop: scaffold proto file and findings log"
```

---

## Task 2: Generate Go protobuf + grpc stubs and commit them

**Files:**
- Create: `interop/go/go.mod`
- Create: `interop/go/gen.go`
- Create: `interop/go/genproto/interop.pb.go` (generated)
- Create: `interop/go/genproto/interop_grpc.pb.go` (generated)

- [ ] **Step 2.1: Initialize the Go module**

```bash
cd interop/go
go mod init gitlab.com/devnw/zig/grpc-zig/interop/go
go get google.golang.org/grpc@v1.66.0
go get google.golang.org/protobuf@v1.34.2
cd ../..
```

Run: confirm `interop/go/go.mod` exists and lists the two deps.

- [ ] **Step 2.2: Add the codegen driver**

Create `interop/go/gen.go`:

```go
//go:build generate

package main

//go:generate protoc -I=../proto --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ../proto/interop.proto
```

- [ ] **Step 2.3: Run codegen**

```bash
cd interop/go
mkdir -p genproto
# Move the proto's emitted files under genproto/ via the go_package
# option (already set on the proto file).
protoc -I=../proto \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  ../proto/interop.proto
cd ../..
```

Expected: `interop/go/genproto/interop.pb.go` and `interop/go/genproto/interop_grpc.pb.go` are created.

If `protoc` or the plugins are missing, the engineer needs:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# protoc itself: distro package or https://github.com/protocolbuffers/protobuf/releases
```

- [ ] **Step 2.4: Verify the generated code compiles**

```bash
cd interop/go && go build ./... && cd ../..
```

Expected: silent success.

- [ ] **Step 2.5: Commit**

```bash
git add interop/go/go.mod interop/go/go.sum interop/go/gen.go interop/go/genproto/
git commit -m "interop(go): generate protobuf + grpc stubs"
```

---

## Task 3: Write the Go reference server (and a test that proves it serves Echo)

**Files:**
- Create: `interop/go/server/main.go`
- Create: `interop/go/server/main_test.go`

- [ ] **Step 3.1: Write the failing test**

Create `interop/go/server/main_test.go`:

```go
package main

import (
	"context"
	"net"
	"testing"
	"time"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
)

func TestEchoRoundTrip(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	srv := grpc.NewServer()
	pb.RegisterInteropServer(srv, &server{})
	go srv.Serve(lis)
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := pb.NewInteropClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Echo(ctx, &pb.EchoRequest{Payload: []byte("hello"), Tag: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Payload) != "hello" {
		t.Fatalf("payload mismatch: %q", resp.Payload)
	}
	if resp.Tag != "go" {
		t.Fatalf("tag mismatch: %q", resp.Tag)
	}
}
```

- [ ] **Step 3.2: Run the test to confirm it fails**

```bash
cd interop/go && go test ./server/...
```

Expected: FAIL with "undefined: server" (or similar — the `server` struct doesn't exist yet).

- [ ] **Step 3.3: Implement the server**

Create `interop/go/server/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedInteropServer
}

func (s *server) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	return &pb.EchoResponse{Payload: req.Payload, Tag: req.Tag}, nil
}

func main() {
	port := flag.Int("port", 50061, "listen port")
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterInteropServer(srv, &server{})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		srv.GracefulStop()
	}()

	log.Printf("interop-go-server listening on %s", lis.Addr())
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
```

- [ ] **Step 3.4: Run the test, expect pass**

```bash
cd interop/go && go test ./server/...
```

Expected: PASS.

- [ ] **Step 3.5: Build the binary and confirm it can listen**

```bash
cd interop/go && go build -o ../../zig-out/bin/grpc-interop-go-server ./server && cd ../..
./zig-out/bin/grpc-interop-go-server --port 50061 &
SERVER_PID=$!
sleep 1
ss -tlnp 2>/dev/null | grep -E "50061" || netstat -tln | grep -E "50061"
kill $SERVER_PID
```

Expected: a line shows port 50061 listening, then dies cleanly.

- [ ] **Step 3.6: Commit**

```bash
git add interop/go/server/
git commit -m "interop(go): reference Echo server"
```

---

## Task 4: Write the Go reference client (with a test that proves it talks to the server)

**Files:**
- Create: `interop/go/client/main.go`
- Create: `interop/go/client/main_test.go`

- [ ] **Step 4.1: Write the failing test**

Create `interop/go/client/main_test.go`:

```go
package main

import (
	"context"
	"net"
	"testing"
	"time"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
)

// Stand up an in-process server and verify our `runEcho` produces
// the expected response struct.
type echoServer struct {
	pb.UnimplementedInteropServer
}

func (s *echoServer) Echo(_ context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	return &pb.EchoResponse{Payload: req.Payload, Tag: "server-" + req.Tag}, nil
}

func TestRunEcho(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterInteropServer(srv, &echoServer{})
	go srv.Serve(lis)
	defer srv.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := runEcho(ctx, lis.Addr().String(), "hello-from-client", "go-client")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Payload) != "hello-from-client" {
		t.Fatalf("payload: %q", resp.Payload)
	}
	if resp.Tag != "server-go-client" {
		t.Fatalf("tag: %q", resp.Tag)
	}
}
```

- [ ] **Step 4.2: Run the test to confirm it fails**

```bash
cd interop/go && go test ./client/...
```

Expected: FAIL with "undefined: runEcho".

- [ ] **Step 4.3: Implement the client**

Create `interop/go/client/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// runEcho performs one Echo RPC and returns the response. Extracted
// out of main() so the test can drive it without spawning subprocesses.
func runEcho(ctx context.Context, target, message, tag string) (*pb.EchoResponse, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()
	c := pb.NewInteropClient(conn)
	return c.Echo(ctx, &pb.EchoRequest{Payload: []byte(message), Tag: tag})
}

func main() {
	target := flag.String("target", "127.0.0.1:50061", "server host:port")
	message := flag.String("message", "ping", "Echo payload")
	tag := flag.String("tag", "go-client", "Echo tag")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runEcho(ctx, *target, *message, *tag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	if string(resp.Payload) != *message {
		fmt.Fprintf(os.Stderr, "FAIL: payload mismatch: got %q want %q\n", resp.Payload, *message)
		os.Exit(2)
	}
	log.Printf("OK payload=%q tag=%q", resp.Payload, resp.Tag)
}
```

- [ ] **Step 4.4: Run the test, expect pass**

```bash
cd interop/go && go test ./client/...
```

Expected: PASS.

- [ ] **Step 4.5: Build the binary and verify Go-Go via the binaries**

```bash
cd interop/go && go build -o ../../zig-out/bin/grpc-interop-go-client ./client && cd ../..
./zig-out/bin/grpc-interop-go-server --port 50061 &
SERVER_PID=$!
sleep 1
./zig-out/bin/grpc-interop-go-client --target 127.0.0.1:50061 --message hello --tag go-go
RC=$?
kill $SERVER_PID
test $RC -eq 0
```

Expected: client prints `OK payload="hello"...`, exits 0; the final `test` succeeds.

- [ ] **Step 4.6: Commit**

```bash
git add interop/go/client/
git commit -m "interop(go): reference Echo client"
```

---

## Task 5: Add the proto3 wire codec for `EchoRequest` / `EchoResponse` in Zig

**Files:**
- Create: `interop/zig/harness.zig`
- Create: `interop/zig/harness_test.zig`

The grpc-zig project has no general protobuf codec yet (`src/proto/service.zig` defines messages that delegate to a writer/reader interface that doesn't exist). For this plan we hand-write a minimal proto3 encoder/decoder for two fields (`bytes` and `string`, both wire type 2 — LEN). This is enough for the interop messages and keeps the scope tight.

- [ ] **Step 5.1: Write the failing test**

Create `interop/zig/harness_test.zig`:

```zig
const std = @import("std");
const testing = std.testing;
const harness = @import("harness.zig");

test "encode/decode EchoRequest round-trip matches Go-emitted bytes" {
    const allocator = testing.allocator;

    const req = harness.EchoRequest{ .payload = "hello", .tag = "go" };
    const bytes = try harness.encodeEchoRequest(allocator, req);
    defer allocator.free(bytes);

    // Bytes verified against `protoc --decode_raw` output for the same
    // message — field 1 (LEN, "hello"), field 2 (LEN, "go").
    const expected = [_]u8{
        0x0a, 0x05, 'h', 'e', 'l', 'l', 'o',
        0x12, 0x02, 'g', 'o',
    };
    try testing.expectEqualSlices(u8, &expected, bytes);

    const decoded = try harness.decodeEchoRequest(allocator, bytes);
    defer harness.freeEchoRequest(allocator, decoded);
    try testing.expectEqualStrings("hello", decoded.payload);
    try testing.expectEqualStrings("go", decoded.tag);
}

test "decode tolerates fields out of order and unknown fields" {
    const allocator = testing.allocator;
    // Same message, tag first then payload, with an extra unknown field 99
    // (LEN, 0x03 "xyz") in the middle that decode must skip.
    const bytes = [_]u8{
        0x12, 0x02, 'g', 'o',
        0xfa, 0x06, 0x03, 'x', 'y', 'z', // field 99, wire type 2, len 3, "xyz"
        0x0a, 0x05, 'h', 'e', 'l', 'l', 'o',
    };
    const decoded = try harness.decodeEchoRequest(allocator, &bytes);
    defer harness.freeEchoRequest(allocator, decoded);
    try testing.expectEqualStrings("hello", decoded.payload);
    try testing.expectEqualStrings("go", decoded.tag);
}
```

- [ ] **Step 5.2: Run the test to confirm it fails**

Wire it via `interop/zig/harness_test.zig` as a separate test executable in `build.zig` (Step 5.6 covers this). For now, fail-first verification can be done with:

```bash
zig test interop/zig/harness_test.zig --dep harness=interop/zig/harness.zig 2>&1 | head -20
```

Expected: FAIL with "module 'harness' not found" or similar — `harness.zig` doesn't exist yet.

- [ ] **Step 5.3: Implement the codec**

Create `interop/zig/harness.zig`:

```zig
//! Minimal proto3 wire codec for the interop EchoRequest/EchoResponse
//! messages. Only handles wire type 2 (LEN) for `bytes` and `string`
//! fields 1 and 2. Unknown fields are skipped on decode.

const std = @import("std");

pub const EchoRequest = struct {
    payload: []const u8 = "",
    tag: []const u8 = "",
};

pub const EchoResponse = struct {
    payload: []const u8 = "",
    tag: []const u8 = "",
};

const FIELD_PAYLOAD = 1;
const FIELD_TAG = 2;

const WIRE_VARINT = 0;
const WIRE_FIXED64 = 1;
const WIRE_LEN = 2;
const WIRE_FIXED32 = 5;

fn writeVarint(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var v = value;
    while (v >= 0x80) {
        try buf.append(allocator, @as(u8, @intCast(v & 0x7f)) | 0x80);
        v >>= 7;
    }
    try buf.append(allocator, @as(u8, @intCast(v)));
}

fn writeLenField(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, field_no: u32, data: []const u8) !void {
    const tag: u64 = (@as(u64, field_no) << 3) | WIRE_LEN;
    try writeVarint(buf, allocator, tag);
    try writeVarint(buf, allocator, @intCast(data.len));
    try buf.appendSlice(allocator, data);
}

pub fn encodeEchoRequest(allocator: std.mem.Allocator, req: EchoRequest) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    if (req.payload.len > 0) try writeLenField(&buf, allocator, FIELD_PAYLOAD, req.payload);
    if (req.tag.len > 0) try writeLenField(&buf, allocator, FIELD_TAG, req.tag);
    return buf.toOwnedSlice(allocator);
}

pub fn encodeEchoResponse(allocator: std.mem.Allocator, resp: EchoResponse) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    if (resp.payload.len > 0) try writeLenField(&buf, allocator, FIELD_PAYLOAD, resp.payload);
    if (resp.tag.len > 0) try writeLenField(&buf, allocator, FIELD_TAG, resp.tag);
    return buf.toOwnedSlice(allocator);
}

const DecodeError = error{ Truncated, UnsupportedWireType };

fn readVarint(bytes: []const u8, pos: *usize) !u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (pos.* < bytes.len) {
        const b = bytes[pos.*];
        pos.* += 1;
        v |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return v;
        shift += 7;
        if (shift >= 64) return DecodeError.Truncated;
    }
    return DecodeError.Truncated;
}

fn skipField(bytes: []const u8, pos: *usize, wire_type: u3) !void {
    switch (wire_type) {
        WIRE_VARINT => _ = try readVarint(bytes, pos),
        WIRE_FIXED64 => {
            if (pos.* + 8 > bytes.len) return DecodeError.Truncated;
            pos.* += 8;
        },
        WIRE_LEN => {
            const len = try readVarint(bytes, pos);
            if (pos.* + len > bytes.len) return DecodeError.Truncated;
            pos.* += @intCast(len);
        },
        WIRE_FIXED32 => {
            if (pos.* + 4 > bytes.len) return DecodeError.Truncated;
            pos.* += 4;
        },
        else => return DecodeError.UnsupportedWireType,
    }
}

fn decodeEchoFields(allocator: std.mem.Allocator, bytes: []const u8, payload: *[]const u8, tag: *[]const u8) !void {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const tag_v = try readVarint(bytes, &pos);
        const field_no: u32 = @intCast(tag_v >> 3);
        const wire_type: u3 = @intCast(tag_v & 0x7);
        if (wire_type != WIRE_LEN or (field_no != FIELD_PAYLOAD and field_no != FIELD_TAG)) {
            try skipField(bytes, &pos, wire_type);
            continue;
        }
        const len = try readVarint(bytes, &pos);
        if (pos + len > bytes.len) return DecodeError.Truncated;
        const slice = try allocator.dupe(u8, bytes[pos .. pos + @as(usize, @intCast(len))]);
        pos += @intCast(len);
        switch (field_no) {
            FIELD_PAYLOAD => payload.* = slice,
            FIELD_TAG => tag.* = slice,
            else => unreachable,
        }
    }
}

pub fn decodeEchoRequest(allocator: std.mem.Allocator, bytes: []const u8) !EchoRequest {
    var payload: []const u8 = "";
    var tag: []const u8 = "";
    try decodeEchoFields(allocator, bytes, &payload, &tag);
    return .{ .payload = payload, .tag = tag };
}

pub fn decodeEchoResponse(allocator: std.mem.Allocator, bytes: []const u8) !EchoResponse {
    var payload: []const u8 = "";
    var tag: []const u8 = "";
    try decodeEchoFields(allocator, bytes, &payload, &tag);
    return .{ .payload = payload, .tag = tag };
}

pub fn freeEchoRequest(allocator: std.mem.Allocator, req: EchoRequest) void {
    if (req.payload.len > 0) allocator.free(req.payload);
    if (req.tag.len > 0) allocator.free(req.tag);
}

pub fn freeEchoResponse(allocator: std.mem.Allocator, resp: EchoResponse) void {
    if (resp.payload.len > 0) allocator.free(resp.payload);
    if (resp.tag.len > 0) allocator.free(resp.tag);
}
```

- [ ] **Step 5.4: Add the test executable to build.zig**

Modify `build.zig` — append after the existing `loopback-test` block:

```zig
    // Interop wire-codec unit tests.
    const interop_codec_tests = b.addTest(.{
        .name = "interop-codec-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interop/zig/harness_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_interop_codec_tests = b.addRunArtifact(interop_codec_tests);
    const interop_codec_test_step = b.step("interop-codec-test", "Run the interop wire-codec unit tests");
    interop_codec_test_step.dependOn(&run_interop_codec_tests.step);
```

- [ ] **Step 5.5: Run the tests, expect pass**

```bash
zig build interop-codec-test
```

Expected: silent success.

- [ ] **Step 5.6: Commit**

```bash
git add interop/zig/harness.zig interop/zig/harness_test.zig build.zig
git commit -m "interop(zig): proto3 wire codec for Echo messages"
```

---

## Task 6: Build the Zig interop server (uses GrpcServer + harness.zig)

**Files:**
- Create: `interop/zig/server_main.zig`
- Modify: `build.zig` — add `interop-server` step

- [ ] **Step 6.1: Write the server main**

Create `interop/zig/server_main.zig`:

```zig
//! Zig interop server. Registers a handler that decodes EchoRequest,
//! mirrors payload+tag back as EchoResponse, and writes via the
//! existing GrpcServer.

const std = @import("std");
const grpc_server = @import("../../src/server.zig");
const transport = @import("../../src/transport.zig");
const harness = @import("harness.zig");

const GrpcServer = grpc_server.GrpcServer;

fn echoHandler(
    request: []const u8,
    _: []const u8,
    trans: *transport.Transport,
    allocator: std.mem.Allocator,
) anyerror!void {
    const decoded = harness.decodeEchoRequest(allocator, request) catch |err| {
        std.log.err("decode EchoRequest: {}", .{err});
        return err;
    };
    defer harness.freeEchoRequest(allocator, decoded);

    const resp = harness.EchoResponse{
        .payload = decoded.payload,
        .tag = decoded.tag,
    };
    const out = try harness.encodeEchoResponse(allocator, resp);
    defer allocator.free(out);
    try trans.writeMessage(out);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    var port: u16 = 50062;
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // program name
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--port")) {
            const v = args.next() orelse return error.MissingPortValue;
            port = try std.fmt.parseInt(u16, v, 10);
        }
    }

    std.log.info("interop-zig-server listening on 127.0.0.1:{d}", .{port});

    var server = try GrpcServer.init(allocator, io, port, "interop");
    defer server.deinit();
    try server.handlers.append(allocator, .{ .name = "Echo", .handler_fn = echoHandler });

    try server.start();
}
```

- [ ] **Step 6.2: Add the build step**

Modify `build.zig` — add after the interop codec test block:

```zig
    // Zig interop server: linked the same way as loopback-test
    // (relative imports of server.zig + transport.zig from inside src/).
    const interop_server = b.addExecutable(.{
        .name = "grpc-interop-zig-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interop/zig/server_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    interop_server.root_module.linkLibrary(zlib_lib);
    const install_interop_server = b.addInstallArtifact(interop_server, .{});
    const interop_server_step = b.step("interop-server", "Build the Zig interop server binary");
    interop_server_step.dependOn(&install_interop_server.step);
```

- [ ] **Step 6.3: Build and confirm it listens**

```bash
zig build interop-server
./zig-out/bin/grpc-interop-zig-server --port 50062 &
SERVER_PID=$!
sleep 1
ss -tlnp 2>/dev/null | grep 50062 || netstat -tln | grep 50062
kill $SERVER_PID 2>/dev/null || true
```

Expected: port 50062 in the listing, then dies.

- [ ] **Step 6.4: Commit**

```bash
git add interop/zig/server_main.zig build.zig
git commit -m "interop(zig): server binary using GrpcServer + Echo handler"
```

---

## Task 7: Build the Zig interop client (uses GrpcClient + harness.zig)

**Files:**
- Create: `interop/zig/client_main.zig`
- Modify: `build.zig` — add `interop-client` step

- [ ] **Step 7.1: Write the client main**

Create `interop/zig/client_main.zig`:

```zig
//! Zig interop client. Encodes EchoRequest, fires it via GrpcClient,
//! decodes the response, and reports OK/FAIL like the Go client.

const std = @import("std");
const grpc_client = @import("../../src/client.zig");
const harness = @import("harness.zig");

const GrpcClient = grpc_client.GrpcClient;

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.io.getStdErr().writer().print("FAIL: " ++ fmt ++ "\n", args) catch {};
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const io = init.io;

    var host: []const u8 = "127.0.0.1";
    var port: u16 = 50062;
    var message: []const u8 = "ping";
    var tag: []const u8 = "zig-client";

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--target")) {
            const v = args.next() orelse fail("--target requires value", .{});
            const colon = std.mem.indexOfScalar(u8, v, ':') orelse fail("--target must be host:port", .{});
            host = try allocator.dupe(u8, v[0..colon]);
            port = try std.fmt.parseInt(u16, v[colon + 1 ..], 10);
        } else if (std.mem.eql(u8, a, "--message")) {
            message = args.next() orelse fail("--message requires value", .{});
        } else if (std.mem.eql(u8, a, "--tag")) {
            tag = args.next() orelse fail("--tag requires value", .{});
        }
    }

    var client = GrpcClient.init(allocator, io, host, port) catch |err| fail("dial: {}", .{err});
    defer client.deinit();

    const req_bytes = try harness.encodeEchoRequest(allocator, .{ .payload = message, .tag = tag });
    defer allocator.free(req_bytes);

    const resp_bytes = client.call("/interop.Interop/Echo", req_bytes, .none) catch |err| fail("call: {}", .{err});
    defer allocator.free(resp_bytes);

    const resp = harness.decodeEchoResponse(allocator, resp_bytes) catch |err| fail("decode: {}", .{err});
    defer harness.freeEchoResponse(allocator, resp);

    if (!std.mem.eql(u8, resp.payload, message)) {
        fail("payload mismatch: got '{s}' want '{s}'", .{ resp.payload, message });
    }
    std.log.info("OK payload='{s}' tag='{s}'", .{ resp.payload, resp.tag });
}
```

- [ ] **Step 7.2: Add the build step**

Modify `build.zig` — append:

```zig
    const interop_client = b.addExecutable(.{
        .name = "grpc-interop-zig-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interop/zig/client_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    interop_client.root_module.linkLibrary(zlib_lib);
    const install_interop_client = b.addInstallArtifact(interop_client, .{});
    const interop_client_step = b.step("interop-client", "Build the Zig interop client binary");
    interop_client_step.dependOn(&install_interop_client.step);
```

- [ ] **Step 7.3: Build the client**

```bash
zig build interop-client
```

Expected: silent success.

- [ ] **Step 7.4: Verify Zig-Zig round-trip via the binaries**

```bash
./zig-out/bin/grpc-interop-zig-server --port 50062 &
SERVER_PID=$!
sleep 1
./zig-out/bin/grpc-interop-zig-client --target 127.0.0.1:50062 --message hello --tag zig-zig
RC=$?
kill $SERVER_PID 2>/dev/null || true
test $RC -eq 0
```

Expected: client logs `OK payload='hello' tag='zig-zig'`, exits 0.

- [ ] **Step 7.5: Commit**

```bash
git add interop/zig/client_main.zig build.zig
git commit -m "interop(zig): client binary using GrpcClient + Echo round-trip"
```

---

## Task 8: Write the pair runner script

**Files:**
- Create: `interop/scripts/run-pair.sh`

- [ ] **Step 8.1: Write the script**

Create `interop/scripts/run-pair.sh` (and `chmod +x`):

```bash
#!/usr/bin/env bash
# run-pair.sh <server-bin> <client-bin> <port> [extra-client-args...]
# Spawns the server, waits for the port to listen, runs the client, and
# kills the server. Exit code is the client's exit code (0 = pass).

set -euo pipefail

SERVER="$1"; shift
CLIENT="$1"; shift
PORT="$1"; shift

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"$SERVER" --port "$PORT" >/tmp/interop-server-$$.log 2>&1 &
SERVER_PID=$!

# Wait up to 5 s for the server to listen on PORT.
for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
    exec 3<&- 3>&- || true
    break
  fi
  sleep 0.1
done

if ! (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
  echo "FAIL: server did not start on port $PORT (log below)" >&2
  cat /tmp/interop-server-$$.log >&2
  exit 90
fi
exec 3<&- 3>&- || true

set +e
"$CLIENT" --target "127.0.0.1:$PORT" "$@"
RC=$?
set -e

if [ $RC -ne 0 ]; then
  echo "--- server log ---" >&2
  cat /tmp/interop-server-$$.log >&2
fi
rm -f /tmp/interop-server-$$.log
exit $RC
```

- [ ] **Step 8.2: Smoke-test it on the Go-Go pair**

```bash
chmod +x interop/scripts/run-pair.sh
interop/scripts/run-pair.sh \
  ./zig-out/bin/grpc-interop-go-server \
  ./zig-out/bin/grpc-interop-go-client \
  50061 --message hello --tag run-pair
echo "EXIT=$?"
```

Expected: client logs `OK ...`, `EXIT=0`.

- [ ] **Step 8.3: Smoke-test on the Zig-Zig pair**

```bash
interop/scripts/run-pair.sh \
  ./zig-out/bin/grpc-interop-zig-server \
  ./zig-out/bin/grpc-interop-zig-client \
  50062 --message hello --tag run-pair
echo "EXIT=$?"
```

Expected: `EXIT=0`.

- [ ] **Step 8.4: Commit**

```bash
git add interop/scripts/run-pair.sh
git commit -m "interop: pair-runner script for cross-stack tests"
```

---

## Task 9: Run the cross-pair matrix and document failures

**Files:**
- Create: `interop/scripts/run-matrix.sh`
- Modify: `docs/interop/findings.md`

- [ ] **Step 9.1: Write the matrix runner**

Create `interop/scripts/run-matrix.sh`:

```bash
#!/usr/bin/env bash
# Run every (server, client) pair across the available stacks. Prints
# a summary table; exit code is the number of failed pairs.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/zig-out/bin"
RUN="$ROOT/interop/scripts/run-pair.sh"

pairs=(
  "go    go    50061 $BIN/grpc-interop-go-server   $BIN/grpc-interop-go-client"
  "go    zig   50063 $BIN/grpc-interop-go-server   $BIN/grpc-interop-zig-client"
  "zig   go    50064 $BIN/grpc-interop-zig-server  $BIN/grpc-interop-go-client"
  "zig   zig   50062 $BIN/grpc-interop-zig-server  $BIN/grpc-interop-zig-client"
)

fails=0
results=()
for pair in "${pairs[@]}"; do
  read -r SRV_LANG CLI_LANG PORT SRV_BIN CLI_BIN <<<"$pair"
  printf "\n>>> %-5s server  ×  %-5s client  on port %s\n" "$SRV_LANG" "$CLI_LANG" "$PORT"
  if "$RUN" "$SRV_BIN" "$CLI_BIN" "$PORT" --message hello --tag "$SRV_LANG-$CLI_LANG"; then
    results+=("PASS  $SRV_LANG×$CLI_LANG")
  else
    results+=("FAIL  $SRV_LANG×$CLI_LANG")
    fails=$((fails + 1))
  fi
done

echo
echo "==================== summary ===================="
for r in "${results[@]}"; do echo "$r"; done
echo "================================================="
exit $fails
```

- [ ] **Step 9.2: Build everything fresh and run the matrix**

```bash
chmod +x interop/scripts/run-matrix.sh
zig build interop-server interop-client
(cd interop/go && go build -o ../../zig-out/bin/grpc-interop-go-server ./server)
(cd interop/go && go build -o ../../zig-out/bin/grpc-interop-go-client ./client)
interop/scripts/run-matrix.sh | tee /tmp/matrix.txt
```

Expected behavior:
- `go × go` — PASS (control).
- `zig × zig` — PASS (loopback-equivalent).
- `go × zig` (Go server, Zig client) — likely FAIL: grpc-zig client sends response-style HEADERS (`:status: 200`) instead of request-style (`:method`, `:scheme`, `:path`, `:authority`, `content-type`, `te: trailers`); a real Go server will reject the stream.
- `zig × go` (Zig server, Go client) — likely FAIL: grpc-zig's `extractPathFromHpack` is incomplete; a real Go client emits a fully HPACK-encoded HEADERS block including dynamic-table updates, and our server's path extraction will likely fail to identify the requested method, so the handler may not run or may produce malformed output.

- [ ] **Step 9.3: Record findings**

Append the following two sections to `docs/interop/findings.md`, replacing the `<...>` placeholders with the actual error strings copied verbatim from `/tmp/matrix.txt`. If a pair unexpectedly passed, write `(unexpected pass — keep watching)` in the Symptom field instead of removing the entry.

```markdown
### go-server × zig-client

**Symptom:** <copy the actual error string from /tmp/matrix.txt>

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

**Symptom:** <copy the actual error string from /tmp/matrix.txt>

**Root cause:** grpc-zig's `Transport.extractPathFromHpack` only
recognizes a small subset of HPACK encodings (indexed header refs
and literal-with-incremental-indexing for fields whose name index
matches `:path` directly). Real gRPC clients emit a fully encoded
HEADERS block with literal-with-indexing and dynamic-table size
updates for headers like `:authority`, `user-agent`, and
`grpc-accept-encoding`. When path extraction fails, `last_method`
stays empty and the handler dispatch in `server.zig` either
mis-routes or produces no response.

**Fix path (separate plan):**
- Replace `extractPathFromHpack` with a complete RFC 7541 decoder
  that maintains the full dynamic table state across requests and
  exposes every header to the dispatch layer (not just `:path`).
- Add HPACK fixture tests using HEADERS blocks captured from
  grpc-go's debug logs so the decoder is verified against real
  client output.
```

- [ ] **Step 9.4: Commit**

```bash
git add interop/scripts/run-matrix.sh docs/interop/findings.md
git commit -m "interop: cross-pair matrix runner + initial findings log"
```

---

## Task 10: Wire the Go-Go pair into CI as a passing job; gate the cross-pair behind allow_failure

**Files:**
- Modify: `.gitlab-ci.yml`

- [ ] **Step 10.1: Add the `interop` stage and two jobs**

Edit `.gitlab-ci.yml`. After the existing `loopback-test:` block, append:

```yaml
  - interop

# Go-Go interop is the control: proves the harness itself works.
# Must pass — this never fails because of grpc-zig protocol gaps.
interop-go-go:
  stage: interop
  image: "golang:1.22"
  tags: ["company", "linux"]
  needs: []
  before_script:
    - apt-get update -qq && apt-get install -y --no-install-recommends curl ca-certificates
    - mkdir -p zig-out/bin
  script:
    - cd interop/go
    - go build -o ../../zig-out/bin/grpc-interop-go-server ./server
    - go build -o ../../zig-out/bin/grpc-interop-go-client ./client
    - cd ../..
    - chmod +x interop/scripts/run-pair.sh
    - interop/scripts/run-pair.sh ./zig-out/bin/grpc-interop-go-server ./zig-out/bin/grpc-interop-go-client 50061 --message ci-hello --tag go-go

# Cross-pair (Zig × Go in either direction) is allowed to fail until
# the protocol gaps documented in docs/interop/findings.md are fixed.
# Keeping the job in CI means we'll see the moment it goes green.
interop-cross:
  stage: interop
  image: "golang:1.22"
  tags: ["company", "linux"]
  needs: ["zig-build-0.16.0"]
  allow_failure: true
  before_script:
    - apt-get update -qq && apt-get install -y --no-install-recommends curl ca-certificates xz-utils python3 build-essential
    - bash scripts/install-zig.sh "$ZIG_VERSION"
    - export PATH="$(pwd)/zig-${ZIG_VERSION}:$PATH"
    - zig version
    - zig build interop-server interop-client
    - cd interop/go && go build -o ../../zig-out/bin/grpc-interop-go-server ./server && go build -o ../../zig-out/bin/grpc-interop-go-client ./client && cd ../..
  script:
    - chmod +x interop/scripts/run-pair.sh interop/scripts/run-matrix.sh
    - interop/scripts/run-matrix.sh
```

Also update `stages:` near the top:

```yaml
stages:
  - lint
  - build
  - test
  - interop
  - security
  - sbom
  - release
```

- [ ] **Step 10.2: Validate locally**

```bash
glab ci lint .gitlab-ci.yml
```

Expected: `✓ CI/CD YAML is valid!`

- [ ] **Step 10.3: Commit and push**

```bash
git add .gitlab-ci.yml
git commit -m "ci: add interop stage with go-go (must pass) + cross (allow_failure)"
git push origin main
```

- [ ] **Step 10.4: Watch the pipeline**

```bash
glab ci status -R devnw/zig/grpc-zig --compact | head -30
```

Expected: `interop-go-go` succeeds; `interop-cross` is the new failing-but-allowed job that produces the matrix output as its log.

---

## Follow-on plans (NOT in this plan's scope)

These should each be written as separate plans before execution. They're listed here only so the reader knows what's deferred:

1. **`fix(transport): proper client request headers`** — split `writeMessage` into server-response and client-request variants; thread the gRPC method path through `GrpcClient.call` and `ClientMux.call`. Likely unblocks the `go × zig` row in the matrix.
2. **`fix(transport): full HPACK request decoder`** — replace `extractPathFromHpack` with something that handles the full RFC 7541 surface a real Go/Rust/Python client emits (literal-with-incremental-indexing for `:authority`, `user-agent`, `grpc-accept-encoding`, etc.). Likely unblocks the `zig × go` row.
3. **Rust interop (tonic)** — analogous to Tasks 2-4 but in Rust under `interop/rust/`.
4. **Python interop (grpcio)** — analogous, under `interop/python/`.
5. **Server-streaming interop scenario** — once unary works across all stacks, add `EchoStream(EchoRequest) returns (stream EchoResponse)` and exercise it in the matrix.
6. **Compression / auth / large-payload scenarios** — currently exercised by the in-process loopback test; promote them to cross-stack matrix once basic interop is green.

---

## Execution notes

- The plan keeps grpc-zig's existing tests untouched. After each task, `zig build test`, `zig build loopback-test`, and the new interop binaries should all build/run cleanly.
- Tasks 1-8 are mechanical. Task 9 is the *interesting* one — it's where this plan delivers value, by surfacing the protocol gaps as concrete failures with logs we can act on.
- Task 10 ships the harness in CI even before the cross-pair is green, so the moment a follow-on plan fixes the protocol, the matrix flips from amber to green automatically and we'll see it.

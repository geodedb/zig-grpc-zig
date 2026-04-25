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

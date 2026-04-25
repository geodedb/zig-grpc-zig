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

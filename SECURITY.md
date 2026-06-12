# Security Policy

## Supported versions

grpc-zig is pre-1.0; only the latest tagged `v0.1.x` release receives fixes.

## Deployment guidance

- Do **not** expose a grpc-zig server directly to untrusted networks. The
  transport is plaintext h2c unless you supply TLS via `on_tls_accept`; deploy
  behind TLS/mTLS termination.
- Enable the auth gate (`require_auth = true`) with a strong, rotated secret.
- The server binds `127.0.0.1` by default; public binds are an explicit opt-in
  (`GrpcServer.initWithBind(..., "0.0.0.0", ...)` or `GRPC_ZIG_BIND_ADDR`).
- Resource limits (message size, frame size, connection count, flow-credit
  timeout) are enforced by default — review the `GRPC_ZIG_*` environment
  variables before raising them.

## Reporting a vulnerability

Open a **confidential** issue at
<https://gitlab.com/devnw/zig/grpc-zig/-/issues/new> (mark it confidential), or
email <benji@vester.by>. Please include a reproduction. You should receive a
response within 7 days.

## Known limitations

Tracked openly in `docs/SECURITY_GAP_ANALYSIS.md` and the issue tracker
(label `type::security`).

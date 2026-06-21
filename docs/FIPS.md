<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS-140-3 Mode (`-Dfips`)

## Flag semantics

`grpc-zig` builds with a `-Dfips` flag (default `false`). When **off**, security
crypto routes through `src/std_shim.zig` (pure `std.crypto`) with zero overhead,
no `fips` dependency, and no OpenSSL link. When **on**
(`-Dfips=true -Dopenssl_path=<prefix>`), the same call sites route through the
linked OpenSSL 3.x FIPS-140-3 provider via the lazy `fips` package, and
`crypto_backend.assertActive()` hard-fails if the validated provider is absent.

```sh
zig build test --summary all
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl --summary all
```

`-Dfips` is added to the EXISTING single `build_options` instance (GAP-0020-safe);
`crypto_backend` is threaded everywhere `build_options_mod` is, plus the
`auth_tests` root.

## Routed (security) call sites

| Site | Primitive | Seam call |
|------|-----------|-----------|
| `src/features/auth.zig` `generateToken` | HS256 JWT signature HMAC-SHA256 | `crypto_backend.Mac.hmac(.sha256, …)` |
| `src/features/auth.zig` `verifyToken` | HS256 JWT verify HMAC-SHA256 | `crypto_backend.Mac.hmac(.sha256, …)` |

## `fips-exempt` (allow-listed non-security) uses

| Site | Reason |
|------|--------|
| `src/features/auth.zig` `HmacSha256` alias | compile-time `mac_length` only; the HMAC computation goes through the seam |
| `src/features/auth.zig` `timing_safe.eql` tag compare | constant-time tag compare, no algorithm choice |

## Behavior changes / removals under `-Dfips=true`

None. HS256 JWT signature/tag bytes are byte-identical under both modes
(HMAC-SHA256 in both backends); verify still uses `std.crypto.timing_safe.eql`
for the constant-time compare.

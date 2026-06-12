# Contributing

## Toolchain

- Zig **0.16.0** (`scripts/install-zig.sh` installs the pinned version).
- Pre-commit: `pre-commit install` (zig fmt, shellcheck, ruff, markdownlint,
  commitizen commit messages, diamond-dep check).

## Workflow

1. Branch from `main`; commits follow Conventional Commits (`feat:`, `fix:`,
   `refactor:`, `chore:`, ...) — enforced by commitizen.
2. `zig build test` must pass locally, plus
   `zig fmt --check src/ build.zig tests/ examples/`.
3. For transport/protocol changes, also run the loopback smoke test:
   `zig build loopback-test && ./zig-out/bin/grpc-loopback-test`.
4. Open a merge request; CI runs unit tests under four optimize modes, the
   Go↔Zig interop matrix, and h2spec conformance — all are required gates.

## Tests

New protocol behavior needs a dedicated `src/*_test.zig` regression test wired
into the `test` step in `build.zig` (see `hpack_varint_test.zig` for the
pattern). Bug fixes follow TDD: write the failing test first.

## Security

See [SECURITY.md](SECURITY.md). Never commit real secrets in code, tests, or
benchmarks — CI runs gitleaks and will block the pipeline.

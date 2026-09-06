# blanket

Rust workspace: universal package-manager kernel. Read ARCHITECTURE.md first;
design history in blanket-notes.md. What is built is in NEXT.md; what has not
been independently reviewed is in REVIEW.md — check it before trusting a
recent feature.

- Build: `cargo build` · unit tests: `cargo test` (offline)
- Heavy integration tests (network + real PyPI): `cargo test -- --ignored`
  or the full checklist: `bash tests/acceptance.sh`
- `cargo test | tail` reports the exit code of `tail`, so a failing suite looks
  green. Use `set -o pipefail`, or do not pipe.
- Never point `BLANKET_STORE` at a real store in tests — use a temp dir. It is
  process-global, so a test that sets or clears it must hold
  `store::STORE_ENV_LOCK`, or it will redirect a concurrent test to the real
  store. Tests that record policy exceptions take the matching guard around
  `policy::clear()`.
- Store objects are immutable and input-addressed; changing what goes INTO
  an object (inputs map in `Identity`) changes its id — never mutate an
  existing object's semantics without a new identity field.
- Pinned artifacts (CPython in src/python.rs, build toolchain in
  src/build.rs) carry sha256s verified at pin time; update the hash whenever
  you update a pin.
- Platforms: macOS arm64 and Linux x86_64. `src/platform.rs` is the only
  place that knows the host; pins are per-platform rows; helpers take an
  explicit `Platform`. Darwin identity goldens must stay byte-identical.
- Linux: sandbox is bubblewrap (`dnf install bubblewrap`); run e2e gates
  with `BLANKET_SANDBOX_TESTS=required` and `TMPDIR` on a real disk (the
  tests keep per-run stores under TMPDIR; a 12 GB tmpfs fills). The
  offline checks in acceptance.sh use `unshare -rn` on Linux.
- LINUX_PORT.md is the port's plan + changelog; append to it when you
  change platform behavior.

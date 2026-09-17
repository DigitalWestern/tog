# blanket

Rust workspace: universal package-manager kernel. Start with STATUS.md
(where the project is, what is next) and docs/human/ARCHITECTURE.md (how
it works, including the layering rules). FOLLOW-UPS.md is the only to-do
list; docs/agent/DESIGNS.md holds designed-but-unbuilt features. Run
`cargo fmt --check` before committing.

- Layers point one way: `commands → tailors → comforter → kernel`; `cli` is
  pure grammar. The kernel never names a tailor; a tailor never names another
  tailor or a command. `tests/architecture.rs` fails the build otherwise.
- One folder per PR (`kernel/`, `comforter/`, one `tailors/<eco>/`, or
  `commands/`) unless the change is a shared-layer review; the allow-list in
  `tests/architecture.rs` is where cross-layer exceptions are documented.
- Adding an ecosystem: implement the `Tailor` trait and register it, see
  docs/human/ADDING-A-TAILOR.md.
- Build: `cargo build` · unit tests: `cargo test` (offline)
- Heavy integration tests (network + real PyPI): `cargo test -- --ignored`
  or the full checklist: `bash tests/acceptance.sh`
- `cargo test | tail` reports the exit code of `tail`, so a failing suite looks
  green. Use `set -o pipefail`, or do not pipe.
- Never point `BLANKET_STORE` at a real store in tests — use a temp dir. It is
  process-global, so a test that sets or clears it must hold
  `store::STORE_ENV_LOCK`, or it will redirect a concurrent test to the real
  store. Tests that realize through a child take
  `supervise::SUPERVISION_TEST_LOCK`; `--ignored` targets need
  `--test-threads=1`. Tests that record policy exceptions take the matching
  guard around `policy::clear()`.
- Store objects are immutable and input-addressed; changing what goes INTO
  an object (inputs map in `Identity`) changes its id — never mutate an
  existing object's semantics without a new identity field.
- Pinned artifacts (CPython in src/tailors/python/mod.rs, build toolchain
  in src/tailors/python/build.rs) carry sha256s verified at pin time; update the hash whenever
  you update a pin.
- Platforms: macOS arm64 and Linux x86_64. `src/kernel/platform.rs` is the only
  place that knows the host; pins are per-platform rows; helpers take an
  explicit `Platform`. Darwin identity goldens must stay byte-identical.
- Linux: sandbox is bubblewrap (`dnf install bubblewrap`); run e2e gates
  with `BLANKET_SANDBOX_TESTS=required` and `TMPDIR` on a real disk (the
  tests keep per-run stores under TMPDIR; a 12 GB tmpfs fills). The
  offline checks in acceptance.sh use `unshare -rn` on Linux.
- When you change platform behavior, update the Platforms section of
  docs/human/ARCHITECTURE.md.
- Documentation stays small. Root + docs/human/ are for humans (concise,
  current); docs/agent/ holds only DESIGNS.md and HITRATE.md. Do not create
  ledgers, review reports, evidence dumps, or changelogs: review results go
  in the pull request description, history is git. When a feature ships,
  move its description from DESIGNS.md into docs/human/ and delete its
  FOLLOW-UPS.md item. Code comments describe behavior; they do not cite plan
  item numbers or documents that may be deleted.

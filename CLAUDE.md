# blanket

Rust workspace: universal package-manager kernel. Read ARCHITECTURE.md first;
design history in blanket-notes.md.

- Build: `cargo build` · unit tests: `cargo test` (offline)
- Heavy integration tests (network + real PyPI): `cargo test -- --ignored`
  or the full checklist: `bash tests/acceptance.sh`
- Never point `BLANKET_STORE` at a real store in tests — use a temp dir.
- Store objects are immutable and input-addressed; changing what goes INTO
  an object (inputs map in `Identity`) changes its id — never mutate an
  existing object's semantics without a new identity field.
- Pinned artifacts (CPython in src/python.rs, build toolchain in
  src/build.rs) carry sha256s verified at pin time; update the hash whenever
  you update a pin.

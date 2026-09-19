<!-- One folder per PR: kernel/, comforter/, commands/, or one tailors/<eco>/.
     A change that has to cross layers is a shared-layer review; the
     exceptions live in the allow-list in tests/architecture.rs. -->

- [ ] `cargo fmt --check` and `cargo test` pass (CI runs both)
- [ ] Platform behavior changed: the Platforms section of docs/human/ARCHITECTURE.md is updated
- [ ] Review findings, if any, are written here rather than in a new document

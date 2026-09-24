# FOLLOW-UPS — open work and decisions

The one to-do list. Every item here is open. When an item ships, delete it;
its pull request description is the record of what was done and how it was
reviewed. Detail for designed-but-unbuilt features lives in
`docs/agent/DESIGNS.md`; known, accepted gaps live in
`docs/human/LIMITATIONS.md`. Code comments cite an item by its title, never
by position.

## Next up, in order

1. **The two-machine toolchain-lock diff.** The toolchain lock shipped on
   Linux on 2026-09-21; everything but this is done. A lock carries a row per
   platform and is written from the releases complete on both, so a lock
   written on Linux must sync on an arm64 Mac without rewriting itself and
   `tog status` must answer identically on both. Sync the same project on
   each machine and diff `tog-toolchain.toml` byte for byte. It is proven by
   test today, not by two machines, and it is part of the macOS gate at the
   bottom of this file. The same run should sync one locked project into two
   fresh stores on one machine and compare the realized object ids: the
   offline replay test (`tests/toolchain_lock.rs`) proves the lock answers
   without the catalog, not that two stores realize the same objects (#136).

## Decisions waiting on the owner

- **Help after every bare `tog` (#145).** Since #142 a successful sync is
  followed by the full help screen, which can scroll the sync result away.
  Watch daily use; the candidates are a short footer, the full screen only
  when nothing needed syncing, or leaving it.
- **A shared system store at `/opt/tog/store`:** decided 2026-09-23: full
  design round on ownership, permissions, and cross-user GC (see #69).
- **First outside target.** Cheapest visible artifact: a GitHub Action
  running `tog --frozen` under the company policy plus `tog sbom`, which
  should work on GitHub-hosted Ubuntu runners if unprivileged user
  namespaces are allowed there. Parked 2026-09-23; revisit after #87
  (see #70).
- **Is `skipped-optional` an exception at all?** An optional dependency
  group the user did not request is a choice, not a waiver, yet it drives the
  strict hit rate down to 8/30 on Python (`docs/agent/HITRATE.md`).
  Decided 2026-09-23: informational closure field, not an exception
  (see #71).
- **Key and credential policy for the trust work.** Where trusted publisher
  keys live, who rotates them, and what revocation means (including a
  company's own internal publisher); a test account for private-registry
  credentials. Blocks the authenticated parts of `docs/agent/DESIGNS.md`
  §2 and §4.

## Open work, each its own pull request

- **`tog audit` without trusted keys (#144).** It exits 2 by design, so a
  recorded policy exception has no command that judges it in the default
  unsigned setup. Decided 2026-09-23: both an unsigned mode of `audit`
  and exceptions in `tog status`; then the exception summary can name a
  real fix again. Stays open until both land.
- **An offline fixture where a sync succeeds (#147).** Every green-sync
  test downloads a toolchain and is ignored, so "bare `tog`, then the
  help" and anything else that runs after a successful sync is verified by
  hand. That includes `tog build` syncing a stale ecosystem first; the
  ignored e2e suites could drop their explicit `sync` step to cover it.

- **Supervision redesign: one signal session per operation.** Today one
  process supervises at most one child; a second concurrent session is
  rejected with a named busy error (`Session::new` in
  `src/kernel/supervise.rs`). That follows from process-wide `sigaction`
  state, not from a design choice. Two alternatives were tried and rejected,
  so do not retry them: a hard rejection enforced in tests turned a green
  suite red because parallel test threads legitimately supervise at once,
  and a blocking lock reintroduces an unbounded silent wait. The interim
  workaround is `SUPERVISION_TEST_LOCK` plus `--test-threads=1` for
  `--ignored` targets. Design: `docs/agent/DESIGNS.md` §5 "Per-operation
  signal sessions" (#57); implementation follows its review.
- **The resolution proxy (#68).** Delegated tools (`add`/`remove`/`update`,
  missing-lock generation, `tog x`) run unsandboxed with network today.
  Design: `docs/agent/DESIGNS.md` §6 (#196). PR 0, the measured evidence,
  shipped in #209; its macOS Mach allow-list waits on one run of
  `tools/proxy_spike/macos_mach.sh` on a Mac. The rest, in order: #198 (PR 1,
  the door type), #199, #200, #201 (PR 3b), #202, #203, #204, #205, #206,
  #207, #208 (PR 10, remove `Legacy`). Found by PR 0 and slotted into those:
  #210 (uv ignores `UV_PYTHON`), #211 (`bundle add` installs), #212 (npm
  notifier and audit requests).
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
  - #174 npm: git-tracked `node_modules` in workspace members moved into backups.
  - #180 build: first build with no lock still needs a catalog row for every ecosystem.
  - #183 `status`/`doctor` create and lease the store; add a read-only context mode.
  - #188 npm: realize `file:` packages as tog-owned trees.
  - #190 `tog x` py: tools in a Rust-locked project build sdists on shipped Rust.
  - #191 provider object-kind rows still live in the tailors' `objects.rs`.
  - #214 npm/pnpm: a required foreign-platform dependency is refused (tailwindcss).
  - #215 python: sdists that need Rust at build time (stable-diffusion-webui).
  - #216 python: `uv pip compile` fails for vllm and MetaGPT; classifier label.
- **`deps` as a `Tailor` method.** `src/commands/deps.rs` still names
  tailors directly. A `Tailor::edit_manifest` method with an "unsupported"
  default would make it registry-driven, the way `Tailor::registry_tool`
  did for `x`. It is its own design review: deps edits user manifests.
  The signature, carrying the resolution door, is in `docs/agent/DESIGNS.md`
  §6; it ships as resolution proxy PR 1 (#198), which also moves the
  Corepack/pnpm path (#169).
- **GC loose ends from #162.** Three small `src/kernel/store/roots.rs`
  fixes: a case-mismatched `gc --dry-run --forget` key previews fewer
  deletions on macOS (#163); the root/2 importer calls a path inside this
  store's own object "another store" (#164); re-importing a
  `node-forest/2` closure adds a legacy `projection_id` projection sync
  never published (#165).
- **`gc --migrate-metadata` as a `fix:` line (#166).** It resolves only a
  transient failure. Recommended: keep `fix:`.
- **Two PEP 440 version grammars.** `src/kernel/toolchain/select.rs` has
  the small numeric `Version`/specifier subset the toolchain selector needs;
  `src/tailors/python/pep440.rs` has the full grammar. The Python source
  reader (toolchain lock PR 3) must lower one into the other and the kernel
  cannot import the tailor's copy. Hoist `pep440.rs` into `src/kernel/`
  and have the selector use it, in its own PR.
- **Unreproduced test flakes.**
  `kernel::gitsrc::realization_tests::realizes_a_commit_and_strips_git_metadata`
  (2026-09-12) and `tailors::cargo::tests::rejects_symlinked_crate_entries`
  (2026-09-15) each failed once in a full parallel run and passed on every
  rerun. The panic messages were not captured. Capture them next time before
  changing anything.
- **macOS arm64 gate. Last, by the owner's choice.** Run on the Mac:
  `cargo test`, `cargo test --test gc -- --ignored`,
  `cargo test --test cli audit`, and
  `cargo test --test toolchain_lock -- --ignored`, including the
  case-insensitive-filesystem paths the root-key code relies on. Darwin
  identity goldens must stay byte-identical, and the two-machine lock diff
  above is run here. Nothing Linux-side clears this.

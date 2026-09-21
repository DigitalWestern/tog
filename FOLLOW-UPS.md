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
   bottom of this file.

## Decisions waiting on the owner

- **Delegated-tool doors under company policy.** `add`/`remove`/`update` and
  missing-lock generation run the ecosystem's own tool unsandboxed with
  network, outside what `tog audit` can see. Options: a registry-proxy
  design round, or refuse those verbs under company policy and require lock
  edits outside tog (keeps the door closed but weakens the agent story).
- **A shared system store at `/opt/tog/store`:** decide, or defer
  explicitly.
- **First outside target.** Cheapest visible artifact: a GitHub Action
  running `tog sync` under the company policy plus `tog sbom`, which
  should work on GitHub-hosted Ubuntu runners if unprivileged user
  namespaces are allowed there.
- **Is `skipped-optional` an exception at all?** An optional dependency
  group the user did not request is a choice, not a waiver, yet it drives the
  strict hit rate down to 8/30 on Python (`docs/agent/HITRATE.md`).
- **Key and credential policy for the trust work.** Where trusted publisher
  keys live, who rotates them, and what revocation means (including a
  company's own internal publisher); a test account for private-registry
  credentials. Blocks the authenticated parts of `docs/agent/DESIGNS.md`
  §2 and §4.

## Open work, each its own pull request

- **`tog audit` does not read the toolchain lock.** `status` reports a
  missing or stale `tog-toolchain.toml` and a closure built from another
  bundle; `audit` reuses only the per-record `closure_state`, so a gate that
  passes `audit` can still be running a toolchain the lock no longer names.
  Fold `inspect::toolchain_lock_state` into the audit freshness verdict; the
  audit fixtures then need a lock beside each closure.
- **Go's lockless resolver picks the lowest satisfying pin, selection the
  newest.** `go::resolve_project_toolchain` (used by `doctor` and the Go
  `status` row) keeps Go's minimum-version rule; the toolchain selector takes
  the newest complete release satisfying `go.mod`. Identical with one pinned
  Go; the day a second pin lands, `doctor` and `status` would name a version
  `sync` does not use. Route both through the lock.

- **npm regressions from the 2026-09-11 hit-rate run.** All four synced on
  2026-09-05 at the same pinned commits. Error text is in
  `docs/agent/HITRATE.md`.
  - *vitejs/vite:* a git-tracked `node_modules` directory inside a pnpm
    workspace member
    (`packages/vite/src/node/__tests__/plugins/fixtures/license/dep-license-mit/node_modules`).
    Projection correctly refuses to overwrite a real directory
    (`replace_project_symlink`, `src/comforter/mod.rs`). Needs a rule:
    either a path that already owns a real `node_modules` is not a workspace
    to project, or the pnpm importer's workspace list is too broad.
  - *microsoft/playwright:* `commit env: cache dependency sha256:… is
    unavailable`. The env commit names a cache object that is missing during
    a single sync. Likely object metadata's cache-dependency recording.
    Reproduce with a fresh store before assuming anything.
  - *mermaid-js/mermaid:* `pnpm patch fastdom has no package@version
    identity`. pnpm `patchedDependencies` keyed by a bare package name
    applies to every version. Decide whether to support it by applying the
    patch to each locked version.
  - *ChatGPTNextWeb/NextChat:* git source checkout of
    `Azure-Samples/aoai-realtime-audio-sdk` at `abf2e9a8…` fails with
    `unable to read tree`. The fetch is too shallow for the checkout; check
    whether the commit is on a non-default branch.
- **Supervision redesign: one signal session per operation.** Today one
  process supervises at most one child; a second concurrent session is
  rejected with a named busy error (`Session::new` in
  `src/kernel/supervise.rs`). That follows from process-wide `sigaction`
  state, not from a design choice. Two alternatives were tried and rejected,
  so do not retry them: a hard rejection enforced in tests turned a green
  suite red because parallel test threads legitimately supervise at once,
  and a blocking lock reintroduces an unbounded silent wait. The interim
  workaround is `SUPERVISION_TEST_LOCK` plus `--test-threads=1` for
  `--ignored` targets. Needs its own design review.
- **Thread the caller's activity token through child processes.** About 25
  sites mint a fresh lease per child, and several extraction and clone
  helpers take no token at all, so protection cannot be proved at the call
  site. The same fix removes the `Store::has` lock-order inversion. Site
  table in `docs/agent/DESIGNS.md` §5.
- **Descriptor-relative project access in sync.** Every command reads the
  project by pathname, so a same-user process that swaps the project
  directory mid-sync can make tog sync the replacement
  (`docs/human/LIMITATIONS.md`). Raised by review on 2026-09-16 and declined
  there as pre-existing. Closing it means every tailor reads through a held
  directory descriptor. Builds on `src/kernel/fsroot.rs`.
- **Missing GC tests.** 18 of the 26 tests the GC design named do not exist
  by name. List in `docs/agent/DESIGNS.md` §5.
- **GC mutation survivor: redundant root marking.** Removing the marking set
  in the sweep is not observable, because `root_live` independently protects
  the same objects. Either add a test that observes the marking set or
  delete it as redundant.
- **`deps` and `x` as `Tailor` methods.** `src/commands/deps.rs` and
  `src/commands/x.rs` are the only command files that still name a tailor
  (Python and Node). A `Tailor::edit_manifest` and a
  `Tailor::registry_tool` method with "unsupported" defaults would make both
  registry-driven. Each is its own design review: deps edits user manifests,
  and x has its own cache and root registration.
- **Two cross-tailor edges, allow-listed in `tests/architecture.rs`.**
  `tailors/python/build.rs` uses the cargo tailor's pinned toolchain to
  build sdists with Rust extensions. `tailors/node/` uses the Python tailor's
  CPython pin, `artifacts`, and `nativelibs` for node-gyp install scripts.
  A kernel-level toolchain/artifact provider would remove both. Each move is
  its own PR: relocate the module, keep object ids byte-identical, then
  delete the allow-list row.
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
  `tailors::node::lock_import::tests::pnpm_9_base32_patch_hashes_are_accepted_and_stored_verbatim`
  (2026-09-20) failed once the same way at `lock_import/mod.rs:1009`, the
  `policy::pending().len() == 1` assertion, although it holds
  `exception_guard`; so some other test records an exception without it.
- **Independent review of `Store::roots_for_sweep`.** The one production
  change in the 2026-09-10 macOS fix commit (`fb8b1d6`): unusable root
  records are routed into the sweep's refusal. It was never reviewed by an
  agent that did not write it.
- **macOS arm64 gate. Last, by the owner's choice.** Run on the Mac:
  `cargo test`, `cargo test --test gc -- --ignored`,
  `cargo test --test cli audit`, and
  `cargo test --test toolchain_lock -- --ignored`, including the
  case-insensitive-filesystem paths the root-key code relies on. Darwin
  identity goldens must stay byte-identical, and the two-machine lock diff
  above is run here. Nothing Linux-side clears this.

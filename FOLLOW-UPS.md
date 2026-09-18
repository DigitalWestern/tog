# FOLLOW-UPS — open work and decisions

The one to-do list. Every item here is open. When an item ships, delete it;
its pull request description is the record of what was done and how it was
reviewed. Detail for designed-but-unbuilt features lives in
`docs/agent/DESIGNS.md`; known, accepted gaps live in
`docs/human/LIMITATIONS.md`. Code comments cite an item by its title, never
by position.

## Next up, in order

1. **`blanket audit`: ship signing plus the `outdated` verdict together.**
   Owner decision 2026-09-16. A record with no `platform` field, no inputs,
   or no exceptions array fails today as `unchecked`, so every project
   synced before those fields existed fails on first adoption. Keep the
   failure (a warning would pass a record with no exceptions list), but
   report it as `outdated` with the fix in the message (`blanket sync` once,
   then commit). Unsigned records get the same treatment, so adopters
   migrate once. The reviewed design is `docs/agent/DESIGNS.md` §5.
   Done when LIMITATIONS.md no longer says a hand-edited record audits as
   it says.
2. **Toolchain lock (WP2), shipped-table adapter first.** The next large
   feature: a committed lock naming the exact toolchain per project. Design,
   remaining PRs, and the recommended order (PR 1 before the lock core) are
   in `docs/agent/DESIGNS.md` §1.

## Decisions waiting on the owner

- **Delegated-tool doors under company policy.** `add`/`remove`/`update` and
  missing-lock generation run the ecosystem's own tool unsandboxed with
  network, outside what `blanket audit` can see. Options: a registry-proxy
  design round, or refuse those verbs under company policy and require lock
  edits outside blanket (keeps the door closed but weakens the agent story).
- **A shared system store at `/opt/blanket/store`:** decide, or defer
  explicitly.
- **First outside target.** Cheapest visible artifact: a GitHub Action
  running `blanket sync` under the company policy plus `blanket sbom`, which
  should work on GitHub-hosted Ubuntu runners if unprivileged user
  namespaces are allowed there.
- **Is `skipped_optional` an exception at all?** An optional dependency
  group the user did not request is a choice, not a waiver, yet it drives the
  strict hit rate down to 8/30 on Python (`docs/agent/HITRATE.md`).
- **Key and credential policy for the trust work.** Where trusted publisher
  keys live, who rotates them, and what revocation means (including a
  company's own internal publisher); a test account for private-registry
  credentials. Blocks the authenticated parts of `docs/agent/DESIGNS.md`
  §2 and §4.

## Open work, each its own pull request

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
  table in `docs/agent/DESIGNS.md` §6.
- **`src/fsroot.rs`: descriptor-relative project writes.** Never started.
  Also the base for contained plan-cache writes and for the toolchain lock.
  Rules in `docs/agent/DESIGNS.md` §6.
- **Descriptor-relative project access in sync.** Every command reads the
  project by pathname, so a same-user process that swaps the project
  directory mid-sync can make blanket sync the replacement
  (`docs/human/LIMITATIONS.md`). Raised by review on 2026-09-16 and declined
  there as pre-existing. Closing it means every tailor reads through a held
  directory descriptor. Probably builds on `src/fsroot.rs`.
- **Missing GC tests.** 18 of the 26 tests the GC design named do not exist
  by name. List in `docs/agent/DESIGNS.md` §6.
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
- **Unreproduced test flakes.**
  `kernel::gitsrc::realization_tests::realizes_a_commit_and_strips_git_metadata`
  (2026-09-12) and `tailors::cargo::tests::rejects_symlinked_crate_entries`
  (2026-09-15) each failed once in a full parallel run and passed on every
  rerun. The panic messages were not captured. Capture them next time before
  changing anything.
- **Independent review of `Store::roots_for_sweep`.** The one production
  change in the 2026-09-10 macOS fix commit (`fb8b1d6`): unusable root
  records are routed into the sweep's refusal. It was never reviewed by an
  agent that did not write it.
- **macOS arm64 gate. Last, by the owner's choice.** Run on the Mac:
  `cargo test`, `cargo test --test gc -- --ignored`, and
  `cargo test --test cli audit`, including the case-insensitive-filesystem
  paths the root-key code relies on. Darwin identity goldens must stay
  byte-identical. Nothing Linux-side clears this.

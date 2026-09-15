# FOLLOW-UPS — flagged items awaiting later decisions

Owner-directed flags from the GC-safety wrap-up (2026-09-10). This file is the
single place a future session (human or model) should look before touching the
flagged code. Items here are deliberate: each one was considered and *not*
taken during the GC-safety work, with the reason recorded.

## Flag 1 — supervision session design: redesign owed, interim behavior is deliberate

**Current behavior (kept on purpose).** One supervised child per process; a
second supervisory session in the same process is rejected with a named
`WouldBlock` busy error (`src/kernel/supervise.rs`, `Session::new`, the `try_lock`
arm). Production entry points run children sequentially through one lease, so
the rejection only fires on a programming error.

**Why the obvious alternatives were rejected (do not re-litigate without
reading these):**
- The B-round reviewer asked for this rejection; Nova implemented it
  (`try_lock` + named error), mutation-checked it — and it turned a green
  505-test suite red: parallel test threads legitimately supervise
  concurrently, and B.2 explicitly permits independent shared operations to
  coexist. `REVIEW.md`, row "Packages B and C, leftover fix round", records
  the withdrawal.
- Restoring a blocking lock (the reviewer's fallback) re-introduces an
  unbounded silent wait — the exact self-deadlock shape B's fixes eliminated
  elsewhere; B's convention is that contention is a named outcome. The
  in-file comment at `Session::new` argues this and is the settled position.

**The real fix (tracked here, out of scope for the GC-safety PR):** make the
signal session per-operation. Process-wide `sigaction` dispositions cannot be
partitioned per store, so today's one-session-per-process rule is a
consequence of that global state, not a design choice. A per-operation
session would let independent operations supervise concurrently. That is a
design change needing its own review round; test-suite concurrency
(`SUPERVISION_TEST_LOCK`, `--test-threads=1` for `--ignored` targets) is the
documented interim workaround.

## Flag 2 — gc.rs rebuild incident: re-examine whether provenance re-verification is owed

**What happened.** During Rho's D fix round (2026-09-09), a mistaken
`git checkout -- src/gc.rs` reverted the file to HEAD (Package A's version),
destroying Kilo's D rewrite in the working tree. Rho rebuilt it from Sol's
pristine snapshot copy plus re-applied edits, then re-verified.

**What was verified after the rebuild (behavioral):**
- full offline suite green (578/0 at the time; 578/0 again after commit-slicing),
- all gc-targeted mutations re-run (22/23 exit 101, M05 known survivor),
- an independent recheck subagent: 17/17 `sol_*` probes, both real-record
  replays refuse with caches intact, repo integrity hash unchanged,
- Atlas's post-stability re-audit found no merge/revert artifacts (no
  duplicated functions, no stale references to removed functions, no
  conflict markers or `.orig`/`.rej` residue).

**What was never verified (provenance):** that the rebuilt file is
byte-lineage-identical to the pre-incident working tree. Behavioral evidence
says it does not matter; this flag exists so a later examiner can decide.

**Question for the examiner:** is post-incident behavioral verification
sufficient (the position taken here), or does the incident warrant a
line-level diff of the committed `src/gc.rs` against Sol's pristine copy plus
the re-applied fix set? Evidence pointers: `/tmp/opencode-sol-D-1ter4V/`
(`pristine/`, `snapshot-files.sha256`, `REVIEW-REPORT.md`),
`docs/agent/D10-ACCEPTANCE-2026-09-09.md` §8, `docs/agent/REVIEW.md` D rows. Note the pristine copy
predates Rho's fixes, so a plain diff is expected to differ; the comparison
must include the four fix hunks (F1 grammar table, F2 `clear_crash_temps`,
F3 report accounting, F4 acceptance tests).

## Follow-up PR list (each its own reviewable unit)

1. **C.10 test matrix** — 20 of 26 named tests still missing. The 11 that
   were blocked by D's in-flight lib-target rewrite are unblocked now that D
   is committed. 6 exist (Kilo's interaction items).
2. **B.5 token threading** — ~25+ `status_owned`/`output_owned` sites mint a
   fresh lease per child instead of holding the caller's token (19 in
   D-touched files). README documents the gap honestly; the thread is not
   done.
3. **`src/fsroot.rs`** — C.4 leftover, never started.
4. **`Store::has` lock order** — self-acquires activity underneath the x-root
   lock (B.3 order inversion). Not reachable as a deadlock today; the real
   fix is item 2's threading.
5. **macOS arm64 gate** — `cargo test` and `cargo test --test gc -- --ignored`
   on the Mac, including the case-insensitive-filesystem paths the root-key
   code relies on. Nothing Linux-side clears this.
6. **M05 mutation survivor** — redundant-marking acceptance gap, known and
   documented in `docs/agent/D10-ACCEPTANCE-2026-09-09.md` §8.
7. **Grammar-table drift for the 21st (kind,schema) pair** — adding a pair
   requires extending `objmeta::grammar_for`; unlisted pairs fail closed
   (refusal), but a listed pair with a wrong grammar needs its own drift test.
8. **Flaky unit test `x::tests::shared_x_lock_blocks_nonblocking_cleanup_until_runner_exit`**
   — failed once in the full `cargo test` run of 2026-09-12 (REFACTOR.md
   Stage 2 gate) and passed on every rerun, including 5/5 in isolation and
   the whole lib suite. The nonblocking exclusive `flock` after
   `drop(shared)` can lose to a sibling test's fork-then-exec window (the
   lock lives on the open file description, which a forked child shares
   until its `CLOEXEC` close). Not caused by the move (`x.rs` moved
   verbatim); fix is to retry the try-lock briefly or isolate the test.
   Also seen once, 2026-09-12 Stage 4 gate:
   `kernel::gitsrc::realization_tests::realizes_a_commit_and_strips_git_metadata`
   failed in one full parallel run and passed 3/3 alone and in the full
   rerun. It holds `SUPERVISION_TEST_LOCK`; the panic was not captured.
   Treat as the same family until reproduced.
9. **`tests/python_select.rs::unpinned_patch_request_fails_closed_before_opening_store`
   fails at HEAD, before the refactor.** Verified 2026-09-12 on `a341b32`
   (the last pre-refactor commit): `blanket sync` opens the store in
   `dispatch` before `preflight_sync` refuses the unpinned patch request,
   so the store tree exists when the test checks it. The refusal itself is
   still correct (exit 1, message intact); only the "before opening the
   store" half of the test is false. Either move the store open after the
   preflight (a behavior change: `sync` would preflight before the
   maintenance sweep) or relax the test. Not touched by the refactor.
10. **`deps` and `x` as `Tailor` methods.** After REFACTOR.md Stage 3,
   `commands/deps.rs` and `commands/x.rs` are the only command files that
   still name a tailor (python and node). A `Tailor::edit_manifest` and a
   `Tailor::registry_tool` method with "unsupported" defaults would make
   both registry-driven; each is its own design review (deps edits user
   manifests; x has its own cache and root registration).
11. **Two cross-tailor edges, allow-listed in `tests/architecture.rs`.**
   `tailors/python/build.rs` uses the cargo tailor's pinned toolchain to
   build sdists with Rust extensions, and `tailors/node/mod.rs` uses the
   Python tailor's CPython pin, `artifacts` (download/provision) and
   `nativelibs` (shared-library env) for node-gyp install scripts. Both
   `artifacts` and `nativelibs` are ecosystem-neutral in practice; a
   kernel-level toolchain/artifact provider would remove both edges. Each
   move is its own PR: relocate the module, keep the object ids
   byte-identical (identity inputs must not change), then delete the
   allow-list row.

## Flag 3 — `blanket audit`: three product decisions the reviewer asked the owner to make

Raised in the 2026-09-11 round-2 review of `blanket audit` (REVIEW.md entry
7). Each has a defensible default implemented; none was guessed at beyond
that default, and none blocks the feature.

- **D1 — toolchain-only records pass with no comparison.** An inputs-free
  `rustfmt.json` (what `blanket fmt` writes) is the one record shape that
  passes with no tie to the project: it has no inputs, so freshness is
  `toolchain-only` and only its exceptions are judged. Options: keep it
  (current, documented in CLI.md); report it `unchecked` unless a flag opts
  in; or bind it to the pinned rustfmt version so there is something to
  compare. Keeping it is reasonable; it should be a conscious call because
  it is the last unconditional pass.
- **D2 — `unchecked` fails, and round 2 made it stricter.** A closure with
  no `platform` field, no recorded inputs, or no `exceptions` array exits 1.
  Every project synced before the Linux-port envelope field therefore fails
  the gate on first adoption until one `blanket sync`. Correct for a gate;
  confirm the rollout story is acceptable.
- **D3 — the gate authenticates nothing.** The record sha256 names a file
  in the working tree; it does not prove who wrote it. Against a hostile
  branch, editing `body.exceptions[]` audits clean. Documented in
  LIMITATIONS.md. If `audit` is meant to gate untrusted branches, the
  evidence has to come from a signature or from store/attestation records,
  which is a feature decision, not a fix.

## Flag 4 — `blanket audit` hardening plan

Ordered by what buys the most trust per hour, except that the Mac gate is
last by the owner's choice. H1–H2 are verification the feature already
owes under this repo's rules; H3 is the one real design piece; the rest
are small. Each item names its exit criterion so a session
can pick it up cold.

- **H1 — independent recheck of the round-2 nit fixes. Done
  2026-09-15.** N1 (mapping extracted to `audit::freshness_from_state` and
  tested directly), N2 (stray-file message), N3 (`policy::test_env_lock`
  held by the env-reading tests) were rechecked by a Claude Opus 5 subagent
  that did not write them, and the recheck was itself reviewed by GPT-5.6
  Sol. N1 and N2 stand; N3's guard was right but applied to three tests when
  seven lib tests read `HOME`/`BLANKET_POLICY` in-process, so the two
  `doctor_*` tests in `src/commands/inspect.rs` and the two `$HOME`-reading
  sandbox tests in `src/kernel/sandbox.rs` now take it too. Two test-only
  edits in all (the mapping test's inner match made exhaustive so a new
  `State` variant cannot skip it, plus the added locks) and two recorded
  residuals on the stray-file path.
  Evidence and method are in the 2026-09-15 row of the `docs/agent/REVIEW.md`
  log; the entry-7 row's "verified by the author only" clause is gone.
- **H2 — acceptance coverage.** Add `blanket audit` to
  `tests/acceptance.sh`: after a real Python and npm sync, run it under the
  offline check (`unshare -rn` on Linux) with `--policy
  docs/human/policy-company.toml`, assert exit 0 on the clean fixtures and
  exit 1 after planting one denied exception; assert `~/.blanket/store` mtime
  is unchanged across the run. Done when the checklist has the rows and they
  pass on Linux.
- **H3 — make the evidence harder to forge (Flag 3 D3).** Two designs,
  pick one after the owner answers D3:
  1. *Store cross-check, opt-in.* Object-affecting exceptions
     (`policy::object_exceptions`: file-collision, install-script-failed,
     git-dependency, unattested_cargo_lock) are already written into store
     `meta/<id>.json` and rechecked on cache hits. `audit --verify-store`
     would open the store read-only (shared lease, no writes) and require
     each closure's object ids to exist and their metadata exceptions to be
     a subset of what the closure records; a closure whose exception list
     was trimmed by hand then fails as `tampered`. Cheap, no new formats,
     but it covers only the object-affecting kinds and breaks the "no store
     access" property, hence opt-in.
  2. *Signed closures.* Sync signs the envelope with a machine or CI key;
     audit verifies the signature before judging. Covers every kind and
     works with no store, but adds key management, a schema change to the
     envelope (additive field), and a story for closures made before the
     key existed. Bigger, and only worth it if the gate is meant to run
     against untrusted branches.
  Done when the chosen design has its own review round and LIMITATIONS.md's
  audit bullet no longer says a hand-edited record audits as it says.
- **H4 — mutation check of `src/commands/audit.rs`.** This repo's rule is that
  fixes get mutation-checked; audit has not been. Flip each arm of
  `Verdict::passes`, each `Freshness` mapping in `freshness_from_state`, the
  `KINDS` membership test, and the `check_name` comparison; every mutant
  must turn at least one test red. Done when the survivors (if any) are
  listed here or in REVIEW.md.
- **H5 — policy provenance in the report.** `policy::load` unions silently;
  the JSON report says what is denied but not which file said so. Return
  the contributing sources from `load` (path → deny entries, strict) and
  emit them under `policy.sources`, so a CI log shows whether a denial came
  from the machine, the repository, or `--policy`. Done when the CLI test
  asserts the sources for a project-plus-flag case.
- **H6 — per-closure attribution guard.** Attribution of exceptions to a
  closure relies on sync realizing and publishing one ecosystem at a time
  (`project.rs` clears the pending list after each write). Add a debug
  assertion, or a test, that the pending list is empty when each
  ecosystem's realization begins, so a future concurrent sync cannot
  silently cross-attribute. Done when the assertion exists and the suite is
  green.
- **H7 — Flag 3 D1 and D2 outcomes.** Whatever the owner decides for the
  toolchain-only pass and the unchecked strictness, encode it in CLI.md, the
  `audit` help text, and one test each. Done when the two decisions are no
  longer open in Flag 3.
- **H8 — Mac gate (deliberately last; the owner does not want to deal with it until the rest is done).** `cargo test` and `cargo test --test cli audit` on
  Darwin. The `inspect::status` → `closure_state` split touches every
  `status` path, and Darwin identity goldens must stay byte-identical (no
  identity input changed, so they should). Done when the LINUX_PORT.md
  2026-09-1x entry records the run.

## npm regressions found by the 2026-09-11 hit-rate run (each its own PR)

All at the pinned 2026-09-05 commits, all `ok` on 2026-09-05, all failing at
`fb8b1d6`; full error text in `docs/agent/HITRATE.md` (2026-09-11 section)
and `tests/fixtures/hitrate-linux-2026-09-11.csv`. The three
workspace-local-package failures (gemini-cli, create-react-app, pi) are
fixed on this branch; these five are not:

8. **vitejs/vite — checked-in `node_modules` inside a workspace member.**
   `packages/vite/src/node/__tests__/plugins/fixtures/license/dep-license-mit/node_modules`
   is a real, git-tracked directory; the pnpm importer lists that fixture as
   a workspace and projection now refuses to overwrite a real directory
   (`replace_project_symlink`, src/comforter/mod.rs). Decide: a fixture path that
   already owns a real `node_modules` is not a workspace to project, or the
   pnpm importer's workspace list is too broad. Loud, correct refusal; needs
   a rule.
9. **microsoft/playwright — `commit env: cache dependency sha256:… is
   unavailable`.** The env commit names a cache object that is not there.
   Likely object-meta/2 cache-dependency recording vs. the harness pruning
   `cache/` between repos — but the prune happens *between* repos, so the
   object was missing during a single sync. Reproduce with a fresh store
   before assuming anything.
10. **mermaid-js/mermaid — `pnpm patch fastdom has no package@version
    identity`.** pnpm `patchedDependencies` keyed by bare package name
    (applies to every version). New fail-closed row; decide whether to
    support name-only patches by applying to each locked version.
11. **paperclipai/paperclip — pnpm patch hash mismatch.** Expected value is
    pnpm's base32 (`fymctidcjqjhi4cj72qtivlxry`), computed is sha256 hex.
    pnpm 9+ stores patch hashes as base32-encoded truncated sha256; blanket
    compares the wrong encoding. Verify against pnpm source before fixing.
12. **ChatGPTNextWeb/NextChat — git source checkout `unable to read tree`.**
    item-4 git realization of `Azure-Samples/aoai-realtime-audio-sdk` at
    `abf2e9a8…`: the fetch is too shallow/partial for the checkout. Check
    whether the commit is on a non-default branch or the tree needs a full
    fetch.

Also noted, not a regression: tailwindcss fails because its pnpm lock marks
`@parcel/watcher-darwin-arm64` as *required* with `os=["darwin"]`; the
harness labels it `py_no_wheel`, which is wrong — add an
`npm_platform_required` class when touching the classifier next.

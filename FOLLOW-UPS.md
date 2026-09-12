# FOLLOW-UPS — flagged items awaiting later decisions

Owner-directed flags from the GC-safety wrap-up (2026-09-10). This file is the
single place a future session (human or model) should look before touching the
flagged code. Items here are deliberate: each one was considered and *not*
taken during the GC-safety work, with the reason recorded.

## Flag 1 — supervision session design: redesign owed, interim behavior is deliberate

**Current behavior (kept on purpose).** One supervised child per process; a
second supervisory session in the same process is rejected with a named
`WouldBlock` busy error (`src/supervise.rs`, `Session::new`, the `try_lock`
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
   (`replace_project_symlink`, src/project.rs). Decide: a fixture path that
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

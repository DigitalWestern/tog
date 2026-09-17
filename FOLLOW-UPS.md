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
7. **Grammar-table drift for the 21st (kind,schema) pair** — implemented
   on `fu/7-grammar-drift`; Sol r5 FIX-THEN-MERGE fixes applied; schema
   successors pending owner decision. Each `KindAdapter` row now has a
   migration grammar, a live required/optional grammar, and, where its
   producer has dynamic or conditional identity shape, a full
   `live_contract` over the complete `Identity`. Contracts beside the
   producer constructors validate collection counts, paired keys,
   platform-specific inputs, and the producer's own provisioning decision
   (`python::artifacts::provisioned_version` is consulted by both the Node
   producer and the `node-env` contract, so a dropped `provisioned:` key is
   caught under the current schema). Debug commits run the generic checks
   before the contract at `Store::commit_internal_impl`. Unknown kinds and
   schema pairs fail closed.

   | kind | undetectable drift | successor schema and field that closes it |
   |---|---|---|
   | `cargo-vendor/1` | A one-crate plan drops its sole `crate:` key and becomes the legitimate empty plan. | `cargo-vendor/2`, an unconditional crate count. |
   | `python-env/2` | A one-wheel plan drops its sole `pkg:` key, or an inspected native sdist drops `native_libs`. | `python-env/3`, a plan digest over the package set plus an explicit native decision (a package count alone cannot see a dropped `native_libs`). |
   | `node-env/3` | A multi-package plan drops one `pkg:` key, or an `artifact:` or Linux `native_libs` key is dropped. | `node-env/4`, a plan digest over the package set and declared artifacts plus an explicit native decision (a provisioning/native flag alone cannot see a dropped package or artifact). |
   | `sdist-build/3` | Both `rust`/`vendor` or both `native_libs`/`native_linker` are dropped together. | `sdist-build/4`, explicit build-mode and native-mode fields. |

   Introducing any successor schema reissues every object id of that kind
   because store objects are input-addressed. That is an owner decision and
   is tracked here. The two-platform matrix uses real producer constructors,
   seeds the Electron checksum manifest and byte-identical local sdists
   (`build::deterministic_tar_gz`: fixed mtimes, ids, order, and gzip
   header, so fixture identities are reproducible across runs and tar
   implementations) for the conditional paths, checks migration readability,
   and rejects every live-required input. A migration-required input must
   be live-required or explicitly `legacy_only`; parking one in
   `live_optional` fails the structural test. The relation tests reject
   one-half drops for NuGet's `pkg:`/`raw:` pair, Go's module triplet,
   BEAM's Linux relocation pair, both sdist pairs, Node's layout/package
   relation in both directions, Node's pkg/provisioned relation, and the
   currently detectable package side of Node/Python conditional relations.
   Count tests reject one dynamic key for every count contract. Limitation
   tests accept and pin the four documented schema gaps above.
8. **Flaky unit test `x::tests::shared_x_lock_blocks_nonblocking_cleanup_until_runner_exit`**
   — failed once in the full `cargo test` run of 2026-09-12 (REFACTOR.md
   Stage 2 gate) and passed on every rerun, including 5/5 in isolation and
   the whole lib suite. The nonblocking exclusive `flock` after
   `drop(shared)` can lose to a sibling test's fork-then-exec window (the
   lock lives on the open file description, which a forked child shares
   until its `CLOEXEC` close). Not caused by the move (`x.rs` moved
   verbatim). **Fixed 2026-09-14 (test only):** after `drop(shared)` the x
   test now retries the nonblocking exclusive try-lock for up to 2 s, 10 ms
   between attempts, and asserts it eventually succeeds; the assertion that
   the try-lock fails *while* `shared` is held is unchanged, and
   `lock_x_root` itself was not touched. 20/20 green in a loop plus a clean
   full `cargo test`. The gitsrc sighting below is still unreproduced.
   Also seen once, 2026-09-12 Stage 4 gate:
   `kernel::gitsrc::realization_tests::realizes_a_commit_and_strips_git_metadata`
   failed in one full parallel run and passed 3/3 alone and in the full
   rerun. It holds `SUPERVISION_TEST_LOCK`; the panic was not captured.
   Treat as the same family until reproduced.
9. **`tests/python_select.rs::unpinned_patch_request_fails_closed_before_opening_store`.
   Fixed 2026-09-16 on `fu/9-sync-preflight-order`.** Owner decision: make
   the behavior match the test. `blanket sync` now loads policy and runs
   every tailor's preflight in `sync::run_command` before `Context::open`,
   so a refused request creates no store tree, runs no maintenance sweep and
   takes no lease. `add`/`remove`/`update` still call `sync::run` with the
   context they opened. The test failed at `origin/main` (`store was
   opened`) and passes on the branch, and now runs in the default suite.
   Because preflight now happens before a possibly long wait on the store
   lease, `run_command` records the directory's (dev, ino) first and refuses
   if the pathname names a different directory after `Context::open`; the
   tailor set preflight checked is the one synced. **Residual, not fixed:**
   after that check, the sync (policy, detection results, every tailor's
   file reads) still addresses the project by pathname, so a same-user
   process that swaps the directory mid-sync can make blanket sync the
   replacement under the original's policy. Pre-existing on `main` for every
   command; closing it means directory-fd-relative project access in every
   tailor, which is its own design item.
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

**Owner decisions, 2026-09-16:**
- D1: bind the rustfmt record to the pinned rustfmt version so it is
  compared like every other record; the `toolchain-only` pass goes away.
- D2: keep the failure (a warning would pass a record with no exceptions
  list), but give pre-envelope records their own `outdated` verdict whose
  message is the fix (`blanket sync` once, commit). Ship it with D3 so
  adopters migrate once.
- D3: signed closures (H3 design 2). `audit` is expected to judge records
  committed by people and machines other than the one running it, so the
  store cross-check, which needs a local store and covers four of fourteen
  kinds, is not enough. Design and review before code.

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
- **H2 — acceptance coverage. Done (2026-09-14).** `tests/acceptance.sh`
  step 13 runs `blanket audit --policy docs/human/policy-company.toml` over
  the polyglot project synced in step 11, under `deny_net` (`unshare -rn` on
  Linux): four rows — exit 0 on the clean python + node closures, exit 1
  naming the kind and subject after planting one `install-script-failed`
  exception into `node.json`, clean and planted `--json` reports requiring
  current passing/denied verdicts, and the absent store path under an
  unwritable directory after all three audit runs. Run on Linux (Fedora,
  2026-09-14) via a scratch driver that extracts the step-13 and helper lines
  from `tests/acceptance.sh` with `sed -n` and runs them against a real
  `proj-poly` sync: passed=4 failed=0. The full checklist was not re-run.
- **H3 — make the evidence harder to forge (Flag 3 D3).** The owner chose
  design 2, signed closures (2026-09-16, Flag 3); design 1 is kept for the
  record:
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
- **H4 — mutation check of `src/commands/audit.rs`. Done 2026-09-14.** 31
  hand-written mutants over every decision the gate makes (each clause of
  `Verdict::passes`, `Report::passes`, every `State` arm of
  `freshness_from_state`, the `KINDS` membership test, `check_name`, the
  `policy::denied` call and the missing-record branch in `evaluate`, and the
  three guards in `freshness`). 30 died on the first pass; the one survivor
  was `Report::passes` `.all(…)` → `.any(…)`, invisible because every test
  built a single-verdict report — a project with one clean and one denied
  closure would have exited 0. A new unit test,
  `one_failing_closure_fails_the_whole_report`, kills it; the full set
  re-run afterwards is 31 killed, 0 survivors. Table and per-mutant kill
  list: docs/agent/AUDIT-MUTATION-2026-09-14.md; the driver and mutant
  definitions are checked in under docs/agent/audit-mutation-2026-09-14/,
  with a log row in docs/agent/REVIEW.md.
- **H5 — policy provenance in the report. Done (2026-09-15).**
  `policy::load_with_sources` returns the merged policy plus every policy
  that contributed, in merge order, with its origin and optional `path`,
  `strict`, and `deny`; `load` is now a thin wrapper over it, so there is one
  loading algorithm and no caller changed. `audit::effective_policy` appends
  the `--policy` file after the ordinary chain. `--json` emits sources under
  `policy.sources` with lossy UTF-8 paths, adds lowercase raw-byte
  `path_bytes` only for non-UTF-8 paths, and omits `path` for strictness-only
  sources (additive; every existing field is unchanged). The same lossy path
  helper keeps `project` and closure `path` strings JSON-safe, adding sibling
  `project_bytes` or `path_bytes` only for non-UTF-8 paths. The text report
  prints one source line per source on stdout. File paths are always
  Rust-Debug-quoted as `policy: <origin> "<path>" [denies ...] [(strict)]`;
  strictness-only sources omit the path. Lines come before verdicts regardless
  of `--quiet`; existing file sources are listed even when they deny nothing.
  Covered by `policy::tests::load_with_sources_attributes_each_deny_to_the_file_that_asked_for_it`
  and `cli::audit_json_attributes_each_policy_to_its_source_file`.
- **H6 — per-closure attribution guard. DONE ON `fu/4-attribution-guard` (2026-09-15).**
  Exception attribution now uses an explicit `policy::Attribution` token
  backed by the same process-global frame stack in production and tests.
  `Tailor::prepare`, `Tailor::sync`, and closure-producing build/format paths
  receive the token and forward it to the comforter writer. Writers validate
  object bodies, claim only their matching ecosystem's innermost frame before
  writing, and mark it published only after the write completes. Nested
  attribution handles dependency-edit delegates that publish a Node `x`
  closure, while edit frames are discarded before the subsequent sync. Finish
  requires publication when success is reported and rejects unclaimed
  exceptions. Cache hits and edits with no closure explicitly discard their
  frames. Only the frame's owning thread may record into it; a frame that
  was claimed but never published cannot finish; `claim` is crate-private to
  the comforter boundary and `clear`/`drain` are gone from the public API.
  The process-global test lock serializes every test that records or
  opens attribution, and the mixed Cargo/pnpm ignored e2e regression covers
  the original cross-ecosystem contamination case. Five adversarial Sol
  rounds (docs/agent/REVIEW.md); r5 on the token design was FIX-THEN-MERGE
  and its two blockers (cross-thread record, claimed-unpublished finish) are
  the two rules above.
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
11. **paperclipai/paperclip — pnpm patch hash mismatch.** *Fixed.* The guess
    above was wrong: pnpm 9 writes `createBase32HashFromFile`, which is **md5**
    (not a truncated sha256) in RFC 4648 base32, lowercased with padding
    stripped — 26 characters
    ([crypto.base32-hash](https://github.com/pnpm/pnpm/blob/v9.15.0/packages/crypto.base32-hash/src/index.ts),
    called from
    [calcPatchHashes.ts](https://github.com/pnpm/pnpm/blob/v9.15.0/lockfile/settings-checker/src/calcPatchHashes.ts)).
    pnpm 10 and 11 switched that same call site to `createHexHashFromFile`,
    the full sha256 hex ([crypto/hash](https://github.com/pnpm/pnpm/blob/v10.15.0/crypto/hash/src/index.ts)).
    Both generations first read as UTF-8 with replacement, then hash after
    `content.split('\r\n').join('\n')`. `check_patch_hash`
    (src/tailors/node/lock_import/pnpm.rs) accepts `sha256-<hex>`, bare hex,
    and the pnpm 9 base32 form, and reports whether a declaration matched raw
    bytes or normalized/lossy text. The pnpm 9 md5 form is always
    normalized/lossy; SHA-256 forms accept either digest. A normalized match
    records the raw-byte SHA-256 in `NpmPatch.content_sha256`, while a raw
    match records `None`, preserving every previously accepted identity.
    It fails closed on anything else. Lock import records the md5 form as a
    `weak-integrity` exception and a denying policy refuses it. At realization
    `apply_verified_patch` rechecks the hash, requires a raw match when no raw
    SHA-256 was bound and the bound digest otherwise, then
    writes the exact verified bytes to a fresh private `stage-*` directory
    under `<store>/tmp`, feeds that snapshot to `patch`, and removes the whole
    directory on every ordinary exit path; GC reclaims an interrupted stage.
    md5 and the base32 encoder are hand-written, with no new
    dependency. The declared string is stored verbatim because `NpmPatch.hash`
    is an environment-identity input. Existing raw SHA-256-declared patch ids
    stay byte-identical; normalized matches use
    `patch[<hash>;sha256:<raw hex>]`.
12. **ChatGPTNextWeb/NextChat — git source checkout `unable to read tree`.**
    item-4 git realization of `Azure-Samples/aoai-realtime-audio-sdk` at
    `abf2e9a8…`: the fetch is too shallow/partial for the checkout. Check
    whether the commit is on a non-default branch or the tree needs a full
    fetch.

Also noted, not a regression: tailwindcss fails because its pnpm lock marks
`@parcel/watcher-darwin-arm64` as *required* with `os=["darwin"]`. **Done:**
`tests/hitrate.py` now has an `npm_platform_required` class (matching
`required dependency does not support host`, placed above
`py_sdist_build_failed`/`py_no_wheel` so it wins); the
`tests/fixtures/hitrate-linux-2026-09-11.csv` row keeps its historical
`py_no_wheel` label because the fixture is a record of that run.

# Review queue

Independent adversarial review coverage, original briefs, and completed rounds. PLAN.md tracks what to *build*; this file tracks what has not
been independently *checked*. They are different debts and they were getting
confused inside one paragraph of the old NEXT.md.

## Ground rules

- **Independent** means not the agent that wrote the code and not the
  supervising agent. Self-review and supervisor sign-off do not clear an entry
  here; they only downgrade it from ⬛ to 🟡.
- **Reviewed** means an adversarial round that produced written findings, and
  the fixes for those findings were re-checked. A round that finds nothing is a
  finished round only if it was looking for the right things — see the recurring
  defect classes below.
- Record every completed round in the log at the bottom. An entry leaves this
  file only when it is ✅.

Current status: all five review entries are ✅. The briefs below preserve the
original risk questions; gate outcomes and remaining platform validation are
in [REVIEW-2026-09-06.md](REVIEW-2026-09-06.md).

Legend: ⬛ never reviewed · 🟡 partial, final round missing · ✅ reviewed and fixes rechecked

---

## 1. ✅ CLI levels one and two — PR #20, branch `cli/levels-1-2`

Original review brief: approximately 5,970 lines. Reviewed by Astra on
2026-09-06; findings R1–R4, R11, R13–R15 and rechecks are in the report.

| Area | Files |
|---|---|
| Grammar and dispatch | `src/cli.rs` (1894), `src/main.rs` (rewritten, 1736) |
| `add`/`remove`/`update` | `src/deps.rs` (1175) |
| `status`/`ls`/`doctor` | `src/inspect.rs` (1086) |
| `blanket x` | `src/xrun.rs` (316) |
| Output | `src/ui.rs` (198) |
| Tests | `tests/cli.rs` |

**Why this is first.** It contains the two most dangerous new behaviours in the
codebase, and both are dangerous by design rather than by accident:

- `deps.rs` delegates every manifest and lockfile edit to a store tool (uv, the
  store node's npm, cargo, go, bundler, mix) **running unsandboxed with
  network** — its own module doctrine says so explicitly, and calls it the same
  trust boundary as missing-lockfile generation. It also edits one file itself:
  a plain requirements file, by text append.
- `xrun.rs` creates project directories under `~/.blanket/x/`, registers them as
  gc roots, and `exec`s.

**Look for:** argument injection into the delegated tool command lines (the
recurring class — see below); the evidence ladder choosing the wrong ecosystem
on ambiguous input, and whether a wrong choice is recoverable or silently
destructive; the requirements-file text append corrupting an existing file
(encoding, missing trailing newline, duplicate or conflicting pins); gc roots
that `x` creates and never removes; `-C <dir>` path handling; usage errors
leaking an exit code other than 2, and command failures leaking 2.

**Also included in this review:** the merge commit `1b63849` and the
test-locking changes in `9dd1f94`, which touch `store.rs`, `cargo.rs`,
`golang.rs`, `inspect.rs` and `policy.rs`. Test-only code, but it changed
locking, and locking changes deserve an adversary too.

## 2. ✅ Item 4, git dependencies — PRs #14 (npm), #15 (python), #16 (cargo)

Files: `src/gitsrc.rs`, `src/npm.rs`, `src/npm_lock_import.rs`, `src/pypi.rs`,
`src/cargo.rs`, `tests/git_deps.rs`.

**Why it matters.** This is the first feature that fetches arbitrary remote code
identified by a URL, and it **deliberately skips three checks that exist for
tarballs** — the "only https registry tarballs" gate, the missing-integrity
error, and the SRI policy check — on the argument that the commit hash *is* the
verification. That argument was tested in this round; see R5–R7 and R10.

**Look for:** whether the `rev-parse HEAD` check can be bypassed or satisfied by
something other than the requested commit; the full-history fallback path used
for servers that refuse reachable-sha fetches; submodules taken at recorded
commits; whether `.git` removal is complete in every path, including failure
paths; URL normalization collisions, where two different repositories normalize
to one store identity; symlinks or paths in the fetched tree escaping the store
object.

## 3. ✅ Item 5, artifacts and electron provisioning — PRs #13, #17

Files: `src/artifacts.rs`, `src/npm.rs`, `tests/electron_provision.rs`.

**Look for:** the environment-variable table, where every entry is supposed to
have been read out of the published package's own source and never from memory
— spot-check that claim against the real packages; skip switches that quietly
disable a security control rather than a download; the electron release zip
landing in the cache its installer reads without an integrity check on the way
in.

## 4. ✅ PR #19 review fixes — supervising agent only

Commits `2967d4a` (lockfile attestation, portable deterministic packing, input
validation) and `c3de1bd`. These fixes had only supervisor verification before this round. R7 and R8
record gaps found during the independent recheck.

## 5. ✅ Items 7, 10, 12 and gc — final round rechecked

These had one to five Astra rounds each. Only the **last** round's fixes went
unverified: Codex hit its usage limit and the supervising agent verified them
against the findings and the gate instead. So review the final fix commits, not
the whole feature.

| Item | Area | Final fix commit | Main file |
|---|---|---|---|
| 7 | pnpm/yarn (PR #11) | `5c312f7` | `src/npm_lock_import.rs` |
| 10 | manifests (PR #12) | `28a7db7` | `src/manifest.rs`, `src/pep440.rs` |
| 12 | native libs (PR #10) | `ebf852b` | `src/nativelibs.rs` |
| gc | (PR #8) | `f5ff425` | `src/gc.rs` |

---

## Recurring defect classes

Astra's roughly seventy findings clustered into a small number of shapes. Check
these first in any new area; they have each already been real here at least
once.

- **Argument injection** into a delegated tool's command line (found in tar
  handling and dependency-edit delegation).
- **Archive links escaping** the extraction root.
- **Sandbox escape by delegation** — a resolver executing build backends outside
  the sandbox.
- **Destructive gc** — collecting a pre-registry project's objects.
- **Incomplete identity** — an input that affects output but is left out of the
  store object id, so two different environments share one id.
- **Process-global state in tests** — `BLANKET_STORE` and `policy`'s pending
  exception list have both produced non-deterministic suite failures that
  masked, rather than revealed, real behaviour.

## Logistics

- **2026-09-06 review complete:** Astra reviewed all five entries; Luna agents
  implemented fixes and Astra rechecked them. See
  [the written findings and validation](REVIEW-2026-09-06.md).
- **Gates:** `cargo test` for unit/integration tests without network;
  `cargo test -- --ignored` for network and real toolchains. On Linux use
  disk-backed `TMPDIR`, a disposable `BLANKET_STORE`, and
  `BLANKET_SANDBOX_TESTS=required`.
- Use `--target-dir` for a separate Cargo build directory. Exporting
  `CARGO_TARGET_DIR` also redirects nested fixture builds.
- The original queue incorrectly claimed per-ecosystem dependency-edit tests
  existed. They are now implemented in `tests/deps_e2e.rs`.
- The new CLI and follow-up fixes still need validation on macOS arm64;
  previous macOS acceptance results predate them.
- Capture Cargo's exit status directly; piping to `tail` can hide failures.

## Logistics

- **Codex** hit its usage limit at 03:18 on 2026-09-06; it resets
  **2026-09-12**. Astra rounds are queued behind that. Per PLAN.md working rules,
  Claude subagents are the stand-in while Codex is rate-limited.
- **Gates:** `cargo test` for unit; `cargo test -- --ignored` for e2e, which
  needs network and real toolchains. On Linux put `TMPDIR` on a real disk.
- **The e2e gates have not been run on the CLI branch.** 33 tests are `--ignored`
  there, including the per-ecosystem `add` tests.
- **`cargo test | tail` reports the exit code of `tail`, not cargo.** A failing
  suite looks green. Use `set -o pipefail`, or do not pipe.

## Log

Completed rounds. Add a row when an entry above reaches ✅.

| Date | Area | Reviewer | Rounds | Findings | Outcome |
|---|---|---|---|---|---|
| ≤2026-09-06 | items 7, 10, 12, gc, and earlier work | GPT-6 Astra | 1–5 each | ~70 fixed, several security-relevant | 🟡 final round unverified |
| 2026-09-06 | items 4 and 5 | supervising agent only | — | — | ⬛ not independent |
| 2026-09-06 | CLI levels 1–2 (PR #20), Git, artifacts, #19, final fixes of #8/#10/#11/#12 | GPT-6 Astra | review + iterative fix rechecks | 15 categories; see report | ✅ reviewed and fixes rechecked; macOS validation outstanding |
| 2026-09-07 | WP4 pnpm dependency edits (branch `wp4/deps-pnpm-yarn`): `blanket add/remove/update` through the store pnpm, Corepack hash verification, workspace-glob lock selection, per-run scratch for pnpm's modules state | GPT-5.6 Sol (Codex), independent, r1–r2; Claude Opus 5 subagent (fresh, did not write the code; not independent of Codex), r3–r4; r5 supervising agent only (author's recheck of its own round-4 fixes) | 5 | r1: 5 blocker (ancestor-lock selection crossed projects; non-exact `packageManager` accepted; Yarn scratch TOCTOU, workspace-member scratch, store-Yarn not guaranteed — Yarn edits then removed) + 1 should; r2: 1 blocker (ancestor pnpm checked before the project's own package-lock) + 5 should; r3: 3 should (only `+sha224` accepted; `{a,b}`/`?` globs silently non-matching; pnpm home not gc-reclaimable) + 2 nit; r4: 1 blocker (pnpm wrote `node_modules/.modules.yaml` into the user's project and refused an installed project's own store) + 1 should (case-sensitive `npm_config_` scrub) + 2 nit; r5: all four verified by the author (modules state redirected into a per-run stage with `enable-modules-dir=false`, proven against pnpm 9.12.3 and by two installed-project e2e tests), 2 nits open (registry metadata re-fetched every edit; pre-installed workspace e2e stops before `sync`) | 🟡 superseded by the 2026-09-08 round-6 review below |
| 2026-09-08 | WP4 pnpm dependency edits (branch `wp4/deps-pnpm-yarn`), round 6: cold re-review of the round-4/5 fixes plus a sweep of the rest of the diff | Claude Opus 5 subagent (fresh, did not write the code; not independent of Claude — Codex unavailable) | 1 (two passes) | 1 blocker (`node-linker` unforced: a committed `.npmrc` with `node-linker=hoisted` makes a workspace-root edit a real install that rewrites a member's `node_modules`; reproduced and fixed) + 1 blocker (workspace globs have no alternation support, so `(apps|libs)/*` silently excluded a real member and `add` wrote a stray `package-lock.json`; membership now reads the lock's `importers`) + 4 should (per-importer relative-path invariant was false — claim corrected and the real guarantee documented; `force_env` panicked on a non-char-boundary prefix slice; pnpm store escaped to `~/.pnpm-store`; hand-written `pnpm-workspace.yaml` rejected by the lockfile-shaped YAML parser, now unreached for members in the lock) + 8 nit | 🟡 superseded by the 2026-09-08 round-7 review below |
| 2026-09-08 | WP4 pnpm dependency edits (branch `wp4/deps-pnpm-yarn`), round 7: cold re-review of the round-6 fixes | Claude Opus 5 subagent (fresh, did not write the code; not independent of Claude — Codex unavailable) | 1 | Four of five round-6 fixes verified correct against the real pnpm 9.12.3 — notably `node-linker=isolated` was proven NOT to desync the lockfile from how a project installs (`isolated`, `hoisted` and `pnp` all produce a byte-identical `pnpm-lock.yaml`; `node-linker` is not recorded in the lock's `settings:`), and deleting the flag makes the e2e fail at the asserted line. 1 should (an unparseable `pnpm-lock.yaml` hard-failed every edit under the workspace root, including a merge-conflicted lock that pnpm itself auto-merges) + 1 nit (a directory literally named `a\b` matched importer `a/b` through a backslash rewrite) + design finding: the round-6 lockfile lookup could only ever return "yes", so every non-member query still fell through to the glob matcher, which the reviewer timed as exponential — 143 s on a 37-character pattern, roughly 10× per extra `**`, unbounded | ✅ fallback deleted outright: membership is now the `importers` lookup and nothing else, which removes the glob matcher, the unsupported-pattern list and `pnpm_workspace_packages` (net −169 lines) and takes three unfixed round-6 items with it. Unparseable lock is now a refusal naming `pnpm install` as the remedy; the backslash rewrite is gone because the key is built from path components. Stated cost, now in LIMITATIONS.md: a member added since the last `pnpm install` is not yet a member. Fixes not independently re-reviewed; Mac gate outstanding |
| 2026-09-08 | WP4 pnpm dependency edits (branch `wp4/deps-pnpm-yarn`), round 8: review of the round-7 membership rewrite (`07c5853`) | Claude Opus 5 subagent (fresh, did not write the code; not independent of Claude — Codex unavailable) | 1 | MERGE-AFTER-FIXES: 2 blocker + 3 should-fix. Blockers, both verified independently by the supervising agent against the pinned pnpm 9.12.3: (1) round 7's component-wise key dropped pnpm's own backslash normalisation — pnpm writes importer key `packages/a/b` for the on-disk directory `packages/a\b`, so the round-7 commit message's justification was backwards and the change was a regression; (2) a workspace member added since the last `pnpm install` fell through to npm silently, writing a stray `package-lock.json` inside a real pnpm workspace that then wins every later lock selection. Should-fix: an apostrophe in a package path (`packages/it's`, which pnpm writes unquoted) made the YAML splitter open a quoted scalar and reject the whole lockfile, wedging every project in the workspace behind advice that regenerates the same file; a broken doc comment left by the round-7 deletion; the merge-conflict message claimed pnpm self-merges, true of 9.12.3 but not of current pnpm | ✅ all five fixed in `0a3ab11` with three mutation-checked regression tests; fixes not themselves re-reviewed |

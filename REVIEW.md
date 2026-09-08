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

Current status: the five original review entries are ✅; entry 6 (WP1) is ✅
on Linux evidence with the Mac gate outstanding. The briefs below preserve the
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

## 6. ✅ WP1 `blanket fmt` — branch `wp1/fmt-rust`

Files: `src/rustfmt.rs` (new: pins, `rustfmt/1` identity, allowlisted
extraction, `lib` link, pre-commit probe), `src/main.rs` (`run_fmt`),
`src/cli.rs` (`parse_fmt`, `LS_WORDS`), `src/sandbox.rs` (status-returning
runner, shared `sandbox-exec:`/`bwrap:` setup-failure classifier),
`src/project.rs` (descriptor-anchored closure publication), `src/cargo.rs`,
`src/inspect.rs`, `src/sbom.rs`, `src/gc.rs`, `tests/fmt_e2e.rs`,
`tests/cli.rs`.

**Why it matters.** The first command that runs a store tool with the user's
whole workspace writable and no projection; the first store object whose
tree links into another object; the first closure written into a workspace
root that may be an ancestor of the directory blanket was run in.

**Looked for:** argument injection into the tar and cargo-fmt command lines;
the archive allowlist against the real tarballs on both platforms; the
absolute-path probe leaking into a committed object; closure writes escaping
the project through a symlinked `.blanket`; gc following the `lib` link into
the Rust object; other callers of the split sandbox runner seeing a changed
failure surface; script precedence hijacked from an ancestor `package.json`;
exit-status pass-through vs blanket's own 0/1/2.

Reviewed 2026-09-06/07: Sol r1–r2 (REWORK), Claude Opus 5 subagent r3–r5
(MERGE at r5). Findings and rechecks are summarised in the log row below;
the three open nits are listed there. Linux acceptance on the final commit
9fabfb5: 35/35 (`tests/acceptance.sh` with a disk-backed TMPDIR); `cargo
test`, `fmt_e2e --ignored`, and `gc --ignored` green. Mac cold/warm gate
outstanding.

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
| 2026-09-07 | WP2 toolchain-lock design (branch `wp2/toolchain-lock-design`, docs-only: ARCHITECTURE.md, CLI.md, LIMITATIONS.md, LINUX_PORT.md, PLAN.md) | GPT-5.6 Sol (Codex), independent, r1–r4; Claude Opus 5 subagent (fresh, did not write the text; not independent of Codex), r5–r6; r7 supervising agent only (author's recheck of its own round-6 fixes) | 10 | r1: 1 blocker + 5 should; r2: 3 blocker + 3 should; r3: 4 blocker + 2 should; r4: 3 blocker + 3 should (lock re-read before publication; bundle id vs component versions; `x/3` key coverage); r5: 4 should (two publication rules; store root dropped from the `x/3` key; digests not algorithm-qualified; CPython prefixes) + 2 nit; r6: 2 should (whole-file input digest wedged the lock after `blanket add`; descriptor-relative helper had no PR owner or test) + 3 nit; r7: all five verified by the author, every touched citation re-checked, `--frozen` boundary sentence byte-identical in exactly two places; r8: not a review — the owner's three product decisions applied, plus five corrections the earlier rounds had left open (false `src/store.rs:69` citation, undefined `bundle_id`/canonical bytes, invented CLI.md `(planned:)` convention, staleness blind to a newly added higher-precedence source, and an unsandboxed-evaluation claim contradicted by `src/ruby.rs:580`); r9: Claude Opus 5 subagent, full citation audit of every reference r8 added or moved — all accurate except `src/ruby.rs:580`, which is the comment and not the call (fixed to 582-596) — plus 1 should-fix confirmed by the supervising agent against the source: r8's "main has two unsandboxed evaluators, not one" was itself an incomplete count (`plan_dotnet` via `run_dotnet` is a third, and Ruby and Elixir each have a second call site), so the guarantee is now a reachability rule with a named, PR-owned, per-ecosystem-tested module (`src/toolchain_input.rs`) instead of any count; r10: Claude Opus 5 subagent, re-audit of the r9 fixes — every citation r9 added or moved re-opened at its exact line and all accurate, but 2 blockers in the new text: the reachability rule was promoted to an absolute claim about all of `--frozen` while ARCHITECTURE.md's own flow (lines 816, 840-842, 753-754) has a *passing* frozen run continue into dependency planning, which `plan_ruby`'s unconditional Gate 1 (`src/ruby.rs:582-596`) evaluates the Gemfile from — so the marker acceptance test was false as written; and "the reader spawns no process at all" was unsatisfiable for the Python and Elixir precedence rows, which still listed `setup.py`-computed metadata and `mix.exs` compatibility as sources — plus 2 should-fix bookkeeping contradictions (three different round counts across PLAN.md and this row; an Outcome cell asserting round 8 was "not reviewed at all" in the same row recording r9's review of it) | 🟡 round-6 fixes verified by the author only; round 8 (owner product decisions: catalog off the reproducibility path, `/dev/urandom` + `fsync` publication, absence-aware staleness under root-anchored discovery, defined `bundle_id`/canonical bytes, `(planned:)` markers removed, structural sandbox guarantee) was applied by the supervising agent and then reviewed in r9, whose fixes r10 reviewed in turn; r10's own fixes — scoping the reachability rule to frozen validation and stating plainly what frozen does after it, and making every ecosystem's reader declarative-only so `setup.py`-computed metadata and `mix.exs` are not frozen sources — are the currently unreviewed layer; docs-only, Mac gate is `cargo test` |
| 2026-09-07 | WP2 secure archive extractor (branch `wp2/archive-extractor`): `src/archive.rs`, Go toolchain as first consumer | supervising agent only (author's own checks: unit tests with hand-built hostile ustar members, real GNU tar listing and extraction, Go e2e) | — | — | ⬛ superseded by the 2026-09-08 review below |
| 2026-09-08 | WP2 secure archive extractor (branch `wp2/archive-extractor`), round 1 of real review: adversarial review of the listing parser, the listing/extraction gap, and symlink containment | Claude Opus 5 subagent (fresh, did not write the code; not independent of Claude — Codex unavailable) | 1 | No out-of-destination write was achievable. 1 should (attacker-chosen owner/group names containing spaces add `-tv` columns; the fixed column skip then returned `"<date> <time> ../escape"` as the name, so the `..` refusal was bypassed and `validate` returned Ok on an archive it exists to refuse — the module was saved only by the tar behaviours its docstring says it does not trust) + 1 should (the Go migration's refusal policy was never exercised against a real Go tarball) + 2 nit (list/extract TOCTOU; locale unpinned). Verified good: the bsdtar 8-column assumption against real libarchive 3.8.7 including old-mtime, device and hard-link lines; that `--strip-components` strips names but not symlink targets | 🟡 fixed by the author and re-verified (`--numeric-owner` on every invocation, `LC_ALL`/`LANG` pinned, and every listing cross-checked against a column-free `tar -t` so an unmodelled layout fails closed; the regression test fails without each layer; `go_e2e --ignored` now proves the real Go tarball passes `validate`). Fixes not independently re-reviewed; Mac gate outstanding |
| 2026-09-08 | WP2 secure archive extractor (branch `wp2/archive-extractor`), round 2: cold re-review of the round-1 fixes | Claude Opus 5 subagent (fresh, did not write the code; not independent of Claude — Codex unavailable) | 1 | Confirmed the round-1 column-shift hole is closed, and the `tar -t` cross-check caught a fifth unmodelled layout nobody had predicted (GNU tar collapses the date into one token for an unrepresentable mtime, giving four leading columns). 1 blocker (a `.` component in a member name inflated the symlink depth budget, so `./l -> ../ESCAPED` validated and extracted a link pointing outside the destination; padding the dots made the climb unbounded) + 1 should (lexical containment under-counted when a target resolved through another symlink defined in the same archive) + 5 nit | 🟡 both fixed by replacing the depth walk rather than patching it: `.` no longer counts toward depth, and lexical resolution is now kept sound by refusing any target that resolves through an archive-defined symlink and any member written through one. Fixes not independently re-reviewed; Mac gate outstanding. Reviewer's architectural finding accepted: column-parsing `tar -tv` is not a durable foundation and reading tar headers directly is the intended replacement before a second consumer adopts this module |
| 2026-09-08 | WP2 secure archive extractor (branch `wp2/archive-extractor`), round 3: review of the round-2 containment fix (`d0ee293`) | Claude Opus 5 subagent (fresh, did not write the code; stalled partway, completed by the supervising agent — not independent for the second half) | 1 | no blockers, no should-fix. Subagent: `root/lib/link -> ../bin/tool` still accepted after real extraction and kernel re-resolution; `--strip-components` counts `.` identically under GNU tar 1.35 and bsdtar 3.8.7; 10,494-archive single-symlink fuzz with real extraction, zero escapes. Supervising agent: member ordering is irrelevant because the symlink set is complete before judging (both orders refused on real archives), a contained symlink cannot be used as a directory, symlink chains are refused, and all three new tests are load-bearing under mutation | ✅ reviewed; report `wt/logs/wp2-archive-extractor.r3.report.md`; Mac gate outstanding (bsdtar column count verified on libarchive 3.8.7 only) |
| 2026-09-06 | WP2 Python exact selection (branch `wp2/python-exact-selection`): exact `.python-version` patch fails closed unless pinned; `python::lookup` exact-or-newest-minor | GPT-5.6 Sol (Codex), independent | 3 | r1: 3 should (non-canonical spellings accepted, minor test not order-proving, vacuous Darwin e2e); r2: 1 should (test order); r3: none | ✅ MERGE on Linux evidence; Mac gate (`cargo test`, `python_select --ignored`) outstanding |
| 2026-09-06 | WP2 Go exact selection (branch `wp2/go-selected-version`): `ensure_go_for` takes the selected version; unpinned selection fails before store access; status compares the go.mod selection | GPT-5.6 Sol (Codex), independent | 3 | r1: 3 should (pre-field closure reported synced, test not proving lookup-before-store, stale LIMITATIONS row); r2: 1 should (test not offline under regression); r3: none | ✅ MERGE on Linux evidence; Mac gate (`cargo test`, `go_e2e --ignored`) outstanding |
| 2026-09-07 | WP4 x lifecycle (branch `wp4/x-lifecycle`): `blanket x --clean`, per-root locks for running tools, descriptor-relative cleanup | GPT-5.6 Sol (Codex), independent, r1–r3; Claude Opus 5 subagent (fresh, did not write the code; not independent of Codex), r4–r5 | 5 | r1: 2 blocker (lock inode deleted with the root; destructive legacy prefix match) + 4 should; r2: 3 blocker (intermediate symlink followed; `.locks` not reserved; legacy roots ignore the ecosystem filter) + 2 should; r3: 1 blocker (containment TOCTOU after pathname validation) + 4 should; r4: 2 should (symlinked home chain: `x` and `--clean` disagreed; cached projection validated twice) + 4 nit; r5: none blocking, 5 nits open (lock unlink before registry removal; two fds per candidate on very large `~/.blanket/x`; three refusals lack a next step; legacy ecosystem precedence differs between matcher and summary; LINUX_PORT changelog placement — fixed) | ✅ MERGE on Linux evidence; Mac gate (`cargo test`, `gc --ignored` x lifecycle cold/warm) outstanding |
| 2026-09-07 | WP1 `blanket fmt` (branch `wp1/fmt-rust`): pinned rustfmt object, writable fmt sandbox mode, descriptor-anchored closure publication, script precedence and `--eco` | GPT-5.6 Sol (Codex), independent, r1–r2; Claude Opus 5 subagent (fresh, did not write the code; not independent of Codex), r3–r5 | 5 | r1: 4 blocker (predictable closure temp name; absolute store path in the object; rustfmt treated as a sync component; Mac gate) + 2 should; r2: 2 blocker (`DYLD_LIBRARY_PATH` probe; closure containment) + 3 should + 1 nit; r3: 1 should (`--eco` forwarded to the script) + 2 nit; r4: 1 should (`blanket sbom` failed on the rustfmt closure) + 3 nit; r5: none blocking, 3 nits open (`--eco` typo is an exit-1 refusal, not a suggestion; host-socket scan is Linux-only — now documented in LIMITATIONS.md; `ls rustfmt` not-found advice says `sync`) | ✅ MERGE on Linux evidence; Mac gate (cold/warm acceptance, `cargo test`, `fmt_e2e --ignored`) outstanding |

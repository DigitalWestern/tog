# Review queue

What still needs an **independent adversarial review**, why it matters, and
where to look. NEXT.md tracks what to *build*; this file tracks what has not
been independently *checked*. They are different debts and they were getting
confused inside one paragraph of NEXT.md.

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

Legend: ⬛ never reviewed · 🟡 partial, final round missing · ✅ done

---

## 1. ⬛ CLI levels one and two — PR #20, branch `cli/levels-1-2`

The largest unreviewed surface in the project: ~5,970 lines, none of it seen by
an independent reviewer.

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

**Also unreviewed in this branch:** the merge commit `1b63849` and the
test-locking changes in `9dd1f94`, which touch `store.rs`, `cargo.rs`,
`golang.rs`, `inspect.rs` and `policy.rs`. Test-only code, but it changed
locking, and locking changes deserve an adversary too.

## 2. ⬛ Item 4, git dependencies — PRs #14 (npm), #15 (python), #16 (cargo)

Files: `src/gitsrc.rs`, `src/npm.rs`, `src/npm_lock_import.rs`, `src/pypi.rs`,
`src/cargo.rs`, `tests/git_deps.rs`.

**Why it matters.** This is the first feature that fetches arbitrary remote code
identified by a URL, and it **deliberately skips three checks that exist for
tarballs** — the "only https registry tarballs" gate, the missing-integrity
error, and the SRI policy check — on the argument that the commit hash *is* the
verification. That argument is probably right. It has never been attacked.

**Look for:** whether the `rev-parse HEAD` check can be bypassed or satisfied by
something other than the requested commit; the full-history fallback path used
for servers that refuse reachable-sha fetches; submodules taken at recorded
commits; whether `.git` removal is complete in every path, including failure
paths; URL normalization collisions, where two different repositories normalize
to one store identity; symlinks or paths in the fetched tree escaping the store
object.

## 3. ⬛ Item 5, artifacts and electron provisioning — PRs #13, #17

Files: `src/artifacts.rs`, `src/npm.rs`, `tests/electron_provision.rs`.

**Look for:** the environment-variable table, where every entry is supposed to
have been read out of the published package's own source and never from memory
— spot-check that claim against the real packages; skip switches that quietly
disable a security control rather than a download; the electron release zip
landing in the cache its installer reads without an integrity check on the way
in.

## 4. ⬛ PR #19 review fixes — supervising agent only

Commits `2967d4a` (lockfile attestation, portable deterministic packing, input
validation) and `c3de1bd`. These are *fixes produced by review*, which never
themselves went through review — historically a good place to find defects.

## 5. 🟡 Items 7, 10, 12 and gc — final round missing

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
  handling; `deps.rs` is now the biggest untested instance of the same shape).
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

- **Codex** hit its usage limit at 03:18 on 2026-09-06; it resets
  **2026-09-12**. Astra rounds are queued behind that. Per NEXT.md delegation,
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
| 2026-09-06 | CLI levels 1–2 (PR #20) | none | 0 | — | ⬛ queued |

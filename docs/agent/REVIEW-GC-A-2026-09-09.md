# GC safety Package A: isolation and independent adversarial review

Reviewed commit: **`9b11e05eb4422040f39a547fb0f14f82ff1aa1d4`**, on
`wp-gc-safety`, parent `1e065a46eb73aca05c5ea7b96f6f198a429012db`.
Reviewer: **Codex**, reviewing the supplied implementation; did not write
or fix A's implementation. Date: 2026-09-09. **Disposition: FIX-FIRST, 🟡.**
Seven findings below: four P1 safety defects/limitations, two P2 recovery
or dry-run defects, and one P2 coverage finding. Inherited problems are
identified explicitly; this is not a claim that A introduced all seven.

## Starting questions

The review brief from implementation-plan §5.1, verbatim:

> can a root record be crafted (odd
> key case, symlinked registry file, a path that is a dangling symlink, a
> path on an unmounted mount point) that makes `collect_roots` *pass* when it
> should stop? Does `--forget` interact with `--register` in an order that
> loses a record? Does the early return after a real `--forget` skip anything
> the user expected to happen in the same invocation? Is the sweep-blocking
> error reachable from every entry into `gc::collect`, including
> `--project`?

## Isolation

The full initial dirty tree was inspected before staging: status, every
tracked file's complete diff, the staged rename, and the four initially
untracked files. A was recovered from the original implementation's local
session patches, including the portions subsequently rewritten by C/D.
The recovered diff matches the original A file statistics exactly after
excluding its plan-status edit: **10 files, 594 insertions, 54 deletions**.
No behavior was repaired while recovering it.

A separate index started from the parent commit and received only that
recovered patch. The commit used that index on the current branch. The
ordinary index was reconciled only for the ten A paths; its pre-existing
`PLAN.md` → `BLANKET-IMPLEMENTATION-PLAN.md` staged rename remains staged.
No shared working-tree source file was rewritten to perform the isolation.

| File | Included in A | Left uncommitted |
|---|---|---|
| `src/gc.rs` | Legacy unavailable-root refusal and diagnostic; `Options::forgotten`; borrowing options after removing `Copy`; five named tests; related fixture uniqueness change | B activity/busy handling; C `root/2` liveness; D metadata migration, certification, sweep changes, and the `commit_legacy` fixture adaptation |
| `src/store.rs` | Registry-only `lookup_root`/`forget_root`, key validation, public `root_key`, registry comment, named lookup/forget test | B activity APIs; C record schema, diagnostics, publication, import and path handling; D object metadata/producers/adapters |
| `src/cli.rs` | `--forget` arguments, validation, help and parsing tests; keyed roots help | D `--migrate-metadata` option; C/D help updates |
| `src/main.rs` | Keyed root listing; register/forget preflight; real/dry forgetting; early return; options ownership adjustment | B leases/supervision; C root diagnostics and dry-run registration handling; D migration/maintenance |
| `tests/gc.rs` | `gc_keeps_deleted_node_project_until_forgotten` with A's refusal expectation, keyed listing parser, no-sweep-after-forget assertion, keyed x-root assertions and canonical-path capture | C's later successful `root/2` sweep expectation; D's migration-refusal rewrite of the upgrade test |
| `ARCHITECTURE.md` | Original “GC root safety” section | Later B/C/D guarantees and unrelated toolchain/design edits |
| `CLI.md` | Keyed roots comment and original forget/unavailable-root paragraph | Expanded C/D option table and other help/design edits |
| `LIMITATIONS.md` | A's unavailable-root behavior and explicit notice that a store-wide job lock is still a follow-up | B/C/D and unrelated design limitations |
| `README.md` | Keyed roots/forget examples and A's safety paragraph | B/C/D behavior and unrelated design edits |
| `REVIEW.md` | Original A implementation/self-review row | Pre-existing B/C/D/design review records; this new independent round replaces A's row after the commit |

**Overlapping hunks resolved, with no unresolved entanglement:**
`gc::collect_roots` combined A's legacy guard with C's new authoritative
record branch; `Store::lookup_root`/`forget_root` combined A recovery with
C's later registry implementation; `main::run_gc` combined A ordering with
B locks, C registration changes, and D maintenance; the deleted-project
integration hunk changed its expected result under C. Historical A patches
established the exact earlier text, so these were separated without guessing.
The analogous documentation overlaps were resolved the same way.

All changes in the following initially dirty source files stayed out:
`archive.rs`, `artifacts.rs`, `build.rs`, `build_requires.rs`, `cargo.rs`,
`deps.rs`, `dotnet.rs`, `elixir.rs`, `fetch.rs`, `gitsrc.rs`, `golang.rs`,
`inspect.rs`, `lib.rs`, `manifest.rs`, `nativelibs.rs`, `npm.rs`, `policy.rs`,
`project.rs`, `pypi.rs`, `python.rs`, `ruby.rs`, `rustfmt.rs`, `sandbox.rs`,
and `xrun.rs` (all under `src/`). These are B supervision/activity,
C publication/projection, D producer/metadata work, or their related
tests and adaptations. `tests/cli.rs` stayed out. The entire plan rewrite,
`CLAUDE.md`, `LINUX_PORT.md`, `NEXT.md`, and untracked
`PLAN-REVIEW-2026-09-09.md`, `src/activity.rs`, `src/supervise.rs`, and
`tests/supervise_signals.rs` stayed out.

Another process edited non-A work during this session, including a new
`src/objmeta.rs` and later changes in shared source files. Those edits were
preserved and never added to A. To avoid claiming results for a moving
target, dirty-tree validation below uses a frozen reconstruction of the
**initial** dirty tree, with byte-verified copies of its initial untracked
files. It does not certify that other process's later edits.

## Validation and isolation failures

All runs used Linux x86_64, a short disk-backed `TMPDIR`, disposable
`BLANKET_STORE`, `BLANKET_SANDBOX_TESTS=required`, and separate Cargo
`--target-dir` directories. Cargo exit statuses were captured directly.
The ordinary suite used `cargo test --offline`; the ignored GC suite used
`cargo test --offline --test gc -- --ignored` (Cargo dependency resolution
is offline; those integration fixtures download their pinned toolchains).

| Tree / check | Result |
|---|---|
| Isolated A: `cargo fmt --check`, `git diff --check` | Pass |
| Isolated A: ordinary suite | **452 passed, 0 failed, 47 ignored**, including 416 library tests |
| Isolated A: ignored `tests/gc.rs` | **3 passed**: deleted node until forgotten, pre-registry upgrade, and x cleanup/busy coverage |
| Frozen initial dirty tree: ordinary suite | **483 passed, 0 failed, 48 ignored**, including 431 library tests and 15 supervision acceptance cases |
| Frozen initial dirty tree: ignored `tests/gc.rs` | **3 passed** with its C/D-adjusted expectations |
| Isolated A after restoring all mutations | Ordinary suite **452 passed, 0 failed, 47 ignored**; clean source diff and formatting pass |

The first ordinary-suite attempt in **both** trees failed only
`sandbox::tests::linux_host_socket_in_writable_root_is_rejected_before_bwrap`:
`InvalidInput: path must be shorter than SUN_LEN` at socket fixture creation
(`src/sandbox.rs:1075` in A; `:1283` in the dirty snapshot).
The initial temporary path was too long. Moving the fixture base to a
shorter directory fixed both runs without changing code. **Attribution:
review harness path choice, neither A nor B/C/D.** There were no remaining
unmodified-suite failures to attribute to either package set. The expected
failures from deliberate mutations are listed separately below.

## Reproduced findings

Source line references in this section refer to **the A commit**, not the
moving dirty checkout. The runnable fixture is
[`review-fixtures/gc-a/adversarial.py`](review-fixtures/gc-a/adversarial.py);
all 22 recorded cases, including complete argv/stdout/stderr and fixture
paths, are in [`adversarial.jsonl`](review-fixtures/gc-a/adversarial.jsonl).
Its assertions confirm the observed behavior, including unsafe behavior;
a successful run of this evidence script is **not** a safety acceptance.

### A-R1 — P1: exact-key forgetting can delete a different record

**Introduced by A.** `src/cli.rs:1272–1275` lowercases the requested key;
`src/store.rs:88–116,147–163` accepts both cases and matches filenames
exactly. Fixture `case-fold-forgets-other-record` creates two valid records,
one named `abcdef0123456789abcdef0123456789abcdef01`, the other its uppercase
spelling, pointing at different projects. `store roots` prints both.
Passing the uppercase key to `gc --forget` exits 0, prints the lowercase
key/project, removes the lowercase record, and leaves the requested
uppercase record. Thus an explicit choice to release one project's
protection releases another's. The existing parsing test requires this
case conversion, so simply running the suite endorses the faulty boundary.
**Open:** preserve exact identity or consistently refuse noncanonical
registry keys; recheck listing, lookup, and forgetting together.

### A-R2 — P1: skipped registry entries bypass the unavailable-root guard

**Inherited enumeration behavior exposed by A's safety claim.**
`Store::roots`, `src/store.rs:88–116`, silently skips nonregular entries and
empty pathname records. `collect_roots` consequently never sees them.
Fixtures `symlink`, `dangling-symlink`, and `empty-record` first prove that
a regular record keeps an aged, referenced object. They then replace that
record with, respectively, a symlink to its saved valid contents, a dangling
symlink, or an empty file. The initialized marker remains. `store roots`
exits 0 with an empty listing; `gc --project --keep-days=0` exits 0 and
**deletes the live object**, leaving the registry entry on disk.
**Open:** establish a fail-closed registry enumeration/recovery policy.
C has related work in the dirty tree, but none of it is protection supplied
by the isolated A commit, and it was not re-reviewed here.

### A-R3 — P1: lossy pathname serialization can select another project

**Inherited identity defect, directly relevant to A's pathname authority.**
`register_root` writes `project_dir.display()` (`src/store.rs:73`),
`roots` uses `text.trim()` (`:103`), and the key hashes
`to_string_lossy()` (`:676`). Fixture `trailing-space-selects-other-project`
creates `project ` with a live closure and `project` with an empty closure
directory. `gc --register '<path>/project ' --keep-days=0` succeeds and
**deletes the former's live object**: the registry reader selects the latter.
Fixture `lossy-path-identity` repeats the loss with distinct Unix names
ending in byte `FF` and literal U+FFFD; from inside the byte-named directory,
`gc --register . --keep-days=0` registers under the other spelling's key and
sweeps the object. This also demonstrates a key collision without attacking
SHA-1. **Open:** byte-preserving, unambiguous path/identity representation
or explicit rejection before registration; coordinate with C's record work.

### A-R4 — P1: an unmounted path can pass by resolving its backing tree

**Inherited pathname-only identity limitation; not an introduced regression.**
Fixture `unmounted-with-backing-closures` uses an actual tmpfs mount inside
`unshare -Urnm`. The backing mountpoint first gets an empty
`.blanket/closures`; the mounted filesystem gets a live closure and is
registered. GC while mounted retains the object. After `umount`,
`gc --project --keep-days=0` exits 0 and **deletes it** while the record
survives. `collect_roots` (`src/gc.rs:142–173`) checks that *a* directory
and closure directory resolve, without establishing that this is the
registered project. The paired `unmounted-bare` case correctly stops when
the backing directory lacks closures. **Open:** account for this residual
identity limitation when approving A; a stronger authoritative record or
explicitly narrowed guarantee belongs in the follow-up. No C/D implementation
was attempted in this review.

### A-R5 — P2: dry-run forgetting combined with registration writes records

**Inherited registration behavior conflicts with A's new combined command
and “writes nothing” contract.** `src/main.rs:375–377` calls
`register_root` regardless of `options.dry_run`. Fixture
`dry-forget-register-writes` combines `gc --dry-run --forget OLD --register
NEW` for different projects. It exits 0, prints `registered root NEW`
and `would forget root OLD`, and leaves a newly written NEW record alongside
the unchanged OLD record. The fixture records the exact before/after
registry filenames. **Open:** make the combined preview nonmutating or
reject the combination explicitly; test at the CLI boundary. C's later
dry-registration change remains outside A and is not credited as a fix here.

### A-R6 — P2: one corrupt record disables all key-based recovery

**A's new recovery path depends on reading every record.**
`lookup_root` (`src/store.rs:147–163`) invokes `roots()` before selecting
the requested key. Fixture `unrelated-invalid-record-blocks-all-forgetting`
creates a healthy record and a separate 40-hex record containing byte `FF`.
`gc --forget HEALTHY` and `gc --forget CORRUPT` both exit 1 with only
`stream did not contain valid UTF-8`; both records remain. Thus corruption
elsewhere prevents an otherwise valid explicit recovery, and even knowing
the corrupt file's key provides no CLI recovery. **Open:** define exact-key
recovery independently of unrelated record decoding, with an intentional
policy for forgetting unreadable/malformed records.

### A-R7 — P2: two protection mutations survive the full suite and A e2e

**Coverage defect in A.** M3 changes the requested-key filter into
“ignore every root whenever `forgotten` is nonempty.” All **452 ordinary
tests** and `gc_keeps_deleted_node_project_until_forgotten` still pass.
The unit named `dry_run_forget_ignores_only_the_requested_root_and_writes_nothing`
has only one root, and the integration preview does not assert preservation
of the other root's liveness. The separate two-root fixture reports zero
objects for A and one wrongly collectible live object for M3.

M4 deletes **all** `run_gc` preflight checks (same-root registration,
duplicate keys, and complete key lookup before mutation). The same full
suite and A integration test still pass. A separate fixture shows the real
commit refuses register-and-forget of one key, while M4 exits 0 and deletes
that record. **Open:** add behavioral coverage at these boundaries and
require the corresponding mutations to fail; do not infer that every key
guard is protected by A's current suite.

## Mutation results and answers to the remaining questions

The exact six mutation patches, runner, logs and differential CLI evidence
are in [`review-fixtures/gc-a/`](review-fixtures/gc-a/).

| Mutation | Existing tests | Behavioral evidence |
|---|---|---|
| M1: restore pre-A stale-root dropping | Three failures: `missing_project_blocks_sweep_and_preserves_record`, `missing_closures_directory_blocks_sweep`, `io_error_on_project_path_blocks_sweep` | Each gets `Ok(Report { objects: 1, … })` instead of refusal. Differential fixture proves A retains the object and record, then M1 actually deletes both in that same store. |
| M2: remove forgotten-key exclusion | `dry_run_forget_ignores_only_the_requested_root_and_writes_nothing` fails | The requested missing root blocks the preview. |
| M3: exclude all roots for any forget | Full suite and A ignored integration **survive** | Two-root differential preview exposes the unrelated live object. |
| M4: remove all register/forget preflight | Full suite and A ignored integration **survive** | Differential same-key registration/forgetting loses the record only under the mutation. |
| M5: remove real-forget early return | A ignored integration fails at `tests/gc.rs:232` | `forget unexpectedly swept store objects`. |
| M6: remove store key validation | `forget_rejects_unknown_and_malformed_keys` fails | Malformed key returns `NotFound` instead of `InvalidInput`. |

The unmodified preflight correctly rejects same-key registration/forgetting
in either order (including a canonicalizing symlink alias), duplicate keys,
and a valid key followed by an unknown key **before registry changes**.
The dry-run problem is A-R5; case-induced wrong-record forgetting is A-R1.

A real `--forget --project --collect-legacy --keep-days=0` deliberately
returns before **all** sweep phases. The fixture retains both an aged object
and an aged stage; a subsequent GC removes them. Registration, if supplied,
runs before that return. This agrees with A's explicit “forget removes only
records” contract, so the early return itself is not filed as a defect.
Users must issue a separate GC to request the sweep.

The only production caller of `gc::collect` in A is `run_gc`. Within
`collect`, `collect_roots` precedes every sweep, including project cleanup.
Twenty CLI combinations (missing path, dangling symlink, symlink loop,
missing closures, and non-directory, each under ordinary/dry-run/project/
project+dry-run) all stop and preserve the object and root record. There is
no alternate `--project` route around this check. The enumeration and
identity bypasses above happen *before* or *inside* that root resolution.

Recurring classes from `REVIEW.md` were applied: pre-registry collection
refuses without initialization even with `--project --collect-legacy`, and
the existing ignored upgrade test passes; identity failures are A-R3/A-R4.
A's new unit tests use explicit stores and introduce no `set_var` or
`remove_var`; integration children receive their own store through
`Command::env`. No new process-global-state finding was reproduced.
Five malformed/injection-shaped keys (`../outside`, an option spelling,
40-hex-plus-traversal, shell-substitution text, and a short key) are refused;
the sentinel remains absent. Forgetting introduces no delegated command
boundary. No argument-execution finding was reproduced.

## Reproduction and remaining work

From this repository, create a short, disk-backed scratch directory and a
clean worktree of the reviewed commit. The mutation runner refuses a dirty
worktree or a different revision, and restores every mutated file in a
`finally` block. It operates only in the created `isolated` worktree:

```sh
review_repo=$(git rev-parse --show-toplevel)
review_scratch=$(mktemp -d /home/ethan/gcar.XXXXXX)
git worktree add --detach "$review_scratch/isolated" 9b11e05eb4422040f39a547fb0f14f82ff1aa1d4
printf '%s\n' "$review_scratch" > "$review_scratch/a-tmp-path"
python3 "$review_repo/review-fixtures/gc-a/mutations.py" "$review_scratch"
TMPDIR="$review_scratch" python3 "$review_repo/review-fixtures/gc-a/adversarial.py" "$review_scratch/blanket-a"
TMPDIR="$review_scratch" python3 "$review_repo/review-fixtures/gc-a/mutation_evidence.py" "$review_scratch"
```

Adjust only the scratch parent for another machine. The mounted cases need
Linux user/mount namespaces; inability to run them is reported as a failure,
not silently counted as coverage. Every store and mountpoint is newly
created by the fixtures. Original complete Cargo logs and snapshots are
also retained locally at
`/home/ethan/repos/blanket-repo/wt/tmp/a-review`.

**No implementation fixes were made.** A's implementation isolation and
independent review are delivered; finding disposition/fixes, regression
coverage, and an independent recheck by someone who did not write the fixes
remain open. A's row remains 🟡. The separate **macOS arm64 gate remains
unrun: `cargo test` and `cargo test --test gc -- --ignored`**. These Linux
results do not clear it. No real store was collected and no Package D work
was begun by this review.

This report, its evidence bundle, and the updated `REVIEW.md` round are
left uncommitted, separate from the isolated A implementation commit.

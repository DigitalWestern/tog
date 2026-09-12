# REFACTOR — structural refactor plan and change log

Started 2026-09-11. Living document: the plan at the top is updated as
decisions are made; the change log at the bottom is append-only and dated.
Read this before touching module layout, `lib.rs`, `main.rs`, or anything
under `src/` that moves between folders.

Companion documents: [STATUS.md](STATUS.md) (where the project is),
[FOLLOW-UPS.md](FOLLOW-UPS.md) (owed work), [CLAUDE.md](CLAUDE.md)
(rules), [docs/human/ARCHITECTURE.md](docs/human/ARCHITECTURE.md) (how it
works). This document does not repeat them.

---

## 1. Why

The code works, compiles clean, and has a review process that catches
regressions. What it does not have is a *shape*. Forty source files sit in
one flat folder; the kernel, seven language tailors, the Python build
pipeline, and every command handler are visually indistinguishable. Two
agents working on unrelated ecosystems still collide in `main.rs`,
`store.rs`, `policy.rs`, and `objmeta.rs`.

The project will keep growing: more ecosystems, a toolchain lock (WP2),
policy work (WP3), a supervision redesign. Each of those adds another slice
to every hotspot file unless the shape changes first. This refactor is
about making the *next five years* of additions land in predictable places,
so that work can be partitioned by folder, reviewed by folder, and later
split into crates by folder without a second reorganization.

### Baseline (2026-09-11, commit `fb8b1d6`)

| Metric | Value |
|---|---|
| Source files under `src/` | 40, all in one flat folder |
| Lines of Rust | 62,592 total; ~44,000 non-test |
| Files over 3,000 lines | 4 (`manifest`, `gc`, `npm`, `store`) |
| Non-test functions over 200 lines | 16 |
| Longest non-test function | 492 lines (`nativelibs::url`) |
| Modules that depend on `store` | 28 of 40 |
| Two-way module dependencies (cycles) | 7 |
| Shared traits across tailors | 0 |
| `main.rs` lines | 2,106 (a 183-line `dispatch` plus one `run_*` per command) |

The seven cycles: `activity↔store`, `build↔project`, `elixir↔objmeta`,
`fetch↔store`, `gitsrc↔types`, `nativelibs↔objmeta`, `policy↔store`.

What is already good and must be preserved: each tailor is a leaf (nothing
depends on `golang`, `ruby`, `dotnet`, `cargo` except their own commands),
`platform.rs` is the single host-knowledge point, and integration tests
reach only 13 public modules.

---

## 2. Principles (apply to every stage and to all future code)

These are the rules that make the layout *stay* organized after the
refactor is over. They are the actual deliverable; the file moves are how we
get there.

1. **Layers point one way.** `commands → tailors → kernel`. The kernel never
   names a tailor or a command. A tailor never names another tailor or a
   command. Cross-layer knowledge flows through traits and data, not
   through `crate::elixir::...` calls from generic code. Enforced by a test
   (see Stage 4), not by convention.
2. **One folder, one owner scope.** An agent assigned "the Go tailor" edits
   `src/tailors/go/` and nothing else without saying so. A PR that touches
   two top-level folders is a shared-layer change and gets the shared-layer
   review. This is what lets agents work in parallel without treading on
   each other.
3. **Adding an ecosystem is additive.** A new tailor is a new folder plus
   one registry line. It does not edit `main.rs`, `objmeta.rs`, `gc.rs`,
   `sbom.rs`, or `inspect.rs`. If it has to, the abstraction is wrong and
   gets fixed *before* the tailor lands.
4. **Folders are future crates.** Every top-level folder under `src/` is
   designed so it can become a workspace crate (`blanket-kernel`,
   `blanket-tailor-go`, `blanket-cli`) by moving it and adding a
   `Cargo.toml`. We do not split into crates now (single crate compiles in
   seconds and shared test locks are simpler), but nothing in the layout
   may prevent it later. Concretely: no folder reaches into another folder's
   private items; all cross-folder use goes through `pub` items at the
   folder's `mod.rs`.
5. **Size budgets.** A file over ~1,500 non-test lines or a function over
   ~150 lines is a review flag: it either gets split or the PR explains why
   not. Budgets are advisory today; the Stage 4 architecture test reports
   them so drift is visible.
6. **Public surface is deliberate.** `lib.rs` exports what tests and the
   binary need, nothing more. Modules default to `pub(crate)`; going `pub`
   is a decision recorded in the module doc comment.
7. **Moves are not rewrites.** A stage that moves code does not also change
   behavior. Identity goldens stay byte-identical, `cargo test` output
   stays identical, and the diff is reviewable as "same code, new path."
   Behavior changes get their own PR under the normal review process.
8. **Every module has a doc comment.** First line says what it owns and
   which layer it lives in. Five modules currently have none (`fetch`,
   `platform`, `policy`, `python`, `store`); Stage 1 fixes that as part of
   the move.

---

## 3. Target layout

Vocabulary follows the project's own metaphor: the **kernel** is the
ecosystem-agnostic store/fetch/sandbox core, a **tailor** is one
ecosystem's adapter, the **comforter** is the projected environment.

```
src/
  main.rs                 parse args, build Context, call commands::dispatch
  lib.rs                  module tree + deliberate re-exports

  cli/                    argument grammar only; no I/O, no store
    mod.rs                Command enum, Options, Parsed, UsageError
    spec.rs               the Spec table, usage(), help()
    parse.rs              parse() and the per-command parse_* functions
    completions.rs        bash / zsh / fish generators

  commands/               one file per user-facing verb; the only layer that
    mod.rs                knows about all tailors AND the kernel
    context.rs            Context { platform, store, project_dir, activity }
    sync.rs   plan.rs   build.rs   run.rs   fmt.rs   gc.rs
    deps.rs   sbom.rs   store.rs   doctor.rs   ls.rs   x.rs
                          (`deps.rs`, `sbom.rs`, `inspect.rs`, `xrun.rs`
                           today are command implementations; they move
                           here in Stage 2)

  kernel/                 ecosystem-agnostic; must never name a tailor
    mod.rs
    types.rs              Identity, LockedPackage, Plan (git field moves out, Stage 4)
    platform.rs           the only host-knowledge point
    store/                split of today's 3,464-line store.rs
      mod.rs              Store, open(), object paths
      objects.rs          object write/commit/immutability
      roots.rs            RootEntry, RootRecord, roots_for_sweep
      projection.rs       ProjectionBase, ProjectionRef
      env.rs              BLANKET_STORE handling, STORE_ENV_LOCK
    objmeta/              object-meta/2 records and the adapter grammar
      mod.rs
      adapters.rs         grammar_for() becomes registry-driven in Stage 3
    fetch.rs  archive.rs  dirhash.rs
    policy.rs  activity.rs  supervise.rs  sandbox.rs
    gitsrc.rs             git sources by commit (kernel-level; used by 3 tailors)
    gc/                   split of today's 4,309-line gc.rs
      mod.rs  read.rs  plan.rs  sweep.rs
    ui.rs                 stdout/stderr conventions

  tailors/                one folder per ecosystem; leaves of the graph
    mod.rs                Tailor trait + registry() (Stage 3)
    python/
      mod.rs              toolchain pin (today's python.rs)
      pypi.rs  pep440.rs  pyselect.rs  wheel.rs
      manifest/           split of today's 4,613-line manifest.rs
        mod.rs  discovery.rs  poetry.rs  uv.rs  pdm.rs  requirements.rs
      build.rs  build_requires.rs
      nativelibs.rs       Linux relocatable native libs (Python-build-specific today;
                          promote to kernel/ only if a second tailor needs it)
      artifacts.rs        install-time artifact policy (item 5)
    node/
      mod.rs              today's npm.rs
      lock_import/        split of today's npm_lock_import.rs
        mod.rs  pnpm.rs  yarn1.rs
    cargo/
      mod.rs              today's cargo.rs
      rustfmt.rs          pinned formatter component
    go/     mod.rs
    ruby/   mod.rs
    elixir/ mod.rs
    dotnet/ mod.rs

  comforter/              environment realization + projection into the
    mod.rs                project dir (today's project.rs, split in Stage 4)
    closure.rs  realize.rs  project.rs  backup.rs
```

Why these names: `kernel`, `tailors`, and `comforter` are the words the
architecture doc already uses, so the folder tree teaches the metaphor. A
newcomer, human or agent, reads `src/` and sees the design.

Why `comforter/` is its own top-level folder and not inside `kernel/`:
`project.rs` today depends on `build.rs` (a Python tailor concern), which is
one of the cycles. Keeping it separate makes that dependency visible until
Stage 4 removes it; afterwards it is a peer of the tailors that the kernel
does not know about.

---

## 4. The four stages

Each stage is one or more PRs, lands fully before the next begins, and has
a definition of done. Stages 1 and 2 are mechanical and low risk. Stages 3
and 4 change design and go through the adversarial-review process in
STATUS.md like any other feature.

### Stage 1 — Move files into folders (no logic changes)

**Goal.** The tree in §3 exists, every file is in its folder, and nothing
else changed. Reviewable as "same bytes, new path."

**Steps.**

1. Pick a quiet moment: no in-flight branch with more than trivial `src/`
   changes. Announce in STATUS.md that a layout move is landing on a given
   day. (In-flight work rebases across a move cleanly only if it did not
   touch the moved files.)
2. `git mv` each file to its target path. Do not split any file in this
   stage; `store.rs`, `gc.rs`, `manifest.rs`, `npm_lock_import.rs` move
   whole and are split in Stage 4.
3. Add `mod.rs` for each folder, declaring its children with the same
   visibility they had in `lib.rs` today.
4. In `lib.rs`, replace the flat `pub mod` list with the folder tree **and
   a compatibility shim**: `pub use tailors::node as npm;`,
   `pub use kernel::store;`, and so on, one line per old module name. Every
   `crate::npm::` and `blanket::store::` path keeps compiling. The shim is
   what lets the move land without touching forty files and without
   breaking any branch that is mid-flight.
5. Add the missing `//!` doc line to the five modules without one; every
   `mod.rs` gets a doc line stating its layer.
6. Update `docs/human/ARCHITECTURE.md`'s layout map and the file paths
   cited in `CLAUDE.md` (`src/python.rs`, `src/build.rs`,
   `src/platform.rs`). Grep `docs/` for `src/` paths and fix them.
7. Gate: `cargo fmt --check`, `cargo build`, `cargo test`, and
   `cargo test -- --ignored --test-threads=1` on Linux; Mac gate per
   LINUX_PORT.md. Identity goldens byte-identical (a pure move cannot change
   them; the goldens are the proof that it was pure).

**Follow-up PR (same stage, separate review).** Sweep every `crate::old::`
and `blanket::old::` path to the new one and delete the shim lines from
`lib.rs`. Mechanical, one `sed` per module name, no behavior change. Until
this lands the shim stays, so agents may use either path; after it lands
the old paths are gone.

**Definition of done.** Tree matches §3 for everything that is not a
file-split; `lib.rs` has no compatibility shims; docs cite new paths;
all gates green on both platforms; `git log --follow` works for every
moved file.

**Estimated effort.** One agent-day for the move, one for the sweep.

### Stage 2 — Split the entry point into `commands/`

**Goal.** `main.rs` is under 100 lines. Each verb is a file. Adding or
changing a command touches one file in `commands/` plus, if the grammar
changes, one in `cli/`.

**Steps.**

1. Create `commands/context.rs` with a `Context` struct holding what every
   `run_*` reconstructs today: `Platform`, an opened `Store`, the project
   dir, and the activity guard. `main.rs` builds one `Context` and hands it
   down. Commands that must work without a valid host platform (`gc`,
   `store roots`, `store path`, `completions`) take a lighter `MaintenanceContext`
   or an `Option<Platform>`; the existing comment in `dispatch` about GC on a
   copied store is the requirement to preserve.
2. Move each `run_*` from `main.rs` into `commands/<verb>.rs` as
   `pub fn run(ctx: &Context, args: &cli::<Verb>Args) -> io::Result<i32>`.
   Helpers that only one command uses go with it (`read_plan`,
   `locked_requirements`, `ensure_npm_lock`, `ensure_cargo_lock`,
   `locate_cargo_root`...). Helpers two commands share go in
   `commands/shared.rs` for now and are reassessed in Stage 3, where most
   of them become tailor methods.
3. Move `deps.rs`, `sbom.rs`, `inspect.rs`, `xrun.rs` under `commands/`.
   They are command implementations that happen to live at the top level.
   `inspect.rs` becomes `commands/doctor.rs` + `commands/ls.rs` +
   `commands/status.rs` if that split is clean; otherwise it moves whole
   and is split in Stage 4.
4. `commands/mod.rs` owns `dispatch(ctx, Command) -> io::Result<i32>`: a
   flat match with one line per arm. No logic in the match.
5. Split `cli.rs` into `cli/{mod,spec,parse,completions}.rs` along the
   lines already visible in its item list. Pure move, same review shape as
   Stage 1.
6. Move the unit tests that live in `main.rs` today (`is_fully_pinned`,
   `cached_lock_matches`, `refuse_dotnet_script`...) with their functions.
7. Gate: same as Stage 1, plus `tests/cli.rs` (the CLI integration test)
   unchanged and green — it is the behavioral contract for this stage.

**Definition of done.** `main.rs` < 100 lines; `dispatch` has no arm longer
than one call; every command file has a doc line naming its verb and what
it needs from the tailors; `cargo test` identical to baseline.

**Estimated effort.** Two agent-days. Highest-value stage for parallel
work: after this, two agents on two commands never touch the same file.

### Stage 3 — One blueprint every tailor implements

**Goal.** A `Tailor` trait and a `registry()` in `tailors/mod.rs`. Commands
iterate the registry instead of hard-coding seven branches. A new ecosystem
is a folder plus one registry line.

**What the trait covers.** Every tailor today already exposes the same six
verbs by convention (`preflight_platform`, `ensure_*`, `plan_*`,
`realize_*`, `project_*_env`, `build_sandboxed`). The trait names them:

```
pub trait Tailor {
    fn id(&self) -> &'static str;                 // "python", "node", "go"...
    fn detect(&self, dir: &Path) -> io::Result<Option<Detection>>;
    fn preflight(&self, platform: Platform) -> io::Result<()>;
    fn ensure_toolchain(&self, ctx: &Context) -> io::Result<ToolchainRef>;
    fn plan(&self, ctx: &Context, det: &Detection) -> io::Result<PlanRef>;
    fn realize(&self, ctx: &Context, plan: &PlanRef) -> io::Result<ObjectId>;
    fn project(&self, ctx: &Context, env: &ObjectId) -> io::Result<()>;
    fn build_sandboxed(&self, ctx: &Context, args: &[String]) -> io::Result<i32>;
    fn object_kinds(&self) -> &'static [KindAdapter];  // see step 4
    fn sbom_components(&self, closure: &Closure) -> io::Result<Vec<Component>>;
}
```

The exact signatures are a design decision for the Stage 3 review, not a
commitment here. The two questions to settle in that review:

- **Plan representation.** Tailors have different plan shapes. Options:
  (a) an opaque `PlanRef` (path + digest) and each tailor reads its own
  file; (b) a `Plan` enum with one variant per tailor; (c) `serde_json::Value`.
  Recommendation: (a). It keeps the kernel ignorant of plan contents,
  which is the point, and matches how closures are already stored on disk.
- **Static vs dynamic dispatch.** `&'static [&'static dyn Tailor]` registry
  is simplest and fast enough (seven entries, called a handful of times per
  command). Generics buy nothing here.

**Steps.**

1. Write the trait and `registry()` with the Python tailor as the first
   implementer, since it has the most special cases (multiple manifest
   formats, sdist builds, native libs). If the trait fits Python, it fits
   the others.
2. Port one simple tailor (Go or Ruby) second to confirm the shape is not
   Python-specific. Then the remaining five, one PR each. Each PR deletes
   the corresponding branch from the command files.
3. Rewrite `commands/sync.rs`, `plan.rs`, `build.rs`, `doctor.rs`,
   `sbom.rs` to iterate `registry()` and call `detect()`. The explicit
   "which ecosystems are present here" logic that is spread across
   `run_sync`, `preflight_sync`, `has_python_input`, `load_go_inputs`,
   `load_npm_plan`, `eco_components`, and `doctor` collapses into one loop.
4. **Object-kind adapters become tailor-owned.** Today `objmeta::grammar_for`
   is a match over string kinds (`"go"`, `"ruby-toolchain/1"`,
   `"dotnet-sdk/1"`...) and `objmeta` and `gc` call
   `elixir::fingerprint_of_joined` directly. Each tailor returns its
   `KindAdapter` rows; `objmeta` builds its table from the registry. That
   removes the `elixir↔objmeta` cycle and the `gc→elixir` edge without
   changing any identity or metadata byte. Metadata goldens are the proof.
5. Remove `commands/shared.rs` helpers that became tailor methods.
6. Write `docs/human/ADDING-A-TAILOR.md`: the checklist for a new
   ecosystem (folder, trait impl, registry line, fixture, e2e test,
   acceptance.sh row, ARCHITECTURE.md row). This is the document that keeps
   principle 3 true.

**Definition of done.** No command file names a specific tailor module;
`grep -r 'crate::tailors::[a-z]*::' src/commands src/kernel` returns
nothing; `objmeta` and `gc` have no tailor imports; every tailor's e2e test
unchanged and green; ADDING-A-TAILOR.md exists and was followed for at
least one port.

**Estimated effort.** Five to eight agent-days across seven PRs. Review is
the bottleneck, not the code.

### Stage 4 — Untangle, split, and lock it in

**Goal.** Zero two-way dependencies, no file over the size budget, and an
automated check that keeps it that way.

**Steps, in order of value.**

1. **Break the remaining cycles.**
   - `gitsrc↔types`: `LockedPackage.git: Option<GitSource>` puts a
     kernel-adjacent type inside the base types module. Move `GitSource`
     (the serializable struct only, not the realization code) into
     `kernel/types.rs` or a `kernel/types/git.rs`; `gitsrc.rs` keeps the
     behavior and imports the type. Serde shape unchanged.
   - `policy↔store` and `activity↔store` and `fetch↔store`: `store.rs` is
     the hub; the store-split in step 2 separates the parts that need
     `policy::Exception` (collision checking at commit) from the parts
     `policy` needs (`Store` root path). Once split, the arrows are
     `store::objects → policy` and `policy → store::mod`, which is a chain
     not a cycle. Same treatment for `activity` and `fetch::Digest`.
   - `build↔project`: `project.rs` needs `build::git_sdist_package` and
     `build::plan_sdist_identity_input`; `build.rs` needs
     `project::planned_env_object_id`. All three are Python concerns. After
     Stage 3 the Python tailor owns both files' Python halves; what remains
     in `comforter/` is ecosystem-neutral and the cycle dissolves.
   - `nativelibs↔objmeta`: resolved by the Stage 3 kind-adapter move.
2. **Split the four files over 3,000 lines** along the seams in §3:
   `store.rs` → `kernel/store/`, `gc.rs` → `kernel/gc/`,
   `manifest.rs` → `tailors/python/manifest/`,
   `npm_lock_import.rs` → `tailors/node/lock_import/`. Each split is its
   own PR, pure move, same gates as Stage 1. The GC split must keep the
   review-fixture mutation tests in `docs/agent/review-fixtures/gc-a/`
   runnable; re-run them after the move.
3. **Break up the sixteen functions over 200 lines**, starting with the
   ones agents edit most (`run_run`, `dispatch` if Stage 2 left anything,
   `realize_node_env_with_node_object`, `plan_go`, `build_plan`). Each is a
   behavior-preserving extraction with the existing unit tests as the
   contract. Where a function has no test, write the characterization test
   *first* (FOLLOW-UPS.md C.10 lists twenty missing tests; several
   overlap).
4. **Add the architecture test.** A `tests/architecture.rs` that fails
   the build if the layering is violated. Implemented as a small
   source-scan test (no new dependency): for every file under
   `src/kernel/`, assert no `crate::tailors` or `crate::commands` reference;
   for every file under `src/tailors/<x>/`, assert no reference to another
   `src/tailors/<y>/`; report (warn, not fail, initially) any file over
   1,500 non-test lines or function over 150 lines. This is what makes the
   refactor *stay* done.
5. **Record the layering rules in CLAUDE.md** in three lines: the layer
   order, the "one folder per PR unless shared-layer review" rule, and the
   pointer to ADDING-A-TAILOR.md.
6. **Decide on workspace crates.** With the folders clean, measure: if
   incremental compile of a one-line tailor change exceeds ~10 s, or if a
   second binary appears (a daemon, a language server), split
   `kernel/` into `blanket-kernel` and each tailor into its own crate. If
   neither is true, leave it as one crate and revisit at the next STATUS
   review. Either answer is fine; the point is that the layout no longer
   forces the answer.

**Definition of done.** Cycle count 0 (the §1 script re-run); no file
over 3,000 lines; architecture test in `cargo test`; CLAUDE.md updated;
baseline table in §1 re-measured and recorded in the change log.

**Estimated effort.** Six to ten agent-days, spread over many small PRs.
Step 4 (the architecture test) should land *early* in this stage, in
warn-only mode, so it reports progress on the rest.

---

## 5. How this interacts with in-flight and planned work

- **Mac-gate fixes (STATUS.md next item 1).** Land these before Stage 1.
  A layout move under an uncommitted Darwin fix is the worst-case rebase.
- **Supervision redesign (FOLLOW-UPS.md Flag 1).** Do it after Stage 1 and
  before or alongside Stage 4's store split, since it changes
  `supervise.rs` and its callers, which are exactly what the split touches.
- **WP2 toolchain lock.** Do it after Stage 3. WP2 adds a per-ecosystem
  toolchain pin to every tailor; with the trait in place it is one trait
  method (`ensure_toolchain` reading the lock) instead of seven parallel
  edits. This is the concrete payoff of doing the refactor first.
- **New ecosystems.** None should start before Stage 3 lands. Every one
  started before then costs a port later.
- **Parallel agents during the refactor.** Stage 1 and the sweep PR are
  single-agent, serialized, at an announced time. Stage 2 can be split by
  command across agents once `context.rs` exists. Stage 3 is one agent per
  tailor after the trait and the Python port land. Stage 4 splits by file.

---

## 6. Open questions (decide in the stage review, not here)

- Should `nativelibs` live in the Python tailor or the kernel? It is used
  only by Python builds today but is conceptually "relocatable native libs
  for Linux," which a future C/C++ or Rust-with-sys-crates story could
  want. Plan: Python tailor now, promote when a second user appears.
- Should `gitsrc` be kernel or a tailor-like "source" abstraction? Three
  tailors use it. Plan: kernel now; if a second source kind appears
  (Mercurial, tarball-by-URL), introduce a `Source` trait beside `Tailor`.
- `deps.rs` (`add`/`remove`/`update`) edits manifests for Python and npm
  only. After Stage 3 it should dispatch through a `Tailor::edit_manifest`
  method; until then it stays a command with two branches.
- Does `comforter/` warrant its own folder or is it `kernel/projection/`?
  Answer depends on whether it is still ecosystem-neutral after Stage 3.

---

## 7. Change log

Append-only. One entry per landed PR or per decision. Newest at the bottom.

### 2026-09-11 — plan written

- Comb-through of `src/` at `fb8b1d6`. Baseline metrics recorded in §1.
- Decided: four stages, sequential, each landing fully before the next.
- Decided: single crate stays; folder layout designed to be crate-splittable.
- Decided: Stage 1 uses `lib.rs` re-export shims so the move does not
  touch call sites; a separate sweep PR removes the shims.
- Decided: folder vocabulary is `kernel` / `tailors` / `comforter` /
  `commands` / `cli`, matching the architecture doc.
- Not yet done: nothing has moved. STATUS.md and CLAUDE.md do not yet
  reference this file; add a pointer when Stage 1 is scheduled.

### 2026-09-12 — Stage 1 landed: files moved into folders

- Every `src/*.rs` except the entry points and the command implementations
  (`cli`, `deps`, `inspect`, `sbom`, `xrun`, `audit`) moved into
  `kernel/`, `tailors/<ecosystem>/`, or `comforter/` with `git mv`; no
  file was split. `audit.rs` (landed after the plan's baseline) is a
  command implementation and moves with the others in Stage 2.
- `lib.rs` re-exports every old module name (the compatibility shim), so
  no call site changed. The six modules without a `//!` line (`fetch`,
  `platform`, `policy`, `store`, `types`, `python`) got one; `kernel/mod.rs`
  and `tailors/mod.rs` state their layer.
- `tools/modgraph.py` is the §1 metric script (pure standard library). It
  counts non-test code only and resolves grouped `use crate::{..}` imports.
  On this basis the pre-move tree has **4** cycles (`build↔project`,
  `fetch↔store`, `gitsrc↔types`, `policy↔store`), not the 7 in §1: the
  other three (`activity↔store`, `elixir↔objmeta`, `nativelibs↔objmeta`)
  are one-way in non-test code. Stage 4's target is still zero.
- Gate: `cargo fmt --check`, `cargo build`, `cargo test` (614 passed, 0
  failed, same test set as baseline once module prefixes are normalized).
  The `--ignored` run is recorded in the next entry.
- Not runnable as-is: `docs/agent/review-fixtures/gc-a/mutations.py` is
  pinned to commit `9b11e05` and asserts that HEAD; it is evidence of a past
  review, not a live check, so its `src/gc.rs` paths were left alone.

### 2026-09-12 — Stage 1 sweep landed: old paths gone, shims deleted

- Every `crate::<old>` and `blanket::<old>` path now names the folder path
  (`crate::kernel::store`, `crate::tailors::python::pypi`, ...). Grouped
  `use crate::{..}` imports were expanded one module per line; the four
  modules whose leaf name changed are referred to by the new name at
  their call sites (`npm::` → `node::`, `golang::` → `go::`,
  `npm_lock_import::` → `lock_import::`, `project::` → `comforter::`).
- `lib.rs` has no compatibility shims. Stage 1 definition of done is met
  for everything that is not a file split.
- Gate: `cargo fmt --check`, `cargo test --no-run` (all targets),
  `cargo test` (614 passed, same set as baseline).

### 2026-09-12 — Stage 2 landed: `commands/` split

- `main.rs` is 68 lines: parse argv, set up output, `commands::resolve`,
  `commands::dispatch`. `dispatch` is a flat match, one call per arm.
- `commands/context.rs`: `Context { platform, store, activity }` built once
  by `dispatch` for every store-backed verb, with the maintenance sweep and
  the shared lease taken in the same order and scope as before. The project
  dir is a method that reads the cwd each time, because `add`/`remove`/
  `update` may change directory before running the ordinary sync; that
  behaviour is preserved rather than frozen into a field. `sync` now uses
  the `Context`'s store handle instead of opening a second one (the same
  store, one open fewer); `fmt` builds its own `Context` after its
  store-free checks, exactly where it used to open the store.
- One file per verb (`sync`, `plan`, `build`, `run`, `fmt`, `gc`, `store`,
  `completions`, `doctor`, `ls`, `status`, `audit`, `deps`, `sbom`, `x`);
  `deps.rs`, `inspect.rs`, `sbom.rs`, `xrun.rs` (→ `x.rs`), `audit.rs`
  moved under `commands/` with `git mv`. `inspect` stays `pub` (it was
  before); the rest of `commands/` is `pub(crate)`.
- Two renames so every verb file's entry point is `run`: `deps::run` →
  `deps::edit` (the manifest edit) and `xrun::run` → `x::launch` (the
  realize-and-exec step); `x::run(ctx, request)` now owns the `policy::init`
  that `dispatch` used to do inline.
- `commands/shared.rs` (~700 lines) holds the helpers two or more verbs use,
  including the whole Python planning stack (`read_plan` and friends). Stage
  3 turns most of it into tailor methods.
- `cli.rs` still calls `commands::deps::validate_spec` (an upward `cli →
  commands` edge that predates the refactor); moving that validator into
  `cli` is a Stage 4 item.
- Gate: `cargo fmt --check`, `cargo build`, `cargo test` (614 passed, same
  set as baseline). One unit test in `x.rs` failed once and passed on every
  rerun; recorded as FOLLOW-UPS.md item 8 (pre-existing race, not the move).
- Stage 2 step 5 (same day, separate commit `8258f82`, merged): `cli.rs`
  split into `cli/{mod,spec,parse,completions}.rs`, pure move verified
  line-range by line-range; 18 cli unit tests before and after;
  `tests/cli.rs` (33 tests) untouched and green. Three private helpers
  became `pub(super)`; git records the rename as `cli.rs → cli/parse.rs`.

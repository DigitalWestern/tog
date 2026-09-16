# Adding a tailor

A tailor is one ecosystem's adapter. Adding one is a folder plus a registry
line; no command file changes. This is the checklist that keeps that true
(REFACTOR.md principle 3). It was followed for the seven existing tailors
when they were ported to the `Tailor` trait on 2026-09-12.

## 1. The folder: `src/tailors/<eco>/`

| File | Owns |
|---|---|
| `mod.rs` | The pinned toolchain (per-platform rows with sha256s, verified at pin time), `preflight_platform`, `ensure_<toolchain>_for`, `plan_*`, `realize_*`, `project_*_env`, and `build_sandboxed` if the ecosystem builds. Declares the sibling modules. |
| `tailor.rs` | `pub struct <Eco>;` and `impl Tailor for <Eco>` (`src/tailors/mod.rs`). Each method is one verb's branch: `detect`, `preflight`, `prepare` (missing-lock generation), `plan`, `sync`, `build*`, `run_env`, `listing`, `closure_state`, `doctor`, `sbom_components`, `fmt*`, `object_kinds`. Only implement what the ecosystem has; the defaults say "not supported". |
| `objects.rs` | `pub static KINDS: &[KindAdapter]`: one row per (kind, schema) pair the tailor commits to the store, with the live grammar, migration grammar, and the function that recovers a legacy record's dependencies. Add the producer's full `live_contract` beside its identity constructor whenever it has dynamic counts, paired keys, or platform-conditional inputs. A kind without a row is refused by GC, never certified. The registry hands every tailor's rows to the kernel at startup (`tailors::install_kinds`, called by `commands::dispatch`); nothing to wire by hand. |
| `inputs.rs` (optional) | Project-inputs-to-plan loaders when they are more than a few lines. |

Rules the tailor must keep:

- It depends on `crate::kernel` and `crate::comforter` only. Never on
  another tailor, never on `crate::commands`. `tests/architecture.rs`
  fails the build otherwise.
- Every method takes the project directory explicitly; a tailor never reads
  the current directory.
- Store objects are input-addressed: what goes into `Identity.inputs`
  defines the object id. A new input means a new schema value
  (`"<kind>/2"`), a new `objects.rs` row, and the old row kept for the
  records already on disk.
- Add a producer-backed matrix case for every row and every conditional
  shape. The case must call the real identity constructor. Seed small offline
  fixtures when construction needs external evidence, then assert the live
  contract, required-input omissions, relation mutations, count mutations,
  and migration-grammar acceptance.
- Closures are written through `comforter::write_closure` and read through
  `comforter::read_closure`; `.blanket/closures/<eco>.json` is the proof a
  project was synced and is what `status`, `ls`, `sbom`, and `audit` read.

## 2. The registry line

`src/tailors/mod.rs`, `REGISTRY`: add `&<eco>::tailor::<Eco>` in display
order (this order is `plan` output, `sync` narration, `status` rows, `ls`).

## 3. The vocabulary lists (still hand-maintained)

These name ecosystems outside the registry; keep them in step:

- `src/cli/spec.rs`: `LS_WORDS` (what `ls <ecosystem>` accepts) and
  `BUILD_WORDS` if the ecosystem builds; the grammar has no I/O and so does
  not read the registry.
- `src/commands/inspect.rs`: `ECOSYSTEMS` (display order; a unit test
  asserts it matches the registry).
- `src/commands/deps.rs`: `Eco` if the ecosystem supports
  `add`/`remove`/`update` (REFACTOR.md §6: a `Tailor::edit_manifest`
  method is the planned replacement).
- `src/commands/x.rs`: only if the ecosystem has a registry-tool runner.

## 4. Tests and evidence

- A fixture under `tests/fixtures/<eco>-hello/` small enough to sync in
  seconds.
- An e2e test `tests/<eco>_e2e.rs` marked `#[ignore]` that syncs, runs, and
  (if applicable) builds the fixture offline the second time; it takes
  `supervise::SUPERVISION_TEST_LOCK` and a temp `BLANKET_STORE`.
- A metadata golden in the `objects.rs` row's test module for every kind:
  a legacy record adapts to the exact dependency set the producer wrote.
- A row in `tests/acceptance.sh` and in `docs/human/ARCHITECTURE.md`'s
  tailor table; a `docs/agent/LINUX_PORT.md` entry if the sandbox or
  platform pins change.
- Review per STATUS.md: an agent who did not write the tailor reviews it
  before it is called shipped.

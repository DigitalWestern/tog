# Adding a tailor

A tailor is one ecosystem's adapter. Adding one is a folder plus a registry
line; no command file changes. This is the checklist that keeps that true
(layering rule 3 in docs/human/ARCHITECTURE.md). It was followed for the seven existing tailors
when they were ported to the `Tailor` trait on 2026-09-12.

## 1. The folder: `src/tailors/<eco>/`

| File | Owns |
|---|---|
| `catalog.toml` | The toolchain catalog: every release tog can realize, one verified row per platform, and the `default` a project with no pin gets. Generated, never hand-edited: add a reader for the ecosystem's upstream to `tools/catalog.py` and run `python3 tools/catalog.py <eco>` (see "Regenerating a catalog" below). |
| `mod.rs` | `static CATALOG: Shipped` over `include_str!("catalog.toml")` and `toolchain_catalog` (the parsed release bundles, with the recipe ids the identities commit to), `preflight_platform`, `ensure_<toolchain>_for`, `plan_*`, `realize_*`, `project_*_env`, and `build_sandboxed` if the ecosystem builds. Declares the sibling modules. |
| `tailor.rs` | `pub struct <Eco>;` and `impl Tailor for <Eco>` (`src/tailors/mod.rs`). Each method is one verb's branch: `detect`, `preflight`, `prepare` (missing-lock generation), `plan`, `sync`, `build*`, `run_env`, `refused_command` (`tog run` verbs refused before any environment is looked up), `listing`, `closure_state`, `doctor`, `sbom_components`, `fmt*`, `object_kinds`, `toolchain_kinds` (which of those kinds `doctor` lists as realized toolchains), `toolchain_catalog`, `registry_tool` (`tog x`). Only implement what the ecosystem has; the defaults say "not supported". |
| `objects.rs` | `pub static KINDS: &[KindAdapter]`: one row per (kind, schema) pair the tailor commits to the store, with the live grammar, migration grammar, and the function that recovers a legacy record's dependencies. Add the producer's full `live_contract` beside its identity constructor whenever it has dynamic counts, paired keys, or platform-conditional inputs. A kind without a row is refused by GC, never certified. The registry hands every tailor's rows to the kernel at startup (`tailors::install_kinds`, called by `commands::dispatch`); nothing to wire by hand. |
| `inputs.rs` (optional) | Project-inputs-to-plan loaders when they are more than a few lines. |

Rules the tailor must keep:

- It depends on `crate::kernel` and `crate::comforter` only. Never on
  another tailor, never on `crate::commands`. `tests/architecture.rs`
  fails the build otherwise.
- Every method takes the project directory explicitly; a tailor never reads
  the current directory.
- Regenerating a catalog: `python3 tools/catalog.py <eco> [<eco> ...]`
  (stdlib Python; set `GH_TOKEN` or be logged in to `gh` for the GitHub
  API). It adds every upstream release of the maintained lines that has a
  verifiable build for both supported platforms, re-verifies every row
  already in the file (they must not change: object ids and existing locks
  depend on them), prints each release it skipped and why, and never moves
  the default. `--set-default <release>` moves it, deliberately and in its
  own reviewable diff. `--check` writes nothing and exits non-zero if the
  file would change. An upstream re-publish (a Homebrew rebuild, a newer
  Hex for a BEAM pair) is a new release beside the old one, with a higher
  `revision`, and `--check` names it. Listings and checksum files are
  fetched fresh every run; only archives are cached. The generator's own
  offline tests: `python3 tools/test_catalog.py` (Python 3.11+).
  `tests/catalog_upstream.rs` re-checks samples later:
  `cargo test --test catalog_upstream -- --ignored`.
- Every artifact row `toolchain_catalog` emits must be served from an
  endpoint `SourcePolicy::shipped()` (`src/kernel/toolchain/source.rs`)
  lists under the row's `provider`; the registry test in `src/tailors/mod.rs`
  fails otherwise. Add the publisher's `https://` prefix there.
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
  `comforter::read_closure`; `.tog/closures/<eco>.json` is the proof a
  project was synced and is what `status`, `ls`, `sbom`, and `audit` read.
- `prepare` is the one method that writes project inputs: it generates the
  dependency lock when there is none, with the ecosystem's own tool. `plan`
  and `sync` read the lock and refuse a missing one through
  `tailors::missing_lock`, which names the file. `--frozen` skips `prepare`,
  so that refusal is how the promise never to modify project inputs is kept.
- `prepare`, `sync`, and any closure-producing `build` or `fmt` method receive
  a mutable `policy::Attribution`. Forward that token unchanged to the
  comforter writer. The tailor does not record, claim, finish, or discard the
  token itself. The command layer owns that lifecycle.

## 2. The registry line

`src/tailors/mod.rs`, `REGISTRY`: add `&<eco>::tailor::<Eco>` in display
order (this order is `plan` output, `sync` narration, `status` rows, `ls`).

## 3. The vocabulary lists (still hand-maintained)

These name ecosystems outside the registry; a test fails until each is in
step:

- `src/cli/spec.rs`: one `ECOSYSTEM_WORDS` row (id, lock ecosystem,
  whether it builds, extra closures). The `ls`, `build` and
  `update --toolchain` words are derived from it; the grammar may not name
  a tailor, so it mirrors the registry, and a parser test compares them.
- `add`/`remove`/`update`, only if the ecosystem has a public package
  registry: `Tailor::package_registry` (the `prefix:` and the registry's
  name), `Tailor::registry_exists`, and `Tailor::edit_manifest`, usually in
  the tailor's own `edit.rs`. The edit's tool runs through the
  `ResolutionDoor` it is given. `claims_package_name` and `edit_root` are
  optional. Nothing in `src/commands/deps.rs` changes.
- `tog x`, only if the ecosystem implements `Tailor::registry_tool`: a
  `(id, spelling)` row in `X_REGISTRIES` (`src/cli/spec.rs`), which the
  parser reads for the `--<word>`/`--<id>` flags and the `<word>:` prefix,
  and the two flags in the `x` help. A parser test fails until the row
  matches `RegistryTool::spelling`, and a help test until the help lists
  it. Everything else `x` needs lives in the tailor's `RegistryTool`.

## 4. Tests and evidence

- A fixture under `tests/fixtures/<eco>-hello/` small enough to sync in
  seconds.
- An e2e test `tests/<eco>_e2e.rs` marked `#[ignore]` that syncs, runs, and
  (if applicable) builds the fixture offline the second time; it takes
  `supervise::SUPERVISION_TEST_LOCK` and a temp `TOG_STORE`.
- A metadata golden in the `objects.rs` row's test module for every kind:
  a legacy record adapts to the exact dependency set the producer wrote.
- A row in `tests/acceptance.sh` and in `docs/human/ARCHITECTURE.md`'s
  tailor section; if the sandbox or platform pins change, update the
  Platforms section there.
- Review: an agent who did not write the tailor reviews it before it is
  called shipped, and the result goes in the pull request description.

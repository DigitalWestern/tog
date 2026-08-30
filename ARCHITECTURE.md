# Blanket architecture

Blanket is a **universal realization and environment kernel with
ecosystem-native planners**. One binary that (eventually) replaces
per-language package managers by owning the outer loop every ecosystem
shares: fetch a toolchain, lock a dependency graph, materialize it into an
immutable store, project an environment, run tasks.

The MVP proves the kernel with one ecosystem (Python) end to end.

## The model (stolen from Nix, minus the interface)

- **Store** (`~/.blanket/store`, `BLANKET_STORE` overrides): input-addressed
  immutable objects at `objects/<hash16>-<name>-<version>/`. An object's id
  is a hash of its `Identity` — kind, name, version, and every input that
  determines the output (artifact sha256s, dependency object ids). Objects
  are committed atomically (staged dir + rename) and made read-only.
- **Artifact cache** (`cache/sha256/<hash>`): every downloaded file, stored
  by verified content hash. Never refetched; enables offline reconstruction.
- **Environments are store objects too**: a `python-env` object is a
  venv-shaped immutable tree (pyvenv.cfg + `bin/python` symlink to the
  CPython object + merged site-packages). Identity = CPython object +
  sorted set of package artifact hashes. Identical locks share one object;
  conflicting locks coexist as different objects.
- **Projection**: a project's `.venv` is one symlink into the store, swapped
  atomically. Rollback = swapping back (instant cache hit). Provenance is
  written to `.blanket/closure.json`.

## Phases (the kernel-adapter boundary)

Per design review with Sol: **Plan → Realize → Project.**

1. **Plan** (adapter, `pypi.rs`): parse hash-pinned `requirements.txt`
   (pip/uv `--generate-hashes` format, `==` pins only), lock each
   requirement to one exact PyPI artifact by matching file hashes and
   selecting the best wheel for the platform (native arm64 > abi3 >
   universal2 > pure > sdist). Output: a typed `Plan`. Successful plans are
   cached in `.blanket/plan.json` keyed by input hash, so unchanged locks
   never touch the network again.
2. **Realize** (kernel, `store.rs`/`fetch.rs`/`python.rs`/`project.rs`):
   download+verify artifacts into the cache, provision the pinned CPython
   (astral-sh/python-build-standalone, checksums pinned in `python.rs`),
   assemble the env object, commit atomically.
3. **Project** (`project.rs`): atomic `.venv` symlink + closure JSON.

## Deliberate MVP decisions

- **Store root is user-local**, not `/opt/blanket/store` (Sol's pick).
  Binary-cache sharing — the only thing that *requires* one global logical
  path — is out of MVP scope, and identities are machine-independent, so
  migration is "re-realize", not a format break. Revisit at the binary
  cache milestone.
- **Env-level granularity**: wheels install directly into the env object
  rather than per-package store objects merged by clonefile. Sharing is at
  whole-environment level. Per-package objects are a later optimization
  the identity scheme already permits.
- **Wheels only** in the realize path; an sdist in the plan is a clear
  error. Sandboxed sdist builds (sandbox-exec, network denied) are M3.
- **CPython pins are trust-on-first-use** (hashes computed at pin time).
  A signed provider manifest replaces the static table post-MVP.
- **No solver**: blanket consumes existing hash-pinned lockfiles
  (`uv pip compile --generate-hashes`). Sol's "locked-plan realizer, not a
  universal resolver."
- `__pycache__` writes fail silently inside read-only store envs; Python
  degrades gracefully (no bytecode cache). Precompilation is a later
  optimization.

## Layout

    src/main.rs     CLI: sync | plan | run | store path
    src/types.rs    Identity, Plan, LockedPackage
    src/store.rs    immutable store: stage/commit/cache
    src/fetch.rs    verified downloads
    src/python.rs   pinned CPython provisioning
    src/pypi.rs     Python planner (adapter)
    src/wheel.rs    PEP 427 wheel installer
    src/project.rs  env realization + projection
    tests/acceptance.sh   end-to-end checklist against real PyPI

## Roadmap after MVP

M3: sandboxed sdist builds (sandbox-exec deny-by-default, no network).
M4: npm lockfile importer against the same kernel (peer-aware node_modules
    projection) — the second-ecosystem stress test of the kernel thesis.
M5: garbage collection (`blanket gc`), per-package store objects, binary
    cache + `/opt/blanket/store` decision, signed toolchain manifests.

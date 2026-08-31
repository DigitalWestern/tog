# Blanket architecture

Blanket is a **universal realization and environment kernel with
ecosystem-native planners**. One binary that (eventually) replaces
per-language package managers by owning the outer loop every ecosystem
shares: fetch a toolchain, lock a dependency graph, materialize it into an
immutable store, project an environment, run tasks.

Two ecosystems (Python, JavaScript/npm) are built and proven on real
projects: Next.js 15 + vitest suites, vite apps (build AND dev server),
prisma, native addons compiled hermetically (better-sqlite3, sharp),
FastAPI apps with native wheels. The npm tailor cost ~450 lines against
Python's ~1500 + kernel — the kernel thesis holding empirically.

## The model (stolen from Nix, minus the interface)

- **Store** (`~/.blanket/store`, `BLANKET_STORE` overrides): input-addressed
  immutable objects at `objects/<hash16>-<name>-<version>/`. An object's id
  is a hash of its `Identity` — kind, name, version, and every input that
  determines the output (artifact sha256s, dependency object ids). Objects
  are committed atomically (staged dir + rename) and made read-only.
- **Artifact cache** (`cache/sha256/<hash>`): every downloaded file, stored
  by verified content hash. Never refetched; enables offline reconstruction.
- **Environments are store objects too** (comforters): a `python-env` object is a
  venv-shaped immutable tree (pyvenv.cfg + `bin/python` symlink to the
  CPython object + merged site-packages). Identity = CPython object +
  sorted set of package artifact hashes. Identical locks share one object;
  conflicting locks coexist as different objects.
- **Projection**: a project's `.venv` is one symlink into the store, swapped
  atomically. Rollback = swapping back (instant cache hit). Provenance is
  written to `.blanket/closure.json`.
- **Node projection is a forest** (`node-forest/1`): `node_modules` is a
  symlink to `~/.blanket/forests/<project-key>/<projection-id>/node_modules`,
  a WRITABLE per-project directory holding one symlink per top-level package
  into the immutable store object (pnpm's proven resolution model). The
  ecosystem treats node_modules' top level as scratch space — vite's `.vite`
  dep cache, prisma's `.prisma` client — and the forest absorbs those writes
  while package contents stay read-only in the store. Forests live OUTSIDE
  the project so test runners never crawl store packages' own test files.
  Declared-mutable packages (`package.json` → `"blanket": {"mutablePackages":
  [...]}`) switch the projection to a whole-tree APFS clonefile copy so
  runtime writes inside those packages succeed; the closure records them as
  `mutable_state: "unattested"`. `blanket sync --fresh` rebuilds the
  projection, dropping caches and mutable state.

## Vocabulary

The blanket theme, used in docs and conversation (code keeps the boring
technical identifiers):

| word | meaning | technical term in code |
|---|---|---|
| **blanket** | the tool itself | binary `blanket` (crate name would be `blanket-pm`; `blanket` is taken on crates.io) |
| **tailor** | a per-ecosystem adapter: measures an ecosystem and cuts its packages to fit (the PyPI tailor, the npm tailor) | adapter modules `pypi.rs`, `npm.rs` |
| **pattern** | the fully locked plan a tailor cuts — the exact instructions an environment is made from | `Plan` / `NpmPlan` |
| **comforter** | a realized environment — stitched once, immutable, shared by every project with the same lock | env object (`python-env` / `node-env`) |
| **closet** | where finished comforters are kept, folded, never altered | the store |

The story: each language's tailor cuts a pattern; blanket realizes it
into a comforter, kept folded in the closet. Your `.venv` and
`node_modules` are comforters.

Names were collision-checked (2026-08-30): every word passes the
"no famous tool already means this to developers" test. Earlier
candidates rejected for failing it: loom (major Rust testing crate,
Java's Project Loom), quilt (the Unix patch tool Debian packaging uses).
"blanket" itself: kept per the yarn precedent (npm's yarn thrived beside
Hadoop YARN) — the only cost is publishing any future crate as
`blanket-pm`.

## Phases (the kernel-adapter boundary)

Per design review with Sol: **Plan → Realize → Project.**

1. **Plan** (the tailor — adapter, `pypi.rs`): parse hash-pinned `requirements.txt`
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

## Hermetic install scripts (the npm compatibility keystone)

npm lifecycle scripts (preinstall/install/postinstall, plus npm's implicit
`node-gyp rebuild` for binding.gyp packages) run at realize time inside the
network-denied sandbox: writes confined to the package's own directory plus
a scratch HOME, reads limited to the staged tree + toolchain objects +
system. node-gyp comes shimmed from the store node's bundled npm, headers
from the store node object (`npm_config_nodedir`), and gyp's Python is the
store's pinned CPython — native addons compile against pinned toolchains,
never developer-shell drift. Script failure in an optional package warns
and continues (npm parity); in a required package it aborts, fail-closed.

Honesty notes (Sol review 3, 2026-08-31): this is a **cooperative
network-denial build sandbox, not hostile-code containment** — mach-lookup
is broad, daemons could outlive a script, and packages inside one
realization are only partially isolated from each other (fresh scratch
HOME per package and read-only tool shims, but a parent package's write
rule covers its nested children). Any script failure aborts the whole
realization — npm's tolerate-optional-failures behavior is deliberately
NOT mirrored, because a half-built package must never enter an immutable,
forever-cache-hit object. Scripts run per-package in lockfile order
(deepest first), not dependency order. Host Xcode/SDK versions are not
part of build identity (same accepted impurity as Python sdist builds).

For packages that download binaries at install time (old sharp, various
prebuild-install users), projects declare the downloads as verified inputs:

    "blanket": { "artifacts": [ { "url": "https://...", "sha256": "<hex>",
                                  "path": ".npm/_libvips/<file>" } ] }

Blanket prefetches each through the verified artifact cache and plants it
at the HOME-relative path before scripts run; the package's own downloader
finds its cache warm and never touches the (denied) network. Artifacts are
identity inputs, so the env object id changes with them.

## Resolution is delegated; realization is owned

- Ranged `requirements.txt` → blanket runs `uv pip compile
  --generate-hashes` into `requirements.lock.txt` (staleness-stamped,
  regenerated when the source changes).
- `package.json` with no `package-lock.json` (bun/yarn/pnpm projects) →
  blanket runs `npm install --package-lock-only`.

Planning may touch the network with the ecosystem's own resolver; every
byte that reaches an environment still goes through the verified cache and
the hash-pinned plan. Be clear about the trust boundary: delegated
planning runs uv/npm **with your user privileges, unsandboxed** — exactly
the exposure of running those tools yourself (which is the status quo it
replaces), no more, no less. Resolving a hostile dependency tree can run
code at plan time (PEP 517 metadata builds); blanket's guarantees start at
realization.

Declared artifacts, honestly: the mechanism is **cache seeding** — it
works when the declaration matches where a package's downloader looks
(sharp's npm-cache convention today). It is an explicit, verified escape
hatch, not a stable contract with arbitrary installers.

## Store concurrency

Publication (rename→chmod→meta) and incomplete-object sweeping serialize on
a cross-process file lock (`tmp/.publish.lock`), so a concurrent `has()`
never mistakes a mid-publication object for a crashed one. Stage dirs and
download temp files use collision-proof names (atomic sequence numbers —
SystemTime ticks in microseconds on macOS and concurrent threads really do
collide; a shared download tmp once passed stream-hash verification while
the file held two writers' interleaved bytes).

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
- **Sdists build in a sandbox** (sandbox-exec, deny-by-default, no
  network) using a pinned hermetic pip/setuptools/wheel toolchain; the
  built wheel is a derivation-style store object. v0 sandbox limitations,
  eyes open: mach-lookup and process-exec are still broad (Seatbelt
  hermeticity, not hostile-code containment), and macOS deployment-target
  versions in wheel tags are not compared.
- **CPython pins are trust-on-first-use** (hashes computed at pin time).
  A signed provider manifest replaces the static table post-MVP.
- **No solver**: blanket consumes existing hash-pinned lockfiles
  (`uv pip compile --generate-hashes`). Sol's "locked-plan realizer, not a
  universal resolver."
- `blanket run` sets PYTHONDONTWRITEBYTECODE=1 (site-packages is
  read-only). Precompilation at realize time is a later optimization.
- **RECORD is left as shipped** inside installed dist-info: not verified
  on install, not rewritten to reflect actual layout. importlib.metadata
  version/metadata queries work; file listings may be inaccurate. Honest
  gap, scheduled with the M5 hardening pass.
- These are **immutable Python environments**, venv-shaped — not drop-in
  venvs: no activate scripts, and pip cannot mutate them (by design).

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

## Roadmap

M3 (done): sandboxed sdist builds.
M4 (done): npm tailor — lockfile importer, pinned Node, forest projection.
M4.5 (done): real-project compatibility — hermetic lifecycle scripts,
    declared artifacts, workspaces (link entries), uv/npm resolution
    delegation, mutable-package projections, store concurrency locks.
    Known remaining npm gaps: per-workspace nested node_modules (version
    conflicts inside workspaces are rejected with a hoisting hint), git/file
    `resolved` URLs, install scripts that need network for logic (not just
    artifacts) — those fail closed with instructions.
M5: hardening pass — RECORD verification/rewrite, Mach-service allowlist in
    the sandbox, macOS deployment-target tag comparison, reproducibility
    checks (rebuild + compare), garbage collection (`blanket gc` — forests
    and backups included), per-package store objects, binary cache +
    /opt/blanket/store decision, signed toolchain manifests.
See ROADMAP.md for direction (enterprise frame, expansion tracks).

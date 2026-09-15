# Blanket architecture

Blanket is a universal realization and environment kernel with
ecosystem-native planners. One binary that (eventually) replaces per-language
package managers by owning the outer loop every ecosystem shares: fetch a
toolchain, lock a dependency graph, materialize it into an immutable store,
project an environment, run tasks.

Seven ecosystems are built. Python and JavaScript/npm are proven on real
projects: Next.js 15 + vitest suites, vite apps (build and dev server),
prisma, native addons compiled hermetically (better-sqlite3, sharp), FastAPI
apps with native wheels. Cargo, Go, Ruby, Elixir, and .NET all landed
2026-08-31 as wrap-hermetically tailors. Tailor cost, measured honestly
(adapter code excluding tests): Python ~1030 lines (pypi+wheel+python+build),
npm ~1015, cargo ~690, go ~600, ruby ~540, elixir ~620, dotnet ~540. The
kernel thesis holds. pnpm v9/v6 and Yarn classic lockfile importers shipped
2026-09-06 (`src/tailors/node/lock_import/`). Current version: blanket 0.1.0.

## The model

Stolen from Nix, minus the interface.

- **Store** (`~/.blanket/store`, `BLANKET_STORE` overrides): input-addressed
  immutable objects at `objects/<hash16>-<name>-<version>/`. An object's id
  is a hash of its `Identity`: kind, name, version, and every input that
  determines the output (artifact sha256s, dependency object ids). Objects
  are committed atomically (staged dir + rename) and made read-only.
- **Artifact cache** (`cache/sha256/<hash>`): every downloaded file, stored
  by verified content hash. Never refetched; enables offline reconstruction.
- **Comforters (environments are store objects too)**: a `python-env` object
  is a venv-shaped immutable tree. Identity = CPython object + sorted set of
  package artifact hashes. Identical locks share one object; conflicting
  locks coexist as different objects.
- **Projection**: a project's `.venv` is one symlink into the store, swapped
  atomically. Rollback = swapping back (instant cache hit). Provenance lives
  in `.blanket/closure.json`.
- **Node projection is a forest** (`node-forest/2`): the root `node_modules`
  is a symlink into `<BLANKET_STORE>/forests/<project-key>/<projection-id>/`,
  each workspace importer gets its own symlink, and the immutable env holds
  the same layout. The forest is a writable per-project directory that
  absorbs scratch writes (vite's `.vite` cache, prisma's `.prisma` client)
  while package contents stay read-only in the store. Forests live outside
  the project so test runners never crawl store packages' own test files.
  Declared-mutable packages (`"blanket": {"mutablePackages": [...]}`) switch
  to a whole-tree copy-on-write clone, recorded `unattested` in the closure.

Per design review: **Plan → Realize → Project**. The tailor (adapter) turns
manifests and lockfiles into a typed `Plan`. The kernel realizes it: verify
downloads into the cache, provision pinned toolchains, commit objects
atomically. Projection writes the symlink and the closure JSON. Plans are
cached in `.blanket/plan.json` keyed by input hash, so unchanged locks never
touch the network again.

## Vocabulary

The blanket theme, used in docs and conversation (code keeps boring
identifiers):

| word | meaning | in code |
|---|---|---|
| **tailor** | a per-ecosystem adapter that cuts a package graph to fit | `pypi.rs`, `npm.rs`, ... |
| **pattern** | the fully locked plan a tailor cuts | `Plan` / `NpmPlan` |
| **comforter** | a realized environment, stitched once, immutable, shared | `python-env` / `node-env` object |
| **closet** | where finished comforters are kept, folded, never altered | the store |

Your `.venv` and `node_modules` are comforters.

## Platforms

`src/kernel/platform.rs` defines `Platform` (`aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu`) and is the only module that knows the host. Every
pin table has one row per platform; every toolchain identity carries the
triple, so a store shared between a Mac and a Linux box never confuses
objects. Anything unsupported on a platform fails with
`io::ErrorKind::Unsupported` and a `LINUX_PORT.md` stage reference before
touching the store or the network.

## The tailors

**Python** (`tailors/python/`: `pypi.rs`, `manifest/`, `wheel.rs`, `mod.rs`,
`pyselect.rs`, `env.rs`). Resolution of ranged requirements is delegated to the
store-pinned uv (`uv pip compile --generate-hashes`); hash-pinned
requirements and `pyproject.toml` dependencies are locked directly, choosing
the best wheel per platform (native arm64 > abi3 > universal2 > pure >
sdist). CPython comes from astral-sh/python-build-standalone with sha256s
pinned in `python/mod.rs`; interpreter selection happens before locking
(`.python-version` wins, then `requires-python`). Wheels install into the
env object; sdists build in a network-denied sandbox (legacy setuptools
records keep `sdist-build/2`, PEP 517 uses `sdist-build/3` with an immutable
build environment). Environments are immutable: no activate scripts, pip
cannot mutate them.

**npm** (`tailors/node/`: `plan.rs`, `realize.rs`, `project.rs`, `lock_import/`). `package-lock.json` is parsed
locally; a pnpm v9/v6 or Yarn classic lockfile is imported by
`lock_import/` (dependency-free strict YAML for pnpm, `lock_source`
recorded); with none of these, the store node's bundled npm runs
`npm install --package-lock-only`. Lifecycle scripts run hermetically (below).
Native addons compile against the pinned Node. Existing locks win over
ranged manifests, so a bare machine needs nothing installed besides blanket.

**cargo** (`cargo.rs`). Rust has no installed-environment analog, so the
comforter is everything cargo needs to build fully offline: a pinned
toolchain object (rustc + cargo + rust-std, TOFU-pinned sha256s) plus a
`cargo-vendor` object of every registry crate, hash-verified, with blanket
generated `.cargo-checksum.json`. Vendor identity is the sorted crate
checksums only, so locks with the same crate set share one object.
Enforcement is a cargo wrapper under `.blanket/cargo-home/bin/` that execs
the store cargo with `--frozen`; user-supplied `--config` is rejected and
`RUSTC` is forced. `blanket build` sandboxes the compile with a disposable
`CARGO_HOME` (a build script must never be able to rewrite the wrapper that
later runs unsandboxed). Honest gap: `blanket run cargo build` is
offline-configured but not sandboxed; use `blanket build`. `blanket fmt`
realizes a separate pinned `rustfmt` object linked against the Rust object.

**go** (`golang.rs`, `dirhash.rs`). go.sum is an authentication ledger, not
a lock graph, so the closure is computed by the store Go toolchain itself
(`go mod tidy -diff`, then `go mod download -json all`), and blanket
re-verifies every artifact (dirhash h1, byte-for-byte reproduced, plus raw
sha256) before bytes enter the cache. The comforter is a `go-modcache`
object. Enforcement is pure environment: `GOTOOLCHAIN=local` (the `auto`
default silently swaps toolchains), `GOROOT`, `GOENV=off`, `GOPROXY=off`.
`blanket build` runs `go build -mod=readonly` with the project read-only.
cgo uses host clang, the standing accepted impurity.

**ruby** (`ruby.rs`). Bundler-shaped: lock parsing and platform selection
are delegated to the pinned portable Ruby's own Bundler/RubyGems via a
helper script, because `Gem::Platform` matching has wildcards and
specificity scores no hand parser should reimplement. Gem hashes come from
the lock's CHECKSUMS or rubygems.org, always platform-qualified (the bare
endpoint returns the latest-pushed variant). Gems install dependency-first
inside the network-denied sandbox into one immutable GEM_HOME object;
binstubs are wrapper scripts, never symlinks (symlinks dangle after the
store-commit rename; this bit once). Every blanket invocation strips
`BUNDLE_*`/`RUBYOPT` and forces `BUNDLE_FROZEN`, `GEM_HOME`/`GEM_PATH`.
v0 gaps: non-rubygems.org sources, PATH/GIT gems.

**elixir** (`elixir.rs`). mix.lock is an Elixir term literal that Mix itself
evaluates as code, so blanket parses it under the pinned toolchain with a
strict AST grammar: exact 8-field `{:hex, ...}` tuples of literals only;
calls, variables, and legacy tuple shapes are rejected loudly. Hex tarballs
are dual-checksum verified (outer tar sha256, inner content sha256). The
`beam` object is four pinned artifacts: OTP, the Elixir release zip, plus
OTP-qualified Hex and rebar3 builds (the legacy `hex.ez` hangs on OTP 29;
found live). Deps are source trees, realized as a `hex-deps` object and
projected as a writable clonefile copy so native builds can write into their
own sources. `blanket build` sandboxes `mix compile`.

**dotnet** (`dotnet.rs`). NuGet's `packages.lock.json` is opt-in upstream;
blanket makes it mandatory. The lock's `contentHash` is a semantic hash, so
blanket never raw-compares: it fetches nupkgs into a local folder feed, then
the pinned NuGet installs from that feed in locked mode, verifying every
contentHash. The SDK is the extractor and part of the object identity. Builds
are the strictest boundary: `blanket run` refuses build-capable verbs
(MSBuild executes arbitrary code and belongs only in the sandbox), and every
`blanket build` runs a fresh offline locked restore into scratch. `global.json`
must be an exact pin with `rollForward = "disable"`.

## Toolchain lock

Every ecosystem has a pinned toolchain table with exact selection rules;
the tables and selectors live in `src/kernel/platform.rs` and the per-ecosystem
modules. The committed `blanket-toolchain.toml` lock design (WP2, 2026-09-06)
and its implementation history are archived in `docs/agent/PLAN-2026-09-09.md`.

## Permissive by default, strict as a switch

Sync records recoverable verification gaps in each closure and continues;
`.blanket/policy.toml` denies named kinds (`install-script-failed`,
`git-dependency`, ...). User and project policies are unioned; deny entries
are only added. `BLANKET_STRICT=1` or `blanket sync --strict` denies every
exception. Object-affecting exceptions are written into store metadata and
rechecked on cache hits, so `--fresh` cannot bypass one. `blanket audit`
(`src/commands/audit.rs`) is the CI admission gate: it re-judges the exceptions the
closures already record against the policy chain plus an optional
`--policy` file (union, so it can only tighten), refuses to pass a stale or
unchecked closure, and touches neither the store nor the network.

## Hermetic install scripts and native libraries

npm lifecycle scripts (and npm's implicit `node-gyp rebuild`) run at realize
time in a network-denied sandbox: writes confined to the package directory
plus a scratch HOME, node-gyp shimmed from the store node, gyp's Python the
store CPython. This is a cooperative network-denial build sandbox, not
hostile-code containment. Packages that download binaries at install time
get them via declared artifacts: the project pins `url` + `sha256`, blanket
prefetches through the verified cache and plants the file where the package's
downloader looks. Linux builds needing C libraries get one pinned
`native-libs/libset/3` object, a fixed conda-forge closure (zlib, OpenSSL,
freetype, cairo, ...) with prefixes relocated at staging; the set id is an
input of every derivation that mounts it. macOS arm64 has no native pin yet
and fails closed.

## GC root safety

The store's `roots/<sha1>` registry records every project whose closure can
protect store objects. New `root/2` records contain the complete object set
and typed projection references, so GC never opens the project's diagnostic
path: a moved, unmounted, or deleted project keeps its tools protected.
Legacy pathname-only records stay conservative: if the project cannot be
read, the whole sweep stops before any deletion, dry run included.
`blanket store roots` prints each key beside its path. `blanket gc --forget
<key>` is the explicit recovery valve: it removes only the registry file, and
a root is never removed implicitly.

Sweeps run in four phases, `gc::{read, validate, plan, execute}`. `read`
gathers every root and record and holds a descriptor for each directory it
may delete from. `validate` proves the retained set or refuses with every
blocked reason at once. `plan` builds the complete deletion plan in memory.
`execute` is the only phase that deletes, re-checking each candidate against
the `(dev, ino)` the plan recorded. A dry run stops after `plan` and prints
it, so preview and sweep are the same phases over the same snapshot.

Whether an object may be deleted is decided by `meta/<id>.json`
(`object-meta/2`): explicit dependency object ids, algorithm-qualified cache
digests, and an `evidence` marker, `"explicit"` or `"adapted:<kind>@<n>"`.
Adapters in `src/kernel/objmeta.rs` upgrade legacy records to this form; each is a
pure function of one record plus a read-only index, dispatched on the
(kind, schema) pair, and never guesses from a current default pin. Unknown
or incomplete metadata blocks deletion. A legacy record whose evidence cannot
be fully accounted for stays legacy, and on a store whose records cannot all
be adapted, the sweep refuses and names what to fix. The containment guard
keeps migration sound: a proposed dependency set is checked against what the
old reader retained, and one that would narrow retention keeps legacy
protection instead of being published.

Each row in that (kind, schema) coverage matrix declares two input grammars.
Its `grammar` is the migration grammar, which remains compatible with legacy
records. Its `live_required` and `live_optional` fields describe the inputs
the current producer writes, including dynamic prefixes for conditional
package entries. The live check validates required names, the live key
whitelist, and the row's `live_relations` for paired or conditional inputs.
Debug builds enforce all three at the one publication choke point,
`Store::commit_internal_impl`, so a producer that starts writing a new input,
drops a required one, or emits an impossible partial group fails at the commit
that drifts rather than years later during migration.
A panic there means the producer and its row disagree: restore the producer if
the drift is accidental (a dropped input like `artifact_sha256` would let
distinct artifacts share an object id); update the row only for an intentional,
compatible addition; introduce a new schema value when identity semantics
change. A kind or schema with no registered row is rejected at commit time and
also fails closed at sweep time. Public tailor realization entry points call
`tailors::install_kinds()` before they can publish, while commands call it
through `commands::dispatch`; direct kernel callers install it explicitly.
Release builds skip the check; it catches developer error, it is not a store
invariant.

Status, 2026-09-10: implemented and independently reviewed on Linux (the
review ledger, [docs/agent/REVIEW.md](docs/agent/REVIEW.md), records the
rounds); the macOS gate has not run since this work landed. The boundary:
it covers cooperating blanket processes on a local filesystem with working
advisory locks and atomic rename; not old binaries, not programs launched
directly from store paths, not malicious same-user changes, not network
filesystems where `flock` is advisory in name only.

## Store concurrency

Publication and incomplete-object sweeping serialize on a cross-process file
lock (`tmp/.publish.lock`), so a concurrent `has()` never mistakes a
mid-publication object for a crashed one. Store-consuming operations hold an
activity lease (`src/kernel/activity.rs`), shared or exclusive, with a fixed
ordering: activity, then x-root, then project transaction, then cache, then
publication. Each process supervises at most one awaited store-consuming
child (`src/kernel/supervise.rs`) and forwards TERM to it. Contention is a named
outcome, not a hang: GC acquires exclusive activity and skips safely while a
managed job holds the shared lease. Stage dirs and download temps use
collision-proof names.

## Layout

Folders follow the layers (see [REFACTOR.md](../../REFACTOR.md) for the
rules and the change log): `commands → tailors → comforter → kernel`. The
kernel never names a tailor; a tailor never names another tailor;
`tests/architecture.rs` fails the build otherwise (its allow-list is where
the few documented exceptions live).

Entry point and grammar:

    src/main.rs     parse argv, set up output, call commands::resolve/dispatch
    src/cli/        command grammar + help (pure, unit-tested; see CLI.md):
                    mod.rs types, spec.rs the table, parse.rs, completions.rs

Commands (`src/commands/`, one file per verb; the only layer that knows
every tailor and the kernel):

    mod.rs          resolve() for the implicit forms, dispatch(): one call per verb
    shared.rs       project-directory and exit-code helpers two or more verbs share
    sync.rs  plan.rs  build.rs  run.rs  fmt.rs  gc.rs  store.rs  completions.rs
    doctor.rs  ls.rs  status.rs   thin verbs over inspect.rs
    inspect.rs      status / ls / doctor: read-only views over closures + store
    audit.rs        blanket audit: recorded exceptions judged against a policy
    deps.rs         add / remove / update, delegated to each ecosystem's tool
    sbom.rs         CycloneDX 1.5 JSON from the closure envelopes
    x.rs            blanket x: run a registry tool without adding it to a project

Kernel (`src/kernel/`, ecosystem-agnostic):

    types.rs        Identity, Plan, LockedPackage, GitSource
    digest.rs       validated content digests (sha1/sha256/sha512)
    context.rs      Context { platform, store, activity lease } for store-backed verbs
    cyclonedx.rs    CycloneDX component builders every tailor's sbom uses
    store/          immutable store: mod.rs Store and locks, objects.rs
                    stage/commit/cache, roots.rs the root registry,
                    projection.rs projection refs, env.rs BLANKET_STORE,
                    fsops.rs descriptor-level filesystem helpers
    fetch.rs        verified downloads
    archive.rs      archive validation and delegated extraction
    dirhash.rs      Go module dirhash verification
    gitsrc.rs       git sources realized by commit
    policy.rs       permissive/strict exception policy
    gc/             store garbage collection: read.rs snapshot, plan.rs
                    validate + plan, sweep.rs execute, migrate.rs maintenance
    objmeta.rs      object-meta/2 records; kind rows are installed by
                    commands::dispatch or public tailor entry points
    activity.rs     store activity leases
    supervise.rs    supervised child processes
    platform.rs     the only module that knows the host
    sandbox.rs      hermetic build sandbox (Seatbelt / bubblewrap)
    ui.rs           output conventions: quiet/verbose/color, error channel

Comforter (`src/comforter/`): ecosystem-neutral closure records, projection
symlinks, clone-tree and backup helpers (`mod.rs`) and `status.rs`, the
projection-currency checks `blanket status` is built from. It names no
tailor; Python environment realization lives in `tailors/python/env.rs`.

Tailors (`src/tailors/<ecosystem>/`, leaves of the module graph). Every
folder has `tailor.rs` (its `impl Tailor`, the one blueprint every
ecosystem answers: detect, preflight, plan, sync, build, run_env, listing,
closure_state, sbom_components, object_kinds) and `objects.rs` (the store
object kinds it produces, with their live and migration identity grammars and
legacy-metadata adapters); `src/tailors/mod.rs` holds the trait and the registry the
commands iterate. See docs/human/ADDING-A-TAILOR.md.

    python/mod.rs          pinned CPython provisioning
    python/inputs.rs       project inputs to a Python plan (uv lock, plan cache)
    python/pypi.rs         Python planner (adapter)
    python/wheel.rs        PEP 427 wheel installer
    python/pyselect.rs     CPython constraint parsing and selection
    python/pep440.rs       PEP 440 versions and specifiers
    python/manifest/       manifest discovery (discovery.rs), poetry.rs, uv.rs,
                           requirements.rs, setup.rs, markers.rs
    python/env.rs          venv-shaped env object realization and projection
    python/build.rs        sandboxed sdist-to-wheel builds
    python/build_requires.rs  PEP 517 build requirements
    python/nativelibs.rs   pinned, relocatable native libraries for Linux builds
    python/artifacts.rs    install-time artifact policy
    node/mod.rs            pins, plan types, scripts, path helpers
    node/plan.rs           package-lock.json planning
    node/realize.rs        env realization and sandboxed install scripts
    node/project.rs        node_modules projection and workspace links
    node/inputs.rs         missing-lock generation, lockfile importers
    node/lock_import/      pnpm.rs and yarn1.rs importers over yaml.rs
    cargo/mod.rs           Cargo.lock importer + registry vendor realization
    cargo/inputs.rs        toolchain resolution, workspace root, missing-lock generation
    cargo/rustfmt.rs       pinned formatter component for `blanket fmt`
    go/mod.rs              module closure via the pinned Go toolchain
    go/inputs.rs           toolchain selection from go.mod, the GoPlan
    ruby/mod.rs            Bundler-delegated planning, blanket-verified gems
    elixir/mod.rs          Mix/Hex, AST-validated lockfile
    dotnet/mod.rs          NuGet packages.lock.json (blanket-mandatory)

## Where the rest lives

Human docs sit next to this one (`docs/human/CLI.md` is the command
reference, `docs/human/LIMITATIONS.md` the recorded, accepted gaps). The
agent archive under `docs/agent/` holds the review ledger (`REVIEW.md`),
the dated review reports, the archived plan (`PLAN-2026-09-09.md`,
including the full WP2 toolchain-lock design), the platform changelog
(`LINUX_PORT.md`), and the frozen item-number index (`NEXT.md`).

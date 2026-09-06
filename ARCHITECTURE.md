# Blanket architecture

Blanket is a **universal realization and environment kernel with
ecosystem-native planners**. One binary that (eventually) replaces
per-language package managers by owning the outer loop every ecosystem
shares: fetch a toolchain, lock a dependency graph, materialize it into an
immutable store, project an environment, run tasks.

Seven ecosystems are built. Python and JavaScript/npm are proven on real
projects: Next.js 15 + vitest suites, vite apps (build AND dev server),
prisma, native addons compiled hermetically (better-sqlite3, sharp),
FastAPI apps with native wheels. Cargo (Rust), Go, Ruby, Elixir, and
.NET all landed 2026-08-31 as wrap-hermetically tailors. Tailor cost,
measured honestly (adapter code excluding tests): Python ~1030 lines
(pypi+wheel+python+build), npm ~1015 (self-contained), cargo ~690,
go ~600, ruby ~540, elixir ~620, dotnet ~540 — the curve's overall
trend holds; the kernel thesis holds.

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
  [...]}`) switch the projection to a whole-tree copy-on-write clone (APFS clonefile on macOS, `cp --reflink=auto` on Linux) so
  runtime writes inside those packages succeed; the closure records them as
  `mutable_state: "unattested"`. `blanket sync --fresh` rebuilds the
  projection, dropping caches and mutable state.

## Platforms

`src/platform.rs` defines `Platform` (`aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu`). Every pin table has one row per platform;
every toolchain identity carries the triple, so a store shared between a
Mac and a Linux box never confuses objects (artifact-cache entries are
shared by content hash). Selection helpers take an explicit `Platform` so
both variants are unit-tested in one binary; `Platform::host()` is called
only at entry points. Anything not yet supported on a platform fails with
`io::ErrorKind::Unsupported` and a `LINUX_PORT.md` stage reference before
touching the store or the network.

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
   or [project].dependencies from `pyproject.toml`
   (pip/uv `--generate-hashes` format, `==` pins only), lock each
   requirement to one exact PyPI artifact by matching file hashes and
   selecting the best wheel for the platform (native arm64 > abi3 >
   universal2 > pure > sdist). Output: a typed `Plan`. Successful plans are
   cached in `.blanket/plan.json` keyed by input hash, so unchanged locks
   never touch the network again.
   Interpreter selection is performed before locking: an explicit
   `.python-version` wins, otherwise declared Python constraints are
   intersected and the compatible pinned CPython is recorded in the plan.
2. **Realize** (kernel, `store.rs`/`fetch.rs`/`python.rs`/`project.rs`):
   download+verify artifacts into the cache, provision the pinned CPython
   (astral-sh/python-build-standalone, checksums pinned in `python.rs`),
   assemble the env object, commit atomically.
3. **Project** (`project.rs`): atomic `.venv` symlink + closure JSON.

## Permissive by default, strict as a switch

Sync records recoverable verification gaps in each closure and continues.
`.blanket/policy.toml` (or `BLANKET_POLICY`) accepts:

    strict = false
    deny = ["install-script-failed", "git-dependency"]

The user policy and project policy are unioned; deny entries are only added.
`BLANKET_STRICT=1` and `blanket sync --strict` deny every exception.

| kind | recorded when |
|---|---|
| `requirement-skipped` | a project-local or direct Python requirement is skipped |
| `file-collision` | a later Python wheel replaces a file |
| `install-script-failed` | an npm lifecycle script fails in the sandbox |
| `weak-integrity` | an npm SHA-1 integrity is accepted and verified |
| `unattested-mutable-state` | an npm mutable projection is created |
| `toolchain-component-unavailable` | Cargo requests an unavailable component |
| `git-dependency` | reserved for the future git dependency tailor |

Object-affecting exceptions are written into store metadata. A strict policy
rechecks them on cache hits, so `blanket sync --fresh` cannot bypass an
exception; the object must be rebuilt permissively or the cause fixed.
The closure now says: “here are exactly the N of M that are not fully
verified.”

## Hermetic install scripts (the npm compatibility keystone)

npm lifecycle scripts (preinstall/install/postinstall, plus npm's implicit
`node-gyp rebuild` for binding.gyp packages) run at realize time inside the
network-denied sandbox: writes confined to the package's own directory plus
a scratch HOME, reads limited to the staged tree + toolchain objects +
system. node-gyp comes shimmed from the store node's bundled npm, headers
from the store node object (`npm_config_nodedir`), and gyp's Python is the
store's pinned CPython — native addons compile against pinned toolchains,
never developer-shell drift. A failed script keeps its extracted package and
records `install-script-failed`; strict policy aborts.

Honesty notes (Sol review 3, 2026-08-31): this is a **cooperative
network-denial build sandbox, not hostile-code containment** — mach-lookup
is broad, daemons could outlive a script, and packages inside one
realization are only partially isolated from each other (fresh scratch
HOME per package and read-only tool shims, but a parent package's write
rule covers its nested children). Permissive mode retains a half-built
package as an immutable object carrying the exception; strict mode refuses
it. Scripts run per-package in lockfile order
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

## The cargo tailor (wrap hermetically — possibly permanently)

Rust has no installed-environment analog: cargo compiles source crates into
the final artifact. So the comforter is **everything cargo needs to build
fully offline**: a pinned toolchain object (`rust`: rustc + cargo +
rust-std component tarballs from static.rust-lang.org, TOFU-pinned sha256s)
plus a `cargo-vendor` object — every registry crate from Cargo.lock,
hash-verified, extracted into cargo's directory-source layout with
blanket-generated `.cargo-checksum.json` (complete per-file sha256 maps;
extraction rejects symlinks/hardlinks/special entries). Vendor identity =
sorted crate checksums only — deliberately excludes the toolchain and the
lock digest, so any two locks with the same crate set share one object.

Enforcement cannot ride on CARGO_HOME config precedence (a project's
`.cargo/config.toml` outranks it), so projection writes a **cargo wrapper**
(`.blanket/cargo-home/bin/cargo`, first on PATH under `blanket run`) that
execs the store cargo with `--frozen --config <blanket-config>` — CLI
config outranks everything; project config still merges for rustflags,
linkers, and aliases. Hardening from Sol's code review (all reproduced
before fixing): user-supplied `--config` is rejected (a later --config
outranks ours — reproduced vendor-source swap under intact provenance);
`RUSTC` is forced to the store compiler and `RUSTC_WRAPPER`/
`RUSTC_WORKSPACE_WRAPPER` cleared (project `[build] rustc` is honored
even under --frozen); projection paths are canonicalized-and-contained
per component (a symlinked cargo-home/bin carried writes outside the
project). Workspace rooting is delegated to the pinned cargo
(`locate-project --workspace`) — an ancestor-walk picks the wrong lock
when independent packages nest. Provenance: `.blanket/cargo-closure.json`
(rust + vendor object ids, Cargo.lock sha256, plan).

`blanket build [args]` runs the store cargo inside the same seatbelt
sandbox as sdist/npm-script builds: network denied, reads = project +
toolchain + vendor objects, writes = project `target/` + scratch only,
`CARGO_TARGET_DIR` forced project-local. The build gets a **disposable
per-build CARGO_HOME** in scratch — the projected cargo-home is never
writable in-sandbox, or a build script could replace the wrapper that
later runs unsandboxed under `blanket run`. Sandboxes cannot nest on
macOS — tests assert offline-ness via clean-target rebuilds, not outer
sandbox wrappers.

Honesty notes: `blanket run cargo build` is offline-configured but NOT
sandboxed (build.rs / proc-macros are arbitrary code; use `blanket build`
for the network-denied path). Toolchain files resolve against the pin
table (nearest ancestor, rustup precedence; `stable` → newest pin, beta/
nightly/foreign targets fail closed; extra components record
`toolchain-component-unavailable`). git dependencies
and alternative registries fail closed. `cargo install` through the
wrapper lands in cargo-home/bin, outside the closure — unmanaged.
Missing Cargo.lock is generated by the *store* cargo (network, unsandboxed
— the same delegated-planning trust boundary as uv/npm). External path
dependencies aren't validated at plan time; the build sandbox makes them
fail loudly. Because rooting delegates to cargo, even `blanket plan`
realizes the toolchain first (~105MB once, then cached) — correctness
over a light first plan.

## The Go tailor (delegation computes, the kernel verifies)

go.sum is an authentication ledger, not a lock graph (Sol review 4), so
the closure is computed by the STORE Go toolchain itself: `go mod tidy
-diff` gates consistency (an out-of-sync manifest triggers a delegated
`go mod tidy`, the same named-resolver mutation as uv/cargo lockfile
generation), then `go mod download -json all` runs in a disposable copy.
Blanket then re-verifies EVERY artifact itself — dirhash h1 (`dirhash.rs`
reproduces go.sum's Hash1 byte-for-byte, proven against real values) plus
raw sha256 — before bytes enter the verified cache. The comforter is a
`go-modcache` object: cache/download skeleton (zips/.mod/.info/.ziphash)
from the verified cache, extracted offline by the store Go (whose version
is an identity input — the extractor is part of the recipe).

Enforcement is pure process environment (Go has no project config file):
GOTOOLCHAIN=local (the "auto" default silently swaps toolchains!),
GOROOT=<store go>, GOENV=off, GOWORK=off, GOFLAGS cleared, GOPROXY=off +
GOSUMDB=off when offline — set as real env vars by `blanket run` and
`blanket build`, one helper, everywhere. `blanket build [go]` runs
`go build -mod=readonly` in the sandbox with the project READ-ONLY:
outputs are staged in scratch and moved in by blanket afterwards;
-mod/-modfile/-modcacherw/-toolexec/-overlay/-exec/-o are rejected.
v0 fail-closed gaps: go.work workspaces, local-path replace directives.
cgo uses host clang (the standing accepted impurity).

## The Ruby tailor (delegate the semantics, own the bytes)

Bundler-shaped: lock parsing and platform selection are delegated to the
pinned portable Ruby's OWN Bundler/RubyGems via an embedded helper script
(Gem::Platform matching has wildcards and specificity scores no hand
parser should reimplement — Sol review 5), emitting the local-platform
closure dependency-first as JSON. Hashes come from the lock's CHECKSUMS
section (bundler ≥2.6, when present) or the rubygems.org v2 API —
ALWAYS platform-qualified: the bare endpoint returns the latest-PUSHED
variant (racc 1.8.1 returns the java gem's sha; caught live by fetch
verification). Every .gem is fetched through the verified cache and its
embedded gemspec is cross-checked against the plan post-download.

Realize: one immutable GEM_HOME object per closure (`ruby-gems`), gems
installed dependency-first INSIDE the network-denied sandbox via
Gem::Installer driven directly by the helper (the `gem install` CLI
requires network-class code at load time and dies EPERM in-sandbox) —
native C extensions compile here against host clang (standing impurity).
Binstubs are wrapper SCRIPTS, never symlinks (symlinks dangle after the
store-commit rename — Sol reproduced the e2e passing via host /usr/bin
fallback). Executable-name collisions are detected before install, not
left to PATH order. The planning helper is split: the Gemfile-evaluating
consistency gate's output is never parsed (a hostile Gemfile can't forge
plan JSON); artifact coordinates come from a LOCK-ONLY mode. There is no
project-side plan cache (an editable cache with a predictable key is
forgeable authority); `blanket run` resolves closure objects THROUGH the
store by recorded id, never by recorded path (kernel-wide:
project::closure_object, applied to cargo/go/ruby). Toolchain: Homebrew portable-ruby 3.4.6 (relocatable,
bundler included; the ruby Homebrew itself ships on — newest portable
artifact; ruby-lang source may be ahead, documented gap).

Enforcement: bundler's local .bundle/config OUTRANKS plain env (the
reverse of cargo), so every blanket-controlled invocation strips
BUNDLE_*/BUNDLER_*/RUBYOPT/RUBYLIB/RUBYGEMS_GEMDEPS/GEMRC and forces
BUNDLE_IGNORE_CONFIG=1, BUNDLE_GEMFILE, BUNDLE_FROZEN, GEM_HOME/GEM_PATH
(kernel `sandbox::force_env` primitive — Sol review 5's env-projection
contract). PATH is ruby-first, then gem binstubs: a gem executable named
`ruby` must never shadow the toolchain. v0 fail-closed gaps: non-
rubygems.org sources, PATH/GIT gems, gems whose installers need network
or absent host libraries (mysql2-class).

## The Elixir tailor (a code-shaped lockfile, parsed — never eval'd)

mix.lock is an Elixir term LITERAL that Mix itself evaluates as code, so
blanket's planning parses it under the pinned toolchain with a strict AST
grammar (Code.string_to_quoted + static atom encoder; exact 8-field
`{:hex, ...}` tuples of literals only — calls, variables, operators, and
legacy shorter tuple shapes are rejected loudly). Artifact authority is
the lock alone; the Gemfile-forging lesson from Ruby applied preemptively.
Every hex tarball is dual-checksum verified by blanket: outer = sha256 of
the .tar (the lock's 8th field), inner = sha256(VERSION ++
metadata.config ++ contents.tar.gz) (the 4th field).

Toolchain (`beam` object) is FOUR pinned artifacts: OTP
(macOS: erlef/otp_builds community arm64 build; Linux: our own Fedora build published in DigitalWestern/blanket-toolchains because hex.pm's Ubuntu build cannot load crypto on Fedora — relocatable by
construction), the Elixir release zip (platform-neutral BEAM code keyed
to the OTP major — it contains NEITHER Hex nor rebar3), plus Hex and
rebar3 from builds.hex.pm, both OTP-QUALIFIED builds (the legacy
unqualified hex.ez is compiled for old OTP and hangs on 29 — found
live). Deps are SOURCE trees: realized as an immutable `hex-deps` object
(extracted contents + hex_metadata.config + the exact binary `.hex`
marker Mix pairs with the lock), then projected as a writable CLONEFILE
copy in the forests dir — native builds (make/rebar3 ports) write into
their own source trees (npm mutablePackages precedent, recorded
unattested). `blanket build [elixir]` = sandboxed `mix compile`, network
denied, writes only the beam-fingerprint-qualified build root
(`_build/blanket-<fp>`) + the deps projection; Mix's loopback-TCP
compilation lock is disabled in-sandbox (MIX_OS_CONCURRENCY_LOCK=false).
Enforcement is env (force_env): scrub MIX_*/HEX_*/REBAR_*/ERL_*/ELIXIR_*
and force MIX_DEPS_PATH/MIX_ARCHIVES/MIX_REBAR3/HEX_OFFLINE/MIX_TARGET.
v0 fail-closed gaps: git deps, non-hexpm repos, umbrella projects
untested, legacy lock entry shapes.

## The .NET tailor (semantic hashes, mandatory locks, sandbox-only builds)

NuGet's packages.lock.json is opt-in upstream; blanket makes it
MANDATORY (missing → delegated store-SDK `restore --use-lock-file`).
v1 locks only, one SDK-style .csproj, PackageReference only — solutions,
Central Package Management (lock v2+), PackageDownload, workloads, and
custom MSBuild SDKs fail closed (Sol review 7's boundary). The lock's
contentHash is a SEMANTIC hash (signed nupkgs hash transformed bytes,
not the download), so blanket never raw-compares: it fetches nupkgs into
a local folder feed (raw sha256 into the verified cache), then the
PINNED NuGet installs from that feed in locked mode — verifying every
contentHash and writing the exact global-packages layout; the SDK is the
extractor and part of the object identity (Go precedent). SDK pins come
from Microsoft's release-metadata endpoint (an HTTPS checksum channel —
published hashes, not signed metadata).

Realization verifies a synthetic project built only from the validated plan
and lock: the user's .csproj and global.json are never evaluated, and the
restore runs in the network-denied sandbox. All packages become exact-pinned
direct references in that verifier; its first lock target is used when a lock
contains multiple targets. The package identity includes both semantic lock
hashes and raw downloaded sha256 values, plus the full SDK object id.

Builds are the strictest boundary yet: project obj/ is NEVER authority —
every `blanket build [dotnet]` runs a fresh offline locked restore into
scratch (attesting project.assets.json) then `build --no-restore`, with
build servers disabled, shared compilation off, response files and
restore/source/path overrides rejected by an argument allowlist, and outputs
built in scratch before an assets attestation and atomic publish to
bin/blanket-<sdk-fp>. Build-capable verbs (build/run/test/publish/pack/
msbuild/restore/clean/watch) are REFUSED by `blanket run` — MSBuild
executes arbitrary code and belongs only in the sandbox; `blanket run
dotnet <app.dll>` runs compiled apps. One bounded sandbox write root is
added for CoreCLR's hardcoded /tmp/.dotnet mutex dir (its `shm` child is
pre-created: the runtime's own mkdtemp-in-/tmp fallback is denied by both
sandboxes). global.json:
exact pin + rollForward=disable, sdk.paths/msbuild-sdks rejected, and
ancestor global.json/Directory.Packages.props/Directory.Build.rsp/
packages.config files fail closed.

## Resolution is delegated; realization is owned

- Ranged `requirements.txt` or `pyproject.toml` project dependencies →
  blanket runs the STORE-pinned uv
  (`uv pip compile --generate-hashes`) into `requirements.lock.txt`
  (staleness-stamped, regenerated when the source changes).
- JavaScript lock selection is `package-lock.json` first, then a pnpm
  `pnpm-lock.yaml` importer (v9 and the compatible v6 importer shape), then a
  Yarn classic v1 `yarn.lock`; these are parsed directly into the npm plan.
  The pnpm subset uses a dependency-free strict 2-space YAML parser;
  workspace links stay project-local and the closure records `lock_source`.
  A package.json with none of those lockfiles falls back to the store node's
  bundled npm (`npm install --package-lock-only`).
- Missing `Cargo.lock` → the store cargo runs `generate-lockfile`.

Delegated resolvers come from the store (uv and npm are pinned toolchain
components like CPython/Node), while existing npm lockfiles are parsed
locally — a bare machine needs nothing installed besides blanket itself.
Proven with a scrubbed-PATH (`/usr/bin:/bin`) sync + run on both ecosystems,
2026-08-31.

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
- **Sdists build in a sandbox** (macOS: sandbox-exec/Seatbelt; Linux: bubblewrap with user/net/pid/ipc/uts namespaces — same `BuildSpec` contract, see `src/sandbox.rs` and LINUX_PORT.md stage 3; deny-by-default, no
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
    src/policy.rs   permissive/strict exception policy
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
    artifacts) — those retain the package with `install-script-failed`;
    strict policy refuses them.
M5: hardening pass — RECORD verification/rewrite, Mach-service allowlist in
    the sandbox, macOS deployment-target tag comparison, reproducibility
    checks (rebuild + compare), garbage collection (`blanket gc` — forests
    and backups included), per-package store objects, binary cache +
    /opt/blanket/store decision, signed toolchain manifests.
See ROADMAP.md for direction (enterprise frame, expansion tracks).

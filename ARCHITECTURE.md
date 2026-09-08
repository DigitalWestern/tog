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
- **Node projection is a forest** (`node-forest/2`): the root
  `node_modules` is a symlink to
  `~/.blanket/forests/<project-key>/<projection-id>/node_modules`, and each
  workspace importer gets its own symlink at
  `<project>/<workspace>/node_modules` pointing to
  `.../<projection-id>/workspaces/<workspace-with-slashes-encoded>/node_modules`.
  The immutable node environment contains the same root/workspace importer
  layout; each forest is a writable per-project directory holding one
  symlink per top-level package into that layout (pnpm's proven resolution
  model). Workspace links are relative symlinks back to source directories,
  and each importer gets its own `.bin`. The ecosystem treats node_modules'
  top level as scratch space — vite's `.vite` dep cache, prisma's `.prisma`
  client — and the forest absorbs those writes while package contents stay
  read-only in the store. Forests live OUTSIDE the project so test runners
  never crawl store packages' own test files.
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

1. **Plan** (the tailor — adapter, `manifest.rs` + `pypi.rs`): discover and
   normalize requirements files, PEP 621 metadata, Poetry metadata/locks,
   uv locks, `setup.cfg`, computed `setup.py` metadata, and conventional
   requirements directories into one list of PEP 508 requirement strings.
   Optional/development groups stay out unless explicitly requested. A found
   empty manifest creates an interpreter-only plan; absent and unreadable
   manifests have separate diagnostics. Hash-pinned `requirements.txt`
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
| `git-dependency` | pinned Git dependency; npm prepare is not executed |
| `skipped_optional` | an optional/dev dependency group was not requested |
| `unattested_index` | a manifest names a private index or index-like option |
| `lock_disagreement` | a lock content digest disagrees with its manifest |

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

## Pinned native libraries (Linux first)

Compiled Python sdists and npm `node-gyp` builds that need C libraries get a
single pinned `native-libs/libset/3` object. Version 3 is a fixed conda-forge
closure for Linux x86_64: pkg-config, zlib, libffi, OpenSSL, expat, libpng,
freetype, fontconfig, pixman, cairo, glib, harfbuzz, fribidi, pango, libxml2,
libiconv, and the exact runtime closure recorded in the table in
`src/nativelibs.rs`. The selected historical records are `.tar.bz2` because
those are the available forms for this coherent pin; the extractor also
supports modern `.conda` archives with `/usr/bin/zstd`.

The object is staged at its final input-addressed path. Conda's
`info/paths.json` or legacy `info/has_prefix` entries are rewritten there:
text prefixes become the object path, while every binary-string occurrence
uses a same-length null-padded replacement. Unlisted payload hardlinks are
also swept, and staging rejects any declared placeholder that survives. The
conda pkg-config wrapper is replaced with a direct real-binary launcher so
the isolated `PKG_CONFIG_PATH`/`PKG_CONFIG_LIBDIR` cannot be widened. Build
sandboxes mount the object read-only and set those variables, compiler include
and link flags, an object `rpath`, and the object `bin` directory. The native
set id includes the canonical store root and is an input of every derivation
that mounts it, including the Python and npm environment identities.

Extensions retain the object-library runpath, so `blanket run` does not need
the host's library search path. Python and npm closure envelopes record the
native object reference for liveness/GC. macOS arm64 has no v3 native pin yet;
requests fail closed with the normal unsupported-platform error and do not
touch the store or network.

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
`toolchain-component-unavailable`). Pinned Git dependencies are vendored from
verified source objects; workspace-inherited manifests currently fail closed.
Alternative registries fail closed. `cargo install` through the
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

## Toolchain lock and exact version selection

WP2 design, 2026-09-06. The lock is a small committed planning input, not a
second dependency lock. Today it wraps mostly static CPython/uv
(`src/python.rs:10-20`, `src/python.rs:108-129`), Node (`src/npm.rs:114-146`),
Rust (`src/cargo.rs:15-68`), and Go (`src/golang.rs:24-45`) tables, plus
Python's unconstrained default (`src/pyselect.rs:114-125`); it makes that
choice durable without changing any default version.

### File and schema

The file is `blanket-toolchain.toml` at the project root, next to manifests and
outside ignored `.blanket/`; workspaces use the same nearest root as their
planner. TOML is reviewable with strict unknown-field/type errors, and the
writer emits canonical key/array order so equivalent locks have identical bytes.

The schema is versioned and intentionally boring:

- root keys are `schema_version`, `blanket_version`, and `toolchain`;
- each `toolchain.<ecosystem>` has `runtime`, a `release` key naming the catalog
  bundle the row was minted from — provenance and a uniqueness check, never a
  key blanket looks up to honor the lock —
  `bundle_id`, its primary component (or BEAM pair), optional integer
  `revision`, a complete `components` list, component tables, `inputs` rows,
  and `platforms.<triple>.artifacts.<component>` rows;
- component tables have exact `version` and, when applicable, `embedded_in`;
  independent artifact rows have `provider`, `build`, stable `recipe`, `url`,
  and a verified, algorithm-qualified `digest` — `sha256:<hex>` or
  `sha512:<hex>`, the same shape `bundle_id` uses, so the row names the
  algorithm the verifier must use. `src/fetch.rs:93-102` already models that
  algorithm-qualified `Digest`, and the artifacts already verified under
  sha512 today (the .NET SDK at `src/dotnet.rs:95`, Hex and rebar3 at
  `src/elixir.rs:759-760`) keep their published digests instead of being
  re-pinned. `recipe` covers extraction, layout, and relocation;
- an embedded component has metadata and `embedded_in = "<parent>"` but no
  artifact row; `embedded_in` may chain, and the digest of the nearest
  independently fetched ancestor covers the whole chain (node-gyp sits inside
  bundled npm, which sits inside the Node artifact —
  `lib/node_modules/npm/node_modules/node-gyp/`, `src/npm.rs:166`).
  Independently fetched components get one row per platform, so npm/node-gyp
  and Go stdlib appear once; and
- `inputs` is the ecosystem's **whole consulted path list, in precedence
  order** — not just the file that won. A row always has `path` and `field`. It
  has `sha256` when the file exists, and `value` when discovery found a request
  at `field`; `absent = true` marks that it found none. The two facts are
  independent, so the three real states each have one spelling and none is a
  special case: file missing (`absent`, no `sha256`), file present without the
  field (`absent` with `sha256`), field found (`value` with `sha256`). `value`
  is the canonical parsed request; `sha256` is the digest of that source file's
  whole bytes as read through the held root descriptor, the same whole-file
  digest `status` already computes for recorded inputs (`sha256_file`,
  `src/inspect.rs:332-334`). Recording absence is what makes the list a
  complete statement about the project instead of a list of survivors: if the
  lock only recorded the winner, creating a *higher*-precedence file — no
  `.python-version`, so `requires-python` won; then someone adds
  `.python-version` — would change nothing the lock knows about, and blanket
  would keep serving the old runtime while every other tool in the repo moved.
  With absence recorded, that file appearing is a row flipping from absent to
  present, which is the same comparison as any other change.
  **Staleness is one rule for every row: re-derive the row and compare. A row
  is stale when a `value` appears where the record has `absent`, when the record
  has a `value` and re-derivation finds none, or when both have a `value` and
  they differ.
  That rule decides staleness in ordinary sync, under `--frozen`, and in
  `status` alike, and the ecosystem is stale when any of its rows is.** The
  digest is a fast path, never a verdict: a matching digest proves the file is
  untouched and lets all three skip the re-parse, while a differing digest
  forces the re-parse and nothing else, so a comment, a whitespace edit, or a
  `blanket add` that delegates a rewrite of `pyproject.toml`, `package.json`,
  or `go.mod` to uv, npm, or go leaves the lock fresh — the `field` key exists
  precisely because those sources are multi-purpose. A present file that no
  longer parses is stale: there is no `value` to compare.
  `changed_inputs` (`src/inspect.rs:337-352`) therefore cannot be reused
  verbatim — it reports "changed" on digest inequality alone, knows nothing
  about `field` or `value`, and never looks at a path that has no row — so the
  lock needs a presence- and value-aware sibling. The alternative, digesting
  only the extracted field for multi-purpose manifests, is rejected: it
  re-encodes `value`, which the row already records in readable form, and it
  buries a per-ecosystem extraction rule inside the digest definition instead
  of one `sha256_file` call for every source. Provider-native hashes are
  evidence only; Blanket's own verified artifact digest is mandatory.

Both triples appear for every fetched component even when syncing on one host;
platform-neutral components repeat their digest. A lock records provider
builds, components, recipes, and per-platform bytes — never dependency entries,
credentials, store paths, object ids, or host facts. `blanket_version` is
provenance, not staleness: `schema_version`, recipe support, source inputs, and
artifact rows decide compatibility, and trust fixes never rewrite old locks.
Because recipe ids are append-only, "recipe support" can only fail forward — a
lock written by a newer blanket naming a recipe this one has never heard of —
never backward, so a lock keeps working under every later blanket.

The catalog unit is a complete **release bundle per ecosystem**. Its unique,
opaque `release` key is not a version selector: recipe revisions of one primary
version take distinct keys and `bundle_id`s, never duplicates. A lock copies
exactly one bundle, and rows mixing two releases are rejected as an
inconsistency inside the lock itself, which is a check the lock can do alone.
Only project `inputs` sit outside the bundle.

The immutable `bundle_id` is sha256 over the bundle's canonical serialization,
defined here so two implementations agree byte for byte. The serialization is a
sequence of records; each record is a sequence of fields; each field is emitted
as `<byte length in decimal>:<UTF-8 bytes>`, so no value can be mistaken for a
delimiter and no two distinct field sequences can serialize alike. The records,
in order, are: one `("bundle", "1")` version record; one
`("component", name, version, embedded_in-or-empty)` record per component,
sorted by name; and one
`("artifact", triple, component, provider, build, recipe, url, digest)` record
per platform artifact row, sorted by triple then component. Nothing else
enters the hash — not `release`, not `revision`, not `inputs`, not the
ecosystem name. The leading version record is how the definition grows without
an exception: a schema that adds a hashed field mints serialization `"2"`, new
bundles get `"2"` ids, and every bundle already minted keeps the id its own
recorded serialization produced.

The lock's own canonical bytes are defined just as tightly, because
byte-identical locks from both platforms is a tested claim: UTF-8, LF endings,
one trailing newline, no comments, tables emitted in the schema's declared
order, keys within a table in the schema's declared order, arrays in the order
the schema states (never in discovery order), basic double-quoted strings with
no unnecessary escapes, and integers with no leading zeros or sign. A writer
that follows it and a reader that re-serializes what it read produce the same
bytes, which is what lets publication compare bytes rather than parse trees.

This Node bundle uses shipped pins: npm is embedded in the Node artifact and
node-gyp inside that bundled npm, so the Node artifact's two platform rows are
the whole independently-fetched set. Its `.node-version` holds `24.20.0\n`,
whose sha256 is that input row's digest, and its `package.json` carries no
`engines.node`, which the second row records rather than omits:

```toml
schema_version = 1
blanket_version = "0.1.0"

[toolchain.node]
runtime = "node"
release = "node-24.20.0-r1"
bundle_id = "sha256:2b37e2816f777fb287f11e8b188b92645449251a51ec217eb12ed51668093c5f"
primary = "node"
revision = 1
components = ["node", "bundled-npm", "node-gyp"]
[toolchain.node.component.node]
version = "24.20.0"
[toolchain.node.component.bundled-npm]
version = "11.19.0"
embedded_in = "node"
[toolchain.node.component.node-gyp]
version = "12.4.0"
embedded_in = "bundled-npm"
[[toolchain.node.inputs]]
path = ".node-version"
field = "version"
value = "24.20.0"
sha256 = "5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800"
[[toolchain.node.inputs]]
path = "package.json"
field = "engines.node"
absent = true
sha256 = "9f2c1a7c8b0a5f4e6d3b2718c9a04e5f1d6b83c27a4e90f5b1c8d3a672e4f0b9"
[toolchain.node.platforms."aarch64-apple-darwin".artifacts.node]
provider = "nodejs.org"
build = "24.20.0"
recipe = "nodejs/legacy"
url = "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz"
digest = "sha256:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8"
[toolchain.node.platforms."x86_64-unknown-linux-gnu".artifacts.node]
provider = "nodejs.org"
build = "24.20.0"
recipe = "nodejs/legacy"
url = "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz"
digest = "sha256:855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec"
```

Real locks include every consulted field; missing rows, bad digests, or an
unknown schema invalidate the lock without host fallback.

**The shipped catalog is not on the path that honors a lock.** A lock row
carries the component version, the retrieval URL, the algorithm-qualified
digest, and the recipe id, and those four are everything realization needs, so
honoring a committed lock reads the lock and nothing else. The catalog is
consulted in exactly two places — creating a lock where there is none, and
`blanket update --toolchain` — because those are the only moments blanket
*chooses* a version. Upgrading blanket therefore cannot invalidate a committed
lock: a new blanket ships a new catalog, the old lock names no catalog key that
must still exist, and the same bytes are fetched and verified as before. The
only failures left when honoring a lock are the honest ones — the schema
version is newer than this blanket understands, the recipe id is unknown, the
bytes are genuinely gone upstream, or what comes back does not match the
recorded digest.

Two rules make that safe without reintroducing the catalog. First, the digest
is the authority and the URL is only a hint: bytes are verified against the
recorded algorithm-qualified digest before anything is extracted or linked, so
a URL cannot substitute content. Second, retrieval is gated by a shipped
**provider host allowlist** — the hosts blanket's providers publish from — and
that list is append-only, never version-scoped, so it constrains where a lock
may send blanket without ever going stale. HTTPS-only retrieval fails
`file://`, off-allowlist hosts, and hash-mismatch rows before fetch. The
residual exposure is stated plainly in LIMITATIONS.md: a hostile committed lock
can still aim a request at some other allowlisted host, which is a request an
attacker can observe, but it cannot install bytes blanket did not verify.

Recipe ids are append-only for the same reason. `nodejs/legacy`,
`rust-toolchain/1`, `go-toolchain/1` and their successors are never removed and
never redefined; an output-affecting change mints a new id and leaves the old
one supported. A recipe id in a five-year-old lock still resolves, which is
what makes "the catalog left the reproducibility path" true rather than
half-true — otherwise the catalog would be gone but blanket's own code would
have quietly taken its place as the thing an upgrade can break.

Every lock implementation needs a reusable pre-materialization extractor in
`src/archive.rs`: list and validate every entry first (no absolute paths/`..`,
hard links, or special files; symlinks only when targets are contained), with
`TAR_OPTIONS` and `UNZIPOPT` unset for delegated tar/unzip; its PR below owns
the containment tests. Existing helpers are not this contract: `build_requires`
checks extracted links after materialization (`src/build_requires.rs:499-566`,
`src/build_requires.rs:579-619`), while `gitsrc` validates before *packing* and
its ustar helper only checks header capacity (`src/gitsrc.rs:924-981`,
`src/gitsrc.rs:1120-1132`).

The recipe is also an identity boundary. Implementations already use recipe
markers such as `rust-toolchain/1` (`src/cargo.rs:107-129`) and
`go-toolchain/1` (`src/golang.rs:59-68`), and the native set's identity version
is `native-libs/libset/3` (`src/nativelibs.rs:553-564`, version at
`src/nativelibs.rs:21`). CPython and Node identities keep their existing
artifact/platform inputs with no new schema input (`src/python.rs:131-152`,
`src/npm.rs:149-158`), so their legacy recipe mapping must preserve those ids.
Any output-affecting extraction, layout, or relocation revision gets a new
recipe identity and a new lock component row; the legacy mapping keeps existing
object ids, including the byte-identical Darwin goldens.

### Pre-planning security gate

The lock is not permission to read arbitrary project paths: each
`inputs.path` is project-relative, normalized, and free of `..`; the allowed
set comes from manifest discovery. To close TOCTOU, open the project root once
and every input descriptor-relative beneath that held descriptor with
`O_NOFOLLOW` at every component; a symlinked input or ancestor is an error.

None of that plumbing exists today: `grep -rn "openat\|O_NOFOLLOW\|renameat\|custom_flags" src/`
returns nothing, the tree is path-based `fs::*` plus `symlink_metadata`, and
the only nofollow syscall is `utimensat`'s `AT_SYMLINK_NOFOLLOW`
(`src/gitsrc.rs:1106-1110`); `libc` is already a dependency (`Cargo.toml:15`).
So this section's descriptor-relative helper — hold a root descriptor, walk
each component with `openat`/`O_NOFOLLOW`, create with `O_EXCL`, rename with
`renameat` — gets a module of its own, `src/fsroot.rs`, owned by PR 3 below
exactly as `src/archive.rs` is owned by PR 2, with the refusal tests named
there. (The WP1 `wp1/fmt-rust` branch's descriptor-anchored closure
publication is the model; it is not on main.) `fs::read`/`fs::write`/
`fs::rename` do not satisfy anything in this section.

The retained snapshot includes `blanket-toolchain.toml`: its held descriptor,
identity metadata (including inode), and bytes, alongside source descriptors.
Ordinary sync opens the lock through the held project root and keeps the
per-project writer lock shared through planning, realization, and publication,
so `update --toolchain` cannot install L1 while sync plans from L0. That lock
is an optimization, not the guarantee: immediately before publication, and
regardless of lock ownership, reopen `blanket-toolchain.toml` through the held
root descriptor with descriptor-relative `openat` and `O_NOFOLLOW` and compare
its bytes to the snapshot. A mismatch aborts with `blanket-toolchain.toml
changed during sync (update --toolchain race)`, leaving the old closure and
projection untouched.

The lock has exactly two writers — the first writable sync of a project with
no lock, and `blanket update --toolchain` — and both publish by ONE rule, with
no weaker path for the first write: create the temp file descriptor-relative
in the held project-root directory with `O_EXCL` and `O_NOFOLLOW`, write it,
`fsync` that file descriptor, rename it descriptor-relative and without
following symlinks over `blanket-toolchain.toml`, then `fsync` the held root
directory descriptor, mirroring closure publication. Both syncs carry weight
and neither is a nicety: the file `fsync` is what makes the rename publish
bytes instead of a filesystem-dependent window of zeros after a power loss,
and the directory `fsync` is what makes the rename itself durable. A `write`
that has only left the process is not on the disk.

The temp name is drawn from the operating system — 16 bytes read from
`/dev/urandom`, rendered hex, as `.blanket-toolchain.toml.<hex>.tmp`. That is
the randomness source already in the tree (`src/sbom.rs:36-41`, the CycloneDX
`urn:uuid` v4), factored into one helper rather than added a second time, and
it reads identically on Linux and macOS. Process identity is deliberately not
the source. Pid-plus-sequence — the shape download temps use
(`src/fetch.rs:360-366`) — separates concurrent writers inside one machine,
which is all `src/fetch.rs` needs, but it has fixed points: a sequence
restarts at 0 in every process, and a pid is reused after wrap and starts from
the same small numbers in every PID namespace. So
`.blanket-toolchain.toml.1.0.tmp` is the exact name the first write of a
containerized run picks, every run, on every machine; one leftover at that
name wedges every later run of that image permanently. A random name has no
fixed point to wedge, and it is one rule at every scale — a laptop, a CI
matrix, a build farm sharing a network filesystem — with no separate
collision case to reason about.

`O_EXCL` and `O_NOFOLLOW` keep their whole benefit: a symlink or any other
file at a name only this process chose still fails the create loudly instead
of being written through, in a fresh clone's very first sync as much as in an
update. A create that loses to an existing name retries on fresh randomness a
bounded number of times and then reports; it is never resolved by unlinking
what is in the way, because blanket cannot know that file is its own.

A leftover temp is inert — never read, never an input, never a lock, and never
consulted for staleness; it is garbage the user (or a `.gitignore` rule) may
delete at any time. Blanket unlinks its own temp on every exit path it
controls, success and error alike, and never scans for or deletes a temp it
did not create.

After dependency planning, on EVERY sync (including an existing-lock sync),
reopen the source inputs through the held root descriptor with `O_NOFOLLOW` and
recheck identity metadata and bytes before publishing the closure or
projection; a change aborts and leaves lock, closure, and projection untouched.

--frozen never modifies project inputs, blanket-toolchain.toml, or the catalog
cache; it may realize store objects and write the projection after validation
succeeds; validation failure exits before any write. That sentence is
byte-identical in exactly two places — here and in CLI.md's "Planned (WP2
design ...)" section. It appears in neither CLI.md's help screen nor its
command grammar, and neither gains a `(planned:)` marker, because the help
screen is the spec for the bytes `blanket --help` actually prints and the
grammar is the spec for what the parser actually accepts. A marker in either
would be a convention no other verb uses, an unimplemented flag advertised to
users, and one more thing to remember to delete the day WP2 lands. Design work
lives in the prose sections that say they are design work; the specs describe
what ships. The regression proving the boundary is
`tests/toolchain_lock.rs::frozen_validation_failure_precedes_all_writes`.
Frozen validation evaluates nothing at all: every reader below is
declarative-only, so the sandboxed probe described here is a planning-path
tool and never a validation one. `setup.py`-computed metadata and `mix.exs`
compatibility are therefore not frozen sources, exactly as the Gemfile's
`ruby` directive is not. Where the probe does run, on the ordinary planning
path, it is sandboxed: network denied, project read-only, and scratch-only
writes. The setup `BuildSpec` argv is
`["/bin/sh", "-c", "exec <build-env>/bin/python setup.py egg_info --egg-base
<scratch>/egg-info ><scratch>/egg-info.log 2>&1"]`, with the project root as
cwd and the build environment, CPython, and scratch declared as its roots
(`src/manifest.rs:162-178`). It is not `/bin/sh setup.py`.

The guarantee is therefore stated as a rule about reachability, not as a list
of functions not to call. **Treat every ecosystem's ordinary planning path as
an unsandboxed evaluator of project code, and give frozen toolchain-lock
validation no way to reach any of them.** The rule's scope is exactly the
phase it names, and what happens on either side of that phase is stated here
rather than left to inference. Validation reads its inputs, compares them to
the lock, and decides; it plans no dependencies, and a validation failure
exits before any evaluator runs at all. Once validation succeeds, `--frozen`
continues into ordinary sync, where dependency planning still delegates to
the native tools and those tools do evaluate project code: `plan_ruby`'s
Gate 1 (`src/ruby.rs:582-596`) evaluates the Gemfile on every call, lock
present or not. That is the delegated-resolver trust boundary this document
already accepts for dependencies, and the toolchain lock's whole purpose is
to stay off it — no toolchain version is ever learned from an evaluator.
That is the only form of the rule that stays true: counting today's
evaluators is the fragile version, and every count written so far has been
wrong. Round 7 named Elixir's plan gate (`src/elixir.rs:1097-1110`) as the
only one. Round 8 said two, adding Ruby — planning runs the store Ruby on a
helper that **evaluates the Gemfile** to check Gemfile/lock equivalence and
the `ruby` directive, through a `run_ruby` that is a plain `Command` with
neither sandbox nor network denial (`src/ruby.rs:311-317`,
`src/ruby.rs:333-352`, called at `src/ruby.rs:582-596`). Two was also wrong:
`plan_dotnet` shells out to `dotnet restore --use-lock-file` through
`run_dotnet` (`src/dotnet.rs:603-635`, `src/dotnet.rs:715-740`), another plain
`Command` in the project directory, and MSBuild evaluates the `.csproj` plus
any `Directory.Build.props`/`.targets` it finds, including `<Exec>` tasks
hooked to Restore. Ruby and Elixir each have a second such call site outside
the ranges already cited (`src/ruby.rs:560`, `src/elixir.rs:1089`). The count
is not the point and no count is recorded here. Because the rule is about
reachability rather than a catalogue, it also covers call sites that are not
planning at all: `blanket add` and `blanket update` run the store tool in the
project directory through `run_checked` (`src/ruby.rs:290-297`,
`src/elixir.rs:896-904`), and frozen invokes neither verb.

What frozen calls instead is named, owned, and tested like every other
guarantee in this design. `src/toolchain_input.rs`, owned by PR 3 below
exactly as `src/fsroot.rs` is, exposes one reader per ecosystem that returns
the toolchain request from declarative sources only — the `path`/`field` pairs
the precedence table lists — and nothing in it calls a planner. Its unit tests
assert per ecosystem that the reader spawns no process at all, which is a
property a test can check directly and a call graph cannot quietly drift past.
A Gemfile is a Ruby program — `ruby "3.3.4"` sits beside arbitrary code that
runs to produce it — so Ruby's reader takes `.ruby-version` and the Ruby entry
in `.tool-versions`, and frozen refuses rather than evaluate a Gemfile to
learn a version. That treatment is uniform rather than a Ruby special case:
Python's reader takes `.python-version` and a `requires-python` declared in
`pyproject.toml`, and Elixir's takes the OTP and Elixir entries in
`.tool-versions`. A project whose only statement of its version is computed —
`setup.py` metadata, `mix.exs`, a Gemfile directive — fails frozen closed with
a message naming the declarative file to add. No reader has an evaluating
fallback, so there is no per-ecosystem exception to remember and the
`path`/`field` rows every input requires are always real files and real
fields. The end-to-end regression is a frozen run against a project
whose Gemfile writes a marker file when evaluated: validation completes and
the marker does not exist.

### Lifecycle and concurrency

On the first writable `blanket sync` with no lock, selection runs against the
shipped catalog, stderr names the selected runtimes and the created
`blanket-toolchain.toml`, and the file is published by the shared publication
rule above — descriptor-relative `O_EXCL`/`O_NOFOLLOW` temp in the held project
root, flushed, then renamed without following symlinks; the committed file
remains for review.

The lock gate runs before dependency planning. Missing or stale under
`--frozen`, strict policy, or a read-only project is an error naming `blanket
update --toolchain [<ecosystem>]`, and ordinary sync also refuses stale locks.
Permissive mode cannot change a runtime silently: that is a correctness error,
not a hidden exception; other gaps still record one (`src/policy.rs:187-204`).

Writers take the per-project lock exclusively around read/compare/rename.
Byte-identical candidates keep the first file and let the second sync succeed
as a cache hit; different candidates leave the existing file, discard the
loser, and fail naming both selections, inputs, and `blanket update
--toolchain`. Ordinary sync creates a lock when there is none but never
rewrites one; only `blanket update --toolchain` replaces an existing lock.
That rule is per file, and the per-ecosystem case follows from it: a lock with
no section for an ecosystem newly present in the project — `[toolchain.python]`
committed, then a `package.json` appears — is stale, not absent, so ordinary
sync refuses and names `blanket update --toolchain`, which adds the section.

`blanket update --toolchain` updates every ecosystem present in the project —
present as source discovery finds it, not as the lock's existing sections list
it, which is how a newly added ecosystem gains one — or only the named one; it
is separate from dependency update and cannot take package names. It
re-reads sources, chooses the globally selected newest compatible stable/LTS
release described below, verifies every platform row, writes one lock
atomically, then runs ordinary sync; it never updates a dependency lock.
`--frozen` instead validates the committed lock with no catalog fallback and no
resolver-generated dependency-lock write, exiting before realization on a
missing, stale, or unresolvable input.

### Selection sources and precedence

Source discovery is explicit rather than an abstract "read the ecosystem" step.

It is also **anchored at the project root, not at the current directory.** The
root is the one blanket already resolves — the nearest manifest/workspace root
walking up from cwd — and it is where `blanket-toolchain.toml` sits once there
is one, so the anchor is defined identically before the first lock exists and
after, with no separate rule for the creating sync. The table below describes
where each ecosystem's own tools look, which is cwd-relative for most of them;
blanket's toolchain discovery starts at that root instead, so the consulted
path list is a property of the project and every developer, every CI job, and
every subdirectory produces the same list, the same lock, and the same
staleness verdict. A cwd-relative walk would make `blanket status` answer differently
depending on which directory the person was standing in, which is not a
property a committed lock can have. The cost is real and recorded in
LIMITATIONS.md: a toolchain source file in a subdirectory — `web/.node-version`
under a root-level lock — is not a toolchain source for blanket, though uv or
`nvm` would honor it. One toolchain per lock root is the rule; per-subproject
toolchains would need per-subproject sections and are not in this design.


| ecosystem | native tools walk from | walk boundary | source precedence (blanket reads these from the lock root) | compatibility intersection and conflict |
|---|---|---|---|---|
| Python | cwd | parents through the uv project/workspace root; [uv documents this walk](https://docs.astral.sh/uv/reference/cli/) | `.python-version`, then a `requires-python` declared in `pyproject.toml`, including Poetry's `tool.poetry.dependencies.python`; `setup.py`-computed metadata is deliberately not a source, because reading it means running a build hook | use the supported request grammar below; intersect with metadata; current code parses at `src/pyselect.rs:309-362` but reads one supplied directory at `src/pyselect.rs:368-404` |
| Node | cwd | nearest package/workspace root | exact `.node-version`, then `engines.node` | intersect exact/range; empty intersection or conflicting same-level declarations is a hard error; current code only has platform rows (`src/npm.rs:114-146`) |
| Cargo | cwd | Cargo workspace root | nearest `rust-toolchain`, then `rust-toolchain.toml`, then shipped default | channel, targets, and supported components must intersect the catalog; an unsupported or conflicting request is a hard error; current nearest-file walk is `src/cargo.rs:246-264` |
| Go | module/project root | no workspace expansion; an ancestor `go.work` is refused | `go` is the minimum; non-`default` `toolchain goX.Y.Z` is exact; absent or `toolchain default` means newest compatible once | exact toolchain must be a catalog release and satisfy the minimum; otherwise fail closed; platform filtering is `go_pins` (`src/golang.rs:72-83`) and directive parsing is `src/golang.rs:243-269` |
| Ruby | cwd | parents through the project root | exact `.ruby-version`, then a Ruby entry in `.tool-versions`; the Gemfile's `ruby` directive is deliberately not a source, because reading it means evaluating a Ruby program | intersect exact declarations; disagreement is a hard error; current code has only platform rows (`src/ruby.rs:47-67`) |
| Elixir | cwd | parents through the Mix workspace root | exact `.tool-versions` OTP/Elixir; `mix.exs` compatibility is deliberately not a source, because reading it means evaluating an Elixir program | intersect OTP/Elixir requirements and OTP-qualified Hex/rebar rows; empty intersection is a hard error; current plan checks `mix.exs`/`mix.lock` at `src/elixir.rs:1075-1110` and pins OTP at `src/elixir.rs:26-31` |
| .NET | project directory | inspect ancestors only to reject inherited SDK inputs | exact project `global.json` with `rollForward = "disable"` | no roll-forward or second source; a mismatch is a hard error; current ancestor rejection and exact gate are `src/dotnet.rs:542-593` |

Python requests use a supported subset of uv's grammar: exact `X.Y.Z`, minor
`X.Y` (newest compatible catalog release once, then locked), or a PEP 440-style
specifier set restricted to `>=`, `<`, `==`, `~=`, and `!=`, comma-joined
(newest satisfying release once, then locked). An explicit CPython prefix is a
supported spelling of the same request, not a second implementation:
`python3.12`, `cpython-3.12`, `cpython@3.12` and their `Python`/`CPython`
casings are stripped today (`src/pyselect.rs:334-341`), and the unit test
`python_version_formats_and_unsupported_interpreters` asserts they parse
(`src/pyselect.rs:718-753`); the lock keeps them and records the canonical
`X.Y[.Z]` in `value`. The refusals stay exactly where they are today
(`src/pyselect.rs:321-333`): non-CPython implementations (`pypy`, miniconda),
variants (`-dev`, a trailing `t`, free-threaded) and `system` fail as
`unsupported Python interpreter request`, while paths, executables, and other
free-form text that is neither a version nor a supported specifier fail as
`invalid .python-version request`. Either message's next step is to put an
`X.Y`, `X.Y.Z`, or supported specifier in `.python-version`, then run
`blanket update --toolchain`.

The lock then supplies the exact artifact. A matching source request is stable;
a changed source stops sync with both values and `blanket update --toolchain`.
An exact request with no matching catalog row is a hard error in every
ecosystem, a range is selected once at lock creation or explicit update and
never reselected on sync, and dependency lockfiles stay delegated to native
tools. Every sentence in this section describes choosing a version, which
happens only at lock creation and `blanket update --toolchain`; a sync that
honors an existing lock runs none of it and reads no catalog. The exact-selection fixes are already open as two PRs — CPython
(`src/pyselect.rs:170-188`, `src/python.rs:87-93`) in #21
`wp2/python-exact-selection`, and Go (`src/golang.rs:140-157`) in #22
`wp2/go-selected-version` — which together are ordered item 0 below.
For Go this intentionally changes today's resolver, which treats non-default
`toolchain` as a lower bound and picks the lowest satisfying pin
(`src/golang.rs:243-269`): the Go-selection PR must fail closed when exact
`toolchain goX.Y.Z` is absent, while `default`/absent selects newest once.
Regression: with a newer row present, `go 1.22` plus exact `toolchain
go1.24.2` still locks 1.24.2, never 1.25.

Current selectors filter candidates by the passed platform: Python while
collecting pins (`src/pyselect.rs:129-136`), Go in `go_pins`
(`src/golang.rs:72-83`), npm by taking the platform's Node row
(`src/npm.rs:767-770`). The lock selector is different: with `C_p` the complete
releases for platform `p`, it selects only from the intersection of `C_p` over
every `p` in `Platform::ALL` (`src/platform.rs:83-86`) — complete meaning each
required component has one valid row per platform, embedded ones via a parent.

Each ecosystem declares a primary component — `node`, `cpython`, `go`; BEAM
uses the `(otp, elixir)` pair compared lexicographically, OTP first and Elixir
second. Exact/range matching and ordering use that primary version, never
`release`. The global order is primary version descending, highest explicit
`revision` (otherwise newest catalog order), then the provider/build/recipe
tuple, canonical artifact tuple, and `bundle_id`; `release` keys are unique and
duplicates are catalog errors. Channel is deliberately not an ordering key:
two bundles that tie on primary version are the same upstream release and so
the same channel, so an LTS-before-stable tie-break could never fire. Channel
is an admission property instead — only stable/LTS builds enter the catalog,
and a range takes the newest admitted release.
Exact requests filter by primary version and ranges take the first satisfying
candidate, so recipe revisions of one upstream version coexist. The selector
never uses the host: an asymmetric catalog (Darwin-only A, Linux-only B,
complete C) chooses C and produces byte-identical locks from both platform
values, and tests compare those bytes, not only the selected version.

### Carrying the runtime through every operation

The closure records one selected toolchain object reference per ecosystem,
alongside the lock digest and source-input rows. Python records environment,
version, and inputs (`src/project.rs:612-637`); the other closures record
direct refs and plans (`src/cargo.rs:1121-1129`, `src/golang.rs:907-915`,
`src/ruby.rs:852-860`, `src/elixir.rs:1428-1439`, `src/dotnet.rs:995-1003`).
Node records environment/version/projection and inputs
(`src/npm.rs:2418-2443`); add direct runtime refs and normalize all seven.

`blanket run` resolves every runtime through that closure id using
`project::closure_object` (`src/project.rs:197-234`). Today Node calls the
global platform pin after sync (`src/main.rs:1404-1412`) while Cargo/Go use
closure ids (`src/main.rs:1416-1433`); later refreshes must not alter a run.

The cached `x` key becomes `x/3`: store root, ecosystem, package request,
platform, primary runtime version, selected `bundle_id`, and runtime object id.
The store root stays in the key exactly as `x/2` hashes it today
(`src/xrun.rs:326-334`), because every other input is store-independent —
`cpython_identity`/`node_identity` take no store root (`src/python.rs:131-152`,
`src/npm.rs:149-158`), unlike the env identities (`src/project.rs:279-282`,
`src/npm.rs:1241-1244`). Dropping it would make `BLANKET_STORE=/a blanket x
ruff` and `BLANKET_STORE=/b blanket x ruff` share one `~/.blanket/x/`
directory, and the second store would fail in `check_cached_projection` with
`cached environment object is missing or outside the active store; run the
command again` (`src/xrun.rs:269-273`) — a permanent failure that re-running
cannot clear, where today the key differs and the miss is clean. Because
`bundle_id` covers every component and artifact row, a changed uv, recipe, or
any other bundle component yields a fresh x environment even when the runtime
object's id is unchanged. Current `x/2` omits runtime identity
(`src/xrun.rs:325-340`), and Node x also calls global `ensure_node_for`
(`src/xrun.rs:375`, `src/xrun.rs:456-505`). New `x/3` dirs never reuse `x/2`;
old ones remain GC roots until collected. Project `x` reads the lock and
outside-project `x` uses shipped selection; both key on the store root, bundle,
and runtime ids.

The lock digest, bundle id, runtime id, and dependency plan are written before
projection; unchanged rows resolve the old object, while any bundle-component
change through `update --toolchain` creates a new lock and forces a fresh
native plan and closure. `status` compares the committed lock digest and then
re-derives every input row from the lock root — including the rows recorded
`absent`, which is how it notices a newly added higher-precedence file — using
the recorded `sha256` to skip re-parsing files whose bytes are untouched, and
compares presence and `value` by the one staleness rule above, so a digest
mismatch alone never reports stale, before reporting `toolchain lock
stale/missing` (`src/inspect.rs:336-373`, `src/inspect.rs:480-572`). Without
that re-parse `status` would exit 1 after every `blanket add` that rewrites a
multi-purpose manifest, breaking its documented CI gate; without re-deriving
the absent rows it would exit 0 while blanket and the rest of the repo
disagreed about the runtime.

### Identity, migration, and GC

Writing the lock does not write or mutate a store object. Rows map to the
existing identity mapping for the selected recipe and verified artifact
hashes; a recipe change creates a new identity input rather than changing an
old object's semantics. The existing Darwin identity tests, including the
CPython goldens (`src/python.rs:271-295`) and Rust golden
(`src/cargo.rs:1293-1301`), remain byte-identical.

Legacy seeding is an evidence conversion, not a reconstruction: it validates
every closure object id/path through the active store, then reads identity
metadata; recorded paths never authorize a read. Old closures prove only:

| ecosystem | recoverable from verified closure/object | incomplete fields that refuse seeding |
|---|---|---|
| Python | CPython version and artifact/platform from the env identity; the plan and, when present, input records | the current closure has no separate uv reference, so a complete companion row needs an unambiguous shipped mapping |
| Node | Node version and artifact/platform from the env identity; bundled npm/node-gyp are inside that artifact | embedded component metadata or source inputs absent from the old closure |
| Rust | rust object, vendor object, lock digest, and `CargoPlan`'s `rust_version`, crates, and members (`src/cargo.rs:402-406`, `src/cargo.rs:1121-1129`) | channel, requested components, and targets are not recorded; never claim those fields can be recovered |
| Go | Go object, module-cache object, `go_version` in the plan, and go.sum digest (`src/golang.rs:907-915`) | the consulted go.mod directives and their old snapshot are absent |
| Ruby | Ruby/gems objects, versions, and gem plan (`src/ruby.rs:852-860`) | an old `.ruby-version` or compatibility input not recorded in the closure |
| Elixir | BEAM object and the plan's OTP, Elixir, Hex, and rebar metadata (`src/elixir.rs:1428-1439`) | mix.exs compatibility evidence and any missing source snapshot |
| .NET | SDK object and SDK version in the plan (`src/dotnet.rs:995-1003`) | global.json evidence or other compatibility fields not recorded |

Seeding succeeds only if every required lock field, including its source
snapshot and both platform rows, is proved by that evidence or by a unique
shipped-table mapping. Otherwise the mapping is unrecoverable and sync refuses
with `blanket update --toolchain`; it never guesses from the current default,
and a same-platform closure is not foreign-platform evidence. With an existing
lock, realize the current platform from its row.

If a recorded input now differs, the old closure is not a migration authority:
keep the old lock and closure, report both values, and require `blanket update
--toolchain` to snapshot the changed source and write a new lock. Legacy
closures with no snapshot for a consulted field take the same refusal. This
preserves rollback and stops changed source pairing with old dependencies.
Closure object refs keep toolchains alive through the existing root/GC walk;
the lock itself is not a GC root.

### Interaction with WP3

The lock needs provider build, component recipe, URL, and a verified,
algorithm-qualified digest for both triples. Sync downloads only the current
row and never rewrites the other.
Until WP3, the compiled rows in the ecosystem modules are the shipped catalog
(`src/python.rs:22-85`, `src/npm.rs:122-135`, `src/cargo.rs:25-68`,
`src/golang.rs:32-45`); `src/platform.rs:83-86` is only the supported-platform
enumeration, so locks are writable offline. WP3 must retain the rows existing
locks need, and an unrelated refresh cannot alter an Identity or a lock.

### Acceptance and ordered implementation

Acceptance is: different catalog snapshots replay the same lock in two stores,
including a snapshot that no longer contains the lock's `release` key at all,
which is the upgrade case and must succeed rather than report stale; a no-pin
project writes it on writable sync and refuses under `--frozen`; exact
selection, asymmetric-catalog, byte-identical BEAM, Linux-to-Mac, and
`file://`/off-allowlist-host/hash/link rejection fixtures all pass; a source
file appearing at a path recorded `absent` reports stale, and one appearing at
a path with no row at all is impossible because every consulted path has a row;
frozen validation against a project whose Gemfile writes a marker when
evaluated completes with no marker, and every `src/toolchain_input.rs` reader spawns no
process; and the project-side `src/fsroot.rs` refusals all
fail closed — a symlinked `blanket-toolchain.toml`, a symlinked input file, a
symlinked ancestor directory of either, and an occupied temp name. ACTIVATION
stays dormant until selection sources and runtime propagation land: the feature
is off, and the lock is neither written nor required.

0. **Exact selection fixes (open now as two PRs, not one)** — #21 `wp2/python-exact-selection` (`src/pyselect.rs`, `src/python.rs`) and #22 `wp2/go-selected-version` (`src/golang.rs`), each with its own unit tests: exact patches, duplicate rows, selected-Go realization, unchanged defaults, Darwin goldens.
1. **Shipped-table adapter and source selection** — pin modules, `src/platform.rs`, selector tests: complete bundles, matrix intersections, carrying the existing verified digests (including the sha512s .NET/Hex/rebar already use) into catalog rows, and legacy seeding (evidence-based success plus the refusal when evidence is missing). No lock-byte or replay tests before the format exists.
2. **Secure archive extractor (own PR, before activation)** — `src/archive.rs` and unit tests for absolute paths, `..`, hard links, special files, symlink escape, and an outside sentinel under GNU tar and (asymmetric until the Mac gate) bsdtar.
3. **Lock core, dormant** — parser/writer plus `src/cli.rs`, `src/main.rs`, and project input handling: canonical bytes as defined above, the consulted-path input list with its absent rows, and the concurrent writer/reader lock. This PR also owns `src/toolchain_input.rs`, the per-ecosystem declarative readers, with a unit test per ecosystem asserting the reader spawns no process. It also owns `src/fsroot.rs`, the descriptor-relative root helper (`openat`/`O_NOFOLLOW` walk, `O_EXCL` create on an `/dev/urandom` name, file `fsync`, `renameat`, directory `fsync`), and moves `src/sbom.rs`'s `/dev/urandom` read into the shared helper it calls rather than adding a second randomness path. Unit tests refuse a symlinked `blanket-toolchain.toml`, a symlinked input file, a symlinked ancestor directory, and an occupied temp name; `fs::read`/`fs::write`/`fs::rename` do not pass them. Activation stays off; stale/frozen/replay/exit-status tests wait for it.
4. **Runtime propagation** — `src/main.rs`, `src/xrun.rs`, `src/inspect.rs`, `src/project.rs`, and closure writers: closure-selected runtimes, refresh isolation, old-`x/2` non-reuse; this permits activation.
5. **Activation and update** — `src/cli.rs`, `src/main.rs`, lock core, integration tests: update, two-store replay including the dropped-`release` upgrade replay, no-pin creation, stale/frozen refusal (with `frozen_validation_failure_precedes_all_writes` and the Gemfile-marker regression), added-higher-precedence-source staleness, unchanged dependency locks, foreign-platform refusal, exact statuses, Linux/Mac diff.

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
  network). Blanket inspects the archive's `pyproject.toml` before any
  build code runs. Legacy/setuptools-compatible requirements retain the
  `sdist-build/2` derivation; other PEP 517 requirements are resolved into
  one immutable Python build environment and use `sdist-build/3`, whose
  inputs include that environment. Rust sdists additionally include the
  pinned Rust and Cargo-vendor objects; a generated `Cargo.lock` is recorded
  as unattested. The sandbox remains cooperative hermeticity (mach-lookup
  and process-exec are broad), and host C/C++ SDK versions are not in the
  identity.
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

Command surface (`cli.rs` is pure; everything it decides is unit-testable):

    src/cli.rs      command grammar + help (pure, unit-tested; see CLI.md)
    src/main.rs     dispatcher + per-ecosystem orchestration
    src/ui.rs       output conventions: quiet/verbose/color, error channel
    src/inspect.rs  status / ls / doctor: read-only views over closures + store
    src/deps.rs     add / remove / update, delegated to each ecosystem's tool
    src/xrun.rs     blanket x: run a registry tool without adding it to a project

Kernel — identity, the store, and how anything becomes an object:

    src/types.rs    Identity, Plan, LockedPackage
    src/store.rs    immutable store: stage/commit/cache
    src/fetch.rs    verified downloads
    src/gitsrc.rs   git sources realized by commit (NEXT.md item 4)
    src/project.rs  env realization + projection
    src/policy.rs   permissive/strict exception policy
    src/gc.rs       store garbage collection
    src/sbom.rs     CycloneDX 1.5 JSON from the closure envelopes
    src/platform.rs the only module that knows the host
    src/sandbox.rs  hermetic build sandbox (Seatbelt / bubblewrap)
    src/build.rs    sandboxed sdist-to-wheel builds
    src/build_requires.rs  static inspection of PEP 517 build requirements
    src/nativelibs.rs      pinned, relocatable native libraries for Linux builds
    src/artifacts.rs       install-time artifact policy (NEXT.md item 5)

Python:

    src/pypi.rs     Python planner (adapter)
    src/wheel.rs    PEP 427 wheel installer
    src/python.rs   pinned CPython provisioning
    src/pyselect.rs CPython constraint parsing and selection
    src/pep440.rs   dependency-free PEP 440 parser and specifier evaluator
    src/manifest.rs Python manifest discovery and normalization

Ecosystem tailors — each imports a lockfile and plans a closure:

    src/npm.rs             npm planner, projection, lifecycle scripts
    src/npm_lock_import.rs pnpm and Yarn classic lockfile importers
    src/cargo.rs           Cargo.lock importer + registry vendor realization
    src/golang.rs          module closure via the pinned Go toolchain
    src/ruby.rs            Bundler-delegated planning, blanket-verified gems
    src/elixir.rs          Mix/Hex, AST-validated lockfile
    src/dotnet.rs          NuGet packages.lock.json (blanket-mandatory)

    tests/acceptance.sh   end-to-end checklist against real PyPI

## Roadmap

M3 (done): sandboxed sdist builds.
M4 (done): npm tailor — lockfile importer, pinned Node, forest projection.
M4.5 (done): real-project compatibility — hermetic lifecycle scripts,
    declared artifacts, workspaces (link entries), uv/npm resolution
    delegation, mutable-package projections, store concurrency locks.
    Known remaining npm gaps: install scripts that need network for logic
    (not just artifacts) — those retain the package with
    `install-script-failed`; strict policy refuses them. (Nested
    per-workspace node_modules landed with item 7, and git `resolved` URLs
    with item 4.)
M5: hardening pass — RECORD verification/rewrite, Mach-service allowlist in
    the sandbox, macOS deployment-target tag comparison, reproducibility
    checks (rebuild + compare), garbage collection (`blanket gc` — forests
    and backups included), per-package store objects, binary cache +
    /opt/blanket/store decision, signed toolchain manifests.
See PLAN.md for direction and the ordered work packages.

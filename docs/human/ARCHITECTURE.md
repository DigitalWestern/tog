# Tog architecture

Tog is a universal realization and environment kernel with
ecosystem-native planners. One binary that (eventually) replaces per-language
package managers by owning the outer loop every ecosystem shares: fetch a
toolchain, lock a dependency graph, materialize it into an immutable store,
project an environment, run tasks.

Seven ecosystems are built. Python and JavaScript/npm are proven on real
projects: Next.js 15 + vitest suites, vite apps (build and dev server),
prisma, native addons compiled hermetically (better-sqlite3, sharp), FastAPI
apps with native wheels. Cargo, Go, Ruby, Elixir, and .NET all landed
2026-08-31 as wrap-hermetically tailors. Tailor cost, measured
2026-10-06 by one rule (every `.rs` file under `src/tailors/<name>/`, less
blank lines, comment lines including doc comments, and `#[cfg(test)]`
modules): Node ~11.7k, Python ~10.0k, Elixir ~2.7k, Go ~2.2k, Ruby ~2.0k,
.NET ~1.9k, Cargo ~1.8k. The first estimates
(~500-1000 lines each) were about 10x low for the two proven tailors:
real projects needed lock importers, native builds and sandboxed scripts. pnpm v9/v6 and Yarn classic lockfile importers shipped
2026-09-06 (`src/tailors/node/lock_import/`). Current version: tog 0.1.0.

## The model

Stolen from Nix, minus the interface.

- **Store** (`~/.tog/store`, `TOG_STORE` overrides): input-addressed
  immutable objects at `objects/<hash16>-<name>-<version>/`. An object's id
  is a hash of its `Identity`: kind, name, version, and every input that
  determines the output (artifact sha256s, dependency object ids). Objects
  are committed atomically (staged dir + rename) and made read-only.
  Changing what goes into an object means adding an identity input; an
  existing object's meaning is never reinterpreted in place.
- **Artifact cache** (`cache/sha256/<hash>`): every downloaded file, stored
  by verified content hash. Never refetched; enables offline reconstruction.
- **Store records** (`records/<kind>/<sha256 of key>.json`): small facts tog
  checked itself and would otherwise ask the network again, such as the
  digest rubygems.org serves for a gem coordinate or the inputs of the last
  passing `mix deps.get --check-locked` in a project. They are store data,
  never project data: a repository cannot ship one, so a record can stand in
  for a network answer where a project-owned cache would be forgeable.
- **Comforters (environments are store objects too)**: a `python-env` object
  is a venv-shaped immutable tree. Identity = CPython object + sorted set of
  package artifact hashes. Identical locks share one object; conflicting
  locks coexist as different objects.
- **Projection**: a project's `.venv` is one symlink into the store, swapped
  atomically. Rollback = swapping back (instant cache hit). Provenance lives
  in `.tog/closures/<ecosystem>.json`, one file per ecosystem, and that file
  is committed: `tog audit` reads it.
- **Node projection is a forest** (`node-forest/2`): the root `node_modules`
  is a symlink into `<TOG_STORE>/forests/<project-key>/<projection-id>/`,
  each workspace importer gets its own symlink, and the immutable env holds
  the same layout. The forest is a writable per-project directory that
  absorbs scratch writes (vite's `.vite` cache, prisma's `.prisma` client)
  while package contents stay read-only in the store. Forests live outside
  the project so test runners never crawl store packages' own test files.
  Declared-mutable packages (`"tog": {"mutablePackages": [...]}`) switch
  to a whole-tree copy-on-write clone, recorded `unattested` in the closure.
  So does a registry package that depends on a workspace package (a plugin
  whose peer is the package the repository develops): Node resolves a
  package's dependencies from the package's real path, a store object can
  hold no link into a project, so only a copy inside the projection can
  reach the project's own source. pnpm and npm locks say which packages
  those are; a `yarn.lock` records no peer dependencies, so for Yarn the
  realized packages' own manifests are read. The closure lists the packages
  as `workspace_dependents`, each with an `unattested-mutable-state`
  exception.

Per design review: **Plan → Realize → Project**. The tailor (adapter) turns
manifests and lockfiles into a typed `Plan`. The kernel realizes it: verify
downloads into the cache, provision pinned toolchains, commit objects
atomically. Projection writes the symlink and the closure JSON. Plans are
cached in `.tog/plan.json` (`.tog/go-plan.json` for Go) keyed by input hash,
so unchanged locks never touch the network again. The plan cache is
machine-local and is not committed; the closure JSON is.

A sync opens the project once as a `kernel::fsroot::ProjectRoot`, a held
directory descriptor, and hands it to every `Tailor` method it calls
(`detect`, `check_inputs`, `preflight`, `prepare`, `plan`, `sync`). Every
project read and write goes through it, never through the project's path, so
a project renamed or replaced mid-sync cannot substitute another project's
files. Manifests and dependency locks the user authors are read with
`read_input`, which resolves from the descriptor but follows a symlink the
project contains. tog's own state is walked one component at a time with
`O_NOFOLLOW`, so a `.tog`, `.venv` parent or `cargo-home` swapped for a
symlink is refused rather than followed: closures (read for the exception
summary and root registration, and written),
`.tog/policy.toml`, the plan and setup.py caches, the Python manifest
snapshots and lock stamp, `.tog/cargo-home` (`tog-config.toml` and the 0755
`cargo` shim), the `.venv` and `node_modules` links (`replace_symlink`,
which publishes a new link with an exclusive rename so a real entry that
appears meanwhile is refused, not replaced), and a real `.venv` or
`node_modules` moved into a store backup (`move_dir_out`). Tree walks (the
Go source digest) open each subdirectory with the same no-follow rule
(`subdir`). The toolchain guard keeps a duplicate of the descriptor. The
GC root is recorded under the canonical path the project was opened at,
used as it is and never resolved again: the per-project lock is keyed on
it, root registration imports the project's existing closures through the
descriptor and refuses a symlinked `.tog`, and `check_still_named` walks
that recorded path from `/` with `O_NOFOLLOW` and compares it with the held
directory before each tailor, before a root is registered, and again after
the closure is renamed into place. What still goes by path: the ecosystem
tools the tailors run start in the project by path, files above the project
are read by path, and commands that do not sync open the project by path.
Those windows are in `docs/human/LIMITATIONS.md`.

## Vocabulary

The bedding theme (a tog is a duvet's warmth rating), used in docs and
conversation; code keeps boring identifiers, and the CLI never prints any of
these words. The words it does print — store, realize, project, closure,
exception, permissive — are defined in the README:

| word | meaning | in code |
|---|---|---|
| **tailor** | a per-ecosystem adapter that cuts a package graph to fit | `src/tailors/<ecosystem>/` |
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
`io::ErrorKind::Unsupported` and a message naming the platform, before
touching the store or the network.

Rules the Linux port settled, which apply to any future platform:

- **A new platform is rows, not a port.** Pins are per-platform rows in the
  existing tables; helpers take an explicit `Platform` rather than asking
  the host. Adding `aarch64-unknown-linux-gnu` means new rows and a wheel-tag
  band.
- **Pin hashes come from the provider's published checksums** at pin time
  and are pasted as constants (trust on first use). Never pin a sha256
  computed only from our own download.
- **One sandbox contract, two engines.** Tailors describe a build; the
  sandbox runs it under Seatbelt on macOS and bubblewrap on Linux with the
  same deny-by-default rules (no network, declared reads and writes,
  scrubbed environment, `SOURCE_DATE_EPOCH`). A path that would need a
  sandbox the platform lacks fails loudly; it never runs unsandboxed.
  On Linux a declared root an open `ProjectRoot` holds is bound from the
  held descriptor (bubblewrap binds `/proc/self/fd/<n>`), and the system
  shell closes those descriptors before the build runs, since a host
  directory's descriptor leads out through `..` (#497).
- **The host C toolchain is an unpinned build input** on both platforms
  (Xcode clang on macOS, `/usr` gcc on Linux). Pinning it is a backlog item.
  A build spec also names its host view: `Full` binds the host's whole `/usr`,
  so a build can link any library the host has; `RuntimeOnly` (Linux only;
  Seatbelt treats it as `Full`) keeps the host's runtime files and the C
  runtime's development files and leaves every other header, `-l` library,
  static archive and pkg-config file out of the compiler's and linker's
  default search paths and out of pkg-config. Other shared libraries the
  host's tools load move to a `.tog-host-runtime` subdirectory that `ld`
  never searches, named there by the sandbox's own loader cache
  (`kernel/ldcache.rs`: the host's `/etc/ld.so.cache`, rewritten), which
  the loader searches after a program's own RUNPATH. Library subdirectories
  holding development files are curated the same way. Each curated host
  directory is bound once at `/.tog-host-files`, and the files the view
  keeps are symlinks into it, so setting the view up costs a few hundred
  mounts rather than one per library file. Ruby gems with native
  extensions, Python sdists that compile Rust or native code, and npm
  install scripts build under `RuntimeOnly` first, so an object committed
  under the `runtime-only/2` view does not depend on which `-dev` packages
  the building host has installed. The retry against the whole host, its
  `host-build-inputs` record and the `host-fallback/1` identity are shared
  (`kernel/hostfallback.rs`).
- **Darwin identity goldens stay byte-identical.** A platform change that
  alters a macOS object id is a bug.
- **Archive extensions must agree.** GNU tar always prefers the PAX record
  when a member carries both a GNU long name and a PAX `path`; macOS bsdtar
  prefers whichever block came last, so the two read the same bytes as two
  different names. The reader refuses conflicting paths or link targets
  before extraction on either platform, including conflicts that a
  names-only listing cannot reveal.

## The tailors

**Python** (`tailors/python/`: `pypi.rs`, `manifest/`, `unpack/wheel.rs`, `mod.rs`,
`pyselect.rs`, `env.rs`). Resolution of ranged requirements is delegated to the
store-pinned uv (`uv pip compile --generate-hashes`); hash-pinned
requirements and `pyproject.toml` dependencies are locked directly, choosing
the best wheel per platform (native arm64 > abi3 > universal2 > pure >
sdist). CPython comes from astral-sh/python-build-standalone with sha256s
pinned in `kernel/provider/cpython.rs`; interpreter selection happens before locking
(`.python-version` wins, then `requires-python`). Wheels install into the
env object; sdists build in a network-denied sandbox (legacy setuptools
records keep `sdist-build/2`, PEP 517 uses `sdist-build/4` with an immutable
build environment. Rust builds use `sdist-build/5`, adding a versioned Rust
flag configuration. Plain builds keep their existing identities, and old
Rust `/4` records remain readable). Environments are immutable: no activate scripts, pip
cannot mutate them.

**npm** (`tailors/node/`: `plan.rs`, `realize.rs`, `project.rs`, `lock_import/`). `package-lock.json` is parsed
locally; a pnpm v9/v6 or Yarn classic lockfile is imported by
`lock_import/` (dependency-free strict YAML for pnpm, `lock_source`
recorded); with none of these, the store node's bundled npm runs
`npm install --package-lock-only`. Before planning, `plan` and `sync`
refuse a lock that disagrees with the package.json files it was generated
from, as `npm ci` and `--frozen-lockfile` installs do: npm's per-manifest
dependency maps (the root's and each workspace member's), pnpm's importer
specifiers, and Yarn classic's `name@spec` selectors (with no entry left
that nothing depends on; a `link:` dependency, which Yarn classic never
locks, is linked to its directory inside the project). A pnpm `file:`
dependency on a directory that is not an importer (in a v9 lock, and in a
v6 lock, where the entry is keyed `file:<dir>` with its name beside it) is
a copy, as pnpm installs it: the directory is packed into a tarball the
same way every time (leaving out `node_modules` and `.git`, skipping FIFOs
and sockets, following a symlink that stays inside the project and
refusing one that leaves it, a loop, or a tree past a size limit), its
digest is the package's integrity, and the environment extracts it like a
registry tarball, with a `node_modules` of its own. In the SBOM it has no
registry purl, since nothing on the registry is being named: a `tog:local`
property carries its directory. `tog status` packs the directory again, so
an edit to it is a change (`src/tailors/node/local_package.rs`). Every other
`file:`/`link:` dependency is a symlink into the user's source, so nothing
is ever placed beneath one: a target that is itself an importer gets its
dependencies from its own projected `node_modules` (as pnpm installs it),
and any other linked package gets them in the nearest enclosing importer's
`node_modules`, where Node looks from the package's real path. Every
importer's and linked package's dependencies are then checked against that
lookup chain, and a layout where one would shadow another, or a link that
would sit inside a registry package, is refused. pnpm `patchedDependencies` follow
pnpm's precedence (exact version, then the one npm semver range the version
satisfies, then a bare name or `name@*` that covers every version, two of
those settled by the snapshot's recorded hash, and refused when that hash
covers different bytes), and any snapshot whose recorded `patch_hash`
disagrees with the selected patch is refused. Keys are read as written:
whitespace around a key, its name or its version is refused. Ranges
are read by `kernel/semver.rs`, node-semver's grammar and `satisfies`,
checked case by case against node-semver itself
(`kernel/semver_cases.tsv`). Lifecycle scripts run hermetically (below).
Native addons compile against the pinned Node. Existing locks win over
ranged manifests, so a bare machine needs nothing installed besides tog.

**cargo** (`tailors/cargo/`). Rust has no installed-environment analog, so the
comforter is everything cargo needs to build fully offline: a pinned
toolchain object (rustc + cargo + rust-std, TOFU-pinned sha256s) plus a
`cargo-vendor` object of every registry crate, hash-verified, with tog
generated `.cargo-checksum.json`. Vendor identity is the sorted crate
checksums plus their count (`cargo-vendor/2`), so locks with the same crate
set share one object.
Enforcement is a cargo wrapper under `.tog/cargo-home/bin/` that execs
the store cargo with `--frozen`; user-supplied `--config` is rejected and
`RUSTC` is forced. `tog build` sandboxes the compile with a disposable
`CARGO_HOME` (a build script must never be able to rewrite the wrapper that
later runs unsandboxed). Honest gap: `tog run cargo build` is
offline-configured but not sandboxed; use `tog build`. `tog fmt`
realizes a separate pinned `rustfmt` object linked against the Rust object.
It writes no closure: the release row pins the rustfmt archive by sha256, so
the formatter that runs is the pinned one by construction, and a record of
it would prove nothing the lock does not. Nothing roots the object, so gc
can reclaim it between runs. A `.tog/closures/rustfmt.json` an older tog
wrote is a retired name (`store::RETIRED_CLOSURES`): every closure reader
but gc's live-set walk skips it, and a `tog fmt` without `--check` deletes it
once another closure sits beside it (a root over an empty closures
directory stops every sweep, and forgetting it needs the exclusive lease),
or once gc has forgotten the project's root. gc forgets a root whose only
closures are retired records when it protects nothing they do not name.

Every cargo run that resolves (`tog add`/`remove`/`update`, a missing
`Cargo.lock`, `tog attest`, and the `Cargo.lock` of a Python sdist's Rust
extension) goes through the resolution door, confined, at the workspace
root (`kernel/provider/cargo_door.rs`). cargo reaches the network only
through the proxy session, with TLS interception: the proxy terminates
cargo's tunnels with a leaf from tog's per-process certificate authority,
serves crates.io through the `crates_index` route (each index line's
`cksum` is a claim the `.crate` download is verified against), forwards
git fetches through the git row, and forwards any other host as
`unattested-index`. The lock records crates.io as
`registry+https://github.com/rust-lang/crates.io-index` whatever the
transport, so a lock written through interception is byte-identical to a
direct run. Cargo's resolution outputs are the root `Cargo.toml` and
`Cargo.lock` plus every member manifest `[workspace] members` names; its
inputs are `.cargo/config.toml` and `.cargo/config` at the root.

Every Node run that resolves (`tog add`/`remove`/`update` with npm or the
pinned pnpm, a missing `package-lock.json`, `tog x`'s npm resolution, and
`tog attest`) goes through the same door, confined, at the lock root (the
project, or the pnpm workspace root), with the tool run in the member the
edit was made in (`tailors/node/door.rs`). Both tools are pointed at the
session on the command line, where their flags beat `.npmrc`; the proxy
serves `registry.npmjs.org` through the `npm` route (`tailors/node/
registry.rs`: each packument's `integrity` is a claim its tarball is
verified against, a sha1-only `shasum` is `weak-integrity`), git
dependencies through the git row, and a scoped registry or a direct-URL
tarball as `unattested-index`. The lock records the registry's own URLs,
so it is byte-identical to a direct run. Node's resolution outputs are
`package.json`, the locks, and every workspace member's `package.json`
from every place a member can be named; its inputs are `.npmrc`,
`pnpm-workspace.yaml`, `.pnpmfile.cjs`, and each member's `.npmrc`
(`tailors/node/resolve.rs`). The pinned pnpm runs as `node <script>` from
the store environment object its `tog x` cache root links into.

Every uv run (`tog add`/`remove`/`update`, a missing
`requirements.lock.txt`, an sdist's build requirements, `tog x`, and
`tog attest`) goes through the same door, confined, at the lock root (the
project, or the uv workspace root that lists it as a member, with uv run
in the member) (`tailors/python/door.rs`). The proxy serves `pypi.org/simple`
and `files.pythonhosted.org` through the `pypi` route
(`tailors/python/registry.rs`: each index page's file hashes are claims
its downloads are verified against, a sha1 hash is `weak-integrity`), git
dependencies through the git row (GitHub's `raw.githubusercontent.com`
metadata read at a commit is a git fetch too), and any other index or a
direct URL as `unattested-index`. The default index is forced to PyPI on
every invocation, so a project's `[[tool.uv.index]]` default never
replaces it. Every run starts with `--no-build` (the probe): no
third-party code runs in it. When uv refuses because something must be
built or its metadata prepared, `resolution-build` permission is required
before any backend runs, including the project's own. The permission also
covers dynamic and transitive build requirements. A denial stops the
operation. An allowed rerun records the exception in its receipt. uv's cache is private to each attempt. An allowed retry starts with an
empty cache, so its receipt records every contributing fetch and exception. A compiled lock is headed by `tog` in
place of uv's command line (`--custom-compile-command`), so the same
resolution writes the same bytes on every machine. Python's resolution
outputs are `pyproject.toml`, `uv.lock`, `requirements.in`,
`requirements.txt`, `requirements.lock.txt`, and every uv workspace
member's `pyproject.toml`; its inputs are `setup.cfg`, `setup.py`, and
every file a requirements file includes inside the project
(`tailors/python/resolve.rs`).

`targets`, `components` and `profile` in `rust-toolchain(.toml)` are lock
rows (`toolchain.targets`, `toolchain.components`, `toolchain.profile`):
lists sorted and deduplicated, each written only when present, so a lock
for a project without them is unchanged. A file that does not parse is an
error and a stale lock, never the "absent" row. A table with no channel
(only components, targets or a profile) means rustup's default toolchain,
which for tog is the catalog's explicit default: the lock records that
release and provisions the listed components onto it. Sync provisions what
the rows ask for from the official channel manifest
`channel-rust-<version>.toml`, pinned by sha256 as the release's
`channel-manifest` row in `provider/rust.catalog.toml` and kept in the
store's content-addressed cache under that sha256, so a release seen once
plans offline (`provider/rust_channel.rs` reads it, following its
`renames`). `tools/catalog.py cargo` writes that row after verifying the
manifest's signature with `gpgv` against the Rust release key in
`tools/keys/`; tog checks the sha256 only. A named component or target the
manifest does not publish for the host, or marks `available = false`, is a
hard error naming it. A profile expands the way rustup expands it: through
the host's own list, the aggregate `rust` package's `components` and
`extensions` for that host. A profile member off that list (`rust-mingw`
off Windows) is not part of this host's toolchain and is left out. A member
on it that the release did not build is a hard error, and every such member
is named at once (1.96.1's `complete` names `miri-preview` and
`rustc-codegen-cranelift-preview`). Each extension is its own `rust-component/1` object
(one archive, keyed by its sha256), and the toolchain a build sees is an
assembled `rust` object (`rust-toolchain/2`): a copy of the base object
with the components merged in, keyed by the base id, the manifest digest,
and every component object id (`provider/rust_extras.rs`). It must be one
real tree because rustc and clippy-driver find their sysroot from their own
canonical path. Its files are hard links to the base and component objects'
files (a copy, reflinked where the filesystem can, only when a link
cannot be made), and store removal never changes a file's mode, so a
shared inode stays read-only. The base `rust` object (`rust-toolchain/1`) keeps its id, and a
project asking for nothing beyond it uses it directly. GC reaches the base,
the components and the manifest through the assembled object's
dependencies. The profile never enters an identity: it is expanded first,
so `profile = "default"` and its components by name are one object.
rustfmt as a component is the bundle's own `rustfmt` row, the
same archive `tog fmt` realizes, and every bundle row is checked against the
manifest, so there is one pin.

`[toolchain] path` names a toolchain directory on this machine, which
rustup runs as it is (`provider/rust_path.rs`). The lock records it in
place of a catalog release: a row marked `source = "path"` whose URL is
the tree's `file://` path, whose build is the first lines of its
`bin/rustc -vV` and `bin/cargo -V`, and whose digest is a sha256 over the
tree's names, bytes, executable bits and (contained) symlink targets. The
reader comes from the tailor (`Tailor::external_toolchain`), because only
it knows what a path means; the command layer hands it to resolution on
`EcosystemInput::external`, so `comforter` never looks a tailor up, and the
lock writer and reader stay generic and check that the marker and the
`file://` URL go together. The tree is walked through descriptors: every
directory and file is opened with O_NOFOLLOW relative to its held parent
and checked against the entry the walk saw, a file's bytes are hashed (and,
on import, copied) from that one descriptor, and every symlink is resolved
component by component against the tree on disk, through any links it
passes, and refused if it would leave. A first pass checks the links
before any file is read. Every realization re-probes and re-hashes the
tree and refuses one that is no longer the locked tree, naming
`tog update --toolchain rust`; the per-file sums are cached in the store
(`cache/rust-path-tree/`, keyed by the tree's path) under each file's
device, inode, size and modification and change times, so an unchanged
file is not read again, and a mismatch is confirmed by a full read before
it refuses. The digest a lock is written from is always a full read, never
the cache, and a copy whose hash disagrees with the lock re-reads the tree
and rewrites the cache before it reports, so a stale cached sum cannot
survive into the next run. The tree is then imported as a `rust` object (`rust-path/1`: a
copy whose hash, taken of the bytes as written, must be the locked one,
keyed by the tree hash and build, with no store dependencies), so builds,
closures and GC treat it like any other toolchain. Each use records the
`external-toolchain` exception (a toolchain from no pinned release),
which a policy can deny; the company template does. rustup refuses a path
beside a channel, components, targets or a profile, and so does the lock's
reader. `tog fmt` runs the tree's own `rustfmt`, so the import is also the
formatter object.

**go** (`tailors/go/`, `kernel/dirhash.rs`). go.sum is an authentication ledger, not
a lock graph, so the closure is computed by the store Go toolchain itself
(`go mod tidy -diff`, then `go mod download -json all`), and tog
re-verifies every artifact (dirhash h1, byte-for-byte reproduced, plus raw
sha256) before bytes enter the cache. The comforter is a `go-modcache`
object. Enforcement is pure environment: `GOTOOLCHAIN=local` (the `auto`
default silently swaps toolchains), `GOROOT`, `GOENV=off`, `GOPROXY=off`.
`tog build` runs `go build -mod=readonly` with the project read-only.
cgo uses host clang, the standing accepted impurity.

**ruby** (`tailors/ruby/`). Bundler-shaped: lock parsing and platform selection
are delegated to the pinned portable Ruby's own Bundler/RubyGems via a
helper script, because `Gem::Platform` matching has wildcards and
specificity scores no hand parser should reimplement. Gem hashes come from
the lock's CHECKSUMS or rubygems.org, always platform-qualified (the bare
endpoint returns the latest-pushed variant). A rubygems.org digest is
recorded in the store by (name, version, platform) once the downloaded
`.gem` hashes to it and its gemspec names that coordinate, so an unchanged
lock without CHECKSUMS re-syncs offline; a CHECKSUMS digest is the repo's
claim and is never recorded. Gems install dependency-first
inside the network-denied sandbox into one immutable GEM_HOME object;
binstubs are wrapper scripts, never symlinks (symlinks dangle after the
store-commit rename; this bit once). On Linux each gem whose gemspec
declares native extensions installs against the host C runtime alone
(`HostView::RuntimeOnly`, recorded in the gem object's identity as
`build_view`; pure-Ruby gems compile nothing and install against the full
view). Those builds also get tog's pinned native library set
(`kernel/provider/nativelibs.rs`, the one Python sdists and npm addons
use) through pkg-config, gcc's `CPATH`/`LIBRARY_PATH` and mkmf's
`--with-cppflags`/`--with-ldflags`, which carry its rpath into the
extension (`ruby/native_libs.rs`, #329). The gems identity says whether
it did (`native`, and the set's id as `native_libs`); whether a gem is
native is read from its gemspec once and kept as a store record keyed by
its sha256, so a warm sync names the set without downloading anything. A
gem whose native extension needs a library outside the set
is rebuilt against the whole host after recording
`host-build-inputs`, which the object carries so a cache hit replays it.
Before that retry the failed attempt's own gem and extension directories
are removed from the shared GEM_HOME, and any other change it made refuses
the retry (`ruby/gem_home.rs`). Such an object is committed under its own
identity (`build_view = "host-fallback/1"`, `host_fallback` = the gems that
fell back, `host_inputs` = `hostview::host_build_inputs`, a stat-based
fingerprint of what the full view shows beyond the C-runtime-only one,
what its symlinks resolve to, and the compiler, taken before and after each
fallback build and required to match), never under the runtime-only id,
and a store record keyed by the runtime-only id and that fingerprint lets
a later sync over the same store on a host in the same state reuse it
(`ruby/native.rs`).
Every tog invocation strips
`BUNDLE_*`/`RUBYOPT` and forces `BUNDLE_FROZEN`, `GEM_HOME`/`GEM_PATH`.
Every Bundler run (a missing lock, an edit, the planner's helper checks,
`tog attest`) is confined through the resolution door (`ruby/door.rs`),
reaching rubygems.org only through the session's RubyGems mirror
(`ruby/registry.rs`); the helper's checks get no route at all.
v0 gaps: non-rubygems.org sources, PATH/GIT gems.

**elixir** (`tailors/elixir/`). mix.lock is an Elixir term literal that Mix itself
evaluates as code, so tog parses it under the pinned toolchain with a
strict AST grammar: exact 8-field `{:hex, ...}` tuples of literals only;
calls, variables, and legacy tuple shapes are rejected loudly. Hex tarballs
are dual-checksum verified (outer tar sha256, inner content sha256). The
`beam` object is four pinned artifacts: OTP, the Elixir release zip, plus
OTP-qualified Hex and rebar3 builds (the legacy `hex.ez` hangs on OTP 29;
found live). Deps are source trees, realized as a `hex-deps` object and
projected as a writable clonefile copy so native builds can write into their
own sources. `tog build` sandboxes `mix compile`. The consistency gate,
`mix deps.get --check-locked`, needs the Hex registry, so it runs only when
its inputs (every `mix.exs`, mix.lock, the BEAM object, the project path)
hash differently from its last pass in this project, which tog records in
the store; an unchanged project re-syncs offline. Every mix run (the gate,
a missing lock, `deps.update`, `tog attest`) is confined through the
resolution door (`elixir/door.rs`), reaching repo.hex.pm only through the
session's Hex mirror (`elixir/registry.rs`); the lock parser gets no route.

**dotnet** (`tailors/dotnet/`). NuGet's `packages.lock.json` is opt-in upstream;
tog makes it mandatory. The lock's `contentHash` is a semantic hash, so
tog never raw-compares: it fetches nupkgs into a local folder feed, then
the pinned NuGet installs from that feed in locked mode, verifying every
contentHash. The SDK is the extractor and part of the object identity. Builds
are the strictest boundary: `tog run` refuses build-capable verbs
(MSBuild executes arbitrary code and belongs only in the sandbox), and every
`tog build` runs a fresh offline locked restore into scratch. `global.json`
must be an exact pin with `rollForward = "disable"`. A missing lock and
`tog attest` run restore confined through the resolution door
(`dotnet/door.rs`), with a `nuget.config` whose one source is the
session's NuGet mirror (`dotnet/registry.rs`).

## Resolution doors

A resolution door is where tog runs an ecosystem's own tool to choose
versions or check a lock: the one kind of child that may use the network
and evaluate project code (a Gemfile, a `build.rs`, a csproj). Every one
starts through `ResolutionDoor::run_confined` (`src/kernel/resolve/`):
isolated on a snapshot of the project, its network fenced to tog's
recording proxy, its declared outputs published all or nothing with a
signed resolution record. There is no unsandboxed mode. Isolation is
bubblewrap, or rootless podman where bubblewrap cannot make a user
namespace (`resolve/container.rs`), and a host with neither refuses the
door naming what is missing (`tog doctor --isolation`). Host-local
helpers that only read what tog staged (an offline `go mod`, a Gem spec
read) go through `kernel::supervise`'s `local_*` functions, whose tripwire
refuses a resolver outside its reviewed offline forms.

The census, by door kind:

| ecosystem | edit (`add`/`remove`/`update`) | missing lock | planner (in a sync) | `attest` |
|---|---|---|---|---|
| Go | confined | confined | confined | confined |
| Cargo | confined | confined, and an sdist's `Cargo.lock` (detached) | none | confined |
| Node (npm, pnpm) | confined | confined | none | confined (a `yarn.lock` is refused) |
| Python (uv) | confined | confined | confined | confined |
| Ruby (Bundler) | confined | confined | confined | confined |
| Elixir (mix) | `update` confined, `add`/`remove` refused | confined | confined | confined |
| .NET | refused | confined | none (reads the lock) | confined |

`tog x` resolves a registry tool into `~/.tog/x` through a door of its
own kind, confined the same way.

`tog build` and installation builds run project code in the build sandbox,
which denies network access and records no resolution ledger. `tog run`
uses the projected runtime and dependencies but executes on the host,
without a sandbox or network restriction. Run untrusted tests only in a
separate disposable job that holds no signing key or other secrets.

## Toolchain lock

Every ecosystem has a pinned toolchain table with exact selection rules;
the tables and the selectors realization uses live in the per-ecosystem
modules, with the platform enumeration in `src/kernel/platform.rs`. A
committed `tog-toolchain.toml` at the project root records the exact
toolchain per ecosystem: the release it was minted from, the components and
their versions, and one artifact row per supported platform with a verified
algorithm-qualified digest. Selection reads a catalog; honoring a lock does
not, so the same file replays in any store and the `release` key may name a
bundle the catalog no longer has. `tests/toolchain_lock.rs`
(`two_fresh_stores_realize_the_same_runtimes_from_a_retired_release`,
network-gated) syncs a Python and npm lock whose releases no catalog has
into two fresh stores and checks equal runtime objects, lock bytes and
`tog status`. The two-machine half (a lock written on Linux synced unchanged
on an arm64 Mac, and the Mac writing the same bytes) ran by hand on
2026-09-25.

`src/comforter/toolchain.rs` is the activation surface. `resolve` answers,
with no writes at all, which toolchain the project uses and where the answer
came from, before the store is opened: a refusal under `--frozen`, strict
policy, or a stale lock therefore leaves no trace. `commit` is the only
writer — it takes the toolchain-input flock, re-reads the file under it,
publishes a pending lock through the descriptor-anchored rule in
`src/kernel/fsroot.rs`, and installs the process-global guard every closure
writer rechecks before publication. The modes are the grammar: ordinary sync
creates a lock when there is none and never rewrites one, `--frozen`
validates and never creates, `plan`/`build`/`fmt` honor a lock and fall back
to the shipped selection, and `tog update --toolchain [<ecosystem>]` is the
one writer allowed to replace a lock.

Staleness is one rule everywhere — re-derive each consulted row and compare
presence and value, never the file digest alone — so ordinary sync,
`--frozen` and `tog status` reach the same verdict. `status` reports a
missing or stale lock, a missing section, and a closure built from another
bundle as `changed` naming `tog-toolchain.toml`, and a verdict that sync
would refuse is answered ahead of the tailor's own comparison. `tog audit`
reuses the same combination (`inspect::locked_closure_state`), so each of
those verdicts makes the record `stale` and fails the gate.

A tailor whose builds run on another ecosystem's toolchain names it as a
helper (`Tailor::helpers`): Node's node-gyp runs on `python`, Python's
sdists compile with `rust`. `tailors::helper_selections` decides each one
the same way for `sync`, `status` and `tog x`: the project's own selection
when the project has that ecosystem, the tailor's `default_helper`
otherwise (the shipped 3.12 for node-gyp; none for Rust, where each sdist's
toolchain file picks). What an sdist with no channel of its own falls back
to is pinned in the Python lock section instead (`Tailor::helper_pins`,
written as `[toolchain.python.helpers] rust = "<version>"` when the section
is written, the catalog's default at that moment), so a newer tog with a
newer default does not change a locked project's wheel ids. A section from
before the pin keeps the Rust those builds used (1.96.1,
`LEGACY_SDIST_RUST` in `tailors/python/build.rs`). A section may pin only
the helpers its tailor declares (`Tailor::helpers`); any other name is
refused on read, naming `tog update --toolchain <ecosystem>`. The section's
`bundle_id` covers its pins (`Bundle::section_id`: the bundle's canonical
bytes followed by one `helper` record per pin), so an edited pin is refused
like an edited row and a closure built under other pins is `changed`; a
section with no pins keeps the bundle's own id, so every lock from before
pins reads byte for byte as it did. A closure records the decision as
`toolchain.helpers.<ecosystem>`, the bundle id or `null`, and `status` holds
a synced closure to it: re-locking the helper ecosystem, or removing its
manifest so the default applies, is `changed` naming "the <helper>
toolchain <ecosystem> builds with". A closure written before the record
existed counts as `null`, which is what it was built on.

Cached `tog x` environments key on `x/3`: store root, ecosystem, package
request, platform, the primary runtime version, the selected `bundle_id`
and the realized runtime object, so a changed bundle component gives a
fresh environment. A registry tool
that builds with helpers (npm's node-gyp Python, a `py:` tool's Rust for
sdists with a Rust extension) keys on `x/4` instead: the `x/3` fields plus
`<helper>=<build identity>` for each, decided as above for the project `x`
runs in and written to the request record's `helpers`. Python's Rust helper
identity includes both its base runtime object id and its full selection
fingerprint, covering channel manifests and extension components. Python has
no default Rust, so a `py:` tool outside a project that locks Rust has no helper,
keeps its `x/3` name, and its sdists build on what their own toolchain
file picks; inside one they build on the locked Rust. The key only names the
directory. A run reuses it only when the request record it wrote there
(`.tog/x.json`) says `ready`, so a directory left without one, as a tog
before `x/4` left them, is realized again in place. Only the bare
`tog x --clean` removes it, since nothing records what it was made for,
and it does so under the store its closure's objects live in, so that
store's root record goes with it. One whose store cannot be recovered is
skipped. The pnpm cache a dependency edit uses follows the same rule.

The catalog a lock is minted from
(`src/kernel/toolchain/`). Each ecosystem's catalog is a checked-in,
generated data file: `src/tailors/<eco>/catalog.toml`, and
`src/kernel/provider/cpython.catalog.toml` for CPython and uv, and
`src/kernel/provider/rust.catalog.toml` for Rust (providers rather than
tailor files, because the Python tailor builds with both). The binary embeds each file and
`toolchain/document.rs` parses it once into release bundles: components,
and per platform one artifact row with the provider, build, append-only
recipe id, URL and algorithm-qualified digest (`sha256:…` or `sha512:…`,
exactly the digest realization verifies; .NET, Hex and rebar3 keep their
sha512). The rows carry the same bytes realization fetches; they mint no
new object identity. A document also names its `default`, the release a
project with no pin gets, so what is available and what is the default
are separate facts: adding a newer release never moves the default. The
files are written only by `python3 tools/catalog.py [eco ...]`, which reads
each upstream's release listing (go.dev's JSON, Node's signed
`SHASUMS256.txt`, python-build-standalone's `SHA256SUMS`, portable-ruby,
erlef and `tog-toolchains` OTP builds with Hex and rebar3 from
`builds.hex.pm`, .NET release metadata, and every stable Rust release from
1.70.0 in static.rust-lang.org's channel manifests, each signature checked
with `gpgv` before its rows are read), verifies every row against a
second published checksum where one exists, and reports each release it
skips because a supported platform has no build. It is append-only: rows
already shipped are re-verified against the choices they record and must be
identical, an upstream re-publish becomes a new release with a higher
`revision` beside the old one, and the default moves only with
`--set-default <release>`. `--check` rewrites nothing and
fails if the file would change. A unit test holds each file to the
generator's canonical spelling, and `tests/catalog_upstream.rs`
(`--ignored`) re-checks the default, newest and oldest release of each
against upstream. The kernel
names no tailor: it validates the bundles it is handed (unique
release keys and bundle ids, resolvable embedding chains, one row per
platform and component) and selects from the releases complete on every
supported platform, so an asymmetric catalog chooses the same bundle from
either platform. Order is primary version descending (BEAM compares the
`(otp, elixir)` pair, OTP first), highest explicit revision, then the
provider/build/recipe tuple, the artifact tuple and the bundle id; exact
requests filter by primary version and ranges take the first satisfying
candidate, except that a catalog's default wins whenever the request
admits it (so `>=22` and a bare `24` keep the shipped `node-24.20.0`,
while `22` takes the newest 22 release). A `||` range (`engines.node`, Poetry's `python`) lowers to one
`AnyOf` request whose alternatives each AND their terms, so it too takes the
first candidate any alternative admits; a `*` alternative in either
reader, and an empty or `x` alternative in `engines.node`, drops the
constraint. `engines.node` is parsed by the same `kernel/semver.rs` the
pnpm patch keys use, then lowered with the toolchain's own refusals on
top (no prerelease or build, no `>*` or `<*`). It reads node semver's partials throughout: a bare
or `=` partial is its whole line (`24` is `>=24,<25`, only three
components are exact), a zero-bearing X-range keeps every stated
component (`24.0.x` is `>=24.0,<24.1`), and `>`, `<=`, `^`, `~` and
hyphen ranges bound the stated line (`<=22` is `<23`, `1.2 - 2.3` is
`>=1.2,<2.4`). The Node catalog holds every release of the LTS lines
Node's release schedule lists as active, so an exact `.node-version` on
one of them selects it. `SourcePolicy` is the typed endpoint policy every toolchain
download checks (shipped `https://` defaults per publisher, credential references only,
never a secret, and not part of lock validity; the defaults are data the
kernel owns, so a new tailor's publisher is added there). A toolchain row's
URL must fall under one of its `provider`'s endpoints before the cache is
consulted, and a network fetch follows redirects itself, at most ten and
`https://` only, authorizing each `Location` before requesting it; a row or
hop off the policy fails with the URL and publisher named. No credential is
sent yet; the policy for them is decided (#72) and builds under #404 and #405. Package-registry downloads do not pass through it. A
closure written before the lock existed records no `toolchain`, so it
plays no part in selection: the next sync selects from the catalog as it
would for a new project, writes the lock, and re-realizes the closure,
which `tog status` reports as needing a sync until then.

## Permissive by default, strict as a switch

Sync records recoverable verification gaps in each closure and continues;
`.tog/policy.toml` denies named kinds (`install-script-failed`,
`git-dependency`, ...). User and project policies are unioned; deny entries
are only added. `TOG_STRICT=1` or `tog --strict` denies every
exception. Each operation loads the chain and holds it as a
`policy::PolicyScope` while it runs. A nested sync loads its own settings.
Scopes belong to their creating thread and cannot be moved or shared with
other threads. Dropping a scope restores the enclosing scope on that thread,
and a read outside every scope on that thread sees the default policy plus
the requested strictness. Workers receive an explicit policy snapshot.
An early read never pins the policy for a later operation. Object-affecting exceptions are written into store metadata and
rechecked on cache hits, so `--fresh` cannot bypass one. `tog audit`
(`src/commands/audit.rs`) is the CI admission gate: it re-judges the exceptions the
closures already record against the policy chain plus an optional
`--policy` file (merged, so it can only tighten), refuses to pass a stale or
outdated closure, and touches neither the store nor the network.

Closure records are signed. With `TOG_SIGNING_KEY` set, `sync`
and the other closure writers load an Ed25519 key once at preflight, held for that
operation only (`comforter::SigningScope`), and the one closure writer
(`comforter::write_closure_inner`) signs every envelope it publishes over the
canonical bytes of the whole record (`src/kernel/signing.rs`: the parsed
value minus its top-level `signature`, serialized compact with keys in byte
order). Trust is the machine policy's `[signing] trusted` list; project and
`--policy` files can only intersect with it (`policy::merge`), so a working
tree can never vouch for itself. Under a policy with a `[signing]` table,
`audit` verifies each file's signature over the complete envelope it read
before believing any field: `bad-signature`, `untrusted`, and unsigned
`outdated` records are not evaluated further. Without one it judges every
record on its contents and reports signatures as not checked (`--signed`
refuses to run that way, and so does a plain audit under CI unless
`--allow-unsigned` is passed); a signature that fails to verify is
`bad-signature` either way. A detected ecosystem with no primary closure is
`missing`. Store identity is
untouched: the signature lives in the envelope, not in any object's inputs.
`tog keygen` creates keys; the developer loop (`run`, `ls`, `status`, ...)
accepts unsigned records.

Each realization carries a `policy::Attribution` token from the command layer
through its tailor to the comforter writer. The process-global frame stack keeps
records in the innermost realization, only the thread that opened a frame may
record into it, nested delegates own child frames, and a writer claims its
matching frame before publication and marks it published only after the
closure write completes. A realization that changed something must finish with
a published closure; a sync that found nothing to realize finishes without
one; operations that intentionally write no closure (dependency edits, cache
hits) discard their token. A frame that was claimed but never published
cannot finish at all: if a write fails after the claim, the claimed exceptions
leave with the dropped attribution frame and the error surfaces.

## Hermetic install scripts and native libraries

npm lifecycle scripts (and npm's implicit `node-gyp rebuild`) run at realize
time in a network-denied sandbox: writes confined to the package directory
plus a scratch HOME, node-gyp shimmed from the store node, gyp's Python a
store CPython: the one the project's `tog-toolchain.toml` names when the
project also locks Python, the shipped 3.12 otherwise. Its object id is the
`gyp_python` input of `node-env/5`, so a different interpreter is a different
environment. Likewise a Python sdist with a Rust extension compiles with the
project's locked Rust when the lock has a `rust` section, and with the shipped
Rust its toolchain file resolves to otherwise (the Python section's pinned Rust
when the file names no channel); `sdist-build/5` commits
to that Rust object id through its `rust` input and to the Rust flag policy
through `rust_build_config`. Both helpers come from
`kernel/provider/`. This is a cooperative network-denial build sandbox, not
hostile-code containment. Packages that download binaries at install time
get them via declared artifacts: the project pins `url` + `sha256`, tog
prefetches through the verified cache and plants the file where the package's
downloader looks. Electron's release zip is provisioned by tog itself, and
because the env identity names that zip, a failed provisioning fails the
sync rather than publishing an env without it. Linux builds needing C libraries get one pinned
`native-libs/libset/3` object, a fixed conda-forge closure (zlib, OpenSSL,
freetype, cairo, ...) with prefixes relocated at staging; the set id is an
input of every derivation that mounts it. macOS arm64 has no native pin yet
and fails closed.

## Store format

A store says which format it is in: `<store>/format` holds one line,
`tog-store 1` (`src/kernel/store/format.rs`). This tog reads format 1 and
nothing else. There is no migration code: a store it cannot read is
refused, and the fix is to empty it.

- No directory, or an empty one: a new store is created, marker first.
- The marker says `tog-store 1`: the store opens.
- Store directories but no marker: a store written before the marker
  existed, or one a reset did not finish. Refused.
- A higher number: a newer tog wrote it. Refused, and the fix is to update
  this tog.
- Anything else in the marker, or a marker that cannot be read (its mode,
  an I/O error): refused.

The marker is read twice. `Store::open` reads it when a command starts, and
every activity lease (`Store::activity`, `Store::try_activity_exclusive`)
reads it again once the lease is held, before the operation reads any
record. The second read is the one that counts: a command can open the
store, wait for its lease behind a `tog gc --reset`, and get the lease on a
store that has changed underneath it. Only a reset removes a marker, and a
reset needs the exclusive lease, so a marker read under a lease stays true
for as long as the lease is held. A `Store` made without the check
(`Store::handle`, for a store an x environment's own records name) is
validated the same way at its lease; `tests/architecture.rs` lists the
functions allowed to make one.

Creating a store and emptying one both hold an exclusive `flock` on the
store root directory. `Store::open` holds it while it reads the marker and
creates what is missing, so two togs creating one store take turns, and
neither creates namespaces inside a store a reset is emptying. A tog that
finds the root held prints one line saying what it is waiting for, then
waits. The store therefore has to be on a filesystem where a directory can
be locked with `flock`, which local Linux and macOS filesystems allow.
Where it cannot, opening or resetting the store fails before anything is
deleted, and the error says to point `TOG_STORE` at a local disk. Not
before anything is written: an open may already have created the root
directory, and a reset may already have created its lock files and `tmp/`.
There is no fallback lock.

The one reader that takes no lock is `tog store path`, which only prints
the path and reads the marker to say whether the store is refused. It reads
the marker a second time before it calls namespaces without a marker an old
store, because a store being created publishes the marker before its first
namespace. During a reset it can report the store as having no marker. That
is true at that moment, and it stops when the reset finishes. `tog doctor`
is not such a reader: it opens the store (waiting for the root lock like
any other command, and saying so) and then takes a shared lease without
waiting. So behind a sweep or a sync it reports the store as in use, as a
warning, and still runs every check that needs no store. Behind a reset
that holds the root lock it waits until the reset is done.

A refusal is an error whose message says why and whose fix is a separate
`tog:     fix:` line (a `"fix"` key under `--json`): `tog gc --reset`, or
`tog update --self` for a store a newer tog wrote. Moving the directory
aside works too. A reset empties whichever store the command selects, so
the fix acts on the store that was refused when it is pasted into the
environment the refused command ran in (the same `HOME` and `TOG_STORE`,
and no store symlink moved in between). The bare command is
printed only when it selects that store from any directory: `TOG_STORE` is
unset or absolute, and names it. Otherwise the line reads
`TOG_STORE=<that store> tog gc --reset` with the absolute path. That
covers `tog x --clean`, which meets other stores, and a relative
`TOG_STORE`, which `tog -C <dir>` resolves from `<dir>` and the shell
that pastes the fix resolves from wherever it is. The path is spelled
exactly for a POSIX shell: bare, in single quotes, or, for a path that is
not UTF-8 or holds control characters, as `"$(printf '...')"` with its
bytes in octal. `tog gc --reset` (`src/kernel/gc/reset.rs`) locates the
root without reading the marker, takes the exclusive lease, and then:

1. unlinks the marker and fsyncs the root directory, so the removal is on
   disk before anything else is deleted;
2. removes `objects/`, `meta/`, `roots/`, `records/`, `resolve/`,
   `forests/`, `root-locks/` and staging;
3. recreates the namespaces and fsyncs them;
4. publishes the new marker: written to a temporary file, fsynced, renamed
   into place, and the root directory fsynced.

A reset can be interrupted at any point, by a killed process or a power
failure. What the next command finds:

| Interrupted | The store afterwards |
|---|---|
| Before the marker is unlinked | Unchanged: accepted or refused as before. |
| After the unlink, before the root fsync (step 1) | A killed process leaves no marker. A power failure may bring the old marker back, and nothing has been deleted yet, so the store is whole. |
| During steps 2 and 3, or while the new marker's temporary file is written | No marker, durably. Refused, and running the reset again finishes the job. |
| After the rename, before the last fsync (step 4) | A killed process leaves the new marker. A power failure leaves either no marker or the new one. |
| After the last fsync | The new marker, durably. |

So an interrupted reset leaves one of two things: a store with no marker,
which is refused until the reset is run again, or a store with the current
marker over a reset that had already finished its work. Both are safe,
because the old marker's removal is on disk before anything is deleted and
the fresh namespaces are on disk before the new marker is published. What
it never leaves is a marked store holding half of its old records. It keeps `cache/` (downloads are
stored under their own digest and are checked again on every use, so no
store format reads them wrong), `backups/` (the user's own moved-aside
directories) and `run-homes/`. The next `tog` in a project finds its objects
gone and syncs again, mostly from the kept cache.

On a refused store, every command that would read or write the store stops
with that error. Three still work: `tog store path` prints the path with a
warning and the fix, `tog doctor` reports the store row as `fail` with the
fix, and `tog gc --reset` empties it. `tog doctor` opens and leases the
store once and hands the pair to its checks, so the store rows are either
all read under that lease or replaced by one row: failing for a store it
could not open, a warning for one that is in use. Commands that never open a store
(`--help`, `version`) are unaffected. `tog x --clean` is the one command
that meets stores other than the configured one: an environment whose own
store is refused is skipped and reported, and nothing in that store changes.

## GC root safety

The store's `roots/<sha1>` registry records every project whose closure can
protect store objects. New `root/2` records contain the complete object set
and typed projection references, so GC never opens the project's diagnostic
path: a moved, unmounted, or deleted project keeps its tools protected.
A pathname-only record, the form before `root/2`, holds a project path and
nothing else, so it names no objects: GC reports it unusable and the whole
sweep stops before any deletion, dry run included, until `tog gc --register`
records the project again or `tog gc --forget` drops it.
`tog store roots` prints each key beside its path. `tog gc --forget
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
digests, and the `evidence` marker `"explicit"`.
Explicit evidence names what the realization actually read, which can be
less than its identity names: a node env's identity carries every declared
artifact and provisioned download the plan could use, but only the ones an
install script was given are cache dependencies, because a commit refuses to
claim a cache entry that is not present.
A record is the whole of the evidence: the sweep reads it without knowing
the object's kind, so an object of a kind or schema this tog no longer
produces is kept or collected like any other. A record the sweep cannot read
(no schema, another schema, any other evidence marker, an identity that does
not hash to its id, a malformed dependency) blocks deletion: the sweep
refuses, lists every such record, and names `tog gc --drop-object <id>` for
each.

Every (kind, schema) pair a producer commits has a row (`ObjectKind`, in the
producer's `objects.rs`: the tailor's, or `src/kernel/provider/objects.rs`
for the toolchains and build inputs the kernel providers make). Its `live_required` and `live_optional` fields
describe the inputs the current producer writes, including dynamic prefixes
for conditional package entries. Where identity shape has collection or platform semantics,
the producer's layer owns a `live_contract` beside its rows
in `objects.rs`; it receives the whole `Identity` and validates count fields,
paired keys, and platform-conditional inputs. The live check validates
required names and the live key whitelist before calling that contract.
Debug builds enforce all three at the one publication choke point,
`Store::commit_internal`, so a producer that starts writing a new input,
drops a required one, or emits an impossible partial group fails at the commit
that drifts.
A panic there means the producer and its row disagree: restore the producer if
the drift is accidental (a dropped input like `artifact_sha256` would let
distinct artifacts share an object id); update the row only for an intentional,
compatible addition; introduce a new schema value when identity semantics
change. A kind or schema with no registered row is rejected at commit time.
Public tailor realization entry points call
`tailors::install_kinds()` before they can publish, while commands call it
through `commands::dispatch`; direct kernel callers install it explicitly.
Release builds skip the check; it catches developer error, it is not a store
invariant.

Status, 2026-09-10: implemented and independently reviewed on Linux; the
macOS gate has not run since this work landed. The boundary:
it covers cooperating tog processes on a local filesystem with working
advisory locks and atomic rename; not old binaries, not programs launched
directly from store paths, not malicious same-user changes, not network
filesystems where `flock` is advisory in name only.

### Identity schemas of the environment and build kinds

Four rows had drifts their contracts could not see, because every check was
conditional on the presence of the key it checked. All four shipped their
successor together, accepting one store-wide rebuild of those kinds:

| kind | successor | what the bump adds | the drift it closes |
|---|---|---|---|
| `cargo-vendor` | `cargo-vendor/2` | `crates`, the exact number of `crate:` keys | `version` is `max(1, count)`, so a one-crate plan that lost its only `crate:` key hashed to the empty plan |
| `python-env` | `python-env/3` | `package_digest` over every `pkg:` entry, and a `native` decision | a one-wheel plan that lost its only `pkg:` key became the empty environment; a native sdist could lose `native_libs` |
| `node-env` | `node-env/4` | `plan_digest` over every `pkg:` and `artifact:` entry, and a `native` decision | a multi-package plan could lose one package, or a declared `artifact:` or Linux `native_libs` key |
| `sdist-build` | `sdist-build/4` | `build_mode` and `native_mode` | dropping *both* halves of `rust`/`vendor` or `native_libs`/`native_linker` left the valid shape that never had one |
| Rust `sdist-build` | `sdist-build/5` | `rust_build_config` | changed Rust flags could reuse a wheel built with the previous environment. Plain builds retain `/4` |

Each added input is written unconditionally, including in the empty case, and
the producer derives it from the *plan* — the locked package list, the
declared artifact list, the crate vector — in a traversal separate from the
loop that writes the identity inputs. The contract then recomputes it from
the inputs the finished identity carries. Those are two different sources on
purpose: a producer whose insert loop writes one fewer input than its plan
names makes them disagree, so the drift fails the commit instead of
colliding with a legitimate smaller identity. Deriving both sides from the
input map would move the added input along with the drift and catch nothing.
(A dropped `provisioned:` key was always caught: the `pkg:` value names the
package, and the contract asks the producer's own provisioning decision
whether that package must carry one.)

`node-env/5` followed on its own. `node-env/4` named the Node object but not
the CPython node-gyp ran on, which was the shipped pin: a pin change could
rebuild a native addon under an unchanged id, and a project's locked Python
was ignored. `/5` adds `gyp_python`, that interpreter's object id, written
unconditionally (whether any package runs node-gyp is known only after
extraction). It becomes a recorded dependency only when an install script
ran with it: the interpreter is realized only then, and a script handed
`$PYTHON` can leave a symlink or wrapper to it, so the environment it built
must keep it alive. A pure-JavaScript environment does not retain a CPython.
Every other `/4` input is
unchanged, and the test goldens check that dropping `gyp_python` gives back the
`/4` ids byte for byte. `sdist-build` needed no successor for its Rust: the
`rust` input was already the Rust object id, so honoring the project's
selection changes the value and never the shape.

A new schema reissues every object id of its kind. Nothing caches the old id:
a re-sync computes the successor identity, misses the store, and realizes
fresh, and the orphaned old-schema objects are swept as ordinary garbage
when nothing roots them. The old schema's row is deleted with its producer,
so publishing it again is refused at commit.

## Store concurrency

Publication and incomplete-object sweeping serialize on a cross-process file
lock (`tmp/.publish.lock`), so a concurrent `has()` never mistakes a
mid-publication object for a crashed one. Store-consuming operations hold an
activity lease (`src/kernel/activity.rs`), shared or exclusive, with a fixed
ordering: activity, then x-root, then the toolchain-input lock, then project
transaction, then cache, then publication. Each operation supervises its own awaited
store-consuming child (`src/kernel/supervise.rs`) and forwards TERM to it; any number run at
once. The signal handlers are installed once per process and never removed: each supervision
registers with them, keeps its own cursors into the signal counts, and with none registered
the handler acts as the disposition tog inherited, including handler masks,
syscall restart behavior and one-shot handlers. Cancellation caught by the
reap boundary carries the child's exit status. A TERM caught after that
boundary is re-raised when the last session leaves. New operations cannot
register while that inherited delivery is pending, including when the caller
blocks TERM. A helper that runs
such a child takes the caller's `&StoreActivity` rather than taking a lease of
its own, so the lease that protects a stage directory is visibly the one held
across its children and its commit (`tests/architecture.rs` lists the few raw
children that touch no store path). Contention is a named
outcome, not a hang: GC acquires exclusive activity and skips safely while a
managed job holds the shared lease. Stage dirs and download temps use
collision-proof names.

## Layering rules

These keep the layout organized. The first is enforced by
`tests/architecture.rs`; the rest are review rules.

1. **Layers point one way:** `commands → tailors → comforter → kernel`. The
   kernel never names a tailor or a command; a tailor never names another
   tailor or a command. Cross-layer knowledge flows through traits and data.
   The test fails the build on a violation; its allow-list is the one place
   a documented exception lives, with the reason beside it.
2. **One folder, one owner scope.** Work assigned to one tailor edits
   `src/tailors/<ecosystem>/` and nothing else without saying so. A PR that
   touches two top-level folders is a shared-layer change and is reviewed as
   one.
3. **Adding an ecosystem is additive:** a new folder plus one registry line
   (docs/human/ADDING-A-TAILOR.md). If a tailor has to edit a command, the
   kernel, or another tailor, the abstraction is wrong and gets fixed first.
   The test checks the kernel half: non-test kernel code has no `match`
   or `matches!` pattern holding a tailor's id or lock ecosystem, and no
   `==` or `!=` against one (comparisons under `kernel/provider/` wait for
   a pull request that has to touch that heavy-watched tree).
4. **Folders are future crates.** Nothing may prevent a top-level folder
   becoming its own crate later: no reaching into another folder's private
   items; cross-folder use goes through `pub` items at the folder's `mod.rs`.
5. **Size budgets:** a file over 1,500 non-test lines or a function over 150
   lines is a review flag. `tests/size_baseline.txt` lists today's
   offenders at their current size, and the architecture test is a
   ratchet: it fails when a listed one grows, a new one crosses a budget,
   or a listed one shrinks without its line being updated.
6. **Public surface is deliberate.** `lib.rs` exports what tests and the
   binary need. Making an item `pub` is a decision, noted in the module doc
   comment.
7. **Moves are not rewrites.** A PR that moves code does not also change
   behavior; identity goldens and test output stay identical.
8. **Every module has a doc comment** whose first line says what it owns
   and which layer it lives in.

## Layout

Folders follow the layers above.

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
    audit.rs        tog audit: closure records judged against a policy, signatures checked under [signing]
    keygen.rs       tog keygen: a closure-signing key and its policy table
    deps.rs         add / remove / update, delegated to each ecosystem's tool
    sbom.rs         CycloneDX 1.5 JSON from the closure envelopes
    selfupdate.rs   tog update --self, and doctor's version row (release lookup)
    x/              tog x: run a registry tool without adding it to a project
                    (mod.rs; lock.rs the per-environment locks; cleanup.rs --clean)

Kernel (`src/kernel/`, names no tailor; `provider/` holds the pinned toolchains
and build inputs tailors share, so no tailor reaches into another):

    types.rs        Identity, Plan, LockedPackage, GitSource
    digest.rs       validated content digests (sha1/sha256/sha512)
    context.rs      Context { platform, store, activity lease } for store-backed verbs
    cyclonedx.rs    CycloneDX component builders every tailor's sbom uses
    store/          immutable store: mod.rs Store and locks, objects.rs
                    stage/commit/cache, roots.rs the root registry,
                    closure_import.rs closure references into a root
                    record, projection.rs projection refs, env.rs TOG_STORE,
                    fsops.rs descriptor-level filesystem helpers
    fetch.rs        verified downloads
    fsroot.rs       ProjectRoot: project files read and published through a
                    held directory descriptor, never through a symlink
    archive.rs      archive validation and delegated extraction
    dirhash.rs      Go module dirhash verification
    gitsrc.rs       git sources realized by commit
    policy.rs       permissive/strict exception policy and the [signing] trust chain
    signing.rs      Ed25519 closure signing: key files, canonical bytes, verify
    gc/             store garbage collection: read.rs snapshot, plan.rs
                    validate + plan, sweep.rs execute, drop.rs --drop-object,
                    reset.rs --reset
    objmeta.rs      object-meta/2 records; kind rows are installed by
                    commands::dispatch or public tailor entry points
    activity.rs     store activity leases
    pep440.rs       PEP 440 versions and specifiers: Python interpreter
                    selection, Python locks, markers, and the toolchain
                    lock's Python constraints all read them here
    supervise.rs    supervised child processes
    platform.rs     the only module that knows the host
    toolchain/      release-bundle catalog: mod.rs types + validation + bundle id,
                    document.rs the generated catalog files, select.rs version
                    requests and the global order, source.rs the typed
                    endpoint policy
    sandbox.rs      hermetic build sandbox (Seatbelt / bubblewrap)
    hostview.rs     HostView::RuntimeOnly on Linux: the host's runtime files
                    plus the C runtime's development files, nothing else
    hostfallback.rs C-runtime-first builds: the retry against the whole host,
                    host-fallback identities and their store records
    provider/       shared toolchain providers, the pinned things more than one
                    tailor realizes: cpython.rs (CPython + uv from
                    cpython.catalog.toml, realization; node-gyp's
                    interpreter too), rust.rs (Rust from
                    rust.catalog.toml, toolchain files), rust_channel.rs and
                    rust_extras.rs (components, targets and profiles from
                    the channel manifest), rust_path.rs (a local toolchain
                    directory), crates.rs (Cargo.lock
                    vendoring; sdists with Rust extensions too),
                    crates_index.rs (crates.io's sparse index as a
                    resolution-proxy route) and cargo_door.rs (the store
                    cargo confined through the resolution door, for the
                    Cargo tailor and Python's sdist Cargo.lock),
                    nativelibs.rs (the Linux native library set), artifacts.rs
                    (install-time artifact policy)
    ui.rs           output conventions: quiet/verbose/color, error channel

Comforter (`src/comforter/`): ecosystem-neutral closure records, projection
symlinks, clone-tree and backup helpers (`mod.rs`), `records.rs`, the
committed closure records read as they are (envelope, body, exceptions,
any platform) for `ls`, `status`, `audit` and `sbom`, and `status.rs`, the
projection-currency checks `tog status` is built from. Freshness asks the
tailors, so it stays in `commands/inspect.rs`. It names no tailor; Python environment realization lives in `tailors/python/env.rs`.

Tailors (`src/tailors/<ecosystem>/`, leaves of the module graph). Every
folder has `tailor.rs` (its `impl Tailor`, the one blueprint every
ecosystem answers: detect, preflight, plan, sync, build, run_env,
refused_command, listing, closure_state, sbom_components, object_kinds,
toolchain_kinds) and `objects.rs` (the store
object kinds it produces, with their identity grammars);
`src/tailors/mod.rs` holds the trait and the registry the
commands iterate. See docs/human/ADDING-A-TAILOR.md. A command file never
spells a tailor's name as a string: `tests/architecture.rs` fails on a
literal in `src/commands/` that is a tailor id, lock ecosystem, or registry
word (read from the registry), except the rows its debt table keeps for
the open issues that remove them.

`Tailor::registry_tool` is how `tog x` reaches an ecosystem. Its default
answers "tog x does not support <id>"; Python and Node return a
`RegistryTool` (`registry_tool.rs` in each folder) that supplies the cache
directory prefix (`py`, `npm`), the runtime object id in the cache key, the
command-line word and message labels, the executable directory,
resolve-realize-project for one package, the launch environment, and
whether a cached projection still points at its environment.
`commands/x/` keeps the `~/.tog/x` directory, the `x/3`/`x/4` key,
the request record, gc root registration, and the policy checks on a
cached hit (`mod.rs`), the lifecycle lock (`lock.rs`), and
`tog x --clean` (`cleanup.rs`). It owns the one package-name and version
validator the parser also calls, and is ecosystem-neutral except for the
Corepack `pnpm` delegate path, which is Node by definition. The grammar
cannot ask the registry (the cli layer names no tailor), so
`cli::spec::X_REGISTRIES` mirrors each registry tool's `spelling` for the
`--<word>`/`--<id>` flags and the `<word>:` prefix, and a parser test fails
when the two differ.

    python/mod.rs          CPython pin lookup over kernel/provider/cpython.rs
    python/inputs.rs       project inputs to a Python plan (uv lock, plan cache)
    python/pypi.rs         Python planner (adapter)
    python/unpack/wheel.rs PEP 427 wheel installer
    python/pyselect.rs     CPython constraint parsing and selection
    python/manifest/       manifest discovery (discovery.rs), poetry.rs, uv.rs,
                           requirements.rs, setup.rs, markers.rs
    python/env.rs          venv-shaped env object realization and projection
    python/build.rs        sandboxed sdist-to-wheel builds
    python/sdist_view.rs   which host view an sdist build runs in, host fallback
    python/build_requires.rs  PEP 517 build requirements
    python/registry_tool.rs  `tog x` from PyPI: uv resolve, env realize, .venv
    python/run_refusal.rs  `tog run` refusals: pip install into a projected .venv
    node/mod.rs            pins, plan types, scripts, path helpers
    node/plan.rs           package-lock.json planning
    node/freshness.rs      lock-vs-package.json checks for npm and pnpm locks
    node/realize.rs        env realization and sandboxed install scripts
    node/script_view.rs    install scripts: C-runtime-only first, host fallback
    node/project.rs        node_modules projection and workspace links
    node/inputs.rs         missing-lock generation, lockfile importers
    node/door.rs           npm and the pinned pnpm confined through the
                           resolution door (interception, the npm route)
    node/registry.rs       the npm registry as a resolution-proxy route
    node/resolve.rs        resolution outputs and inputs, the missing-lock
                           door, `tog attest` for npm and pnpm
    node/registry_tool.rs  `tog x` from npm: npm resolve, env realize, node_modules
    node/run_refusal.rs    `tog run` refusals: npm-family installs over node_modules
    node/lock_import/      pnpm.rs and yarn1.rs importers over yaml.rs;
                           pnpm/record.rs is what the lock says about the
                           manifests, read by node/freshness.rs;
                           pnpm/patch.rs reads and hashes patch files
    cargo/mod.rs           project Cargo env + sandboxed build over
                           kernel/provider/{rust,crates}.rs
    cargo/inputs.rs        toolchain resolution, workspace root, missing-lock generation
    cargo/edit.rs          `tog add`/`remove`/`update` through the edit door
    cargo/resolve.rs       resolution outputs and inputs, the missing-lock and
                           `tog attest` doors at the workspace root
    cargo/rustfmt.rs       pinned formatter component for `tog fmt`
    go/mod.rs              module closure via the pinned Go toolchain
    go/inputs.rs           toolchain selection from go.mod, the GoPlan
    ruby/mod.rs            Bundler-delegated planning, tog-verified gems
    ruby/native.rs         native gems: C-runtime-only first, host fallback identity
    ruby/native_libs.rs    native gems build with tog's pinned native library set
    ruby/gem_home.rs       what a failed gem build may leave before its retry
    elixir/mod.rs          Mix/Hex, AST-validated lockfile
    elixir/check_locked.rs whether mix deps.get --check-locked must run again
    dotnet/mod.rs          NuGet packages.lock.json (tog-mandatory)

## Where the rest lives

- `STATUS.md`: where the project is and what is next.
- `FOLLOW-UPS.md`: the ordered to-do list and open decisions, one line
  per item pointing at its GitHub issue, which holds the detail.
- `docs/human/CLI.md`: the command reference.
- `docs/human/LIMITATIONS.md`: known, accepted gaps.
- `docs/human/ADDING-A-TAILOR.md`: how to add an ecosystem.
- `docs/agent/DESIGNS.md`: designed but unbuilt work (the toolchain lock's
  open parts, release catalog and trust, company policy layer, signal
  sessions, the resolution proxy).
- `docs/agent/HITRATE.md`: the real-project hit-rate measurement.

Review results live in each pull request's description. Older plans,
reviews, and changelogs were removed on 2026-09-16 and remain in git
history.

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
2026-08-31 as wrap-hermetically tailors. Tailor cost, measured honestly
(adapter code excluding tests): Python ~1030 lines (pypi+wheel+python+build),
npm ~1015, cargo ~690, go ~600, ruby ~540, elixir ~620, dotnet ~540. The
kernel thesis holds. pnpm v9/v6 and Yarn classic lockfile importers shipped
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
symlink is refused rather than followed: closures (read for toolchain
seeding, the exception summary and root registration, and written),
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
- **The host C toolchain is an unpinned build input** on both platforms
  (Xcode clang on macOS, `/usr` gcc on Linux). Pinning it is a backlog item.
  A build spec also names its host view: `Full` binds the host's whole `/usr`,
  so a build can link any library the host has; `RuntimeOnly` (Linux only;
  Seatbelt treats it as `Full`) keeps the host's runtime files and the C
  runtime's development files and leaves every other header, `-l` library,
  static archive and pkg-config file out of the compiler's and linker's
  default search paths and out of pkg-config. Other shared libraries the
  host's tools load move to a `.tog-host-runtime` subdirectory that `ld`
  never searches, reached through `LD_LIBRARY_PATH`. Ruby gems with native
  extensions install under `RuntimeOnly`, so a gem object committed under
  the `runtime-only/1` view does not depend on which `-dev` packages the
  building host has installed.
- **Darwin identity goldens stay byte-identical.** A platform change that
  alters a macOS object id is a bug.
- **Archive extensions must agree.** GNU tar always prefers the PAX record
  when a member carries both a GNU long name and a PAX `path`; macOS bsdtar
  prefers whichever block came last, so the two read the same bytes as two
  different names. The reader refuses conflicting paths or link targets
  before extraction on either platform, including conflicts that a
  names-only listing cannot reveal.

## The tailors

**Python** (`tailors/python/`: `pypi.rs`, `manifest/`, `wheel.rs`, `mod.rs`,
`pyselect.rs`, `env.rs`). Resolution of ranged requirements is delegated to the
store-pinned uv (`uv pip compile --generate-hashes`); hash-pinned
requirements and `pyproject.toml` dependencies are locked directly, choosing
the best wheel per platform (native arm64 > abi3 > universal2 > pure >
sdist). CPython comes from astral-sh/python-build-standalone with sha256s
pinned in `kernel/provider/cpython.rs`; interpreter selection happens before locking
(`.python-version` wins, then `requires-python`). Wheels install into the
env object; sdists build in a network-denied sandbox (legacy setuptools
records keep `sdist-build/2`, PEP 517 uses `sdist-build/4` with an immutable
build environment). Environments are immutable: no activate scripts, pip
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
that nothing depends on). A `file:`/`link:` dependency is a
symlink into the user's source, so nothing is ever placed beneath one: a
target that is itself an importer gets its dependencies from its own
projected `node_modules` (as pnpm installs it), and any other local package
gets them in the nearest enclosing importer's `node_modules`, where Node
looks from the package's real path. Every importer's and local package's
dependencies are then checked against that lookup chain, and a layout where
one would shadow another, or a link that would sit inside a registry
package, is refused; a `file:` package whose dependencies conflict with its
workspace member's is not supported yet. pnpm `patchedDependencies` follow
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
view); a gem whose native extension needs another host
library is rebuilt against the whole host after recording
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
the store; an unchanged project re-syncs offline.

**dotnet** (`tailors/dotnet/`). NuGet's `packages.lock.json` is opt-in upstream;
tog makes it mandatory. The lock's `contentHash` is a semantic hash, so
tog never raw-compares: it fetches nupkgs into a local folder feed, then
the pinned NuGet installs from that feed in locked mode, verifying every
contentHash. The SDK is the extractor and part of the object identity. Builds
are the strictest boundary: `tog run` refuses build-capable verbs
(MSBuild executes arbitrary code and belongs only in the sandbox), and every
`tog build` runs a fresh offline locked restore into scratch. `global.json`
must be an exact pin with `rollForward = "disable"`.

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
before the pin, and one seeded from a pre-lock closure, keep the Rust those
builds used (`Tailor::legacy_helper_pins`: 1.96.1). A section may pin only
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
fresh environment and an `x/2` directory is never reused. A registry tool
that builds with helpers (npm's node-gyp Python) keys on `x/4` instead: the
`x/3` fields plus `<helper>=<object id>` for each, decided as above for the
project `x` runs in and written to the request record's `helpers`. `py:`
tools have none and keep their `x/3` names; every `npm:` cache from before
is a miss.

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
sent yet; the policy for them is decided (#72) and builds under #404 and #405. Package-registry downloads do not pass through it. `seed` chooses a bundle
from a pre-lock closure's recorded platform and exact versions and refuses,
naming `tog update --toolchain`, when either is missing, when the
version is not in the catalog, or when the bundle is incomplete on the
other platform: a closure realized on one platform is not evidence for the
other. The closure's version strings are only a claim. Each tailor's
`legacy_toolchain_evidence` also reads the runtime object the closure
names (through its environment object for Python and Node) in the active
store, located by `Store::existing` and read by `Store::published_identity`.
The seeding lookup itself only reads: no lease, lock file, touch or created
directory (the command around it, `status` and `doctor` included, may
already have opened the store). An object the store
holds proves the artifact rows its identity was built from
(`comforter::toolchain::prove_legacy_runtime`), and those proofs decide
between releases that share a version. An object the store lacks proves
nothing: a unique version still seeds, and a tie refuses and says the
object was missing. An object whose kind, platform or version contradicts
the closure, or whose metadata does not hash to its id, refuses outright.

## Permissive by default, strict as a switch

Sync records recoverable verification gaps in each closure and continues;
`.tog/policy.toml` denies named kinds (`install-script-failed`,
`git-dependency`, ...). User and project policies are unioned; deny entries
are only added. `TOG_STRICT=1` or `tog --strict` denies every
exception. Object-affecting exceptions are written into store metadata and
rechecked on cache hits, so `--fresh` cannot bypass one. `tog audit`
(`src/commands/audit.rs`) is the CI admission gate: it re-judges the exceptions the
closures already record against the policy chain plus an optional
`--policy` file (merged, so it can only tighten), refuses to pass a stale or
outdated closure, and touches neither the store nor the network.

Closure records are signed. With `TOG_SIGNING_KEY` set, `sync` and `fmt`
load an Ed25519 key once at preflight and the one closure writer
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
refuses to run that way); a signature that fails to verify is
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
when the file names no channel); `sdist-build/4` already commits
to that Rust object id through its `rust` input. Both helpers come from
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

## GC root safety

The store's `roots/<sha1>` registry records every project whose closure can
protect store objects. New `root/2` records contain the complete object set
and typed projection references, so GC never opens the project's diagnostic
path: a moved, unmounted, or deleted project keeps its tools protected.
Legacy pathname-only records stay conservative: if the project cannot be
read, the whole sweep stops before any deletion, dry run included.
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
digests, and an `evidence` marker, `"explicit"` or `"adapted:<kind>@<n>"`.
Explicit evidence names what the realization actually read, which can be
less than its identity names: a node env's identity carries every declared
artifact and provisioned download the plan could use, but only the ones an
install script was given are cache dependencies, because a commit refuses to
claim a cache entry that is not present.
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
package entries. Where identity shape has collection or platform semantics,
the tailor owns a `live_contract` beside the producer's identity constructor
in `objects.rs`; it receives the whole `Identity` and validates count fields,
paired keys, and platform-conditional inputs. The live check validates
required names and the live key whitelist before calling that contract.
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
when nothing roots them. Their rows stay registered, marked `superseded_by`,
so a pre-`object-meta/2` record of the old layout still migrates rather than
blocking the sweep; publishing a superseded schema is refused at commit.

## Store concurrency

Publication and incomplete-object sweeping serialize on a cross-process file
lock (`tmp/.publish.lock`), so a concurrent `has()` never mistakes a
mid-publication object for a crashed one. Store-consuming operations hold an
activity lease (`src/kernel/activity.rs`), shared or exclusive, with a fixed
ordering: activity, then x-root, then the toolchain-input lock, then project
transaction, then cache, then publication. Each process supervises at most one awaited store-consuming
child (`src/kernel/supervise.rs`) and forwards TERM to it. A helper that runs
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
    x.rs            tog x: run a registry tool without adding it to a project

Kernel (`src/kernel/`, names no tailor; `provider/` holds the pinned toolchains
and build inputs tailors share, so no tailor reaches into another):

    types.rs        Identity, Plan, LockedPackage, GitSource
    digest.rs       validated content digests (sha1/sha256/sha512)
    context.rs      Context { platform, store, activity lease } for store-backed verbs
    cyclonedx.rs    CycloneDX component builders every tailor's sbom uses
    store/          immutable store: mod.rs Store and locks, objects.rs
                    stage/commit/cache, roots.rs the root registry,
                    projection.rs projection refs, env.rs TOG_STORE,
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
                    validate + plan, sweep.rs execute, migrate.rs maintenance
    objmeta.rs      object-meta/2 records; kind rows are installed by
                    commands::dispatch or public tailor entry points
    activity.rs     store activity leases
    supervise.rs    supervised child processes
    platform.rs     the only module that knows the host
    toolchain/      release-bundle catalog: mod.rs types + validation + bundle id,
                    document.rs the generated catalog files, select.rs version
                    requests and the global order, source.rs the typed
                    endpoint policy, legacy.rs seeding from closures
    sandbox.rs      hermetic build sandbox (Seatbelt / bubblewrap)
    hostview.rs     HostView::RuntimeOnly on Linux: the host's runtime files
                    plus the C runtime's development files, nothing else
    provider/       shared toolchain providers, the pinned things more than one
                    tailor realizes: cpython.rs (CPython + uv from
                    cpython.catalog.toml, realization; node-gyp's
                    interpreter too), rust.rs (Rust from
                    rust.catalog.toml, toolchain files), rust_channel.rs and
                    rust_extras.rs (components, targets and profiles from
                    the channel manifest), rust_path.rs (a local toolchain
                    directory), crates.rs (Cargo.lock
                    vendoring; sdists with Rust extensions too),
                    nativelibs.rs (the Linux native library set), artifacts.rs
                    (install-time artifact policy)
    ui.rs           output conventions: quiet/verbose/color, error channel

Comforter (`src/comforter/`): ecosystem-neutral closure records, projection
symlinks, clone-tree and backup helpers (`mod.rs`) and `status.rs`, the
projection-currency checks `tog status` is built from. It names no
tailor; Python environment realization lives in `tailors/python/env.rs`.

Tailors (`src/tailors/<ecosystem>/`, leaves of the module graph). Every
folder has `tailor.rs` (its `impl Tailor`, the one blueprint every
ecosystem answers: detect, preflight, plan, sync, build, run_env,
refused_command, listing, closure_state, sbom_components, object_kinds,
toolchain_kinds) and `objects.rs` (the store
object kinds it produces, with their live and migration identity grammars and
legacy-metadata adapters); `src/tailors/mod.rs` holds the trait and the registry the
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
resolve-realize-project for one package, the launch environment, whether a
cached projection still points at its environment, and the packages a
pre-record cache root was made for. `commands/x.rs` keeps the `~/.tog/x`
directory, the `x/3`/`x/4` key, the lifecycle lock, gc root registration, and the
policy checks on a cached hit, and is ecosystem-neutral except for the
Corepack `pnpm` delegate path, which is Node by definition. The grammar
cannot ask the registry (the cli layer names no tailor), so
`cli::spec::X_REGISTRIES` mirrors each registry tool's `spelling` for the
`--<word>`/`--<id>` flags and the `<word>:` prefix, and a parser test fails
when the two differ.

    python/mod.rs          CPython pin lookup over kernel/provider/cpython.rs
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
    python/registry_tool.rs  `tog x` from PyPI: uv resolve, env realize, .venv
    python/run_refusal.rs  `tog run` refusals: pip install into a projected .venv
    node/mod.rs            pins, plan types, scripts, path helpers
    node/plan.rs           package-lock.json planning
    node/freshness.rs      lock-vs-package.json checks for npm and pnpm locks
    node/realize.rs        env realization and sandboxed install scripts
    node/project.rs        node_modules projection and workspace links
    node/inputs.rs         missing-lock generation, lockfile importers
    node/registry_tool.rs  `tog x` from npm: npm resolve, env realize, node_modules
    node/run_refusal.rs    `tog run` refusals: npm-family installs over node_modules
    node/lock_import/      pnpm.rs and yarn1.rs importers over yaml.rs
    cargo/mod.rs           project Cargo env + sandboxed build over
                           kernel/provider/{rust,crates}.rs
    cargo/inputs.rs        toolchain resolution, workspace root, missing-lock generation
    cargo/rustfmt.rs       pinned formatter component for `tog fmt`
    go/mod.rs              module closure via the pinned Go toolchain
    go/inputs.rs           toolchain selection from go.mod, the GoPlan
    ruby/mod.rs            Bundler-delegated planning, tog-verified gems
    ruby/native.rs         native gems: C-runtime-only first, host fallback identity
    ruby/gem_home.rs       what a failed gem build may leave before its retry
    elixir/mod.rs          Mix/Hex, AST-validated lockfile
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

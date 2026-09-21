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

Six writes under `.tog/` go through `kernel::fsroot::ProjectRoot`, which
walks every component from a held project descriptor with `O_NOFOLLOW`, so a
`.tog` swapped for a symlink is refused rather than followed: the closure
JSON (`.tog/closures/<ecosystem>.json`), the plan cache (`.tog/plan.json`),
the Python manifest snapshots (`.tog/manifest-requirements.txt`,
`.tog/manifest-constraints.txt`), the lock stamp (`.tog/lock-source.hash`,
also removed through the descriptor by `tog update`), and the setup.py
metadata cache (`.tog/egg-info.json`). The rest of `.tog/` is still written
by pathname: `uv pip compile` writes `requirements.lock.txt` itself, and the
cargo tailor creates `.tog/cargo-home/` with `tog-config.toml` and a `cargo`
shim behind its own canonicalized containment check. Closing those is
"Descriptor-relative project access in sync" in `FOLLOW-UPS.md`.

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
pinned in `python/mod.rs`; interpreter selection happens before locking
(`.python-version` wins, then `requires-python`). Wheels install into the
env object; sdists build in a network-denied sandbox (legacy setuptools
records keep `sdist-build/2`, PEP 517 uses `sdist-build/4` with an immutable
build environment). Environments are immutable: no activate scripts, pip
cannot mutate them.

**npm** (`tailors/node/`: `plan.rs`, `realize.rs`, `project.rs`, `lock_import/`). `package-lock.json` is parsed
locally; a pnpm v9/v6 or Yarn classic lockfile is imported by
`lock_import/` (dependency-free strict YAML for pnpm, `lock_source`
recorded); with none of these, the store node's bundled npm runs
`npm install --package-lock-only`. Lifecycle scripts run hermetically (below).
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
endpoint returns the latest-pushed variant). Gems install dependency-first
inside the network-denied sandbox into one immutable GEM_HOME object;
binstubs are wrapper scripts, never symlinks (symlinks dangle after the
store-commit rename; this bit once). Every tog invocation strips
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
own sources. `tog build` sandboxes `mix compile`.

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
bundle the catalog no longer has.

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
does not read the lock yet (`FOLLOW-UPS.md`). Cached `tog x` environments
key on `x/3`: store root, ecosystem, package request, platform, the primary
runtime version, the selected `bundle_id` and the realized runtime object,
so a changed bundle component gives a fresh environment and an `x/2`
directory is never reused.

The catalog a lock is minted from
(`src/kernel/toolchain/`). Each tailor's `toolchain_catalog` turns its pin
rows into release bundles: components, and per platform one artifact row
with the provider, build, append-only recipe id, URL and algorithm-qualified
digest (`sha256:…` or `sha512:…`, exactly the digest the pin already
verifies; .NET, Hex and rebar3 keep their sha512). The rows carry the same
bytes realization fetches; they mint no new object identity. The kernel
names no tailor: it validates the bundles it is handed (unique
release keys and bundle ids, resolvable embedding chains, one row per
platform and component) and selects from the releases complete on every
supported platform, so an asymmetric catalog chooses the same bundle from
either platform. Order is primary version descending (BEAM compares the
`(otp, elixir)` pair, OTP first), highest explicit revision, then the
provider/build/recipe tuple, the artifact tuple and the bundle id; exact
requests filter by primary version and ranges take the first satisfying
candidate. `SourcePolicy` is the typed endpoint policy retrieval will check
(shipped `https://` defaults per publisher, credential references only,
never a secret, and not part of lock validity; the defaults are data the
kernel owns, so a new tailor's publisher is added there). `seed` chooses a bundle
from a pre-lock closure's recorded platform and exact versions and refuses,
naming `tog update --toolchain`, when either is missing, when the
version is not in the catalog, or when the bundle is incomplete on the
other platform: a closure realized on one platform is not evidence for the
other.

## Permissive by default, strict as a switch

Sync records recoverable verification gaps in each closure and continues;
`.tog/policy.toml` denies named kinds (`install-script-failed`,
`git-dependency`, ...). User and project policies are unioned; deny entries
are only added. `TOG_STRICT=1` or `tog sync --strict` denies every
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
tree can never vouch for itself. `audit` verifies each file's signature over
the complete envelope it read before believing any field: `bad-signature`,
`untrusted`, and unsigned `outdated` records are not evaluated further, and a
detected ecosystem with no primary closure is `missing`. Store identity is
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
plus a scratch HOME, node-gyp shimmed from the store node, gyp's Python the
store CPython. This is a cooperative network-denial build sandbox, not
hostile-code containment. Packages that download binaries at install time
get them via declared artifacts: the project pins `url` + `sha256`, tog
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
ordering: activity, then x-root, then project transaction, then cache, then
publication. Each process supervises at most one awaited store-consuming
child (`src/kernel/supervise.rs`) and forwards TERM to it. Contention is a named
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
   lines is a review flag. The architecture test prints offenders
   (`cargo test --test architecture -- --nocapture`); it does not fail.
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
    audit.rs        tog audit: signed closure records judged against a policy
    keygen.rs       tog keygen: a closure-signing key and its policy table
    deps.rs         add / remove / update, delegated to each ecosystem's tool
    sbom.rs         CycloneDX 1.5 JSON from the closure envelopes
    x.rs            tog x: run a registry tool without adding it to a project

Kernel (`src/kernel/`, ecosystem-agnostic):

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
                    select.rs version requests and the global order, source.rs
                    the typed endpoint policy, legacy.rs seeding from closures
    sandbox.rs      hermetic build sandbox (Seatbelt / bubblewrap)
    ui.rs           output conventions: quiet/verbose/color, error channel

Comforter (`src/comforter/`): ecosystem-neutral closure records, projection
symlinks, clone-tree and backup helpers (`mod.rs`) and `status.rs`, the
projection-currency checks `tog status` is built from. It names no
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
    cargo/rustfmt.rs       pinned formatter component for `tog fmt`
    go/mod.rs              module closure via the pinned Go toolchain
    go/inputs.rs           toolchain selection from go.mod, the GoPlan
    ruby/mod.rs            Bundler-delegated planning, tog-verified gems
    elixir/mod.rs          Mix/Hex, AST-validated lockfile
    dotnet/mod.rs          NuGet packages.lock.json (tog-mandatory)

## Where the rest lives

- `STATUS.md`: where the project is and what is next.
- `FOLLOW-UPS.md`: open decisions and the ordered to-do list.
- `docs/human/CLI.md`: the command reference.
- `docs/human/LIMITATIONS.md`: known, accepted gaps.
- `docs/human/ADDING-A-TAILOR.md`: how to add an ecosystem.
- `docs/agent/DESIGNS.md`: designed but unbuilt work (toolchain lock,
  release catalog and trust, company policy layer).
- `docs/agent/HITRATE.md`: the real-project hit-rate measurement.

Review results live in each pull request's description. Older plans,
reviews, and changelogs were removed on 2026-09-16 and remain in git
history.

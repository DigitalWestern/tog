# Blanket limitations ledger

A standing, honest record of what blanket fails to address or doesn't get
right, per ecosystem and kernel-wide. Items graduate OFF this list only
when fixed and regression-tested. Started 2026-08-31. When adding items,
say what breaks, for whom, and how it fails (loud/silent).

## Kernel-wide

- **CLI exit status is 0 / 1 / 2** (success / command failed / usage
  error) since 2026-09-06; before that a bad `gc` or `sbom` argument
  exited 1. `blanket build -h` and `blanket run -h` now print blanket's
  help; a tool argument that is literally `-h` needs `--` in front
  (`blanket build -- -h`). `--verbose` shows subprocess command lines only
  for the subprocesses `main.rs` starts (uv, npm, cargo lock generation);
  the tailors' own subprocesses are not yet traced. See CLI.md.
- **`blanket status` compares recorded inputs only.** Python and Node
  closures written since 2026-09-06 record the root manifest and lock files
  (`inputs`); `-r` includes, `requirements/` directory members, and
  workspace-member package.json files are not recorded, so an edit there is
  reported as synced. Cargo, Ruby, Elixir and .NET compare the lock hash
  only, not the manifest. Go compares the selected `go.mod` toolchain
  version as well as the `go.sum` hash, but `go.mod` `require`/`replace`
  edits are still detected only indirectly through `go.sum`/`go mod tidy`.
  Closures from before a required field exists show as "synced (unchecked)"
  until the next sync.
- **There is no committed toolchain lock yet (WP2 design only).** `sync`
  selects from compiled pins and does not compare `.node-version`,
  `.ruby-version`, `.tool-versions`, or a cross-platform runtime row; Node,
  Ruby, and Elixir therefore remain single-pin selections, and `status` does
  not report a stale/missing toolchain lock. The release-bundle catalog
  authority, bundle ids, algorithm-qualified artifact digests, HTTPS-only
  retrieval, the one hardened publication rule shared by both lock writers,
  the unconditional descriptor-relative pre-publication compare, the reusable
  pre-materialization extractor, the source matrix, per-platform BEAM rows,
  the `--frozen` write boundary, the presence- and value-based input staleness
  rule over the whole consulted path list, the shipped provider host allowlist,
  the descriptor-relative root helper (`src/fsroot.rs`, not yet written), and
  store-root-scoped bundle-complete `x/3` keys in ARCHITECTURE.md are not
  implementation guarantees yet. In particular,
  the generic fetch helper still accepts `file://` for mirrors and tests
  (`src/fetch.rs:319-380`); the dormant lock cannot authorize that path.
  Implementation remains open.
- **Legacy closures cannot always seed a complete toolchain lock (WP2 design
  boundary).** Older provenance can lack Rust channel/components/targets,
  Go source directives, companion-tool refs, or compatibility-input snapshots.
  Writable sync must refuse those migrations with `blanket update --toolchain`
  rather than guess; a changed recorded source takes the same loud path. This
  remains until the WP2 implementation adds complete closure evidence.
- **One toolchain per lock root: a toolchain source file in a subdirectory is
  not a toolchain source (WP2 design boundary).** Toolchain discovery is
  anchored at the directory holding `blanket-toolchain.toml`, never at the
  current directory, so that the same project yields the same lock and the same
  `status` verdict from every directory, every developer, and every CI job. The
  cost is that `web/.node-version` under a root-level lock is invisible to
  blanket while `nvm` and uv would honor it. Silent divergence from those tools;
  per-subproject toolchains would need per-subproject lock sections and are not
  in this design.
- **A committed toolchain lock can aim a request at any allowlisted provider
  host (WP2 design boundary).** Honoring a lock deliberately does not consult
  the shipped catalog, so that upgrading blanket can never invalidate a
  committed lock. Bytes are still authorized by the recorded
  algorithm-qualified digest and the URL by an append-only provider host
  allowlist, so a hostile lock cannot install unverified content — but it can
  cause an HTTPS request to a different allowlisted host, which an attacker
  positioned there can observe. Reviewing a lock diff is reviewing its URLs.
- **`blanket add` / `remove` / `update` delegate to store tools with
  network, unsandboxed** (uv, the store npm, cargo, go, bundler, mix) — the
  same trust boundary as missing-lockfile generation. Rows that refuse with
  instructions instead of editing: Poetry and PDM projects, pnpm and yarn
  lockfiles, setup.py/setup.cfg, `requirements/` directories, Elixir add and
  remove, and all of .NET. The registry existence check for an ambiguous
  bare name in a polyglot directory is one HTTPS GET per candidate
  registry; a private-registry name needs the explicit prefix.
- **`blanket x` covers PyPI and npm** (cargo and go later). Each tool's
  environment lives under `~/.blanket/x/` as a registered project root;
  `blanket x --clean` removes the projection and unregisters it from the
  originating store, while the immutable store object remains until the next
  `blanket gc`. A removed **node** environment also orphans its
  `~/.blanket/forests/<project-key>/<projection-id>` node_modules forest,
  which plain `blanket gc` never visits: only `blanket gc --project` reclaims
  it, and the cleanup summary says so. A permanent per-root lock under
  `~/.blanket/x/.locks/` protects running tools, including roots being
  recreated after cleanup; a successful removal unlinks its own lock file
  while still holding it, so `.locks` stays bounded. Partial roots are marked
  `realizing` before work starts and are cleanable. Cleanup requires an
  absolute `HOME` and accepts exactly the layouts `blanket x` itself accepts:
  `$HOME` and `~/.blanket` may be symlinks (the cache can live on another
  volume) and are resolved once, while a symlinked or non-directory
  `~/.blanket/x` is refused by both commands. Cleanup skips all dot-prefixed
  entries, so the permanent lock directory cannot be mistaken for an
  environment. Legacy
  roots without `x.json` are matched by exact package recovered from their
  generated manifest; an ecosystem-only filter may use only the recovered
  manifest or the generated `py-`/`npm-` prefix as ecosystem evidence, never
  as package evidence. Unrecoverable roots are skipped with a hint to run
  `blanket x --clean` without a tool; a skipped root still counts as
  considered, so such a run reports `removed 0 environment(s), skipped N`
  rather than `nothing to clean`, and still exits 0.
- **`x` cleanup is conservative under a concurrent rename**: removal is
  descriptor-relative and never follows a symlink, but if a candidate name is
  replaced while it is being removed, the replacement is left for a later
  cleanup retry and the original registry entry is retained.
- **Two platforms: macOS arm64 and Linux x86_64 (glibc).** Linux landed
  2026-09-05 (LINUX_PORT.md). Not pinned: Intel macOS, aarch64 Linux,
  musl/Alpine — each is a row per pin table plus a wheel-tag band, not a
  port. Linux verified on Fedora 44 only; other glibc distros untested.
- **Linux host C toolchain is an unpinned build input** (gcc, binutils,
  glibc headers, and for nokogiri host zlib) — the exact analogue of the
  Xcode item below. Two Linux hosts with different gcc/glibc can produce
  different "identical" objects. Host packages required for native
  builds on Fedora: `gcc gcc-c++ make binutils glibc-devel
  pkgconf-pkg-config patch zlib-ng-compat-devel libxcrypt-devel`.
  Pinning a C toolchain as a store object is the roadmap item that
  closes this for both platforms.
- **Pinned native library objects are store-root-specific**: `native-libs/libset/3`
  relocates absolute object paths into binaries/configuration and therefore
  includes the canonical `BLANKET_STORE` root in its identity. Moving a store
  requires re-realizing the libset (and its dependent builds), not copying the
  object under the old id. The wrapper, relocation, and identity corrections
  are the v2 -> v3 bump.
- **Linux sandbox roots are canonical paths.** bubblewrap binds the
  canonicalized path of every declared root; a caller that declares a
  symlink alias and then refers to files through the alias will not see
  them (Seatbelt resolves aliases itself). Every tailor passes store or
  scratch paths, which are canonical; the contract only matters for new
  callers of `Sandbox`/`BuildSpec`. An undeclared cwd is an empty tmpfs.
- **Linux sandbox (bubblewrap) is cooperative hermeticity too**: a Unix
  socket inside an immutable read root (store object) is not scanned for
  (write roots, cwd and scratch are, and are rejected pre-mount); a
  daemon started by a build can outlive it. Same class as Seatbelt.
- **Our own OTP artifact for Linux** (blanket-toolchains release): built
  on Fedora 44, glibc floor 2.43, dynamically linked to the host
  `libcrypto.so.3`. It will not run on older glibc hosts; a static-OpenSSL
  build on an older baseline is the fix. Provenance is published but the
  trust model is still TOFU.
- **Source-built native gems/addons link host libraries** (e.g. nokogiri
  → `libz.so.1`); recorded, not pinned.
- **Copy-on-write projection falls back to a full copy** on filesystems
  without reflink (ext4); XFS/btrfs get `cp --reflink`. Silent, slower.
- **Store objects are trusted from permissions + metadata** (Sol, ruby
  review): same-user replacement of object contents after commit is
  undetected. Needs content spot-verification or an explicitly narrower
  documented trust boundary.
- **TOFU pins everywhere**: CPython, Node, Rust, Go, portable-ruby, uv
  hashes were computed at pin time, not from signed manifests. Signed
  provider manifests are the fix (Rust/Go publish signatures/official
  JSON we already partially use).
- **Sandbox is cooperative hermeticity, not hostile-code containment**:
  mach-lookup broad, process-exec broad, daemons can outlive scripts,
  same-realization packages only partially isolated. Documented since M4.5.
- **Host Xcode/clang/SDK is an unpinned build input** (macOS) for every
  native compile (python sdists, npm gyp, cgo, ruby extconf). Not in
  build identity; two machines with different Xcodes can produce
  different "identical" objects. A pinned toolchain would close this.
- **Delegated planning runs unsandboxed with user privileges** (uv, npm,
  cargo generate-lockfile, go mod tidy/download, bundle lock, Gemfile
  eval). Status-quo trust, deliberate — but a hostile manifest executes
  code at PLAN time. Fails silent (it's the design).
- **Project-side plan caches for go/python lack contained atomic writes**
  (ruby's was removed entirely); a symlinked .blanket could redirect a
  cache write outside the project.
- **Reproducibility is asserted, not measured**: no rebuild-twice-and-
  compare checks (the last unimplemented item from Sol's original list).
- **xcrun cache-write warnings** inside every sandboxed native build
  (cosmetic; build succeeds).
- **No streaming extractors**: decompression bombs are caught by
  post-extraction size caps, not preflight limits.
- **Only the Go toolchain tarball goes through the pre-materialization
  extractor** (`src/archive.rs`: hostile members refused before tar writes;
  `TAR_OPTIONS` unset, `LC_ALL`/`LANG` pinned to `C`, `--numeric-owner` on
  every invocation). CPython, Node, Rust/rustfmt, Ruby, .NET, Elixir/OTP,
  and native-library tarballs still rely on the platform tar's own defences
  until their call sites migrate in the WP2 lock PRs. **The `-tv` listing is
  parsed by column position**, which is a human format blanket predicts from
  the platform (5 leading columns for GNU tar, 8 for bsdtar). Owner and group
  names come out of the archive, so `--numeric-owner` is a parsing guarantee
  rather than a cosmetic one: a name containing a space would otherwise add
  columns and shift the date into the parsed name, walking a `../` member
  past the containment check. Every listing is additionally cross-checked
  against a column-free `tar -t`, and any disagreement refuses the archive,
  so an unmodelled column layout fails closed instead of silently
  mis-parsing. Containment is decided lexically, which is only sound while
  lexical resolution agrees with the filesystem's, so a symlink target that
  would resolve *through* another symlink in the same archive is refused, as
  is any member whose own path passes through one. Parsing a human-readable
  listing by column remains a fragile foundation; reading tar headers
  directly is the intended replacement before a second consumer adopts this
  module. The bsdtar column count has been verified against libarchive
  3.8.7 on Linux; macOS ships an older bsdtar, so the Mac gate is still what
  confirms it there.

## Python

Interpreter selection is limited to the five pinned CPython builds for the
two supported host platforms. A canonical two-part `.python-version` request
selects the newest pinned patch for that minor; a canonical three-part request
must match a pinned build exactly and otherwise fails closed with the
available pins and the command to accept the pinned patch. Noncanonical
release spellings, unsupported implementations, and unsatisfiable constraints
fail closed. Explicit requests still win over metadata conflicts with a
warning. An explicit CPython prefix (`python3.12`, `cpython-3.12`,
`cpython@3.12`) is accepted as the same request and stays accepted under WP2.
The narrower WP2 request grammar — exact `X.Y.Z`, minor `X.Y`, or a restricted
PEP 440 specifier set, each resolved against the catalog once and then locked,
with non-CPython implementations, variants, paths, and executables refused —
is design-only until lock activation.

- **Pin-table row order is not a selection contract**: minor requests choose
  the newest numeric patch regardless of row ordering; both orders are covered
  by unit tests. The table remains static until the release-catalog work
  replaces it.

Manifest discovery covers Poetry/PDM/uv/hatch metadata, Poetry/uv lockfile
hashes, setup.cfg, sandboxed setup.py egg_info, and requirements directories.
It reports `no_manifest` when no Python input exists, treats an empty found
manifest as a successful interpreter-only environment, and reports
`unreadable_manifest` for a found file that cannot be parsed or whose
sandboxed metadata probe fails. Optional/development groups and private index
configuration are recorded or skipped rather than silently trusted. setup.py
remains a cooperative metadata execution boundary inside the existing
sandbox, and uv fallback still delegates resolution.

- **RECORD files are left as shipped**: not verified on install, not
  rewritten; importlib file listings can lie. Silent. Wheel `.data`
  `purelib`, `platlib`, `headers`, `scripts`, and `data` schemes are routed.
- **Project-local/editable and direct Python requirements are skipped** with
  exception `requirement-skipped`; strict via policy. Other malformed
  requirements still fail closed.
- **Sdists with dynamic build requirements** (PEP 517
  `get_requires_for_build_wheel`) are unsupported because inspection is
  deliberately non-executing. Static PEP 517 backends including hatchling,
  flit, and setuptools-rust are supported when their declared requirements
  resolve. Loud.
- **`setup_requires` in legacy `setup.py` is not handled**: pip would need
  network access to discover/install it, which is denied in the build
  sandbox. This is the explicit item-11 boundary; declare the dependency in
  `pyproject.toml` instead. Loud.
- **Rust sdists without a shipped `Cargo.lock`** use a store-Cargo-generated
  lock in the scratch source and record `unattested_cargo_lock`; strict policy
  rejects that exception.
- **Immutable venvs are not drop-in venvs**: no activate scripts; pip
  can't mutate them (by design, but surprises tooling that shells out to
  pip). Loud-ish.
- **No bytecode precompilation**: read-only site-packages +
  PYTHONDONTWRITEBYTECODE = slower cold starts.
- **macOS deployment-target wheel tags not compared** at selection.
  Theoretical silent wrong-wheel risk.
- **Environment markers/extras in a pinned file trigger a full re-lock
  via uv** rather than direct consumption (universal locks get
  platform-re-locked; versions can shift). Semi-silent.
- **Project-level `uv pip compile` in `src/main.rs` can still execute
  resolve-time metadata builds outside the sandbox.** This pre-existing
  exposure is tracked separately; sdist build-requirement resolution now
  rejects build-time sdists instead.

## JavaScript / npm

- **Workspace-local node_modules are supported for imported pnpm, Yarn
  classic, and npm v7+ lockfiles**, including conflicting versions. The
  projection keeps the importer set outside the project under the forest;
  unsupported local sources still fail closed. Loud.
- **Git sources are realized only when pinned to a full commit** (NEXT.md
  item 4). A lockfile entry naming a 40-character commit — `git+https`,
  `git+ssh`, a GitHub codeload/archive tarball, or a pnpm `{repo, commit}`
  resolution — is fetched by that commit, stripped of `.git`, and stored as a
  `git-source/2` object whose identity includes the normalized URL and commit.
  Explicit Git sources use commit verification; codeload/archive URLs with
  supplied integrity retain tarball verification across npm, pnpm and Yarn.
  Checkout blobs and recursive submodule pins are checked before publication;
  attribute-transformed content, escaping symlinks and symlink cycles fail
  closed. Ambient Git configuration is disabled, so custom credential helpers,
  URL rewrites and Git proxy settings are unavailable (SSH agents remain usable).
  A branch, tag or
  bare repository URL still fails closed as `npm_git_dep`, because the bytes
  it names can change. npm runs a git dependency's `prepare` script; blanket
  does not (it is unsandboxed build logic with its own dependency needs) and
  records `git-dependency` naming the package. Python and Cargo git dependencies work the
  same way: a python `pkg @ git+URL@<commit>` checkout is packed into a
  deterministic sdist and built through the ordinary sdist path, and a cargo
  `git+…#<commit>` source is vendored as a directory source whose Git source
  object id is an identity input. Cargo git dependencies are NOT re-verified against the
  project's Cargo.lock at `blanket run` time: the config stanzas are rebuilt
  from that lock, so a lock edited after a sync is caught by cargo, not by
  blanket. Local `file:` links are projected when
  the lock records their project-relative target.
- **Install scripts that need network for LOGIC** (not just artifacts) are
  permissive with exception `install-script-failed`; strict via policy.
  Declared-artifacts only covers downloads whose cache location matches the
  declaration (sharp-style). Electron-class packages need per-version
  artifact declarations.
- **Skipped install-time downloads are not in the closure** (NEXT.md item 5):
  packages with a documented switch (puppeteer, cypress) are installed without
  their browser or binary and record `artifact_not_provisioned` naming the
  command that fetches it. `blanket run` works; the missing artifact does not
  appear until the user runs that command, and it is not verified by blanket
  when they do. Loud, per package.
- **Prebuilt binaries are compiled instead of downloaded** where the installer
  supports it (prebuild-install, node-pre-gyp), recorded as
  `built_from_source`. The result is built from the package's own sources in
  the sandbox rather than the upstream binary, so it can differ from what npm
  would have installed — and it fails if the compile needs headers the pinned
  native library set does not carry.
- **Wheels shipping the same file path** are permissive with exception
  `file-collision`; the later deterministic wheel wins. Strict via policy.
- **SHA-1 npm integrity** is permissive with exception `weak-integrity`;
  the tarball is still verified. Strict via policy.
- **Lifecycle scripts run in lockfile order, not dependency order**. Their
  nearest importer `.bin` directory is first on PATH, followed by the root
  `.bin`; deeper package-local `.bin` directories are not separately built.
  Rarely bites; silent when it does.
- **npm optional-dependency failure parity is permissive with exception
  `install-script-failed`**; the extracted package is retained. Strict via
  policy.
- **Process-tree quiescence after scripts not enforced** (a daemon
  started by postinstall can outlive realization).
- **Yarn Berry is not imported**: its cache-zip checksums are not tarball
  integrity values, so item 7 rejects it loudly and names the npm/pnpm
  conversion path. pnpm/yarn classic imports discover `bin` and legacy
  `directories.bin` entries from each extracted package.json before launcher
  generation. Lockfile-less projects still fall back to npm resolution.

## Rust / cargo

- **Pinned Git dependencies work for standalone crates.** Crate selection
  matches the locked name and version. Workspace-inherited manifests and
  symlinks escaping the copied crate fail closed before publication; workspace
  metadata is not yet rewritten into standalone vendor manifests.
- **Alternative registries fail closed.** Loud.
- **Extra rust-toolchain components** are permissive with exception
  `toolchain-component-unavailable`; strict via policy.
- **`cargo install` through the wrapper is unmanaged**: lands in
  .blanket/cargo-home/bin outside the closure. Silent gap, documented.
- **Host Xcode/SDK not in build identity** (kernel-wide item; bites
  -sys crates hardest).
- **`blanket build` covers `build` only** — no sandboxed test/clippy/doc
  invocations yet; those run via `blanket run cargo ...` offline but
  unsandboxed.
- **beta/nightly/custom toolchains and non-arm64 targets fail closed**
  (single-pin table). Loud.
- **target/ is unmanaged scratch**: no shared build cache, no
  derivation-level caching (correct v0 boundary per Sol, still a gap).

## Go

- **One exact Go pin is realizable per supported platform.** A `go.mod`
  selection without a matching `(platform, version)` row fails before store
  or network access and tells the user to use a pinned version or add a
  verified row; the regression coverage also guards the rejection against a
  cached-default fallback. Archive extraction and a release catalog with
  additional Go pins remain future work.
- **Current Go selection treats a non-default `toolchain` directive as a
  lower-bound suggestion and chooses the lowest pin satisfying it and `go`**;
  a newer catalog row can therefore replace an exact upstream directive until
  the WP2 selection implementation makes non-default `toolchain goX.Y.Z` exact.
  The design change is not implemented yet.
- **go.work workspaces fail closed** (including ancestor detection).
  Loud.
- **Local-path replace directives fail closed.** Loud.
- **Graph-only modules are excluded from the closure** (correct for
  builds; means `blanket run go mod graph`-style introspection may want
  modules the modcache lacks → GOPROXY=off errors). Semi-loud.
- **Private modules unsupported**: GOPROXY forced to proxy.golang.org,
  GOVCS=*:off, GOPRIVATE scrubbed. Loud for private-repo users.
- **Planner runs `go mod tidy` on out-of-sync manifests automatically**
  — mutates the user's go.mod/go.sum as a named resolver step (uv/cargo
  precedent, but more aggressive than some users expect).
- **`blanket build` stages outputs then moves them**: `-o`-dependent
  workflows and multi-binary expectations differ subtly from plain
  `go build`. -mod/-toolexec/-o etc. rejected (deliberate).
- **Plan-cache key includes only *.go sources**: go:embed content and
  non-.go inputs don't invalidate the cached plan (tidy itself doesn't
  care, but exotic cases could). Silent, narrow.

## Ruby

- **git and path gems fail closed; non-rubygems.org sources fail
  closed.** Loud.
- **Gems whose installers need network or absent host libraries fail
  closed** (mysql2/rmagick/charlock_holmes-class; legacy libv8). No
  declared-artifacts mechanism for gems yet. Loud.
- **Default/bundled-gem preactivation edge**: a locked json/psych/openssl
  older than the toolchain's default can Gem::LoadError if something
  activates the default before Bundler setup. Untested matrix (Sol
  flagged; conflict tests still owed). Potentially silent.
- **`bundle exec` compatibility unproven** — env-based GEM_HOME
  activation works for `blanket run ruby/rake`; full bundler runtime
  activation against the frozen lock hasn't been exercised on a real
  Rails-class app.
- **System /etc/gemrc still read** (GEMRC=/dev/null blocks only the
  user file). Narrow, silent.
- **Portable-ruby is a Homebrew-internal artifact**: third-party
  embedding is explicitly not their project goal; its pkg-config carries
  build prefixes. Relocation works today (probed) but is not a contract.
  Also: newest portable build (3.4.6) trails ruby-lang stable (3.4.10
  security fixes in bundled gems).
- **CHECKSUMS-section locks fail closed if bundler's checksum registry
  API drifts** (deliberate fail-closed, but means new bundler formats
  need code updates).

## Elixir

- **Two OTP steps run outside the sandbox on Linux**: the `Install -cross
  -minimal` relocation of the extracted OTP tree and the OTP runtime
  probe (`src/elixir.rs`) run as direct children with a clean env. They
  only touch the staged store object, but they are the one non-sandboxed
  build step in the kernel.
- **OTP cache hits skip the runtime-compatibility probe.** The Linux OTP
  object was built on Fedora 44 (glibc 2.43 floor, OpenSSL 3.x; see the
  provenance file in `DigitalWestern/blanket-toolchains`); a store copied
  to a host with an older glibc or a different OpenSSL ABI fails only at
  execution time, not at `sync`. The probe runs on first realization
  only. Loud, but late.
- **git deps and non-hexpm repos fail closed.** Loud.
- **Umbrella projects untested** — likely partially working, deliberately
  unverified; treat as unsupported until the test matrix exists. Silent
  risk if attempted.
- **Legacy mix.lock entry shapes (3/6/7-field) fail closed** with a
  "refresh the lock" message. Loud.
- **No rebar3 build for OTP 29 published yet**: the pinned otp-28
  escript runs on the 29 VM (BEAM forward-compat) — works, but is a
  version-skew impurity until upstream publishes otp-29 builds.
- **Mix's compilation lock is disabled in-sandbox**
  (MIX_OS_CONCURRENCY_LOCK=false; it needs loopback TCP): concurrent
  unsandboxed `blanket run mix compile` against the same build root is
  unprotected. Narrow.
- **`blanket build` runs MIX_ENV=dev only**; test/prod builds go through
  `blanket run mix` (offline-configured, unsandboxed).
- **Hex/OTP/Elixir version matrix is single-pin**: .tool-versions and
  mix.exs elixir requirements are not consulted. Loud only when a build
  fails.
- **deps projection is whole-tree writable** (native builds write
  in-tree): one dep's build can modify a sibling dep in the projection —
  cooperative hermeticity, same class as npm's clone mode. Recorded
  unattested in the closure.

## .NET

- **Strictest v0 boundary of any tailor** (all loud): one SDK-style
  .csproj only; no solutions/.sln, no ProjectReference lock entries, no
  Central Package Management (lock v2/v3), no packages.config, no
  PackageDownload (targeting/runtime packs must ship in the pinned SDK),
  no workloads, no custom MSBuild SDKs, nuget.org only.
- **Build-capable dotnet verbs refused at `blanket run`** — stricter
  than other tailors; everything compiling goes through `blanket build
  dotnet`. Deliberate (MSBuild executes arbitrary code), but a UX cliff
  for `dotnet test`/`dotnet run` habits; `blanket build dotnet` covers
  build only (no test/publish verbs yet). The run guard is advisory, not a
  security boundary: wrappers such as `sh -c` can bypass it. During
  realization and build, blanket never evaluates project code outside the
  network-denied build sandbox; missing-lock lock generation is the explicit
  host-side exception.
- **Restore-time MSBuild evaluation is delegated-planning trust** (props/
  targets/property functions run unsandboxed during missing-lock generation).
  The NuGet config and environment are pinned/cleared, but project MSBuild
  code still runs on the host; only generate locks with sync for projects
  trusted enough to run during lock generation. Same class as other resolvers,
  with more code surface.
- **Ancestor SDK inputs fail closed**: global.json above the project,
  Directory.Packages.props, Directory.Build.rsp, and packages.config in the
  project or any ancestor are rejected, even when the file is not in the
  project directory.
- **Preflight is a fail-closed text scan, not an XML parse** (accepted
  trade-off): banned MSBuild constructs are rejected by name scanning, so
  exotic-but-legitimate projects can be refused; nothing banned can hide,
  because XML cannot entity-encode element/attribute names. Full MSBuild
  semantics are only known to MSBuild itself, which is why the build
  sandbox — not preflight — is the actual security boundary.
- **Output publication has a microsecond non-atomic window** (accepted
  trade-off): the old bin/blanket-<fp> is renamed aside before the new one
  is renamed in; a reader in that window sees no output. True atomic swap
  needs macOS renamex_np(RENAME_SWAP) via libc. The last good build always
  survives a failed publication.
- **Machine-wide /tmp/.dotnet mutex dir is a sandbox write allowance**
  (bounded, local-only; still shared mutable state between sandboxed and
  host dotnet processes). blanket pre-creates its `shm` subdirectory on
  both platforms because CoreCLR otherwise mkdtemp()s in `/tmp` itself,
  which neither sandbox permits; macOS purges `/private/tmp`, so the
  directory is re-created on every sync rather than assumed present.
- **releases.json is a checksum channel, not signed metadata** — SDK
  pins are only as strong as HTTPS to Microsoft's CDN.
- **Lock does not cover asset selection**: project.assets.json is
  re-derived per build and attested but not diffed against expectations;
  a NuGet behavior change across SDK pins changes builds under the same
  lock (SDK is in identity, so objects differ — but silently).

## Real-project proof gaps (all ecosystems)

- Python/npm were proven on Ethan's real projects (CX-Games, deja,
  Financial-Filing…). Cargo was proven on blanket itself. **Go and Ruby
  have only been proven on small synthetic-but-real-dependency projects**
  (cobra/toml; rake/racc/nokogiri) — no large real-world Go service or
  Rails app has run under blanket yet.

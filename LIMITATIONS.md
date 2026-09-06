# Blanket limitations ledger

A standing, honest record of what blanket fails to address or doesn't get
right, per ecosystem and kernel-wide. Items graduate OFF this list only
when fixed and regression-tested. Started 2026-08-31. When adding items,
say what breaks, for whom, and how it fails (loud/silent).

## Kernel-wide

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
- **No GC** (`blanket gc` unbuilt): store, forests, backups, and the
  planner-modcache grow forever.
- **Reproducibility is asserted, not measured**: no rebuild-twice-and-
  compare checks (the last unimplemented item from Sol's original list).
- **xcrun cache-write warnings** inside every sandboxed native build
  (cosmetic; build succeeds).
- **No streaming extractors**: decompression bombs are caught by
  post-extraction size caps, not preflight limits.

## Python

- **RECORD files are left as shipped**: not verified on install, not
  rewritten; importlib file listings can lie. Silent.
- **Project-local/editable and direct Python requirements are skipped** with
  exception `requirement-skipped`; strict via policy. Other malformed
  requirements still fail closed.
- **Sdists with dynamic build requirements** (PEP 517 get_requires jobs)
  unsupported; setuptools-family only. Loud.
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

## JavaScript / npm

- **Nested per-workspace node_modules rejected** (version conflicts
  inside workspaces need hoisting). Loud with hint.
- **git:// and file:// `resolved` URLs fail closed.** Loud.
- **Install scripts that need network for LOGIC** (not just artifacts) are
  permissive with exception `install-script-failed`; strict via policy.
  Declared-artifacts only covers downloads whose cache location matches the
  declaration (sharp-style). Electron-class packages need per-version
  artifact declarations.
- **Wheels shipping the same file path** are permissive with exception
  `file-collision`; the later deterministic wheel wins. Strict via policy.
- **SHA-1 npm integrity** is permissive with exception `weak-integrity`;
  the tarball is still verified. Strict via policy.
- **Lifecycle scripts run in lockfile order, not dependency order**, and
  ancestor .bin dirs aren't on script PATH (Sol review 3 leftover).
  Rarely bites; silent when it does.
- **npm optional-dependency failure parity is permissive with exception
  `install-script-failed`**; the extracted package is retained. Strict via
  policy.
- **Process-tree quiescence after scripts not enforced** (a daemon
  started by postinstall can outlive realization).
- **bun/yarn/pnpm lockfiles are re-resolved via npm** — versions may
  differ from the original lock. Loud note printed, but versions shift.

## Rust / cargo

- **git dependencies fail closed.** Loud.
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
  host dotnet processes).
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

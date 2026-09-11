# Blanket limitations ledger

A standing, honest record of what blanket fails to address or does not get
right. Items leave this list only when fixed and regression-tested. Each
entry says what breaks, for whom, and whether it fails loud or silent.

Platforms: macOS arm64 and Linux x86_64 (glibc). All GC-safety work
(Packages A–D, merged 2026-09-10) was validated on Linux only — **no macOS
validation since**. Linux claims are verified on Fedora 44; other glibc
distros are untested. Intel macOS, aarch64 Linux, and musl/Alpine are
unported (a pin-table row plus a wheel-tag band each, not a port).

## Kernel-wide

- **`blanket fmt` is Rust-only**; other ecosystems fail clearly (pinned rustfmt 1.96.1, no
  `Cargo.lock`; `status` ignores the rustfmt closure; a sync rustfmt request still records
  `toolchain-component-unavailable` while `fmt` realizes it on demand).
- **GC is conservative around legacy state.** Store jobs hold a shared activity lease; GC
  skips while work is active (older binaries do not know the protocol). `root/2` records
  survive moves, but legacy pathname-only roots and unresolved metadata block the sweep — an
  unreadable registry record blocks it too, and `blanket gc --forget <key>` is the give-up
  valve.
- **The GC safety guarantee has a stated boundary.** It covers cooperating blanket processes
  on a local filesystem with working locks and atomic rename. Not covered: older binaries;
  programs run directly from store paths; malicious same-user modification; descendants
  outliving the awaited child; orphans after SIGKILL of the supervising blanket; network
  filesystems, where `flock` is advisory in name only.
- **Signal delivery has three edges.** Parent-directed TERM is forwarded to the direct child;
  a group-directed TERM reaches parent and child independently and is forwarded too
  (at-least-once). Parent-only INT/QUIT/HUP are caught and waited on after startup, not
  forwarded — terminal process-group delivery (`^C`) is the supported path. A cancellation
  across the spawn boundary is never dropped. `128 + signal` is a shell-visible exit code, not
  a wait status.
- **CLI exit status is 0 / 1 / 2** (success / command failed / usage error); `run`, `x` and
  `fmt` pass the program's status through. A literal `-h` tool argument needs `--` first.
- **`blanket status` compares recorded inputs only.** `-r` includes, `requirements/` members,
  and workspace-member package.json are not recorded. Cargo/Ruby/Elixir/.NET compare the lock
  hash only; Go catches `require`/`replace` only via `go.sum`; pre-field closures show "synced
  (unchecked)".
- **There is no committed toolchain lock yet (WP2 design only).**
  `.node-version`/`.ruby-version`/`.tool-versions` are not consulted; Node, Ruby and Elixir
  are single-pin. The catalog/digest machinery (WP2) is design-only
  (`docs/agent/PLAN-2026-09-09.md`), and the
  generic fetch helper still accepts `file://` — the dormant lock cannot authorize that path.
- **One toolchain per lock root**: discovery is anchored at the lock root, so
  `web/.node-version` is invisible to blanket. A committed lock can aim at any allowlisted
  provider host; a hostile lock can cause an HTTPS request to a different allowlisted host.
  Reviewing a lock diff is reviewing its URLs.
- **`add` / `remove` / `update` delegate to store tools with network, unsandboxed** (uv, npm,
  pnpm, cargo, go, bundler, mix) — the same trust boundary as missing-lockfile generation.
  Refusal rows: Poetry/PDM, setup.py, `requirements/` dirs, Elixir add/remove, Yarn, .NET.
- **pnpm edits require a root `packageManager` field** with an exact pinned version.
  Membership is the `pnpm-lock.yaml` `importers` list and nothing else. **A member added since
  the last `pnpm install` is not in the lock and cannot be distinguished from a deliberate
  exclusion**, so edits refuse loudly with two remedies: `pnpm install` at the root, or a
  `.blanket` directory in it.
- **Yarn classic edits remain a refusal** (no lockfile-only edit mode); run the Yarn command
  blanket names. Yarn Berry is not imported (cache-zip checksums are not tarball integrity
  values).
- **`blanket x` covers PyPI and npm**. A removed *node* environment orphans its node_modules
  forest under `<store>/forests/`, which plain `blanket gc` never visits: only `blanket gc
  --project` reclaims it. Cleanup skips candidates whose originating store cannot be
  recovered.
- **Automatic metadata migration is fail-closed.** A pre-`object-meta/2` store is upgraded in
  place only where a per-kind, per-schema adapter can reconstruct the dependency set; one
  unresolved record blocks every sweep. Records that will not migrate — collected inputs,
  ambiguous matches, vanished pin tables — need a rebuild under the current producer; the
  store keeps its pre-D retention.
- **`cargo test -- --ignored` must run single-threaded**: the supervisor owns process-wide
  signal dispositions and rejects a second concurrent child (`--test-threads=1`; the offline
  suite holds `SUPERVISION_TEST_LOCK`).
- **Unpinned host build inputs.** The Linux host C toolchain (gcc, glibc headers, host zlib)
  and the macOS Xcode/clang/SDK are not in build identity — two hosts can produce different
  "identical" objects. The Linux OTP artifact needs glibc 2.43 and host `libcrypto.so.3`;
  source-built gems/addons link host libraries.
- **Pinned native-library objects are store-root-specific**: `native-libs/libset/3` includes
  the canonical `BLANKET_STORE` root in its identity; moving a store requires re-realizing the
  libset. **Linux sandbox roots are canonical paths** (a symlink alias root is invisible).
  Both matter only to new callers.
- **Sandboxes are cooperative hermeticity, not hostile-code containment.** bubblewrap does not
  scan immutable read roots for Unix sockets (the fmt host-socket scan is Linux-only); build
  daemons can outlive a run. **Store objects are trusted from permissions + metadata, and all
  toolchain pins are TOFU** (pin-time hashes, not signed manifests): same-user content
  replacement after commit is undetected.
- **Delegated planning runs unsandboxed with user privileges** (uv, npm, cargo, go, bundler):
  a hostile manifest executes code at PLAN time. **Plan caches for go/python lack contained
  atomic writes**: a symlinked `.blanket` could redirect a cache write outside the project.
- **Only the Go toolchain tarball goes through the pre-materialization extractor**; CPython,
  Node, Rust, Ruby, .NET, Elixir/OTP and native-library tarballs still rely on the platform
  tar's own defences. The `-tv` listing is parsed by column position; a column-free `tar -t`
  cross-check fails closed on unmodelled layouts. Reading tar headers directly is the intended
  replacement; bsdtar columns are verified against libarchive 3.8.7 on Linux, and the Mac gate
  confirms them there.

## Python

Selection covers the five pinned CPython builds per platform. A two-part `.python-version`
  picks the newest pinned patch for the minor; a three-part request must match a pin
  exactly.
- **RECORD files are left as shipped**: not verified on install; importlib listings can lie;
  project-local/editable and direct requirements are skipped (`requirement-skipped`). **Sdists
  with dynamic build requirements** (PEP 517 `get_requires_for_build_wheel`) are unsupported —
  inspection is non-executing. Static backends are supported; `setup_requires` in legacy
  setup.py is unhandled — declare it in `pyproject.toml`. Rust sdists without a shipped
  `Cargo.lock` get a store-Cargo lock recorded `unattested_cargo_lock`.
- **Immutable venvs are not drop-in venvs**: no activate scripts, and pip cannot mutate them.
  No bytecode precompilation — slower cold starts.
- **macOS deployment-target wheel tags are not compared** — theoretical silent wrong-wheel
  risk. Markers/extras in a pinned file trigger a full uv re-lock; versions can shift.
  **Project-level `uv pip compile` in `src/main.rs` can still execute resolve-time metadata
  builds outside the sandbox** — sdist build-requirement resolution rejects build-time sdists
  instead.

## JavaScript / npm

- **Install scripts needing network for logic** are permissive with `install-script-failed`
  (declared-artifacts covers only matching cache locations; Electron-class needs per-version
  declarations). **Git sources are realized only when pinned to a full commit.**
  Branch/tag/bare URLs and ambient Git config fail closed. npm runs a git dep's `prepare`
  script; blanket does not. Python and Cargo git deps work the same way, but Cargo's are not
  re-verified against the project's Cargo.lock at `run` — a post-sync lock edit is caught by
  cargo, not blanket.
- **Skipped install-time downloads are not in the closure**: puppeteer- and cypress-class
  packages record `artifact_not_provisioned`, fetched unverified only when the user runs that
  command.
- **Prebuilt binaries are compiled instead of downloaded; the result can differ from what npm
  would install. Wheel file-path collisions (`file-collision`) and SHA-1 npm integrity
  (`weak-integrity`) are permissive; strict via policy. Lifecycle scripts run in lockfile
  order, not dependency order (rarely bites, silent), and process-tree quiescence is not
  enforced: a postinstall daemon can outlive realization.

## Rust / cargo

- **Pinned Git dependencies work for standalone crates**; workspace-inherited manifests and
  escaping symlinks fail closed, and workspace metadata is not rewritten into vendor
  manifests. **Fail-closed rows**: alternative registries; beta/nightly/custom toolchains and
  non-arm64 targets. Loud.
- **Extra rust-toolchain components** are permissive with `toolchain-component-unavailable`.
  **`blanket build` covers `build` only** — no sandboxed test/clippy/doc; those run via
  `blanket run cargo ...` offline but unsandboxed. target/ is unmanaged scratch (no shared
  build cache). **`cargo install` through the wrapper is unmanaged** (lands in
  `.blanket/cargo-home/bin`, outside the closure).

## Go

- **One exact Go pin is realizable per supported platform.** An unmatched `go.mod` selection
  fails before store or network access. A non-default `toolchain` directive is a lower-bound
  suggestion: the lowest satisfying pin wins, so a newer catalog row can replace an exact
  upstream directive. **Fail-closed rows**: go.work workspaces (including ancestor detection);
  local-path replace directives. Loud.
- **Graph-only modules are excluded from the closure**, so modgraph introspection can hit
  GOPROXY=off errors. **Private modules are unsupported**: GOPROXY forced to proxy.golang.org,
  GOVCS off, GOPRIVATE scrubbed.
- **The planner runs `go mod tidy` on out-of-sync manifests automatically**, mutating
  go.mod/go.sum. **`blanket build` stages outputs then moves them**: `-o`-dependent workflows
  differ from plain `go build`; `-mod`/`-toolexec`/`-o` are rejected. The plan-cache key
  includes only `*.go` sources — go:embed and non-.go inputs do not invalidate it.

## Ruby

- **git and path gems fail closed; non-rubygems.org sources fail closed.** So do gems whose
  installers need network or absent host libraries (mysql2/rmagick-class) — no
  declared-artifacts mechanism for gems yet. **Default/bundled-gem preactivation edge**: a
  locked json/psych/openssl older than the toolchain's default can Gem::LoadError if something
  activates the default before Bundler setup. Untested matrix; potentially silent.
- **`bundle exec` compatibility is unproven**: env-based GEM_HOME activation works for
  `blanket run ruby/rake`; full bundler runtime activation has not been exercised on a real
  Rails-class app.
- **System /etc/gemrc is still read** (GEMRC=/dev/null blocks only the user file).
  **Portable-ruby is a Homebrew-internal artifact**: relocation is probed to work but is not a
  contract, and its newest build (3.4.6) trails ruby-lang stable (3.4.10 security fixes in
  bundled gems). **CHECKSUMS-section locks fail closed if bundler's checksum registry API
  drifts**; new bundler formats need code updates.

## Elixir

- **Two OTP steps run outside the sandbox on Linux**: the `Install -cross -minimal` relocation
  and the OTP runtime probe (`src/elixir.rs`). They touch only the staged object — the one
  non-sandboxed build step in the kernel. **OTP cache hits skip the runtime probe**: the OTP
  object was built on Fedora 44 (glibc 2.43 floor, OpenSSL 3.x); a store copied to an
  incompatible host fails only at execution time. Loud, but late.
- **Fail-closed rows**: git deps; non-hexpm repos; legacy mix.lock entry shapes (3/6/7-field —
  "refresh the lock"). **Umbrella projects are untested**. **No rebar3 build for OTP 29 exists
  yet**: the pinned otp-28 escript runs on the 29 VM — a version-skew impurity until upstream
  ships otp-29 builds. **Mix's compilation lock is disabled in-sandbox**, so concurrent
  unsandboxed `mix compile` against one build root is unprotected; `blanket build` runs
  MIX_ENV=dev only. **The Hex/OTP/Elixir matrix is single-pin** (`.tool-versions` and mix.exs
  elixir requirements are not consulted). **The deps projection is whole-tree writable**: one
  dep's build can modify a sibling dep, recorded unattested in the closure.

## .NET

- **Strictest v0 boundary of any tailor** (all loud): one SDK-style .csproj only — no .sln, no
  ProjectReference lock entries, no Central Package Management, no
  packages.config/PackageDownload, no workloads, no custom MSBuild SDKs, nuget.org only.
  Ancestor SDK inputs (global.json, Directory.Packages.props, Directory.Build.rsp,
  packages.config) fail closed.
- **Build-capable dotnet verbs are refused at `blanket run`**; everything compiling goes
  through `blanket build dotnet`, which covers build only (no test/publish verbs). The guard
  is advisory — `sh -c` can bypass it. **Restore-time MSBuild evaluation runs unsandboxed
  during missing-lock generation** (delegated-planning trust; the project's MSBuild code runs
  on the host). **Preflight is a fail-closed text scan, not an XML parse**:
  exotic-but-legitimate projects can be refused; nothing banned can hide (XML cannot
  entity-encode element names) — the build sandbox, not preflight, is the security boundary.
- **Output publication has a microsecond non-atomic window**: a reader during the rename sees
  no output; the last good build survives a failed publication. `/tmp/.dotnet` is a bounded,
  local-only sandbox write allowance. **releases.json is a checksum channel, not signed
  metadata.** **The lock does not cover asset selection**: project.assets.json is re-derived
  and attested but not diffed; a NuGet behavior change across SDK pins changes builds under
  the same lock, silently.

## Real-project proof gaps (all ecosystems)

- Python/npm were proven on Ethan's real projects (CX-Games, deja, Financial-Filing…). Cargo
  was proven on blanket itself. **Go and Ruby have only been proven on small
  synthetic-but-real-dependency projects** — Go on a hello-world module pulling `rsc.io/quote`
  plus a cgo build; Ruby on rake/racc/nokogiri with nokogiri's native build. No large
  real-world Go service or Rails app has run under blanket yet.

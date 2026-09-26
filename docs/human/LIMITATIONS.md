# Tog limitations ledger

A standing, honest record of what tog fails to address or does not get
right. Items leave this list only when fixed and regression-tested. Each
entry says what breaks, for whom, and whether it fails loud or silent.

Platforms: macOS arm64 and Linux x86_64 (glibc). All GC-safety work
(Packages A–D, merged 2026-09-10) was validated on Linux only — **no macOS
validation since**. Linux claims are verified on Fedora 44; other glibc
distros are untested. Intel macOS, aarch64 Linux, and musl/Alpine are
unported (a pin-table row plus a wheel-tag band each, not a port).

## Kernel-wide

- **`tog fmt` is Rust-only**; other ecosystems fail clearly (the locked Rust release's
  rustfmt, or a local toolchain's own, no
  `Cargo.lock`; `status` ignores the rustfmt closure).
- **`tog audit` judges signed records only.** A pass proves that every closure file in
  the working tree carries a valid signature from a key the machine policy trusts, that
  every detected ecosystem has its primary closure, that each record is current for the
  inputs on disk (and that the `rustfmt` record names the rustfmt this binary pins), and
  that no recorded exception is denied or unknown. It reads `tog-toolchain.toml` the way
  `status` does: a missing lock, a missing section, a stale lock row, or a record built from
  another bundle than the lock names is `stale`. It does not prove the signer's sync was
  honest or safe to run: it does not cover the doors that run unsandboxed with network
  (`add`/`remove`/`update`, where the ecosystem's own tool edits the manifest and lock, and
  missing-lock generation during `sync`/`plan`, where uv, npm, cargo, bundler, mix resolve
  with network), nor does it re-verify store bytes, re-check object metadata, or judge what
  `tog run`/`x` executed. A job that runs untrusted project code must not hold a signing
  key. The machine policy is whatever `TOG_POLICY` or `$HOME` selects: the gate's
  workflow, environment, binary, and machine policy must be controlled outside the
  untrusted checkout, and pointing `TOG_POLICY` at a checkout-controlled file gives that
  file machine authority. `projected_at` is authenticated metadata, not an expiry: a genuine
  old record whose recorded inputs still match passes. Any record the gate cannot believe or
  compare (no signature, no recorded inputs, no recorded platform, no exception record)
  fails as `outdated` rather than passing, so pre-signing projects need one `tog`
  under a trusted key (and one `tog fmt` for a `rustfmt` record) before the gate is
  useful. An exception kind this binary does not know (a record written by a newer tog)
  fails as `unknown` rather than being permitted. Loud.
- **GC is conservative around legacy state.** Store jobs hold a shared activity lease; GC
  skips while work is active (older binaries do not know the protocol). `root/2` records
  survive moves, but legacy pathname-only roots and unresolved metadata block the sweep — an
  unreadable registry record blocks it too, and `tog gc --forget <key>` is the give-up
  valve.
- **The GC safety guarantee has a stated boundary.** It covers cooperating tog processes
  on a local filesystem with working locks and atomic rename. Not covered: older binaries;
  programs run directly from store paths; malicious same-user modification; descendants
  outliving the awaited child; orphans after SIGKILL of the supervising tog; network
  filesystems, where `flock` is advisory in name only.
- **Signal delivery has three edges.** Parent-directed TERM is forwarded to the direct child;
  a group-directed TERM reaches parent and child independently and is forwarded too
  (at-least-once). Parent-only INT/QUIT/HUP are caught and waited on after startup, not
  forwarded — terminal process-group delivery (`^C`) is the supported path. A cancellation
  across the spawn boundary is never dropped. `128 + signal` is a shell-visible exit code, not
  a wait status. An inherited ignored SIGCHLD (`SIG_IGN` or `SA_NOCLDWAIT`) is overridden while
  a child is supervised, so its exit status is not auto-reaped away; the child still execs with
  the inherited `SIG_IGN`.
- **The tools a sync runs find the project by pathname.** A sync holds the project
  directory open from its first read to its last write: detection, the project's own
  `.tog/policy.toml`, manifests, locks, closures (including the ones root registration
  imports), `.venv`/`node_modules` links and `.tog` all go through that one descriptor. The GC
  root and the per-project lock are keyed on the canonical path the project was opened at,
  never resolved again, and the sync refuses once that path stops naming the held directory
  (after the store wait, before each ecosystem, before a root is registered, and after the
  closure is renamed into place). Three things still go by path. The ecosystem tools a sync
  starts (uv, npm, cargo, go, mix, bundle, dotnet, a `setup.py` probe) run in the project by
  path, so a same-user process that renames the directory away, puts another project at its
  path, and puts the original back while one of them runs can make that tool read or write
  the replacement. Loud when the tool's output is read back (a lock it wrote is missing from
  the held directory); silent otherwise. Files above the project (a Cargo workspace root, a
  parent `go.work`, .NET `Directory.*` files, a parent `.tog/policy.toml`, the machine
  policy) are read by path. Commands that do not sync (`status`, `doctor`, `run`'s
  environment, `gc --register`) open the project by path.
- **CLI exit status is 0 / 1 / 2** (success / command failed / usage error); `run`, `x` and
  `fmt` pass the program's status through. A tool argument that is spelled like one of tog's
  own options needs `--` first: `-h`/`--help` for all four, and for `fmt` and `x` also the
  global options (`-C`, `-q`, `-v`, `--no-color`) while they precede the tool's first
  non-option word. `run` and `build` never take one, so they need no `--` for those.
- **`tog status` compares recorded inputs only.** `-r` includes, `requirements/` members,
  and workspace-member package.json are not recorded. Cargo/Ruby/Elixir/.NET compare the lock
  hash only; Go catches `require`/`replace` only via `go.sum`; a closure written before those
  fields were recorded is reported `unchecked` and fails the command, since nothing about it
  can be compared.
- **One toolchain per lock root.** Toolchain discovery is anchored at the project root
  where `tog-toolchain.toml` sits, not at the current directory, so every developer, CI
  job and subdirectory produces the same consulted-path list and the same staleness
  verdict. The cost is that a toolchain source in a subdirectory — `web/.node-version`
  under a root-level lock — is not a toolchain source for tog, though uv or `nvm` would
  honor it. Per-subproject toolchains would need per-subproject sections and are not
  designed.
- **The two-machine lock diff has been run once, by hand.** A lock carries a row per
  platform and is written from the intersection of releases complete on both. On
  2026-09-25 a seven-ecosystem lock written on Linux synced unchanged on an arm64 Mac, the
  Mac wrote the same bytes from scratch, and `tog status` matched. No CI job repeats it, so
  a change after that date is proven by test, not by two machines.
- **A committed lock is a set of URLs to review.** A lock can aim at any allowlisted
  provider host, and a hostile lock can cause an HTTPS request to a different allowlisted
  host. Reviewing a lock diff is reviewing its URLs. The generic fetch helper still
  accepts `file://`; the lock does not authorize that path, and does not close it either.
- **Frozen validation reads declarative files only.** A project whose only statement of
  its runtime version is computed — `setup.py` metadata, `mix.exs` compatibility, a
  Gemfile `ruby` directive — cannot be validated under `--frozen` and is refused with the
  declarative file to add. Reading those sources means running project code, which is
  exactly what frozen promises not to do.
- **`add` / `remove` / `update` delegate to store tools with network, unsandboxed** (uv, npm,
  pnpm, cargo, go, bundler, mix) — the same trust boundary as missing-lockfile generation.
  Refusal rows: Poetry/PDM, setup.py, `requirements/` dirs, Elixir add/remove, Yarn, .NET.
- **pnpm edits require a root `packageManager` field** with an exact pinned version.
  Membership is the `pnpm-lock.yaml` `importers` list and nothing else. **A member added since
  the last `pnpm install` is not in the lock and cannot be distinguished from a deliberate
  exclusion**, so edits refuse loudly with two remedies: `pnpm install` at the root, or a
  `.tog` directory in it.
- **Yarn classic edits remain a refusal** (no lockfile-only edit mode); run the Yarn command
  tog names. Yarn Berry is not imported (cache-zip checksums are not tarball integrity
  values).
- **`tog x` covers PyPI and npm**. A removed *node* environment orphans its node_modules
  forest under `<store>/forests/`, which plain `tog gc` never visits: only `tog gc
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
- **Unpinned host build inputs.** The Linux host C toolchain (gcc, binutils, glibc headers)
  and the macOS Xcode/clang/SDK are not in build identity — two hosts can produce different
  "identical" objects. The Linux OTP artifact needs glibc 2.43 and host `libcrypto.so.3`.
  Linux gem native extensions build against the host C runtime alone (glibc, kernel headers,
  libxcrypt, the compiler's own files): every other host header, `-l` library, static
  archive and pkg-config file is absent from that sandbox. A gem that needs another host
  library fails that build, is rebuilt against the whole host, and records
  `host-build-inputs`, which a policy can deny. Pure-Ruby gems compile nothing and install
  against the whole host. Setting the view up costs about two seconds per native gem on a
  Fedora 44 workstation, and more on a host with a larger library directory.
  Python sdist builds and npm addons still see the whole host `/usr` and can link any host
  library. macOS gem builds are unchanged.
- **Pinned native-library objects are store-root-specific**: `native-libs/libset/3` includes
  the canonical `TOG_STORE` root in its identity; moving a store requires re-realizing the
  libset. **Linux sandbox roots are canonical paths** (a symlink alias root is invisible).
  Both matter only to new callers.
- **Tog's security claim is provenance, not runtime containment.** Acquisition and build
  happen behind one door, builds cannot reach the network, and every closure lists what went
  in and every exception waved through. A hostile package can still put its payload in its
  build output and run it at `tog run` time with full network. Do not describe tog
  as stopping malicious code from running.
- **Sandboxes are cooperative hermeticity, not hostile-code containment.** bubblewrap does not
  scan immutable read roots for Unix sockets (the fmt host-socket scan is Linux-only); build
  daemons can outlive a run. **Store objects are trusted from permissions + metadata, and all
  toolchain pins are TOFU** (pin-time hashes, not signed manifests): same-user content
  replacement after commit is undetected.
- **Delegated planning runs unsandboxed with user privileges** (uv, npm, cargo, go, bundler):
  a hostile manifest executes code at PLAN time.
- **Every tar archive is unpacked through the pre-materialization extractor**
  (`src/kernel/archive.rs`, #236). It reads every entry from the
  archive's own headers (ustar names and the POSIX prefix field, PAX `path`/`linkpath`/`size`,
  GNU long names), cross-checks that listing against `tar -t`, refuses the whole archive on an
  absolute name, `..`, a hard link, a special file, an escaping symlink, a name that is not
  UTF-8 or carries a control, bidirectional-override or zero-width character, two names that
  APFS would fold into one (by case or by Unicode normalization; for a per-platform build such
  as a toolchain or conda package, only on macOS, since Linux CPython and ncurses ship
  terminfo names like `2621A` beside `2621a`), or a layout it cannot model
  (sparse members, a global header that renames, a PAX key it does not know, unknown type
  letters, bad checksums), refuses past a 1 GiB running member-data budget before anything
  is written, and extracts with `TAR_OPTIONS` unset and tar told to restore no
  extended attributes, ACLs, file flags or AppleDouble metadata: an object holds names, bytes
  and the executable bit, nothing else. The one `tar -c` in the tree (git-source packing)
  lives there too, so no other production code names `/usr/bin/tar` at all — an
  architecture test fails the build if it does. PAX values other than `path`, `linkpath` and `size`
  may be any bytes and are never read. The `tar -t` listing carries only `--numeric-owner`:
  it writes nothing, and bsdtar documents the restore flags for other modes, so on `-t`
  they could only fail. That leaves a Mac-packed tarball's `._name` companions refused on
  macOS by the cross-check, as before, rather than extracted as the wrong tree (#307 stays
  open until a macOS run shows whether `--no-mac-metadata` on `-t` lifts it). Single
  manifests read out of an sdist come from the same validated in-process stream, never a
  second tar child. The Elixir release zip and Hex's own `.ez` archive are
  unpacked by `/usr/bin/unzip`, inheriting the user's `UNZIP`/`UNZIPOPT`. Wheels, zip sdists
  and the outer zip of a `.conda` package are read in process with the `zip` crate.

## Python

Selection covers every patch of each maintained CPython minor that python-build-standalone
  published a checksummed build of for both platforms. A few patches never got one (3.10.0,
  3.10.1, 3.10.10, 3.11.0, 3.11.2; `tools/catalog.py python` reports them) and are refused. A
  two-part `.python-version` picks the default (3.12.14) on its minor, else the newest pinned
  patch; a three-part request must match a pin exactly.
- **RECORD files are left as shipped**: not verified on install; importlib listings can lie;
  project-local/editable and direct requirements are skipped (`requirement-skipped`). **Sdists
  with dynamic build requirements** (PEP 517 `get_requires_for_build_wheel`) are unsupported —
  inspection is non-executing. Static backends are supported; `setup_requires` in legacy
  setup.py is unhandled — declare it in `pyproject.toml`. Rust sdists without a shipped
  `Cargo.lock` get a store-Cargo lock recorded `unattested-cargo-lock`.
- **Immutable venvs are not drop-in venvs**: no activate scripts, and pip cannot mutate them.
  `tog run pip ...` and `tog run activate` are refused with the verb that replaces them
  (`tog add`, `tog run <command>`) rather than left to report a missing file, but **no pip
  shim and no `activate` script are planned**: a shim that accepted `pip install` would have
  to either mutate a read-only store object or silently rewrite the manifest, and an
  `activate` script inside the projection would have to be written into a read-only object.
  For a shell, `tog env` prints the environment as exports and `eval "$(tog env)"` applies
  it; that environment is then **ambient** for that shell — every later command sees it,
  tog's or not, and it outlives a `cd` out of the project. direnv is the way to scope it back
  to a directory (`echo 'eval "$(tog env)"' > .envrc && direnv allow`), which is why tog
  prints the environment instead of activating anything itself.
  No bytecode precompilation — slower cold starts.
- **macOS deployment-target wheel tags are not compared** — theoretical silent wrong-wheel
  risk. Markers/extras in a pinned file trigger a full uv re-lock; versions can shift.
  **Project-level `uv pip compile` in `src/commands/shared.rs` can still execute resolve-time metadata
  builds outside the sandbox** — sdist build-requirement resolution rejects build-time sdists
  instead.

## JavaScript / npm

- **`npm install` is refused, not prevented.** `tog run npm install` is refused with an
  explanation, but npm run directly in the project still replaces the `node_modules` symlink
  with a real directory. Nothing enforces the projection at the filesystem level. `tog status`
  reports it as a real directory written over the projection and the next sync moves it
  aside and re-projects, so it is recoverable, not prevented.
- **Install scripts needing network for logic** are permissive with `install-script-failed`
  (declared-artifacts covers only matching cache locations; Electron-class needs per-version
  declarations). **Git sources are realized only when pinned to a full commit.**
  Branch/tag/bare URLs and ambient Git config fail closed. npm runs a git dep's `prepare`
  script; tog does not. Python and Cargo git deps work the same way, but Cargo's are not
  re-verified against the project's Cargo.lock at `run` — a post-sync lock edit is caught by
  cargo, not tog.
- **Skipped install-time downloads are not in the closure**: puppeteer- and cypress-class
  packages record `artifact-not-provisioned`, fetched unverified only when the user runs that
  command. Electron's zip is provisioned instead, and a failed provisioning fails the sync.
- **Prebuilt binaries are compiled instead of downloaded; the result can differ from what npm
  would install. Wheel file-path collisions (`file-collision`), SHA-1 npm integrity, and pnpm 9
  MD5 patch hashes (`weak-integrity`) are permissive; strict via policy. Lifecycle scripts run in lockfile
  order, not dependency order (rarely bites, silent), and process-tree quiescence is not
  enforced: a postinstall daemon can outlive realization.

## Rust / cargo

- **Pinned Git dependencies work for standalone crates**; workspace-inherited manifests and
  escaping symlinks fail closed, and workspace metadata is not rewritten into vendor
  manifests. **Fail-closed rows**: alternative registries; beta/nightly channels. Loud.
  Cross `targets` get their standard library from the release's signed channel manifest,
  but tog provides no linker or C sysroot for them, so a crate that links for another
  platform still needs one on the machine. A custom toolchain works as a local directory
  (`path =` in rust-toolchain.toml), below.
- **A local toolchain (`[toolchain] path`) is trusted by content, not by origin.** The lock
  records its `rustc -vV`/`cargo -V` lines and a hash of the whole tree, so it proves the
  tree did not change, not who built it; every use records `external-toolchain`, which the
  company template denies. Locking runs the tree's own `bin/rustc` and `bin/cargo` for their
  versions (in the build sandbox, so it needs bubblewrap on Linux). The tree is re-hashed on every sync, build and
  fmt: the walk and link checks run in full, but a file whose device, inode, size and times
  are unchanged is not read again (its sum is cached in the store), so only the first
  hash of a full toolchain costs seconds. That key is the file's device, inode, size,
  mtime and ctime (seconds and nanoseconds), so a write that leaves all of them as they
  were (an NFS mount with coarse or cached attributes, or a write through a shared `mmap`
  that never updates the times) is not seen until the import's copy, hashed from the
  bytes, disagrees. That refusal re-reads the whole tree and rewrites the cache. Locking
  (`tog update --toolchain rust`) always reads every file. The lock row names
  an absolute path on one machine and one host platform, so a checkout elsewhere needs
  `tog update --toolchain rust`. As in rustup, a path cannot be combined with a channel,
  components, targets or a profile. A symlink in the tree is resolved against the tree
  itself, through any links it passes, and a tree with one that leads outside is refused.
- **No `profile` in rust-toolchain means rustc, cargo and the host std** (rustup's
  `minimal`), not rustup's configured default; ask for `profile = "default"` to get
  clippy, rustfmt and the docs. **No channel means the catalog's default release**
  (rustup's would be its configured default toolchain).
- **`profile = "complete"` fails on releases that did not build all of it** (1.96.1 lists
  `miri` and `rustc-codegen-cranelift` for Linux and macOS and marks both unavailable), as
  rustup's does; name the components instead.
  **`tog build` covers `build` only** — no sandboxed test/clippy/doc; those run via
  `tog run cargo ...` offline but unsandboxed. target/ is unmanaged scratch (no shared
  build cache). **`cargo install` through the wrapper is unmanaged** (lands in
  `.tog/cargo-home/bin`, outside the closure).

## Go

- **Only the Go lines go.dev lists as supported are realizable** (every release of each). An
  unmatched `go.mod` selection fails before store or network access. A non-default
  `toolchain` directive is exact; `go` alone is a minimum that takes the default (1.27.0) when
  it satisfies, else the newest release, where go itself would take the lowest.
  **Fail-closed rows**: go.work workspaces (including ancestor detection);
  local-path replace directives. Loud.
- **Graph-only modules are excluded from the closure**, so modgraph introspection can hit
  GOPROXY=off errors. **Private modules are unsupported**: GOPROXY forced to proxy.golang.org,
  GOVCS off, GOPRIVATE scrubbed.
- **The planner runs `go mod tidy` on out-of-sync manifests automatically**, mutating
  go.mod/go.sum. **`tog build` stages outputs then moves them**: `-o`-dependent workflows
  differ from plain `go build`; `-mod`/`-toolexec`/`-o` are rejected. The plan-cache key
  includes only `*.go` sources — go:embed and non-.go inputs do not invalidate it.

## Ruby

- **git and path gems fail closed; non-rubygems.org sources fail closed.** So do gems whose
  installers need network or absent host libraries (mysql2/rmagick-class) — no
  declared-artifacts mechanism for gems yet. **Default/bundled-gem preactivation edge**: a
  locked json/psych/openssl older than the toolchain's default can Gem::LoadError if something
  activates the default before Bundler setup. Untested matrix; potentially silent.
- **`bundle exec` compatibility is unproven**: env-based GEM_HOME activation works for
  `tog run ruby/rake`; full bundler runtime activation has not been exercised on a real
  Rails-class app.
- **System /etc/gemrc is still read** (GEMRC=/dev/null blocks only the user file).
  **Portable-ruby is a Homebrew-internal artifact**: relocation is probed to work but is not a
  contract, and its builds trail ruby-lang: the newest 3.4 build (3.4.6, the default) lacks
  the 3.4.10 security fixes in bundled gems, and Ruby 4.0 has no build at all. **CHECKSUMS-section locks fail closed if bundler's checksum registry API
  drifts**; new bundler formats need code updates.

## Elixir

- **Two OTP steps run outside the sandbox on Linux**: the `Install -cross -minimal` relocation
  and the OTP runtime probe (`src/tailors/elixir/mod.rs`). They touch only the staged object — the one
  non-sandboxed build step in the kernel. **OTP cache hits skip the runtime probe**: the OTP
  object was built on Fedora 44 (glibc 2.43 floor, OpenSSL 3.x); a store copied to an
  incompatible host fails only at execution time. Loud, but late.
- **Fail-closed rows**: git deps; non-hexpm repos; legacy mix.lock entry shapes (3/6/7-field —
  "refresh the lock"). **Umbrella projects are untested**. **Only OTP releases with a Linux build in
  `tog-toolchains` are realizable** (OTP 29.0.5 today, with each Elixir 1.20 patch); erlef
  publishes the Darwin builds for many more. **No rebar3 build for OTP 29 exists
  yet**: the pinned otp-28 escript runs on the 29 VM — a version-skew impurity until upstream
  ships otp-29 builds. **Mix's compilation lock is disabled in-sandbox**, so concurrent
  unsandboxed `mix compile` against one build root is unprotected; `tog build` runs
  MIX_ENV=dev only. **mix.exs elixir requirements are not consulted**: the OTP and Elixir
  entries in `.tool-versions` are the declarative sources the toolchain lock reads, because
  reading mix.exs means evaluating an Elixir program. **The deps projection is whole-tree
  writable**: one
  dep's build can modify a sibling dep, recorded unattested in the closure.

## .NET

- **Only an exact `global.json` selects the SDK.** `sdk.rollForward` must be `"disable"`;
  there is no second source and no roll-forward, so a mismatch is a hard error rather than a
  quiet upgrade.
- **Strictest v0 boundary of any tailor** (all loud): one SDK-style .csproj only — no .sln, no
  ProjectReference lock entries, no Central Package Management, no
  packages.config/PackageDownload, no workloads, no custom MSBuild SDKs, nuget.org only.
  Ancestor SDK inputs (global.json, Directory.Packages.props, Directory.Build.rsp,
  packages.config) fail closed.
- **Build-capable dotnet verbs are refused at `tog run`**; everything compiling goes
  through `tog build dotnet`, which covers build only (no test/publish verbs). The guard
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
  was proven on tog itself. **Go and Ruby have only been proven on small
  synthetic-but-real-dependency projects** — Go on a hello-world module pulling `rsc.io/quote`
  plus a cgo build; Ruby on rake/racc/nokogiri with nokogiri's native build. No large
  real-world Go service or Rails app has run under tog yet.

# Blanket limitations ledger

A standing, honest record of what blanket fails to address or doesn't get
right, per ecosystem and kernel-wide. Items graduate OFF this list only
when fixed and regression-tested. Started 2026-08-31. When adding items,
say what breaks, for whom, and how it fails (loud/silent).

## Kernel-wide

- **macOS arm64 only.** No Linux (the enterprise enforcement point) or
  Intel mac support. Highest-leverage single item on the books.
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
- **Host Xcode/clang/SDK is an unpinned build input** for every native
  compile (python sdists, npm gyp, cgo, ruby extconf). Not in build
  identity; two machines with different Xcodes can produce different
  "identical" objects. Linux + pinned toolchain would close this.
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
- **Editable installs (`-e .`) unsupported** — the loudest daily-driver
  gap for library development. Loud (planner rejects).
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
- **Install scripts that need network for LOGIC** (not just artifacts)
  fail closed; declared-artifacts only covers downloads whose cache
  location matches the declaration (sharp-style). Electron-class
  packages need per-version artifact declarations. Loud.
- **Lifecycle scripts run in lockfile order, not dependency order**, and
  ancestor .bin dirs aren't on script PATH (Sol review 3 leftover).
  Rarely bites; silent when it does.
- **npm optional-dependency failure parity deliberately not mirrored**
  (any script failure aborts the whole realization; npm would tolerate
  optional failures). Loud, stricter-than-npm.
- **Process-tree quiescence after scripts not enforced** (a daemon
  started by postinstall can outlive realization).
- **bun/yarn/pnpm lockfiles are re-resolved via npm** — versions may
  differ from the original lock. Loud note printed, but versions shift.

## Rust / cargo

- **git dependencies fail closed.** Loud.
- **Alternative registries fail closed.** Loud.
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

## Real-project proof gaps (all ecosystems)

- Python/npm were proven on Ethan's real projects (CX-Games, deja,
  Financial-Filing…). Cargo was proven on blanket itself. **Go and Ruby
  have only been proven on small synthetic-but-real-dependency projects**
  (cobra/toml; rake/racc/nokogiri) — no large real-world Go service or
  Rails app has run under blanket yet.

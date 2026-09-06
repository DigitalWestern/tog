# Blanket — north star & follow-ups

*Written 2026-08-30 to re-orient future sessions. The MVP works (see
README/ARCHITECTURE); this document is about where it's pointed.*

## The frame: enterprise first

Blanket is posed for the **company's** benefit, with individual developers
advantaged by extension. The pitch in one line:

> Today software enters a company through fifty doors — pip, npm, brew,
> curl|bash — none with a complete inventory. Blanket is one door, with a
> perfect manifest of everything that came through it.

### What "one door" already means, today, in the MVP

- Every artifact is fetched through one code path, verified against a
  pinned hash, and re-verified on every cache hit.
- Every environment (comforter) records its complete closure — exact
  inputs, hash-level — in the closet's metadata and `.blanket/closure.json`.
  "What is on this machine and where did every byte come from" is already
  a query, not a forensic investigation.
- Builds run in a network-denied sandbox: a dependency cannot phone home
  or pull surprise inputs during install. (Proven by acceptance test.)
- Toolchains (CPython, Node) are pinned and verified — no developer-shell
  drift.

### The enterprise security model to build (the real follow-up)

The trust question Ethan raised: *who runs the security checks?* The
answer that fits blanket's shape: **blanket is the data plane, not the
security vendor.** Companies don't outsource judgment; they buy
enforcement points and evidence. So:

1. **SBOM export** (`blanket sbom`): emit the closure as standard
   CycloneDX/SPDX so companies' *existing* scanners (Snyk, Grype, Trivy,
   internal tooling) can vet what blanket installed. We produce evidence;
   their tools render verdicts. Cheap to build — the closure JSON already
   holds everything; this is a format translation.
2. **Policy hooks** (`blanket sync --policy <file>` or a policy server):
   allow/deny by registry host, package name/version, license, max age,
   CVE feed. Sync fails closed if policy says no. The company writes the
   policy; blanket enforces it at the door.
3. **Registry allowlist**: today a lockfile can point `resolved` at any
   https host (documented trust gap). Policy should be able to pin
   registries to the company mirror.
4. **Signed toolchain manifests**: replace trust-on-first-use pins with a
   signed provider manifest so toolchain provenance is verifiable.
5. **Central closet**: a shared/binary cache so the company builds an
   artifact once, signs it, and every laptop and CI runner reuses it.
   This is where the `/opt/blanket/store` fixed-path decision (Sol) comes
   back into scope.
6. **Honesty constraints** (from Sol's review, keep these in the pitch):
   - Promise the **complete managed closure**, never "complete inventory"
     — programs can still load bytes via plugins/runtime downloads.
   - "One door" is only true **if enforced** — without CI admission
     checks, registry proxies, or device management, blanket is door
     fifty-one. Enforcement integrations are part of the product, not an
     afterthought.

## The four pillars (all of them — don't shrink the ambition)

The goal was never "a better pip." Blanket does all four jobs, one
binary:

| pillar | status | next step |
|---|---|---|
| **Package manager** | ✅ built for Python + npm + cargo (hash-pinned lockfile realizer) | fourth ecosystem (Go is next-cheapest); native resolver later |
| **Toolchain manager** | ✅ built (pinned CPython 3.12/3.13, Node 24, Rust 1.96.1 w/ rust-toolchain.toml resolution) | more versions + languages; signed manifests; `.python-version`-style selection per project everywhere |
| **Task runner** | ⬜ not started | `blanket test` / `blanket build` / `blanket <script>` reading package.json scripts + a `blanket.toml` for cross-language tasks. Sol's caution: mise already owns this shape — differentiate by running tasks *inside the projected env* with provenance, or wait for a real polyglot workspace need |
| **Runtime manager** | 🟡 partial | today blanket owns *distribution + invocation* of runtimes (the uv/zig model, deliberately chosen over bun-style engine rewrites). A native runtime remains a possible later optimization, per-ecosystem, where it buys speed or security — the interface already allows it |

Boiling the ocean is the point; the architecture (kernel + tailors) is
what makes the ocean boilable one pot at a time.

## Expansion: breadth AND depth (decided 2026-08-30)

The "go wide vs. go deep" question is answered: **both, as parallel
tracks.** Breadth proves the kernel thesis keeps compounding (each new
tailor should get cheaper); depth proves blanket is a daily driver, not
a demo. Neither is credible alone: ten shallow languages is a toy, two
perfect languages is a niche tool.

### Breadth track — more tailors

Ordered by (usefulness to Ethan) x (cheapness given the kernel):

1. ~~**cargo (Rust)**~~ **DONE 2026-08-31** — wrapped hermetically per
   Sol's design (GO-WITH-CHANGES, all adopted except plan-time `cargo
   metadata` path-dep validation — the build sandbox enforces it
   naturally): vendored directory sources with generated checksums, cargo
   wrapper forcing `--frozen --config`, sandboxed `blanket build`, pinned
   toolchain with rust-toolchain.toml resolution. Sol's code review
   (round 2) was NO-GO with four reproduced exploits — user --config
   override, symlinked-bin projection escape, ancestor-lock mis-rooting,
   build-script wrapper poisoning — all fixed same day (+ RUSTC forcing,
   toolchain identity schema) with regression tests. Cost: ~690 adapter
   lines (npm ~1015, python ~1030 incl. wheel/toolchain/build) — the
   curve falls, modestly. Known v0 gaps (fail closed): git deps,
   alternative registries, beta/nightly/cross targets.
2. ~~**Go**~~ **DONE 2026-08-31** — fourth tailor, one session after
   cargo. Closure via store-Go `go mod download -json` (go.sum is a
   ledger, not a lock — Sol), blanket-owned dirhash h1 + sha256
   verification, immutable go-modcache objects, env-enforced pinning
   (GOTOOLCHAIN=local et al.), sandboxed staged-output builds. Kernel
   gained the universality contracts Sol prescribed: closure envelope
   (.blanket/closures/<eco>.json) + generic sandbox BuildSpec +
   multi-ecosystem `blanket build` dispatch. Real-project proof: cobra +
   BurntSushi/toml from a bare go.mod (auto-tidy resolution, 8-module
   verified closure). v0 gaps fail closed: go.work, local-path replaces.
3. ~~**Ruby (Gemfile.lock)**~~ **DONE 2026-08-31** — fifth tailor, same
   session as Go. Bundler-delegated lock/platform analysis (embedded
   helper under the pinned portable-ruby 3.4.6), CHECKSUMS-or-API hash
   pinning (v2 API must be platform-qualified — bare endpoint returns
   the latest-pushed variant's sha), Gem::Installer driven directly
   in-sandbox (the CLI needs network code at load), dependency-first
   installs, BUNDLE_IGNORE_CONFIG enforcement (.bundle/config OUTRANKS
   env — inverse of cargo). Kernel gained force_env + BuildSpec stdin
   null. ~540 adapter lines. v0 gaps fail closed: git/path gems,
   non-rubygems sources, network-needing installers.
3b. ~~**Elixir/Hex**~~ **DONE 2026-08-31** — sixth tailor. AST-parsed
   mix.lock (never eval'd; strict 8-field grammar), dual-checksum hex
   tarballs, four-artifact BEAM toolchain (OTP/Elixir/Hex/rebar3 — the
   latter two OTP-qualified builds; unqualified legacy artifacts hang on
   new OTP, found live), clonefile deps projection (source trees are
   written into by native builds — the "writable unattested projection"
   kernel lesson), sandboxed mix compile with the loopback-TCP Mix lock
   disabled. Real proof: telemetry (rebar3) + jason. ~620 adapter lines.
3c. ~~**.NET/NuGet**~~ **DONE 2026-08-31** — seventh tailor. Mandatory
   packages.lock.json (v1), semantic contentHash verified THROUGH the
   pinned NuGet (signed nupkgs hash transformed bytes — never raw
   compare), per-build fresh offline restore (obj/ never authority),
   build-capable verbs sandbox-only, SDK pinned from Microsoft's
   release-metadata checksum channel. ~540 adapter lines. Strict v0
   boundary (see LIMITATIONS.md).
4. **System packages (the Homebrew replacement)** — the big one, kept
   deliberately last: Sol's review was right that GUI apps, services,
   and privileged installs are a *different product* (host-effects
   model). Start with the easy 80%: CLI tools and libraries, which fit
   the closet perfectly.
5. **JVM (Maven/Gradle)** — explicitly deprioritized: Sol's analysis
   says Gradle's executable build logic effectively requires embedding
   Gradle itself. Route around the dragon until enterprise pull demands
   it.

Breadth-track health metric: **lines of code per new tailor should keep
falling** (npm took ~450 where Python took ~1500 + the kernel). If a new
tailor costs more than the last one, the kernel is leaking and we stop
and fix the kernel instead.

### Depth track — make Python + JavaScript daily drivers

Python tailor:
- environment markers (`; python_version < "3.13"`) and extras
  (`package[extra]`) — the two loudest v0 rejections real lockfiles hit
- editable installs (`-e .`) as an explicit **mutable overlay** on top of
  the immutable comforter (Sol's design: the closet stays pure; the
  workspace is a declared exception)
- sdists with dynamic build requirements (PEP 517 `get_requires_...`
  metadata jobs run in the planning sandbox, per the original Sol design)
- RECORD verification on install + rewrite after (closes the loudest
  documented lie)
- bytecode precompilation at realize time (startup speed, deterministic)

JavaScript tailor:
- ~~**lifecycle scripts in the build sandbox**~~ **DONE 2026-08-31** —
  scripts run network-denied with pinned toolchains; better-sqlite3
  compiles from source; download-at-install packages (old sharp) work via
  declared artifacts (`blanket.artifacts`: url+sha256 as verified inputs).
  Note the roadmap's original "same recipe as Python sdists" was
  optimistic — Sol was right that download-dependent scripts needed their
  own mechanism (declared artifacts), and vite turned out to be blocked by
  something else entirely (writable node_modules top level → forest
  projection), not by scripts.
- ~~workspaces/monorepos (`link:` entries)~~ **DONE 2026-08-31** (nested
  per-workspace node_modules still rejected with a hoisting hint)
- `blanket add <pkg>` — delegate resolution to a vendored resolver or
  embedded tool, keep realization ours (the "cheat early" doctrine).
  Half-done: missing lockfiles are already delegated (npm
  --package-lock-only, uv pip compile).

Shared depth (kernel):
- per-package store objects with copy-on-write assembly (APFS clonefile)
  so comforters share squares-worth of disk, not just whole-environment
  dedup
- reproducibility spot-checks: rebuild a derivation twice, compare bytes,
  quarantine mismatches (the last unimplemented item from Sol's original
  acceptance list)
- the M5 hardening backlog (ARCHITECTURE.md)

Sequencing rule of thumb: alternate. Ship one depth item that unblocks a
real project of Ethan's (npm lifecycle scripts → vite works), then one
breadth item (cargo tailor), and keep alternating so neither track
starves.

## Standing follow-up list

- [x] `blanket sbom` — CycloneDX 1.5 export of a project's closure(s) —
      done 2026-08-31 (all seven ecosystems; purls, pinned hashes, toolchain
      store-ids; SPDX and a dependency graph remain open)
- [ ] Policy engine v0 — registry allowlist + package allow/deny, fail closed
- [ ] Task runner v0 — `blanket run <script>` from package.json scripts
- [x] Third tailor — cargo (wrap, hermetically) — done 2026-08-31
- [ ] Cargo follow-ups: git deps, per-crate vendor objects (M5
      per-package plan), `blanket build` for test/clippy invocations,
      declared artifacts for network-needing build scripts
- [ ] M5 hardening backlog (ARCHITECTURE.md): RECORD rewrite, Mach-service
      allowlist, deployment-target tags, streaming extractors, `blanket gc`
      (now also: forests + backups, with liveness checks)
- [ ] Sol review 3 leftovers (2026-08-31): dependency-order lifecycle
      execution + ancestor .bin paths; true npm optional-failure parity
      (remove failed package subtree from the object + identity); planner
      subprocess sandboxing (uv/npm run unsandboxed by design for now);
      process-tree quiescence after install scripts; Xcode/SDK fingerprint
      in build identity
- [ ] Store-object content verification on use (Sol ruby review, kernel
      scope): objects are currently trusted from permissions + metadata;
      same-user replacement of an object's contents is undetected. Either
      content-hash spot verification or an explicitly documented narrower
      trust boundary. Also: contained atomic writes for the remaining
      project-side plan caches (go-plan.json, python plan.json).
- [ ] Central closet / binary cache + fixed store path decision
- [ ] Friendlier CLI errors (e.g. `node.js` typo → "did you mean node?")
- [x] Linux support — landed 2026-09-05, LINUX_PORT.md (also unlocks the "Linux as reference hermetic
      builder" idea)

## Open questions for Ethan + Claude to chew on together

1. Which enterprise proof-of-concept is most convincing: SBOM export
   feeding an off-the-shelf scanner, or the policy-blocked `sync` demo
   ("watch blanket refuse a denied package at the door")?
2. Does the task runner earn its place before a third language does, or
   after? (What would *you* use first, day to day?)
3. ~~Deep vs. wide?~~ **Answered: both, alternating** — see the
   expansion tracks above. First concrete pair: npm lifecycle scripts
   (depth, unblocks vite projects), then the cargo tailor (breadth).

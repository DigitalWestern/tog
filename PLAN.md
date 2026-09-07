# Blanket — the plan (2026-09-06)

This is the one working document. An agent handed this file should be able to
pick the next unclaimed work package, implement it, get it reviewed, merge it,
and update this file. Everything else in the repo is reference:
ARCHITECTURE.md (how it works), CLI.md (command surface), LIMITATIONS.md
(honest ledger of what is wrong), HITRATE.md (measurements), REVIEW.md (what
has not been independently checked), LINUX_PORT.md (platform changelog),
blanket-notes.md (design history). NEXT.md is a frozen index of shipped items
kept only because code comments cite its numbers.

## 1. What blanket is and where it is going

One binary that owns the outer loop every language shares: provision a pinned
toolchain, realize a locked dependency graph into an immutable
content-addressed store, project an environment, run the code. Seven
ecosystems (Python, npm, Cargo, Go, Ruby, Elixir, .NET) on macOS arm64 and
Linux x86_64. Resolution is deliberately delegated to each ecosystem's own
pinned tool; blanket owns everything after resolution. Nix's model without
Nix's interface.

**Decisions taken 2026-09-06 with the owner:**

- **One product, one switch.** There is no personal track and no enterprise
  track. Permissive by default; `.blanket/policy.toml` (strict, deny lists,
  and the package-level rules in WP5) is the company layer. Nothing is ever
  loosened silently.
- **Personal daily driver is the road; enterprise is the destination.**
  Every enterprise property (verified inputs, sealed builds, complete managed
  closure) falls out of the store model and is already there. What remains for
  companies is enforcement knobs, and those wait until the tool is a daily
  driver.
- **Headline feature: `blanket fmt` just works.** In a Rust project it fetches
  the pinned rustfmt if missing and runs it. There is never a separate
  `blanket install <tool>` step. This is the shape every tool invocation should
  have.
- **Toolchain versions must track upstream without code edits.** Today every
  CPython/Node/Rust/Go/Ruby/OTP/.NET version is a hand-typed pin table in
  `src/*.rs`. This is the largest gap between the code and the owner's intent.
- **Two platforms, both gated.** macOS arm64 and Linux x86_64 are the
  product. The code is written once with per-platform pin rows, and the Linux
  unit suite carries frozen darwin identity goldens, so a Linux run proves the
  *plan* is identical on the Mac. It does not prove the Mac can *execute* it:
  the sandbox engine (Seatbelt vs bubblewrap), tar (BSD vs GNU), file cloning
  (clonefile vs reflink), the host C toolchain (Xcode vs gcc), and native
  library provisioning (Linux only today) all differ at runtime. Windows is
  out of scope until further notice; it is a different product surface (no
  sandbox engine to lean on, different symlink and path semantics), not a
  port, and nothing in this plan should bend toward it.
- **"One door" stays qualified.** Blanket is a complete manifest of what came
  through *it*; without CI admission, registry proxies, or device management
  it is door fifty-one. Keep that sentence wherever the pitch appears.

## 2. Working rules for agents

- **Read first:** CLAUDE.md (invariants), ARCHITECTURE.md, LIMITATIONS.md, and
  the WP you are taking. Check REVIEW.md before trusting a recent feature.
- **One work package per branch per PR.** Rebase on main; do not bundle.
  Parallel agents use separate git worktrees.
- **Gates before a PR:** `cargo fmt --check`; `cargo test` (offline; capture
  cargo's exit status, never pipe to `tail`); the relevant `--ignored` network
  tests with a disposable `BLANKET_STORE`, disk-backed `TMPDIR`, and on Linux
  `BLANKET_SANDBOX_TESTS=required`. Use `--target-dir`, never
  `CARGO_TARGET_DIR`.
- **Mac before merge.** Agents run on the Linux box; the Mac is the owner's
  laptop. Every work package lists a **Mac before merge** line naming exactly
  what must run there. The way it has been done: the owner (or a terminal
  agent on the Mac, which runs under Codex's sandbox with `LANG=C.UTF-8` and
  `ps` blocked) checks out the branch, runs the listed commands, and pastes
  the results or pushes a `mac-verify-*` branch with any fix, as PRs #2-#4
  did. A PR does not merge on Linux evidence alone unless the owner says so,
  and then REVIEW.md gets a row saying "Linux evidence only" that WP0-style
  work must later clear. Default Mac gate for any PR: `cargo build`,
  `cargo test`, and the `--ignored` tests the PR touches.
- **Independent adversarial review before merge.** Sol (Codex,
  `codex exec -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only
  --dangerously-bypass-approvals-and-sandbox -o <out> "<brief>" < /dev/null`)
  reviews the diff with a written brief; fix every blocker/should; Sol
  rechecks. Implementation is Luna (`-m gpt-5.6-luna`). Astra (`gpt-6-astra`)
  is reserved for owner-requested plan reviews: it costs too much usage for
  per-PR rounds. Self-review only downgrades a REVIEW.md entry, never clears it. If
  Codex is rate-limited, a fresh Claude subagent that did not write the code is
  the stand-in, and REVIEW.md records that it was not independent.
- **Invariants that end a PR if broken:** store objects are input-addressed
  and immutable (new semantics need a new identity field); darwin identity
  goldens stay byte-identical; every pin carries a verified sha256; platform
  helpers take an explicit `Platform`; permissive mode records an exception,
  it never hides one.
- **Bookkeeping in the same PR:** LIMITATIONS.md gains or loses a row;
  REVIEW.md log gets a row; HITRATE.md gets a dated column, never an
  overwrite; this file's WP status line is updated. Stale references in code
  comments and user-facing strings to "NEXT.md item N" are replaced with the
  behaviour they describe when the file is touched anyway.
- **Do not** change default toolchain versions, write into a user's project,
  or widen what a bare word can trigger, outside the WP that specifies it.

## 3. Work packages, in order

Order is Astra's (adversarial plan review, 2026-09-06) with the owner's
agreement. WP0 and WP1 first; WP2 before any default changes; WP3 needs WP2.
WP4 items may interleave anywhere after WP1. WP5 last.

### WP0 — macOS arm64 validation of the current main — OPEN

What the Mac has already proven: at commit dbf7ac4 (2026-09-05, PRs #2-#4,
LINUX_PORT.md rounds 1-3) `cargo build`, `cargo test`, and
`tests/acceptance.sh` passed 35/35 on macOS arm64, after three Mac-found
fixes (Go locale, an unused_mut warning, the .NET CoreCLR shm directory).

What it has not: the 76 commits since, which include Git sources (#14-#16),
artifacts and electron provisioning (#13, #17), pnpm/yarn importers, manifest
coverage, build isolation, native libraries, gc, the CLI (#20), the
2026-09-06 review fixes (#19 and follow-ups), the in-process ustar check
that replaced trusting tar's exit code (f856e98), the pnpm empty-lock fix,
and the rustfmt pass. BSD tar behaviour under the new ustar validation is the
single most likely Mac-only break.

**Mac before merge (this is the whole package):** on main, `cargo build`,
`cargo test`, `cargo test -- --ignored` with a disposable `BLANKET_STORE`,
`bash tests/acceptance.sh`, the six `deps_e2e` round trips, and the `x`
cold/warm smoke (`blanket x ruff --version`, `blanket x prettier --version`).
Record results in REVIEW-2026-09-06.md, add the REVIEW.md log row, and
append a round-4 entry to LINUX_PORT.md. Any Mac-only fix goes on a
`mac-verify-round4` branch like the earlier rounds. Also re-measure the two
`npm_git_dep` hit-rate rows (hoppscotch, tabby) that predate Git sources, as
a dated column in HITRATE.md.

### WP1 — `blanket fmt` on the existing pinned Rust toolchain — OPEN

Contract (Astra): works in a project that has never been synced (discover the
Cargo workspace, do not resolve dependencies); fetches the rustfmt/cargo-fmt
component matching the project's resolved Rust toolchain as an immutable
store object with its own identity and a closure/GC reference; is allowed to
edit source files (today `run` requires projection and the build sandbox
permits only target writes, so `fmt` needs its own execution mode: no
network, project tree writable, store read-only); supports `--check`; passes
the tool's exit status through unchanged.

Bare-word rule: `blanket fmt` is a **named** command, not an unknown-word
fallthrough. A typo stays a usage error (tests/cli.rs protects this).
Precedence when a package.json script is also named `fmt`: the script wins,
same as `dev`/`test` today. Ambiguous polyglot directories require
`blanket fmt --eco rust` (or the ecosystem prefix CLI.md already uses for
`add`). Start with Rust only; Python (ruff format via `x`), Go (gofmt is in
the toolchain), and the rest follow the same contract in WP4.

Acceptance: a fresh clone of a Rust repo with no store runs `blanket fmt
--check` and exits with rustfmt's status; second run is a cache hit; the
component appears in `blanket ls` and survives `blanket gc`.

**Mac before merge:** the rustfmt component needs its own darwin pin row
with a verified sha256, and the new `fmt` execution mode goes through
Seatbelt, not bubblewrap. Run the acceptance above on the Mac cold and warm,
plus `cargo test` and the `fmt` `--ignored` test. Darwin identity goldens
must be unchanged.

### WP2 — Toolchain lock and exact version selection — DESIGN REWORKED ROUND 2; IMPLEMENTATION OPEN

Status: the design is reworked in ARCHITECTURE.md after the second adversarial
review; implementation is open and follows its ordered PRs. Lock activation is
dormant until source selection and runtime propagation land, so intermediate
PRs neither write nor require a toolchain lock.

The design is documented before implementation; changes to the contract update
ARCHITECTURE.md in the same PR as the affected implementation.

Problem: once versions self-update (WP3), "which Python when the project says
nothing" gets two answers (table default vs newest today), and newest-today
drifts between machines. Also, exact selection is sloppy now and a live
catalog will expose it.

- **A committed toolchain lock**, outside the ignored `.blanket/`, recording
  for each ecosystem the exact provider build, components, and per-platform
  hashes (name and format to be chosen in the design; one file). First
  writable sync of a project with no pin creates it visibly and atomically;
  frozen/CI sync (`--frozen`, or strict policy) refuses a missing or stale
  lock; concurrent writers must agree. Upgrades are an explicit command
  (`blanket update --toolchain`), never a side effect.
- **Selection sources.** Read what each ecosystem's own tools read, then the
  lock: `.python-version` (uv semantics), `rust-toolchain(.toml)` (rustup),
  `go.mod` `toolchain` (advisory upstream, exact in blanket), `.node-version`
  / `engines` (advisory), `.ruby-version`, `.tool-versions` (asdf, for
  Elixir/OTP), `global.json` with roll-forward disabled (.NET). Today blanket
  honours Python/Rust/Go inputs only; Node, Ruby, Elixir select nothing and
  .NET accepts one fixed SDK (src/npm.rs:137, src/ruby.rs:57,
  src/dotnet.rs:132, LIMITATIONS.md). Ranges (`requires-python >=3.10`) pick
  the newest compatible supported stable/LTS once and lock it.
- **Exact selection bugs to fix first:** `pyselect` substitutes a patch
  version even for an exact request (src/pyselect.rs:170); `python::lookup`
  returns the first matching row (src/python.rs:87); Go realization takes no
  selected version (src/golang.rs:145).
- **Carry the selected runtime through every operation.** Node `run` and
  cached `x` environments take the global pin (src/main.rs:1409,
  src/xrun.rs:325); `x` keys omit runtime identity; `status` must compare
  toolchain inputs too. A catalog refresh must never pair old dependencies
  with a new runtime silently.
- Existing projects seed their lock from the runtime recorded in their
  closure. Writing a lock does not violate input addressing; unrelated
  catalog refreshes must not change any object identity.

Acceptance: two fresh stores with different catalogs replay identical
environments from the same committed lock; a project with no pin gets a lock
written on first sync and a refusal under `--frozen`; every exact-selection
bug above has a regression test; selection uses the intersection of complete
releases across both supported platforms and asymmetric catalogs produce
identical lock bytes from either platform value.

**Mac before merge:** the lock carries a hash per platform, so a lock written
on Linux must sync on the Mac without rewriting itself, and vice versa.
Sync the same project on both machines and diff the lock file (it must be
identical) and `blanket status` (both "synced"). Run `cargo test` and the
selection `--ignored` tests on the Mac.

### WP3 — Release catalog with one authenticated provider — OPEN

- **Catalog, not just a release list.** For each ecosystem: usable
  distributions (python-build-standalone builds, nodejs.org, static.rust-lang,
  go.dev, portable-ruby, erlef otp_builds plus blanket-toolchains for Linux
  OTP, Microsoft release metadata), provider build revisions, platform
  requirements (glibc floor), extraction recipes, and companion tools that must
  move together: uv, bundled npm, Bundler, OTP-qualified Hex and rebar3,
  Elixir-per-OTP compatibility.
- **Refresh and trust protocol.** Immutable catalog snapshots in the store;
  atomic refresh with timeout and last-good fallback; historical retention so
  old locks stay realizable; trusted publisher keys with rotation and
  revocation; invalid signature is a hard failure, never a warning. Two
  distinct modes: `--offline` (no network at all) and "shipped catalog only"
  (the tables compiled into this binary, for zero-surprise installs).
- **Signatures exist for more than expected.** Go, Rust, and Node publish
  signed checksums; python-build-standalone publishes GitHub attestations
  (audit them; blanket is TOFU today, src/python.rs:10). Portable-ruby and the
  Linux OTP artifact are TOFU by construction; say so in the catalog entry
  and in LIMITATIONS.md.
- **Do one provider completely first** (Rust or Go: smallest surface, signed
  upstream, already has toolchain-file resolution), with the behavioural gates
  below, then add the others one PR each. Default versions do not move until
  WP2 has merged.
- **Rebuild the Linux OTP artifact** on an older declared baseline with static
  OpenSSL and a runtime check on the supported distros. Static OpenSSL alone
  does not lower the glibc floor (LIMITATIONS.md:63).

Acceptance: one binary discovers a newly published upstream release without a
code change; a failed refresh falls back to last-good and says so; offline
replay of a locked project succeeds with the network denied; a tampered
catalog is rejected.

**Mac before merge:** every catalog provider must produce darwin-arm64 rows,
and the Mac must realize a toolchain from the catalog rather than the
compiled-in table (verify with `-v` that the catalog was the source). Offline
replay is run on the Mac with the network off. The `--offline` and "shipped
catalog only" modes are tested on both.

### WP4 — Daily-driver gaps and the `x` lifecycle — OPEN

Any of these may be taken after WP1 merges; each is its own PR.

- Python editable installs (`-e .` / the project itself) as a declared
  mutable overlay; dev/optional dependency groups installable by flag.
- `blanket add/remove/update` for pnpm, Yarn, Poetry, and PDM projects
  (today they refuse with instructions; LIMITATIONS.md:24).
- `x` lifecycle: `blanket x --clean`, unregister an environment, protect a
  running tool from concurrent gc. (gc already knows the roots:
  src/gc.rs:111.)
- Extend `x` to cargo, go, gems, hex, nuget tools **after** WP1 has proven a
  model for compiled tools (Cargo today stores vendored sources; `cargo
  install` output is unmanaged, LIMITATIONS.md:226).
- `fmt` for the remaining ecosystems under the WP1 contract.
- One real project per fixture-only ecosystem (Cargo, Go, Ruby, Elixir,
  .NET), recorded in HITRATE.md. Extend `tests/hitrate.py` to measure a
  build/test/format command, not only `sync`.
- Re-run the 60-repo hit rate after WP1 and after WP3; dated columns.
- Carry-overs from the retired NEXT.md/ROADMAP.md: SBOM `vcs` external
  references for Git components; standalone vendoring of workspace-inherited
  Cargo Git crates; artifact provisioning entries (sharp <0.33, node-sass,
  sentry-cli) only when a real project needs them; SPDX SBOM and dependency
  graph.

**Mac before merge (per item):** editable installs and dev groups exercise
clonefile projection, so run the Python `--ignored` tests on the Mac; the
`add/remove/update` delegates run unsandboxed and are platform-neutral, so
the six `deps_e2e` round trips on the Mac suffice; `x` lifecycle and any
compiled-tool model for cargo/go tools need a Mac cold/warm run because the
binaries are per-platform artifacts; the real-project-per-ecosystem proofs
are measured on both machines and recorded as two columns.

### WP5 — The company layer, all inside policy — OPEN, last

- Policy engine: today `deny` names exception categories and strict rejects
  even `built_from_source` (src/policy.rs:42). Add package-level rules
  (name/version allow and deny) with a story for what the user sees when each
  fires.
- Protected machine-wide policy: home and ancestor policies already tighten
  together, but `BLANKET_POLICY` replaces home-policy selection
  (src/policy.rs:150). Mandatory rules need unconditional loading a project
  or env var cannot bypass.
- Enforcement must cover every door: delegated planners (uv/npm/cargo/go/
  bundler/mix run unsandboxed with network), toolchain acquisition, cache
  hits, `run`, and `x`. Say in ARCHITECTURE.md which are covered.
- Private registry configuration and authentication **before** any
  allowlist claim: Python forces public PyPI and Go forces the public proxy
  while clearing private-module settings (src/main.rs:780,
  src/golang.rs:164). Cover delegates, redirects, Git sources, and cached
  decisions.
- Age and license rules only once package records carry publication dates
  and licenses (they carry neither today: src/types.rs:46, src/npm.rs:217).
  Define the metadata source and missing-data behaviour first.
- Shared store / binary cache across machines: only on real demand.

**Mac before merge:** policy loading, registry configuration, and
authentication are pure logic and need only `cargo test` on the Mac, except
that any enforcement inside a build goes through Seatbelt and must be shown
to deny on the Mac too (the network-denied sandbox acceptance check already
exists for both engines; extend it rather than adding a new one).

## 4. Backlog (unranked, from the retired ROADMAP.md standing list)

- M5 hardening (ARCHITECTURE.md): RECORD verification and rewrite,
  Mach-service allowlist, deployment-target tags, streaming extractors.
- Sol review 3 leftovers: dependency-order lifecycle execution and ancestor
  `.bin` paths; true npm optional-failure parity; planner subprocess
  sandboxing; process-tree quiescence after install scripts; Xcode/SDK
  fingerprint in build identity.
- Store-object content verification on use (same-user replacement is
  undetected) or an explicitly narrower documented trust boundary; contained
  atomic writes for the remaining project-side plan caches.
- Per-package store objects with copy-on-write assembly; reproducibility
  spot-checks (rebuild twice, compare, quarantine mismatches); bytecode
  precompilation at realize time.
- Pinned C toolchain as a store object (closes the unpinned host gcc/glibc
  and Xcode inputs on both platforms).
- Breadth: system packages (CLI tools and libraries first; GUI apps and
  services are a different product); JVM deliberately deprioritized.
- Health metric for any new tailor: lines of code per tailor must keep
  falling, or stop and fix the kernel.

## 5. Status log

| Date | Change |
|---|---|
| 2026-09-06 | PLAN.md created; ROADMAP.md retired; NEXT.md frozen as an index. Astra plan review: PROCEED-WITH-CHANGES, folded in above. Main at this commit has rustfmt applied and `cargo fmt --check` clean. |
| 2026-09-06 | Platform rules added: Mac-before-merge gate per work package; WP0 restated against the last Mac-verified commit (dbf7ac4, 76 commits behind main); Windows explicitly out of scope. Local and origin main confirmed identical at 0268405. |
| 2026-09-06 | WP2 design written; implementation open, ordered PRs listed in ARCHITECTURE.md. |
| 2026-09-06 | WP2 design reworked after adversarial review: recipe identities, embedded components, frozen input safety, global cross-platform selection, conservative legacy seeding, and the implementation order are now explicit. |
| 2026-09-06 | WP2 design reworked round 2: catalog-authorized HTTPS artifacts, per-platform BEAM rows, descriptor-relative input snapshots, explicit source-discovery matrix, sandbox-only frozen probes, and dormant lock activation are now explicit. |

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
`bash tests/acceptance.sh`, the ten `deps_e2e` round trips, and the `x`
cold/warm smoke (`blanket x ruff --version`, `blanket x prettier --version`).
Record results in REVIEW-2026-09-06.md, add the REVIEW.md log row, and
append a round-4 entry to LINUX_PORT.md. Any Mac-only fix goes on a
`mac-verify-round4` branch like the earlier rounds. Also re-measure the two
`npm_git_dep` hit-rate rows (hoppscotch, tabby) that predate Git sources, as
a dated column in HITRATE.md.

### WP1 — `blanket fmt` on the existing pinned Rust toolchain — IMPLEMENTED and reviewed (5 rounds, MERGE on Linux evidence; PR open); Mac gate outstanding

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

### WP2 — Toolchain lock and exact version selection — DESIGN REVIEWED (10 rounds; round-10 findings fixed, those fixes themselves unreviewed); Python and Go exact selection and the secure extractor (`src/archive.rs`) landed; REST OF IMPLEMENTATION OPEN

Status: the design is reworked in ARCHITECTURE.md after ten adversarial
review rounds; implementation is open and follows its ordered PRs, of which item 0 is
already open as PRs #21 (`wp2/python-exact-selection`) and #22
(`wp2/go-selected-version`). Round 6 adds one staleness rule for input rows —
only a re-parsed `value` decides, a digest mismatch alone never does, in sync,
`--frozen`, and `status` alike, so `blanket add` rewriting a multi-purpose
manifest cannot wedge the lock — gives the descriptor-relative root helper a
module (`src/fsroot.rs`) and named refusal tests in PR 3 and acceptance, makes
the publication temp name unique rather than fixed (round 8 replaced the
pid-plus-sequence shape it chose), defines the polyglot case
(a lock missing a newly present ecosystem is stale, and `update --toolchain`
adds it), and moves the `--frozen` write-boundary prose out of CLI.md's literal
help screen.

Round 8 applies the owner's product decisions and the standing rule that the
design prefers one dynamic mechanism over a mechanism plus its exceptions.
(1) **The shipped catalog leaves the reproducibility path.** A lock row carries
version, URL, algorithm-qualified digest, and recipe id, which is everything
realization needs, so honoring a lock reads the lock and nothing else; the
catalog is consulted only when choosing a version, at lock creation and
`update --toolchain`. Upgrading blanket can no longer invalidate a committed
lock. Retrieval stays constrained by the digest and by an append-only provider
host allowlist rather than by the catalog, and recipe ids become append-only so
blanket's own code cannot take the catalog's place as the thing an upgrade
breaks. (2) **Publication uses OS randomness and real durability** — a
`/dev/urandom` temp name (the source already in `src/sbom.rs`, factored into one
helper, not a second one), `O_EXCL`, `fsync` the file, `renameat`, `fsync` the
directory. Pid-plus-sequence is dropped because it has fixed points: a sequence
restarts at 0 and PID namespaces reissue the same small pids, so one leftover
`.blanket-toolchain.toml.1.0.tmp` would wedge every later run of a container
image. The round-6 claim that `src/store.rs:69` uses that shape was wrong — it
is pid-only — and the citation is gone. (3) **Staleness compares the whole
consulted path list, including absence**, so adding a higher-precedence source
(no `.python-version`, then one appears) is a row flipping from absent to
present rather than a change nothing in the lock can see; discovery is anchored
at the project root, never at cwd, so the verdict is a property of the project.
(4) **`bundle_id` and the lock's canonical bytes are defined**, length-prefixed
records with a leading serialization-version record, so the definition can grow
without regressing old ids. (5) **The `(planned:)` markers are gone from CLI.md**
— the help screen and grammar are specs for what ships, not a place to advertise
unimplemented flags under a convention no other verb uses. (6) **The "never
evaluates project code unsandboxed" claim is now structural rather than an
Elixir-only blocklist**, which was incomplete: `src/ruby.rs:582-596` evaluates
the Gemfile through an unsandboxed `Command` with network. Ruby's toolchain input
comes from `.ruby-version`/`.tool-versions`, and frozen refuses rather than
evaluate a Gemfile to learn a version.

Round 9 reviewed round 8. Its citation audit found every reference accurate
except `src/ruby.rs:580`, which points at the comment rather than the call
(now `582-596`). Its one substantive finding: round 8's own sentence "main has
two unsandboxed evaluators of project code, not one" was another incomplete
count — `plan_dotnet` runs `dotnet restore` through a plain `Command`
(`src/dotnet.rs:603-635`, `src/dotnet.rs:715-740`) and MSBuild evaluates the
project's `.csproj` and `Directory.Build.props`/`.targets`, and Ruby and
Elixir each have a second call site outside the cited ranges. Rather than
correct the number, the guarantee is now a reachability rule that records no
number at all — treat every planning path as unsandboxed — backed by a named
module `src/toolchain_input.rs` with a PR owner and a per-ecosystem test that
the reader spawns no process, mirroring how `src/fsroot.rs` is specified.

Round 10 reviewed round 9. Its own citation audit re-opened every reference
round 9 added or moved and found all of them accurate, including the `580` ->
`582-596` correction. Its two blockers were in the new prose rather than the
citations. First, the reachability rule had been promoted to an absolute claim
about all of `--frozen`, but this document's own flow has a *passing* frozen
run continue into ordinary sync and dependency planning, and `plan_ruby`'s
Gate 1 evaluates the Gemfile on every call — so the rule contradicted the flow
and the marker acceptance test was false as written. The rule is now scoped to
frozen *toolchain-lock validation*, with what frozen does after validation
stated plainly instead of left to inference: planning still delegates to the
native tools, which do evaluate project code, and that is the delegated-resolver
boundary the design already accepts for dependencies. Second, "the reader
spawns no process at all" was unsatisfiable for two of the seven precedence
rows, which still listed `setup.py`-computed metadata and `mix.exs`
compatibility as sources. Every reader is now declarative-only, uniformly:
Python reads `.python-version` and a `requires-python` declared in
`pyproject.toml`, Elixir reads the `.tool-versions` OTP/Elixir entries, and a
project whose only statement of its version is computed fails frozen closed
with a message naming the declarative file to add. Round 10 also found three
different round counts across this file and REVIEW.md, and a REVIEW.md Outcome
cell claiming round 8 was never reviewed in the same row that records round 9
reviewing it; both are corrected.

The design already gave both lock writers one hardened publication rule, kept the store root in the `x/3` key, made artifact digests
algorithm-qualified so the existing sha512 rows are carried over, kept explicit
CPython prefixes as a supported `.python-version` spelling, required an
unconditional descriptor-relative lock snapshot compare, separated bundle ids
from component versions, and assigned extractor and legacy-seeding tests. Lock
activation is dormant until source selection and runtime propagation land, so
intermediate PRs neither write nor require a toolchain lock.

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
- **Exact selection bugs to fix first:** ✅ `pyselect` requires canonical
  release spelling and a pinned
  three-part request and keeps two-part selection minor-scoped
  (`unpinned_patch_request_fails_closed`,
  `exact_pinned_request_selects_without_warning_in_supported_spellings`,
  `explicit_request_pin_choice_is_newest_for_minor_and_exact_for_patch`);
  ✅ `python::lookup` matches exact versions and chooses the newest numeric
  patch from a minor
  (`lookup_uses_the_newest_numeric_patch_in_a_wrongly_ordered_table`);
  ✅ Go realization takes the `go.mod`-selected version and an unpinned
  selection fails before store or network access
  (`golang::tests::ensure_go_for_rejects_unpinned_version_before_store_access`).
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

### WP4 — Daily-driver gaps and the `x` lifecycle — IN PROGRESS (x lifecycle reviewed, MERGE on Linux evidence, PR open; Mac gate outstanding)
### WP4 — Daily-driver gaps and the `x` lifecycle — PARTIAL (pnpm edits implemented, reviewed through round 9 with round-9 fixes themselves unreviewed, PR open, Mac gate outstanding; Yarn classic/Berry remain refusal; Poetry/PDM open)

Any of these may be taken after WP1 merges; each is its own PR.

- Python editable installs (`-e .` / the project itself) as a declared
  mutable overlay; dev/optional dependency groups installable by flag.
- `blanket add/remove/update` for pnpm projects (branch wp4/deps-pnpm-yarn,
  9 review rounds, the round-9 fixes themselves unreviewed; Mac gate
  outstanding). Workspace membership comes from `pnpm-lock.yaml`'s
  `importers` list and nothing else; `pnpm-workspace.yaml` is never read,
  because since pnpm 10 it is also the settings file of a repository that has
  no workspace. Yarn
  classic remains a refusal because it has no lockfile-only edit mode and a
  workspace-faithful scratch edit is future work; Poetry and PDM remain
  separate follow-up work (they still refuse with instructions; see
  LIMITATIONS.md).
- IMPLEMENTED and reviewed (branch wp4/x-lifecycle, 5 review rounds, MERGE on
  Linux evidence); Mac cold/warm gate outstanding:
  `blanket x --clean`, unregister an environment, protect a running tool from
  concurrent gc, repair a missing projection, and contain cleanup through
  open directory descriptors. (gc already knows the roots: src/gc.rs:111.)
  Covered by `cli::tests::x_owns_only_its_leading_flags`,
  `xrun::tests::shared_x_lock_blocks_nonblocking_cleanup_until_exec`,
  `xrun::tests::fd_relative_removal_does_not_follow_replaced_x_directory`,
  `xrun::tests::runner_and_cleanup_agree_about_a_symlinked_home`,
  `xrun::tests::cleanup_unlinks_the_root_lock_and_a_waiter_relocks_the_new_file`,
  `xrun::tests::ready_cache_hit_records_each_exception_once`,
  `x_clean_is_offline_and_strict_about_trailing_arguments`,
  `cached_x_narrates_each_object_exception_once`,
  `x_clean_py_leaves_legacy_npm_root`, and the ignored
  `x_clean_removes_registered_environment_and_running_x_is_busy`.
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
the ten `deps_e2e` round trips on the Mac suffice — including all four
pnpm cases: `pnpm_add_update_remove_roundtrip`,
`pnpm_workspace_member_and_root_roundtrip`,
`pnpm_edits_leave_an_installed_project_untouched` (runs the store pnpm's
real `install` first), and
`nested_independent_npm_project_does_not_use_ancestor_pnpm_lock`; `x`
lifecycle and any compiled-tool model for cargo/go tools need a Mac
cold/warm run because the binaries are per-platform artifacts; the
real-project-per-ecosystem proofs are measured on both machines and
recorded as two columns.

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
| 2026-09-07 | WP2 design (branch wp2/toolchain-lock-design, docs-only): the toolchain lock is designed in ARCHITECTURE.md — release-bundle catalog authority with catalog-authorized HTTPS artifacts and algorithm-qualified digests, recipe identities and bundle ids separate from component versions, the source-discovery matrix and supported request grammars, global cross-platform selection, one hardened descriptor-relative publication rule for both lock writers with unique temp names, an unconditional lock snapshot compare, value-based input staleness (a digest mismatch alone is never stale) in sync, `--frozen` and `status` alike, the `--frozen` write boundary with sandbox-only probes, the polyglot missing-section rule, conservative legacy seeding, store-root-scoped bundle-complete `x/3` keys, the pre-materialization extractor and `src/fsroot.rs` with named refusal tests, and dormant activation behind ordered PRs (item 0 open as #21/#22). Round 8 applies the owner's product decisions: the shipped catalog leaves the reproducibility path (a lock is honored from its own version/URL/digest/recipe rows, with an append-only provider host allowlist and append-only recipe ids, so upgrading blanket cannot invalidate a committed lock), publication uses a `/dev/urandom` temp name with `fsync`-rename-`fsync` durability (pid-plus-sequence dropped; the false `src/store.rs:69` citation removed), staleness compares the whole consulted path list including absent rows under root-anchored discovery, `bundle_id` and canonical lock bytes are defined, CLI.md's invented `(planned:)` markers are gone, and the sandboxed-evaluation guarantee is structural rather than an Elixir-only blocklist that missed the Ruby evaluator at `src/ruby.rs:582-596`. Review: Codex Sol rounds 1–4 (REWORK), Claude Opus 5 subagent rounds 5–6 (MERGE-AFTER-FIXES), round 7 a supervising-agent recheck of the round-6 fixes (not independent), round 8 owner decisions applied by the supervising agent and then reviewed in round 9, whose fixes round 10 reviewed in turn; round 10's fixes are the currently unreviewed layer. Implementation open. |
| 2026-09-07 | WP2 secure archive extractor (branch wp2/archive-extractor, ordered PR 2 of the design): `src/archive.rs` lists every tarball member and refuses absolute names, `..`, hard links, special files, and symlinks not lexically contained after `--strip-components` before tar writes anything; delegated tar runs with `TAR_OPTIONS` unset; per-platform listing parser (GNU tar / bsdtar), unparseable lines refuse. First consumer: the Go toolchain tarball (`extract_go_toolchain`), byte-identical extraction flags. Unit tests build hostile ustar members by hand and prove an outside sentinel and the destination stay untouched. No independent review yet (supervising agent only). |
| 2026-09-06 | WP2 Python exact-selection bugs fixed (branch wp2/python-exact-selection): an exact `.python-version` patch must be pinned or sync fails closed; `python::lookup` is exact-or-newest-minor over canonical spellings; regression tests use misordered synthetic pin tables in both orders; the ignored e2e proves the store is never opened. Sol: 3 rounds. |
| 2026-09-06 | WP2 Go exact-selection bug fixed (branch wp2/go-selected-version): realization takes the go.mod-selected version and an unpinned selection fails before store or network access; status compares the go.mod selection and treats pre-field closures as unchecked. Regression test `ensure_go_for_rejects_unpinned_version_before_store_access`. Sol: 3 rounds. |
| 2026-09-07 | WP4 x lifecycle (branch wp4/x-lifecycle): `blanket x --clean` removes and unregisters cached x roots through validated directory descriptors and fd-relative removal (symlinks unlinked, never traversed; candidate inode re-checked before removal); running tools hold an inherited shared lock under `~/.blanket/x/.locks/`, kept CLOEXEC until exec; cleanup resolves the home chain the way `blanket x` does, narrates each persisted exception once, unlinks its own per-root lock, and names `blanket gc --project` for node roots; legacy roots are matched by the exact generated package. Review: Codex Sol rounds 1–3 (REWORK), Claude Opus 5 subagent rounds 4 (MERGE-AFTER-FIXES) and 5 (MERGE; 5 nits recorded in REVIEW.md). Mac cold/warm gate outstanding. |
| 2026-09-07 | WP1 `blanket fmt` (branch wp1/fmt-rust): pinned rustfmt/cargo-fmt as its own store object (`rustfmt/1`, per-platform verified sha256, relative `lib` link to the paired Rust object, sandboxed pre-commit probe), lockless Cargo workspace discovery, a writable-project/no-network fmt sandbox mode on both engines with a shared setup-failure classifier, descriptor-anchored closure publication, `--check` and status pass-through, package.json `fmt` script precedence with an explicit `--eco` as the escape hatch, `stage-*` scratch so gc reclaims interrupted runs, `ls`/`sbom`/`gc` aware of the toolchain-only closure. Review: Codex Sol rounds 1–2 (REWORK), Claude Opus 5 subagent rounds 3–4 (MERGE-AFTER-FIXES) and 5 (MERGE; 3 nits recorded in REVIEW.md). Linux: `fmt_e2e`/`gc` `--ignored` green; acceptance 35/35 on 9fabfb5 (`tests/acceptance.sh`, disk-backed TMPDIR). Mac cold/warm gate outstanding. |
| 2026-09-07 | WP4 pnpm dependency edits (branch wp4/deps-pnpm-yarn): `blanket add/remove/update` delegate to the store pnpm at the exact `packageManager` release (Corepack `+sha224/sha256/sha512` suffix verified by algorithm, other algorithms refused by name), select the lock from `pnpm-lock.yaml`'s `importers` list alone, never from `pnpm-workspace.yaml` (which since pnpm 10 is also a non-workspace repository's settings file); a project the lock does not list inside a real workspace is refused rather than guessed, ancestor npm/Yarn locks are boundaries, and mixed roots are rejected before delegation, and run `--lockfile-only` with pnpm's modules state (`enable-modules-dir=false`, `modules-dir`, `virtual-store-dir`) redirected into a per-run store stage so an installed project's `node_modules` is neither read nor written; the `npm_config_` scrub is case-insensitive; lifecycle scripts are off for every verb. Yarn classic and Berry remain refusals with the conversion command; Poetry/PDM open. Review: Codex Sol rounds 1–2 (REWORK), Claude Opus 5 subagent rounds 3–4 (MERGE-AFTER-FIXES), round 5 a supervising-agent recheck of the round-4 fixes (not independent). Mac gate (the four pnpm `deps_e2e` round trips) outstanding. |
| 2026-09-08 | GC safety brief revised after a code-grounded review: `gc --forget` and `store roots` key display move from Package D into Package A as the recovery valve for the blocked sweeps A introduces (B upgrades forgetting to exclusive activity protection; D keeps the x-cleanup unregistration rules and the shared-dependency acceptance); B states the long-job-blocks-GC consequence and names the post-C/D relaxation of the execution-time hold as a follow-up; B pins the flock per-open-file-description rationale behind the recursive-acquisition ban and prefers a process-global guard registry keyed by canonical store root; B pins the supervisor design — same process group, terminal SIGINT/SIGQUIT/SIGHUP handled as no-ops rather than forwarded, SIGTERM forwarded once, reap-then-exit with the existing 128+n status mapping and the `kill -INT`-the-supervisor edge documented, stop/continue signals left at default, x's close-on-exec lock inheritance vestigial but retained; the busy-skip outcome exits 0 per the x convention and `store roots` is classified as needing no protection; Delivery records that the C/D producer audits dominate the effort. |
# GC safety implementation brief (2026-09-08)

Status: proposed implementation; no runtime changes made by this brief.
This is the next task requested by the owner, not a request to implement
the unrelated toolchain-lock design. Implement the packages below in order.

## Outcome and deliberate tradeoffs

1. Remember what a project needs even when its folder is unavailable.
2. Keep everything a running Blanket job could need until the job finishes.
3. Delete only after checking complete records; uncertainty keeps data safe.

First release deliberately retains every environment recorded for a project
until the user explicitly forgets that project. It also skips GC while any
job is using the same store, and because a job holds the shared lock through
execution, a long-running managed job (a dev server under `run`, a long x
session) postpones GC for its whole lifetime; cron or nightly collection on
an active machine will often report the skipped outcome. This costs disk
space and cleanup opportunities, but makes the initial safety contract small
enough to verify. Automatic retirement of old environments, collecting
unrelated objects during a running job, and — once Packages C and D make
root records the authority — relaxing the hold so it spans realization and
publication only, freeing GC to run during long executions, are follow-ups,
not acceptance requirements.

The guarantee covers cooperating Blanket processes on a local filesystem
with working advisory locks and atomic rename. Do not claim protection from
older Blanket binaries ignoring the new protocol, programs launched directly
from store paths, malicious same-user changes to the store, or detached
children that outlive the managed job. Document these boundaries explicitly.

## Relevant existing code

- `src/store.rs`: `RootEntry`, `register_root`, `roots`, `remove_root_entry`,
  `has`, `stage`, `commit`, `publish_lock`, `gc_lock`, `object_refs`, deletion
  helpers. Root records currently contain only a project pathname.
- `src/gc.rs`: `collect`, `collect_roots`, `read_closures`, `read_meta`,
  `mark_live`, and all four sweep functions. `collect_roots` currently drops
  an entry when a directory is missing. Activity uses a ten-minute timestamp;
  stages use a 24-hour threshold.
- `src/project.rs::write_closure`: shared publication point for ecosystem
  closures, already using directory descriptors for project-side writes.
- `src/main.rs`: command dispatch, `run_gc`, `run_store_roots`, and `run_run`.
  `src/cli.rs`: parsing, help, and completion definitions.
- `src/fetch.rs::CacheLease`: existing cache protection using `gc_lock`.
- `src/xrun.rs`: execution and explicit cleanup, including per-root locks.
  `src/sandbox.rs`: inherited-descriptor cleanup; do not assume a lock
  descriptor automatically survives sandbox execution.
- `tests/gc.rs`: existing integration test expects deleted projects to lose
  protection. Change that expectation, not merely the test's wording.

## Package A — stop forgetting unavailable projects

Ship this small safety fix first. Replace the automatic stale-root removal
in `collect_roots`. An unreadable/missing project or closures directory with
only a legacy pathname record must stop collection before ANY sweep starts.
Report which record cannot be resolved and how to register it once accessible.
Distinguish I/O errors instead of using `Path::is_dir` as a deletion decision.
Do not remove registry entries during ordinary GC, including dry runs.

Blocking is a full stop, so A also ships the recovery valve that Package D
used to own: `blanket gc --forget <root-key>...` (repeatable, exact keys,
no wildcard or pathname guessing) removes only that root's registry record
and never touches project files or store objects, and `blanket store roots`
prints each entry's key next to its path so the key of an unavailable
project is discoverable. Forgetting validates the key against existing
registry records alone and never resolves the project path, so it works
while the project is unavailable; removal is a single registry-file unlink,
and Package B wraps forgetting in exclusive activity protection once that
exists. `--dry-run --forget` simulates the removal in memory and writes
nothing. Registering and forgetting the same key in one invocation is
rejected. A forgotten project loses its protection by explicit choice;
ordinary GC still never removes records.

Acceptance: delete, rename, or make a registered project inaccessible; with
old objects and `--keep-days 0`, GC deletes nothing and preserves the record.
Forgetting the unresolvable root unblocks the next GC, which may then
collect its unshared objects when retention policy allows. Reject unknown
or malformed keys with a clear error. Use injected I/O errors for permission
coverage when tests run as root.

## Package B — protect the whole job, without a timer

Add a persistent `store/activity.lock` and an RAII `StoreActivity` guard in
`src/store.rs` (or a focused new module). Jobs take a shared OS lock before
the first store check/read/stage and hold it throughout realization,
publication, projection, and execution. GC tries an exclusive lock and,
if busy, returns a distinct skipped outcome: `cleanup skipped: a Blanket
job is using this store`. Do not print a successful collection summary for
this case; the skip is an expected outcome, not a failure, so exit 0 with
that line, matching the existing x busy-cleanup convention. Never unlink
this lock file. Failure to acquire/open it is an
error, never permission to proceed.

Acquire the activity lock before existing `gc_lock` and `publish_lock`.
When both existing locks are needed, preserve `gc_lock -> publish_lock`.
Acquire activity before x per-root locks too. Root-record writes use the
publication lock. Avoid recursive OS lock acquisition: `File::lock` is
flock(2), tied to the open file description, so a second `open` of the same
lock file inside one process holds an independent lock that conflicts with
the first — an in-process exclusive-over-exclusive acquisition deadlocks,
and so does a shared-to-exclusive upgrade, regardless of what the lock
names suggest. Share an existing guard for the same canonical store inside
a process — preferred: one process-global registry keyed by canonical store
root that hands back the already-held descriptor and counts holders, so
nesting reuses the held descriptor instead of opening a new one — or pass
a borrowed operation context explicitly. Do not silently open separately
locked handles in nested calls. No shared-to-exclusive upgrades; requesting
exclusive while shared is held in the same process is an error, not a wait.

Audit every command and library entry point that consumes or changes store
resources: implicit sync, plan when realizing tools, sync, build, run, fmt,
dependency editing, x, registration, forget and x cleanup. Read-only
inspections that read objects also need protection. Pure help/parsing and
store-path reporting need none, and `store roots` reads only the registry,
so it needs none either. Keep a coverage table in this section during implementation:
entry point, acquisition site, last resource use, release site. A guard only
in CLI dispatch does not protect public library realization calls; make the
operation context required by those APIs or acquire at their outer boundary.

For `run` and `x`, retain a supervising Blanket process holding the guard
until the foreground child exits, replacing final `CommandExt::exec` where
necessary. Preserve arguments, environment, working directory, stdio, exit
status, interrupt handling and Unix signal behavior. Share one process
execution helper rather than implementing these twice. Keep the child in
the supervisor's own process group — no setsid, no process-group changes —
so terminal-generated signals reach the child directly, and install no-op
handlers for exactly SIGINT, SIGQUIT and SIGHUP in the supervisor:
forwarding those would deliver each terminal signal twice. `SIGTERM` cannot
be terminal-generated, so its handler forwards once to the child. The
supervisor exits only after reaping the child, propagating its status with
the existing 128+n mapping for a signal-killed child (the npm script path,
src/main.rs:1709, is the precedent), and reports spawn failure the way the
replaced `exec` did. An explicit `kill -INT` aimed at the supervisor alone
is the one documented deviation: the child is not signaled, because the
supervisor cannot distinguish that from a terminal interrupt. Leave stop
and continue signals (SIGTSTP/SIGCONT) at their default so a ^Z stops
supervisor and child together exactly as the shell expects, and a child
that ignores a signal leaves the supervisor waiting, exactly as the shell
waits on an exec'd child today. Preserve the x per-root guard through the
same lifetime; the supervisor holding it makes the deliberate
close-on-exec clearing that used to carry it across `exec` vestigial, and
that mechanism stays in place — do not redesign x locking in this package.
The supervisor must not exit on a forwarded termination signal while
leaving the child using the store; handle and reap the child first. Normal
sandbox child descriptor scrubbing stays intact. A killed supervisor
or deliberately detached descendant is outside this first contract and must
be called out; do not claim crash-proof protection for surviving descendants.

GC holds exclusive activity protection from before reading roots until the
last deletion finishes. This covers objects, cached archives, stages, forests
and backups. Existing recency windows may remain as extra retention policy;
they no longer establish whether a job is active. Keep existing cache leases
until tests establish that changing them is necessary; do not redesign fetch
locking in this package.

Acceptance: two simultaneous jobs share the lock; GC skips while either is
alive, then collects after both finish, and the skip exits 0 with the
distinct line. Backdate an actively used object and
stage beyond all existing windows and prove they survive. Test nested store
calls and nested Blanket invocations without deadlock. Test foreground child
execution, nonzero exits, spawn failure, SIGINT and SIGTERM, the 128+n exit
status of a signal-killed child, a terminal SIGINT during the wait reaching
the child exactly once, and an abrupt exit with no surviving child. Use
subprocess barriers/pipes, not long sleeps.
Run execution/locking tests on Linux and macOS before calling support complete.

## Package C — keep project records inside the store

Replace pathname-only records with a versioned `root/2` JSON record under
the existing `roots/<key>` location. Retain the existing key for migration.
Fields: schema, root key, diagnostic project path, sorted unique object IDs,
and sorted unique managed projection references. Encode filesystem paths
losslessly (Unix path bytes with an explicit encoding); do not use display
strings as new authority. Projections must be typed references relative to
approved forests/backups bases, never arbitrary deletion paths.

Each successful closure publication adds its references to the root's
existing sets. It MUST NOT replace another ecosystem's references or remove
references from an earlier environment. The record is an accumulating safety
record, not a mirror whose contents shrink when project files disappear.
GC reads these records without opening the project directory. Project path
availability is diagnostic only. Forest retention must work offline too.

Introduce a typed `ClosureRefs` argument at `write_closure` and update all
callers: Python, Node, Cargo, Go, Ruby, Elixir, .NET and rustfmt. Callers supply
the exact environment/toolchain IDs and managed projections they created.
Do not infer the authoritative set by recursively searching arbitrary JSON
strings. Pass the actual Store explicitly instead of guessing it from body
paths. Validate IDs, projection components and store ownership at the API
boundary; reject absolute projection refs, `..`, and cross-store references.

Publication sequence while activity protection is held:

1. Validate the new reference set and its dependency metadata.
2. Under `publish_lock`, read and validate the previous record, merge sets,
   write a unique create-new temporary file, fsync it, rename atomically,
   and fsync the registry directory. Persist initialization only after a
   valid record is durable. Reuse existing descriptor-safe patterns.
3. Publish the project closure using the existing descriptor-relative writer.

Persist protection before publishing the closure. Failure after step 2 leaves
extra protection, which is safe. Failure before step 2 must not publish the
closure. Activity protection spans any earlier projection work as well.
Serialization must prevent two ecosystems publishing concurrently from
overwriting each other's references. Fault-inject each publication boundary.

Migration: accept legacy pathname records for inspection, but never interpret
unavailable ones as empty. `blanket gc --register <dir>` explicitly imports
all supported closure schemas using declarative, schema-specific readers,
then writes root/2. Unknown, malformed or ambiguous closures fail import
without replacing the old record. Migration must never execute project code,
run a package manager or access the network. Ordinary GC does not silently
rewrite records. An unresolved legacy record blocks the whole sweep until
registered or explicitly forgotten. Dry-run registration validates/reports
the proposed import in memory and writes nothing.

Acceptance: a project moved out of sight retains tools and forests; two
ecosystems and two historical environments all remain protected; a simulated
crash never leaves a visible closure with missing root protection. Include
non-UTF-8 paths, unknown schema, malformed IDs and symlinked registry entries.

## Package D — make deletion require complete evidence

Split GC into a read/validate/plan phase and a deletion phase. No destructive
action starts until ALL roots and metadata needed for the decision validate.
Treat malformed roots, unknown schemas and unreadable metadata as errors.
Missing or incomplete dependency information must not be silently treated as
an empty dependency list. In this first implementation, abort the whole
sweep on that uncertainty; do not invent partial-recovery rules.

The present `refs` field is generated by guessing from `Identity.inputs`.
Introduce versioned metadata with explicit typed object references and cache
digests supplied by realization callers at commit. Audit every commit caller
including shared toolchains, formatter-to-Rust references and native build
inputs. Record runtime dependencies at minimum; retaining build inputs too is
acceptable for this conservative release. Preserve existing object identity
hashes unless actual output inputs change. On cache hits, do not silently
certify old inferred metadata as the new complete schema.

Legacy metadata with unproven reference completeness blocks destructive GC
until explicitly migrated from a known schema with a tested adapter. Supply
adapters for currently shipped identity kinds; unknown kinds stay blocked.
Migration can add metadata atomically under protection without changing object
contents, but must validate the expected ID and reject inconsistent existing
data. `--collect-legacy` cannot override incomplete evidence; update help and
tests to explain the stricter behavior. This may leave some old stores unable
to collect safely; list the exact unresolved kinds and recovery action.

Starting with every durable root, traverse explicit dependencies transitively.
Also retain dependencies of objects retained by existing age/legacy policy.
An object can be removed only when it is absent from that complete retained
set, activity is exclusively locked, and retention policy permits deletion.
Cached artifacts use explicit digests; managed projections use explicit root
references. Preserve existing age settings unless separately documented.

Use the same validated in-memory deletion plan for dry-run and real GC.
Dry-run never removes roots, migrates records or refreshes timestamps. Report
skipped/blocked decisions distinctly from candidates and freed bytes. Hold
locks until execution finishes; do not save a plan and later execute it
without repeating validation. Use held parent-directory descriptors and
existing no-follow removal primitives for deletion. Never follow a symlink
outside the managed directories. Recheck candidate identity before removing
it; replacement or an unexpected file type stops that deletion with an error.

Package A already shipped `blanket gc --forget <root-key>` (repeatable) and
key display in `blanket store roots`: forgetting explicitly removes only that
project's protection record, even if its folder is unavailable; it never
deletes project files. Subsequent GC may reclaim its unshared resources.
D's obligations are the upgrades: forgetting takes exclusive activity
protection so it cannot race a job publishing the root, and the deletion
plan treats a forgotten root as removed before traversal — what remains
collectible is recomputed from the surviving records, never assumed from
the forgotten root's contents. x cleanup may unregister its root only after
successful validated cleanup and with the same lock order; failed/busy
cleanup retains protection.

Acceptance: shared dependency survives forgetting one of two projects; after
forgetting both it becomes collectible when age policy allows. Corrupt a late
root/metadata entry and prove no earlier candidate was deleted. Cover missing
transitive metadata, cycles, unknown metadata schema, invalid refs, traversal
strings, symlink replacement, dry-run immutability, and failed x cleanup.

## Delivery and verification

Use four reviewable commits/packages in the order above. The locking and
supervision code in B is the smallest part; the producer audits in C (a
declarative reader per shipped closure schema) and D (explicit refs at
every commit caller plus a tested adapter per shipped identity kind) are
the majority of the effort and should be sized as such. Within C and D,
migrate producers before enabling collection based on the new schema. Do not
ship a permissive fallback just to keep legacy tests green. Do not implement
per-object leases, automatic expiry of missing roots, background GC, remote
store locking, general path-resolution redesign or toolchain-lock validation
as part of this task.

Add fast offline subprocess tests to normal test execution; the key safety
cases must not live only in ignored network integration tests. Test stores
must be temporary; environment-mutating unit tests use `STORE_ENV_LOCK`.
Run `cargo fmt --check`, `cargo test`, then relevant ignored `gc`, `fmt_e2e`
and x lifecycle integration tests on a disposable store. Check actual test
target names before invoking them. Record commands, results and platform
gaps. Update CLI.md, ARCHITECTURE.md and LIMITATIONS.md to match delivered
behavior; append review status to REVIEW.md. In the final implementation
report, explain plainly that unavailable projects remain protected, active
jobs postpone cleanup, and forgetting a project is now an explicit action.

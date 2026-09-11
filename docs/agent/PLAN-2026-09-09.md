# Blanket — implementation plan (rewritten 2026-09-09)

This is the one working document for what remains to be **built**. An engineer
handed this file should be able to pick the next open work package, implement
it, get it reviewed, merge it, and update this file. Everything else in the
repo is reference:

| File | What it is |
|---|---|
| `ARCHITECTURE.md` | how the system works, and the WP2 toolchain-lock design |
| `CLI.md` | the command surface (help screens and grammar are specs) |
| `LIMITATIONS.md` | honest ledger of what is wrong or missing |
| `REVIEW.md` | what has **not** been independently reviewed |
| `REVIEW-2026-09-06.md` | the written findings of the 2026-09-06 review |
| `PLAN-REVIEW-2026-09-09.md` | this re-review's findings and incorporated corrections |
| `HITRATE.md` | hit-rate measurements, dated columns |
| `LINUX_PORT.md` | platform changelog; append when platform behaviour changes |
| `blanket-notes.md` | design history |
| `NEXT.md` | frozen index of shipped item numbers (do not rename, do not reuse numbers) |

`REVIEW.md` tracks a different debt from this file: this file says what to
build, `REVIEW.md` says what has not been adversarially checked. Do not merge
the two ledgers.

**Read this file as a roadmap, not as a completion claim.** Section 3 is the
status index; package sections describe delivered and remaining work in detail.
Resolve disagreements against commit, review, and test evidence, then update
both sections. A heading or summary is never evidence by itself.

**Implementation handoff, re-reviewed 2026-09-09.** Read
`PLAN-REVIEW-2026-09-09.md` for the findings behind this revision. The
working tree now contains the Linux implementation of GC safety Packages A–D
on `wp-gc-safety`, including the source, tests, and directly related
documentation. Do not blindly commit the whole dirty tree: isolate this work
from the broader plan rewrite, run the gates, and obtain the independent
review it still lacks. WP0 transcript capture and the small WP1 follow-ups can
proceed separately. Mac-before-merge remains the standing gate unless the
owner explicitly waives it. Do not wait until September 12: review
availability has already been restored.

The contracts below supersede the earlier GC API and signal recipes. Keep
the approved supervisor, conservative retention, and automatic migration.
Use explicit activity ownership; publish durable protection before switching
projections; migrate under a separate exclusive maintenance phase. Later WP3
key/credential inputs do not block this GC sequence.

---

## 1. What blanket is and where it is going

One binary that owns the outer loop every language shares: provision a pinned
toolchain, realize a locked dependency graph into an immutable
content-addressed store, project an environment, run the code. Seven
ecosystems (Python, npm, Cargo, Go, Ruby, Elixir, .NET) on macOS arm64 and
Linux x86_64. Resolution is deliberately delegated to each ecosystem's own
pinned tool; blanket owns everything after resolution. Nix's model without
Nix's interface.

### Standing decisions (taken with the owner 2026-09-06, still in force)

- **One product, one switch.** There is no personal track and no enterprise
  track. Permissive by default; `.blanket/policy.toml` (strict, deny lists,
  and the package-level rules in WP5) is the company layer. Nothing is ever
  loosened silently.
- **Personal daily driver is the road; enterprise is the destination.**
  The store model supports verified inputs and managed closures, but
  `LIMITATIONS.md` still records unpinned host build inputs, delegated planners,
  and incomplete enforcement. Do not describe those properties as complete.
  Company enforcement follows daily-driver work, except the protected source
  policy that WP3 needs before authenticated catalog refresh.
- **Headline feature: `blanket fmt` just works.** In a Rust project it fetches
  the pinned rustfmt if missing and runs it. There is never a separate
  `blanket install <tool>` step. This is the shape every tool invocation
  should have.
- **Toolchain versions must track upstream without code edits.** Today every
  CPython/Node/Rust/Go/Ruby/OTP/.NET version is a hand-typed pin table in
  `src/*.rs`. This is the largest gap between the code and the owner's intent.
- **Two platforms, both gated.** macOS arm64 and Linux x86_64 are the product.
  The code is written once with per-platform pin rows, and the Linux unit
  suite carries frozen darwin identity goldens, so a Linux run proves the
  *plan* is identical on the Mac. It does **not** prove the Mac can *execute*
  it: the sandbox engine (Seatbelt vs bubblewrap), tar (BSD vs GNU), file
  cloning (clonefile vs reflink), the host C toolchain (Xcode vs gcc), native
  library provisioning (Linux only today), and the inherited-descriptor scrub
  (`src/sandbox.rs:591-635` is `#[cfg(target_os = "linux")]` with no Seatbelt
  counterpart) all differ at runtime. Windows is out of scope until further
  notice; it is a different product surface, not a port, and nothing in this
  plan should bend toward it.
- **"One door" stays qualified.** Blanket is a complete manifest of what came
  through *it*; without CI admission, registry proxies, or device management
  it is door fifty-one. Keep that sentence wherever the pitch appears.

---

## 2. Working rules for agents

- **Read first:** `CLAUDE.md` (invariants), `ARCHITECTURE.md`,
  `LIMITATIONS.md`, and the work package you are taking. Check `REVIEW.md`
  before trusting a recent feature.
- **One work package per branch per PR.** Rebase on main; do not bundle.
  Parallel agents use separate git worktrees.
- **Gates before a PR:** `cargo fmt --check`; `cargo test` (offline; capture
  cargo's exit status, never pipe to `tail`); the relevant `--ignored` network
  tests with a disposable `BLANKET_STORE`, disk-backed `TMPDIR`, and on Linux
  `BLANKET_SANDBOX_TESTS=required`. Use `--target-dir`, never
  `CARGO_TARGET_DIR` (it also redirects nested fixture builds).
- **Mac before merge.** Agents run on the Linux box; the Mac is the owner's
  laptop. Every work package below carries a **Mac before merge** line naming
  exactly what must run there. The established procedure: the owner (or a
  terminal agent on the Mac, which runs under Codex's sandbox with
  `LANG=C.UTF-8` and `ps` blocked) checks out the branch, runs the listed
  commands, and pastes the results or pushes a `mac-verify-*` branch with any
  fix, as PRs #2–#4 did. A PR does not merge on Linux evidence alone unless
  the owner says so, and then `REVIEW.md` gets a row saying "Linux evidence
  only" that WP0-style work must later clear. Default Mac gate for any PR:
  `cargo build`, `cargo test`, and the `--ignored` tests the PR touches.
- **Independent adversarial review before merge.** Sol (Codex,
  `codex exec -m gpt-5.6-sol -c model_reasoning_effort=xhigh -s read-only
  -o <out> "<brief>" < /dev/null`)
  reviews the diff with a written brief; fix every blocker/should; Sol
  rechecks. Implementation is Luna (`-m gpt-5.6-luna`). Astra (`gpt-6-astra`)
  is reserved for owner-requested plan reviews: it costs too much usage for
  per-PR rounds. Self-review only downgrades a `REVIEW.md` entry, never clears
  it. If Codex is rate-limited, a fresh Claude subagent that did not write the
  code is the stand-in, and `REVIEW.md` records that it was not independent.
  `REVIEW.md` records a Codex usage limit hit on 2026-09-06; **the owner
  confirmed on 2026-09-09 that the limit has reset and Codex is available
  again.** Reviews proceed normally. The Claude-subagent rounds run during the
  outage are still marked "not independent of Claude" and stay 🟡 until a Codex
  round clears them — that is a record of how they were reviewed, not a queue
  of blocked work.
- **Invariants that end a PR if broken:** store objects are input-addressed
  and immutable (new *semantics* need a new identity field; note that object
  *metadata* under `meta/<id>.json` is outside the identity hash, so adding
  metadata fields is not an identity change — `src/types.rs:19-29`); darwin
  identity goldens stay byte-identical (`python::tests::darwin_identity_unchanged`, `src/python.rs:329`;
  `cargo::tests::darwin_identity_unchanged`, `src/cargo.rs:1293`); every pin carries a verified algorithm-qualified digest (including existing sha512 pins); platform
  helpers take an explicit `Platform`; permissive mode records an exception,
  it never hides one.
- **Bookkeeping in the same PR:** `LIMITATIONS.md` gains or loses a row;
  `REVIEW.md` log gets a row; when a hit-rate measurement was actually run,
  `HITRATE.md` gets a dated column, never an overwrite; section 3 of this file is updated; `LINUX_PORT.md` gains an entry
  if platform behaviour changed. Stale references in code comments and
  user-facing strings to "NEXT.md item N" are replaced with the behaviour they
  describe when the file is touched anyway.
- **Test hygiene (from `CLAUDE.md` and past non-determinism):** never point
  `BLANKET_STORE` at a real store; it is process-global, so a test that sets
  or clears it holds `store::STORE_ENV_LOCK`. Tests recording policy
  exceptions take the matching guard around `policy::clear()`. Use subprocess
  barriers (FIFOs, pipes) rather than sleeps in concurrency tests.
- **Do not** change default toolchain versions, write into a user's project,
  or widen what a bare word can trigger, outside the work package that
  specifies it.

---

## 3. Status ledger

The tables separate delivered work, outstanding review, remaining scope, and
external gates. A delivered feature can also have a platform gate; that is a
different status dimension. No entry asserts evidence the repository lacks.

### 3.1 Implemented and independently reviewed (✅ in `REVIEW.md`)

| Work | Where | Evidence |
|---|---|---|
| CLI levels 1–2 | `src/cli.rs`, `src/main.rs`, `src/deps.rs`, `src/inspect.rs`, `src/xrun.rs`, `src/ui.rs` | `REVIEW.md` entry 1; Astra 2026-09-06 |
| Git dependencies (item 4) | `src/gitsrc.rs` and callers | `REVIEW.md` entry 2 |
| Artifacts / electron provisioning (item 5) | `src/artifacts.rs`, `src/npm.rs` | `REVIEW.md` entry 3 |
| PR #19 review fixes | `2967d4a`, `c3de1bd` | `REVIEW.md` entry 4 |
| Items 7, 10, 12 and the original `gc` | `src/npm_lock_import.rs`, `src/manifest.rs`, `src/nativelibs.rs`, `src/gc.rs` | `REVIEW.md` entry 5 |
| WP2 secure archive extractor | `src/archive.rs` (+ Go tarball as first consumer) | `REVIEW.md` 2026-09-08 round 3, report `wt/logs/wp2-archive-extractor.r3.report.md` |
| WP2 Python exact selection | `src/pyselect.rs`, `src/python.rs` | Sol, 3 rounds |
| WP2 Go exact selection | `src/golang.rs` | Sol, 3 rounds |

Every ✅ row above is ✅ **on Linux evidence**. See 3.4.

### 3.2 Implemented, but a review round or a reviewer's follow-up is outstanding

| Work | Where | What is missing |
|---|---|---|
| **GC safety Package D (rewrite)** | uncommitted on `wp-gc-safety`: `src/objmeta.rs` (new), `src/gc.rs`, `src/store.rs`, `src/cargo.rs`, producer drift tests, `tests/cli.rs` | **Every review round.** The rewrite is the author's own work and has had no independent adversarial pass. Highest-value targets are listed at the end of §5.4. macOS untouched |
| **GC safety Packages B and C** | uncommitted on `wp-gc-safety`: `src/activity.rs`, `src/supervise.rs`, `src/fetch.rs`, `src/store.rs`, `src/project.rs`, `src/gc.rs`, `src/main.rs`, `src/cli.rs`, ecosystem producers, `tests/gc.rs`, `tests/supervise_signals.rs` | One independent adversarial round each, 2026-09-09, both **fix-first**; the named blockers are fixed and the signal/PTY transcript now exists. Still open: B.4's audit table, B.5's exclusion list, the session-serialisation and `Store::has` lock-order findings, C.10's missing test matrix, `src/fsroot.rs`. macOS gate untouched. See `REVIEW.md` |
| WP2 design round-10 fixes | `ARCHITECTURE.md` §"Toolchain lock" | round 10's own fixes are the currently unreviewed layer |
| WP2 extractor round-3 follow-up | `src/archive.rs` | reviewed ✅, but the reviewer's architectural finding stands: column-parsing `tar -tv` is not a durable foundation; read tar headers directly before a **second** consumer adopts the module |
| WP4 pnpm edits, including round-9 fixes | `src/deps.rs`, `src/npm_lock_import.rs` | earlier Sol review does not clear the later Claude fixes; final independent round outstanding |
| WP4 `x` lifecycle | `src/xrun.rs`, `src/cli.rs`, `src/gc.rs` | final Claude-only rounds need an independent follow-up; Mac gate outstanding |
| WP1 `blanket fmt` | `src/rustfmt.rs`, `src/main.rs`, `src/sandbox.rs`, `src/project.rs` | final Claude-only rounds need an independent follow-up; Mac gate outstanding |

### 3.3 Partially implemented

| Work | Done | Not done |
|---|---|---|
| **WP2 toolchain lock** | design in `ARCHITECTURE.md` (10 rounds); ordered PR 0 (exact selection, Python + Go) and ordered PR 2 (`src/archive.rs`) merged | ordered PRs 1, 2b, 3, 4, 5: archive-header follow-up, shipped-table adapter and source selection, the dormant lock core with `src/toolchain_input.rs` and `src/fsroot.rs`, runtime propagation, activation and `update --toolchain`. Neither `src/toolchain_input.rs` nor `src/fsroot.rs` exists yet |
| **WP4 daily-driver gaps** | pnpm `add`/`remove`/`update`; `x --clean` lifecycle | Yarn classic/Berry (refusal), Poetry/PDM (refusal), Python editable installs and dependency groups, `x` for cargo/go/gems/hex/nuget tools, `fmt` for non-Rust ecosystems, per-ecosystem real-project hit-rate rows, SBOM `vcs` refs, SPDX, Cargo workspace-inherited Git vendoring |
| **GC safety** | Packages A–C implemented and adversarially reviewed once each (B and C fix-first, fixes applied); **Package D rewritten 2026-09-09** after failing its round — per-kind/per-schema adapters, the D.4 phase split, the coverage matrix and all 27 D.10 tests now exist and pass on Linux | Package A still has no independent round; **the Package D rewrite has had no review at all** and is author's-own-work — see `REVIEW.md` and §5.4; macOS gate untouched for every package. A pre-existing Package B defect surfaced: parallel test threads collide on the one-supervised-child-per-process rule, so `--ignored` targets need `--test-threads=1` |
| **`blanket fmt`** | Rust | every other ecosystem (WP4) |

### 3.4 Blocked on the owner's Mac, external parties, or independent review

Nothing in this bucket may be described as done, and no work package may
assume it has cleared.

| Blocked item | Blocked on | Evidence in repo |
|---|---|---|
| **WP0** — a recorded macOS run against current main | capturing the transcript | the owner stated 2026-09-09 that the Mac is on the current build and healthy. No command output is recorded, so the four Mac gates below stay open as *bookkeeping*; this is not a doubt about the machine. Last **recorded** Mac run is `dbf7ac4`, 2026-09-05, acceptance 35/35 (`README.md`, `LINUX_PORT.md`) |
| Mac gate for WP1 `fmt` | a recorded run | `REVIEW.md` "Mac gate outstanding" |
| Mac gate for WP4 `x` lifecycle | a recorded run | `REVIEW.md` "Mac gate outstanding" |
| Mac gate for WP4 pnpm edits | a recorded run | `REVIEW.md` "Mac gate outstanding" |
| Mac gate for WP2 extractor (bsdtar column layout verified on libarchive 3.8.7 only) | a recorded run | `REVIEW.md` round-3 row |
| WP3 provider signature verification | external providers | **no signing material, key, or verified signature exists in this repository.** Every statement about which upstreams publish signatures is an unverified assumption until WP3's evidence spike records it |
| WP3 trusted publisher keys, rotation, revocation | the owner | no key material in the repo |
| WP5 private-registry authentication | the owner / credentials | no credentials in the repo |
| Rebuilt Linux OTP artifact on an older glibc baseline | build host + the owner | `LIMITATIONS.md:63` |
| Shared store / binary cache | real demand | none recorded |

### 3.5 Genuinely open

WP0 (transcript capture, see 3.4), the remaining WP1 gate work, WP2 ordered PRs 1/2b/3/4/5,
all of WP3, the WP4 items listed in 3.3, all of WP5, the independent review
and platform gates for GC safety Packages A–D, and the backlog in section 6.

---

## 4. Work packages

Implementation order: isolate and review the implemented **GC A–D** work;
WP0 transcript capture and WP1 nits are parallel obligations, not
prerequisites for the Linux GC implementation. **GC safety B/C/D precede WP2
lock-core work** (section 5 — this is the owner's current request and it
changes `Store::commit`, `write_closure`, and the process model, so it should
land before WP2's lock core touches the same files); WP2 before any default
toolchain changes; WP3 needs WP2; WP4 items may interleave anywhere after
WP1; WP5 last.

### WP0 — macOS arm64 validation of current main — OPEN; the Mac is available, the transcript is not captured

**Objective.** Prove the Mac can *execute* what the Linux suite proves it can
*plan*, and **write the proof down**.

**Owner statement, 2026-09-09:** the MacBook is on the current build and
everything is working there. That resolves the availability question — WP0 is
no longer waiting on access, only on someone capturing the output. Treat this
package as a transcript-capture job, not an investigation. Until the transcript
exists, `REVIEW.md` and §3.4 keep saying "Mac gate outstanding", because the
repository records evidence, not assurances; that distinction is bookkeeping
hygiene rather than scepticism.

**User-visible behaviour.** None; this package changes no behaviour. Its
output is evidence.

**What the Mac has already proven.** At commit `dbf7ac4` (2026-09-05, PRs
#2–#4, `LINUX_PORT.md` rounds 1–3): `cargo build`, `cargo test`, and
`tests/acceptance.sh` 35/35 on macOS arm64, after three Mac-found fixes (Go
locale, an `unused_mut` warning, the .NET CoreCLR shm directory).

**What it has not.** Everything merged since, which now includes: Git sources
(#14–#16), artifacts and electron provisioning (#13, #17), pnpm/yarn
importers, manifest coverage, build isolation, native libraries, `gc`, the CLI
(#20), the 2026-09-06 review fixes (#19 and follow-ups), the in-process ustar
check that replaced trusting tar's exit code (`f856e98`), the pnpm empty-lock
fix, the rustfmt pass, `src/archive.rs`, WP1 `fmt`, the `x` lifecycle, the
pnpm dependency edits, and (once merged) GC safety Package A.

**Highest-risk Mac-only breaks, in order.**
1. **bsdtar under `src/archive.rs`.** The listing parser's column model was
   verified against GNU tar 1.35 and libarchive 3.8.7 on Linux only. The
   round-2 review found a fifth unmodelled GNU layout nobody predicted; assume
   bsdtar on macOS has its own.
2. **The `fmt` sandbox mode under Seatbelt** — a writable project tree with a
   read-only store is a new Seatbelt profile shape.
3. **`clonefile` projection** for editable/mutable trees.
4. **The inherited-descriptor scrub.** `src/sandbox.rs:591-635` is Linux-only;
   macOS has no counterpart, so a leaked descriptor into a Seatbelt child is
   not detected by any existing test.
5. **`x` cold/warm** — per-platform binaries, so a Linux warm run proves
   nothing about the Mac.

**Mac before merge (this is the whole package).** On a single named commit of
`main`, recorded by hash:
```
cargo build
cargo test
cargo test -- --ignored     # disposable BLANKET_STORE, disk-backed TMPDIR
bash tests/acceptance.sh
cargo test --test deps_e2e -- --ignored    # the ten deps_e2e round trips
cargo test --test fmt_e2e  -- --ignored
cargo test --test gc       -- --ignored
blanket x ruff --version   # cold, then warm
blanket x prettier --version
```

**Bookkeeping.** Record results in `REVIEW-2026-09-06.md`; add the `REVIEW.md`
log row; append a round-4 entry to `LINUX_PORT.md`. Any Mac-only fix goes on a
`mac-verify-round4` branch like the earlier rounds. Re-measure the two
`npm_git_dep` hit-rate rows (hoppscotch, tabby) that predate Git sources, as a
dated column in `HITRATE.md`.

**Completion criteria.** A named commit hash, a pasted transcript of each
command above, a `LINUX_PORT.md` round-4 entry, and a `REVIEW.md` row. WP0 is
not complete while any listed command is unrun; a partial run is recorded as a
partial run.

#### Recommended decision (owner approval required)

Run WP0 against a **frozen commit** taken after GC safety Package A merges and
before Package B starts, rather than chasing `main`. Rationale: B changes the
process model on both platforms, so a Mac baseline taken just before it is the
useful comparison point. *Requires the owner: only they have the Mac.*

---

### WP1 — `blanket fmt` — IMPLEMENTED and reviewed (5 rounds, MERGE on Linux evidence); Mac gate outstanding

**Objective.** `blanket fmt` in a Rust project fetches the pinned
rustfmt/cargo-fmt component if missing and runs it, with no separate install
step.

**Delivered.** `src/rustfmt.rs` (per-platform verified sha256, `rustfmt/1`
identity, allowlisted extraction, relative `lib` link to the paired Rust
object, sandboxed pre-commit probe), `src/main.rs::run_fmt`,
`src/cli.rs::parse_fmt` and `LS_WORDS`, `src/sandbox.rs` (status-returning
runner, shared `sandbox-exec:`/`bwrap:` setup-failure classifier),
`src/project.rs` (descriptor-anchored closure publication), `src/cargo.rs`,
`src/inspect.rs`, `src/sbom.rs`, `src/gc.rs`, `tests/fmt_e2e.rs`,
`tests/cli.rs`. Lockless Cargo workspace discovery; a writable-project,
no-network fmt sandbox mode on both engines; `--check` and exit-status
pass-through; `package.json` `fmt` script precedence with `--eco` as the
escape hatch; `stage-*` scratch so gc reclaims interrupted runs.

**Remaining work — three open nits from round 5** (each is its own small PR
or folded into the Mac-fix branch):

1. `--eco` typo is an exit-1 refusal, not a suggestion. *Change:*
   `src/cli.rs::parse_fmt` — on an unknown `--eco` value, list the known
   ecosystems in the error. *Test:* `cli::tests::fmt_eco_typo_lists_choices`.
2. The bubblewrap host-socket scan is Linux-only (documented in
   `LIMITATIONS.md`, no code change intended). *Bookkeeping only:* confirm the
   `LIMITATIONS.md` row still reads correctly after the Mac gate.
3. `blanket ls rustfmt` not-found advice says "run `blanket sync`", which is
   wrong: the rustfmt closure is created by `fmt`, not `sync`. *Change:*
   `src/inspect.rs` ls not-found message. *Test:*
   `inspect::tests::ls_rustfmt_not_found_names_fmt`.

**Mac before merge.** The rustfmt component's darwin pin row and verified
sha256 must realize on the Mac; the fmt execution mode goes through Seatbelt,
not bubblewrap. Run the cold and warm acceptance (`blanket fmt --check` in a
fresh clone with no store, then again), `cargo test`, and
`cargo test --test fmt_e2e -- --ignored`. Darwin identity goldens must be
unchanged.

**Independent review.** Rounds 1–2 were Sol (independent); rounds 3–5 were a
Claude subagent (fresh, but not independent of Claude). One fresh Codex round can run now to close this properly.

**Completion criteria.** The three nits fixed with the named tests; the Mac
gate transcript recorded; `REVIEW.md` entry 6 moved off "Linux evidence only".

---

### WP2 — Toolchain lock and exact version selection — DESIGN REVIEWED; ordered PRs 0 and 2 landed; PRs 1, 2b, 3, 4, 5 OPEN

**Objective.** A committed toolchain lock outside the ignored `.blanket/`
records, per ecosystem, the exact provider build, components, and per-platform
algorithm-qualified digests. Honoring a lock chooses no new version and consults no refreshed catalog.
It still validates local source/trust policy and, once WP3 enables publisher
authentication, the required proof. A catalog or binary upgrade alone cannot
change the locked bytes; explicit revocation or tightened policy can refuse
their use without rewriting the lock.

**Prerequisites.** Follow the GC-first sequence in §4. **Do not start PR 3 (the lock
core) before GC safety Package C** — both rewrite `project::write_closure`'s
signature and its callers, and doing them in either order is fine but doing
them concurrently guarantees a painful merge. The recommended order is C, then
D, then WP2 PR 3.

**Design.** `ARCHITECTURE.md` §"Toolchain lock and exact version selection"
(lines 633–1279) is the contract after ten adversarial rounds. Changes to the
contract update `ARCHITECTURE.md` in the same PR as the affected
implementation. The design's load-bearing conclusions, in one paragraph each,
so this file does not drift from it:

- **The shipped catalog is off the reproducibility path.** A lock row carries
  version, URL, algorithm-qualified digest, and recipe id — everything
  realization needs to select the artifact. The catalog is consulted only
  when *choosing* a version, at lock creation and `update --toolchain`.
  Retrieval checks the digest and the effective configured endpoint policy,
  including every redirect. Shipped upstream endpoints are defaults, not an
  unchangeable allowlist. Recipe ids remain append-only. Authentication is a
  separate predicate from matching a lock-supplied checksum; WP3 adds that
  predicate and its locally replayable proof.
- **Publication uses OS randomness and real durability.** A `/dev/urandom`
  temp name (the source already in `src/sbom.rs`, factored into one shared
  helper), `O_EXCL`, `fsync` the file, `renameat`, `fsync` the directory.
  Pid-plus-sequence was dropped because it has fixed points (a sequence
  restarts at 0; PID namespaces reissue small pids), so one leftover temp
  would wedge every later run of a container image.
- **Staleness compares the whole consulted path list, including absence.** A
  source appearing where the lock recorded `absent` is stale. Discovery is
  anchored at the project root, never at cwd. Only a re-parsed `value`
  decides; a digest mismatch alone is never stale, so `blanket add` rewriting
  a multi-purpose manifest cannot wedge the lock.
- **`bundle_id` and the lock's canonical bytes are defined** as
  length-prefixed records with a leading serialization-version record.
- **Frozen toolchain-lock validation evaluates no project code.** The rule is
  scoped to *validation*: a passing frozen run then continues into ordinary
  dependency planning, which does delegate to native tools that evaluate
  project code — the delegated-resolver boundary the design already accepts.
  Every toolchain-input reader is declarative-only and lives in a named module
  `src/toolchain_input.rs`, with a per-ecosystem test that the reader spawns
  no process. A project whose only statement of its version is *computed*
  (`setup.py` metadata, `mix.exs` compatibility) fails frozen closed with a
  message naming the declarative file to add.

**Remaining ordered PRs** (numbering matches `ARCHITECTURE.md:1254-1279`):

**PR 1 — shipped-table adapter and source selection.**
- *Files:* `src/python.rs:22-85`, `src/npm.rs:122-135`, `src/cargo.rs:25-68`,
  `src/golang.rs:32-45`, `src/ruby.rs`, `src/elixir.rs`, `src/dotnet.rs`,
  `src/platform.rs:83-86`, plus a new selector module.
- *Data model:* the compiled pin rows become catalog rows carrying version,
  URL, algorithm-qualified digest (carrying the existing sha512 rows .NET/Hex/
  rebar already use), recipe id, and platform.
- *Behaviour:* selection uses the **intersection of complete releases across
  both supported platforms**, so asymmetric catalogs produce identical lock
  bytes from either platform value.
- *Also in this PR:* define a typed source-policy interface with shipped
  endpoint defaults and explicit publisher/endpoint/credential-reference
  fields. WP3 supplies protected policy loading and authentication; WP2 must
  not embed an append-only host list into lock validity. Never put secrets in
  catalog rows or locks. Provider-specific credentials are not needed for
  this interface/fixture work.
- *Also in this PR:* legacy seeding — evidence-based success plus the refusal
  when evidence is missing, per the per-ecosystem table at
  `ARCHITECTURE.md:1218-1226`.
- *Not in this PR:* lock-byte or replay tests; the format does not exist yet.
- *Today's gap this fixes:* Node, Ruby and Elixir select nothing and .NET
  accepts one fixed SDK (`npm::node_pin`, `src/npm.rs:137`; `ruby::ruby_pin`,
  `src/ruby.rs:57`; `dotnet::SDK_VERSION`, `src/dotnet.rs:27`, enforced at
  `src/dotnet.rs:132` and `src/dotnet.rs:338`).

**PR 2b — archive-header follow-up, before a second consumer.** Replace the
`tar -tv` column parser with direct tar-header validation, including supported
extended headers and all existing traversal/link/special-file refusals.
Preserve the existing Go consumer and outside-sentinel tests; verify GNU tar
and macOS extraction behavior. No other toolchain adopts the extractor until
this PR passes review. It is a scheduled prerequisite, not an unranked nit.

**PR 3 — lock core, dormant.**
- *Files:* new `src/toolchain_input.rs` (per-ecosystem declarative readers),
  extend the descriptor-relative helper extracted by GC C as `src/fsroot.rs` (root helper: `openat`/`O_NOFOLLOW`
  walk, `O_EXCL` create on a `/dev/urandom` name, file `fsync`, `renameat`,
  directory `fsync`), plus `src/cli.rs`, `src/main.rs`, project input
  handling; move `src/sbom.rs`'s `/dev/urandom` read into the shared helper
  rather than adding a second randomness path.
- *Tests:* one per ecosystem asserting the reader spawns no process; `fsroot`
  refusals for a symlinked `blanket-toolchain.toml`, a symlinked input file, a
  symlinked ancestor directory, and an occupied temp name — and a test that
  `fs::read`/`fs::write`/`fs::rename` do **not** pass those refusals.
- *Concurrency integration:* the toolchain-input lock is distinct from C's
  project transaction lock. Acquire activity → x-root (if any) → toolchain
  input lock → project transaction → cache → publication. Do not repurpose a
  shared input lock as an exclusive publication lock. Pure frozen input
  validation must complete before any store bootstrap or automatic metadata
  maintenance writes; preserve the frozen no-writes regression.
- *Activation stays off:* the lock is neither written nor required.

**PR 4 — runtime propagation.**
- *Files:* `src/main.rs:1598` (Node `run` takes the global pin via
  `npm::ensure_node_for`; likewise `src/main.rs:1008` and `src/xrun.rs:1546`,
  `src/xrun.rs:1827`), `src/xrun.rs:98` and `src/xrun.rs:1582` (the `x/2`
  cache keys omit runtime identity — the design's `x/3` key is
  store-root-scoped and bundle-complete), `src/inspect.rs` (`status` must compare toolchain inputs),
  `src/project.rs` and every closure writer (closure-selected runtimes,
  refresh isolation, old-`x/2` non-reuse).
- *Security requirement:* a catalog refresh must never pair old dependencies
  with a new runtime silently.

**PR 5 — activation and `update --toolchain`.**
- *Files:* `src/cli.rs`, `src/main.rs`, the lock core, integration tests.
- *Behaviour:* first writable sync of a project with no pin creates the lock
  visibly and atomically; `--frozen` or strict policy refuses a missing or
  stale lock; concurrent writers must agree; upgrades are only
  `blanket update --toolchain`, never a side effect.
- *Named tests from the design:* two-store replay including the dropped-
  `release` upgrade replay; no-pin creation; stale/frozen refusal with
  `frozen_validation_failure_precedes_all_writes` and the Gemfile-marker
  regression; added-higher-precedence-source staleness; unchanged dependency
  locks; foreign-platform refusal; exact statuses; the Linux/Mac lock diff.

**Migration and compatibility.** Legacy closures seed a lock only from proved
evidence; an unrecoverable mapping refuses with `blanket update --toolchain`
and never guesses from the current default. A same-platform closure is not
foreign-platform evidence. Writing a lock does not write or mutate a store
object; darwin goldens stay byte-identical.

**Linux verification.** `cargo fmt --check`, `cargo test`, and the selection
`--ignored` tests (`tests/python_select.rs`, `tests/go_e2e.rs`) with a
disposable store and `BLANKET_SANDBOX_TESTS=required`.

**Mac before merge.** The lock carries a hash per platform, so a lock written
on Linux must sync on the Mac without rewriting itself, and vice versa. Sync
the same project on both machines and diff the lock file (must be byte
identical) and `blanket status` (both "synced"). Run `cargo test` and the
selection `--ignored` tests on the Mac.

**Independent review.** The design has had 10 rounds; round 10's fixes are
unreviewed. Every implementation PR needs its own round.

**Completion criteria.** Ordered items 0–5 and the extractor follow-up below merged; the acceptance list at
`ARCHITECTURE.md:1256-1270` passes on Linux; the two-machine lock diff is
recorded; `LIMITATIONS.md` loses the "Node/Ruby/Elixir select nothing" and
"one fixed .NET SDK" rows.

#### Recommended decision

Take **PR 1 next** (after GC safety), not PR 3. It establishes tested selection independently of lock parsing.
It does not close user-visible runtime-selection limitations until runtime
propagation and activation also land; update those rows only when behavior
actually changes. PR 3's `write_closure` neighbourhood is exactly what GC Package C
rewrites; sequencing PR 1 first keeps the two apart.

---

### WP3 — Release catalog with one authenticated provider — OPEN, needs WP2

**Objective.** One binary discovers a newly published upstream release without
a code change.

**Prerequisites.** WP2 PRs 1, 2b, 3, 4, 5. Default versions do not move until WP2
has merged.

**Scope.**
- **Catalog, not just a release list.** Per ecosystem: usable distributions
  (python-build-standalone builds, nodejs.org, static.rust-lang, go.dev,
  portable-ruby, erlef otp_builds plus blanket-toolchains for Linux OTP,
  Microsoft release metadata), provider build revisions, platform requirements
  (glibc floor), extraction recipes, and companion tools that must move
  together: uv, bundled npm, Bundler, OTP-qualified Hex and rebar3,
  Elixir-per-OTP compatibility.
- **Trust is a configured list, not a compiled-in constant** (owner direction,
  2026-09-09). "Which publishers count as real" must be data the user or the
  company sets, because an enterprise mirrors its toolchains internally and
  will want blanket pulling from its own repository, signed by its own key.
  Do not hardcode a fixed set of upstream publishers and bolt private
  registries on later; the internal publisher is a first-class case from the
  first PR. See the trust-configuration rules below: this shares the source
  policy mechanism with WP5 private-registry work.
  Keep endpoint permission, publisher authentication, and credential handling
  distinct within that mechanism; a registry login does not prove authorship.
- **Refresh and trust protocol.** Immutable catalog snapshots in the store;
  atomic refresh with timeout and last-good fallback; historical retention so
  old locks stay realizable; trusted publisher keys with rotation and
  revocation; an invalid signature is a hard failure, never a warning. Two
  distinct modes: `--offline` (no network at all) and "shipped catalog only"
  (the tables compiled into this binary, for zero-surprise installs).
- **Rebuild the Linux OTP artifact** on an older declared baseline with static
  OpenSSL and a runtime check on the supported distros. Static OpenSSL alone
  does not lower the glibc floor (`LIMITATIONS.md:212-213`, and the
  shared-store note at `LIMITATIONS.md:490-492`).

**Security and failure modes.** A tampered catalog is rejected. A transport
failure or timeout
may fall back to a still-valid last-good snapshot and says so. A present but
invalid signature, revoked signer, malformed signed payload, or detected
rollback fails hard; it must not enter the network-failure fallback path.
Offline replay with cached artifacts and required proof succeeds with the
network denied. TOFU sources are named as TOFU in
the catalog entry and in `LIMITATIONS.md` (blanket is TOFU today for
python-build-standalone — the pins carry checksums verified at pin time, not
signatures, `src/python.rs:10-13`).

**What this repository does *not* contain.** No publisher keys, no captured
signature, no attestation bundle, and no verification code. **Every claim
about which upstream publishes what signing material is unverified.** The plan
therefore starts WP3 with an evidence step, not with an implementation.

**Trust configuration rules.** These follow the existing policy model
(`src/policy.rs`), which tightens through ancestors and never loosens silently:

- The trusted-publisher set is **configuration**, expressed through shared
  project/home/protected-machine policy loading. **WP3 PR 1 owns the protected
  loading prerequisite**; WP5 later extends it. It is not a constant in
  `src/*.rs`. The shipped upstream publishers are the *default
  contents* of that list, not a privileged category.
- **Adding a publisher is an explicit, recorded configuration change at an
  authorized user/machine scope.** Lower-precedence/project layers may only
  intersect/restrict an allowed set, not union in a new publisher. A company
  may authorize only its own key. Trusted use of an explicitly authorized
  publisher is not automatically an exception that strict mode then rejects;
  log the configuration change and retain provenance separately from package
  verification exceptions.
- **A project can never widen the set beyond what home or machine policy
  allows.** A company can pin the set to its own internal publisher and a
  checked-out repo cannot add to it. WP3 PR 1 owns unconditional protected
  machine-policy loading; environment overrides cannot suppress it.
- **An invalid signature is a hard failure under every configuration.** Making
  the publisher list configurable must not create a spelling of "trust
  anything"; an empty or unparseable list fails closed.
- **Each catalog row records which publisher vouched for it,** so
  `blanket ls`, `blanket sbom`, and an audit can answer "where did this
  toolchain come from and who signed it" without re-fetching.
- **Locked replay and cache hits recheck current policy.** A checksum copied
  into an attacker-editable lock is integrity data, not proof that an allowed
  publisher signed it. Authenticated rows carry/reference a signed payload
  binding artifact digests, versions, platform/components, and recipe/bundle
  identity. Cache the verifiable proof with immutable provenance; offline
  replay needs that proof locally as well as the artifacts. Refuse missing
  proof under authenticated policy, including old WP2-only locks; do not
  silently relabel them signed or rewrite their locked bytes.
- A revoked/removed key or endpoint can intentionally make an old lock
  unusable. Report a policy/trust refusal distinctly from stale project inputs.
  Catalog refresh alone never changes the result for locked artifact bytes.
  Define expiry/rollback and offline revocation freshness in the owner-approved
  key policy before activation; an unreachable revocation service is not
  permission to bypass the configured freshness requirement.
- Keep three typed concepts: permitted endpoints (including redirects),
  publisher trust/proof, and credential references scoped to endpoint/audience.
  Never forward credentials to a different redirect origin by default. A
  successful private-registry login is not artifact signature verification.
  Implement an internal-publisher fixture with a test key and authenticated
  local test endpoint; real production credentials are not needed for that.


**Ordered PRs.**

**PR 0 — provider evidence spike (docs + fixtures only).** For each of the
seven providers, fetch and record: the exact URL of any checksum file,
signature, or attestation; its format; the key or trust root it chains to; and
whether it covers the artifact blanket actually downloads. Commit the captured
material as test fixtures under `tests/fixtures/catalog/<provider>/` and a
table in `ARCHITECTURE.md`. Providers with nothing verifiable are recorded as
TOFU by construction with a `LIMITATIONS.md` row. **No provider is described
as "signed" anywhere in the repo until this PR lands its evidence.**

**PR 1 — shared trust foundation and one authenticated provider.** Start with
unconditional protected policy loading, typed endpoint/trust/credential
configuration, effective-set intersection, and a fixture internal publisher.
Then implement catalog rows, signed-payload verification, refresh, snapshot
storage, valid last-good fallback, and the two offline modes. Choose a provider
with evidence-backed authentication from PR 0; checksum-only/TOFU support does
not satisfy this milestone. If no production provider qualifies yet, finish
and test the machinery with the fixture publisher and leave live-provider
activation explicitly open; do not invent a trust root. *Recommended provider below.*

**PRs 2–7 — one provider each**, reusing PR 1's machinery.

**PR 8 — Linux OTP artifact rebuild** on the older baseline, with the runtime
distro check.

**Acceptance.** One binary discovers a newly published upstream release
without a code change; a transport failure falls back to a still-valid
last-good snapshot and says so; offline replay with cached artifacts and proof
succeeds with the network denied; tampered/invalidly signed catalogs fail
without fallback. Also test: internal publisher, project attempts to widen
machine policy, environment attempts to suppress machine policy, revoked key
on a cache hit and locked replay, missing offline proof, unauthorized redirect,
credential non-forwarding, expired snapshot, and rollback rejection. Record
TOFU evidence honestly; it cannot satisfy authenticated-provider acceptance.

**Mac before merge.** Every catalog provider must produce darwin-arm64 rows,
and the Mac must realize a toolchain from the catalog rather than the
compiled-in table (verify with `-v` that the catalog was the source). Offline
replay is run on the Mac with the network off. `--offline` and "shipped
catalog only" are tested on both.

**Completion criteria.** PR 0's evidence table exists; PR 1's provider passes
all four acceptance gates on Linux and the Mac; each later provider PR repeats
them; `LIMITATIONS.md` carries one honest row per TOFU source.

#### Recommended decision (owner approval required for the trust root)

- **Do PR 0 before choosing the first provider.** Choosing on assumed
  signature availability is exactly the mistake this plan must not make.
- **Provisional first provider: Go or Rust**, decided by PR 0's evidence —
  both have the smallest surface and already have toolchain-file resolution
  (`go.mod` `toolchain`, `rust-toolchain.toml`). Pick whichever PR 0 shows has
  verifiable signing material covering the exact artifact blanket downloads.
- **Trusted key management needs the owner.** Where keys live, who rotates
  them, and what revocation means operationally are policy decisions, not
  implementation details. *Do not invent a key policy.* The owner's standing
  direction (2026-09-09) is that the mechanism must accommodate a company's own
  internal publisher, so design the storage and rotation story for "one
  enterprise key alongside or instead of the upstream ones" from the start,
  rather than for upstream publishers only.
- **WP3 owns shared policy/trust infrastructure; WP5 owns the remaining
  ecosystem credential adapters and enforcement coverage.** Keep one source
  configuration model, with distinct authentication and authorization checks.
  Move the mandatory-loading prerequisite here rather than creating a cycle
  in which WP3 waits for WP5 and WP5 waits for WP3.

---

### WP4 — Daily-driver gaps and the `x` lifecycle — PARTIAL

Any of these may be taken after WP1 merges; each is its own PR. Two are
implemented (below); the rest are open.

#### 4a. Implemented, Mac gate outstanding

- **`x` lifecycle** (branch `wp4/x-lifecycle`): `blanket x --clean`,
  unregistering an environment, protecting a running tool from concurrent gc
  through per-root locks under `~/.blanket/x/.locks/`, repairing a missing
  projection, and containing cleanup through open directory descriptors.
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
  **Package B rebuilds the execution end of this** (see 5.2); do not redesign
  `x` locking outside that package.
- **pnpm `add`/`remove`/`update`** (branch `wp4/deps-pnpm-yarn`): workspace
  membership comes from `pnpm-lock.yaml`'s `importers` list and nothing else;
  `pnpm-workspace.yaml` is never read, because since pnpm 10 it is also the
  settings file of a repository that has no workspace. Round-9 fixes are
  themselves unreviewed. Mac gate: the four pnpm `deps_e2e` round trips.

#### 4b. Open items

Each of the following gets the full treatment when taken; the sketch here
names the files and the shape so the next engineer does not start from zero.

**4b-1. Python editable installs and dependency groups.**
- *Objective:* `-e .` (the project itself) as a declared mutable overlay, and
  dev/optional dependency groups installable by flag.
- *Files:* `src/project.rs` (`environment_identity`, `project_env_inner`,
  `clone_tree`), `src/pypi.rs`, `src/manifest.rs` (group discovery),
  `src/cli.rs` (the flag), `src/main.rs::run_sync`.
- *Data model:* the mutable overlay must be an identity input — an env with an
  editable overlay is not the same object as one without. Follow the npm
  `mutable_packages` / `mutable_scope` precedent (`src/npm.rs:2423`, `src/npm.rs:2433`),
  including its honest `mutable_scope: "whole-tree-clone"` wording.
- *Security:* an editable install makes part of the projection writable;
  record it as an exception, never silently.
- *Tests:* `tests/linux_python.rs` unit coverage plus an `--ignored` e2e that
  edits the project source and proves the change is visible without a
  re-sync, and that a second project with the same lock but no editable
  overlay gets a **different** object id.
- *Mac gate:* exercises `clonefile` projection — run the Python `--ignored`
  tests on the Mac.

**4b-2. Yarn classic and Berry dependency edits.**
- *Current state:* both refuse with the conversion command
  (`src/deps.rs`, `LIMITATIONS.md`).
- *Why it is hard:* Yarn classic has no lockfile-only edit mode, so a
  workspace-faithful scratch edit is required — the same class of problem the
  pnpm work solved with `enable-modules-dir=false` and a redirected
  modules-dir, which Yarn classic has no equivalent for.
- *Recommended decision:* **leave as a refusal.** Berry (`yarn 2+`) has
  `--mode=update-lockfile` and is the cheaper target if the owner wants one;
  Yarn classic should stay a documented refusal until a real project demands
  it. *Owner may overrule.*

**4b-3. Poetry and PDM dependency edits.** Both refuse with instructions
today. Each is its own PR following the pnpm shape: delegate to the store's
pinned tool, never read the tool's own workspace-settings file as authority,
and redirect any install-side state into a per-run store stage.

**4b-4. `x` for cargo, go, gems, hex, nuget tools.** Take this **after** WP1
has proven a model for compiled tools. Cargo today stores vendored sources;
`cargo install` output is unmanaged (`LIMITATIONS.md:413`).

**4b-5. `fmt` for the remaining ecosystems** under the WP1 contract: Python
(ruff format via `x`), Go (gofmt is already in the toolchain), then the rest.
Each keeps the WP1 rules: named command, script precedence, `--eco` escape
hatch, own store object with a closure/GC reference, exit-status pass-through.

**4b-6. One real project per fixture-only ecosystem** (Cargo, Go, Ruby,
Elixir, .NET), recorded in `HITRATE.md`. Extend `tests/hitrate.py` to measure
a build/test/format command, not only `sync`. Measured on both machines and
recorded as two columns.

**4b-7. Re-run the 60-repo hit rate** after WP1 and after WP3; dated columns,
never an overwrite.

**4b-8. Carry-overs from the retired NEXT.md/ROADMAP.md:** SBOM `vcs` external
references for Git components; standalone vendoring of workspace-inherited
Cargo Git crates; artifact provisioning entries (sharp <0.33, node-sass,
sentry-cli) only when a real project needs them; SPDX SBOM and dependency
graph.

**Mac before merge (per item).** Editable installs and dev groups exercise
clonefile projection, so run the Python `--ignored` tests on the Mac. The
`add`/`remove`/`update` delegates run unsandboxed and are platform-neutral, so
the ten `deps_e2e` round trips on the Mac suffice — including all four pnpm
cases: `pnpm_add_update_remove_roundtrip`,
`pnpm_workspace_member_and_root_roundtrip`,
`pnpm_edits_leave_an_installed_project_untouched` (runs the store pnpm's real
`install` first), and
`nested_independent_npm_project_does_not_use_ancestor_pnpm_lock`. `x`
lifecycle and any compiled-tool model for cargo/go tools need a Mac cold/warm
run because the binaries are per-platform artifacts.

---

### WP5 — The company layer, all inside policy — OPEN, last

**Objective.** Enforcement knobs for companies, entirely inside
`.blanket/policy.toml` and the machine-wide policy. Permissive stays the
default; nothing is ever loosened silently.

**Prerequisites.** WP1, WP2, the authenticated WP3 foundation, GC safety,
and the selected daily-driver WP4 milestones. Open-ended WP4 breadth (for
example Yarn classic kept as a refusal) is not an impossible completion gate.
WP3 has already delivered mandatory source-policy loading. Remaining company
features follow daily-driver readiness: the tool
must be a daily driver first.

**Items.**
- **Package-level rules.** Today `deny` names exception *categories* (`policy::KINDS`,
  `src/policy.rs:42`) and strict rejects even `built_from_source`. Add
  name/version allow and deny lists, with a defined story for what the user
  sees when each fires.
- **Protected machine-wide policy — foundation delivered by WP3 PR 1.**
  The current `BLANKET_POLICY` override can replace home-policy selection
  (`policy::load`); WP3 must correct the source/trust path before activation.
  WP5 extends the same unconditional loader to package/category rules and
  adds tests proving neither project nor environment can weaken them.
- **Enforcement must cover every door:** delegated planners (uv/npm/cargo/go/
  bundler/mix run unsandboxed with network), toolchain acquisition, cache
  hits, `run`, and `x`. State in `ARCHITECTURE.md` which doors are covered and
  which are not.
- **Private registry configuration and authentication — before any allowlist
  claim.** **Design this jointly with WP3's trusted-publisher list** (owner
  direction, 2026-09-09). WP3 owns the shared implementation; WP5 extends it
  with ecosystem-specific credentials while keeping endpoint permission and
  publisher authentication separate. Python forces public PyPI (`--index-url https://pypi.org/simple` with the
  user's index environment removed, `src/main.rs:843-850`) and Go forces the
  public proxy while clearing private-module settings (`GOPRIVATE`/`GOFLAGS`/
  `GONOSUMDB` blanked at `src/golang.rs:190-193`, `GOPROXY` pinned at
  `src/golang.rs:198-207`).
  Cover delegates, redirects, Git sources, and cached decisions.
- **Age and license rules only once package records carry publication dates
  and licenses.** They carry neither today (`types::LockedPackage`, `src/types.rs:46`;
  `npm::NpmPackage`, `src/npm.rs:217`). Define the metadata source and the missing-data
  behaviour first.
- **Shared store / binary cache across machines: only on real demand.**

**Mac before merge.** Policy loading, registry configuration, and
authentication are pure logic and need only `cargo test` on the Mac, except
that any enforcement inside a build goes through Seatbelt and must be shown to
deny on the Mac too — extend the existing network-denied sandbox acceptance
check (`tests/sandbox_deny.rs`) rather than adding a new one.

**External gate.** Production private-registry verification needs owner
credentials/test accounts (3.4). Configuration, token scoping, redirect tests,
and a local authenticated fixture are implementable before those arrive.

---

## 5. GC safety — Packages A (done), B, C, D

This is the owner's current work. It is a separate track from the toolchain
lock; do not conflate them.

### 5.0 Outcome, tradeoffs, and the guarantee's boundary

Three properties, in order:

1. Remember what a project needs even when its folder is unavailable.
2. Keep everything a running Blanket job could need until the job finishes.
3. Delete only after checking complete records; uncertainty keeps data safe.

**Deliberate first-release costs. The owner accepted these on 2026-09-09
after they were put plainly: cleanup deferring while work is running is a
timing cost, not a correctness cost.** Every environment recorded for a project
is retained until the user explicitly forgets that project. GC is skipped
while any job is using the same store, and because a job holds the shared
lock through *execution*, a long-running managed job (a dev server under
`run`, a long `x` session) postpones GC for its whole lifetime. Cron or
nightly collection on an active machine will often report the skipped
outcome. This costs disk space and cleanup opportunities and buys a safety
contract small enough to verify.

**Explicit non-goals of this track** (follow-ups, not acceptance criteria):
automatic retirement of old environments; collecting unrelated objects during
a running job; and — once C and D make root records the authority — relaxing
the hold so it spans realization and publication only, freeing GC to run
during long executions.

**Boundary of the guarantee.** It covers cooperating Blanket processes on a
local filesystem with working advisory locks and atomic rename. It does not
cover: older Blanket binaries that ignore the protocol; programs launched
directly from store paths; malicious same-user changes to the store; descendants remaining after the awaited direct child exits (including
orphans after supervisor SIGKILL); or network filesystems where `flock`
is advisory-in-name-only. Every one of these must be stated in
`LIMITATIONS.md` and in `ARCHITECTURE.md` §"GC root safety".

**Out of scope for the whole track** (do not implement as part of it):
per-object leases, automatic expiry of missing roots, background GC, remote
store locking, a general path-resolution redesign, and toolchain-lock
validation.

### 5.1 Package A — stop forgetting unavailable projects — IMPLEMENTED on `wp-gc-safety`, review outstanding

**Delivered** (uncommitted working tree on `wp-gc-safety`):

- `src/gc.rs::collect_roots` no longer drops a root whose directory is
  missing. An unreadable or missing project, a non-directory at the recorded
  path, or a missing/non-directory `.blanket/closures` stops the sweep before
  any sweep function runs, via `unresolvable_root` (`src/gc.rs:179-191`),
  which names the key, the path, the underlying `io::Error`, and
  `blanket gc --forget <key>`. I/O errors are distinguished from "not a
  directory" instead of collapsing both into `Path::is_dir`.
- Dry runs stop at the same place: previewing must not turn uncertainty into
  a cleanup decision.
- `blanket gc --forget <root-key>...` (`src/cli.rs::parse_gc`,
  `src/cli.rs::valid_root_key`, `src/main.rs::run_gc`): repeatable, exact
  40-hex keys only, no wildcards and no pathname guessing. Every key is
  resolved before the registry changes, duplicates are rejected, and
  registering and forgetting the same key in one invocation is rejected.
  `--dry-run --forget` reports and writes nothing;
  `gc::Options::forgotten` excludes the record from the in-memory liveness
  calculation only. A real `--forget` returns before sweeping.
- `src/store.rs::{lookup_root, forget_root, validate_root_key, root_key}`
  resolve against registry records alone and never touch the project path.
- `blanket store roots` prints `<key>  <path>` (`src/main.rs:338-343`).
- Tests: `store::tests::lookup_and_forget_work_off_registry_records_alone`,
  `gc::tests::missing_project_blocks_sweep_and_preserves_record`,
  `gc::tests::dry_run_forget_ignores_only_the_requested_root_and_writes_nothing`,
  `gc::tests::missing_closures_directory_blocks_sweep`,
  `gc::tests::io_error_on_project_path_blocks_sweep`,
  `gc::tests::forget_rejects_unknown_and_malformed_keys`,
  `cli::tests` gc parsing cases, and the ignored
  `tests/gc.rs::gc_keeps_deleted_node_project_until_forgotten`.
- Docs updated in the same change: `ARCHITECTURE.md` §"GC root safety",
  `CLI.md`, `LIMITATIONS.md`, `README.md`, `REVIEW.md`.

**Still owed for A.**
- Isolate Package A's source/tests and directly related docs into one
  reviewable commit on `wp-gc-safety`; preserve the separate plan rewrite.
  Inspect the full dirty tree before staging, and do not use blanket staging.
- One independent adversarial round. ~~`REVIEW.md` currently records
  "Self-review only"~~ **done 2026-09-09** (Astra's FIX-FIRST round, see
  `REVIEW-GC-A-2026-09-09.md` and `REVIEW.md`); fixes live on
  `vega/gc-a-fixes`, verified push-ready by Iris the same day.
- Mac gate: `cargo test`, `cargo test --test gc -- --ignored`.
- Review brief for A, to hand the reviewer: can a root record be crafted (odd
  key case, symlinked registry file, a path that is a dangling symlink, a
  path on an unmounted mount point) that makes `collect_roots` *pass* when it
  should stop? Does `--forget` interact with `--register` in an order that
  loses a record? Does the early return after a real `--forget` skip anything
  the user expected to happen in the same invocation? Is the sweep-blocking
  error reachable from every entry into `gc::collect`, including
  `--project`?

**Known interaction with C.** A's full-stop is the *bridge*, not the final
behaviour. Package C now makes root records self-sufficient (`root/2`), so an
unavailable project no longer blocks the sweep when the record itself says
what to keep. A's block applies only to records still in the legacy
pathname-only form. This is recorded in `ARCHITECTURE.md`; A's tests remain
and are retargeted at legacy records.

---

### 5.2 Package B — protect the whole job, without a timer — IMPLEMENTED LOCALLY; review and platform gates outstanding

**Objective.** Every store-consuming operation owns shared activity protection
from its first resource read through its last awaited child. Cleanup owns
exclusive protection. No timer establishes whether a job is active.

**Planned sequencing gate.** Package A's independent review and merge remain
outstanding; the implementation is nevertheless present locally. B has no
design dependency on C or D. The owner has approved the unconditional
supervisor and the consequence that a long-running job postpones cleanup for
its whole lifetime.

**Delivered in the current working tree.** `src/activity.rs` provides the
operation-owned shared/exclusive store lease and `src/supervise.rs` routes
store-consuming child processes through the signal-aware supervisor.
Production entry points use the activity/lock order and keep the lease through
their final awaited child; the Linux library, CLI, and ignored GC integration
tests pass. The independent review, macOS gate, and the full B.8 signal/PTY
transcript are still outstanding, so the completion criteria below are not
cleared.

**User-visible behavior.** A busy sweep, including `--dry-run`, prints exactly
`cleanup skipped: a Blanket job is using this store`, exits 0, and prints no
collection summary. `gc --register` uses the same busy-skip convention.
`gc --forget` is an explicit requested mutation: on contention it exits 1 with
`a Blanket job is using this store; retry when it finishes`. This is the
reviewer's adopted implementation choice; no renewed approval is needed.
`x --clean` skips busy candidates with its existing narration. The recency
windows remain retention policy, never activity evidence.

#### B.1 Explicit activity ownership

Add `src/activity.rs`. Keep an operation-owned token, not a process-global
boolean saying that some other thread happens to hold a lock:

```rust
pub enum ActivityMode { Shared, Exclusive }
pub struct StoreActivity { /* canonical root, mode, owned RAII lease */ }
impl Store {
    pub fn activity(&self, mode: ActivityMode) -> io::Result<StoreActivity>;
    pub fn try_activity_exclusive(&self) -> io::Result<Option<StoreActivity>>;
    pub(crate) fn require_activity(
        &self, activity: &StoreActivity, what: &str,
    ) -> io::Result<()>;
}
```

- The token owns the OS lock for its entire lifetime. Nested calls borrow it;
  work moved to a thread explicitly clones/owns a lease. A check must validate
  the token's canonical store root and the required mode. Mere presence in a
  global map is not authorization to keep using resources after another
  operation drops its guard.
- Store-consuming public library APIs take the token explicitly. Required
  core changes include `Store::{has,stage,commit}`, fetch/cache entry points,
  realization, projection, publication, and destructive registry APIs. Make
  `Store::has` return `io::Result<bool>` so a missing/wrong token or failed
  publication lock is an error, not a cache miss. Propagate `?` at callers;
  do not turn failures back into `false`.
- `Store::open` may create/canonicalize the store and lock infrastructure
  before acquisition. That bootstrap exception permits no object inspection,
  cache reads, metadata migration, or deletion. Pure path construction is
  likewise not resource use.
- Lock file: `<store>/activity.lock`, opened
  `O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC`, mode `0o600`, with `fchmod` after open.
  Reject non-regular files. Never unlink or replace it.
- Failure to open or lock is an error. Activity descriptors remain
  close-on-exec; the supervising Blanket process owns protection.
- No shared-to-exclusive upgrades. An explicit attempt to upgrade a held
  operation token returns an error rather than waiting on itself. Maintenance
  that needs exclusive access runs as a separate operation before a job owns
  resources (D.3). Test this along with independent-operation exclusion.

#### B.2 Local and cross-process exclusion

Independent shared operations may coexist. Independent exclusive operations
must exclude each other and every shared operation, including other threads
in the same process. Re-entry is explicit borrowing/cloning of the **same
operation's** token; never hand an unrelated job an existing exclusive token.

Use a per-canonical-root in-process reader/writer coordinator plus the OS lock
(or independently opened OS locks with explicit operation-token reuse).
If a registry is used, its key includes canonical root **and lock kind**;
activity, cache, and publication locks cannot alias. Do not hold a global
registry mutex while blocking on an OS lock; use per-entry coordination so a
wait for store A cannot freeze operations needed to release store B.

Keep `fetch::acquire_gc_lock`'s cache-lease sharing registry separate in this
package. Cache leases deliberately share a process-held descriptor, whereas
activity exclusivity separates operations. Superficial similarity does not
justify one generic reuse rule. A cache lease must also own/borrow activity
for as long as its verified file remains usable. Publication locks remain
actual critical-section locks, never automatically shared between threads.

#### B.3 Lock ordering and `x` origin discovery

For a single store, the acquisition order is:

```
activity → x per-root lock (when needed) → project transaction lock (C) → gc/cache lease → publish_lock
```

A cold `x` already holds its per-root lock during realization; realization
then downloads and publishes. Putting x-root last would prohibit that normal
path. Never acquire an earlier lock while retaining a later one. Drop cache
leases before entering work that needs an x-root lock. GC takes exclusive
activity, then `gc_lock`, then `publish_lock`; it needs no x-root lock to
sweep objects. Nested operations reuse activity explicitly rather than
reacquiring it behind a later lock.

For `x --clean`, discover the candidate's originating store as an untrusted,
non-mutating hint, acquire that store's exclusive activity nonblockingly,
then acquire the candidate's x-root lock nonblockingly. Re-read and validate
candidate identity, origin, and registration under both guards before any
removal. If the origin changed, release and retry from discovery; never
upgrade or acquire another store lock while holding x-root. Unknown origin
is a named skip, not permission to delete. The relevant store is the
candidate's originating store, not the caller's current `BLANKET_STORE`.

A multi-store operation processes stores sequentially without retaining one
store's locks while acquiring another's. The pnpm delegate's borrowed `x`
environment keeps both its activity token and x-root lease until the delegate
has exited (`src/xrun.rs`'s node delegate helper is part of the audit).

#### B.4 Entry-point coverage

Fill this table with concrete acquisition/release symbols in the PR. Every
row must have a test reaching a protected primitive; a CLI-only guard is not
sufficient for public library calls.

**Audit filled 2026-09-09** against the working tree (B/C/D uncommitted;
`HEAD` = `9b11e05`). "Requirement" is the rule this row must meet;
"As built" names the symbols that exist. Rows marked ✗ or ◐ are **not**
cleared — they are the residue B.4 was meant to expose.

| Entry | Requirement | As built | State |
|---|---|---|---|
| sync / implicit bare `blanket` | before planning or tool provisioning; through publication | `main.rs::run_sync` (1151) acquires **no** lease; protection is per-helper (`project.rs:242,784,1461`) and per-child (`status_owned`) | ◐ no operation-wide lease |
| plan | before provisioning/reading store tools; through final plan write | `main.rs::run_plan` (967) acquires **no** lease; `ensure_npm_lock` (1104) and `locked_requirements` (943) each mint a fresh lease per child | ◐ no operation-wide lease |
| build | before store use; through sandbox child reap | `main.rs::run_build` (1315) acquires **no** lease; `build.rs:356` `status_owned` per child; `sandbox.rs:104,153` take their own shared lease | ◐ no operation-wide lease |
| fmt, including fmt scripts | before provisioning; through all formatter/script children | `main.rs::run_fmt:1540` `store.activity(Shared)`; last use `rustfmt::…(&activity)` (1570) after `refs.object_path(&store,&activity,…)` (1558–1559); script path delegates at 1507–1508 | ✓ |
| run, including npm pre/main/post scripts | before runtime/projection lookup; through the final awaited child | `main.rs::run_run(…, activity: &StoreActivity)` (1603–1607) borrows the caller's token; last use `supervise::status(&mut command, activity)` (1849), per-step at 1841 | ✓ |
| x, cold and warm | before cache/projection lookup and x-root lock; through child reap | `xrun.rs:2001` `store.activity(Shared)` | ✓ |
| x --clean | originating-store discovery/revalidation protocol in B.3; through unregistration | `xrun.rs:1637` `origin_store.try_activity_exclusive()` on the **candidate's** store | ✓ |
| add / remove / update | before store delegate lookup; through delegate and follow-on sync | `deps.rs` acquires **no** lease anywhere (0 sites); its six delegate spawns each mint a fresh lease via `status_owned`/`output_owned` (e.g. `deps.rs:1076`) | ◐ lease not held across delegate→sync |
| sbom / status / ls / doctor | before object/meta/probe reads; through final read | `inspect.rs` and `sbom.rs` acquire **no** activity at all (0 sites each), yet `inspect.rs:784` enumerates `store.root.join("meta")` and reads each record | ✗ **uncovered store reads** |
| gc, register, forget | exclusive before registry mutation or sweep snapshot; through final mutation | `main.rs::run_gc:400` `try_activity_exclusive`, held through `migrate_metadata` (424), `register_root_from_project_with_activity` (463), `forget_root_with_activity` (476), `collect_with_activity` (491) | ✓ |
| store roots | diagnostic, independently decoded atomic records; no activity lock required | `main.rs::run_store_roots` (379), no lease | ✓ by design |
| store path / help / completions / parsing | no resource consumption; no activity lock | no store access | ✓ by design |

The four ◐ rows share one shape: the **CLI entry point holds nothing**, and
protection is reassembled from short per-helper and per-child leases. That
satisfies "the store is protected while a child runs" but not B's actual
objective — "from its first resource read through its last awaited child".
Between two consecutive children the store is unprotected and a sweep may
interleave. B.5's token threading is the fix for the per-child half; the
entry points themselves still need an operation-wide token.

The ✗ row is a genuine hole rather than a weaker guarantee: `status`, `ls`,
`doctor` and `sbom` read store metadata with no lease of any kind, which is
exactly the case B.4 calls out ("a leaf reading `object_path()` with
`fs::read` is still a store consumer even if it never calls `Store::has`").

Audit `project::*`, the seven ecosystem ensure/realize/project APIs,
`rustfmt`, `nativelibs`, `gitsrc`, `build`, `fetch`, `policy::check_cached`,
and inspection helpers. A leaf reading `object_path()` with `fs::read` is
still a store consumer even if it never calls `Store::has`.

#### B.5 Supervision covers all awaited store-consuming children

Add one shared `src/supervise.rs` implementation. Its public shape is:

```rust
pub fn status(command: &mut Command, activity: &StoreActivity)
    -> io::Result<ExitStatus>;
pub fn output(command: &mut Command, activity: &StoreActivity)
    -> io::Result<Output>;
```

Both wrappers use the same spawn/wait lifecycle; callers map final exit status
at the command boundary. The output wrapper preserves `Command::output`'s
capture behavior and the status wrapper preserves inherited stdio. Replace the
two `CommandExt::exec` sites in `main.rs::run_run` and `xrun::run`, **and**
route existing store-consuming `.spawn()`, `.status()`, and `.output()` paths
through that lifecycle: npm pre/main/post scripts (`main.rs:1743`), planners,
dependency-edit delegates, sandbox builds, and fmt. Preserve concurrent pipe
draining for captured output; waiting before draining can deadlock a child.
Pure host probes may stay outside only when they cannot outlive protection
for store resources; record each exclusion in the audit.

The helper borrows the operation's activity token; it cannot return or drop
that token while an awaited child lives. A child is not detached merely
because the previous caller used `.status()` rather than `exec`. A normal
TERM to the Blanket parent must not orphan any of these children and expose
their resources to GC. Hold one operation token across the complete npm
pre/main/post sequence and across the delegate-to-sync transition.

The owner-approved extra supervising process is unconditional for `run` and
`x`; no opt-out or exec fast path. Existing waiting paths already have a
parent and need signal-safe waiting, not another extra process.

**Exclusion list, filled 2026-09-09.** Every production `.status()`,
`.output()` or `.spawn()` in `src/` that does **not** go through
`src/supervise.rs`, and why it is out. Test-module and test-helper sites are
excluded from this list by construction and are not repeated here
(`extract_ruby_bottle_for_test`, `project.rs::local_sdist`,
`project.rs::local_native_sdist`, and the `#[cfg(test)]` blocks in
`golang.rs`, `build_requires.rs`, `sandbox.rs`, `elixir.rs`, `build.rs`,
`cargo.rs`, `dotnet.rs`, `gitsrc.rs`, `store.rs`, `archive.rs`).

| Site | What it runs | Disposition |
|---|---|---|
| `pypi.rs:62` | `/usr/bin/getconf GNU_LIBC_VERSION` | **Legitimate.** Pure host probe; touches no store path and cannot outlive store protection. |
| `dotnet.rs:1080` | `/usr/bin/id -u` | **Legitimate.** Pure host probe. |
| `sandbox.rs:353`, `sandbox.rs:501` | unmanaged sandbox entry point | **Legitimate by construction.** Documented in-code as the path for "callers that do not consume a store"; store callers use the activity-aware sibling. |
| `sandbox.rs:895`, `sandbox.rs:941` | `--version` and classification probes | **Legitimate by construction.** These are the `None` arm of an `Option<&StoreActivity>`; the `Some` arm already routes through `supervise::output`. |
| `build_requires.rs:112,119`; `archive.rs:537,547` | delegated build/extract | **Legitimate by construction.** `None` arm of `Option<&Store>`; the `Some` arm calls `status_owned`/`output_owned`. |
| `cargo.rs:246` `extract_rust_components` | `/usr/bin/tar -xJf … -C <staged>` | **Gap.** Extracts into a **store staging directory**, which GC sweeps. No token is threaded in, so protection cannot be proved at the call site; it depends on an unverified outer lease (`cargo.rs:155`). |
| `elixir.rs:796` `extract_otp_archive` | `/usr/bin/tar -xzf … -C <destination>` | **Gap.** Same shape; no token parameter. |
| `dotnet.rs:115` `extract_sdk_archive` | `/usr/bin/tar -xzf … -C <staged>` | **Gap.** Same shape; no token parameter. |
| `elixir.rs:494` `run_installer_spec` | ecosystem installer | **Gap.** Runs a store-provisioning installer with no token. |
| `project.rs:751,757,767` `clone_tree` | tree copy for projection | **Gap.** Writes projection content with no token parameter. |
| `gitsrc.rs:172` `run_git` | `git` against a fetched tree | **Unproven.** `gitsrc.rs:493,1003` take a lease, but `run_git` receives no token, so no call site proves it. |

The six **Gap**/**Unproven** rows are not signal-safety defects — they are
the same "cannot be proved at the call site" shape as B.5's `*_owned`
problem, one level lower: these helpers take a `&Path` and no token at all,
so threading a token through them is a signature change, not a call change.
They are the reason B.5's completion criteria are not cleared.

#### B.6 Signal and wait lifecycle

Use one serialized supervisory session per Blanket process; explicitly reject
unsupported concurrent sessions rather than share a global child PID between
them. This does not prohibit two separate Blanket jobs. Design a session
around an event-driven or signal-safe pending-notification mechanism; the
following are acceptance requirements, not permission to paste an unchecked
`AtomicI32` handler into both callers.

1. Save inherited dispositions and masks. Install handlers before spawning.
   Serialize signal notification with spawn/PID publication and reap/PID
   clearing. TERM arriving before PID publication becomes pending
   cancellation; it is never lost and never sent to PID 0 or -1. Do not
   signal a PID after reap. Restore state on success and spawn failure.
2. Keep the child in the caller's foreground process group. For ordinarily
   default INT/QUIT/HUP dispositions, the parent catches these and waits;
   terminal group delivery reaches the child directly and is not forwarded
   again. Preserve an inherited ignored disposition where applicable. Reset
   temporary supervisor handlers and restore the intended child signal mask
   before exec. A caught disposition alone does not fix a signal lost during
   the fork/exec interval. Startup cancellation must either prevent launch or
   reach the launched child; test both sides of the spawn boundary.
3. Parent-directed TERM is forwarded to the current live direct child.
   Repeated parent-directed TERM remains meaningful; do not permanently
   suppress every TERM after the first. Handler code uses only
   async-signal-safe operations, preserves errno, and performs no logging or
   allocation. Notification coalescing is acceptable, silently dropping
   cancellation during setup is not.
4. Reap the child before returning, retrying interrupted waits. Define and
   test terminal stop/continue, including a child that stops itself: the
   supervisor must let the controlling shell observe a stopped job and resume
   the child on continuation. A child ignoring termination keeps the parent
   waiting and the store protected.
5. Preserve arguments, cwd, environment, stdio and tracing. Preserve numeric
   exits (0/1/42 etc.); map a signaled child to `128 + signal`, consistently
   with existing npm-script behavior. This preserves shell-visible numbers,
   not `WIFSIGNALED` for callers inspecting Blanket's raw wait status; document
   that distinction.
6. Return status through callers and drop guards normally before the final
   `exit`. On error, never return while a spawned child remains unreaped.
   Spawn failures retain the existing command-specific error context.

**Boundaries to document.** Parent-only INT/QUIT/HUP is not forwarded after
startup (terminal group delivery is the supported path). A group-directed
TERM can reach both parent and child; forwarding can produce another TERM,
so do not promise exactly-once delivery for that case. SIGKILL of the
supervisor cannot be caught: its activity lock is released and a surviving
child may be orphaned. Descendants remaining after the direct child exits
are outside this release's guarantee, whether or not they intentionally
called `setsid`. Do not name a test as if SIGKILL kills the child automatically.

**SIGPIPE.** Preserve the current Rust toolchain's behavior. With normal
compiler settings, Rust ignores SIGPIPE in Blanket itself but resets it to
`SIG_DFL` before child exec; it is not an inherited child-ignore defect.
Test a broken-pipe child through both old-style exec characterization and the
new runner. Do not change compiler flags or install a SIGPIPE workaround.

#### B.7 Descriptor handling and the projection-namespace bridge

Activity descriptors remain `O_CLOEXEC`. With supervision, leave x-root
locks close-on-exec too: remove `make_lock_inheritable` at the execution
boundary and replace the old inheritance test with parent-held lifetime
coverage. Preserve x-root acquisition, cleanup, and inode-recheck behavior.
A vestigial inheritable descriptor is not harmless: descendants could retain
it after the supervisor ends. Keep Linux's sandbox descriptor scrub intact;
record the remaining macOS scrub gap for unrelated inherited descriptors.

Before C/D land, the old forest/backup directories are shared by sibling
stores (`<store.parent()>/forests` and `backups`). A per-store activity lock
cannot make sweeping those directories safe. B must stop deleting from that
shared namespace, including under `gc --project`, and print a named skipped
reason while allowing validated object/cache/stage collection to continue.
C writes new projections into store-owned directories; D collects only those.
Old shared projections remain protected from automatic deletion. This is
conservative over-retention, not an unsupported cross-store safety claim.

#### B.8 Required tests

Normal offline suite, temporary stores, subprocess pipes/FIFOs as barriers:

- Two shared jobs run concurrently; GC skips until both finish, including
  backdated objects/stages beyond the recency windows.
- Borrowed/cloned tokens retain protection through the last use; a different
  thread dropping its own token cannot unprotect a reader. Wrong-store tokens
  fail, and independent exclusive operations never overlap.
- Canonical-root aliases coordinate; cache/activity lock kinds do not alias;
  a blocked acquisition for one store cannot freeze another store's release.
- A cold x and a pnpm delegate perform fetch/publication under x-root without
  deadlock; x-clean discovers/revalidates the originating store before removal.
- Every B.4 route reaches protected primitives, including public library
  realization, cached policy checks, and npm pre/main/post scripts.
- Spawn failure, numeric exit 42, signal-to-status mapping, and sequential
  children preserve behavior and reset supervisor state.
- Parent TERM before spawn, during PID publication, during an ordinary wait,
  and at reap cannot lose cancellation, signal an invalid/stale PID, or leave
  a protected child alive after the helper returns. Test repeated TERM.
- Terminal INT reaches a trapping child once; parent-only INT follows the
  documented boundary; group TERM matches its documented weaker guarantee.
- PTY-backed stop/continue tests include group ^Z and a child stopping itself.
- Parent TERM while an npm script, delegate, captured-output command, fmt,
  or sandbox build runs retains the activity lock until the child is reaped.
- `supervisor_sigkill_documents_orphan_boundary`: kill the supervisor,
  observe lock release and possible surviving child, then have the test
  harness explicitly terminate/reap its test processes.
- A nested `blanket run blanket ls` completes. A nested exclusive command
  (`blanket run blanket gc`) reports busy instead of waiting forever.
- Child descriptors do not include activity/x-root locks; SIGPIPE preserves
  current toolchain behavior; capture a child producing more than a pipe
  buffer to verify output draining.
- Two sibling stores cannot have their aged shared legacy projections deleted
  by either store's GC while the other store runs a job.

Use test seams around setup/reap and real subprocesses for signal delivery;
no sleeps as race synchronization. Record commands and results. Run
`cargo fmt --check`, `cargo test`, and relevant ignored gc/fmt/x/deps tests
with disposable stores, disk-backed TMPDIR, and required Linux sandbox gates.

#### B.9 Adopted decisions and completion

Explicit operation tokens replace the earlier process-global guard check.
The cache registry stays separate. Busy `--forget` exits 1; busy sweeps exit
0. The supervisor is unconditional and covers existing waiting children as
well as the replaced exec sites. Automatic maintenance never upgrades a job's
shared token. SIGPIPE is preserved as characterized, not fixed speculatively.

**Mac before merge.** Run the complete offline execution/locking suite,
including PTY and descriptor tests, and the relevant gc/fmt/x/deps ignored
tests. Record the supervising process's RSS on the Mac alongside the earlier
~7 MB Linux measurement; investigate a material difference. Update CLI,
architecture, limitations, and review evidence in the same PR.

**Completion.** B.4 is filled in; every audited store consumer owns a valid
activity token through its final child; all B.8 cases pass; shared legacy
projection sweeping is disabled; independent review and Mac gates are recorded.

---

### 5.3 Package C — keep project records inside the store — IMPLEMENTED LOCALLY; review and platform gates outstanding

**Objective.** GC learns what a project needs from the store's own record, not
from the project directory. A project that is moved, unmounted, or deleted
keeps its protection without blocking the sweep.

**Planned sequencing gate.** Package B's independent review and merge remain
outstanding; the implementation is nevertheless present locally. Publication
happens under activity protection.

**Delivered in the current working tree.** `root/2` records carry typed,
lossless project/projection data and durable object roots; new forests and
backups are store-owned, while legacy sibling namespaces remain retention
only. The producer audit and the Linux GC/x integration coverage are present.
The independent review, macOS gate, and the remaining C acceptance transcript
are still outstanding, so the completion criteria below are not cleared.

**User-visible behaviour.** A project with a `root/2` record whose folder is
gone no longer stops `blanket gc`; its tools and forests stay protected.
`blanket gc --register <dir>` explicitly imports legacy roots. New forests
and backups live inside their owning store; old shared paths remain retained.
A guarded ordinary sync also imports a legacy root before changing it.

#### C.1 The exact `root/2` record schema

One JSON object per file at the existing `roots/<key>` location. The key is SHA-1 of the canonical project's **raw Unix path bytes**.
This preserves every existing UTF-8 key byte-for-byte. Change the private
`store::root_key` helper and test both valid UTF-8 stability and distinct
non-UTF-8 keys. Existing non-UTF-8 pathname-only records were already written
lossily and cannot be repaired by guessing; see C.8.

```json
{
  "schema": "root/2",
  "key": "3f2a...40 hex...",
  "project_path": { "encoding": "utf8", "value": "/home/e/proj" },
  "objects": [
    "0123456789abcdef0123456789abcdef01234567-cpython-3.12.7",
    "89ab...-python.env-1"
  ],
  "projections": [
    { "base": "forests", "components": [{"encoding":"utf8","value":"<forest-key>"}, {"encoding":"utf8","value":"<projection-id>"}] },
    { "base": "backups", "components": [{"encoding":"utf8","value":"<reserved-backup-name>"}] }
  ],
  "updated": 1757400000
}
```

- `schema` — exactly `"root/2"`. Anything else is refused, never downgraded.
- `key` — must equal the file name. A mismatch is a malformed record.
- `project_path` — **diagnostic only.** Never authority, never resolved
  during a sweep.
- `objects` — sorted, unique, exact object ids.
- `projections` — sorted, unique typed references.
- `updated` — informational.

#### C.2 Lossless path encoding

Unix paths are byte strings, not text. `project_path` is a tagged value:

- `{"encoding":"utf8","value":"<string>"}` when the raw bytes are valid UTF-8.
  Writers must prefer this so records stay readable.
- `{"encoding":"base64","value":"<standard base64 of the raw bytes>"}`
  otherwise.

Readers accept both and reconstruct with
`OsString::from_vec` / `OsStrExt` (already imported in `src/store.rs:7`).
Display strings are never new authority: nothing in GC may use
`to_string_lossy()` output to decide a deletion.

Raw-byte hashing fixes the key collision for new non-UTF-8 registrations.
It does not recover bytes discarded by old pathname-only records. A legacy
lossy-key collision must never merge two projects or let forgetting one drop
the other's protection. Leave ambiguous legacy records intact and name the
explicit registration/forgetting recovery steps (C.8).

#### C.3 Object and projection reference formats

**Object references** are bare object-id strings. Validation at the API
boundary:
- the whole string is an object id — reuse the predicate behind
  `store::object_id_token` (`store.rs:655-670`) but require a *full-string*
  match, not "contains an id" (the existing token scanner exists for the
  guess-from-JSON path that C is replacing);
- no `/`, no NUL, no `..`;
- `store.object_path(id)` is lexically inside `store.root/objects`.

**Projection references** are typed, never arbitrary deletion paths:
```rust
pub enum ProjectionBase { Forests, Backups, LegacyForests, LegacyBackups }
pub struct ProjectionRef { base: ProjectionBase, components: Vec<OsString> }
```
New `Forests` and `Backups` resolve under `store.root/<base>/<components…>`.
They are owned by this store, not its parent directory. `LegacyForests` and
`LegacyBackups` refer to the old sibling directories under `store.root.parent()`
and are **retention-only**: no automatic GC execution may delete there.
Wire spellings are `forests`, `backups`, `legacy-forests`, `legacy-backups`.
Components use C.2's tagged lossless encoding individually, reconstructing
`OsString`; reject empty, `.`, `..`, slash, NUL, and an empty component list.

Change new Node/Elixir forest construction and backup helpers to use the
explicit store-owned bases. Do not move or delete a live legacy projection.
On resync, prepare a new store-owned projection and switch to it only after
root publication. Keep existing legacy references in the union. The old
shared namespace is retained indefinitely in this track; a future explicit
ownership migration can reclaim it. Merely proving lexical containment in a
shared parent directory is not proof of store ownership.

**Component counts differ per producer and that is fine** — components are
opaque. Derive new project-key hashes from raw canonical path bytes (UTF-8
results stay unchanged), not lossy display strings. Note for implementers: the Node forest key is
`short_sha256(path, 32)` (`gc.rs:233`) while the Elixir forest key is the
first 8 bytes of sha256, i.e. 16 hex chars (`elixir.rs:1381-1382`), and the
Elixir projection has a third component `hex-deps`. Do not encode an
assumption about component count anywhere.

#### C.4 Validation rules and store ownership checks

Enforced at the `ClosureRefs` API boundary, before anything is written:
- every object id validates as above;
- every projection ref rejects absolute paths, `..`, empty components, and
  NUL;
- **store ownership:** an object path supplied by a caller must have
  `path.parent().parent() == store.root` after canonicalization; a projection
  must resolve under `store.root/{forests,backups}` through no-follow anchored
  directories. Cross-store references are rejected with the offending path
  in the message. Only the legacy importer may construct retention-only
  sibling references; those must never become deletion authority.
- the `Store` is **passed explicitly**. Delete
  `project::store_from_closure_body` and its fallback to `Store::open()` from
  normal publication. Update `xrun::originating_store`, which currently calls
  this helper, in the same PR: new x markers carry explicit canonical store
  provenance; existing markers/closures use a narrow declarative, validated
  legacy-origin reader. An ambiguous origin skips cleanup. Do not retain a
  generic recursive JSON path guess under a different name.

#### C.5 `ClosureRefs` API shape

```rust
pub struct ClosureRefs {
    objects: BTreeSet<String>,
    projections: BTreeSet<ProjectionRef>,
}

impl ClosureRefs {
    pub fn new() -> Self;
    /// Validated store object, given the path realization returned.
    pub fn object_path(&mut self, store: &Store, activity: &StoreActivity, path: &Path) -> io::Result<&mut Self>;
    /// Validated store object, given an id directly.
    pub fn object_id(&mut self, store: &Store, activity: &StoreActivity, id: &str) -> io::Result<&mut Self>;
    /// Optional refs (e.g. nativelibs) without an `if let` at each caller.
    pub fn optional_object_id(&mut self, store: &Store, activity: &StoreActivity, id: Option<&str>) -> io::Result<&mut Self>;
    pub fn forest(&mut self, store: &Store, activity: &StoreActivity, path: &Path) -> io::Result<&mut Self>;
    pub fn backup(&mut self, store: &Store, activity: &StoreActivity, path: &Path) -> io::Result<&mut Self>;
    pub fn is_empty(&self) -> bool;
}
```

`write_closure` requires explicit store, activity, and reference parameters:

```rust
pub fn write_closure(
    project_dir: &Path,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &StoreActivity,
    refs: ClosureRefs,
) -> io::Result<()>
```

Making them required (rather than an `Option` or a builder default) is
deliberate: a new tailor cannot forget them, because the code will not
compile.

#### C.6 Publication ordering and crash boundaries

The transaction covers **actual project projections and backups**, not just
closure JSON. Today Python changes `.venv` before `write_closure`, and Node
changes root/workspace links before it. Adding a root write inside the old
function alone is insufficient. Split the producer flow into preparation,
durable protection, and visible publication, under one activity token:

1. **Prepare and validate.** Resolve the explicit store, read any legacy root
   and all its closures (C.8), compute the complete new reference set, prepare
   new forest trees in store-owned staging, and reserve unique backup
   destinations. Existing project links and user directories remain intact.
   Validate direct object IDs and their existing complete metadata using
   non-mutating reads. C does not certify transitive metadata completeness;
   D adds that gate once its schemas/adapters exist.
2. **Persist protection under `publish_lock`.** Re-read/validate the previous
   root record, union imported history and all new references, and write a
   unique create-new temporary in `roots/`. Fsync the file, rename relative
   to held directory descriptors, then fsync `roots/`. Persist `.initialized`
   after the first valid durable root. A root may name a reserved projection
   or backup destination not created yet: that safely over-retains and is not
   missing object metadata. Release the short publication lock afterwards.
3. **Publish projections and backups.** Only after the root is durable may
   the producer move a user's old directory into the reserved backup,
   publish prepared forests, or switch `.venv`/root/workspace symlinks.
   Keep the activity token throughout; use the planned destinations exactly.
   Fsync changed parent directories where durability of the rename matters.
4. **Publish the project closure** using the descriptor-relative writer.
   The writer validates the supplied references and verifies/merges durable
   protection, but cannot be the first protection write if step 3 already
   changed the project. A small shared publication/preparation API may expose
   the phase-2 operation to producers; do not duplicate the transaction eight
   times. Required `Store`, activity, and `ClosureRefs` arguments remain.

Factor the existing descriptor helpers from `project.rs` into `src/fsroot.rs`
now. Use OS-random create-new temp names, file/directory fsync, no-follow
walks, and bounded retries for collisions. WP2 PR 3 extends this helper for
its lock/input rules instead of introducing another implementation.

A failure after step 2 leaves extra protection. A failure before step 2
must leave both project projection links and user backup sources unchanged.
A failure between multiple workspace switches leaves all old and new targets
protected. Root union never shrinks, including when a later closure write
fails. Serialize concurrent same-project publication through the existing
per-root project transaction lock at `<store>/root-locks/<raw-path-key>`
(never unlink it), acquired after activity/x-root and before cache/publication
locks; test two
simultaneous ecosystem publications so backup/link operations cannot race.

**Fault injection.** Cover preparation, root temp write/fsync/rename,
backup move, forest rename, each project symlink switch, and closure write.
Restart after each boundary, age candidates past retention windows, then GC:
visible projections and moved user backups must survive. Test both an
existing root and a first registration. The first-registration failure case
must not be confused with a legitimately initialized empty registry.

#### C.7 The eight producer changes

Seven ecosystems plus the rustfmt toolchain closure. Callers supply the exact
IDs and projections they created; nothing is inferred by walking JSON.

| # | Producer | Call site | Objects | Projections |
|---|---|---|---|---|
| 1 | Python | `project::project_env_inner` → `write_closure` (`project.rs:854`) | env object id; native-libs object id from `nativelibs::env_reference` (`nativelibs.rs:1386`) when present | reserved store-owned backup destination; split `backup_real_dir` into prepare/move so the root is durable before the move (the old return value is discarded at `project.rs:826`) |
| 2 | Node | `npm::project_node_env` (`npm.rs:2443`) | env object id; native-libs object id | forest `{forests, [short_sha256(project,32), proj_id]}`; reserved backups for the three old `backup_real_dir` sites at `npm.rs:2248`, `npm.rs:2254` and `npm.rs:2256`; protect before moving |
| 3 | Cargo | `cargo.rs:1121` | `rust_obj` id, `vendor_obj` id | none |
| 4 | Go | `golang::project_go_env` (`golang.rs:937`) | `go_obj` id, `modcache_obj` id | none |
| 5 | Ruby | `ruby::project_ruby_env` (`ruby.rs:852`) | `ruby_obj` id, `gems_obj` id | none |
| 6 | Elixir | `elixir.rs:1428` | `beam_obj` id, `deps_obj` id | `{forests, [<16-hex key>, <deps object id>, "hex-deps"]}` from `expected_projection` (`elixir.rs:1372-1388`) |
| 7 | .NET | `dotnet::project_dotnet_env` (`dotnet.rs:1019`) | `sdk_obj` id, `packages_obj` id | none |
| 8 | rustfmt | `main.rs::run_fmt` (`main.rs:1458`) | `rust_object` id, `rustfmt_object` id | none |

Each producer's local `object_ref` closure (six near-identical copies at
`cargo.rs:1111`, `golang.rs:924`, `dotnet.rs:1008`, `elixir.rs:1421`,
`ruby.rs:840`, `main.rs:1446`) should be replaced by the `ClosureRefs`
methods; the closure bodies keep emitting their existing `{"path","id"}`
JSON for human readers, but that JSON is no longer authority.

**GC changes in the same PR.** `gc::collect_object_ids` (`gc.rs:255`),
`gc::collect_project_paths` (`gc.rs:288`), and the `node-forest/1|2`
reconstruction (`gc.rs:222-238`) are the guess-from-JSON path. They stay only
for reading **legacy** records during migration and are deleted from the
root-reading path; `collect_roots` reads `root/2` records and never opens the
project directory. `read_closures` becomes the declarative importer used by explicit
`gc --register` and the legacy transition before ordinary publication.

#### C.8 Migration and exact-key recovery

- Legacy `root/1` is a bare absolute pathname line. Classify that format
  explicitly; unknown/malformed JSON must never fall back to pathname mode.
  Read it for inspection/import, never as an empty root. Unresolved legacy
  records block sweeps until registered or explicitly forgotten.
- `gc --register <dir>` imports every `.blanket/closures/*.json` with a
  declarative reader dispatched by envelope ecosystem **and supported body
  schema**. Include legacy body-only formats that shipped, or name a refusal.
  Validate all closures before replacing any root. Import recorded object
  references and recoverable projections; never certify an inferred empty
  set. Backups that old closures never recorded stay protected by the blanket
  prohibition on deleting the shared legacy backup namespace.
- Ordinary sync encountering a pathname-only root runs the same importer
  **before changing projections** and unions every ecosystem's old references
  with its new ones. Import failure leaves the old record and project intact
  and names `gc --register`/explicit forgetting as recovery. A resync of Python
  must not drop an existing Node environment's protection. No ordinary sweep
  imports or writes root records.
- Readers execute no project code, package manager, or network request.
  Unknown, malformed, cross-store, and ambiguous closures refuse import.
  `--dry-run --register` validates/imports in memory only.
- UTF-8 root keys are unchanged. New non-UTF-8 paths use raw-byte keys. If an
  old lossy record might correspond to such a path, do not merge/re-key it by
  guess: report both keys, preserve the old record, and require explicit
  recovery. A genuine UTF-8 path containing U+FFFD must remain distinct from
  a non-UTF-8 path that was formerly displayed with that character.
- Split diagnostic enumeration from strict sweep decoding. `store roots`
  reports each syntactically valid key, including corrupt-record/symlink
  diagnostics, without requiring every record to decode successfully.
- `gc --forget <key>` validates the exact key and entry type/identity using
  the held roots directory, independently of record-body parsing. It can
  unlink a malformed record or the registry symlink **itself**, never its
  target. Do not call `roots()` to locate it. Validate the complete requested
  key set before any mutation; unknown keys abort. Refuse directory entries
  and other unexpected types with a precise recovery diagnostic. A corrupt
  unrelated key must not prevent forgetting the selected one. Fsync the
  registry directory after the removals; dry-run performs no unlink/fsync
  mutation. This is explicit loss of protection, not an implicit sweep.

#### C.9 Failure modes to cover explicitly

| Case | Required behaviour |
|---|---|
| Non-UTF-8 project path | tagged encoding and raw-byte key round-trip; distinct byte paths stay distinct, including a literal U+FFFD UTF-8 path |
| Malformed JSON in `roots/<key>` | sweep refuses, names the key and `--forget` |
| Unknown schema (`root/3`) | refuse; never fall back to pathname reading |
| Malformed object id in a record | refuse |
| Absolute or `..`-bearing projection ref | refuse at read and at write |
| Cross-store object ref | refuse at write |
| Symlinked registry entry `roots/<key>` | **refuse loudly.** Today `roots()` silently skips non-files (`store.rs:94-96`); open records with `O_NOFOLLOW` and report a symlink as a malformed record rather than a silent omission |
| Project moved out of sight | tools and forests stay protected; sweep proceeds |
| Two ecosystems, two historical environments | all four object sets remain protected |
| Crash between record write and closure write | no visible closure with missing root protection |

#### C.10 Tests

Unit: `store::tests::{root2_roundtrips_a_non_utf8_path,
root2_rejects_unknown_schema, root2_rejects_absolute_projection,
root2_rejects_cross_store_object, root2_merge_is_a_union_never_a_replace,
symlinked_registry_entry_is_a_malformed_record}`;
`project::tests::{closure_refs_reject_a_bare_path_that_merely_contains_an_id,
publication_persists_the_record_before_the_closure}`; per-producer
`*::tests::closure_refs_name_every_object_this_producer_created`.

Fault injection: `gc::tests::crash_after_record_write_leaves_extra_protection`,
`gc::tests::crash_before_record_write_publishes_no_closure`.

Integration (`tests/gc.rs`, non-ignored where possible):
`moved_project_keeps_its_tools_and_forests`,
`two_ecosystems_and_two_environments_all_stay_protected`,
`register_imports_every_shipped_closure_schema`,
`register_refuses_an_unknown_closure_and_keeps_the_old_record`,
`register_runs_no_project_code`,
`legacy_record_still_blocks_until_registered_or_forgotten`,
`forest_retention_works_with_the_project_directory_absent`,
`sibling_stores_have_disjoint_new_projection_namespaces`,
`legacy_shared_forests_and_backups_are_never_swept`,
`sync_imports_all_legacy_ecosystems_before_switching_one`,
`forget_corrupt_record_works_with_an_unrelated_corrupt_record`,
`forget_registry_symlink_never_touches_its_target`,
`utf8_keys_unchanged_and_non_utf8_keys_distinct`,
`legacy_lossy_key_is_not_silently_reassigned`,
`x_cleanup_revalidates_explicit_or_legacy_origin`.

**Linux verification.** `cargo fmt --check`, `cargo test`,
`cargo test --test gc -- --ignored`, plus `fmt_e2e` and the `x` lifecycle
ignored tests (rustfmt is producer 8 and `x` registers roots).

**Mac before merge.** `cargo test`, `cargo test --test gc -- --ignored`, and
one real sync per ecosystem available on the Mac, to prove the eight
producers write valid records under clonefile projection.

**Completion criteria.** All eight producers pass `ClosureRefs`; `write_closure`
has no store-guessing fallback; `collect_roots` opens no project directory for
a `root/2` record; every row in C.9 has a test; migration is documented in
`ARCHITECTURE.md` and `CLI.md`.

#### C.11 Adopted decisions

1. Use raw-byte keys now. UTF-8 compatibility costs no re-keying; ambiguous
   old non-UTF-8 evidence is retained and refused rather than guessed.
2. Use JSON with tagged paths/components, explicit store/activity arguments,
   and store-owned new projection/backup namespaces.
3. Retain union semantics with no automatic pruning. Protect legacy shared
   projection areas from automatic collection.
4. Use the same declarative legacy importer for `--register` and a guarded
   sync transition. Ordinary sweeps do not migrate root records. This is
   distinct from D's automatic **object-metadata** maintenance.
5. Exact-key forgetting must work despite malformed record contents. Diagnostic
   enumeration is tolerant; the deletion planner remains fail-closed.

---

### 5.4 Package D — make deletion require complete evidence — **REWRITTEN 2026-09-09** after its rejection; review outstanding

> **Rejected once, then rewritten rather than patched.** The 2026-09-09
> independent round found seven blockers (`REVIEW.md`). The rewrite replaces
> the adapters, the sweep, and the publication API:
>
> - `src/objmeta.rs` is new: the record reader, a read-only metadata index,
>   and 20 adapters dispatched on the **(kind, schema)** pair. Each is a pure
>   function of one validated legacy record plus that index, returning
>   `Proven(ObjectDeps)` or `Unresolved(reason)`. The guessed `refs` array is
>   never read as evidence and is no longer written.
> - `ObjectDeps::from_identity` and the inferring three-argument
>   `Store::commit` are deleted. There is no code path left that can stamp an
>   inferred set `evidence: "explicit"`.
> - `cache_digests` are reconstructed from each producer's own input grammar,
>   with a fixture per matrix row. npm keeps each package's published SRI
>   algorithm; `native-libs` recovers its archive digests only after proving
>   the pinned table still hashes to the record's `manifest_sha256`, and a
>   test asserts the manifest digest is not emitted as a cached artifact.
> - `gc::{read, validate, plan, execute}` exist and only `execute` deletes.
>   A dry run stops after `plan` and carries its unwritten upgrades as an
>   in-memory overlay, so the preview and the sweep agree on candidates and
>   on freed bytes.
> - The containment guard is kept and made precise (transitive; ignores
>   tokens that address no cached file), and mutation-checked in both
>   directions.
> - All 27 D.10 acceptance tests exist, plus the adapter matrix, ten producer
>   drift tests, and the C.10 items D interacts with.
>
> **Still true: do not merge, and do not run `blanket gc` against a real
> store.** The rewrite has had no independent adversarial round and no macOS
> execution. See `REVIEW.md` for what the Linux evidence does and does not
> cover.
>
> **Two deliberate deviations from the D.2 table**, both from the call-site
> audit that table asks for, and both documented in the ARCHITECTURE.md
> matrix: `cargo-vendor` does not record the Rust toolchain (the vendor tree
> is built by `tar` alone, the identity does not commit to a toolchain, and
> recording one let one identity publish two different dependency sets — the
> exact divergence that made a migrated store un-syncable); and `native-libs`
> recovers its digests from the pinned table gated on the manifest hash,
> because no record anywhere holds the individual archive digests.


**Objective.** No destructive action starts until every root and every piece
of metadata needed for the decision has been read and validated. Dependency
information is explicit and supplied at commit, never guessed.

**Planned sequencing gate.** Packages B and C's independent review and merge
remain outstanding; the implementation is nevertheless present locally.

**Delivered in the current working tree.** `object-meta/2` records carry
explicit dependencies, algorithm-qualified cache digests, and an evidence
marker. Automatic metadata maintenance runs before shared jobs; the sweep is
the four D.4 phases; the coverage matrix is in `ARCHITECTURE.md` and every row
has a fixture; the D.10 acceptance suite exists and passes. Linux gates run:
`cargo fmt --check`, `cargo test` (12 consecutive clean runs), `cargo test
--test gc -- --ignored`, `cargo test --test fmt_e2e -- --ignored`, and the
producer e2e suites (single-threaded — see the supervision note below). The
independent review and the macOS gate are still outstanding, so the completion
criteria below are not cleared.

**A pre-existing Package B defect this work surfaced.** The supervisor owns
process-wide signal dispositions and rejects a second concurrent child in the
same process. That is sound for production, where each entry point runs its
children sequentially under one lease, but a test binary runs independent
operations in parallel threads. Reproduced with the five `gitsrc` realization
tests alone, none of which Package D touches. The offline suite now takes
`supervise::SUPERVISION_TEST_LOCK` in the tests that realize through a child;
`--ignored` suites must run with `--test-threads=1`. Making the supervisor
wait rather than reject is a Package B decision and was deliberately not made
here.

**User-visible behaviour.** `blanket gc` either deletes from a fully validated
plan or refuses with a specific reason and deletes nothing. `--dry-run` prints
that same plan. Legacy metadata is upgraded automatically when its exact dependencies can
be proved. Unknown layouts or irrecoverable historical evidence block
collection; the message names the exact kinds/schemas, object IDs, and
recovery action. A supported kind alone is not proof that a record can be
migrated.

#### D.1 The versioned object-metadata schema

`meta/<id>.json` becomes:

```json
{
  "schema": "object-meta/2",
  "id": "<object id>",
  "identity": { "kind": "<kind>", "name": "<name>", "version": "<version>", "inputs": {} },
  "created": 1757400000,
  "exceptions": [],
  "dependencies": [ "<object id>" ],
  "cache_digests": [ { "algo": "sha256", "hex": "..." } ],
  "evidence": "explicit"
}
```

- `dependencies` — **explicit, typed, supplied by the realization caller.**
  Sorted, unique, full-string object ids.
- `cache_digests` — algorithm-qualified. Today cache retention is inferred by
  scanning identity inputs for any 64-hex token
  (`gc::cache_hashes_from_value`, `gc.rs:437-464`); that heuristic is
  replaced.
- `evidence` — `"explicit"` when a caller supplied the set, or
  `"adapted:<kind>@<n>"` when an adapter derived it from a legacy record.
  Never `"explicit"` for an inferred set.
- **Do not reuse the name `refs`.** The existing `refs` field is generated by
  guessing from `Identity.inputs` (`store::object_refs`, `store.rs:681-690`)
  and is read back by `gc::read_meta` (`gc.rs:370-415`) with `has_refs` as a
  legacy boundary. A v1 `refs` must never be mistaken for proven
  completeness; keep it readable, stop writing it.
- **This is not an identity change.** `Identity::object_id` hashes the
  `Identity` struct only (`types.rs:19-29`); `meta/<id>.json` is outside it.
  Object ids and darwin goldens are unchanged. Say so in the PR description,
  because `CLAUDE.md`'s immutability invariant will otherwise look violated.

#### D.2 `Store::commit` and every producer that must be audited

```rust
pub struct ObjectDeps {
    objects: BTreeSet<String>,     // validated store object ids
    cache: BTreeSet<fetch::Digest> // algorithm-qualified artifact digests
}

pub fn commit(
    &self,
    activity: &StoreActivity,
    identity: &Identity,
    staged: &Path,
    exceptions: &[Exception],
    deps: &ObjectDeps,
) -> io::Result<(PathBuf, Vec<Exception>)>
```

Starting inventory of non-test producers, all of which must be audited.
The expected sets below are prompts for that audit, not exhaustive proof.
Enumerate current call sites again; test by identity kind **and schema**,
not by attaining a fixed count of 19:

| # | Call site | Identity kind | Expected dependencies |
|---|---|---|---|
| 1 | `python.rs:243` | `cpython` | none; cache digest of the CPython artifact |
| 2 | `python.rs:292` | `uv` | none; cache digest of the uv artifact |
| 3 | `npm.rs:211` | `nodejs` | none; cache digest of the Node artifact |
| 4 | `npm.rs:1653` | `node-env` | node object; native-libs object; per-package cache digests |
| 5 | `cargo.rs:181` | `rust` | none; cache digest |
| 6 | `cargo.rs:826` | `cargo-vendor` | rust object; crate cache digests; git-source objects **(deviation, owner-accepted 2026-09-09: the vendor identity no longer records a rust toolchain — see plan §5.4 vendor section and ARCHITECTURE.md; validated by Sol)** |
| 7 | `golang.rs:176` | `go` | none; cache digest |
| 8 | `golang.rs:918` | `go-modcache` | go object; module cache digests |
| 9 | `ruby.rs:239` | `ruby` | none; cache digest |
| 10 | `ruby.rs:834` | `ruby-gems` | ruby object; gem cache digests |
| 11 | `elixir.rs:813` | `beam` | artifact digests for OTP, Elixir, and any bundled/provisioned Hex/rebar inputs |
| 12 | `elixir.rs:1366` | `hex-deps` | beam object; every Hex package outer tarball digest; audit companion tools against the BEAM producer |
| 13 | `dotnet.rs:98` | `dotnet-sdk` | none; cache digest |
| 14 | `dotnet.rs:1002` | `nuget-packages` | sdk object; package cache digests |
| 15 | `project.rs:691` | `python-env` | cpython object; native-libs object; sdist-build objects; wheel cache digests |
| 16 | `build.rs:829` | `sdist-build` | cpython object; build-toolchain objects; sdist cache digest |
| 17 | `gitsrc.rs:546` | `git-source` | none (the commit is the verification); no cache digest |
| 18 | `nativelibs.rs:599` | `native-libs` | library artifact cache digests |
| 19 | `rustfmt.rs:171` | `rustfmt` | **the paired rust object** — `rustfmt/1` links `lib` into it, so this is the shared-toolchain reference the brief calls out; cache digest of the component |

Test-only call sites that must also be updated so tests do not certify legacy
metadata by accident: `gc.rs:802`, `gc.rs:1044`, `npm.rs:2603`, `npm.rs:2666`.

**Recording rule.** New records retain runtime dependencies and realized
build-input objects, plus artifact cache digests. Capture IDs/digests while
realizing inputs, not by re-parsing the new object's arbitrary JSON. Add
ordering support to `fetch::Digest` for the illustrated BTreeSet, preserving
algorithm and hex as a pair. Metadata publication validates the ID/Identity
relationship and dependencies without calling the mtime-mutating `has`.

**Coverage artifact.** Commit a matrix in `ARCHITECTURE.md`: producer, identity
kind/schema, each source of runtime/build refs, each artifact algorithm, and
adapter outcome for each shipped legacy layout. Include `sdist-build/2` and
`/3`, Python env's fingerprint versus direct-ID sdist entries, and BEAM
fingerprints. A syntactically valid unknown layout returns unresolved.
Tests must remove one required input at a time and prove the adapter refuses
rather than certifying an incomplete set.

**Cache hits must not certify.** `Store::cache_hit` (`store.rs:348-370`)
returns early for an existing object. It must **not** stamp `evidence:
"explicit"` onto metadata that was written by an older binary. Upgrading a
record is a separate, deliberate migration step (D.3).

#### D.3 Automatic maintenance and pure legacy adapters

The owner's automatic-migration decision stands. Implement it through an
explicit **maintenance phase**, never a shared-to-exclusive upgrade inside
`Store::has` or `cache_hit`:

- Every eligible writable command attempts maintenance before it starts a
  resource-consuming job (sync/plan/build/fmt/run/x/dependency edits and an
  ordinary sweep). Recovery/inspection operations — exact forgetting,
  root-only registration, x-clean, store inspection, and help — do not depend
  on automatic metadata maintenance succeeding. The standalone migration
  command remains explicitly available. A short shared preflight may inspect whether
  legacy metadata exists, but it owns no long-lived resource paths/leases.
  Drop that preflight token completely before trying exclusive activity.
  Re-read all migration inputs under the exclusive token; the earlier probe
  is a hint, not a snapshot for writing. Release exclusive maintenance before
  taking the job's shared token. Do not acquire it while holding x-root,
  project, cache, or publication locks.
- If another job prevents exclusive acquisition, announce that metadata
  maintenance is deferred and continue ordinary non-destructive work under
  shared protection. Retry on the next eligible invocation; never bypass
  GC's incomplete-evidence refusal. Read-only inspection and help need not
  trigger migration. `--dry-run` never writes migration records.
- GC already acquires exclusive activity: perform the maintenance phase under
  that token before its deletion snapshot. `gc --migrate-metadata` runs this
  phase alone and returns without sweeping. It is incompatible with
  register/forget/project-sweep/collect-legacy/keep-days options; `--dry-run`
  may preview it. Busy explicit migration exits 1 with a retry diagnostic.
- The adapter is a **pure function** of a validated legacy record and a
  read-only metadata index: `Proven(ObjectDeps)` or `Unresolved(reason)`.
  One adapter per known kind may dispatch by schema, but every shipped
  schema variant needs fixtures. Unknown schema values, conflicting IDs,
  invalid references, or malformed metadata are errors, never downgrade-to-v1
  opportunities. No network, package manager, build, or current-default guess.
- Prove indirect references using exact legacy input semantics and matching
  validated metadata. For example, a build fingerprint is not an object ID.
  An adapter may need to match other identity records; it must reject
  ambiguous or missing matches. Historical build inputs may already have
  been collected by older GC: report the missing evidence and block; do not
  promise all old stores become collectable merely because all kinds have an
  adapter. An explicitly documented historical schema with no retained build
  input promise may use a narrower evidence version only if its full runtime
  closure is provable; do not silently choose that relaxation in this PR.
- Compute and validate candidate dependency graphs before publishing upgrades.
  Adapters never trust the old guessed `refs` field as completeness evidence.
  Preserve original identity, ID, creation/retention timestamps, and exceptions
  byte-semantically. Atomic metadata replacement uses create-new random temps,
  file fsync, rename, and directory fsync under exclusive activity and the
  publication lock. Do not modify object contents or touch object mtimes.
- Publish only proved records with `evidence: "adapted:<kind>@<version>"`.
  Unknown/unresolved records remain unchanged. A failed/partial maintenance
  run is idempotently retryable and cannot start deletion. Announce actual
  upgraded and unresolved counts. A schema marker is not authority unless
  every required field and reference validates.
- `cache_hit` never stamps old records `explicit`. An already-existing object
  keeps its proven metadata; on a concurrent commit, validate that supplied
  identity/dependency evidence agrees or refuse inconsistent data. Different
  candidates must not silently replace each other's dependency sets.
- `--collect-legacy` still controls the existing age/legacy retention choice;
  it cannot authorize deletion through missing or incomplete evidence. Give
  object-specific recovery instructions; a rebuild under the new producer
  can help only if it actually regenerates and validates missing evidence,
  not if it merely returns the same old cache hit.

Automatic migration is additive maintenance, not a destructive permission
prompt. The earlier explicit-only D.3 contract is superseded. Root-record
migration remains C's separate declarative import protocol.

#### D.4 Read / validate / plan / delete phases

Split `gc::collect` (`gc.rs:81-116`) into four:

```rust
fn read(store: &Store, activity: &StoreActivity) -> io::Result<Snapshot>;
fn validate(snapshot: &Snapshot, options: &Options) -> io::Result<Validated>;
fn plan(validated: &Validated, options: &Options) -> io::Result<Plan>;
fn execute(plan: &Plan, store: &Store, activity: &StoreActivity, out: &mut W) -> io::Result<Report>;
```

- `Snapshot`: root records, object metadata, object entries, cache entries,
  stage entries, forest entries, backup entries — with held parent-directory
  descriptors for each swept directory.
- `validate`: malformed roots, unknown schemas, and unreadable metadata are
  **errors**. Missing or incomplete dependency information is **not** an empty
  dependency list — in this first implementation it aborts the whole sweep.
  Do not invent partial-recovery rules.
- `plan`: a fully-formed in-memory deletion plan and retention skips, only
  after validation succeeds. Validation failure returns structured blocked
  diagnostics; there is no partially executable plan with blocked evidence.
- `execute`: the only phase that deletes, under the same continuously held
  locks. Never save a plan and execute it later without repeating validation.

**The read phase must not mutate.** In particular it must not call
`Store::has`, which touches the object's mtime (`store.rs:238-247`), and must
not call `store::touch_path`.

#### D.5 Dry-run behaviour

- Uses the **same pure adapters, validation, and planning rules** as a real
  sweep. Legacy records that can be proven are adapted in memory only. A real
  sweep persists those same upgrades in its maintenance phase, then snapshots
  again. Migration does not reset age timestamps, so both paths choose the
  same candidates for the same filesystem state and captured decision time.
- Unknown/unresolved evidence blocks both paths. Preview may show reasons and
  proposed metadata upgrades, but must not show any deletion as authorized
  while validation is blocked. Concurrent changes or elapsed age thresholds
  can legitimately change a later run; tests freeze the clock/snapshot.
- Never removes roots, never migrates records, never refreshes timestamps.
- Reports skipped and blocked decisions **distinctly** from deletion
  candidates and freed bytes. Output categories: `would remove …`,
  `blocked: …` (with the reason and the recovery action), `skipped: …`
  (retention policy).
- Package A's `--dry-run --forget` in-memory exclusion continues to work
  against the new plan.

#### D.6 Transitive dependency traversal

- Start from **every durable root's** `objects` set (Package C's `root/2`).
- Add objects retained by existing age/legacy policy as marking roots, and
  traverse **their** dependencies too — the current `retained_object_ids`
  behaviour (`gc.rs:350-368`, tested by
  `gc::tests::retained_object_keeps_old_dependency`) is correct and must be
  preserved.
- BFS over `dependencies`, visited-set terminated, so cycles are handled.
- A reachable id with **no metadata** aborts the sweep, naming the id and its
  referrer.
- An object may be removed only when: it is absent from the complete retained
  set, **and** activity is exclusively locked, **and** retention policy
  permits deletion.
- Cached artifacts are retained by explicit `cache_digests` on retained
  objects; managed projections by explicit `ProjectionRef`s on surviving
  root records.
- Preserve the existing `--keep-days` semantics and the `ACTIVE_WINDOW` /
  `STAGE_WINDOW` constants as retention policy unless a change is documented
  separately.

#### D.7 Corruption, no-follow deletion, and replacement checks

- Use the existing no-follow primitives: `store::remove_tree_at` (`store.rs:590`),
  `store::remove_tree_entry_at` (`store.rs:536`), `store::unlink_if_same`
  (`store.rs:509`), `store::stat_at` (`store.rs:432`). Do not add a second
  removal path.
- Hold parent directory descriptors for `objects/`, `meta/`, every supported
  artifact namespace (`cache/sha1`, `cache/sha256`, `cache/sha512`), `tmp/`,
  each store-owned `forests/<key>/`, and store-owned `backups/` from read
  through execution. Delete relative to them. Other cache namespaces (for
  example generated Cargo locks) are named retention-only skips until a
  separate producer-specific cache contract exists; never sweep them as
  unreferenced artifact hashes.
- Forest and backup retention both consult surviving root projections.
  Retaining `hex-deps` protects the containing swept ancestor as well; compare
  ancestor/descendant relationships, not just string equality. Preserve
  C's prohibition on deletion from the shared legacy sibling namespaces.
- **Never follow a symlink outside the managed directories.**
- **Recheck candidate identity before removal:** `fstatat` the name relative
  to the held parent and compare `(dev, ino)` and file type against what the
  plan recorded. A replacement or an unexpected file type stops **that**
  deletion with an error; it does not silently skip and it does not proceed.
- Convert `sweep_projects` to descriptor-relative enumeration, size calculation,
  and deletion in the store-owned namespace. Never follow tree symlinks to
  count bytes or delete contents. A post-validation execution I/O/replacement
  error stops remaining execution and reports any deletions already completed;
  there is no filesystem rollback. The zero-deletions promise applies to
  validation failures, not to an error after deletion has started.

#### D.8 Interaction with forgetting roots and `x` cleanup

- `gc --forget` (shipped in A) gains **exclusive activity protection**, so it
  cannot race a job publishing that root.
- The deletion plan treats a forgotten root as **removed before traversal**.
  What remains collectible is recomputed from the surviving records; it is
  never assumed from the forgotten root's contents.
- `xrun::clean` (`xrun.rs:1340`) may unregister its root **only after
  successful validated cleanup**, and under the same lock order
  (`activity → x per-root → project transaction → cache → publication`). Failed or busy cleanup **retains**
  protection. See `xrun::registration_for` (`xrun.rs:1319`) and
  `originating_store` (`xrun.rs:1292`) — cleanup already removes the matching
  registry entry in the *originating* store, and that must stay true.

#### D.9 Adopted decisions

1. Retain realized build inputs as well as runtime dependencies in new records.
   Do not guess missing historical evidence in order to meet a migration count.
2. Write `dependencies`, not legacy inferred `refs`; use explicit or versioned
   adapted evidence and validate it when reading.
3. No generic legacy fallback. Cover known kinds and every shipped schema
   variant; unknown/incomplete evidence blocks collection.
4. Keep `--collect-legacy` as a retention option, with no override for missing
   evidence. The owner authorized conservative automatic migration; do not
   reopen an approval question about the old explicit-only recommendation.
5. Run automatic metadata maintenance on the first eligible writable use,
   before taking the long-lived shared token. A busy store defers maintenance
   visibly; it never weakens the sweep. Keep the standalone
   `gc --migrate-metadata` command and immutable dry-run behavior (D.3/D.5).

#### D.10 Acceptance tests

Every failure mode the brief lists, named:

- `shared_dependency_survives_forgetting_one_of_two_projects`
- `after_forgetting_both_the_shared_dependency_is_collectible_when_age_allows`
- `corrupt_late_root_deletes_nothing_earlier` (corrupt the *last* root record;
  assert no earlier candidate was removed)
- `corrupt_late_metadata_deletes_nothing_earlier`
- `missing_transitive_metadata_aborts_the_sweep`
- `dependency_cycle_terminates_and_retains_both`
- `unknown_metadata_schema_blocks_destructive_gc`
- `invalid_reference_in_metadata_is_an_error`
- `traversal_string_in_a_reference_is_rejected`
- `symlink_replacement_of_a_candidate_stops_that_deletion`
- `type_change_of_a_candidate_stops_that_deletion`
- `dry_run_removes_no_root_migrates_nothing_and_refreshes_no_timestamp`
- `dry_run_and_real_sweep_produce_the_same_plan`
- `failed_x_cleanup_retains_the_root_record`
- `busy_x_cleanup_retains_the_root_record`
- `collect_legacy_cannot_override_incomplete_evidence`
- `legacy_metadata_with_an_adapter_migrates_and_validates_the_id`
- `legacy_metadata_with_an_unknown_kind_stays_blocked_and_is_named`
- `cache_hit_does_not_certify_old_inferred_metadata`
- adapter tests per identity kind and shipped schema:
  `adapter_<kind>_<schema>_recovers_the_expected_dependencies`, plus missing,
  ambiguous, and unsupported-layout fixtures from the coverage matrix
- `automatic_maintenance_precedes_shared_job_activity`
- `busy_automatic_maintenance_defers_without_lock_upgrade`
- `migration_failure_never_starts_deletion`
- `dry_run_adapts_in_memory_and_matches_real_plan_at_the_same_time`
- `sha1_sha256_and_sha512_artifacts_follow_retained_object_digests`
- `hex_package_tarballs_remain_cached_for_a_retained_hex_object`
- `retained_backup_and_nested_hex_projection_are_not_deleted`
- `partial_execution_error_reports_completed_deletions_honestly`

**Where each named test lives (2026-09-09 rewrite).** All present and
passing.

| D.10 name | Location |
|---|---|
| `shared_dependency_survives_forgetting_one_of_two_projects` | `gc::tests` |
| `after_forgetting_both_the_shared_dependency_is_collectible_when_age_allows` | `gc::tests` |
| `corrupt_late_root_deletes_nothing_earlier` | `gc::tests` |
| `corrupt_late_metadata_deletes_nothing_earlier` | `gc::tests` |
| `missing_transitive_metadata_aborts_the_sweep` | `gc::tests` |
| `dependency_cycle_terminates_and_retains_both` | `gc::tests` |
| `unknown_metadata_schema_blocks_destructive_gc` | `gc::tests` |
| `invalid_reference_in_metadata_is_an_error` | `gc::tests` |
| `traversal_string_in_a_reference_is_rejected` | `gc::tests` |
| `symlink_replacement_of_a_candidate_stops_that_deletion` | `gc::tests` (drives `read`/`validate`/`plan`, mutates, then `execute`) |
| `type_change_of_a_candidate_stops_that_deletion` | `gc::tests` (same shape) |
| `dry_run_removes_no_root_migrates_nothing_and_refreshes_no_timestamp` | `gc::tests` |
| `dry_run_and_real_sweep_produce_the_same_plan` | `gc::tests` |
| `failed_x_cleanup_retains_the_root_record` | `tests/cli.rs`, offline through the real binary |
| `busy_x_cleanup_retains_the_root_record` | `tests/cli.rs`, offline; holds the per-root lock the way a running tool does |
| `collect_legacy_cannot_override_incomplete_evidence` | `gc::tests` |
| `legacy_metadata_with_an_adapter_migrates_and_validates_the_id` | `gc::tests` |
| `legacy_metadata_with_an_unknown_kind_stays_blocked_and_is_named` | `gc::tests` |
| `cache_hit_does_not_certify_old_inferred_metadata` | `gc::tests` |
| `adapter_<kind>_<schema>_recovers_the_expected_dependencies` | `objmeta::tests`, one per matrix row, plus missing / ambiguous / unsupported-layout / traversal / schema-collision refusals (39 tests). Ten producer modules additionally pin their adapter to the producer's **own** identity function (`legacy_adapter*`), so an identity change that outruns its adapter fails the build |
| `automatic_maintenance_precedes_shared_job_activity` | `gc::tests` |
| `busy_automatic_maintenance_defers_without_lock_upgrade` | `gc::tests` |
| `migration_failure_never_starts_deletion` | `gc::tests` |
| `dry_run_adapts_in_memory_and_matches_real_plan_at_the_same_time` | `gc::tests` |
| `sha1_sha256_and_sha512_artifacts_follow_retained_object_digests` | `gc::tests` |
| `hex_package_tarballs_remain_cached_for_a_retained_hex_object` | `gc::tests` |
| `retained_backup_and_nested_hex_projection_are_not_deleted` | `gc::tests` |
| `partial_execution_error_reports_completed_deletions_honestly` | `gc::tests` |

C.10 items whose behaviour D's sweep decides, added with it:
`crash_after_record_write_leaves_extra_protection`,
`crash_before_record_write_publishes_no_closure`,
`legacy_record_still_blocks_until_registered_or_forgotten`,
`legacy_shared_forests_and_backups_are_never_swept`,
`forest_retention_works_with_the_project_directory_absent` (all `gc::tests`),
and `x_cleanup_revalidates_explicit_or_legacy_origin` (`tests/cli.rs`, both
the `x-request/2` marker and the closure-derived legacy origin).

**Linux verification.** `cargo fmt --check`; `cargo test`;
`cargo test --test gc -- --ignored`; `cargo test --test fmt_e2e -- --ignored`;
the `x` lifecycle ignored tests; on a disposable store with a disk-backed
`TMPDIR` and `BLANKET_SANDBOX_TESTS=required`. Check actual test target names
before invoking them. **Run every `--ignored` target with
`--test-threads=1`**: the supervisor rejects a second concurrent child per
process, which is correct for production but collides across parallel test
threads (a pre-existing Package B limitation, reproducible with the `gitsrc`
realization tests alone).

**Mac before merge.** `cargo test`, `cargo test --test gc -- --ignored`, and a
real sync + `gc --dry-run` + `gc` cycle on a Mac store, because the
descriptor-relative deletion primitives and `clonefile`-created forests differ
there.

**Completion criteria.** Four sweep phases exist and only `execute` deletes sweep
candidates; every current commit producer supplies explicit deps; the
kind/schema coverage matrix and pure adapters are tested; automatic
maintenance follows D.3 and never upgrades a shared job token; every test in
D.10 passes; `--collect-legacy` help and tests describe
the stricter behaviour; `ARCHITECTURE.md`, `CLI.md` and `LIMITATIONS.md`
match delivered behaviour.

**What a fresh adversarial round should target first (2026-09-09 rewrite).**
Ordered by where the author's own confidence is weakest, not by how hard the
code was to write.

1. **Adapter/producer agreement for the six plan-based producers.** Ten
   pin-based producers have drift tests that build the identity with the
   producer's own function and assert the adapter recovers it. `node-env/3`,
   `python-env/2`, `cargo-vendor/1`, `go-modcache/1`, `ruby-gems/1`,
   `hex-deps/1`, `nuget-packages/1` and both `sdist-build` schemas are pinned
   only by fixtures hand-derived from a call-site audit. If a fixture
   mis-states the producer's input grammar, the adapter is confidently wrong
   and the containment guard will not catch it, because the guard compares
   against the *old* reader, not against the producer. Read
   `npm::node_env_identity`, `project::environment_identity` and
   `build::plan_sdist_identity_input` against `objmeta::{node_env_v3,
   python_env_v2, sdist_build_v2, sdist_build_v3}` line by line.
2. **The `cargo-vendor` deviation.** Dropping the Rust toolchain from the
   dependency set is a retention *narrowing* justified by the claim that the
   project's `root/2` closure always records `rust_object`. Verify that claim
   for every path that realizes a vendor tree, including `blanket build` on an
   sdist with a Rust extension, and check what happens to a vendor object
   retained only by age.
3. **The `python-env/2` fast-path fingerprint match.** `python_env_v2` picks
   the one `sdist-build/2` record matching name, sdist digest, toolchain,
   interpreter and platform. The package *version* is not in the fingerprint.
   Construct a store where two `sdist-build/2` records differ only in version
   and confirm the match is refused as ambiguous rather than guessed.
4. **`native-libs` gated recovery.** The adapter trusts the current pinned
   table once `manifest_sha256` matches. Confirm the manifest hash actually
   commits to every archive digest the adapter then emits, and that a partial
   table cannot produce a colliding manifest.
5. **The containment guard's cache-presence rule.** It ignores 64-hex tokens
   with no file at `cache/sha256/<hex>`. Probe the race: a token whose file is
   fetched *between* the guard's read and the sweep. The publication lock is
   held across migration, but confirm the ordering rather than assume it.
6. **`execute` after a partial failure.** The report names completed
   deletions, but there is no rollback and the metadata companion is unlinked
   after the object. Check the window where an object is gone and its record
   is not, and what the next sweep does with it.
7. **Whether an unresolved record can ever be resolved in practice.** D.3 says
   a rebuild helps only if it regenerates and validates the missing evidence.
   `cache_hit` deliberately does not certify. Confirm there is a real recovery
   path for each unresolved reason, or say plainly in `LIMITATIONS.md` that
   some stores never sweep again.

---

### 5.5 Delivery and verification for the whole GC track

- Four reviewable commits/packages in order: **A (done, needs review) → B →
  C → D.**
- **Size by risk, not line count.** B's process/signal lifecycle is substantial
  work with a full subprocess audit; do not treat it as a two-exec-site patch.
  C's transaction and namespace changes and D's per-schema evidence adapters
  are also substantial. Implement within each package in small reviewable
  commits, with its activation/completion gate last; do not claim a whole
  package complete because its shared helper compiles.
- Within C and D, **migrate producers before enabling collection based on the
  new schema.**
- **Do not ship a permissive fallback just to keep legacy tests green.**
- Add fast offline subprocess tests to normal test execution; the key safety
  cases must not live only in ignored network integration tests.
- Test stores must be temporary; environment-mutating unit tests use
  `store::STORE_ENV_LOCK`.
- Record commands, results and platform gaps for each package.
- Update `CLI.md`, `ARCHITECTURE.md` and `LIMITATIONS.md` to match delivered
  behaviour; append review status to `REVIEW.md`.
- In the final implementation report, explain plainly that unavailable
  projects remain protected, active jobs postpone cleanup, and forgetting a
  project is now an explicit action.

---

## 6. Backlog (unranked, from the retired ROADMAP.md standing list)

Reviewed 2026-09-09. Items that the GC track or WP2 now subsume are marked;
the rest stand.

| Item | Status after this review |
|---|---|
| M5 hardening: RECORD verification and rewrite, Mach-service allowlist, deployment-target tags, streaming extractors | stands. Streaming extractors connect to the WP2 extractor's architectural finding (read tar headers directly instead of parsing `tar -tv`); do them together |
| Sol review 3 leftovers: dependency-order lifecycle execution and ancestor `.bin` paths; true npm optional-failure parity; planner subprocess sandboxing; process-tree quiescence after install scripts; Xcode/SDK fingerprint in build identity | stands. **Process-tree quiescence overlaps GC Package B**: B's supervisor bounds the awaited direct child; descendants surviving its exit remain outside the guarantee. Do not claim B closes this |
| Store-object content verification on use (same-user replacement is undetected), or an explicitly narrower documented trust boundary | stands, and GC Package D's replacement recheck is *not* this — D checks the deletion candidate, not the object a job is about to use |
| Contained atomic writes for the remaining project-side plan caches | stands; `src/fsroot.rs` (extracted by GC C, extended by WP2 PR 3) is the helper they should use |
| Per-package store objects with copy-on-write assembly | stands; deferred by the "env-level granularity" MVP decision |
| Reproducibility spot-checks (rebuild twice, compare, quarantine mismatches) | stands |
| Bytecode precompilation at realize time | stands |
| Pinned C toolchain as a store object (closes the unpinned host gcc/glibc and Xcode inputs on both platforms) | stands. Recording the current host Xcode/SDK fingerprint can land earlier; a managed C toolchain is the stronger reproducibility follow-up, not a prerequisite to honest fingerprinting |
| Breadth: system packages (CLI tools and libraries first; GUI apps and services are a different product) | stands |
| JVM | deliberately deprioritized |
| Health metric: lines of code per tailor must keep falling, or stop and fix the kernel | stands; measure it again after GC Package C, which adds per-producer code |

---

## 7. Decisions and external inputs

The owner requested this re-review and incorporation of the reviewer's
corrections. The implementation choices below are adopted, not pending
permission questions. Previously approved product decisions remain in force.
Only the external inputs in §7.2 remain open, scoped to their stated gates.

### 7.1 Adopted implementation choices

| # | Decision | Where |
|---|---|---|
| 1 | Finish/review GC A, then B → C → D; Mac transcript work is a separate merge gate | handoff, §4 |
| 2 | WP2 PR 1 precedes lock core; extractor 2b precedes a second consumer | WP2 |
| 3 | WP3 evidence spike precedes authenticated-provider choice; WP3 PR 1 owns mandatory source-policy loading | WP3 |
| 4 | Yarn classic stays a documented refusal absent a concrete need | 4b-2 |
| 5 | Explicit activity tokens, fallible `has`, and separate cache-lease semantics | B.1–B.3 |
| 6 | Supervise all awaited store-consuming children; correct signal lifecycle and preserve actual SIGPIPE behavior | B.5–B.7 |
| 7 | Busy explicit forget/migration exits 1; busy sweeps exit 0 | B, D.3 |
| 8 | Raw-byte root keys preserve UTF-8 compatibility; ambiguous lossy legacy records are not guessed | C.1/C.8 |
| 9 | Durable root union before projection/backup changes; store-owned new projection namespaces | C.3/C.6 |
| 10 | Root imports on explicit register or guarded legacy sync transition; never during an ordinary sweep | C.8 |
| 11 | Automatic metadata maintenance before long-lived shared activity, deferred visibly if busy; dry-run adapters stay in memory | D.3/D.5 |
| 12 | Explicit dependencies and algorithm-qualified caches, with adapters/tests per kind and schema; unknown evidence blocks | D.1–D.3 |

### 7.2 Owner decisions and remaining external inputs

**Answered 2026-09-09.**

| # | Question | Owner's answer |
|---|---|---|
| 1 | Merge policy for the WP1/WP2/WP4 branches | Moot — all six are already merged into `main` (`34fa8b5`). What is owed is one Mac run, not five merge decisions |
| 2 | GC B: the supervisor is unconditional, one extra process per `run`/`x` | **Approved.** Measured at ~7 MB and no CPU |
| 3 | GC B/5.0: a long-running job postpones cleanup for its lifetime | **Accepted** as a timing cost, not a correctness cost |
| 4 | GC D: metadata migration — explicit command, or automatic? | **Automatic on first run**, overruling this plan's recommendation. Binding maintenance protocol in D.3/D.5 |
| 5 | GC D: `blanket gc --migrate-metadata` as new CLI surface | **Approved**, but as the explicit alternative rather than the only path |
| 6 | Codex review availability | Limits reset; not a blocker. Reviews proceed normally |

**Still open.**

| # | Question | Why it is the owner's |
|---|---|---|
| 1 | Capture a WP0 transcript on the Mac against `main` at a named commit | the owner asserted 2026-09-09 that the Mac is current and healthy; no command output has been recorded, so §3.4 still lists the gate as unevidenced. This is bookkeeping, not doubt |
| 2 | WP3 trusted-key policy: where keys live, who rotates, what revocation means — now including a company's own internal publisher | security policy, no material in the repo. Owner has given direction (configurable trust) but not a key policy |
| 3 | WP5 private-registry credentials and a test account | credentials |

---

## 8. Status log

Newest last. Historical entries describe earlier drafts, not current
implementation instructions; the revised package sections take precedence.
One row per change to this plan or to a package's status.

| Date | Change |
|---|---|
| 2026-09-06 | PLAN.md created; ROADMAP.md retired; NEXT.md frozen as an index. Astra plan review: PROCEED-WITH-CHANGES, folded in. Main at that commit has rustfmt applied and `cargo fmt --check` clean. |
| 2026-09-06 | Platform rules added: Mac-before-merge gate per work package; WP0 restated against the last Mac-verified commit (`dbf7ac4`, then 76 commits behind main); Windows explicitly out of scope. Local and origin main confirmed identical at `0268405`. |
| 2026-09-06 | WP2 Python exact-selection bugs fixed (`wp2/python-exact-selection`): an exact `.python-version` patch must be pinned or sync fails closed; `python::lookup` is exact-or-newest-minor over canonical spellings. Sol: 3 rounds. |
| 2026-09-06 | WP2 Go exact-selection bug fixed (`wp2/go-selected-version`): realization takes the go.mod-selected version; an unpinned selection fails before store or network access. Sol: 3 rounds. |
| 2026-09-07 | WP2 toolchain-lock **design** landed in ARCHITECTURE.md (`wp2/toolchain-lock-design`, docs-only) after ten adversarial rounds: catalog off the reproducibility path, `/dev/urandom` + `fsync` publication, absence-aware staleness under root-anchored discovery, defined `bundle_id` and canonical lock bytes, and a structural (not blocklist-based) sandboxed-evaluation guarantee scoped to frozen validation. Round 10's own fixes are the currently unreviewed layer. Implementation open. |
| 2026-09-07 | WP2 secure archive extractor (`wp2/archive-extractor`, ordered PR 2): `src/archive.rs` validates every tarball member before tar writes anything; first consumer is the Go toolchain tarball. |
| 2026-09-07 | WP4 `x` lifecycle (`wp4/x-lifecycle`): `blanket x --clean`, per-root shared locks for running tools, descriptor-relative cleanup. Sol r1–3, Claude r4–5 (MERGE on Linux evidence). Mac cold/warm gate outstanding. |
| 2026-09-07 | WP1 `blanket fmt` (`wp1/fmt-rust`): pinned rustfmt as its own store object, a writable-project/no-network fmt sandbox mode on both engines, descriptor-anchored closure publication, `--check` and status pass-through, `fmt` script precedence with `--eco`. Sol r1–2, Claude r3–5 (MERGE on Linux evidence). Linux acceptance 35/35 on `9fabfb5`. Mac gate outstanding. |
| 2026-09-07 | WP4 pnpm dependency edits (`wp4/deps-pnpm-yarn`): `add`/`remove`/`update` through the store pnpm at the exact `packageManager` release, lockfile-only edits with pnpm's modules state redirected into a per-run store stage. Yarn classic/Berry and Poetry/PDM remain refusals. |
| 2026-09-08 | WP2 extractor reviewed to ✅ over three rounds; the reviewer's architectural finding stands: column-parsing `tar -tv` is not a durable foundation and reading tar headers directly is the intended replacement before a second consumer adopts the module. |
| 2026-09-08 | WP4 pnpm membership rewritten twice under review (rounds 6–9) to read `pnpm-lock.yaml`'s `importers` list alone; `pnpm-workspace.yaml` is never consulted, because since pnpm 10 it is also a non-workspace repository's settings file. Round-9 fixes are unreviewed. |
| 2026-09-08 | GC safety brief revised after a code-grounded review: `gc --forget` and `store roots` key display moved from Package D into Package A as the recovery valve for the blocked sweeps A introduces; B states the long-job-blocks-GC consequence, pins the flock per-open-file-description rationale behind the recursive-acquisition ban, prefers a process-global guard registry keyed by canonical store root, and pins the supervisor design; the busy-skip outcome exits 0 per the `x` convention; Delivery records that the C/D producer audits dominate the effort. |
| 2026-09-08 | GC safety **Package A implemented** on `wp-gc-safety`: unavailable pathname-only roots block ordinary and dry-run sweeps without deleting registry records; `gc --forget` is repeatable and exact-key-only; `--dry-run --forget` is registry-immutable; `store roots` prints keys. Packages B–D remain open; independent review and the Mac gate are outstanding. |
| **2026-09-09** | **Plan rewritten and renamed `PLAN.md` → `BLANKET-IMPLEMENTATION-PLAN.md`** (docs-only; no source, test, or fixture change). The GC safety brief that had been appended to the end of the old file is now section 5, integrated with the work packages instead of sitting beside them. Status is consolidated into one ledger (§3) with five buckets — reviewed, review-outstanding, partial, blocked, open — replacing the per-package status lines that had drifted (WP4 carried two contradictory headings). Every remaining package (WP0–WP5, GC B/C/D, backlog) is restated as concrete steps naming source modules, symbols, call sites, schemas, and test names: B specifies the `src/activity.rs` API, the `activity → gc_lock → publish_lock → x-root` order, the reuse of the existing `fetch::acquire_gc_lock` registry pattern, the 17-row entry-point coverage table, and the `src/supervise.rs` supervisor down to no-op-vs-`SIG_IGN` handlers and guard-drop-before-`exit`; C specifies the `root/2` schema, tagged lossless path encoding, typed `ProjectionRef`s, the `ClosureRefs` API, the publication sequence, and all eight producer call sites (including four discarded `backup_real_dir` return values); D specifies `object-meta/2` with `dependencies`/`cache_digests`/`evidence`, all 19 `Store::commit` producers plus four test-only sites, per-kind adapters, the four GC phases, and 20+ named acceptance tests. Open implementation choices are recorded as recommendations (§7.1) and owner questions (§7.2) rather than settled silently. No claim of Mac validation, provider signatures, credentials, or independent review is made beyond what the repository evidences. **This plan is not complete work; it is a roadmap.** |

| **2026-09-09** | **Owner decisions taken after the rewrite, in conversation.** (1) All six WP branches are already merged into `main` at `34fa8b5`; the "five pieces awaiting a merge decision" framing in the rewrite's first summary was wrong, and §7.2 is corrected — one Mac transcript is owed, not five merge calls. (2) The GC Package B supervisor is **approved unconditionally**; measured cost is ~7 MB RSS and no CPU for a process blocked in `waitpid`. (3) The long-job-postpones-cleanup consequence is **accepted** as a timing cost. (4) Object-metadata migration in Package D runs **automatically on first use**, overruling this plan's "migration is a command" recommendation; §D.9.5 now carries the five binding safety rules that make automatic migration acceptable, chiefly that it never enables a deletion it could not otherwise justify and that unknown identity kinds stay blocked. `--migrate-metadata` still ships as the explicit alternative. (5) Codex limits have reset; review availability is no longer a constraint. (6) The Mac is on the current build and healthy per the owner; the gates stay listed until a transcript is captured, as bookkeeping. (7) **New owner direction for WP3:** the trusted-publisher set is *configuration*, not a compiled-in constant, because an enterprise mirrors toolchains internally and will want blanket pulling from its own repository signed by its own key. WP3 gains a "Trust configuration rules" block following the existing tighten-never-loosen policy model, and WP3's trusted-publisher list and WP5's private-registry authentication are now explicitly one mechanism rather than two. |
| **2026-09-09** | **GC safety Package D rewritten** after its rejection. New `src/objmeta.rs`: record reader, read-only metadata index, and 20 per-kind/per-schema adapters that are pure functions of one validated legacy record plus that index. `ObjectDeps::from_identity` and the inferring three-argument `Store::commit` deleted, so no path can certify a guess. `gc.rs` rebuilt around D.4's `read`/`validate`/`plan`/`execute`; the dry run stops after `plan` and carries its unwritten upgrades as an in-memory overlay, so preview and sweep agree on candidates and freed bytes. `cargo-vendor` no longer records the Rust toolchain (audit finding: the vendor tree is built by `tar` alone and the identity does not commit to a toolchain, so recording it let one identity publish two different dependency sets); `native-libs` recovers its archive digests only after proving the pinned table still hashes to the record's `manifest_sha256`. Containment guard kept, made transitive and cache-presence-aware, mutation-checked both ways. All 27 D.10 tests, the adapter matrix, ten producer drift tests and six C.10 interaction items exist and pass. **No review, no macOS.** Separately: a pre-existing Package B defect surfaced — the supervisor rejects a second concurrent child per process, which parallel test threads violate; offline tests take a new `supervise::SUPERVISION_TEST_LOCK`, `--ignored` targets need `--test-threads=1`, and making the supervisor wait instead is left as a Package B decision. |

| **2026-09-09** | **Owner-requested plan re-review incorporated.** `PLAN-REVIEW-2026-09-09.md` records eleven source-grounded findings. Revised GC B to use explicit operation-owned activity tokens, a realizable lock order, supervision of all awaited store-consuming children, and a tested signal lifecycle. Revised C to persist protection before projection/backup publication, use raw-byte root keys and store-owned projection namespaces, retain shared legacy paths, and make corrupt-record forgetting and legacy sync transitions explicit. Revised D to run automatic metadata maintenance before shared jobs, adapt dry runs in memory, audit each kind/schema, and preserve all supported cache algorithms. Reconciled WP2 replay with WP3 configurable endpoint/publisher policy and moved mandatory policy loading ahead of authenticated refresh. Updated `ARCHITECTURE.md`'s affected design contract. Existing code, review, and Mac gate statuses are not cleared by this design review. The handoff starts with isolating and independently reviewing Package A, then B → C → D. |
| **2026-09-09** | **GC safety Packages B–D implemented locally.** The current working tree adds operation-owned activity leases and supervised children, durable `root/2` protection with store-owned projection/backup namespaces, explicit `object-meta/2` dependencies/evidence, automatic metadata maintenance, and fail-closed GC across the supported cache algorithms. Linux library/CLI/integration gates are green, including the ignored GC suite; independent adversarial review, the macOS gate, and the package-specific signal/PTY acceptance transcript remain open. Legacy sibling-home forests/backups remain retention-only by design. |
| **2026-09-09** | **Plan re-review status corrected after implementation.** Packages A–D are implementation-present in the dirty working tree, not merely designs. Their section headings and the status ledger now distinguish that fact from the still-missing independent review, macOS execution evidence, and completion gates. |

---

## 9. What this plan does not claim

Stated plainly, because a plan that reads as confident is easy to mistake for
a status report:

- **No macOS validation is recorded** for anything merged after commit
  `dbf7ac4` (2026-09-05). The owner stated on 2026-09-09 that the machine is
  current and healthy; that is an assurance, and this repository stores
  evidence. Every "Mac before merge" line stays an outstanding obligation until
  a transcript lands.
- **No external provider signature has been verified** by this repository, and
  no publisher key, attestation, or captured signature is stored in it.
- **No credentials** for any private registry exist here.
- **Independent review is per change and per final revision.** Some features
  merged after 2026-09-06 had earlier Sol rounds; the final Claude-only fixes
  listed in §3.2 still need independent follow-up. Do not erase those earlier
  rounds or claim that this plan review clears implementation review debt.
  Codex is available now.
- **GC safety Packages A–D are implemented in the current working tree but
  have not had the required independent adversarial review or macOS platform
  gate.** The Linux tests are evidence of implementation health, not a merge
  or completion claim. The package-specific signal/PTY acceptance evidence is
  also not recorded.

### Two known stale references to the old file name

The 2026-09-09 rename updated `CLAUDE.md`, `README.md`, `NEXT.md`,
`REVIEW.md`, `ARCHITECTURE.md` and `CLI.md`. Two references were deliberately
left alone:

- `src/archive.rs:2` — `//! (PLAN.md WP2, ordered PR 2 …)`. This is Rust
  source, and the rename was a documentation-only change. **Fix it in the next
  PR that touches `src/archive.rs`**, per the standing rule about replacing
  stale doc references when a file is being edited anyway.
- `REVIEW.md`'s 2026-09-07 log row lists `PLAN.md` among the files a
  docs-only PR touched. That is an accurate historical record of that PR and
  is intentionally not rewritten.

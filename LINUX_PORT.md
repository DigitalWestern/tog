# Linux port — plan and changelog

Blanket runs on macOS arm64 only. LIMITATIONS.md calls Linux "the
enterprise enforcement point" and "the highest-leverage single item on the
books." This document is the plan for closing it, in stages that each
leave `main` shippable, plus a changelog that grows as stages land.

Rule for this file: every stage has a checklist and a **Landed** block.
When a stage (or part of one) merges, fill in the date, commit, and what
was actually measured. Never mark a box without a commit to point at.

Target for the port: **x86_64-unknown-linux-gnu** (glibc). Development
and verification host is `m6-fedora` (Fedora 44, kernel 7.1, Ryzen
7640HS 6C/12T, 32 GB, XFS `/home`, tmpfs `/tmp`, SELinux enforcing,
bubblewrap 0.12 installed, unprivileged user namespaces enabled).

---

## Changelog

### 2026-09-06 — `x` cleanup validates its filesystem boundary

`x --clean` now requires an absolute `HOME`, validates the real
`HOME/.blanket/x` directory chain without following symlinks, reserves all
dot-prefixed entries including `.locks`, and rechecks each candidate's
canonical parent immediately before deletion. The checks are shared by the
Linux and macOS paths; no sandbox, extraction, or toolchain pin changed.

### 2026-09-06 — running `x` tools hold an inherited shared lock

`blanket x` now takes a shared `flock` on each cached environment's
`.blanket/x.lock` and clears close-on-exec before replacing itself with the
tool. `x --clean` uses a non-blocking exclusive lock, reports a running tool
as in use, and leaves its registered root for a later retry. This uses the
same advisory-lock contract on Linux and macOS; no sandbox or toolchain pin
changed.

### 2026-09-06 — `x` cleanup lock made stable across projection deletion

The lifecycle follow-up moved the per-environment `flock` to the permanent
`~/.blanket/x/.locks/<root-name>.lock` directory. Linux and macOS runners
share the same blocking shared / nonblocking exclusive contract, so a runner
waiting behind cleanup revalidates a deleted root while still holding the
lock. No sandbox, extraction, or toolchain pin changed.

### 2026-09-06 — ustar limits validated in-process, not delegated to tar

`pack_checkout` no longer infers ustar representability from the tar
subprocess. The two tars disagree about what an unrepresentable entry means:
GNU tar fails the run, while bsdtar prints `Pathname too long` (or
`Link contents too long`), **skips that entry, and exits 0**. The previous
code read only the exit status, so on macOS an overlong path produced a
successful pack of a *truncated* tree, and `cache_insert` stored it under a
hash asserting the whole checkout. That is a store-integrity bug, not just a
platform-divergent test: the object is immutable and input-addressed, so a
silently short archive is indistinguishable from a correct one afterwards.

`ustar_fits` in `src/gitsrc.rs` now checks every collected path before tar is
spawned — 100-byte name field, 155-byte prefix, split on a `/`, one name byte
reserved for a directory's trailing slash — plus a 100-byte check on symlink
targets, which have no prefix field to spill into. The boundaries were derived
by packing each shape with bsdtar and counting surviving entries, not from the
spec alone; `ustar_fits_matches_the_header_layout` pins all of them. Packing
now fails identically on both platforms regardless of which tar is on PATH.

The old test built 2048 overlong entries to prove tar's diagnostics could not
deadlock the stderr pipe. Pre-flight validation means tar never runs for that
input, so the case was rewritten to one path and one symlink; the stderr
drain in `pack_checkout` is unchanged and still covers other tar failures.

Not covered: the ustar 8 GiB octal size field. No checkout is expected to
carry a file that large, and it has not been tested which tar drops versus
fails there.

### 2026-09-06 — adversarial review follow-up

Implementation commit `61c8b50` rechecks the CLI and review debt listed in
REVIEW.md. Git source packing uses sorted null-delimited paths with explicit
nonrecursive tar input; GNU tar receives `--verbatim-files-from`, while BSD
tar relies on `--null`. All entry mtimes use `utimensat` with no symlink
following. Tar failure cannot be hidden by gzip success or hang on a full
diagnostic pipe. Git source identities move to `git-source/2`; registry
identity goldens remain unchanged.

The Go integration fixture now selects the locale its greeting assertion
expects. Validation uses disk-backed TMPDIR and Cargo's `--target-dir`
argument; exporting `CARGO_TARGET_DIR` redirected a nested native fixture
build into the outer test target directory. Final gate outcomes and the
remaining macOS arm64 validation are in REVIEW-2026-09-06.md.

### 2026-09-05 — plan written, Linux baseline measured

- Cloned to `~/repos/blanket` on m6-fedora; installed stable Rust via
  rustup (cargo 1.98.1).
- `cargo build --release`: clean on Linux, 16 s. No `#[cfg]` errors; the
  crate has no platform-conditional compilation beyond `cfg(unix)`.
- `cargo test` (offline): **65 passed, 0 failed**, 14 ignored (network
  e2e). The kernel logic is portable as-is.
- `blanket sync` on a one-dependency npm project with a throwaway store:
  downloads `node-v24.20.0-darwin-arm64.tar.gz` into the store, then
  fails with `cannot execute binary file`. This is the expected failure
  and the whole port in one line: **the code is portable, the pins are
  not.**
- Inventoried every macOS-specific surface (see "Surface inventory").
  Result: 8 toolchain pin tables, 1 wheel selector, 1 npm platform
  check, 1 sandbox implementation, 1 copy-on-write helper, and a
  handful of hardcoded tool paths. Nothing else.

### 2026-09-05 (later) — stage 1 implemented; plan reordered; stage 3 de-risked

- **Stage 1 implemented** by a Codex GPT-5.6 implementer from an
  adversarially pre-reviewed brief (GPT-6 reviewer found 12 issues in the
  brief before any code was written: three identity fingerprints the brief
  had missed, a path in `npm.rs` where a "sandbox unavailable" error would
  have been downgraded to a permissive install-script exception, missing
  platform in two `.blanket/` cache keys, musl detection, and more). Review
  of the resulting diff: **no macOS store-id drift across nine baseline
  identities**; one blocker (golden tests reconstructed identities by hand
  instead of calling production constructors) and six should-fix items,
  addressed in a second pass. Commit hash recorded under Stage 1 "Landed".
- **Plan reordered: the Linux sandbox (old stage 3) now lands before the
  Linux pins (old stage 2).** Reason: the Python and npm round-trip gates,
  and every stage 4 tailor's e2e test, need the sandbox. Landing it first
  lets seven streams run in parallel worktrees afterwards. See "Parallel
  streams" below.
- **bubblewrap prototype passed 10/10 on m6-fedora** (SELinux enforcing,
  non-root): network denied, `~/.ssh` invisible with scratch under `/home`,
  undeclared reads denied, read-only roots reject writes, host gcc compiles
  and runs, PID namespace isolated, env clean, nested-under-Codex works.
  `sudo ausearch -m avc` shows **zero** AVC denials. Open question 1 closed.
  Findings folded into the stage 3 mapping table (`--unshare-user`,
  `/etc/ld.so.conf.d`, the `PWD` shim).
- **Host prerequisites**: stock Fedora 44 Server had `gcc` and `make` but
  not `gcc-c++` (C++ probe failed with `cannot execute 'cc1plus'`).
  Installed `gcc-c++ glibc-devel pkgconf-pkg-config binutils`; C++ now
  compiles inside the sandbox. Open question 4 partially closed (nokogiri
  and node-gyp still to be exercised).
- **Stage 2 pin checksums fetched from official sources**, each alongside
  its darwin sibling, and every darwin value matched the pin already in
  `src/` (validates the sourcing). Values recorded under Stage 2.
- Second reviewer pass produced the parallel-stream table, the manylinux
  selector algorithm, and three latent bugs in the current `score()` that
  would misbehave on Linux if reused. Recorded under Stage 2.
- **OTP on Fedora: no prebuilt Linux OTP works.** hex.pm bob's
  `ubuntu-24.04/OTP-29.0.5` (sha256 verified against `builds.txt`)
  relocates with `Install -minimal` and boots, but `crypto` fails to load:
  `undefined symbol: EVP_sm4_cbc, version OPENSSL_3.0.0`. Fedora 44 builds
  OpenSSL 3.5.8 without SM4 (`openssl list` shows none). erlef/otp_builds
  publishes macOS only; bob only Ubuntu. Reviewer decision: **build OTP
  from source once on this box (option b2), publish with provenance, pin
  its sha256; scope it to glibc ≥ 2.43 hosts honestly; long-term move to a
  static-OpenSSL build on an older-glibc baseline (b3).** Source build
  started 2026-09-05 inside the bwrap prototype sandbox with network
  denied; configure flags and provenance manifest recorded under Stage 4.
- Stage 4 Linux checksums fetched from official sources for Rust (3
  components), Go, .NET SDK, portable-ruby `x86_64_linux`, all with darwin
  siblings matching the existing pins. Recorded under Stage 4.

### 2026-09-05 (evening) — streams landed in parallel; Codex ran out; Claude took over

- **Stage 1 follow-ups merged** (7464ca5), reviewer verdict MERGE.
- **Stream H merged** (4ca4417): `hitrate.py` pins the 60 repos to their
  default-branch commits as of 2026-09-02 (resolved via the GitHub API),
  reports `ok` vs `ok_with_exceptions`, classifies Linux failures.
- **Stream P (Python) implemented and gated on the host**: Linux CPython
  3.12.14/3.13.15 + uv pins, manylinux selector with glibc banding,
  `python-planner/3` key, `CC=gcc CXX=g++` for sdist builds. Real results
  on m6-fedora: `tests/acceptance.sh` sections 1–3, 5–7, 9 pass; 4a/4b
  (offline reprojection/reconstruction) pass under `unshare -rn` after the
  harness got a portable network-deny wrapper (d55e5f1); section 8 (sdist)
  and 9b (npm) fail only because the Linux sandbox and Node pin are on
  other branches. First Linux `blanket sync` of a real Python lock
  succeeded at 14:2x local time.
- **Streams RUST / DOTNET / GO** implemented, reviewed, committed on
  `lp/rust`, `lp/dotnet`, `lp/go`. Verified on Linux without the sandbox:
  `rustc`/`cargo 1.96.1` and `go1.27.0 linux/amd64` run from store objects;
  the .NET SDK object realizes and its muxer reports 9.0.317. Their
  sandboxed build gates run once the sandbox lands.
- **Stream B review (sandbox) came back REWORK** with three real blockers:
  inherited fds ≥ 3 reach the build (bwrap preserves them), no
  `--unshare-ipc`, and host Unix sockets inside bound roots are a channel
  out; plus cwd/mount-order edge cases, vacuous tests, preflight gaps.
  Fix round in progress. Until it lands, Linux native builds fail
  `Unsupported`, by design.
- **Codex hit its usage limit at ~14:30** (resets 2026-09-06 23:51).
  Every in-flight Codex agent died: the sandbox fix round, npm, Ruby, and
  BEAM streams mid-implementation, and the Python review. Partial work
  was preserved in each worktree. Claude subagents resumed each stream
  from the same briefs; the supervisor reviewed Rust/.NET/Go directly.
- **OTP artifact published**: github.com/DigitalWestern/blanket-toolchains,
  release `otp-29.0.5-x86_64-unknown-linux-gnu-fedora44`, sha256
  `18ae1abc8fd39306c502e9a7fd6885df3125f56d783cb577057ec29ad17d01c4`,
  re-downloaded and re-hashed after publishing. Built in 59 s inside the
  bwrap prototype with network denied; crypto/ssl probes pass.

### 2026-09-05 (night) — Linux port functionally complete; all gates green

- Sandbox (stream B), Python, npm, Rust, .NET, Go, Ruby, BEAM all merged
  into `linux-port`. 143 offline unit tests (65 this morning). Every
  ignored e2e gate passes on m6-fedora with `BLANKET_SANDBOX_TESTS=required`.
- Gate debugging on the merged tree found: a 12 GB tmpfs `/tmp` that fills
  when tests keep per-run stores under `TMPDIR` (run gates with `TMPDIR`
  on disk); the CoreCLR shm/EXDEV bug (fixed in `dotnet.rs`); a directory
  creation race when two syncs share `/tmp/.dotnet` (fixed); and three
  test bugs (closure `body` wrapper, esbuild platform packages have no
  entry point, nokogiri links host zlib).
- Host prerequisites confirmed for native builds on Fedora 44:
  `gcc gcc-c++ make binutils glibc-devel pkgconf-pkg-config patch
  zlib-ng-compat-devel libxcrypt-devel` (installed today).
- Stage 5 (hit rate on Linux) started with the pinned 60-repo lock.

---

### 2026-09-05 (closeout) — stages 5–7 landed; port complete on m6-fedora

- Stage 5: hit rate measured on the same 60 pinned repos. python 16/30
  (macOS 18/30); npm 21/30 (macOS 21/30) after 53e384d fixed the one bug
  behind all seven Linux-only npm misses (GNU tar vs 0666 directories in
  registry tarballs). HITRATE.md carries the per-repo comparison; its
  first draft had the macOS column built from the 28-repo re-run CSV
  alone (showing 15/30 and 4/30) — regenerated from both macOS CSVs.
- Stage 6 partially landed (496c612): closure envelope `platform` field,
  README "Working across machines", identity separation proven by the
  darwin goldens. The live shared-store check needs the Mac.
- Stage 7 landed (83c67f3).
- Final state of `linux-port`: `bash tests/acceptance.sh` passed=35
  failed=0 on Fedora 44; every ignored e2e gate (cargo, go, dotnet, ruby,
  elixir, npm_scripts, linux_python, sandbox_deny) green with
  `BLANKET_SANDBOX_TESTS=required`; 158 offline unit tests (65 this
  morning). Worktrees and `lp/*` branches removed after merge.
- **What only Ethan can do before merging to `main`** (needs the Mac):
  `cargo test` on macOS arm64 (the darwin goldens ran here in one binary
  but the Seatbelt path itself has not executed since the refactor), a
  `blanket sync` on an already-synced project to confirm the cache still
  hits (planner schema bumped to `python-planner/3`, so expect exactly
  one re-plan for python), and the stage 6 shared-store check.

---

### 2026-09-05 (review round) — two independent reviews of PR #1, fixes applied

Claude (Fable) and GPT-6 Astra each reviewed the full diff adversarially
and returned MERGE-AFTER-FIXES. Both found the same hole; Astra found a
real macOS test regression. Applied in this round:

- **macOS `cargo test` would have failed** (Astra, blocker): the two new
  `dotnet` temp-dir unit tests built their fixtures under
  `std::env::temp_dir()` and the validator demands canonical paths; on
  macOS `TMPDIR` is under `/var -> /private/var`. Fixed by canonicalizing
  the test base; reproduced and verified here with a symlinked TMPDIR.
- **Undeclared cwd was a read-only view of the host** (both, blocker):
  `run_build_spec` with a cwd outside every declared root `--ro-bind`-ed
  the whole subtree; a probe listed `~/.ssh`. Now an empty tmpfs is
  mounted at the cwd (command can start there; nothing visible; writes
  stay in the sandbox). Seatbelt grants only metadata reads there, so the
  two backends now agree. Tests inverted accordingly.
- **Lock-source stamp is platform-free again** (both): the stamp is
  per-machine state; qualifying it by platform would have forced one
  needless `uv pip compile` on every Mac project after merge. Restored to
  main's exact byte format; `planner_input_hash` keeps the platform.
- **The ignored network-denial gate accepted a sandbox setup failure as
  a denial** (Astra): it now requires a non-`Unsupported` error whose
  text proves the build ran and exited non-zero inside the sandbox.
- **Closure envelopes from another platform are refused** (Astra):
  `read_closure` returns `Unsupported` naming both triples; envelopes
  without the field (pre-port, all darwin) are accepted. Unit-tested.
- `bwrap` is looked up at `/usr/bin/bwrap` first, PATH second (Claude);
  `--hostname blanket` inside the UTS namespace so the host name stops
  leaking into builds (Claude); README's macOS acceptance sentence now
  says the Mac re-run is owed; LIMITATIONS gained the canonical-root
  contract, the two unsandboxed OTP steps, and the OTP cache-hit
  compatibility gap; the `linux_python` coverage row now says what the
  gate actually covers (Astra).
- Not changed, recorded: declared symlink aliases are not preserved on
  Linux (documented contract, LIMITATIONS); OTP runtime compatibility is
  probed on first realization only (LIMITATIONS + NEXT); the `.ssh`
  unit test still creates its scratch under the real `$HOME/.cache`.
- Verification after the fixes: 159 offline unit tests, all ignored e2e
  gates and `tests/acceptance.sh` re-run on m6-fedora (results in the
  PR). Still owed on the Mac: `cargo test`, `bash tests/acceptance.sh`,
  a warm-project resync, the stage-6 shared-store check.

### 2026-09-05 (Mac verification, round 1) — first run on macOS arm64 after the merge

Run by the user's macOS terminal agent on macOS 26.6.2 / arm64 / cargo
1.96.1 at merge commit d857378. `cargo test`: 156 passed, 0 failed, 15
ignored (the Linux-only sandbox checks print their skip line). Acceptance
stopped at one failure, section 10e: the Go fixture printed
`Ahoy, world!` instead of `Hello, world.`

- **Not a port regression — a locale-dependent fixture.** `rsc.io/quote`'s
  `Hello()` calls `rsc.io/sampler`, which picks the greeting from
  `LC_ALL`/`LC_MESSAGES`/`LANG`; its table's "Pirate" row has an
  unparseable tag, so a C/POSIX/`C.UTF-8` locale (what the agent's shell
  runs with) matches it. Reproduced on m6-fedora: `LANG=C.UTF-8 ./hello`
  prints `Ahoy, world!`, `LANG=en_US.UTF-8` prints `Hello, world.`
  Fix: `tests/acceptance.sh` runs the binary with `LC_ALL=en_US.UTF-8`.
  Every earlier pass (both machines) ran from an `en_US.UTF-8` shell.
- macOS build warned `unused_mut` in `bwrap_command` (the only mutation
  is inside the Linux `cfg` block). Silenced with `#[allow(unused_mut)]`;
  no behavior change.
- Sections 10f (ruby) and 10g (elixir) passed before the run was stopped;
  10h (dotnet) onward and the warm-project resync are still owed. Two
  harmless diagnostics recorded for the ledger: `xcrun` cannot write its
  cache under the agent's sandboxed `TMPDIR` (Rust builds still succeed),
  and Mix cannot subscribe to its TCP event bus inside Seatbelt (`:eperm`,
  expected — network is denied).

### 2026-09-05 (Mac verification, round 2) — Go passes; dotnet exposes a latent macOS bug

Same agent, commit eb44849. Section 10e passed with the locale pinned;
10f and 10g passed; 10h (dotnet) failed inside blanket's Seatbelt sandbox:
`mkdtemp("/tmp/.coreclr.Ypqb8g") == nullptr; errno == EPERM` while
CoreCLR created the `NuGet-Migrations` named mutex. The script exited
before its summary line (30 checks had passed).

- **Latent macOS bug, older than the port, exposed by macOS's `/private/
  tmp` purge.** The Seatbelt profile allows writes under `/private/tmp/
  .dotnet` and the scratch dir only. When `/private/tmp/.dotnet/shm` is
  missing, CoreCLR creates it via `mkdtemp("/tmp/.coreclr.XXXXXX")` +
  `rename`, and the mkdtemp in `/tmp` itself is denied. Every earlier Mac
  pass ran while `shm` still existed from some previous dotnet run; macOS
  removes unaccessed `/private/tmp` entries after three days and on
  reboot, so the pass depended on machine history. Stage 4 had found the
  same code path failing on Linux (EXDEV across bind mounts) and fixed it
  by pre-creating `shm`, but deliberately left macOS alone to keep the
  darwin path untouched. `ensure_dotnet_tmp` now pre-creates `shm` (0700,
  owned by the invoking uid) on both platforms; the Seatbelt profile is
  unchanged. Unit test renamed accordingly; LIMITATIONS and ARCHITECTURE
  updated.
- Warm-project resync still not done: the agent found no project on the
  Mac with a pre-existing `.blanket/closures/` directory. Next round
  syncs one of the repo's own fixtures twice instead (cold, then warm)
  and reports what the second sync re-does.

### 2026-09-05 (Mac verification, round 3) — macOS closed

Same agent, commit dbf7ac4. `cargo build` with no warnings; `bash
tests/acceptance.sh` **passed=35 failed=0** end to end, including 10h
(dotnet) with the pre-created `shm`, 11 (polyglot) and 12 (sbom).
Cold-then-warm syncs of `proj-a`, `go-hello` and `proj-npm` in one fresh
store: cold 1.5 s / 8.0 s / 3.1 s, warm 0.01 s / 0.00 s / 0.01 s, each
warm run printing only the `synced:` line with the same object path as
its cold run (no fetch, plan, lock, compile or build). Environment
commands worked in all three (the Go binary printed `Ahoy, world!` when
run from the agent's C-locale shell, as expected; the acceptance check's
pinned locale printed `Hello, world.`). Recurring harmless diagnostics:
`xcrun` cache writes denied under Seatbelt, Mix's TCP event bus `:eperm`,
NuGet's "issue verifying workloads" notice. macOS verification of the
port is complete; the only Mac-dependent item left is the optional
stage-6 live shared-store check. README and NEXT updated.

---

## Surface inventory (what is actually macOS-specific)

Everything below hardcodes `aarch64-apple-darwin` or a Darwin-only
mechanism. Line numbers as of commit 4fa8d48.

| # | File | What | Linux equivalent |
|---|---|---|---|
| 1 | `src/python.rs:22,27` | CPython 3.12.14 / 3.13.15 pins (python-build-standalone 20260825, `aarch64-apple-darwin-install_only`) | Same release, `x86_64-unknown-linux-gnu-install_only` |
| 2 | `src/python.rs:43` | uv 0.12.7 pin | `uv-x86_64-unknown-linux-gnu.tar.gz` |
| 3 | `src/npm.rs:116` | Node 24.20.0 `darwin-arm64` | `linux-x64`; sha from `SHASUMS256.txt` |
| 4 | `src/npm.rs:327` | lockfile `os`/`cpu` check against `darwin`/`arm64` | `linux`/`x64` |
| 5 | `src/pypi.rs:209-300` | wheel selector: bands for `macosx_*_arm64`, `universal2`, `any` | bands for `manylinux_*_x86_64` (glibc-versioned), `linux_x86_64`, `any`; no universal2 analogue |
| 6 | `src/cargo.rs:14-38` | rustc/rust-std/cargo 1.96.1 `aarch64-apple-darwin` tarballs; `PLATFORM` also gates `rust-toolchain` targets | `x86_64-unknown-linux-gnu` tarballs from static.rust-lang.org (`.sha256` sidecars) |
| 7 | `src/golang.rs:23-26` | Go 1.27.0 `darwin-arm64` | `linux-amd64`; sha from go.dev/dl JSON |
| 8 | `src/ruby.rs:28` | Homebrew portable-ruby 3.4.6 `arm64_big_sur` bottle | portable-ruby publishes `x86_64_linux` bottles (Homebrew-on-Linux uses them) — verify relocation on glibc |
| 9 | `src/elixir.rs:28` | OTP 29.0.5 from erlef/otp_builds (macOS-only project) | **Source decision needed**: hex.pm "bob" builds (`builds.hex.pm/builds/otp/ubuntu-*`), or build OTP once and pin our own artifact. Elixir zip, hex, rebar3 are BEAM bytecode and stay as-is |
| 10 | `src/dotnet.rs:29` | .NET SDK 9.0.317 `osx-arm64` | `linux-x64` tarball from the same releases.json channel |
| 11 | `src/build.rs:104` and every `("platform", "aarch64-apple-darwin")` identity input (python, uv, node, cargo, go, ruby, elixir, dotnet) | platform string baked into store object identity | derive from one `Platform::host()`; **this is what keeps Mac and Linux objects from colliding in a shared store** |
| 12 | `src/sandbox.rs` (whole file) | Seatbelt profile + `/usr/bin/sandbox-exec` | bubblewrap (`bwrap`) with user+net+pid namespaces; see stage 3 |
| 13 | `src/project.rs:88` | `clone_tree`: `cp -c` (APFS clonefile) with plain-copy fallback | `cp --reflink=auto` (XFS/btrfs reflink; silently plain-copies elsewhere) |
| 14 | `src/*.rs` (13 sites) | `/usr/bin/tar`, `/usr/bin/unzip`, `/usr/bin/id`, `/bin/cp`, `/bin/sh` | All exist on Fedora at the same paths. Leave; note bsdtar vs GNU tar flag differences (`--strip-components` is fine on both) |
| 15 | `src/pypi.rs:367`, `src/npm.rs:334` and similar | error strings that say "macOS arm64" / "darwin/arm64" | print the host triple |
| 16 | `src/store.rs:31,92`, `src/fetch.rs:245` | comments about `/private/tmp` and microsecond clocks | behavior is already correct on Linux; comments only |
| 17 | `tests/acceptance.sh`, `tests/hitrate.py`, `tests/*_e2e.rs` | assume the Mac binary and Mac pins | run on both; stage 5 |

Not on the list because it is already fine: `wheel.rs` uses `cfg(unix)`;
store atomicity (rename, read-only chmod) is POSIX; `ureq` is pure Rust
TLS; the forest projection is symlinks.

---

## Design decisions (made once, applied everywhere)

1. **One `Platform` type, one `host()` call.** A new `src/platform.rs`
   with an enum of supported targets and `Platform::host()` built from
   `std::env::consts::{OS, ARCH}`. Every pin table becomes a function of
   `Platform`. Every `"platform"` identity input reads
   `Platform::host().triple()`. Unsupported hosts fail at startup with
   the triple in the message, not deep inside a tailor.
2. **Pins are per-platform rows in the same table, not a second table.**
   Adding `aarch64-unknown-linux-gnu` later must be a row, not a port.
3. **Object identities already include platform, so a store shared
   between a Mac and a Linux box (NFS, synced dir) is safe by
   construction.** Stage 6 verifies that claim rather than assuming it.
4. **Hashes are fetched from the provider's published checksums at pin
   time, then pasted as constants** (same TOFU posture as today; see
   LIMITATIONS "TOFU pins everywhere"). Never compute a pin's sha256
   from a download we made ourselves without cross-checking the
   provider's published value.
5. **The Linux sandbox is the same `BuildSpec` contract.** Tailors do not
   learn about bwrap. `sandbox.rs` grows a backend switch; the deny-by-
   default semantics (no network, declared reads, declared writes,
   scrubbed env, `SOURCE_DATE_EPOCH`) are identical.
6. **No silent degradation.** Until the Linux sandbox lands, any path that
   would call the sandbox on Linux fails with a loud "sandbox unavailable
   on this platform (LINUX_PORT.md stage 3)" error. It does not run the
   build unsandboxed.
7. **Host C toolchain stays an unpinned build input on Linux too** (gcc
   from `/usr`), mirroring the Xcode item in LIMITATIONS. Pinning it is a
   separate roadmap item, not part of this port.

---

## Parallel streams (after stage 1 and the sandbox land)

One git worktree per stream under `~/repos/blanket-wt/<stream>`, one
implementer agent each, one reviewer pass each, merged into `linux-port` in
the order below. Each stream owns its listed files and its own e2e test;
touching any other file is a review blocker. The supervisor owns shared
core (`platform.rs`, `store.rs`, `fetch.rs`, `project.rs`), docs, and the
acceptance/hit-rate harnesses.

| Stream | Owns | Needs | Merge gate (fresh store) |
|---|---|---|---|
| B: sandbox (stage 3) | `sandbox.rs`, `tests/sandbox_deny.rs` | stage 1 | `sandbox_deny` passes on Linux incl. read/write/network denials and an overlapping read-only-parent / writable-child mount |
| P: Python (stage 2) | `python.rs`, `pypi.rs`, `build.rs`, `main.rs` planner-key lines | B | `linux_python` round-trip: 3.12 manylinux wheel selection, a compiled-extension import (markupsafe), uv 0.12.7; the sdist build is the `sdist_build` gate (docopt) and 3.13 is covered by the pin/identity unit tests plus a manual realization |
| N: npm (stage 2 + lifecycle) | `npm.rs`, `tests/npm_scripts.rs` | P, B | new `linux_npm` round-trip: optional-platform package selection (`@esbuild/linux-x64` chosen, darwin skipped), a source-built addon |
| Rust (stage 4) | `cargo.rs`, `tests/cargo_e2e.rs` | B | `cargo_sync_build_and_run_again_offline` |
| .NET (stage 4) | `dotnet.rs`, `tests/dotnet_e2e.rs` | B | `dotnet_sync_sandboxed_build_and_run` |
| Go (stage 4) | `golang.rs`, `tests/go_e2e.rs` | B | `go_sync_build_and_rebuild_offline` |
| Ruby (stage 4) | `ruby.rs`, `tests/ruby_e2e.rs` | B | `ruby_sync_native_ext_and_run` (nokogiri) |
| BEAM (stage 4) | `elixir.rs`, `tests/elixir_e2e.rs` | B | `elixir_sync_sandboxed_build_and_run` |

Merge order: B → P → N → Rust → .NET → Go → Ruby → BEAM. Rust/.NET/Go/
Ruby/BEAM can run concurrently with P and N since they share no files.
One owner for `npm.rs`: stage 2 npm pins and stage 3 lifecycle-script
sandboxing are the same stream, or they will conflict.

## Stage 0 — baseline and branch

Goal: a branch, this document, and a recorded Linux failure mode to
measure everything else against.

- [x] Branch `linux-port` from `main` (4fa8d48).
- [x] This document committed.
- [x] Linux build + offline unit tests pass unchanged (see changelog).
- [x] Smoke failure recorded (`cannot execute binary file`, Node pin).

**Landed:** 2026-09-05, this commit.

---

## Stage 1 — platform abstraction (no behavior change on macOS)

Goal: remove every hardcoded `aarch64-apple-darwin` string and route it
through one type. macOS object ids must not change (the triple string is
identical), so existing Mac stores stay valid.

Files: new `src/platform.rs`; edits in `python.rs`, `npm.rs`, `cargo.rs`,
`golang.rs`, `ruby.rs`, `elixir.rs`, `dotnet.rs`, `build.rs`,
`project.rs`, `lib.rs`.

- [x] `Platform` enum: `Aarch64AppleDarwin`, `X86_64UnknownLinuxGnu`.
      `host() -> io::Result<Platform>` (error names the unsupported
      triple). `triple()`, `node_slug()` (`darwin-arm64` / `linux-x64`),
      `go_slug()`, `dotnet_rid()`, `npm_os()`, `npm_cpu()`.
- [x] Every pin struct gains a `platform: Platform` field; lookups filter
      by `Platform::host()`. Linux rows may be absent in this stage; a
      missing row fails loud ("no <toolchain> pinned for <triple>").
- [x] Every `("platform", "aarch64-apple-darwin")` identity input reads
      the host triple.
- [x] `cargo.rs` `PLATFORM` const (also used to validate
      `rust-toolchain` targets and the `lib/rustlib/<triple>` check)
      becomes host-derived.
- [x] `project::clone_tree`: on Linux use `cp -a --reflink=auto`; keep
      `cp -c` on macOS; same plain-copy fallback.
- [x] `sandbox.rs`: on non-macOS, `run_in` returns the loud stage-3 error
      (decision 6).
- [x] Error strings: "macOS arm64" / "darwin/arm64" → host triple.
- [x] Unit test: `Platform::host()` on this box is
      `X86_64UnknownLinuxGnu`; triple round-trips.
- [x] macOS regression: on the Mac, `cargo test` passes and a previously
      synced project resyncs as a cache hit (object ids unchanged).

Exit: `cargo test` green on both machines. `blanket sync` on Linux now
fails with "no nodejs pinned for x86_64-unknown-linux-gnu" instead of
downloading the wrong binary.

**Landed:** 2026-09-05, commits 872b807 (implementation) and 7464ca5
(follow-ups). 82 offline tests pass on Linux (65 before). Reviewer's
final verdict MERGE: nine macOS toolchain object ids, the sdist-build and
ruby-gems identities recomputed from `main` and byte-identical; Seatbelt
path unchanged; on Linux all seven ecosystems fail `Unsupported` with a
stage reference before the store is opened or anything is downloaded
(verified with `BLANKET_STORE=/dev/null`). macOS regression run on real
hardware still owed (next time the Mac pulls this branch: `cargo test`
and a resync of an existing project must be a cache hit).

---

## Stage 2 — Node and Python on Linux (the two measured ecosystems)

Goal: `blanket sync` and `blanket run` work on Linux for the ecosystems
that have a hit-rate number, without native builds (those need stage 3).

Files: `npm.rs`, `python.rs`, `pypi.rs`, `tests/fixtures`.

- [x] Node 24.20.0 `linux-x64` pin; sha256 from
      `https://nodejs.org/dist/v24.20.0/SHASUMS256.txt`:
      `855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec`
      (fetched 2026-09-05; darwin line in the same file matched the
      existing pin `40e5607e…`).
- [x] CPython `x86_64-unknown-linux-gnu-install_only` pins from
      python-build-standalone release 20260825. That release publishes no
      `.sha256` sidecars; the GitHub release-asset `digest` field is the
      source (darwin digests matched existing pins `62eef3fc…`/`d681f7ce…`):
      - 3.12.14: `cbdd2f0cf02f941bc5c81e546f377275e322733abffe805ac29d2b7e8a58f7e3`
      - 3.13.15: `8a70011ae25276a9925f89304cdc086466cd269ee6cfe68a9506694ca5ff4f9c`
- [x] uv 0.12.7 `x86_64-unknown-linux-gnu` pin:
      `788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21`
      (`.sha256` sidecar and GitHub asset digest agree; darwin sidecar
      matched existing pin `127ebdda…`). Tarball root is
      `uv-x86_64-unknown-linux-gnu/`; the existing `--strip-components 1`
      handles it.
- [x] `npm.rs` lockfile platform check uses `npm_os()`/`npm_cpu()`.
      Optional deps for other platforms (e.g. `@esbuild/darwin-arm64`)
      must be skipped, and `@esbuild/linux-x64` must be selected. Add a
      fixture lockfile that carries both.
- [x] `pypi.rs::score` gets a platform parameter (and, on Linux, the host
      glibc version injected, so tests can vary it). Algorithm (reviewer-
      specified, 2026-09-05): expand compressed tag sets (`py3.cp312`,
      `manylinux_2_17_x86_64.manylinux2014_x86_64`) and pick the best
      compatible tuple. Parse anchored `manylinux_(\d+)_(\d+)_x86_64` and
      compare `(major, minor) <= host glibc`; map legacy aliases
      `manylinux1`→2.5, `manylinux2010`→2.12, `manylinux2014`→2.17.
      Reject `musllinux_*` and every foreign arch. Rank lexicographically
      `(family, abi, Reverse(abi3_floor), Reverse(glibc_floor), filename)`
      with families manylinux → `linux_x86_64` → `any` → sdist and abi
      exact → abi3 → none (the last tiebreak makes selection
      deterministic). Host glibc: call `gnu_get_libc_version()` through a
      tiny `extern "C"` declaration gated to Linux (no `libc` crate), read
      once into a `OnceLock`; if unavailable, fall back to
      `/usr/bin/getconf GNU_LIBC_VERSION`; failure is an error, never a
      guess. m6-fedora is glibc 2.43, so nearly every manylinux wheel on
      PyPI qualifies, but the comparison must exist for older hosts.
- [x] Three latent bugs in the current `score()` to fix while touching it,
      because on Linux they would silently pick wrong wheels: (1) ~line
      267 the pure-wheel check accepts `py2`/`py27`/`py4` via `n <= ours`;
      (2) ~line 248 a `cp312-abi3` wheel is promoted to "exact" instead
      of abi3; (3) ~line 235 the platform match is macOS-only regardless
      of host. Include the host glibc version and a selector schema
      string in the python planner cache key (`main.rs` ~264).
- [x] Unit tests for the Linux selector mirroring the existing macOS
      cases (exact > abi3 > pure; cross-platform wheel rejected; glibc
      too-new wheel rejected).
- [x] `tests/acceptance.sh` sections 1–4 (proj-a/proj-b: markupsafe +
      six; conflicting versions coexist; identical lock is a cache hit;
      offline reprojection) pass on Linux. markupsafe ships manylinux
      wheels, so this exercises native-wheel selection without a build.
- [x] npm smoke: the stage-0 one-dependency project syncs; `blanket run`
      of a package.json script works; a vite fixture builds (no native
      addons).
- [x] Python sdist path: confirm it fails with the stage-3 error, not a
      crash.

Exit: pure/prebuilt projects sync on Linux. Record the object id of the
Linux CPython object and confirm it differs from the Mac's (platform is
in identity).

**Landed:** 2026-09-05, commits 5636721 (python) and 061a635 (npm), merged
1be23c9 / 97cfd34. Reviewed (MERGE-WITH-FIXES, all applied). Verified on
m6-fedora: acceptance.sh sections 1–8, 10, 10b pass; offline
reprojection/reconstruction under `unshare -rn`; `tests/linux_python.rs`;
all four `npm_scripts` gates incl. the Linux round-trip (esbuild 0.25.9
selects only `@esbuild/linux-x64`; an N-API addon builds from source);
better-sqlite3 11.10.0 compiles under the sandbox and runs. One
deliberate macOS change: abi3 wheels now rank above `py3-none-<plat>`
wheels, as pip does (pinned by a darwin test).

---

## Stage 3 — Linux build sandbox (bubblewrap)

Goal: the same deny-by-default hermeticity on Linux that Seatbelt gives on
macOS, behind the unchanged `BuildSpec`/`Sandbox` API. This unblocks sdist
builds, npm lifecycle scripts, and `blanket build` for cargo/go/elixir/
dotnet.

Why bubblewrap: present on Fedora by default (Flatpak depends on it),
setuid-free with unprivileged user namespaces (enabled on m6-fedora:
`/proc/sys/user/max_user_namespaces` = 102975), and its CLI maps 1:1 onto
the existing profile. `unshare(1)` alone cannot express per-path
read/write policy. nsjail/firejail are not installed and are heavier.

Files: `sandbox.rs` (backend enum: `Seatbelt`, `Bwrap`), `tests/sandbox_deny.rs`.

Profile mapping (Seatbelt → bwrap):

| Seatbelt | bwrap |
|---|---|
| `(deny default)` + explicit allows | no root bind; only what is listed below is visible |
| `(deny network*)` | `--unshare-net` |
| process basics | `--unshare-user --unshare-pid --proc /proc --die-with-parent --new-session` |
| `/usr /bin /sbin /opt /dev /private/etc` read-only | `--ro-bind /usr /usr`, symlinks `/bin /lib /lib64 /sbin` → `usr/...` (Fedora merged-usr), `--ro-bind` each of `/etc/ld.so.cache`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`, `/etc/alternatives`, `/etc/localtime`, `/etc/passwd`, then `--dev /dev`, `--proc /proc`, `--tmpfs /tmp` |
| Xcode / CLT read-only | nothing extra: gcc/binutils live in `/usr` (decision 7) |
| `(allow file-read* (subpath R))` | `--ro-bind R R` |
| `(allow file-read* file-write* (subpath W))` | `--bind W W` |
| scratch = HOME/TMPDIR | `--bind scratch scratch --setenv HOME --setenv TMPDIR` |
| `env_clear()` | `--clearenv` then `--setenv` for each. **bwrap's `--chdir` injects `PWD`**; to keep the env byte-clean either `--unsetenv PWD` (bwrap ≥ 0.12 honours it after chdir) or exec through `/usr/bin/env -u PWD --` |
| stdin null | unchanged (`Stdio::null()`) |

- [x] **Prototype (2026-09-05):** a standalone `sandbox.sh` implementing
      the table above passed 10/10 checks on m6-fedora, reproduced by the
      supervisor; zero AVC denials in the audit log. The exact working
      argv is in the changelog notes and the prototype directory; the
      Rust implementation should reproduce it flag for flag.
- [x] `Sandbox::run_in` dispatches on the `Platform` it is given; bwrap
      argv built from the same `read`/`write` lists. Keep the profile
      string builder for Seatbelt untouched.
- [x] Preflight: `bwrap --version` and a trivial `--unshare-user true`
      run at first use; failure message names the fix (`dnf install
      bubblewrap`, or the userns sysctl). Cache the result per process.
- [x] SELinux: verified 2026-09-05 in enforcing mode, non-root, binds
      under `/home` and `/tmp`: no AVC denials. Nothing special needed.
- [x] Store paths under `/home` must be bind-mounted, not the whole of
      `/home`. Confirm that a build cannot read `$HOME/.ssh` (add this
      to `sandbox_deny`).
- [x] `tests/sandbox_deny.rs` (`evil-0.1.tar.gz` reaching the network)
      passes on Linux with the same assertion.
- [x] Python sdist → wheel build works: pick a setuptools sdist with a C
      extension (e.g. `markupsafe` sdist forced, or the existing
      `tests/sdist_build.rs` fixture) and confirm the built wheel object
      is created and imports.
- [x] npm native addon: `better-sqlite3` from source under the sandbox
      (README lists it as proven on macOS). node-gyp needs the store
      CPython (already passed as a read root), `make`, `gcc`, `g++` from
      `/usr`. Known so far: stock Fedora 44 Server lacked `gcc-c++`
      (installed 2026-09-05 with `glibc-devel pkgconf-pkg-config
      binutils`). Reviewer's expected baseline for native builds:
      `gcc gcc-c++ make binutils glibc-devel pkgconf-pkg-config`; note
      python-build-standalone's CPython was built with clang and its
      sysconfig defaults `CC=clang`, so the sandbox env must set
      `CC=gcc CXX=g++` (or clang must be installed). Record the final
      list in README as the Linux equivalent of Xcode CLT.
- [x] `blanket build` for cargo (blanket building itself, as on macOS)
      works offline in the sandbox.
- [x] Unsandboxed-run guard in `main.rs` (`blanket run cargo build`
      refusal) behaves identically.

Exit: all `#[ignore]` e2e tests that exist for python and npm pass on
Linux (`cargo test --test sandbox_deny --test sdist_build
--test npm_scripts --test run_scripts -- --ignored`).

**Landed:** 2026-09-05, commit on `lp/sandbox` merged as 531c00a.
Reviewer round 1: REWORK (fd inheritance, IPC namespace, host Unix
sockets, cwd/mount order, vacuous tests, preflight); all nine closed.
21 Linux sandbox unit tests + `bwrap_contract` pass with
`BLANKET_SANDBOX_TESTS=required` on Fedora 44, SELinux enforcing,
non-root. Seatbelt path byte-identical (profile golden). Accepted gap
for LIMITATIONS.md: a Unix socket inside an immutable read root is not
scanned (write roots, cwd, scratch are). Build stderr is relayed live.

---

## Stage 4 — remaining toolchain pins

Goal: cargo, go, ruby, elixir, dotnet tailors realize on Linux. Each is
mostly a table row plus one verification run of its existing e2e test.
Order by certainty.

- [x] **Rust 1.96.1** `x86_64-unknown-linux-gnu` (static.rust-lang.org
      `.sha256` sidecars, 2026-09-05): rustc `3545a0efad2355ecb0a3b9ac02efee96e27f1f9d24b7ce2fc3f279b2efb0d923`,
      rust-std `1bf4fde5048cca33e6ea00c7471281ed96d792f6923141e3db45072743a1afae`,
      cargo `ecc53a3c49fab5ab8c9301b3bbc8fb1dff9be6c65287add3f57a0fe8fddfea9e`.
      `tests/cargo_e2e.rs` passes.
- [x] **.NET SDK 9.0.317** `linux-x64` from the same
      `builds.dotnet.microsoft.com` path; sha512 from releases.json:
      `145bf69dcb88c4b905feb531cfdd7894a75fc875d2a030e958a13d1fb1131521c8cebd8a8a6e0fbd1a433ebae9cde86356b6adad07b1ad81efb92b36ff8a3333`.
      `tests/dotnet_e2e.rs` passes. Note `/tmp/.dotnet` mutex dir is a
      sandbox write allowance on Linux too (bind it, tmpfs is fine).
- [x] **Go 1.27.0** `linux-amd64` from go.dev; sha256 from
      `https://go.dev/dl/?mode=json`:
      `675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685`. `tests/go_e2e.rs` passes. cgo uses
      host gcc (decision 7).
- [x] **Ruby 3.4.6** portable-ruby `x86_64_linux` bottle from
      Homebrew/homebrew-portable-ruby releases (GitHub asset digest
      `40932a3950ccc8bf9d13d98e692e5518427cc66b4f9520956cec349629d25259`).
      Portable Ruby is built to
      relocate, but validate 3.4.6 specifically: inspect the ELF
      interpreter and RPATH, `rbconfig` and pkg-config prefixes, then
      after commit `require 'openssl'`, `require 'zlib'`, and compile and
      load nokogiri. `tests/ruby_e2e.rs` currently covers rake/racc only;
      extend it. nokogiri needs `zlib-devel xz patch` for its vendored
      build, or `libxml2-devel libxslt-devel` for system-library mode;
      record whichever is chosen as a host prerequisite.
- [x] **Erlang/OTP 29.0.5** — bob builds FAILED the gate on Fedora (see
      changelog: SM4 symbol missing from Fedora's OpenSSL). Decision:
      our own source build, published under the project's GitHub org with
      a provenance manifest. Source `otp_src_29.0.5.tar.gz` sha256
      `86f6f40d4638852b0383235b02a70d8450184e441e83a06a108bf8e5bf1b2e04`
      (GitHub release digest). Built inside the bwrap sandbox, network
      denied, `SOURCE_DATE_EPOCH=315532800`, with
      `--with-ssl=/usr --with-ssl-lib-subdir=lib64 --enable-dynamic-ssl-lib
      --with-ssl-rpath=no --with-termcap --without-wx --without-javac
      --without-odbc --disable-saved-compile-time`; packaged as a
      `make release` tree (relocate with `Install -minimal <prefix>`, one
      path level to strip). The provenance file records source hash,
      flags, gcc/binutils/glibc/openssl/ncurses versions, ELF NEEDED and
      GLIBC symbol-version floor, and the crypto/ssl probe result. The
      artifact is honest about its floor (glibc 2.43, `libcrypto.so.3`
      with Fedora's symbol subset). Identity keeps platform + all four
      artifact digests + a relocation-schema revision. Long-term (own
      roadmap item): static OpenSSL on an older-glibc baseline. Elixir
      zip / hex / rebar3 stay as-is. `tests/elixir_e2e.rs` passes.
- [x] Every new pin's platform row added alongside the macOS row, never
      replacing it.

Exit: `bash tests/acceptance.sh` passes on Linux end to end.

**Landed:** 2026-09-05. Commits: cargo 3ee2e8c, dotnet ff4c033 (+ shm
pre-create fix), go b56c8d9, ruby ef056b3, elixir on `lp/beam`; merged
d5d9f72, 26b8c5d, 8e15efe, 2682894, f35cba2. Every stage 4 gate passes on
m6-fedora with the Linux sandbox: `cargo_e2e` (sandboxed build + offline
rebuild), `go_e2e` (incl. cgo), `dotnet_e2e` (locked restore + sandboxed
build + run), `ruby_e2e` (nokogiri 1.18.10 compiled from source under
the sandbox), `elixir_e2e` (mix compile sandboxed on our own OTP build).
Three gate-test bugs and one real Linux bug were found on the merged
tree: CoreCLR creates `/tmp/.dotnet/shm` via mkdtemp+rename, which fails
with EXDEV across bwrap bind mounts; blanket now pre-creates it on Linux.
Ruby open question 3 answered: portable-ruby relocates with no repair
(static openssl/zlib; RbConfig and pkg-config follow the object path).
`bash tests/acceptance.sh` passes through 10f on Linux.

---

## Stage 5 — hit rate on Linux

Goal: the product-truth number for Linux, measured the same way as
HITRATE.md (2026-09-02: python 18/30, npm 21/30 after NEXT.md item 3).

- [ ] `tests/hitrate.py` runs unmodified on Linux (it shells out to git
      and the binary; check `timeout` handling and `/tmp` usage on
      tmpfs — 12 GB tmpfs may be tight for 30 shallow clones + stores;
      point `--work` at `/home` if needed).
- [ ] Same repo list as the 2026-09-02 run (`tests/fixtures/
      hitrate-2026-09-02.csv`) so the numbers are comparable.
- [ ] Results in `HITRATE.md` as a new dated section with a per-repo
      table and a **macOS vs Linux** column. Every Linux-only miss gets a
      failure class; every Linux-only hit gets an explanation (expected:
      more manylinux wheels than macOS arm64 wheels for scientific
      packages, so Python may score higher here).
- [ ] The 12-core box makes this run faster than the Mac; record wall
      time so future re-measures are planned on Linux.
- [ ] Harness caveats (reviewer, 2026-09-05): `hitrate.py` follows each
      repo's HEAD, so pin the commit list from the 2026-09-02 CSV for a
      like-for-like comparison; it counts a sync as "ok" even when it
      carried permissive install-script exceptions, so report exceptions
      per repo separately; its failure classifier has darwin-only
      patterns and needs Linux equivalents.

Exit: two numbers in HITRATE.md, one per platform, from the same list.

**Landed:** 2026-09-05, commits 2b795cc (measurement) and 53e384d (fix +
re-measure). Same 60 repos, pinned to their 2026-09-02 commits via
`tests/fixtures/hitrate-repos.lock`. **python: Linux 16/30 vs macOS
18/30. npm: Linux 21/30 vs macOS 21/30** (was 14/30 before 53e384d: all
seven Linux-only npm misses were GNU tar refusing 0666 directories in
registry tarballs; `--delay-directory-restore`, Linux only). Per-repo
table with errors and exception counts in HITRATE.md; raw CSVs in
`tests/fixtures/hitrate-linux-2026-09-05*.csv`. Follow-ups (the
remaining Linux-only misses): wheel `.data/headers` scheme (greenlet
3.5.5; also misses on macOS), and CPython 3.10/3.11 pins (miss on both,
classed `platform_unsupported` here). Harness caveats from the reviewer
were all applied (pinned commits, exceptions counted separately, Linux
failure classes).

---

## Stage 6 — one project, two machines

Goal: verify decision 3 (platform in identity) and document the
cross-machine workflow, since this is exactly how the author uses
blanket: Mac by day, Linux server overnight.

- [ ] Sync the same project (blanket itself, or CX-Games) on both
      machines against separate stores. Confirm `.blanket/closure.json`
      records the platform and that the projections are independent.
- [ ] Shared store test: point both machines' `BLANKET_STORE` at one
      directory (rsync a Mac store onto the Linux box). Confirm the
      Linux sync adds objects and never reuses a Mac toolchain or env
      object (ids differ), and that artifact-cache entries (`cache/
      sha256/`) ARE shared, since a wheel or tarball is platform-tagged
      by name, not by content.
- [ ] `git pull` on one machine after a sync on the other: `.venv`,
      `node_modules`, `.blanket/` are gitignored; confirm nothing
      platform-specific is committed.
- [ ] README section: "Working across machines."
- [ ] Known gaps to check (reviewer, 2026-09-05): python/npm env ids
      include the store root path, so hold the root constant when
      comparing platforms; concurrent cross-host downloads into one store
      can collide on the `pid-seq-digest` temp name in `fetch.rs`, and
      rsync bypasses the publication lock, so test a quiescent snapshot
      separately from live sharing; `.blanket/closures/*.json` has no
      envelope-level platform field yet (add one).

Exit: written proof that a mixed-platform store is safe, or a bug fixed.

**Landed (partially):** 2026-09-05, commit 496c612. Done on m6-fedora:
`.blanket/closures/<eco>.json` now carries an envelope-level `platform`
field (the projecting host triple); README gained "Working across
machines"; identity separation is proven by the unit goldens (nine
darwin object ids byte-identical to `main`, every Linux toolchain/env id
differs because `Platform` is an identity input); `.venv`,
`node_modules`, `.blanket/` were confirmed gitignored. **Still owed, and
only possible with the Mac:** the live shared-store check (rsync a Mac
store here, sync, confirm objects are added and never reused, and that
`cache/sha256/` entries are shared). Do it after the branch is merged
and before relying on one store from two hosts.

---

## Stage 7 — docs and ledger

- [ ] LIMITATIONS.md: remove "macOS arm64 only"; add Linux items: host
      gcc/glibc unpinned (mirrors Xcode item); `aarch64-linux` and musl
      not pinned; bubblewrap is cooperative hermeticity, same class as
      Seatbelt; reflink copies fall back to full copies on ext4.
- [ ] ARCHITECTURE.md: sandbox section describes both backends; forest
      and clone projection wording ("APFS clonefile") generalized to
      "copy-on-write clone (APFS clonefile / XFS+btrfs reflink)".
- [ ] README status line: "macOS arm64 and Linux x86_64."
- [ ] CLAUDE.md: note the Linux host, bwrap prerequisite, and that
      `cargo test -- --ignored` on Linux needs bubblewrap.
- [ ] ROADMAP.md: tick "Linux support"; add follow-ups discovered here.
- [ ] NEXT.md: fold Linux-derived work into the ordering (most likely:
      pinned Linux C toolchain, aarch64-linux row).

**Landed:** 2026-09-05, commit 83c67f3 (LIMITATIONS ledger for two
platforms, README status + Linux prerequisites, ARCHITECTURE platforms /
sandbox / clone wording, ROADMAP tick, NEXT.md status, CLAUDE.md Linux
notes). One ledger note still to add when the BEAM Install step is next
touched: OTP's `Install -cross -minimal` relocation runs as a direct
child, not through the sandbox (it only rewrites paths under the store
object, but it is the one non-sandboxed step).

---

## Out of scope for this port

- Intel macOS (`x86_64-apple-darwin`). A row per pin table once someone
  needs it.
- `aarch64-unknown-linux-gnu` (Graviton, Raspberry Pi, Apple Silicon
  VMs). Same: rows, not code. Worth doing right after stage 4.
- musl / Alpine. The pinned toolchains are glibc builds; a musl row needs
  different upstream artifacts and a `musllinux` wheel band.
- Windows. Not a Unix; the store model needs symlink privileges and a
  different sandbox. Not planned.
- Pinning the C toolchain (gcc, binutils, glibc headers) as a store
  object. This is the real "Linux as reference hermetic platform" item
  from ROADMAP and deserves its own plan after the port works.

## Open questions (answer in the changelog when known)

1. ~~Does bubblewrap run cleanly under Fedora's enforcing SELinux for a
   non-root user with binds under `/home`?~~ **Yes** (2026-09-05): 10/10
   prototype checks, zero AVC denials.
2. ~~Which OTP source for Linux: hex.pm bob builds or our own build?~~
   **Our own build** (2026-09-05): bob's Ubuntu build cannot load crypto
   on Fedora (SM4 symbol); details in the changelog and Stage 4.
3. ~~Does Homebrew portable-ruby `x86_64_linux` relocate correctly outside
   `/home/linuxbrew`?~~ **Yes** (2026-09-05): the ruby e2e gate realizes it
   under the store and builds nokogiri; pkg-config prefixes remain a
   non-contract on both platforms.
4. Is the host toolchain as found on m6-fedora (gcc 16.2, make 4.4, no `gcc-c++`, no `libxml2-devel`) enough
   for node-gyp and setuptools C extensions, or is a `dnf install`
   prerequisite required? **Partly answered** (2026-09-05): `gcc-c++`
   was missing and is required for C++ (node-gyp); installed with
   `glibc-devel pkgconf-pkg-config binutils`. **Answered** (2026-09-05, night):
   `CC=gcc CXX=g++ LDSHARED="gcc -shared"` must be forced for sdist builds
   (python-build-standalone's sysconfig defaults to clang; done in
   `build.rs`); nokogiri builds from its vendored sources and only needs
   host `libz.so.1` (allowlisted in the ruby gate); full prerequisite list
   is in README.

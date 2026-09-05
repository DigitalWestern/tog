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

- [ ] `Platform` enum: `Aarch64AppleDarwin`, `X86_64UnknownLinuxGnu`.
      `host() -> io::Result<Platform>` (error names the unsupported
      triple). `triple()`, `node_slug()` (`darwin-arm64` / `linux-x64`),
      `go_slug()`, `dotnet_rid()`, `npm_os()`, `npm_cpu()`.
- [ ] Every pin struct gains a `platform: Platform` field; lookups filter
      by `Platform::host()`. Linux rows may be absent in this stage; a
      missing row fails loud ("no <toolchain> pinned for <triple>").
- [ ] Every `("platform", "aarch64-apple-darwin")` identity input reads
      the host triple.
- [ ] `cargo.rs` `PLATFORM` const (also used to validate
      `rust-toolchain` targets and the `lib/rustlib/<triple>` check)
      becomes host-derived.
- [ ] `project::clone_tree`: on Linux use `cp -a --reflink=auto`; keep
      `cp -c` on macOS; same plain-copy fallback.
- [ ] `sandbox.rs`: on non-macOS, `run_in` returns the loud stage-3 error
      (decision 6).
- [ ] Error strings: "macOS arm64" / "darwin/arm64" → host triple.
- [ ] Unit test: `Platform::host()` on this box is
      `X86_64UnknownLinuxGnu`; triple round-trips.
- [ ] macOS regression: on the Mac, `cargo test` passes and a previously
      synced project resyncs as a cache hit (object ids unchanged).

Exit: `cargo test` green on both machines. `blanket sync` on Linux now
fails with "no nodejs pinned for x86_64-unknown-linux-gnu" instead of
downloading the wrong binary.

**Landed:** _(date, commit, notes)_

---

## Stage 2 — Node and Python on Linux (the two measured ecosystems)

Goal: `blanket sync` and `blanket run` work on Linux for the ecosystems
that have a hit-rate number, without native builds (those need stage 3).

Files: `npm.rs`, `python.rs`, `pypi.rs`, `tests/fixtures`.

- [ ] Node 24.20.0 `linux-x64` pin; sha256 from
      `https://nodejs.org/dist/v24.20.0/SHASUMS256.txt`.
- [ ] CPython 3.12.14 and 3.13.15 `x86_64-unknown-linux-gnu-install_only`
      pins from python-build-standalone release 20260825; sha256 from the
      release's `.sha256` sidecars / `SHA256SUMS`.
- [ ] uv 0.12.7 `x86_64-unknown-linux-gnu` pin; sha256 from the release's
      `.sha256` sidecar. Tarball root is `uv-x86_64-unknown-linux-gnu/`;
      the existing `--strip-components 1` handles it.
- [ ] `npm.rs` lockfile platform check uses `npm_os()`/`npm_cpu()`.
      Optional deps for other platforms (e.g. `@esbuild/darwin-arm64`)
      must be skipped, and `@esbuild/linux-x64` must be selected. Add a
      fixture lockfile that carries both.
- [ ] `pypi.rs::score` gets a platform parameter. Linux bands:
      0 `manylinux*_x86_64` exact ABI (glibc tag ≤ host glibc),
      1 `manylinux*_x86_64` abi3, 2 `linux_x86_64` (PEP 600 says
      unportable; accept, rank below manylinux), 4 `any` pure, 6 sdist.
      Support both `manylinux_X_Y_x86_64` (PEP 600) and the legacy
      aliases `manylinux1` (2.5), `manylinux2010` (2.12), `manylinux2014`
      (2.17). Reject `musllinux`. Host glibc version read once from
      `gnu_get_libc_version`-equivalent (parse `ldd --version` or
      `confstr`); m6-fedora is glibc 2.43, so effectively every manylinux
      wheel on PyPI qualifies, but the comparison must exist.
- [ ] Unit tests for the Linux selector mirroring the existing macOS
      cases (exact > abi3 > pure; cross-platform wheel rejected; glibc
      too-new wheel rejected).
- [ ] `tests/acceptance.sh` sections 1–4 (proj-a/proj-b: markupsafe +
      six; conflicting versions coexist; identical lock is a cache hit;
      offline reprojection) pass on Linux. markupsafe ships manylinux
      wheels, so this exercises native-wheel selection without a build.
- [ ] npm smoke: the stage-0 one-dependency project syncs; `blanket run`
      of a package.json script works; a vite fixture builds (no native
      addons).
- [ ] Python sdist path: confirm it fails with the stage-3 error, not a
      crash.

Exit: pure/prebuilt projects sync on Linux. Record the object id of the
Linux CPython object and confirm it differs from the Mac's (platform is
in identity).

**Landed:** _(date, commit, notes)_

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
| process basics | `--unshare-pid --proc /proc --die-with-parent --new-session` |
| `/usr /bin /sbin /opt /dev /private/etc` read-only | `--ro-bind /usr /usr`, symlinks `/bin /lib /lib64 /sbin` → `/usr/...` (Fedora merged-usr), `--ro-bind /etc/ld.so.cache`, `/etc/ld.so.conf*`, `/etc/alternatives`, `/etc/localtime`, `/etc/passwd` (minimal), `--dev /dev`, `--tmpfs /tmp` |
| Xcode / CLT read-only | nothing extra: gcc/binutils live in `/usr` (decision 7) |
| `(allow file-read* (subpath R))` | `--ro-bind R R` |
| `(allow file-read* file-write* (subpath W))` | `--bind W W` |
| scratch = HOME/TMPDIR | `--bind scratch scratch --setenv HOME --setenv TMPDIR` |
| `env_clear()` | `--clearenv` then `--setenv` for each |
| stdin null | unchanged (`Stdio::null()`) |

- [ ] `Sandbox::run_in` dispatches on `Platform::host()`; bwrap argv
      built from the same `read`/`write` lists. Keep the profile string
      builder for Seatbelt untouched.
- [ ] Preflight: `bwrap --version` and a trivial `--unshare-user true`
      run at first use; failure message names the fix (`dnf install
      bubblewrap`, or the userns sysctl). Cache the result per process.
- [ ] SELinux: verify bwrap works in enforcing mode on this box (it
      should; Flatpak relies on it). If a denial appears, record the AVC
      in this file and the workaround, never `setenforce 0`.
- [ ] Store paths under `/home` must be bind-mounted, not the whole of
      `/home`. Confirm that a build cannot read `$HOME/.ssh` (add this
      to `sandbox_deny`).
- [ ] `tests/sandbox_deny.rs` (`evil-0.1.tar.gz` reaching the network)
      passes on Linux with the same assertion.
- [ ] Python sdist → wheel build works: pick a setuptools sdist with a C
      extension (e.g. `markupsafe` sdist forced, or the existing
      `tests/sdist_build.rs` fixture) and confirm the built wheel object
      is created and imports.
- [ ] npm native addon: `better-sqlite3` from source under the sandbox
      (README lists it as proven on macOS). node-gyp needs the store
      CPython (already passed as a read root), `make`, `gcc`, `g++` from
      `/usr`. Record whether Fedora's default toolchain is sufficient or
      whether `dnf install gcc-c++ make` was required (then note it in
      README as a host prerequisite, like Xcode CLT on macOS).
- [ ] `blanket build` for cargo (blanket building itself, as on macOS)
      works offline in the sandbox.
- [ ] Unsandboxed-run guard in `main.rs` (`blanket run cargo build`
      refusal) behaves identically.

Exit: all `#[ignore]` e2e tests that exist for python and npm pass on
Linux (`cargo test --test sandbox_deny --test sdist_build
--test npm_scripts --test run_scripts -- --ignored`).

**Landed:** _(date, commit, notes)_

---

## Stage 4 — remaining toolchain pins

Goal: cargo, go, ruby, elixir, dotnet tailors realize on Linux. Each is
mostly a table row plus one verification run of its existing e2e test.
Order by certainty.

- [ ] **Rust 1.96.1** `x86_64-unknown-linux-gnu`: `rustc`, `rust-std`,
      `cargo` tarballs from `static.rust-lang.org/dist/`, sha256 from the
      `.sha256` sidecars. `tests/cargo_e2e.rs` passes.
- [ ] **.NET SDK 9.0.317** `linux-x64` from the same
      `builds.dotnet.microsoft.com` path; sha512 from releases.json.
      `tests/dotnet_e2e.rs` passes. Note `/tmp/.dotnet` mutex dir is a
      sandbox write allowance on Linux too (bind it, tmpfs is fine).
- [ ] **Go 1.27.0** `linux-amd64` from go.dev; sha256 from
      `https://go.dev/dl/?mode=json`. `tests/go_e2e.rs` passes. cgo uses
      host gcc (decision 7).
- [ ] **Ruby 3.4.6** portable-ruby `x86_64_linux` bottle from
      Homebrew/homebrew-portable-ruby releases. Risk: relocation and
      glibc floor. Probe `ruby -e 'puts RUBY_PLATFORM'` and `gem env`
      from the store object; `tests/ruby_e2e.rs` (rake, racc, nokogiri
      native build) passes. If nokogiri's extconf needs host
      libxml2-devel, record it as a host prerequisite.
- [ ] **Erlang/OTP 29.0.5** — decide the source (inventory row 9):
      (a) hex.pm bob builds (`builds.hex.pm/builds/otp/ubuntu-24.04/
      OTP-29.0.5.tar.gz`, checksums in `builds.txt`); these are compiled
      against Ubuntu's glibc/openssl and may need `libcrypto` at a
      specific soname on Fedora, or (b) build OTP from source once in
      the sandbox and pin our own artifact. Prefer (a) if `crypto:start()`
      succeeds on Fedora; otherwise (b). Elixir zip / hex / rebar3 stay
      as-is. `tests/elixir_e2e.rs` passes.
- [ ] Every new pin's platform row added alongside the macOS row, never
      replacing it.

Exit: `bash tests/acceptance.sh` passes on Linux end to end.

**Landed:** _(date, commit, notes)_

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

Exit: two numbers in HITRATE.md, one per platform, from the same list.

**Landed:** _(date, commit, notes)_

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

Exit: written proof that a mixed-platform store is safe, or a bug fixed.

**Landed:** _(date, commit, notes)_

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

**Landed:** _(date, commit, notes)_

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

1. Does bubblewrap run cleanly under Fedora's enforcing SELinux for a
   non-root user with binds under `/home`? (Expected yes.)
2. Which OTP source for Linux: hex.pm bob builds or our own build?
3. Does Homebrew portable-ruby `x86_64_linux` relocate correctly outside
   `/home/linuxbrew`? Its pkg-config prefixes were already noted as a
   non-contract on macOS.
4. Is the host toolchain as found on m6-fedora (gcc 16.2, make 4.4, no `gcc-c++`, no `libxml2-devel`) enough
   for node-gyp and setuptools C extensions, or is a `dnf install`
   prerequisite required? Record the exact package list.

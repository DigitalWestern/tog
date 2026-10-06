# FOLLOW-UPS — open work and decisions

The one ordered to-do list. Every item here is open, and each is one line
(or a short paragraph) pointing at the GitHub issue that holds the detail:
the file paths, the options, and the pick. "Next up, in order" is the order
of work; decisions block their items until the owner makes them; everything
else is under "Open work", where the quality-review list (#264) is ordered
and the macOS gate is last by the owner's choice. When an item ships, delete
its line; its pull request description is the record of what was done and
how it was reviewed. Designs for work not yet built live in
`docs/agent/DESIGNS.md`; known, accepted gaps live in
`docs/human/LIMITATIONS.md`. Code comments cite an item by its title, never
by position.

## Next up, in order

The resolution proxy (#68), then the cleanup. Today Go and Cargo resolve
confined through the proxy (PRs 1 to 5: #198, #199, #200, #202, #203).
Every other ecosystem's `add`, `remove`, `update`, and missing-lock
generation runs through the door's unsandboxed `Legacy` mode with network,
the largest gap in what tog promises. Design: `docs/agent/DESIGNS.md` §6
(#196), evidence in #209. One pull request each, in this order:

1. **#204 (PR 6): Node.** npm and pnpm. npm already skips its audit,
   fund and update-notifier requests (#212).
2. **#205 (PR 7): Python.** uv. Every uv call already passes
   `--python <store python>` (#210); the forced row's own `--python` then
   replaces it.
3. **#206 (PR 8): Ruby and Elixir.** Bundler and Hex mirrors. Edits
   already resolve without installing (#211).
4. **#207 (PR 9): .NET.** The `nuget.config` mirror.
5. **#201 (PR 3b): the container backend and `tog-isolate`.** Moved after
   the doors: Go shipped confined without it, so no door waits on it. It
   must land before #208, because removing `Legacy` leaves a host without
   the native sandbox with no way to resolve.
6. **#208 (PR 10): remove `Legacy`.**

The macOS door (Seatbelt rules, the Mach allow-list from one run of
`tools/proxy_spike/macos_mach.sh` on a Mac, tree freeze) is not one of
these; it waits with the macOS gate below.

After the proxy: the test-suite audit (#351) and then the quality review
(#264), both under "Open work", each in its listed order.

## Decisions waiting on the owner

None open.

## Open work, each its own pull request

- **#462: tests: fsroot socket fixture renames across filesystems under a long TMPDIR.** fsroot test socket fixture crosses filesystems with a long TMPDIR. Pick: bind through the held directory fd alias.
- **#463: tests: sandbox socket fixtures fail before assertions under a long TMPDIR.** sandbox socket fixtures exceed SUN_LEN with a long TMPDIR. Pick: a shared Linux fd-alias binding helper, batched with required sandbox work.
- **#464: macOS supervision: deferred notification-pipe initialization and validation.** macOS supervision initialization and validation. Deferred by the owner on 2026-10-04.
- **#465: heavy: audit shared state before allowing parallel ignored suites.** audit shared state before running ignored suites in parallel. Keep --test-threads=1 until local evidence supports removal.
- **#466: ci: GitHub Actions job startup blocked by account billing or spending limit.** Actions jobs cannot start because of account billing or spending-limit restrictions. Pick: owner repairs account access, use documented local checks meanwhile.
- **#495: explicit Python package sources.** Define per-package source and metadata-build trust rules for PyTorch-style indexes. Keep undeclared indexes refused until that design ships.
- **#469: root removal identity.** Carry the decoded record's device/inode and held directory through deletion. Refuse replacements, including directory entries.
- **Action leftovers (#427).** Left: the first tag that carries
  `action.yml`. At that tag, change `@main` in `action.yml`'s header and in
  CLI.md to it.
- **A shared system store at `/opt/tog/store`: review, then build (#69).**
  The design is DESIGNS.md §7 (2026-10-05). Next: an independent review
  round, then its four implementation PRs in order.

- **Resolution proxy PR 5 review leftovers (#428).** One checklist issue
  per theme:
  - #430 signing key: other TOML parsers quote the failing line, and the no-store sandbox relay is unscrubbed.
  - #431 cargo confinement edges: a symlinked spelling of the root, grandchild-held pipes (left open by #57), an offline git-dependency test.
- **Test-suite audit of 2026-09-27 (#351).** Nine reviewers, one per
  area, looked for tests that stay green when the code they name is
  broken. The fake passes were fixed in #351; what remains is grouped by
  theme, one issue and one PR (or one per file block) each:
  - #348 tests: security and integrity checks with no offline test.
  - #349 product and CI problems found by the audit.
  - #367 tests: the artifact size caps in kernel::fetch (8 GiB artifact, 256 MiB text) have no test (from the #363 review).
  - #373 sandbox: host-socket scan leftovers (from the #372 review).
  - #411 tests: an objmeta socket test fails under a long TMPDIR, path over SUN_LEN (found during #400).
- **Quality review of 2026-09-24 (#264).** A whole-codebase review after
  the 09-20 to 09-24 run. #264 holds the work order and the overall verdict.
  Each line is one issue and one PR, in order:
  - #238 http: pypi, rubygems, dotnet and deps call ureq directly, bypassing kernel::fetch.
  - #240 store: a CacheLease holds gc.lock exclusively, so separate tog processes download one at a time.
  - #247 dead code: the non-heavy part shipped; left are the unused items in heavy-watched files (`fetch.rs`, `archive.rs`, `sandbox.rs`, `provider/`) and the CI job that builds with `--cfg tog_dead_code -D dead_code`.
  - #245 kernel: consolidate duplicated primitives. Left after the first pass: the file hash copy in `provider/crates.rs` and `fetch.rs` (heavy gate), the pid temp names in `fetch.rs`, `validate_object_complete` and `exceptions()` reading records their own way.
  - #246 left: move the recipe checks in `kernel/provider` (cpython, rust, rust_path) onto `Selected::checked_artifact`. Deferred because those files wake the heavy suite.
  - #248 sandbox and gitsrc: collapse the _with_activity twin of every entry point.
  - #256 design: the Tailor trait has 35+ methods, a dozen used by one ecosystem, and its docs have drifted.
  - #255 design: the kernel knows every ecosystem by name, and tog run is hard-wired to Node.
  - #257 design: move process-global state (policy, signing key, input guard, kinds) into Context.
  - #258 design: an error type that separates refusals, staleness, network and bugs.
  - #243 sandbox: the macOS Seatbelt profile reads all of /opt, its timezone rule is dead, and CI never runs it.
  - #237 archive: symlink containment compares names case-sensitively.
- **Found in the #316 review (2026-09-26).** One issue and one PR each:
  - #317 archive: hard links in registry packages are refused; allow contained ones.
  - #321 tests: kernel_smoke realizes against the developer's own store, so a local run can pass on cached objects.
  - #319 archive: read_member runs a tar -t cross-check it does not need.
- **Found in the #323 review (2026-09-26).** One issue and one PR each:
  - #324 ci: adding the heavy label during a path-triggered heavy run restarts it on the same commit.
  - #325 ci: tailor changes to extraction do not trigger the heavy suite on their own.
- **Found in the #327 work (2026-09-26).** One issue and one PR each:
  - #328 sandbox: opt Python sdist builds and npm addons into HostView::RuntimeOnly.
  - #329 ruby: give native gem builds tog's pinned native-libs set.
- **Found in the #399 release work (2026-10-03).** One issue and one PR each:
  - #402 selfupdate: `update --self`, `doctor` and `install.sh` cannot read a release while the repository is private.
  - #334 sandbox: RuntimeOnly setup costs ~2 s per native gem; measure on the runner.
  - #330 sandbox: HostView::RuntimeOnly is a no-op on macOS.
  - #332 hostview: LD_LIBRARY_PATH outranks DT_RUNPATH for relocated host libraries.
  - #331 hostview: kept library subdirectories are bound whole (accepted unless a gem hits it).
  - #333 ruby: host-fallback fingerprint is stat-based, not content-based (accepted).
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
  - #188 npm: realize `file:` packages as tog-owned trees.
  - #216 python: `uv pip compile` fails for vllm and MetaGPT; classifier label.
  - #476 fetch: state and audit that a cache hit is trusted by its digest's source, not its writer (from #287).
  - #289 interrupt: the bwrap preflight misreports Ctrl-C as "bwrap unavailable" (`sandbox.rs`, heavy gate). The exit code is fixed.
  - #295 tests: four sandbox tests fail instead of skipping when bubblewrap is missing.
  - #300 heavy: the Elixir end-to-end test cannot run on ubuntu-22.04 (OTP needs glibc 2.43).
  - #307 archive: a tarball with macOS AppleDouble (`._name`) members is refused on macOS but extracted on Linux. The extraction carries `--no-mac-metadata`; the listing carries no restore flag (bsdtar documents them for other modes). On the Mac, try `/usr/bin/tar --no-mac-metadata -tf` on such a tarball: if it accepts the flag and prints the `._` members, add it to `TAR_LIST_FLAGS` and close.
- **Unreproduced test flakes (#65).**
  `kernel::gitsrc::realization_tests::realizes_a_commit_and_strips_git_metadata`
  (2026-09-12) and `tailors::cargo::tests::rejects_symlinked_crate_entries`
  (2026-09-15) each failed once in a full parallel run and passed on every
  rerun. The panic messages were not captured. Two `supervise_signals`
  timeouts under a loaded machine (2026-09-25) are captured on #65. Capture
  the rest the same way before changing anything.
- **The release catalog and the company layer (#404, #405).** Key and
  credential policy decided 2026-10-03 (#72): trusted keys are entries in
  the files of the machine/home policy chain, rotation is a commit to that
  policy, and revocation is removal from the list, after which `tog audit`
  fails any record the removed key signed. The private-registry test
  account is a GitHub Packages registry under the DigitalWestern org. This
  unblocks the authenticated parts of `docs/agent/DESIGNS.md` §2 (WP3,
  #404) and §4 (WP5, #405); §2 PR 0, the provider evidence spike, comes
  first.
- **macOS arm64 gate (#66). Last, by the owner's choice.** The suites
  below and the two-machine lock diff passed on the Mac on 2026-09-25
  (after #305); `tests/supervise_signals.rs` (#57) and the Mach allow-list
  are what is left. Run on the Mac:
  `cargo test`, `cargo test --test gc -- --ignored`,
  `cargo test --test cli audit`, and
  `cargo test --test toolchain_lock -- --ignored`, including the
  case-insensitive-filesystem paths the root-key code relies on. Darwin
  identity goldens must stay byte-identical. It also covers
  `cargo test --test supervise_signals` for the per-operation signal
  sessions (#57; everything but the `/proc` cases runs there), and the
  resolution proxy's Mach allow-list (`tools/proxy_spike/macos_mach.sh`). Nothing Linux-side
  clears this.

- **Held project mounts (#497).** Sandbox mounts still resolve project paths. Bind the held directory through a descriptor rather than accepting a replacement at that name. See `src/kernel/sandbox/`.
- **Tool-opened absolute inputs (#499).** Bundler and uv now name project inputs relative to the held directory. Cargo's `--manifest-path` (`src/kernel/provider/crates.rs`) and external absolute requirements files still reopen a path. Name the manifest relative to the held cwd, and give external files a held input or a snapshot.


- **External requirements consistency (#501).** Select external absolute Python requirements once across command stages, using held input descriptors or immutable snapshots. Preserve existing supported external requirements. See `src/comforter/status.rs` and `src/tailors/python/inputs.rs`.

- **Object metadata byte limits (#502).** Give object-metadata reads and writes one explicit shared cap. Oversized existing records must refuse without deleting their object. This is separate from #375's guarded opens and the fact-record limit.

- **Unreadable rollback cleanup (#503).** Replace the pathname cleanup helper with held-descriptor removal so mode-000 and search-only directories do not leave rollback or teardown data behind. See `src/kernel/store/fsops.rs::remove_tree`.

- **Shared file hashing (#504).** Unify crate and fetch hashing through one descriptor/reader helper in the digest layer.
- **Random fetch temporaries (#505).** Share random suffixes for download/install temporaries while preserving exclusive creation and GC prefixes.
- **Complete reference metadata (#506).** Use the shared semantic parser for referenced objects and replace legitimate minimal fixtures with complete records.
- **Shared exception parsing (#507).** Add checked exceptions to object metadata records instead of reading that field separately.
- **SRI alternatives (#508).** Preserve all strongest hash candidates through Node planning and verification. The consolidation preserves first-entry behavior on ties.
- **Provider selection checks (#509).** Share recipe, runtime, and digest checks in the remaining CPython, Rust, and Rust-path providers.
- **#524: tests: gaps found in the review of #459 to #496.** e2e children that keep the caller's environment, the tar call-site scan, a subkey signature case, three node tests under `TOG_STRICT=1`. One checklist.
- **#525: review follow-ups from #474 to #492.** Small hardening items: one Elixir preflight, old project records, `STOPPED_BY`, links in an object's `bin/`, `meta/` listing and read cap, the silent digest skip. One checklist.
- **#527: tests: gaps found in the review of #526.** Machine policy inode reuse, ecosystems and lock from one root, real uv and Bundler after a swap, detached publication after a rename, the other ancestor walkers under a search-only directory. One checklist.

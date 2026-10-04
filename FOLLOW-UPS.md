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

1. **#204 (PR 6): Node.** npm and pnpm. Absorbs #212 (npm notifier and
   audit requests).
2. **#205 (PR 7): Python.** uv. Absorbs #210 (`uv pip compile` ignores
   `UV_PYTHON`).
3. **#206 (PR 8): Ruby and Elixir.** Bundler and Hex mirrors. Absorbs
   #211 (`bundle add` installs).
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

- **Plain `tog audit` in CI without keys (#395).** Since #394 it judges
  records with signatures unchecked instead of exiting 2; `--signed` is the
  fail-closed form and CLI.md has the migration note. Open: also refuse
  when `CI` is set unless `--unsigned` is passed. Pick: leave it until tog
  has an outside user. `v0.1.0` (2026-10-03) is private, so no released
  caller can be broken yet.

## Open work, each its own pull request

- **The action's fixture wakes the heavy suite (#426).** A change under
  `tests/fixtures/action-demo/` runs the e2e job. Pick: move the fixture
  out of `tests/`.
- **Action leftovers (#427).** The first tag that carries `action.yml`, a
  store cache between runs, and a self-test of the signed path.
- **Leftover `rustfmt.json` from an older tog (#416).** A lone record is
  never cleaned up by `tog fmt`, and `tog gc --register` on such a project
  gives an unhelpful message. Pick: gc forgets a root whose only closure is
  retired.
- **Record `skipped-optional` as an informational closure field (#71).**
  Decided 2026-09-23: an optional group the user did not request is a
  choice, not an exception. Record it as `optional_groups_skipped` so
  `status` and `sbom` still see it, check the python-env identity before
  assuming no identity impact, then re-run the Python hit rate and add a
  dated column to `docs/agent/HITRATE.md`.
- **A shared system store at `/opt/tog/store`: the design round (#69).**
  Decided 2026-09-23: a full design round with independent review, no code
  until it lands. Scope: ownership and permissions on the shared path, GC
  across users, the activity lease across uids, and the trust boundary a
  shared store changes.
- **An offline fixture where a sync succeeds (#147).** Every green-sync
  test downloads a toolchain and is ignored, so anything that runs after a
  successful sync is verified by hand. The bare-`tog` footer decision is now
  a unit-tested function (`cli::after_command`); the end-to-end path is not.
  That includes `tog build` syncing a stale ecosystem first; the
  ignored e2e suites could drop their explicit `sync` step to cover it.

- **Resolution proxy PR 5 review leftovers (#428).** One checklist issue
  per theme:
  - #430 signing key: other TOML parsers quote the failing line, and the no-store sandbox relay is unscrubbed.
  - #431 cargo confinement edges: a symlinked spelling of the root, grandchild-held pipes (left open by #57), an offline git-dependency test.
  - #432 resolution ledger: `content_query_keys` never recorded, and `tog plan`'s sdist ledgers unrooted.
- **Test-suite audit of 2026-09-27 (#351).** Nine reviewers, one per
  area, looked for tests that stay green when the code they name is
  broken. The fake passes were fixed in #351; what remains is grouped by
  theme, one issue and one PR (or one per file block) each:
  - #348 tests: security and integrity checks with no offline test.
  - #349 product and CI problems found by the audit.
  - #355 store: a path inside a local object is treated as foreign during closure import (from the #354 review).
  - #359 elixir: Hex metadata cross-check matches substrings, not the top-level app/version (from the #358 review).
  - #367 tests: the artifact size caps in kernel::fetch (8 GiB artifact, 256 MiB text) have no test (from the #363 review).
  - #369 python: wheel entry-point and entry-name validation leftovers (from the #368 review).
  - #418 fmt: a never-synced project whose only closure is the retired rustfmt.json never self-heals, and `gc --register` refuses it (from #409).
  - #371 comforter: closure_object probe follows symlinks out of the object (from the #370 review).
  - #373 sandbox: host-socket scan leftovers (from the #372 review).
  - #375 store: metadata readers and record writer leftovers (from the #374 review).
  - #377 catalog: uv GitHub digest unchecked, uv .sha256 parse, Node signer not pinned (from the #348 Tooling review).
  - #410 ci: eight test files skip sandboxed tests silently because the main test step doesn't require the sandbox (from the #400 review).
  - #411 tests: an objmeta socket test fails under a long TMPDIR, path over SUN_LEN (found during #400).
  - #380 python markers: platform_release/platform_version, extras `in` versus uv, and documented divergences from packaging (from the #348 Python markers block).
  - #382 node: credentials in lockfile URLs beyond tarballs, mutable-mode hoisting, bin case collisions (from the #348 Lockfile shapes block).
  - #387 gc: `--drop-object` recovery leftovers: the sweep's refusal names no fix, rooted objects, the advice's shell line untested (from the #384 review).
- **Quality review of 2026-09-24 (#264).** A whole-codebase review after
  the 09-20 to 09-24 run. #264 holds the work order and the overall verdict.
  Each line is one issue and one PR, in order:
  - #238 http: pypi, rubygems, dotnet and deps call ureq directly, bypassing kernel::fetch.
  - #241 store: object commit never fsyncs; a power loss can leave an empty completion record.
  - #242 gc: crashed download temp files in tmp/ are never removed.
  - #240 store: a CacheLease holds gc.lock exclusively, so separate tog processes download one at a time.
  - #244 supervise: waits forever for stderr EOF if the child leaves a background process.
  - #247 dead code: about 90 unused items hidden by pub mod, plus a CI check to keep it at zero.
  - #245 kernel: consolidate duplicated primitives (base64, SRI, metadata parser, forest key, file hash, temp names).
  - #246 tailors: shared closure_state, checked_artifact, object_ref and merge_record helpers; cargo status misses GC'd objects.
  - #248 sandbox and gitsrc: collapse the _with_activity twin of every entry point.
  - #249 x.rs: reuse kernel fsops, one lock, one name validator, and split the file.
  - #413 x clean: delete before unregister, corrupt registry entries, pathname ownership reads (from the #408 review). Do it with #249.
  - #250 python manifest: four requirements include walkers; uv.lock silently drops edges; pypi host check is a substring.
  - #261 perf: every sync parses every metadata record before starting.
  - #251 commands: one project-discovery function; tog <script> and tog run <script> disagree.
  - #252 commands: sbom, ls and store path create the store; sbom refuses closures from another platform.
  - #253 cli: usage mistakes exit 1 after opening the store instead of exit 2.
  - #254 commands: small fixes: deps changes cwd, stale help pointers, three manifest lists, inspect.rs belongs in comforter.
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
  - #318 architecture: tar_runs_only_in_kernel_archive cannot see a bare "tar".
- **Found in the #323 review (2026-09-26).** One issue and one PR each:
  - #324 ci: adding the heavy label during a path-triggered heavy run restarts it on the same commit.
  - #325 ci: tailor changes to extraction do not trigger the heavy suite on their own.
- **Found in the #327 work (2026-09-26).** One issue and one PR each:
  - #328 sandbox: opt Python sdist builds and npm addons into HostView::RuntimeOnly.
  - #329 ruby: give native gem builds tog's pinned native-libs set.
- **Found in the #399 release work (2026-10-03).** One issue and one PR each:
  - #402 selfupdate: `update --self`, `doctor` and `install.sh` cannot read a release while the repository is private.
  - #403 doctor: suggests an update the release has no asset for on this machine.
  - #334 sandbox: RuntimeOnly setup costs ~2 s per native gem; measure on the runner.
  - #330 sandbox: HostView::RuntimeOnly is a no-op on macOS.
  - #332 hostview: LD_LIBRARY_PATH outranks DT_RUNPATH for relocated host libraries.
  - #335 hostview: stale view skeletons after SIGKILL.
  - #337 tests: no subprocess test that the view skeleton is 0700 under umask 0777.
  - #331 hostview: kept library subdirectories are bound whole (accepted unless a gem hits it).
  - #333 ruby: host-fallback fingerprint is stat-based, not content-based (accepted).
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
  - #183 `status`/`doctor` create and lease the store; add a read-only context mode.
  - #188 npm: realize `file:` packages as tog-owned trees.
  - #190 `tog x` py: tools in a Rust-locked project build sdists on shipped Rust.
  - #191 provider object-kind rows still live in the tailors' `objects.rs`.
  - #215 python: sdists that need Rust at build time (stable-diffusion-webui).
  - #216 python: `uv pip compile` fails for vllm and MetaGPT; classifier label.
  - #219 descriptor: delegated tools a sync starts still run with a path cwd.
  - #220 descriptor: files above the project (Cargo workspace, `go.work`, .NET `Directory.*`) read by path.
  - #221 descriptor: `status`, `doctor` and `run`'s environment still read by path.
  - #267 tests: non-tog children in npm_scripts and deps_e2e inherit the developer's environment.
  - #272 pnpm freshness: a new workspace member without an importer passes, and overrides match by name only.
  - #277 gc: run homes under `<store>/run-homes` are never reclaimed.
  - #279 node: run refusal misses npm abbreviations and nested installs, and refuses bare `bun`.
  - #283 dotnet: block `OutDir` and `PublishDir`, and parse the lock once per sync.
  - #285 pnpm lock reader: four edge cases (trailing colon, parentheses in paths, unquoted `@` keys, a third document) not yet confirmed against js-yaml.
  - #287 store records: no gc for `records/`, orphaned `tmp/record-*` temporaries, Elixir check-locked hash blind spots.
  - #289 interrupt: the bwrap preflight misreports Ctrl-C as "bwrap unavailable", and an interrupted sync exits 1 rather than 130.
  - #295 tests: four sandbox tests fail instead of skipping when bubblewrap is missing.
  - #297 python: two PEP 440 grammars; hoist `pep440.rs` into the kernel.
  - #300 heavy: the Elixir end-to-end test cannot run on ubuntu-22.04 (OTP needs glibc 2.43).
  - #302 acceptance.sh: step 13 carries its own copy of the closure signing format.
  - #307 archive: a tarball with macOS AppleDouble (`._name`) members is refused on macOS but extracted on Linux. The extraction carries `--no-mac-metadata`; the listing carries no restore flag (bsdtar documents them for other modes). On the Mac, try `/usr/bin/tar --no-mac-metadata -tf` on such a tarball: if it accepts the flag and prints the `._` members, add it to `TAR_LIST_FLAGS` and close.
- **Two PEP 440 version grammars (#297).** `src/kernel/toolchain/select.rs` has
  the small numeric `Version`/specifier subset the toolchain selector needs;
  `src/tailors/python/pep440.rs` has the full grammar. The toolchain lock's
  Python source reader (`src/kernel/toolchain/resolve.rs`) parses
  `requires-python` with the kernel subset while `pyselect` uses the full
  grammar, and the kernel cannot import the tailor's copy. Hoist
  `pep440.rs` into `src/kernel/` and have the selector use it, in its own
  PR.
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

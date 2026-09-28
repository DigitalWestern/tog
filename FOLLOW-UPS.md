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

Nothing queued; the next item comes from "Open work" below.

## Decisions waiting on the owner

- **Help after every bare `tog` (#145).** Since #142 a successful sync is
  followed by the full help screen, which can scroll the sync result away.
  Watch daily use; the candidates are a short footer, the full screen only
  when nothing needed syncing, or leaving it.
- **First outside target.** Cheapest visible artifact: a GitHub Action
  running `tog --frozen` under the company policy plus `tog sbom`, which
  should work on GitHub-hosted Ubuntu runners if unprivileged user
  namespaces are allowed there. Parked 2026-09-23 until the Ubuntu sandbox
  behavior (#87) was understood. That condition has fired: #87 was fixed by
  #173 (the sandbox mirrors the host's `/bin` and `/lib` layout, so Ubuntu
  22.04 can sandbox) and its follow-up #175 is closed. Un-parking #70 is the
  owner's call.
- **Key and credential policy for the trust work.** Where trusted publisher
  keys live, who rotates them, and what revocation means (including a
  company's own internal publisher); a test account for private-registry
  credentials. Blocks the authenticated parts of `docs/agent/DESIGNS.md`
  §2 and §4 (#72).

## Open work, each its own pull request

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
- **`tog audit` without trusted keys (#144).** It exits 2 by design, so a
  recorded policy exception has no command that judges it in the default
  unsigned setup. Decided 2026-09-23: both an unsigned mode of `audit`
  and exceptions in `tog status`; then the exception summary can name a
  real fix again. Stays open until both land.
- **An offline fixture where a sync succeeds (#147).** Every green-sync
  test downloads a toolchain and is ignored, so "bare `tog`, then the
  help" and anything else that runs after a successful sync is verified by
  hand. That includes `tog build` syncing a stale ecosystem first; the
  ignored e2e suites could drop their explicit `sync` step to cover it.

- **Supervision redesign: one signal session per operation.** Today one
  process supervises at most one child; a second concurrent session is
  rejected with a named busy error (`Session::new` in
  `src/kernel/supervise.rs`). That follows from process-wide `sigaction`
  state, not from a design choice. Two alternatives were tried and rejected,
  so do not retry them: a hard rejection enforced in tests turned a green
  suite red because parallel test threads legitimately supervise at once,
  and a blocking lock reintroduces an unbounded silent wait. The interim
  workaround is `SUPERVISION_TEST_LOCK` plus `--test-threads=1` for
  `--ignored` targets. Design: `docs/agent/DESIGNS.md` §5 "Per-operation
  signal sessions" (#57); implementation follows its review.
- **The resolution proxy (#68).** Delegated tools (`add`/`remove`/`update`,
  missing-lock generation, `tog x`) run unsandboxed with network today.
  Design: `docs/agent/DESIGNS.md` §6 (#196). PR 0, the measured evidence,
  shipped in #209; its macOS Mach allow-list waits on one run of
  `tools/proxy_spike/macos_mach.sh` on a Mac. The rest, in order: #198 (PR 1,
  the door type), #199, #200, #201 (PR 3b), #202, #203, #204, #205, #206,
  #207, #208 (PR 10, remove `Legacy`). Found by PR 0 and slotted into those:
  #210 (uv ignores `UV_PYTHON`), #211 (`bundle add` installs), #212 (npm
  notifier and audit requests).
- **Test-suite audit of 2026-09-27 (#351).** Nine reviewers, one per
  area, looked for tests that stay green when the code they name is
  broken. The fake passes were fixed in #351; what remains is grouped by
  theme, one issue and one PR (or one per file block) each:
  - #348 tests: security and integrity checks with no offline test.
  - #349 product and CI problems found by the audit.
  - #350 tests: duplicate and trivial tests to delete or merge, and ignored tests to promote.
  - #355 store: a path inside a local object is treated as foreign during closure import (from the #354 review).
  - #359 elixir: Hex metadata cross-check matches substrings, not the top-level app/version (from the #358 review).
  - #367 tests: the artifact size caps in kernel::fetch (8 GiB artifact, 256 MiB text) have no test (from the #363 review).
  - #369 python: wheel entry-point and entry-name validation leftovers (from the #368 review).
  - #371 comforter: closure_object probe follows symlinks out of the object (from the #370 review).
  - #373 sandbox: host-socket scan leftovers (from the #372 review).
  - #375 store: metadata readers and record writer leftovers (from the #374 review).
  - #377 catalog: uv GitHub digest unchecked, uv .sha256 parse, Node signer not pinned (from the #348 Tooling review).
  - #380 python markers: platform_release/platform_version, and documented divergences from packaging (from the #348 Python markers block).
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
  - #259 legacy: drop pre-release legacy toolchain seeding and x legacy roots now.
  - #249 x.rs: reuse kernel fsops, one lock, one name validator, and split the file.
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
  - #334 sandbox: RuntimeOnly setup costs ~2 s per native gem; measure on the runner.
  - #330 sandbox: HostView::RuntimeOnly is a no-op on macOS.
  - #332 hostview: LD_LIBRARY_PATH outranks DT_RUNPATH for relocated host libraries.
  - #335 hostview: stale view skeletons after SIGKILL.
  - #337 tests: no subprocess test that the view skeleton is 0700 under umask 0777.
  - #331 hostview: kept library subdirectories are bound whole (accepted unless a gem hits it).
  - #333 ruby: host-fallback fingerprint is stat-based, not content-based (accepted).
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
  - #174 npm: git-tracked `node_modules` in workspace members moved into backups.
  - #180 build: first build with no lock still needs a catalog row for every ecosystem.
  - #183 `status`/`doctor` create and lease the store; add a read-only context mode.
  - #188 npm: realize `file:` packages as tog-owned trees.
  - #190 `tog x` py: tools in a Rust-locked project build sdists on shipped Rust.
  - #191 provider object-kind rows still live in the tailors' `objects.rs`.
  - #214 npm/pnpm: a required foreign-platform dependency is refused (tailwindcss).
  - #215 python: sdists that need Rust at build time (stable-diffusion-webui).
  - #216 python: `uv pip compile` fails for vllm and MetaGPT; classifier label.
  - #219 descriptor: delegated tools a sync starts still run with a path cwd.
  - #220 descriptor: files above the project (Cargo workspace, `go.work`, .NET `Directory.*`) read by path.
  - #221 descriptor: `status`, `doctor` and `run`'s environment still read by path.
  - #267 tests: non-tog children in npm_scripts and deps_e2e inherit the developer's environment.
  - #272 pnpm freshness: a new workspace member without an importer passes, and overrides match by name only.
  - #277 gc: run homes under `<store>/run-homes` are never reclaimed.
  - #278 rust_path: the version probe's scratch directory is created with `create_dir_all`.
  - #279 node: run refusal misses npm abbreviations and nested installs, and refuses bare `bun`.
  - #283 dotnet: block `OutDir` and `PublishDir`, and parse the lock once per sync.
  - #285 pnpm lock reader: four edge cases (trailing colon, parentheses in paths, unquoted `@` keys, a third document) not yet confirmed against js-yaml.
  - #287 store records: no gc for `records/`, orphaned `tmp/record-*` temporaries, Elixir check-locked hash blind spots.
  - #289 interrupt: the bwrap preflight misreports Ctrl-C as "bwrap unavailable", and an interrupted sync exits 1 rather than 130.
  - #294 size ratchet: the function heuristic counts `#[cfg(test)]` functions outside `mod tests` as production code.
  - #295 tests: four sandbox tests fail instead of skipping when bubblewrap is missing.
  - #296 ci: add a Dependabot updater for the SHA-pinned actions.
  - #297 python: two PEP 440 grammars; hoist `pep440.rs` into the kernel.
  - #298 doctor: the version row shows a package-download message when no release exists.
  - #300 heavy: the Elixir end-to-end test cannot run on ubuntu-22.04 (OTP needs glibc 2.43).
  - #301 acceptance.sh: steps 9 and 9b re-run two ignored suites the heavy workflow already runs, one multi-threaded.
  - #302 acceptance.sh: step 13 carries its own copy of the closure signing format.
  - #307 archive: a tarball with macOS AppleDouble (`._name`) members is refused on macOS but extracted on Linux. The extraction carries `--no-mac-metadata`; the listing carries no restore flag (bsdtar documents them for other modes). On the Mac, try `/usr/bin/tar --no-mac-metadata -tf` on such a tarball: if it accepts the flag and prints the `._` members, add it to `TAR_LIST_FLAGS` and close.
  - #308 tests: python fixture tarballs are packed with raw `/usr/bin/tar`, not `tar_create`.
- **`deps` as a `Tailor` method (#61).** `src/commands/deps.rs` still names
  tailors directly. A `Tailor::edit_manifest` method with an "unsupported"
  default would make it registry-driven, the way `Tailor::registry_tool`
  did for `x`. It is its own design review: deps edits user manifests.
  The signature, carrying the resolution door, is in `docs/agent/DESIGNS.md`
  §6; it ships as resolution proxy PR 1 (#198), which also moves the
  Corepack/pnpm path (#169).
- **GC loose ends from #162.** Three small `src/kernel/store/roots.rs`
  fixes: a case-mismatched `gc --dry-run --forget` key previews fewer
  deletions on macOS (#163); the root/2 importer calls a path inside this
  store's own object "another store" (#164); re-importing a
  `node-forest/2` closure adds a legacy `projection_id` projection sync
  never published (#165).
- **`gc --migrate-metadata` as a `fix:` line (#166).** It resolves only a
  transient failure. Recommended: keep `fix:`.
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
- **macOS arm64 gate (#66). Last, by the owner's choice.** The suites
  below and the two-machine lock diff passed on the Mac on 2026-09-25
  (after #305); #57 and the Mach allow-list are what is left. Run on the Mac:
  `cargo test`, `cargo test --test gc -- --ignored`,
  `cargo test --test cli audit`, and
  `cargo test --test toolchain_lock -- --ignored`, including the
  case-insensitive-filesystem paths the root-key code relies on. Darwin
  identity goldens must stay byte-identical. It also covers the per-operation signal sessions
  implementation (#57) once that lands, and the resolution proxy's Mach
  allow-list (`tools/proxy_spike/macos_mach.sh`). Nothing Linux-side
  clears this.

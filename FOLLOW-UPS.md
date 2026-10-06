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

The resolution proxy (#68), then the cleanup. Today Go, Cargo, and Node
resolve confined through the proxy (PRs 1 to 6: #198, #199, #200, #202,
#203, #204). Every other ecosystem's `add`, `remove`, `update`, and
missing-lock generation runs through the door's unsandboxed `Legacy` mode
with network, the largest gap in what tog promises. Design:
`docs/agent/DESIGNS.md` §6 (#196), evidence in #209. One pull request
each, in this order:

1. **#205 (PR 7): Python.** uv. Every uv call already passes
   `--python <store python>` (#210); the forced row's own `--python` then
   replaces it. PR 6 left it `ConfinedSpec::cwd` (a workspace member
   below the lock root), `door::Publish`, and `door::proxy_env` (the
   proxy variables and `SSL_CERT_FILE` of an intercepting session).
2. **#206 (PR 8): Ruby and Elixir.** Bundler and Hex mirrors. Edits
   already resolve without installing (#211).
3. **#207 (PR 9): .NET.** The `nuget.config` mirror.
4. **#201 (PR 3b): the container backend and `tog-isolate`.** Moved after
   the doors: Go shipped confined without it, so no door waits on it. It
   must land before #208, because removing `Legacy` leaves a host without
   the native sandbox with no way to resolve.
5. **#208 (PR 10): remove `Legacy`.**

The macOS door (Seatbelt rules, the Mach allow-list from one run of
`tools/proxy_spike/macos_mach.sh` on a Mac, tree freeze) is not one of
these; it waits with the macOS gate below.

After the proxy: the test-suite audit (#351) and then the quality review
(#264), both under "Open work", each in its listed order.

## Decisions waiting on the owner

None open.

## Open work, each its own pull request

- **Found in the `tog <file>` work (2026-10-05).** One issue and one PR each:
- **#464: macOS supervision: deferred notification-pipe initialization and validation.** macOS supervision initialization and validation. Deferred by the owner on 2026-10-04.
- **#465: heavy: audit shared state before allowing parallel ignored suites.** audit shared state before running ignored suites in parallel. Keep --test-threads=1 until local evidence supports removal.
- **#466: ci: GitHub Actions job startup blocked by account billing or spending limit.** Actions jobs cannot start because of account billing or spending-limit restrictions. Pick: owner repairs account access, use documented local checks meanwhile.
- **#495: explicit Python package sources.** Define per-package source and metadata-build trust rules for PyTorch-style indexes. Keep undeclared indexes refused until that design ships.
- **Action leftovers (#427).** Left: the first tag that carries
  `action.yml`. At that tag, change `@main` in `action.yml`'s header and in
  CLI.md to it.
- **A shared system store at `/opt/tog/store`: review, then build (#69).**
  The design is DESIGNS.md §7 (2026-10-05). Next: an independent review
  round, then its four implementation PRs in order.

- **Resolution proxy PR 5 review leftovers (#428).** One checklist issue
  per theme:
- **Test-suite audit of 2026-09-27 (#351).** Nine reviewers, one per
  area, looked for tests that stay green when the code they name is
  broken. The fake passes were fixed in #351; what remains is grouped by
  theme, one issue and one PR (or one per file block) each:
  - #349 product and CI problems found by the audit.
- **Quality review of 2026-09-24 (#264).** A whole-codebase review after
  the 09-20 to 09-24 run. #264 holds the work order and the overall verdict.
  Each line is one issue and one PR, in order:
  - #257 design: move process-global state (policy, signing key, input guard, kinds) into Context. The input guard now keeps one snapshot per sync, so two projects in one process no longer clear each other's. Left: carry the policy frames, the signing key, the guard and the installed kinds in `Context`, designed with #57's per-operation sessions.
  - #258 design: an error type that separates refusals, staleness, network and bugs. The `detected()` bug is fixed. Left is the `TogError` classes (Refused, Stale, Unsupported, Network, Interrupted) with distinct exit codes, starting with `fsroot::refusal`.
  - #243 sandbox: the macOS Seatbelt profile reads all of /opt, its timezone rule is dead, and CI never runs it.
- **Found in the #316 review (2026-09-26).** One issue and one PR each:
  - #321 tests: kernel_smoke realizes against the developer's own store, so a local run can pass on cached objects.
- **Found in the #323 review (2026-09-26).** One issue and one PR each:
- **Found in the #327 work (2026-09-26).** One issue and one PR each:
  - #328 sandbox: opt Python sdist builds and npm addons into HostView::RuntimeOnly.
  - #329 ruby: give native gem builds tog's pinned native-libs set.
- **Found in the #399 release work (2026-10-03).** One issue and one PR each:
  - #334 sandbox: RuntimeOnly setup costs ~2 s per native gem; measure on the runner.
  - #330 sandbox: HostView::RuntimeOnly is a no-op on macOS.
  - #331 hostview: kept library subdirectories are bound whole (accepted unless a gem hits it).
  - #333 ruby: host-fallback fingerprint is stat-based, not content-based (accepted).
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
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






- **Provider selection checks (#509).** Share recipe, runtime, and digest checks in the remaining CPython, Rust, and Rust-path providers.
- **#527: tests: gaps found in the review of #526.** Left: real uv and Bundler e2e runs after a swap, a Node `tog sync` under a search-only parent, and the sandbox.rs socket tests under a long TMPDIR (heavy-watched). One checklist.
- **#555: fetch and cache hardening from the review of #532 to #545.** The poisoned-entry removal race, tests for `fetch_text_or_missing` and `download_unpinned`, `Interrupted` in `hash_reader`, the insert temporary and its mode. One checklist.
- **#556: archive link and `read_member` follow-ups from #542 and #543.** `read_member` follows links without `validate`'s rules, two refusals missing from the docs, missing tests, stale comments. One checklist.
- **#557: what wakes the heavy suite (#546, #547).** Zip extraction and git-source packing are unwatched, the `kernel/` exemption is wider than the gate, two label gaps. A CI-cost decision. One checklist.
- **#558: test and doc gaps from the review of #535 to #541.** A wrong file name in a Rust refusal, dead-code leftovers, a test that fakes its refusal, line counts, the toolchain guard's ancestor matching. One checklist.
- **#559: host fallback and host view follow-ups from #549 to #551.** No e2e for a Ruby gem that really falls back, the npm exception detail, clang under `/usr/lib/llvm-<N>`, `realpath` to the uncurated copy, lone `lib*.so` symlinks. One checklist.
- **#560: e2e layouts with HOME inside the project.** Python and Ruby tests that the PR 7 and PR 8 doors will refuse. One checklist.

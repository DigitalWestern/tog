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

The resolution proxy (#68), then the cleanup. Today Go, Cargo, Node, and
Python resolve confined through the proxy (PRs 1 to 7: #198, #199, #200,
#202, #203, #204, #205). Every other ecosystem's `add`, `remove`, `update`, and
missing-lock generation runs through the door's unsandboxed `Legacy` mode
with network, the largest gap in what tog promises. Design:
`docs/agent/DESIGNS.md` §6 (#196), evidence in #209. One pull request
each, in this order:

1. **#206 (PR 8): Ruby and Elixir.** Bundler and Hex mirrors. Edits
   already resolve without installing (#211).
2. **#207 (PR 9): .NET.** The `nuget.config` mirror.
3. **#201 (PR 3b): the container backend and `tog-isolate`.** Moved after
   the doors: Go shipped confined without it, so no door waits on it. It
   must land before #208, because removing `Legacy` leaves a host without
   the native sandbox with no way to resolve.
4. **#208 (PR 10): remove `Legacy`.**

The macOS door (Seatbelt rules, the Mach allow-list from one run of
`tools/proxy_spike/macos_mach.sh` on a Mac, tree freeze) is not one of
these; it waits with the macOS gate below.

After the proxy: what is left of the quality review (#264), under "Open
work", in its listed order.

## Decisions waiting on the owner

None open.

## Open work, each its own pull request

- **Found in the review of #567 to #610 (2026-10-06).** One checklist issue per theme:
  - #615 design questions: SRI candidate choice, cargo's symlinked members, the ecosystem-arm check in `kernel/provider`, the `hard_link_target` doc.
- **Found in #617 and #618 (2026-10-07).** One checklist issue per theme:
  - #619 held project root: `tog fmt` reads cargo config by path, a cross-filesystem `rename_in` holds the file in memory, strict walks need read permission on search-only parents.
  - #620 test gaps: the dev-files hook and symlinked directories, the hook for tailors other than Ruby, the `sandbox_deny` header, a CPython test in `tests/cli.rs`, the proxy reader's upper cap.
- **#464: macOS supervision: deferred notification-pipe initialization and validation.** macOS supervision initialization and validation. Deferred by the owner on 2026-10-04.
- **#495: explicit Python package sources.** Define per-package source and metadata-build trust rules for PyTorch-style indexes. Keep undeclared indexes refused until that design ships.
- **Action leftovers (#427).** Left: the first tag that carries
  `action.yml` (at that tag, change `@main` in `action.yml`'s header and in
  CLI.md to it), and an opt-in store cache.
- **A shared system store at `/opt/tog/store`: review, then build (#69).**
  The design is DESIGNS.md §7 (2026-10-05). Next: an independent review
  round, then its four implementation PRs in order.

- **Quality review of 2026-09-24 (#264).** A whole-codebase review after
  the 09-20 to 09-24 run. #264 (closed) holds the overall verdict. What
  is left, one issue and one PR each, in order:
  - #257 design: move process-global state (policy, signing key, input guard, kinds) into Context. The input guard now keeps one snapshot per sync, so two projects in one process no longer clear each other's. Left: carry the policy frames, the signing key, the guard and the installed kinds in `Context`, designed with #57's per-operation sessions.
  - #258 design: an error type that separates refusals, staleness, network and bugs. The `detected()` bug is fixed. Left is the `TogError` classes (Refused, Stale, Unsupported, Network, Interrupted) with distinct exit codes, starting with `fsroot::refusal`.
  - #243 sandbox: the macOS Seatbelt profile reads all of /opt, its timezone rule is dead, and CI never runs it.
- **Found in the #399 release work (2026-10-03).** One issue and one PR each:
  - #330 sandbox: HostView::RuntimeOnly is a no-op on macOS.
- **Smaller open issues from the 2026-09-23/24 run.** One line each; the
  issue has the options and the pick.
  - #300 heavy: the Elixir end-to-end test cannot run on ubuntu-22.04 (OTP needs glibc 2.43).
  - #307 archive: a tarball with macOS AppleDouble (`._name`) members is refused on macOS but extracted on Linux. The extraction carries `--no-mac-metadata`; the listing carries no restore flag (bsdtar documents them for other modes). On the Mac, try `/usr/bin/tar --no-mac-metadata -tf` on such a tarball: if it accepts the flag and prints the `._` members, add it to `TAR_LIST_FLAGS` and close.
- **The release catalog and the company layer (#404, #405).** Key and
  credential policy decided 2026-10-03 (#72): trusted keys are entries in
  the files of the machine/home policy chain, rotation is a commit to that
  policy, and revocation is removal from the list, after which `tog audit`
  fails any record the removed key signed. The private-registry test
  account is a GitHub Packages registry under the DigitalWestern org. This
  unblocks the authenticated parts of `docs/agent/DESIGNS.md` §2 (WP3,
  #404) and §4 (WP5, #405); §2 PR 0, the provider evidence spike, comes
  first.
- **#560: e2e layouts with HOME inside the project.** Python and Ruby tests that the PR 7 and PR 8 doors will refuse. One checklist.
- **macOS arm64 gate. Last, by the owner's choice.** The suites
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

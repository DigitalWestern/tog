# STATUS — where tog is, and what is next

Updated 2026-09-25.

## What tog is

One binary that owns the outer loop every language ecosystem shares:
provision a pinned toolchain, lock a dependency graph, realize it into an
immutable content-addressed store, project an environment, run your code.
Nix's model without Nix's interface. Seven ecosystems built: Python, npm,
Cargo, Go, Ruby, Elixir, .NET.

## Where we are

| Area | State |
|---|---|
| Seven ecosystems, Linux x86_64 | Shipped. The offline suite runs on every PR (`.github/workflows/ci.yml`); the network end-to-end tests (`cargo test -- --ignored`) and `tests/acceptance.sh` run weekly, by hand, and on PRs that change extraction, downloads, toolchain catalogs or `Cargo.lock` or carry the `heavy` label, in the [`heavy`](.github/workflows/heavy.yml) workflow, all but Elixir (its Linux OTP needs a newer glibc than the runner has, #300). **Last green `heavy` run: none yet** (workflow added 2026-09-25); put the date and run link here after each green run |
| macOS arm64 | Last run 2026-09-25 on 4a2bffa (Apple Silicon, macOS 27.0), by hand: `cargo test` 1221/0, `cargo test -- --ignored` 67/0 with every ecosystem end to end (Elixir too), `tests/acceptance.sh` 39/0, `tests/install.sh` 85/0. The two-machine lock diff passed the same day: a seven-ecosystem lock written on Fedora synced unchanged on the Mac, the Mac wrote the same bytes, and `tog status` matched. CI still runs no macOS job (#243), so PRs after that are Linux-verified only. What the gate (#66) still needs: the signal sessions (#57) and resolution proxy once they land |
| Python + npm on real projects | Proven (Next.js, vite, prisma, native addons, FastAPI). Latest hit rate (2026-09-23): Python 26/30, npm 28/30; 27 and 29 with #213's Rust catalog (`docs/agent/HITRATE.md`) |
| Other ecosystems | Fixture-proven on every PR (`tests/`). Cargo, Go, Ruby and .NET each also have a network end-to-end test against the real registry in the [`heavy`](.github/workflows/heavy.yml) workflow (Elixir's cannot run on the runner, #300), not on real projects the way Python and npm are |
| Store GC (root protection, object metadata, fail-closed sweep) | Shipped and independently reviewed on Linux |
| Module layout | Refactor finished 2026-09-12: one folder per layer, the `Tailor` trait and registry, layering enforced by `tests/architecture.rs` (rules in `docs/human/ARCHITECTURE.md`) |
| Policy admission gate (`tog audit`, company policy template) | Shipped and independently reviewed on Linux. Every record is compared (2026-09-17); `tog fmt` writes no record since #386 (2026-10-03). Closure records are signed (`tog keygen`, `TOG_SIGNING_KEY`) and `audit` verifies them against the machine policy's `[signing]` table; unsigned or pre-field records are `outdated`, a missing primary closure fails (2026-09-18, PRs #77 and #78) |
| `tog sync` preflight | Refused syncs no longer touch the store (2026-09-16, PR #40) |
| Toolchain lock (WP2) | Shipped on Linux 2026-09-21. A committed `tog-toolchain.toml` names the exact toolchain per ecosystem: the first writable sync writes it, every later sync honors it, a source that disagrees stops the sync, `tog --frozen` validates without writing, `tog update --toolchain [<eco>]` is the one writer that replaces it, `tog status` reports the verdict, and `tog x` keys its cache on the selected bundle. Described in `docs/human/ARCHITECTURE.md` "Toolchain lock"; the parts still open are in `docs/agent/DESIGNS.md` §1. **Not yet run on two machines**: see FOLLOW-UPS.md "Next up, in order" |
| Release catalog and trust (WP3), company layer (WP5) | Designed, not built (`docs/agent/DESIGNS.md` §2, §4) |
| Toolchain catalogs (2026-09-24) | Every ecosystem's releases are generated, verified data files (`catalog.toml`, `tools/catalog.py --check`), append-only, with an explicit default (#195). Rust ships 43 releases, 1.70.0 to 1.98.1; `rust-toolchain.toml` targets, components, profile and `path` are lock rows, and tog provisions every component from the signed channel manifest (#213) |
| Resolution proxy (#68) | Designed and reviewed over four rounds (`docs/agent/DESIGNS.md` §6, #196); PR 0 evidence shipped (#209). PRs 1 to 4 shipped on Linux (#198, #199, #200, #202): Go resolves confined through the proxy. The rest is the current track, in the order FOLLOW-UPS.md "Next up, in order" gives. Today every other ecosystem's delegated tools (`add`/`remove`/`update`, missing-lock generation) run unsandboxed with network. Each moves into the sandbox with its own PR (#203 to #207), and PR 10 (#208) removes the unsandboxed mode |
| Linux sandbox on Ubuntu 24.04 | AppArmor-restricted user namespaces are detected; `doctor` agrees with bwrap and CI runs a 24.04 job (#173, #194) |
| User-experience review (2026-09-19) | Shipped on Linux: the CLI contract, help layout and `--json` promise (#122, #123); daily-use and error text — download progress, pip/npm guidance, the signing notice, distro `doctor` hints, error context (#125); docs and installer — a getting-started walkthrough, `install.sh --uninstall`, the `.tog/` commit rule (#128, this PR). `tog env` with the direnv recipe and an editor guide, plain-words help summaries, advisories routed through `tog: warning:`, and the once-per-store note on how a read-only environment is used (#108, #112, #106, #103). 2026-09-22: a bare `tog` syncs then shows the help (a short footer of next commands since 2026-10-03, #145), help screens open with START HERE and carry EXAMPLES. Still open from #106: lifting the sandbox stderr tail out of the Python tailor; from #103: `npm install` run directly is refused, not prevented |
| Commands sync on their own (2026-09-21) | `tog run`, `tog env` and `tog <script>` make the offline check `tog status` makes and sync first when the project is not synced or its inputs changed, one line on stderr saying why; a directory with no manifest says so instead of naming `tog sync`. The automatic store-maintenance warning is three `tog: warning:` lines at most (record, summary, once-per-store), the migration's own accounting stays with `tog gc --migrate-metadata`. 2026-09-22: every `tog: warning:` line is followed by a `tog:     fix:` line naming the command that resolves it; advisories with nothing to do became progress lines |
| No sync verb (2026-09-22, #143) | The cargo model: a bare `tog` is the setup step, and `--frozen`, `--fresh` and `--strict` go on it (no help screen after them, and no project is a failure). `sync`, `install` and `i` still work as hidden aliases but are not listed, completed or suggested; `tog help setup` and `tog help inputs` replace `tog help sync`. `tog build` syncs first when the ecosystem it builds is stale, as `run` does; `x` does not, because it runs in its own environment. Every "run 'tog sync'" message says `tog` |
| Updating tog itself (2026-09-21, #140) | `tog --version` prints the commit and its date (`build.rs`, `unknown build` outside a checkout); `tog update --self` replaces the binary from the newest GitHub release with `install.sh`'s asset names and checksum rule, refusing an unwritable directory before it downloads; `tog doctor` opens with a `version` row that says when a release is newer and `not checked` when offline. `v0.1.0` (Linux x86_64) is the first release, but the repository is private and both verbs ask GitHub anonymously, so they still report that the manifest cannot be read |
| Comment-audit leftovers | #88 to #96 shipped in #126 and #127: cargo scratch prefix, one ruby download, node messages, a dead python helper, registry init, `tar_command` platform, the value-flag rule, `object_path_exists` renamed |

## What is next

The ordered list is "Next up, in order" in [FOLLOW-UPS.md](FOLLOW-UPS.md),
followed by the rest of that file. Each line there points at the GitHub
issue that holds the detail. This file does not repeat the list, so the two
cannot disagree.

## How work happens here

- After a pull request merges, every problem found along the way and not
  shipped in it becomes its own GitHub issue (file paths, the options, the
  pick), with a one-line pointer in FOLLOW-UPS.md (see CLAUDE.md or
  AGENTS.md, which say the same).
- An agent implements; a *different* agent reviews adversarially; the review
  outcome (rounds, findings, what was fixed or declined) goes in the pull
  request description. Self-review does not count.
- The GitHub issue tracker holds the detail of open work and decisions.
  FOLLOW-UPS.md holds the order and one line per open item pointing at its
  issue. Designs live only in `docs/agent/DESIGNS.md`. When something ships,
  update `docs/human/ARCHITECTURE.md`, `CLI.md`, or `LIMITATIONS.md`, delete
  its FOLLOW-UPS line and anything it made stale in DESIGNS.md.
- Do not add new ledger, report, or evidence documents. Evidence goes in the
  PR; history is git.

# STATUS — where tog is, and what is next

Updated 2026-09-22.

## What tog is

One binary that owns the outer loop every language ecosystem shares:
provision a pinned toolchain, lock a dependency graph, realize it into an
immutable content-addressed store, project an environment, run your code.
Nix's model without Nix's interface. Seven ecosystems built: Python, npm,
Cargo, Go, Ruby, Elixir, .NET.

## Where we are

| Area | State |
|---|---|
| Seven ecosystems, Linux x86_64 | Shipped, acceptance-tested |
| macOS arm64 | Last run 2026-09-10, and it has not run since: eleven days and every PR below are Linux-verified only. The toolchain lock adds the two-machine lock diff to what that run has to cover. That run was green (`cargo test`, `gc --ignored` 3/3, sandboxed self-build), but the gate now also has to cover the Darwin identity goldens the schema successors added, which must stay byte-identical. It is deliberately the last item in FOLLOW-UPS.md |
| Python + npm on real projects | Proven (Next.js, vite, prisma, native addons, FastAPI). Latest hit rate: Python 26/30, npm 20/30 (`docs/agent/HITRATE.md`) |
| Other ecosystems | Fixture-proven only (`tests/`) |
| Store GC (root protection, object metadata, fail-closed sweep) | Shipped and independently reviewed on Linux |
| Module layout | Refactor finished 2026-09-12: one folder per layer, the `Tailor` trait and registry, layering enforced by `tests/architecture.rs` (rules in `docs/human/ARCHITECTURE.md`) |
| Policy admission gate (`tog audit`, company policy template) | Shipped and independently reviewed on Linux. Every record is compared, including the `rustfmt` record against its pin (2026-09-17). Closure records are signed (`tog keygen`, `TOG_SIGNING_KEY`) and `audit` verifies them against the machine policy's `[signing]` table; unsigned or pre-field records are `outdated`, a missing primary closure fails (2026-09-18, PRs #77 and #78) |
| `tog sync` preflight | Refused syncs no longer touch the store (2026-09-16, PR #40) |
| Toolchain lock (WP2) | Shipped on Linux 2026-09-21. A committed `tog-toolchain.toml` names the exact toolchain per ecosystem: the first writable sync writes it, every later sync honors it, a source that disagrees stops the sync, `tog --frozen` validates without writing, `tog update --toolchain [<eco>]` is the one writer that replaces it, `tog status` reports the verdict, and `tog x` keys its cache on the selected bundle. Described in `docs/human/ARCHITECTURE.md` "Toolchain lock"; the reasoning stays in `docs/agent/DESIGNS.md` §1. **Not yet run on two machines** — see below |
| Release catalog and trust (WP3), company layer (WP5) | Designed, not built (`docs/agent/DESIGNS.md` §2, §4) |
| User-experience review (2026-09-19) | Shipped on Linux: the CLI contract, help layout and `--json` promise (#122, #123); daily-use and error text — download progress, pip/npm guidance, the signing notice, distro `doctor` hints, error context (#125); docs and installer — a getting-started walkthrough, `install.sh --uninstall`, the `.tog/` commit rule (#128, this PR). `tog env` with the direnv recipe and an editor guide, plain-words help summaries, advisories routed through `tog: warning:`, and the once-per-store note on how a read-only environment is used (#108, #112, #106, #103). 2026-09-22: a bare `tog` syncs then shows the help, help screens open with START HERE and carry EXAMPLES. Still open from #106: lifting the sandbox stderr tail out of the Python tailor; from #103: `npm install` run directly is refused, not prevented |
| Commands sync on their own (2026-09-21) | `tog run`, `tog env` and `tog <script>` make the offline check `tog status` makes and sync first when the project is not synced or its inputs changed, one line on stderr saying why; a directory with no manifest says so instead of naming `tog sync`. The automatic store-maintenance warning is three `tog: warning:` lines at most (record, summary, once-per-store), the migration's own accounting stays with `tog gc --migrate-metadata`. 2026-09-22: every `tog: warning:` line is followed by a `tog:     fix:` line naming the command that resolves it; advisories with nothing to do became progress lines |
| No sync verb (2026-09-22, #143) | The cargo model: a bare `tog` is the setup step, and `--frozen`, `--fresh` and `--strict` go on it (no help screen after them, and no project is a failure). `sync`, `install` and `i` still work as hidden aliases but are not listed, completed or suggested; `tog help setup` and `tog help inputs` replace `tog help sync`. `tog build` syncs a stale project first, as `run` does; `x` does not, because it runs in its own environment. Every "run 'tog sync'" message says `tog` |
| Updating tog itself (2026-09-21, #140) | `tog --version` prints the commit and its date (`build.rs`, `unknown build` outside a checkout); `tog update --self` replaces the binary from the newest GitHub release with `install.sh`'s asset names and checksum rule, refusing an unwritable directory before it downloads; `tog doctor` opens with a `version` row that says when a release is newer and `not checked` when offline. No release is tagged yet, so until `v0.1.0` is pushed both verbs report that the manifest cannot be read |
| Comment-audit leftovers | #88 to #96 shipped in #126 and #127: cargo scratch prefix, one ruby download, node messages, a dead python helper, registry init, `tar_command` platform, the value-flag rule, `object_path_exists` renamed |

## What is next

The ordered list is issue #73; [FOLLOW-UPS.md](FOLLOW-UPS.md) keeps the
detail behind each item:

1. The two-machine toolchain-lock diff: sync one project on Linux and on an
   arm64 Mac, and prove the lock file and `tog status` are identical. It is
   the last thing between WP2 and done, and it is part of the macOS gate.

## How work happens here

- One folder per PR where possible (see CLAUDE.md).
- An agent implements; a *different* agent reviews adversarially; the review
  outcome (rounds, findings, what was fixed or declined) goes in the pull
  request description. Self-review does not count.
- Open work and decisions live only in FOLLOW-UPS.md. Designs live only in
  `docs/agent/DESIGNS.md`. When something ships, update
  `docs/human/ARCHITECTURE.md`, `CLI.md`, or `LIMITATIONS.md` and delete its
  FOLLOW-UPS item.
- Do not add new ledger, report, or evidence documents. Evidence goes in the
  PR; history is git.

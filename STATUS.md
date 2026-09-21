# STATUS — where tog is, and what is next

Updated 2026-09-21.

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
| macOS arm64 | Last run 2026-09-10, and it has not run since: eleven days and every PR below are Linux-verified only. That run was green (`cargo test`, `gc --ignored` 3/3, sandboxed self-build), but the gate now also has to cover the Darwin identity goldens the schema successors added, which must stay byte-identical. It is deliberately the last item in FOLLOW-UPS.md |
| Python + npm on real projects | Proven (Next.js, vite, prisma, native addons, FastAPI). Latest hit rate: Python 26/30, npm 20/30 (`docs/agent/HITRATE.md`) |
| Other ecosystems | Fixture-proven only (`tests/`) |
| Store GC (root protection, object metadata, fail-closed sweep) | Shipped and independently reviewed on Linux |
| Module layout | Refactor finished 2026-09-12: one folder per layer, the `Tailor` trait and registry, layering enforced by `tests/architecture.rs` (rules in `docs/human/ARCHITECTURE.md`) |
| Policy admission gate (`tog audit`, company policy template) | Shipped and independently reviewed on Linux. Every record is compared, including the `rustfmt` record against its pin (2026-09-17). Closure records are signed (`tog keygen`, `TOG_SIGNING_KEY`) and `audit` verifies them against the machine policy's `[signing]` table; unsigned or pre-field records are `outdated`, a missing primary closure fails (2026-09-18, PRs #77 and #78) |
| `tog sync` preflight | Refused syncs no longer touch the store (2026-09-16, PR #40) |
| Toolchain lock (WP2) | PR 1 shipped (2026-09-18): the pin tables are catalog rows (`src/kernel/toolchain/`), with the cross-platform selector, the typed source policy and legacy seeding, all unit-tested. PR 2b shipped: tar headers read directly. The identity schema successors `cargo-vendor/2`, `python-env/3`, `node-env/4` and `sdist-build/4` shipped 2026-09-20 (PRs #121 and #124), so #47 is unblocked. No lock file is written yet; the remaining PRs are in `docs/agent/DESIGNS.md` §1 |
| Release catalog and trust (WP3), company layer (WP5) | Designed, not built (`docs/agent/DESIGNS.md` §2, §4) |
| User-experience review (2026-09-19) | Shipped on Linux: the CLI contract, help layout and `--json` promise (#122, #123); daily-use and error text — download progress, pip/npm guidance, the signing notice, distro `doctor` hints, error context (#125); docs and installer — a getting-started walkthrough, `install.sh --uninstall`, the `.tog/` commit rule (#128, this PR). Still open: #103, #106, #108, and the vocabulary half of #112 |
| Comment-audit leftovers | #92 to #96 shipped in #126 (cargo scratch prefix, one ruby download, node messages, a dead python helper). #88 to #91 are in #127, still open |

## What is next

The ordered list is issue #73; [FOLLOW-UPS.md](FOLLOW-UPS.md) keeps the
detail behind each item:

1. Toolchain lock PR 3, the dormant lock core (#47), then #48 and #49.

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

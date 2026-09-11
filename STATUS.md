# STATUS — where blanket is, and what is next

Updated 2026-09-10. Read this instead of the archived plan; the archive
([docs/agent/PLAN-2026-09-09.md](docs/agent/PLAN-2026-09-09.md)) holds the
full design history and work-package specs.

## What blanket is

One binary that owns the outer loop every language ecosystem shares:
provision a pinned toolchain, lock a dependency graph, realize it into an
immutable content-addressed store, project an environment, run your code.
Nix's model without Nix's interface. Seven ecosystems built: Python, npm,
Cargo, Go, Ruby, Elixir, .NET.

## Where we are

| Area | State |
|---|---|
| Seven ecosystems, Linux x86_64 | Shipped, acceptance-tested |
| macOS arm64 | Shipped through 2026-09-05 (`dbf7ac4`); **nothing since then is Mac-validated**, including all GC-safety work |
| Python + npm on real projects | Proven (Next.js, vite, prisma, native addons, FastAPI) |
| Other ecosystems | Fixture-proven only (`tests/`) |
| Store GC (root protection, metadata migration, fail-closed sweep) | Shipped and merged to `main` 2026-09-10; independently reviewed and mutation-tested on Linux. **Mac gate (see below) has not run — owner waived it for the merge** |
| Toolchain lock design (WP2) | Designed, not implemented |
| Security/policy work (WP3), WP5 | Designed in the archived plan, not started |

The GC-safety work is the most recent large change. Every piece of it was
reviewed by an agent who did not write the code, fixed, re-checked, and
committed as a clean series on `wp-gc-safety` (see `git log` and
[docs/agent/REVIEW.md](docs/agent/REVIEW.md)).

## What is next (in order)

1. **macOS gate** — `cargo test` and
   `cargo test --test gc -- --ignored` on the Mac. The GC-safety work was
   merged with the owner's waiver; until this gate runs, treat GC behavior
   on the Mac as unverified. Run it before relying on GC on a Mac.
2. **Follow-up PRs** — see [FOLLOW-UPS.md](FOLLOW-UPS.md) for the list:
   C.10 test matrix (20 missing tests), B.5 lease threading, `fsroot.rs`,
   `Store::has` lock order, M05 mutation survivor.
3. **Supervision redesign** (FOLLOW-UPS.md Flag 1) — make the signal
   session per-operation so independent operations can supervise
   concurrently. Design change, needs its own review round.
4. **WP2 toolchain lock** — the next big feature: a committed lock naming
   exact toolchain versions per project. Design at
   `docs/agent/PLAN-2026-09-09.md` (WP2 sections).

## How work happens here

- Agents implement; a *different* agent reviews adversarially; fixes get
  mutation-checked; only then does code commit. Self-review does not count.
- The review ledger is [docs/agent/REVIEW.md](docs/agent/REVIEW.md) — check
  it before trusting a recent feature.
- Dated reports and evidence live in [docs/agent/](docs/agent/); everything
  a human needs is at the repo root and in [docs/human/](docs/human/).
- What has not been reviewed is not shipped; what is owed is in
  FOLLOW-UPS.md, never in someone's head.

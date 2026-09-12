# STATUS — where blanket is, and what is next

Updated 2026-09-12. Read this instead of the archived plan; the archive
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
| macOS arm64 | Mac gate run 2026-09-10 on the merged GC-safety tree (uncommitted fixes in the working tree): the tree did not compile on Darwin; after the fixes, `cargo test` green ×5, `gc --ignored` 3/3, sandboxed `blanket build` of blanket green. See the 2026-09-10 entry in [docs/agent/LINUX_PORT.md](docs/agent/LINUX_PORT.md) |
| Python + npm on real projects | Proven (Next.js, vite, prisma, native addons, FastAPI) |
| Other ecosystems | Fixture-proven only (`tests/`) |
| Store GC (root protection, metadata migration, fail-closed sweep) | Shipped and merged to `main` 2026-09-10; independently reviewed and mutation-tested on Linux. Mac gate run 2026-09-10 and green after fixes. **The gate also exposed two `gc_roots` failures that are not Mac-specific** (fixture id / A-R2 refusal message — merge `19b33e1` claimed them green); fixed, **not yet re-run on Linux and not independently reviewed** |
| Toolchain lock design (WP2) | Designed, not implemented |
| Policy admission gate (`blanket audit`, company policy template) | Shipped and merged to `main` 2026-09-12 (PR #28). Independently reviewed, two rounds, on Linux ([docs/agent/REVIEW.md](docs/agent/REVIEW.md) entry 7); three product decisions still await the owner in [FOLLOW-UPS.md](FOLLOW-UPS.md) Flag 3 and a hardening plan is Flag 4. Mac gate not run |
| Security/policy work (WP3), WP5 | Designed in the archived plan; `blanket audit` (row above) is the first shipped piece, the rest not started |

The GC-safety work is the most recent large change. Every piece of it was
reviewed by an agent who did not write the code, fixed, re-checked, and
committed as a clean series on `wp-gc-safety` (see `git log` and
[docs/agent/REVIEW.md](docs/agent/REVIEW.md)).

## What is next (in order)

A structural refactor is in progress alongside the items below; see
[REFACTOR.md](REFACTOR.md) for the stages and the change log. All four
stages landed 2026-09-12: folders per layer, `commands/` split, the `Tailor`
trait and registry, zero two-way module cycles, no file over 3,000 lines, no
function over 200, and `tests/architecture.rs` keeps it that way. A new
ecosystem is a folder plus one line, see
[docs/human/ADDING-A-TAILOR.md](docs/human/ADDING-A-TAILOR.md). Old
`crate::<module>` paths are gone, so an in-flight branch that touched a
moved file rebases by re-pointing its imports at the folder paths in
ARCHITECTURE.md's layout.

1. **Land the Mac-gate fixes** — commit the 2026-09-10 working-tree fixes
   (Darwin compile errors, symlinked-`TMPDIR` fixtures, APFS test skips,
   `gc_roots` fixture id, `roots_for_sweep` unusable-record routing), re-run
   `cargo test` and `cargo test --test gc_roots` on Linux, and get the one
   production change (`Store::roots_for_sweep`) an independent review.
2. **Decide the `blanket audit` open questions** — the gate is merged with
   defensible defaults, but FOLLOW-UPS.md Flag 3 still needs an answer
   (D1 toolchain-only records pass uncompared; D2 unchecked exits 1 on
   first adoption; D3 the gate does not authenticate the record). Then work
   the Flag 4 hardening plan, starting with an independent recheck of the
   round-2 nit fixes; the Mac gate is deliberately its last item.
3. **Follow-up PRs** — see [FOLLOW-UPS.md](FOLLOW-UPS.md) for the list:
   C.10 test matrix (20 missing tests), B.5 lease threading, `fsroot.rs`,
   `Store::has` lock order, M05 mutation survivor.
4. **Supervision redesign** (FOLLOW-UPS.md Flag 1) — make the signal
   session per-operation so independent operations can supervise
   concurrently. Design change, needs its own review round.
5. **WP2 toolchain lock** — the next big feature: a committed lock naming
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

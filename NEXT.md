# NEXT.md — frozen index (2026-09-06)

The live plan is [PLAN.md](PLAN.md). This file exists only because code
comments, user-facing strings, HITRATE.md and LIMITATIONS.md cite
"NEXT.md item N". Every item below has shipped; the numbers must not be
reused. Full write-ups are in the git history of this file (last complete
version: commit 5ce0363).

| Item | What it was | Shipped |
|---|---|---|
| 1 | Hit-rate measurement harness (`tests/hitrate.py`, HITRATE.md) | 2026-09-02 |
| 2 | `blanket run dev` / `test`: package.json scripts in the projected env | 1a1308c |
| 3 | Permissive by default, strict as a switch (`.blanket/policy.toml`) | 3a3d96c |
| 4 | Git dependencies realized by commit (npm, Python, Cargo; `src/gitsrc.rs`) | 2026-09-06 |
| 5 | Built-in install-time artifact policy (`src/artifacts.rs`, electron provisioning) | 2026-09-06 |
| 7 | pnpm v9/v6 and Yarn classic lockfile importers (`src/npm_lock_import.rs`) | 2026-09-06 |
| 8 | Constraint-aware CPython selection; 3.10/3.11/3.14 pins | 2026-09-05 |
| 9 | Wheel `.data/headers` scheme | 2026-09-05 |
| 10 | Manifest coverage: Poetry, PDM, setup.py egg_info, requirements dirs (`src/manifest.rs`) | 2026-09-06 |
| 11 | Build isolation for compiled sdists (PEP 517 envs, Rust vendoring) | 2026-09-05 |
| 12 | Pinned native libraries, Linux (`src/nativelibs.rs`, libset v3) | 2026-09-06 |
| 13 | Store GC (`blanket gc`) | 2026-09-06 |

(There was no item 6.) Anything these items left open is listed under WP4 in
PLAN.md. When touching code that still says "deferred to NEXT.md item 4",
replace the text with the behaviour it describes; that deferral no longer
exists.

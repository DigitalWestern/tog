# Implementation-plan re-review — 2026-09-09

Reviewed the 1,962-line working-tree plan against the implementation on
`wp-gc-safety` at `1e065a4`, including the uncommitted Package A changes,
`ARCHITECTURE.md`, `CLAUDE.md`, `LIMITATIONS.md`, and the review ledger.
The owner subsequently requested that the findings be incorporated into the
plan for implementation. This is a design review, not independent approval
of Package A or any future implementation.

**Verdict before revision: change before implementation.** The product
decisions stand: an unconditional supervisor, conservative retention, jobs
postponing cleanup, automatic metadata migration, two platforms, and
configurable publisher trust. The defects were in how those decisions were
translated into APIs, sequencing, and acceptance tests. The revised plan
addresses the findings below and gives Luna a bounded starting sequence.

Original-plan line numbers below refer to the version reviewed, before edits.

| Finding | Evidence and consequence | Required correction incorporated into the plan |
|---|---|---|
| **R1 — P1: lock order contradicts cold `x`** | B.3, original line 945, puts the per-root lock last. `xrun::run` takes it before checking/realizing the environment, which then takes cache and publication locks. `xrun::clean` discovers the originating store only after locking the candidate. | Use activity → x-root → project transaction (C) → cache lease → publication. Discover a cleanup candidate's store without relying on the result for deletion, acquire activity, acquire x-root, and revalidate. Preserve the guard for pnpm's borrowed `x` environment too. |
| **R2 — P1: a process-global presence check is not a lifetime guarantee** | B.1/B.4/B.5, original lines 899–1045. Thread B can pass `require_activity` using thread A's guard, then continue after A drops it. Reusing an exclusive descriptor for unrelated operations also defeats in-process exclusion. `Store::has` currently returns `bool`, so it cannot return the proposed error. | Require an explicit operation-owned activity token in store-consuming library APIs. Clone/borrow it deliberately across nested work. Serialize independent exclusive operations locally and across processes. Keep the cache-lease registry's different sharing semantics separate. Make `has` fallible. |
| **R3 — P1: replacing two `exec` calls misses existing children** | B.6, original line 1049. npm scripts use `Command::status` at `main.rs:1743`; delegates and sandbox runners also wait on children. A signal terminating the Blanket parent can release activity while its child keeps using the store. | Audit all store-consuming spawn/status/output paths, including npm pre/main/post scripts, delegates, builds, and fmt. Use common signal-aware spawn/wait machinery. Hold activity through the entire operation and all awaited children. |
| **R4 — P1: the signal recipe has startup and teardown races** | B.6 sets `CHILD_PID` only after spawn. A TERM in that interval is lost or targets an invalid PID; a stale PID after reap can target another process. Global handler state is not restored between calls. Group-directed TERM can already reach the child, so unconditional forwarding can duplicate delivery. | Define the supervised session lifecycle, pending cancellation, mask/handler restoration, positive live-PID checks, and serialized use. Test startup, failed spawn, reap, sequential children, terminal groups, and parent-only signals. Document the remaining group-TERM and SIGKILL boundaries rather than promising exact signal equivalence. |
| **R5 — P1: automatic migration has no legal lock transition** | D.3 says explicit migration only; D.9.5 overrides that. B acquires shared protection before use and forbids upgrading it, while migration requires exclusive protection. D.5 also promises identical dry-run planning without migration. | Add a maintenance preflight that releases its short shared probe before trying exclusive protection, re-reads under exclusive protection, and defers visibly if busy. Never upgrade an active job. Dry-run runs the same pure adapters in memory; real GC publishes proven upgrades before taking its deletion snapshot. |
| **R6 — P1: root-before-closure does not protect projection publication** | C.6, original line 1361. Python moves backups and switches `.venv` at `project.rs:826–836` before `write_closure`; Node likewise switches workspace links before the closure. A crash can leave a visible environment or moved user backup without a durable root reference. | Split preparation, durable root union, and projection/closure publication. Reserve backup destinations and protect them before moving user data. Add fault injection around actual symlink switches and backup moves, not only JSON writes. |
| **R7 — P1: sibling stores share a deletion namespace** | C.3/D.7 derive forests/backups from `store.root.parent()`. Two supported `BLANKET_STORE` paths under the same parent have separate activity locks and root registries but share those directories. GC in A can delete B's projection. | Put new projections/backups under the owning store; keep legacy sibling references explicitly typed and retention-only. Never automatically sweep the old shared namespace. B disables that unsafe sweep before C's namespace migration. Test two sibling stores with an active job and aged projections. |
| **R8 — P1: configurable trust conflicts with the WP2 replay contract** | WP2 and `ARCHITECTURE.md:808–841` require a shipped append-only host allowlist and say locks never become invalid. WP3 permits private publishers and key revocation, but mandatory policy loading is deferred to WP5, which depends on WP3. A lock-supplied digest alone is not publisher authentication. | Establish the shared source-policy interface in WP2 and protected policy loading in WP3 before authenticated refresh. Keep publisher authentication, endpoint permission, and credentials distinct fields in one mechanism. Define trust rechecks on cached/replayed locks, revocation refusals, and offline proof requirements. Catalog refresh alone still cannot change locked bytes. |
| **R9 — P2: the corruption recovery command depends on parsing corruption** | C.9 tells users to forget malformed or symlinked records. Existing `lookup_root` calls `roots()` and parses all records; it cannot recover through the proposed fail-closed reader. | Separate strict sweep decoding from diagnostic enumeration and exact-key, descriptor-relative forgetting. A corrupt unrelated record must not prevent forgetting a selected key. Never follow a registry symlink. |
| **R10 — P2: legacy-root transition during normal publication is unspecified** | C.6 must union with a previous record, but C.8 describes only explicit `gc --register` import. Resyncing one ecosystem can otherwise replace a pathname-only record without retaining the other ecosystems. Deleting `store_from_closure_body` also breaks its `x` cleanup caller. | Before any projection change, import all legacy closures or refuse with recovery instructions. Use the same declarative readers for explicit registration and guarded publication; ordinary sweeps stay read-only. Replace `x` store discovery with explicit marker provenance, retaining a narrow declarative legacy reader. |
| **R11 — P2: producer counts are mistaken for a completeness proof** | D.2/D.3 mandate 19 adapters but identity kinds have multiple layouts (`sdist-build/2` and `/3`, fingerprint versus object-id references). The `hex-deps` row omits package tarball digests; `fetch` stores sha1 and sha512 as well as sha256, while D.7 only opens sha256. | Audit by kind **and schema**, with a coverage matrix, rejected unknown layouts, and an unresolved result when exact refs cannot be proved. Include package artifact digests, supported cache algorithms, historical build-input gaps, and graph validation before certifying metadata. |

Additional corrections incorporated:

- Raw-byte root hashing preserves every UTF-8 key; the earlier claim that it
  re-keys every record was wrong. New non-UTF-8 paths use lossless keys;
  ambiguous old lossy records are never silently attributed to a new path.
- The SIGPIPE explanation was wrong: Rust normally resets SIGPIPE to default
  before child exec. Preserve the toolchain's actual behavior and test it.
  See the [Rust behavior table](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/on-broken-pipe.html).
- Signal masks and handled dispositions have distinct fork/exec behavior;
  installing a no-op handler alone does not solve the spawn interval. See
  [signal semantics](https://www.man7.org/linux/man-pages/man7/signal.7.html).
- Removed stale September 12 review waits, duplicate status classifications,
  unsupported blanket independence claims, and renewed approval prompts for
  already-authorized or routine implementation choices.
- Scheduled the archive-header rewrite before its second consumer; made the
  future fsroot helper extend the helper extracted by C; stopped requiring
  invented hit-rate measurements in every PR.

**Implementation handoff:** isolate and independently review Package A first;
then implement B, C, and D in order using the revised contracts and regression
cases. The plan review does not clear code-review or Mac execution gates.
Future trust-key provisioning remains an explicit WP3 input, not a blocker
for the GC work tomorrow.

Validation: source/contract inspection; `git diff --check`; balanced Markdown
fences and parsed JSON examples; a stale-contract scan of the current plan;
and an executable hash comparison confirming unchanged UTF-8 keys and distinct
raw-byte keys for the former non-UTF-8 collision. These checks passed after
correction of the illustrative metadata JSON. No Rust source was changed by
this review and no implementation test or Mac execution result is claimed.

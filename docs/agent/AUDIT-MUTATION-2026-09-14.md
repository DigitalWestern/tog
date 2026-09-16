# Mutation check of `src/commands/audit.rs` — 2026-09-14

FOLLOW-UPS.md Flag 4 item **H4**. The repo's rule is that fixes get
mutation-checked; `blanket audit` had never been. This is a by-hand check:
no mutation-testing crate, every mutant is an explicit one-line edit that is
reproducible from the table below.

**Result: 31 mutants, 31 killed. One survivor in round 1 (M09), killed by a
new test; round 2 re-ran the whole set with that test in place and every
mutant is red.**

## Method

- Target: `src/commands/audit.rs` only. The mutants cover every decision the
  item names — each clause of `Verdict::passes`, `Report::passes`, every
  `State` arm of `freshness_from_state`, the `policy::KINDS` membership test
  and the `policy::denied` call in `evaluate`, `check_name`'s comparison —
  plus the three guards in `freshness` and the missing-exception-record
  branch of `evaluate`, which are the same kind of admission decision.
- Test set per mutant: `cargo test --lib --test cli audit`. Those are the
  only two binaries that hold audit tests (16 unit tests in
  `src/commands/audit.rs::tests` after this round, and
  `cli::audit_is_an_offline_admission_gate_over_recorded_exceptions`); every
  other binary reports `0 passed … filtered out` under that filter.
- Driver: `docs/agent/audit-mutation-2026-09-14/run.py`, with the 31
  mutants as (old snippet, new snippet) pairs in `mutants.py` beside it.
  It runs a clean baseline first and stops if it is red; then, per mutant,
  asserts the source snippet it replaces is unique, runs the test set,
  records the exit code and the failing tests, restores a pristine copy of
  the file and compares the restore byte-for-byte before the next mutant.
  A compile error or other non-test failure under a mutant is reported as
  such, not as a kill, and the driver exits nonzero unless every requested
  mutant was killed by a test. Re-run the whole set with
  `python3 docs/agent/audit-mutation-2026-09-14/run.py`, or one mutant by
  id (`... run.py M09`).
- Baseline before round 1: 15 unit tests + 1 CLI test, exit 0.

## The survivor

**M09 — `Report::passes`: `.all(Verdict::passes)` → `.any(Verdict::passes)`.**
Every existing test built a `Report` from exactly one verdict, where "all
pass" and "any passes" cannot be told apart. With `any`, a project whose
`rustfmt` closure is clean and whose `python` closure has a denied exception
would have audited **clean and exited 0** — the gate would wave through the
build it exists to stop.

Killed by a new unit test,
`commands::audit::tests::one_failing_closure_fails_the_whole_report`: it
judges a clean toolchain-only closure together with a closure carrying a
denied `git-dependency` exception, in both orders, and asserts exactly one
verdict passes while the report does not (`Report::passes` and the JSON
`passed` field; text rendering is not asserted). It
also asserts an all-clean two-verdict report still passes, so the negative
assertion is not vacuous.

No other survivor. No production code changed.

## The table

Round 1 is the state before the new test; round 2 is the same 31 mutants
re-run with it applied, proving no kill was lost. "+N more" counts the other
tests that also went red.

| # | Site | Mutation | Source change | Round 1 | Round 2 |
|---|---|---|---|---|---|
| M01 | Verdict | denied.is_empty() -> true | `self.denied.is_empty() && self.unknown.is_empty()` → `true && self.unknown.is_empty()` | `audit_reads_the_project_without_a_store` (+5 more) | `audit_reads_the_project_without_a_store` (+6 more) |
| M02 | Verdict | denied.is_empty() -> false | `self.denied.is_empty() && self.unknown.is_empty()` → `false && self.unknown.is_empty()` | `clean_when_every_recorded_exception_is_permitted` (+2 more) | `clean_when_every_recorded_exception_is_permitted` (+3 more) |
| M03 | Verdict | unknown.is_empty() -> true | `&& self.unknown.is_empty() && matches!(` → `&& true && matches!(` | `unknown_kind_is_never_permitted_and_no_policy_can_name_it` | `unknown_kind_is_never_permitted_and_no_policy_can_name_it` |
| M04 | Verdict | unknown.is_empty() -> false | `&& self.unknown.is_empty() && matches!(` → `&& false && matches!(` | `clean_when_every_recorded_exception_is_permitted` (+2 more) | `clean_when_every_recorded_exception_is_permitted` (+3 more) |
| M05 | Verdict | freshness arm drops ToolchainOnly | `Freshness::Current \| Freshness::ToolchainOnly )` → `Freshness::Current )` | `toolchain_only_closure_is_judged_but_not_compared` | `one_failing_closure_fails_the_whole_report` (+1 more) |
| M06 | Verdict | freshness arm also accepts Stale | `Freshness::Current \| Freshness::ToolchainOnly )` → `Freshness::Current \| Freshness::ToolchainOnly \| Freshness::Stale(_) )` | `every_status_state_but_synced_fails` (+2 more) | `every_status_state_but_synced_fails` (+2 more) |
| M07 | Verdict | freshness matches! -> true | `&& matches!( self.freshness, Freshness::Current \| Freshness::ToolchainOnly )` → `&& true` | `every_status_state_but_synced_fails` (+3 more) | `every_status_state_but_synced_fails` (+3 more) |
| M08 | Verdict | freshness matches! -> false | `&& matches!( self.freshness, Freshness::Current \| Freshness::ToolchainOnly )` → `&& false` | `clean_when_every_recorded_exception_is_permitted` (+2 more) | `clean_when_every_recorded_exception_is_permitted` (+3 more) |
| M09 | Report | all -> any | `self.verdicts.iter().all(Verdict::passes)` → `self.verdicts.iter().any(Verdict::passes)` | **survived** | `one_failing_closure_fails_the_whole_report` |
| M10 | Report | -> true | `self.verdicts.iter().all(Verdict::passes)` → `true` | `audit_reads_the_project_without_a_store` (+4 more) | `audit_reads_the_project_without_a_store` (+5 more) |
| M11 | freshness_from_state | Synced -> Stale | `State::Synced => Freshness::Current,` → `State::Synced => Freshness::Stale("mutant".into()),` | `clean_when_every_recorded_exception_is_permitted` (+5 more) | `clean_when_every_recorded_exception_is_permitted` (+5 more) |
| M12 | freshness_from_state | NotSynced -> Current | `State::NotSynced => Freshness::Stale("no closure for these inputs".into()),` → `State::NotSynced => Freshness::Current,` | `every_status_state_but_synced_fails` | `every_status_state_but_synced_fails` |
| M13 | freshness_from_state | Changed -> Current | `State::Changed(files) => { Freshness::Stale(format!("{} changed since the last sync", files.join(", "))) }` → `State::Changed(_files) => Freshness::Current,` | `every_status_state_but_synced_fails` (+2 more) | `every_status_state_but_synced_fails` (+2 more) |
| M14 | freshness_from_state | ProjectionMissing -> Current | `State::ProjectionMissing(what) => { Freshness::Stale(format!("{what} is not the synced projection")) }` → `State::ProjectionMissing(_what) => Freshness::Current,` | `every_status_state_but_synced_fails` (+1 more) | `every_status_state_but_synced_fails` (+1 more) |
| M15 | freshness_from_state | ForeignPlatform -> Current | `State::ForeignPlatform(platform) => { Freshness::Stale(format!("synced on {platform}, not this host")) }` → `State::ForeignPlatform(_platform) => Freshness::Current,` | `every_status_state_but_synced_fails` (+1 more) | `every_status_state_but_synced_fails` (+1 more) |
| M16 | freshness_from_state | Unchecked -> Current | `State::Unchecked(why) => Freshness::Unchecked(why),` → `State::Unchecked(_why) => Freshness::Current,` | `every_status_state_but_synced_fails` (+1 more) | `every_status_state_but_synced_fails` (+1 more) |
| M17 | freshness_from_state | Unchecked -> Stale | `State::Unchecked(why) => Freshness::Unchecked(why),` → `State::Unchecked(why) => Freshness::Stale(why),` | `every_status_state_but_synced_fails` (+1 more) | `every_status_state_but_synced_fails` (+1 more) |
| M18 | evaluate | KINDS membership inverted | `if !policy::KINDS.contains(&exception.kind.as_str()) {` → `if policy::KINDS.contains(&exception.kind.as_str()) {` | `audit_reads_the_project_without_a_store` (+7 more) | `audit_reads_the_project_without_a_store` (+7 more) |
| M19 | evaluate | every kind is known (never unknown) | `if !policy::KINDS.contains(&exception.kind.as_str()) {` → `if false {` | `unknown_kind_is_never_permitted_and_no_policy_can_name_it` | `unknown_kind_is_never_permitted_and_no_policy_can_name_it` |
| M20 | evaluate | every kind is unknown | `if !policy::KINDS.contains(&exception.kind.as_str()) {` → `if true {` | `audit_reads_the_project_without_a_store` (+7 more) | `audit_reads_the_project_without_a_store` (+7 more) |
| M21 | check_name | != -> == | `if stem != closure.ecosystem {` → `if stem == closure.ecosystem {` | `audit_reads_the_project_without_a_store` (+11 more) | `audit_reads_the_project_without_a_store` (+12 more) |
| M22 | check_name | always Ok | `if stem != closure.ecosystem {` → `if false {` | `closure_named_for_another_ecosystem_is_refused` | `closure_named_for_another_ecosystem_is_refused` |
| M23 | check_name | file_stem -> file_name (ignore the stem) | `.file_stem()` → `.file_name()` | `audit_reads_the_project_without_a_store` (+11 more) | `audit_reads_the_project_without_a_store` (+12 more) |
| M24 | evaluate | denied() inverted | `} else if policy::denied(policy, &exception.kind) {` → `} else if !policy::denied(policy, &exception.kind) {` | `audit_reads_the_project_without_a_store` (+8 more) | `audit_reads_the_project_without_a_store` (+9 more) |
| M25 | evaluate | nothing is ever denied | `} else if policy::denied(policy, &exception.kind) {` → `} else if false {` | `audit_reads_the_project_without_a_store` (+6 more) | `audit_reads_the_project_without_a_store` (+7 more) |
| M26 | evaluate | everything is denied | `} else if policy::denied(policy, &exception.kind) {` → `} else if true {` | `clean_when_every_recorded_exception_is_permitted` (+4 more) | `clean_when_every_recorded_exception_is_permitted` (+4 more) |
| M27 | evaluate | no-record guard inverted (stale wins/loses swapped) | `if !matches!(freshness, Freshness::Stale(_)) {` → `if matches!(freshness, Freshness::Stale(_)) {` | `unchecked_closure_is_reported_unchecked_not_clean` | `unchecked_closure_is_reported_unchecked_not_clean` |
| M28 | evaluate | no exception record is never downgraded to unchecked | `if !matches!(freshness, Freshness::Stale(_)) {` → `if false {` | `unchecked_closure_is_reported_unchecked_not_clean` | `unchecked_closure_is_reported_unchecked_not_clean` |
| M29 | freshness | rustfmt name alone buys toolchain-only | `if closure.ecosystem == "rustfmt" && closure.body.get("inputs").is_none() {` → `if closure.ecosystem == "rustfmt" {` | `toolchain_only_closure_is_judged_but_not_compared` | `toolchain_only_closure_is_judged_but_not_compared` |
| M30 | freshness | orphaned-closure check disabled | `if !present.contains(&closure.ecosystem.as_str()) {` → `if false {` | `stale_closure_never_audits_clean` (+1 more) | `stale_closure_never_audits_clean` (+1 more) |
| M31 | freshness | missing-platform check inverted | `if closure.platform.is_none() {` → `if closure.platform.is_some() {` | `clean_when_every_recorded_exception_is_permitted` (+5 more) | `clean_when_every_recorded_exception_is_permitted` (+5 more) |

## Not covered

- `render` (text and JSON shaping) was not mutated line by line; the item
  names the decision points, not the formatter, and the existing tests
  already assert the rendered strings byte-for-byte.
- `effective_policy`, `read_policy_file` and `policy::union` are
  `kernel/policy` surface, checked by the 2026-09-11 round, not re-mutated
  here.
- Linux x86_64 only. The audit path has no platform-specific behaviour
  beyond `Platform::host()`, which M31 exercises through the
  recorded-platform guard, but the mutants were not re-run on Darwin.

# D.10 acceptance transcript — GC safety Package D (rewrite)

Recorded 2026-09-09 on Fedora 44 / x86_64 (`m6-fedora`), against the
uncommitted `wp-gc-safety` working tree. **Linux only. Nothing here was run on
macOS**, and none of it has been independently reviewed — see the Package D
row in `REVIEW.md`.

Environment: `TMPDIR=/home/ethan/.cache/blanket-testtmp` (disk-backed, not the
12 GB tmpfs), `BLANKET_SANDBOX_TESTS=required`, and a disposable
`BLANKET_STORE` for the `--ignored` targets. No real store was swept at any
point.

---

## 1. Gates

```
### cargo fmt --check
(clean, no output)

### cargo test (offline suite)
test result: ok. 510 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.97s
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.55s
test result: ok. 0 passed; 0 failed; 10 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 0.21s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 6 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 4.02s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 17 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.62s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The offline suite was run **12 consecutive times** while establishing that it
is deterministically green; all 12 passed. A single green run does not
establish this, which is how the supervision collision in section 5 was found.

---

## 2. The 27 named D.10 cases, each run on its own

```
### gc::tests — 25 named cases, run individually
test gc::tests::shared_dependency_survives_forgetting_one_of_two_projects ... ok
test gc::tests::after_forgetting_both_the_shared_dependency_is_collectible_when_age_allows ... ok
test gc::tests::corrupt_late_root_deletes_nothing_earlier ... ok
test gc::tests::corrupt_late_metadata_deletes_nothing_earlier ... ok
test gc::tests::missing_transitive_metadata_aborts_the_sweep ... ok
test gc::tests::dependency_cycle_terminates_and_retains_both ... ok
test gc::tests::unknown_metadata_schema_blocks_destructive_gc ... ok
test gc::tests::invalid_reference_in_metadata_is_an_error ... ok
test gc::tests::traversal_string_in_a_reference_is_rejected ... ok
test gc::tests::symlink_replacement_of_a_candidate_stops_that_deletion ... ok
test gc::tests::type_change_of_a_candidate_stops_that_deletion ... ok
test gc::tests::dry_run_removes_no_root_migrates_nothing_and_refreshes_no_timestamp ... ok
test gc::tests::dry_run_and_real_sweep_produce_the_same_plan ... ok
test gc::tests::collect_legacy_cannot_override_incomplete_evidence ... ok
test gc::tests::legacy_metadata_with_an_adapter_migrates_and_validates_the_id ... ok
test gc::tests::legacy_metadata_with_an_unknown_kind_stays_blocked_and_is_named ... ok
test gc::tests::cache_hit_does_not_certify_old_inferred_metadata ... ok
test gc::tests::automatic_maintenance_precedes_shared_job_activity ... ok
test gc::tests::busy_automatic_maintenance_defers_without_lock_upgrade ... ok
test gc::tests::migration_failure_never_starts_deletion ... ok
test gc::tests::dry_run_adapts_in_memory_and_matches_real_plan_at_the_same_time ... ok
test gc::tests::sha1_sha256_and_sha512_artifacts_follow_retained_object_digests ... ok
test gc::tests::hex_package_tarballs_remain_cached_for_a_retained_hex_object ... ok
test gc::tests::retained_backup_and_nested_hex_projection_are_not_deleted ... ok
test gc::tests::partial_execution_error_reports_completed_deletions_honestly ... ok

### tests/cli.rs — the two x-cleanup cases and the C.10 origin case
test failed_x_cleanup_retains_the_root_record ... ok
test busy_x_cleanup_retains_the_root_record ... ok
test x_cleanup_revalidates_explicit_or_legacy_origin ... ok
```

Two of the 27 bullets are the `x --clean` pair; they live in `tests/cli.rs`
because `xrun::clean` reads `HOME`, which is process-global, so they are
driven through the real binary with a per-child `HOME` and `BLANKET_STORE`.
Both are offline. The third case shown is the C.10 origin item.

The remaining D.10 bullet — "adapter tests per identity kind and shipped
schema" — is section 3.

---

## 3. Adapter coverage matrix and producer drift checks

```
### adapter coverage matrix (objmeta::tests)
test objmeta::tests::adapter_go_go_toolchain_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_cargo_vendor_refuses_a_git_crate_whose_source_object_is_gone ... ok
test objmeta::tests::adapter_git_source_git_source_2_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_go_modcache_refuses_an_ambiguous_toolchain_match ... ok
test objmeta::tests::adapter_go_modcache_go_modcache_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_cargo_vendor_cargo_vendor_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_go_modcache_refuses_a_collected_toolchain ... ok
test objmeta::tests::adapter_beam_beam_toolchain_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_cpython_v1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_dotnet_sdk_dotnet_sdk_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_hex_deps_refuses_an_unmatched_beam_fingerprint ... ok
test objmeta::tests::adapter_never_re_adapts_an_already_certified_record ... ok
test objmeta::tests::adapter_node_env_refuses_an_unshipped_schema ... ok
test objmeta::tests::adapter_node_env_refuses_an_unknown_identity_input ... ok
test objmeta::tests::adapter_nodejs_v1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_node_env_node_env_3_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_nuget_packages_nuget_packages_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_node_env_keeps_each_published_integrity_algorithm ... ok
test objmeta::tests::adapter_refuses_a_schemaless_kind_that_grew_a_schema ... ok
test objmeta::tests::adapter_python_env_refuses_a_fingerprint_with_no_matching_build ... ok
test objmeta::tests::adapter_native_libs_refuses_an_older_libset_version ... ok
test objmeta::tests::adapter_refuses_a_syntactically_valid_unknown_layout ... ok
test objmeta::tests::adapter_native_libs_refuses_a_manifest_this_build_cannot_reproduce ... ok
test objmeta::tests::adapter_rejects_a_traversal_string_in_a_reference ... ok
test objmeta::tests::adapter_python_env_python_env_2_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_hex_deps_hex_deps_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_refuses_a_pinned_toolchain_missing_its_artifact_digest ... ok
test objmeta::tests::adapter_python_env_python_env_2_resolves_a_fast_path_fingerprint ... ok
test objmeta::tests::adapter_ruby_ruby_toolchain_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_ruby_gems_ruby_gems_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_rustfmt_rustfmt_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_rust_rust_toolchain_1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_rust_refuses_when_any_component_digest_is_missing ... ok
test objmeta::tests::adapter_native_libs_recovers_the_pinned_manifest_digests ... ok
test objmeta::tests::adapter_sdist_build_refuses_a_platform_mismatched_interpreter ... ok
test objmeta::tests::adapter_uv_v1_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_sdist_build_sdist_build_2_recovers_the_expected_dependencies ... ok
test objmeta::tests::adapter_sdist_build_schemas_do_not_share_a_path ... ok
test objmeta::tests::adapter_sdist_build_sdist_build_3_recovers_the_expected_dependencies ... ok
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 471 filtered out; finished in 0.00s

### producer drift checks (adapter pinned to the producer's own identity function)
test npm::tests::legacy_adapter_recovers_the_pinned_node_artifact ... ok
test ruby::tests::legacy_adapter_recovers_the_pinned_ruby_artifact ... ok
test cargo::tests::legacy_adapter_recovers_the_pinned_rust_components ... ok
test rustfmt::tests::legacy_adapter_recovers_the_paired_rust_object_and_component ... ok
test dotnet::tests::legacy_adapter_recovers_the_pinned_sdk_artifact ... ok
test golang::tests::legacy_adapter_recovers_the_pinned_go_artifacts ... ok
test elixir::tests::legacy_adapter_matches_the_beam_object_by_its_own_fingerprint ... ok
test elixir::tests::legacy_adapter_recovers_the_beam_toolchain_artifacts ... ok
test python::tests::legacy_adapters_recover_the_pinned_cpython_and_uv_artifacts ... ok
test nativelibs::tests::legacy_adapter_recovers_every_pinned_library_and_invents_none ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 0.00s

### C.10 items D interacts with
test gc::tests::crash_after_record_write_leaves_extra_protection ... ok
test gc::tests::crash_before_record_write_publishes_no_closure ... ok
test gc::tests::legacy_record_still_blocks_until_registered_or_forgotten ... ok
test gc::tests::legacy_shared_forests_and_backups_are_never_swept ... ok
test gc::tests::forest_retention_works_with_the_project_directory_absent ... ok
```

One `adapter_<kind>_<schema>_recovers_the_expected_dependencies` per row of
the matrix in `ARCHITECTURE.md`, plus the refusal cases the plan asks for:
a required input removed one at a time, an ambiguous match, a collected build
input, an unshipped schema, a schema on a kind whose producer never wrote one,
a traversal string in a reference, and a record that is already certified.

The ten `legacy_adapter*` drift checks build the identity with the
**producer's own identity function** and assert the adapter recovers exactly
what that producer supplies at commit. They cover the ten pin-based producers.
They do **not** cover the six plan-based producers (`node-env`, `python-env`,
`cargo-vendor`, `go-modcache`, `ruby-gems`, `hex-deps`, `nuget-packages`,
`sdist-build`), whose fixtures were hand-derived from a call-site audit. That
is the single biggest gap in this evidence and the first thing a review round
should attack — see the ordered list at the end of §5.4 of the plan.

---

## 4. `--ignored` targets

Every one run with `--test-threads=1` (see section 5).

```
cargo test --test gc              -- --ignored --test-threads=1    3 passed
cargo test --test fmt_e2e         -- --ignored --test-threads=1    2 passed
cargo test --test git_deps        -- --ignored --test-threads=1    4 passed
cargo test --test build_isolation -- --ignored --test-threads=1    3 passed
cargo test --test cargo_e2e       -- --ignored --test-threads=1    1 passed
cargo test --test sdist_build     -- --ignored --test-threads=1    1 passed
cargo test --test native_libs     -- --ignored --test-threads=1    1 passed
cargo test --test linux_python    -- --ignored --test-threads=1    1 passed
cargo test --test go_e2e          -- --ignored --test-threads=1    1 passed
cargo test --test ruby_e2e        -- --ignored --test-threads=1    1 passed
cargo test --test elixir_e2e      -- --ignored --test-threads=1    1 passed
cargo test --test dotnet_e2e      -- --ignored --test-threads=1    2 passed
cargo test --test npm_scripts     -- --ignored --test-threads=1    6 passed
cargo test --test deps_e2e        -- --ignored --test-threads=1   10 passed
```

One caveat on `npm_scripts`, recorded rather than smoothed over: on its first
run it reported 2 of 6 failing
(`permissive_install_script_is_cached_but_rejected_strict` and one other). That
run was concurrent with eight foreground full-suite passes sharing the same
target directory. Re-run in isolation it is 6/6, as shown above. The failing
assertions were not captured before the run was overwritten, so the cause is
**not** established — only that it does not reproduce in isolation. A review
round should run this target on a quiet machine before trusting it.

These matter beyond coverage: they are the only evidence that the producers
still publish correct dependency evidence after `ObjectDeps::from_identity`
and the inferring `Store::commit` were deleted, and after `cargo-vendor`
stopped recording the Rust toolchain. A producer that published a set the
adapter cannot reproduce would fail here on the second sync, because
`validate_cached_dependency_evidence` turns a cache hit with different
evidence into a hard error.

---

## 5. A pre-existing Package B defect this work surfaced

The supervisor owns process-wide signal dispositions and **rejects** a second
concurrent child in the same process:

```
another child is already being supervised in this process; supervision owns
process-wide signal dispositions, so its children are run one at a time
```

That is correct for production, where every entry point runs its children
sequentially under one lease. It is wrong for a test binary, which runs
independent operations in parallel threads. Reproduced with the five
`gitsrc::realization_tests` cases **alone** — none of which Package D touches,
and which fail this way on five runs out of five:

```
cargo test --lib realization_tests   # 5 runs, 5 failures, before any fix
```

Worked around, not fixed:

- offline suite: a new `supervise::SUPERVISION_TEST_LOCK`, taken by the tests
  that realize through a child (`gitsrc`, `cargo`, `build`, `project`,
  `supervise`), the same convention and for the same reason as
  `store::STORE_ENV_LOCK`;
- `--ignored` targets: `--test-threads=1`.

Making the supervisor wait rather than reject would remove the need for both.
That is a Package B decision — its review considered reject-vs-block and chose
reject — so it was deliberately not taken here. It is recorded in
`LIMITATIONS.md` and `LINUX_PORT.md`.

---

## 6. Mutation check of the containment guard

The guard is the one piece of the rejected implementation the brief said to
keep, so it was checked by removing it rather than by reading it. With
`certification_covers_legacy_retention` bypassed, the `hex-deps` fixture whose
inner content checksum names a real cached file is certified anyway:

```
test gc::tests::migration_refuses_to_certify_less_than_the_legacy_reader_retained ... FAILED

assertion `left == right` failed: the narrower certification was accepted:
metadata migration: 2 upgraded, 0 unresolved
  left: 0
```

Restored, it refuses that record and migrates the otherwise-identical fixture
with nothing at the inner checksum's address
(`migration_certifies_a_record_whose_evidence_it_can_account_for`). The guard
is doing work in both directions: it is not a blanket refusal, and it is not
decorative.

---

## 7. What this transcript does not establish

- **No macOS execution.** The descriptor-relative deletion primitives,
  `clonefile`-created forests, and the new `libc::stat` mtime path all differ
  there. The Mac gate in §5.4 stands.
- **No independent review.** Every line of the rewrite is the author's own
  work.
- **Adapter/producer agreement is fixture-based for six producers**, as
  described in section 3.
- **Not every legacy store becomes collectable.** The adapters cover all 20
  shipped kind/schema pairs, but a record whose build input an older sweep
  already collected, whose match is ambiguous, or whose pin table this binary
  no longer carries stays unresolved — and one unresolved record blocks every
  sweep. That is the intended direction; it is not a claim that old stores
  will start collecting.

---

## 8. Fix round after Sol's independent review (2026-09-09, agent Rho)

Sol's FIX-FIRST report (`1 P1 + 3 P2`, evidence
`/tmp/opencode-sol-D-1ter4V/`) was closed with four fixes. Each fix has a
regression test that fails without it; every failing-without-fix direction
was verified by applying the inverse mutation to a disposable copy of the
tree (`/var/tmp/blanket-rho/`) and running the named test. Everything here is
Linux, offline, disk-backed (`TMPDIR` and the cargo target on the xfs root,
not the /tmp tmpfs), disposable stores only, `BLANKET_SANDBOX_TESTS=required`.

### F1 (P1) — adapters fail closed on incomplete and unknown grammars

`objmeta::adapt_inner` now runs a mechanical grammar table for all 20
supported (kind, schema) pairs before any derivation: every required input
present, no unrecognized input in a pinned-producer record, and group pairing
complete (NuGet `raw:`/`pkg:`, Go `mod:`/`modfile:`/`info:`). Any violation
returns `Unresolved` naming the field; a pair with no table entry keeps the
existing "no adapter covers" refusal.

- Regression tests: `deleting_any_required_input_of_a_real_layout_refuses`
  (8 pairs, every required key deleted one at a time),
  `nuget_record_missing_its_raw_hash_refuses`,
  `go_modcache_missing_one_triplet_field_refuses`,
  `unknown_input_in_a_pinned_producer_record_refuses`.
- Mutation `R1-grammar-check-removed` (enforcement call no-op'd): the named
  tests fail (exit 101).
- Sol's real-record replay (`replay_incomplete.py` re-pointed at a fixed
  binary) now reports `refusing to sweep: metadata maintenance left 1
  uncertified legacy record(s)` for both the NuGet `raw:`-removed and Go
  `modfile:`-removed records, and both producer cache files survive.

### F2 (P2) — the read phase no longer deletes registry temporaries

`Store::roots_for_sweep` no longer unlinks `.<key>.tmp.<pid>.<seq>` residue;
it returns the names and `roots_for_sweep` stays a read. `gc::read` carries
them in the snapshot; `gc::execute` clears them via
`Store::clear_crash_temps` only — under the exclusive lease, after the plan
has been validated. Dry runs and failed validations leave crash residue (and
the `roots/` directory mtime) exactly as found; the directory-timestamp
writes Sol observed during enumeration were the unlink itself and are gone.

- Regression tests: `dry_run_leaves_crashed_registry_temporaries` (dry run
  leaves the file *and* the roots mtime; a real sweep then clears it),
  `failed_validation_leaves_crashed_registry_temporaries`.
- Mutation `R2-temp-unlink-in-read-phase` (unlink restored in the read): the
  tests fail (exit 101).

### F3 (P2) — every completed deletion is reported, even on error

`execute` accounts for a removal (bytes + counter) immediately after the
candidate is gone, before the companion metadata unlink, so a companion
failure can never drop a completed deletion from the report. The error names
the orphaned `meta/<id>.json` record and the recovery command
(`blanket gc --migrate-metadata` / delete the stray record).

- Regression test: `object_removed_but_metadata_unlink_fails_is_reported`
  (meta/ chmod 0555 between plan and execute): the object is gone, the
  "deletions already completed: 1 objects" line is printed, the recovery path
  is named, and the next sweep — after removing the stray record — is not
  wedged.
- Mutation `R3-report-after-companion` (Objects counter dropped): the test
  fails (exit 101).

### F4 (P2) — the five mutation survivors are now caught

- M09: the native-libs drift test builds its identity with the producer's own
  `identity()` function instead of a hand-built copy. Caught (exit 101).
- M10: new `nativelibs::tests::manifest_hash_covers_every_pinned_archive_digest`
  recomputes the manifest hash from the pinned rows independently, so omitting
  the archive digests from the producer's hash fails. Caught (exit 101).
- M11: new `tests/cli.rs::command_dispatch_runs_automatic_metadata_maintenance`
  seeds a legacy record and runs an ordinary writable command (`blanket x`)
  through the real binary, asserting the record is migrated by dispatch-time
  maintenance. Removing every `automatic_maintenance` call in `main.rs` fails
  it. Caught (exit 101).
- M17: both C.10 crash tests now exercise real publication
  (`project::write_closure`): record published, closure removed reproduces the
  crash window; the before-record case drives publication against an
  unavailable reference. Plus
  `project::tests::strict_publication_writes_the_durable_root_record`.
  Removing the root publication from `write_closure_inner` fails them.
  Caught (exit 101).
- M19/M20: `retained_backup_and_nested_hex_projection_are_not_deleted` now
  exercises both directions of `related` — a claim strictly inside an
  enumerated candidate (deep claim) and a claim over a whole forest project
  directory (ancestor claim). Equality-only survives neither. Caught
  (exit 101 for both M19 and M20).

### Mutation table after the fix round (23 mutations, all re-run)

| Mutation | Exit | Caught by |
|---|---:|---|
| M01-containment-bypass | 101 | `migration_refuses_to_certify_less_than_the_legacy_reader_retained` |
| M02-cache-presence-removed | 101 | `migration_certifies_a_record_whose_evidence_it_can_account_for` |
| M03-transitive-cache-removed | 101 | `hex_package_tarballs_remain_cached_for_a_retained_hex_object` |
| M04-overlay-removed | 101 | `dry_run_adapts_in_memory_and_matches_real_plan_at_the_same_time` |
| M05-roots-removed | 0 | redundant marking; same objects protected via `root_live` (known survivor, not a finding — unchanged from Sol) |
| M06-cache-retention-removed | 101 | `sha1_sha256_and_sha512_artifacts_follow_retained_object_digests` |
| M07-partial-report-removed | 101 | `partial_execution_error_reports_completed_deletions_honestly` |
| M08-cpython-digest-key-renamed | 101 | `legacy_adapters_recover_the_pinned_cpython_and_uv_artifacts` |
| M09-native-producer-digest-key-renamed | 101 | native drift test via the real `identity()` (was 0) |
| M10-native-manifest-omits-digests | 101 | `manifest_hash_covers_every_pinned_archive_digest` (was 0) |
| M11-maintenance-not-called-by-main | 101 | `command_dispatch_runs_automatic_metadata_maintenance` (was 0) |
| M12-supervisor-removed | 101 | 8+ of 17 signal/process tests |
| M13-transitive-object-traversal-removed | 101 | `shared_dependency_survives_forgetting_one_of_two_projects` |
| M14-npm-emits-wrong-sha256 | 101 | `keeps_each_published_integrity_algorithm` (was 0) |
| M15-hex-emits-inner-digest | 101 | `hex_package_tarballs_remain_cached_for_a_retained_hex_object` |
| M16-native-emits-manifest-digest | 101 | `adapter_native_libs_recovers_the_pinned_manifest_digests` |
| M17-publication-skips-root-record | 101 | `gc::tests::crash_*` via real publication (was 0) |
| M18-unknown-schema-accepted | 101 | `unknown_metadata_schema_blocks_destructive_gc` |
| M19-ancestor-guard-removed-existing-test | 101 | `retained_backup_and_nested_hex_projection_are_not_deleted` (was 0) |
| M20-ancestor-guard-removed-deep-claim | 101 | same fixture, deep + ancestor claims (was 0) |
| R1-grammar-check-removed | 101 | F1's grammar tests |
| R2-temp-unlink-in-read-phase | 101 | F2's registry-temporary tests |
| R3-report-after-companion | 101 | F3's report test |

### Fresh test counts (this round, Linux, offline)

- `cargo fmt --check`: clean.
- `cargo test`: **578 passed, 0 failed** (lib 520, main 7, cli 32,
  git_deps 1, sandbox_deny 1, supervise_signals 17).
- `cargo test --test gc -- --ignored --test-threads=1`: 3 passed
  (`TMPDIR=/var/tmp/blanket-rho/tmp`, disposable
  `BLANKET_STORE=/var/tmp/blanket-rho/store`).
- Mutation runs: 23 (20 Sol mutations + 3 fix-verification mutations), each
  applied to a disposable copy at `/var/tmp/blanket-rho/tree` and restored.

### What this round does not establish

- No macOS execution; the Mac gate stands.
- The fixes are uncommitted and have **not** been independently rechecked; a
  fresh reviewer must confirm the four reproductions are closed (Sol's probes
  `sol_dry_run_must_not_unlink_registry_temporary`,
  `sol_failed_validation_must_not_unlink_registry_temporary`,
  `sol_object_removed_but_metadata_unlink_fails_must_be_reported`, and the
  real-record replay with its intentional-exit logic removed).
- M05 remains a survivor by design: `root_live` independently protects the
  same rooted objects, so removing the marking set is not observable through
  candidate deletion.

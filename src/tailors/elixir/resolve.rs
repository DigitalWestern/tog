//! The Elixir resolution doors: the store mix confined through the proxy
//! session's Hex mirror for a missing lock, the planner's
//! `--check-locked` gate and `tog attest`, and the helper's mix.lock parse
//! confined with no route at all.

use super::check_locked::{check_locked_inputs, check_locked_passed, record_check_locked};
use super::door::{elixir_tool, run_mix, run_mix_checked, MixPublish, MixRun, OUTPUTS, SCRATCH};
use super::{err, read_mix_lock, require_lock, validate_plan, ElixirPlan, HexDep, HELPER};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::record;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Executable mix manifests can load app manifests, nested configuration,
/// and arbitrary data. Cover every visible regular project file.
pub(crate) fn resolution_inputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    crate::kernel::resolve::inputs::project_files(project, &super::door::EXCLUDE, &OUTPUTS)
}

/// mix.exs, mix.lock and the config files, by digest: a closure's
/// `resolution_basis`.
pub(crate) fn resolution_basis(
    project: &ProjectRoot,
) -> io::Result<crate::comforter::join::Digests> {
    let mut listed: Vec<PathBuf> = OUTPUTS.iter().map(PathBuf::from).collect();
    listed.extend(resolution_inputs(project)?);
    record::file_digests(project, &listed)
}

/// `prepare`: mix.lock, resolved by the store mix when there is none. The
/// one place the Elixir tailor writes project inputs. `mix deps.get` runs
/// confined through `door` (a missing-lock door), and mix.lock and the
/// signed resolution record are published together through its
/// transaction.
pub fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    ui::note("no mix.lock; resolving with the store mix...");
    let basis = resolution_basis(project)?;
    let args = ["mix", "deps.get"];
    let spec = crate::tailors::record_spec(
        &super::tailor::Elixir,
        project,
        elixir_tool(selected)?,
        &args,
    )?;
    run_mix_checked(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &args,
            online: true,
            inputs: Some(&basis),
            files: Vec::new(),
            publish: MixPublish::Project {
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(())
}

/// `tog update` for Elixir: `mix deps.update` through the edit door, which
/// publishes mix.lock with its record.
pub(crate) fn update(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
    args: &[&str],
) -> io::Result<()> {
    let basis = resolution_basis(project)?;
    let spec = crate::tailors::record_spec(
        &super::tailor::Elixir,
        project,
        elixir_tool(selected)?,
        args,
    )?;
    run_mix_checked(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args,
            online: true,
            inputs: Some(&basis),
            files: Vec::new(),
            publish: MixPublish::Project {
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(())
}

/// The consistency gate: `mix deps.get --check-locked`, exit status only
/// (it evaluates mix.exs, delegated trust and never artifact authority).
/// It needs the Hex registry, so it reaches the mirror. Its Hex home is
/// private scratch: project code must never seed configuration or code for
/// another run. Registry reuse belongs to the proxy cache. Nothing in the
/// project may change.
fn check_locked(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    basis: &crate::comforter::join::Digests,
) -> io::Result<()> {
    let out = run_mix(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &["mix", "deps.get", "--check-locked"],
            online: true,
            inputs: Some(basis),
            files: Vec::new(),
            publish: MixPublish::Detached,
        },
    )?;
    if !out.status.success() {
        return Err(err(format!(
            "mix.exs and mix.lock are out of sync; run `tog run mix deps.get` and retry\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The helper's strict parse of `lock`, confined with no route: the helper
/// and a copy of the bytes read through the held descriptor are handed to
/// the run, so what it parses is exactly what the plan hashes.
fn parse_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    lock: &str,
    basis: &crate::comforter::join::Digests,
) -> io::Result<Vec<HexDep>> {
    let helper = format!("{SCRATCH}/helper.exs");
    let lock_copy = format!("{SCRATCH}/mix.lock");
    let out = run_mix(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &["elixir", &helper, "lock", &lock_copy],
            online: false,
            inputs: Some(basis),
            files: vec![
                (PathBuf::from("helper.exs"), HELPER.as_bytes().to_vec()),
                (PathBuf::from("mix.lock"), lock.as_bytes().to_vec()),
            ],
            publish: MixPublish::Detached,
        },
    )?;
    if !out.status.success() {
        return Err(err(format!(
            "mix.lock analysis failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    #[derive(Deserialize)]
    struct HelperOut {
        entries: Vec<HexDep>,
    }
    let parsed: HelperOut =
        serde_json::from_slice(&out.stdout).map_err(|e| err(format!("helper output: {e}")))?;
    Ok(parsed.entries)
}

/// Plan: AST-parse mix.lock under the pinned toolchain (lock-only, no
/// eval), after the `--check-locked` gate unless its inputs are unchanged
/// since it last passed. The project is read through the held descriptor.
/// Returns the plan, the lock's sha256, and the resolution basis.
pub fn plan_elixir(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<(ElixirPlan, String, crate::comforter::join::Digests)> {
    let observed = project.observing_inputs()?;
    let project = &observed;
    let basis = resolution_basis(project)?;
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    require_lock(project)?;
    let lock = read_mix_lock(project)?;
    let bind = |input: String, basis: &crate::comforter::join::Digests| {
        format!(
            "{input}:{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(basis).expect("string map")
            ))
        )
    };
    let inputs = check_locked_inputs(project, beam_obj, &lock)?.map(|input| bind(input, &basis));
    let unchanged = match &inputs {
        Some(inputs) => check_locked_passed(door.store(), project, inputs)?,
        None => false,
    };
    if unchanged {
        ui::trace("mix.exs and mix.lock unchanged since their last passing check");
    } else {
        check_locked(door, project, beam_obj, &basis)?;
        // Recorded only when the inputs still hash the same after the
        // check, so the record names the bytes the check actually read.
        let after_basis = resolution_basis(project)?;
        let after = check_locked_inputs(project, beam_obj, &read_mix_lock(project)?)?
            .map(|input| bind(input, &after_basis));
        if let (Some(before), Some(after)) = (&inputs, &after) {
            if before == after {
                record_check_locked(door.store(), door.lease(), project, before);
            }
        }
    }
    let mut deps = parse_lock(door, project, beam_obj, &lock, &basis)?;
    deps.sort_by(|a, b| a.app.cmp(&b.app));
    let plan = ElixirPlan {
        // The toolchain this plan was made under is the selected one, so
        // the plan records the selection's versions, never the shipped pins.
        otp_version: selected.version("otp")?.to_string(),
        elixir_version: selected.version("elixir")?.to_string(),
        deps,
    };
    validate_plan(&plan)?;
    if read_mix_lock(project)? != lock {
        return Err(err("mix.lock changed while planning; re-run 'tog'"));
    }
    // The resolution files this plan was built from, so the resolution
    // join binds a record to this generation of mix.exs and its lock.
    project.verify_observed_inputs()?;
    if resolution_basis(project)? != basis {
        return Err(err(
            "Elixir resolution inputs changed while planning; run `tog` again",
        ));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes())), basis))
}

/// `tog attest` for Elixir: `mix deps.get --check-locked` in the project
/// through `door`'s transaction with the record's producer. A mix.exs the
/// lock no longer matches fails the check; a lock it would rewrite anyway
/// is refused by the record. Nothing is published here.
pub fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    require_lock(project)?;
    let basis = resolution_basis(project)?;
    let args = ["mix", "deps.get", "--check-locked"];
    let mut spec = crate::tailors::record_spec(
        &super::tailor::Elixir,
        project,
        elixir_tool(selected)?,
        &args,
    )?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = run_mix(
        door,
        MixRun {
            beam_obj,
            lock_root: project.path(),
            args: &args,
            online: true,
            inputs: Some(&basis),
            files: Vec::new(),
            publish: MixPublish::Project {
                receipt: Some(record::producer(spec, slot.clone())),
            },
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "mix.lock in {} is not what mix deps.get would write, so it is not attested; \
             run `tog` to bring it up to date and commit the result\n{}",
            project.path().display(),
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("mix's lock check published no record"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::ledger::{self, Entry, LedgerObjects};
    use crate::kernel::resolve::testing::{relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC};
    use crate::kernel::resolve::DoorKind;
    use crate::kernel::testutil::TempDir;
    use crate::tailors::elixir::registry::REPO_HOST;
    use std::fs;

    #[test]
    fn basis_refuses_a_lock_or_manifest_replaced_after_consumption() {
        let temp = TempDir::named("elixir-basis-race");
        fs::write(temp.0.join("mix.exs"), "manifest A").unwrap();
        fs::write(temp.0.join("mix.lock"), "lock A").unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let observed = held.observing_inputs().unwrap();
        resolution_basis(&observed).unwrap();
        fs::write(temp.0.join("mix.lock"), "lock B").unwrap();
        assert!(resolution_basis(&observed).is_err());
        let observed = held.observing_inputs().unwrap();
        resolution_basis(&observed).unwrap();
        fs::write(temp.0.join("mix.exs"), "manifest B").unwrap();
        assert!(resolution_basis(&observed).is_err());
    }

    #[test]
    fn an_included_manifest_change_or_new_file_invalidates_the_basis() {
        let temp = TempDir::named("elixir-included-input");
        fs::create_dir_all(temp.0.join("apps/web/mix.exs").parent().unwrap()).unwrap();
        fs::write(temp.0.join("mix.exs"), "manifest").unwrap();
        fs::write(temp.0.join("mix.lock"), "lock").unwrap();
        fs::write(temp.0.join("apps/web/mix.exs"), "included manifest A").unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let basis = resolution_basis(&held).unwrap();
        assert!(basis.contains_key("apps/web/mix.exs"));
        fs::write(temp.0.join("apps/web/mix.exs"), "included manifest B").unwrap();
        let files = crate::tailors::resolution_files(&super::super::tailor::Elixir, &held)
            .unwrap()
            .unwrap();
        assert!(
            crate::comforter::join::check_basis_for_test(&held, "elixir", &files, &basis).is_err()
        );
        let basis = resolution_basis(&held).unwrap();
        fs::write(temp.0.join("new-data.txt"), "new input").unwrap();
        let files = crate::tailors::resolution_files(&super::super::tailor::Elixir, &held)
            .unwrap()
            .unwrap();
        assert!(
            crate::comforter::join::check_basis_for_test(&held, "elixir", &files, &basis).is_err()
        );
    }

    /// A harness whose upstream answers repo.hex.pm from the recorded Hex
    /// rows, and whose proxy every door in this thread uses while it
    /// lives. builds.hex.pm is not served: no route permits it.
    fn hex_harness(label: &str) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(20);
        let rows = stored_rows("elixir", label);
        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            &[REPO_HOST],
            &rows.0.to_string_lossy(),
        )));
        std::mem::forget(rows);
        PROXY_FOR_TEST.with(|slot| slot.set(Some(&harness.proxy)));
        Some(harness)
    }

    fn done() {
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        PROXY_FOR_TEST.with(|slot| slot.set(None));
    }

    fn through_door<T>(
        harness: &Harness,
        kind: DoorKind,
        job: impl FnOnce(&mut ResolutionDoor<'_>) -> T,
    ) -> (T, Vec<Exception>) {
        let mut attribution = Attribution::open("elixir").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            kind,
            &mut attribution,
        )
        .unwrap();
        let out = job(&mut door);
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        (out, recorded)
    }

    fn entries(harness: &Harness, objects: &LedgerObjects) -> Vec<Entry> {
        let portable = ledger::PortableLedger::parse(
            &ledger::read_portable(&harness.store, &objects.ledger).unwrap(),
        )
        .unwrap();
        portable.entries().cloned().collect()
    }

    fn manifest(deps: &str) -> String {
        format!(
            "defmodule Demo.MixProject do\n  use Mix.Project\n\n  def project do\n    \
             [app: :demo, version: \"0.1.0\", deps: [{deps}]]\n  end\nend\n"
        )
    }

    /// The whole Elixir door against the recorded repo.hex.pm: a missing
    /// lock resolved by `mix deps.get` through the Hex mirror, the
    /// planner's `--check-locked` gate through it and the helper's lock
    /// parse with no route at all, and `tog attest`'s check: an unchanged
    /// lock signed, a drifted mix.exs refused.
    #[test]
    #[ignore = "realizes the store BEAM over the network"]
    fn mix_resolves_through_the_hex_mirror() {
        let _serial = policy::attribution_test_lock();
        let label = "mix_resolves_through_the_hex_mirror";
        let Some(harness) = hex_harness(label) else {
            return;
        };
        let selected = super::super::shipped_selection().unwrap();
        let beam = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        let temp = TempDir::named("elixir-mirror");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("mix.exs"), manifest("{:jason, \"1.4.5\"}")).unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();

        let (generated, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &held, &beam, &selected)
        });
        generated.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join("mix.lock")).unwrap();
        assert!(
            lock.contains("\"jason\": {:hex, :jason, \"1.4.5\""),
            "{lock}"
        );
        assert!(dir.join(".tog/resolution/elixir.json").is_file());
        assert!(
            !dir.join("deps").exists(),
            "deps were fetched into the project"
        );

        // A prior project's writable Hex home must never enter this run.
        let shared = harness.store.root.join("planner-hexhome");
        fs::create_dir_all(&shared).unwrap();
        let marker = dir.join("cross-project-code-ran");
        fs::write(
            shared.join("hex.config"),
            format!(
                "File.write!({:?}, \"injected\"); []",
                marker.to_str().unwrap()
            ),
        )
        .unwrap();
        let ((planned, ledgers), recorded) = through_door(harness, DoorKind::Planner, |door| {
            let planned = plan_elixir(door, &held, &beam, &selected);
            (planned, door.take_kept_ledgers())
        });
        let (plan, _, basis) = planned.unwrap();
        assert!(
            !marker.exists(),
            "a previous project injected Hex config code"
        );
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(plan.deps.len(), 1, "{:?}", plan.deps);
        assert_eq!(plan.deps[0].version, "1.4.5");
        assert!(basis.contains_key("mix.lock"), "{basis:?}");
        assert_eq!(
            ledgers.len(),
            2,
            "the gate and the parse each leave a ledger"
        );
        let gate = entries(harness, &ledgers[0]);
        assert!(
            gate.iter()
                .any(|e| e.url == "https://repo.hex.pm/packages/jason"),
            "{gate:?}"
        );
        assert!(entries(harness, &ledgers[1]).is_empty());

        let (attested, recorded) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &beam, &selected)
        });
        let (record, _) = attested.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(record.outputs.len(), 2, "{:?}", record.outputs);

        fs::write(
            dir.join("mix.exs"),
            manifest("{:jason, \"1.4.5\"}, {:telemetry, \"1.4.2\"}"),
        )
        .unwrap();
        let before = fs::read(dir.join("mix.lock")).unwrap();
        let (drifted, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &beam, &selected)
        });
        let why = drifted.unwrap_err().to_string();
        assert!(why.contains("not attested"), "{why}");
        assert_eq!(fs::read(dir.join("mix.lock")).unwrap(), before);
        done();
    }
}

//! The Ruby resolution doors: the store Bundler confined through the proxy
//! session's RubyGems mirror for a missing lock and `tog attest`, and the
//! planner's two helper checks confined with no route at all.

use super::door::{ruby_tool, run_ruby, run_ruby_checked, RubyPublish, RubyRun, OUTPUTS, SCRATCH};
use super::{err, GEMFILE, GEMFILE_LOCK, HELPER};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::record;
use crate::kernel::resolve::{DelegateReport, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use std::io;
use std::path::{Path, PathBuf};

/// The helper's file name in the run's scratch directory.
const HELPER_FILE: &str = "helper.rb";

/// Executable Gemfiles can load arbitrary project files. Bind all visible
/// regular files until precise input discovery has a reviewed design.
pub(crate) fn resolution_inputs(project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    crate::kernel::resolve::inputs::project_files(project, &super::door::EXCLUDE, &OUTPUTS)
}

/// The Gemfile and Gemfile.lock, by digest: a closure's
/// `resolution_basis`.
pub(crate) fn resolution_basis(
    project: &ProjectRoot,
) -> io::Result<crate::comforter::join::Digests> {
    let mut files: Vec<PathBuf> = OUTPUTS.iter().map(PathBuf::from).collect();
    files.extend(resolution_inputs(project)?);
    record::file_digests(project, &files)
}

/// `prepare`: Gemfile.lock, resolved by the store Bundler when there is
/// none. The one place the Ruby tailor writes project inputs. `bundle
/// lock` runs confined through `door` (a missing-lock door), and the
/// Gemfile, Gemfile.lock and the signed resolution record are published
/// together through its transaction.
pub fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    if !project.is_input_file(Path::new(GEMFILE)) {
        return Err(err("Gemfile not found"));
    }
    ui::note("no Gemfile.lock; resolving with the store bundler...");
    let basis = resolution_basis(project)?;
    let args = ["bundle", "lock"];
    let spec =
        crate::tailors::record_spec(&super::tailor::Ruby, project, ruby_tool(selected)?, &args)?;
    run_ruby_checked(
        door,
        RubyRun {
            ruby_obj,
            lock_root: project.path(),
            args: &args,
            online: true,
            inputs: Some(&basis),
            frozen: false,
            files: Vec::new(),
            publish: RubyPublish::Project {
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(())
}

/// One mode of the planner's helper over the project, confined with no
/// route: `check` evaluates the Gemfile (exit status only), `plan` reads
/// Gemfile.lock alone. Neither needs the network, so neither gets any.
pub(super) fn helper(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    ruby_obj: &Path,
    mode: &str,
    basis: Option<&crate::comforter::join::Digests>,
) -> io::Result<DelegateReport> {
    let helper = format!("{SCRATCH}/{HELPER_FILE}");
    let mut args = vec!["ruby", helper.as_str(), mode];
    if mode == "check" {
        args.push(GEMFILE);
    }
    args.push(GEMFILE_LOCK);
    run_ruby(
        door,
        RubyRun {
            ruby_obj,
            lock_root: project.path(),
            args: &args,
            online: false,
            inputs: basis,
            frozen: true,
            files: vec![(PathBuf::from(HELPER_FILE), HELPER.as_bytes().to_vec())],
            publish: RubyPublish::Detached,
        },
    )
}

/// `tog attest` for Ruby: `bundle lock` in the project, frozen, through
/// `door`'s transaction with the record's producer. `bundle lock` with
/// `BUNDLE_FROZEN=true` still re-resolves a Gemfile the lock no longer
/// matches and writes the new lock into the stage (measured), so the
/// record's byte-unchanged rule is what refuses it. The check publishes nothing,
/// not even the receipt: `tog attest` publishes every record only once
/// every check passed.
pub fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    if !project.is_input_file(Path::new(GEMFILE)) {
        return Err(err("Gemfile not found"));
    }
    super::require_lock(project)?;
    let basis = resolution_basis(project)?;
    let args = ["bundle", "lock"];
    let mut spec =
        crate::tailors::record_spec(&super::tailor::Ruby, project, ruby_tool(selected)?, &args)?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = run_ruby(
        door,
        RubyRun {
            ruby_obj,
            lock_root: project.path(),
            args: &args,
            online: true,
            inputs: Some(&basis),
            frozen: true,
            files: Vec::new(),
            publish: RubyPublish::Project {
                receipt: Some(record::producer(spec, slot.clone())),
            },
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "Gemfile.lock in {} is not what bundle lock would write, so it is not attested; \
             run `tog` to bring it up to date and commit the result\n{}",
            project.path().display(),
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("Bundler's lock check published no record"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::ledger::{self, Entry};
    use crate::kernel::resolve::testing::{relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC};
    use crate::kernel::resolve::DoorKind;
    use crate::kernel::testutil::TempDir;
    use crate::tailors::edit::EditVerb;
    use crate::tailors::ruby::registry::{GEMS_HOST, INDEX_HOST};
    use sha2::{Digest as _, Sha256};
    use std::fs;

    #[test]
    fn basis_refuses_a_lock_or_manifest_replaced_after_consumption() {
        let temp = TempDir::named("ruby-basis-race");
        fs::write(temp.0.join("Gemfile"), "manifest A").unwrap();
        fs::write(temp.0.join("Gemfile.lock"), "lock A").unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let observed = held.observing_inputs().unwrap();
        resolution_basis(&observed).unwrap();
        fs::write(temp.0.join("Gemfile.lock"), "lock B").unwrap();
        assert!(resolution_basis(&observed).is_err());
        let observed = held.observing_inputs().unwrap();
        resolution_basis(&observed).unwrap();
        fs::write(temp.0.join("Gemfile"), "manifest B").unwrap();
        assert!(resolution_basis(&observed).is_err());
    }

    #[test]
    fn an_included_manifest_change_or_new_file_invalidates_the_basis() {
        let temp = TempDir::named("ruby-included-input");
        fs::create_dir_all(temp.0.join("dependencies.rb").parent().unwrap()).unwrap();
        fs::write(temp.0.join("Gemfile"), "manifest").unwrap();
        fs::write(temp.0.join("Gemfile.lock"), "lock").unwrap();
        fs::write(temp.0.join("dependencies.rb"), "included manifest A").unwrap();
        let held = ProjectRoot::open(&temp.0).unwrap();
        let basis = resolution_basis(&held).unwrap();
        assert!(basis.contains_key("dependencies.rb"));
        fs::write(temp.0.join("dependencies.rb"), "included manifest B").unwrap();
        let files = crate::tailors::resolution_files(&super::super::tailor::Ruby, &held)
            .unwrap()
            .unwrap();
        assert!(
            crate::comforter::join::check_basis_for_test(&held, "ruby", &files, &basis).is_err()
        );
        let basis = resolution_basis(&held).unwrap();
        fs::write(temp.0.join("new-data.txt"), "new input").unwrap();
        let files = crate::tailors::resolution_files(&super::super::tailor::Ruby, &held)
            .unwrap()
            .unwrap();
        assert!(
            crate::comforter::join::check_basis_for_test(&held, "ruby", &files, &basis).is_err()
        );
    }

    /// A harness whose upstream answers from the recorded RubyGems rows,
    /// and whose proxy every door in this thread uses while it lives. The
    /// recorded `/versions` was cut to the two gems the census used, so its
    /// index row carries the upstream digest; the copy here serves the cut
    /// body under its own.
    fn ruby_harness(label: &str) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(20);
        let rows = stored_rows("ruby", label);
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/registry/ruby");
        let index: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(source.join("index.json")).unwrap()).unwrap();
        let mut kept: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(rows.0.join("index.json")).unwrap()).unwrap();
        for mut row in index {
            if row["url"] != "https://index.rubygems.org/versions" {
                continue;
            }
            let file = row["file"].as_str().unwrap().to_string();
            let body = fs::read(source.join(&file)).unwrap();
            fs::create_dir_all(rows.0.join(&file).parent().unwrap()).unwrap();
            fs::write(rows.0.join(&file), &body).unwrap();
            row["sha256"] = hex::encode(Sha256::digest(&body)).into();
            kept.push(row);
        }
        fs::write(
            rows.0.join("index.json"),
            serde_json::to_vec(&kept).unwrap(),
        )
        .unwrap();
        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            &[INDEX_HOST, GEMS_HOST],
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

    /// `job` with a door of `kind` over the harness store, and what the door
    /// recorded.
    fn through_door<T>(
        harness: &Harness,
        kind: DoorKind,
        job: impl FnOnce(&mut ResolutionDoor<'_>) -> T,
    ) -> (T, Vec<Exception>) {
        let mut attribution = Attribution::open("ruby").unwrap();
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

    fn entries(harness: &Harness, report: &DelegateReport) -> Vec<Entry> {
        let objects = report.ledger.as_ref().expect("a ledger");
        let portable = ledger::PortableLedger::parse(
            &ledger::read_portable(&harness.store, &objects.ledger).unwrap(),
        )
        .unwrap();
        portable.entries().cloned().collect()
    }

    /// The whole Ruby door against the recorded rubygems.org: a missing
    /// lock resolved by `bundle lock` through the mirror (the lock still
    /// names rubygems.org, and every request is a compact-index read), the
    /// planner's two helper checks with no route at all, `bundle add
    /// --skip-install` through the edit door (no gem is downloaded), and
    /// `tog attest`'s check: an unchanged lock signed, a drifted Gemfile
    /// refused.
    #[test]
    #[ignore = "realizes the store Ruby over the network"]
    fn bundler_resolves_through_the_rubygems_mirror() {
        let _serial = policy::attribution_test_lock();
        let label = "bundler_resolves_through_the_rubygems_mirror";
        let Some(harness) = ruby_harness(label) else {
            return;
        };
        let selected = super::super::shipped_selection().unwrap();
        let ruby_obj = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        let temp = TempDir::named("ruby-mirror");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Gemfile"),
            "source \"https://rubygems.org\"\n\ngem \"rake\", \"13.4.2\"\n",
        )
        .unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();

        let (generated, recorded) = through_door(harness, DoorKind::MissingLock, |door| {
            generate_lock(door, &held, &ruby_obj, &selected)
        });
        generated.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join("Gemfile.lock")).unwrap();
        assert!(lock.contains("remote: https://rubygems.org/"), "{lock}");
        assert!(lock.contains("rake (13.4.2)"), "{lock}");
        assert!(dir.join(".tog/resolution/ruby.json").is_file());

        let ((check, plan), recorded) = through_door(harness, DoorKind::Planner, |door| {
            let check = helper(door, &held, &ruby_obj, "check", None).unwrap();
            let plan = helper(door, &held, &ruby_obj, "plan", None).unwrap();
            assert_eq!(door.take_kept_ledgers().len(), 2);
            (check, plan)
        });
        assert!(recorded.is_empty(), "{recorded:?}");
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );
        let plan_out = String::from_utf8_lossy(&plan.stdout);
        assert!(
            plan_out.contains("\"full_name\":\"rake-13.4.2\""),
            "{plan_out}"
        );

        let texts = ["rainbow@3.1.1".to_string()];
        let (added, recorded) = through_door(harness, DoorKind::Edit, |door| {
            let runs = super::super::edit::bundler_runs(EditVerb::Add, &texts, false);
            let mut last = None;
            for args in runs {
                let spec = crate::tailors::record_spec(
                    &super::super::tailor::Ruby,
                    &held,
                    ruby_tool(&selected).unwrap(),
                    &args,
                )
                .unwrap();
                last = Some(run_ruby_checked(
                    door,
                    RubyRun {
                        ruby_obj: &ruby_obj,
                        lock_root: &dir,
                        args: &args,
                        online: true,
                        inputs: None,
                        frozen: false,
                        files: Vec::new(),
                        publish: RubyPublish::Project {
                            receipt: Some(record::producer(spec, Default::default())),
                        },
                    },
                ));
            }
            last.unwrap()
        });
        let added = added.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join("Gemfile.lock")).unwrap();
        assert!(lock.contains("rainbow (3.1.1)"), "{lock}");
        let gemfile = fs::read_to_string(dir.join("Gemfile")).unwrap();
        assert!(gemfile.contains("gem \"rainbow\""), "{gemfile}");
        let found = entries(harness, &added);
        assert!(!found.is_empty());
        for entry in &found {
            assert!(
                entry.url.starts_with("https://index.rubygems.org/"),
                "a lock-only edit downloads no gem: {found:?}"
            );
            assert_ne!(entry.class, "refused", "{found:?}");
        }

        let (attested, recorded) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &ruby_obj, &selected)
        });
        let (record, _) = attested.unwrap();
        assert!(recorded.is_empty(), "{recorded:?}");
        assert_eq!(record.outputs.len(), 2, "{:?}", record.outputs);

        fs::write(
            dir.join("Gemfile"),
            "source \"https://rubygems.org\"\n\ngem \"rake\", \"13.4.2\"\ngem \"rainbow\", \"3.1.0\"\n",
        )
        .unwrap();
        let before = fs::read(dir.join("Gemfile.lock")).unwrap();
        let (drifted, _) = through_door(harness, DoorKind::Attest, |door| {
            attest_project(door, &held, &ruby_obj, &selected)
        });
        let why = drifted.unwrap_err().to_string();
        assert!(why.contains("would change Gemfile.lock"), "{why}");
        assert_eq!(fs::read(dir.join("Gemfile.lock")).unwrap(), before);
        done();
    }
}

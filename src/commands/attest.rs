//! `tog attest [<ecosystem>...]`: give existing locks a signed resolution
//! record, and move a record's ledger between machines.
//!
//! Attesting runs in two phases. First, each ecosystem's own lock check
//! runs through a verification door (`Tailor::attest_lock`), publishing
//! nothing: a check that leaves the lock and manifest byte-unchanged yields
//! a record signed with the process key. Only when every check passed does
//! the second phase write them: as the project's receipts
//! (`.tog/resolution/<ecosystem>.json`, through `record::publish_receipts`,
//! all or nothing, under the project lock, and only while each lock still
//! reads as its record signed it), or with `--record-out` outside the
//! checkout, which is then left unchanged. A failed check therefore leaves
//! no receipt behind, whichever ecosystem it was, and a failed publication
//! puts back the receipts it already wrote. A process killed between two
//! publications can leave a partial set; each receipt in it still attests
//! its own lock, and rerunning `tog attest` completes it.
//!
//! The ledger transfers never run a tool. `--ledger-export` writes the
//! portable bytes of the ledger the committed record names, from the local
//! store. `--ledger-import` stores portable bytes only when an attesting
//! record in this project names exactly those bytes, then roots the object
//! under the project so the next closure write retains it.

use crate::cli::{Command, LedgerTransfer};
use crate::comforter::join;
use crate::comforter::toolchain::Mode;
use crate::commands::shared::no_inputs;
use crate::commands::sync::{preflight_sync, Scope};
use crate::kernel::context::{self, Context};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::record::{self, Judgment, ResolutionRecord};
use crate::kernel::resolve::{transaction, DoorKind, ResolutionDoor};
use crate::kernel::ui;
use crate::tailors::{self, Tailor};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Run `tog attest` as parsed. It validates the host, preflights the
/// project, and loads the signing key itself, before it opens the store.
pub fn run(command: Command) -> io::Result<i32> {
    let Command::Attest {
        ecosystems,
        record_out,
        ledger,
    } = command
    else {
        unreachable!("dispatch hands attest only its own command");
    };
    let platform = Platform::host()?;
    let project = ProjectRoot::open(&context::project_dir())?;
    policy::init_in(&project)?;
    match ledger {
        Some(LedgerTransfer::Export { ecosystem, file }) => {
            export_ledger(platform, &project, &ecosystem, &file)
        }
        Some(LedgerTransfer::Import { file }) => import_ledger(platform, &project, &file),
        None => attest(platform, &project, &ecosystems, record_out.as_deref()),
    }?;
    Ok(0)
}

/// The tailors to attest: the named ones, or every detected ecosystem that
/// declares a lock the resolution join judges. A named ecosystem that is
/// not here, or declares no such lock, is refused before any work.
fn targets(
    project: &ProjectRoot,
    present: &[&'static dyn Tailor],
    named: &[String],
) -> io::Result<Vec<&'static dyn Tailor>> {
    let mut targets = Vec::new();
    if named.is_empty() {
        for tailor in present {
            if tailors::resolution_files(*tailor, project)?.is_some() {
                targets.push(*tailor);
            }
        }
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "nothing to attest in {}: no ecosystem found here has a lock that a \
                     resolution door produces",
                    project.path().display()
                ),
            ));
        }
        return Ok(targets);
    }
    for id in named {
        let Some(tailor) = present.iter().copied().find(|tailor| tailor.id() == id) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no {id} project in {}", project.path().display()),
            ));
        };
        if tailors::resolution_files(tailor, project)?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "tog attest does not support {id}: it has no lock that a resolution door \
                     produces, so there is nothing to sign"
                ),
            ));
        }
        targets.push(tailor);
    }
    Ok(targets)
}

fn attest(
    platform: Platform,
    project: &ProjectRoot,
    named: &[String],
    record_out: Option<&Path>,
) -> io::Result<()> {
    crate::comforter::init_signing()?;
    if record_out.is_some() && crate::comforter::signing_key().is_none() {
        // The CI flow hands this file to a later sync, which attests only a
        // signed record: an unsigned one would be written, uploaded, and
        // then never count.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--record-out writes a record for another machine's sync, which attests only a \
             signed one, and TOG_SIGNING_KEY is not set; export TOG_SIGNING_KEY=<key file the \
             sync's machine policy trusts>",
        ));
    }
    let present = tailors::detected_in(project)?;
    if present.is_empty() {
        return Err(no_inputs());
    }
    let targets = targets(project, &present, named)?;
    let scope = match named {
        [one] => Scope::Only(one),
        _ => Scope::All,
    };
    // The committed toolchain lock names the tool; attesting never writes
    // one, so the lock is read the way `--frozen` reads it.
    let (_, toolchain) = preflight_sync(platform, project, Mode::Frozen, scope)?;
    let ctx = Context::open(platform)?;
    // An interrupted publication is finished or undone before any check
    // reads the lock it was replacing.
    transaction::recover_project(&ctx.store, &ctx.activity, project.path())?;
    project.check_still_named()?;
    if crate::comforter::signing_key().is_none() {
        ui::warning(
            "resolution records written unsigned: TOG_SIGNING_KEY is not set, so no sync \
             will attest them",
            "export TOG_SIGNING_KEY=<key file your machine policy trusts>",
        );
    }
    let ids: Vec<&str> = targets.iter().map(|tailor| tailor.id()).collect();
    let host = crate::commands::shared::CommandHost { platform };
    check_then_publish(
        &ids,
        |id| {
            let tailor = targets
                .iter()
                .find(|tailor| tailor.id() == id)
                .expect("the ids are the targets'");
            let selected = toolchain.get(tailor.lock_ecosystem())?;
            // The door records its run's exceptions (a tier's
            // `unconfined-resolution`) into this scope, and the record
            // carries them; attesting publishes no closure, so the scope is
            // discarded.
            let mut attribution = policy::Attribution::open(tailor.id())?;
            let checked = ResolutionDoor::open(
                &ctx.store,
                &ctx.activity,
                platform,
                DoorKind::Attest,
                &mut attribution,
            )
            .and_then(|mut door| tailor.attest_lock(&ctx, project, selected, &host, &mut door));
            attribution.discard();
            checked
        },
        |records| match record_out {
            Some(out) => {
                for (record, bytes) in records {
                    let written = write_record(record, bytes, out, named.len() == 1)?;
                    written_note(record, &written);
                }
                Ok(())
            }
            None => {
                record::publish_receipts(&ctx.store, &ctx.activity, project, records)?;
                for (record, _) in records {
                    written_note(
                        record,
                        &project.path().join(record::receipt_path(&record.ecosystem)),
                    );
                }
                Ok(())
            }
        },
    )
}

/// The two phases of attesting `ids`, in order: `check` each one, which
/// publishes nothing, then `publish` every record only once all passed. A
/// failed check stops before anything is written, so no ecosystem's
/// receipt or `--record-out` file is left behind for a partial set.
fn check_then_publish(
    ids: &[&str],
    mut check: impl FnMut(&str) -> io::Result<(ResolutionRecord, Vec<u8>)>,
    publish: impl FnOnce(&[(ResolutionRecord, Vec<u8>)]) -> io::Result<()>,
) -> io::Result<()> {
    let mut records = Vec::new();
    for id in ids {
        let (record, bytes) = check(id)?;
        if record.ecosystem != *id {
            return Err(io::Error::other(format!(
                "the {id} lock check returned a {} record",
                record.ecosystem
            )));
        }
        records.push((record, bytes));
    }
    publish(&records)
}

fn written_note(record: &ResolutionRecord, to: &Path) {
    ui::note(&format!(
        "attest: {} {} record ({} {}) written to {}",
        record.ecosystem,
        record.door,
        record.tool.name,
        record.tool.version,
        to.display()
    ));
}

/// Write one signed record for `--record-out`: to `out` itself when
/// exactly one ecosystem was named, else to `<out>/<ecosystem>.json`.
/// Returns where it went.
fn write_record(
    record: &ResolutionRecord,
    bytes: &[u8],
    out: &Path,
    one_named: bool,
) -> io::Result<PathBuf> {
    let path = if one_named {
        out.to_path_buf()
    } else {
        fs::create_dir_all(out).map_err(|error| {
            io::Error::new(error.kind(), format!("create {}: {error}", out.display()))
        })?;
        out.join(format!("{}.json", record.ecosystem))
    };
    fs::write(&path, bytes).map_err(|error| {
        io::Error::new(error.kind(), format!("write {}: {error}", path.display()))
    })?;
    Ok(path)
}

fn export_ledger(
    platform: Platform,
    project: &ProjectRoot,
    ecosystem: &str,
    file: &Path,
) -> io::Result<()> {
    let receipt = project.path().join(record::receipt_path(ecosystem));
    let bytes = record::read_receipt(project, ecosystem)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} does not exist, so no ledger is named; run 'tog attest {ecosystem}' first",
                receipt.display()
            ),
        )
    })?;
    let record = record::parse_unverified(&bytes, ecosystem).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not a resolution record: {reason}", receipt.display()),
        )
    })?;
    let ctx = Context::open(platform)?;
    let portable = record::read_ledger(&ctx.store, &ctx.activity, &record)?;
    fs::write(file, &portable).map_err(|error| {
        io::Error::new(error.kind(), format!("write {}: {error}", file.display()))
    })?;
    ui::note(&format!(
        "attest: wrote the {ecosystem} ledger {} ({} bytes) to {}",
        record.ledger.object,
        portable.len(),
        file.display()
    ));
    Ok(())
}

/// The attesting committed record in `project` whose ledger is exactly
/// `portable`, judged as the sync's join judges it.
fn attesting_record_for(
    project: &ProjectRoot,
    portable: &[u8],
) -> io::Result<Option<ResolutionRecord>> {
    let trusted = join::trusted_keys(&policy::effective());
    for tailor in tailors::detected_in(project)? {
        let Some(files) = tailors::resolution_files(tailor, project)? else {
            continue;
        };
        let Some(bytes) = record::read_receipt(project, tailor.id())? else {
            continue;
        };
        let origin = project
            .path()
            .join(record::receipt_path(tailor.id()))
            .display()
            .to_string();
        if let Judgment::Attests(attested) =
            record::judge(&origin, &bytes, tailor.id(), &trusted, &files, project)?
        {
            if record::describes_ledger(&attested.record, portable) {
                return Ok(Some(attested.record));
            }
        }
    }
    Ok(None)
}

fn import_ledger(platform: Platform, project: &ProjectRoot, file: &Path) -> io::Result<()> {
    let portable = fs::read(file).map_err(|error| {
        io::Error::new(error.kind(), format!("read {}: {error}", file.display()))
    })?;
    let Some(record) = attesting_record_for(project, &portable)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is not the ledger of any attesting resolution record in {} (its sha256 is \
                 {}); import the ledger the committed record names, on a machine whose policy \
                 trusts the record's key",
                file.display(),
                project.path().display(),
                record::portable_sha256(&portable)
            ),
        ));
    };
    let ctx = Context::open(platform)?;
    let objects = record::commit_ledger(&ctx.store, &ctx.activity, &record, &portable)?;
    // Root it under the project now; the next closure write retains it
    // through the closure's references.
    crate::kernel::resolve::ledger::root(&ctx.store, &ctx.activity, project, &objects)?;
    let id = objects.ledger;
    ui::note(&format!(
        "attest: stored the {} ledger {id} and rooted it under {}",
        record.ecosystem,
        project.path().display()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::resolve::ledger::{Entry, PortableLedger};
    use crate::kernel::resolve::record::{
        file_digests, Isolation, LedgerSummary, RecordDoor, RecordFacts, Tool,
        FAIL_PUBLISH_FOR_TEST,
    };
    use crate::kernel::store::Store;
    use crate::kernel::testutil::TempDir;
    use std::sync::Mutex;

    /// `FAIL_PUBLISH_FOR_TEST` is process-global: the tests that publish
    /// run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Fixture {
        _temp: TempDir,
        store: Store,
        dir: PathBuf,
    }

    /// A store, and a project with one lock file per fake ecosystem.
    fn fixture(label: &str) -> Fixture {
        let temp = TempDir::named(&format!("attest-{label}"));
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp", "roots", "root-locks", "forests"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        for ecosystem in ["alpha", "beta"] {
            fs::write(dir.join(format!("{ecosystem}.lock")), "pinned 1.0.0\n").unwrap();
        }
        Fixture {
            store: Store::for_test(root.canonicalize().unwrap()),
            dir: dir.canonicalize().unwrap(),
            _temp: temp,
        }
    }

    /// What a passing check of `ecosystem` returns: a record over its lock
    /// as it is now.
    fn checked(dir: &Path, ecosystem: &str) -> (ResolutionRecord, Vec<u8>) {
        let project = ProjectRoot::open(dir).unwrap();
        let mut ledger = PortableLedger::new(ecosystem, "attest").unwrap();
        ledger.insert(Entry {
            class: "metadata".into(),
            method: "GET".into(),
            url: "https://registry.example/pinned".into(),
            status: 200,
            sha256: None,
            claimed: None,
            verified: false,
            freshness: None,
            redirected_to: None,
        });
        let record = ResolutionRecord::new(RecordFacts {
            ecosystem: ecosystem.into(),
            door: RecordDoor::Attest,
            tool: Tool {
                name: format!("{ecosystem}pm"),
                version: "1.0.0".into(),
            },
            command: vec!["check".into()],
            outputs: file_digests(&project, &[PathBuf::from(format!("{ecosystem}.lock"))]).unwrap(),
            inputs: Default::default(),
            ledger: LedgerSummary::of(&ledger.identity().object_id(), &ledger),
            isolation: Isolation::Confined,
            exceptions: Vec::new(),
        })
        .unwrap();
        let bytes = record::envelope_bytes(&record.envelope(None).unwrap()).unwrap();
        (record, bytes)
    }

    fn receipt(dir: &Path, ecosystem: &str) -> Option<Vec<u8>> {
        fs::read(dir.join(record::receipt_path(ecosystem))).ok()
    }

    /// Attest `alpha` then `beta` through the real two phases, publishing
    /// into the project; `beta_check` decides the second check.
    fn attest_both(
        fx: &Fixture,
        beta_check: impl Fn(&Path) -> io::Result<(ResolutionRecord, Vec<u8>)>,
    ) -> io::Result<()> {
        let activity = fx.store.activity(ActivityMode::Exclusive).unwrap();
        let project = ProjectRoot::open(&fx.dir).unwrap();
        check_then_publish(
            &["alpha", "beta"],
            |id| match id {
                "alpha" => Ok(checked(&fx.dir, "alpha")),
                _ => beta_check(&fx.dir),
            },
            |records| record::publish_receipts(&fx.store, &activity, &project, records),
        )
    }

    #[test]
    fn a_failed_later_check_leaves_no_receipt_for_an_earlier_one() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("second-fails");
        let error =
            attest_both(&fx, |_| Err(io::Error::other("beta's lock check failed"))).unwrap_err();
        assert!(error.to_string().contains("beta's lock check failed"));
        assert_eq!(receipt(&fx.dir, "alpha"), None);
        assert_eq!(receipt(&fx.dir, "beta"), None);
        assert!(!fx.dir.join(record::RESOLUTION_DIR).exists());
        // With both passing, both are published.
        attest_both(&fx, |dir| Ok(checked(dir, "beta"))).unwrap();
        assert_eq!(receipt(&fx.dir, "alpha"), Some(checked(&fx.dir, "alpha").1));
        assert_eq!(receipt(&fx.dir, "beta"), Some(checked(&fx.dir, "beta").1));
        assert!(!fx.dir.join(".tog/journal/alpha.json").exists());
    }

    #[test]
    fn a_check_returning_another_ecosystems_record_publishes_nothing() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("wrong-record");
        let error = attest_both(&fx, |dir| Ok(checked(dir, "alpha"))).unwrap_err();
        assert!(
            error.to_string().contains("returned a alpha record"),
            "{error}"
        );
        assert_eq!(receipt(&fx.dir, "alpha"), None);
    }

    /// Publishing the second receipt fails after the first was published:
    /// the first is put back as it was. With no prior receipt the new one
    /// is removed, and so are the directories this run created.
    #[test]
    fn a_failed_publication_removes_a_new_receipt_and_its_directories() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("rollback-absent");
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = Some("beta".into());
        let result = attest_both(&fx, |dir| Ok(checked(dir, "beta")));
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = None;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("simulated failure"), "{error}");
        assert!(error.contains("no receipt was published"), "{error}");
        assert_eq!(receipt(&fx.dir, "alpha"), None);
        assert!(!fx.dir.join(record::RESOLUTION_DIR).exists());
        assert!(!fx.dir.join(".tog").exists());
    }

    /// With a prior receipt, the first is restored byte for byte and with
    /// its own mode.
    #[test]
    fn a_failed_publication_restores_a_prior_receipt_and_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("rollback-prior");
        let prior = fx.dir.join(record::receipt_path("alpha"));
        fs::create_dir_all(fx.dir.join(record::RESOLUTION_DIR)).unwrap();
        fs::write(&prior, b"the prior receipt").unwrap();
        fs::set_permissions(&prior, fs::Permissions::from_mode(0o640)).unwrap();
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = Some("beta".into());
        let result = attest_both(&fx, |dir| Ok(checked(dir, "beta")));
        *FAIL_PUBLISH_FOR_TEST.lock().unwrap() = None;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("no receipt was published"), "{error}");
        assert_eq!(
            receipt(&fx.dir, "alpha").as_deref(),
            Some(&b"the prior receipt"[..])
        );
        assert_eq!(
            fs::metadata(&prior).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(receipt(&fx.dir, "beta"), None);
        assert!(fx.dir.join(record::RESOLUTION_DIR).is_dir());
        assert!(!fx.dir.join(".tog/journal/alpha.json").exists());
        assert!(!fx.dir.join(".tog/journal/beta.json").exists());
    }

    /// A lock that changed after its check passed is not given the record
    /// the check signed.
    #[test]
    fn a_lock_changed_after_its_check_is_not_published() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fx = fixture("changed");
        let error = attest_both(&fx, |dir| {
            let checked = checked(dir, "beta");
            fs::write(dir.join("alpha.lock"), "pinned 2.0.0\n").unwrap();
            Ok(checked)
        })
        .unwrap_err();
        assert!(error.to_string().contains("alpha.lock changed"), "{error}");
        assert_eq!(receipt(&fx.dir, "alpha"), None);
        assert_eq!(receipt(&fx.dir, "beta"), None);
    }
}

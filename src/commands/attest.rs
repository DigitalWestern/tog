//! `tog attest [<ecosystem>...]`: give existing locks a signed resolution
//! record, and move a record's ledger between machines.
//!
//! Attesting runs each ecosystem's own lock check through a verification
//! door (`Tailor::attest_lock`). A check that leaves the lock and manifest
//! byte-unchanged returns a record, which this command signs with the
//! process key and writes to `.tog/resolution/<ecosystem>.json`, or with
//! `--record-out` to a path outside the checkout. Every ecosystem is checked
//! before anything is written, so a failure leaves no partial set.
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
use crate::kernel::ui;
use crate::tailors::{self, Tailor};
use std::collections::BTreeSet;
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
    let ctx = Context::open(platform, true)?;
    project.check_still_named()?;
    let key = crate::comforter::signing_key();
    let mut records = Vec::new();
    for tailor in &targets {
        let selected = toolchain.get(tailor.lock_ecosystem())?;
        let record = tailor.attest_lock(&ctx, project, selected)?;
        if record.ecosystem != tailor.id() {
            return Err(io::Error::other(format!(
                "the {} lock check returned a {} record",
                tailor.id(),
                record.ecosystem
            )));
        }
        let envelope = record.envelope(key.as_deref())?;
        records.push((record, record::envelope_bytes(&envelope)?));
    }
    if key.is_none() {
        ui::warning(
            "resolution records written unsigned: TOG_SIGNING_KEY is not set, so no sync \
             will attest them",
            "export TOG_SIGNING_KEY=<key file your machine policy trusts>",
        );
    }
    for (record, bytes) in &records {
        let written = write_record(project, record, bytes, record_out, named.len() == 1)?;
        ui::note(&format!(
            "attest: {} {} record ({} {}) written to {}",
            record.ecosystem,
            record.door,
            record.tool.name,
            record.tool.version,
            written.display()
        ));
    }
    Ok(())
}

/// Write one signed record: into the project as its receipt, or under
/// `record_out` (the path itself when exactly one ecosystem was named,
/// else `<record_out>/<ecosystem>.json`). Returns where it went.
fn write_record(
    project: &ProjectRoot,
    record: &ResolutionRecord,
    bytes: &[u8],
    record_out: Option<&Path>,
    one_named: bool,
) -> io::Result<PathBuf> {
    let Some(out) = record_out else {
        let receipt = record::receipt_path(&record.ecosystem);
        project.write_file(&receipt, bytes)?;
        return Ok(project.path().join(receipt));
    };
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
    let ctx = Context::open(platform, false)?;
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
    let ctx = Context::open(platform, false)?;
    let id = record::commit_ledger(&ctx.store, &ctx.activity, &record.ecosystem, &portable)?;
    // Root it under the project now; the next closure write retains it
    // through the closure's references.
    let lock = ctx.store.project_lock_in(project)?;
    ctx.store.register_root_parts_with_project_lock(
        &ctx.activity,
        project,
        BTreeSet::from([id.clone()]),
        BTreeSet::new(),
        &lock,
    )?;
    ui::note(&format!(
        "attest: stored the {} ledger {id} and rooted it under {}",
        record.ecosystem,
        project.path().display()
    ));
    Ok(())
}

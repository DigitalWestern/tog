//! The Go resolution doors: the store go confined through the proxy
//! session's Go mirror, for the planner's tidy gate and closure download,
//! missing-lock `go mod tidy`, and `tog attest`'s lock check.

use super::tool::{run_go, run_go_checked, GoPublish, GoRun, OUTPUTS};
use super::{err, read_gomod, read_gosum, reject_local_replaces, reject_workspaces, tailor};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::ledger::LedgerObjects;
use crate::kernel::resolve::record;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Consistency gate: the tidy -diff first pass is non-mutating (prints a
/// diff, exit nonzero when go.mod/go.sum need changes). Needs the source
/// tree, so it runs on a snapshot of the project, confined, and may change
/// nothing in it. Its module cache is the persistent planner cache
/// (resolver-trust only; never feeds objects). The run's ledger is rooted
/// under the project and added to `ledgers`.
pub(super) fn is_tidy(
    door: &mut ResolutionDoor<'_>,
    go_obj: &Path,
    project: &ProjectRoot,
    gate_cache: &Path,
    ledgers: &mut Vec<LedgerObjects>,
) -> io::Result<bool> {
    let out = run_go(
        door,
        GoRun {
            go_obj,
            lock_root: project.path(),
            modcache: gate_cache,
            args: &["mod", "tidy", "-diff"],
            publish: GoPublish::Detached {
                project,
                discard: &[],
            },
        },
    )?;
    ledgers.extend(out.ledger);
    Ok(out.status.success())
}

/// The planner's persistent module cache, under the store root. Every Go
/// door binds it read-write as its `GOMODCACHE`. Only the confined store go
/// writes it, only from the proxy's Go route, and go checks each module it
/// adds against go.sum and the checksum database; a plan re-verifies every
/// artifact it names (`verified_module`), so nothing in it is trusted.
pub(crate) fn gate_cache(store: &Store) -> io::Result<PathBuf> {
    let gate_cache = store.root.join("planner-modcache");
    fs::create_dir_all(&gate_cache)?;
    Ok(gate_cache)
}

/// `prepare`: go.mod and go.sum brought up to date by the store `go mod
/// tidy` when the tidy gate fails, the same delegated mutation as `cargo
/// generate-lockfile`. The one place the Go tailor writes project inputs;
/// a plan that finds the pair untidy refuses instead. The tidy runs
/// confined through `door` (a missing-lock door), and go.mod, go.sum and the
/// signed resolution record are published together through its
/// transaction.
pub fn tidy_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    go_obj: &Path,
    tool: record::Tool,
) -> io::Result<()> {
    reject_workspaces(project)?;
    let gomod =
        read_gomod(project).map_err(|e| io::Error::new(e.kind(), format!("go.mod: {e}")))?;
    reject_local_replaces(&gomod)?;
    let gate_cache = gate_cache(door.store())?;
    let tidy = is_tidy(
        &mut door.reopen(DoorKind::Planner),
        go_obj,
        project,
        &gate_cache,
        &mut Vec::new(),
    )?;
    if tidy {
        return Ok(());
    }
    ui::note("go.mod/go.sum need updating; resolving with the store go mod tidy...");
    let args = ["mod", "tidy"];
    let spec = crate::tailors::record_spec(&tailor::Go, project, tool, &args)?;
    run_go_checked(
        door,
        GoRun {
            go_obj,
            lock_root: project.path(),
            modcache: &gate_cache,
            args: &args,
            publish: GoPublish::Project {
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(())
}

/// `tog attest` for Go: the module closure downloads (`go mod download
/// -json all`, in a disposable copy, so a lock it would extend is caught by
/// the next step rather than hidden), then `go mod tidy -diff` in the project
/// through `door`'s transaction with the record's producer. The record
/// carries the tidy check's ledger; the download's is rooted under the
/// project beside it. A pair go would change, or a check that fails,
/// publishes nothing.
pub fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    go_obj: &Path,
    tool: record::Tool,
    publish_receipt: bool,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    reject_workspaces(project)?;
    let gomod =
        read_gomod(project).map_err(|e| io::Error::new(e.kind(), format!("go.mod: {e}")))?;
    reject_local_replaces(&gomod)?;
    let gosum = read_gosum(project)?.unwrap_or_default();
    let (store, activity) = (door.store(), door.lease());
    let gate_cache = gate_cache(store)?;
    let scratch = store.stage_with_activity(activity)?;
    let downloaded = download_closure(
        door,
        project,
        go_obj,
        &scratch.join("attest"),
        &gate_cache,
        &gomod,
        &gosum,
        &mut Vec::new(),
    );
    let _ = crate::kernel::store::remove_tree(&scratch);
    let downloaded = downloaded?;
    if !downloaded.status.success() {
        return Err(err(format!(
            "go's lock check failed: go mod download: {}",
            String::from_utf8_lossy(&downloaded.stderr).trim()
        )));
    }
    let args = ["mod", "tidy", "-diff"];
    let mut spec = crate::tailors::record_spec(&tailor::Go, project, tool, &args)?;
    spec.require_unchanged = true;
    spec.publish_receipt = publish_receipt;
    let slot = record::RecordSlot::default();
    let report = run_go(
        door,
        GoRun {
            go_obj,
            lock_root: project.path(),
            modcache: &gate_cache,
            args: &args,
            publish: GoPublish::Project {
                receipt: Some(record::producer(spec, slot.clone())),
            },
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "go.mod and go.sum in {} are not what go mod tidy would write, so they are not \
             attested; run `tog` to bring them up to date and commit the result\n{}",
            project.path().display(),
            String::from_utf8_lossy(&report.stdout).trim()
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("go's lock check published no record"))
}

/// The go a resolution record names: the selected release.
pub(crate) fn go_tool(toolchain: &Selected) -> io::Result<record::Tool> {
    Ok(record::Tool {
        name: "go".to_string(),
        version: toolchain.version("go")?.to_string(),
    })
}

/// Run the closure download in a DISPOSABLE copy of the manifest (go mod
/// download may rewrite go.mod/go.sum, which are discarded). The module
/// cache is the persistent planner cache: warm downloads, and trust is
/// irrelevant because every artifact is re-verified by
/// `closure_from_download`. The run's ledger is rooted under `project` and
/// added to `ledgers`.
#[allow(clippy::too_many_arguments)]
pub(super) fn download_closure(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    go_obj: &Path,
    work: &Path,
    gate_cache: &Path,
    gomod: &str,
    gosum: &str,
    ledgers: &mut Vec<LedgerObjects>,
) -> io::Result<std::process::Output> {
    fs::create_dir_all(work)?;
    fs::write(work.join("go.mod"), gomod)?;
    if !gosum.is_empty() {
        fs::write(work.join("go.sum"), gosum)?;
    }
    ui::note("computing Go module closure with the store toolchain...");
    let report = run_go(
        door,
        GoRun {
            go_obj,
            lock_root: work,
            modcache: gate_cache,
            args: &["mod", "download", "-json", "all"],
            publish: GoPublish::Detached {
                project,
                discard: &OUTPUTS,
            },
        },
    )?;
    ledgers.extend(report.ledger.clone());
    Ok(report.into())
}

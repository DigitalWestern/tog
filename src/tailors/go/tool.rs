//! Running the store go: as a resolver confined through the door, reaching
//! the network only through the proxy session's Go mirror, or with the
//! module proxy off as a host-local helper.

use super::go_env;
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::door::{ConfinedSpec, ReceiptProducer, Target, Wire, Wiring};
use crate::kernel::resolve::ledger;
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The store go with tog's forced environment, its output captured.
pub(super) fn go_spec(
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    offline: bool,
    args: &[&str],
) -> DelegateSpec {
    let mut spec = DelegateSpec::new(go_obj.join("bin/go"));
    spec.args(args).lock_root(cwd).capture();
    for (k, v) in go_env(go_obj, modcache, offline) {
        if v.is_empty() {
            spec.env_remove(&k);
        } else {
            spec.env(&k, &v);
        }
    }
    spec
}

/// Where a confined go run's results go.
pub(crate) enum GoPublish<'a> {
    /// A planner or check run: nothing in the lock root may change except
    /// the files in `discard` (a disposable work copy's go.mod and go.sum),
    /// which are thrown away. The ledger is rooted under `project`.
    Detached {
        project: &'a ProjectRoot,
        discard: &'a [&'a str],
    },
    /// A run in the project whose go.mod and go.sum are published through
    /// the transaction, with the receipt the producer makes.
    Project {
        receipt: Option<ReceiptProducer<'a>>,
    },
}

/// One confined run of the store go.
pub(crate) struct GoRun<'a> {
    pub go_obj: &'a Path,
    /// The directory go runs in: the project, or a tog-owned work copy.
    pub lock_root: &'a Path,
    /// The persistent planner module cache, bound read-write.
    pub modcache: &'a Path,
    pub args: &'a [&'a str],
    pub publish: GoPublish<'a>,
}

/// Why go runs isolated, for the missing-capability message.
const WHY: &str = "fetches modules from the network and reads the project's go.mod";

/// The files a Go door may publish.
pub(crate) const OUTPUTS: [&str; 2] = ["go.mod", "go.sum"];

/// The `ConfinedSpec` of `run`, through the process proxy on the Go route.
/// Tests replace the route, the proxy, and the permitted set.
pub(crate) fn go_confined<'a>(
    run: &GoRun<'_>,
    publish: GoPublish<'a>,
) -> io::Result<ConfinedSpec<'a>> {
    let mut confined = ConfinedSpec::new("go", "go", WHY);
    confined.store_reads = vec![run.go_obj.to_path_buf()];
    confined.cache_roots = vec![fs::canonicalize(run.modcache)?];
    confined.routes = vec![super::registry::route()?];
    confined.wire = Some(Box::new(|wire: &Wire<'_>| {
        Ok(Wiring {
            args: wire.args.to_vec(),
            env: super::registry::proxy_env(wire.address)
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            ..Wiring::default()
        })
    }));
    match publish {
        GoPublish::Detached { discard, .. } => {
            confined.target = Target::Detached;
            confined.scratch_outputs = discard
                .iter()
                .map(|path| PathGlob::new(path))
                .collect::<io::Result<_>>()?;
        }
        GoPublish::Project { receipt } => {
            confined.outputs = OUTPUTS.iter().map(PathBuf::from).collect();
            confined.target = Target::Project { receipt };
        }
    }
    Ok(confined)
}

/// Run the store go confined through `door`. A Detached run's ledger is
/// rooted under its project before this returns, and its ids come back in
/// the report for the closure's references.
pub(crate) fn run_go(
    door: &mut ResolutionDoor<'_>,
    mut run: GoRun<'_>,
) -> io::Result<DelegateReport> {
    let publish = std::mem::replace(&mut run.publish, GoPublish::Project { receipt: None });
    let project = match &publish {
        GoPublish::Detached { project, .. } => Some(*project),
        GoPublish::Project { .. } => None,
    };
    let confined = go_confined(&run, publish)?;
    let spec = go_spec(run.go_obj, run.lock_root, run.modcache, false, run.args);
    let report = door
        .run_confined(spec, confined)
        .map_err(|e| io::Error::new(e.kind(), format!("store go {}: {e}", run.args.join(" "))))?;
    if let (Some(project), Some(objects)) = (project, &report.ledger) {
        ledger::root(door.store(), door.lease(), project, objects)?;
    }
    Ok(report)
}

/// `run_go` that fails on a nonzero exit, naming go's own words.
pub(crate) fn run_go_checked(
    door: &mut ResolutionDoor<'_>,
    run: GoRun<'_>,
) -> io::Result<DelegateReport> {
    let args = run.args.join(" ");
    let report = run_go(door, run)?;
    if crate::kernel::ui::verbose() {
        eprint!("{}", String::from_utf8_lossy(&report.stdout));
    }
    if !report.status.success() {
        return Err(io::Error::other(format!(
            "store go {args} failed: {}",
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    Ok(report)
}

/// The command `run_go_offline` starts. With the proxy off nothing should
/// fetch; `GOVCS` and `GOAUTH` close the remaining ways a module could (a
/// version-control fetch, an auth helper), `HOME` in `cwd` and no
/// `XDG_CONFIG_HOME` keep the user's Go configuration out, and the
/// host-local tripwire requires all of them.
pub(super) fn offline_command(
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    args: &[&str],
) -> std::process::Command {
    let mut spec = go_spec(go_obj, cwd, modcache, true, args);
    spec.env("GOVCS", "*:off")
        .env("GOAUTH", "off")
        .env("HOME", cwd)
        .env_remove("XDG_CONFIG_HOME");
    spec.command()
}

/// The store go with the module proxy off (`GOPROXY=off`): an extraction
/// from a module cache tog staged, a host-local helper.
pub(super) fn run_go_offline(
    activity: &StoreActivity,
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    args: &[&str],
) -> io::Result<std::process::Output> {
    telemetry_off(cwd)?;
    let mut cmd = offline_command(go_obj, cwd, modcache, args);
    crate::kernel::supervise::local_output(&mut cmd, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store go {args:?}: {e}")))
}

/// Turn Go telemetry off for a run whose `HOME` is `home` (with no
/// `XDG_CONFIG_HOME`, Go's config directory is `home/.config`). A fresh
/// `HOME` has no mode file, and Go would otherwise start its telemetry
/// child on every run, which can outlive the run and write into a
/// directory tog is about to remove.
fn telemetry_off(home: &Path) -> io::Result<()> {
    let dir = home.join(".config/go/telemetry");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("mode"), "off\n")
}

//! Running the store go: as a resolver through the door, or with the
//! module proxy off as a host-local helper.

use super::go_env;
use crate::kernel::activity::StoreActivity;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use std::io;
use std::path::Path;

/// Run the store Go for a delegated edit (`tog add` and friends).
pub(crate) fn run_checked(
    door: &mut ResolutionDoor<'_>,
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<()> {
    crate::kernel::ui::trace(&format!(
        "run: go {} (in {})",
        args.join(" "),
        cwd.display()
    ));
    let out = run_go(door, go_obj, cwd, modcache, offline, args)?;
    if crate::kernel::ui::verbose() {
        eprint!("{}", String::from_utf8_lossy(&out.stdout));
    }
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "store go {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

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

/// The store go as a resolver: through the door.
pub(super) fn run_go(
    door: &mut ResolutionDoor<'_>,
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<DelegateReport> {
    door.run(go_spec(go_obj, cwd, modcache, offline, args))
        .map_err(|e| io::Error::new(e.kind(), format!("run store go {args:?}: {e}")))
}

/// The command `run_go_offline` starts. With the proxy off nothing should
/// fetch; `GOVCS` and `GOAUTH` close the remaining ways a module could (a
/// version-control fetch, an auth helper), and the host-local tripwire
/// requires them.
pub(super) fn offline_command(
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    args: &[&str],
) -> std::process::Command {
    let mut spec = go_spec(go_obj, cwd, modcache, true, args);
    spec.env("GOVCS", "*:off").env("GOAUTH", "off");
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
    let mut cmd = offline_command(go_obj, cwd, modcache, args);
    crate::kernel::supervise::local_output(&mut cmd, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store go {args:?}: {e}")))
}

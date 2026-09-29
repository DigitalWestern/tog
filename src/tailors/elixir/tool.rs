//! Running the store mix and elixir: as a resolver through the door, or
//! the helper's offline `hexmark` mode as a host-local helper.

use super::{beam_path, forced_env, ENV_REMOVE, ENV_REMOVE_PREFIXES};
use crate::kernel::activity::StoreActivity;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use std::io;
use std::path::Path;
use std::process::Command;

/// Run the store mix for a delegated edit (`tog update`).
pub(crate) fn run_checked(
    door: &mut ResolutionDoor<'_>,
    beam_obj: &Path,
    cwd: &Path,
    scratch: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<()> {
    crate::kernel::ui::trace(&format!("run: {} (in {})", args.join(" "), cwd.display()));
    let out = run_mix(door, beam_obj, cwd, scratch, offline, args)?;
    if crate::kernel::ui::verbose() {
        eprint!("{}", String::from_utf8_lossy(&out.stdout));
    }
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "store {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The store mix or elixir with tog's forced environment, its output
/// captured.
pub(super) fn mix_spec(
    beam_obj: &Path,
    cwd: &Path,
    scratch: &Path,
    offline: bool,
    args: &[&str],
) -> DelegateSpec {
    let mut spec = DelegateSpec::new(beam_obj.join("elixir/bin").join(args[0]));
    spec.args(&args[1..]).lock_root(cwd);
    spec.env("PATH", beam_path(beam_obj));
    spec.env("HOME", scratch);
    spec.env("TMPDIR", scratch);
    let mut set = forced_env(beam_obj, &scratch.join("deps"), scratch);
    if !offline {
        set.retain(|(k, _)| k != "HEX_OFFLINE");
    }
    spec.force_env(ENV_REMOVE_PREFIXES, ENV_REMOVE, &set);
    spec.capture();
    spec
}

/// The store mix as a resolver: through the door.
pub(super) fn run_mix(
    door: &mut ResolutionDoor<'_>,
    beam_obj: &Path,
    cwd: &Path,
    scratch: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<DelegateReport> {
    door.run(mix_spec(beam_obj, cwd, scratch, offline, args))
        .map_err(|e| io::Error::new(e.kind(), format!("run store mix {args:?}: {e}")))
}

/// The helper's offline `hexmark` mode (`HEX_OFFLINE=1`): a host-local
/// helper over a dependency tog already verified.
pub(super) fn run_hexmark(
    activity: &StoreActivity,
    beam_obj: &Path,
    scratch: &Path,
    args: &[&str],
) -> io::Result<std::process::Output> {
    let mut cmd = hexmark_command(beam_obj, scratch, args);
    crate::kernel::supervise::local_output(&mut cmd, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store mix {args:?}: {e}")))
}

/// The command `run_hexmark` starts: the offline mix environment, with no
/// `XDG_CONFIG_HOME` through which a user `.erlang` could run.
pub(super) fn hexmark_command(beam_obj: &Path, scratch: &Path, args: &[&str]) -> Command {
    let mut command = mix_spec(beam_obj, scratch, scratch, true, args).command();
    command.env_remove("XDG_CONFIG_HOME");
    command
}

/// The command `probe_otp_runtime` starts: the staged `erl` evaluating the
/// reviewed probe in an empty environment.
pub(super) fn otp_probe_command(otp_root: &Path, scratch: &Path) -> Command {
    let mut command = Command::new(otp_root.join("bin/erl"));
    command
        .args([
            "-noshell",
            "-eval",
            crate::kernel::resolve::tripwire::OTP_RUNTIME_PROBE,
        ])
        .current_dir(scratch);
    // Every inherited variable removed by name rather than `env_clear`:
    // the same empty environment, but the removals stay visible to the
    // host-local tripwire, which requires the probe inherit nothing.
    for (key, _) in std::env::vars_os() {
        command.env_remove(key);
    }
    command
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env("LANG", "C")
        .stdin(std::process::Stdio::null());
    command
}

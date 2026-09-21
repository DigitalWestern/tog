//! Hermetic build sandbox with sandbox-exec/Seatbelt on macOS and bubblewrap
//! on Linux.
//!
//! Deny-by-default profile: no network, reads limited to declared inputs
//! (store + system runtime), writes limited to the build's private
//! directories. This is a hermeticity mechanism, not containment for
//! hostile code — it makes "undeclared network access fails" true, which is
//! what the kernel needs.
//!
//! Unix sockets in writable roots, the working directory, and scratch are
//! rejected before mounting. Immutable read roots are intentionally not
//! scanned: sockets there remain an accepted cooperative-hermeticity gap.

use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// A sandboxed build, ecosystem-agnostic: tailors construct the spec — argv,
/// environment, read/write roots, scratch — and the kernel executes it. Keeps
/// sandbox policy in one place as tailors multiply.
pub struct BuildSpec {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    /// Read-only roots beyond the system defaults (store objects, project).
    pub read: Vec<PathBuf>,
    /// Writable roots (outputs, caches). scratch is added automatically.
    pub write: Vec<PathBuf>,
    /// Writable scratch dir; becomes HOME and TMPDIR.
    pub scratch: PathBuf,
    /// PATH inside the sandbox.
    pub path: String,
}

/// Strip every inherited variable whose name starts with one of
/// `remove_prefixes` (compared ASCII case-insensitively: npm and pnpm collect
/// their settings with `/^npm_config_/i`, so `Npm_Config_registry` is as live
/// as `npm_config_registry`, and removing more of the user's environment is
/// the safe direction for every other prefix list too) or equals one of
/// `remove` (exact), then apply `set` last so tog's values win.
pub fn force_env(
    cmd: &mut Command,
    remove_prefixes: &[&str],
    remove: &[&str],
    set: &[(String, String)],
) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().into_owned();
        // `str::get` rather than `name[..len]`: the index is a byte offset
        // that need not be a char boundary, and `to_string_lossy` turns any
        // invalid byte into a three-byte replacement character, so slicing
        // panics on env names tog does not control. Out-of-boundary and
        // too-short both yield `None`, which is "no match".
        let has_prefix = remove_prefixes.iter().any(|prefix| {
            name.get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        });
        if has_prefix || remove.contains(&name.as_str()) {
            cmd.env_remove(&key);
        }
    }
    for (k, v) in set {
        cmd.env(k, v);
    }
}

pub fn run_build_spec(spec: &BuildSpec) -> io::Result<()> {
    run_build_spec_on(Platform::host()?, spec)
}

pub(crate) fn run_build_spec_on(platform: Platform, spec: &BuildSpec) -> io::Result<()> {
    let status = run_build_spec_status_on(platform, spec)?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "sandboxed command failed ({status}): {}",
            crate::kernel::ui::shell_line(&spec.argv)
        ),
    ))
}

/// Store-consuming counterpart to `run_build_spec_on`. The activity lease is
/// held through sandbox setup, the child, and its reap.
pub(crate) fn run_build_spec_on_for_store(
    platform: Platform,
    spec: &BuildSpec,
    store: &Store,
) -> io::Result<()> {
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    run_build_spec_on_with_activity(platform, spec, &activity)
}

pub(crate) fn run_build_spec_on_with_activity(
    platform: Platform,
    spec: &BuildSpec,
    activity: &StoreActivity,
) -> io::Result<()> {
    let status = run_build_spec_status_on_with_activity(platform, spec, activity)?;
    if status.success() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "sandboxed command failed ({status}): {}",
            crate::kernel::ui::shell_line(&spec.argv)
        ),
    ))
}

/// Run a build specification and return the child status. Sandbox setup
/// failures remain errors, while a command's ordinary non-zero status is
/// returned to callers that must preserve tool exit semantics (for example
/// `rustfmt --check`).
pub(crate) fn run_build_spec_status_on(
    platform: Platform,
    spec: &BuildSpec,
) -> io::Result<std::process::ExitStatus> {
    let argv: Vec<&str> = spec.argv.iter().map(String::as_str).collect();
    let mut write: Vec<&Path> = spec.write.iter().map(PathBuf::as_path).collect();
    write.push(&spec.scratch);
    let sandbox = Sandbox {
        read: spec.read.iter().map(PathBuf::as_path).collect(),
        write,
    };
    sandbox.run_in_status_on(
        platform,
        &argv,
        &spec.path,
        &spec.scratch,
        &spec.cwd,
        &spec.env,
    )
}

pub(crate) fn run_build_spec_status_on_for_store(
    platform: Platform,
    spec: &BuildSpec,
    store: &Store,
) -> io::Result<std::process::ExitStatus> {
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    run_build_spec_status_on_with_activity(platform, spec, &activity)
}

pub(crate) fn run_build_spec_status_on_with_activity(
    platform: Platform,
    spec: &BuildSpec,
    activity: &StoreActivity,
) -> io::Result<std::process::ExitStatus> {
    let argv: Vec<&str> = spec.argv.iter().map(String::as_str).collect();
    let mut write: Vec<&Path> = spec.write.iter().map(PathBuf::as_path).collect();
    write.push(&spec.scratch);
    let sandbox = Sandbox {
        read: spec.read.iter().map(PathBuf::as_path).collect(),
        write,
    };
    sandbox.run_in_status_on_with_activity(
        platform,
        &argv,
        &spec.path,
        &spec.scratch,
        &spec.cwd,
        &spec.env,
        activity,
    )
}

pub struct Sandbox<'a> {
    /// Directories the build may read (store objects, staged sources).
    pub read: Vec<&'a Path>,
    /// Directories the build may read AND write (build tmp, output).
    pub write: Vec<&'a Path>,
}

impl Sandbox<'_> {
    fn profile(&self) -> String {
        let mut p = String::from(
            "(version 1)\n\
             (deny default)\n\
             (deny network*)\n\
             ; process basics\n\
             (allow process-exec*)\n\
             (allow process-fork)\n\
             (allow process-info*)\n\
             (allow signal (target same-sandbox))\n\
             (allow sysctl-read)\n\
             (allow mach-lookup)\n\
             ; dyld must map dylibs; without this every exec SIGABRTs\n\
             (allow file-map-executable)\n\
             (allow file-read* (literal \"/\"))\n\
             ; system runtime, read-only\n\
             (allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\")\n\
                (subpath \"/System\") (subpath \"/Library\") (subpath \"/private/etc\")\n\
                (subpath \"/opt\") (subpath \"/var/db/timezone\") (subpath \"/dev\"))\n\
             ; C/C++ toolchain (read-only): Xcode or CLT via xcode-select\n\
             (allow file-read* (subpath \"/Applications/Xcode.app\")\n\
                (literal \"/var/db/xcode_select_link\")\n\
                (literal \"/private/var/db/xcode_select_link\"))\n\
             (allow file-read-metadata)\n\
             (allow file-write-data (literal \"/dev/null\") (literal \"/dev/dtracehelper\"))\n",
        );
        for r in &self.read {
            p.push_str(&format!(
                "(allow file-read* (subpath {:?}))\n",
                r.display().to_string()
            ));
        }
        for w in &self.write {
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath {:?}))\n",
                w.display().to_string()
            ));
        }
        p
    }

    /// Run `cmd` inside the sandbox with a scrubbed environment.
    /// `env_path` becomes PATH; HOME/TMPDIR point into the writable tmp.
    pub fn run(&self, cmd: &[&str], env_path: &str, tmp: &Path) -> io::Result<()> {
        self.run_in(cmd, env_path, tmp, tmp, &[])
    }

    /// Like `run`, but with an explicit working directory and extra
    /// environment variables (npm lifecycle scripts need npm_config_*).
    pub fn run_in(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<()> {
        self.run_in_on(Platform::host()?, cmd, env_path, tmp, cwd, envs)
    }

    pub(crate) fn run_in_on(
        &self,
        platform: Platform,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<()> {
        let status = self.run_in_status_on(platform, cmd, env_path, tmp, cwd, envs)?;
        if status.success() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "sandboxed command failed ({status}): {}",
                crate::kernel::ui::shell_line(cmd)
            ),
        ))
    }

    pub(crate) fn run_in_on_with_activity(
        &self,
        platform: Platform,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
        activity: &StoreActivity,
    ) -> io::Result<()> {
        let status =
            self.run_in_status_on_with_activity(platform, cmd, env_path, tmp, cwd, envs, activity)?;
        if status.success() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "sandboxed command failed ({status}): {}",
                crate::kernel::ui::shell_line(cmd)
            ),
        ))
    }

    fn run_in_status_on(
        &self,
        platform: Platform,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<std::process::ExitStatus> {
        match platform {
            Platform::Aarch64AppleDarwin => self.run_seatbelt_status(cmd, env_path, tmp, cwd, envs),
            Platform::X86_64UnknownLinuxGnu => self.run_bwrap_status(cmd, env_path, tmp, cwd, envs),
        }
    }

    fn run_in_status_on_with_activity(
        &self,
        platform: Platform,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
        activity: &StoreActivity,
    ) -> io::Result<std::process::ExitStatus> {
        match platform {
            Platform::Aarch64AppleDarwin => {
                self.run_seatbelt_status_with_activity(cmd, env_path, tmp, cwd, envs, activity)
            }
            Platform::X86_64UnknownLinuxGnu => {
                self.run_bwrap_status_with_activity(cmd, env_path, tmp, cwd, envs, activity)
            }
        }
    }

    fn run_seatbelt_status(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<std::process::ExitStatus> {
        let profile = self.profile();
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(&profile)
            .args(cmd)
            .current_dir(cwd) // cwd must be readable in-sandbox (getcwd)
            .env_clear()
            .env("PATH", env_path)
            .env("HOME", tmp)
            .env("TMPDIR", tmp)
            .env("LANG", "en_US.UTF-8")
            .env("SOURCE_DATE_EPOCH", "315532800"); // reproducibility nudge
        for (k, v) in envs {
            command.env(k, v);
        }
        // Keep the historical unmanaged entry point available to tests and
        // callers that do not consume a store. Production store callers use
        // the activity-aware sibling below.
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::inherit());
        command.stderr(std::process::Stdio::piped());
        let child = command.spawn()?;
        let output = wait_with_stderr_relay(child)?;
        if let Some(SandboxFailureKind::Setup) =
            classify_sandbox_failure(&output.status, &output.stderr)
        {
            return Err(sandbox_failure_error(
                SandboxFailureKind::Setup,
                &output.status,
                &output.stderr,
                cmd,
            ));
        }
        Ok(output.status)
    }

    fn run_seatbelt_status_with_activity(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
        activity: &StoreActivity,
    ) -> io::Result<std::process::ExitStatus> {
        let profile = self.profile();
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(&profile)
            .args(cmd)
            .current_dir(cwd) // cwd must be readable in-sandbox (getcwd)
            .env_clear()
            .env("PATH", env_path)
            .env("HOME", tmp)
            .env("TMPDIR", tmp)
            .env("LANG", "en_US.UTF-8")
            .env("SOURCE_DATE_EPOCH", "315532800"); // reproducibility nudge
        for (k, v) in envs {
            command.env(k, v);
        }
        let (status, stderr) =
            crate::kernel::supervise::status_with_stderr(&mut command, activity)?;
        if let Some(SandboxFailureKind::Setup) = classify_sandbox_failure(&status, &stderr) {
            return Err(sandbox_failure_error(
                SandboxFailureKind::Setup,
                &status,
                &stderr,
                cmd,
            ));
        }
        Ok(status)
    }

    fn run_bwrap_status(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<std::process::ExitStatus> {
        self.run_bwrap_status_inner(cmd, env_path, tmp, cwd, envs, None)
    }

    fn run_bwrap_status_with_activity(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
        activity: &StoreActivity,
    ) -> io::Result<std::process::ExitStatus> {
        self.run_bwrap_status_inner(cmd, env_path, tmp, cwd, envs, Some(activity))
    }

    fn run_bwrap_status_inner(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
        activity: Option<&StoreActivity>,
    ) -> io::Result<std::process::ExitStatus> {
        if let Some(activity) = activity {
            self.reject_host_sockets(cwd, tmp)?;
            let bwrap = bwrap_preflight_with_activity(Some(activity))?;
            let args = self.bwrap_args(cmd, env_path, tmp, cwd, envs)?;
            let mut command = bwrap_command(bwrap)?;
            command
                .args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::piped());
            let (status, stderr) =
                crate::kernel::supervise::status_with_stderr(&mut command, activity)?;
            if let Some(SandboxFailureKind::Setup) = classify_sandbox_failure(&status, &stderr) {
                return Err(sandbox_failure_error(
                    SandboxFailureKind::Setup,
                    &status,
                    &stderr,
                    cmd,
                ));
            }
            return Ok(status);
        }
        let output = self.run_bwrap_with_stdout(
            cmd,
            env_path,
            tmp,
            cwd,
            envs,
            std::process::Stdio::inherit(),
        )?;
        if let Some(SandboxFailureKind::Setup) =
            classify_sandbox_failure(&output.status, &output.stderr)
        {
            return Err(sandbox_failure_error(
                SandboxFailureKind::Setup,
                &output.status,
                &output.stderr,
                cmd,
            ));
        }
        Ok(output.status)
    }

    fn run_bwrap_with_stdout(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
        stdout: std::process::Stdio,
    ) -> io::Result<std::process::Output> {
        self.reject_host_sockets(cwd, tmp)?;
        let bwrap = bwrap_preflight()?;
        let args = self.bwrap_args(cmd, env_path, tmp, cwd, envs)?;
        let mut command = bwrap_command(bwrap)?;
        // stderr is piped so bwrap's own setup errors ("bwrap: ...") can be
        // classified, but the build's diagnostics must still reach the user:
        // a relay thread streams every byte to our stderr and keeps the
        // leading bytes for classification.
        let child = command
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(stdout)
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        wait_with_stderr_relay(child)
    }

    fn reject_host_sockets(&self, cwd: &Path, scratch: &Path) -> io::Result<()> {
        let mut roots = Vec::with_capacity(self.write.len() + 2);
        roots.extend(self.write.iter().copied());
        roots.push(cwd);
        roots.push(scratch);

        let mut scanned = Vec::new();
        for root in roots {
            let root = fs::canonicalize(root)?;
            if scanned
                .iter()
                .any(|parent: &PathBuf| root.starts_with(parent))
            {
                continue;
            }
            scanned.retain(|parent| !parent.starts_with(&root));
            if let Some(socket) = find_socket_without_following_symlinks(&root)? {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "host Unix socket exposed by sandbox path: {}",
                        socket.display()
                    ),
                ));
            }
            scanned.push(root);
        }
        Ok(())
    }

    fn bwrap_args(
        &self,
        cmd: &[&str],
        env_path: &str,
        tmp: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<Vec<OsString>> {
        let read: Vec<PathBuf> = self
            .read
            .iter()
            .map(|path| fs::canonicalize(path))
            .collect::<io::Result<_>>()?;
        let mut write: Vec<PathBuf> = self
            .write
            .iter()
            .map(|path| fs::canonicalize(path))
            .collect::<io::Result<_>>()?;
        let scratch = fs::canonicalize(tmp)?;
        let cwd = fs::canonicalize(cwd)?;
        if !write.iter().any(|path| path == &scratch) {
            write.push(scratch.clone());
        }

        let mut args = vec![
            OsString::from("--unshare-user"),
            OsString::from("--unshare-net"),
            OsString::from("--unshare-pid"),
            OsString::from("--unshare-ipc"),
            OsString::from("--unshare-uts"),
            OsString::from("--hostname"),
            OsString::from("tog"),
            OsString::from("--unshare-cgroup-try"),
            OsString::from("--die-with-parent"),
            OsString::from("--new-session"),
            OsString::from("--clearenv"),
        ];
        push_bind(&mut args, "--ro-bind", "/usr", "/usr");
        push_arg(&mut args, "--symlink");
        push_arg(&mut args, "usr/bin");
        push_arg(&mut args, "/bin");
        push_arg(&mut args, "--symlink");
        push_arg(&mut args, "usr/lib");
        push_arg(&mut args, "/lib");
        push_arg(&mut args, "--symlink");
        push_arg(&mut args, "usr/lib64");
        push_arg(&mut args, "/lib64");
        push_arg(&mut args, "--symlink");
        push_arg(&mut args, "usr/sbin");
        push_arg(&mut args, "/sbin");

        for item in [
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/alternatives",
            "/etc/localtime",
            "/etc/passwd",
            "/etc/group",
            "/etc/nsswitch.conf",
            "/etc/hosts",
        ] {
            if Path::new(item).exists() {
                push_bind(&mut args, "--ro-bind", item, item);
            }
        }
        push_arg(&mut args, "--dev");
        push_arg(&mut args, "/dev");
        push_arg(&mut args, "--proc");
        push_arg(&mut args, "/proc");
        push_arg(&mut args, "--tmpfs");
        push_arg(&mut args, "/tmp");

        let cwd_is_declared = read
            .iter()
            .chain(write.iter())
            .any(|root| cwd.starts_with(root));
        if !cwd_is_declared {
            // An undeclared cwd must exist so the command can start there,
            // but nothing under it was declared readable: give it an empty
            // tmpfs (Seatbelt grants only metadata reads on an undeclared
            // cwd; a read-only bind here would expose the whole subtree).
            // Mounted before declared children so a declared child under
            // it still binds on top.
            push_arg(&mut args, "--tmpfs");
            push_arg(&mut args, cwd.as_os_str());
        }
        for path in &read {
            push_bind_path(&mut args, "--ro-bind", path);
        }
        for path in &write {
            push_bind_path(&mut args, "--bind", path);
        }

        push_setenv(&mut args, "PATH", env_path);
        push_setenv(&mut args, "HOME", &scratch);
        push_setenv(&mut args, "TMPDIR", &scratch);
        push_setenv(&mut args, "LANG", "en_US.UTF-8");
        push_setenv(&mut args, "SOURCE_DATE_EPOCH", "315532800");
        for (key, value) in envs {
            push_setenv(&mut args, key, value);
        }
        push_arg(&mut args, "--chdir");
        args.push(cwd.into_os_string());
        push_arg(&mut args, "--unsetenv");
        push_arg(&mut args, "PWD");

        // bwrap 0.12 adds PWD while processing --chdir. Keep the environment
        // identical to Seatbelt's env_clear projection in the exec transition.
        push_arg(&mut args, "/usr/bin/env");
        push_arg(&mut args, "-u");
        push_arg(&mut args, "PWD");
        push_arg(&mut args, "--");
        args.extend(cmd.iter().map(|arg| OsString::from(arg)));
        Ok(args)
    }
}

/// Longest stderr prefix retained for sandbox setup classification; bwrap's own
/// setup errors are a single short line.
const STDERR_PREFIX_LIMIT: usize = 4096;

/// Copy a child's stderr to ours as it arrives, retaining the first
/// `STDERR_PREFIX_LIMIT` bytes. Relay failures (e.g. our stderr closed) are
/// ignored: they must not turn a successful build into a failure.
fn relay_stderr(mut stderr: std::process::ChildStderr) -> Vec<u8> {
    use std::io::{Read as _, Write as _};
    let mut prefix = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut sink = io::stderr();
    loop {
        let read = match stderr.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let keep = read.min(STDERR_PREFIX_LIMIT - prefix.len());
        prefix.extend_from_slice(&buffer[..keep]);
        let _ = sink.write_all(&buffer[..read]);
    }
    let _ = sink.flush();
    prefix
}

fn wait_with_stderr_relay(mut child: std::process::Child) -> io::Result<std::process::Output> {
    let stderr = child.stderr.take().expect("stderr is piped");
    let relay = std::thread::spawn(move || relay_stderr(stderr));
    let output = child.wait_with_output()?;
    let stderr = relay.join().map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "sandbox stderr relay thread panicked")
    })?;
    Ok(std::process::Output {
        status: output.status,
        stdout: output.stdout,
        stderr,
    })
}

/// The opening words of the "not installed" message, so the test and the
/// formatter agree on one spelling.
const BWRAP_UNAVAILABLE_PREFIX: &str = "bubblewrap unavailable";

/// Bubblewrap is missing or refused to start. Names this host's install
/// command rather than one distro's, and the kernel knob a hardened image
/// turns off.
fn bwrap_unavailable() -> String {
    let install = crate::kernel::platform::install_hint(
        Platform::X86_64UnknownLinuxGnu,
        crate::kernel::platform::HostPackages::Bubblewrap,
    );
    format!(
        "{BWRAP_UNAVAILABLE_PREFIX}: install it ({install}) and ensure unprivileged user \
         namespaces are enabled (/proc/sys/user/max_user_namespaces > 0)"
    )
}

/// The binary the preflight probe execs. A failure to exec *this* is a
/// property of the host, because tog chose it and it is in the ro-bound
/// `/usr`; a failure to exec anything else is a property of that command.
const PROBE_TARGET: &str = "/usr/bin/true";

/// A bubblewrap that starts but cannot exec. Ubuntu 22.04's bubblewrap
/// cannot resolve tog's merged-/usr bind layout, so the raw
/// `execvp /usr/bin/true: No such file or directory` reads like a missing
/// file in the user's project rather than a host limitation.
///
/// Only the probe's own target gets that explanation. bwrap prints the
/// same line when a build spec names a binary that is not in the closure,
/// and blaming Ubuntu for that would send the user to the wrong place.
fn explained_bwrap_stderr(stderr: &str) -> String {
    let raw = stderr.trim_end();
    if !raw.contains("execvp") || !raw.contains("No such file or directory") {
        return raw.to_string();
    }
    if raw.contains(PROBE_TARGET) {
        return format!(
            "the sandbox starts but cannot exec inside it ({raw}): this host's bubblewrap does \
             not resolve tog's /usr bind layout, known on Ubuntu 22.04 and fixed by a newer \
             bubblewrap (Ubuntu 24.04, Debian 13); sandboxed work stays unavailable until then"
        );
    }
    format!(
        "the sandbox started but could not exec the command ({raw}): either that binary is not \
         in the closure bound into the sandbox, or this host's bubblewrap does not resolve \
         tog's /usr bind layout (known on Ubuntu 22.04; a newer bubblewrap fixes it)"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SandboxFailureKind {
    Setup,
    Command,
}

/// Classify a non-zero sandbox result without looking at the host platform.
/// Engine setup diagnostics have distinct prefixes; all other stderr belongs
/// to the command and must remain an ordinary exit status.
fn classify_sandbox_failure(
    status: &std::process::ExitStatus,
    stderr: &[u8],
) -> Option<SandboxFailureKind> {
    if status.success() {
        return None;
    }
    if stderr.starts_with(b"bwrap:") || stderr.starts_with(b"sandbox-exec:") {
        Some(SandboxFailureKind::Setup)
    } else {
        Some(SandboxFailureKind::Command)
    }
}

fn sandbox_failure_error(
    kind: SandboxFailureKind,
    status: &std::process::ExitStatus,
    stderr: &[u8],
    cmd: &[&str],
) -> io::Error {
    match kind {
        SandboxFailureKind::Setup => io::Error::new(
            io::ErrorKind::Unsupported,
            explained_bwrap_stderr(&String::from_utf8_lossy(stderr)),
        ),
        SandboxFailureKind::Command => io::Error::new(
            io::ErrorKind::Other,
            format!(
                "sandboxed command failed ({status}): {}",
                crate::kernel::ui::shell_line(cmd)
            ),
        ),
    }
}

#[cfg(target_os = "linux")]
const SYS_CLOSE_RANGE: std::ffi::c_long = 436;
#[cfg(target_os = "linux")]
const CLOSE_RANGE_CLOEXEC: std::ffi::c_uint = 1 << 2;
#[cfg(target_os = "linux")]
const F_SETFD: std::ffi::c_int = 2;
#[cfg(target_os = "linux")]
const FD_CLOEXEC: std::ffi::c_int = 1;
#[cfg(target_os = "linux")]
const ENOSYS: i32 = 38;
#[cfg(target_os = "linux")]
const EINVAL: i32 = 22;
#[cfg(target_os = "linux")]
const EBADF: i32 = 9;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
    fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
}

#[cfg(target_os = "linux")]
fn inherited_fds() -> io::Result<Vec<RawFd>> {
    let mut fds = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        else {
            continue;
        };
        if fd >= 3 {
            fds.push(fd);
        }
    }
    Ok(fds)
}

#[cfg(target_os = "linux")]
fn mark_inherited_fds_cloexec(fds: &[RawFd]) -> io::Result<()> {
    // SAFETY: close_range takes three integer arguments; an unsupported
    // kernel reports ENOSYS/EINVAL through errno, which is handled below.
    let close_range_result =
        unsafe { syscall(SYS_CLOSE_RANGE, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if close_range_result == 0 {
        return Ok(());
    }
    // ENOSYS: kernel < 5.9 (no close_range). EINVAL: 5.9/5.10 have the
    // syscall but not CLOSE_RANGE_CLOEXEC (added in 5.11).
    let error = io::Error::last_os_error();
    if !matches!(error.raw_os_error(), Some(ENOSYS) | Some(EINVAL)) {
        return Err(error);
    }
    mark_fds_cloexec_with_fcntl(fds)
}

/// Fallback for kernels without `close_range(CLOSE_RANGE_CLOEXEC)`: mark each
/// listed descriptor individually. Descriptors closed since the list was
/// taken (EBADF) are fine — they cannot leak.
#[cfg(target_os = "linux")]
fn mark_fds_cloexec_with_fcntl(fds: &[RawFd]) -> io::Result<()> {
    for &fd in fds {
        // SAFETY: fcntl takes an integer descriptor; a stale one fails with
        // EBADF rather than touching another process's state.
        let result = unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(EBADF) {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn bwrap_command(path: &Path) -> io::Result<Command> {
    // Only the Linux block below mutates `command`; without the attribute macOS
    // builds warn about an unused `mut`.
    #[allow(unused_mut)]
    let mut command = Command::new(path);
    #[cfg(target_os = "linux")]
    {
        // The fallback list is collected before fork because pre_exec must
        // not allocate while the child is between fork and exec.
        let fds = inherited_fds()?;
        // SAFETY: the post-fork closure only calls close_range/fcntl on the
        // descriptor numbers collected above, which are async-signal-safe and
        // allocate nothing.
        unsafe {
            command.pre_exec(move || mark_inherited_fds_cloexec(&fds));
        }
    }
    Ok(command)
}

fn find_socket_without_following_symlinks(path: &Path) -> io::Result<Option<PathBuf>> {
    let metadata = fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    if file_type.is_socket() {
        return Ok(Some(path.to_path_buf()));
    }
    if !file_type.is_dir() {
        return Ok(None);
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_socket() {
            return Ok(Some(entry_path));
        }
        if file_type.is_dir() {
            if let Some(socket) = find_socket_without_following_symlinks(&entry_path)? {
                return Ok(Some(socket));
            }
        }
    }
    Ok(None)
}

/// `tog doctor`: is the build sandbox usable on this host? Runs the
/// same preflight the real sandbox runs, so a green answer here means a
/// green sandboxed build.
pub fn probe(platform: Platform) -> io::Result<String> {
    match platform {
        Platform::X86_64UnknownLinuxGnu => {
            bwrap_preflight().map(|path| format!("bubblewrap at {}", path.display()))
        }
        Platform::Aarch64AppleDarwin => {
            let seatbelt = Path::new("/usr/bin/sandbox-exec");
            if seatbelt.is_file() {
                Ok("sandbox-exec (Seatbelt) at /usr/bin/sandbox-exec".to_string())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "/usr/bin/sandbox-exec not found",
                ))
            }
        }
    }
}

fn bwrap_preflight() -> io::Result<&'static Path> {
    bwrap_preflight_with_activity(None)
}

fn bwrap_preflight_with_activity(activity: Option<&StoreActivity>) -> io::Result<&'static Path> {
    static PREFLIGHT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    match PREFLIGHT.get_or_init(|| {
        let Some(path) = find_bwrap() else {
            return Err(bwrap_unavailable());
        };
        let mut version_command = bwrap_command(&path).map_err(|error| error.to_string())?;
        version_command
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let version_ok = match activity {
            Some(activity) => supervise_output_status(&mut version_command, activity),
            None => version_command
                .status()
                .map(|status| status.success())
                .unwrap_or(false),
        };
        if !version_ok {
            return Err(bwrap_unavailable());
        }
        let probe_args = [
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--hostname",
            "tog",
            "--unshare-cgroup-try",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--symlink",
            "usr/bin",
            "/bin",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            PROBE_TARGET,
        ];
        let mut probe_command = bwrap_command(&path).map_err(|error| error.to_string())?;
        probe_command
            .args(probe_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let probe_output = match activity {
            Some(activity) => {
                let output = crate::kernel::supervise::output(&mut probe_command, activity)
                    .map_err(|error| error.to_string())?;
                (output.status, output.stderr)
            }
            None => {
                let output = probe_command.output().map_err(|error| error.to_string())?;
                (output.status, output.stderr)
            }
        };
        if probe_output.0.success() {
            Ok(path)
        } else if probe_output.1.starts_with(b"bwrap:") {
            Err(explained_bwrap_stderr(&String::from_utf8_lossy(
                &probe_output.1,
            )))
        } else {
            Err(bwrap_unavailable())
        }
    }) {
        Ok(path) => Ok(path.as_path()),
        Err(message) => Err(io::Error::new(io::ErrorKind::Unsupported, message.clone())),
    }
}

fn supervise_output_status(command: &mut Command, activity: &StoreActivity) -> bool {
    crate::kernel::supervise::output(command, activity)
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn find_bwrap() -> Option<PathBuf> {
    // The distro binary first (mirrors the hardcoded /usr/bin/sandbox-exec on
    // macOS); PATH only as a fallback for unusual installs.
    let system = PathBuf::from("/usr/bin/bwrap");
    if let Ok(metadata) = fs::metadata(&system) {
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Some(system);
        }
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("bwrap");
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let Ok(candidate) = fs::canonicalize(candidate) else {
            continue;
        };
        if candidate.is_absolute() {
            return Some(candidate);
        }
    }
    None
}

fn push_arg(args: &mut Vec<OsString>, value: impl Into<OsString>) {
    args.push(value.into());
}

fn push_bind(args: &mut Vec<OsString>, flag: &str, source: &str, destination: &str) {
    push_arg(args, flag);
    push_arg(args, source);
    push_arg(args, destination);
}

fn push_bind_path(args: &mut Vec<OsString>, flag: &str, path: &Path) {
    push_arg(args, flag);
    args.push(path.as_os_str().to_os_string());
    args.push(path.as_os_str().to_os_string());
}

fn push_setenv(args: &mut Vec<OsString>, key: &str, value: impl AsRef<OsStr>) {
    push_arg(args, "--setenv");
    push_arg(args, key);
    args.push(value.as_ref().to_os_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[cfg(target_os = "linux")]
    use std::fs::File;
    use std::os::unix::ffi::OsStrExt;
    #[cfg(target_os = "linux")]
    use std::os::unix::io::AsRawFd;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    #[cfg(target_os = "linux")]
    const F_GETFD: std::ffi::c_int = 1;

    /// `TOG_SANDBOX_TESTS=required` (any non-empty value) turns every
    /// Linux skip into a panic so CI cannot report skipped checks as passed.
    fn required_sandbox_tests() -> bool {
        matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty())
    }

    fn linux_ready(test_name: &str) -> bool {
        match Platform::host() {
            Ok(Platform::X86_64UnknownLinuxGnu) => {}
            Ok(platform) => {
                if required_sandbox_tests() {
                    panic!(
                        "required Linux sandbox test {test_name} cannot run on {}",
                        platform.triple()
                    );
                }
                eprintln!("skip {test_name}: not Linux ({})", platform.triple());
                return false;
            }
            Err(error) => {
                if required_sandbox_tests() {
                    panic!("required Linux sandbox test {test_name} unavailable: {error}");
                }
                eprintln!("skip {test_name}: not a supported Linux host ({error})");
                return false;
            }
        }
        if let Err(error) = bwrap_preflight() {
            if required_sandbox_tests() {
                panic!("required Linux sandbox test {test_name} preflight failed: {error}");
            }
            eprintln!("skip {test_name}: {error}");
            return false;
        }
        true
    }

    fn temp_dir(test_name: &str) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tog-sandbox-{test_name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create unique sandbox test directory");
        path
    }

    fn run(
        sandbox: &Sandbox<'_>,
        cmd: &[&str],
        scratch: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<()> {
        sandbox.run_in_on(
            Platform::X86_64UnknownLinuxGnu,
            cmd,
            "/usr/bin:/bin",
            scratch,
            cwd,
            envs,
        )
    }

    fn run_capture(
        sandbox: &Sandbox<'_>,
        cmd: &[&str],
        scratch: &Path,
        cwd: &Path,
        envs: &[(String, String)],
    ) -> io::Result<Vec<u8>> {
        let output = sandbox.run_bwrap_with_stdout(
            cmd,
            "/usr/bin:/bin",
            scratch,
            cwd,
            envs,
            std::process::Stdio::piped(),
        )?;
        if !output.status.success() {
            let failure = classify_sandbox_failure(&output.status, &output.stderr)
                .expect("non-zero status has a sandbox failure classification");
            return Err(sandbox_failure_error(
                failure,
                &output.status,
                &output.stderr,
                cmd,
            ));
        }
        Ok(output.stdout)
    }

    fn read_lines(path: &Path) -> BTreeSet<String> {
        fs::read_to_string(path)
            .expect("read sandbox output")
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn linux_network_is_denied() {
        if !linux_ready("linux_network_is_denied") {
            return;
        }
        assert!(
            Path::new("/usr/bin/curl").is_file(),
            "network probe requires /usr/bin/curl"
        );
        let root = temp_dir("network");
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        use std::io::Write;
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        let host_connection =
            std::net::TcpStream::connect(address).expect("host positive network control");
        let network_url = format!("http://127.0.0.1:{}/", address.port());
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        // curl exit 7 is "could not connect": the only acceptable outcome.
        // 0 means the namespace leaked; anything else means the probe itself
        // did not run (e.g. curl failed to exec), which must not pass.
        let result = run_capture(
            &sandbox,
            &[
                "/usr/bin/sh",
                "-c",
                "/usr/bin/curl -fsS --connect-timeout 2 --max-time 3 \"$1\" >/dev/null 2>&1; echo rc=$?",
                "sh",
                network_url.as_str(),
            ],
            &scratch,
            &scratch,
            &[],
        );
        drop(host_connection);
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
        let stdout = result.expect("network probe wrapper failed");
        assert_eq!(
            String::from_utf8_lossy(&stdout).trim(),
            "rc=7",
            "curl inside the sandbox must fail with 'could not connect'"
        );
    }

    #[test]
    fn linux_home_ssh_is_invisible() {
        if !linux_ready("linux_home_ssh_is_invisible") {
            return;
        }
        // Reads $HOME and creates a scratch directory under it; a policy
        // test repointing HOME at its own temporary tree mid-run would send
        // this one there (and race that tree's cleanup).
        let _env = crate::kernel::policy::test_env_lock();
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME is set"));
        let cache = home.join(".cache");
        fs::create_dir_all(&cache).unwrap();
        let scratch = cache.join(format!(
            "tog-test-ssh-{}",
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&scratch).unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let home_ssh = home.join(".ssh");
        let home_ssh_string = home_ssh.to_str().expect("home path is UTF-8");
        let result = run(
            &sandbox,
            &[
                "/usr/bin/sh",
                "-c",
                "if [ -e \"$1\" ]; then exit 1; fi",
                "sh",
                home_ssh_string,
            ],
            &scratch,
            &scratch,
            &[],
        );
        fs::remove_dir(&scratch).unwrap();
        assert!(result.is_ok(), "$HOME/.ssh was visible: {result:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_inherited_directory_and_socket_fds_are_closed() {
        if !linux_ready("linux_inherited_directory_and_socket_fds_are_closed") {
            return;
        }
        let root = temp_dir("inherited-fds");
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        // Same reason as `linux_home_ssh_is_invisible`: $HOME is read here,
        // and opening a directory a policy test is about to delete is a race.
        let _env = crate::kernel::policy::test_env_lock();
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME is set"));
        let directory = File::open(home).unwrap();
        let (socket, _peer) = UnixStream::pair().unwrap();
        let directory_fd = directory.as_raw_fd();
        let socket_fd = socket.as_raw_fd();
        // SAFETY: both descriptors are owned by the live `directory` and
        // `socket` values above.
        assert_eq!(unsafe { fcntl(directory_fd, F_SETFD, 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { fcntl(socket_fd, F_SETFD, 0) }, 0);

        let result = run(
            &Sandbox {
                read: vec![],
                write: vec![&scratch],
            },
            &[
                "/usr/bin/sh",
                "-c",
                "if /usr/bin/test -e /proc/self/fd/$1 || /usr/bin/test -e /proc/self/fd/$2; then exit 1; fi; if /usr/bin/ls /proc/self/fd/$1/ >/dev/null 2>&1; then exit 2; fi",
                "sh",
                &directory_fd.to_string(),
                &socket_fd.to_string(),
            ],
            &scratch,
            &scratch,
            &[],
        );
        fs::remove_dir_all(root).unwrap();
        assert!(
            result.is_ok(),
            "inherited directory/socket fd leaked: {result:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_host_socket_in_writable_root_is_rejected_before_bwrap() {
        let root = temp_dir("host-socket");
        let scratch = root.join("scratch");
        let writable = root.join("writable");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&writable).unwrap();
        let socket_path = writable.join("listener.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let result = run(
            &Sandbox {
                read: vec![],
                write: vec![&writable, &scratch],
            },
            &["/usr/bin/true"],
            &scratch,
            &scratch,
            &[],
        );
        drop(listener);
        fs::remove_dir_all(root).unwrap();
        let error = result.expect_err("host Unix socket was exposed");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(
            error.to_string().contains("listener.sock"),
            "socket path missing from error: {error}"
        );
    }

    #[test]
    fn linux_undeclared_read_is_denied() {
        if !linux_ready("linux_undeclared_read_is_denied") {
            return;
        }
        let root = temp_dir("read");
        let scratch = root.join("scratch");
        let declared = root.join("declared");
        let sibling = root.join("sibling");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&declared).unwrap();
        fs::create_dir(&sibling).unwrap();
        let secret = sibling.join("secret");
        fs::write(&secret, "undeclared").unwrap();
        let sandbox = Sandbox {
            read: vec![&declared],
            write: vec![&scratch],
        };
        let secret_string = secret.to_str().unwrap();
        let result = run(
            &sandbox,
            &["/usr/bin/cat", secret_string],
            &scratch,
            &scratch,
            &[],
        );
        fs::remove_dir_all(root).unwrap();
        assert!(result.is_err(), "undeclared sibling was readable");
    }

    #[test]
    fn linux_declared_write_and_read_only_write() {
        if !linux_ready("linux_declared_write_and_read_only_write") {
            return;
        }
        let root = temp_dir("write");
        let scratch = root.join("scratch");
        let declared = root.join("declared");
        let readonly = root.join("readonly");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&declared).unwrap();
        fs::create_dir(&readonly).unwrap();
        let sandbox = Sandbox {
            read: vec![&readonly],
            write: vec![&declared, &scratch],
        };
        let declared_string = declared.to_str().unwrap();
        let result = run(
            &sandbox,
            &["/usr/bin/touch", &format!("{declared_string}/result")],
            &scratch,
            &scratch,
            &[],
        );
        assert!(result.is_ok(), "declared write failed: {result:?}");
        assert!(declared.join("result").exists());

        let readonly_string = readonly.to_str().unwrap();
        let result = run(
            &sandbox,
            &["/usr/bin/touch", &format!("{readonly_string}/blocked")],
            &scratch,
            &scratch,
            &[],
        );
        fs::remove_dir_all(root).unwrap();
        assert!(result.is_err(), "read-only root accepted a write");
    }

    #[test]
    fn linux_overlapping_mounts_keep_writable_child() {
        if !linux_ready("linux_overlapping_mounts_keep_writable_child") {
            return;
        }
        let root = temp_dir("overlap");
        let scratch = root.join("scratch");
        let parent = root.join("parent");
        let child = parent.join("w");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&child).unwrap();
        let sandbox = Sandbox {
            read: vec![&parent],
            write: vec![&child, &scratch],
        };
        let child_file = child.join("x");
        let child_file_string = child_file.to_str().unwrap();
        let result = run(
            &sandbox,
            &["/usr/bin/touch", child_file_string],
            &scratch,
            &parent,
            &[],
        );
        assert!(result.is_ok(), "writable child was shadowed: {result:?}");
        assert!(child_file.exists());

        let parent_file = parent.join("y");
        let parent_file_string = parent_file.to_str().unwrap();
        let result = run(
            &sandbox,
            &["/usr/bin/touch", parent_file_string],
            &scratch,
            &parent,
            &[],
        );
        fs::remove_dir_all(root).unwrap();
        assert!(result.is_err(), "read-only parent accepted a write");
    }

    #[test]
    fn linux_unbound_cwd_is_enterable_but_empty() {
        if !linux_ready("linux_unbound_cwd_is_enterable_but_empty") {
            return;
        }
        let root = temp_dir("cwd");
        let scratch = root.join("scratch");
        let project = root.join("project");
        let output = scratch.join("pwd");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&project).unwrap();
        fs::write(project.join("secret"), b"host data").unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let result = run(
            &sandbox,
            &[
                "/usr/bin/sh",
                "-c",
                r#"pwd > "$1"; ls -A | wc -l >> "$1"; cat secret >> "$1" 2>/dev/null || echo unreadable >> "$1""#,
                "sh",
                output.to_str().unwrap(),
            ],
            &scratch,
            &project,
            &[],
        );
        assert!(result.is_ok(), "unbound cwd failed: {result:?}");
        let lines: Vec<String> = fs::read_to_string(&output)
            .unwrap()
            .lines()
            .map(|l| l.trim().to_string())
            .collect();
        assert_eq!(
            lines,
            vec![
                project.display().to_string(),
                "0".to_string(),
                "unreadable".to_string()
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_writable_child_under_undeclared_cwd_stays_writable() {
        if !linux_ready("linux_writable_child_under_undeclared_cwd_stays_writable") {
            return;
        }
        let root = temp_dir("cwd-child");
        let scratch = root.join("scratch");
        let project = root.join("project");
        let out = project.join("out");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&project).unwrap();
        fs::create_dir(&out).unwrap();
        // cwd is neither a read nor a write root: the implicit empty tmpfs
        // at cwd must precede the writable child so it cannot shadow it.
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&out, &scratch],
        };
        let out_file = out.join("x");
        let result = run(
            &sandbox,
            &["/usr/bin/touch", out_file.to_str().unwrap()],
            &scratch,
            &project,
            &[],
        );
        assert!(
            result.is_ok(),
            "writable child under implicit cwd was shadowed: {result:?}"
        );
        assert!(out_file.exists());

        let project_file = project.join("y");
        let result = run(
            &sandbox,
            &["/usr/bin/touch", project_file.to_str().unwrap()],
            &scratch,
            &project,
            &[],
        );
        // The undeclared cwd is a private tmpfs: a write there succeeds
        // inside the sandbox but never reaches the host directory.
        assert!(
            result.is_ok(),
            "write into the tmpfs cwd failed: {result:?}"
        );
        assert!(
            !project_file.exists(),
            "implicit cwd write reached the host"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fcntl_cloexec_fallback_marks_fds() {
        // Exercises the pre-5.11 fallback path directly; close_range is
        // available on this host so the production path never reaches it.
        let root = temp_dir("cloexec-fallback");
        let file = File::open(&root).unwrap();
        let fd = file.as_raw_fd();
        // SAFETY: fd is owned by the live `file` value above.
        assert_eq!(unsafe { fcntl(fd, F_SETFD, 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { fcntl(fd, F_GETFD) } & FD_CLOEXEC, 0);
        let closed_fd = {
            let extra = File::open(&root).unwrap();
            extra.as_raw_fd()
        };
        mark_fds_cloexec_with_fcntl(&[fd, closed_fd]).expect("EBADF for a closed fd is tolerated");
        // SAFETY: fd is owned by the live `file` value above.
        assert_eq!(unsafe { fcntl(fd, F_GETFD) } & FD_CLOEXEC, FD_CLOEXEC);
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_environment_is_exact() {
        if !linux_ready("linux_environment_is_exact") {
            return;
        }
        let root = temp_dir("env");
        let scratch = root.join("scratch");
        let output = scratch.join("env");
        fs::create_dir(&scratch).unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let env_output = run_capture(
            &sandbox,
            &["/usr/bin/env"],
            &scratch,
            &scratch,
            &[("CUSTOM".to_string(), "ok".to_string())],
        );
        fs::write(&output, env_output.expect("env command failed")).unwrap();
        let expected = [
            format!("CUSTOM=ok"),
            format!("HOME={}", scratch.display()),
            "LANG=en_US.UTF-8".to_string(),
            "PATH=/usr/bin:/bin".to_string(),
            "SOURCE_DATE_EPOCH=315532800".to_string(),
            format!("TMPDIR={}", scratch.display()),
        ]
        .into_iter()
        .collect();
        assert_eq!(read_lines(&output), expected);
        assert!(!read_lines(&output)
            .iter()
            .any(|line| line.starts_with("PWD=")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_group_lookup_works() {
        if !linux_ready("linux_group_lookup_works") {
            return;
        }
        let root = temp_dir("group");
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let result = run(
            &Sandbox {
                read: vec![],
                write: vec![&scratch],
            },
            &["/usr/bin/id", "-gn"],
            &scratch,
            &scratch,
            &[],
        );
        fs::remove_dir_all(root).unwrap();
        assert!(result.is_ok(), "id -gn failed: {result:?}");
    }

    #[test]
    fn linux_pid_namespace_is_small() {
        if !linux_ready("linux_pid_namespace_is_small") {
            return;
        }
        let root = temp_dir("pid");
        let scratch = root.join("scratch");
        let output = scratch.join("ps");
        fs::create_dir(&scratch).unwrap();
        let output_string = output.to_str().unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let result = run(
            &sandbox,
            &[
                "/usr/bin/sh",
                "-c",
                "/usr/bin/ps -e > \"$1\"",
                "sh",
                output_string,
            ],
            &scratch,
            &scratch,
            &[],
        );
        assert!(result.is_ok(), "ps command failed: {result:?}");
        let rows = fs::read_to_string(&output)
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.contains("PID"))
            .count();
        fs::remove_dir_all(root).unwrap();
        assert!(rows <= 3, "PID namespace exposed {rows} processes");
    }

    #[test]
    fn linux_ipc_namespace_is_isolated() {
        if !linux_ready("linux_ipc_namespace_is_isolated") {
            return;
        }
        let root = temp_dir("ipc");
        let scratch = root.join("scratch");
        let output = scratch.join("ipc");
        fs::create_dir(&scratch).unwrap();
        let host = Command::new("/usr/bin/readlink")
            .arg("/proc/self/ns/ipc")
            .output()
            .expect("read host IPC namespace");
        assert!(host.status.success());
        let output_string = output.to_str().unwrap();
        let result = run(
            &Sandbox {
                read: vec![],
                write: vec![&scratch],
            },
            &[
                "/usr/bin/sh",
                "-c",
                r#"/usr/bin/readlink /proc/self/ns/ipc > "$1""#,
                "sh",
                output_string,
            ],
            &scratch,
            &scratch,
            &[],
        );
        assert!(result.is_ok(), "IPC namespace probe failed: {result:?}");
        let sandbox_ipc = fs::read_to_string(&output).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_ne!(
            sandbox_ipc.trim(),
            String::from_utf8_lossy(&host.stdout).trim()
        );
    }

    #[test]
    fn linux_stdin_is_null() {
        if !linux_ready("linux_stdin_is_null") {
            return;
        }
        let root = temp_dir("stdin");
        let scratch = root.join("scratch");
        let output = scratch.join("stdin");
        fs::create_dir(&scratch).unwrap();
        let output_string = output.to_str().unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let result = run(
            &sandbox,
            &[
                "/usr/bin/sh",
                "-c",
                "read x; echo rc=$? > \"$1\"",
                "sh",
                output_string,
            ],
            &scratch,
            &scratch,
            &[],
        );
        assert!(result.is_ok(), "stdin probe failed: {result:?}");
        assert_eq!(fs::read_to_string(&output).unwrap().trim(), "rc=1");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_paths_with_space_and_unicode_work() {
        if !linux_ready("linux_paths_with_space_and_unicode_work") {
            return;
        }
        let root = temp_dir("unicode");
        let scratch = root.join("scratch");
        let read_root = root.join("read root λ");
        let input = read_root.join("input file");
        let output = scratch.join("output");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&read_root).unwrap();
        fs::write(&input, "unicode-ok").unwrap();
        let input_string = input.to_str().unwrap();
        let output_string = output.to_str().unwrap();
        let sandbox = Sandbox {
            read: vec![&read_root],
            write: vec![&scratch],
        };
        let result = run(
            &sandbox,
            &[
                "/usr/bin/sh",
                "-c",
                "/usr/bin/cat \"$1\" > \"$2\"",
                "sh",
                input_string,
                output_string,
            ],
            &scratch,
            &scratch,
            &[],
        );
        assert!(result.is_ok(), "unicode path command failed: {result:?}");
        assert_eq!(fs::read_to_string(&output).unwrap(), "unicode-ok");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_nonzero_exit_has_existing_error_shape() {
        if !linux_ready("linux_nonzero_exit_has_existing_error_shape") {
            return;
        }
        let root = temp_dir("failure");
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let result = run(
            &sandbox,
            &["/usr/bin/sh", "-c", "exit 7"],
            &scratch,
            &scratch,
            &[],
        );
        let error = result.expect_err("non-zero command unexpectedly succeeded");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.to_string(),
            "sandboxed command failed (exit status: 7): /usr/bin/sh -c 'exit 7'"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_command_stderr_is_relayed_and_classified_as_command_failure() {
        if !linux_ready("linux_command_stderr_is_relayed_and_classified_as_command_failure") {
            return;
        }
        let root = temp_dir("stderr");
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let sandbox = Sandbox {
            read: vec![],
            write: vec![&scratch],
        };
        let cmd = ["/usr/bin/sh", "-c", "echo build diagnostic >&2; exit 3"];
        let output = sandbox
            .run_bwrap_with_stdout(
                &cmd,
                "/usr/bin:/bin",
                &scratch,
                &scratch,
                &[],
                std::process::Stdio::piped(),
            )
            .unwrap();
        fs::remove_dir_all(root).unwrap();
        // The relay thread retained the build's own stderr (and forwarded it
        // to ours); a build printing to stderr is still a command failure.
        assert_eq!(output.stderr, b"build diagnostic\n");
        let error = sandbox_failure_error(
            SandboxFailureKind::Command,
            &output.status,
            &output.stderr,
            &cmd,
        );
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            error.to_string(),
            "sandboxed command failed (exit status: 3): /usr/bin/sh -c 'echo build diagnostic >&2; exit 3'"
        );
    }

    /// The Ubuntu 22.04 failure is a host limitation, not a missing file in
    /// the user's project. Doctor and every sandboxed build must say which,
    /// keep the raw bwrap line for the bug report, and name the fix.
    #[test]
    fn a_bwrap_that_cannot_exec_is_explained_not_forwarded_raw() {
        let raw = format!("bwrap: execvp {PROBE_TARGET}: No such file or directory");
        let explained = explained_bwrap_stderr(&raw);
        assert!(explained.contains(&raw), "{explained}");
        assert!(explained.contains("Ubuntu 22.04"), "{explained}");
        assert!(explained.contains("cannot exec inside it"), "{explained}");

        // bwrap prints the same line when a build spec names a binary the
        // closure does not contain. That is far more often the cause, so
        // it must not be blamed on the host alone.
        let missing = "bwrap: execvp /store/objects/env/bin/cc: No such file or directory";
        let other = explained_bwrap_stderr(missing);
        assert!(other.contains(missing), "{other}");
        assert!(other.contains("not in the closure"), "{other}");
        assert!(!other.contains("cannot exec inside it"), "{other}");

        // Every other bwrap diagnostic stays its own words.
        let unrelated = "bwrap: Can't find source path /missing: No such file";
        assert_eq!(explained_bwrap_stderr(unrelated), unrelated);
        assert_eq!(explained_bwrap_stderr("bwrap: oops\n"), "bwrap: oops");
    }

    /// The "just install it" case names this host's package manager.
    #[test]
    fn missing_bubblewrap_names_an_install_command() {
        let message = bwrap_unavailable();
        assert!(message.starts_with(BWRAP_UNAVAILABLE_PREFIX), "{message}");
        assert!(message.contains("max_user_namespaces"), "{message}");
        // An actual install command, not just the word "bubblewrap" from
        // the prefix: this host's manager, or every one tog knows.
        assert!(
            ["apt install", "dnf install", "pacman -S"]
                .iter()
                .any(|command| message.contains(command)),
            "no install command in: {message}"
        );
    }

    #[test]
    fn linux_bwrap_setup_failure_is_unsupported() {
        if !linux_ready("linux_bwrap_setup_failure_is_unsupported") {
            return;
        }
        let bwrap = bwrap_preflight().unwrap();
        let root = temp_dir("setup-failure");
        let missing = root.join("does-not-exist");
        let mut command = bwrap_command(bwrap).unwrap();
        let output = command
            .args([
                "--unshare-user",
                "--ro-bind",
                missing.to_str().unwrap(),
                "/missing",
                "/usr/bin/true",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let error = sandbox_failure_error(
            SandboxFailureKind::Setup,
            &output.status,
            &output.stderr,
            &["/usr/bin/true"],
        );
        fs::remove_dir_all(root).unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().starts_with("bwrap:"));
    }

    #[test]
    fn both_sandbox_engines_classify_setup_failures_by_prefix() {
        use std::os::unix::process::ExitStatusExt;

        let status = std::process::ExitStatus::from_raw(1);
        assert_eq!(
            classify_sandbox_failure(&status, b"bwrap: cannot mount /missing\n"),
            Some(SandboxFailureKind::Setup)
        );
        assert_eq!(
            classify_sandbox_failure(&status, b"sandbox-exec: invalid profile\n"),
            Some(SandboxFailureKind::Setup)
        );
        assert_eq!(
            classify_sandbox_failure(&status, b"formatter: could not parse input\n"),
            Some(SandboxFailureKind::Command)
        );
        assert_eq!(
            classify_sandbox_failure(
                &std::process::ExitStatus::from_raw(0),
                b"sandbox-exec: no\n"
            ),
            None
        );
    }

    #[test]
    fn linux_bwrap_argv_sample() {
        if !linux_ready("linux_bwrap_argv_sample") {
            return;
        }
        let root = temp_dir("argv");
        let scratch = root.join("scratch");
        let read_root = root.join("read root λ");
        let write_root = root.join("write");
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(&read_root).unwrap();
        fs::create_dir(&write_root).unwrap();
        let sandbox = Sandbox {
            read: vec![&read_root],
            write: vec![&write_root],
        };
        let args = sandbox
            .bwrap_args(
                &["/usr/bin/sh", "-c", "printf sample"],
                "/usr/bin:/bin",
                &scratch,
                &scratch,
                &[("CHECK".to_string(), "ok".to_string())],
            )
            .unwrap();
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        println!("bwrap argv sample: bwrap {rendered}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn macos_profile_golden() {
        let sandbox = Sandbox {
            read: vec![Path::new("/fixed/read")],
            write: vec![Path::new("/fixed/write")],
        };
        assert_eq!(
            sandbox.profile(),
            "(version 1)\n\
(deny default)\n\
(deny network*)\n\
; process basics\n\
(allow process-exec*)\n\
(allow process-fork)\n\
(allow process-info*)\n\
(allow signal (target same-sandbox))\n\
(allow sysctl-read)\n\
(allow mach-lookup)\n\
; dyld must map dylibs; without this every exec SIGABRTs\n\
(allow file-map-executable)\n\
(allow file-read* (literal \"/\"))\n\
; system runtime, read-only\n\
(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\")\n\
   (subpath \"/System\") (subpath \"/Library\") (subpath \"/private/etc\")\n\
   (subpath \"/opt\") (subpath \"/var/db/timezone\") (subpath \"/dev\"))\n\
; C/C++ toolchain (read-only): Xcode or CLT via xcode-select\n\
(allow file-read* (subpath \"/Applications/Xcode.app\")\n\
   (literal \"/var/db/xcode_select_link\")\n\
   (literal \"/private/var/db/xcode_select_link\"))\n\
(allow file-read-metadata)\n\
(allow file-write-data (literal \"/dev/null\") (literal \"/dev/dtracehelper\"))\n\
(allow file-read* (subpath \"/fixed/read\"))\n\
(allow file-read* file-write* (subpath \"/fixed/write\"))\n"
        );
    }

    /// npm and pnpm read `/^npm_config_/i`; the scrub must be as broad, and
    /// tog's forced value must be the only survivor.
    #[test]
    fn force_env_strips_prefixes_case_insensitively_and_forced_values_win() {
        // Names are test-private so a parallel test never sees a real
        // setting appear; only the prefix is what the scrub keys on.
        let names = [
            "Npm_Config_tog_test_registry",
            "NPM_config_tog_test_forced",
            "npm_config_tog_test_forced",
            "npm_config_tog_test_store_dir",
            "NPM_CONFIG_TOG_TEST_STORE_DIR",
            "PNPM_TOG_TEST_HOME",
            "pnpm_tog_test_home",
            "TOG_FORCE_ENV_KEEP",
        ];
        for name in names {
            std::env::set_var(name, "user");
        }
        let mut cmd = Command::new("true");
        force_env(
            &mut cmd,
            &["npm_config_", "PNPM_"],
            &[],
            &[("npm_config_tog_test_forced".into(), "true".into())],
        );
        let envs: std::collections::BTreeMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for name in names {
            std::env::remove_var(name);
        }
        for removed in [
            "Npm_Config_tog_test_registry",
            "NPM_config_tog_test_forced",
            "npm_config_tog_test_store_dir",
            "NPM_CONFIG_TOG_TEST_STORE_DIR",
            "PNPM_TOG_TEST_HOME",
            "pnpm_tog_test_home",
        ] {
            assert_eq!(
                envs.get(removed),
                Some(&None),
                "{removed} survived: {envs:?}"
            );
        }
        assert_eq!(
            envs.get("npm_config_tog_test_forced"),
            Some(&Some("true".to_string()))
        );
        assert!(
            !envs.contains_key("TOG_FORCE_ENV_KEEP"),
            "an unrelated variable was touched: {envs:?}"
        );
    }

    /// The prefix comparison indexes by byte offset. Env names are not
    /// tog's to choose, and `to_string_lossy` widens any invalid byte to
    /// a three-byte replacement character, so a name can put a multi-byte
    /// character across the offset a prefix length lands on. Slicing there
    /// panics and takes down every caller — `tog run` for Ruby, Elixir
    /// and .NET as much as a pnpm edit.
    #[test]
    fn force_env_survives_names_that_straddle_a_prefix_boundary() {
        // "abc" + U+FFFD: the replacement character occupies bytes 3..6, so
        // byte 5 (the length of "PNPM_") is inside it.
        let straddles = "abc\u{fffd}_tog_test";
        assert!(!straddles.is_char_boundary(5));
        // A non-UTF-8 name reaches the same place through `to_string_lossy`.
        let invalid = OsStr::from_bytes(b"abc\xff_tog_test");
        std::env::set_var(straddles, "user");
        std::env::set_var(invalid, "user");
        let mut cmd = Command::new("true");
        // Prefixes of several lengths, none of which match these names.
        force_env(&mut cmd, &["npm_config_", "PNPM_", "YARN_"], &[], &[]);
        // Reaching this line at all is the point: the old slicing panicked
        // here. A sibling test sets its own variables in the same process
        // environment, so assert about these two names only.
        let touched: Vec<String> = cmd
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        std::env::remove_var(straddles);
        std::env::remove_var(invalid);
        for name in [straddles, "abc\u{fffd}_tog_test"] {
            assert!(
                !touched.iter().any(|seen| seen == name),
                "a name matching no prefix was scrubbed: {touched:?}"
            );
        }
    }
}

//! The container backend of the resolution door (kernel layer): rootless
//! podman, for a Linux host where bubblewrap cannot create a user namespace
//! (`kernel.unprivileged_userns_clone=0`, or AppArmor's
//! `restrict_unprivileged_userns`) but podman can, through its setuid
//! `newuidmap`.
//!
//! The container is built the way the native sandbox is, from the same
//! parts. Its root is a directory tog writes into the run's stage: the
//! host's loader links (`/lib64 -> usr/lib64` and the rest, mirrored by
//! [`sandbox::system_root_args`]) and nothing else, mounted as an overlay
//! (`--rootfs <dir>:O`) so podman never writes into it, and read-only
//! (`--read-only`). Onto it go the same read-only system runtime (`/usr`
//! and the host `/etc` entries), the same store objects, snapshot, scratch,
//! proxy socket and relay. So nothing is pulled and no image is trusted:
//! the root is the host's own `/usr`, exactly what bubblewrap shows.
//!
//! The rest of the fence, flag by flag: `--network none` (loopback only,
//! where the relay listens), `--userns keep-id` (files the tool writes are
//! the developer's), `--cap-drop all` and `no-new-privileges`, podman's
//! default seccomp profile with the relay's own filter inside it, and the
//! relay told to refuse a user namespace (`--deny-userns`), which
//! bubblewrap's `--disable-userns` does for the native sandbox.
//! `--pids-limit` bounds the tree. `label=disable` turns off SELinux
//! labeling, which would otherwise refuse the container the snapshot
//! under the developer's home. bubblewrap runs unlabeled too.
//!
//! The relay is the container's pid 1, as it is bubblewrap's: when the tool
//! exits it kills every process left, and its exit ends the container.
//! Whatever happens to the `podman` client (an interrupt, a crash),
//! [`Removal`] force-removes the container by name before the door reads
//! anything, so no process of the run outlives it.

use super::confine::{ConfinedRun, Mounts};
use super::relay;
use crate::kernel::activity::StoreActivity;
use crate::kernel::sandbox;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Processes one run may have at once. A package manager's tree is far
/// smaller; a fork bomb stops here.
const PIDS_LIMIT: &str = "4096";

/// The directory, in the run's stage, that becomes the container's root.
const ROOTFS: &str = "rootfs";

/// Directories the root needs before podman mounts onto it.
const ROOT_DIRS: [&str; 8] = ["usr", "etc", "run", "run/tog", "tmp", "proc", "dev", "sys"];

/// The flags every container of a run gets, the preflight's included, so
/// the probe cannot pass on a configuration the run never uses.
const FENCE: [&str; 21] = [
    "--network",
    "none",
    "--userns",
    "keep-id",
    "--cap-drop",
    "all",
    "--security-opt",
    "no-new-privileges",
    "--security-opt",
    "label=disable",
    "--read-only",
    "--read-only-tmpfs=false",
    "--pids-limit",
    PIDS_LIMIT,
    "--hostname",
    "tog",
    "--no-hosts",
    "--unsetenv-all",
    "--pull",
    "never",
    "--log-driver=none",
];

/// The rootless podman this machine can run a fenced container with, found
/// and tried once per process. An interrupt during the probe is returned
/// and nothing is cached.
pub fn preflight(activity: &StoreActivity) -> io::Result<&'static Path> {
    static PREFLIGHT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    if let Some(verdict) = PREFLIGHT.get() {
        return verdict_of(verdict);
    }
    let verdict = run_preflight(activity)?;
    verdict_of(PREFLIGHT.get_or_init(|| verdict))
}

fn verdict_of(verdict: &'static Result<PathBuf, String>) -> io::Result<&'static Path> {
    match verdict {
        Ok(path) => Ok(path.as_path()),
        Err(message) => Err(io::Error::new(io::ErrorKind::Unsupported, message.clone())),
    }
}

fn run_preflight(activity: &StoreActivity) -> io::Result<Result<PathBuf, String>> {
    let Some(podman) = find_podman() else {
        return Ok(Err("podman not found".to_string()));
    };
    let scratch = std::env::temp_dir().join(format!(
        "tog-podman-probe-{}-{}",
        std::process::id(),
        sequence()
    ));
    let verdict = probe_container(&podman, &scratch, activity);
    let _ = fs::remove_dir_all(&scratch);
    match verdict {
        Ok(Ok(())) => Ok(Ok(podman)),
        Ok(Err(reason)) => Ok(Err(reason)),
        Err(error) if crate::kernel::supervise::stop_signal(&error).is_some() => Err(error),
        Err(error) => Ok(Err(error.to_string())),
    }
}

/// Run `/usr/bin/true` in a container fenced exactly as a run is.
fn probe_container(
    podman: &Path,
    scratch: &Path,
    activity: &StoreActivity,
) -> io::Result<Result<(), String>> {
    fs::create_dir(scratch)?;
    fs::set_permissions(scratch, fs::Permissions::from_mode(0o700))?;
    let (rootfs, system) = root(scratch)?;
    let name = name();
    let mut args = run_args(&name);
    for (source, destination) in &system {
        args.extend(mount(source, destination, true)?);
    }
    args.extend(rootfs_args(&rootfs)?);
    args.push("/usr/bin/true".into());
    let mut command = sandbox::bwrap_command(podman)?;
    command.args(&args);
    let removal = Removal::new(podman, name);
    let output = crate::kernel::supervise::local_output(&mut command, activity);
    drop(removal);
    let output = output?;
    if output.status.success() {
        return Ok(Ok(()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no message");
    Ok(Err(format!(
        "rootless podman cannot run a fenced container here ({}): {reason}",
        output.status
    )))
}

/// The distro podman first, then `PATH`, as for bubblewrap.
fn find_podman() -> Option<PathBuf> {
    let executable = |path: &Path| {
        fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    };
    let system = PathBuf::from("/usr/bin/podman");
    if executable(&system) {
        return Some(system);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("podman"))
        .filter(|candidate| executable(candidate))
        .filter_map(|candidate| fs::canonicalize(candidate).ok())
        .find(|candidate| candidate.is_absolute())
}

fn sequence() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A container name no other run of any tog shares: the process, a
/// counter, and the clock.
pub fn name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("tog-resolve-{}-{}-{nanos}", std::process::id(), sequence())
}

/// `podman run` and the fence, up to the mounts.
pub fn run_args(name: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["run".into(), "--rm".into(), "--name".into(), name.into()];
    args.extend(FENCE.iter().map(OsString::from));
    args
}

/// The root's last arguments: the overlay of `rootfs`. Everything after
/// them is the command.
pub fn rootfs_args(rootfs: &Path) -> io::Result<Vec<OsString>> {
    let mut spec = checked(rootfs)?.to_os_string();
    spec.push(":O");
    Ok(vec!["--rootfs".into(), spec])
}

/// Make the container root in `stage`, and return it with the read-only
/// system binds every container gets: `/usr`, the host's split-`/usr`
/// directories, and the host `/etc` entries. The loader links are written
/// into the root itself, checked as the native sandbox checks them.
pub fn root(stage: &Path) -> io::Result<(PathBuf, Vec<(PathBuf, PathBuf)>)> {
    let rootfs = stage.join(ROOTFS);
    fs::create_dir(&rootfs)?;
    for dir in ROOT_DIRS {
        fs::create_dir_all(rootfs.join(dir))?;
    }
    let mut binds = Vec::new();
    let system = sandbox::system_root_args(Path::new("/"))?;
    for triple in system.chunks(3) {
        let [flag, source, destination] = triple else {
            return Err(io::Error::other(
                "the system runtime arguments are malformed",
            ));
        };
        let inside = Path::new(destination)
            .strip_prefix("/")
            .map_err(|_| io::Error::other("a system runtime path is not absolute"))?;
        match flag.to_str() {
            Some("--symlink") => std::os::unix::fs::symlink(source, rootfs.join(inside))?,
            Some("--ro-bind") => {
                fs::create_dir_all(rootfs.join(inside))?;
                binds.push((PathBuf::from(source), PathBuf::from(destination)));
            }
            _ => {
                return Err(io::Error::other(format!(
                    "the system runtime has an argument the container cannot mount: {flag:?}"
                )))
            }
        }
    }
    for entry in sandbox::HOST_ETC_ENTRIES {
        if Path::new(entry).exists() {
            binds.push((PathBuf::from(entry), PathBuf::from(entry)));
        }
    }
    Ok((rootfs, binds))
}

/// One `--mount` of `source` at `destination`.
pub fn mount(source: &Path, destination: &Path, read_only: bool) -> io::Result<[OsString; 2]> {
    let mut spec = OsString::from("type=bind,src=");
    spec.push(checked(source)?);
    spec.push(",dst=");
    spec.push(checked(destination)?);
    if read_only {
        spec.push(",ro=true");
    }
    Ok(["--mount".into(), spec])
}

/// A path podman's option grammar can carry: it splits `--mount` on commas
/// and `--rootfs` on its last colon, so a path with either is refused
/// rather than misread.
fn checked(path: &Path) -> io::Result<&std::ffi::OsStr> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || bytes.contains(&b',') || bytes.contains(&b':') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} cannot be mounted into a container: podman's mount syntax cannot name a \
                 path with a comma or a colon",
                path.display()
            ),
        ));
    }
    Ok(path.as_os_str())
}

/// The podman argv of a `Proxy` run: the same mounts as `confine::proxy_args`,
/// on a root of loader links in the stage (`super::container`).
pub(super) fn podman_args(
    run: &ConfinedRun<'_>,
    mounts: &Mounts,
    name: &str,
) -> io::Result<Vec<OsString>> {
    let mut args = run_args(name);
    let (rootfs, system) = root(run.snapshot.stage())?;
    for (source, destination) in &system {
        args.extend(mount(source, destination, true)?);
    }
    // bubblewrap's `--tmpfs /tmp`: writable and executable, as there.
    args.push("--tmpfs".into());
    args.push("/tmp:rw,exec,nosuid,nodev".into());
    for root in &mounts.read_roots {
        args.extend(mount(root, root, true)?);
    }
    for root in &mounts.cache_roots {
        args.extend(mount(root, root, false)?);
    }
    for root in run.snapshot.roots() {
        args.extend(mount(&root.staged, &root.real, false)?);
    }
    args.extend(mount(&mounts.scratch, &mounts.scratch, false)?);
    args.extend(mount(
        &mounts.proxy_socket,
        Path::new(relay::PROXY_SOCKET),
        true,
    )?);
    if let Some(ca_file) = &mounts.ca_file {
        args.extend(mount(ca_file, Path::new(relay::CA_FILE), true)?);
    }
    args.extend(mount(
        &mounts.executable,
        Path::new(relay::TOG_EXECUTABLE),
        true,
    )?);
    // The relay's two descriptors, 3 and 4, pass into the container.
    args.push("--preserve-fds".into());
    args.push("2".into());
    args.push("--workdir".into());
    args.push(mounts.cwd.clone().into_os_string());
    args.extend(rootfs_args(&rootfs)?);
    for part in [
        relay::TOG_EXECUTABLE,
        relay::VERB,
        "--exec-log-fd",
        "3",
        "--env-fd",
        "4",
        // A container has no `--disable-userns`: the relay's filter
        // refuses the tool a user namespace instead.
        "--deny-userns",
        relay::PROXY_SOCKET,
        relay::LISTEN_ADDRESS,
        "--",
    ] {
        args.push(part.into());
    }
    args.extend(run.argv.iter().cloned());
    Ok(args)
}

/// Force-removes the named container when dropped: after the run, after a
/// failed run, and after an interrupt, when the `podman` client may be gone
/// and the container still running.
pub struct Removal {
    podman: PathBuf,
    name: String,
}

impl Removal {
    pub fn new(podman: &Path, name: String) -> Removal {
        Removal {
            podman: podman.to_path_buf(),
            name,
        }
    }
}

impl Drop for Removal {
    fn drop(&mut self) {
        remove(&self.podman, &self.name);
    }
}

/// `podman rm --force --time 0 --ignore <name>`, waited for. It runs
/// outside the supervisor on purpose: after an interrupt the supervisor
/// refuses new children, and this is the one that must still run. It
/// reads and writes no store path.
// Reviewed site (tests/architecture.rs): the forced removal of a resolution container, which must run after an interrupt.
#[allow(clippy::disallowed_methods)]
fn remove(podman: &Path, name: &str) {
    let mut command = std::process::Command::new(podman);
    command
        .args(["rm", "--force", "--time", "0", "--ignore", name])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let _ = command.status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts_refuse_what_podman_would_misread() {
        let [flag, spec] = mount(Path::new("/a/b"), Path::new("/c"), true).unwrap();
        assert_eq!(flag, "--mount");
        assert_eq!(spec, "type=bind,src=/a/b,dst=/c,ro=true");
        let [_, spec] = mount(Path::new("/a"), Path::new("/a"), false).unwrap();
        assert_eq!(spec, "type=bind,src=/a,dst=/a");
        for bad in ["/a,b", "/a:b", "relative"] {
            assert!(
                mount(Path::new(bad), Path::new("/x"), true).is_err(),
                "{bad}"
            );
            assert!(
                mount(Path::new("/x"), Path::new(bad), true).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            rootfs_args(Path::new("/stage/rootfs")).unwrap(),
            ["--rootfs", "/stage/rootfs:O"]
        );
    }

    #[test]
    fn every_container_is_fenced() {
        let args: Vec<String> = run_args("tog-resolve-x")
            .into_iter()
            .map(|arg| arg.into_string().unwrap())
            .collect();
        let joined = args.join(" ");
        for wanted in [
            "run --rm --name tog-resolve-x",
            "--network none",
            "--userns keep-id",
            "--cap-drop all",
            "--security-opt no-new-privileges",
            "--read-only",
            "--pids-limit 4096",
            "--unsetenv-all",
            "--pull never",
        ] {
            assert!(joined.contains(wanted), "{wanted} missing from {joined}");
        }
    }

    #[test]
    fn the_root_holds_only_the_loader_links_and_mount_points() {
        let stage = crate::kernel::testutil::TempDir::named("container-root");
        let (rootfs, binds) = root(&stage.0).unwrap();
        assert!(binds.iter().any(|(source, _)| source == Path::new("/usr")));
        for entry in fs::read_dir(&rootfs).unwrap() {
            let entry = entry.unwrap();
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            if meta.file_type().is_symlink() {
                continue;
            }
            assert!(meta.is_dir(), "{}", entry.path().display());
            let mut inside = fs::read_dir(entry.path()).unwrap().map(|e| e.unwrap());
            // Only `run/tog` and split-`/usr` mount points nest.
            assert!(
                inside.all(|e| e.file_type().unwrap().is_dir()),
                "{}",
                entry.path().display()
            );
        }
    }

    #[test]
    fn names_are_unique_in_a_process() {
        assert_ne!(name(), name());
    }
}

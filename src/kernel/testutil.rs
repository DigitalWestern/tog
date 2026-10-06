//! Test-only helpers shared across layers (kernel layer, `cfg(test)`).

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) mod upstream;

/// Create fixture archives from the declared tree, without host metadata.
pub(crate) fn tar_create() -> Command {
    let mut command = Command::new("/usr/bin/tar");
    command.env_remove("TAR_OPTIONS");
    #[cfg(target_os = "macos")]
    {
        // bsdtar otherwise adds AppleDouble members and binary provenance
        // xattrs inherited from the process that created the fixture.
        command.env("COPYFILE_DISABLE", "1").arg("--no-xattrs");
    }
    command
}

/// A Unix socket listening at `path`, however long `path` is. A socket
/// address holds about 108 bytes, which a long `TMPDIR` exceeds. On Linux
/// the socket is bound through the parent directory's `/proc/self/fd`
/// alias, so it is made where it lives, on that filesystem, with no
/// process-wide `chdir`. Elsewhere a long path is bound under `/tmp` and
/// renamed in, which needs `TMPDIR` on the same filesystem as `/tmp`.
pub(crate) fn bind_socket(path: &std::path::Path) -> std::os::unix::net::UnixListener {
    use std::os::unix::net::UnixListener;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let parent = path.parent().expect("a socket path has a parent");
        let name = path.file_name().expect("a socket path names a file");
        let directory = std::fs::File::open(parent).unwrap();
        let alias = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        UnixListener::bind(alias).unwrap()
    }
    #[cfg(not(target_os = "linux"))]
    {
        if path.as_os_str().len() < 100 {
            return UnixListener::bind(path).unwrap();
        }
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let short = PathBuf::from(format!(
            "/tmp/tog-sock-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&short);
        let listener = UnixListener::bind(&short).unwrap();
        std::fs::rename(&short, path).unwrap();
        listener
    }
}

/// A scratch directory named `tog-<label>-<pid>-<nanos>-<seq>`, gone on
/// drop even when a store inside it has made its objects read-only: a plain
/// `remove_dir_all` fails on those and leaves the tree behind, and enough
/// leftovers fill the per-user /tmp quota.
pub struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub fn new() -> Self {
        Self::named("test")
    }

    /// A scratch directory whose name says which test made it, for the
    /// leftover a killed run leaves.
    ///
    /// The clock alone is not unique: macOS's ticks in microseconds, so two
    /// tests with one label could share a directory without the sequence.
    pub fn named(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        Self::create(std::env::temp_dir().join(format!(
            "tog-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )))
    }

    /// A scratch directory at `tog-<name>` with no per-call suffix, for a
    /// fixture whose path enters the result under test and so must be the
    /// same on every call. Callers serialize their use of one name.
    pub fn fixed(name: &str) -> Self {
        Self::create(std::env::temp_dir().join(format!("tog-{name}")))
    }

    fn create(path: PathBuf) -> Self {
        std::fs::create_dir_all(&path).unwrap();
        // The store records object paths under its canonicalized root and
        // compares them exactly; on macOS the temp dir sits under /var, a
        // symlink to /private/var.
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = crate::kernel::store::remove_tree(&self.0);
    }
}

/// An executable script at `relative` under `root` that exits 0: a store
/// program a test can point a command at, which the host-local tripwire
/// resolves like the real one.
pub(crate) fn store_program(root: &std::path::Path, relative: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Every command `build` makes with one of its own environment edits
/// undone, named by the variable: a variable it sets removed, one it
/// removes set. A host-local form must refuse each.
pub(crate) fn loosened(build: impl Fn() -> Command) -> Vec<(String, Command)> {
    let edits: Vec<(std::ffi::OsString, bool)> = build()
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.is_some()))
        .collect();
    edits
        .into_iter()
        .map(|(key, set)| {
            let mut command = build();
            if set {
                command.env_remove(&key);
            } else {
                command.env(&key, "loosened");
            }
            (key.to_string_lossy().into_owned(), command)
        })
        .chain(std::iter::once({
            // A variable no form admits: a caller adding one (a loader
            // preload, a tool setting outside the checked families) must be
            // refused as surely as one loosening a forced value.
            let mut command = build();
            command.env("LD_PRELOAD", "/tmp/loosened.so");
            ("+LD_PRELOAD".to_string(), command)
        }))
        .collect()
}

/// A lease on an empty scratch store, for a test whose code under test takes
/// the caller's activity token but must return before touching any store.
/// The directory is removed when the `TempDir` drops.
pub(crate) fn detached_lease() -> (TempDir, crate::kernel::activity::StoreActivity) {
    let temp = TempDir::new();
    let activity = crate::kernel::activity::StoreActivity::acquire(
        &temp.0,
        crate::kernel::activity::ActivityMode::Shared,
    )
    .unwrap();
    (temp, activity)
}

/// The scope a test's resolution doors record into, for a test that calls a
/// planner or realizer directly. It holds the attribution test lock, the
/// last one in the whole-crate order (see `policy::attribution_test_lock`),
/// and its frame is discarded when it drops.
pub(crate) struct DoorScope {
    attribution: crate::kernel::policy::Attribution,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl DoorScope {
    pub(crate) fn new() -> Self {
        let guard = crate::kernel::policy::attribution_test_lock();
        Self {
            attribution: crate::kernel::policy::Attribution::open("test").unwrap(),
            _guard: guard,
        }
    }

    pub(crate) fn door<'a>(
        &'a mut self,
        store: &'a crate::kernel::store::Store,
        activity: &'a crate::kernel::activity::StoreActivity,
        platform: crate::kernel::platform::Platform,
        kind: crate::kernel::resolve::DoorKind,
    ) -> crate::kernel::resolve::ResolutionDoor<'a> {
        crate::kernel::resolve::ResolutionDoor::open(
            store,
            activity,
            platform,
            kind,
            &mut self.attribution,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod socket_tests {
    use super::*;

    /// A socket path longer than a socket address holds is bound where it
    /// is: the entry at that path is a socket.
    #[test]
    fn bind_socket_takes_a_path_past_the_address_limit() {
        use std::os::unix::fs::FileTypeExt as _;
        let temp = TempDir::named("bind-socket");
        let deep = temp.0.join("d".repeat(60)).join("e".repeat(60));
        std::fs::create_dir_all(&deep).unwrap();
        let path = deep.join("listener.sock");
        assert!(path.as_os_str().len() > 108, "{}", path.display());
        let _listener = bind_socket(&path);
        let stat = std::fs::symlink_metadata(&path).unwrap();
        assert!(stat.file_type().is_socket());
    }
}

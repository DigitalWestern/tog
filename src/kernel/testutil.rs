//! Test-only helpers shared across layers (kernel layer, `cfg(test)`).

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// A scratch directory named `tog-test-<label>-<pid>-<nanos>`, gone on
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
    pub fn named(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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

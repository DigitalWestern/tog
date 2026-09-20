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

pub struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

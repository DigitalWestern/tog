//! Operation-scoped input observations. The digest recorded after planning
//! must describe the bytes the planner consumed, even during file replacement.

use super::ProjectRoot;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub(super) struct Inputs {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    digests: BTreeMap<PathBuf, Option<String>>,
    changed: bool,
}

fn changed(path: &Path) -> io::Error {
    io::Error::other(format!(
        "{} changed while planning; nothing was published; run `tog` again",
        path.display()
    ))
}

impl ProjectRoot {
    /// A fresh observation scope for this held directory. Ordinary clones
    /// share it, while other roots and subsequent operations remain independent.
    pub(crate) fn observing_inputs(&self) -> io::Result<Self> {
        let mut root = self.try_clone()?;
        root.observed = Some(Arc::new(Inputs::default()));
        Ok(root)
    }

    pub(super) fn observe_input(&self, path: &Path, bytes: Option<&[u8]>) -> io::Result<()> {
        let Some(observed) = &self.observed else {
            return Ok(());
        };
        let digest = bytes.map(|bytes| hex::encode(Sha256::digest(bytes)));
        let mut state = observed.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(first) = state.digests.get(path) {
            if first != &digest {
                state.changed = true;
                return Err(changed(&self.path.join(path)));
            }
        } else {
            state.digests.insert(path.to_path_buf(), digest);
        }
        Ok(())
    }

    /// Only after this operation deliberately regenerates a file, allow its
    /// next read to establish the new input. This never clears a prior conflict.
    pub(crate) fn regenerated_input(&self, path: &Path) {
        if let Some(observed) = &self.observed {
            observed
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .digests
                .remove(path);
        }
    }

    /// Verify consumed files and missing inputs against the held directory
    /// before realization. A later publication also checks the resolution basis.
    pub(crate) fn verify_observed_inputs(&self) -> io::Result<()> {
        let Some(observed) = &self.observed else {
            return Ok(());
        };
        let state = observed.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.changed {
            return Err(changed(&self.path));
        }
        let mut current = self.try_clone()?;
        current.observed = None;
        for (path, first) in &state.digests {
            let digest = current
                .read_input(path)?
                .map(|bytes| hex::encode(Sha256::digest(bytes)));
            if &digest != first {
                return Err(changed(&self.path.join(path)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn replaced_consumed_lock_is_refused_even_if_an_error_was_ignored() {
        let temp = TempDir::new();
        std::fs::write(temp.0.join("uv.lock"), "generation A").unwrap();
        let root = ProjectRoot::open(&temp.0).unwrap();
        let observed = root.observing_inputs().unwrap();
        observed.read_input(Path::new("uv.lock")).unwrap();
        std::fs::write(temp.0.join("uv.lock"), "generation B").unwrap();
        assert!(observed
            .try_clone()
            .unwrap()
            .read_input(Path::new("uv.lock"))
            .is_err());
        std::fs::write(temp.0.join("uv.lock"), "generation A").unwrap();
        assert!(observed.verify_observed_inputs().is_err());
        root.observing_inputs()
            .unwrap()
            .verify_observed_inputs()
            .unwrap();
    }

    #[test]
    fn missing_inputs_are_checked_and_own_generated_locks_can_be_consumed() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&temp.0)
            .unwrap()
            .observing_inputs()
            .unwrap();
        assert!(!root.is_input_file(Path::new("requirements.lock.txt")));
        std::fs::write(temp.0.join("requirements.lock.txt"), "generated").unwrap();
        assert!(root.verify_observed_inputs().is_err());
        root.regenerated_input(Path::new("requirements.lock.txt"));
        root.read_input(Path::new("requirements.lock.txt")).unwrap();
        root.verify_observed_inputs().unwrap();
    }
}

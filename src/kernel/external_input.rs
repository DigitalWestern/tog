//! Project inputs that live outside the project directory: an absolute
//! `tog.toml` `[python].requirements` path, or a requirements include
//! beside the project. The held descriptor cannot read them, so they are
//! read by path, and a path can name a different file from one moment to
//! the next.
//!
//! Each is therefore read once per held project: the first stage that
//! names one (manifest planning, the closure's input digest, the `tog
//! status` check) takes a snapshot, and every later stage of the same
//! command sees those bytes. A file replaced between stages cannot make a
//! command plan from one file and record the digest of another (#501). A
//! new command opens a new project root and reads the file afresh, so an
//! edit is still seen as a change.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What one spelling of an external path named when it was first read:
/// `None` when it was absent or not a regular file.
type Snapshot = Option<Arc<Vec<u8>>>;

/// The external inputs one held project has read. Shared by the root and
/// every root derived from it (`try_clone`, `subdir`, `parent`).
#[derive(Debug, Default)]
pub(crate) struct ExternalInputs {
    /// Keyed by the spelling a caller used and by its canonical path, so
    /// the manifest walk (canonical) and the input record (as configured)
    /// agree on one read.
    read: Mutex<BTreeMap<PathBuf, Snapshot>>,
    /// Each spelling's canonical path, resolved once, so a symlink
    /// retargeted mid-command does not move a later stage to another file.
    canonical: Mutex<BTreeMap<PathBuf, PathBuf>>,
}

impl ExternalInputs {
    /// The bytes of the regular file at `path`, or `None` when it is
    /// absent or not a regular file, as of this project's first read.
    pub(crate) fn read(&self, path: &Path) -> io::Result<Snapshot> {
        let mut read = self.read.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(snapshot) = read.get(path) {
            return Ok(snapshot.clone());
        }
        let canonical = match self.canonical(path) {
            Ok(canonical) => canonical,
            Err(error) if absent(&error) => {
                read.insert(path.to_path_buf(), None);
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let snapshot = match read.get(&canonical) {
            Some(snapshot) => snapshot.clone(),
            None => {
                let snapshot = read_regular(&canonical)?.map(Arc::new);
                read.insert(canonical, snapshot.clone());
                snapshot
            }
        };
        read.insert(path.to_path_buf(), snapshot.clone());
        Ok(snapshot)
    }
}

impl ExternalInputs {
    /// `path.canonicalize()`, as of this project's first resolution of it.
    pub(crate) fn canonical(&self, path: &Path) -> io::Result<PathBuf> {
        let mut canonical = self.canonical.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(resolved) = canonical.get(path) {
            return Ok(resolved.clone());
        }
        let resolved = path.canonicalize()?;
        canonical.insert(path.to_path_buf(), resolved.clone());
        // A canonical path resolves to itself.
        canonical.insert(resolved.clone(), resolved.clone());
        Ok(resolved)
    }
}

/// A missing file, a file where a directory was named, and a symlink loop
/// all read as absent, as `Path::is_file` reads them.
fn absent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || error.raw_os_error() == Some(libc::ENOTDIR)
        || error.raw_os_error() == Some(libc::ELOOP)
}

/// Open once without blocking (a FIFO swapped in does not hang the
/// command) and read the descriptor whose type was checked.
fn read_regular(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if absent(&error) => return Ok(None),
        Err(error) => {
            // Some nonregular entries (Unix sockets) cannot be opened at
            // all. Those are absent too. A regular file that cannot be
            // opened is an error.
            if !fs::metadata(path).is_ok_and(|meta| meta.is_file()) {
                return Ok(None);
            }
            return Err(error);
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        io::Error::new(error.kind(), format!("read {}: {error}", path.display()))
    })?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_replaced_after_its_first_read_keeps_its_snapshot() {
        let temp = crate::kernel::testutil::TempDir::new();
        let file = temp.0.join("requirements.txt");
        fs::write(&file, "six==1.17.0\n").unwrap();
        let inputs = ExternalInputs::default();
        assert_eq!(
            inputs.read(&file).unwrap().as_deref().map(Vec::as_slice),
            Some(&b"six==1.17.0\n"[..])
        );
        fs::write(&file, "six==1.16.0\n").unwrap();
        assert_eq!(
            inputs.read(&file).unwrap().as_deref().map(Vec::as_slice),
            Some(&b"six==1.17.0\n"[..])
        );
        // A new reader (the next command) sees the edit.
        assert_eq!(
            ExternalInputs::default()
                .read(&file)
                .unwrap()
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"six==1.16.0\n"[..])
        );
    }

    #[test]
    fn a_symlinked_spelling_shares_the_canonical_read() {
        let temp = crate::kernel::testutil::TempDir::new();
        let file = temp.0.join("requirements.txt");
        let link = temp.0.join("link.txt");
        fs::write(&file, "six==1.17.0\n").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let inputs = ExternalInputs::default();
        inputs.read(&file.canonicalize().unwrap()).unwrap();
        fs::write(&file, "six==1.16.0\n").unwrap();
        assert_eq!(
            inputs.read(&link).unwrap().as_deref().map(Vec::as_slice),
            Some(&b"six==1.17.0\n"[..])
        );
    }

    #[test]
    fn a_missing_file_stays_missing_for_the_command() {
        let temp = crate::kernel::testutil::TempDir::new();
        let file = temp.0.join("requirements.txt");
        let inputs = ExternalInputs::default();
        assert!(inputs.read(&file).unwrap().is_none());
        fs::write(&file, "six\n").unwrap();
        assert!(inputs.read(&file).unwrap().is_none());
    }
}

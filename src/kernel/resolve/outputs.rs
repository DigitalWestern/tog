//! The immutable copy of a door run's accepted outputs (kernel layer).
//!
//! Once the tool's whole process tree has stopped and the diff has
//! classified its changes, each accepted output is opened inside the stage
//! without following any symlink on the way (`openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` and
//! `O_NOFOLLOW`, or a component-by-component `O_NOFOLLOW` walk where the
//! kernel has no `openat2`), checked to be a regular file with `fstat`, and
//! copied into a tog-owned directory under the store's `tmp/`. The copy is
//! made read-only and its directory is held open. Everything after this
//! point (the receipt's digests, publication) reads the copy, never the
//! stage, so nothing the tool left behind can change what is published.
//!
//! Each copy is also checked for secrets that must never reach a lockfile:
//! the proxy session token and the proxy's address. A tool that echoes one
//! into an output fails the door.

use crate::kernel::activity::StoreActivity;
use crate::kernel::resolve::snapshot::{self, Snapshot};
use crate::kernel::store::{self, Store};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// No single lockfile or manifest a door writes is anywhere near this; a
/// larger output is refused rather than copied.
pub const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;

/// A string that must not appear in any output, and how to name it.
#[derive(Clone, Debug)]
pub struct Forbidden {
    pub label: String,
    pub bytes: Vec<u8>,
}

impl Forbidden {
    pub fn new(label: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Forbidden {
        Forbidden {
            label: label.into(),
            bytes: bytes.into(),
        }
    }
}

/// One accepted output in the copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputFile {
    /// Relative to the lock root.
    pub relative: PathBuf,
    pub sha256: [u8; 32],
    /// Permission bits the tool left on the file (0o777 mask).
    pub mode: u32,
    pub len: u64,
    name: String,
}

/// The read-only copy of every accepted output. The directory is removed
/// when this is dropped.
#[derive(Debug)]
pub struct Outputs {
    dir: PathBuf,
    dir_fd: fs::File,
    files: Vec<OutputFile>,
}

impl Drop for Outputs {
    fn drop(&mut self) {
        let _ = snapshot::remove_private_tree(&self.dir);
    }
}

impl Outputs {
    /// No outputs: for a publication that replaces only the receipt (`tog
    /// attest`, whose lock check changed nothing), while its held outputs
    /// must still read as they did.
    pub fn none(store: &Store, activity: &StoreActivity) -> io::Result<Outputs> {
        store.require_activity(activity, "resolution output copy")?;
        let dir = snapshot::create_private_dir(&store.root.join("tmp"), "resolve-out")?;
        let dir_fd = open_dir(&dir)?;
        Ok(Outputs {
            dir,
            dir_fd,
            files: Vec::new(),
        })
    }

    /// Copy `relatives` (outputs relative to the lock root, as classified)
    /// out of the snapshot's stage.
    pub fn copy(
        store: &Store,
        activity: &StoreActivity,
        snapshot: &Snapshot,
        relatives: &[PathBuf],
        forbidden: &[Forbidden],
    ) -> io::Result<Outputs> {
        store.require_activity(activity, "resolution output copy")?;
        let stage_root = open_dir(&snapshot.lock_root().staged)?;
        let dir = snapshot::create_private_dir(&store.root.join("tmp"), "resolve-out")?;
        let dir_fd = open_dir(&dir)?;
        let mut outputs = Outputs {
            dir,
            dir_fd,
            files: Vec::new(),
        };
        let mut problems = Vec::new();
        for (index, relative) in relatives.iter().enumerate() {
            snapshot::check_relative(relative)?;
            let shown = snapshot.lock_root().real.join(relative);
            let source = open_beneath(stage_root.as_raw_fd(), relative).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "the declared output {} could not be opened without following a \
                         symlink: {error}",
                        shown.display()
                    ),
                )
            })?;
            let stat = store::fd_stat(source.as_raw_fd())?;
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "the declared output {} is not a regular file",
                        shown.display()
                    ),
                ));
            }
            if stat.st_size as u64 > MAX_OUTPUT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the declared output {} is {} bytes; outputs over {MAX_OUTPUT_BYTES} \
                         bytes are refused",
                        shown.display(),
                        stat.st_size
                    ),
                ));
            }
            let name = index.to_string();
            let (bytes, sha256) = outputs.write_copy(source, &name, &shown)?;
            for needle in forbidden {
                if !needle.bytes.is_empty() && contains(&bytes, &needle.bytes) {
                    problems.push(format!("{} contains {}", shown.display(), needle.label));
                }
            }
            outputs.files.push(OutputFile {
                relative: relative.clone(),
                sha256,
                mode: stat.st_mode as u32 & 0o777,
                len: bytes.len() as u64,
                name,
            });
        }
        set_mode(outputs.dir_fd.as_raw_fd(), 0o500)?;
        if !problems.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the resolution tool wrote a secret into an output, so nothing was \
                     published: {}",
                    snapshot::listing(&problems)
                ),
            ));
        }
        Ok(outputs)
    }

    pub fn files(&self) -> &[OutputFile] {
        &self.files
    }

    pub fn get(&self, relative: &Path) -> Option<&OutputFile> {
        self.files.iter().find(|file| file.relative == relative)
    }

    /// The copy's bytes, re-read through the held directory and checked
    /// against the digest taken when it was written.
    pub fn contents(&self, file: &OutputFile) -> io::Result<Vec<u8>> {
        let handle = store::open_file_at(
            self.dir_fd.as_raw_fd(),
            file.name.as_bytes(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let mut bytes = Vec::with_capacity(file.len as usize);
        (&handle)
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if digest != file.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the stored copy of {} changed after it was taken",
                    file.relative.display()
                ),
            ));
        }
        Ok(bytes)
    }

    fn write_copy(
        &self,
        mut source: fs::File,
        name: &str,
        shown: &Path,
    ) -> io::Result<(Vec<u8>, [u8; 32])> {
        let mut bytes = Vec::new();
        (&mut source)
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_OUTPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the declared output {} grew past the size limit",
                    shown.display()
                ),
            ));
        }
        let mut copy = store::open_file_at(
            self.dir_fd.as_raw_fd(),
            name.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        copy.write_all(&bytes)?;
        copy.sync_all()?;
        set_mode(copy.as_raw_fd(), 0o400)?;
        let sha256 = Sha256::digest(&bytes).into();
        Ok((bytes, sha256))
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn set_mode(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: fchmod on a descriptor the caller holds.
    if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn open_dir(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("open {}: {error}", path.display())))
}

/// Open `relative` below `dirfd` read-only, refusing any symlink on the
/// way or at the end, and any escape from `dirfd`.
pub(crate) fn open_beneath(dirfd: RawFd, relative: &Path) -> io::Result<fs::File> {
    snapshot::check_relative(relative)?;
    #[cfg(target_os = "linux")]
    match openat2_beneath(dirfd, relative) {
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EPERM)) => {}
        other => return other,
    }
    open_by_components(dirfd, relative)
}

#[cfg(target_os = "linux")]
fn openat2_beneath(dirfd: RawFd, relative: &Path) -> io::Result<fs::File> {
    let path = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains NUL"))?;
    // SAFETY: open_how is plain data; zeroed is its documented default.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: openat2 with a live directory fd, a NUL-terminated path and a
    // correctly sized open_how; a returned fd is owned by the File.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor to us.
    Ok(unsafe { fs::File::from_raw_fd(fd as RawFd) })
}

/// The portable equivalent: every directory is opened `O_NOFOLLOW |
/// O_DIRECTORY` relative to the one before, and the leaf `O_NOFOLLOW`.
fn open_by_components(dirfd: RawFd, relative: &Path) -> io::Result<fs::File> {
    let names: Vec<&[u8]> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.as_bytes()),
            _ => None,
        })
        .collect();
    let (leaf, parents) = names.split_last().expect("checked non-empty");
    let mut held: Option<fs::File> = None;
    for name in parents {
        let at = held.as_ref().map_or(dirfd, |dir| dir.as_raw_fd());
        held = Some(store::open_file_at(
            at,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?);
    }
    let at = held.as_ref().map_or(dirfd, |dir| dir.as_raw_fd());
    store::open_file_at(
        at,
        leaf,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::resolve::snapshot::SnapshotSpec;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn setup(temp: &TempDir) -> (Store, PathBuf) {
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp", "roots", "records"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let dir = temp.0.join("project");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("package.json"), b"{}").unwrap();
        fs::write(dir.join("sub/package.json"), b"{}").unwrap();
        (
            Store {
                root: root.canonicalize().unwrap(),
            },
            dir.canonicalize().unwrap(),
        )
    }

    fn snap(store: &Store, dir: &Path) -> Snapshot {
        let activity = store.activity(ActivityMode::Shared).unwrap();
        Snapshot::build(
            store,
            &activity,
            &SnapshotSpec {
                lock_root: dir,
                extra_roots: &[],
                exclude: &[],
            },
        )
        .unwrap()
    }

    fn copy(store: &Store, snapshot: &Snapshot, relatives: &[&str]) -> io::Result<Outputs> {
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let relatives: Vec<PathBuf> = relatives.iter().map(PathBuf::from).collect();
        Outputs::copy(
            store,
            &activity,
            snapshot,
            &relatives,
            &[
                Forbidden::new("the proxy session token", b"tok-secret".to_vec()),
                Forbidden::new("the proxy address", b"127.0.0.1:8119".to_vec()),
            ],
        )
    }

    #[test]
    fn outputs_are_copied_read_only_and_survive_stage_changes() {
        let temp = TempDir::named("outputs-copy");
        let (store, dir) = setup(&temp);
        let snapshot = snap(&store, &dir);
        let staged = snapshot.lock_root().staged.clone();
        fs::write(staged.join("package-lock.json"), b"lock v1").unwrap();
        fs::set_permissions(
            staged.join("package-lock.json"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        fs::write(staged.join("sub/package.json"), b"{\"x\":1}").unwrap();
        let outputs = copy(
            &store,
            &snapshot,
            &["package-lock.json", "sub/package.json"],
        )
        .unwrap();
        // Whatever happens to the stage afterwards does not reach the copy.
        fs::write(staged.join("package-lock.json"), b"lock v2").unwrap();
        let lock = outputs.get(Path::new("package-lock.json")).unwrap();
        assert_eq!(outputs.contents(lock).unwrap(), b"lock v1");
        assert_eq!(lock.mode, 0o640);
        assert_eq!(lock.sha256, <[u8; 32]>::from(Sha256::digest(b"lock v1")));
        let dir_mode = fs::metadata(&outputs.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o500);
        let file_mode = fs::metadata(outputs.dir.join("0"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o400);
        let held = outputs.dir.clone();
        drop(outputs);
        assert!(!held.exists());
    }

    #[test]
    fn output_containing_the_token_fails() {
        let temp = TempDir::named("outputs-token");
        let (store, dir) = setup(&temp);
        let snapshot = snap(&store, &dir);
        let staged = snapshot.lock_root().staged.clone();
        fs::write(
            staged.join("package-lock.json"),
            b"resolved: http://tog:tok-secret@127.0.0.1:8119/x.tgz",
        )
        .unwrap();
        let message = copy(&store, &snapshot, &["package-lock.json"])
            .unwrap_err()
            .to_string();
        assert!(message.contains("the proxy session token"), "{message}");
        assert!(message.contains("the proxy address"), "{message}");
        assert!(message.contains("package-lock.json"), "{message}");
    }

    #[test]
    fn a_symlink_anywhere_on_the_path_is_refused() {
        let temp = TempDir::named("outputs-symlink");
        let (store, dir) = setup(&temp);
        let snapshot = snap(&store, &dir);
        let staged = snapshot.lock_root().staged.clone();
        fs::remove_file(staged.join("package.json")).unwrap();
        symlink("sub/package.json", staged.join("package.json")).unwrap();
        assert!(copy(&store, &snapshot, &["package.json"]).is_err());
        fs::remove_dir_all(staged.join("sub")).unwrap();
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("package.json"), b"{}").unwrap();
        symlink(&outside, staged.join("sub")).unwrap();
        assert!(copy(&store, &snapshot, &["sub/package.json"]).is_err());
        // The component walk refuses the same paths.
        let root = open_dir(&staged).unwrap();
        assert!(open_by_components(root.as_raw_fd(), Path::new("sub/package.json")).is_err());
        assert!(open_by_components(root.as_raw_fd(), Path::new("package.json")).is_err());
    }

    #[test]
    fn a_fifo_output_is_refused_without_blocking() {
        let temp = TempDir::named("outputs-fifo");
        let (store, dir) = setup(&temp);
        let snapshot = snap(&store, &dir);
        let path = snapshot.lock_root().staged.join("package-lock.json");
        let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path in the test's own stage.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let message = copy(&store, &snapshot, &["package-lock.json"])
            .unwrap_err()
            .to_string();
        assert!(message.contains("not a regular file"), "{message}");
    }
}

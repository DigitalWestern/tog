//! Descriptor-relative project access (kernel layer). A `ProjectRoot` holds
//! a project directory open as a descriptor, reached from `/` one component
//! at a time with openat(O_NOFOLLOW), and every project-relative file it
//! reads or publishes is resolved from that descriptor, never from the
//! project's pathname: a project directory renamed or replaced while a
//! command runs cannot substitute another project's files.
//!
//! Two read disciplines share the descriptor. tog's own state (`.tog`,
//! closures, caches) and the toolchain inputs are walked one component at a
//! time with O_NOFOLLOW (`read_file`, `write_file`, `entry`): no component is
//! ever followed through a symlink, so a symlinked `.tog` cannot redirect a
//! cache write outside the project. Inputs the user authors (manifests,
//! dependency locks) are read with `read_input`, which resolves from the
//! descriptor but follows a symlink the project itself contains, as a
//! pathname read inside the project always has.
//!
//! What `write_file` guarantees: the file is created with O_EXCL under a
//! random temporary name in the held parent, written, fsynced, and renamed
//! over the destination, which is checked first and refused unless it is
//! absent or a regular file. A concurrent same-user writer that swaps a
//! symlink in after that check gets its symlink replaced, never written
//! through; two writers of the same file each publish a complete file and
//! the last rename wins. The temporary's inode is checked before the rename
//! and before cleanup, which narrows but cannot close the window in which
//! a hostile same-user process swaps the temporary itself. A replaced file
//! is a fresh inode with mode 0644 under the umask, not the old file's
//! mode. Temporary cleanup after a failure is best-effort.

use crate::kernel::store::{
    fd_stat, fsync_directory, mkdir_at, open_file_at, read_dir_names_at, remove_tree_entry_at,
    rename_at, same_inode, stat_at, stat_at_following, unlink_if_same,
};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

mod held;
mod rename_in;
use held::HeldEntry;
pub(crate) use held::{held_root_for, start_in};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
/// An ancestor on the walk to a project: held for lookups below it, never
/// listed, so search permission is enough on Linux (`O_PATH`).
#[cfg(target_os = "linux")]
const ANCESTOR_FLAGS: libc::c_int =
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const ANCESTOR_FLAGS: libc::c_int = DIRECTORY_FLAGS;
const TEMP_ATTEMPTS: usize = 8;

/// What a project-relative name resolves to, without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// No such name, or a parent directory that does not exist.
    Absent,
    Regular,
    Directory,
    Symlink,
    /// A FIFO, a socket, or a device.
    Other,
}

/// A project directory held open as a descriptor.
#[derive(Debug)]
pub struct ProjectRoot {
    /// Set for a root `open` made: while it lives, a child started in its
    /// path starts in this directory (`start_in`). Declared before `dir`
    /// so its row leaves the table before the descriptor closes.
    _held: Option<HeldEntry>,
    dir: fs::File,
    path: PathBuf,
    /// The files outside the project this root has read, shared with every
    /// root derived from it, so one command reads each once (#501).
    external: std::sync::Arc<crate::kernel::external_input::ExternalInputs>,
}

/// The held directory, for a caller that must issue a descriptor-relative
/// call this type has no method for (the resolution transaction's
/// `renameat2(RENAME_EXCHANGE)`). The descriptor stays owned here.
impl AsRawFd for ProjectRoot {
    fn as_raw_fd(&self) -> RawFd {
        self.dir.as_raw_fd()
    }
}

impl ProjectRoot {
    /// Canonicalize `project_dir`, then open that path from `/` one
    /// component at a time with O_NOFOLLOW, so an ancestor swapped for a
    /// symlink after canonicalization is refused rather than followed.
    pub fn open(project_dir: &Path) -> io::Result<Self> {
        let path = project_dir.canonicalize().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("open project {}: {error}", project_dir.display()),
            )
        })?;
        let dir = walk_from_root(&path)?;
        let held = HeldEntry::register(&path, &dir);
        Ok(Self {
            dir,
            path,
            _held: Some(held),
            external: Default::default(),
        })
    }

    /// The directory an open root holds at `path` (`None` if none does), as
    /// a readable root with no cwd binding of its own: a confined door's lock
    /// root is the tree tog opened, though renamed or replaced since (#498).
    ///
    /// The path it returns is canonical, as `open`'s is. A path that climbs
    /// (`..`), or that reaches below a held root through a symlink, is not
    /// a held spelling: it is resolved as it stands now and looked up again.
    pub(crate) fn held_at(path: &Path) -> io::Result<Option<Self>> {
        let Some((held, path)) = held_root_for(path)? else {
            return Ok(None);
        };
        let dir = open_file_at(held.as_raw_fd(), b".", DIRECTORY_FLAGS, 0)?;
        Ok(Some(Self {
            _held: None,
            dir,
            path,
            external: Default::default(),
        }))
    }

    /// The canonical project path, for messages. Every operation goes
    /// through the descriptor, not this path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Open a project-relative regular file for reading without following
    /// a symlink at any component. `Ok(None)` when any component is absent.
    /// A symlink anywhere on the path, a non-directory where a directory is
    /// expected, or a destination that is not a regular file (a FIFO, a
    /// device, a directory) is an error, so a tampered cache fails closed
    /// instead of being read as a miss.
    pub(crate) fn open_file(&self, relative: &Path) -> io::Result<Option<fs::File>> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "read", &mut display)? else {
            return Ok(None);
        };
        let fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let file = match open_file_at(
            fd,
            name.as_bytes(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(refusal(format!(
                    "{} is a symlink; refusing to read through it",
                    display.display()
                )));
            }
            // A socket refuses to open before its type can be seen on a
            // descriptor, so classify a failed open by the entry itself.
            Err(error) => {
                if let Ok(stat) = stat_at(fd, name.as_bytes()) {
                    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                        return Err(refusal(format!(
                            "{} is not a regular file; refusing to read it",
                            display.display()
                        )));
                    }
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!("read {}: {error}", display.display()),
                ));
            }
        };
        if !file.metadata()?.file_type().is_file() {
            return Err(refusal(format!(
                "{} is not a regular file; refusing to read it",
                display.display()
            )));
        }
        Ok(Some(file))
    }

    /// The bytes of a project-relative file, or `None` when it is absent.
    /// Refusals (`InvalidData`) are those of `open_file`; a bad relative
    /// path is `InvalidInput`; anything else is the OS error from the walk.
    pub fn read_file(&self, relative: &Path) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = self.open_file(relative)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    /// Publish `bytes` at a project-relative path atomically, creating
    /// missing parent directories. Refuses a symlink or a non-directory at
    /// any parent, a destination that is neither absent nor a regular file,
    /// and a temporary name that stays occupied after a bounded number of
    /// fresh random names.
    pub fn write_file(&self, relative: &Path, bytes: &[u8]) -> io::Result<()> {
        self.publish(relative, bytes, &mut random_temp_name)
    }

    /// `write_file` with an explicit permission mode (an executable shim),
    /// set on the temporary before it is renamed into place, so the file is
    /// never visible with the wrong mode.
    pub fn write_file_mode(
        &self,
        relative: &Path,
        bytes: &[u8],
        mode: libc::mode_t,
    ) -> io::Result<()> {
        self.publish_mode(
            relative,
            &mut &bytes[..],
            Some(mode),
            false,
            &mut random_temp_name,
        )
    }

    /// Point a project-relative symlink (a `.venv` or `node_modules`
    /// projection) at `target`, atomically: a new link is made under a
    /// random temporary name in the held parent and renamed over the
    /// destination, then the parent is fsynced. Missing parents are created
    /// with the no-follow walk. An existing symlink is replaced; a real file
    /// or directory at the destination is user state and is refused, never
    /// overwritten. `label` names the projection in messages.
    pub fn replace_symlink(&self, relative: &Path, target: &Path, label: &str) -> io::Result<()> {
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let held = self.open_creating(&parents, &mut display)?;
        display.push(name);
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        // Whether the name was absent when checked. An absent name is
        // published with an exclusive rename, so a real file or directory
        // that appears in between is refused rather than replaced.
        let absent = match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFLNK => false,
            Ok(_) => {
                return Err(refusal(format!(
                    "{label} {} is a real file or directory; refusing to overwrite it",
                    display.display()
                )))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
            refusal(format!(
                "{label} target contains a NUL byte; refusing to publish"
            ))
        })?;
        let mut made = None;
        for _ in 0..TEMP_ATTEMPTS {
            let candidate = random_temp_name(name.as_bytes(), 0)?;
            let temp = CString::new(candidate.clone()).expect("hex names hold no NUL");
            // SAFETY: parent_fd is an open directory and both strings are
            // valid NUL-terminated strings that outlive the call.
            if unsafe { libc::symlinkat(target.as_ptr(), parent_fd, temp.as_ptr()) } == 0 {
                made = Some(candidate);
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::new(
                    error.kind(),
                    format!("create temporary link for {label}: {error}"),
                ));
            }
        }
        let temp = made.ok_or_else(|| {
            refusal(format!(
                "every temporary name for {label} {} is occupied; remove stale .tog-tmp \
                 entries and retry",
                display.display()
            ))
        })?;
        let renamed = if absent {
            rename_at_noreplace(parent_fd, &temp, name.as_bytes()).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    refusal(format!(
                        "{label} {} appeared while it was being published; refusing to \
                         overwrite it",
                        display.display()
                    ))
                } else {
                    error
                }
            })
        } else {
            rename_at(parent_fd, &temp, name.as_bytes())
        };
        let result = renamed
            .map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidData {
                    error
                } else {
                    io::Error::new(error.kind(), format!("publish {label}: {error}"))
                }
            })
            .and_then(|()| {
                fsync_directory(parent_fd).map_err(|error| {
                    io::Error::new(error.kind(), format!("sync {label} parent: {error}"))
                })
            });
        if result.is_err() {
            if let Ok(stat) = stat_at(parent_fd, &temp) {
                let _ = unlink_if_same(parent_fd, &temp, &stat, 0);
            }
        }
        result
    }

    /// The target of a project-relative symlink, read without following
    /// it. `None` when the name is absent or is not a symlink.
    pub fn read_link(&self, relative: &Path) -> io::Result<Option<PathBuf>> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "inspect", &mut display)? else {
            return Ok(None);
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
        let mut buffer = vec![0u8; libc::PATH_MAX as usize + 1];
        // SAFETY: parent_fd is open, name is NUL-terminated, and the buffer
        // is writable for its whole length.
        let length = unsafe {
            libc::readlinkat(
                parent_fd,
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::EINVAL) => Ok(None),
                _ => Err(io::Error::new(
                    error.kind(),
                    format!("read link {}: {error}", display.display()),
                )),
            };
        }
        buffer.truncate(length as usize);
        Ok(Some(PathBuf::from(std::ffi::OsString::from_vec(buffer))))
    }

    /// Remove a project-relative symlink tog placed (a stale workspace
    /// link). `Ok(())` when it is already absent. Anything that is not a
    /// symlink is refused, so a user's real file or directory that took the
    /// name is never removed.
    pub fn remove_symlink(&self, relative: &Path) -> io::Result<()> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "remove", &mut display)? else {
            return Ok(());
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let stat = match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
            return Err(refusal(format!(
                "{} is not a symlink; refusing to remove it",
                display.display()
            )));
        }
        unlink_if_same(parent_fd, name.as_bytes(), &stat, 0).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("remove {}: {error}", display.display()),
            )
        })?;
        Ok(())
    }

    /// Remove a project-relative directory tree tog owns (`.tog/cargo-home`
    /// on `--fresh`) without following a symlink anywhere: a symlink at the
    /// name is unlinked, never followed, and nothing outside the tree is
    /// touched. `Ok(())` when it is already absent.
    pub fn remove_dir_all(&self, relative: &Path) -> io::Result<()> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "remove", &mut display)? else {
            return Ok(());
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        remove_tree_entry_at(parent_fd, name.as_bytes()).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("remove {}: {error}", display.display()),
            )
        })
    }

    /// fsync a project directory (`.` for the root) reached with the
    /// no-follow walk, so an entry just renamed out of it is durable.
    pub fn sync_dir(&self, relative: &Path) -> io::Result<()> {
        if relative == Path::new(".") {
            return fsync_directory(self.dir.as_raw_fd());
        }
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "sync", &mut display)? else {
            return Ok(());
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let dir = open_directory_at(parent_fd, name.as_bytes(), &display, "sync")?;
        fsync_directory(dir.as_raw_fd())
    }

    /// Move a real project directory (a pre-tog `.venv` or `node_modules`)
    /// out of the project into `destination_dir` under `destination_name`,
    /// with one `renameat` from the held parent. Refuses unless the name is
    /// a real directory now; a symlink is never followed or moved.
    pub fn move_dir_out(
        &self,
        relative: &Path,
        destination_dir: &fs::File,
        destination_name: &[u8],
    ) -> io::Result<()> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "move", &mut display)? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is gone", display.display()),
            ));
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let stat = stat_at(parent_fd, name.as_bytes())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(refusal(format!(
                "{} is not a real directory; refusing to move it",
                display.display()
            )));
        }
        rename_between(
            parent_fd,
            name.as_bytes(),
            destination_dir.as_raw_fd(),
            destination_name,
        )
    }

    /// Open a project-relative file to hold an advisory lock on, creating
    /// it and any missing parent directory. The name is opened
    /// descriptor-relative with `O_NOFOLLOW`, so a symlink planted at it
    /// fails closed rather than making the caller lock a file outside the
    /// project. The descriptor is read/write because `flock` upgrades are
    /// refused on a read-only description on some systems.
    pub fn open_lock_file(&self, relative: &Path) -> io::Result<fs::File> {
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let held = self.open_creating(&parents, &mut display)?;
        display.push(name);
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match open_file_at(
            parent_fd,
            name.as_bytes(),
            libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        ) {
            Ok(file) => Ok(file),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Err(refusal(format!(
                "{} is a symlink; refusing to lock through it",
                display.display()
            ))),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("open {}: {error}", display.display()),
            )),
        }
    }

    /// What a project-relative path names, seen from the held descriptor
    /// without following a symlink at any component. A caller can refuse a
    /// tampered destination before it does work a later refusal would have
    /// to unwind. An absent parent reads as `Entry::Absent`, the same as an
    /// absent name: neither can be written through.
    pub fn entry(&self, relative: &Path) -> io::Result<Entry> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "inspect", &mut display)? else {
            return Ok(Entry::Absent);
        };
        let fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match stat_at(fd, name.as_bytes()) {
            Ok(stat) => Ok(match stat.st_mode & libc::S_IFMT {
                libc::S_IFREG => Entry::Regular,
                libc::S_IFDIR => Entry::Directory,
                libc::S_IFLNK => Entry::Symlink,
                _ => Entry::Other,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Entry::Absent),
            Err(error) => Err(error),
        }
    }

    /// Remove a project-relative regular file through the held descriptor.
    /// `Ok(())` when the file or any parent is already absent. A symlink, a
    /// directory, or anything else at the destination is refused rather than
    /// unlinked, so a `.tog` or a cache entry swapped for a symlink cannot
    /// make a caller delete something outside the project. The unlink
    /// carries the inode the check saw, so an entry replaced in between is
    /// left alone rather than removed blind.
    pub fn remove_file(&self, relative: &Path) -> io::Result<()> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "remove", &mut display)? else {
            return Ok(());
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        let stat = match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => {}
            libc::S_IFLNK => {
                return Err(refusal(format!(
                    "{} is a symlink; refusing to remove it",
                    display.display()
                )))
            }
            libc::S_IFDIR => {
                return Err(refusal(format!(
                    "{} is a directory; refusing to remove it",
                    display.display()
                )))
            }
            _ => {
                return Err(refusal(format!(
                    "{} is not a regular file; refusing to remove it",
                    display.display()
                )))
            }
        }
        // `Ok(false)` means the entry went away or was replaced between the
        // check above and the unlink. Both are the caller's desired end
        // state -- the file it asked to remove is not there -- and removing
        // whatever took its place is exactly what this walk refuses to do,
        // so there is nothing to report.
        unlink_if_same(parent_fd, name.as_bytes(), &stat, 0).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("remove {}: {error}", display.display()),
            )
        })?;
        Ok(())
    }

    /// Create a project-relative directory and any missing parents, walking
    /// from the held descriptor one component at a time. Refuses a symlink
    /// or a non-directory at any component, so a caller that then reads or
    /// writes inside it cannot be redirected outside the project. An
    /// existing real directory is left as it is.
    pub fn create_dir_all(&self, relative: &Path) -> io::Result<()> {
        let (mut components, name) = split_relative(relative)?;
        components.push(name);
        let mut display = self.path.clone();
        self.open_creating(&components, &mut display)?;
        Ok(())
    }

    /// A second descriptor for the same held directory, for a holder that
    /// outlives the borrow it was handed (the toolchain-input guard).
    pub fn try_clone(&self) -> io::Result<Self> {
        let dir = self.dir.try_clone()?;
        let held = self
            ._held
            .as_ref()
            .map(|_| HeldEntry::register(&self.path, &dir));
        Ok(Self {
            dir,
            path: self.path.clone(),
            _held: held,
            external: self.external.clone(),
        })
    }

    /// Promote an ancestor used for reading into the directory a delegated
    /// tool will enter. Read-only ancestor walks must not install unrelated
    /// process-wide cwd bindings. Clones preserve their holder's role.
    pub(crate) fn with_cwd_binding(mut self) -> Self {
        if self._held.is_none() {
            self._held = Some(HeldEntry::register(&self.path, &self.dir));
        }
        self
    }

    /// A current filesystem name of the held directory, verified against
    /// its identity. This also works after the original name is replaced.
    pub(crate) fn current_name(&self) -> io::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        let path = fs::read_link(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))?;
        #[cfg(not(target_os = "linux"))]
        let path = self.path.canonicalize()?;
        let now = walk_from_root(&path)?;
        if !same_inode(&fd_stat(now.as_raw_fd())?, &fd_stat(self.dir.as_raw_fd())?) {
            return Err(refusal(
                "held directory name changed while resolving it".into(),
            ));
        }
        Ok(path)
    }

    /// Resolve an input alias without replacing the descriptor already held.
    /// Refuse if the resolved name no longer names that same directory.
    pub(crate) fn canonicalize_name(mut self) -> io::Result<Self> {
        let path = self.path.canonicalize()?;
        let now = walk_from_root(&path)?;
        if !same_inode(&fd_stat(now.as_raw_fd())?, &fd_stat(self.dir.as_raw_fd())?) {
            return Err(refusal(
                "input directory changed while resolving its name".into(),
            ));
        }
        let bound = self._held.take().is_some();
        self.path = path;
        if bound {
            self._held = Some(HeldEntry::register(&self.path, &self.dir));
        }
        Ok(self)
    }

    /// Does the canonical path still name the directory this descriptor
    /// holds? Every read and write here goes through the descriptor, so a
    /// renamed or replaced project cannot redirect them; but the path is
    /// what the store records as a GC root and what a child process is
    /// started in, so a sync refuses to finish once the two disagree. The
    /// stored canonical path is walked from `/` with O_NOFOLLOW exactly as
    /// it was recorded, never canonicalized again: an ancestor swapped for
    /// a symlink since `open` fails the walk instead of being resolved to
    /// wherever it now points.
    pub fn check_still_named(&self) -> io::Result<()> {
        let held = fd_stat(self.dir.as_raw_fd())?;
        let moved = |detail: String| {
            io::Error::other(format!(
                "{}: {detail}; run 'tog' again",
                self.path.display()
            ))
        };
        // Only the identity is compared, so the directory is not opened
        // for reading again: a held ancestor that can be searched but not
        // listed is still checked (#480).
        let now = match walk_from_root_with(&self.path, ANCESTOR_FLAGS) {
            Ok(now) => now,
            Err(error) => {
                return Err(moved(format!(
                    "the project directory was moved or became unreadable during sync ({error})"
                )))
            }
        };
        if !same_inode(&fd_stat(now.as_raw_fd())?, &held) {
            return Err(moved(
                "the project directory was moved or replaced during sync".into(),
            ));
        }
        Ok(())
    }

    /// The bytes of a project input the user authors (a manifest, a
    /// dependency lock, a version file), or `None` when it is absent.
    ///
    /// Resolved from the held descriptor, so a project directory renamed or
    /// replaced mid-command cannot substitute another project's files. A
    /// symlink the project itself contains is followed, as a pathname read
    /// inside the project would follow it: that is the user's own layout,
    /// not a race. The strict no-follow walk (`read_file`) stays for tog's
    /// own state under `.tog` and for toolchain inputs. `relative` may climb
    /// with `..` (a requirements include beside the project); it may not be
    /// absolute, since an absolute path would ignore the descriptor.
    pub fn read_input(&self, relative: &Path) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = self.open_input(relative)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read {}: {error}", self.path.join(relative).display()),
            )
        })?;
        Ok(Some(bytes))
    }

    /// `read_input` as UTF-8 text. Invalid UTF-8 is `InvalidData`, as
    /// `fs::read_to_string` reports it.
    pub fn read_input_string(&self, relative: &Path) -> io::Result<Option<String>> {
        match self.read_input(relative)? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not valid UTF-8", self.path.join(relative).display()),
                )
            }),
        }
    }

    /// What a project input names, resolved from the held descriptor and
    /// following symlinks the way `Path::is_file` does: a dangling symlink
    /// or a missing parent is `Entry::Absent`, and `Entry::Symlink` is
    /// never returned.
    pub fn input_entry(&self, relative: &Path) -> io::Result<Entry> {
        let name = input_name(relative)?;
        match stat_at_following(self.dir.as_raw_fd(), &name) {
            Ok(stat) => Ok(match stat.st_mode & libc::S_IFMT {
                libc::S_IFREG => Entry::Regular,
                libc::S_IFDIR => Entry::Directory,
                _ => Entry::Other,
            }),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ENOTDIR)
                    || error.raw_os_error() == Some(libc::ELOOP) =>
            {
                Ok(Entry::Absent)
            }
            Err(error) => Err(error),
        }
    }

    /// `input_entry(relative) == Entry::Regular`, with an unreadable
    /// parent read as absent, as `Path::is_file` reads it.
    pub fn is_input_file(&self, relative: &Path) -> bool {
        matches!(self.input_entry(relative), Ok(Entry::Regular))
    }

    /// `input_entry(relative) == Entry::Directory`, as `Path::is_dir`.
    pub fn is_input_dir(&self, relative: &Path) -> bool {
        matches!(self.input_entry(relative), Ok(Entry::Directory))
    }

    /// The names in a project directory (`.` for the root itself), sorted,
    /// or `None` when it is absent. Resolved like `read_input`.
    pub fn read_input_dir(&self, relative: &Path) -> io::Result<Option<Vec<std::ffi::OsString>>> {
        let Some(dir) = self.input_subdir(relative)? else {
            return Ok(None);
        };
        let mut names = read_dir_names_at(dir.dir.as_raw_fd())?;
        names.sort();
        Ok(Some(names))
    }

    /// The names in a directory of tog's own state (`.tog/closures`),
    /// sorted, or `None` when it or a parent is absent. Walked like
    /// `read_file`: a symlink at any component, the listed directory
    /// included, is refused rather than listed through.
    pub fn read_dir(&self, relative: &Path) -> io::Result<Option<Vec<std::ffi::OsString>>> {
        let Some(dir) = self.subdir(relative)? else {
            return Ok(None);
        };
        let mut names = read_dir_names_at(dir.dir.as_raw_fd())?;
        names.sort();
        Ok(Some(names))
    }

    /// A project subdirectory held as its own root, reached with the strict
    /// no-follow walk of `read_file`: a symlink or a non-directory at any
    /// component is refused, never followed, so a tree walk that saw a
    /// directory cannot be redirected by a swap before it opens it. `None`
    /// when a component is absent. Its `path` is this root's path joined
    /// with `relative`.
    pub fn subdir(&self, relative: &Path) -> io::Result<Option<ProjectRoot>> {
        let mut display = self.path.clone();
        let Some((held, name)) = self.open_parent(relative, "read", &mut display)? else {
            return Ok(None);
        };
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match open_directory_at(parent_fd, name.as_bytes(), &display, "read") {
            Ok(dir) => {
                let held = HeldEntry::register(&display, &dir);
                Ok(Some(ProjectRoot {
                    dir,
                    path: display,
                    _held: Some(held),
                    external: self.external.clone(),
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// A project subdirectory held as its own root (a workspace member),
    /// resolved like `read_input`; `None` when it is absent or not a
    /// directory. Its `path` is this root's path joined with `relative`.
    pub fn input_subdir(&self, relative: &Path) -> io::Result<Option<ProjectRoot>> {
        let name = input_name(relative)?;
        match open_file_at(
            self.dir.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        ) {
            Ok(dir) => {
                let path = if relative == Path::new(".") {
                    self.path.clone()
                } else {
                    self.path.join(relative)
                };
                let held = HeldEntry::register(&path, &dir);
                Ok(Some(ProjectRoot {
                    dir,
                    path,
                    _held: Some(held),
                    external: self.external.clone(),
                }))
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                Ok(None)
            }
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("open {}: {error}", self.path.join(relative).display()),
            )),
        }
    }

    /// The regular file at `path`, a path outside the project (an absolute
    /// `tog.toml` requirements path, an include beside the project), as
    /// this root first read it; `None` when it is absent or not a regular
    /// file. Read once, so every stage of a command sees the same bytes.
    pub fn read_external(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        Ok(self.external.read(path)?.map(|bytes| bytes.to_vec()))
    }

    /// `path.canonicalize()` for a path outside the project, as this root
    /// first resolved it.
    pub fn external_canonical(&self, path: &Path) -> io::Result<PathBuf> {
        self.external.canonical(path)
    }

    /// `path` relative to this root, when it lies under the root's
    /// canonical path: how a caller holding an absolute path it built from
    /// `path()` turns it back into a descriptor-relative one.
    pub fn relative<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        path.strip_prefix(&self.path).ok()
    }

    /// The directory that contains the held one, reached through `..` from
    /// the descriptor, never the path: while `check_still_named` holds it is
    /// the path's parent, and if the project is moved it is wherever the
    /// held directory now is. `None` at `/`. Its `path` is `path().parent()`,
    /// for messages.
    pub fn parent(&self) -> io::Result<Option<ProjectRoot>> {
        // The displayed name can become shallower than the actual directory
        // after a move. Only descriptor identity determines the end of a walk.
        let path = self.path.parent().unwrap_or(Path::new("/"));
        // A parent tog may search but not list (0111) is held the way the
        // walk to a project holds it: files below it open by name, and
        // nothing here lists it (#480).
        let dir = open_file_at(self.dir.as_raw_fd(), b"..", DIRECTORY_FLAGS, 0)
            .or_else(|error| {
                if error.kind() == io::ErrorKind::PermissionDenied
                    && ANCESTOR_FLAGS != DIRECTORY_FLAGS
                {
                    open_file_at(self.dir.as_raw_fd(), b"..", ANCESTOR_FLAGS, 0)
                } else {
                    Err(error)
                }
            })
            .map_err(|error| {
                io::Error::new(error.kind(), format!("open {}: {error}", path.display()))
            })?;
        if same_inode(&fd_stat(dir.as_raw_fd())?, &fd_stat(self.dir.as_raw_fd())?) {
            return Ok(None);
        }
        Ok(Some(ProjectRoot {
            _held: None,
            dir,
            path: path.to_path_buf(),
            external: self.external.clone(),
        }))
    }

    /// This root, then each directory above it (`parent`), up to `/`. Opened
    /// one at a time as the walk reaches it, so a walk that stops early
    /// holds nothing more.
    pub fn ancestors(&self) -> impl Iterator<Item = io::Result<ProjectRoot>> {
        let mut next = Some(self.try_clone());
        std::iter::from_fn(move || {
            let current = next.take()?;
            if let Ok(root) = &current {
                next = root.parent().transpose();
            }
            Some(current)
        })
    }

    /// A project input opened for reading the way `read_input` resolves it,
    /// for a caller that needs the file itself (its device and inode).
    /// A malformed parent component is an error, not a missing input.
    pub fn open_input_file(&self, relative: &Path) -> io::Result<Option<fs::File>> {
        self.open_input_with_missing(relative, false)
    }

    fn open_input(&self, relative: &Path) -> io::Result<Option<fs::File>> {
        self.open_input_with_missing(relative, true)
    }

    fn open_input_with_missing(
        &self,
        relative: &Path,
        not_dir_is_absent: bool,
    ) -> io::Result<Option<fs::File>> {
        let name = input_name(relative)?;
        let display = self.path.join(relative);
        let file = match open_file_at(
            self.dir.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || (not_dir_is_absent && error.raw_os_error() == Some(libc::ENOTDIR)) =>
            {
                return Ok(None)
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("read {}: {error}", display.display()),
                ))
            }
        };
        if !file.metadata()?.file_type().is_file() {
            return Err(refusal(format!(
                "{} is not a regular file; refusing to read it",
                display.display()
            )));
        }
        Ok(Some(file))
    }

    /// Walk to the parent directory of a project-relative path, creating
    /// nothing. Returns the held parent descriptor (`None` when the project
    /// root itself is the parent) together with the final name, and pushes
    /// the whole path onto `display`. `Ok(None)` when a parent is absent.
    fn open_parent<'a>(
        &self,
        relative: &'a Path,
        verb: &str,
        display: &mut PathBuf,
    ) -> io::Result<Option<(Option<fs::File>, &'a OsStr)>> {
        let (parents, name) = split_relative(relative)?;
        let mut held: Option<fs::File> = None;
        for parent in parents {
            display.push(parent);
            let fd = held
                .as_ref()
                .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
            // Every parent is only a base for the lookup below it, so it is
            // held like an ancestor: search permission is enough.
            match open_directory_with(fd, parent.as_bytes(), display, verb, ANCESTOR_FLAGS) {
                Ok(dir) => held = Some(dir),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        display.push(name);
        Ok(Some((held, name)))
    }

    /// Open each component in turn from the held descriptor, creating the
    /// ones that are absent. Returns the last descriptor, opened for
    /// reading so a caller can fsync it, or `None` when `components` is
    /// empty and the project root itself is the parent. The components
    /// before it are held like ancestors, so a search-only one is passed.
    fn open_creating(
        &self,
        components: &[&OsStr],
        display: &mut PathBuf,
    ) -> io::Result<Option<fs::File>> {
        let mut held: Option<fs::File> = None;
        for (index, component) in components.iter().enumerate() {
            display.push(component);
            let fd = held
                .as_ref()
                .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
            let created = mkdir_at(fd, component.as_bytes(), 0o755).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("create {}: {error}", display.display()),
                )
            })?;
            let flags = if index + 1 == components.len() {
                DIRECTORY_FLAGS
            } else {
                ANCESTOR_FLAGS
            };
            let dir = open_directory_with(fd, component.as_bytes(), display, "write", flags)?;
            if created {
                fsync_held(fd)?;
            }
            held = Some(dir);
        }
        Ok(held)
    }

    fn publish(
        &self,
        relative: &Path,
        bytes: &[u8],
        temp_name: &mut dyn FnMut(&[u8], usize) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        self.publish_mode(relative, &mut &bytes[..], None, false, temp_name)
    }

    /// `replace_link` lets the rename replace a symlink at the destination
    /// (the link itself, never what it names), as `rename_in` does. The
    /// contents are streamed from `source` into the temporary, so a large
    /// file is never held in memory whole.
    fn publish_mode(
        &self,
        relative: &Path,
        source: &mut dyn io::Read,
        mode: Option<libc::mode_t>,
        replace_link: bool,
        temp_name: &mut dyn FnMut(&[u8], usize) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let held = self.open_creating(&parents, &mut display)?;
        display.push(name);
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => match stat.st_mode & libc::S_IFMT {
                libc::S_IFLNK if replace_link => {}
                libc::S_IFLNK => {
                    return Err(refusal(format!(
                        "{} is a symlink; refusing to replace it",
                        display.display()
                    )))
                }
                libc::S_IFDIR => {
                    return Err(refusal(format!(
                        "{} is a directory; refusing to replace it",
                        display.display()
                    )))
                }
                libc::S_IFREG => {}
                _ => {
                    return Err(refusal(format!(
                        "{} is not a regular file; refusing to replace it",
                        display.display()
                    )))
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let (temp, mut file) = {
            let mut last = Vec::new();
            let mut opened = None;
            for attempt in 0..TEMP_ATTEMPTS {
                let candidate = temp_name(name.as_bytes(), attempt)?;
                match open_file_at(
                    parent_fd,
                    &candidate,
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o644,
                ) {
                    Ok(file) => {
                        opened = Some((candidate, file));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        last = candidate;
                    }
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("create temporary for {}: {error}", display.display()),
                        ))
                    }
                }
            }
            match opened {
                Some(opened) => opened,
                None => {
                    return Err(refusal(format!(
                        "every temporary name for {} is occupied (last tried {:?}); \
                         remove stale .tog-tmp entries and retry",
                        display.display(),
                        OsStr::from_bytes(&last)
                    )))
                }
            }
        };
        let created = fd_stat(file.as_raw_fd())?;
        let mut renamed = false;
        // `file` stays open through the identity checks below so the inode
        // it names cannot be recycled under them.
        let result = (|| {
            if let Some(mode) = mode {
                // SAFETY: the descriptor is owned by `file` for this call.
                if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            io::copy(source, &mut file)?;
            file.sync_all()?;
            let current = stat_at(parent_fd, &temp)?;
            if !same_inode(&current, &created) {
                return Err(refusal(format!(
                    "temporary for {} was replaced while it was being written",
                    display.display()
                )));
            }
            rename_at(parent_fd, &temp, name.as_bytes()).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("publish {}: {error}", display.display()),
                )
            })?;
            renamed = true;
            fsync_directory(parent_fd)
        })();
        if result.is_err() && !renamed {
            let _ = unlink_if_same(parent_fd, &temp, &created, 0);
        }
        drop(file);
        result
    }
}

fn refusal(message: String) -> io::Error {
    crate::kernel::error::refused(io::ErrorKind::InvalidData, message)
}

/// Split a project-relative path into its parent components and its file
/// name, validated on the raw bytes: not empty, not absolute, no NUL, and
/// no empty, `.`, or `..` component (`a//b`, `a/./b` and `a/b/` are all
/// refused; `Path::components` would have normalized them away).
fn split_relative(relative: &Path) -> io::Result<(Vec<&OsStr>, &OsStr)> {
    let bytes = relative.as_os_str().as_bytes();
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("project-relative path {relative:?} {reason}"),
        )
    };
    if bytes.is_empty() {
        return Err(invalid("is empty"));
    }
    if bytes.contains(&0) {
        return Err(invalid("contains a NUL byte"));
    }
    if bytes[0] == b'/' {
        return Err(invalid("is absolute"));
    }
    let mut components = Vec::new();
    for segment in bytes.split(|byte| *byte == b'/') {
        match segment {
            b"" => return Err(invalid("has an empty component")),
            b"." => return Err(invalid("contains a `.` component")),
            b".." => return Err(invalid("contains a `..` component")),
            _ => components.push(OsStr::from_bytes(segment)),
        }
    }
    let name = components
        .pop()
        .expect("a non-empty path has a last component");
    Ok((components, name))
}

/// A project-input name for `openat` from the held descriptor: not empty,
/// not absolute, no NUL. Unlike `split_relative` it may climb or repeat a
/// separator, since it is resolved by the kernel the way a pathname
/// relative to the project would be.
fn input_name(relative: &Path) -> io::Result<Vec<u8>> {
    let bytes = relative.as_os_str().as_bytes();
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("project-relative path {relative:?} {reason}"),
        )
    };
    if bytes.is_empty() {
        return Err(invalid("is empty"));
    }
    if bytes.contains(&0) {
        return Err(invalid("contains a NUL byte"));
    }
    if bytes[0] == b'/' {
        return Err(invalid("is absolute"));
    }
    Ok(bytes.to_vec())
}

/// Open an absolute path from `/` one component at a time with O_NOFOLLOW,
/// taking the components as given: nothing is canonicalized, so a symlink
/// at any component is refused rather than resolved.
///
/// Only the last component is opened for reading. On Linux every ancestor
/// is held as an `O_PATH` descriptor, which needs search permission alone,
/// as the kernel's own lookup of the path would: a project under a
/// search-only (0111) directory opens. Each ancestor is still opened with
/// O_NOFOLLOW and O_DIRECTORY and checked to be a directory on its
/// descriptor. Elsewhere every component is opened for reading.
fn walk_from_root(path: &Path) -> io::Result<fs::File> {
    walk_from_root_with(path, DIRECTORY_FLAGS)
}

/// `walk_from_root`, opening the last component with `last_flags`:
/// `ANCESTOR_FLAGS` for a caller that only identifies the directory.
fn walk_from_root_with(path: &Path, last_flags: libc::c_int) -> io::Result<fs::File> {
    let components = path
        .components()
        .map(|component| match component {
            std::path::Component::RootDir => Ok(None),
            std::path::Component::Normal(name) => Ok(Some(name)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a canonical absolute path", path.display()),
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let names: Vec<&std::ffi::OsStr> = components.into_iter().flatten().collect();
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a canonical absolute path", path.display()),
        ));
    }
    let root = CString::new("/").expect("no NUL");
    let root_flags = if names.is_empty() {
        last_flags
    } else {
        ANCESTOR_FLAGS
    };
    // SAFETY: the path is a valid NUL-terminated string and the returned
    // descriptor is owned by the File below.
    let fd = unsafe { libc::open(root.as_ptr(), root_flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by open and ownership moves into File.
    let mut dir = unsafe { fs::File::from_raw_fd(fd) };
    let mut current = PathBuf::from("/");
    for (index, name) in names.iter().enumerate() {
        current.push(name);
        let flags = if index + 1 == names.len() {
            last_flags
        } else {
            ANCESTOR_FLAGS
        };
        dir = open_directory_with(
            dir.as_raw_fd(),
            name.as_bytes(),
            &current,
            "open project",
            flags,
        )?;
        if !is_directory_stat(&fd_stat(dir.as_raw_fd())?) {
            return Err(refusal(format!(
                "{} is not a real directory; refusing to open project through it",
                current.display()
            )));
        }
    }
    Ok(dir)
}

/// The current path of what the descriptor `fd` holds, from the kernel
/// (`/proc/self/fd` on Linux, `F_GETPATH` on macOS): the file or directory
/// actually opened, wherever it is now, never a name looked up again.
pub(crate) fn descriptor_path(fd: RawFd) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        fs::read_link(format!("/proc/self/fd/{fd}"))
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = [0 as libc::c_char; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes at most PATH_MAX bytes to this buffer.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, bytes.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful F_GETPATH writes a NUL-terminated pathname.
        let path = unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()) };
        Ok(std::ffi::OsString::from_vec(path.to_bytes().to_vec()).into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the path of a held descriptor is unsupported on this platform",
        ))
    }
}

fn is_directory_stat(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

/// Rename `old` over `new` in one held directory only if `new` does not
/// exist: `renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)`
/// on macOS. A name that appeared since the caller saw it absent fails with
/// `AlreadyExists` instead of being replaced. On a Linux filesystem that
/// lacks the flag, a hard link of the entry (which also refuses an existing
/// name) followed by unlinking `old` gives the same result.
pub(crate) fn rename_at_noreplace(dirfd: RawFd, old: &[u8], new: &[u8]) -> io::Result<()> {
    rename_between_noreplace(dirfd, old, dirfd, new)
}

/// [`rename_at_noreplace`] from one held directory into another on the
/// same filesystem.
pub(crate) fn rename_between_noreplace(
    from: RawFd,
    old: &[u8],
    to: RawFd,
    new: &[u8],
) -> io::Result<()> {
    let old_c = CString::new(old)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    let new_c = CString::new(new)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: both descriptors are open directories and both names are
        // NUL-terminated relative names that outlive the call.
        let status = unsafe {
            libc::renameat2(
                from,
                old_c.as_ptr(),
                to,
                new_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINVAL) | Some(libc::ENOSYS)
        ) {
            return Err(error);
        }
        // SAFETY: as above; flags 0 links the entry itself, never a
        // symlink's target.
        if unsafe { libc::linkat(from, old_c.as_ptr(), to, new_c.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        if unsafe { libc::unlinkat(from, old_c.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: both descriptors are open directories and both names are
        // NUL-terminated relative names that outlive the call.
        let status = unsafe {
            libc::renameatx_np(from, old_c.as_ptr(), to, new_c.as_ptr(), libc::RENAME_EXCL)
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (from, to, old_c, new_c);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "an exclusive rename is not available on this platform",
        ))
    }
}

/// `renameat` between two held directories.
fn rename_between(from: RawFd, old: &[u8], to: RawFd, new: &[u8]) -> io::Result<()> {
    let old = CString::new(old)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    let new = CString::new(new)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: both descriptors are open directories and both names are
    // NUL-terminated relative names that outlive the call.
    if unsafe { libc::renameat(from, old.as_ptr(), to, new.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// fsync a held directory, which may be an `O_PATH` ancestor: that kind
/// cannot be fsynced, so the directory is reopened for reading through it.
fn fsync_held(fd: RawFd) -> io::Result<()> {
    match fsync_directory(fd) {
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
            let dir = open_file_at(fd, b".", DIRECTORY_FLAGS, 0)?;
            fsync_directory(dir.as_raw_fd())
        }
        result => result,
    }
}

fn open_directory_at(
    parent_fd: RawFd,
    name: &[u8],
    display: &Path,
    verb: &str,
) -> io::Result<fs::File> {
    open_directory_with(parent_fd, name, display, verb, DIRECTORY_FLAGS)
}

fn open_directory_with(
    parent_fd: RawFd,
    name: &[u8],
    display: &Path,
    verb: &str,
    flags: libc::c_int,
) -> io::Result<fs::File> {
    open_file_at(parent_fd, name, flags, 0).map_err(|error| match error.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => refusal(format!(
            "{} is not a real directory; refusing to {verb} through it",
            display.display()
        )),
        _ => io::Error::new(
            error.kind(),
            format!("{verb} {}: {error}", display.display()),
        ),
    })
}

/// Operating-system randomness: `count` bytes from `/dev/urandom`. One
/// shared helper, so every temporary name and identifier in the tree reads
/// the same source on Linux and macOS.
pub fn urandom_bytes(count: usize) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut bytes = vec![0u8; count];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// 32 random hex digits for a temporary's name. Carries no process
/// identity, so two runs in containers that reuse small pids never pick the
/// same name, and nobody can guess it ahead of time.
pub fn random_suffix() -> io::Result<String> {
    Ok(hex::encode(urandom_bytes(16)?))
}

/// `.tog-tmp.<32 hex>`: a fresh random name per attempt, so an occupied
/// name (a crash leftover, or an entry planted at a guessable name) is
/// stepped around, never unlinked and never written through. The name
/// carries no process identity, so two runs in containers that reuse small
/// pids never pick the same fixed point. The destination name is not part
/// of it, so a destination of any valid length publishes.
fn random_temp_name(_name: &[u8], _attempt: usize) -> io::Result<Vec<u8>> {
    Ok(format!(".tog-tmp.{}", random_suffix()?).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::{symlink, FileTypeExt as _};

    fn project(temp: &TempDir) -> PathBuf {
        let dir = temp.0.join("proj");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `held_at` returns a canonical path whatever spelling it is asked
    /// with: a climbing path is resolved to the held root it names, and a
    /// path below a held root through a symlink is the symlink's target,
    /// never a second name for it. A real subdirectory is held by its
    /// parent's root (#498).
    #[test]
    fn held_at_returns_a_canonical_path_for_any_spelling() {
        let temp = TempDir::named("held-at-spelling");
        let dir = project(&temp).canonicalize().unwrap();
        fs::create_dir(dir.join("child")).unwrap();
        let outside = temp.0.canonicalize().unwrap().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, dir.join("link")).unwrap();
        let _holder = ProjectRoot::open(&dir).unwrap();
        let climbing = ProjectRoot::held_at(&dir.join("child/.."))
            .unwrap()
            .unwrap();
        assert_eq!(climbing.path(), dir.as_path());
        let child = ProjectRoot::held_at(&dir.join("child")).unwrap().unwrap();
        assert_eq!(child.path(), dir.join("child").as_path());
        // The symlink's target is outside every held root: not held, so
        // the caller opens it by its canonical path as it always did.
        assert!(ProjectRoot::held_at(&dir.join("link")).unwrap().is_none());
        let via_link = ProjectRoot::held_at(&dir.join("link/../proj/child"));
        assert_eq!(
            via_link.unwrap().unwrap().path(),
            dir.join("child").as_path()
        );
    }

    /// Two held roots at one path that disagree about a directory below it
    /// (a real directory in one, a symlink in the other) refuse, whichever
    /// was opened first: the symlink is never resolved in place of the
    /// directory the other root holds (#498).
    #[test]
    fn held_at_refuses_roots_that_disagree_through_a_symlink() {
        for symlink_first in [false, true] {
            let temp = TempDir::named("held-at-conflict");
            let dir = project(&temp).canonicalize().unwrap();
            let outside = temp.0.canonicalize().unwrap().join("outside");
            fs::create_dir(&outside).unwrap();
            let member = |real: bool| {
                if real {
                    fs::create_dir(dir.join("member")).unwrap();
                } else {
                    symlink(&outside, dir.join("member")).unwrap();
                }
            };
            member(!symlink_first);
            let _first = ProjectRoot::open(&dir).unwrap();
            fs::rename(&dir, temp.0.join("moved")).unwrap();
            fs::create_dir(&dir).unwrap();
            member(symlink_first);
            let _second = ProjectRoot::open(&dir).unwrap();
            let error = ProjectRoot::held_at(&dir.join("member")).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::ESTALE), "{symlink_first}");
        }
    }

    /// `held_at` finds the directory an open root holds at a path, by that
    /// path's held spelling, even after the project is renamed and another
    /// put in its place. The root it returns has its own descriptor, so it
    /// outlives the holder, and adds no binding of its own (#498).
    #[test]
    fn held_at_reads_the_held_directory_and_outlives_its_holder() {
        let temp = TempDir::named("held-at");
        let dir = project(&temp).canonicalize().unwrap();
        fs::write(dir.join("marker"), "held").unwrap();
        assert!(ProjectRoot::held_at(&dir).unwrap().is_none());
        let holder = ProjectRoot::open(&dir).unwrap();
        fs::rename(&dir, temp.0.join("moved")).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("marker"), "decoy").unwrap();
        let found = ProjectRoot::held_at(&dir).unwrap().unwrap();
        assert_eq!(found.path(), dir.as_path());
        drop(holder);
        assert!(ProjectRoot::held_at(&dir).unwrap().is_none());
        assert_eq!(
            found
                .read_input_string(Path::new("marker"))
                .unwrap()
                .as_deref(),
            Some("held")
        );
    }

    /// A child started in a held project's path enters the held directory:
    /// a project swapped for another between tog's open and the spawn does
    /// not redirect it, nor does one in a held root's subdirectory. Once
    /// the root is dropped, the path is used again. Deleted held roots,
    /// missing held members and conflicting roots refuse execution.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_child_started_in_a_held_root_enters_the_held_directory() {
        let temp = TempDir::named("held-cwd");
        let dir = project(&temp);
        fs::create_dir_all(dir.join("member")).unwrap();
        fs::write(dir.join("marker"), "held").unwrap();
        fs::write(dir.join("member/marker"), "held member").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let canonical = dir.canonicalize().unwrap();
        fs::rename(&canonical, temp.0.join("moved")).unwrap();
        // Reviewed site: a test child, run to see which directory it is in.
        #[allow(clippy::disallowed_methods)]
        let read = |dir: &Path| {
            let mut command = std::process::Command::new("/bin/cat");
            command.arg("marker");
            start_in(&mut command, dir);
            String::from_utf8(command.output().unwrap().stdout).unwrap()
        };
        assert_eq!(read(&canonical), "held");
        assert_eq!(read(&canonical.join("member")), "held member");
        fs::create_dir_all(canonical.join("member")).unwrap();
        fs::write(canonical.join("marker"), "swapped").unwrap();
        fs::write(canonical.join("member/marker"), "swapped member").unwrap();
        assert_eq!(read(&canonical), "held");
        let replacement = ProjectRoot::open(&canonical).unwrap();
        let mut conflict = std::process::Command::new("/bin/true");
        start_in(&mut conflict, &canonical);
        assert_eq!(
            conflict.status().unwrap_err().raw_os_error(),
            Some(libc::ESTALE)
        );
        drop(replacement);
        fs::remove_dir_all(temp.0.join("moved/member")).unwrap();
        let mut missing = std::process::Command::new("/bin/true");
        start_in(&mut missing, &canonical.join("member"));
        assert_eq!(
            missing.status().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        drop(root);
        assert_eq!(read(&canonical), "swapped");

        let again = ProjectRoot::open(&canonical).unwrap();
        fs::remove_dir_all(&canonical).unwrap();
        fs::create_dir_all(&canonical).unwrap();
        fs::write(canonical.join("marker"), "remade").unwrap();
        let mut deleted = std::process::Command::new("/bin/true");
        start_in(&mut deleted, &canonical);
        assert_eq!(
            deleted.status().unwrap_err().raw_os_error(),
            Some(libc::ESTALE)
        );
        drop(again);
        assert_eq!(read(&canonical), "remade");
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn cloned_and_member_roots_keep_their_cwd_binding() {
        let temp = TempDir::named("held-cwd-clones");
        let dir = project(&temp);
        fs::create_dir(dir.join("member")).unwrap();
        fs::write(dir.join("marker"), "held").unwrap();
        fs::write(dir.join("member/marker"), "member held").unwrap();
        let original = ProjectRoot::open(&dir).unwrap();
        let cloned = original.try_clone().unwrap();
        drop(original);
        fs::rename(&dir, temp.0.join("moved")).unwrap();
        fs::create_dir_all(dir.join("member")).unwrap();
        fs::write(dir.join("marker"), "replacement").unwrap();
        fs::write(dir.join("member/marker"), "replacement member").unwrap();
        let mut read = std::process::Command::new("/bin/cat");
        read.arg("marker");
        start_in(&mut read, cloned.path());
        assert_eq!(read.output().unwrap().stdout, b"held");
        let member = cloned.input_subdir(Path::new("member")).unwrap().unwrap();
        drop(cloned);
        let mut read = std::process::Command::new("/bin/cat");
        read.arg("marker");
        start_in(&mut read, member.path());
        assert_eq!(read.output().unwrap().stdout, b"member held");
    }

    /// A listening socket at `path`, however long, through the shared
    /// test helper (which says how a path past `sun_path` is bound).
    fn bind_socket(path: &Path) -> std::os::unix::net::UnixListener {
        crate::kernel::testutil::bind_socket(path)
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn writes_read_back_and_create_parents() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let path = Path::new(".tog/cache/plan.json");
        assert_eq!(root.read_file(path).unwrap(), None);
        root.write_file(path, b"{\"a\":1}").unwrap();
        assert_eq!(
            root.read_file(path).unwrap().as_deref(),
            Some(&b"{\"a\":1}"[..])
        );
        assert_eq!(
            fs::read(root.path().join(".tog/cache/plan.json")).unwrap(),
            b"{\"a\":1}"
        );
        assert_eq!(entries(&root.path().join(".tog/cache")), vec!["plan.json"]);
    }

    #[test]
    fn rewrite_replaces_the_file_and_leaves_no_temporary() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let path = Path::new(".tog/plan.json");
        root.write_file(path, b"one").unwrap();
        root.write_file(path, b"two").unwrap();
        assert_eq!(root.read_file(path).unwrap().unwrap(), b"two");
        assert_eq!(entries(&root.path().join(".tog")), vec!["plan.json"]);
    }

    #[test]
    fn remove_file_deletes_a_regular_file_and_tolerates_an_absent_one() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let path = Path::new(".tog/lock-source.hash");
        // Absent name, and absent parent, are both a no-op.
        root.remove_file(path).unwrap();
        root.write_file(path, b"abc").unwrap();
        root.remove_file(path).unwrap();
        assert_eq!(root.read_file(path).unwrap(), None);
        assert!(entries(&root.path().join(".tog")).is_empty());
        root.remove_file(path).unwrap();
    }

    #[test]
    fn remove_file_refuses_a_symlinked_parent_and_a_symlinked_target() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("lock-source.hash"), b"keep").unwrap();
        symlink(&outside, dir.join(".tog")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root
            .remove_file(Path::new(".tog/lock-source.hash"))
            .unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert_eq!(fs::read(outside.join("lock-source.hash")).unwrap(), b"keep");

        // And a symlink at the destination name itself, under a real parent.
        let other = temp.0.join("other-proj");
        fs::create_dir_all(other.join(".tog")).unwrap();
        symlink(
            outside.join("lock-source.hash"),
            other.join(".tog/lock-source.hash"),
        )
        .unwrap();
        let root = ProjectRoot::open(&other).unwrap();
        let error = root
            .remove_file(Path::new(".tog/lock-source.hash"))
            .unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
        assert_eq!(fs::read(outside.join("lock-source.hash")).unwrap(), b"keep");
    }

    #[test]
    fn remove_file_refuses_a_directory() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        root.create_dir_all(Path::new(".tog/closures")).unwrap();
        let error = root.remove_file(Path::new(".tog/closures")).unwrap_err();
        assert!(error.to_string().contains("is a directory"), "{error}");
        assert!(root.path().join(".tog/closures").is_dir());
    }

    #[test]
    fn entry_classifies_without_following_a_symlink() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside.json");
        fs::write(&outside, b"outside").unwrap();
        fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        symlink(&outside, dir.join(".tog/closures/python.json")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();

        assert_eq!(root.entry(Path::new(".tog/absent")).unwrap(), Entry::Absent);
        assert_eq!(
            root.entry(Path::new("no-such-dir/name")).unwrap(),
            Entry::Absent
        );
        assert_eq!(
            root.entry(Path::new(".tog/closures")).unwrap(),
            Entry::Directory
        );
        // The symlink is reported as a symlink, not as the regular file it
        // points at, so a caller refuses instead of writing through it.
        assert_eq!(
            root.entry(Path::new(".tog/closures/python.json")).unwrap(),
            Entry::Symlink
        );
        root.write_file(Path::new(".tog/plan.json"), b"{}").unwrap();
        assert_eq!(
            root.entry(Path::new(".tog/plan.json")).unwrap(),
            Entry::Regular
        );
    }

    #[test]
    fn entry_refuses_a_symlinked_ancestor() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dir.join(".tog")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root.entry(Path::new(".tog/plan.json")).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
    }

    #[test]
    fn create_dir_all_makes_the_chain_and_is_idempotent() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        root.create_dir_all(Path::new(".tog/closures")).unwrap();
        assert!(root.path().join(".tog/closures").is_dir());
        root.create_dir_all(Path::new(".tog/closures")).unwrap();
        assert_eq!(entries(&root.path().join(".tog")), vec!["closures"]);
    }

    #[test]
    fn create_dir_all_refuses_a_symlinked_component() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dir.join(".tog")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root.create_dir_all(Path::new(".tog/closures")).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert!(entries(&outside).is_empty(), "created through the symlink");
    }

    #[test]
    fn refuses_a_symlinked_ancestor() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dir.join(".tog")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root
            .write_file(Path::new(".tog/plan.json"), b"x")
            .unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert!(entries(&outside).is_empty(), "wrote through the symlink");
        let error = root.read_file(Path::new(".tog/plan.json")).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
    }

    /// A project under a search-only (0111) directory is reachable by its
    /// name, as the kernel's own lookup reaches it: it opens, and its
    /// recorded path still names it at publication.
    #[test]
    fn a_project_under_a_search_only_ancestor_opens() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = TempDir::new();
        let parent = temp.0.join("search-only");
        let dir = parent.join("proj");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o111)).unwrap();
        let opened = ProjectRoot::open(&dir).and_then(|root| {
            root.write_file(Path::new(".tog/plan.json"), b"x")?;
            root.check_still_named()?;
            root.read_file(Path::new(".tog/plan.json"))
        });
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(opened.unwrap().as_deref(), Some(&b"x"[..]));
    }

    /// Inside a project, a strict walk passes a search-only (0111)
    /// directory as the kernel's own lookup does: only the directory it
    /// opens for reading, or lists, needs read permission. A file below it
    /// is read and written, a subdirectory is held and listed, and a new
    /// directory is created under it.
    #[test]
    fn a_strict_walk_passes_a_search_only_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = TempDir::new();
        let dir = project(&temp);
        let gate = dir.join("gate");
        fs::create_dir_all(gate.join("pkg/inner")).unwrap();
        fs::write(gate.join("pkg/package.json"), b"{}").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o111)).unwrap();
        let walked = (|| -> io::Result<_> {
            let read = root.read_file(Path::new("gate/pkg/package.json"))?;
            let held = root.subdir(Path::new("gate/pkg"))?.is_some();
            let listed = root.read_dir(Path::new("gate/pkg"))?;
            root.write_file(Path::new("gate/pkg/inner/new/out.txt"), b"y")?;
            let entry = root.entry(Path::new("gate/pkg/inner/new/out.txt"))?;
            Ok((read, held, listed, entry))
        })();
        fs::set_permissions(&gate, fs::Permissions::from_mode(0o755)).unwrap();
        let (read, held, listed, entry) = walked.unwrap();
        assert!(held);
        assert_eq!(read.as_deref(), Some(&b"{}"[..]));
        assert_eq!(listed, Some(vec!["inner".into(), "package.json".into()]));
        assert_eq!(entry, Entry::Regular);
        assert_eq!(fs::read(gate.join("pkg/inner/new/out.txt")).unwrap(), b"y");
    }

    /// The walk from `/` holds ancestors without reading them, but never
    /// through a symlink: a recorded path whose ancestor became one fails.
    #[test]
    fn the_walk_refuses_an_ancestor_that_is_a_symlink() {
        let temp = TempDir::new();
        let real = temp.0.join("real");
        fs::create_dir_all(real.join("proj")).unwrap();
        symlink(&real, temp.0.join("link")).unwrap();
        let error = walk_from_root(&temp.0.join("link/proj")).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        walk_from_root(&real.join("proj")).unwrap();
    }

    #[test]
    fn refuses_a_symlinked_target() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let victim = temp.0.join("victim");
        fs::write(&victim, b"original").unwrap();
        fs::create_dir_all(dir.join(".tog")).unwrap();
        symlink(&victim, dir.join(".tog/plan.json")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root
            .write_file(Path::new(".tog/plan.json"), b"x")
            .unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert!(fs::symlink_metadata(dir.join(".tog/plan.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(entries(&dir.join(".tog")), vec!["plan.json"]);
        let error = root.read_file(Path::new(".tog/plan.json")).unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
    }

    fn fixed_temp_name(name: &[u8], attempt: usize) -> io::Result<Vec<u8>> {
        let mut temp = b".".to_vec();
        temp.extend_from_slice(name);
        temp.extend_from_slice(format!(".tog-tmp.fixed.{attempt}").as_bytes());
        Ok(temp)
    }

    #[test]
    fn refuses_when_every_temporary_name_is_occupied() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let victim = temp.0.join("victim");
        fs::write(&victim, b"original").unwrap();
        fs::create_dir_all(dir.join(".tog")).unwrap();
        for attempt in 0..TEMP_ATTEMPTS {
            let name = fixed_temp_name(b"plan.json", attempt).unwrap();
            symlink(&victim, dir.join(".tog").join(OsStr::from_bytes(&name))).unwrap();
        }
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root
            .publish(Path::new(".tog/plan.json"), b"x", &mut fixed_temp_name)
            .unwrap_err();
        assert!(error.to_string().contains("occupied"), "{error}");
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert_eq!(entries(&dir.join(".tog")).len(), TEMP_ATTEMPTS);
        assert!(!dir.join(".tog/plan.json").exists());
    }

    #[test]
    fn steps_past_an_occupied_temporary_name() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let victim = temp.0.join("victim");
        fs::write(&victim, b"original").unwrap();
        fs::create_dir_all(dir.join(".tog")).unwrap();
        let occupied = fixed_temp_name(b"plan.json", 0).unwrap();
        symlink(&victim, dir.join(".tog").join(OsStr::from_bytes(&occupied))).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        root.publish(Path::new(".tog/plan.json"), b"x", &mut fixed_temp_name)
            .unwrap();
        assert_eq!(fs::read(dir.join(".tog/plan.json")).unwrap(), b"x");
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert_eq!(entries(&dir.join(".tog")).len(), 2);
    }

    #[test]
    fn rejects_malformed_relative_paths() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let cases: [(&[u8], &str); 10] = [
            (b"", "is empty"),
            (b"/etc/passwd", "is absolute"),
            (b"..", "`..`"),
            (b"a/../b", "`..`"),
            (b".", "`.`"),
            (b"a/./b", "`.`"),
            (b"a/b/.", "`.`"),
            (b"a//b", "empty component"),
            (b"a/b/", "empty component"),
            (b"a\0b", "NUL"),
        ];
        for (bytes, reason) in cases {
            let path = Path::new(OsStr::from_bytes(bytes));
            let write = root.write_file(path, b"x").unwrap_err();
            assert_eq!(write.kind(), io::ErrorKind::InvalidInput, "{path:?}");
            assert!(write.to_string().contains(reason), "{path:?}: {write}");
            let read = root.read_file(path).unwrap_err();
            assert_eq!(read.kind(), io::ErrorKind::InvalidInput, "{path:?}");
        }
        assert!(entries(root.path()).is_empty());
    }

    #[test]
    fn refuses_a_directory_destination() {
        let temp = TempDir::new();
        let dir = project(&temp);
        fs::create_dir_all(dir.join(".tog/plan.json")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root
            .write_file(Path::new(".tog/plan.json"), b"x")
            .unwrap_err();
        assert!(error.to_string().contains("is a directory"), "{error}");
        assert!(dir.join(".tog/plan.json").is_dir());
        let error = root.read_file(Path::new(".tog/plan.json")).unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn refuses_to_read_a_fifo() {
        let temp = TempDir::new();
        let dir = project(&temp);
        fs::create_dir_all(dir.join(".tog")).unwrap();
        let fifo = CString::new(dir.join(".tog/plan.json").as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root.read_file(Path::new(".tog/plan.json")).unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn refuses_a_socket_for_reading_and_as_a_destination() {
        let temp = TempDir::new();
        let dir = project(&temp);
        fs::create_dir_all(dir.join(".tog")).unwrap();
        let _listener = bind_socket(&dir.join(".tog/plan.json"));
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root.read_file(Path::new(".tog/plan.json")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not a regular file"), "{error}");
        let error = root
            .write_file(Path::new(".tog/plan.json"), b"x")
            .unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert!(fs::symlink_metadata(dir.join(".tog/plan.json"))
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(entries(&dir.join(".tog")), vec!["plan.json"]);
    }

    #[test]
    fn refuses_a_file_where_a_directory_is_expected() {
        let temp = TempDir::new();
        let dir = project(&temp);
        fs::write(dir.join(".tog"), b"not a directory").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = root
            .write_file(Path::new(".tog/plan.json"), b"x")
            .unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert_eq!(fs::read(dir.join(".tog")).unwrap(), b"not a directory");
        let error = root.read_file(Path::new(".tog/plan.json")).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_utf8_names_round_trip() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let path = PathBuf::from(OsStr::from_bytes(b".tog/caf\xe9.json"));
        root.write_file(&path, b"x").unwrap();
        assert_eq!(root.read_file(&path).unwrap().unwrap(), b"x");
        assert_eq!(
            fs::read(root.path().join(OsStr::from_bytes(b".tog/caf\xe9.json"))).unwrap(),
            b"x"
        );
    }

    /// APFS stores names as UTF-8 and refuses any other bytes (EILSEQ), so
    /// on macOS the same write is an error that leaves nothing behind.
    #[cfg(target_os = "macos")]
    #[test]
    fn non_utf8_names_are_refused_by_apfs_and_leave_nothing() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let path = PathBuf::from(OsStr::from_bytes(b".tog/caf\xe9.json"));
        let error = root.write_file(&path, b"x").unwrap_err();
        assert!(
            error.to_string().contains("Illegal byte sequence"),
            "{error}"
        );
        assert_eq!(entries(&dir.join(".tog")), Vec::<String>::new());
    }

    #[test]
    fn a_name_at_name_max_publishes_and_a_longer_one_is_an_error() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let longest = "n".repeat(255);
        root.write_file(Path::new(&longest), b"x").unwrap();
        assert_eq!(root.read_file(Path::new(&longest)).unwrap().unwrap(), b"x");
        let error = root
            .write_file(Path::new(&"n".repeat(256)), b"x")
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENAMETOOLONG), "{error}");
        assert_eq!(entries(root.path()), vec![longest]);
    }

    /// The temp-name hook runs after the destination check and before the
    /// temporary is created, which is where a concurrent writer would act.
    #[test]
    fn a_symlink_swapped_in_after_the_check_is_replaced_not_followed() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let victim = temp.0.join("victim");
        fs::write(&victim, b"original").unwrap();
        fs::create_dir_all(dir.join(".tog")).unwrap();
        fs::write(dir.join(".tog/plan.json"), b"old").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let link = dir.join(".tog/plan.json");
        let mut swap = |name: &[u8], attempt: usize| {
            fs::remove_file(&link).unwrap();
            symlink(&victim, &link).unwrap();
            fixed_temp_name(name, attempt)
        };
        root.publish(Path::new(".tog/plan.json"), b"new", &mut swap)
            .unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        let published = fs::symlink_metadata(&link).unwrap();
        assert!(published.file_type().is_file());
        assert_eq!(fs::read(&link).unwrap(), b"new");
        assert_eq!(entries(&dir.join(".tog")), vec!["plan.json"]);
    }

    #[test]
    fn open_lock_file_creates_its_parents_and_refuses_a_symlink() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let relative = Path::new(".tog/toolchain-input.lock");
        let file = root.open_lock_file(relative).unwrap();
        assert!(dir.join(relative).is_file());
        // The descriptor carries an advisory lock, and reopening the same
        // name finds the file that is there rather than making a new one.
        file.lock_shared().unwrap();
        drop(file);
        drop(root.open_lock_file(relative).unwrap());
        assert_eq!(entries(&dir.join(".tog")), vec!["toolchain-input.lock"]);

        // A symlink planted at the name fails closed instead of locking the
        // file it points at.
        let victim = temp.0.join("victim-lock");
        fs::write(&victim, b"").unwrap();
        fs::remove_file(dir.join(relative)).unwrap();
        symlink(&victim, dir.join(relative)).unwrap();
        let error = root.open_lock_file(relative).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("is a symlink"), "{error}");

        // So does a symlinked ancestor directory.
        fs::remove_file(dir.join(relative)).unwrap();
        fs::remove_dir(dir.join(".tog")).unwrap();
        let elsewhere = temp.0.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        symlink(&elsewhere, dir.join(".tog")).unwrap();
        let error = root.open_lock_file(relative).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
    }

    #[test]
    fn a_rename_failure_after_the_temporary_exists_cleans_it_up() {
        let temp = TempDir::new();
        let dir = project(&temp);
        fs::create_dir_all(dir.join(".tog")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let destination = dir.join(".tog/plan.json");
        let mut swap_in_directory = |name: &[u8], attempt: usize| {
            fs::create_dir(&destination).unwrap();
            fixed_temp_name(name, attempt)
        };
        let error = root
            .publish(Path::new(".tog/plan.json"), b"new", &mut swap_in_directory)
            .unwrap_err();
        assert!(error.to_string().contains("publish"), "{error}");
        assert!(destination.is_dir());
        assert_eq!(entries(&dir.join(".tog")), vec!["plan.json"]);
    }

    #[test]
    fn concurrent_writers_leave_one_complete_file() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = std::sync::Arc::new(ProjectRoot::open(&dir).unwrap());
        let workers: Vec<_> = (0..4u8)
            .map(|worker| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let body = vec![b'a' + worker; 4096];
                    for _ in 0..25 {
                        root.write_file(Path::new(".tog/plan.json"), &body).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let bytes = fs::read(dir.join(".tog/plan.json")).unwrap();
        assert_eq!(bytes.len(), 4096);
        assert!(bytes.iter().all(|byte| *byte == bytes[0]), "torn write");
        assert_eq!(entries(&dir.join(".tog")), vec!["plan.json"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusals_do_not_leak_descriptors() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dir.join(".tog")).unwrap();
        fs::create_dir_all(dir.join("real/plan.json")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        // Other test threads open files concurrently, so count only the
        // descriptors that point into this fixture.
        let fixture = temp.0.canonicalize().unwrap();
        let open_descriptors = || {
            fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter(|entry| {
                    fs::read_link(entry.as_ref().unwrap().path())
                        .is_ok_and(|target| target.starts_with(&fixture))
                })
                .count()
        };
        let before = open_descriptors();
        assert_eq!(before, 1, "the held project root");
        for _ in 0..50 {
            root.write_file(Path::new(".tog/plan.json"), b"x")
                .unwrap_err();
            root.read_file(Path::new(".tog/plan.json")).unwrap_err();
            root.write_file(Path::new("real/plan.json"), b"x")
                .unwrap_err();
            root.read_file(Path::new("real/plan.json")).unwrap_err();
        }
        assert_eq!(open_descriptors(), before);
    }

    #[test]
    fn open_refuses_a_missing_project_or_a_file() {
        let temp = TempDir::new();
        assert!(ProjectRoot::open(&temp.0.join("absent")).is_err());
        let file = temp.0.join("file");
        fs::write(&file, b"x").unwrap();
        let error = ProjectRoot::open(&file).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
    }

    #[test]
    fn open_resolves_a_symlinked_project_path_to_its_real_directory() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let alias = temp.0.join("alias");
        symlink(&dir, &alias).unwrap();
        let root = ProjectRoot::open(&alias).unwrap();
        assert_eq!(root.path(), dir.canonicalize().unwrap());
        root.write_file(Path::new(".tog/plan.json"), b"x").unwrap();
        assert_eq!(fs::read(dir.join(".tog/plan.json")).unwrap(), b"x");
    }

    #[test]
    fn inputs_read_the_held_directory_after_it_is_renamed_and_replaced() {
        let temp = TempDir::new();
        let dir = project(&temp);
        fs::create_dir_all(dir.join("member")).unwrap();
        fs::write(dir.join("package.json"), b"original").unwrap();
        fs::write(dir.join("member/package.json"), b"member").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        root.check_still_named().unwrap();

        let moved = temp.0.join("moved");
        fs::rename(&dir, &moved).unwrap();
        fs::create_dir_all(dir.join("member")).unwrap();
        fs::write(dir.join("package.json"), b"impostor").unwrap();
        fs::write(dir.join("extra.json"), b"impostor").unwrap();

        let error = root.check_still_named().unwrap_err();
        assert!(
            error.to_string().contains("moved or replaced during sync"),
            "{error}"
        );
        assert_eq!(
            root.read_input(Path::new("package.json")).unwrap().unwrap(),
            b"original"
        );
        assert!(!root.is_input_file(Path::new("extra.json")));
        assert!(root.is_input_dir(Path::new("member")));
        let names = root.read_input_dir(Path::new(".")).unwrap().unwrap();
        assert_eq!(names, vec!["member", "package.json"]);
        let member = root.input_subdir(Path::new("member")).unwrap().unwrap();
        assert_eq!(
            member
                .read_input(Path::new("package.json"))
                .unwrap()
                .unwrap(),
            b"member"
        );
        let clone = root.try_clone().unwrap();
        assert_eq!(
            clone
                .read_input_string(Path::new("package.json"))
                .unwrap()
                .as_deref(),
            Some("original")
        );

        // A removed path is refused too, and so is a restored one only when
        // it is not the held directory.
        fs::remove_dir_all(&dir).unwrap();
        assert!(root.check_still_named().is_err());
        fs::rename(&moved, &dir).unwrap();
        root.check_still_named().unwrap();
    }

    #[test]
    fn inputs_follow_a_symlink_inside_the_project_and_refuse_odd_names() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let shared = temp.0.join("shared.lock");
        fs::write(&shared, b"shared").unwrap();
        symlink(&shared, dir.join("package-lock.json")).unwrap();
        symlink(temp.0.join("missing"), dir.join("dangling.json")).unwrap();
        fs::create_dir_all(dir.join("dir")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();

        // A symlink the project contains is the user's layout: followed, as
        // a pathname read would follow it.
        assert_eq!(
            root.read_input(Path::new("package-lock.json"))
                .unwrap()
                .unwrap(),
            b"shared"
        );
        assert!(root.is_input_file(Path::new("package-lock.json")));
        assert_eq!(
            root.input_entry(Path::new("dangling.json")).unwrap(),
            Entry::Absent
        );
        assert!(root
            .read_input(Path::new("dangling.json"))
            .unwrap()
            .is_none());
        assert!(root.read_input(Path::new("absent/x")).unwrap().is_none());
        let error = root.read_input(Path::new("dir")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let error = root.read_input(Path::new("/etc/hostname")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        fs::write(dir.join("bad.txt"), [0xff, 0xfe]).unwrap();
        let error = root.read_input_string(Path::new("bad.txt")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[test]
    fn projection_writes_go_through_the_held_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = TempDir::new();
        let dir = project(&temp);
        let env = temp.0.join("env");
        let other = temp.0.join("other-env");
        fs::create_dir_all(&env).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::create_dir_all(dir.join(".venv/lib")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();

        // A real directory is user state: refused, then moved out whole.
        let error = root
            .replace_symlink(Path::new(".venv"), &env, ".venv")
            .unwrap_err();
        assert!(
            error.to_string().contains("real file or directory"),
            "{error}"
        );
        let backups = temp.0.join("backups");
        fs::create_dir_all(&backups).unwrap();
        let backups_dir = fs::File::open(&backups).unwrap();
        root.move_dir_out(Path::new(".venv"), &backups_dir, b"saved")
            .unwrap();
        assert!(backups.join("saved/lib").is_dir());
        root.sync_dir(Path::new(".")).unwrap();

        // Links are made and replaced atomically, read back, and removed.
        root.replace_symlink(Path::new(".venv"), &env, ".venv")
            .unwrap();
        root.replace_symlink(Path::new(".venv"), &other, ".venv")
            .unwrap();
        assert_eq!(fs::read_link(dir.join(".venv")).unwrap(), other);
        assert_eq!(root.read_link(Path::new(".venv")).unwrap(), Some(other));
        assert_eq!(root.read_link(Path::new("absent")).unwrap(), None);
        fs::write(dir.join("file"), b"x").unwrap();
        assert_eq!(root.read_link(Path::new("file")).unwrap(), None);
        let error = root.remove_symlink(Path::new("file")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("is not a symlink; refusing to remove it"),
            "{error}"
        );
        root.remove_symlink(Path::new(".venv")).unwrap();
        root.remove_symlink(Path::new(".venv")).unwrap();
        assert!(dir.join(".venv").symlink_metadata().is_err());
        assert!(!entries(&dir)
            .iter()
            .any(|name| name.starts_with(".tog-tmp")));

        // A tree tog owns is removed without following a symlink inside it.
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        root.write_file_mode(
            Path::new(".tog/cargo-home/bin/cargo"),
            b"#!/bin/sh\n",
            0o755,
        )
        .unwrap();
        let mode = fs::metadata(dir.join(".tog/cargo-home/bin/cargo"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        symlink(&outside, dir.join(".tog/cargo-home/escape")).unwrap();
        root.remove_dir_all(Path::new(".tog/cargo-home")).unwrap();
        assert!(!dir.join(".tog/cargo-home").exists());
        assert!(outside.join("keep").is_file());
        root.remove_dir_all(Path::new(".tog/cargo-home")).unwrap();

        // Once the project is renamed away, every write lands in the held
        // directory, never at the old path.
        let moved = temp.0.join("moved");
        fs::rename(&dir, &moved).unwrap();
        fs::create_dir_all(&dir).unwrap();
        root.replace_symlink(Path::new("node_modules"), &env, "node_modules")
            .unwrap();
        assert!(moved.join("node_modules").symlink_metadata().is_ok());
        assert!(dir.join("node_modules").symlink_metadata().is_err());
    }

    #[test]
    fn still_named_walks_the_stored_path_without_resolving_it_again() {
        let temp = TempDir::new();
        let parent = temp.0.join("parent");
        let dir = parent.join("proj");
        fs::create_dir_all(&dir).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        root.check_still_named().unwrap();
        // The same directory, but reached through an ancestor that is now a
        // symlink: re-canonicalizing would find the held inode and pass.
        let real = temp.0.join("parent-real");
        fs::rename(&parent, &real).unwrap();
        symlink(&real, &parent).unwrap();
        let error = root.check_still_named().unwrap_err();
        assert!(error.to_string().contains("moved"), "{error}");
    }

    #[test]
    fn strict_listing_and_subdirectories_refuse_a_symlink() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let outside = temp.0.join("outside");
        fs::create_dir_all(outside.join("closures")).unwrap();
        fs::write(outside.join("closures/python.json"), b"{}").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        assert_eq!(root.read_dir(Path::new(".tog/closures")).unwrap(), None);
        assert!(root.subdir(Path::new("src")).unwrap().is_none());

        symlink(&outside, dir.join(".tog")).unwrap();
        let error = root.read_dir(Path::new(".tog/closures")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        fs::remove_file(dir.join(".tog")).unwrap();
        fs::create_dir_all(dir.join(".tog")).unwrap();
        symlink(outside.join("closures"), dir.join(".tog/closures")).unwrap();
        let error = root.read_dir(Path::new(".tog/closures")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        symlink(&outside, dir.join("src")).unwrap();
        let error = root.subdir(Path::new("src")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        // An input walk follows the same link; the strict one does not.
        assert!(root.input_subdir(Path::new("src")).unwrap().is_some());

        fs::create_dir_all(dir.join("pkg/inner")).unwrap();
        fs::write(dir.join("pkg/b"), b"").unwrap();
        fs::write(dir.join("pkg/a"), b"").unwrap();
        let pkg = root.subdir(Path::new("pkg")).unwrap().unwrap();
        assert_eq!(pkg.path(), root.path().join("pkg"));
        assert_eq!(
            root.read_dir(Path::new("pkg")).unwrap().unwrap(),
            vec!["a", "b", "inner"]
        );
        assert!(pkg.subdir(Path::new("inner")).unwrap().is_some());
    }

    #[test]
    fn an_exclusive_rename_refuses_an_existing_name() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let held = fs::File::open(&dir).unwrap();
        symlink("target", dir.join("temp")).unwrap();
        fs::create_dir_all(dir.join("taken")).unwrap();
        let error = rename_at_noreplace(held.as_raw_fd(), b"temp", b"taken").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert!(dir.join("taken").is_dir());
        fs::write(dir.join("file"), b"keep").unwrap();
        let error = rename_at_noreplace(held.as_raw_fd(), b"temp", b"file").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert_eq!(fs::read(dir.join("file")).unwrap(), b"keep");
        rename_at_noreplace(held.as_raw_fd(), b"temp", b"free").unwrap();
        assert_eq!(
            fs::read_link(dir.join("free")).unwrap(),
            Path::new("target")
        );
        assert!(dir.join("temp").symlink_metadata().is_err());
    }

    /// `rename_in` moves a file from outside the project into the held
    /// directory with its mode, replaces a regular file there, and leaves
    /// no temporary behind. A project renamed after it was opened receives
    /// the file in the directory tog holds, not at the old path.
    #[test]
    fn rename_in_moves_a_file_into_the_held_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = TempDir::named("rename-in");
        let dir = project(&temp);
        let scratch = temp.0.join("scratch");
        fs::create_dir_all(&scratch).unwrap();
        let built = scratch.join("app");
        fs::write(&built, b"binary").unwrap();
        fs::set_permissions(&built, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.join("app"), b"old").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        root.rename_in(&built, Path::new("app")).unwrap();
        assert!(built.symlink_metadata().is_err());
        assert_eq!(fs::read(dir.join("app")).unwrap(), b"binary");
        let mode = fs::metadata(dir.join("app")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        // Missing parents are created below the held root.
        fs::write(&built, b"nested").unwrap();
        root.rename_in(&built, Path::new("bin/app")).unwrap();
        assert_eq!(fs::read(dir.join("bin/app")).unwrap(), b"nested");

        // Renamed, with another directory at the old path.
        let moved = temp.0.join("moved");
        fs::rename(&dir, &moved).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::write(&built, b"held").unwrap();
        root.rename_in(&built, Path::new("app")).unwrap();
        assert_eq!(fs::read(moved.join("app")).unwrap(), b"held");
        assert!(dir.join("app").symlink_metadata().is_err());
        assert!(!entries(&moved)
            .iter()
            .any(|name| name.starts_with(".tog-tmp")));
    }

    /// A symlink at the destination is replaced by the file, never written
    /// through: its target keeps its bytes. A directory there is refused
    /// and left alone, and so is a FIFO. A symlink or a directory as the
    /// source is never moved in.
    #[test]
    fn rename_in_replaces_a_symlink_and_refuses_a_directory() {
        let temp = TempDir::named("rename-in-refuse");
        let dir = project(&temp);
        let scratch = temp.0.join("scratch");
        fs::create_dir_all(&scratch).unwrap();
        let outside = temp.0.join("outside");
        fs::write(&outside, b"keep").unwrap();
        symlink(&outside, dir.join("app")).unwrap();
        let built = scratch.join("app");
        fs::write(&built, b"binary").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        root.rename_in(&built, Path::new("app")).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        let entry = dir.join("app").symlink_metadata().unwrap();
        assert!(entry.file_type().is_file());
        assert_eq!(fs::read(dir.join("app")).unwrap(), b"binary");

        fs::create_dir_all(dir.join("tool/src")).unwrap();
        fs::write(&built, b"binary").unwrap();
        let error = root.rename_in(&built, Path::new("tool")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("is a directory"), "{error}");
        assert!(dir.join("tool/src").is_dir());
        assert!(built.is_file(), "a refused source was consumed");

        let fifo = CString::new(dir.join("pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: the path is NUL-terminated and outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let error = root.rename_in(&built, Path::new("pipe")).unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert!(fs::symlink_metadata(dir.join("pipe"))
            .unwrap()
            .file_type()
            .is_fifo());

        // A parent in the project that is a symlink is not walked through.
        symlink(&scratch, dir.join("linked")).unwrap();
        let error = root.rename_in(&built, Path::new("linked/app")).unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert!(built.is_file());

        let link = scratch.join("link");
        symlink(&outside, &link).unwrap();
        let error = root.rename_in(&link, Path::new("other")).unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
        assert!(dir.join("other").symlink_metadata().is_err());
        let error = root.rename_in(&scratch, Path::new("other")).unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert!(scratch.is_dir());
    }

    /// A source on another filesystem than the project is published as a
    /// copy with its mode, under the rename's rules: a symlink at the
    /// destination is replaced, its target untouched, and the source is
    /// removed. `/dev/shm` is the second filesystem where it is one.
    #[test]
    fn rename_in_across_filesystems_publishes_a_copy() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        const NAME: &str = "rename_in_across_filesystems_publishes_a_copy";
        let temp = TempDir::named("rename-in-xdev");
        let dir = project(&temp);
        let shm = Path::new("/dev/shm");
        let Ok(shm_meta) = fs::metadata(shm) else {
            eprintln!("skip {NAME}: no /dev/shm");
            return;
        };
        if shm_meta.dev() == fs::metadata(&dir).unwrap().dev() {
            eprintln!("skip {NAME}: /dev/shm shares the temp filesystem");
            return;
        }
        let other = TempDir(shm.join(format!("tog-rename-in-xdev-{}", random_suffix().unwrap())));
        fs::create_dir(&other.0).unwrap();
        let built = other.0.join("app");
        // Larger than any copy buffer, so the stream is read in pieces.
        let binary: Vec<u8> = (0..(4 << 20) + 7)
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(&built, &binary).unwrap();
        fs::set_permissions(&built, fs::Permissions::from_mode(0o750)).unwrap();
        let outside = temp.0.join("outside");
        fs::write(&outside, b"keep").unwrap();
        symlink(&outside, dir.join("app")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        root.rename_in(&built, Path::new("app")).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        let entry = dir.join("app").symlink_metadata().unwrap();
        assert!(entry.file_type().is_file());
        assert_eq!(entry.permissions().mode() & 0o7777, 0o750);
        assert!(fs::read(dir.join("app")).unwrap() == binary);
        assert!(built.symlink_metadata().is_err());
        assert!(!entries(&dir)
            .iter()
            .any(|name| name.starts_with(".tog-tmp")));

        // A directory there is refused across filesystems too, and the
        // source stays.
        fs::write(&built, b"binary").unwrap();
        fs::create_dir(dir.join("tool")).unwrap();
        let error = root.rename_in(&built, Path::new("tool")).unwrap_err();
        assert!(error.to_string().contains("is a directory"), "{error}");
        assert!(built.is_file());
    }
}

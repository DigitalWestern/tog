//! Descriptor-relative project writes (kernel layer). A `ProjectRoot` holds
//! a project directory open as a descriptor, reached from `/` one component
//! at a time with openat(O_NOFOLLOW), and every project-relative file it
//! reads or publishes is walked the same way from that descriptor. No
//! component of a project-relative path is ever followed through a symlink,
//! so a symlinked `.tog` cannot redirect a cache write outside the project.
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
    fd_stat, fsync_directory, mkdir_at, open_file_at, rename_at, same_inode, stat_at,
    unlink_if_same,
};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
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
    dir: fs::File,
    path: PathBuf,
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
        let root = CString::new("/").expect("no NUL");
        // SAFETY: the path is a valid NUL-terminated string and the returned
        // descriptor is owned by the File below.
        let fd = unsafe { libc::open(root.as_ptr(), DIRECTORY_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was returned by open and ownership moves into File.
        let mut dir = unsafe { fs::File::from_raw_fd(fd) };
        let mut current = PathBuf::from("/");
        for component in path.components() {
            let std::path::Component::Normal(name) = component else {
                continue;
            };
            current.push(name);
            dir = open_directory_at(dir.as_raw_fd(), name.as_bytes(), &current, "open project")?;
        }
        Ok(Self { dir, path })
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
    fn open_file(&self, relative: &Path) -> io::Result<Option<fs::File>> {
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
            match open_directory_at(fd, parent.as_bytes(), display, verb) {
                Ok(dir) => held = Some(dir),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        display.push(name);
        Ok(Some((held, name)))
    }

    /// Open each component in turn from the held descriptor, creating the
    /// ones that are absent. Returns the last descriptor, or `None` when
    /// `components` is empty and the project root itself is the parent.
    fn open_creating(
        &self,
        components: &[&OsStr],
        display: &mut PathBuf,
    ) -> io::Result<Option<fs::File>> {
        let mut held: Option<fs::File> = None;
        for component in components {
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
            let dir = open_directory_at(fd, component.as_bytes(), display, "write")?;
            if created {
                fsync_directory(fd)?;
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
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let held = self.open_creating(&parents, &mut display)?;
        display.push(name);
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => match stat.st_mode & libc::S_IFMT {
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
            file.write_all(bytes)?;
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
    io::Error::new(io::ErrorKind::InvalidData, message)
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

fn open_directory_at(
    parent_fd: RawFd,
    name: &[u8],
    display: &Path,
    verb: &str,
) -> io::Result<fs::File> {
    open_file_at(parent_fd, name, DIRECTORY_FLAGS, 0).map_err(|error| match error.raw_os_error() {
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

/// `.tog-tmp.<32 hex>`: a fresh random name per attempt, so an occupied
/// name (a crash leftover, or an entry planted at a guessable name) is
/// stepped around, never unlinked and never written through. The name
/// carries no process identity, so two runs in containers that reuse small
/// pids never pick the same fixed point. The destination name is not part
/// of it, so a destination of any valid length publishes.
fn random_temp_name(_name: &[u8], _attempt: usize) -> io::Result<Vec<u8>> {
    Ok(format!(".tog-tmp.{}", hex::encode(urandom_bytes(16)?)).into_bytes())
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
        let _listener = std::os::unix::net::UnixListener::bind(dir.join(".tog/plan.json")).unwrap();
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
    fn toolchain_lock_and_inputs_fail_closed() {
        // The lock and its inputs are read through the held root, so a
        // symlinked lock, a symlinked input file, and a symlinked ancestor
        // are all refused instead of read through.
        let temp = TempDir::new();
        let dir = project(&temp);
        let victim = temp.0.join("victim");
        fs::write(&victim, b"3.12.1\n").unwrap();
        let root = ProjectRoot::open(&dir).unwrap();

        symlink(&victim, dir.join("tog-toolchain.toml")).unwrap();
        let error = root.read_file(Path::new("tog-toolchain.toml")).unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");

        fs::remove_file(dir.join("tog-toolchain.toml")).unwrap();
        symlink(&victim, dir.join(".python-version")).unwrap();
        let error = root.read_file(Path::new(".python-version")).unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");

        fs::remove_file(dir.join(".python-version")).unwrap();
        let outside = temp.0.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::remove_dir(dir.join("sub")).unwrap();
        symlink(&outside, dir.join("sub")).unwrap();
        let error = root
            .read_file(Path::new("sub/.python-version"))
            .unwrap_err();
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
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
    fn plain_path_reads_do_not_fail_closed() {
        // The negative half of the lock guarantee: ordinary path reads
        // follow a symlinked input, so only the held-descriptor walk above
        // refuses. If this ever fails, the refusal tests prove nothing.
        let temp = TempDir::new();
        let dir = project(&temp);
        let victim = temp.0.join("victim");
        fs::write(&victim, b"3.12.1\n").unwrap();
        symlink(&victim, dir.join(".python-version")).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        assert!(root.read_file(Path::new(".python-version")).is_err());
        assert_eq!(
            fs::read(dir.join(".python-version")).unwrap(),
            b"3.12.1\n",
            "plain read refused a symlink it should follow"
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
}

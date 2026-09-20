//! Descriptor-relative project writes (kernel layer). A `ProjectRoot` holds
//! a project directory open as a descriptor, reached from `/` one component
//! at a time with openat(O_NOFOLLOW), and every project-relative file it
//! reads or publishes is walked the same way from that descriptor. No
//! component of a project-relative path is ever followed through a symlink,
//! so a symlinked `.tog` cannot redirect a cache write outside the project.
//!
//! What `write_file` guarantees: the file is created with O_EXCL under a
//! random temporary name in the held parent, written, fsynced, and renamed
//! over the destination, which is checked first and refused if it is a
//! symlink or a directory. A concurrent same-user writer that swaps a
//! symlink in after that check gets its symlink replaced, never written
//! through; cooperating writers serialize on the project transaction lock.
//! A replaced file is a fresh inode with mode 0644 under the umask, not
//! the old file's mode. Temporary cleanup after a failure is best-effort.
//!
//! `open_file` is public because a caller may need the descriptor it read
//! from (to hold it, or to compare its identity later), not just the bytes.

use crate::kernel::store::{
    fsync_directory, mkdir_at, open_file_at, rename_at, stat_at, unlink_at,
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
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open a project-relative regular file for reading without following
    /// a symlink at any component. `Ok(None)` when any component is absent.
    /// A symlink anywhere on the path, a non-directory where a directory is
    /// expected, or a destination that is not a regular file (a FIFO, a
    /// device, a directory) is an error, so a tampered cache fails closed
    /// instead of being read as a miss.
    pub fn open_file(&self, relative: &Path) -> io::Result<Option<fs::File>> {
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let mut held: Option<fs::File> = None;
        for parent in parents {
            display.push(parent);
            let fd = held
                .as_ref()
                .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
            match open_directory_at(fd, parent.as_bytes(), &display, "read") {
                Ok(dir) => held = Some(dir),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        display.push(name);
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

    /// The bytes of a project-relative file, or `None` when it is absent.
    /// Refusals are those of `open_file`.
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
    /// any parent, a symlink or a directory at the destination, and a
    /// temporary name that stays occupied after a bounded number of fresh
    /// random names.
    pub fn write_file(&self, relative: &Path, bytes: &[u8]) -> io::Result<()> {
        self.publish(relative, bytes, &mut random_temp_name)
    }

    fn publish(
        &self,
        relative: &Path,
        bytes: &[u8],
        temp_name: &mut dyn FnMut(&[u8], usize) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let mut held: Option<fs::File> = None;
        for parent in parents {
            display.push(parent);
            let fd = held
                .as_ref()
                .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
            let created = mkdir_at(fd, parent.as_bytes(), 0o755).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("create {}: {error}", display.display()),
                )
            })?;
            let dir = open_directory_at(fd, parent.as_bytes(), &display, "write")?;
            if created {
                fsync_directory(fd)?;
            }
            held = Some(dir);
        }
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
                _ => {}
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
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            rename_at(parent_fd, &temp, name.as_bytes()).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("publish {}: {error}", display.display()),
                )
            })?;
            fsync_directory(parent_fd)
        })();
        if result.is_err() {
            unlink_at(parent_fd, &temp);
        }
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

/// `.<name>.tog-tmp.<pid>.<16 hex>`: a fresh random name per attempt, so an
/// occupied name (a crash leftover, or an entry planted at a guessable
/// name) is stepped around, never unlinked and never written through.
fn random_temp_name(name: &[u8], _attempt: usize) -> io::Result<Vec<u8>> {
    use ring::rand::SecureRandom as _;
    let mut nonce = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| io::Error::other("system randomness is unavailable"))?;
    let mut temp = Vec::with_capacity(name.len() + 40);
    temp.push(b'.');
    temp.extend_from_slice(name);
    temp.extend_from_slice(
        format!(".tog-tmp.{}.{}", std::process::id(), hex::encode(nonce)).as_bytes(),
    );
    Ok(temp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::symlink;

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
    fn name_too_long_is_an_error_not_a_panic() {
        let temp = TempDir::new();
        let root = ProjectRoot::open(&project(&temp)).unwrap();
        let long = "n".repeat(300);
        let error = root.write_file(Path::new(&long), b"x").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENAMETOOLONG), "{error}");
        assert!(entries(root.path()).is_empty());
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
        let open_descriptors = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = open_descriptors();
        for _ in 0..50 {
            root.write_file(Path::new(".tog/plan.json"), b"x")
                .unwrap_err();
            root.read_file(Path::new(".tog/plan.json")).unwrap_err();
            root.write_file(Path::new("real/plan.json"), b"x")
                .unwrap_err();
            root.read_file(Path::new("real/plan.json")).unwrap_err();
        }
        // The count is process-wide and other test threads open files too,
        // so allow their noise; a leak here would add at least 50.
        let after = open_descriptors();
        assert!(
            after < before + 25,
            "descriptors: {before} before, {after} after"
        );
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

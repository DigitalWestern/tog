//! The table of project directories open `ProjectRoot`s hold, and the
//! lookups through it: the directory a child process is started in, and
//! the root a confined door snapshots and publishes into.

use super::{input_name, ANCESTOR_FLAGS};
use crate::kernel::store::{fd_stat, open_file_at};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The project directories open `ProjectRoot`s hold, by canonical path. A
/// tool tog starts "in the project" is given a path (`DelegateSpec`'s lock
/// root), and a process's working directory is only a path until the child
/// enters it: a project swapped and restored between tog's open and that
/// chdir would start the tool in the other directory. With this table the
/// child enters the directory tog holds instead (`held_dir_for`).
static HELD: std::sync::Mutex<Vec<(u64, PathBuf, RawFd)>> = std::sync::Mutex::new(Vec::new());

/// One `HELD` row, removed when its root is dropped. The row names the
/// root's own descriptor, not a duplicate: `ProjectRoot` drops this before
/// its `dir`, and every use of the descriptor happens under the table's
/// lock, so a row is never read after its descriptor closes.
#[derive(Debug)]
pub(super) struct HeldEntry(u64);

impl HeldEntry {
    pub(super) fn register(path: &Path, dir: &fs::File) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        held_table().push((id, path.to_path_buf(), dir.as_raw_fd()));
        Self(id)
    }
}

impl Drop for HeldEntry {
    fn drop(&mut self) {
        held_table().retain(|(id, _, _)| *id != self.0);
    }
}

fn held_table() -> std::sync::MutexGuard<'static, Vec<(u64, PathBuf, RawFd)>> {
    HELD.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Resolve a child's cwd through every held root containing the requested
/// path. All matching roots must identify the same directory. A failed or
/// conflicting held lookup refuses execution instead of falling back to a
/// replacement pathname. Paths outside all held roots keep normal behavior.
/// The path returned is the spelling that matched, never what it names now.
fn held_dir_for(path: &Path) -> io::Result<Option<(fs::File, PathBuf)>> {
    let mut matched = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let table = held_table();
    let mut matches = held_matches(&table, &matched);
    if matches.is_empty() {
        if let Ok(canonical) = matched.canonicalize() {
            matches = held_matches(&table, &canonical);
            matched = canonical;
        }
    }
    let mut selected: Option<(fs::File, libc::stat)> = None;
    for (fd, below) in matches {
        if fd_stat(fd)?.st_nlink == 0 {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let name = if below.as_os_str().is_empty() {
            b".".to_vec()
        } else {
            input_name(&below)?
        };
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let directory = open_file_at(fd, &name, flags, 0)?;
        let identity = fd_stat(directory.as_raw_fd())?;
        if let Some((_, first)) = &selected {
            if first.st_dev != identity.st_dev || first.st_ino != identity.st_ino {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
        } else {
            selected = Some((directory, identity));
        }
    }
    Ok(selected.map(|(directory, _)| (directory, matched)))
}

/// `held_dir_for` for a caller that keeps the path (`ProjectRoot::held_at`):
/// the directory a held root has at `path`, with `path` in canonical form.
/// The spelling given is matched only when it is absolute with no climbing
/// component and every component below the held root is a real directory.
/// Any other spelling is canonicalized, which resolves what it names now,
/// and matched once more. A renamed project still matches by the canonical
/// path it was opened at, which is the spelling its callers hold.
pub(crate) fn held_root_for(path: &Path) -> io::Result<Option<(fs::File, PathBuf)>> {
    let plain = path.is_absolute()
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    if plain {
        if let Some(found) = held_below(path)? {
            return Ok(Some((found, path.to_path_buf())));
        }
    }
    match path.canonicalize() {
        Ok(canonical) if canonical != path => {
            Ok(held_below(&canonical)?.map(|found| (found, canonical)))
        }
        Ok(_) => Ok(None),
        // A plain path nothing holds and nothing names is not held. One
        // that climbs cannot be compared without resolving it.
        Err(_) if plain => Ok(None),
        Err(error) => Err(error),
    }
}

/// The directory at `path` (canonical in form) under every held root that
/// contains it, walked from the held descriptor one component at a time
/// without following a symlink. `None` when no root holds it or a
/// component below the root is not a real directory. Roots that disagree
/// (two directories, or a directory in one and a symlink in another), or a
/// held directory since removed, refuse as `held_dir_for` does.
fn held_below(path: &Path) -> io::Result<Option<fs::File>> {
    let table = held_table();
    let mut selected: Option<(fs::File, libc::stat)> = None;
    let mut aliased = false;
    'roots: for (fd, below) in held_matches(&table, path) {
        if fd_stat(fd)?.st_nlink == 0 {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let mut directory = open_file_at(fd, b".", ANCESTOR_FLAGS, 0)?;
        for name in below.iter() {
            directory =
                match open_file_at(directory.as_raw_fd(), name.as_bytes(), ANCESTOR_FLAGS, 0) {
                    Ok(next) => next,
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::ENOTDIR) | Some(libc::ELOOP)
                        ) =>
                    {
                        aliased = true;
                        continue 'roots;
                    }
                    Err(error) => return Err(error),
                };
        }
        let identity = fd_stat(directory.as_raw_fd())?;
        if let Some((_, first)) = &selected {
            if first.st_dev != identity.st_dev || first.st_ino != identity.st_ino {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
        } else {
            selected = Some((directory, identity));
        }
    }
    // One held root has a real directory here and another has a symlink:
    // the roots disagree about what the path names, so nothing is chosen.
    if aliased && selected.is_some() {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    if aliased {
        return Ok(None);
    }
    Ok(selected.map(|(directory, _)| directory))
}

/// Enter a held cwd directly in the child, without first resolving its old
/// pathname. The descriptor belongs to the command and closes on exec.
/// A held lookup refusal becomes a spawn error. The post-fork hooks only
/// make async-signal-safe calls and construct raw errno errors.
pub(crate) fn start_in(command: &mut std::process::Command, dir: &Path) {
    use std::os::unix::process::CommandExt as _;
    match held_dir_for(dir) {
        Ok(Some((held, _))) => {
            // std performs this chdir before pre_exec. It must not touch
            // the replaceable project path or require that path to exist.
            command.current_dir("/");
            // SAFETY: fchdir is async-signal-safe and the closure owns its fd.
            unsafe {
                command.pre_exec(move || {
                    if libc::fchdir(held.as_raw_fd()) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Ok(None) => {
            command.current_dir(dir);
        }
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(libc::ESTALE);
            // SAFETY: this hook returns a raw errno without allocation.
            unsafe {
                command.pre_exec(move || Err(io::Error::from_raw_os_error(errno)));
            }
        }
    }
}

fn held_matches(table: &[(u64, PathBuf, RawFd)], path: &Path) -> Vec<(RawFd, PathBuf)> {
    table
        .iter()
        .filter_map(|(_, root, fd)| Some((*fd, path.strip_prefix(root).ok()?.to_path_buf())))
        .collect()
}

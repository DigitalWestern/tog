//! Declared sandbox roots an open project root holds (#497), and handing
//! descriptors to bubblewrap.

use super::Sandbox;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The declared roots (and the working directory) an open project root
/// holds, each resolved once through its held descriptor (#497). The socket
/// scan walks that descriptor and bubblewrap binds it, so a project renamed
/// or swapped (and even swapped back) since tog opened it is not what the
/// build sees. A root no open project root holds keeps its pathname.
#[derive(Default)]
pub(super) struct HeldRoots {
    roots: Vec<HeldRoot>,
}

pub(super) struct HeldRoot {
    /// The path the caller declared.
    requested: PathBuf,
    /// Where the sandbox shows it: the canonical path it was opened at.
    pub(super) dest: PathBuf,
    dir: fs::File,
    /// The descriptor number bubblewrap receives it at, for a root it
    /// binds (`None` for a working directory that is no declared root).
    target: Option<RawFd>,
}

/// The first descriptor number a held root is passed at. The shell that
/// closes them reads one digit, so at most seven are passed.
const HELD_FD_FIRST: RawFd = 3;
const HELD_FD_LAST: RawFd = 9;

impl HeldRoots {
    pub(super) fn resolve(sandbox: &Sandbox<'_>, cwd: &Path) -> io::Result<Self> {
        let mut held = Self::default();
        let mut next = HELD_FD_FIRST;
        for path in sandbox.read.iter().chain(&sandbox.write) {
            if held.find(path).is_some() {
                continue;
            }
            let Some((dir, dest)) = crate::kernel::fsroot::held_root_for(path)? else {
                continue;
            };
            if next > HELD_FD_LAST {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "the sandbox binds more than {} directories of open projects",
                        HELD_FD_LAST - HELD_FD_FIRST + 1
                    ),
                ));
            }
            held.roots.push(HeldRoot {
                requested: path.to_path_buf(),
                dest,
                dir,
                target: Some(next),
            });
            next += 1;
        }
        if held.find(cwd).is_none() {
            if let Some((dir, dest)) = crate::kernel::fsroot::held_root_for(cwd)? {
                held.roots.push(HeldRoot {
                    requested: cwd.to_path_buf(),
                    dest,
                    dir,
                    target: None,
                });
            }
        }
        Ok(held)
    }

    pub(super) fn find(&self, path: &Path) -> Option<&HeldRoot> {
        self.roots.iter().find(|root| root.requested == path)
    }

    /// Each declared root as (bind source, place in the sandbox), the
    /// writable ones with scratch added: a held one is bound from its
    /// descriptor at the path it was opened at.
    pub(super) fn place(
        &self,
        read: &[&Path],
        write: &[&Path],
        scratch: &Path,
    ) -> io::Result<(Vec<(PathBuf, PathBuf)>, Vec<(PathBuf, PathBuf)>)> {
        let read = read
            .iter()
            .map(|path| self.place_one(path))
            .collect::<io::Result<_>>()?;
        let mut write: Vec<(PathBuf, PathBuf)> = write
            .iter()
            .map(|path| self.place_one(path))
            .collect::<io::Result<_>>()?;
        let scratch = fs::canonicalize(scratch)?;
        if !write.iter().any(|(_, path)| path == &scratch) {
            write.push((scratch.clone(), scratch));
        }
        Ok((read, write))
    }

    /// One path as (bind source, place in the sandbox).
    pub(super) fn place_one(&self, path: &Path) -> io::Result<(PathBuf, PathBuf)> {
        match self.find(path) {
            Some(found) => Ok((found.source(), found.dest.clone())),
            None => fs::canonicalize(path).map(|path| (path.clone(), path)),
        }
    }

    /// `(source, target)` for every root bubblewrap binds.
    pub(super) fn passed(&self) -> Vec<(RawFd, RawFd)> {
        use std::os::fd::AsRawFd as _;
        self.roots
            .iter()
            .filter_map(|root| Some((root.dir.as_raw_fd(), root.target?)))
            .collect()
    }

    /// The shell script that closes every passed descriptor and runs its
    /// arguments, or `None` when nothing is passed.
    pub(super) fn close_script(&self) -> Option<String> {
        let closes: Vec<String> = self
            .roots
            .iter()
            .filter_map(|root| Some(format!("{}<&-", root.target?)))
            .collect();
        (!closes.is_empty()).then(|| format!("exec {}; exec \"$@\"", closes.join(" ")))
    }
}

impl HeldRoot {
    /// The bind source bubblewrap opens: its own copy of the descriptor.
    fn source(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.target.expect("a bound root has a target")
        ))
    }

    /// This process's view of the held directory, for the socket scan.
    /// The trailing `.` makes the scan start in the directory rather than
    /// at the descriptor's symlink.
    pub(super) fn alias(&self) -> PathBuf {
        use std::os::fd::AsRawFd as _;
        PathBuf::from(format!("/proc/self/fd/{}/.", self.dir.as_raw_fd()))
    }
}

/// Hand each `(source, target)` descriptor to the command at `target`.
/// This runs after `bwrap_command` marked every inherited descriptor
/// close-on-exec, so the targets are the only ones that survive. Each
/// source is first copied above every target, so a source numbered like
/// another target is not overwritten before it is moved.
pub(crate) fn pass_fds(command: &mut Command, fds: Vec<(RawFd, RawFd)>) {
    if fds.is_empty() {
        return;
    }
    let floor = fds.iter().map(|(_, target)| *target).max().unwrap_or(2) + 1;
    // Allocated before fork: the closure runs between fork and exec.
    let mut high = vec![0; fds.len()];
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the closure calls only fcntl/dup2/close, which are
    // async-signal-safe, on vectors allocated before fork.
    unsafe {
        command.pre_exec(move || {
            for (slot, (source, _)) in high.iter_mut().zip(&fds) {
                *slot = libc::fcntl(*source, libc::F_DUPFD_CLOEXEC, floor);
                if *slot < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for (copy, (_, target)) in high.iter().zip(&fds) {
                // dup2 leaves the new descriptor without close-on-exec.
                if libc::dup2(*copy, *target) < 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(*copy);
            }
            Ok(())
        });
    }
}

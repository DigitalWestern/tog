//! `ProjectRoot::rename_in`: a file staged outside the project (a build
//! output in scratch) moved into the held directory with one `renameat`.

use super::{random_temp_name, refusal, rename_between, split_relative, ProjectRoot};
use crate::kernel::store::{
    fd_stat, fsync_directory, open_file_at, same_inode, stat_at, unlink_if_same,
};
use std::fs;
use std::io::{self, Read as _};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

impl ProjectRoot {
    /// Move a regular file from outside the project (a build output staged
    /// in scratch) to a project-relative path, the mirror image of
    /// `move_dir_out`: one `renameat` from the source's parent directory
    /// into the held parent, so a project renamed or replaced since it was
    /// opened receives the file in the directory tog holds, never at its
    /// old path. Missing parents are created with the no-follow walk, and
    /// the file and the destination directory are fsynced.
    ///
    /// The source must be a regular file now: a symlink or a directory in
    /// scratch is never moved in. At the destination a regular file is
    /// replaced, and so is a symlink: the rename replaces the link itself
    /// and never writes through it, as the pathname rename this replaces
    /// did. A directory or any other entry there is user state and is
    /// refused. A source on another filesystem than the project (scratch
    /// in a store elsewhere) is published as a copy of the checked file,
    /// with its permission bits, under the same rules, and the source is
    /// removed.
    pub fn rename_in(&self, from: &Path, relative: &Path) -> io::Result<()> {
        let (Some(source_parent), Some(source_name)) = (from.parent(), from.file_name()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} names no file to move", from.display()),
            ));
        };
        let source_parent = if source_parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            source_parent
        };
        let source_dir = open_file_at(
            libc::AT_FDCWD,
            source_parent.as_os_str().as_bytes(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("open {}: {error}", source_parent.display()),
            )
        })?;
        // Opened without following a symlink, so the check below and the
        // fsync are on the entry the rename moves.
        let source = open_file_at(
            source_dir.as_raw_fd(),
            source_name.as_bytes(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => refusal(format!(
                "{} is a symlink; refusing to move it into the project",
                from.display()
            )),
            _ => io::Error::new(error.kind(), format!("open {}: {error}", from.display())),
        })?;
        let opened = fd_stat(source.as_raw_fd())?;
        if opened.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(refusal(format!(
                "{} is not a regular file; refusing to move it into the project",
                from.display()
            )));
        }
        source.sync_all()?;
        let (parents, name) = split_relative(relative)?;
        let mut display = self.path.clone();
        let held = self.open_creating(&parents, &mut display)?;
        display.push(name);
        let parent_fd = held
            .as_ref()
            .map_or(self.dir.as_raw_fd(), AsRawFd::as_raw_fd);
        match stat_at(parent_fd, name.as_bytes()) {
            Ok(stat) => match stat.st_mode & libc::S_IFMT {
                libc::S_IFREG | libc::S_IFLNK => {}
                libc::S_IFDIR => {
                    return Err(refusal(format!(
                        "{} is a directory; refusing to replace it",
                        display.display()
                    )))
                }
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
        // The name in scratch must still be the file checked above.
        let current = stat_at(source_dir.as_raw_fd(), source_name.as_bytes())?;
        if !same_inode(&current, &opened) {
            return Err(refusal(format!(
                "{} was replaced before it could be moved into the project",
                from.display()
            )));
        }
        match rename_between(
            source_dir.as_raw_fd(),
            source_name.as_bytes(),
            parent_fd,
            name.as_bytes(),
        ) {
            Ok(()) => fsync_directory(parent_fd),
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                self.copy_in(&source, &opened, relative).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "copy {} to {} across filesystems: {error}",
                            from.display(),
                            display.display()
                        ),
                    )
                })?;
                // The copy is in place, so the source goes, as the rename
                // would have taken it. Only the file checked above.
                unlink_if_same(source_dir.as_raw_fd(), source_name.as_bytes(), &opened, 0)?;
                Ok(())
            }
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("move {} to {}: {error}", from.display(), display.display()),
            )),
        }
    }

    /// The cross-filesystem half of `rename_in`: the bytes of the source
    /// descriptor it checked, published through the held parent with the
    /// source's permission bits (not set-ID bits, which a write can clear).
    /// The temporary is written and fsynced before one rename replaces the
    /// destination, a symlink there included, so a failed copy leaves the
    /// destination as it was.
    fn copy_in(
        &self,
        mut source: &fs::File,
        opened: &libc::stat,
        relative: &Path,
    ) -> io::Result<()> {
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes)?;
        self.publish_mode(
            relative,
            &bytes,
            Some(opened.st_mode & 0o777),
            true,
            &mut random_temp_name,
        )
    }
}

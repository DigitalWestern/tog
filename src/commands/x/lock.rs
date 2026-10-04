//! The `~/.tog/x` directory and the per-environment advisory locks: the
//! runner holds one shared while it builds or runs an environment, and
//! `tog x --clean` takes it exclusive before removing one.

use super::*;

/// Open the shared x directory, creating it the first time. A symlinked
/// `$HOME` or `~/.tog` is followed, like cleanup's `validated_x_dir` does,
/// but `x` itself must be a real directory: a symlink there could point the
/// locks and environments anywhere.
pub(super) fn open_x_dir(x_dir: &Path) -> io::Result<fs::File> {
    if let Ok(metadata) = fs::symlink_metadata(x_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(other(format!(
                "x: environment directory {} is not a private directory",
                x_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(x_dir)?;
    }
    open_directory_path(&x_dir.canonicalize()?)
}

/// Open an absolute directory one component at a time, refusing symlinks at
/// every component. The final identity is checked by the caller against the
/// directory that was validated before this open.
pub(super) fn open_directory_path(path: &Path) -> io::Result<fs::File> {
    if !path.is_absolute() {
        return Err(other(format!(
            "x: cleanup directory {} is not absolute; refusing to clean",
            path.display()
        )));
    }
    let mut directory = store::open_real_directory(Path::new("/"), "root directory")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(other(format!(
                "x: cleanup directory {} contains an unsupported path component",
                path.display()
            )));
        };
        directory = store::open_directory_at(directory.as_raw_fd(), name.as_bytes())?;
    }
    Ok(directory)
}

pub(super) fn ensure_x_locks_dir_at(x_dir_fd: RawFd) -> io::Result<fs::File> {
    match store::stat_at(x_dir_fd, X_LOCKS_DIR.as_bytes()) {
        Ok(stat) if !store::is_directory(&stat) => {
            return Err(other(
                "x: lock directory is not a private directory; refusing to clean",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            store::mkdir_at(x_dir_fd, X_LOCKS_DIR.as_bytes(), 0o700)?;
        }
        Err(error) => return Err(error),
    }
    let locks = store::open_directory_at(x_dir_fd, X_LOCKS_DIR.as_bytes())?;
    locks.set_permissions(fs::Permissions::from_mode(0o700))?;
    Ok(locks)
}

pub(super) fn x_root_lock_name(root_name: &OsStr) -> String {
    format!("{}.lock", root_name.to_string_lossy())
}

/// A successful cleanup unlinks the lock file it holds, so `.locks` stays
/// bounded. That means a waiter can be handed a lock on an inode the lock
/// pathname no longer names, which would protect nothing. Every acquisition
/// therefore re-checks the pathname against the locked inode and retries.
pub(super) const LOCK_ATTEMPTS: usize = 8;

/// The per-environment advisory lock, opened relative to an already-open x
/// directory, so renaming a pathname cannot make the lock refer to another
/// environment. `None` only when `nonblocking` and someone else holds it.
/// The descriptor is close-on-exec: `run` clears that only immediately
/// before exec, so a running tool keeps cleanup out.
pub(super) fn lock_x_root_at(
    x_dir_fd: RawFd,
    root_name: &OsStr,
    exclusive: bool,
    nonblocking: bool,
) -> io::Result<Option<fs::File>> {
    let lock_name = x_root_lock_name(root_name);
    for _ in 0..LOCK_ATTEMPTS {
        let locks = ensure_x_locks_dir_at(x_dir_fd)?;
        let file = store::open_file_at(
            locks.as_raw_fd(),
            lock_name.as_bytes(),
            libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|error| {
            io::Error::new(error.kind(), format!("x: open lock {lock_name}: {error}"))
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let mut operation = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        if nonblocking {
            operation |= libc::LOCK_NB;
        }
        // SAFETY: flock operates on the owned lock descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            let error = io::Error::last_os_error();
            if nonblocking
                && matches!(
                    error.raw_os_error(),
                    Some(errno) if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK
                )
            {
                return Ok(None);
            }
            return Err(io::Error::new(
                error.kind(),
                format!("x: lock {lock_name}: {error}"),
            ));
        }
        match store::stat_at(locks.as_raw_fd(), lock_name.as_bytes()) {
            Ok(stat) if store::stat_identity(&stat) == store::fd_identity(&file)? => {
                return Ok(Some(file));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        drop(file);
    }
    Err(other(format!(
        "x: lock file for environment {} kept being replaced while it was acquired; retry later",
        root_name.to_string_lossy()
    )))
}

/// Drop the per-environment lock file after its environment is gone. Called
/// while the exclusive lock is still held; a later runner recreates the file,
/// and the identity re-check in `lock_x_root_at` keeps that safe.
pub(super) fn remove_x_root_lock_at(x_dir_fd: RawFd, root_name: &OsStr) -> io::Result<()> {
    let locks = ensure_x_locks_dir_at(x_dir_fd)?;
    store::remove_tree_entry_at(locks.as_raw_fd(), x_root_lock_name(root_name).as_bytes())
}

/// [`lock_x_root_at`] for an environment named by its path.
pub(super) fn lock_x_root(
    root: &Path,
    exclusive: bool,
    nonblocking: bool,
) -> io::Result<Option<fs::File>> {
    let (Some(x_dir), Some(root_name)) = (root.parent(), root.file_name()) else {
        return Err(other(format!(
            "x: environment root {} has no parent directory or name",
            root.display()
        )));
    };
    let x_dir = open_x_dir(x_dir)?;
    lock_x_root_at(x_dir.as_raw_fd(), root_name, exclusive, nonblocking)
}

pub(super) fn acquire_x_root(root: &Path) -> io::Result<fs::File> {
    let lock =
        lock_x_root(root, false, false)?.expect("blocking shared x lock always returns a file");
    // The lock is acquired before inspecting or creating the projection. A
    // cleanup that won the race can therefore remove the old root safely.
    ensure_x_metadata_dir(root)?;
    Ok(lock)
}

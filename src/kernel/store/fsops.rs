//! Descriptor-level filesystem helpers (kernel store): openat/mkdirat/
//! renameat/unlinkat wrappers, same-inode checks, and tree removal that
//! never follows a symlink. Shared by the registry, object commit, gc, and
//! the project-write helper in `kernel::fsroot`, which is why the
//! `pub(crate)` wrappers exist: every raw syscall wrapper lives here. The
//! store-supervised copy-on-write tree clone lives here too, so a kernel
//! provider can copy out of a store object without naming the comforter.

use super::*;

pub(super) fn errno_location() -> *mut libc::c_int {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: libc returns the calling thread's errno slot.
        unsafe { libc::__errno_location() }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: libc returns the calling thread's errno slot.
        unsafe { libc::__error() }
    }
}

pub(super) fn fd_set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl operates on the caller-owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn fd_stat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: stat is initialized by fstat before it is read.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is borrowed for the duration of this call.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

pub(super) fn is_regular_file(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
}

/// Create and validate a store-owned directory path one component at a
/// time. `create_dir_all` follows an existing symlink, which is not suitable
/// for a store namespace whose contents may later be deleted by GC.
pub(super) fn ensure_directory_tree(root: &Path, relative: &Path) -> io::Result<()> {
    let root_stat = fs::symlink_metadata(root)?;
    if root_stat.file_type().is_symlink() || !root_stat.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("store root {} is not a real directory", root.display()),
        ));
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("store namespace {} is not relative", relative.display()),
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(stat) => {
                if stat.file_type().is_symlink() || !stat.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "store namespace {} is not a real directory",
                            current.display()
                        ),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                let stat = fs::symlink_metadata(&current)?;
                if stat.file_type().is_symlink() || !stat.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "store namespace {} is not a real directory",
                            current.display()
                        ),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Create `path` as a directory only this user can enter, or accept an
/// existing one that is already that. The parent must be trusted: the
/// check is on the final component, which is never followed if it is a
/// symlink.
pub(super) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing run home {}: {why}; remove it and run again",
                path.display()
            ),
        )
    };
    let stat = fs::symlink_metadata(path)?;
    if stat.file_type().is_symlink() {
        return Err(refuse("it is a symlink"));
    }
    if !stat.is_dir() {
        return Err(refuse("it is not a directory"));
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if stat.uid() != uid {
        return Err(refuse(&format!(
            "it is owned by uid {}, not {uid}",
            stat.uid()
        )));
    }
    if stat.mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn open_file_at(
    dirfd: RawFd,
    name: &[u8],
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<fs::File> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: dirfd is borrowed for the duration of the call and name is a
    // valid NUL-terminated relative entry name.
    // openat is variadic, so mode must be passed as c_uint; mode_t is u16 on
    // Darwin and u32 on Linux.
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by openat and ownership moves into File.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

pub(crate) fn rename_at(dirfd: RawFd, old_name: &[u8], new_name: &[u8]) -> io::Result<()> {
    let old_name = CString::new(old_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    let new_name = CString::new(new_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: both names are valid relative names and dirfd remains borrowed
    // for this call.
    if unsafe { libc::renameat(dirfd, old_name.as_ptr(), dirfd, new_name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Rename `old_name` under `from_dir` to `new_name` under `to_dir`, both
/// resolved from held descriptors, so a symlink planted at either parent's
/// path after it was opened cannot redirect the move.
pub(super) fn rename_between(
    from_dir: RawFd,
    old_name: &[u8],
    to_dir: RawFd,
    new_name: &[u8],
) -> io::Result<()> {
    let old_name = CString::new(old_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    let new_name = CString::new(new_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: both names are valid relative names and both descriptors stay
    // borrowed for this call.
    if unsafe { libc::renameat(from_dir, old_name.as_ptr(), to_dir, new_name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn unlink_at(dirfd: RawFd, name: &[u8]) {
    let Ok(name) = CString::new(name) else {
        return;
    };
    // SAFETY: dirfd is borrowed and name is a valid relative entry name.
    unsafe {
        let _ = libc::unlinkat(dirfd, name.as_ptr(), 0);
    }
}

/// Create one directory entry under `dirfd`. `Ok(true)` when this call
/// created it, `Ok(false)` when an entry of that name already existed
/// (whatever its type: the caller opens it with O_NOFOLLOW to find out).
pub(crate) fn mkdir_at(dirfd: RawFd, name: &[u8], mode: libc::mode_t) -> io::Result<bool> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: dirfd is borrowed for the call and name is a NUL-terminated
    // relative entry name.
    if unsafe { libc::mkdirat(dirfd, name.as_ptr(), mode) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EEXIST) {
        return Ok(false);
    }
    Err(error)
}

/// fsync a directory descriptor so a just-created, renamed, or unlinked
/// entry is durable. Plain fsync rather than `File::sync_all`, whose Darwin
/// F_FULLFSYNC is not defined for directories; EINTR is retried.
pub(crate) fn fsync_directory(dirfd: RawFd) -> io::Result<()> {
    loop {
        // SAFETY: dirfd is borrowed for the duration of the call.
        if unsafe { libc::fsync(dirfd) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Make a just-published tree's contents durable before anything records it
/// as complete. Linux flushes the tree's whole filesystem with one
/// `syncfs`, far cheaper than one fsync per file of a large object; other
/// platforms fsync every file and directory in the tree. Symlinks are not
/// followed.
pub(crate) fn sync_tree(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let dir = fs::File::open(path)?;
        loop {
            // SAFETY: the descriptor is borrowed for the duration of the call.
            if unsafe { libc::syncfs(dir.as_raw_fd()) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Ok(());
        }
        let file = fs::File::open(path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                sync_tree(&entry?.path())?;
            }
            fsync_directory(file.as_raw_fd())
        } else {
            file.sync_all()
        }
    }
}

pub(crate) fn stat_at(dirfd: RawFd, name: &[u8]) -> io::Result<libc::stat> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: stat is initialized by fstatat before it is read, and name is a
    // NUL-terminated path that lives through the call.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: dirfd is borrowed for the duration of this call.
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

/// The target text of the symlink `name` under `dirfd`, read without
/// following it and without resolving any other pathname.
pub(crate) fn read_link_at(dirfd: RawFd, name: &[u8]) -> io::Result<PathBuf> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    let mut buffer = vec![0u8; 256];
    loop {
        // SAFETY: dirfd is borrowed for the duration of the call, name is a
        // NUL-terminated entry name, and buffer is writable for its length.
        let read = unsafe {
            libc::readlinkat(
                dirfd,
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        // A target that fills the buffer may have been cut short: retry
        // with more room until it fits.
        let read = read as usize;
        if read < buffer.len() {
            buffer.truncate(read);
            return Ok(PathBuf::from(OsString::from_vec(buffer)));
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

/// `stat_at` that follows a symlink at the last component, the way a
/// pathname `metadata` call does, but resolved from `dirfd`.
pub(crate) fn stat_at_following(dirfd: RawFd, name: &[u8]) -> io::Result<libc::stat> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: stat is initialized by fstatat before it is read, and name is a
    // NUL-terminated path that lives through the call.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: dirfd is borrowed for the duration of this call.
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

pub(crate) fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

pub(super) fn is_directory(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

pub(super) fn is_symlink(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

pub(super) fn entry_names_at(dirfd: RawFd) -> io::Result<Vec<OsString>> {
    // fdopendir takes ownership of its descriptor, so duplicate the borrowed
    // directory fd before handing it to libc.
    // SAFETY: fcntl duplicates the borrowed descriptor.
    let duplicate = unsafe { libc::fcntl(dirfd, libc::F_DUPFD, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = fd_set_cloexec(duplicate) {
        // SAFETY: duplicate is owned here because fdopendir has not taken it.
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    // SAFETY: duplicate is a valid directory descriptor and ownership moves
    // to the DIR until closedir.
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: errno_location points at this thread's errno slot.
        unsafe { *errno_location() = 0 };
        // SAFETY: directory remains valid until closedir below.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            // SAFETY: errno_location points at this thread's errno slot.
            let errno = unsafe { *errno_location() };
            // SAFETY: directory owns the duplicated descriptor.
            unsafe { libc::closedir(directory) };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            return Ok(names);
        }
        // SAFETY: d_name is a NUL-terminated name supplied by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(OsString::from_vec(name.to_bytes().to_vec()));
        }
    }
}

/// Enumerate a directory through an already-open descriptor. Callers use this
/// for directories whose pathname may be renamed while they work.
pub(crate) fn read_dir_names_at(dirfd: RawFd) -> io::Result<Vec<OsString>> {
    entry_names_at(dirfd)
}

pub(crate) fn unlink_if_same(
    dirfd: RawFd,
    name: &[u8],
    expected: &libc::stat,
    flags: libc::c_int,
) -> io::Result<bool> {
    let current = match stat_at(dirfd, name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !same_inode(&current, expected) {
        return Ok(false);
    }
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: dirfd is borrowed and name is NUL-terminated for this call.
    if unsafe { libc::unlinkat(dirfd, name.as_ptr(), flags) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(true)
}

pub(crate) fn remove_tree_entry_at(parentfd: RawFd, name: &[u8]) -> io::Result<()> {
    let expected = match stat_at(parentfd, name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let _ = remove_tree_entry_if_same(parentfd, name, &expected)?;
    Ok(())
}

/// Remove one entry only if it is still the exact directory entry described
/// by the caller's snapshot. A replacement directory is never opened or
/// removed, and a replacement symlink is never unlinked.
pub(crate) fn remove_tree_entry_if_same(
    parentfd: RawFd,
    name: &[u8],
    expected: &libc::stat,
) -> io::Result<bool> {
    let current = match stat_at(parentfd, name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !same_inode(&current, expected) {
        return Ok(false);
    }
    if is_symlink(expected) || !is_directory(expected) {
        return unlink_if_same(parentfd, name, expected, 0);
    }

    let name_c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: name_c is NUL-terminated and parentfd is borrowed.
    let childfd = unsafe {
        libc::openat(
            parentfd,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if childfd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        if error.raw_os_error() == Some(libc::ELOOP) {
            // The original directory was replaced; never clean the new
            // symlink under the old snapshot.
            return Ok(false);
        }
        return Err(error);
    };
    // SAFETY: childfd was returned by openat and ownership moves into File.
    let child = unsafe { fs::File::from_raw_fd(childfd) };
    let actual = fd_stat(child.as_raw_fd())?;
    if !same_inode(&actual, expected) {
        return Ok(false);
    }
    let mut mode = actual.st_mode;
    mode |= 0o200;
    // SAFETY: child is owned by this function.
    let _ = unsafe { libc::fchmod(child.as_raw_fd(), mode) };
    remove_tree_at(child.as_raw_fd())?;
    unlink_if_same(parentfd, name, expected, libc::AT_REMOVEDIR)
}

/// Remove the contents of a possibly read-only directory through a borrowed
/// descriptor. It never resolves a child pathname: symlinks are unlinked and
/// directories are opened with O_NOFOLLOW before recursion. The caller owns
/// the directory itself and may remove it with unlinkat(AT_REMOVEDIR).
pub(crate) fn remove_tree_at(dirfd: RawFd) -> io::Result<()> {
    let stat = fd_stat(dirfd)?;
    if !is_directory(&stat) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not a directory",
        ));
    }
    let mut mode = stat.st_mode;
    mode |= 0o200;
    // SAFETY: dirfd is borrowed by the caller.
    let _ = unsafe { libc::fchmod(dirfd, mode) };
    for name in entry_names_at(dirfd)? {
        remove_tree_entry_at(dirfd, name.as_os_str().as_bytes())?;
    }
    Ok(())
}

/// Remove a possibly read-only staged tree (restore write bits on its
/// directories first). Unlinking a file needs a writable directory, never a
/// writable file, so file modes are left alone: an object's file may be a
/// hard link shared with another object (an assembled Rust toolchain links
/// its base), and removing one name must not change the other.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) -> io::Result<()> {
        let md = fs::symlink_metadata(p)?;
        if !md.is_dir() {
            return Ok(());
        }
        let mut perms = md.permissions();
        perms.set_mode(perms.mode() | 0o200);
        let _ = fs::set_permissions(p, perms);
        for entry in fs::read_dir(p)? {
            unlock(&entry?.path())?;
        }
        Ok(())
    }
    let _ = unlock(path);
    fs::remove_dir_all(path)
}

/// Open an advisory lock without ever following a replacement or symlink at
/// the lock pathname.  The descriptor is also the authority used for the
/// permission change, so a concurrent rename cannot redirect chmod(2).
pub(super) fn open_private_lock(path: &Path, label: &str) -> io::Result<fs::File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("open {label} lock {}: {error}", path.display()),
            )
        })?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} lock {} is not a regular file", path.display()),
        ));
    }
    // SAFETY: `file` is the descriptor just inspected and is owned here.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

/// Open a directory that must be a real one: a symlink or any other file
/// type at `path` is refused, and the open itself follows no symlink. The
/// store, gc and the comforter's projection moves all open this way.
pub(crate) fn open_real_directory(path: &Path, label: &str) -> io::Result<fs::File> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("open {label} {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} is not a real directory", path.display()),
        ));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub(super) fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

pub(super) fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Store-aware copy-on-write clone. The copy utility is a child that reads a
/// store object and writes a managed projection, so its complete spawn/wait
/// interval runs under the caller's operation lease.
pub fn clone_tree_with_activity(
    activity: &StoreActivity,
    src: &Path,
    dest: &Path,
    platform: crate::kernel::platform::Platform,
) -> io::Result<()> {
    let clone = if platform.is_macos() {
        let mut command = std::process::Command::new("/bin/cp");
        command.args(["-Rc"]).arg(src).arg(dest);
        crate::kernel::supervise::local_status(&mut command, activity)?
    } else {
        let mut command = std::process::Command::new("/bin/cp");
        command.args(["-a", "--reflink=auto"]).arg(src).arg(dest);
        crate::kernel::supervise::local_status(&mut command, activity)?
    };
    if !clone.success() {
        if dest.exists() {
            crate::kernel::store::remove_tree(dest)?;
        }
        let mut plain = std::process::Command::new("/bin/cp");
        plain.arg("-R").arg(src).arg(dest);
        let plain_status = crate::kernel::supervise::local_status(&mut plain, activity)?;
        if !plain_status.success() {
            return Err(io::Error::other("cloning projected tree failed"));
        }
    }
    restore_write_bits(dest)
}

/// Give the owner write permission back on every entry of a tree cloned
/// out of the read-only store, without following symlinks.
pub fn restore_write_bits(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    let mode = md.permissions().mode();
    if mode & 0o200 == 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200))?;
    }
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            restore_write_bits(&entry?.path())?;
        }
    }
    Ok(())
}

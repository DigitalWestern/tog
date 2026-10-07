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

/// What is at an object metadata file's name.
pub(crate) enum MetaFile {
    /// A regular file, open for reading.
    File(fs::File),
    Missing,
    /// A symlink, a FIFO, a socket, a directory: anything but a regular file.
    NotRegular,
}

/// Open the metadata file `name` under the held directory `dirfd`. The open
/// follows no symlink and does not block on a FIFO, and the descriptor's own
/// type is checked after it: a stat first could be answered by a regular
/// file that is swapped before the open. Every reader of `meta/<id>.json`
/// opens it here, so none of them can be redirected or hung.
pub(crate) fn open_meta_file_at(dirfd: RawFd, name: &[u8]) -> io::Result<MetaFile> {
    let file = match open_file_at(
        dirfd,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(MetaFile::Missing),
        // A symlink (ELOOP) or a socket (ENXIO on Linux, EOPNOTSUPP on
        // macOS) cannot be opened at all. EACCES is a regular file this user
        // cannot read, or a directory: only the second is about the shape.
        Err(error) => {
            return match error.raw_os_error() {
                Some(libc::ELOOP | libc::ENXIO | libc::EOPNOTSUPP) => Ok(MetaFile::NotRegular),
                Some(libc::EACCES) if !is_regular_at(dirfd, name) => Ok(MetaFile::NotRegular),
                _ => Err(error),
            }
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(MetaFile::NotRegular);
    }
    // O_NONBLOCK was only for the open; a regular-file read must not see
    // EAGAIN from a filesystem that honours it (FUSE).
    // SAFETY: fcntl on a descriptor this function owns.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(MetaFile::File(file))
}

/// Whether `name` under `dirfd` is a regular file, not following a symlink.
/// Only for naming a failed open, so an entry that cannot be stated counts
/// as regular and the open's own error stands.
fn is_regular_at(dirfd: RawFd, name: &[u8]) -> bool {
    let Ok(name) = CString::new(name) else {
        return true;
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: name is NUL-terminated and stat is a valid out-pointer.
    let result = unsafe {
        libc::fstatat(
            dirfd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    // SAFETY: fstatat filled the buffer when it returned 0.
    result != 0 || unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFREG
}

/// Open the directory `name` under `dirfd`, following no symlink.
pub(crate) fn open_directory_at(dirfd: RawFd, name: &[u8]) -> io::Result<fs::File> {
    open_file_at(
        dirfd,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
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

/// A file's identity, device and inode, comparable across `stat` calls.
// `st_dev` is a u64 on Linux but an i32 on macOS: the cast is a no-op
// here and needed there, and clippy only sees the target it runs on.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn stat_identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

/// [`stat_identity`] of an open file.
pub(crate) fn fd_identity(file: &fs::File) -> io::Result<(u64, u64)> {
    Ok(stat_identity(&fd_stat(file.as_raw_fd())?))
}

pub(crate) fn is_directory(stat: &libc::stat) -> bool {
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

    let child = match open_file_at(
        parentfd,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(child) => child,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(false)
        }
        #[cfg(target_os = "linux")]
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let Some(child) = reopen_private_directory(parentfd, name, expected)? else {
                return Ok(false);
            };
            child
        }
        Err(error) => return Err(error),
    };
    let actual = fd_stat(child.as_raw_fd())?;
    if !same_inode(&actual, expected) {
        return Ok(false);
    }
    restore_owner_bits(child.as_raw_fd(), actual.st_mode)?;
    remove_tree_at(child.as_raw_fd())?;
    unlink_if_same(parentfd, name, expected, libc::AT_REMOVEDIR)
}

/// Open an unreadable private directory without resolving a replacement
/// pathname for chmod. O_PATH permits holding it before restoring owner rwx.
#[cfg(target_os = "linux")]
fn reopen_private_directory(
    parent: RawFd,
    name: &[u8],
    expected: &libc::stat,
) -> io::Result<Option<fs::File>> {
    use std::os::unix::fs::PermissionsExt;
    let held = match open_file_at(
        parent,
        name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(held) => held,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let actual = fd_stat(held.as_raw_fd())?;
    if !same_inode(&actual, expected) {
        return Ok(None);
    }
    // The proc magic link refers to this open inode, even after a rename.
    // fchmod itself cannot operate on an O_PATH descriptor.
    fs::set_permissions(
        format!("/proc/self/fd/{}", held.as_raw_fd()),
        fs::Permissions::from_mode(actual.st_mode | 0o700),
    )?;
    let readable = open_file_at(
        held.as_raw_fd(),
        b".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    Ok(Some(readable))
}

/// Add owner rwx to the directory held by `dirfd` so its entries can be
/// listed and unlinked. A directory this user does not own (EPERM) is left
/// as it is: listing it or unlinking from it then fails with the error that
/// actually stops the removal, and a directory that is already writable is
/// still removed.
fn restore_owner_bits(dirfd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: dirfd is borrowed by the caller.
    if unsafe { libc::fchmod(dirfd, mode | 0o700) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EPERM) {
            return Err(error);
        }
    }
    Ok(())
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
    restore_owner_bits(dirfd, stat.st_mode)?;
    for name in entry_names_at(dirfd)? {
        remove_tree_entry_at(dirfd, name.as_os_str().as_bytes())?;
    }
    Ok(())
}

/// Remove a possibly read-only or unreadable staged tree (owner rwx is
/// restored on its directories as they are reached). Unlinking a file needs a writable directory, never a
/// writable file, so file modes are left alone: an object's file may be a
/// hard link shared with another object (an assembled Rust toolchain links
/// its base), and removing one name must not change the other.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    // The tree goes through the same held-descriptor removal GC uses: the
    // parent is opened once, the entry is removed only while it is still
    // the one stat saw, and nothing below it is reached by a pathname. A
    // directory with no read or search permission (mode 000) has its
    // owner bits restored through its own descriptor, a symlink is
    // unlinked and never followed, and file modes are left alone.
    let (parent, name) = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => (parent, name),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} names no directory entry to remove", path.display()),
            ))
        }
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let parent = open_parent(parent)?;
    let expected = stat_at(parent.as_raw_fd(), name.as_bytes())?;
    remove_tree_failpoint();
    if remove_tree_entry_if_same(parent.as_raw_fd(), name.as_bytes(), &expected)? {
        return Ok(());
    }
    // The entry was not removed by this call. If it is simply gone (a
    // concurrent remover got there first), say NotFound, the error callers
    // already tolerate for a tree that is not there. Only an entry that is
    // now a different file is reported as replaced.
    match stat_at(parent.as_raw_fd(), name.as_bytes()) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} was removed by someone else", path.display()),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("{} was replaced while it was removed", path.display()),
        )),
    }
}

#[cfg(test)]
thread_local! {
    /// A test's hook between `remove_tree`'s first stat and the removal, so
    /// a concurrent remover or replacement can be interleaved there.
    static REMOVE_TREE_FAILPOINT: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn remove_tree_failpoint() {
    REMOVE_TREE_FAILPOINT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn remove_tree_failpoint() {}

/// Hold the directory a tree is removed from. Every use of it is a `*at`
/// call relative to it (fstatat, openat, unlinkat), never a listing, so on
/// Linux it is opened O_PATH and a parent without read permission (a
/// search-only `0o311` directory, say) still works.
fn open_parent(parent: &Path) -> io::Result<fs::File> {
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_DIRECTORY | libc::O_CLOEXEC;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(parent)
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

/// `remove_tree` and the cleanups built on it (a commit's rollback of its
/// staged tree, `TempDir` teardown) remove directories with no read or
/// search permission, and never reach through a symlink.
#[cfg(test)]
mod remove_tree_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Under `root`: a mode-000 directory and a search-only one, each
    /// holding a read-only file; a symlink to `outside`; and a hard link to
    /// `shared`, a read-only file outside the tree. `root` itself ends up
    /// mode 000.
    fn plant(root: &Path, outside: &Path, shared: &Path) {
        for (dir, bits) in [("closed", 0o000), ("search-only", 0o100)] {
            let dir = root.join("nested").join(dir);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("file"), "data").unwrap();
            mode(&dir.join("file"), 0o444);
            mode(&dir, bits);
        }
        std::os::unix::fs::symlink(outside, root.join("link")).unwrap();
        fs::hard_link(shared, root.join("shared")).unwrap();
        mode(root, 0o000);
    }

    /// The external symlink target and the hard-linked file survive,
    /// with the file's mode untouched.
    fn assert_outside_kept(outside: &Path, shared: &Path) {
        assert_eq!(fs::read_to_string(outside.join("keep")).unwrap(), "outside");
        assert_eq!(fs::read_to_string(shared).unwrap(), "shared");
        let kept = fs::metadata(shared).unwrap();
        assert_eq!(kept.permissions().mode() & 0o777, 0o444);
        assert_eq!(std::os::unix::fs::MetadataExt::nlink(&kept), 1);
    }

    fn outside(temp: &TempDir) -> (PathBuf, PathBuf) {
        let outside = temp.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), "outside").unwrap();
        let shared = temp.0.join("shared");
        fs::write(&shared, "shared").unwrap();
        mode(&shared, 0o444);
        (outside, shared)
    }

    #[test]
    fn unreadable_and_search_only_directories_are_removed() {
        let temp = TempDir::named("remove-tree-closed");
        let (outside, shared) = outside(&temp);
        let root = temp.0.join("tree");
        fs::create_dir(&root).unwrap();
        plant(&root, &outside, &shared);
        remove_tree(&root).unwrap();
        assert!(fs::symlink_metadata(&root).is_err());
        assert_outside_kept(&outside, &shared);
    }

    #[test]
    fn a_symlink_given_as_the_tree_is_unlinked_not_followed() {
        let temp = TempDir::named("remove-tree-link");
        let (outside, shared) = outside(&temp);
        let link = temp.0.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        remove_tree(&link).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert_outside_kept(&outside, &shared);
    }

    #[test]
    fn a_temp_dir_holding_unreadable_directories_is_torn_down() {
        let keep = TempDir::named("remove-tree-teardown-keep");
        let (outside, shared) = outside(&keep);
        let temp = TempDir::named("remove-tree-teardown");
        let root = temp.0.clone();
        plant(&root, &outside, &shared);
        drop(temp);
        assert!(fs::symlink_metadata(&root).is_err());
        assert_outside_kept(&outside, &shared);
    }

    /// The parent is held O_PATH: removing a tree from a directory this
    /// user may write and search but not list still works.
    #[test]
    fn a_tree_under_an_unlistable_parent_is_removed() {
        let temp = TempDir::named("remove-tree-parent");
        let parent = temp.0.join("parent");
        let tree = parent.join("tree");
        fs::create_dir_all(tree.join("nested")).unwrap();
        fs::write(tree.join("nested/file"), "data").unwrap();
        mode(&parent, 0o300);
        if fs::read_dir(&parent).is_ok() {
            mode(&parent, 0o700);
            eprintln!("skipped: this user lists a 0300 directory (root or CAP_DAC_READ_SEARCH)");
            return;
        }
        let removed = remove_tree(&tree);
        mode(&parent, 0o700);
        removed.unwrap();
        assert!(fs::symlink_metadata(&tree).is_err());
        assert!(parent.is_dir());
    }

    fn with_failpoint<T>(hook: impl FnMut() + 'static, run: impl FnOnce() -> T) -> T {
        REMOVE_TREE_FAILPOINT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let result = run();
        REMOVE_TREE_FAILPOINT.with(|slot| *slot.borrow_mut() = None);
        result
    }

    /// A tree another remover takes away after the first stat is reported
    /// NotFound, the error callers such as the rustfmt scratch cleanup
    /// already tolerate, not as replaced.
    #[test]
    fn a_tree_removed_concurrently_reports_not_found() {
        let temp = TempDir::named("remove-tree-gone");
        let tree = temp.0.join("tree");
        fs::create_dir_all(tree.join("nested")).unwrap();
        let other = tree.clone();
        let error = with_failpoint(
            move || fs::remove_dir_all(&other).unwrap(),
            || remove_tree(&tree),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    }

    /// A tree replaced after the first stat is left alone and reported.
    /// The old tree is moved aside, not removed, so the filesystem cannot
    /// hand its inode number to the replacement (ext4 reuses a freed one
    /// at once, and the replacement would then look like the same tree).
    #[test]
    fn a_tree_replaced_concurrently_is_kept_and_reported() {
        let temp = TempDir::named("remove-tree-replaced");
        let tree = temp.0.join("tree");
        fs::create_dir(&tree).unwrap();
        let other = tree.clone();
        let aside = temp.0.join("tree-old");
        let error = with_failpoint(
            move || {
                fs::rename(&other, &aside).unwrap();
                fs::create_dir(&other).unwrap();
                fs::write(other.join("new"), "kept").unwrap();
            },
            || remove_tree(&tree),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted, "{error}");
        assert_eq!(fs::read_to_string(tree.join("new")).unwrap(), "kept");
    }

    /// A commit that finds its object already published (a cache hit)
    /// rolls its staged tree back with `remove_tree`.
    #[test]
    fn a_cache_hit_rolls_back_an_unreadable_staged_tree() {
        let temp = TempDir::named("remove-tree-rollback");
        let (outside, shared) = outside(&temp);
        let store = Store::open_at(&temp.0.join("store")).unwrap();
        let id = store.publish_bare_test("rollback", "1");
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let staged = store.stage_with_activity(&activity).unwrap();
        fs::create_dir(staged.join("tree")).unwrap();
        plant(&staged.join("tree"), &outside, &shared);
        let identity = crate::kernel::types::Identity {
            kind: "test".into(),
            name: "rollback".into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        assert_eq!(identity.object_id(), id);
        store
            .commit_with_activity_and_deps(&activity, &identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        assert!(fs::symlink_metadata(&staged).is_err());
        assert_outside_kept(&outside, &shared);
    }
}

//! `blanket x <tool>`: run a tool from a registry without adding it to the
//! project, cached forever (CLI.md 2.4). A synthetic single-requirement
//! plan goes through the ordinary realize path, so the environment is an
//! input-addressed store object; the second run is a store hit. Each tool
//! gets a tiny project directory under `~/.blanket/x/` holding the
//! projection and its closure, which registers it as a gc root like any
//! other project.

use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

use sha2::{Digest, Sha224, Sha256, Sha512};

use crate::comforter;
use crate::commands::inspect;
use crate::kernel::context::Context;
use crate::kernel::fetch;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store::{self, RootEntry, Store};
use crate::kernel::ui;
use crate::tailors::node;
use crate::tailors::python;
use crate::tailors::python::pypi;
use crate::tailors::python::pyselect;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `python` or `node`, when the spelling or a flag decided it.
    pub ecosystem: Option<String>,
    /// The package providing the tool, when its name differs.
    pub from: Option<String>,
    /// `tool` or `tool@version`.
    pub tool: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanRequest {
    pub ecosystem: Option<String>,
    pub from: Option<String>,
    pub tool: Option<String>,
}

const X_REQUEST_FILE: &str = ".blanket/x.json";
const X_LOCKS_DIR: &str = ".locks";

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// `ruff@0.6.1` → (`ruff`, Some(`0.6.1`)); `@scope/cli@2` keeps its scope.
pub fn split_version(text: &str) -> (&str, Option<&str>) {
    match text.rfind('@') {
        Some(0) | None => (text, None),
        Some(index) => (&text[..index], Some(&text[index + 1..])),
    }
}

/// The executable name a package installs, by convention: the package
/// name without an npm scope.
fn default_bin(package: &str) -> &str {
    package.rsplit_once('/').map_or(package, |(_, name)| name)
}

fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn home() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| other("x: HOME is not set; set HOME to an absolute directory"))?;
    if !home.is_absolute() {
        return Err(other(format!(
            "x: HOME must be an absolute directory, got {}; refusing to use it",
            home.display()
        )));
    }
    Ok(home)
}

fn x_root_name(
    store: &Store,
    platform: Platform,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
) -> String {
    let key = hex::encode(Sha256::digest(
        format!(
            "x/2\0{}\0{ecosystem}\0{package}\0{}\0{}",
            store.root.display(),
            version.unwrap_or(""),
            platform.triple()
        )
        .as_bytes(),
    ));
    format!(
        "{}-{}-{}",
        if ecosystem == "python" { "py" } else { "npm" },
        safe(package),
        &key[..16]
    )
}

fn ensure_x_metadata_dir(root: &Path) -> io::Result<()> {
    if root
        .file_name()
        .is_some_and(|name| name.as_bytes().first() == Some(&b'.'))
    {
        return Err(other(format!(
            "x: environment root {} may not start with '.'",
            root.display()
        )));
    }
    if let Ok(metadata) = fs::symlink_metadata(root) {
        if metadata.file_type().is_symlink() {
            return Err(other(format!(
                "x: environment root {} is a symlink; refusing to use it",
                root.display()
            )));
        }
    }
    fs::create_dir_all(root)?;
    let metadata_dir = root.join(".blanket");
    if let Ok(metadata) = fs::symlink_metadata(&metadata_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(other(format!(
                "x: metadata directory {} is not a private directory",
                metadata_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(&metadata_dir)?;
    }
    Ok(())
}

fn ensure_x_locks_dir(x_dir: &Path) -> io::Result<PathBuf> {
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
    let locks = x_dir.join(X_LOCKS_DIR);
    if let Ok(metadata) = fs::symlink_metadata(&locks) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(other(format!(
                "x: lock directory {} is not a private directory",
                locks.display()
            )));
        }
    } else {
        match fs::create_dir(&locks) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let mut permissions = fs::metadata(&locks)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&locks, permissions)?;
    Ok(locks.canonicalize()?)
}

fn fd_set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY: fcntl operates on the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: fcntl operates on the caller-owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fd_identity(file: &fs::File) -> io::Result<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn stat_at(dirfd: RawFd, name: &[u8]) -> io::Result<libc::stat> {
    let name = CString::new(name).map_err(|_| {
        other(
            "x: directory entry contains NUL; refusing to clean; \
             remove the offending entry from ~/.blanket/x by hand",
        )
    })?;
    // SAFETY: stat is initialized by fstatat before it is read, and name is
    // NUL-terminated for the duration of the call.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: dirfd is borrowed for the duration of this call.
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn stat_identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

fn stat_is_real_directory(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

fn open_directory_at(dirfd: RawFd, name: &[u8]) -> io::Result<fs::File> {
    let name = CString::new(name).map_err(|_| {
        other(
            "x: directory entry contains NUL; refusing to clean; \
             remove the offending entry from ~/.blanket/x by hand",
        )
    })?;
    // SAFETY: name is NUL-terminated for this call and dirfd is borrowed.
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly opened and ownership moves to the File.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// Open an absolute directory one component at a time, refusing symlinks at
/// every component. The final identity is checked by the caller against the
/// directory that was validated before this open.
fn open_directory_path(path: &Path) -> io::Result<fs::File> {
    if !path.is_absolute() {
        return Err(other(format!(
            "x: cleanup directory {} is not absolute; refusing to clean",
            path.display()
        )));
    }
    let root = CString::new("/").expect("literal has no NUL");
    // SAFETY: root is NUL-terminated and the flags request a directory fd
    // that cannot follow a symlink.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut directory = unsafe { fs::File::from_raw_fd(fd) };
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
        let next = open_directory_at(directory.as_raw_fd(), name.as_bytes())?;
        directory = next;
    }
    Ok(directory)
}

fn ensure_x_locks_dir_at(x_dir_fd: RawFd) -> io::Result<fs::File> {
    let locks = match stat_at(x_dir_fd, X_LOCKS_DIR.as_bytes()) {
        Ok(stat) => {
            if !stat_is_real_directory(&stat) {
                return Err(other(
                    "x: lock directory is not a private directory; refusing to clean",
                ));
            }
            open_directory_at(x_dir_fd, X_LOCKS_DIR.as_bytes())?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = CString::new(X_LOCKS_DIR).expect("literal has no NUL");
            // SAFETY: x_dir_fd is borrowed and name is NUL-terminated.
            if unsafe { libc::mkdirat(x_dir_fd, name.as_ptr(), 0o700) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            open_directory_at(x_dir_fd, X_LOCKS_DIR.as_bytes())?
        }
        Err(error) => return Err(error),
    };
    // SAFETY: the descriptor is owned by the returned File.
    if unsafe { libc::fchmod(locks.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(locks)
}

fn x_root_lock_name(root_name: &OsString) -> io::Result<CString> {
    CString::new(format!("{}.lock", root_name.to_string_lossy()))
        .map_err(|_| other("x: environment root has an invalid lock name"))
}

/// A successful cleanup unlinks the lock file it holds, so `.locks` stays
/// bounded. That means a waiter can be handed a lock on an inode the lock
/// pathname no longer names, which would protect nothing. Every acquisition
/// therefore re-checks the pathname against the locked inode and retries.
const LOCK_ATTEMPTS: usize = 8;

/// Open the stable per-environment advisory lock relative to an already-open
/// x directory. Cleanup uses this path so renaming the pathname cannot make
/// its lock refer to a different environment.
fn lock_x_root_at(
    x_dir_fd: RawFd,
    root_name: &OsString,
    exclusive: bool,
    nonblocking: bool,
) -> io::Result<Option<fs::File>> {
    let lock_name = x_root_lock_name(root_name)?;
    for _ in 0..LOCK_ATTEMPTS {
        let locks = ensure_x_locks_dir_at(x_dir_fd)?;
        // SAFETY: the name is NUL-terminated and locks is owned by this loop.
        let fd = unsafe {
            libc::openat(
                locks.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is newly opened and ownership moves to the File.
        let file = unsafe { fs::File::from_raw_fd(fd) };
        // SAFETY: the descriptor is owned by file.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
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
            return Err(error);
        }
        match stat_at(locks.as_raw_fd(), lock_name.to_bytes()) {
            Ok(stat) if stat_identity(&stat) == fd_identity(&file)? => return Ok(Some(file)),
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
/// and the identity re-check in the lock helpers keeps that safe.
fn remove_x_root_lock_at(x_dir_fd: RawFd, root_name: &OsString) -> io::Result<()> {
    let locks = ensure_x_locks_dir_at(x_dir_fd)?;
    let lock_name = x_root_lock_name(root_name)?;
    // SAFETY: locks is an open directory and the name is NUL-terminated.
    if unsafe { libc::unlinkat(locks.as_raw_fd(), lock_name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    Ok(())
}

/// Open the stable per-environment advisory lock. A shared lock remains
/// close-on-exec during resolution and realization; run clears that flag only
/// immediately before exec so a running tool keeps cleanup out.
fn lock_x_root(root: &Path, exclusive: bool, nonblocking: bool) -> io::Result<Option<fs::File>> {
    let x_dir = root.parent().ok_or_else(|| {
        other(format!(
            "x: environment root {} has no parent",
            root.display()
        ))
    })?;
    let locks = ensure_x_locks_dir(x_dir)?;
    let root_name = root.file_name().ok_or_else(|| {
        other(format!(
            "x: environment root {} has no name",
            root.display()
        ))
    })?;
    let path = locks.join(format!("{}.lock", root_name.to_string_lossy()));
    for _ in 0..LOCK_ATTEMPTS {
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(other(format!(
                    "x: lock file {} is a symlink; refusing to use it",
                    path.display()
                )));
            }
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&path, permissions)?;
        let mut operation = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        if nonblocking {
            operation |= libc::LOCK_NB;
        }
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
                format!("lock {}: {error}", path.display()),
            ));
        }
        fd_set_cloexec(file.as_raw_fd(), true)?;
        // A cleanup that removed this environment unlinked its lock file
        // while holding the lock. Waking up on an unlinked inode would
        // protect nothing, so acquire again against the current file.
        match fs::symlink_metadata(&path) {
            Ok(metadata) if (metadata.dev(), metadata.ino()) == fd_identity(&file)? => {
                return Ok(Some(file));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        drop(file);
    }
    Err(other(format!(
        "x: lock file {} kept being replaced while it was acquired; retry later",
        path.display()
    )))
}

fn acquire_x_root(root: &Path) -> io::Result<fs::File> {
    let lock =
        lock_x_root(root, false, false)?.expect("blocking shared x lock always returns a file");
    // The lock is acquired before inspecting or creating the projection. A
    // cleanup that won the race can therefore remove the old root safely.
    ensure_x_metadata_dir(root)?;
    Ok(lock)
}

#[cfg(test)]
fn write_x_request(
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
) -> io::Result<()> {
    write_x_request_inner(root, ecosystem, package, version, state, None)
}

fn write_x_request_for_store(
    root: &Path,
    store: &Store,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
) -> io::Result<()> {
    write_x_request_inner(root, ecosystem, package, version, state, Some(&store.root))
}

fn write_x_request_inner(
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
    store_root: Option<&Path>,
) -> io::Result<()> {
    let path = root.join(X_REQUEST_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(other(format!(
                "x: request record {} is not a regular file; refusing to overwrite it",
                path.display()
            )));
        }
    }
    let tmp = root
        .join(".blanket")
        .join(format!(".x.json.tmp.{}", std::process::id()));
    let mut record = serde_json::json!({
        "schema": if store_root.is_some() { "x-request/2" } else { "x-request/1" },
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "state": state,
    });
    if let Some(store_root) = store_root {
        record["store_root"] = serde_json::Value::String(store_root.display().to_string());
    }
    fs::write(&tmp, serde_json::to_vec_pretty(&record)?)?;
    fs::rename(tmp, path)
}

fn choose_ecosystem(request: &Request, cwd: &Path) -> io::Result<&'static str> {
    if request.ecosystem.is_some() {
        return choose_from_project(request, &[]);
    }
    for dir in cwd.ancestors() {
        let present = inspect::detected(dir)?;
        if !present.is_empty() {
            return choose_from_project(request, &present);
        }
        // An existing blanket metadata directory is an explicit project
        // boundary, even when the project currently has no manifest. This
        // prevents an unrelated package in an outer checkout from deciding
        // `x`'s registry.
        if dir.join(".blanket").is_dir() {
            break;
        }
    }
    Err(other(format!(
        "x: say which registry provides '{}': 'blanket x py:{0}' (PyPI) or 'blanket x npm:{0}' (npm)",
        request.tool
    )))
}

fn choose_from_project(request: &Request, present: &[&str]) -> io::Result<&'static str> {
    if let Some(name) = request.ecosystem.as_deref() {
        return match name {
            "python" => Ok("python"),
            "node" => Ok("node"),
            other_name => Err(other(format!("x: unsupported ecosystem '{other_name}'"))),
        };
    }
    let python = present.contains(&"python");
    let node = present.contains(&"node");
    match (python, node) {
        (true, true) => Err(other(
            "x: both Python and Node projects are present; choose explicitly with --py or --npm",
        )),
        (true, false) => {
            ui::trace("x: Python, because this project has a Python manifest");
            Ok("python")
        }
        (false, true) => {
            ui::trace("x: npm, because this project has a package.json");
            Ok("node")
        }
        (false, false) => Err(other(format!(
            "x: say which registry provides '{}': 'blanket x py:{0}' (PyPI) or 'blanket x npm:{0}' (npm)",
            request.tool
        ))),
    }
}

fn validate_text(label: &str, value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || value.chars().any(char::is_whitespace)
        || value.starts_with('-')
    {
        return Err(other(format!("x: invalid {label} '{value}'")));
    }
    Ok(())
}

fn validate_package(ecosystem: &str, package: &str) -> io::Result<()> {
    validate_text("package", package)?;
    if package.starts_with('/')
        || package.contains('\\')
        || package
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || (ecosystem == "python" && package.contains('/'))
    {
        return Err(other(format!("x: invalid package '{package}'")));
    }
    Ok(())
}

fn validate_version(version: &str) -> io::Result<()> {
    validate_text("version", version)
}

/// Whether `version` is the exact release syntax accepted for a delegated
/// package-manager tool: MAJOR.MINOR.PATCH with an optional prerelease.
/// Build metadata is deliberately excluded because Corepack's hash suffix is
/// handled separately by the package-manager field parser.
pub(crate) fn is_exact_version(version: &str) -> bool {
    fn decimal_component(value: &str) -> bool {
        !value.is_empty()
            && (value.len() == 1 || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
    }

    let (release, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(a, b)| (a, Some(b)));
    let components: Vec<&str> = release.split('.').collect();
    if components.len() != 3 || !components.iter().all(|part| decimal_component(part)) {
        return false;
    }
    let Some(prerelease) = prerelease else {
        return true;
    };
    !prerelease.is_empty()
        && prerelease.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier.len() == 1
                    || !identifier.starts_with('0'))
        })
}

fn validate_exact_version(version: &str) -> io::Result<()> {
    if !is_exact_version(version) {
        return Err(other(format!(
            "x: node tool version must be an exact MAJOR.MINOR.PATCH release (a prerelease suffix is allowed), found {version:?}"
        )));
    }
    Ok(())
}

fn validate_from_bin(bin: &str) -> io::Result<()> {
    if bin.is_empty()
        || bin == "."
        || bin == ".."
        || !bin
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ".-_".contains(ch))
    {
        return Err(other("x: --from requires a single safe executable name"));
    }
    Ok(())
}

fn canonical_link_target(path: &Path) -> Option<PathBuf> {
    let target = fs::read_link(path).ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        path.parent()?.join(target)
    };
    target.canonicalize().ok()
}

fn encoded_workspace(workspace: &str) -> Option<String> {
    if workspace.is_empty()
        || workspace
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(workspace.replace('%', "%25").replace('/', "%2F"))
}

fn check_projection_target(
    store: &Store,
    root: &Path,
    ecosystem: &str,
    closure: &serde_json::Value,
    env_path: &Path,
) -> io::Result<()> {
    let missing = || {
        other(format!(
            "x: cached {ecosystem} projection is missing or points elsewhere; run the command again"
        ))
    };
    match ecosystem {
        "python" => {
            if canonical_link_target(&root.join(".venv")) != Some(env_path.to_path_buf()) {
                return Err(missing());
            }
        }
        "node" => {
            if closure["projection_schema"] != "node-forest/2" {
                return Err(missing());
            }
            let projection_id = closure["projection_id"].as_str().ok_or_else(missing)?;
            if projection_id.is_empty() || !projection_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(missing());
            }
            let project_key =
                hex::encode(Sha256::digest(root.canonicalize()?.as_os_str().as_bytes()));
            // New projections are owned by the originating store. Keep a
            // read-only compatibility candidate for pre-root/2 x records,
            // whose forest lived beside the store under blanket home.
            let mut forest_bases = vec![store.root.join("forests")];
            if let Some(home) = store.root.parent() {
                let legacy = home.join("forests");
                if legacy != forest_bases[0] {
                    forest_bases.push(legacy);
                }
            }
            let workspaces = closure["workspaces"].as_array();
            let found = forest_bases
                .into_iter()
                .map(|base| base.join(&project_key[..32]).join(projection_id))
                .any(|projection| {
                    let Some(expected) = projection.join("node_modules").canonicalize().ok() else {
                        return false;
                    };
                    if canonical_link_target(&root.join("node_modules")) != Some(expected) {
                        return false;
                    }
                    workspaces.is_none_or(|workspaces| {
                        workspaces.iter().all(|workspace| {
                            let Some(source) = workspace.as_str() else {
                                return false;
                            };
                            let Some(encoded) = encoded_workspace(source) else {
                                return false;
                            };
                            let Some(expected) = projection
                                .join("workspaces")
                                .join(encoded)
                                .join("node_modules")
                                .canonicalize()
                                .ok()
                            else {
                                return false;
                            };
                            canonical_link_target(&root.join(source).join("node_modules"))
                                == Some(expected)
                        })
                    })
                });
            if !found {
                return Err(missing());
            }
        }
        _ => {}
    }
    Ok(())
}

/// A cached `x` projection bypasses the normal realization functions. Check
/// both the persisted closure and the store metadata before executing it, so
/// a stricter policy cannot be bypassed by a previously realized tool.
fn cached_projection(
    store: &Store,
    root: &Path,
    ecosystem: &str,
) -> io::Result<(serde_json::Value, String)> {
    let closure = comforter::read_closure(root, ecosystem)?;
    let path_text = closure["env_object"].as_str().ok_or_else(|| {
        other("x: cached closure has no environment object; run the command again")
    })?;
    let path = PathBuf::from(path_text);
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .map(str::to_owned)
        .ok_or_else(|| {
            other(
                "x: cached closure has a malformed environment object; \
                 run the command again to rebuild it",
            )
        })?;
    if path != store.object_path(&id) || !store.has(&id)? {
        return Err(other(
            "x: cached environment object is missing or outside the active store; run the command again",
        ));
    }
    let env_path = path.canonicalize().map_err(|_| {
        other(
            "x: cached environment object is unavailable; \
             run the command again to rebuild it",
        )
    })?;
    check_projection_target(store, root, ecosystem, &closure, &env_path)?;
    Ok((closure, id))
}

fn check_cached_projection(store: &Store, root: &Path, ecosystem: &str) -> io::Result<()> {
    let (closure, id) = cached_projection(store, root, ecosystem)?;
    policy::check_cached(store, &id)?;

    let persisted: Vec<policy::Exception> = if closure["exceptions"].is_null() {
        Vec::new()
    } else {
        serde_json::from_value(closure["exceptions"].clone())
            .map_err(|error| other(format!("x: invalid cached closure exceptions: {error}")))?
    };
    policy::check_exception_set(&id, &persisted)?;
    let object_exceptions = store.exceptions(&id)?;
    for exception in persisted {
        if !object_exceptions.contains(&exception) {
            policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct XRecord {
    ecosystem: String,
    package: String,
    version: Option<String>,
    state: Option<String>,
    store_root: Option<PathBuf>,
}

#[derive(Debug)]
struct CleanFilter {
    ecosystem: Option<String>,
    package: Option<String>,
    version: Option<String>,
}

struct XCandidate {
    path: PathBuf,
    name: OsString,
    /// The shared `~/.blanket/x` descriptor, not a per-candidate clone. It is
    /// the same directory for every candidate and is only ever read from, so
    /// cloning it per entry cost one extra descriptor each and put a large
    /// `~/.blanket/x` against the process descriptor limit before cleanup had
    /// removed anything.
    x_dir: Rc<fs::File>,
    directory: fs::File,
    identity: (u64, u64),
}

fn read_x_request(root: &Path) -> Option<XRecord> {
    let path = root.join(X_REQUEST_FILE);
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .ok()?;
    let stat = file.metadata().ok()?;
    if !stat.is_file() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_reader(file).ok()?;
    Some(XRecord {
        ecosystem: value.get("ecosystem")?.as_str()?.to_string(),
        package: value.get("package")?.as_str()?.to_string(),
        version: value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        state: value
            .get("state")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        store_root: value
            .get("store_root")
            .and_then(|value| value.as_str().map(PathBuf::from)),
    })
    .filter(|_| {
        matches!(
            value.get("schema").and_then(serde_json::Value::as_str),
            Some("x-request/1" | "x-request/2")
        )
    })
}

fn clean_filter(request: CleanRequest) -> io::Result<CleanFilter> {
    let Some(tool) = request.tool else {
        if request.from.is_some() {
            return Err(other("x: --clean --from requires a tool name"));
        }
        return Ok(CleanFilter {
            ecosystem: request.ecosystem,
            package: None,
            version: None,
        });
    };
    let (tool, tool_version) = split_version(&tool);
    let (package, from_version) = request.from.as_deref().map_or((tool, None), split_version);
    let version = match (from_version, tool_version) {
        (Some(from), Some(tool)) if from != tool => {
            return Err(other(
                "x: --from package version conflicts with the tool version; specify only one or use the same version",
            ));
        }
        (Some(from), _) => Some(from),
        (_, tool) => tool,
    };
    Ok(CleanFilter {
        ecosystem: request.ecosystem,
        package: Some(package.to_string()),
        version: version.map(str::to_string),
    })
}

fn safe_x_root(root: &Path, x_dir: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(root).ok()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    let metadata_dir = root.join(".blanket");
    let metadata = fs::symlink_metadata(&metadata_dir).ok()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    let canonical = root.canonicalize().ok()?;
    if canonical.parent() != Some(x_dir) {
        return None;
    }
    Some(canonical)
}

/// Resolve a user-controlled ancestor of the cleanup anchor. `$HOME` and
/// `~/.blanket` are routinely symlinks (the usual "move the cache off the
/// root disk" setup) and `blanket x` follows them when it creates and
/// registers a root, so cleanup follows them too — otherwise it could never
/// remove what the runner just made. Containment is carried by the no-follow
/// component walk below the resolved anchor and by the descriptor identity
/// checks, not by refusing a symlinked ancestor.
fn canonical_real_directory(path: &Path, label: &str) -> io::Result<Option<PathBuf>> {
    let canonical = match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(other(format!(
                "x: could not resolve {label} {}: {error}",
                path.display()
            )));
        }
    };
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        other(format!(
            "x: could not inspect {label} {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(other(format!(
            "x: {label} {} is not a directory; refusing to clean",
            path.display()
        )));
    }
    Ok(Some(canonical))
}

/// The final `x` component is checked without following it, matching the
/// runner's own `ensure_x_locks_dir` check, so both commands accept and
/// refuse exactly the same layouts.
fn existing_real_directory(path: &Path, label: &str) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(other(format!(
            "x: {label} {} is a symlink; refusing to clean",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_dir() => Err(other(format!(
            "x: {label} {} is not a directory; refusing to clean",
            path.display()
        ))),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(other(format!(
            "x: could not inspect {label} {}: {error}",
            path.display()
        ))),
    }
}

/// Return the canonical cleanup anchor. The home chain (`$HOME` and
/// `~/.blanket`) is resolved the way the runner resolves it and the result
/// must be a real directory; the final `x` component is never followed.
/// Missing `.blanket` or `x` means there is nothing to clean; an existing
/// unsafe component is an error.
#[derive(Debug)]
struct ValidatedXDir {
    path: PathBuf,
    directory: fs::File,
}

fn validated_x_dir(x_dir: &Path) -> io::Result<Option<ValidatedXDir>> {
    if !x_dir.is_absolute() {
        return Err(other(format!(
            "x: cleanup directory {} is not absolute; refusing to clean",
            x_dir.display()
        )));
    }
    let blanket_dir = x_dir.parent().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no .blanket parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let home_dir = blanket_dir.parent().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no HOME parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let blanket_name = blanket_dir.file_name().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no .blanket parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let x_name = x_dir.file_name().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no name; refusing to clean",
            x_dir.display()
        ))
    })?;
    let Some(home_canonical) = canonical_real_directory(home_dir, "HOME")? else {
        return Err(other(format!(
            "x: HOME directory {} does not exist; refusing to clean",
            home_dir.display()
        )));
    };
    let Some(blanket_canonical) =
        canonical_real_directory(&home_canonical.join(blanket_name), "$HOME/.blanket")?
    else {
        return Ok(None);
    };
    // Below the resolved home chain nothing is followed: the `x` component
    // must be a real directory and `open_directory_path` walks the canonical
    // path one no-follow component at a time.
    let canonical = blanket_canonical.join(x_name);
    if !existing_real_directory(&canonical, "$HOME/.blanket/x")? {
        return Ok(None);
    }
    let expected = fs::symlink_metadata(&canonical)?;
    let directory = open_directory_path(&canonical)?;
    let actual = fd_identity(&directory)?;
    if actual != (expected.dev(), expected.ino()) {
        return Err(other(format!(
            "x: cleanup directory {} changed while it was being opened; retry later",
            canonical.display()
        )));
    }
    Ok(Some(ValidatedXDir {
        path: canonical,
        directory,
    }))
}

fn has_safe_closures(root: &Path) -> bool {
    fs::symlink_metadata(root.join(".blanket/closures"))
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn x_candidates(x_dir: &Path) -> io::Result<Vec<XCandidate>> {
    let Some(validated) = validated_x_dir(x_dir)? else {
        return Ok(Vec::new());
    };
    let mut candidates = Vec::new();
    let shared_x_dir = Rc::new(validated.directory);
    for name in store::read_dir_names_at(shared_x_dir.as_raw_fd())? {
        if name.as_bytes().first() == Some(&b'.') {
            continue;
        }
        let path = validated.path.join(&name);
        let metadata = match stat_at(shared_x_dir.as_raw_fd(), name.as_bytes()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !stat_is_real_directory(&metadata) {
            continue;
        }
        let Some(canonical) = safe_x_root(&path, &validated.path) else {
            continue;
        };
        let directory = match open_directory_at(shared_x_dir.as_raw_fd(), name.as_bytes()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => continue,
            Err(error) => return Err(error),
        };
        if fd_identity(&directory)? != stat_identity(&metadata) {
            continue;
        }
        let marker = match stat_at(directory.as_raw_fd(), b".blanket") {
            Ok(marker) if stat_is_real_directory(&marker) => true,
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        if !marker {
            continue;
        }
        // The marker is written before realization, so it is also ownership
        // evidence for a root that failed before it could write a closure or
        // register itself with a store.
        if read_x_request(&canonical).is_none() && !has_safe_closures(&canonical) {
            continue;
        }
        candidates.push(XCandidate {
            path: canonical,
            name,
            x_dir: Rc::clone(&shared_x_dir),
            directory,
            identity: stat_identity(&metadata),
        });
    }
    Ok(candidates)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateMatch {
    Match,
    NoMatch,
    Unrecoverable,
}

#[derive(Debug)]
struct LegacyPackage {
    package: String,
    version: Option<String>,
}

/// Ecosystem recovered from a legacy generated manifest, for a root that
/// carries no recorded request. The matcher and the summary must read this
/// the same way: a legacy root that parses as both would otherwise be matched
/// for deletion as one ecosystem and reported to the user as the other.
fn recovered_legacy_ecosystem(path: &Path) -> Option<&'static str> {
    if legacy_packages(path, "python").is_some() {
        Some("python")
    } else if legacy_packages(path, "node").is_some() {
        Some("node")
    } else {
        None
    }
}

fn legacy_packages(path: &Path, ecosystem: &str) -> Option<Vec<LegacyPackage>> {
    match ecosystem {
        "python" => {
            let text = fs::read_to_string(path.join("requirements.in")).ok()?;
            let first = text.lines().next()?.trim();
            if first.is_empty() {
                return None;
            }
            let (package, version) = match first.split_once("==") {
                Some((package, version)) if !package.is_empty() && !version.is_empty() => {
                    (package, Some(version.to_string()))
                }
                None => (first, None),
                _ => return None,
            };
            if package.chars().any(char::is_whitespace) {
                return None;
            }
            Some(vec![LegacyPackage {
                package: package.to_string(),
                version,
            }])
        }
        "node" => {
            let text = fs::read_to_string(path.join("package.json")).ok()?;
            let value: serde_json::Value = serde_json::from_str(&text).ok()?;
            let dependencies = value.get("dependencies")?.as_object()?;
            let mut packages = Vec::with_capacity(dependencies.len());
            for (package, version) in dependencies {
                let version = version.as_str()?.to_string();
                packages.push(LegacyPackage {
                    package: package.clone(),
                    version: Some(version),
                });
            }
            Some(packages)
        }
        _ => None,
    }
}

fn old_root_matches(path: &Path, filter: &CleanFilter) -> CandidateMatch {
    let Some(package) = filter.package.as_deref() else {
        let Some(ecosystem) = filter.ecosystem.as_deref() else {
            return CandidateMatch::Match;
        };
        let name_ecosystem = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| {
                if name.starts_with("py-") {
                    Some("python")
                } else if name.starts_with("npm-") {
                    Some("node")
                } else {
                    None
                }
            });
        let recovered_ecosystem = recovered_legacy_ecosystem(path).or(name_ecosystem);
        return match recovered_ecosystem {
            Some(recovered) if recovered == ecosystem => CandidateMatch::Match,
            Some(_) => CandidateMatch::NoMatch,
            None => CandidateMatch::Unrecoverable,
        };
    };
    let ecosystems: Vec<&str> = filter
        .ecosystem
        .as_deref()
        .map_or_else(|| vec!["python", "node"], |ecosystem| vec![ecosystem]);
    let mut recovered = false;
    for ecosystem in ecosystems {
        let Some(packages) = legacy_packages(path, ecosystem) else {
            continue;
        };
        recovered = true;
        if packages.iter().any(|record| {
            record.package == package
                && filter
                    .version
                    .as_deref()
                    .map_or(true, |version| record.version.as_deref() == Some(version))
        }) {
            return CandidateMatch::Match;
        }
    }
    if recovered {
        CandidateMatch::NoMatch
    } else {
        CandidateMatch::Unrecoverable
    }
}

fn record_matches(record: &XRecord, filter: &CleanFilter) -> bool {
    filter
        .ecosystem
        .as_deref()
        .map_or(true, |ecosystem| ecosystem == record.ecosystem)
        && filter
            .package
            .as_deref()
            .map_or(true, |package| package == record.package)
        && filter
            .version
            .as_deref()
            .map_or(true, |version| Some(version) == record.version.as_deref())
}

/// Best-effort ecosystem of a candidate, used only to word the summary. The
/// recorded request wins, then a recovered legacy manifest, then the
/// generated name prefix.
fn candidate_ecosystem(path: &Path) -> Option<&'static str> {
    if let Some(record) = read_x_request(path) {
        return match record.ecosystem.as_str() {
            "python" => Some("python"),
            "node" => Some("node"),
            _ => None,
        };
    }
    if let Some(recovered) = recovered_legacy_ecosystem(path) {
        return Some(recovered);
    }
    let name = path.file_name().and_then(|name| name.to_str())?;
    if name.starts_with("npm-") {
        Some("node")
    } else if name.starts_with("py-") {
        Some("python")
    } else {
        None
    }
}

fn candidate_matches(candidate: &XCandidate, filter: &CleanFilter) -> CandidateMatch {
    read_x_request(&candidate.path).map_or_else(
        || old_root_matches(&candidate.path, filter),
        |record| {
            if record_matches(&record, filter) {
                CandidateMatch::Match
            } else {
                CandidateMatch::NoMatch
            }
        },
    )
}

/// Decide whether a cached root can be executed as it stands. A `true` answer
/// means the cached projection has already been fully validated here,
/// including its policy exceptions: callers must not validate it a second
/// time or every persisted exception is narrated and queued twice.
fn x_request_is_ready(
    store: &Store,
    root: &Path,
    ecosystem: &str,
    executable: &Path,
) -> io::Result<bool> {
    // x-request/1 records written before lifecycle states were added, and
    // roots without a marker, are legacy complete records when their
    // projection is valid. A realization marker is always incomplete.
    let marker_exists = fs::symlink_metadata(root.join(X_REQUEST_FILE)).is_ok();
    let record = read_x_request(root);
    if marker_exists && record.is_none() {
        return Ok(false);
    }
    if record
        .as_ref()
        .and_then(|record| record.state.as_deref())
        .is_some_and(|state| state != "ready")
    {
        return Ok(false);
    }
    if !executable.is_file() || cached_projection(store, root, ecosystem).is_err() {
        return Ok(false);
    }
    // Keep policy failures as failures. They must not be mistaken for a
    // missing projection and bypassed by a fresh realization.
    check_cached_projection(store, root, ecosystem)?;
    Ok(true)
}

fn x_request_file_exists(root: &Path) -> bool {
    fs::symlink_metadata(root.join(X_REQUEST_FILE)).is_ok()
}

enum Registration {
    Found {
        store: Store,
        entry: RootEntry,
    },
    NotFound,
    #[cfg(test)]
    Unknown,
}

fn originating_store(root: &Path) -> io::Result<Option<Store>> {
    let marker = root.join(X_REQUEST_FILE);
    let marker_present = match fs::symlink_metadata(&marker) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(other(format!(
                    "x: explicit request marker {} is not a regular file",
                    marker.display()
                )));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if marker_present {
        let record = read_x_request(root).ok_or_else(|| {
            other(format!(
                "x: explicit request marker {} is malformed",
                marker.display()
            ))
        })?;
        if let Some(store_root) = record.store_root {
            let store_root = store_root.canonicalize().map_err(|error| {
                other(format!(
                    "x: recorded originating store {} is unavailable: {error}",
                    store_root.display()
                ))
            })?;
            let root_stat = fs::symlink_metadata(&store_root)?;
            let objects = store_root.join("objects");
            let objects_stat = fs::symlink_metadata(&objects)?;
            if root_stat.file_type().is_symlink()
                || !root_stat.is_dir()
                || objects_stat.file_type().is_symlink()
                || !objects_stat.is_dir()
            {
                return Err(other(format!(
                    "x: recorded originating store {} is not a real store",
                    store_root.display()
                )));
            }
            return Ok(Some(Store { root: store_root }));
        }
    }

    let closures = root.join(".blanket/closures");
    let entries = match fs::read_dir(&closures) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut found: Option<Store> = None;
    for entry in entries {
        let entry = entry?;
        let stat = fs::symlink_metadata(entry.path())?;
        if stat.file_type().is_symlink()
            || !stat.is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(entry.path())?;
        let value: serde_json::Value = match serde_json::from_reader(file) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let body = value.get("body").unwrap_or(&value);
        let mut paths = Vec::new();
        collect_legacy_object_references(body, &mut paths);
        for path in paths {
            let Some(store) = comforter::store_from_object_path(&path) else {
                continue;
            };
            let Some(id) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !store::is_object_id(id) || store.object_path(id) != path {
                continue;
            }
            let object_stat = match fs::symlink_metadata(&path) {
                Ok(stat) => stat,
                Err(_) => continue,
            };
            if object_stat.file_type().is_symlink() || !object_stat.is_dir() {
                continue;
            }
            if let Some(previous) = &found {
                if previous.root != store.root {
                    return Err(other(
                        "x: legacy closure references more than one originating store",
                    ));
                }
            } else {
                found = Some(store);
            }
        }
    }
    Ok(found)
}

/// Does this candidate's closure claim any store object at all?
///
/// `originating_store` answers "which store owns this?", and returns `None`
/// both for a projection that names objects nobody can resolve and for one
/// that names nothing. Those are very different: the first is an unresolved
/// ownership claim that cleanup must defer on, the second is an empty shell
/// left by a partial run, which references nothing and can be removed under
/// the x-root lock alone.
fn closure_claims_an_object(root: &Path) -> io::Result<bool> {
    if read_x_request(root)
        .and_then(|record| record.store_root)
        .is_some()
    {
        return Ok(true);
    }
    let closures = root.join(".blanket/closures");
    let entries = match fs::read_dir(&closures) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let stat = fs::symlink_metadata(entry.path())?;
        if stat.file_type().is_symlink()
            || !stat.is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(entry.path())?;
        let value: serde_json::Value = match serde_json::from_reader(file) {
            Ok(value) => value,
            // An unreadable closure is itself an unresolved claim.
            Err(_) => return Ok(true),
        };
        let body = value.get("body").unwrap_or(&value);
        let mut paths = Vec::new();
        collect_legacy_object_references(body, &mut paths);
        for path in paths {
            // The question is what the closure *claims*, not what still
            // resolves. A store that has been moved or deleted makes
            // `store_from_object_path` fail, and that is exactly the case
            // where deleting the projection would be a guess.
            if names_a_store_object(&path) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Structural test for `<any store>/objects/<object-id>`, with no
/// requirement that the store still exists.
fn names_a_store_object(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    path.components()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| {
            let (std::path::Component::Normal(objects), std::path::Component::Normal(id)) =
                (pair[0], pair[1])
            else {
                return false;
            };
            objects == "objects" && id.to_str().is_some_and(store::is_object_id)
        })
}

fn collect_legacy_object_references(value: &serde_json::Value, paths: &mut Vec<PathBuf>) {
    match value {
        serde_json::Value::String(text) => {
            let path = Path::new(text);
            if path.is_absolute() {
                paths.push(path.to_path_buf());
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_legacy_object_references(value, paths);
            }
        }
        serde_json::Value::Object(values) => {
            if let (Some(id), Some(path)) = (
                values.get("id").and_then(serde_json::Value::as_str),
                values.get("path").and_then(serde_json::Value::as_str),
            ) {
                let path = Path::new(path);
                if path.is_absolute()
                    && store::is_object_id(id)
                    && path.file_name() == Some(id.as_ref())
                {
                    paths.push(path.to_path_buf());
                }
            }
            for value in values.values() {
                collect_legacy_object_references(value, paths);
            }
        }
        _ => {}
    }
}

fn registration_for_store(root: &Path, store: Store) -> io::Result<Registration> {
    let canonical = root.canonicalize()?;
    let entry = store.roots()?.into_iter().find(|entry| {
        entry
            .path
            .canonicalize()
            .map_or(false, |path| path == canonical)
    });
    Ok(
        entry.map_or(Registration::NotFound, |entry| Registration::Found {
            store,
            entry,
        }),
    )
}

#[cfg(test)]
fn registration_for(root: &Path) -> io::Result<Registration> {
    let Some(store) = originating_store(root)? else {
        return Ok(Registration::Unknown);
    };
    registration_for_store(root, store)
}

/// Remove cached x projections. The store objects remain available for the
/// ordinary GC pass; deleting a projection is deliberately not object GC.
pub fn clean(request: CleanRequest) -> io::Result<()> {
    let filter = clean_filter(request)?;
    let x_dir = home()?.join(".blanket/x");
    let candidates = x_candidates(&x_dir)?;
    let mut matched = 0usize;
    let mut removed = 0usize;
    let mut skipped = 0usize;
    let mut removed_node = false;
    for candidate in candidates {
        match candidate_matches(&candidate, &filter) {
            CandidateMatch::Match => {}
            CandidateMatch::NoMatch => continue,
            CandidateMatch::Unrecoverable => {
                println!(
                    "blanket: skipped x environment {} (legacy root package could not be recovered; use 'blanket x --clean' with no tool to remove all x environments)",
                    candidate.path.display()
                );
                // A root that was considered and skipped still counts, so a
                // run that skipped everything does not then claim there was
                // nothing to clean.
                matched += 1;
                skipped += 1;
                continue;
            }
        }
        matched += 1;
        let ecosystem = candidate_ecosystem(&candidate.path);
        // Origin metadata is only a hint until the originating store is
        // protected. Never delete an x projection whose store cannot be
        // recovered, and never use the caller's current BLANKET_STORE as a
        // substitute for that provenance.
        let origin = originating_store(&candidate.path)?;
        if origin.is_none() && closure_claims_an_object(&candidate.path)? {
            // An unresolved ownership claim is a named skip, never permission
            // to delete. The caller's current BLANKET_STORE is not evidence
            // about this candidate: the projection can belong to a store that
            // is not the one this invocation happens to be pointed at.
            println!(
                "blanket: skipped x environment {} (it claims store objects whose originating store could not be recovered; restore that store's closure, or remove the directory yourself once you know nothing is using it)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        }
        // An empty projection claims nothing, so there is no originating
        // store to protect and the x-root lock below is the whole guard.
        let unowned = origin.is_none();
        let origin_store = match origin {
            Some(store) => store,
            None => Store::open()?,
        };
        let Some(activity) = origin_store.try_activity_exclusive()? else {
            println!(
                "blanket: skipped x environment {} (in use by a running tool; retry later; originating store is busy)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        };
        let Some(_lock) = lock_x_root_at(candidate.x_dir.as_raw_fd(), &candidate.name, true, true)?
        else {
            println!(
                "blanket: skipped x environment {} (in use by a running tool; retry later)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        };
        let _project_lock = origin_store.project_lock(&candidate.path)?;
        // Re-read the untrusted origin after both guards. A changed marker is
        // a race, not permission to remove the candidate. An unowned
        // projection must still be unowned: gaining a claim while it was
        // being locked is the same race.
        match originating_store(&candidate.path)? {
            Some(revalidated_store) if !unowned => {
                if revalidated_store.root != origin_store.root {
                    println!(
                        "blanket: skipped x environment {} (originating store changed while it was being locked; retry later)",
                        candidate.path.display()
                    );
                    skipped += 1;
                    continue;
                }
            }
            None if unowned && !closure_claims_an_object(&candidate.path)? => {}
            _ => {
                println!(
                    "blanket: skipped x environment {} (origin changed while it was being locked; retry later)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
        }
        let registration = registration_for_store(&candidate.path, origin_store.clone())?;
        let current = match stat_at(candidate.x_dir.as_raw_fd(), candidate.name.as_bytes()) {
            Ok(current) => current,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                println!(
                    "blanket: skipped x environment {} (it disappeared or changed; retry later)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if stat_identity(&current) != candidate.identity || !stat_is_real_directory(&current) {
            println!(
                "blanket: skipped x environment {} (it disappeared or changed; retry later)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        }
        // The candidate descriptor belongs to the directory that passed the
        // containment checks. Removing by pathname here would let a rename
        // followed by a symlink replacement redirect deletion elsewhere.
        store::remove_tree_at(candidate.directory.as_raw_fd())?;
        let current = stat_at(candidate.x_dir.as_raw_fd(), candidate.name.as_bytes())?;
        if stat_identity(&current) != candidate.identity || !stat_is_real_directory(&current) {
            println!(
                "blanket: skipped x environment {} (it disappeared or changed; retry later)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        }
        let name = CString::new(candidate.name.as_bytes())
            .map_err(|_| other("x: environment root has an invalid name"))?;
        // SAFETY: candidate.x_dir is an open directory and name is
        // NUL-terminated for this call.
        if unsafe {
            libc::unlinkat(
                candidate.x_dir.as_raw_fd(),
                name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if ecosystem == Some("node") {
            removed_node = true;
        }
        match registration {
            Registration::Found { store, entry } => {
                store.remove_root_entry_with_activity(&activity, &entry)?;
                println!(
                    "blanket: removed x environment {}",
                    candidate.path.display()
                );
            }
            Registration::NotFound => println!(
                "blanket: removed x environment {} (no matching registry entry in its originating store)",
                candidate.path.display()
            ),
            #[cfg(test)]
            Registration::Unknown => println!(
                "blanket: removed x environment {} (registry entry could not be dropped: originating store not found)",
                candidate.path.display()
            ),
        }
        // Only now has the environment stopped existing anywhere: the tree is
        // gone and so is its registry entry. Unlinking the lock before the
        // registry removal left a window in which a fresh runner could take a
        // new lock on the same name while the originating store still listed
        // the environment as registered. This still runs under the exclusive
        // lock taken above, so `.locks` stays bounded; a later runner
        // recreates the file.
        remove_x_root_lock_at(candidate.x_dir.as_raw_fd(), &candidate.name)?;
        removed += 1;
    }
    if matched == 0 {
        println!("blanket: x clean: nothing to clean");
    } else {
        // A removed node environment also orphans its
        // ~/.blanket/forests/<project-key>/<projection-id> node_modules
        // forest, which plain `blanket gc` never visits.
        let forests = if removed_node {
            ", and 'blanket gc --project' also reclaims the node_modules forest each removed node environment used"
        } else {
            ""
        };
        println!(
            "blanket: x clean removed {removed} environment(s), skipped {skipped}; store objects remain until the next 'blanket gc'{forests}"
        );
    }
    Ok(())
}

/// `blanket x`: `x` has its own cached projection path and therefore does
/// not pass through sync's policy initialization. Load the cwd policy,
/// including all applicable ancestors, before realization or any cache-hit
/// checks.
pub fn run(ctx: &Context, request: Request) -> io::Result<i32> {
    let cwd = ctx.project_dir();
    policy::init(&cwd, false)?;
    launch(ctx.platform, &cwd, request, &ctx.activity)
}

pub fn launch(
    platform: Platform,
    cwd: &Path,
    request: Request,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<i32> {
    let ecosystem = choose_ecosystem(&request, cwd)?;
    let (tool, tool_version) = split_version(&request.tool);
    let (package, from_version) = request.from.as_deref().map_or((tool, None), split_version);
    validate_package(ecosystem, package)?;
    if let Some(version) = tool_version {
        validate_version(version)?;
    }
    if let Some(version) = from_version {
        validate_version(version)?;
    }
    let version = match (from_version, tool_version) {
        (Some(from), Some(tool)) if from != tool => {
            return Err(other(
                "x: --from package version conflicts with the tool version; specify only one or use the same version",
            ));
        }
        (Some(from), _) => Some(from),
        (_, tool) => tool,
    };
    let bin = if request.from.is_some() {
        validate_from_bin(tool)?;
        tool
    } else {
        default_bin(tool)
    };
    if tool.is_empty() || package.is_empty() {
        return Err(other("x: empty tool name"));
    }
    let x_home = home()?;
    let store = Store::open()?;
    store.require_activity(activity, "x")?;
    let root = x_home
        .join(".blanket/x")
        .join(x_root_name(&store, platform, ecosystem, package, version));
    let _x_lock = acquire_x_root(&root)?;
    let (executable, path_prefix, env): (PathBuf, Vec<PathBuf>, Vec<(String, PathBuf)>) =
        match ecosystem {
            "python" => {
                let venv = root.join(".venv");
                let executable = venv.join("bin").join(bin);
                // A pre-state x-request/1 root has no marker but can still
                // be a complete legacy cache. Preserve that cache path only
                // when its projected executable already exists.
                let ready = x_request_is_ready(&store, &root, "python", &executable)?;
                if !ready {
                    write_x_request_for_store(
                        &root,
                        &store,
                        ecosystem,
                        package,
                        version,
                        "realizing",
                    )?;
                    realize_python(&store, activity, platform, &root, package, version)?;
                    write_x_request_for_store(&root, &store, ecosystem, package, version, "ready")?;
                } else {
                    // `x_request_is_ready` already validated this projection
                    // against the store and the active policy. Validating it
                    // again would narrate and queue every persisted exception
                    // twice.
                    if !x_request_file_exists(&root) {
                        write_x_request_for_store(
                            &root, &store, ecosystem, package, version, "ready",
                        )?;
                    }
                }
                if !executable.is_file() {
                    return Err(other(format!(
                        "'{package}' installed but provides no '{bin}' executable; name it with --from: 'blanket x --from {package} <tool>'"
                    )));
                }
                (
                    executable,
                    vec![venv.join("bin")],
                    vec![("VIRTUAL_ENV".to_string(), venv)],
                )
            }
            _ => {
                let node_modules = root.join("node_modules");
                let executable = node_modules.join(".bin").join(bin);
                let ready = x_request_is_ready(&store, &root, "node", &executable)?;
                if !ready {
                    write_x_request_for_store(
                        &root,
                        &store,
                        ecosystem,
                        package,
                        version,
                        "realizing",
                    )?;
                    realize_node(&store, activity, platform, &root, package, version)?;
                    write_x_request_for_store(&root, &store, ecosystem, package, version, "ready")?;
                } else {
                    // Already validated by `x_request_is_ready`; see above.
                    if !x_request_file_exists(&root) {
                        write_x_request_for_store(
                            &root, &store, ecosystem, package, version, "ready",
                        )?;
                    }
                }
                if !executable.is_file() {
                    return Err(other(format!(
                        "'{package}' installed but provides no '{bin}' executable; name it with --from: 'blanket x --from {package} <tool>'"
                    )));
                }
                let node_obj = node::ensure_node_for(&store, platform)?;
                (
                    executable,
                    vec![node_modules.join(".bin"), node_obj.join("bin")],
                    Vec::new(),
                )
            }
        };
    let mut path: Vec<String> = path_prefix
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    path.push(std::env::var("PATH").unwrap_or_default());
    let mut command = Command::new(&executable);
    command.args(&request.args).env("PATH", path.join(":"));
    for (key, value) in env {
        command.env(key, value);
    }
    if ecosystem == "python" {
        command.env("PYTHONDONTWRITEBYTECODE", "1");
    }
    ui::trace_command(&command);
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

fn node_cache_root(
    store: &Store,
    platform: Platform,
    package: &str,
    version: Option<&str>,
) -> io::Result<PathBuf> {
    let key = hex::encode(Sha256::digest(
        format!(
            "x/2\0{}\0node\0{package}\0{}\0{}",
            store.root.display(),
            version.unwrap_or(""),
            platform.triple()
        )
        .as_bytes(),
    ));
    Ok(home()?
        .join(".blanket/x")
        .join(format!("npm-{}-{}", safe(package), &key[..16])))
}

/// The digest algorithms a Corepack `packageManager` hash suffix may name.
/// Corepack has written `+sha224.`, `+sha256.` and (currently) `+sha512.`;
/// the suffix is always lower-case hex, never base64 SRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorepackAlgo {
    Sha224,
    Sha256,
    Sha512,
}

impl CorepackAlgo {
    /// Named verbatim by every refusal that rejects an algorithm.
    pub(crate) const SUPPORTED: &'static str = "sha224, sha256, sha512";

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "sha224" => Some(Self::Sha224),
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Width of the hex digest the suffix must carry.
    pub(crate) fn hex_len(self) -> usize {
        match self {
            Self::Sha224 => 56,
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    fn hex_digest(self, bytes: &[u8]) -> String {
        match self {
            Self::Sha224 => hex::encode(Sha224::digest(bytes)),
            Self::Sha256 => hex::encode(Sha256::digest(bytes)),
            Self::Sha512 => hex::encode(Sha512::digest(bytes)),
        }
    }
}

/// A parsed Corepack hash suffix: the algorithm plus its lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CorepackHash {
    pub(crate) algo: CorepackAlgo,
    pub(crate) hex: String,
}

/// Realize a Node package whose executable is needed by another delegate.
/// This is the same registered `~/.blanket/x/` environment used by
/// `blanket x`, so a delegate's second invocation is a normal cache hit.
pub(crate) fn realize_node_tool(
    store: &Store,
    platform: Platform,
    package: &str,
    version: &str,
    corepack_hash: Option<&CorepackHash>,
) -> io::Result<(PathBuf, fs::File)> {
    validate_exact_version(version)?;
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let root = node_cache_root(store, platform, package, Some(version))?;
    // Take the same shared lifecycle lock `blanket x` takes, and hand it back
    // to the caller. `blanket x --clean` removes a cached root under an
    // exclusive lock, so without this a cleanup running alongside a
    // dependency edit could delete the delegate's environment out from under
    // it. The caller holds the lock for as long as it uses the root.
    let x_lock = acquire_x_root(&root)?;
    let executable = root.join("node_modules/.bin").join(default_bin(package));
    if executable.is_file() {
        check_cached_projection(store, &root, "node")?;
        if let Some(expected) = corepack_hash {
            verify_corepack_hash(store, &root, package, version, expected)?;
        }
        return Ok((root, x_lock));
    }
    realize_node(store, &activity, platform, &root, package, Some(version))?;
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}@{version}' installed but provides no '{package}' executable"
        )));
    }
    if let Some(expected) = corepack_hash {
        verify_corepack_hash(store, &root, package, version, expected)?;
    }
    Ok((root, x_lock))
}

fn verify_corepack_hash(
    store: &Store,
    root: &Path,
    package: &str,
    version: &str,
    expected: &CorepackHash,
) -> io::Result<()> {
    let algo = expected.algo;
    let name = algo.name();
    if expected.hex.len() != algo.hex_len()
        || !expected.hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(other(format!(
            "x: packageManager has a malformed {name} hash for {package}@{version}"
        )));
    }
    let closure = comforter::read_closure(root, "node")?;
    let packages = closure["packages"].as_array().ok_or_else(|| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: realized node closure has no package list; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let pnpm = packages.iter().find(|entry| {
        entry["path"].as_str() == Some("node_modules/pnpm")
            && entry["version"].as_str() == Some(version)
    });
    let Some(pnpm) = pnpm else {
        return Err(other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: realized node closure has no reachable pnpm artifact; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        )));
    };
    let integrity = pnpm["integrity"].as_str().ok_or_else(|| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: pnpm artifact has no integrity and no reachable cache path; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let digest = fetch::Digest::from_sri(integrity).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: pnpm artifact integrity is invalid ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let cache_path = store.cache_path(digest.algo(), digest.hex());
    let bytes = fetch::read_cache_verified_digest(store, &digest).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: verified pnpm artifact cache {} is not reachable ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache",
            cache_path.display()
        ))
    })?;
    let actual = algo.hex_digest(&bytes);
    if actual != expected.hex.to_ascii_lowercase() {
        return Err(other(format!(
            "x: Corepack {name} mismatch for {package}@{version}: packageManager declares {}, cached pnpm tarball has {actual}; nothing runs",
            expected.hex
        )));
    }
    Ok(())
}

fn realize_python(
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    platform: Platform,
    root: &Path,
    package: &str,
    version: Option<&str>,
) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let selection = pyselect::select_python(platform, &[])?;
    let pin = selection.pin;
    let spec = match version {
        Some(version) => format!("{package}=={version}\n"),
        None => format!("{package}\n"),
    };
    let input = root.join("requirements.in");
    let output = root.join("requirements.txt");
    fs::write(&input, &spec)?;
    ui::note(&format!("resolving {} with the store uv...", spec.trim()));
    let uv = python::ensure_uv_for(store, platform)?.join("uv");
    let mut command = Command::new(uv);
    command
        .args(["pip", "compile"])
        .arg(&input)
        .arg("--generate-hashes");
    if !ui::verbose() {
        command.arg("--quiet");
    }
    command
        .args(["--python-version", pin.version])
        .args(["--index-url", "https://pypi.org/simple"])
        .arg("-o")
        .arg(&output)
        .current_dir(root)
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    ui::trace_command(&command);
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    if !status.success() {
        return Err(other(format!(
            "could not resolve '{}' from PyPI (uv pip compile exit {status})",
            spec.trim()
        )));
    }
    let text = fs::read_to_string(&output)?;
    let plan = pypi::plan_python(platform, &text, pin.version)?;
    let env = crate::tailors::python::env::realize_env(store, platform, &plan)?;
    crate::tailors::python::env::project_env_with_selection(root, &env, &plan, &selection)?;
    ui::synced(&format!("x {package}"), &env);
    Ok(())
}

fn realize_node(
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    platform: Platform,
    root: &Path,
    package: &str,
    version: Option<&str>,
) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let manifest = serde_json::json!({
        "name": "blanket-x",
        "private": true,
        "dependencies": { package: version.unwrap_or("latest") },
    });
    fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let lock = root.join("package-lock.json");
    if lock.exists() {
        fs::remove_file(&lock)?;
    }
    ui::note(&format!(
        "resolving {package}@{} with the store npm...",
        version.unwrap_or("latest")
    ));
    let node_obj = node::ensure_node_for(store, platform)?;
    let mut command = Command::new(node_obj.join("bin/npm"));
    command.args(["install", "--package-lock-only", "--ignore-scripts"]);
    if !ui::verbose() {
        command.arg("--silent");
    }
    command.current_dir(root).env(
        "PATH",
        format!(
            "{}:{}",
            node_obj.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );
    ui::trace_command(&command);
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    if !status.success() {
        return Err(other(format!(
            "could not resolve '{package}' from npm (npm exit {status})"
        )));
    }
    let plan = node::plan_npm(platform, &fs::read_to_string(&lock)?)?;
    let env = node::realize_node_env(store, platform, &plan, &[])?;
    node::project_node_env(root, &env, platform, &plan, &[], false)?;
    ui::synced(&format!("x {package}"), &env);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn versions_and_bins() {
        assert_eq!(split_version("ruff"), ("ruff", None));
        assert_eq!(split_version("ruff@0.6.1"), ("ruff", Some("0.6.1")));
        assert_eq!(split_version("@angular/cli"), ("@angular/cli", None));
        assert_eq!(
            split_version("@angular/cli@18"),
            ("@angular/cli", Some("18"))
        );
        assert_eq!(default_bin("@angular/cli"), "cli");
        assert_eq!(default_bin("prettier"), "prettier");
        assert_eq!(safe("@angular/cli"), "_angular_cli");
    }

    #[test]
    fn ecosystem_from_spelling_or_project() {
        let request = |eco: Option<&str>| Request {
            ecosystem: eco.map(str::to_string),
            from: None,
            tool: "ruff".into(),
            args: vec![],
        };
        assert_eq!(
            choose_from_project(&request(Some("python")), &[]).unwrap(),
            "python"
        );
        let error = choose_from_project(&request(None), &[]).unwrap_err();
        assert!(error.to_string().contains("blanket x py:ruff"), "{error}");
        assert_eq!(
            choose_from_project(&request(None), &["node"]).unwrap(),
            "node"
        );
        let error = choose_from_project(&request(None), &["python", "node"]).unwrap_err();
        assert!(
            error.to_string().contains("both Python and Node"),
            "{error}"
        );
    }

    #[test]
    fn from_version_is_split_and_conflicts_are_rejected() {
        let (package, version) = split_version("six@1.17.0");
        assert_eq!((package, version), ("six", Some("1.17.0")));
        let error = validate_package("python", "/tmp/tool").unwrap_err();
        assert!(error.to_string().contains("invalid package"), "{error}");
        assert!(validate_from_bin("../tool").is_err());
        assert!(validate_version("1.0\n--index-url evil").is_err());
    }

    #[test]
    fn shared_x_lock_blocks_nonblocking_cleanup_until_runner_exit() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-lock-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("x").join("py-ruff-test");
        fs::create_dir_all(&root).unwrap();
        let shared = lock_x_root(&root, false, false)
            .unwrap()
            .expect("shared lock");
        let flags = unsafe { libc::fcntl(shared.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert!(lock_x_root(&root, true, true).unwrap().is_none());
        drop(shared);
        // `drop` closes this process's descriptor, but a `flock` lives on the
        // open file description, not on the descriptor. Any sibling test that
        // spawns a child forks the whole descriptor table, so between that
        // `fork` and the `exec` that honours `FD_CLOEXEC` the child holds a
        // second reference to this shared lock. The exclusive try-lock below
        // then loses with `EWOULDBLOCK` through no fault of `lock_x_root`.
        // The window is microseconds wide, so retry briefly; the assertion
        // above still proves the lock blocks while `shared` is held.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let exclusive = loop {
            if let Some(file) = lock_x_root(&root, true, true).unwrap() {
                break Some(file);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            exclusive.is_some(),
            "exclusive lock stayed blocked for two seconds after the shared lock was dropped"
        );
        drop(exclusive);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cleanup_lock_waits_for_runner_recreation() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-lock-race-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("x").join("py-race-test");
        fs::create_dir_all(&root).unwrap();
        let cleanup = lock_x_root(&root, true, false)
            .unwrap()
            .expect("cleanup lock");
        let (ready_tx, ready_rx) = mpsc::channel();
        let runner_root = root.clone();
        let runner = thread::spawn(move || {
            let shared = acquire_x_root(&runner_root).unwrap();
            ready_tx.send(()).unwrap();
            drop(shared);
        });

        assert!(
            ready_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "runner inspected or recreated the root before acquiring its shared lock"
        );
        fs::remove_dir_all(&root).unwrap();
        drop(cleanup);
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("runner did not recreate the root after cleanup released its lock");
        runner.join().unwrap();
        assert!(root.join(".blanket").is_dir());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn fd_relative_removal_does_not_follow_replaced_x_directory() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-remove-fd-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let x_dir = base.join("home/.blanket/x");
        let root = x_dir.join("py-victim-test");
        let victim = base.join("victim");
        fs::create_dir_all(root.join(".blanket/nested")).unwrap();
        fs::write(root.join(".blanket/nested/old"), b"old").unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, root.join("victim-link")).unwrap();

        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        let root_fd =
            open_directory_at(validated.directory.as_raw_fd(), b"py-victim-test").unwrap();
        fs::rename(&x_dir, x_dir.with_extension("old")).unwrap();
        std::os::unix::fs::symlink(&victim, &x_dir).unwrap();

        store::remove_tree_at(root_fd.as_raw_fd()).unwrap();

        assert!(victim.join("keep").is_file());
        assert!(!root.join(".blanket/nested/old").exists());
        drop(root_fd);
        drop(validated);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn dot_prefixed_entries_are_not_x_candidates() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-lock-entry-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let x_dir = base.join("home/.blanket/x");
        let root = x_dir.join("py-active");
        fs::create_dir_all(root.join(".blanket/closures")).unwrap();
        let shared = lock_x_root(&root, false, false)
            .unwrap()
            .expect("active root shared lock");
        let lock_path = x_dir.join(".locks/py-active.lock");
        assert!(lock_path.is_file());
        fs::create_dir_all(x_dir.join(".locks/.blanket")).unwrap();
        fs::write(x_dir.join(".locks/.blanket/x.json"), "{}").unwrap();

        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.path != x_dir.join(".locks")),
            "the permanent lock directory was enumerated as an environment"
        );
        drop(shared);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn legacy_clean_matching_reads_exact_generated_package() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-legacy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let exact = base.join("py-ruff-legacy");
        let similar = base.join("py-ruff-lsp-legacy");
        fs::create_dir_all(exact.join(".blanket")).unwrap();
        fs::create_dir_all(similar.join(".blanket")).unwrap();
        fs::write(exact.join("requirements.in"), "ruff\n").unwrap();
        fs::write(similar.join("requirements.in"), "ruff-lsp\n").unwrap();
        let filter = clean_filter(CleanRequest {
            ecosystem: Some("python".into()),
            from: None,
            tool: Some("ruff".into()),
        })
        .unwrap();
        assert_eq!(old_root_matches(&exact, &filter), CandidateMatch::Match);
        assert_eq!(old_root_matches(&similar, &filter), CandidateMatch::NoMatch);
        let unknown = base.join("py-unknown-legacy");
        fs::create_dir_all(unknown.join(".blanket")).unwrap();
        assert_eq!(
            old_root_matches(&unknown, &filter),
            CandidateMatch::Unrecoverable
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn clean_records_package_identity_not_executable_name() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-record-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("npm-scope-foo");
        fs::create_dir_all(root.join(".blanket")).unwrap();
        write_x_request(&root, "node", "@scope/foo", None, "realizing").unwrap();
        let request = serde_json::from_reader::<_, serde_json::Value>(
            fs::File::open(root.join(X_REQUEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(request["state"], "realizing");
        assert!(request.get("tool").is_none());

        let scoped = clean_filter(CleanRequest {
            ecosystem: Some("node".into()),
            from: None,
            tool: Some("@scope/foo".into()),
        })
        .unwrap();
        assert!(record_matches(&read_x_request(&root).unwrap(), &scoped));

        let from = clean_filter(CleanRequest {
            ecosystem: Some("python".into()),
            from: Some("httpie".into()),
            tool: Some("http".into()),
        })
        .unwrap();
        assert!(record_matches(
            &XRecord {
                ecosystem: "python".into(),
                package: "httpie".into(),
                version: None,
                state: Some("ready".into()),
                store_root: None,
            },
            &from
        ));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cleanup_finds_alias_registration_in_closure_store() {
        // Closures record canonical object paths (Store::open canonicalizes
        // its root), and originating_store compares them exactly; temp_dir()
        // is a symlink alias on macOS (/var -> /private/var).
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "blanket-x-registry-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let x_dir = base.join("x");
        let root = x_dir.join("py-ruff-registry");
        let store = Store {
            root: base.join("other-store"),
        };
        fs::create_dir_all(store.root.join("objects")).unwrap();
        fs::create_dir_all(store.root.join("meta")).unwrap();
        let object = store.root.join("objects").join("a".repeat(40) + "-env");
        fs::create_dir_all(&object).unwrap();
        fs::create_dir_all(root.join(".blanket/closures")).unwrap();
        fs::write(
            root.join(".blanket/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": {"env_object": object.display().to_string()}
            })
            .to_string(),
        )
        .unwrap();
        let entry = store.register_root(&root).unwrap();
        let alias = base.join("x-alias");
        std::os::unix::fs::symlink(&x_dir, &alias).unwrap();
        fs::write(
            &entry.registry_path,
            format!("{}\n", alias.join(root.file_name().unwrap()).display()),
        )
        .unwrap();

        match registration_for(&root).unwrap() {
            Registration::Found {
                store: originating,
                entry,
            } => {
                assert_eq!(originating.root, store.root);
                assert_eq!(
                    entry.path.canonicalize().unwrap(),
                    root.canonicalize().unwrap()
                );
                originating.remove_root_entry(&entry).unwrap();
            }
            Registration::NotFound | Registration::Unknown => {
                panic!("originating store registration was not found")
            }
        }
        assert!(store.roots().unwrap().is_empty());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn realizing_marker_makes_partial_root_a_cleanup_candidate() {
        let base = std::env::temp_dir().join(format!(
            "blanket-x-partial-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("home/.blanket/x/py-partial");
        ensure_x_metadata_dir(&root).unwrap();
        write_x_request(&root, "python", "ruff", None, "realizing").unwrap();
        let candidates = x_candidates(&base.join("home/.blanket/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        fs::remove_dir_all(base).unwrap();
    }

    fn temp_base(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blanket-x-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Prepare an environment root the way the runner does, so cleanup will
    /// enumerate it: metadata directory plus a lifecycle marker.
    fn seed_root(root: &Path) {
        ensure_x_metadata_dir(root).unwrap();
        write_x_request(root, "python", "ruff", None, "realizing").unwrap();
    }

    /// `$HOME` on another volume is a routine setup, and `blanket x` follows
    /// the symlink when it creates and registers a root. Cleanup has to reach
    /// exactly the same environment or it could never remove what the runner
    /// just made.
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_home() {
        let base = temp_base("symlinked-home");
        let real_home = base.join("volume/home");
        fs::create_dir_all(&real_home).unwrap();
        let home = base.join("home");
        std::os::unix::fs::symlink(&real_home, &home).unwrap();

        let x_dir = home.join(".blanket/x");
        let root = x_dir.join("py-linked-home");
        // Runner path: creates .blanket/x, .locks and the root itself.
        let shared = acquire_x_root(&root).unwrap();
        seed_root(&root);
        assert!(real_home
            .join(".blanket/x/.locks/py-linked-home.lock")
            .is_file());
        drop(shared);

        // Cleanup path: the same environment, named by its real location.
        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        assert_eq!(
            validated.path,
            real_home.canonicalize().unwrap().join(".blanket/x")
        );
        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        drop(validated);
        fs::remove_dir_all(base).unwrap();
    }

    /// The same contract for a symlinked `~/.blanket` — "move the cache off
    /// the root disk".
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_blanket_directory() {
        let base = temp_base("symlinked-blanket");
        let real_blanket = base.join("volume/blanket");
        fs::create_dir_all(&real_blanket).unwrap();
        let home = base.join("home");
        fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink(&real_blanket, home.join(".blanket")).unwrap();

        let x_dir = home.join(".blanket/x");
        let root = x_dir.join("py-linked-blanket");
        let shared = acquire_x_root(&root).unwrap();
        seed_root(&root);
        assert!(real_blanket
            .join("x/.locks/py-linked-blanket.lock")
            .is_file());
        drop(shared);

        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        assert_eq!(
            validated.path,
            real_blanket.canonicalize().unwrap().join("x")
        );
        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        drop(validated);
        fs::remove_dir_all(base).unwrap();
    }

    /// The final `x` component is where both commands stop following: the
    /// runner refuses it as a private directory and cleanup refuses to clean
    /// it, so neither can be pointed at a directory outside the home chain.
    #[test]
    fn runner_and_cleanup_both_refuse_a_symlinked_x_directory() {
        let base = temp_base("symlinked-x");
        let home = base.join("home");
        fs::create_dir_all(home.join(".blanket")).unwrap();
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let x_dir = home.join(".blanket/x");
        std::os::unix::fs::symlink(&elsewhere, &x_dir).unwrap();

        let runner = ensure_x_locks_dir(&x_dir).unwrap_err();
        assert!(
            runner.to_string().contains("is not a private directory"),
            "{runner}"
        );
        let cleanup = validated_x_dir(&x_dir).unwrap_err();
        assert!(
            cleanup
                .to_string()
                .contains("is a symlink; refusing to clean"),
            "{cleanup}"
        );
        assert!(elsewhere.is_dir(), "the symlink target was touched");
        fs::remove_dir_all(base).unwrap();
    }

    /// A relative `HOME` is still refused, by both commands, before anything
    /// is opened.
    #[test]
    fn cleanup_refuses_a_relative_home() {
        let error = validated_x_dir(Path::new("relative-home/.blanket/x")).unwrap_err();
        assert!(error.to_string().contains("is not absolute"), "{error}");
    }

    /// A successful cleanup unlinks the lock file it holds so `.locks` cannot
    /// grow one stale file per environment ever created. A runner that was
    /// already waiting on that inode must not be handed a lock that protects
    /// nothing: it revalidates and locks the file the pathname names now.
    #[test]
    fn cleanup_unlinks_the_root_lock_and_a_waiter_relocks_the_new_file() {
        let base = temp_base("lock-unlink");
        let x_dir = base.join("home/.blanket/x");
        let root = x_dir.join("py-unlink");
        fs::create_dir_all(&root).unwrap();
        let x_fd = open_directory_path(&x_dir.canonicalize().unwrap()).unwrap();
        let name = OsString::from("py-unlink");
        let cleanup = lock_x_root_at(x_fd.as_raw_fd(), &name, true, true)
            .unwrap()
            .expect("cleanup lock");
        let lock_path = x_dir.join(".locks/py-unlink.lock");
        assert!(lock_path.is_file());

        let (ready_tx, ready_rx) = mpsc::channel();
        let waiter_root = root.clone();
        let waiter = thread::spawn(move || {
            let lock = lock_x_root(&waiter_root, true, false)
                .unwrap()
                .expect("blocking lock");
            let identity = fd_identity(&lock).unwrap();
            ready_tx.send(identity).unwrap();
            lock
        });
        assert!(
            ready_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "the waiter took the lock while cleanup still held it"
        );

        remove_x_root_lock_at(x_fd.as_raw_fd(), &name).unwrap();
        assert!(
            !lock_path.exists(),
            "cleanup left its lock file behind: {}",
            lock_path.display()
        );
        drop(cleanup);

        let identity = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the waiter never acquired a lock after cleanup released it");
        let current = fs::symlink_metadata(&lock_path).expect("the waiter recreated the lock file");
        assert_eq!(
            identity,
            (current.dev(), current.ino()),
            "the waiter holds a lock on an inode the lock pathname no longer names"
        );
        drop(waiter.join().unwrap());
        // Unlinking twice is not an error: the file may already be gone.
        remove_x_root_lock_at(x_fd.as_raw_fd(), &name).unwrap();
        drop(x_fd);
        fs::remove_dir_all(base).unwrap();
    }

    /// The pending-exception queue is shared, so a test that asserts on its
    /// length starts from an empty queue under a lock of its own.
    fn exception_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        policy::clear();
        guard
    }

    /// A cache hit validates the projection exactly once. `x_request_is_ready`
    /// ends with `check_cached_projection`, so a caller that validated again
    /// would narrate and queue every persisted exception twice.
    #[test]
    fn ready_cache_hit_records_each_exception_once() {
        let _guard = exception_guard();
        let base = temp_base("ready-exceptions");
        fs::create_dir_all(base.join("store/objects/test-env/bin")).unwrap();
        fs::create_dir_all(base.join("store/meta")).unwrap();
        // `Store::has` takes the publish lock under `tmp/`.
        fs::create_dir_all(base.join("store/tmp")).unwrap();
        // Closures record the store's own canonical object path.
        let store = Store {
            root: base.join("store").canonicalize().unwrap(),
        };
        let object = store.root.join("objects/test-env");
        let executable = object.join("bin/ruff");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        // A complete object is a read-only directory with metadata.
        fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
        let exception = serde_json::json!({
            "kind": policy::FILE_COLLISION,
            "subject": "ruff",
            "detail": "cached test exception"
        });
        fs::write(
            store.root.join("meta/test-env.json"),
            serde_json::json!({"id": "test-env", "exceptions": [exception.clone()]}).to_string(),
        )
        .unwrap();

        let root = base.join("home/.blanket/x/py-ready");
        fs::create_dir_all(root.join(".blanket/closures")).unwrap();
        std::os::unix::fs::symlink(&object, root.join(".venv")).unwrap();
        fs::write(
            root.join(".blanket/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "platform": Platform::host().unwrap().triple(),
                "body": {
                    "env_object": object.display().to_string(),
                    "exceptions": [exception]
                }
            })
            .to_string(),
        )
        .unwrap();

        assert!(policy::pending().is_empty());
        assert!(x_request_is_ready(&store, &root, "python", &root.join(".venv/bin/ruff")).unwrap());
        assert_eq!(
            policy::pending().len(),
            1,
            "a cache hit narrated the same exception more than once: {:?}",
            policy::pending()
        );
        policy::clear();
        // The object is published read-only; make it removable again.
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(base).unwrap();
    }

    /// A run that considered a root and skipped it as unrecoverable has not
    /// found "nothing to clean": unrecoverable candidates count as matched.
    #[test]
    fn unrecoverable_candidates_count_as_matched() {
        let base = temp_base("unrecoverable");
        let root = base.join("home/.blanket/x/mystery");
        fs::create_dir_all(root.join(".blanket/closures")).unwrap();
        let filter = clean_filter(CleanRequest {
            ecosystem: None,
            from: None,
            tool: Some("ruff".into()),
        })
        .unwrap();
        let candidates = x_candidates(&base.join("home/.blanket/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidate_matches(&candidates[0], &filter),
            CandidateMatch::Unrecoverable
        );
        assert_eq!(candidate_ecosystem(&candidates[0].path), None);
        fs::remove_dir_all(base).unwrap();
    }

    /// The summary names `blanket gc --project` only for node environments,
    /// whose removal also orphans a `~/.blanket/forests` projection.
    #[test]
    fn candidate_ecosystem_reads_record_then_manifest_then_name() {
        let base = temp_base("ecosystem");
        let recorded = base.join("py-recorded");
        ensure_x_metadata_dir(&recorded).unwrap();
        write_x_request(&recorded, "node", "prettier", None, "ready").unwrap();
        assert_eq!(candidate_ecosystem(&recorded), Some("node"));

        let legacy = base.join("npm-legacy");
        fs::create_dir_all(legacy.join(".blanket")).unwrap();
        fs::write(
            legacy.join("package.json"),
            r#"{"dependencies":{"prettier":"1.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(candidate_ecosystem(&legacy), Some("node"));

        let named = base.join("py-named");
        fs::create_dir_all(named.join(".blanket")).unwrap();
        assert_eq!(candidate_ecosystem(&named), Some("python"));

        let unknown = base.join("mystery");
        fs::create_dir_all(unknown.join(".blanket")).unwrap();
        assert_eq!(candidate_ecosystem(&unknown), None);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn exact_node_tool_versions_are_full_releases() {
        assert!(is_exact_version("9.1.2"));
        assert!(is_exact_version("9.1.2-rc.1"));
        assert!(is_exact_version("9.12.3-beta.0"));
        for version in [
            "9",
            "9.x",
            "^9.1.0",
            "latest",
            "9.01.2",
            "9.1.2+build",
            "9.12.3-beta.01",
        ] {
            assert!(
                !is_exact_version(version),
                "accepted floating version {version}"
            );
        }
    }
}

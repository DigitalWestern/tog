//! `tog x <tool>`: run a tool from a registry without adding it to the
//! project, cached forever. A synthetic single-requirement plan goes
//! through the ordinary realize path, so the environment is an
//! input-addressed store object; the second run is a store hit. Each tool
//! gets a tiny project directory under `~/.tog/x/` holding the
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

use sha2::{Digest, Sha256};

use crate::comforter;
use crate::commands::inspect;
use crate::commands::shared::{registry_tool, registry_tools, CachedTool};
use crate::kernel::activity::StoreActivity;
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::store::{self, RootEntry, Store};
use crate::kernel::toolchain::runtime::Selected;
use crate::kernel::ui;

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

const X_REQUEST_FILE: &str = ".tog/x.json";
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

/// The toolchain an `x` environment runs on: the project's lock when `x`
/// runs inside one, the shipped selection otherwise. `x` chooses no
/// version of its own and writes no lock.
pub(crate) fn x_toolchain(platform: Platform, cwd: &Path, ecosystem: &str) -> io::Result<Selected> {
    crate::commands::shared::selected_toolchain(platform, cwd, ecosystem)
        .map_err(|error| other(format!("x: {error}")))
}

/// The store object id of the runtime a selection names, from the selected
/// bundle's own row and without touching the store. A shipped pin table
/// could answer by version alone, but the key has to name the object the
/// environment will actually run on, which is the one the selection's
/// digest and recipe identify.
fn runtime_object_id(
    platform: Platform,
    ecosystem: &str,
    toolchain: &Selected,
) -> io::Result<String> {
    registry_tool(ecosystem)?.runtime_object_id(platform, toolchain)
}

/// The helper toolchains an `x` environment of `ecosystem` builds with
/// (`RegistryTool::helpers`), decided as `sync` decides them for the
/// project `x` runs in, and each one's runtime object id for the key.
fn x_helpers(
    platform: Platform,
    cwd: &Path,
    ecosystem: &str,
) -> io::Result<(
    std::collections::BTreeMap<String, Selected>,
    Vec<(String, String)>,
)> {
    let tool = registry_tool(ecosystem)?;
    let helpers =
        crate::commands::shared::selected_helpers(platform, cwd, ecosystem, tool.helpers())
            .map_err(|error| other(format!("x: {error}")))?;
    let ids = helpers
        .iter()
        .map(|(helper, selected)| {
            Ok((
                helper.clone(),
                tool.helper_object_id(platform, helper, selected)?,
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok((helpers, ids))
}

/// The name of the directory a cached `x` environment lives in under
/// `~/.tog/x`, for a caller that has to find one without re-deriving the
/// key by hand.
pub fn environment_name(
    store_root: &Path,
    platform: Platform,
    cwd: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
) -> io::Result<String> {
    let store = Store::handle(store_root.to_path_buf());
    let toolchain = x_toolchain(platform, cwd, ecosystem)?;
    let runtime_object = runtime_object_id(platform, ecosystem, &toolchain)?;
    let (_, helper_objects) = x_helpers(platform, cwd, ecosystem)?;
    x_root_name(
        &store,
        platform,
        ecosystem,
        package,
        version,
        &toolchain,
        &runtime_object,
        &helper_objects,
    )
}

/// The directory one cached `x` environment lives in.
///
/// The key names the store root because everything else in it is
/// store-independent: two stores must not share one `~/.tog/x/` directory,
/// or the second store's run would find a projection pointing into the
/// first and fail in a way rerunning cannot clear.
///
/// `bundle_id` covers every component version and every platform artifact
/// row, so a changed uv, a changed extraction recipe, or any other bundle
/// component yields a fresh environment; the runtime object id is what the
/// projection actually points at. The name's first word is the registry
/// tool's `cache_prefix`.
///
/// A tool that builds with helper toolchains (npm's node-gyp Python) keys
/// on each helper's runtime object too, under `x/4`: the `x/3` preimage
/// with `<helper>=<object id>` fields appended. A tool with none keys on
/// the `x/3` preimage alone. The key only names the directory: a cache hit
/// also needs the request record (`.tog/x.json`) the run wrote there, so a
/// directory an older tog made without one is rebuilt in place, never
/// reused, and bare `tog x --clean` removes it.
#[allow(clippy::too_many_arguments)]
fn x_root_name(
    store: &Store,
    platform: Platform,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    toolchain: &Selected,
    runtime_object: &str,
    helper_objects: &[(String, String)],
) -> io::Result<String> {
    let fields = format!(
        "\0{}\0{ecosystem}\0{package}\0{}\0{}\0{}\0{}\0{runtime_object}",
        store.root.display(),
        version.unwrap_or(""),
        platform.triple(),
        toolchain.primary_version(),
        toolchain.bundle_id()
    );
    let preimage = if helper_objects.is_empty() {
        format!("x/3{fields}")
    } else {
        let mut preimage = format!("x/4{fields}");
        for (helper, object) in helper_objects {
            preimage.push_str(&format!("\0{helper}={object}"));
        }
        preimage
    };
    let key = hex::encode(Sha256::digest(preimage.as_bytes()));
    Ok(format!(
        "{}-{}-{}",
        registry_tool(ecosystem)?.cache_prefix(),
        safe(package),
        &key[..16]
    ))
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
    let metadata_dir = root.join(".tog");
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
    locks.canonicalize()
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
             remove the offending entry from ~/.tog/x by hand",
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

// `st_dev` is a u64 on Linux but an i32 on macOS: the cast is a no-op
// here and needed there, and clippy only sees the target it runs on.
#[allow(clippy::unnecessary_cast)]
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
             remove the offending entry from ~/.tog/x by hand",
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
    // SAFETY: fd is newly opened and ownership moves to the File.
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
    write_x_request_inner(root, ecosystem, package, version, state, None, None)
}

fn write_x_request_for_store(
    root: &Path,
    store: &Store,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
    runtime: Option<(&Selected, &str, &[(String, String)])>,
) -> io::Result<()> {
    write_x_request_inner(
        root,
        ecosystem,
        package,
        version,
        state,
        Some(&store.root),
        runtime,
    )
}

fn write_x_request_inner(
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
    store_root: Option<&Path>,
    runtime: Option<(&Selected, &str, &[(String, String)])>,
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
        .join(".tog")
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
    // What the directory name was computed from, so a reader of the record
    // can tell which runtime this environment belongs to without
    // recomputing the key.
    if let Some((toolchain, runtime_object, helper_objects)) = runtime {
        record["bundle_id"] = serde_json::Value::String(toolchain.bundle_id());
        record["runtime_object"] = serde_json::Value::String(runtime_object.to_string());
        // The helper runtimes the key names (node-gyp's Python), if any.
        if !helper_objects.is_empty() {
            record["helpers"] = serde_json::Value::Object(
                helper_objects
                    .iter()
                    .map(|(helper, object)| {
                        (helper.clone(), serde_json::Value::String(object.clone()))
                    })
                    .collect(),
            );
        }
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
        // An existing tog metadata directory is an explicit project
        // boundary, even when the project currently has no manifest. This
        // prevents an unrelated package in an outer checkout from deciding
        // `x`'s registry.
        if dir.join(".tog").is_dir() {
            break;
        }
    }
    Err(say_which_registry(&request.tool))
}

/// `x: say which registry provides 'ruff': 'tog x py:ruff' (PyPI) or ...`,
/// one alternative per registry tool.
fn say_which_registry(tool: &str) -> io::Error {
    let choices: Vec<String> = registry_tools()
        .iter()
        .map(|(_, registry)| {
            format!(
                "'tog x {}:{tool}' ({})",
                registry.spelling(),
                registry.registry_name()
            )
        })
        .collect();
    other(format!(
        "x: say which registry provides '{tool}': {}",
        choices.join(" or ")
    ))
}

fn choose_from_project(request: &Request, present: &[&str]) -> io::Result<&'static str> {
    let tools = registry_tools();
    if let Some(name) = request.ecosystem.as_deref() {
        return tools
            .iter()
            .find(|(id, _)| *id == name)
            .map(|(id, _)| *id)
            .ok_or_else(|| other(format!("x: unsupported ecosystem '{name}'")));
    }
    let found: Vec<_> = tools
        .iter()
        .filter(|(id, _)| present.contains(id))
        .collect();
    match found.as_slice() {
        [] => Err(say_which_registry(&request.tool)),
        [(id, registry)] => {
            ui::trace(&format!("x: {}", registry.detection_reason()));
            Ok(id)
        }
        several => {
            let labels: Vec<&str> = several.iter().map(|(_, r)| r.project_label()).collect();
            let flags: Vec<String> = several
                .iter()
                .map(|(_, r)| format!("--{}", r.spelling()))
                .collect();
            Err(other(format!(
                "x: {}{} projects are present; choose explicitly with {}",
                if several.len() == 2 { "both " } else { "" },
                labels.join(" and "),
                flags.join(" or ")
            )))
        }
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
        || (package.contains('/') && !registry_tool(ecosystem)?.scoped_packages())
    {
        return Err(other(format!("x: invalid package '{package}'")));
    }
    Ok(())
}

fn validate_version(version: &str) -> io::Result<()> {
    validate_text("version", version)
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

fn check_projection_target(
    store: &Store,
    root: &Path,
    ecosystem: &str,
    closure: &serde_json::Value,
    env_path: &Path,
) -> io::Result<()> {
    if registry_tool(ecosystem)?.projection_points_at(store, root, closure, env_path)? {
        return Ok(());
    }
    Err(other(format!(
        "x: cached {ecosystem} projection is missing or points elsewhere; run the command again"
    )))
}

/// A cached `x` projection bypasses the normal realization functions. Check
/// both the persisted closure and the store metadata before executing it, so
/// a stricter policy cannot be bypassed by a previously realized tool.
fn cached_projection(
    store: &Store,
    activity: &StoreActivity,
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
    if path != store.object_path(&id) || !store.has_with_activity(activity, &id)? {
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

fn check_cached_projection(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
) -> io::Result<()> {
    let (closure, id) = cached_projection(store, activity, root, ecosystem)?;
    policy::check_cached_with_activity(store, activity, &id)?;

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
    /// The shared `~/.tog/x` descriptor, not a per-candidate clone. It is
    /// the same directory for every candidate and is only ever read from, so
    /// cloning it per entry cost one extra descriptor each and put a large
    /// `~/.tog/x` against the process descriptor limit before cleanup had
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
    if !matches!(
        value.get("schema").and_then(serde_json::Value::as_str),
        Some("x-request/1" | "x-request/2")
    ) {
        return None;
    }
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
    let metadata_dir = root.join(".tog");
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
/// `~/.tog` are routinely symlinks (the usual "move the cache off the
/// root disk" setup) and `tog x` follows them when it creates and
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

/// A cleanup anchor that passed validation: its canonical path and an open
/// descriptor for that exact directory.
#[derive(Debug)]
struct ValidatedXDir {
    path: PathBuf,
    directory: fs::File,
}

/// Return the canonical cleanup anchor. The home chain (`$HOME` and
/// `~/.tog`) is resolved the way the runner resolves it and the result
/// must be a real directory; the final `x` component is never followed.
/// Missing `.tog` or `x` means there is nothing to clean; an existing
/// unsafe component is an error.
fn validated_x_dir(x_dir: &Path) -> io::Result<Option<ValidatedXDir>> {
    if !x_dir.is_absolute() {
        return Err(other(format!(
            "x: cleanup directory {} is not absolute; refusing to clean",
            x_dir.display()
        )));
    }
    let tog_dir = x_dir.parent().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no .tog parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let home_dir = tog_dir.parent().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no HOME parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let tog_name = tog_dir.file_name().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no .tog parent; refusing to clean",
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
    let Some(tog_canonical) =
        canonical_real_directory(&home_canonical.join(tog_name), "$HOME/.tog")?
    else {
        return Ok(None);
    };
    // Below the resolved home chain nothing is followed: the `x` component
    // must be a real directory and `open_directory_path` walks the canonical
    // path one no-follow component at a time.
    let canonical = tog_canonical.join(x_name);
    if !existing_real_directory(&canonical, "$HOME/.tog/x")? {
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
    fs::symlink_metadata(root.join(".tog/closures"))
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
        let marker = match stat_at(directory.as_raw_fd(), b".tog") {
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
}

/// The ecosystem whose registry tool names cache directories with the
/// prefix `name` starts with (`py-ruff-…`).
fn ecosystem_from_name(name: &str) -> Option<&'static str> {
    registry_tools()
        .into_iter()
        .find(|(_, tool)| {
            name.strip_prefix(tool.cache_prefix())
                .is_some_and(|rest| rest.starts_with('-'))
        })
        .map(|(id, _)| id)
}

fn record_matches(record: &XRecord, filter: &CleanFilter) -> bool {
    filter
        .ecosystem
        .as_deref()
        .is_none_or(|ecosystem| ecosystem == record.ecosystem)
        && filter
            .package
            .as_deref()
            .is_none_or(|package| package == record.package)
        && filter
            .version
            .as_deref()
            .is_none_or(|version| Some(version) == record.version.as_deref())
}

/// Best-effort ecosystem of a candidate, used only to word the summary. The
/// recorded request wins, then the generated name prefix.
fn candidate_ecosystem(path: &Path) -> Option<&'static str> {
    if let Some(record) = read_x_request(path) {
        return registry_tools()
            .into_iter()
            .map(|(id, _)| id)
            .find(|id| *id == record.ecosystem);
    }
    ecosystem_from_name(path.file_name().and_then(|name| name.to_str())?)
}

/// Whether `filter` selects `candidate`. Only the request record says what
/// a root was made for, so a root without one matches only a clean with no
/// filter at all: a filtered clean leaves it alone, and the bare
/// `tog x --clean` removes it.
fn candidate_matches(candidate: &XCandidate, filter: &CleanFilter) -> CandidateMatch {
    let matched = match read_x_request(&candidate.path) {
        Some(record) => record_matches(&record, filter),
        None => filter.ecosystem.is_none() && filter.package.is_none() && filter.version.is_none(),
    };
    if matched {
        CandidateMatch::Match
    } else {
        CandidateMatch::NoMatch
    }
}

/// Decide whether a cached root can be executed as it stands. A `true` answer
/// means the cached projection has already been fully validated here,
/// including its policy exceptions: callers must not validate it a second
/// time or every persisted exception is narrated and queued twice.
fn x_request_is_ready(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
    executable: &Path,
) -> io::Result<bool> {
    // Only a root whose run recorded it `ready` is complete. A root with no
    // record, an unreadable one, or one still `realizing` is rebuilt.
    if read_x_request(root)
        .and_then(|record| record.state)
        .as_deref()
        != Some("ready")
    {
        return Ok(false);
    }
    if !executable.is_file() || cached_projection(store, activity, root, ecosystem).is_err() {
        return Ok(false);
    }
    // Keep policy failures as failures. They must not be mistaken for a
    // missing projection and bypassed by a fresh realization.
    check_cached_projection(store, activity, root, ecosystem)?;
    Ok(true)
}

enum Registration {
    Found {
        store: Store,
        // Boxed so the enum is not as large as its one big variant.
        entry: Box<RootEntry>,
    },
    NotFound,
    #[cfg(test)]
    Unknown,
}

/// Which store owns an x root, as cleanup must know it to unregister the
/// root under that store's lease.
enum Origin {
    /// The store the request record names, or else the one store every
    /// object the root's closures reference lives in.
    Store(Store),
    /// No closure at all: a shell a run left before it wrote one, which
    /// references nothing and was never registered with its objects.
    Empty,
    /// The closures name objects, but no single available store can be
    /// recovered from them. Removing the root would orphan its registration.
    Unknown(String),
}

/// The store that owns `root`: the request record's `store_root` when it
/// has one, otherwise the store its closures' object references
/// (`runtime_object`, `env_object`) live in. Only cleanup asks this. A root
/// without a request record is never a cache hit, but deleting one under
/// the wrong store would leave the owner's registration keeping its
/// objects forever.
fn originating_store(root: &Path) -> io::Result<Origin> {
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
            // A handle only: `clean` takes the exclusive lease on it before
            // it reads or removes anything, and the lease validates the
            // store's format marker.
            return Ok(Origin::Store(Store::handle(store_root)));
        }
    }
    closure_owner(root)
}

/// The one store every closure under `root` references objects in, read
/// with the same no-follow rules as the rest of the x root. A closure
/// directory or file that cannot be read leaves the owner unknown, so
/// cleanup skips that root and goes on with the rest.
fn closure_owner(root: &Path) -> io::Result<Origin> {
    Ok(read_closure_owner(root).unwrap_or_else(|error| {
        Origin::Unknown(format!("its closures could not be read: {error}"))
    }))
}

fn read_closure_owner(root: &Path) -> io::Result<Origin> {
    let closures = root.join(".tog/closures");
    let entries = match fs::read_dir(&closures) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Origin::Empty),
        Err(error) => return Err(error),
    };
    let mut found: Option<Store> = None;
    let mut any = false;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let stat = fs::symlink_metadata(&path)?;
        if stat.file_type().is_symlink() || !stat.is_file() {
            return Ok(Origin::Unknown(format!(
                "closure {} is not a regular file",
                path.display()
            )));
        }
        any = true;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let Ok(value) = serde_json::from_reader::<_, serde_json::Value>(file) else {
            return Ok(Origin::Unknown(format!(
                "closure {} is unreadable",
                path.display()
            )));
        };
        let body = &value["body"];
        let mut objects: Vec<PathBuf> = Vec::new();
        let runtime = &body["runtime_object"];
        if !runtime.is_null() {
            match (runtime["id"].as_str(), runtime["path"].as_str()) {
                (Some(id), Some(object))
                    if store::is_object_id(id)
                        && Path::new(object).file_name() == Some(id.as_ref()) =>
                {
                    objects.push(PathBuf::from(object));
                }
                _ => {
                    return Ok(Origin::Unknown(format!(
                        "closure {} has a malformed runtime_object",
                        path.display()
                    )))
                }
            }
        }
        if let Some(env) = body["env_object"].as_str() {
            objects.push(PathBuf::from(env));
        }
        if objects.is_empty() {
            return Ok(Origin::Unknown(format!(
                "closure {} names no store object",
                path.display()
            )));
        }
        for object in objects {
            let Some(store) = comforter::store_from_object_path(&object) else {
                return Ok(Origin::Unknown(format!(
                    "the store holding {} is unavailable",
                    object.display()
                )));
            };
            match &found {
                Some(previous) if previous.root != store.root => {
                    return Ok(Origin::Unknown(
                        "its closures name objects in more than one store".into(),
                    ))
                }
                Some(_) => {}
                None => found = Some(store),
            }
        }
    }
    Ok(match found {
        Some(store) => Origin::Store(store),
        None if any => Origin::Unknown("its closures name no store object".into()),
        None => Origin::Empty,
    })
}

fn registration_for_store(root: &Path, store: Store) -> io::Result<Registration> {
    let canonical = root.canonicalize()?;
    let entry = store.roots()?.into_iter().find(|entry| {
        entry
            .path
            .canonicalize()
            .is_ok_and(|path| path == canonical)
    });
    Ok(
        entry.map_or(Registration::NotFound, |entry| Registration::Found {
            store,
            entry: Box::new(entry),
        }),
    )
}

#[cfg(test)]
fn registration_for(root: &Path) -> io::Result<Registration> {
    match originating_store(root)? {
        Origin::Store(store) => registration_for_store(root, store),
        Origin::Empty | Origin::Unknown(_) => Ok(Registration::Unknown),
    }
}

/// Remove cached x projections. The store objects remain available for the
/// ordinary GC pass; deleting a projection is deliberately not object GC.
// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
/// The exclusive lease `clean` removes one environment under, or `None`
/// with the skip already printed. The lease validates the store's format
/// marker. A recorded store this tog does not read is not ours to change:
/// its registration stays, so the root that registration protects stays
/// too. It is a skip rather than a failure because the store named may not
/// be the configured one, and the fix belongs to that store.
fn clean_lease(origin_store: &Store, environment: &Path) -> io::Result<Option<StoreActivity>> {
    match origin_store.try_activity_exclusive() {
        Ok(Some(activity)) => Ok(Some(activity)),
        Ok(None) => {
            println!(
                "tog: skipped x environment {} (in use by a running tool; retry later; originating store is busy)",
                environment.display()
            );
            Ok(None)
        }
        Err(error) => match store::refusal_fix(&error) {
            Some(fix) => {
                println!(
                    "tog: skipped x environment {} (its originating store is not one this tog reads: {error}; fix: {fix})",
                    environment.display()
                );
                Ok(None)
            }
            None => Err(error),
        },
    }
}

pub fn clean(request: CleanRequest) -> io::Result<()> {
    let filter = clean_filter(request)?;
    let x_dir = home()?.join(".tog/x");
    let candidates = x_candidates(&x_dir)?;
    let mut matched = 0usize;
    let mut removed = 0usize;
    let mut skipped = 0usize;
    let mut notes: Vec<&'static str> = Vec::new();
    for candidate in candidates {
        match candidate_matches(&candidate, &filter) {
            CandidateMatch::Match => {}
            CandidateMatch::NoMatch => continue,
        }
        matched += 1;
        let ecosystem = candidate_ecosystem(&candidate.path);
        // Origin metadata is only a hint until the originating store is
        // protected. The root is removed and unregistered under the store
        // that owns it, never the caller's: a root whose owner cannot be
        // recovered is skipped, because removing it would leave that store's
        // registration keeping its objects. An empty shell references
        // nothing, so the x-root lock below is its whole guard and the
        // caller's store only lends the lease.
        let origin = match originating_store(&candidate.path)? {
            Origin::Unknown(why) => {
                println!(
                    "tog: skipped x environment {} (its owning store could not be recovered: {why}; remove the directory yourself once you know nothing is using it)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
            origin => origin,
        };
        let origin_store = match &origin {
            Origin::Store(store) => store.clone(),
            Origin::Empty | Origin::Unknown(_) => Store::open()?,
        };
        let Some(activity) = clean_lease(&origin_store, &candidate.path)? else {
            skipped += 1;
            continue;
        };
        let Some(_lock) = lock_x_root_at(candidate.x_dir.as_raw_fd(), &candidate.name, true, true)?
        else {
            println!(
                "tog: skipped x environment {} (in use by a running tool; retry later)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        };
        let _project_lock = origin_store.project_lock(&candidate.path)?;
        // Re-read the untrusted origin after both guards. A changed marker or
        // closure is a race, not permission to remove the candidate. An
        // empty shell must still be empty: gaining a claim while it was
        // being locked is the same race.
        match (&origin, originating_store(&candidate.path)?) {
            (Origin::Store(_), Origin::Store(revalidated_store)) => {
                if revalidated_store.root != origin_store.root {
                    println!(
                        "tog: skipped x environment {} (originating store changed while it was being locked; retry later)",
                        candidate.path.display()
                    );
                    skipped += 1;
                    continue;
                }
            }
            (Origin::Empty, Origin::Empty) => {}
            _ => {
                println!(
                    "tog: skipped x environment {} (origin changed while it was being locked; retry later)",
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
                    "tog: skipped x environment {} (it disappeared or changed; retry later)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if stat_identity(&current) != candidate.identity || !stat_is_real_directory(&current) {
            println!(
                "tog: skipped x environment {} (it disappeared or changed; retry later)",
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
                "tog: skipped x environment {} (it disappeared or changed; retry later)",
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
        if let Some(note) = ecosystem
            .and_then(|ecosystem| registry_tool(ecosystem).ok())
            .and_then(|tool| tool.clean_note())
        {
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
        match registration {
            Registration::Found { store, entry } => {
                store.remove_root_entry_with_activity(&activity, &entry)?;
                println!(
                    "tog: removed x environment {}",
                    candidate.path.display()
                );
            }
            Registration::NotFound => println!(
                "tog: removed x environment {} (no matching registry entry in its originating store)",
                candidate.path.display()
            ),
            #[cfg(test)]
            Registration::Unknown => println!(
                "tog: removed x environment {} (registry entry could not be dropped: originating store not found)",
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
        println!("tog: x clean: nothing to clean");
    } else {
        // A removed node environment also orphans its
        // forests/<project-key>/<projection-id> node_modules forest in the
        // originating store, which plain `tog gc` never visits.
        let forests: String = notes.iter().map(|note| format!(", and {note}")).collect();
        println!(
            "tog: x clean removed {removed} environment(s), skipped {skipped}; store objects remain until the next 'tog gc'{forests}"
        );
    }
    Ok(())
}

/// `tog x`: `x` has its own cached projection path and therefore does
/// not pass through sync's policy initialization. Load the cwd policy,
/// including all applicable ancestors, before realization or any cache-hit
/// checks. The dispatcher recorded `--strict` before this runs, so a
/// strict `x` judges the tool under the policy a strict sync would apply.
pub fn run(ctx: &Context, request: Request) -> io::Result<i32> {
    let cwd = ctx.project_dir();
    policy::init(&cwd)?;
    launch(ctx.platform, &cwd, request, &ctx.activity)
}

pub fn launch(
    platform: Platform,
    cwd: &Path,
    request: Request,
    activity: &StoreActivity,
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
    let tool = registry_tool(ecosystem)?;
    let toolchain = x_toolchain(platform, cwd, ecosystem)?;
    let runtime_object = tool.runtime_object_id(platform, &toolchain)?;
    let (helpers, helper_objects) = x_helpers(platform, cwd, ecosystem)?;
    let root = x_home.join(".tog/x").join(x_root_name(
        &store,
        platform,
        ecosystem,
        package,
        version,
        &toolchain,
        &runtime_object,
        &helper_objects,
    )?);
    let _x_lock = acquire_x_root(&root)?;
    let executable = tool.bin_dir(&root).join(bin);
    let mut attribution = policy::Attribution::open(ecosystem)?;
    let ready = x_request_is_ready(&store, activity, &root, ecosystem, &executable)?;
    if !ready {
        write_x_request_for_store(
            &root,
            &store,
            ecosystem,
            package,
            version,
            "realizing",
            Some((
                &toolchain,
                runtime_object.as_str(),
                helper_objects.as_slice(),
            )),
        )?;
        let mut door =
            ResolutionDoor::open(&store, activity, platform, DoorKind::X, &mut attribution)?;
        tool.realize(&mut door, &root, package, version, &toolchain, &helpers)?;
        attribution.finish(true)?;
        write_x_request_for_store(
            &root,
            &store,
            ecosystem,
            package,
            version,
            "ready",
            Some((
                &toolchain,
                runtime_object.as_str(),
                helper_objects.as_slice(),
            )),
        )?;
    } else {
        // `x_request_is_ready` already validated this projection against
        // the store and the active policy. Validating it again would
        // narrate and queue every persisted exception twice.
        attribution.discard();
    }
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}' installed but provides no '{bin}' executable; name it with --from: 'tog x --from {package} <tool>'"
        )));
    }
    let launch_env = tool.launch_env(&store, activity, platform, &root, &toolchain)?;
    let mut path: Vec<String> = launch_env
        .path
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    path.push(std::env::var("PATH").unwrap_or_default());
    let mut command = Command::new(&executable);
    command.args(&request.args).env("PATH", path.join(":"));
    for (key, value) in launch_env.vars {
        command.env(key, value);
    }
    ui::trace_command(&command);
    let status =
        crate::kernel::supervise::child_status(run_installed_tool(&mut command, activity))?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

/// Run the executable `tog x` installed, with the user's arguments. The
/// tool is the user's program (`tog x cowsay`, or a package that ships a
/// `cargo` wrapper), not a resolution tog starts, so neither the door nor
/// the host-local tripwire applies to it.
// Reviewed site (tests/architecture.rs): the user's own program, which may be any tool.
#[allow(clippy::disallowed_methods)]
fn run_installed_tool(
    command: &mut Command,
    activity: &StoreActivity,
) -> io::Result<std::process::ExitStatus> {
    crate::kernel::supervise::status(command, activity)
}

/// Realize `package@version` from `ecosystem`'s registry tool for another
/// command (a dependency edit's pinned pnpm), in the same registered
/// `~/.tog/x/` environment `tog x` would use for it from `project`: both
/// key on the same fields, so the two share one environment rather than
/// realizing it twice. The resolver runs through `door`.
pub(crate) fn realize_cached_tool(
    project: &Path,
    ecosystem: &str,
    package: &str,
    version: &str,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<CachedTool> {
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    store.require_activity(activity, &format!("{ecosystem} tool"))?;
    let tool = registry_tool(ecosystem)?;
    let toolchain = x_toolchain(platform, project, ecosystem)?;
    let runtime_object = tool.runtime_object_id(platform, &toolchain)?;
    let (helpers, helper_objects) = x_helpers(platform, project, ecosystem)?;
    let root = home()?.join(".tog/x").join(x_root_name(
        store,
        platform,
        ecosystem,
        package,
        Some(version),
        &toolchain,
        &runtime_object,
        &helper_objects,
    )?);
    // Take the same shared lifecycle lock `tog x` takes, and hand it back
    // to the caller. `tog x --clean` removes a cached root under an
    // exclusive lock, so without this a cleanup running alongside a
    // dependency edit could delete the delegate's environment out from under
    // it. The caller holds the lock for as long as it uses the root.
    let lock = acquire_x_root(&root)?;
    let executable = tool.bin_dir(&root).join(default_bin(package));
    // The same request record `tog x` writes, so the environment is one
    // `tog x` reuses and `tog x --clean <tool>` can name, and its
    // originating store is known when it is removed.
    let runtime = Some((
        &toolchain,
        runtime_object.as_str(),
        helper_objects.as_slice(),
    ));
    if cached_tool_hit(
        store,
        activity,
        &root,
        ecosystem,
        package,
        version,
        &executable,
        runtime,
    )? {
        return Ok(CachedTool {
            root,
            lock,
            realized: false,
        });
    }
    tool.realize(door, &root, package, Some(version), &toolchain, &helpers)?;
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}@{version}' installed but provides no '{package}' executable"
        )));
    }
    write_x_request_for_store(
        &root,
        store,
        ecosystem,
        package,
        Some(version),
        "ready",
        runtime,
    )?;
    Ok(CachedTool {
        root,
        lock,
        realized: true,
    })
}

/// The cache decision `realize_cached_tool` makes, under the x-root lock
/// its caller holds: reuse the root exactly when `tog x` would
/// (`x_request_is_ready`: a `ready` request record and a valid projection),
/// otherwise mark it `realizing` and answer `false` so the caller rebuilds
/// it. A root with no record, an unreadable one, or one left `realizing`
/// is never reused, whatever executable it holds.
#[allow(clippy::too_many_arguments)]
fn cached_tool_hit(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: &str,
    executable: &Path,
    runtime: Option<(&Selected, &str, &[(String, String)])>,
) -> io::Result<bool> {
    if x_request_is_ready(store, activity, root, ecosystem, executable)? {
        return Ok(true);
    }
    write_x_request_for_store(
        root,
        store,
        ecosystem,
        package,
        Some(version),
        "realizing",
        runtime,
    )?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::sync::mpsc;
    use std::thread;

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

    /// A one-component toolchain selection that no catalog bump moves.
    fn fixed_selection(ecosystem: &str, primary: &str, version: &str) -> Selected {
        use crate::kernel::toolchain::{Bundle, Component, Source};
        Selected {
            helpers: Default::default(),
            ecosystem: ecosystem.into(),
            bundle: Bundle {
                release: format!("{primary}-{version}-r1"),
                revision: Some(1),
                primary: vec![primary.into()],
                components: vec![Component::new(primary, version)],
                artifacts: Vec::new(),
            },
            lock_sha256: None,
            source: Source::Lock,
        }
    }

    /// The cache key follows the runtime. Two environments that differ
    /// only in the bundle they run on, or only in the object that bundle
    /// realizes to, are two directories; everything else about the request
    /// being equal keeps one.
    #[test]
    fn the_x_key_follows_the_runtime() {
        let store = Store::for_test(PathBuf::from("/tmp/tog-x-key-fixture"));
        let platform = Platform::host().unwrap();
        let selected = fixed_selection("python", "cpython", "3.12.14");
        let name = |toolchain: &Selected, runtime_object: &str| {
            x_root_name(
                &store,
                platform,
                "python",
                "ruff",
                Some("0.6.1"),
                toolchain,
                runtime_object,
                &[],
            )
            .unwrap()
        };
        let base = name(&selected, "object-a");
        assert_eq!(base, name(&selected, "object-a"), "the key is not stable");
        assert!(base.starts_with("py-ruff-"), "{base}");

        // A different realized runtime for the same bundle.
        assert_ne!(base, name(&selected, "object-b"));

        // A different bundle: `bundle_id` covers every component and
        // artifact row, so a changed uv or a changed extraction recipe is a
        // different environment even when the runtime object is the same.
        // `release` is provenance and is deliberately not in it.
        let mut renamed = selected.clone();
        renamed.bundle.release = format!("{}-rev2", renamed.bundle.release);
        assert_eq!(selected.bundle_id(), renamed.bundle_id());
        assert_eq!(base, name(&renamed, "object-a"));

        let mut other = selected.clone();
        let component = other.bundle.components.last_mut().unwrap();
        component.version = format!("{}.1", component.version);
        assert_ne!(selected.bundle_id(), other.bundle_id());
        assert_ne!(base, name(&other, "object-a"));
    }

    /// `x` reaches Python and Node only through `Tailor::registry_tool`;
    /// an ecosystem without one is refused in the trait default's words,
    /// and the tools put executables where the cached-root checks look.
    #[test]
    fn registry_tools_come_from_the_tailors() {
        let root = Path::new("/x-root");
        let python = registry_tool("python").unwrap();
        assert_eq!(python.cache_prefix(), "py");
        assert_eq!(python.bin_dir(root), root.join(".venv/bin"));
        let node = registry_tool("node").unwrap();
        assert_eq!(node.cache_prefix(), "npm");
        assert_eq!(node.bin_dir(root), root.join("node_modules/.bin"));
        let error = registry_tool("go").err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), "tog x does not support go");
        assert!(registry_tool("cobol").is_err());
    }

    /// The `x/3` and `x/4` cache directory names, byte for byte. A cached
    /// environment is found again only by recomputing this name, so any
    /// change to the key's bytes (its preimage, the hash, or the `py`/`npm`
    /// prefix a registry tool supplies) orphans every cache directory an
    /// earlier tog made. The toolchain is a fixed bundle, not the shipped
    /// catalog, so a catalog bump does not move these goldens.
    ///
    /// `py:` outside a project that locks Rust has no helper and keeps its
    /// `x/3` name; inside one it keys on the locked Rust under `x/4` (#190).
    /// `npm:` keys on its node-gyp Python under `x/4`; the helper-less
    /// spelling of the same request is still the `x/3` golden, so only the
    /// helper moved it.
    #[test]
    fn x_root_names_are_byte_identical_goldens() {
        let store = Store::for_test(PathBuf::from("/home/golden/.tog/store"));
        let platform = Platform::X86_64UnknownLinuxGnu;
        let python = fixed_selection("python", "cpython", "3.12.14");
        let node = fixed_selection("node", "node", "24.20.0");
        assert_eq!(
            x_root_name(
                &store,
                platform,
                "python",
                "ruff",
                Some("0.6.1"),
                &python,
                "cpython-object",
                &[],
            )
            .unwrap(),
            "py-ruff-215b4362097370ce"
        );
        assert_eq!(registry_tool("python").unwrap().helpers(), ["rust"]);
        let py = |rust: &str| {
            x_root_name(
                &store,
                platform,
                "python",
                "ruff",
                Some("0.6.1"),
                &python,
                "cpython-object",
                &[("rust".to_string(), rust.to_string())],
            )
            .unwrap()
        };
        assert_eq!(py("rust-object"), "py-ruff-d22c85ac801414bf");
        assert_ne!(py("other-rust-object"), py("rust-object"));
        assert_eq!(
            x_root_name(
                &store,
                platform,
                "node",
                "@angular/cli",
                None,
                &node,
                "nodejs-object",
                &[],
            )
            .unwrap(),
            "npm-_angular_cli-5dd983d9952f7476"
        );
        assert_eq!(registry_tool("node").unwrap().helpers(), ["python"]);
        let npm = |gyp_python: &str| {
            x_root_name(
                &store,
                platform,
                "node",
                "@angular/cli",
                None,
                &node,
                "nodejs-object",
                &[("python".to_string(), gyp_python.to_string())],
            )
            .unwrap()
        };
        assert_eq!(npm("cpython-object"), "npm-_angular_cli-c9f235c1ffa1b37a");
        assert_ne!(npm("other-cpython-object"), npm("cpython-object"));
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
        assert!(error.to_string().contains("tog x py:ruff"), "{error}");
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

    /// `--from six@1` asks for version 1 of the package while the tool
    /// `six@2` asks for version 2. The parser refuses that pair, but a
    /// `Request` can reach `x` without the parser, so a run and a clean
    /// each refuse it themselves instead of silently picking one version.
    /// Agreeing versions are fine.
    #[test]
    fn a_from_version_that_disagrees_with_the_tool_version_is_refused() {
        let (_store, activity) = crate::kernel::testutil::detached_lease();
        let cwd = TempDir::named("x-conflict");
        let error = launch(
            Platform::host().unwrap(),
            &cwd.0,
            Request {
                ecosystem: Some("python".into()),
                from: Some("six@1".into()),
                tool: "six@2".into(),
                args: vec![],
            },
            &activity,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--from package version conflicts with the tool version"),
            "{error}"
        );

        let clean = |from: &str, tool: &str| {
            clean_filter(CleanRequest {
                ecosystem: Some("python".into()),
                from: Some(from.into()),
                tool: Some(tool.into()),
            })
        };
        let error = clean("six@1", "six@2").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--from package version conflicts with the tool version"),
            "{error}"
        );
        let agreed = clean("six@1", "six@1").unwrap();
        assert_eq!(agreed.package.as_deref(), Some("six"));
        assert_eq!(agreed.version.as_deref(), Some("1"));
    }

    #[test]
    fn package_bin_and_version_inputs_are_validated() {
        let error = validate_package("python", "/tmp/tool").unwrap_err();
        assert!(error.to_string().contains("invalid package"), "{error}");
        assert!(validate_from_bin("../tool").is_err());
        assert!(validate_version("1.0\n--index-url evil").is_err());
    }

    /// An npm tool run inside a project builds its native addons on the
    /// Python a sync of that project would give node-gyp: the project's own
    /// (3.13 here) when it has Python, the shipped default otherwise. The
    /// helper's object is in the key, so the two never share a cache
    /// directory, and a `py:` tool's name does not depend on it.
    #[test]
    fn an_npm_tool_keys_on_the_projects_gyp_python() {
        let platform = Platform::host().unwrap();
        let temp = TempDir::named("x-gyp");
        let base = &temp.0;
        let store_root = base.join("store");
        let locks_python = base.join("locks-python");
        let node_only = base.join("node-only");
        for (project, python) in [(&locks_python, true), (&node_only, false)] {
            fs::create_dir_all(project.join(".tog")).unwrap();
            fs::write(project.join("package.json"), "{}\n").unwrap();
            if python {
                fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
                fs::write(project.join(".python-version"), "3.13\n").unwrap();
            }
        }

        let (helpers, ids) = x_helpers(platform, &locks_python, "node").unwrap();
        assert!(helpers["python"]
            .version("cpython")
            .unwrap()
            .starts_with("3.13."));
        assert_eq!(ids.len(), 1);
        assert!(ids[0].1.contains("-cpython-3.13."), "{ids:?}");
        let (helpers, ids) = x_helpers(platform, &node_only, "node").unwrap();
        let shipped = crate::tailors::node::shipped_gyp_python().unwrap();
        assert_eq!(helpers["python"].bundle_id(), shipped.bundle_id());
        assert_eq!(
            ids[0].1,
            crate::kernel::provider::cpython::cpython_object_id(&shipped, platform).unwrap()
        );
        let (helpers, ids) = x_helpers(platform, &locks_python, "python").unwrap();
        assert!(helpers.is_empty() && ids.is_empty());

        let name = |project: &Path, ecosystem: &str, package: &str| {
            environment_name(&store_root, platform, project, ecosystem, package, None).unwrap()
        };
        assert_ne!(
            name(&locks_python, "node", "prettier"),
            name(&node_only, "node", "prettier")
        );
    }

    #[test]
    fn a_python_tool_keys_on_the_projects_locked_rust() {
        let platform = Platform::host().unwrap();
        let temp = TempDir::named("x-rust");
        let project = temp.0.join("project");
        let outside = temp.0.join("outside");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"p\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::write(
            project.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.98.0\"\n",
        )
        .unwrap();
        let root = crate::kernel::fsroot::ProjectRoot::open(&project).unwrap();
        let inputs = crate::commands::shared::ecosystem_inputs(&[
            crate::tailors::by_id("cargo").unwrap(),
            crate::tailors::by_id("python").unwrap(),
        ])
        .unwrap();
        let resolved = comforter::toolchain::resolve(
            &root,
            platform,
            inputs,
            comforter::toolchain::Mode::Writable,
            false,
        )
        .unwrap();
        let bytes = resolved.pending.unwrap().canonical_bytes();
        fs::write(project.join("tog-toolchain.toml"), &bytes).unwrap();

        let (helpers, ids) = x_helpers(platform, &project, "python").unwrap();
        assert_eq!(
            helpers["rust"].source,
            crate::kernel::toolchain::Source::Lock
        );
        assert_eq!(helpers["rust"].version("rustc").unwrap(), "1.98.0");
        assert_eq!(
            ids,
            vec![(
                "rust".to_string(),
                crate::kernel::provider::rust::runtime_object_id(platform, &helpers["rust"])
                    .unwrap()
            )]
        );
        let (helpers, ids) = x_helpers(platform, &outside, "python").unwrap();
        assert!(helpers.is_empty() && ids.is_empty());
        assert_eq!(fs::read(project.join("tog-toolchain.toml")).unwrap(), bytes);
    }

    #[test]
    fn shared_x_lock_blocks_nonblocking_cleanup_until_runner_exit() {
        let temp = TempDir::named("x-lock");
        let base = &temp.0;
        let root = base.join("x").join("py-ruff-test");
        fs::create_dir_all(&root).unwrap();
        let shared = lock_x_root(&root, false, false)
            .unwrap()
            .expect("shared lock");
        // SAFETY: fcntl operates on the descriptor owned by `shared`.
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
    }

    #[test]
    fn cleanup_lock_waits_for_runner_recreation() {
        let temp = TempDir::named("x-lock-race");
        let base = &temp.0;
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
        assert!(root.join(".tog").is_dir());
    }

    #[test]
    fn fd_relative_removal_does_not_follow_replaced_x_directory() {
        let temp = TempDir::named("x-remove-fd");
        let base = &temp.0;
        let x_dir = base.join("home/.tog/x");
        let root = x_dir.join("py-victim-test");
        let victim = base.join("victim");
        fs::create_dir_all(root.join(".tog/nested")).unwrap();
        fs::write(root.join(".tog/nested/old"), b"old").unwrap();
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
        assert!(!root.join(".tog/nested/old").exists());
        drop(root_fd);
        drop(validated);
    }

    #[test]
    fn dot_prefixed_entries_are_not_x_candidates() {
        let temp = TempDir::named("x-lock-entry");
        let base = &temp.0;
        let x_dir = base.join("home/.tog/x");
        let root = x_dir.join("py-active");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        let shared = lock_x_root(&root, false, false)
            .unwrap()
            .expect("active root shared lock");
        let lock_path = x_dir.join(".locks/py-active.lock");
        assert!(lock_path.is_file());
        fs::create_dir_all(x_dir.join(".locks/.tog")).unwrap();
        fs::write(x_dir.join(".locks/.tog/x.json"), "{}").unwrap();

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
    }

    #[test]
    fn clean_records_package_identity_not_executable_name() {
        let temp = TempDir::named("x-record");
        let base = &temp.0;
        let root = base.join("npm-scope-foo");
        fs::create_dir_all(root.join(".tog")).unwrap();
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
    }

    /// The request record names the originating store, and its registry
    /// entry is found there even when it was registered through an alias
    /// of the x directory.
    #[test]
    fn cleanup_finds_alias_registration_in_the_recorded_store() {
        let temp = TempDir::named("x-registry");
        let base = &temp.0;
        let x_dir = base.join("x");
        let root = x_dir.join("py-ruff-registry");
        fs::create_dir_all(base.join("other-store/objects")).unwrap();
        fs::create_dir_all(base.join("other-store/meta")).unwrap();
        let store = Store::for_test(base.join("other-store").canonicalize().unwrap());
        let object = store.root.join("objects").join("a".repeat(40) + "-env");
        fs::create_dir_all(&object).unwrap();
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        fs::write(
            root.join(".tog/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": {"env_object": object.display().to_string()}
            })
            .to_string(),
        )
        .unwrap();
        write_x_request_for_store(&root, &store, "python", "ruff", None, "ready", None).unwrap();
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
    }

    #[test]
    fn realizing_marker_makes_partial_root_a_cleanup_candidate() {
        let temp = TempDir::named("x-partial");
        let base = &temp.0;
        let root = base.join("home/.tog/x/py-partial");
        ensure_x_metadata_dir(&root).unwrap();
        write_x_request(&root, "python", "ruff", None, "realizing").unwrap();
        let candidates = x_candidates(&base.join("home/.tog/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
    }

    /// Prepare an environment root the way the runner does, so cleanup will
    /// enumerate it: metadata directory plus a lifecycle marker.
    fn seed_root(root: &Path) {
        ensure_x_metadata_dir(root).unwrap();
        write_x_request(root, "python", "ruff", None, "realizing").unwrap();
    }

    /// `$HOME` on another volume is a routine setup, and `tog x` follows
    /// the symlink when it creates and registers a root. Cleanup has to reach
    /// exactly the same environment or it could never remove what the runner
    /// just made.
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_home() {
        let temp = TempDir::named("x-symlinked-home");
        let base = &temp.0;
        let real_home = base.join("volume/home");
        fs::create_dir_all(&real_home).unwrap();
        let home = base.join("home");
        std::os::unix::fs::symlink(&real_home, &home).unwrap();

        let x_dir = home.join(".tog/x");
        let root = x_dir.join("py-linked-home");
        // Runner path: creates .tog/x, .locks and the root itself.
        let shared = acquire_x_root(&root).unwrap();
        seed_root(&root);
        assert!(real_home
            .join(".tog/x/.locks/py-linked-home.lock")
            .is_file());
        drop(shared);

        // Cleanup path: the same environment, named by its real location.
        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        assert_eq!(
            validated.path,
            real_home.canonicalize().unwrap().join(".tog/x")
        );
        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        drop(validated);
    }

    /// The same contract for a symlinked `~/.tog` — "move the cache off
    /// the root disk".
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_tog_directory() {
        let temp = TempDir::named("x-symlinked-tog");
        let base = &temp.0;
        let real_tog = base.join("volume/tog");
        fs::create_dir_all(&real_tog).unwrap();
        let home = base.join("home");
        fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink(&real_tog, home.join(".tog")).unwrap();

        let x_dir = home.join(".tog/x");
        let root = x_dir.join("py-linked-tog");
        let shared = acquire_x_root(&root).unwrap();
        seed_root(&root);
        assert!(real_tog.join("x/.locks/py-linked-tog.lock").is_file());
        drop(shared);

        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        assert_eq!(validated.path, real_tog.canonicalize().unwrap().join("x"));
        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        drop(validated);
    }

    /// The final `x` component is where both commands stop following: the
    /// runner refuses it as a private directory and cleanup refuses to clean
    /// it, so neither can be pointed at a directory outside the home chain.
    #[test]
    fn runner_and_cleanup_both_refuse_a_symlinked_x_directory() {
        let temp = TempDir::named("x-symlinked-x");
        let base = &temp.0;
        let home = base.join("home");
        fs::create_dir_all(home.join(".tog")).unwrap();
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let x_dir = home.join(".tog/x");
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
    }

    /// A relative `HOME` is still refused, by both commands, before anything
    /// is opened.
    #[test]
    fn cleanup_refuses_a_relative_home() {
        let error = validated_x_dir(Path::new("relative-home/.tog/x")).unwrap_err();
        assert!(error.to_string().contains("is not absolute"), "{error}");
    }

    /// A successful cleanup unlinks the lock file it holds so `.locks` cannot
    /// grow one stale file per environment ever created. A runner that was
    /// already waiting on that inode must not be handed a lock that protects
    /// nothing: it revalidates and locks the file the pathname names now.
    #[test]
    fn cleanup_unlinks_the_root_lock_and_a_waiter_relocks_the_new_file() {
        let temp = TempDir::named("x-lock-unlink");
        let base = &temp.0;
        let x_dir = base.join("home/.tog/x");
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
    }

    /// The pending-exception queue is shared, so a test that asserts on its
    /// length starts from an empty queue under a lock of its own.
    fn exception_guard() -> std::sync::MutexGuard<'static, ()> {
        policy::exception_guard()
    }

    /// A published Python `x` root whose environment object carries
    /// `exceptions` in its metadata: (store, root, object).
    fn ready_python_root(
        base: &Path,
        exceptions: &[serde_json::Value],
    ) -> (Store, PathBuf, PathBuf) {
        fs::create_dir_all(base.join("store/objects/test-env/bin")).unwrap();
        fs::create_dir_all(base.join("store/meta")).unwrap();
        // `Store::has_with_activity` takes the publish lock under `tmp/`.
        fs::create_dir_all(base.join("store/tmp")).unwrap();
        // Closures record the store's own canonical object path.
        let store = Store::for_test(base.join("store").canonicalize().unwrap());
        let object = store.root.join("objects/test-env");
        let executable = object.join("bin/ruff");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        // A complete object is a read-only directory with metadata.
        fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(
            store.root.join("meta/test-env.json"),
            serde_json::json!({"id": "test-env", "exceptions": exceptions}).to_string(),
        )
        .unwrap();

        let root = base.join("home/.tog/x/py-ready");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        std::os::unix::fs::symlink(&object, root.join(".venv")).unwrap();
        fs::write(
            root.join(".tog/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "platform": Platform::host().unwrap().triple(),
                "body": {
                    "env_object": object.display().to_string(),
                    "exceptions": exceptions
                }
            })
            .to_string(),
        )
        .unwrap();
        write_x_request_for_store(&root, &store, "python", "ruff", None, "ready", None).unwrap();
        (store, root, object)
    }

    /// A cache hit validates the projection exactly once. `x_request_is_ready`
    /// ends with `check_cached_projection`, so a caller that validated again
    /// would narrate and queue every persisted exception twice.
    #[test]
    fn ready_cache_hit_records_each_exception_once() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("x-ready-exceptions");
        let base = &temp.0;
        let exception = serde_json::json!({
            "kind": policy::FILE_COLLISION,
            "subject": "ruff",
            "detail": "cached test exception"
        });
        let (store, root, object) = ready_python_root(base, &[exception]);
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();

        assert!(policy::pending().is_empty());
        assert!(x_request_is_ready(
            &store,
            &activity,
            &root,
            "python",
            &root.join(".venv/bin/ruff")
        )
        .unwrap());
        assert_eq!(
            policy::pending().len(),
            1,
            "a cache hit narrated the same exception more than once: {:?}",
            policy::pending()
        );
        let _ = policy::drain();
        drop(activity);
        // The object is published read-only; make it removable again.
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The cache check runs under the x-root lock, and GC takes the activity
    /// lock before the x-root lock. So the check must borrow the lease the
    /// caller already holds, never take one underneath the x-root lock. The
    /// caller here holds the exclusive lease: minting any lease on this
    /// thread would be refused, so a ready answer proves none was taken.
    #[test]
    fn the_x_cache_check_takes_no_lease_under_the_x_root_lock() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("x-borrowed-lease");
        let base = &temp.0;
        let (store, root, object) = ready_python_root(base, &[]);
        let exclusive = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let _x_lock = acquire_x_root(&root).unwrap();
        assert!(x_request_is_ready(
            &store,
            &exclusive,
            &root,
            "python",
            &root.join(".venv/bin/ruff")
        )
        .unwrap());
        // The minting form the borrowed one replaced cannot even be taken on
        // this thread now.
        assert!(store.has("test-env").is_err());
        drop(exclusive);
        let _ = policy::drain();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A root with no request record is never a cache hit, however
    /// complete its projection: the same root with a `ready` record is one,
    /// and so the run rebuilds a record-less root rather than reusing it.
    #[test]
    fn a_root_without_a_request_record_is_never_a_cache_hit() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("x-no-record");
        let base = &temp.0;
        let (store, root, object) = ready_python_root(base, &[]);
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let executable = root.join(".venv/bin/ruff");
        assert!(x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        fs::remove_file(root.join(X_REQUEST_FILE)).unwrap();
        assert!(!x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        // An unreadable record and a run still realizing are not hits either.
        fs::write(root.join(X_REQUEST_FILE), "{").unwrap();
        assert!(!x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        write_x_request_for_store(&root, &store, "python", "ruff", None, "realizing", None)
            .unwrap();
        assert!(!x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        let _ = policy::drain();
        drop(activity);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A root with no request record cannot say what it was made for, so
    /// only the unfiltered clean selects it, and no store owns it.
    #[test]
    fn a_root_without_a_request_record_matches_only_an_unfiltered_clean() {
        let temp = TempDir::named("x-unrecorded");
        let base = &temp.0;
        let root = base.join("home/.tog/x/py-ruff-0123456789abcdef");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        // Its closure names an object in some store: that is no longer
        // read as a claim of ownership.
        fs::write(
            root.join(".tog/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": {"env_object": "/elsewhere/store/objects/0000000000000000000000000000000000000000-env"}
            })
            .to_string(),
        )
        .unwrap();
        let candidates = x_candidates(&base.join("home/.tog/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        let filter = |ecosystem: Option<&str>, tool: Option<&str>| {
            clean_filter(CleanRequest {
                ecosystem: ecosystem.map(str::to_string),
                from: None,
                tool: tool.map(str::to_string),
            })
            .unwrap()
        };
        assert_eq!(
            candidate_matches(&candidates[0], &filter(None, None)),
            CandidateMatch::Match
        );
        for (ecosystem, tool) in [
            (None, Some("ruff")),
            (Some("python"), None),
            (Some("python"), Some("ruff")),
        ] {
            assert_eq!(
                candidate_matches(&candidates[0], &filter(ecosystem, tool)),
                CandidateMatch::NoMatch,
                "{ecosystem:?} {tool:?}"
            );
        }
        // Its closure names an object in a store that is not there, so no
        // owner can be recovered and cleanup would skip it.
        assert!(matches!(
            originating_store(&root).unwrap(),
            Origin::Unknown(why) if why.contains("is unavailable")
        ));
        assert!(matches!(
            registration_for(&root).unwrap(),
            Registration::Unknown
        ));
    }

    /// A closure directory cleanup cannot read leaves the owner unknown, so
    /// that root is skipped instead of stopping the whole clean.
    #[test]
    fn an_unreadable_closure_directory_leaves_the_owner_unknown() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::named("x-unreadable-owner");
        let root = temp.0.join("py-ruff-0123456789abcdef");
        let closures = root.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(closures.join("python.json"), b"{}").unwrap();
        fs::set_permissions(&closures, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&closures).is_ok();
        let origin = originating_store(&root);
        fs::set_permissions(&closures, fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            // Running as root: permissions do not bind, nothing to prove.
            return;
        }
        assert!(matches!(
            origin.unwrap(),
            Origin::Unknown(why) if why.contains("could not be read")
        ));
    }

    /// `candidate_ecosystem` decides which environments the clean summary
    /// calls node, so pin the order it reads: the recorded request, then
    /// the generated name prefix.
    #[test]
    fn candidate_ecosystem_reads_record_then_name() {
        let temp = TempDir::named("x-ecosystem");
        let base = &temp.0;
        let recorded = base.join("py-recorded");
        ensure_x_metadata_dir(&recorded).unwrap();
        write_x_request(&recorded, "node", "prettier", None, "ready").unwrap();
        assert_eq!(candidate_ecosystem(&recorded), Some("node"));

        let named = base.join("npm-named");
        fs::create_dir_all(named.join(".tog")).unwrap();
        assert_eq!(candidate_ecosystem(&named), Some("node"));

        let unknown = base.join("mystery");
        fs::create_dir_all(unknown.join(".tog")).unwrap();
        assert_eq!(candidate_ecosystem(&unknown), None);
    }

    /// A pnpm cache root as `realize_cached_tool` leaves it after a finished
    /// run, minus its request record: the store's environment object, the
    /// `node-forest/2` projection its `node_modules` links into, and the
    /// `pnpm` executable. Returns (store, root, executable, object).
    fn pnpm_cache_without_record(base: &Path) -> (Store, PathBuf, PathBuf, PathBuf) {
        fs::create_dir_all(base.join("store/objects/test-node-env")).unwrap();
        fs::create_dir_all(base.join("store/meta")).unwrap();
        fs::create_dir_all(base.join("store/tmp")).unwrap();
        let store = Store::for_test(base.join("store").canonicalize().unwrap());
        let object = store.root.join("objects/test-node-env");
        fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(
            store.root.join("meta/test-node-env.json"),
            serde_json::json!({"id": "test-node-env", "exceptions": []}).to_string(),
        )
        .unwrap();

        let root = base.join("home/.tog/x/npm-pnpm-0123456789abcdef");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        let projection_id = "ab".repeat(16);
        let key = hex::encode(Sha256::digest(
            root.canonicalize().unwrap().as_os_str().as_bytes(),
        ));
        let forest = store
            .root
            .join("forests")
            .join(&key[..32])
            .join(&projection_id)
            .join("node_modules");
        fs::create_dir_all(forest.join(".bin")).unwrap();
        let executable = forest.join(".bin/pnpm");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&forest, root.join("node_modules")).unwrap();
        fs::write(
            root.join(".tog/closures/node.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "node",
                "platform": Platform::host().unwrap().triple(),
                "body": {
                    "env_object": object.display().to_string(),
                    "projection_schema": "node-forest/2",
                    "projection_id": projection_id,
                }
            })
            .to_string(),
        )
        .unwrap();
        (
            store,
            root.clone(),
            root.join("node_modules/.bin/pnpm"),
            object,
        )
    }

    /// The pnpm cache `realize_cached_tool` uses is reused only when its
    /// request record says `ready`, as `tog x` decides. One a tog before
    /// this record left (no `x.json`) and one an interrupted run left
    /// `realizing` are both marked `realizing` and rebuilt, never reused,
    /// though each holds a working `pnpm`.
    #[test]
    fn a_pnpm_cache_without_a_ready_record_is_rebuilt_not_reused() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("node").unwrap();
        let temp = TempDir::named("x-pnpm-cache");
        let (store, root, executable, object) = pnpm_cache_without_record(&temp.0);
        assert!(executable.is_file());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let hit = |store: &Store| {
            cached_tool_hit(
                store,
                &activity,
                &root,
                "node",
                "pnpm",
                "9.1.0",
                &executable,
                None,
            )
            .unwrap()
        };
        let state = || read_x_request(&root).and_then(|record| record.state);

        // The control: the same root with a `ready` record is reused.
        write_x_request_for_store(&root, &store, "node", "pnpm", Some("9.1.0"), "ready", None)
            .unwrap();
        assert!(hit(&store));
        assert_eq!(state().as_deref(), Some("ready"));

        // Record-less: rebuilt.
        fs::remove_file(root.join(X_REQUEST_FILE)).unwrap();
        assert!(!hit(&store));
        assert_eq!(state().as_deref(), Some("realizing"));

        // Left `realizing` by an interrupted run: rebuilt again.
        assert!(!hit(&store));
        assert_eq!(state().as_deref(), Some("realizing"));

        let _ = policy::drain();
        drop(activity);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

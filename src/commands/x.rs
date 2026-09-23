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

use sha2::{Digest, Sha224, Sha256, Sha512};

use crate::comforter;
use crate::commands::inspect;
use crate::commands::shared::{registry_tool, registry_tools};
use crate::kernel::activity::StoreActivity;
use crate::kernel::context::Context;
use crate::kernel::fetch;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
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
    let store = Store {
        root: store_root.to_path_buf(),
    };
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
/// projection actually points at. A directory an older tog made under the
/// `x/2` key is never reused, and stays a GC root until `tog x --clean`.
/// The name's first word is the registry tool's `cache_prefix`.
///
/// A tool that builds with helper toolchains (npm's node-gyp Python) keys
/// on each helper's runtime object too, under `x/4`: the `x/3` preimage
/// with `<helper>=<object id>` fields appended. A tool with none keeps its
/// `x/3` name byte for byte, so `py:` caches survive; every `npm:` cache
/// from `x/3` is a miss, because none of them could say which Python its
/// native addons were built on.
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
    Unrecoverable,
}

/// Ecosystem recovered from a legacy generated manifest, for a root that
/// carries no recorded request. The matcher and the summary must read this
/// the same way: a legacy root that parses as both would otherwise be matched
/// for deletion as one ecosystem and reported to the user as the other.
/// Registry order decides between two readings.
fn recovered_legacy_ecosystem(path: &Path) -> Option<&'static str> {
    registry_tools()
        .into_iter()
        .find(|(_, tool)| tool.legacy_packages(path).is_some())
        .map(|(id, _)| id)
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

fn old_root_matches(path: &Path, filter: &CleanFilter) -> CandidateMatch {
    let Some(package) = filter.package.as_deref() else {
        let Some(ecosystem) = filter.ecosystem.as_deref() else {
            return CandidateMatch::Match;
        };
        let name_ecosystem = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(ecosystem_from_name);
        let recovered_ecosystem = recovered_legacy_ecosystem(path).or(name_ecosystem);
        return match recovered_ecosystem {
            Some(recovered) if recovered == ecosystem => CandidateMatch::Match,
            Some(_) => CandidateMatch::NoMatch,
            None => CandidateMatch::Unrecoverable,
        };
    };
    let mut recovered = false;
    for (id, tool) in registry_tools() {
        if filter
            .ecosystem
            .as_deref()
            .is_some_and(|ecosystem| ecosystem != id)
        {
            continue;
        }
        let Some(packages) = tool.legacy_packages(path) else {
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
        return registry_tools()
            .into_iter()
            .map(|(id, _)| id)
            .find(|id| *id == record.ecosystem);
    }
    if let Some(recovered) = recovered_legacy_ecosystem(path) {
        return Some(recovered);
    }
    ecosystem_from_name(path.file_name().and_then(|name| name.to_str())?)
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
    activity: &StoreActivity,
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
    if !executable.is_file() || cached_projection(store, activity, root, ecosystem).is_err() {
        return Ok(false);
    }
    // Keep policy failures as failures. They must not be mistaken for a
    // missing projection and bypassed by a fresh realization.
    check_cached_projection(store, activity, root, ecosystem)?;
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

    let closures = root.join(".tog/closures");
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
    let closures = root.join(".tog/closures");
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
            CandidateMatch::Unrecoverable => {
                println!(
                    "tog: skipped x environment {} (legacy root package could not be recovered; use 'tog x --clean' with no tool to remove all x environments)",
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
        // recovered, and never use the caller's current TOG_STORE as a
        // substitute for that provenance.
        let origin = originating_store(&candidate.path)?;
        if origin.is_none() && closure_claims_an_object(&candidate.path)? {
            // An unresolved ownership claim is a named skip, never permission
            // to delete. The caller's current TOG_STORE is not evidence
            // about this candidate: the projection can belong to a store that
            // is not the one this invocation happens to be pointed at.
            println!(
                "tog: skipped x environment {} (it claims store objects whose originating store could not be recovered; restore that store's closure, or remove the directory yourself once you know nothing is using it)",
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
                "tog: skipped x environment {} (in use by a running tool; retry later; originating store is busy)",
                candidate.path.display()
            );
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
        // Re-read the untrusted origin after both guards. A changed marker is
        // a race, not permission to remove the candidate. An unowned
        // projection must still be unowned: gaining a claim while it was
        // being locked is the same race.
        match originating_store(&candidate.path)? {
            Some(revalidated_store) if !unowned => {
                if revalidated_store.root != origin_store.root {
                    println!(
                        "tog: skipped x environment {} (originating store changed while it was being locked; retry later)",
                        candidate.path.display()
                    );
                    skipped += 1;
                    continue;
                }
            }
            None if unowned && !closure_claims_an_object(&candidate.path)? => {}
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
    // A pre-state x-request/1 root has no marker but can still be a
    // complete legacy cache. Preserve that cache path only when its
    // projected executable already exists.
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
        tool.realize(
            &store,
            activity,
            platform,
            &root,
            package,
            version,
            &toolchain,
            &helpers,
            &mut attribution,
        )?;
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
        if !x_request_file_exists(&root) {
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
        }
        attribution.discard();
    }
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}' installed but provides no '{bin}' executable; name it with --from: 'tog x --from {package} <tool>'"
        )));
    }
    let launch_env = tool.launch_env(&store, platform, &root, &toolchain)?;
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
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1))
}

/// Where a delegate's Node tool lives. It is the same directory `tog x`
/// would use for the same package, so the two share one environment rather
/// than realizing it twice; both therefore key on the same fields.
fn node_cache_root(
    store: &Store,
    platform: Platform,
    package: &str,
    version: Option<&str>,
    toolchain: &Selected,
    runtime_object: &str,
    helper_objects: &[(String, String)],
) -> io::Result<PathBuf> {
    Ok(home()?.join(".tog/x").join(x_root_name(
        store,
        platform,
        "node",
        package,
        version,
        toolchain,
        runtime_object,
        helper_objects,
    )?))
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
/// This is the same registered `~/.tog/x/` environment used by
/// `tog x`, so a delegate's second invocation is a normal cache hit.
pub(crate) fn realize_node_tool(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    package: &str,
    version: &str,
    corepack_hash: Option<&CorepackHash>,
    attribution: &mut policy::Attribution,
) -> io::Result<(PathBuf, fs::File, bool)> {
    validate_exact_version(version)?;
    store.require_activity(activity, "node tool")?;
    let tool = registry_tool("node")?;
    let toolchain = x_toolchain(platform, project, "node")?;
    let runtime_object = tool.runtime_object_id(platform, &toolchain)?;
    let (helpers, helper_objects) = x_helpers(platform, project, "node")?;
    let root = node_cache_root(
        store,
        platform,
        package,
        Some(version),
        &toolchain,
        &runtime_object,
        &helper_objects,
    )?;
    // Take the same shared lifecycle lock `tog x` takes, and hand it back
    // to the caller. `tog x --clean` removes a cached root under an
    // exclusive lock, so without this a cleanup running alongside a
    // dependency edit could delete the delegate's environment out from under
    // it. The caller holds the lock for as long as it uses the root.
    let x_lock = acquire_x_root(&root)?;
    let executable = tool.bin_dir(&root).join(default_bin(package));
    if executable.is_file() {
        check_cached_projection(store, activity, &root, "node")?;
        if let Some(expected) = corepack_hash {
            verify_corepack_hash(store, &root, package, version, expected)?;
        }
        return Ok((root, x_lock, false));
    }
    tool.realize(
        store,
        activity,
        platform,
        &root,
        package,
        Some(version),
        &toolchain,
        &helpers,
        attribution,
    )?;
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}@{version}' installed but provides no '{package}' executable"
        )));
    }
    if let Some(expected) = corepack_hash {
        verify_corepack_hash(store, &root, package, version, expected)?;
    }
    Ok((root, x_lock, true))
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

    /// A one-component toolchain selection that no catalog bump moves.
    fn fixed_selection(ecosystem: &str, primary: &str, version: &str) -> Selected {
        use crate::kernel::toolchain::{Bundle, Component, Source};
        Selected {
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
    fn the_x_key_follows_the_runtime_and_never_reuses_an_older_one() {
        let store = Store {
            root: PathBuf::from("/tmp/tog-x-key-fixture"),
        };
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

        // The name an older tog computed is never the name this one picks,
        // so an `x/2` directory is a miss rather than a wrong hit.
        let legacy = hex::encode(Sha256::digest(
            format!(
                "x/2\0{}\0python\0ruff\00.6.1\0{}",
                store.root.display(),
                platform.triple()
            )
            .as_bytes(),
        ));
        assert_ne!(base, format!("py-ruff-{}", &legacy[..16]));
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
    /// `py:` has no helpers and keeps its `x/3` name. `npm:` keys on its
    /// node-gyp Python under `x/4`; the helper-less spelling of the same
    /// request is still the `x/3` golden, so only the helper moved it.
    #[test]
    fn x_root_names_are_byte_identical_goldens() {
        let store = Store {
            root: PathBuf::from("/home/golden/.tog/store"),
        };
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
        assert!(registry_tool("python").unwrap().helpers().is_empty());
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

    #[test]
    fn from_version_is_split_and_conflicts_are_rejected() {
        let (package, version) = split_version("six@1.17.0");
        assert_eq!((package, version), ("six", Some("1.17.0")));
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
        let base = std::env::temp_dir().join(format!(
            "tog-x-gyp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn shared_x_lock_blocks_nonblocking_cleanup_until_runner_exit() {
        let base = std::env::temp_dir().join(format!(
            "tog-x-lock-{}-{}",
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
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cleanup_lock_waits_for_runner_recreation() {
        let base = std::env::temp_dir().join(format!(
            "tog-x-lock-race-{}-{}",
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
        assert!(root.join(".tog").is_dir());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn fd_relative_removal_does_not_follow_replaced_x_directory() {
        let base = std::env::temp_dir().join(format!(
            "tog-x-remove-fd-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn dot_prefixed_entries_are_not_x_candidates() {
        let base = std::env::temp_dir().join(format!(
            "tog-x-lock-entry-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn legacy_clean_matching_reads_exact_generated_package() {
        let base = std::env::temp_dir().join(format!(
            "tog-x-legacy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let exact = base.join("py-ruff-legacy");
        let similar = base.join("py-ruff-lsp-legacy");
        fs::create_dir_all(exact.join(".tog")).unwrap();
        fs::create_dir_all(similar.join(".tog")).unwrap();
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
        fs::create_dir_all(unknown.join(".tog")).unwrap();
        assert_eq!(
            old_root_matches(&unknown, &filter),
            CandidateMatch::Unrecoverable
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn clean_records_package_identity_not_executable_name() {
        let base = std::env::temp_dir().join(format!(
            "tog-x-record-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cleanup_finds_alias_registration_in_closure_store() {
        // Closures record canonical object paths (Store::open canonicalizes
        // its root), and originating_store compares them exactly; temp_dir()
        // is a symlink alias on macOS (/var -> /private/var).
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "tog-x-registry-{}-{}",
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
            "tog-x-partial-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("home/.tog/x/py-partial");
        ensure_x_metadata_dir(&root).unwrap();
        write_x_request(&root, "python", "ruff", None, "realizing").unwrap();
        let candidates = x_candidates(&base.join("home/.tog/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        fs::remove_dir_all(base).unwrap();
    }

    fn temp_base(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tog-x-{label}-{}-{}",
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

    /// `$HOME` on another volume is a routine setup, and `tog x` follows
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
        fs::remove_dir_all(base).unwrap();
    }

    /// The same contract for a symlinked `~/.tog` — "move the cache off
    /// the root disk".
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_tog_directory() {
        let base = temp_base("symlinked-tog");
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
        fs::remove_dir_all(base).unwrap();
    }

    /// The final `x` component is where both commands stop following: the
    /// runner refuses it as a private directory and cleanup refuses to clean
    /// it, so neither can be pointed at a directory outside the home chain.
    #[test]
    fn runner_and_cleanup_both_refuse_a_symlinked_x_directory() {
        let base = temp_base("symlinked-x");
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
        fs::remove_dir_all(base).unwrap();
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
        let base = temp_base("lock-unlink");
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
        fs::remove_dir_all(base).unwrap();
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
        let store = Store {
            root: base.join("store").canonicalize().unwrap(),
        };
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
        (store, root, object)
    }

    /// A cache hit validates the projection exactly once. `x_request_is_ready`
    /// ends with `check_cached_projection`, so a caller that validated again
    /// would narrate and queue every persisted exception twice.
    #[test]
    fn ready_cache_hit_records_each_exception_once() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let base = temp_base("ready-exceptions");
        let exception = serde_json::json!({
            "kind": policy::FILE_COLLISION,
            "subject": "ruff",
            "detail": "cached test exception"
        });
        let (store, root, object) = ready_python_root(&base, &[exception]);
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
        fs::remove_dir_all(base).unwrap();
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
        let base = temp_base("borrowed-lease");
        let (store, root, object) = ready_python_root(&base, &[]);
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
        fs::remove_dir_all(base).unwrap();
    }

    /// A run that considered a root and skipped it as unrecoverable has not
    /// found "nothing to clean": unrecoverable candidates count as matched.
    #[test]
    fn unrecoverable_candidates_count_as_matched() {
        let base = temp_base("unrecoverable");
        let root = base.join("home/.tog/x/mystery");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        let filter = clean_filter(CleanRequest {
            ecosystem: None,
            from: None,
            tool: Some("ruff".into()),
        })
        .unwrap();
        let candidates = x_candidates(&base.join("home/.tog/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidate_matches(&candidates[0], &filter),
            CandidateMatch::Unrecoverable
        );
        assert_eq!(candidate_ecosystem(&candidates[0].path), None);
        fs::remove_dir_all(base).unwrap();
    }

    /// `candidate_ecosystem` decides which environments the clean summary
    /// calls node, so pin the order it reads: the recorded request, then a
    /// recovered legacy manifest, then the generated name prefix.
    #[test]
    fn candidate_ecosystem_reads_record_then_manifest_then_name() {
        let base = temp_base("ecosystem");
        let recorded = base.join("py-recorded");
        ensure_x_metadata_dir(&recorded).unwrap();
        write_x_request(&recorded, "node", "prettier", None, "ready").unwrap();
        assert_eq!(candidate_ecosystem(&recorded), Some("node"));

        let legacy = base.join("npm-legacy");
        fs::create_dir_all(legacy.join(".tog")).unwrap();
        fs::write(
            legacy.join("package.json"),
            r#"{"dependencies":{"prettier":"1.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(candidate_ecosystem(&legacy), Some("node"));

        let named = base.join("py-named");
        fs::create_dir_all(named.join(".tog")).unwrap();
        assert_eq!(candidate_ecosystem(&named), Some("python"));

        let unknown = base.join("mystery");
        fs::create_dir_all(unknown.join(".tog")).unwrap();
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

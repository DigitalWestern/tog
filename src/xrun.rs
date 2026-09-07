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
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::platform::Platform;
use crate::store::{self, RootEntry, Store};
use crate::{inspect, npm, policy, project, pypi, pyselect, python, ui};

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
    let name = CString::new(name)
        .map_err(|_| other("x: directory entry contains NUL; refusing to clean"))?;
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
    let name = CString::new(name)
        .map_err(|_| other("x: directory entry contains NUL; refusing to clean"))?;
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

/// Open the stable per-environment advisory lock relative to an already-open
/// x directory. Cleanup uses this path so renaming the pathname cannot make
/// its lock refer to a different environment.
fn lock_x_root_at(
    x_dir_fd: RawFd,
    root_name: &OsString,
    exclusive: bool,
    nonblocking: bool,
) -> io::Result<Option<fs::File>> {
    let locks = ensure_x_locks_dir_at(x_dir_fd)?;
    let lock_name = format!("{}.lock", root_name.to_string_lossy());
    let lock_name = CString::new(lock_name)
        .map_err(|_| other("x: environment root has an invalid lock name"))?;
    // SAFETY: the name is NUL-terminated and locks is owned by this function.
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
    Ok(Some(file))
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
    Ok(Some(file))
}

fn make_lock_inheritable(lock: &fs::File) -> io::Result<()> {
    fd_set_cloexec(lock.as_raw_fd(), false)
}

fn acquire_x_root(root: &Path) -> io::Result<fs::File> {
    let lock =
        lock_x_root(root, false, false)?.expect("blocking shared x lock always returns a file");
    // The lock is acquired before inspecting or creating the projection. A
    // cleanup that won the race can therefore remove the old root safely.
    ensure_x_metadata_dir(root)?;
    Ok(lock)
}

fn write_x_request(
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
) -> io::Result<()> {
    let path = root.join(X_REQUEST_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(other(format!(
                "x: request record {} is a symlink; refusing to overwrite it",
                path.display()
            )));
        }
    }
    let tmp = root
        .join(".blanket")
        .join(format!(".x.json.tmp.{}", std::process::id()));
    let record = serde_json::json!({
        "schema": "x-request/1",
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "state": state,
    });
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
            let home = store
                .root
                .parent()
                .ok_or_else(|| other("x: cannot locate blanket home for cached projection"))?;
            let project_key = hex::encode(Sha256::digest(
                root.canonicalize()?.to_string_lossy().as_bytes(),
            ));
            let projection = home
                .join("forests")
                .join(&project_key[..32])
                .join(projection_id);
            let expected = projection
                .join("node_modules")
                .canonicalize()
                .map_err(|_| missing())?;
            if canonical_link_target(&root.join("node_modules")) != Some(expected) {
                return Err(missing());
            }
            if let Some(workspaces) = closure["workspaces"].as_array() {
                for workspace in workspaces {
                    let source = workspace.as_str().ok_or_else(missing)?;
                    let encoded = encoded_workspace(source).ok_or_else(missing)?;
                    let expected = projection
                        .join("workspaces")
                        .join(encoded)
                        .join("node_modules")
                        .canonicalize()
                        .map_err(|_| missing())?;
                    if canonical_link_target(&root.join(source).join("node_modules"))
                        != Some(expected)
                    {
                        return Err(missing());
                    }
                }
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
    let closure = project::read_closure(root, ecosystem)?;
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
        .ok_or_else(|| other("x: cached closure has a malformed environment object"))?;
    if path != store.object_path(&id) || !store.has(&id) {
        return Err(other(
            "x: cached environment object is missing or outside the active store; run the command again",
        ));
    }
    let env_path = path
        .canonicalize()
        .map_err(|_| other("x: cached environment object is unavailable"))?;
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
    x_dir: fs::File,
    directory: fs::File,
    identity: (u64, u64),
}

fn read_x_request(root: &Path) -> Option<XRecord> {
    let value: serde_json::Value =
        serde_json::from_reader(fs::File::open(root.join(X_REQUEST_FILE)).ok()?).ok()?;
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
    })
    .filter(|_| value.get("schema").and_then(serde_json::Value::as_str) == Some("x-request/1"))
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

/// Return the canonical cleanup anchor after checking every user-controlled
/// directory above it without following a symlink. Missing `.blanket` or `x`
/// means there is nothing to clean; an existing unsafe component is an error.
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
    if !existing_real_directory(home_dir, "HOME")? {
        return Err(other(format!(
            "x: HOME directory {} does not exist; refusing to clean",
            home_dir.display()
        )));
    }
    if !existing_real_directory(blanket_dir, "$HOME/.blanket")? {
        return Ok(None);
    }
    if !existing_real_directory(x_dir, "$HOME/.blanket/x")? {
        return Ok(None);
    }
    let expected = fs::symlink_metadata(x_dir)?;
    let canonical = x_dir.canonicalize()?;
    let current = fs::symlink_metadata(x_dir)?;
    if expected.dev() != current.dev() || expected.ino() != current.ino() {
        return Err(other(format!(
            "x: cleanup directory {} changed while it was being validated; retry later",
            x_dir.display()
        )));
    }
    let directory = open_directory_path(&canonical)?;
    let actual = fd_identity(&directory)?;
    if actual != (current.dev(), current.ino()) {
        return Err(other(format!(
            "x: cleanup directory {} changed while it was being opened; retry later",
            x_dir.display()
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
    for name in store::read_dir_names_at(validated.directory.as_raw_fd())? {
        if name.as_bytes().first() == Some(&b'.') {
            continue;
        }
        let path = validated.path.join(&name);
        let metadata = match stat_at(validated.directory.as_raw_fd(), name.as_bytes()) {
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
        let directory = match open_directory_at(validated.directory.as_raw_fd(), name.as_bytes()) {
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
            x_dir: validated.directory.try_clone()?,
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
        let recovered_ecosystem = if legacy_packages(path, "python").is_some() {
            Some("python")
        } else if legacy_packages(path, "node").is_some() {
            Some("node")
        } else {
            name_ecosystem
        };
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
    Found { store: Store, entry: RootEntry },
    NotFound,
    Unknown,
}

fn originating_store(root: &Path) -> io::Result<Option<Store>> {
    let closures = root.join(".blanket/closures");
    let entries = match fs::read_dir(&closures) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_reader(fs::File::open(entry.path())?)
        {
            Ok(value) => value,
            Err(_) => continue,
        };
        let body = value.get("body").unwrap_or(&value);
        if let Some(store) = project::store_from_closure_body(body) {
            return Ok(Some(store));
        }
    }
    Ok(None)
}

fn registration_for(root: &Path) -> io::Result<Registration> {
    let Some(store) = originating_store(root)? else {
        return Ok(Registration::Unknown);
    };
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

/// Remove cached x projections. The store objects remain available for the
/// ordinary GC pass; deleting a projection is deliberately not object GC.
pub fn clean(request: CleanRequest) -> io::Result<()> {
    let filter = clean_filter(request)?;
    let x_dir = home()?.join(".blanket/x");
    let candidates = x_candidates(&x_dir)?;
    let mut matched = 0usize;
    let mut removed = 0usize;
    let mut skipped = 0usize;
    for candidate in candidates {
        match candidate_matches(&candidate, &filter) {
            CandidateMatch::Match => {}
            CandidateMatch::NoMatch => continue,
            CandidateMatch::Unrecoverable => {
                println!(
                    "blanket: skipped x environment {} (legacy root package could not be recovered; use 'blanket x --clean' with no tool to remove all x environments)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
        }
        matched += 1;
        let Some(_lock) = lock_x_root_at(candidate.x_dir.as_raw_fd(), &candidate.name, true, true)?
        else {
            println!(
                "blanket: skipped x environment {} (in use by a running tool; retry later)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        };
        let registration = registration_for(&candidate.path)?;
        // The candidate descriptor belongs to the directory that passed the
        // containment checks. Removing by pathname here would let a rename
        // followed by a symlink replacement redirect deletion elsewhere.
        store::remove_tree_at(candidate.directory.as_raw_fd())?;
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
        match registration {
            Registration::Found { store, entry } => {
                store.remove_root_entry(&entry)?;
                println!(
                    "blanket: removed x environment {}",
                    candidate.path.display()
                );
            }
            Registration::NotFound => println!(
                "blanket: removed x environment {} (no matching registry entry in its originating store)",
                candidate.path.display()
            ),
            Registration::Unknown => println!(
                "blanket: removed x environment {} (registry entry could not be dropped: originating store not found)",
                candidate.path.display()
            ),
        }
        removed += 1;
    }
    if matched == 0 {
        println!("blanket: x clean: nothing to clean");
    } else {
        println!(
            "blanket: x clean removed {removed} environment(s), skipped {skipped}; store objects remain until the next 'blanket gc'"
        );
    }
    Ok(())
}

pub fn run(platform: Platform, cwd: &Path, request: Request) -> io::Result<()> {
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
    let root = x_home
        .join(".blanket/x")
        .join(x_root_name(&store, platform, ecosystem, package, version));
    let x_lock = acquire_x_root(&root)?;
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
                    write_x_request(&root, ecosystem, package, version, "realizing")?;
                    realize_python(&store, platform, &root, package, version)?;
                    write_x_request(&root, ecosystem, package, version, "ready")?;
                } else {
                    check_cached_projection(&store, &root, "python")?;
                    if !x_request_file_exists(&root) {
                        write_x_request(&root, ecosystem, package, version, "ready")?;
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
                    write_x_request(&root, ecosystem, package, version, "realizing")?;
                    realize_node(&store, platform, &root, package, version)?;
                    write_x_request(&root, ecosystem, package, version, "ready")?;
                } else {
                    check_cached_projection(&store, &root, "node")?;
                    if !x_request_file_exists(&root) {
                        write_x_request(&root, ecosystem, package, version, "ready")?;
                    }
                }
                if !executable.is_file() {
                    return Err(other(format!(
                        "'{package}' installed but provides no '{bin}' executable; name it with --from: 'blanket x --from {package} <tool>'"
                    )));
                }
                let node_obj = npm::ensure_node_for(&store, platform)?;
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
    // Keep the shared lock private during all realization work. This is the
    // only point where it becomes inheritable by the tool being exec'd.
    make_lock_inheritable(&x_lock)?;
    Err(command.exec())
}

fn realize_python(
    store: &Store,
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
    let status = command.status()?;
    if !status.success() {
        return Err(other(format!(
            "could not resolve '{}' from PyPI (uv pip compile exit {status})",
            spec.trim()
        )));
    }
    let text = fs::read_to_string(&output)?;
    let plan = pypi::plan_python(platform, &text, pin.version)?;
    let env = project::realize_env(store, platform, &plan)?;
    project::project_env_with_selection(root, &env, &plan, &selection)?;
    ui::synced(&format!("x {package}"), &env);
    Ok(())
}

fn realize_node(
    store: &Store,
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
    let node_obj = npm::ensure_node_for(store, platform)?;
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
    let status = command.status()?;
    if !status.success() {
        return Err(other(format!(
            "could not resolve '{package}' from npm (npm exit {status})"
        )));
    }
    let plan = npm::plan_npm(platform, &fs::read_to_string(&lock)?)?;
    let env = npm::realize_node_env(store, platform, &plan, &[])?;
    npm::project_node_env(root, &env, platform, &plan, &[], false)?;
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
    fn shared_x_lock_blocks_nonblocking_cleanup_until_exec() {
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
        make_lock_inheritable(&shared).unwrap();
        let flags = unsafe { libc::fcntl(shared.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
        drop(shared);
        assert!(lock_x_root(&root, true, true).unwrap().is_some());
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
            },
            &from
        ));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cleanup_finds_alias_registration_in_closure_store() {
        let base = std::env::temp_dir().join(format!(
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
}

//! Environment (comforter) realization + projection.
//!
//! An environment is itself a store object (venv-shaped, immutable) whose
//! identity is the python object id plus every locked artifact hash. Two
//! projects with identical locks share one env object; different locks get
//! different objects and coexist. Projection into a project is one symlink.

use crate::fetch::download_verified_held;
use crate::platform::{no_pin, Platform};
use crate::store::{ProjectionBase, ProjectionRef, Store};
use crate::types::{ArtifactKind, Identity, Plan};
use crate::{pyselect, python, wheel};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static CLOSURE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Explicit references protected by one project closure.  The references are
/// validated against the supplied store at the boundary; serialized closure
/// JSON remains explanatory provenance, never deletion authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosureRefs {
    objects: BTreeSet<String>,
    projections: BTreeSet<ProjectionRef>,
}

impl ClosureRefs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn object_path(
        &mut self,
        store: &Store,
        activity: &crate::activity::StoreActivity,
        path: &Path,
    ) -> io::Result<&mut Self> {
        store.require_activity(activity, "closure object reference")?;
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "closure object path has no UTF-8 id",
                )
            })?;
        if path != store.object_path(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "closure object path {} is outside this store",
                    path.display()
                ),
            ));
        }
        self.object_id(store, activity, id)
    }

    pub fn object_id(
        &mut self,
        store: &Store,
        activity: &crate::activity::StoreActivity,
        id: &str,
    ) -> io::Result<&mut Self> {
        store.require_activity(activity, "closure object reference")?;
        if !crate::store::is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("closure object reference is not a complete object id: {id:?}"),
            ));
        }
        let path = store.object_path(id);
        if path.parent().and_then(Path::parent) != Some(store.root.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("closure object {id} is outside this store"),
            ));
        }
        store.validate_object_complete(activity, id)?;
        self.objects.insert(id.to_string());
        Ok(self)
    }

    pub fn optional_object_id(
        &mut self,
        store: &Store,
        activity: &crate::activity::StoreActivity,
        id: Option<&str>,
    ) -> io::Result<&mut Self> {
        if let Some(id) = id {
            self.object_id(store, activity, id)?;
        }
        Ok(self)
    }

    pub fn forest(
        &mut self,
        store: &Store,
        activity: &crate::activity::StoreActivity,
        path: &Path,
    ) -> io::Result<&mut Self> {
        self.projection(store, activity, ProjectionBase::Forests, path)
    }

    pub fn backup(
        &mut self,
        store: &Store,
        activity: &crate::activity::StoreActivity,
        path: &Path,
    ) -> io::Result<&mut Self> {
        self.projection(store, activity, ProjectionBase::Backups, path)
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.projections.is_empty()
    }

    pub(crate) fn into_record_parts(self) -> (BTreeSet<String>, BTreeSet<ProjectionRef>) {
        (self.objects, self.projections)
    }

    fn projection(
        &mut self,
        store: &Store,
        activity: &crate::activity::StoreActivity,
        base: ProjectionBase,
        path: &Path,
    ) -> io::Result<&mut Self> {
        store.require_activity(activity, "closure projection reference")?;
        let reference = store.projection_ref(base, path)?;
        self.projections.insert(reference);
        Ok(self)
    }
}

/// Common closure envelope (Sol review 4): every tailor's provenance lands
/// at .blanket/closures/<ecosystem>.json with a shared outer shape; the
/// `body` stays tailor-owned. Written atomically. Store ownership and exact
/// references are mandatory for production publication.
pub fn write_closure(
    project_dir: &Path,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &crate::activity::StoreActivity,
    refs: ClosureRefs,
) -> io::Result<()> {
    store.require_activity(activity, "closure publication")?;
    write_closure_inner(
        project_dir,
        ecosystem,
        body,
        store,
        activity,
        Some(refs),
        None,
    )
}

/// Publish a closure while the caller holds the project's transaction lock
/// across its preceding projection switch. This is the sequencing primitive
/// used by producers that move a user directory or replace a visible link
/// before writing the envelope.
pub(crate) fn write_closure_with_project_lock(
    project_dir: &Path,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &crate::activity::StoreActivity,
    refs: ClosureRefs,
    project_lock: &fs::File,
) -> io::Result<()> {
    store.require_activity(activity, "closure publication")?;
    write_closure_inner(
        project_dir,
        ecosystem,
        body,
        store,
        activity,
        Some(refs),
        Some(project_lock),
    )
}

/// Named alias retained for callers that adopted the first root/2 draft.
pub fn write_closure_with_refs(
    project_dir: &Path,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &crate::activity::StoreActivity,
    refs: ClosureRefs,
) -> io::Result<()> {
    write_closure(project_dir, ecosystem, body, store, activity, refs)
}

/// Persist the producer's complete root union before a project projection or
/// user backup is switched. This is the phase-2 half of closure publication;
/// `write_closure` repeats the union after the visible closure is written so
/// a crash can only leave extra protection.
pub(crate) fn persist_root_for_refs_with_project_lock(
    project_dir: &Path,
    store: &Store,
    activity: &crate::activity::StoreActivity,
    refs: &ClosureRefs,
    project_lock: &fs::File,
) -> io::Result<()> {
    store.require_activity(activity, "root publication")?;
    let (objects, projections) = refs.clone().into_record_parts();
    store
        .register_root_parts_with_project_lock(
            activity,
            project_dir,
            objects,
            projections,
            project_lock,
        )
        .map(|_| ())
}

/// Compatibility writer for old synthetic unit fixtures. It is not available
/// to production builds, so a producer cannot silently fall back to inferred
/// JSON references.
#[cfg(test)]
pub(crate) fn write_closure_legacy(
    project_dir: &Path,
    ecosystem: &str,
    body: serde_json::Value,
) -> io::Result<()> {
    let store = match store_from_closure_body(&body) {
        Some(store) => store,
        None => Store::open()?,
    };
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    write_closure_inner(project_dir, ecosystem, body, &store, &activity, None, None)
}

fn write_closure_inner(
    project_dir: &Path,
    ecosystem: &str,
    mut body: serde_json::Value,
    store: &Store,
    activity: &crate::activity::StoreActivity,
    explicit_refs: Option<ClosureRefs>,
    supplied_project_lock: Option<&fs::File>,
) -> io::Result<()> {
    store.require_activity(activity, "closure publication")?;
    let project_dir = project_dir.canonicalize()?;
    let blanket_dir = project_dir.join(".blanket");
    let closures_dir = blanket_dir.join("closures");
    // Keep the per-project transaction lock through both durable root
    // publication and the visible closure rename. A second producer cannot
    // observe a root from one generation paired with a closure from another.
    let owned_project_lock = if explicit_refs.is_some() && supplied_project_lock.is_none() {
        Some(store.project_lock(&project_dir)?)
    } else {
        None
    };
    let project_lock = supplied_project_lock.or(owned_project_lock.as_ref());

    // Keep the directory chain open while creating and publishing the file.
    // Path-based create/open/rename would let a swapped parent redirect a
    // closure write after the lexical containment checks below.
    let project_fd = open_directory(&project_dir, "project directory")?;
    mkdir_at(project_fd.as_raw_fd(), ".blanket", &blanket_dir)?;
    let blanket_fd = open_directory_at(project_fd.as_raw_fd(), ".blanket", &blanket_dir)?;
    mkdir_at(blanket_fd.as_raw_fd(), "closures", &closures_dir)?;
    let closures_fd = open_directory_at(blanket_fd.as_raw_fd(), "closures", &closures_dir)?;

    for (path, label) in [
        (&blanket_dir, ".blanket"),
        (&closures_dir, ".blanket/closures"),
    ] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "{} is not a real directory; refusing to write closures",
                path.display()
            )));
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&project_dir) {
            return Err(io::Error::other(format!(
                "{label} at {} escapes the project; refusing to write closures",
                canonical.display()
            )));
        }
    }
    // A symlinked closures dir would carry provenance writes outside the
    // project (same class as the cargo-home/bin escape).
    let dir = closures_dir.canonicalize()?;
    if !dir.starts_with(&project_dir) {
        return Err(io::Error::other(format!(
            "{} escapes the project; refusing to write closures there",
            dir.display()
        )));
    }
    let pending = crate::policy::pending();
    if let Some(body) = body.as_object_mut() {
        body.insert("exceptions".into(), serde_json::to_value(&pending)?);
    }
    // Envelope-level platform (LINUX_PORT.md stage 6): a project synced on
    // a Mac and then on a Linux box carries two different closures over
    // time; readers must not assume the body's object ids are valid for
    // the current host. Additive field, schema unchanged.
    let platform = Platform::host()?.triple();
    // Protect the complete object set before publishing the visible closure.
    // The compatibility writer below is retained only for old synthetic
    // callers whose placeholder paths predate full object ids; real producer
    // closures enter the durable root/2 path here.
    let durable_root = match explicit_refs {
        Some(refs) => {
            let (objects, projections) = refs.into_record_parts();
            let project_lock = project_lock
                .as_ref()
                .expect("strict closure publication owns a project lock");
            store.register_root_parts_with_project_lock(
                activity,
                &project_dir,
                objects,
                projections,
                project_lock,
            )?;
            true
        }
        None => match store.register_root_with_closure(&project_dir, ecosystem, &body) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => false,
            Err(error) => return Err(error),
        },
    };
    let envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": ecosystem,
        "platform": platform,
        "projected_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "body": body,
    });
    let dest = dir.join(format!("{ecosystem}.json"));
    let bytes = serde_json::to_vec_pretty(&envelope)?;
    let dest_name = dest
        .file_name()
        .ok_or_else(|| io::Error::other("closure destination has no file name"))?;
    let (tmp_name, mut file) = loop {
        let counter = CLOSURE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let candidate = format!(
            ".{ecosystem}.json.tmp.{}.{}.{}",
            std::process::id(),
            nanos,
            counter
        );
        match open_closure_temp(closures_fd.as_raw_fd(), &candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let result = (|| {
        use std::io::Write as _;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        rename_at(
            closures_fd.as_raw_fd(),
            &tmp_name,
            closures_fd.as_raw_fd(),
            dest_name,
        )?;
        fsync_directory(&closures_fd)
    })();
    if result.is_err() {
        unlink_at(closures_fd.as_raw_fd(), &tmp_name);
    }
    result?;
    if !durable_root {
        store.register_root_with_activity(activity, &project_dir)?;
    }
    crate::policy::clear();
    Ok(())
}

fn open_directory(path: &Path, label: &str) -> io::Result<fs::File> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} contains a NUL byte; refusing to write closures"),
        )
    })?;
    // SAFETY: path is a valid NUL-terminated path and the returned fd is
    // immediately wrapped in a File that owns it.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("open {label}: {error}"),
        ));
    }
    // SAFETY: fd was returned by open above and is now owned by File.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn mkdir_at(parent_fd: RawFd, name: &str, path: &Path) -> io::Result<()> {
    let name_c = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} contains a NUL byte; refusing to write closures"),
        )
    })?;
    // SAFETY: parent_fd is an open directory and name_c is NUL-terminated.
    let result = unsafe { libc::mkdirat(parent_fd, name_c.as_ptr(), 0o755) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(io::Error::new(
                error.kind(),
                format!("create {}: {error}", path.display()),
            ));
        }
    }
    Ok(())
}

fn open_directory_at(parent_fd: RawFd, name: &str, path: &Path) -> io::Result<fs::File> {
    let name_c = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} contains a NUL byte; refusing to write closures"),
        )
    })?;
    // SAFETY: parent_fd is an open directory and name_c is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
        ) {
            return Err(io::Error::other(format!(
                "{} is not a real directory; refusing to write closures",
                path.display()
            )));
        }
        return Err(io::Error::new(
            error.kind(),
            format!("open {}: {error}", path.display()),
        ));
    }
    // SAFETY: fd was returned by openat above and is now owned by File.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// Atomically install a managed symlink using an already-open parent
/// directory. Existing symlinks may be replaced; a real file or directory is
/// never silently overwritten. This is used for visible project projections
/// after their durable root record has been published.
pub(crate) fn replace_project_symlink(path: &Path, target: &Path, label: &str) -> io::Result<()> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{label} has no parent")))?;
    ensure_real_directory_chain(parent, label)?;
    let parent_fd = open_directory(parent, label)?;
    let destination = path
        .file_name()
        .ok_or_else(|| invalid(format!("{label} has no destination name")))?;
    match crate::store::stat_at(parent_fd.as_raw_fd(), destination.as_bytes()) {
        Ok(stat) => {
            if (stat.st_mode & libc::S_IFMT) != libc::S_IFLNK {
                return Err(invalid(format!(
                    "{label} {} is a real file or directory; refusing to overwrite it",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let counter = CLOSURE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(
        ".{}.blanket-swap.{}.{}.{}",
        destination.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        counter
    );
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        invalid(format!(
            "{label} target contains a NUL byte; refusing to publish"
        ))
    })?;
    let temporary_c = CString::new(temporary.as_bytes())
        .map_err(|_| invalid(format!("{label} temporary name contains a NUL byte")))?;
    // SAFETY: parent_fd is an open directory and both names are valid
    // NUL-terminated strings owned by this function.
    if unsafe { libc::symlinkat(target.as_ptr(), parent_fd.as_raw_fd(), temporary_c.as_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = rename_at(
        parent_fd.as_raw_fd(),
        &temporary,
        parent_fd.as_raw_fd(),
        destination,
    )
    .and_then(|()| fsync_directory(&parent_fd));
    if result.is_err() {
        unlink_at(parent_fd.as_raw_fd(), &temporary);
    }
    result
}

/// Create missing parent directories without following a pre-existing
/// symlink in the path. The final open_directory call still rechecks the
/// resulting parent with O_NOFOLLOW.
fn ensure_real_directory_chain(path: &Path, label: &str) -> io::Result<()> {
    let mut current = path.to_path_buf();
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{label} parent {} is not a real directory",
                            current.display()
                        ),
                    ));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = current.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{label} parent has no directory name"),
                    )
                })?;
                missing.push(name.to_os_string());
                current.pop();
            }
            Err(error) => return Err(error),
        }
    }
    for name in missing.into_iter().rev() {
        current.push(name);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{label} parent {} is not a real directory",
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

fn open_closure_temp(parent_fd: RawFd, name: &str) -> io::Result<fs::File> {
    let name_c = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("closure temp name {name:?} contains a NUL byte"),
        )
    })?;
    // SAFETY: parent_fd is an open directory and name_c is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was returned by openat above and is now owned by File.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn rename_at(
    old_dir_fd: RawFd,
    old_name: &str,
    new_dir_fd: RawFd,
    new_name: &std::ffi::OsStr,
) -> io::Result<()> {
    let old_name = CString::new(old_name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "closure temporary name contains a NUL byte",
        )
    })?;
    let new_name = CString::new(new_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "closure destination name contains a NUL byte",
        )
    })?;
    // SAFETY: both fds remain open directory handles and both names are
    // NUL-terminated relative names.
    let result =
        unsafe { libc::renameat(old_dir_fd, old_name.as_ptr(), new_dir_fd, new_name.as_ptr()) };
    if result < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("publish closure: {error}"),
        ));
    }
    Ok(())
}

fn fsync_directory(dir: &fs::File) -> io::Result<()> {
    // SAFETY: dir owns a valid open directory fd.
    if unsafe { libc::fsync(dir.as_raw_fd()) } < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("sync closure directory: {error}"),
        ));
    }
    Ok(())
}

fn unlink_at(parent_fd: RawFd, name: &str) {
    let Ok(name) = CString::new(name) else {
        return;
    };
    // SAFETY: parent_fd is an open directory and name is a relative name.
    let _ = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
}

#[cfg(test)]
pub(crate) fn store_from_closure_body(body: &serde_json::Value) -> Option<Store> {
    fn find(value: &serde_json::Value) -> Option<Store> {
        match value {
            serde_json::Value::String(text) if Path::new(text).is_absolute() => {
                let path = Path::new(text);
                for ancestor in path.ancestors() {
                    if ancestor.file_name().and_then(|name| name.to_str()) == Some("objects") {
                        let root = ancestor.parent()?.to_path_buf();
                        if root.join("objects").is_dir() {
                            return Some(Store { root });
                        }
                    }
                }
                None
            }
            serde_json::Value::Array(values) => values.iter().find_map(find),
            serde_json::Value::Object(values) => values.values().find_map(find),
            _ => None,
        }
    }
    find(body)
}

/// Read a tailor's closure body back (for `blanket run` and friends).
pub fn read_closure(project_dir: &Path, ecosystem: &str) -> io::Result<serde_json::Value> {
    let path = project_dir.join(format!(".blanket/closures/{ecosystem}.json"));
    let text = fs::read_to_string(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("read {}: {e}; run `blanket sync` first", path.display()),
        )
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse {}: {e}; run `blanket sync` first", path.display()),
        )
    })?;
    if let Some(recorded) = v["platform"].as_str() {
        let host = Platform::host()?;
        if recorded != host.triple() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{}: closure was projected on {recorded}; this host is {}; run `blanket sync` here",
                    path.display(),
                    host.triple()
                ),
            ));
        }
    }
    // Envelopes without a platform field predate the Linux port (all darwin);
    // they are accepted and their object ids simply will not resolve on a
    // foreign store, which already demands a re-sync.
    if v["schema"] != "closure/1" || v["ecosystem"] != ecosystem {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: unknown closure schema/ecosystem; re-run `blanket sync`",
                path.display()
            ),
        ));
    }
    Ok(v["body"].clone())
}

/// Copy-on-write clone of a whole tree (cp -c uses APFS clonefile; plain
/// copy fallback), then restore user-write bits, which the clone inherits
/// as read-only from the store. Used for writable projections of immutable
/// objects (npm mutablePackages, elixir deps trees).
pub fn clone_tree(src: &Path, dest: &Path) -> io::Result<()> {
    clone_tree_for(src, dest, Platform::host()?)
}

pub(crate) fn clone_tree_for(src: &Path, dest: &Path, platform: Platform) -> io::Result<()> {
    use std::process::Command;
    let clone = if platform.is_macos() {
        Command::new("/bin/cp")
            .args(["-Rc"])
            .arg(src)
            .arg(dest)
            .status()?
    } else {
        Command::new("/bin/cp")
            .args(["-a", "--reflink=auto"])
            .arg(src)
            .arg(dest)
            .status()?
    };
    if !clone.success() {
        if dest.exists() {
            crate::store::remove_tree(dest)?;
        }
        let plain = Command::new("/bin/cp")
            .arg("-R")
            .arg(src)
            .arg(dest)
            .status()?;
        if !plain.success() {
            return Err(io::Error::other("cloning projected tree failed"));
        }
    }
    restore_write_bits(dest)
}

/// Store-aware copy-on-write clone. The copy utility is a child that reads a
/// store object and writes a managed projection, so its complete spawn/wait
/// interval must remain under operation protection.
pub(crate) fn clone_tree_for_store(
    store: &Store,
    src: &Path,
    dest: &Path,
    platform: Platform,
) -> io::Result<()> {
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    let clone = if platform.is_macos() {
        let mut command = std::process::Command::new("/bin/cp");
        command.args(["-Rc"]).arg(src).arg(dest);
        crate::supervise::status(&mut command, &activity)?
    } else {
        let mut command = std::process::Command::new("/bin/cp");
        command.args(["-a", "--reflink=auto"]).arg(src).arg(dest);
        crate::supervise::status(&mut command, &activity)?
    };
    if !clone.success() {
        if dest.exists() {
            crate::store::remove_tree(dest)?;
        }
        let mut plain = std::process::Command::new("/bin/cp");
        plain.arg("-R").arg(src).arg(dest);
        let plain_status = crate::supervise::status(&mut plain, &activity)?;
        if !plain_status.success() {
            return Err(io::Error::other("cloning projected tree failed"));
        }
    }
    restore_write_bits(dest)
}

fn restore_write_bits(path: &Path) -> io::Result<()> {
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

/// Resolve an object reference from a closure body, CONTAINED to the
/// active store: the recorded id must exist in the store and the recorded
/// path must be exactly the store's path for that id. A project-editable
/// closure must never inject arbitrary executable paths into `blanket run`
/// (Sol review 5, reproduced against the ruby closure).
pub fn closure_object(
    store: &crate::store::Store,
    closure: &serde_json::Value,
    key: &str,
    probe: &str,
) -> io::Result<PathBuf> {
    let bad = |msg: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure {key}: {msg}; run `blanket sync` first"),
        )
    };
    let id = closure[key]["id"]
        .as_str()
        .ok_or_else(|| bad("missing id"))?;
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(bad("malformed id"));
    }
    if !store.has(id)? {
        return Err(bad("object not in the store"));
    }
    let path = store.object_path(id);
    if closure[key]["path"].as_str().map(Path::new) != Some(path.as_path()) {
        return Err(bad("recorded path disagrees with the store"));
    }
    if !probe.is_empty() && !path.join(probe).exists() {
        return Err(bad("object is missing its expected content"));
    }
    Ok(path)
}

/// Realize the environment object for `plan`. Downloads/validates all
/// artifacts, assembles the venv shape in a staging dir, commits atomically.
/// Cache hit if the identical env already exists.
pub fn realize_env(store: &Store, platform: Platform, plan: &Plan) -> io::Result<PathBuf> {
    realize_env_at_depth(store, platform, plan, 0)
}

/// Canonical package order and duplicate rejection shared by planning and
/// realization.
fn canonical_packages<'a>(plan: &'a Plan) -> io::Result<Vec<&'a crate::types::LockedPackage>> {
    let mut packages: Vec<&crate::types::LockedPackage> = plan.packages.iter().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    for w in packages.windows(2) {
        if w[0].name == w[1].name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate package in plan: {}", w[0].name),
            ));
        }
    }
    Ok(packages)
}

/// Build the one canonical environment identity used by both planning and
/// realization. `cpython_id` is pure during planning and is the realized
/// interpreter object's id during execution; every other input is shared.
fn environment_identity(
    store: &Store,
    platform: Platform,
    plan: &Plan,
    cpython_id: &str,
) -> io::Result<Identity> {
    let pin = python::lookup(platform, &plan.python_version).ok_or_else(|| {
        no_pin(
            &format!("cpython {}", plan.python_version),
            platform,
            "stage 2",
        )
    })?;
    let packages = canonical_packages(plan)?;
    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "python-env/2".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert("cpython".to_string(), cpython_id.to_string());
    let mut native_libs_id = None;
    for p in packages {
        let value = match p.kind {
            ArtifactKind::Wheel => format!("Wheel:{}", p.sha256),
            ArtifactKind::Sdist => {
                // A git dependency is packed into a deterministic sdist first,
                // so its identity is the ordinary sdist derivation over that
                // archive's hash (a pure function of the commit's tree).
                let owned;
                let p = if p.git.is_some() {
                    owned = crate::build::git_sdist_package(store, platform, p)?;
                    &owned
                } else {
                    p
                };
                let sdist = crate::build::plan_sdist_identity_input(
                    store,
                    platform,
                    p,
                    &pin.version,
                    Some(plan),
                )?;
                if native_libs_id.is_none() {
                    native_libs_id = sdist.native_libs_id;
                }
                sdist.input
            }
        };
        inputs.insert(format!("pkg:{}", p.name), value);
    }
    if let Some(native_libs_id) = native_libs_id {
        inputs.insert("native_libs".into(), native_libs_id);
    }
    Ok(Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: plan.python_version.clone(),
        inputs,
    })
}

/// Compute an environment object id without realizing its files. Build
/// planning uses this so an isolated sdist can commit its schema-3 identity
/// into the parent before the parent cache lookup.
pub(crate) fn planned_env_object_id(
    store: &Store,
    platform: Platform,
    plan: &Plan,
) -> io::Result<String> {
    let pin = python::lookup(platform, &plan.python_version).ok_or_else(|| {
        no_pin(
            &format!("cpython {}", plan.python_version),
            platform,
            "stage 2",
        )
    })?;
    let cpython_id = python::object_id_for(platform, &pin.version)?;
    Ok(environment_identity(store, platform, plan, &cpython_id)?.object_id())
}

/// Internal realization entry point used by sdist build environments. The
/// depth is carried through nested build-requirement sdists so a malicious or
/// pathological chain cannot recurse forever.
pub(crate) fn realize_env_at_depth(
    store: &Store,
    platform: Platform,
    plan: &Plan,
    sdist_depth: usize,
) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Python environment", "stage 2")?;
    let pin = python::lookup(platform, &plan.python_version).ok_or_else(|| {
        no_pin(
            &format!("cpython {}", plan.python_version),
            platform,
            "stage 2",
        )
    })?;
    let python_obj = python::ensure_python_for(store, pin, platform)?;

    // Identity planning and realization use exactly the same input builder.
    // In particular, native sdist requirements contribute the pure libset id;
    // the libset itself is realized only by a build that actually runs.
    let cpython_id = python_obj
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let identity = environment_identity(store, platform, plan, &cpython_id)?;
    let id = identity.object_id();
    if store.has(&id)? {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    // Canonical package order + duplicate rejection: identity uses the same
    // helper, and this borrowed list drives deterministic installation.
    let packages = canonical_packages(plan)?;

    // Fetch everything first (all-or-nothing before assembly starts).
    let mut artifacts: Vec<(&crate::types::LockedPackage, PathBuf)> = Vec::new();
    // Keep verified cache leases alive until every wheel has been extracted.
    let mut _cache_leases = Vec::new();
    for &p in &packages {
        let wheel_file = match p.kind {
            ArtifactKind::Wheel => {
                let lease = download_verified_held(store, &p.url, &p.sha256)?;
                let path = lease.to_path_buf();
                drop(lease);
                path
            }
            // sdist -> wheel via sandboxed derivation (network denied).
            ArtifactKind::Sdist => {
                let owned;
                let source = if p.git.is_some() {
                    owned = crate::build::git_sdist_package(store, platform, p)?;
                    &owned
                } else {
                    p
                };
                crate::build::build_sdist_wheel_at_depth(
                    store,
                    platform,
                    source,
                    &pin.version,
                    Some(plan),
                    sdist_depth + 1,
                )?
            }
        };
        artifacts.push((p, wheel_file));
    }
    // Sdist realization may recursively fetch toolchains. Re-verify all
    // wheel inputs only after that work, then hold their leases through wheel
    // extraction and publication.
    for (p, path) in &mut artifacts {
        if p.kind == ArtifactKind::Wheel {
            let lease = download_verified_held(store, &p.url, &p.sha256)?;
            *path = lease.to_path_buf();
            _cache_leases.push(lease);
        }
    }

    let minor = pin.version.split('.').take(2).collect::<Vec<_>>().join(".");
    let staged = store.stage()?;
    let bin = staged.join("bin");
    let site = staged.join(format!("lib/python{minor}/site-packages"));
    fs::create_dir_all(&bin)?;
    fs::create_dir_all(&site)?;

    // Standard venv shape: symlinked interpreter + pyvenv.cfg. CPython finds
    // pyvenv.cfg next to the symlink, so store-side python resolves this env.
    let py_target = python_obj.join("bin/python3");
    symlink(&py_target, bin.join("python"))?;
    symlink("python", bin.join("python3"))?;
    symlink("python", bin.join(format!("python{minor}")))?;
    fs::write(
        staged.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\nversion = {}\n",
            python_obj.join("bin").display(),
            pin.version
        ),
    )?;

    // The env's python path — as it will exist after commit — for shebangs.
    let final_python = store.object_path(&id).join("bin/python");
    let mut installed = BTreeMap::new();
    for (_p, wheel_file) in &artifacts {
        wheel::install_wheel(
            wheel_file,
            &site,
            &bin,
            &minor,
            &final_python,
            &mut installed,
        )?;
    }

    let candidate = crate::policy::object_exceptions();
    let mut deps = crate::store::ObjectDeps::new();
    deps.object_id(&crate::store::object_id_from_path(&python_obj)?)?;
    if let Some(native_id) = identity.inputs.get("native_libs") {
        deps.object_id(native_id)?;
    }
    for (package, wheel_file) in &artifacts {
        match package.kind {
            ArtifactKind::Wheel => {
                deps.cache_digest(crate::fetch::Digest::sha256(&package.sha256)?);
            }
            ArtifactKind::Sdist => {
                let object = wheel_file.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "sdist wheel path has no object parent: {}",
                            wheel_file.display()
                        ),
                    )
                })?;
                deps.object_id(&crate::store::object_id_from_path(object)?)?;
            }
        }
    }
    let (object, applied) = store.commit_with_deps(&identity, &staged, &candidate, &deps)?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// If `path` is a real directory (a pre-blanket install), move it out of the
/// project into `<blanket-home>/backups/` so no tool (tsc, vitest, eslint)
/// ever crawls it again. blanket-home is derived from the env object's store
/// (`<store>/objects/<id>` -> store parent), so tests with temp stores back
/// up into the temp dir, never the real one. Returns the backup location.
pub fn backup_real_dir(path: &Path, env_obj: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(md) if !md.file_type().is_symlink() && md.is_dir() => {}
        _ => return Ok(None),
    }
    let home = env_obj
        .parent() // objects/
        .and_then(|p| p.parent()) // store root
        .and_then(|p| p.parent()) // blanket home
        .ok_or_else(|| io::Error::other("cannot locate blanket home for backup"))?;
    let backups = home.join("backups");
    fs::create_dir_all(&backups)?;
    let project = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let dirname = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dir".into());
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dest = backups.join(format!("{project}-{dirname}-{secs}"));
    fs::rename(path, &dest).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not move existing {} aside to {}: {e}",
                path.display(),
                dest.display()
            ),
        )
    })?;
    eprintln!(
        "blanket: moved existing {} to {} (delete it once you're happy)",
        path.display(),
        dest.display()
    );
    Ok(Some(dest))
}

/// Store-owned backup variant used by new projections.  The legacy helper
/// above remains for old callers/importers; its sibling namespace is
/// retention-only once GC safety B is enabled.
pub fn backup_real_dir_for_store(path: &Path, store: &Store) -> io::Result<Option<PathBuf>> {
    let Some(destination) = reserve_backup_real_dir_for_store(path, store)? else {
        return Ok(None);
    };
    move_reserved_backup(path, &destination)?;
    Ok(Some(destination))
}

/// Reserve a store-owned backup destination without moving the user's
/// directory. Producers use this before publishing a root/2 record; the
/// reservation itself is safe over-retention if a later projection step
/// fails.
pub fn reserve_backup_real_dir_for_store(
    path: &Path,
    store: &Store,
) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(md) if !md.file_type().is_symlink() && md.is_dir() => {}
        _ => return Ok(None),
    }
    let backups = store.root.join("backups");
    store.ensure_namespace(Path::new("backups"))?;
    let backups_dir = open_real_directory(&backups, "store backups")?;
    let mut sequence = 0u64;
    let dest = loop {
        let name = format!(
            "backup-{}-{}-{sequence}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        match crate::store::stat_at(backups_dir.as_raw_fd(), name.as_bytes()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => break backups.join(name),
            Ok(_) => {}
            Err(error) => return Err(error),
        }
        sequence = sequence.saturating_add(1);
    };
    Ok(Some(dest))
}

/// Move a previously reserved real directory into the store-owned backup
/// namespace. The destination is checked lexically before the rename and is
/// never followed as a symlink.
pub fn move_reserved_backup(path: &Path, destination: &Path) -> io::Result<()> {
    let backups = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved backup has no parent directory",
        )
    })?;
    let backup_root = backups.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved backup is not inside a store",
        )
    })?;
    if backups.file_name().and_then(|name| name.to_str()) != Some("backups")
        || destination.parent() != Some(backups)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "reserved backup {} is outside store {}",
                destination.display(),
                backup_root.display()
            ),
        ));
    }

    let source_parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup source has no parent directory",
        )
    })?;
    let source_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup source name is not valid UTF-8",
            )
        })?;
    let destination_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved backup has no destination name",
        )
    })?;
    let source_stat = fs::symlink_metadata(path)?;
    if source_stat.file_type().is_symlink() || !source_stat.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("backup source {} is not a real directory", path.display()),
        ));
    }
    let source_dir = open_real_directory(source_parent, "backup source parent")?;
    let backups_dir = open_real_directory(backups, "store backups")?;
    let source_entry = crate::store::stat_at(source_dir.as_raw_fd(), source_name.as_bytes())?;
    if source_entry.st_dev != source_stat.dev() || source_entry.st_ino != source_stat.ino() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!(
                "backup source {} changed during publication",
                path.display()
            ),
        ));
    }
    match crate::store::stat_at(backups_dir.as_raw_fd(), destination_name.as_bytes()) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "backup destination {} already exists",
                    destination.display()
                ),
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    rename_entry_at(
        source_dir.as_raw_fd(),
        source_name.as_bytes(),
        backups_dir.as_raw_fd(),
        destination_name.as_bytes(),
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not move existing {} aside to {}: {e}",
                path.display(),
                destination.display()
            ),
        )
    })?;
    source_dir.sync_all()?;
    backups_dir.sync_all()?;
    eprintln!(
        "blanket: moved existing {} to {} (delete it once you're happy)",
        path.display(),
        destination.display()
    );
    Ok(())
}

fn open_real_directory(path: &Path, label: &str) -> io::Result<fs::File> {
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

fn rename_entry_at(
    old_dir_fd: RawFd,
    old_name: &[u8],
    new_dir_fd: RawFd,
    new_name: &[u8],
) -> io::Result<()> {
    let old_name = CString::new(old_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source name contains NUL"))?;
    let new_name = CString::new(new_name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination name contains NUL")
    })?;
    // SAFETY: both descriptors are open directories and both names are
    // NUL-terminated relative entry names.
    if unsafe { libc::renameat(old_dir_fd, old_name.as_ptr(), new_dir_fd, new_name.as_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Recover the store from an explicit realized object path.  This is a
/// narrow path-shape check for producer APIs, not the old recursive JSON
/// provenance guess used by legacy x cleanup.
pub(crate) fn store_from_object_path(path: &Path) -> Option<Store> {
    let objects = path.parent()?;
    if objects.file_name()?.to_str()? != "objects" {
        return None;
    }
    let root = objects.parent()?.to_path_buf().canonicalize().ok()?;
    if root.join("objects") != objects.canonicalize().ok()? {
        return None;
    }
    Some(Store { root })
}

/// Project an env into a project directory: `.venv` symlink (atomic swap)
/// plus closure-envelope provenance (.blanket/closures/python.json).
pub fn project_env(project_dir: &Path, env_obj: &Path, plan: &Plan) -> io::Result<()> {
    project_env_inner(project_dir, env_obj, plan, None, &[])
}

/// A project file the plan was computed from, recorded in the closure so
/// `blanket status` can tell whether the projection is still current
/// without re-planning. Additive closure field (`inputs`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InputRecord {
    /// Project-relative path.
    pub path: String,
    pub sha256: String,
}

/// Hash the given files (absolute or project-relative); missing ones are
/// skipped so callers can list every candidate input.
pub fn input_records(project_dir: &Path, candidates: &[PathBuf]) -> io::Result<Vec<InputRecord>> {
    use sha2::{Digest, Sha256};
    let mut records: Vec<InputRecord> = Vec::new();
    for candidate in candidates {
        let absolute = if candidate.is_absolute() {
            candidate.clone()
        } else {
            project_dir.join(candidate)
        };
        if !absolute.is_file() {
            continue;
        }
        let relative = absolute
            .strip_prefix(project_dir)
            .unwrap_or(&absolute)
            .to_string_lossy()
            .into_owned();
        if records.iter().any(|record| record.path == relative) {
            continue;
        }
        records.push(InputRecord {
            sha256: hex::encode(Sha256::digest(fs::read(&absolute)?)),
            path: relative,
        });
    }
    Ok(records)
}

/// `project_env_with_selection` plus the input files recorded for status.
pub fn project_env_with_inputs(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
    inputs: &[InputRecord],
) -> io::Result<()> {
    project_env_inner(project_dir, env_obj, plan, Some(selection), inputs)
}

/// Project a Python env and retain the exact interpreter constraint that led
/// to the selected pin. This is separate from `project_env` to keep the
/// existing kernel-facing helper compatible with hand-built Plans.
pub fn project_env_with_selection(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
) -> io::Result<()> {
    project_env_inner(project_dir, env_obj, plan, Some(selection), &[])
}

fn project_env_inner(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: Option<&pyselect::PythonSelection>,
    inputs: &[InputRecord],
) -> io::Result<()> {
    let venv = project_dir.join(".venv");
    let store = store_from_object_path(env_obj)
        .ok_or_else(|| io::Error::other("environment object is not in a Blanket store"))?;
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    let env_obj = env_obj.canonicalize()?;
    let project_lock = store.project_lock(project_dir)?;
    let native_reference = crate::nativelibs::env_reference(&env_obj)?;
    let backup = reserve_backup_real_dir_for_store(&venv, &store)?;
    let mut refs = ClosureRefs::new();
    refs.object_path(&store, &activity, &env_obj)?;
    if let Some(native_reference) = native_reference.as_ref() {
        let native_id = native_reference["id"].as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native library closure reference has no object id",
            )
        })?;
        refs.object_id(&store, &activity, native_id)?;
    }
    if let Some(backup) = backup.as_ref() {
        refs.backup(&store, &activity, backup)?;
    }
    // Durable protection precedes both the user-data move and the visible
    // .venv switch. A failed later step therefore over-retains safely.
    persist_root_for_refs_with_project_lock(project_dir, &store, &activity, &refs, &project_lock)?;
    if let Some(backup) = backup.as_ref() {
        move_reserved_backup(&venv, backup)?;
    }
    // replace_project_symlink makes and renames its own temporary link; an
    // extra one here would be left behind in the user's project on every
    // sync.
    replace_project_symlink(&venv, &env_obj, ".venv")?;

    let python = selection
        .map(|selection| {
            serde_json::json!({
                "version": selection.pin.version,
                "constraint": selection.constraint,
                "constraint_source": selection.constraint_source,
            })
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "version": plan.python_version,
                "constraint": serde_json::Value::Null,
                "constraint_source": serde_json::Value::Null,
            })
        });
    write_closure_with_project_lock(
        project_dir,
        "python",
        serde_json::json!({
            "env_object": env_obj,
            "native_libs": native_reference,
            "backup_path": backup,
            "plan": plan,
            "python": python,
            "inputs": inputs,
        }),
        &store,
        &activity,
        refs,
        &project_lock,
    )
}

#[cfg(test)]
mod closure_platform_tests {
    use super::*;
    use crate::types::LockedPackage;
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn test_store(label: &str) -> Store {
        let root = std::env::temp_dir().join(format!(
            "blanket-project-identity-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        Store {
            root: root.canonicalize().unwrap(),
        }
    }

    fn local_sdist(store: &Store, name: &str, requires: &str) -> LockedPackage {
        let source = store.root.join(format!("{name}-source"));
        let root = source.join(format!("{name}-1.0"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            format!("[build-system]\nrequires = [{requires}]\nbuild-backend = \"setuptools.build_meta\"\n"),
        )
        .unwrap();
        let archive = store.root.join(format!("{name}-1.0.tar.gz"));
        let status = std::process::Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg(format!("{name}-1.0"))
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = fs::read(&archive).unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(bytes));
        let _ = fs::remove_dir_all(source);
        LockedPackage {
            name: name.into(),
            version: "1.0".into(),
            filename: format!("{name}-1.0.tar.gz"),
            url: format!("file://{}", archive.display()),
            sha256,
            kind: ArtifactKind::Sdist,
            git: None,
        }
    }

    fn local_native_sdist(store: &Store, name: &str) -> LockedPackage {
        let source = store.root.join(format!("{name}-native-source"));
        let root = source.join(format!("{name}-1.0"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            "[build-system]\nrequires = [\"setuptools>=40.8\"]\nbuild-backend = \"setuptools.build_meta\"\n",
        )
        .unwrap();
        fs::write(root.join("binding.gyp"), "{}").unwrap();
        let archive = store.root.join(format!("{name}-1.0.tar.gz"));
        let status = std::process::Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg(format!("{name}-1.0"))
            .status()
            .unwrap();
        assert!(status.success());
        let sha256 = hex::encode(sha2::Sha256::digest(fs::read(&archive).unwrap()));
        let _ = fs::remove_dir_all(source);
        LockedPackage {
            name: name.into(),
            version: "1.0".into(),
            filename: format!("{name}-1.0.tar.gz"),
            url: format!("file://{}", archive.display()),
            sha256,
            kind: ArtifactKind::Sdist,
            git: None,
        }
    }

    fn cached_build_plan(store: &Store, requirement: &str, sha256: &str) -> String {
        let platform = Platform::host().unwrap();
        let requires = vec![requirement.to_string()];
        let key = crate::build_requires::lock_cache_key(platform, "3.12.14", &requires, None);
        let lock = store.cache_path("build-lock", &key);
        let plan_path = store.cache_path("build-plan", &key);
        fs::create_dir_all(lock.parent().unwrap()).unwrap();
        fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
        fs::write(lock, "# cached test lock\n").unwrap();
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![LockedPackage {
                name: "setuptools".into(),
                version: "84.0.0".into(),
                filename: "setuptools.whl".into(),
                url: String::new(),
                sha256: sha256.into(),
                kind: ArtifactKind::Wheel,
                git: None,
            }],
        };
        fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        key
    }

    fn write_closure(dir: &Path, platform: Option<&str>) {
        fs::create_dir_all(dir.join(".blanket/closures")).unwrap();
        let mut v = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"ok": true}
        });
        if let Some(platform) = platform {
            v["platform"] = serde_json::Value::String(platform.to_string());
        }
        fs::write(dir.join(".blanket/closures/python.json"), v.to_string()).unwrap();
    }

    #[test]
    fn foreign_platform_closure_is_refused_and_legacy_is_accepted() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let host = Platform::host().unwrap();
        let foreign = Platform::ALL.iter().copied().find(|p| *p != host).unwrap();
        let dir = std::env::temp_dir().join(format!("blanket-closure-plat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        write_closure(&dir, Some(foreign.triple()));
        let err = read_closure(&dir, "python").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
        assert!(err.to_string().contains(foreign.triple()), "{err}");

        write_closure(&dir, Some(host.triple()));
        assert_eq!(read_closure(&dir, "python").unwrap()["ok"], true);

        write_closure(&dir, None); // pre-port envelope
        assert_eq!(read_closure(&dir, "python").unwrap()["ok"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    fn closure_test_body(store: &Store) -> serde_json::Value {
        serde_json::json!({"store_object": store.object_path("closure-test")})
    }

    /// Publish a complete object so `ClosureRefs::object_id` accepts it.
    /// Self-leases its own shared activity, so callers must not hold the
    /// exclusive lease across it.
    fn complete_object(store: &Store, name: &str) -> String {
        let identity = crate::types::Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), name).unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &crate::store::ObjectDeps::new())
            .unwrap();
        let object = store.object_path(&id);
        let mut perms = fs::metadata(&object).unwrap().permissions();
        perms.set_mode(perms.mode() & !0o222);
        fs::set_permissions(&object, perms).unwrap();
        id
    }

    /// Strict publication must write the durable root record — the thing a
    /// crash between it and the visible closure relies on for protection.
    /// Removing the root publication (while the closure still lands) must
    /// fail this test: the closure is provenance, the record is the
    /// deletion authority.
    #[test]
    fn strict_publication_writes_the_durable_root_record() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let project = std::env::temp_dir().join(format!(
            "blanket-closure-durable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&project);
        let store = test_store("closure-durable");
        fs::create_dir_all(&project).unwrap();
        let id = complete_object(&store, "durable");

        // The publication path takes the exclusive lease itself (through the
        // caller-supplied one); commit above self-leased shared, so take the
        // exclusive lease only now.
        let activity = store
            .activity(crate::activity::ActivityMode::Exclusive)
            .unwrap();
        let mut refs = super::ClosureRefs::new();
        refs.object_id(&store, &activity, &id).unwrap();
        super::write_closure(
            &project,
            "python",
            closure_test_body(&store),
            &store,
            &activity,
            refs,
        )
        .unwrap();
        drop(activity);

        // The closure envelope is provenance...
        assert!(project.join(".blanket/closures/python.json").is_file());
        // ...but the durable root record is what protects the object, and it
        // must name exactly the references the producer supplied.
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert!(record.objects.contains(&id), "{:?}", record.objects);
        let _ = crate::store::remove_tree(&store.root);
        let _ = fs::remove_dir_all(&project);
    }

    #[test]
    fn write_closure_succeeds_for_normal_directories() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let project = std::env::temp_dir().join(format!(
            "blanket-closure-normal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = test_store("closure-normal");
        fs::create_dir_all(&project).unwrap();

        super::write_closure_legacy(&project, "python", closure_test_body(&store)).unwrap();

        let closure: serde_json::Value = serde_json::from_slice(
            &fs::read(project.join(".blanket/closures/python.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(closure["ecosystem"], "python");
        assert_eq!(
            closure["body"]["store_object"].as_str(),
            Some(store.object_path("closure-test").to_str().unwrap())
        );
        assert!(project.join(".blanket/closures").is_dir());

        let _ = fs::remove_dir_all(project);
        let _ = fs::remove_dir_all(store.root);
    }

    #[test]
    fn write_closure_rejects_symlinked_blanket_without_creating_outside_closures() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = std::env::temp_dir().join(format!(
            "blanket-closure-blanket-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let project = root.join("project");
        let outside = root.join("outside");
        let store = test_store("closure-blanket-symlink");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, project.join(".blanket")).unwrap();

        let error =
            super::write_closure_legacy(&project, "python", closure_test_body(&store)).unwrap_err();
        assert!(error.to_string().contains(".blanket"), "{error}");
        assert!(error.to_string().contains("real directory"), "{error}");
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(store.root);
    }

    #[test]
    fn write_closure_rejects_symlinked_closures_without_writing_outside() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = std::env::temp_dir().join(format!(
            "blanket-closure-closures-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let project = root.join("project");
        let outside = root.join("outside");
        let store = test_store("closure-closures-symlink");
        fs::create_dir_all(project.join(".blanket")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, project.join(".blanket/closures")).unwrap();

        let error =
            super::write_closure_legacy(&project, "python", closure_test_body(&store)).unwrap_err();
        assert!(error.to_string().contains(".blanket/closures"), "{error}");
        assert!(error.to_string().contains("real directory"), "{error}");
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(store.root);
    }

    #[test]
    fn fast_sdist_parent_input_keeps_the_legacy_identity() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("fast-golden");
        let fast = local_sdist(&store, "fast-golden", "\"setuptools>=40.8\"");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![fast.clone()],
        };
        let actual = planned_env_object_id(&store, Platform::host().unwrap(), &plan).unwrap();
        let expected = Identity {
            kind: "python-env".into(),
            name: "env".into(),
            version: "3.12.14".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "python-env/2".into()),
                (
                    "store_root".into(),
                    store.root.to_string_lossy().into_owned(),
                ),
                (
                    "cpython".into(),
                    python::object_id_for(Platform::host().unwrap(), "3.12.14").unwrap(),
                ),
                (
                    "pkg:fast-golden".into(),
                    format!(
                        "Sdist:{}:{}",
                        fast.sha256,
                        crate::build::derivation_fingerprint()
                    ),
                ),
            ]),
        }
        .object_id();
        assert_eq!(actual, expected);
        let _ = fs::remove_dir_all(&store.root);
    }

    #[test]
    fn isolated_sdist_build_environment_changes_parent_identity() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("isolated-input");
        let isolated = local_sdist(&store, "isolated-input", "\"setuptools~=83.1\"");
        let fast = local_sdist(&store, "fast-input", "\"setuptools>=40.8\"");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![fast, isolated],
        };
        let key = cached_build_plan(&store, "setuptools~=83.1", &"a".repeat(64));
        let first = planned_env_object_id(&store, Platform::host().unwrap(), &plan).unwrap();
        cached_build_plan(&store, "setuptools~=83.1", &"b".repeat(64));
        let second = planned_env_object_id(&store, Platform::host().unwrap(), &plan).unwrap();
        assert_ne!(
            first, second,
            "schema-3 build-env input must affect parent id"
        );
        assert_eq!(
            key,
            crate::build_requires::lock_cache_key(
                Platform::host().unwrap(),
                "3.12.14",
                &["setuptools~=83.1".into()],
                None,
            )
        );
        let _ = fs::remove_dir_all(&store.root);
    }

    #[test]
    fn planned_and_realized_env_id_match_for_a_native_sdist() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("native-sdist-identity");
        let platform = Platform::host().unwrap();
        let native = local_native_sdist(&store, "native-sdist-identity");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![native],
        };
        let planned = planned_env_object_id(&store, platform, &plan).unwrap();
        let cpython_id = python::object_id_for(platform, &plan.python_version).unwrap();
        let realized = environment_identity(&store, platform, &plan, &cpython_id).unwrap();
        assert_eq!(planned, realized.object_id());
        if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            let native_id = crate::nativelibs::object_id_for(&store, platform).unwrap();
            assert_eq!(
                realized.inputs.get("native_libs").map(String::as_str),
                Some(native_id.as_str())
            );
        }
        let _ = fs::remove_dir_all(&store.root);
    }
}

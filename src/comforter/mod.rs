//! Ecosystem-neutral projection support: closure envelopes and the process
//! signing key, projection symlinks, clone-tree and backup helpers.
//!
//! A closure records what one sync realized for one ecosystem, plus the store
//! references that protect it. Publication registers the durable root record
//! first and renames the visible `.tog/closures/<ecosystem>.json` after,
//! so a crash can only over-retain. Realization itself lives in each tailor.

pub mod join;
pub mod status;
pub mod toolchain;

use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::Platform;
use crate::kernel::signing::SigningKey;
use crate::kernel::store::{ProjectionBase, ProjectionRef, Store};
use crate::kernel::ui;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The closure-signing key for this invocation: `Some(None)` once preflight
/// found no `TOG_SIGNING_KEY`, `Some(Some(key))` once it loaded one,
/// `None` before preflight ran. Every closure a command writes is signed
/// with this one key or none: there is no per-write choice.
static SIGNING_KEY: std::sync::Mutex<Option<Option<std::sync::Arc<SigningKey>>>> =
    std::sync::Mutex::new(None);

/// Load the closure-signing key named by `TOG_SIGNING_KEY`, once, before
/// any store is opened or closure written. An unset variable means every
/// closure is written unsigned. A set variable, including an empty one,
/// must name a loadable key file (regular, mode 0600, one `ed25519:<64
/// hex>` line) or the command fails here; it never downgrades to unsigned.
/// Repeated calls keep the first result.
pub fn init_signing() -> io::Result<()> {
    let mut slot = SIGNING_KEY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Ok(());
    }
    let key = match std::env::var_os("TOG_SIGNING_KEY") {
        None => None,
        Some(path) => Some(std::sync::Arc::new(
            SigningKey::load(Path::new(&path)).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("TOG_SIGNING_KEY: {error}; unset it to write unsigned closures"),
                )
            })?,
        )),
    };
    *slot = Some(key);
    Ok(())
}

/// The loaded signing key, or `None` when none is configured (or preflight
/// never ran, in which case closures are written unsigned and `tog
/// audit` reports them outdated).
pub fn signing_key() -> Option<std::sync::Arc<SigningKey>> {
    SIGNING_KEY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .flatten()
}

/// Replace the process signing key. The one test that sets a key holds
/// `attribution_test_lock` across the set, the write, and the reset; every
/// other closure-writing test holds it too, so none can observe the test
/// key.
#[cfg(test)]
pub(crate) fn set_signing_key_for_test(key: Option<std::sync::Arc<SigningKey>>) {
    *SIGNING_KEY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(key);
}

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
        activity: &crate::kernel::activity::StoreActivity,
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
        activity: &crate::kernel::activity::StoreActivity,
        id: &str,
    ) -> io::Result<&mut Self> {
        store.require_activity(activity, "closure object reference")?;
        if !crate::kernel::store::is_object_id(id) {
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
        activity: &crate::kernel::activity::StoreActivity,
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
        activity: &crate::kernel::activity::StoreActivity,
        path: &Path,
    ) -> io::Result<&mut Self> {
        self.projection(store, activity, ProjectionBase::Forests, path)
    }

    pub fn backup(
        &mut self,
        store: &Store,
        activity: &crate::kernel::activity::StoreActivity,
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
        activity: &crate::kernel::activity::StoreActivity,
        base: ProjectionBase,
        path: &Path,
    ) -> io::Result<&mut Self> {
        store.require_activity(activity, "closure projection reference")?;
        let reference = store.projection_ref(base, path)?;
        self.projections.insert(reference);
        Ok(self)
    }
}

/// Common closure envelope: every tailor's provenance lands at
/// .tog/closures/<ecosystem>.json with a shared outer shape; the `body`
/// stays tailor-owned. Written atomically. Store ownership and exact
/// references are mandatory for production publication.
pub fn write_closure(
    project: &ProjectRoot,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    refs: ClosureRefs,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    store.require_activity(activity, "closure publication")?;
    write_closure_inner(
        project,
        ecosystem,
        body,
        store,
        activity,
        Some(refs),
        None,
        attribution,
    )
}

/// Publish a closure while the caller holds the project's transaction lock
/// across its preceding projection switch. This is the sequencing primitive
/// used by producers that move a user directory or replace a visible link
/// before writing the envelope.
pub(crate) fn write_closure_with_project_lock(
    project: &ProjectRoot,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    refs: ClosureRefs,
    project_lock: &fs::File,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    store.require_activity(activity, "closure publication")?;
    write_closure_inner(
        project,
        ecosystem,
        body,
        store,
        activity,
        Some(refs),
        Some(project_lock),
        attribution,
    )
}

/// Alias for `write_closure`.
pub fn write_closure_with_refs(
    project: &ProjectRoot,
    ecosystem: &str,
    body: serde_json::Value,
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    refs: ClosureRefs,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    write_closure(project, ecosystem, body, store, activity, refs, attribution)
}

/// Persist the producer's complete root union before a project projection or
/// user backup is switched. This is the first half of closure publication;
/// `write_closure` repeats the union after the visible closure is written so
/// a crash can only leave extra protection.
pub(crate) fn persist_root_for_refs_with_project_lock(
    project: &ProjectRoot,
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    refs: &ClosureRefs,
    project_lock: &fs::File,
) -> io::Result<()> {
    store.require_activity(activity, "root publication")?;
    // The first durable step of a projection switch: a toolchain source
    // that moved during planning is caught here, before a user directory
    // is moved or a visible link replaced, and again by the closure writer.
    toolchain::recheck_before_publication()?;
    project.check_still_named()?;
    // Registration imports the closures the project already has. A `.tog`
    // that is a symlink, or anything but a real directory, is refused here,
    // before the import could be pointed at another directory's closures.
    match project.entry(Path::new(".tog"))? {
        Entry::Absent | Entry::Directory => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is not a real directory; remove it and run 'tog' again",
                    project.path().join(".tog").display()
                ),
            ))
        }
    }
    let (objects, projections) = refs.clone().into_record_parts();
    store
        .register_root_parts_with_project_lock(
            activity,
            project,
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
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let store = match store_from_closure_body(&body) {
        Some(store) => store,
        None => Store::open()?,
    };
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    write_closure_inner(
        &ProjectRoot::open(project_dir)?,
        ecosystem,
        body,
        &store,
        &activity,
        None,
        None,
        attribution,
    )
}

fn write_closure_inner(
    project: &ProjectRoot,
    ecosystem: &str,
    mut body: serde_json::Value,
    store: &Store,
    activity: &crate::kernel::activity::StoreActivity,
    mut explicit_refs: Option<ClosureRefs>,
    supplied_project_lock: Option<&fs::File>,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    store.require_activity(activity, "closure publication")?;
    // Keep the per-project transaction lock from before the checks below
    // through both durable root publication and the visible closure rename.
    // Every writer of this project's resolution files (a door's
    // transaction) holds the same lock while it publishes, so what the
    // recheck and the resolution join read cannot change before the closure
    // is visible, and a second producer cannot observe a root from one
    // generation paired with a closure from another. A caller that already
    // holds the lock supplies it: a second `project_lock_in` from this
    // process would wait on it forever.
    let owned_project_lock = if explicit_refs.is_some() && supplied_project_lock.is_none() {
        Some(store.project_lock_in(project)?)
    } else {
        None
    };
    let project_lock = supplied_project_lock.or(owned_project_lock.as_ref());
    // The one place every project write passes through: prove the lock and
    // the toolchain source inputs still read the way this command resolved
    // them before anything of this sync becomes visible.
    toolchain::recheck_before_publication()?;
    if !body.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "closure body must be a JSON object",
        ));
    }
    // The GC root is recorded under the project's path, so the path must
    // still name the directory the closure is published through. The path
    // is the canonical one the root was opened at, used as it is from here
    // on: the lock, the record key and the registrability check never
    // resolve it again.
    project.check_still_named()?;
    let project_dir = project.path().to_path_buf();
    // Writing closures for a project that cannot be registered would leave
    // provenance behind for a project no root record can protect.
    Store::check_registrable_in(project)?;
    // The resolution join records into the attribution before it is
    // claimed, and adds a present ledger to the references before the root
    // is registered. It runs under the project lock, and it binds the
    // joined record to the resolution files the producer's plan read. It
    // writes nothing, so a refusal here leaves the checkout exactly as it
    // was.
    join::join_for_closure(
        project,
        ecosystem,
        &mut body,
        store,
        activity,
        explicit_refs.as_mut(),
    )?;

    // Hold the project directory open and publish through it. Every
    // component of `.tog/closures/<ecosystem>.json` is walked with
    // O_NOFOLLOW from that descriptor, so a `.tog` or `.tog/closures`
    // swapped for a symlink is refused instead of carrying provenance
    // outside the project (same class as the cargo-home/bin escape).
    let closure_path = Path::new(".tog/closures").join(format!("{ecosystem}.json"));
    // Create the directory before the root record is registered: root
    // registration imports whatever closures the project already has, and a
    // symlinked `.tog` must be refused before anything is written.
    project.create_dir_all(Path::new(".tog/closures"))?;

    // Claim after validating the body and before writing the closure. If a
    // later write step fails, the claimed exceptions are gone with the frame;
    // the token is marked published only after the write completes.
    let pending = attribution.claim(ecosystem)?;
    body.as_object_mut()
        .expect("validated closure body object")
        .insert("exceptions".into(), serde_json::to_value(&pending)?);
    // Envelope-level platform: a project synced on
    // a Mac and then on a Linux box carries two different closures over
    // time; readers must not assume the body's object ids are valid for
    // the current host. Additive field, schema unchanged.
    let platform = Platform::host()?.triple();
    check_closure_destination(project, &closure_path)?;
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
                project,
                objects,
                projections,
                project_lock,
            )?;
            true
        }
        None => match store.register_root_with_closure(project, ecosystem, &body) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => false,
            Err(error) => return Err(error),
        },
    };
    let mut envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": ecosystem,
        "platform": platform,
        "projected_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "body": body,
    });
    // Sign the value that is about to be pretty-printed: the signature
    // covers every envelope field and the whole body, exceptions included.
    // `tog audit` rebuilds the same canonical bytes from the file.
    if let Some(key) = signing_key() {
        key.sign(&mut envelope)?;
    }
    project.write_file(&closure_path, &serde_json::to_vec_pretty(&envelope)?)?;
    // The root was registered under the path while the closure was being
    // renamed into the held directory: prove the path still names it, so a
    // swap in that window fails the sync instead of passing silently.
    project.check_still_named()?;
    if !durable_root {
        store.register_root_with_activity(activity, &project_dir)?;
    }
    attribution.mark_published()?;
    Ok(())
}

/// Refuse a tampered destination before the root record is written, so a
/// refused publication never leaves a root behind for a closure that was
/// never published. `write_file` checks again at rename time; this is the
/// early, actionable copy of the same rule.
fn check_closure_destination(project: &ProjectRoot, closure_path: &Path) -> io::Result<()> {
    match project.entry(closure_path)? {
        Entry::Absent | Entry::Regular => {}
        Entry::Symlink => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is a symlink; remove it and run 'tog' again",
                    project.path().join(closure_path).display()
                ),
            ))
        }
        kind => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is a {} where the closure belongs; remove it and run 'tog' again",
                    project.path().join(closure_path).display(),
                    match kind {
                        Entry::Directory => "directory",
                        _ => "special file",
                    }
                ),
            ))
        }
    }
    Ok(())
}

/// Atomically install a managed symlink (`.venv`, `node_modules`) in the
/// project, through the held project descriptor: an existing symlink is
/// replaced, and a real file or directory is never silently overwritten.
/// Used for visible project projections after their durable root record has
/// been published.
pub(crate) fn replace_project_symlink(
    project: &ProjectRoot,
    relative: &Path,
    target: &Path,
    label: &str,
) -> io::Result<()> {
    project.replace_symlink(relative, target, label)
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
                            return Some(Store::for_test(root));
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

/// Read a tailor's closure body back (for `tog run` and friends).
pub fn read_closure(project_dir: &Path, ecosystem: &str) -> io::Result<serde_json::Value> {
    let path = project_dir.join(format!(".tog/closures/{ecosystem}.json"));
    let text = fs::read_to_string(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("read {}: {e}; run `tog` first", path.display()),
        )
    })?;
    closure_body(&path, &text, ecosystem)
}

/// Is there a closure record for `ecosystem` in the held project?
pub fn has_closure(project: &ProjectRoot, ecosystem: &str) -> bool {
    project
        .entry(Path::new(&format!(".tog/closures/{ecosystem}.json")))
        .is_ok_and(|entry| entry != Entry::Absent)
}

/// `read_closure` through a project the command holds: the record is tog
/// state, read with the strict no-follow walk.
pub fn read_closure_in(project: &ProjectRoot, ecosystem: &str) -> io::Result<serde_json::Value> {
    let relative = PathBuf::from(format!(".tog/closures/{ecosystem}.json"));
    let path = project.path().join(&relative);
    let missing = || {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("read {}: not found; run `tog` first", path.display()),
        )
    };
    let bytes = project
        .read_file(&relative)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("read {}: {e}; run `tog` first", path.display()),
            )
        })?
        .ok_or_else(missing)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse {}: not UTF-8; run `tog` first", path.display()),
        )
    })?;
    closure_body(&path, &text, ecosystem)
}

/// The body of a closure envelope read from `path`, checked: it parses,
/// was projected on this host, and is a `closure/1` of `ecosystem`.
fn closure_body(path: &Path, text: &str, ecosystem: &str) -> io::Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse {}: {e}; run `tog` first", path.display()),
        )
    })?;
    if let Some(recorded) = v["platform"].as_str() {
        let host = Platform::host()?;
        if recorded != host.triple() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{}: closure was projected on {recorded}; this host is {}; run `tog` here",
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
                "{}: unknown closure schema/ecosystem; re-run `tog`",
                path.display()
            ),
        ));
    }
    Ok(v["body"].clone())
}

/// Copy-on-write clone of a whole tree (macOS `cp -Rc` clonefile, Linux
/// `cp -a --reflink=auto`, plain `cp -R` fallback), then restore user-write
/// bits, which the clone inherits as read-only from the store. This form
/// takes no lease, so it is only for trees outside any store (the `None`
/// arm of a caller's `Option<&StoreActivity>`); a clone that reads a store
/// object or writes a managed projection uses `clone_tree_with_activity`.
// Reviewed site (tests/architecture.rs): `None` arm of `Option<&StoreActivity>`: no store is involved.
#[allow(clippy::disallowed_methods)]
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
            crate::kernel::store::remove_tree(dest)?;
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
    crate::kernel::store::restore_write_bits(dest)
}

pub(crate) use crate::kernel::store::clone_tree_with_activity;

/// Resolve an object reference from a closure body, CONTAINED to the
/// active store: the recorded id must exist in the store and the recorded
/// path must be exactly the store's path for that id. A project-editable
/// closure must never inject arbitrary executable paths into `tog run`.
pub fn closure_object(
    store: &crate::kernel::store::Store,
    activity: &StoreActivity,
    closure: &serde_json::Value,
    key: &str,
    probe: &str,
) -> io::Result<PathBuf> {
    let bad = |msg: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure {key}: {msg}; run `tog` first"),
        )
    };
    let id = closure[key]["id"]
        .as_str()
        .ok_or_else(|| bad("missing id"))?;
    // The full object-id shape, as `ClosureRefs::object_id` demands at
    // publication: a bare `.` or `..` would name `objects/` or the store root.
    if !crate::kernel::store::is_object_id(id) {
        return Err(bad("malformed id"));
    }
    if !store.has_with_activity(activity, id)? {
        return Err(bad("object not in the store"));
    }
    let path = store.object_path(id);
    if closure[key]["path"].as_str().map(Path::new) != Some(path.as_path()) {
        return Err(bad("recorded path disagrees with the store"));
    }
    if !probe.is_empty() && !path.join(probe).is_file() {
        return Err(bad("object is missing its expected content"));
    }
    Ok(path)
}

/// Reserve a store-owned backup destination without moving the user's
/// directory. Producers use this before publishing a root/2 record; the
/// reservation itself is safe over-retention if a later projection step
/// fails.
pub fn reserve_backup_real_dir_for_store(
    project: &ProjectRoot,
    relative: &Path,
    store: &Store,
) -> io::Result<Option<PathBuf>> {
    if project.entry(relative)? != Entry::Directory {
        return Ok(None);
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
        match crate::kernel::store::stat_at(backups_dir.as_raw_fd(), name.as_bytes()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => break backups.join(name),
            Ok(_) => {}
            Err(error) => return Err(error),
        }
        sequence = sequence.saturating_add(1);
    };
    Ok(Some(dest))
}

/// Move a previously reserved real directory out of the project, through
/// the held project descriptor, into the store-owned backup namespace. The
/// destination is checked lexically before the rename and is never followed
/// as a symlink; the source must still be a real directory.
pub fn move_reserved_backup(
    project: &ProjectRoot,
    relative: &Path,
    destination: &Path,
) -> io::Result<()> {
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
    let destination_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "reserved backup has no destination name",
        )
    })?;
    let path = project.path().join(relative);
    let backups_dir = open_real_directory(backups, "store backups")?;
    match crate::kernel::store::stat_at(backups_dir.as_raw_fd(), destination_name.as_bytes()) {
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
    project
        .move_dir_out(relative, &backups_dir, destination_name.as_bytes())
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
    if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
        project.sync_dir(parent)?;
    } else {
        project.sync_dir(Path::new("."))?;
    }
    backups_dir.sync_all()?;
    // The one advisory for a real directory found where tog projects a
    // symlink, said after the move so it is true when it is read. The
    // project's root record keeps protecting the backup, so `gc --project`
    // will not collect it while the project exists: the way out is to
    // delete it once nothing in it is missed.
    ui::warning(
        &format!(
            "moved existing {} to {}: it was a real directory where tog projects a symlink \
             (an install tool ran here, or tog had never synced this project); delete it \
             once you are sure nothing in it is missed",
            path.display(),
            destination.display()
        ),
        &ui::shell_line(&["rm", "-rf", &destination.display().to_string()]),
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

/// Recover the store from an explicit realized object path.  This is a
/// narrow path-shape check for producer APIs. It never infers provenance by
/// reading JSON.
pub(crate) fn store_from_object_path(path: &Path) -> Option<Store> {
    let objects = path.parent()?;
    if objects.file_name()?.to_str()? != "objects" {
        return None;
    }
    let root = objects.parent()?.to_path_buf().canonicalize().ok()?;
    if root.join("objects") != objects.canonicalize().ok()? {
        return None;
    }
    // A handle only: its users take a lease before they read a record, and
    // the lease validates the store's format marker.
    Some(Store::handle(root))
}

/// A project file the plan was computed from, recorded in the closure so
/// `tog status` can tell whether the projection is still current
/// without re-planning. Additive closure field (`inputs`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InputRecord {
    /// Project-relative path.
    pub path: String,
    pub sha256: String,
}

/// Hash the given files (absolute or project-relative); missing ones are
/// skipped so callers can list every candidate input. A file inside the
/// project is read through the held project descriptor, so the hash is of
/// the directory being synced; one outside it (an include beside the
/// project) is read by its path.
pub fn input_records(
    project: &ProjectRoot,
    candidates: &[PathBuf],
) -> io::Result<Vec<InputRecord>> {
    use sha2::{Digest, Sha256};
    let mut records: Vec<InputRecord> = Vec::new();
    for candidate in candidates {
        let (relative, bytes) = match project.relative(candidate) {
            Some(relative) => (relative.to_path_buf(), None),
            None if candidate.is_relative() => (candidate.clone(), None),
            None => {
                if !candidate.is_file() {
                    continue;
                }
                (candidate.clone(), Some(fs::read(candidate)?))
            }
        };
        let key = relative.to_string_lossy().into_owned();
        if records.iter().any(|record| record.path == key) {
            continue;
        }
        let bytes = match bytes {
            Some(bytes) => bytes,
            None => {
                if !project.is_input_file(&relative) {
                    continue;
                }
                match project.read_input(&relative)? {
                    Some(bytes) => bytes,
                    None => continue,
                }
            }
        };
        records.push(InputRecord {
            sha256: hex::encode(Sha256::digest(bytes)),
            path: key,
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt as _;

    /// An empty store in its own scratch directory, which lives as long as
    /// the returned `TempDir`.
    pub(super) fn test_store(label: &str) -> (TempDir, Store) {
        let temp = TempDir::named(&format!("{label}-store"));
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(temp.0.join(sub)).unwrap();
        }
        let store = Store::for_test(temp.0.clone());
        (temp, store)
    }

    fn write_closure(dir: &Path, platform: Option<&str>) {
        fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        let mut v = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"ok": true}
        });
        if let Some(platform) = platform {
            v["platform"] = serde_json::Value::String(platform.to_string());
        }
        fs::write(dir.join(".tog/closures/python.json"), v.to_string()).unwrap();
    }

    #[test]
    fn closures_are_refused_for_a_project_that_cannot_be_registered() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("unrecordable");
        let dir = &temp.0;
        let project = dir.join("project ");
        fs::create_dir_all(&project).unwrap();
        let (_store_dir, store) = test_store("unrecordable");
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let error = super::write_closure(
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            "python",
            serde_json::json!({}),
            &store,
            &activity,
            ClosureRefs::default(),
            &mut attribution,
        )
        .unwrap_err();
        assert!(error.to_string().contains("path is padded"), "{error}");
        assert!(
            !project.join(".tog").exists(),
            "wrote into a project no record can name"
        );
        attribution.finish(false).unwrap();
    }

    #[test]
    fn foreign_platform_closure_is_refused_and_legacy_is_accepted() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let host = Platform::host().unwrap();
        let foreign = Platform::ALL.iter().copied().find(|p| *p != host).unwrap();
        let temp = TempDir::named("closure-plat");
        let dir = &temp.0;

        write_closure(dir, Some(foreign.triple()));
        let err = read_closure(dir, "python").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
        assert!(err.to_string().contains(foreign.triple()), "{err}");

        write_closure(dir, Some(host.triple()));
        assert_eq!(read_closure(dir, "python").unwrap()["ok"], true);

        write_closure(dir, None); // pre-port envelope
        assert_eq!(read_closure(dir, "python").unwrap()["ok"], true);
    }

    fn closure_test_body(store: &Store) -> serde_json::Value {
        serde_json::json!({"store_object": store.object_path("closure-test")})
    }

    pub(super) fn complete_object(store: &Store, name: &str) -> String {
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        crate::kernel::objmeta::register_test_kinds();
        let identity = crate::kernel::types::Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let id = identity.object_id();
        let staged = store.stage_with_activity(activity).unwrap();
        fs::write(staged.join("payload"), name).unwrap();
        store
            .commit_with_activity_and_deps(
                activity,
                &identity,
                &staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();
        let object = store.object_path(&id);
        let mut perms = fs::metadata(&object).unwrap().permissions();
        perms.set_mode(perms.mode() & !0o222);
        fs::set_permissions(&object, perms).unwrap();
        id
    }

    #[test]
    fn strict_publication_writes_the_durable_root_record() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("closure-durable");
        let project = &temp.0;
        let (_store_dir, store) = test_store("closure-durable");
        let id = complete_object(&store, "durable");

        // The publication path takes the exclusive lease itself (through the
        // caller-supplied one); commit above self-leased shared, so take the
        // exclusive lease only now.
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let mut refs = super::ClosureRefs::new();
        refs.object_id(&store, &activity, &id).unwrap();
        super::write_closure(
            &crate::kernel::fsroot::ProjectRoot::open(project).unwrap(),
            "python",
            closure_test_body(&store),
            &store,
            &activity,
            refs,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();
        drop(activity);

        // The closure envelope is provenance...
        assert!(project.join(".tog/closures/python.json").is_file());
        // ...but the durable root record is what protects the object, and it
        // must name exactly the references the producer supplied.
        let envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(project.join(".tog/closures/python.json")).unwrap())
                .unwrap();
        assert_eq!(envelope["platform"], Platform::host().unwrap().triple());
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert!(record.objects.contains(&id), "{:?}", record.objects);
    }

    fn unique_project(label: &str) -> TempDir {
        TempDir::named(&format!("closure-{label}"))
    }

    fn envelope(project: &Path, ecosystem: &str, body: serde_json::Value) {
        let closures = project.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join(format!("{ecosystem}.json")),
            serde_json::json!({"schema": "closure/1", "ecosystem": ecosystem, "body": body})
                .to_string(),
        )
        .unwrap();
    }

    /// An object reference is the store's own object path, exactly. A path
    /// that merely ends in, or mentions, an object id names something else:
    /// a copy, a file inside the object, or nothing at all. Neither the
    /// producer boundary nor the registration importer may turn it into
    /// protection.
    #[test]
    fn closure_refs_reject_a_bare_path_that_merely_contains_an_id() {
        let (_store_dir, store) = test_store("bare-id-path");
        let id = complete_object(&store, "bare-id");
        let mentioned = complete_object(&store, "mentioned");
        let elsewhere = std::env::temp_dir().join("tog-not-a-store");
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let outside = "is outside this store";
        for (path, needle) in [
            (elsewhere.join(&id), outside),
            (elsewhere.join("objects").join(&id), outside),
            (store.object_path(&id).join("bin"), outside),
            (store.root.join("cache").join(&id), outside),
            (
                store.root.join("objects").join(format!("{id}-copy")),
                "unavailable",
            ),
        ] {
            let mut refs = ClosureRefs::new();
            let error = refs.object_path(&store, &activity, &path).unwrap_err();
            assert!(
                error.to_string().contains(needle),
                "{}: {error}",
                path.display()
            );
            assert!(refs.is_empty());
        }
        let mut refs = ClosureRefs::new();
        refs.object_path(&store, &activity, &store.object_path(&id))
            .unwrap();
        assert_eq!(refs.into_record_parts().0, BTreeSet::from([id.clone()]));
        drop(activity);

        // Registration reads the same rule: only a store object path, or an
        // `{"id", "path"}` pair naming one, is a reference. A string that
        // happens to hold an id, bare or inside a relative path, is prose.
        let project_dir = unique_project("bare-id-import");
        let project = &project_dir.0;
        envelope(
            project,
            "python",
            serde_json::json!({
                "env_object": store.object_path(&id),
                "note": mentioned,
                "relative": format!("objects/{mentioned}"),
                "inside": store.object_path(&mentioned).join("bin/python").display().to_string(),
            }),
        );
        // A path inside an object is refused outright, not read as the
        // object, and the refusal names the object it is inside (#164).
        let error = store
            .root_record_from_project(project)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!(
                "python\" is inside object {mentioned}, not an object root or a projection"
            )),
            "{error}"
        );
        // The same path under another store's root is that store's.
        let foreign = std::path::Path::new("/elsewhere/store/objects")
            .join(&mentioned)
            .join("bin/python");
        envelope(
            project,
            "python",
            serde_json::json!({
                "env_object": store.object_path(&id),
                "foreign": foreign.display().to_string(),
            }),
        );
        let error = store
            .root_record_from_project(project)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("python\" belongs to another store"),
            "{error}"
        );
        let traversal = store
            .object_path(&mentioned)
            .join("../../../foreign-store/objects")
            .join(&id)
            .join("bin/python");
        envelope(
            project,
            "python",
            serde_json::json!({
                "env_object": store.object_path(&id), "traversal": traversal,
            }),
        );
        let error = store
            .root_record_from_project(project)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("contains parent-directory traversal"),
            "{error}"
        );
        assert!(!error.contains("is inside object"), "{error}");
        envelope(
            project,
            "python",
            serde_json::json!({
                "env_object": store.object_path(&id),
                "note": mentioned,
                "relative": format!("objects/{mentioned}"),
            }),
        );
        let record = store.root_record_from_project(project).unwrap();
        assert_eq!(record.objects, BTreeSet::from([id]));
    }

    /// Publication writes the durable root record, then the visible closure.
    /// A closure write that fails therefore leaves the record behind (extra
    /// protection), never a closure without one. The closures directory is
    /// made read-only so the closure write fails after the record write.
    #[test]
    fn publication_persists_the_record_before_the_closure() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root ignores the read-only closures directory");
            return;
        }
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let (_store_dir, store) = test_store("record-before-closure");
        let project_dir = unique_project("record-before-closure");
        let project = &project_dir.0;
        let id = complete_object(&store, "record-first");
        let closures = project.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::set_permissions(&closures, fs::Permissions::from_mode(0o555)).unwrap();

        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let mut refs = ClosureRefs::new();
        refs.object_id(&store, &activity, &id).unwrap();
        let result = super::write_closure(
            &crate::kernel::fsroot::ProjectRoot::open(project).unwrap(),
            "python",
            closure_test_body(&store),
            &store,
            &activity,
            refs,
            &mut attribution,
        );
        drop(activity);
        fs::set_permissions(&closures, fs::Permissions::from_mode(0o755)).unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(
            !closures.join("python.json").exists(),
            "the closure was published"
        );
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "the record was not written first: {error}");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(record.objects, BTreeSet::from([id]));
        attribution.discard();
    }

    /// A project still on a pathname-only record carries closures from every
    /// ecosystem it was synced with. The first sync that publishes a durable
    /// record imports all of them before it switches its own projection, so
    /// resyncing Python never drops Node's protection. An import that fails
    /// changes nothing: the pathname record stays as it was.
    #[test]
    fn sync_imports_all_legacy_ecosystems_before_switching_one() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let (_store_dir, store) = test_store("sync-imports-legacy");
        let project_dir = unique_project("sync-imports-legacy");
        let project = &project_dir.0;
        let old_python = complete_object(&store, "old-python-env");
        let node = complete_object(&store, "node-env");
        let new_python = complete_object(&store, "new-python-env");
        envelope(
            project,
            "python",
            serde_json::json!({"env_object": store.object_path(&old_python)}),
        );
        envelope(
            project,
            "node",
            serde_json::json!({"env_object": store.object_path(&node)}),
        );
        let legacy = store.register_root(project).unwrap();
        let legacy_bytes = fs::read(&legacy.registry_path).unwrap();

        // A closure the importer cannot read stops the switch before any
        // record changes.
        envelope(project, "zig", serde_json::json!({}));
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let mut refs = ClosureRefs::new();
        refs.object_id(&store, &activity, &new_python).unwrap();
        let project_lock = store.project_lock(project).unwrap();
        let error = persist_root_for_refs_with_project_lock(
            &crate::kernel::fsroot::ProjectRoot::open(project).unwrap(),
            &store,
            &activity,
            &refs,
            &project_lock,
        )
        .unwrap_err();
        assert!(error.to_string().contains("zig"), "{error}");
        assert_eq!(fs::read(&legacy.registry_path).unwrap(), legacy_bytes);
        fs::remove_file(project.join(".tog/closures/zig.json")).unwrap();

        // The durable half of a Python resync, before its projection switch:
        // the old Python and Node references are imported with the new one.
        persist_root_for_refs_with_project_lock(
            &crate::kernel::fsroot::ProjectRoot::open(project).unwrap(),
            &store,
            &activity,
            &refs,
            &project_lock,
        )
        .unwrap();
        let everything = BTreeSet::from([old_python.clone(), node.clone(), new_python.clone()]);
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1);
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(record.objects, everything);
        let python = read_closure(project, "python").unwrap();
        assert_eq!(
            python["env_object"],
            serde_json::json!(store.object_path(&old_python)),
            "the projection switched before the import"
        );

        // The visible switch keeps the union.
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        super::write_closure_with_project_lock(
            &crate::kernel::fsroot::ProjectRoot::open(project).unwrap(),
            "python",
            serde_json::json!({"env_object": store.object_path(&new_python)}),
            &store,
            &activity,
            refs,
            &project_lock,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();
        drop(project_lock);
        drop(activity);
        let roots = store.roots().unwrap();
        assert_eq!(roots[0].record.as_ref().unwrap().objects, everything);
    }

    /// Root registration imports the closures the project already has
    /// through the held descriptor. A symlinked `.tog` is refused before the
    /// import could read another directory's closures, and a project swapped
    /// for another after it was opened is refused before anything is
    /// imported from either.
    #[test]
    fn root_publication_imports_closures_only_through_the_held_project() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let (_store_dir, store) = test_store("held-import");
        let project_dir = unique_project("held-import");
        let project = &project_dir.0;
        let outside_dir = unique_project("held-import-outside");
        let outside = &outside_dir.0;
        let foreign = complete_object(&store, "foreign-env");
        let own = complete_object(&store, "own-env");
        envelope(
            outside,
            "node",
            serde_json::json!({"env_object": store.object_path(&foreign)}),
        );
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let mut refs = ClosureRefs::new();
        refs.object_id(&store, &activity, &own).unwrap();

        // A `.tog` that is a symlink to another project's state.
        std::os::unix::fs::symlink(outside.join(".tog"), project.join(".tog")).unwrap();
        let root = crate::kernel::fsroot::ProjectRoot::open(project).unwrap();
        let project_lock = store.project_lock_in(&root).unwrap();
        let error =
            persist_root_for_refs_with_project_lock(&root, &store, &activity, &refs, &project_lock)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(store.roots().unwrap().is_empty());
        fs::remove_file(project.join(".tog")).unwrap();

        // The project renamed away and another put at its path, carrying
        // closures that name a foreign object.
        let moved = project.with_extension("moved");
        fs::rename(project, &moved).unwrap();
        fs::rename(outside, project).unwrap();
        let error =
            persist_root_for_refs_with_project_lock(&root, &store, &activity, &refs, &project_lock)
                .unwrap_err();
        assert!(
            error.to_string().contains("moved or replaced during sync"),
            "{error}"
        );
        assert!(store.roots().unwrap().is_empty());

        // Put back, the held project's own (empty) closures are imported and
        // nothing from the other directory is.
        fs::rename(project, outside).unwrap();
        fs::rename(&moved, project).unwrap();
        persist_root_for_refs_with_project_lock(&root, &store, &activity, &refs, &project_lock)
            .unwrap();
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, root.path());
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(record.objects, BTreeSet::from([own.clone()]));
        drop(project_lock);
        drop(activity);
    }

    #[test]
    fn non_object_body_is_rejected_before_attribution_claim() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        crate::kernel::policy::record(
            crate::kernel::policy::FILE_COLLISION,
            "fixture",
            "collision before invalid publication",
        )
        .unwrap();
        let temp = TempDir::named("closure-non-object");
        let project = &temp.0;
        let (_store_dir, store) = test_store("closure-non-object");
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let error = super::write_closure(
            &crate::kernel::fsroot::ProjectRoot::open(project).unwrap(),
            "python",
            serde_json::json!(["not an object"]),
            &store,
            &activity,
            ClosureRefs::default(),
            &mut attribution,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(crate::kernel::policy::pending().len(), 1);
        assert!(!project.join(".tog").exists());
        attribution.discard();
    }

    /// A write that fails after the claim must not count as published: the
    /// token cannot finish, and the next attribution starts with nothing.
    /// The failure is injected deterministically.
    #[test]
    fn write_failure_after_claim_leaves_the_next_attribution_clean() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        crate::kernel::policy::record(
            crate::kernel::policy::FILE_COLLISION,
            "fixture",
            "collision before a failing write",
        )
        .unwrap();
        let temp = TempDir::named("closure-write-fails");
        let project = &temp.0;
        let (_store_dir, store) = test_store("closure-write-fails");
        let closures = project.join(".tog/closures");
        // A directory squatting on the closure's destination name makes the
        // final rename fail, after the claim and after the temp file was
        // written. Works for any user on Linux and macOS.
        let squatter = closures.join("python.json");
        fs::create_dir_all(&squatter).unwrap();

        let error = super::write_closure_legacy(
            project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        )
        .unwrap_err();
        assert!(squatter.is_dir(), "the squatter was replaced: {error}");
        assert!(
            fs::read_dir(&closures)
                .unwrap()
                .all(|entry| entry.unwrap().file_name() == "python.json"),
            "the failed write left a temp file behind"
        );
        assert!(
            attribution.recorded().is_empty(),
            "claimed exceptions stay claimed"
        );
        let error = attribution.finish(true).unwrap_err();
        assert!(error.to_string().contains("did not complete"), "{error}");

        assert!(crate::kernel::policy::pending().is_empty());
        let next = crate::kernel::policy::Attribution::open("node").unwrap();
        assert!(next.recorded().is_empty());
        next.discard();
    }

    #[test]
    fn write_closure_succeeds_for_normal_directories() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("closure-normal");
        let project = &temp.0;
        let (_store_dir, store) = test_store("closure-normal");
        fs::create_dir_all(project).unwrap();

        super::write_closure_legacy(
            project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let closure: serde_json::Value =
            serde_json::from_slice(&fs::read(project.join(".tog/closures/python.json")).unwrap())
                .unwrap();
        assert_eq!(closure["ecosystem"], "python");
        assert_eq!(
            closure["body"]["store_object"].as_str(),
            Some(store.object_path("closure-test").to_str().unwrap())
        );
        assert!(project.join(".tog/closures").is_dir());
    }

    #[test]
    fn write_closure_signs_with_the_configured_key() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let temp = TempDir::named("closure-signed");
        let project = &temp.0;
        fs::create_dir_all(project).unwrap();
        let (_store_dir, store) = test_store("closure-signed");
        let key_path = project.join("signing.key");
        let public = crate::kernel::signing::generate(&key_path).unwrap();
        let key = std::sync::Arc::new(SigningKey::load(&key_path).unwrap());
        set_signing_key_for_test(Some(key));
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        crate::kernel::policy::record("skipped-optional", "dev", "not requested").unwrap();
        let written = super::write_closure_legacy(
            project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        );
        set_signing_key_for_test(None);
        written.unwrap();
        attribution.finish(true).unwrap();
        let closure: serde_json::Value =
            serde_json::from_slice(&fs::read(project.join(".tog/closures/python.json")).unwrap())
                .unwrap();
        // The signature covers the envelope as written, exceptions included.
        assert_eq!(
            crate::kernel::signing::verify(&closure),
            crate::kernel::signing::Verification::Valid(public)
        );
        assert_eq!(closure["signature"]["key"], public.hex());
        assert_eq!(closure["body"]["exceptions"][0]["kind"], "skipped-optional");
        let mut edited = closure.clone();
        edited["body"]["exceptions"] = serde_json::json!([]);
        assert!(matches!(
            crate::kernel::signing::verify(&edited),
            crate::kernel::signing::Verification::Bad { .. }
        ));
        // `read_closure` accepts the signed record unchanged.
        assert_eq!(
            super::read_closure(project, "python").unwrap()["exceptions"][0]["subject"],
            "dev"
        );
        // Without a key the same writer produces an unsigned record.
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        super::write_closure_legacy(
            project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();
        let closure: serde_json::Value =
            serde_json::from_slice(&fs::read(project.join(".tog/closures/python.json")).unwrap())
                .unwrap();
        assert_eq!(
            crate::kernel::signing::verify(&closure),
            crate::kernel::signing::Verification::Unsigned
        );
    }

    #[test]
    fn write_closure_rejects_symlinked_tog_without_creating_outside_closures() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("closure-tog-symlink");
        let root = &temp.0;
        let project = root.join("project");
        let outside = root.join("outside");
        let (_store_dir, store) = test_store("closure-tog-symlink");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, project.join(".tog")).unwrap();

        let error = super::write_closure_legacy(
            &project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        )
        .unwrap_err();
        assert!(error.to_string().contains(".tog"), "{error}");
        assert!(error.to_string().contains("real directory"), "{error}");
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        attribution.discard();
    }

    #[test]
    fn write_closure_rejects_a_symlinked_destination_without_writing_through_it() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("closure-dest-symlink");
        let root = &temp.0;
        let project = root.join("project");
        let outside = root.join("outside.json");
        let (_store_dir, store) = test_store("closure-dest-symlink");
        fs::create_dir_all(project.join(".tog/closures")).unwrap();
        fs::write(&outside, b"untouched").unwrap();
        symlink(&outside, project.join(".tog/closures/python.json")).unwrap();

        let error = super::write_closure_legacy(
            &project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        )
        .unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
        assert!(
            error.to_string().contains("run 'tog' again"),
            "the refusal does not say what to do: {error}"
        );
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
        // The refusal lands before the root record, so a project whose
        // closure was never published owns no root either.
        assert!(
            store.roots().unwrap().is_empty(),
            "a refused closure still registered a root"
        );
        assert!(
            !project.join(".tog/closures/python.json").is_symlink()
                || fs::read_link(project.join(".tog/closures/python.json")).unwrap() == outside,
            "the symlink was replaced"
        );

        attribution.discard();
    }

    #[test]
    fn write_closure_rejects_symlinked_closures_without_writing_outside() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("closure-closures-symlink");
        let root = &temp.0;
        let project = root.join("project");
        let outside = root.join("outside");
        let (_store_dir, store) = test_store("closure-closures-symlink");
        fs::create_dir_all(project.join(".tog")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, project.join(".tog/closures")).unwrap();

        let error = super::write_closure_legacy(
            &project,
            "python",
            closure_test_body(&store),
            &mut attribution,
        )
        .unwrap_err();
        assert!(error.to_string().contains(".tog/closures"), "{error}");
        assert!(error.to_string().contains("real directory"), "{error}");
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        attribution.discard();
    }
}

/// `closure_object` and `read_closure` turn a project-editable file into a
/// store path that `tog run` executes from. Each refusal below is a closure
/// that must not reach the child.
#[cfg(test)]
mod closure_object_tests {
    use super::tests::{complete_object, test_store};
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::testutil::TempDir;

    fn refusal(store: &Store, closure: serde_json::Value, probe: &str) -> io::Error {
        let activity = store.activity(ActivityMode::Shared).unwrap();
        closure_object(store, &activity, &closure, "runtime_object", probe).unwrap_err()
    }

    fn assert_refused(error: io::Error, reason: &str) {
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert_eq!(
            error.to_string(),
            format!("closure runtime_object: {reason}; run `tog` first")
        );
    }

    #[test]
    fn a_missing_id_is_refused() {
        let (_dir, store) = test_store("closure-object-missing-id");
        for closure in [
            serde_json::json!({}),
            serde_json::json!({"runtime_object": {"path": "/x"}}),
            serde_json::json!({"runtime_object": {"id": 7}}),
        ] {
            assert_refused(refusal(&store, closure, ""), "missing id");
        }
    }

    /// `.` and `..` pass a plain character filter and name `objects/` and
    /// the store root; before the shape check, the store lookup took `.` for
    /// a crashed object and emptied `objects/`.
    #[test]
    fn a_malformed_id_is_refused_and_the_store_is_untouched() {
        let (dir, store) = test_store("closure-object-malformed");
        fs::write(dir.0.join("objects/victim"), "keep").unwrap();
        for id in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "/etc",
            "not-an-object-id",
            "0000000000000000000000000000000000000000-",
            "0000000000000000000000000000000000000000-a..b",
            "000000000000000000000000000000000000000g-a-1",
            "0000000000000000000000000000000000000000_pkg",
            "0000000000000000000000000000000000000000-a@b",
            "0000000000000000000000000000000000000000-a/b",
        ] {
            let closure = serde_json::json!({
                "runtime_object": {"id": id, "path": store.object_path(id)}
            });
            assert_refused(refusal(&store, closure, ""), "malformed id");
            assert!(dir.0.join("objects/victim").is_file(), "id {id:?}");
        }
    }

    #[test]
    fn an_id_the_store_does_not_hold_is_refused() {
        let (_dir, store) = test_store("closure-object-absent");
        let id = "0000000000000000000000000000000000000000-absent-1";
        let closure = serde_json::json!({
            "runtime_object": {"id": id, "path": store.object_path(id)}
        });
        assert_refused(refusal(&store, closure, ""), "object not in the store");
    }

    /// Something at the object's path that is not a published object: a
    /// writable directory, one without metadata, and a symlink out of the
    /// store. Each is refused, and the symlink's target is left alone.
    #[test]
    fn an_unpublished_entry_at_the_object_path_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, store) = test_store("closure-object-unpublished");
        let outside = TempDir::named("closure-object-outside");
        fs::write(outside.0.join("sentinel"), "keep").unwrap();
        let writable = "1111111111111111111111111111111111111111-writable-1";
        fs::create_dir(store.object_path(writable)).unwrap();
        fs::write(dir.0.join(format!("meta/{writable}.json")), "{}").unwrap();
        let unrecorded = "2222222222222222222222222222222222222222-unrecorded-1";
        fs::create_dir(store.object_path(unrecorded)).unwrap();
        fs::set_permissions(
            store.object_path(unrecorded),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        let linked = "3333333333333333333333333333333333333333-linked-1";
        std::os::unix::fs::symlink(&outside.0, store.object_path(linked)).unwrap();
        fs::write(dir.0.join(format!("meta/{linked}.json")), "{}").unwrap();
        for id in [writable, unrecorded, linked] {
            let closure = serde_json::json!({
                "runtime_object": {"id": id, "path": store.object_path(id)}
            });
            assert_refused(refusal(&store, closure, ""), "object not in the store");
        }
        assert_eq!(
            fs::read_to_string(outside.0.join("sentinel")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn a_path_that_disagrees_with_the_store_is_refused() {
        let (_dir, store) = test_store("closure-object-path");
        let id = complete_object(&store, "runtime");
        let other = complete_object(&store, "other");
        let elsewhere = TempDir::named("closure-object-elsewhere");
        for path in [
            None,
            Some(elsewhere.0.join(&id)),
            Some(store.object_path(&id).join("payload")),
            Some(store.root.join("objects/../objects").join(&id)),
            Some(store.object_path(&other)),
        ] {
            let closure = serde_json::json!({"runtime_object": {"id": id, "path": path}});
            assert_refused(
                refusal(&store, closure, ""),
                "recorded path disagrees with the store",
            );
        }
    }

    #[test]
    fn an_object_without_its_probe_is_refused() {
        let (_dir, store) = test_store("closure-object-probe");
        let id = complete_object(&store, "runtime");
        let closure = serde_json::json!({
            "runtime_object": {"id": id, "path": store.object_path(&id)}
        });
        assert_refused(
            refusal(&store, closure, "bin/go"),
            "object is missing its expected content",
        );
        // A directory where the probe file belongs is not the content.
        assert_refused(
            refusal(&store, closure_for(&store, &id), "."),
            "object is missing its expected content",
        );
    }

    fn closure_for(store: &Store, id: &str) -> serde_json::Value {
        serde_json::json!({"runtime_object": {"id": id, "path": store.object_path(id)}})
    }

    /// The key names which reference is resolved and labels the refusal.
    #[test]
    fn the_requested_key_is_the_one_resolved() {
        let (_dir, store) = test_store("closure-object-key");
        let go = complete_object(&store, "go");
        let runtime = complete_object(&store, "runtime");
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let closure = serde_json::json!({
            "go_object": {"id": go, "path": store.object_path(&go)},
            "runtime_object": {"id": runtime, "path": store.object_path(&runtime)},
            "modcache_object": {"id": ".", "path": store.object_path(&runtime)},
        });
        let resolved = closure_object(&store, &activity, &closure, "go_object", "payload");
        assert_eq!(resolved.unwrap(), store.object_path(&go));
        let error = closure_object(&store, &activity, &closure, "modcache_object", "")
            .map(drop)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "closure modcache_object: malformed id; run `tog` first"
        );
    }

    #[test]
    fn a_matching_object_resolves_to_its_store_path() {
        let (_dir, store) = test_store("closure-object-control");
        let id = complete_object(&store, "runtime");
        let closure = serde_json::json!({
            "runtime_object": {"id": id, "path": store.object_path(&id)}
        });
        let activity = store.activity(ActivityMode::Shared).unwrap();
        for probe in ["", "payload"] {
            let path = closure_object(&store, &activity, &closure, "runtime_object", probe);
            assert_eq!(path.unwrap(), store.object_path(&id));
        }
    }

    fn write_envelope(project: &Path, text: &str) -> PathBuf {
        let closures = project.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        let path = closures.join("python.json");
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn read_closure_refuses_a_wrong_schema_or_ecosystem() {
        let project = TempDir::named("read-closure-shape");
        for envelope in [
            serde_json::json!({"schema": "closure/2", "ecosystem": "python", "body": {}}),
            serde_json::json!({"ecosystem": "python", "body": {}}),
            serde_json::json!({"schema": "closure/1", "ecosystem": "node", "body": {}}),
            serde_json::json!({"schema": "closure/1", "body": {}}),
        ] {
            let path = write_envelope(&project.0, &envelope.to_string());
            let error = read_closure(&project.0, "python").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
            assert_eq!(
                error.to_string(),
                format!(
                    "{}: unknown closure schema/ecosystem; re-run `tog`",
                    path.display()
                )
            );
        }
    }

    #[test]
    fn read_closure_refuses_a_missing_or_unparsable_file() {
        let project = TempDir::named("read-closure-missing");
        let path = project.0.join(".tog/closures/python.json");
        let error = read_closure(&project.0, "python").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        assert!(
            error
                .to_string()
                .starts_with(&format!("read {}: ", path.display()))
                && error.to_string().ends_with("; run `tog` first"),
            "{error}"
        );

        write_envelope(&project.0, "{not json");
        let error = read_closure(&project.0, "python").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error
                .to_string()
                .starts_with(&format!("parse {}: ", path.display()))
                && error.to_string().ends_with("; run `tog` first"),
            "{error}"
        );
    }

    #[test]
    fn read_closure_returns_the_body_of_a_matching_envelope() {
        let project = TempDir::named("read-closure-control");
        let envelope = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": Platform::host().unwrap().triple(),
            "body": {"runtime_object": {"id": "x"}},
        });
        write_envelope(&project.0, &envelope.to_string());
        assert_eq!(
            read_closure(&project.0, "python").unwrap(),
            envelope["body"]
        );
    }
}

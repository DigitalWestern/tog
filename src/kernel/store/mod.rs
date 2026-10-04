//! The content-addressed object store (kernel layer): object paths, atomic
//! commit, root records, projection bases, and the `TOG_STORE` override.

use crate::kernel::activity::{ActivityMode, StoreActivity};
use crate::kernel::types::Identity;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

mod env;
mod format;
mod fsops;
mod objects;
mod projection;
mod records;
mod roots;
mod roots_lookup;

use env::home;
#[cfg(test)]
pub(crate) use env::STORE_ENV_LOCK;
pub(crate) use format::lock_root;
pub(crate) use format::RESET_REMOVES;
pub use format::{refusal_fix, Refused, StoreFormat, FORMAT_FILE, STORE_FORMAT};
pub use fsops::*;
pub use objects::*;
pub use projection::*;
pub use roots::*;

/// Closure file stems an older tog wrote that nothing reads any more.
/// `tog fmt` used to leave `.tog/closures/rustfmt.json` at a Cargo
/// workspace root; it now deletes one when it formats beside another
/// closure, and until then every closure reader skips the name: the root
/// importer, `status`, `ls`, `audit`, `sbom`, and the sync summary. gc's
/// live-set walk alone still reads it, so the objects it names stay
/// protected while it exists.
pub const RETIRED_CLOSURES: &[&str] = &["rustfmt"];

/// Whether `path` names a closure file a reader should import: `*.json`,
/// and not a retired record.
pub fn is_closure_file(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "json") && !is_retired_closure(path)
}

/// Whether `path` (a closure file, or just its name) is a retired record:
/// `<stem>.json` with a stem in `RETIRED_CLOSURES`.
pub fn is_retired_closure(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "json")
        && path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| RETIRED_CLOSURES.contains(&stem))
}

/// Content/input-addressed immutable store (the closet).
///
/// Layout:
///   <root>/format                   the store format marker (`format.rs`)
///   <root>/objects/<object-id>/     immutable realized outputs
///   <root>/meta/<object-id>.json    identity + provenance
///   <root>/cache/sha256/<hash>      verified downloaded artifacts
///   <root>/tmp/                     staging for atomic renames
///   <root>/run-homes/<key>/<eco>/   private HOME for `tog run` children
///   <root>/records/<kind>/<k>.json  facts tog verified itself, by key
///
/// ponytail: store root defaults to ~/.tog/store (TOG_STORE overrides).
/// The /opt/tog/store decision only matters once binary-cache sharing
/// exists; identity format is machine-independent so migration is re-realize.
#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

/// Why the store could not be created, in the user's terms: the path that
/// failed, the cause translated out of errno, and the one lever they have.
/// A bare `?` here surfaces as "Permission denied (os error 13)" with no
/// path and no hint that `TOG_STORE` exists.
fn open_error(path: &Path, from_env: bool, error: io::Error) -> io::Error {
    let lever = if from_env {
        "TOG_STORE names this path; point it at a writable directory"
    } else {
        "set TOG_STORE to a writable directory"
    };
    let cause = match error.raw_os_error() {
        Some(code) if code == libc::ENOSPC => "the filesystem is full".to_string(),
        Some(code) if code == libc::EROFS => "the filesystem is read-only".to_string(),
        Some(code) if code == libc::EDQUOT => "the disk quota is exhausted".to_string(),
        _ => match error.kind() {
            io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            io::ErrorKind::NotFound => "a parent directory does not exist".to_string(),
            _ => error.to_string(),
        },
    };
    io::Error::new(
        error.kind(),
        format!("create the store at {}: {cause}; {lever}", path.display()),
    )
}

impl Store {
    /// Where `open` puts the store, and whether `TOG_STORE` chose it.
    fn configured_root() -> (PathBuf, bool) {
        let explicit = std::env::var_os("TOG_STORE").map(PathBuf::from);
        let from_env = explicit.is_some();
        (
            explicit.unwrap_or_else(|| home().join(".tog/store")),
            from_env,
        )
    }

    /// The store `open` would use, without creating or changing anything:
    /// `None` when there is no store (or no `objects` namespace) there yet.
    /// The layout invariant is `open`'s: the canonical root, `objects` and
    /// `meta` must be real directories, never symlinks, and anything else
    /// is an error rather than an absent store. For readers that only
    /// locate the store and never create it (the local Rust tree cache);
    /// anything that commits, leases or sweeps uses `open`.
    pub fn existing() -> io::Result<Option<Store>> {
        let (root, _) = Self::configured_root();
        let root = match root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let real_directory = |path: &Path, absent_is_none: bool| -> io::Result<bool> {
            match fs::symlink_metadata(path) {
                Ok(stat) if !stat.file_type().is_symlink() && stat.is_dir() => Ok(true),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("store path {} is not a real directory", path.display()),
                )),
                Err(error) if absent_is_none && error.kind() == io::ErrorKind::NotFound => {
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        };
        real_directory(&root, false)?;
        // The format rule is `open`'s too: a store it refuses is refused
        // here with the same words, never read.
        format::probe(&root)?.refuse(&root)?;
        if !real_directory(&root.join("objects"), true)? {
            return Ok(None);
        }
        // A missing `meta` only means nothing has finished publishing.
        real_directory(&root.join("meta"), true)?;
        Ok(Some(Store { root }))
    }

    /// The configured store's canonical root and what its format marker
    /// says, without creating or changing anything: `None` when there is no
    /// directory there yet. This is how a store `open` refuses is still
    /// named (`tog store path`), reported (`tog doctor`) and emptied
    /// (`tog gc --reset`).
    pub fn probe() -> io::Result<Option<(PathBuf, StoreFormat)>> {
        let (root, _) = Self::configured_root();
        Self::probe_at(&root)
    }

    /// The configured store's canonical root, without reading anything in
    /// it: `None` when there is no directory there yet. `tog gc --reset`
    /// starts here, because it must work on a store whose marker cannot
    /// even be read.
    pub fn locate() -> io::Result<Option<PathBuf>> {
        let (root, _) = Self::configured_root();
        match root.canonicalize() {
            Ok(root) => Ok(Some(root)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// A handle on the store at `root`, with nothing checked and nothing
    /// created. Safe to hand out because a handle alone reads no record:
    /// every lease primitive (`activity`, `try_activity_exclusive`)
    /// validates the format marker once the lease is held, so an operation
    /// on a store this tog refuses stops there. `root` should be canonical.
    pub fn handle(root: PathBuf) -> Store {
        Store { root }
    }

    /// `handle` for a unit test that lays a store out by hand: the root is
    /// given the current format marker when it exists and has none, so the
    /// leases the test takes accept it. A test of a refused store removes
    /// or rewrites the marker afterwards.
    #[cfg(test)]
    pub(crate) fn for_test(root: impl Into<PathBuf>) -> Store {
        let root = root.into();
        let marker = root.join(FORMAT_FILE);
        if root.is_dir() && fs::symlink_metadata(&marker).is_err() {
            fs::write(&marker, StoreFormat::current_line()).unwrap();
        }
        Store { root }
    }

    /// `probe` for a root the caller names.
    pub fn probe_at(root: &Path) -> io::Result<Option<(PathBuf, StoreFormat)>> {
        let root = match root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let format = format::probe(&root)?;
        Ok(Some((root, format)))
    }

    /// Open the configured store, creating it if nothing is there.
    ///
    /// A store this tog cannot read is refused, never opened: one with
    /// namespaces and no format marker (written before the marker existed),
    /// and one whose marker names a format this tog does not know. The
    /// error names the two ways out, `tog gc --reset` and moving the
    /// directory aside.
    pub fn open() -> io::Result<Store> {
        let (root, from_env) = Self::configured_root();
        Self::open_root(&root, from_env)
    }

    /// `open` for a store at a path the caller names, whatever `TOG_STORE`
    /// says. A test that opens a store in-process uses this to stay out of
    /// the developer's own store without changing the process environment.
    pub fn open_at(root: &Path) -> io::Result<Store> {
        Self::open_root(root, true)
    }

    fn open_root(root: &Path, from_env: bool) -> io::Result<Store> {
        fs::create_dir_all(root).map_err(|error| open_error(root, from_env, error))?;
        let root = root
            .canonicalize()
            .map_err(|error| open_error(root, from_env, error))?;
        // Held while the marker is read and whatever is missing is
        // created: a reset holds the same lock while it empties the store,
        // and a second tog creating this store waits for the first.
        let _held = format::lock_root(&root)?;
        match format::probe(&root)? {
            StoreFormat::Current => {}
            // The marker goes in before the first namespace, so neither a
            // crash nor a second tog can find namespaces without it.
            StoreFormat::Uninitialized => format::write_marker(&root)
                .map_err(|error| open_error(&root.join(FORMAT_FILE), from_env, error))?,
            refused => refused.refuse(&root)?,
        }
        Self::create_namespaces(&root, from_env)?;
        Ok(Store { root })
    }

    /// Make this root a fresh store of the current format, for `gc::reset`
    /// once the old records are gone and while it holds `format::lock_root`.
    /// The namespaces go in first and are made durable, and the marker is
    /// published last: a crash before the marker leaves a store that is
    /// still refused, never a marked one that is half initialised. (A new
    /// store is created the other way round, marker first, in `open_root`:
    /// there the marker is what tells its namespaces from an older tog's.)
    pub(crate) fn reinitialize(&self) -> io::Result<()> {
        Self::create_namespaces(&self.root, false)?;
        let root = open_store_directory(&self.root, "store root")?;
        // `cache` is the one namespace with directories below it: its own
        // entries, then the root's.
        fs::File::open(self.root.join("cache"))?.sync_all()?;
        fsync_directory(root.as_raw_fd())?;
        format::write_marker(&self.root)
    }

    /// Refuse unless the marker says this is a store this tog reads. Called
    /// with a lease held, which is what makes the answer last: the one
    /// operation that removes a marker, `gc --reset`, needs the exclusive
    /// lease.
    fn check_format(&self) -> io::Result<()> {
        match format::probe(&self.root)? {
            StoreFormat::Current => Ok(()),
            StoreFormat::Uninitialized => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "there is no tog store at {}: the directory has no format marker and \
                     nothing stored in it",
                    self.root.display()
                ),
            )),
            refused => refused.refuse(&self.root),
        }
    }

    fn create_namespaces(root: &Path, from_env: bool) -> io::Result<()> {
        for sub in format::NAMESPACES {
            ensure_directory_tree(root, Path::new(sub))
                .map_err(|error| open_error(&root.join(sub), from_env, error))?;
        }
        Ok(())
    }

    /// Ensure a managed namespace exists without following an existing
    /// symlink. Producers use this for store-owned projection parents before
    /// creating or sweeping descendants.
    pub(crate) fn ensure_namespace(&self, relative: &Path) -> io::Result<()> {
        ensure_directory_tree(&self.root, relative)
    }

    pub fn object_path(&self, id: &str) -> PathBuf {
        self.root.join("objects").join(id)
    }

    /// The short per-project key under `forests/` and `run-homes/`: hex of
    /// the first 8 bytes of SHA-256 over the canonical project path. Every
    /// store path derived from a project goes through here so the
    /// namespaces agree on which project a key names.
    pub fn project_key(project_dir: &Path) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        let canonical = project_dir.canonicalize()?;
        Ok(hex::encode(
            &Sha256::digest(canonical.as_os_str().as_bytes())[..8],
        ))
    }

    /// The HOME a `tog run` child of `ecosystem` gets for this project:
    /// `<root>/run-homes/<project key>/<ecosystem>`, created on demand.
    ///
    /// It lives in the store rather than the shared temp root because a
    /// world-writable parent lets another user create the directory first
    /// and plant startup files (`.erlang`, `.iex.exs`) that the child runs
    /// as this user. It is stable per project so `tog env` prints the same
    /// bytes on every call. Both levels under `run-homes` are private to
    /// this user: a symlink or a directory someone else owns is refused,
    /// and one of ours with wider permissions is narrowed to 0700.
    pub fn run_home(&self, project_dir: &Path, ecosystem: &str) -> io::Result<PathBuf> {
        let single = matches!(
            Path::new(ecosystem)
                .components()
                .collect::<Vec<_>>()
                .as_slice(),
            [std::path::Component::Normal(_)]
        );
        if !single || ecosystem.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("run home ecosystem {ecosystem:?} is not one path component"),
            ));
        }
        let key = Self::project_key(project_dir)?;
        let namespace = Path::new("run-homes");
        self.ensure_namespace(namespace)?;
        let mut path = self.root.join(namespace);
        for level in [key.as_str(), ecosystem] {
            path.push(level);
            ensure_private_directory(&path)?;
        }
        Ok(path)
    }

    /// Acquire operation-level protection for this store. The root is
    /// canonicalized before the lease is created so aliases cannot bypass
    /// the in-process coordinator or the on-disk lock.
    // Reviewed site (tests/architecture.rs): lease primitive (operation boundary).
    #[allow(clippy::disallowed_methods)]
    ///
    /// The format marker is validated once the lease is held, before the
    /// caller can read a record under it: a command that opened the store,
    /// then waited here behind a `gc --reset`, is refused if the reset left
    /// the store without its marker.
    // Reviewed site (tests/architecture.rs): lease primitive (operation boundary).
    #[allow(clippy::disallowed_methods)]
    pub fn activity(&self, mode: ActivityMode) -> io::Result<StoreActivity> {
        let activity = StoreActivity::acquire(&self.root, mode)?;
        self.check_format()?;
        Ok(activity)
    }

    /// Try to acquire exclusive activity without waiting. GC uses this form
    /// so a running job can be reported as busy instead of making cleanup
    /// contend with an unbounded command. The format marker is validated
    /// under the lease, as in `activity`.
    pub fn try_activity_exclusive(&self) -> io::Result<Option<StoreActivity>> {
        let Some(activity) = self.try_activity_exclusive_unchecked()? else {
            return Ok(None);
        };
        self.check_format()?;
        Ok(Some(activity))
    }

    /// Try to acquire shared activity without waiting behind an exclusive
    /// job. `doctor` uses this form, so a store that is being swept or
    /// emptied is reported as busy and the rest of its checks still run.
    /// The format marker is validated under the lease, as in `activity`.
    // Reviewed site (tests/architecture.rs): lease primitive (operation boundary).
    #[allow(clippy::disallowed_methods)]
    pub fn try_activity_shared(&self) -> io::Result<Option<StoreActivity>> {
        let Some(activity) = StoreActivity::try_shared(&self.root)? else {
            return Ok(None);
        };
        self.check_format()?;
        Ok(Some(activity))
    }

    /// `try_activity_exclusive` without the format check, for the one
    /// operation that exists to work on a store this tog refuses:
    /// `gc --reset`, which reads no record.
    // Reviewed site (tests/architecture.rs): lease primitive (operation boundary).
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn try_activity_exclusive_unchecked(&self) -> io::Result<Option<StoreActivity>> {
        StoreActivity::try_exclusive(&self.root)
    }

    /// Verify that a caller is still holding an operation-owned lease for
    /// this exact store. An exclusive lease also satisfies a shared read.
    pub(crate) fn require_activity(&self, activity: &StoreActivity, what: &str) -> io::Result<()> {
        let expected = self.root.canonicalize()?;
        if activity.root() != expected || !activity.mode().satisfies(ActivityMode::Shared) {
            return Err(io::Error::other(format!(
                "{what} requires an active shared lease for store {}; the supplied lease belongs to {}",
                expected.display(),
                activity.root().display()
            )));
        }
        Ok(())
    }

    pub(crate) fn require_exclusive_activity(
        &self,
        activity: &StoreActivity,
        what: &str,
    ) -> io::Result<()> {
        let expected = self.root.canonicalize()?;
        if activity.root() != expected || activity.mode() != ActivityMode::Exclusive {
            return Err(io::Error::other(format!(
                "{what} requires an active exclusive lease for store {}",
                expected.display()
            )));
        }
        Ok(())
    }

    /// Exclusive lock shared by fetches and GC. A cache lease keeps this
    /// lock until its verified artifact has been extracted by the caller.
    pub(crate) fn gc_lock(&self) -> io::Result<fs::File> {
        let f = open_private_lock(&self.root.join("gc.lock"), "GC")?;
        f.lock()?;
        Ok(f)
    }

    pub fn cache_path(&self, algo: &str, hex: &str) -> PathBuf {
        self.root.join("cache").join(algo).join(hex)
    }

    /// The object ids `project`'s root record holds now (empty without a
    /// record). A producer that may have to take back what it roots reads
    /// this first, so it never unroots an id someone else rooted before.
    pub(crate) fn rooted_objects_locked(
        &self,
        activity: &StoreActivity,
        project: &crate::kernel::fsroot::ProjectRoot,
        _project_lock: &fs::File,
    ) -> io::Result<BTreeSet<String>> {
        self.require_activity(activity, "root read")?;
        let key = roots::root_key(project.path());
        Ok(self
            .read_root_entry_strict(&key)?
            .and_then(|entry| entry.record)
            .map(|record| record.objects)
            .unwrap_or_default())
    }

    /// Drop `ids` from the project's root record, so `tog gc` may collect
    /// them. The only caller is a resolution transaction releasing the
    /// original copies it rooted for the life of its journal; every other
    /// producer only adds. Ids the record does not hold are ignored, and a
    /// project with no record is left without one. The record may end up
    /// with no objects: an empty root protects nothing and is still a valid
    /// record of the project.
    pub(crate) fn unroot_objects_locked(
        &self,
        activity: &StoreActivity,
        project: &crate::kernel::fsroot::ProjectRoot,
        ids: &BTreeSet<String>,
        _project_lock: &fs::File,
    ) -> io::Result<()> {
        self.require_activity(activity, "root release")?;
        let key = roots::root_key(project.path());
        let Some(mut record) = self
            .read_root_entry_strict(&key)?
            .and_then(|entry| entry.record)
        else {
            return Ok(());
        };
        let before = record.objects.len();
        record.objects.retain(|id| !ids.contains(id));
        if record.objects.len() == before {
            return Ok(());
        }
        record.updated = fsops::unix_secs();
        self.register_root_record_locked(record).map(|_| ())
    }
}

/// Test support for producer tests: drop `project`'s root record and rebuild
/// it the way `gc --register` does, from the closures on disk alone. A
/// producer test compares the result with the record it published directly,
/// so a closure shape the importer cannot read back fails where it is made.
/// The caller must not hold an activity lease: registration takes the
/// exclusive one.
#[cfg(test)]
pub(crate) fn reimport_root_for_test(store: &Store, project: &Path) -> io::Result<RootRecord> {
    let key = Store::root_key(project)?;
    fs::remove_file(store.root.join("roots").join(&key))?;
    store
        .register_root_from_project(project)?
        .record
        .ok_or_else(|| io::Error::other("registration wrote no root/2 record"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::Exception;
    use crate::kernel::testutil::TempDir;
    use std::collections::BTreeMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::process::Command;

    /// A scratch directory laid out as an empty store.
    fn temp_store() -> TempDir {
        let temp = TempDir::named("store-test");
        Store::open_at(&temp.0).unwrap();
        temp
    }

    fn identity() -> Identity {
        crate::kernel::objmeta::register_test_kinds();
        Identity {
            kind: "test".into(),
            name: "object".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        }
    }

    fn staged(store: &Store) -> PathBuf {
        let path = store.stage().unwrap();
        fs::write(path.join("content"), b"content").unwrap();
        path
    }

    /// A crash leaves one of three half-published shapes: a writable object
    /// (before the chmod), an object with no record (before the record's
    /// rename), or a record a power loss left empty. Each reads as absent,
    /// the lookup clears the object, and the next commit publishes a whole
    /// object and record over what is left.
    #[test]
    fn a_crashed_publication_reads_as_absent_and_the_next_commit_replaces_it() {
        use std::os::unix::fs::PermissionsExt;
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let id = identity.object_id();
        let record = store.root.join("meta").join(format!("{id}.json"));
        for crash in ["writable object", "no record", "empty record"] {
            store
                .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
                .unwrap();
            assert!(store.has(&id).unwrap(), "{crash}");
            match crash {
                "writable object" => {
                    let object = store.object_path(&id);
                    let mut perms = fs::metadata(&object).unwrap().permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&object, perms).unwrap();
                }
                "no record" => fs::remove_file(&record).unwrap(),
                _ => fs::write(&record, b"").unwrap(),
            }
            assert!(!store.has(&id).unwrap(), "{crash}");
            assert!(!store.object_path(&id).exists(), "{crash}");

            store
                .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
                .unwrap();
            assert!(store.has(&id).unwrap(), "{crash}");
            crate::kernel::objmeta::read_record_at(&record).unwrap();
            remove_tree(&store.object_path(&id)).unwrap();
            fs::remove_file(&record).unwrap();
        }
    }

    #[test]
    fn long_supported_object_names_use_short_completion_temporaries() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let mut identity = identity();
        identity.name = "n".repeat(180);
        identity.version = "1.0".into();
        let id = identity.object_id();
        assert_eq!(id.len(), 225);
        assert!(is_object_id(&id));
        let (object, _) = store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap();
        assert!(object.is_dir());
        assert_eq!(store.is_complete(&id), Some(true));
        crate::kernel::objmeta::read_record_at(&store.root.join("meta").join(format!("{id}.json")))
            .unwrap();
    }

    fn with_publication_hook<T>(
        hook: impl FnMut(&str) -> io::Result<()> + 'static,
        operation: impl FnOnce() -> T,
    ) -> T {
        objects::PUBLICATION_FAILPOINT.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let result = operation();
        objects::PUBLICATION_FAILPOINT.with(|slot| *slot.borrow_mut() = None);
        result
    }

    #[test]
    fn commit_replaces_a_crashed_destination_that_appears_after_lookup() {
        use std::os::unix::fs::PermissionsExt;
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let id = identity.object_id();
        for crash in ["writable", "missing record", "empty record"] {
            let object = store.object_path(&id);
            let record = store.root.join("meta").join(format!("{id}.json"));
            let old_object = object.clone();
            let old_record = record.clone();
            let stage = staged(&store);
            fs::write(stage.join("replacement"), crash).unwrap();
            let result = with_publication_hook(
                move |at| {
                    if at == "after-lookup" {
                        fs::create_dir(&old_object)?;
                        fs::write(old_object.join("old"), "crashed")?;
                        match crash {
                            "writable" => fs::write(&old_record, "{}")?,
                            "empty record" => {
                                fs::set_permissions(
                                    &old_object,
                                    fs::Permissions::from_mode(0o555),
                                )?;
                                fs::write(&old_record, "")?;
                            }
                            _ => {
                                fs::set_permissions(&old_object, fs::Permissions::from_mode(0o555))?
                            }
                        }
                    }
                    Ok(())
                },
                || store.commit_with_deps(&identity, &stage, &[], &ObjectDeps::new()),
            );
            let (object, _) = result.unwrap();
            assert_eq!(
                fs::read_to_string(object.join("replacement")).unwrap(),
                crash
            );
            assert!(!object.join("old").exists());
            crate::kernel::objmeta::read_record_at(&record).unwrap();
            remove_tree(&object).unwrap();
            fs::remove_file(&record).unwrap();
        }
    }

    #[test]
    fn orphan_completion_is_invalidated_before_a_republication_flush_failure() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let id = identity.object_id();
        store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap();
        let record = store.root.join("meta").join(format!("{id}.json"));
        remove_tree(&store.object_path(&id)).unwrap();
        assert!(record.is_file());
        let stage = staged(&store);
        let result = with_publication_hook(
            |at| {
                if at == "before-sync-tree" {
                    return Err(io::Error::other("injected flush failure"));
                }
                Ok(())
            },
            || store.commit_with_deps(&identity, &stage, &[], &ObjectDeps::new()),
        );
        assert!(result.is_err());
        assert!(
            !record.exists(),
            "old record still certifies the unfinished replacement"
        );
        assert_eq!(store.is_complete(&id), Some(false));
        store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap();
        assert_eq!(store.is_complete(&id), Some(true));
    }

    #[test]
    fn completeness_rechecks_a_record_replaced_after_its_stat() {
        use std::os::unix::ffi::OsStrExt;
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let id = identity.object_id();
        store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap();
        let record = store.root.join("meta").join(format!("{id}.json"));
        let valid = fs::read(&record).unwrap();
        for fifo in [true, false] {
            fs::write(&record, &valid).unwrap();
            let replaced = record.clone();
            let outside = temp.0.join("outside.json");
            fs::write(&outside, "{}").unwrap();
            let complete = with_publication_hook(
                move |at| {
                    if at == "before-completeness-open" {
                        fs::remove_file(&replaced)?;
                        if fifo {
                            let name = CString::new(replaced.as_os_str().as_bytes()).unwrap();
                            // SAFETY: the NUL-terminated name lives through the call.
                            if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
                                return Err(io::Error::last_os_error());
                            }
                        } else {
                            std::os::unix::fs::symlink(&outside, &replaced)?;
                        }
                    }
                    Ok(())
                },
                || store.is_complete(&id),
            );
            assert_eq!(complete, Some(false));
            fs::remove_file(&record).unwrap();
        }
    }

    /// A record is written under a temporary name and renamed into place,
    /// so the add leaves only the record and the registry marker behind,
    /// with no temporary file in `roots/` or `tmp/`. The rename being atomic
    /// is the kernel's promise, not something a test can observe.
    #[test]
    fn roots_registry_adds_leaving_no_temporary_file_and_drops_entries() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let root = store.register_root(&project).unwrap();
        assert_eq!(store.roots().unwrap(), vec![root.clone()]);
        assert_eq!(
            fs::read_to_string(&root.registry_path).unwrap().trim(),
            project.canonicalize().unwrap().display().to_string()
        );
        let names = |dir: &str| -> BTreeSet<String> {
            fs::read_dir(store.root.join(dir))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        };
        assert_eq!(
            names("roots"),
            BTreeSet::from([root.key.clone(), roots::ROOTS_INITIALIZED.to_string()])
        );
        assert!(names("tmp").is_empty(), "{:?}", names("tmp"));
        store.remove_root_entry(&root).unwrap();
        assert!(store.roots().unwrap().is_empty());
    }

    /// A project whose pathname a record cannot hold exactly is refused
    /// before anything is written: recording a lossy spelling files one
    /// project under another project's identity.
    #[test]
    fn registration_refuses_a_pathname_no_record_can_hold() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let padded = temp.0.join("project ");
        fs::create_dir_all(&padded).unwrap();
        assert_eq!(
            store.register_root(&padded).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            Store::root_key(&padded).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        // APFS refuses non-UTF-8 file names (EILSEQ), so the lossy case can
        // only be exercised on Linux.
        #[cfg(target_os = "linux")]
        {
            let mut raw = temp.0.canonicalize().unwrap().into_os_string().into_vec();
            raw.extend_from_slice(b"/project-\xff");
            let lossy = PathBuf::from(OsString::from_vec(raw));
            fs::create_dir_all(&lossy).unwrap();
            assert_eq!(
                store.register_root(&lossy).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(store.roots().unwrap().is_empty(), "a record was written");
    }

    /// A record that cannot be read is still a record. Reporting it keeps GC
    /// able to refuse; skipping it silently drops a project's protection.
    #[test]
    fn unreadable_records_are_reported_not_skipped() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let entry = store.register_root(&project).unwrap();

        for contents in [
            b"".as_slice(),
            b"\xff\n".as_slice(),
            b" /padded\n".as_slice(),
            b"relative/path\n".as_slice(),
            b"/one\n/two\n".as_slice(),
        ] {
            fs::write(&entry.registry_path, contents).unwrap();
            let roots = store.roots().unwrap();
            assert_eq!(roots.len(), 1, "record skipped: {contents:?}");
            assert_eq!(roots[0].key, entry.key);
            assert!(roots[0].unusable.is_some(), "record accepted: {contents:?}");
        }

        fs::remove_file(&entry.registry_path).unwrap();
        std::os::unix::fs::symlink(&project, &entry.registry_path).unwrap();
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "symlinked record skipped");
        assert!(roots[0].unusable.is_some(), "symlinked record accepted");
    }

    #[test]
    fn lookup_and_forget_work_off_registry_records_alone() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let entry = store.register_root(&project).unwrap();

        // Forgetting resolves the key against the registry only, so a record
        // stays forgettable after its project is gone.
        fs::remove_dir_all(&project).unwrap();
        let lookup = store.lookup_root(&entry.key).unwrap();
        assert_eq!(lookup.key, entry.key);

        assert_eq!(
            store.forget_root(&entry.key).unwrap().registry_path,
            entry.registry_path
        );
        assert!(store.roots().unwrap().is_empty());
        let error = store.forget_root(&entry.key).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn forget_rejects_unknown_and_malformed_keys() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        store.register_root(&project).unwrap();

        let error = store.forget_root(&"a".repeat(40)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let error = store.forget_root("not-a-key").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = store.forget_root(&"g".repeat(40)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(store.roots().unwrap().len(), 1);
    }

    /// A record that is not a regular file is refused on its metadata,
    /// before anything opens it. Without that check, reading a FIFO nobody
    /// writes to blocks the listing, the sweep and `--forget` alike, which
    /// is the one registry failure there is no way to recover from.
    #[test]
    fn a_record_that_is_not_a_regular_file_is_never_opened() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let roots = store.root.join("roots");
        fs::create_dir_all(&roots).unwrap();

        let fifo = roots.join("a".repeat(40));
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path in a directory this test owns.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        fs::create_dir(roots.join("b".repeat(40))).unwrap();

        // A regression blocks on the FIFO, so the listing runs on its own
        // thread and a stall fails the test instead of hanging it.
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = store.clone();
        std::thread::spawn(move || {
            let _ = sender.send(reader.roots());
        });
        let records = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("roots() blocked on a FIFO record")
            .unwrap();
        assert_eq!(records.len(), 2);
        for record in records {
            let reason = record.unusable.expect("read as a usable record");
            assert!(reason.contains("not a regular file"), "{reason}");
            // The escape hatch reaches these too, without opening them.
            store.forget_root(&record.key).unwrap();
        }
        assert!(store.roots().unwrap().is_empty());
    }

    /// Exact-key recovery reads one record. Every other record can be
    /// hostile — unreadable bytes, no permissions, a symlink, a directory,
    /// or far too large — and the requested key still resolves.
    #[test]
    fn exact_key_recovery_ignores_every_other_record() {
        use std::os::unix::fs::PermissionsExt;

        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let entry = store.register_root(&project).unwrap();
        let roots = store.root.join("roots");

        let broken = ["a", "b", "c", "d", "e"].map(|c| c.repeat(40));
        fs::write(roots.join(&broken[0]), b"\xff\n").unwrap();
        fs::write(roots.join(&broken[1]), b"unreadable\n").unwrap();
        fs::set_permissions(roots.join(&broken[1]), fs::Permissions::from_mode(0o000)).unwrap();
        std::os::unix::fs::symlink(&project, roots.join(&broken[2])).unwrap();
        fs::create_dir(roots.join(&broken[3])).unwrap();
        fs::write(roots.join(&broken[4]), vec![b'x'; 64 * 1024]).unwrap();

        let found = store.lookup_root(&entry.key).unwrap();
        assert_eq!(found.path, project.canonicalize().unwrap());
        assert!(found.unusable.is_none());
        assert_eq!(store.forget_root(&entry.key).unwrap().key, entry.key);

        // Each broken record is reachable by its own key, so the registry can
        // be emptied without deleting files by hand.
        for key in &broken {
            let entry = store.lookup_root(key).unwrap();
            assert!(entry.unusable.is_some(), "{key} read as a usable record");
            store.forget_root(key).unwrap();
        }
        assert!(store.roots().unwrap().is_empty());
    }

    #[test]
    fn commit_reconciles_cached_exceptions() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let exception = Exception {
            kind: crate::kernel::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        let (object, applied) = store
            .commit_with_deps(
                &identity,
                &staged(&store),
                std::slice::from_ref(&exception),
                &ObjectDeps::new(),
            )
            .unwrap();
        assert_eq!(object, store.object_path(&identity.object_id()));
        assert_eq!(applied, vec![exception.clone()]);

        let error = store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("was published concurrently with different exceptions"));
        assert!(error.to_string().contains("winner:"));
        assert!(error.to_string().contains("staged: []"));

        let (same_object, applied) = store
            .commit_with_deps(
                &identity,
                &staged(&store),
                std::slice::from_ref(&exception),
                &ObjectDeps::new(),
            )
            .unwrap();
        assert_eq!(same_object, object);
        assert_eq!(applied, vec![exception]);
    }

    /// A stage that sat in `tmp/` long enough to look abandoned is published
    /// with a fresh mtime, so a sweep's active window protects it.
    #[test]
    fn publication_refreshes_an_old_stage_mtime() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let staged = staged(&store);
        let old = SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(2 * 24 * 60 * 60))
            .unwrap();
        fs::File::open(&staged).unwrap().set_modified(old).unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        let modified = fs::metadata(store.object_path(&identity.object_id()))
            .unwrap()
            .modified()
            .unwrap();
        let age = SystemTime::now().duration_since(modified).unwrap();
        assert!(age < std::time::Duration::from_secs(10 * 60), "{age:?}");
    }

    #[test]
    fn cache_hit_refuses_a_record_without_evidence() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let digest = "4".repeat(64);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = identity.object_id();
        // Publish, then strip the record of its schema and evidence: a
        // shape no producer writes, so nothing in it can be trusted.
        store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap();
        let meta = store.root.join("meta").join(format!("{id}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&meta).unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        for key in ["schema", "dependencies", "cache_digests", "evidence"] {
            object.remove(key);
        }
        object.insert("refs".into(), serde_json::json!([]));
        fs::write(&meta, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let before = fs::read(&meta).unwrap();

        // A sync publishes the same identity with real evidence and finds
        // the object already there. The cache hit must not certify the
        // record or rewrite it: it refuses, and `tog gc --drop-object` is
        // what clears the object for a rebuild.
        fs::write(store.cache_path("sha256", &digest), b"artifact").unwrap();
        let mut deps = ObjectDeps::new();
        deps.cache_digest(crate::kernel::fetch::Digest::sha256(&digest).unwrap());
        let error = store
            .commit_with_deps(&identity, &staged(&store), &[], &deps)
            .unwrap_err();
        assert!(error.to_string().contains("has no schema"), "{error}");

        assert_eq!(
            fs::read(&meta).unwrap(),
            before,
            "a cache hit rewrote a record it could not read"
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    fn commit_rejects_malformed_kernel_identity_before_publishing() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let valid_identity = Identity {
            kind: "git-source".into(),
            name: "valid-example".into(),
            version: "1".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "git-source/2".into()),
                ("url".into(), "https://example.invalid/repo.git".into()),
                ("commit".into(), "a".repeat(40)),
            ]),
        };
        store
            .commit_with_deps(&valid_identity, &staged(&store), &[], &ObjectDeps::new())
            .expect("valid kernel identity is the control");
        let identity = Identity {
            kind: "git-source".into(),
            name: "example".into(),
            version: "1".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "git-source/2".into()),
                ("url".into(), "https://example.invalid/repo.git".into()),
            ]),
        };
        let id = identity.object_id();
        let result = catch_unwind(AssertUnwindSafe(|| {
            store
                .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
                .unwrap();
        }));
        let payload = result.expect_err("malformed kernel identity was published");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message.contains("object-kind grammar drift"), "{message}");
        assert!(
            !store.object_path(&id).exists(),
            "object directory was published"
        );
        assert!(
            !store.root.join("meta").join(format!("{id}.json")).exists(),
            "meta record was published"
        );
    }

    #[test]
    fn strict_policy_rejects_cached_exceptions() {
        if std::env::var_os("TOG_STORE_STRICT_CHILD").is_some() {
            let store = Store::open().unwrap();
            crate::kernel::policy::init(&store.root).unwrap();
            let error = store
                .commit_with_deps(&identity(), &staged(&store), &[], &ObjectDeps::new())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let exception = Exception {
            kind: crate::kernel::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        store
            .commit_with_deps(
                &identity(),
                &staged(&store),
                std::slice::from_ref(&exception),
                &ObjectDeps::new(),
            )
            .unwrap();
        // libtest names a test by its path inside the crate, so the crate
        // name `module_path!` leads with is dropped. A wrong name selects
        // no test and the child exits 0 having checked nothing.
        let (_, module) = module_path!().split_once("::").unwrap();
        let name = format!("{module}::strict_policy_rejects_cached_exceptions");
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env("TOG_STORE", &store.root)
            .env("TOG_STORE_STRICT_CHILD", "1")
            .env("TOG_STRICT", "1")
            .env_remove("TOG_POLICY")
            .env("HOME", &temp.0)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success(),
            "strict child failed: {stdout}{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(
            stdout.contains("test result: ok. 1 passed;"),
            "the child did not run exactly this test: {stdout}"
        );
    }

    /// A lease is bound to the store that issued it. Presenting one store's
    /// token to another store's primitive must fail, and a shared token must
    /// not satisfy a check that requires exclusive protection.
    #[test]
    fn a_lease_only_authorizes_the_store_and_mode_it_was_taken_for() {
        let first = temp_store();
        let second = temp_store();
        let one = Store {
            root: first.0.canonicalize().unwrap(),
        };
        let two = Store {
            root: second.0.canonicalize().unwrap(),
        };
        let foreign = two.activity(ActivityMode::Shared).unwrap();
        let error = one
            .require_activity(&foreign, "store object lookup")
            .unwrap_err();
        assert!(
            error.to_string().contains("the supplied lease belongs to"),
            "a foreign lease was accepted: {error}"
        );
        assert!(one.require_exclusive_activity(&foreign, "sweep").is_err());
        drop(foreign);

        let shared = one.activity(ActivityMode::Shared).unwrap();
        one.require_activity(&shared, "store object lookup")
            .unwrap();
        let error = one
            .require_exclusive_activity(&shared, "garbage collection")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an active exclusive lease"),
            "a shared lease satisfied an exclusive check: {error}"
        );
        drop(shared);

        // Exclusive stands in for shared, never the reverse.
        let exclusive = one.activity(ActivityMode::Exclusive).unwrap();
        one.require_activity(&exclusive, "store object lookup")
            .unwrap();
        one.require_exclusive_activity(&exclusive, "garbage collection")
            .unwrap();
    }

    /// The wrong-store case reaches a real protected primitive, not just the
    /// checker: `has_with_activity` must refuse rather than answer.
    #[test]
    fn a_foreign_lease_cannot_drive_a_store_lookup() {
        let first = temp_store();
        let second = temp_store();
        let one = Store {
            root: first.0.canonicalize().unwrap(),
        };
        let two = Store {
            root: second.0.canonicalize().unwrap(),
        };
        let foreign = two.activity(ActivityMode::Shared).unwrap();
        let error = one
            .has_with_activity(&foreign, "0000000000000000000000000000000000000000-thing-1")
            .unwrap_err();
        assert!(
            error.to_string().contains("store object lookup requires"),
            "{error}"
        );
    }

    // APFS refuses non-UTF-8 file names (EILSEQ); the root/2 lossless
    // roundtrip is only observable on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn root2_roundtrips_a_non_utf8_path() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join(OsString::from_vec(b"project-\xff".to_vec()));
        fs::create_dir_all(&project).unwrap();
        let record = RootRecord {
            key: root_key(&project.canonicalize().unwrap()),
            project_path: project.canonicalize().unwrap(),
            objects: BTreeSet::from([format!("{}-env", "a".repeat(40))]),
            projections: BTreeSet::from([ProjectionRef::new(
                ProjectionBase::Forests,
                vec![OsString::from("project"), OsString::from("projection")],
            )
            .unwrap()]),
            updated: 1,
        };
        let entry = store.register_root_record(record.clone()).unwrap();
        let (decoded, temps) = store.roots_for_sweep().unwrap();
        assert!(temps.is_empty());
        assert_eq!(decoded[0].record.as_ref(), Some(&record));
        assert_eq!(decoded[0].path, project.canonicalize().unwrap());
        assert!(fs::read_to_string(entry.registry_path)
            .unwrap()
            .contains("base64"));
    }

    /// A store that cannot be created is the first thing a new user hits on
    /// a locked-down machine. The message names the path, says what errno
    /// meant, and names the variable that moves the store.
    #[test]
    fn store_creation_failures_name_the_path_the_cause_and_the_lever() {
        let denied = open_error(
            Path::new("/ro/home/.tog/store"),
            false,
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert_eq!(
            denied.to_string(),
            "create the store at /ro/home/.tog/store: permission denied; \
             set TOG_STORE to a writable directory"
        );
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);

        let full = open_error(
            Path::new("/mnt/small/store"),
            true,
            io::Error::from_raw_os_error(libc::ENOSPC),
        );
        assert!(
            full.to_string().contains("the filesystem is full"),
            "{full}"
        );
        assert!(
            full.to_string().contains("TOG_STORE names this path"),
            "{full}"
        );

        let read_only = open_error(
            Path::new("/store"),
            false,
            io::Error::from_raw_os_error(libc::EROFS),
        );
        assert!(
            read_only
                .to_string()
                .contains("the filesystem is read-only"),
            "{read_only}"
        );
    }

    #[test]
    fn root2_rejects_unknown_schema_before_gc() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let key = root_key(&project.canonicalize().unwrap());
        fs::create_dir_all(store.root.join("roots")).unwrap();
        fs::write(
            store.root.join("roots").join(&key),
            serde_json::json!({"schema": "root/3", "key": key}).to_string(),
        )
        .unwrap();
        let (entries, _) = store.roots_for_sweep().unwrap();
        let reason = entries[0].unusable.as_deref().expect("entry is unusable");
        assert!(reason.contains("unknown schema"), "{reason}");
        assert_eq!(entries[0].key, key);
    }

    /// A complete object named `name`, published through the real commit so
    /// a closure import can validate it.
    fn named_object(store: &Store, name: &str) -> String {
        let mut identity = identity();
        identity.name = name.into();
        store
            .commit_with_deps(&identity, &staged(store), &[], &ObjectDeps::new())
            .unwrap();
        identity.object_id()
    }

    fn store_in(temp: &TempDir) -> Store {
        let root = temp.0.canonicalize().unwrap();
        for sub in ["roots", "forests", "backups"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        Store { root }
    }

    /// Write one `closure/1` envelope into a project, as a producer would.
    fn project_closure(project: &Path, ecosystem: &str, body: serde_json::Value) {
        let closures = project.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join(format!("{ecosystem}.json")),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": ecosystem,
                "body": body,
            })
            .to_string(),
        )
        .unwrap();
    }

    /// The `{"path", "id"}` shape most producers write for an object.
    fn object_ref(store: &Store, id: &str) -> serde_json::Value {
        serde_json::json!({"path": store.object_path(id), "id": id})
    }

    /// A projection reference is relative to a store-owned base. An absolute
    /// or `..`-bearing one would let a record claim, and a sweep walk, any
    /// path on the machine, so it is refused when built, when written, and
    /// when read back.
    #[test]
    fn root2_rejects_absolute_projection() {
        let temp = temp_store();
        let store = store_in(&temp);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = root_key(&project);

        for components in [
            vec![OsString::from("/etc")],
            vec![OsString::from(".."), OsString::from("etc")],
            vec![OsString::from("a/b")],
            vec![OsString::from("")],
            Vec::new(),
        ] {
            assert!(
                ProjectionRef::new(ProjectionBase::Forests, components.clone()).is_err(),
                "built a projection from {components:?}"
            );
            // The fields are public, so a writer can bypass `new`.
            let record = RootRecord {
                key: key.clone(),
                project_path: project.clone(),
                objects: BTreeSet::from([format!("{}-env", "a".repeat(40))]),
                projections: BTreeSet::from([ProjectionRef {
                    base: ProjectionBase::Forests,
                    components: components.clone(),
                }]),
                updated: 1,
            };
            assert!(
                store.register_root_record(record).is_err(),
                "wrote a projection of {components:?}"
            );
            assert!(store.roots().unwrap().is_empty(), "a record was written");
        }

        // Producers name projections by path. One outside the store's own
        // namespace, or climbing out of it, is refused.
        for path in [
            PathBuf::from("/etc/passwd"),
            store.root.join("forests/../objects"),
            store.root.join("../forests/escape"),
        ] {
            assert!(
                store
                    .projection_ref(ProjectionBase::Forests, &path)
                    .is_err(),
                "accepted projection {}",
                path.display()
            );
        }

        // A hand-written record is unusable, never a record that protects a
        // path outside the store.
        for component in ["/etc", "..", "."] {
            fs::write(
                store.root.join("roots").join(&key),
                serde_json::json!({
                    "schema": "root/2",
                    "key": key,
                    "project_path": {"encoding": "utf8", "value": project.display().to_string()},
                    "objects": [],
                    "projections": [{
                        "base": "forests",
                        "components": [{"encoding": "utf8", "value": component}],
                    }],
                    "updated": 1,
                })
                .to_string(),
            )
            .unwrap();
            let (entries, _) = store.roots_for_sweep().unwrap();
            assert_eq!(entries.len(), 1);
            assert!(
                entries[0].unusable.is_some() && entries[0].record.is_none(),
                "read a projection component {component:?} as usable"
            );
        }
    }

    /// A closure that names another store's object protects nothing here,
    /// and a record claiming it would be protection nobody can check. Both
    /// reference forms are refused at write, and nothing is registered.
    #[test]
    fn root2_rejects_cross_store_object() {
        let ours = temp_store();
        let theirs = temp_store();
        let store = store_in(&ours);
        let other = store_in(&theirs);
        let foreign = named_object(&other, "foreign");

        // The producer boundary.
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let error = crate::comforter::ClosureRefs::new()
            .object_path(&store, &activity, &other.object_path(&foreign))
            .map(|_| ())
            .unwrap_err();
        assert!(error.to_string().contains("outside this store"), "{error}");
        // The same id is not an object of this store either.
        assert!(crate::comforter::ClosureRefs::new()
            .object_id(&store, &activity, &foreign)
            .is_err());
        drop(activity);

        // The importer, for both shapes a shipped closure uses.
        for body in [
            serde_json::json!({"env_object": other.object_path(&foreign)}),
            serde_json::json!({"go_object": object_ref(&other, &foreign)}),
        ] {
            let project = ours.0.join("project");
            let _ = fs::remove_dir_all(&project);
            fs::create_dir_all(&project).unwrap();
            project_closure(&project, "go", body.clone());
            let error = store.root_record_from_project(&project).unwrap_err();
            assert!(
                error.to_string().contains("another store")
                    || error.to_string().contains("does not belong"),
                "{body}: {error}"
            );
            assert!(
                store.register_root_from_project(&project).is_err(),
                "{body}"
            );
            assert!(
                store.roots().unwrap().is_empty(),
                "{body}: a record was written"
            );
        }
    }

    /// Protection only grows. A second publication for the same project adds
    /// its references to the record; it never replaces what an earlier
    /// ecosystem or environment recorded, and neither does registration.
    #[test]
    fn root2_merge_is_a_union_never_a_replace() {
        let temp = temp_store();
        let store = store_in(&temp);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let held = crate::kernel::fsroot::ProjectRoot::open(&project).unwrap();
        let first = format!("{}-first", "a".repeat(40));
        let second = format!("{}-second", "b".repeat(40));
        let forest = |name: &str| {
            ProjectionRef::new(ProjectionBase::Forests, vec![OsString::from(name)]).unwrap()
        };

        store
            .register_root_parts_locked(
                &held,
                BTreeSet::from([first.clone()]),
                BTreeSet::from([forest("one")]),
            )
            .unwrap();
        let record = store
            .register_root_parts_locked(
                &held,
                BTreeSet::from([second.clone()]),
                BTreeSet::from([forest("two")]),
            )
            .unwrap()
            .record
            .unwrap();
        assert_eq!(
            record.objects,
            BTreeSet::from([first.clone(), second.clone()])
        );
        assert_eq!(
            record.projections,
            BTreeSet::from([forest("one"), forest("two")])
        );

        // Registration imports the project's closures into the same union.
        let third = named_object(&store, "third");
        project_closure(
            &project,
            "ruby",
            serde_json::json!({"ruby_object": object_ref(&store, &third)}),
        );
        let record = store
            .register_root_from_project(&project)
            .unwrap()
            .record
            .unwrap();
        assert_eq!(record.objects, BTreeSet::from([first, second, third]));
        assert_eq!(
            record.projections,
            BTreeSet::from([forest("one"), forest("two")])
        );
        assert_eq!(store.roots().unwrap().len(), 1);
    }

    /// Leave `identity` as a finished publication does, without the publish
    /// machinery: a read-only object root, then its metadata record.
    fn publish_bare(store: &Store, identity: &Identity) -> String {
        use std::os::unix::fs::PermissionsExt;
        let id = identity.object_id();
        let path = store.object_path(&id);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(
            store.root.join("meta").join(format!("{id}.json")),
            serde_json::to_vec(&serde_json::json!({
                "schema": "object-meta/2",
                "id": id,
                "identity": identity,
                "dependencies": [],
                "cache_digests": [],
                "evidence": "explicit",
            }))
            .unwrap(),
        )
        .unwrap();
        id
    }

    fn sweep_bare(store: &Store, id: &str) {
        let _ = fs::remove_file(store.root.join("meta").join(format!("{id}.json")));
        let _ = fs::remove_dir(store.object_path(id));
    }

    /// Run `published_identity` with `hook` interleaved at its failpoints.
    fn published_with(
        store: &Store,
        id: &str,
        hook: impl FnMut(&str) + 'static,
    ) -> io::Result<Option<Identity>> {
        objects::PUBLISHED_IDENTITY_FAILPOINT
            .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let result = store.published_identity(id);
        objects::PUBLISHED_IDENTITY_FAILPOINT.with(|slot| *slot.borrow_mut() = None);
        result
    }

    /// A sweep or a republish racing the read gives the validated identity
    /// or nothing, never another object's identity, and only absence (or a
    /// publication in flight) is `None`: a symlink or a file where an
    /// object or its record belongs is an error.
    #[test]
    fn published_identity_is_the_validated_identity_or_none() {
        use std::os::unix::fs::PermissionsExt;
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let published = identity();
        let seen_id =
            |seen: io::Result<Option<Identity>>| seen.unwrap().map(|found| found.object_id());
        let id = publish_bare(&store, &published);
        assert_eq!(seen_id(store.published_identity(&id)), Some(id.clone()));

        // Swept before the record is opened.
        let (s, i) = (store.clone(), id.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "before-metadata-open" {
                sweep_bare(&s, &i);
            }
        });
        assert_eq!(seen_id(seen), None);

        // Swept after the record was read: what was read was validated.
        let id = publish_bare(&store, &published);
        let (s, i) = (store.clone(), id.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "after-metadata-read" {
                sweep_bare(&s, &i);
            }
        });
        assert_eq!(seen_id(seen), Some(published.object_id()));

        // Swept and republished under the same id before the record opens.
        let id = publish_bare(&store, &published);
        let (s, i, again) = (store.clone(), id.clone(), published.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "before-metadata-open" {
                sweep_bare(&s, &i);
                publish_bare(&s, &again);
            }
        });
        assert_eq!(seen_id(seen), Some(published.object_id()));

        // A record swapped for another identity under this id is refused.
        let (s, i) = (store.clone(), id.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "before-metadata-open" {
                let mut other = identity();
                other.name = "other".into();
                fs::write(
                    s.root.join("meta").join(format!("{i}.json")),
                    serde_json::to_vec(&serde_json::json!({"identity": other})).unwrap(),
                )
                .unwrap();
            }
        });
        assert!(seen.is_err());

        // A publication in flight (writable root, then no record) is None.
        let mut flight = identity();
        flight.name = "flight".into();
        let flight_id = flight.object_id();
        fs::create_dir_all(store.object_path(&flight_id)).unwrap();
        assert!(store.published_identity(&flight_id).unwrap().is_none());
        fs::set_permissions(
            store.object_path(&flight_id),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(store.published_identity(&flight_id).unwrap().is_none());

        // Wrong types are errors, not misses.
        let mut linked = identity();
        linked.name = "linked".into();
        let linked_id = linked.object_id();
        std::os::unix::fs::symlink(store.object_path(&id), store.object_path(&linked_id)).unwrap();
        assert!(store.published_identity(&linked_id).is_err());
        let mut meta_link = identity();
        meta_link.name = "meta-link".into();
        let meta_link_id = publish_bare(&store, &meta_link);
        let record = store.root.join("meta").join(format!("{meta_link_id}.json"));
        fs::remove_file(&record).unwrap();
        std::os::unix::fs::symlink(store.root.join("meta").join(format!("{id}.json")), &record)
            .unwrap();
        assert!(store.published_identity(&meta_link_id).is_err());

        // A FIFO planted as the record is refused, not waited on: a
        // blocking open would hang `status` forever with no writer.
        let mut piped = identity();
        piped.name = "piped".into();
        let piped_id = publish_bare(&store, &piped);
        let record = store.root.join("meta").join(format!("{piped_id}.json"));
        fs::remove_file(&record).unwrap();
        let name = CString::new(record.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = store.clone();
        std::thread::spawn(move || {
            let _ = sender.send(reader.published_identity(&piped_id).map(|_| ()));
        });
        let error = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("published_identity blocked on a FIFO record")
            .unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    /// `existing` finds a store without creating one, and holds it to
    /// `open`'s layout: a symlinked or non-directory namespace is an error.
    #[test]
    fn existing_never_creates_and_refuses_a_bent_layout() {
        let _lock = STORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("TOG_STORE");
        let temp = temp_store();
        let check = |root: &Path| {
            std::env::set_var("TOG_STORE", root);
            Store::existing()
        };
        let missing = temp.0.join("missing");
        let absent = check(&missing);
        let real = check(&temp.0);
        let bent = temp.0.join("bent");
        fs::create_dir_all(&bent).unwrap();
        std::os::unix::fs::symlink(temp.0.join("objects"), bent.join("objects")).unwrap();
        fs::write(bent.join(FORMAT_FILE), StoreFormat::current_line()).unwrap();
        let linked = check(&bent);
        let flat = temp.0.join("flat");
        fs::create_dir_all(&flat).unwrap();
        fs::write(flat.join("objects"), b"").unwrap();
        fs::write(flat.join(FORMAT_FILE), StoreFormat::current_line()).unwrap();
        let file = check(&flat);
        // A store `open` refuses is refused here too, in the same words.
        let old_store = temp.0.join("old");
        fs::create_dir_all(old_store.join("objects")).unwrap();
        let pre_epoch = check(&old_store);
        match old {
            Some(value) => std::env::set_var("TOG_STORE", value),
            None => std::env::remove_var("TOG_STORE"),
        }
        assert!(absent.unwrap().is_none());
        assert!(!missing.exists());
        assert_eq!(real.unwrap().unwrap().root, temp.0.canonicalize().unwrap());
        assert!(linked
            .unwrap_err()
            .to_string()
            .contains("is not a real directory"));
        assert!(file
            .unwrap_err()
            .to_string()
            .contains("is not a real directory"));
        let refusal = pre_epoch.unwrap_err();
        assert_eq!(refusal_fix(&refusal), Some("tog gc --reset"));
        let refusal = refusal.to_string();
        assert!(refusal.contains("has no format marker"), "{refusal}");
        assert!(!old_store.join(FORMAT_FILE).exists());
    }

    /// The marker is written when the store is created, before any
    /// namespace, and a store without one is never opened or changed.
    /// The shared lease that does not wait: none while another job holds
    /// the store exclusively, one afterwards, and a refusal, not a lease,
    /// on a store whose marker is gone.
    #[test]
    fn try_activity_shared_reports_a_busy_store_and_validates_the_marker() {
        let temp = TempDir::named("store-try-shared");
        let store = Store::open_at(&temp.0.join("store")).unwrap();
        let (hold, held) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let other = store.clone();
        let job = std::thread::spawn(move || {
            let _exclusive = other.try_activity_exclusive().unwrap().unwrap();
            hold.send(()).unwrap();
            released.recv().unwrap();
        });
        held.recv().unwrap();
        assert!(store.try_activity_shared().unwrap().is_none());
        release.send(()).unwrap();
        job.join().unwrap();

        let shared = store.try_activity_shared().unwrap().unwrap();
        assert_eq!(shared.mode(), ActivityMode::Shared);
        // Shared with other readers.
        assert!(store.try_activity_shared().unwrap().is_some());
        drop(shared);

        fs::remove_file(store.root.join(FORMAT_FILE)).unwrap();
        let error = store.try_activity_shared().unwrap_err();
        assert!(refusal_fix(&error).is_some(), "{error}");
        // The refusal let go of the lease it had taken.
        assert!(store.try_activity_exclusive_unchecked().unwrap().is_some());
    }

    #[test]
    fn open_writes_the_marker_and_refuses_a_store_without_one() {
        let temp = TempDir::named("store-format");
        // Missing and empty directories both become a marked store.
        let missing = temp.0.join("missing/store");
        let store = Store::open_at(&missing).unwrap();
        assert_eq!(
            fs::read(store.root.join(FORMAT_FILE)).unwrap(),
            b"tog-store 1\n"
        );
        assert!(store.root.join("objects").is_dir());
        let empty = temp.0.join("empty");
        fs::create_dir(&empty).unwrap();
        let store = Store::open_at(&empty).unwrap();
        assert_eq!(
            Store::probe_at(&empty).unwrap().unwrap().1,
            StoreFormat::Current
        );
        // Opening again changes nothing.
        let marker = fs::metadata(store.root.join(FORMAT_FILE)).unwrap();
        Store::open_at(&empty).unwrap();
        assert_eq!(
            fs::metadata(store.root.join(FORMAT_FILE))
                .unwrap()
                .modified()
                .unwrap(),
            marker.modified().unwrap()
        );
        assert!(Store::probe_at(&temp.0.join("nowhere")).unwrap().is_none());

        // A store from before the marker: refused, named, and untouched.
        let old = temp.0.join("old");
        for sub in ["objects", "meta", "roots"] {
            fs::create_dir_all(old.join(sub)).unwrap();
        }
        let error = Store::open_at(&old).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let text = error.to_string();
        assert!(
            text.contains(&old.canonicalize().unwrap().display().to_string()),
            "{text}"
        );
        assert!(text.contains("has no format marker"), "{text}");
        assert!(text.contains("an older tog wrote it"), "{text}");
        // Not the store a bare `tog` selects, so the fix names it.
        assert_eq!(
            refusal_fix(&error).unwrap(),
            format!(
                "TOG_STORE={} tog gc --reset",
                old.canonicalize().unwrap().display()
            )
        );
        assert!(text.contains("move the directory aside"), "{text}");
        assert!(!old.join(FORMAT_FILE).exists());
        assert!(!old.join("cache").exists(), "a refused store was changed");

        // A marker from a newer tog, and one that is not a marker at all.
        let newer = temp.0.join("newer");
        fs::create_dir(&newer).unwrap();
        fs::write(newer.join(FORMAT_FILE), b"tog-store 2\n").unwrap();
        let error = Store::open_at(&newer).unwrap_err();
        assert_eq!(refusal_fix(&error), Some("tog update --self"));
        let text = error.to_string();
        assert!(text.contains("a newer tog wrote it"), "{text}");
        assert!(text.contains("tog-store 2"), "{text}");
        assert!(
            !newer.join("objects").exists(),
            "a refused store was changed"
        );
        let unknown = temp.0.join("unknown");
        fs::create_dir(&unknown).unwrap();
        fs::write(unknown.join(FORMAT_FILE), b"hello\n").unwrap();
        let error = Store::open_at(&unknown).unwrap_err();
        assert!(refusal_fix(&error).unwrap().ends_with(" tog gc --reset"));
        let text = error.to_string();
        assert!(
            text.contains("a format marker this tog does not know"),
            "{text}"
        );
        assert!(text.contains("hello"), "{text}");
        assert_eq!(fs::read(unknown.join(FORMAT_FILE)).unwrap(), b"hello\n");
    }

    /// `gc --register` over a project holding one closure per ecosystem at
    /// once, each in its sparsest shape: bare object paths, the
    /// `{"path", "id"}` pair, and projections named by their paths. Every
    /// object and projection lands in one record. Each producer's current
    /// closure is re-imported by its own
    /// `closure_refs_name_every_object_this_producer_created` test; this one
    /// covers the sparse shapes and the cross-ecosystem union, and that a
    /// retired record beside them imports nothing.
    #[test]
    fn register_imports_closure_bodies_of_every_ecosystem_together() {
        let temp = temp_store();
        let store = store_in(&temp);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let mut expected = BTreeSet::new();
        let mut object = |name: &str| {
            let id = named_object(&store, name);
            expected.insert(id.clone());
            id
        };
        let python_env = object("python-env");
        let node_env = object("node-env");
        let (rust, vendor) = (object("rust"), object("vendor"));
        let (go, modcache) = (object("go"), object("modcache"));
        let (ruby, gems) = (object("ruby"), object("gems"));
        let (beam, deps) = (object("beam"), object("deps"));
        let (sdk, packages) = (object("sdk"), object("packages"));
        // A retired `rustfmt` record an older `tog fmt` left is skipped by
        // the importer, so the object only it names is not in the record.
        let rustfmt = named_object(&store, "rustfmt");
        let backup = store.root.join("backups/venv-backup");
        let deps_projection = store
            .root
            .join("forests/0123456789abcdef")
            .join(&deps)
            .join("hex-deps");
        let node_forest = store.root.join("forests/0123456789abcdef/projection");

        for (ecosystem, body) in [
            (
                "python",
                serde_json::json!({
                    "env_object": store.object_path(&python_env),
                    "native_libs": null,
                    "backup_path": backup,
                }),
            ),
            (
                "node",
                serde_json::json!({
                    "env_object": store.object_path(&node_env),
                    "projection_schema": "node-forest/2",
                    "projection_id": "projection",
                    "forest_path": node_forest,
                }),
            ),
            (
                "cargo",
                serde_json::json!({
                    "rust_object": object_ref(&store, &rust),
                    "vendor_object": object_ref(&store, &vendor),
                }),
            ),
            (
                "go",
                serde_json::json!({
                    "go_object": object_ref(&store, &go),
                    "modcache_object": object_ref(&store, &modcache),
                }),
            ),
            (
                "ruby",
                serde_json::json!({
                    "ruby_object": object_ref(&store, &ruby),
                    "gems_object": object_ref(&store, &gems),
                }),
            ),
            (
                "elixir",
                serde_json::json!({
                    "beam_object": object_ref(&store, &beam),
                    "deps_object": object_ref(&store, &deps),
                    "deps_projection": deps_projection,
                }),
            ),
            (
                "dotnet",
                serde_json::json!({
                    "sdk_object": object_ref(&store, &sdk),
                    "packages_object": object_ref(&store, &packages),
                }),
            ),
            (
                "rustfmt",
                serde_json::json!({
                    "rust_object": object_ref(&store, &rust),
                    "rustfmt_object": object_ref(&store, &rustfmt),
                }),
            ),
        ] {
            project_closure(&project, ecosystem, body);
        }

        let record = store
            .register_root_from_project(&project)
            .unwrap()
            .record
            .unwrap();
        assert_eq!(record.objects, expected);
        let projections: BTreeSet<PathBuf> = record
            .projections
            .iter()
            .map(|projection| projection.path(&store))
            .collect();
        assert_eq!(
            projections,
            BTreeSet::from([backup, deps_projection, node_forest])
        );
    }

    /// Keys hash the pathname's bytes. A UTF-8 pathname keeps the key every
    /// earlier registry gave it; a pathname that is not UTF-8 is keyed by its
    /// raw bytes, so it never collides with the UTF-8 path that displays the
    /// same way (U+FFFD standing in for the bad byte).
    #[test]
    fn utf8_keys_unchanged_and_non_utf8_keys_distinct() {
        use sha1::Digest as _;
        let temp = temp_store();
        let store = store_in(&temp);
        let utf8 = temp.0.join("projekt-\u{e9}");
        fs::create_dir_all(&utf8).unwrap();
        let utf8 = utf8.canonicalize().unwrap();
        let expected = hex::encode(sha1::Sha1::digest(utf8.to_str().unwrap().as_bytes()));
        assert_eq!(Store::root_key(&utf8).unwrap(), expected);
        assert_eq!(store.register_root(&utf8).unwrap().key, expected);

        let lossy = PathBuf::from(format!("{}/project-\u{fffd}", store.root.display()));
        let raw = PathBuf::from(OsString::from_vec(
            [store.root.as_os_str().as_bytes(), b"/project-\xff"].concat(),
        ));
        assert_eq!(raw.to_string_lossy(), lossy.to_string_lossy());
        assert_ne!(root_key(&lossy), root_key(&raw));

        // APFS refuses non-UTF-8 file names (EILSEQ), so the registered pair
        // is only observable on Linux.
        #[cfg(target_os = "linux")]
        {
            let object = format!("{}-env", "c".repeat(40));
            for path in [&lossy, &raw] {
                fs::create_dir_all(path).unwrap();
                store
                    .register_root_record(RootRecord {
                        key: root_key(path),
                        project_path: path.clone(),
                        objects: BTreeSet::from([object.clone()]),
                        projections: BTreeSet::new(),
                        updated: 1,
                    })
                    .unwrap();
            }
            let (entries, _) = store.roots_for_sweep().unwrap();
            assert_eq!(entries.len(), 3, "{entries:?}");
            for path in [&lossy, &raw] {
                let found: Vec<_> = entries.iter().filter(|entry| &entry.path == path).collect();
                assert_eq!(found.len(), 1, "{path:?} read back as {found:?}");
                assert_eq!(found[0].key, root_key(path));
                assert!(found[0].record.is_some(), "{found:?}");
            }
        }
    }

    /// A scratch store and a project directory beside it, for the run
    /// home tests.
    fn run_home_fixture(label: &str) -> (TempDir, Store, PathBuf) {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join(label);
        fs::create_dir_all(&project).unwrap();
        (temp, store, project)
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A fresh run home is `run-homes/<key>/<ecosystem>` with both levels
    /// private, and asking again returns the same directory.
    #[test]
    fn run_home_is_private_and_stable() {
        let (_temp, store, project) = run_home_fixture("project");
        let home = store.run_home(&project, "elixir").unwrap();
        let key = Store::project_key(&project).unwrap();
        assert_eq!(home, store.root.join("run-homes").join(&key).join("elixir"));
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(home.parent().unwrap()), 0o700);
        assert_eq!(store.run_home(&project, "elixir").unwrap(), home);
    }

    /// The project key is the one the forest paths already use: 16 hex
    /// characters of SHA-256 over the canonical path, the same for any
    /// spelling of the project and different between projects.
    #[test]
    fn project_key_matches_the_forest_key_and_separates_projects() {
        use sha2::{Digest, Sha256};
        let (temp, store, project) = run_home_fixture("one");
        let other = temp.0.join("two");
        fs::create_dir_all(&other).unwrap();
        let canonical = project.canonicalize().unwrap();
        let expected = hex::encode(&Sha256::digest(canonical.as_os_str().as_bytes())[..8]);
        assert_eq!(Store::project_key(&project).unwrap(), expected);
        assert_eq!(
            Store::project_key(&project.join("../one")).unwrap(),
            expected
        );
        assert_ne!(Store::project_key(&other).unwrap(), expected);
        assert_ne!(
            store.run_home(&project, "dotnet").unwrap(),
            store.run_home(&other, "dotnet").unwrap()
        );
    }

    /// A symlink at any level of the run home is refused rather than
    /// followed: it would hand the child a HOME someone else chose.
    #[test]
    fn run_home_refuses_a_symlink_at_every_level() {
        let (temp, store, project) = run_home_fixture("project");
        let elsewhere = temp.0.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let key = Store::project_key(&project).unwrap();
        let namespace = store.root.join("run-homes");
        let levels = [
            namespace.clone(),
            namespace.join(&key),
            namespace.join(&key).join("elixir"),
        ];
        for (index, level) in levels.iter().enumerate() {
            let _ = crate::kernel::store::remove_tree(&namespace);
            for parent in &levels[..index] {
                fs::create_dir(parent).unwrap();
            }
            std::os::unix::fs::symlink(&elsewhere, level).unwrap();
            let error = store.run_home(&project, "elixir").unwrap_err();
            assert!(
                error.to_string().contains(&level.display().to_string()),
                "{}: {error}",
                level.display()
            );
            assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        }
    }

    /// A run home of ours that is readable by others is narrowed to 0700
    /// instead of refused: the contents are still only ours.
    #[test]
    fn run_home_tightens_a_wider_directory_of_ours() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, store, project) = run_home_fixture("project");
        let key = Store::project_key(&project).unwrap();
        let home = store.root.join("run-homes").join(&key).join("dotnet");
        fs::create_dir_all(&home).unwrap();
        for level in [home.parent().unwrap(), home.as_path()] {
            fs::set_permissions(level, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(store.run_home(&project, "dotnet").unwrap(), home);
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(home.parent().unwrap()), 0o700);
    }

    /// An ecosystem name that is not a single path component cannot walk
    /// the run home out of its project's directory.
    #[test]
    fn run_home_refuses_an_ecosystem_that_is_not_one_component() {
        let (_temp, store, project) = run_home_fixture("project");
        for ecosystem in ["", ".", "..", "../elixir", "a/b", "/abs", "elixir/"] {
            let error = store.run_home(&project, ecosystem).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{ecosystem:?}");
        }
    }

    /// A file where a run home level belongs is refused by name.
    #[test]
    fn run_home_refuses_a_file_in_its_place() {
        let (_temp, store, project) = run_home_fixture("project");
        let key = Store::project_key(&project).unwrap();
        let level = store.root.join("run-homes").join(&key);
        fs::create_dir_all(level.parent().unwrap()).unwrap();
        fs::write(&level, b"").unwrap();
        let error = store.run_home(&project, "elixir").unwrap_err();
        assert!(error.to_string().contains("not a directory"), "{error}");
    }
}

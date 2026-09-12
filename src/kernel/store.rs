//! The content-addressed object store (kernel layer): object paths, atomic
//! commit, root records, projection bases, and the `BLANKET_STORE` override.

use crate::activity::{ActivityMode, StoreActivity};
use crate::policy::Exception;
use crate::types::Identity;
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

/// Content/input-addressed immutable store (the closet).
///
/// Layout:
///   <root>/objects/<object-id>/     immutable realized outputs
///   <root>/meta/<object-id>.json    identity + provenance
///   <root>/cache/sha256/<hash>      verified downloaded artifacts
///   <root>/tmp/                     staging for atomic renames
///
/// ponytail: store root defaults to ~/.blanket/store (BLANKET_STORE overrides).
/// The /opt/blanket/store decision only matters once binary-cache sharing
/// exists; identity format is machine-independent so migration is re-realize.
#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEntry {
    pub key: String,
    /// The registered project. Empty when the record is unusable: a record
    /// nobody can read has no pathname to offer, and guessing one selects
    /// somebody else's project.
    pub path: PathBuf,
    pub registry_path: PathBuf,
    /// Why this record cannot be trusted, if it cannot. The record still
    /// exists: it is listed and can be forgotten, but no sweep may run while
    /// one is present.
    pub unusable: Option<String>,
    /// A durable root/2 record, when this entry is not a legacy pathname-only
    /// record.  The pathname remains on RootEntry for diagnostics and for the
    /// legacy importer; GC treats the record as authoritative when present.
    pub record: Option<RootRecord>,
}

impl RootEntry {
    /// What this record protects, for user-facing output.
    pub fn describe(&self) -> String {
        match &self.unusable {
            Some(reason) => format!("unusable record: {reason}"),
            None => self.path.display().to_string(),
        }
    }
}

/// The durable protection record kept inside the store.  `project_path` is
/// diagnostic only: object and projection sets are the sweep authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecord {
    pub key: String,
    pub project_path: PathBuf,
    pub objects: BTreeSet<String>,
    pub projections: BTreeSet<ProjectionRef>,
    pub updated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionBase {
    Forests,
    Backups,
    LegacyForests,
    LegacyBackups,
}

impl ProjectionBase {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Forests => "forests",
            Self::Backups => "backups",
            Self::LegacyForests => "legacy-forests",
            Self::LegacyBackups => "legacy-backups",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Forests => 0,
            Self::Backups => 1,
            Self::LegacyForests => 2,
            Self::LegacyBackups => 3,
        }
    }
}

/// A typed, relative projection reference.  Legacy variants are retention
/// only and are never passed to an automatic deletion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRef {
    pub base: ProjectionBase,
    pub components: Vec<OsString>,
}

impl Ord for ProjectionRef {
    fn cmp(&self, other: &Self) -> Ordering {
        self.base.rank().cmp(&other.base.rank()).then_with(|| {
            self.components
                .iter()
                .map(|component| component.as_os_str().as_bytes())
                .cmp(
                    other
                        .components
                        .iter()
                        .map(|component| component.as_os_str().as_bytes()),
                )
        })
    }
}

impl PartialOrd for ProjectionRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ProjectionRef {
    pub fn new(base: ProjectionBase, components: Vec<OsString>) -> io::Result<Self> {
        let reference = Self { base, components };
        validate_projection_components(&reference.components)?;
        Ok(reference)
    }

    pub fn path(&self, store: &Store) -> PathBuf {
        let base = match self.base {
            ProjectionBase::Forests => store.root.join("forests"),
            ProjectionBase::Backups => store.root.join("backups"),
            ProjectionBase::LegacyForests => {
                store.root.parent().unwrap_or(&store.root).join("forests")
            }
            ProjectionBase::LegacyBackups => {
                store.root.parent().unwrap_or(&store.root).join("backups")
            }
        };
        self.components
            .iter()
            .fold(base, |path, component| path.join(component))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDiagnostic {
    pub key: String,
    pub path: Option<PathBuf>,
    pub problem: Option<String>,
}

/// Explicit dependency evidence supplied when an object is published.  The
/// sets are ordered so the on-disk metadata is deterministic and easy to
/// compare during a cache hit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectDeps {
    pub objects: BTreeSet<String>,
    pub cache: BTreeSet<crate::fetch::Digest>,
}

impl ObjectDeps {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn object_id(&mut self, id: &str) -> io::Result<&mut Self> {
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed dependency object id {id:?}"),
            ));
        }
        self.objects.insert(id.to_string());
        Ok(self)
    }

    pub fn cache_digest(&mut self, digest: crate::fetch::Digest) -> &mut Self {
        self.cache.insert(digest);
        self
    }
}

const ROOTS_INITIALIZED: &str = ".initialized";

/// Generous ceiling on one registry record: four times the longest pathname
/// Linux or macOS will hand back, plus its newline.
const RECORD_LIMIT: u64 = 16 * 1024;

/// Serializes every test that sets or clears `BLANKET_STORE`. The variable is
/// process-global, so an unguarded test clearing it mid-run sends a guarded one
/// to the real `~/.blanket/store` — which is populated, and fails any assertion
/// about a fresh store. One lock for the whole crate: separate per-module locks
/// do not exclude each other. Poison is ignored deliberately, so a single
/// failing test does not cascade into every other holder.
#[cfg(test)]
pub(crate) static STORE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Store {
    pub fn open() -> io::Result<Store> {
        let root = std::env::var_os("BLANKET_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".blanket/store"));
        fs::create_dir_all(&root)?;
        let root = root.canonicalize()?;
        for sub in [
            "objects",
            "meta",
            "cache/sha1",
            "cache/sha256",
            "cache/sha512",
            "tmp",
            "roots",
            "forests",
            "backups",
            "root-locks",
        ] {
            ensure_directory_tree(&root, Path::new(sub))?;
        }
        Ok(Store { root })
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

    /// Acquire operation-level protection for this store. The root is
    /// canonicalized before the lease is created so aliases cannot bypass
    /// the in-process coordinator or the on-disk lock.
    pub fn activity(&self, mode: ActivityMode) -> io::Result<StoreActivity> {
        StoreActivity::acquire(&self.root, mode)
    }

    /// Try to acquire exclusive activity without waiting. Maintenance and GC
    /// use this form so a running job can be reported as busy instead of
    /// making cleanup contend with an unbounded command.
    pub fn try_activity_exclusive(&self) -> io::Result<Option<StoreActivity>> {
        StoreActivity::try_exclusive(&self.root)
    }

    /// Serialize registry/closure publication for one canonical project.
    /// Callers acquire the store activity lease first, then this transaction
    /// lock, then publish/cache locks.
    pub(crate) fn project_lock(&self, project_dir: &Path) -> io::Result<fs::File> {
        let project_dir = project_dir.canonicalize()?;
        let locks = self.root.join("root-locks");
        ensure_directory_tree(&self.root, Path::new("root-locks"))?;
        let key = root_key(&project_dir);
        let path = locks.join(format!("{key}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        // The descriptor is the object whose permissions were inspected;
        // applying chmod by pathname could target a replacement lock name.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.lock()?;
        Ok(file)
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

    /// Validate a referenced object without refreshing its activity marker.
    /// Root publication uses this read-only form so a closure cannot claim a
    /// half-published or foreign object and so preparation does not mutate
    /// mtimes before the durable root exists.
    pub(crate) fn validate_object_complete(
        &self,
        activity: &StoreActivity,
        id: &str,
    ) -> io::Result<()> {
        self.require_activity(activity, "object reference validation")?;
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed object id {id:?}"),
            ));
        }
        let object = self.object_path(id);
        let object_meta = fs::symlink_metadata(&object).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("object reference {id} is unavailable: {error}"),
            )
        })?;
        if object_meta.file_type().is_symlink() || !object_meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference {id} is not a real directory"),
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        if object_meta.permissions().mode() & 0o222 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference {id} is still writable"),
            ));
        }
        let metadata = self.root.join("meta").join(format!("{id}.json"));
        let metadata_stat = fs::symlink_metadata(&metadata).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("object reference {id} has no metadata: {error}"),
            )
        })?;
        if metadata_stat.file_type().is_symlink() || !metadata_stat.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference {id} metadata is not a regular file"),
            ));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&metadata)?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse object reference metadata {id}: {e}"),
                )
            })?;
        if value.get("id").and_then(serde_json::Value::as_str) != Some(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference metadata {id} has a mismatched id"),
            ));
        }
        Ok(())
    }

    /// Register a project whose closure was just written. Registry entries
    /// are keyed by the canonical project path, so moving a project creates a
    /// new root instead of accidentally retaining the old location.
    pub fn register_root(&self, project_dir: &Path) -> io::Result<RootEntry> {
        let activity = self.activity(ActivityMode::Exclusive)?;
        self.register_root_with_activity(&activity, project_dir)
    }

    /// Compatibility pathname-only registration under an already-held
    /// operation lease. New closure publication uses `root/2`; this method is
    /// retained for guarded legacy fixtures and the explicit recovery path.
    pub(crate) fn register_root_with_activity(
        &self,
        activity: &StoreActivity,
        project_dir: &Path,
    ) -> io::Result<RootEntry> {
        self.require_activity(activity, "legacy root registration")?;
        let project_dir = project_dir.canonicalize()?;
        // The record must hold the project's pathname exactly (A-R3): a
        // trailing space or a non-UTF-8 byte would register one project
        // under another project's identity. Refuse instead of recording a
        // lossy spelling.
        let pathname = record_pathname(&project_dir)?.to_string();
        let key = root_key(&project_dir);
        let _project = self.project_lock(&project_dir)?;
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        write_registry_entry(&roots, &key, format!("{pathname}\n").as_bytes())?;
        Ok(RootEntry {
            key: key.clone(),
            path: project_dir,
            registry_path: roots.join(&key),
            unusable: None,
            record: None,
        })
    }

    /// Publish a complete root/2 record atomically.  This is deliberately a
    /// separate entry point from `register_root`, which remains the
    /// pathname-only compatibility writer used by older callers and tests.
    pub fn register_root_record(&self, record: RootRecord) -> io::Result<RootEntry> {
        let activity = self.activity(ActivityMode::Exclusive)?;
        self.register_root_record_with_activity(&activity, record)
    }

    pub(crate) fn register_root_record_with_activity(
        &self,
        activity: &StoreActivity,
        record: RootRecord,
    ) -> io::Result<RootEntry> {
        self.require_activity(activity, "root registration")?;
        let _project = self.project_lock(&record.project_path)?;
        self.register_root_record_locked(record)
    }

    fn register_root_record_locked(&self, record: RootRecord) -> io::Result<RootEntry> {
        let expected = root_key(&record.project_path);
        if record.key != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("root/2 key {} does not match project path", record.key),
            ));
        }
        validate_root_record(&record)?;
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let _publish = self.publish_lock()?;
        write_root_record(&roots, &record)?;
        Ok(RootEntry {
            key: record.key.clone(),
            path: record.project_path.clone(),
            registry_path: roots.join(&record.key),
            unusable: None,
            record: Some(record),
        })
    }

    pub(crate) fn register_root_parts_with_project_lock(
        &self,
        activity: &StoreActivity,
        project_dir: &Path,
        objects: BTreeSet<String>,
        projections: BTreeSet<ProjectionRef>,
        _project: &fs::File,
    ) -> io::Result<RootEntry> {
        self.require_activity(activity, "root publication")?;
        let project_dir = project_dir.canonicalize()?;
        self.register_root_parts_locked(&project_dir, objects, projections)
    }

    fn register_root_parts_locked(
        &self,
        project_dir: &Path,
        objects: BTreeSet<String>,
        projections: BTreeSet<ProjectionRef>,
    ) -> io::Result<RootEntry> {
        let key = root_key(&project_dir);
        let previous = self.read_root_entry_strict(&key)?;
        let mut record = previous
            .as_ref()
            .and_then(|entry| entry.record.clone())
            .unwrap_or_else(|| RootRecord {
                key: key.clone(),
                project_path: project_dir.to_path_buf(),
                objects: BTreeSet::new(),
                projections: BTreeSet::new(),
                updated: unix_secs(),
            });
        if previous
            .as_ref()
            .and_then(|entry| entry.record.as_ref())
            .is_none()
            && project_dir.join(".blanket/closures").is_dir()
        {
            import_existing_project_closures(
                self,
                &project_dir,
                &mut record,
                ImportMode::DropUnresolvable,
            )?;
        }
        record.project_path = project_dir.to_path_buf();
        record.objects.extend(objects);
        record.projections.extend(projections);
        record.updated = unix_secs();
        if record.objects.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "root/2 record has no object references",
            ));
        }
        self.register_root_record_locked(record)
    }

    /// Import all supported closure envelopes for a project into a durable
    /// root/2 record.  The reader is declarative: it never runs a planner,
    /// package manager, or project code.
    pub fn register_root_from_project(&self, project_dir: &Path) -> io::Result<RootEntry> {
        let activity = self.activity(ActivityMode::Exclusive)?;
        self.register_root_from_project_with_activity(&activity, project_dir)
    }

    pub fn register_root_from_project_with_activity(
        &self,
        activity: &StoreActivity,
        project_dir: &Path,
    ) -> io::Result<RootEntry> {
        self.require_exclusive_activity(activity, "root import")?;
        let project_dir = project_dir.canonicalize()?;
        let _project = self.project_lock(&project_dir)?;
        let record = self.root_record_from_project(&project_dir)?;
        self.register_root_record_locked(record)
    }

    /// Validate/import a project without writing its root record.  GC's dry
    /// run uses this to preview registration while keeping the registry
    /// byte-for-byte unchanged.
    pub fn root_record_from_project(&self, project_dir: &Path) -> io::Result<RootRecord> {
        let project_dir = project_dir.canonicalize()?;
        let closures = project_dir.join(".blanket/closures");
        if !closures.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} has no .blanket/closures directory",
                    project_dir.display()
                ),
            ));
        }
        let key = root_key(&project_dir);
        let mut record = RootRecord {
            key: key.clone(),
            project_path: project_dir.clone(),
            objects: BTreeSet::new(),
            projections: BTreeSet::new(),
            updated: unix_secs(),
        };
        if let Some(previous) = self.read_root_entry_strict(&key)? {
            if let Some(previous) = previous.record {
                record.objects.extend(previous.objects);
                record.projections.extend(previous.projections);
            }
        }
        let mut files: Vec<PathBuf> = fs::read_dir(&closures)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        files.sort();
        let mut imported_any = false;
        for path in files {
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let value: serde_json::Value = serde_json::from_reader(fs::File::open(&path)?)
                .map_err(|error| invalid_root_import(&path, error.to_string()))?;
            let body = validate_closure_envelope(&value, &path)?;
            // Explicit registration: the user named this project, so an
            // unresolvable reference is reported rather than dropped.
            import_closure_refs(self, &project_dir, body, &mut record, ImportMode::Strict)?;
            imported_any = true;
        }
        if !imported_any {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} contains no supported closure records",
                    closures.display()
                ),
            ));
        }
        if record.objects.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} did not contain a complete store object reference",
                    closures.display()
                ),
            ));
        }
        Ok(record)
    }

    /// Add one just-written closure to the durable root union.  This is the
    /// transition bridge used by the existing producer API; callers that
    /// already have a complete `RootRecord` should use
    /// `register_root_record` directly.
    pub(crate) fn register_root_with_closure(
        &self,
        project_dir: &Path,
        ecosystem: &str,
        body: &serde_json::Value,
    ) -> io::Result<RootEntry> {
        let project_dir = project_dir.canonicalize()?;
        let _project = self.project_lock(&project_dir)?;
        let key = root_key(&project_dir);
        let previous = self.read_root_entry_strict(&key)?;
        let had_root2 = previous
            .as_ref()
            .and_then(|entry| entry.record.as_ref())
            .is_some();
        let mut record = previous
            .and_then(|entry| entry.record)
            .unwrap_or_else(|| RootRecord {
                key: key.clone(),
                project_path: project_dir.clone(),
                objects: BTreeSet::new(),
                projections: BTreeSet::new(),
                updated: unix_secs(),
            });
        record.project_path = project_dir.clone();
        let _ = ecosystem;
        if !had_root2 {
            // Historical closures are imported best-effort; the body this
            // producer just wrote is held to the strict rule.
            import_existing_project_closures(
                self,
                &project_dir,
                &mut record,
                ImportMode::DropUnresolvable,
            )?;
        }
        import_closure_refs(self, &project_dir, body, &mut record, ImportMode::Strict)?;
        if record.objects.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "closure did not contain a complete store object reference",
            ));
        }
        record.updated = unix_secs();
        self.register_root_record_locked(record)
    }

    /// Read the roots registry without validating whether projects still
    /// exist. `blanket store roots` is an inspection command; GC validates
    /// each path before sweeping and never drops stale records implicitly.
    ///
    /// Every key-named entry is reported, including the ones that cannot be
    /// read. Skipping an unreadable record would hide a project whose record
    /// is still on disk, and GC would then sweep the objects that project is
    /// holding — the failure has to be visible to be refused.
    pub fn roots(&self) -> io::Result<Vec<RootEntry>> {
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        let mut entries = Vec::new();
        for name in read_dir_names_at(roots_dir.as_raw_fd())? {
            if name.as_os_str().as_bytes() == ROOTS_INITIALIZED.as_bytes() {
                let stat = stat_at(roots_dir.as_raw_fd(), name.as_os_str().as_bytes())?;
                if !is_regular_file(&stat) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "root registry initialization marker is not a regular file",
                    ));
                }
                continue;
            }
            let Some(key) = name.to_str() else {
                continue;
            };
            if !is_sha1(&key) {
                continue;
            }
            let path = roots.join(&key);
            entries.push(self.read_root_entry_tolerant_at(roots_dir.as_raw_fd(), &key, path));
        }
        entries.sort_by(|a, b| (&a.path, &a.key).cmp(&(&b.path, &b.key)));
        Ok(entries)
    }

    /// Diagnostic enumeration for `store roots`.  Unlike `roots()`, a bad
    /// record is represented as a diagnostic instead of being silently
    /// omitted; this command is intentionally not a sweep authority.
    pub fn root_diagnostics(&self) -> io::Result<Vec<RootDiagnostic>> {
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        let mut diagnostics = Vec::new();
        for name in read_dir_names_at(roots_dir.as_raw_fd())? {
            let key = name.to_string_lossy().into_owned();
            if key == ROOTS_INITIALIZED {
                continue;
            }
            let path = roots.join(&name);
            if !is_sha1(&key) {
                diagnostics.push(RootDiagnostic {
                    key,
                    path: None,
                    problem: Some("registry entry name is not a root key".into()),
                });
                continue;
            }
            let entry = self.read_root_entry_tolerant_at(roots_dir.as_raw_fd(), &key, path.clone());
            match entry.unusable {
                None => diagnostics.push(RootDiagnostic {
                    key: entry.key,
                    path: Some(entry.path),
                    problem: None,
                }),
                Some(reason) => diagnostics.push(RootDiagnostic {
                    key,
                    path: None,
                    problem: Some(format!("unusable record: {reason}")),
                }),
            }
        }
        diagnostics.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(diagnostics)
    }

    /// Strict root decoding used by GC.  Every registry entry must be a
    /// regular, non-followed file and every record must validate before a
    /// deletion plan can be formed.
    ///
    /// This is a read: interrupted registry temporaries are returned for the
    /// caller's *execute* phase to remove under the exclusive lease, never
    /// unlinked here — a dry run or a sweep that later fails validation must
    /// leave the filesystem exactly as it was found.
    pub(crate) fn roots_for_sweep(&self) -> io::Result<(Vec<RootEntry>, Vec<OsString>)> {
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        let mut entries = Vec::new();
        let mut crash_temps = Vec::new();
        for name in read_dir_names_at(roots_dir.as_raw_fd())? {
            if name.as_os_str().as_bytes() == ROOTS_INITIALIZED.as_bytes() {
                let stat = stat_at(roots_dir.as_raw_fd(), name.as_os_str().as_bytes())?;
                if !is_regular_file(&stat) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "root registry initialization marker is not a regular file",
                    ));
                }
                continue;
            }
            let key = std::str::from_utf8(name.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "root registry contains a non-UTF-8 entry name; remove it manually before sweeping",
                )
            })?;
            if is_own_registry_temp(key) {
                // A crash between the temp write and the rename in
                // write_registry_entry leaves one of our own temporaries
                // behind. Refusing to sweep because of it would wedge every
                // future collection over a file we know is ours and know is
                // dead — but deleting it here would make the read phase
                // mutate the store, and a dry run would too. Record it; the
                // execute phase clears it under the exclusive lease, after
                // the deletion plan has been validated.
                crash_temps.push(name);
                continue;
            }
            if !is_sha1(&key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected root registry entry {key}; remove it manually before sweeping"
                    ),
                ));
            }
            // A key whose record cannot be read (symlink, directory, empty,
            // padded, unknown schema) is reported on the entry as unusable
            // rather than failing the read here, so the sweep's refusal
            // (gc::unusable_root) names the key and `--forget` uniformly
            // (A-R2). The sweep still fails closed: collect_roots refuses on
            // the first unusable entry before anything is deleted.
            let path = roots.join(&name);
            entries.push(self.read_root_entry_tolerant_at(roots_dir.as_raw_fd(), key, path));
        }
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok((entries, crash_temps))
    }

    /// Remove the interrupted registry temporaries a previous sweep read.
    /// Execute-phase only: the caller must hold the exclusive activity lease,
    /// and this runs after the deletion plan has been validated. Each name is
    /// re-checked so a temporary renamed into place by a concurrent writer
    /// (impossible under the lease, but cheap to refuse) is not touched.
    pub(crate) fn clear_crash_temps(&self, temps: &[OsString]) -> io::Result<()> {
        if temps.is_empty() {
            return Ok(());
        }
        let roots = self.root.join("roots");
        let roots_dir = open_store_directory(&roots, "roots")?;
        for name in temps {
            let key = name.to_string_lossy();
            if !is_own_registry_temp(&key) {
                continue;
            }
            let stat = match stat_at(roots_dir.as_raw_fd(), name.as_bytes()) {
                Ok(stat) => stat,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if !is_regular_file(&stat) {
                continue;
            }
            unlink_at(roots_dir.as_raw_fd(), name.as_bytes());
        }
        Ok(())
    }
    /// created before the registry feature may have objects but no roots
    /// directory, so Store::open creating that directory is not sufficient.
    /// Valid root entries are accepted as initialized for compatibility with
    /// stores written by the first registry implementation, before the marker
    /// was added.
    pub(crate) fn registry_initialized(&self) -> io::Result<bool> {
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        for name in read_dir_names_at(roots_dir.as_raw_fd())? {
            let stat = stat_at(roots_dir.as_raw_fd(), name.as_os_str().as_bytes())?;
            if name.as_os_str().as_bytes() == ROOTS_INITIALIZED.as_bytes() {
                // A malformed marker is still an initialized-but-corrupt
                // registry; roots_for_sweep will report the exact defect.
                return Ok(true);
            }
            if !is_regular_file(&stat) || !is_sha1(&name.to_string_lossy()) {
                return Ok(true);
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub fn remove_root_entry(&self, entry: &RootEntry) -> io::Result<()> {
        let activity = self.activity(ActivityMode::Exclusive)?;
        self.remove_root_entry_with_activity(&activity, entry)
    }

    /// Exact-key registry removal under an existing exclusive operation
    /// lease. The registry directory is held by descriptor and the selected
    /// entry is rechecked by `(dev, ino)` before `unlinkat`; a replaced entry
    /// is never removed as if it were the one the caller decoded.
    pub(crate) fn remove_root_entry_with_activity(
        &self,
        activity: &StoreActivity,
        entry: &RootEntry,
    ) -> io::Result<()> {
        self.require_exclusive_activity(activity, "root removal")?;
        Self::validate_root_key(&entry.key)?;
        let roots_path = self.root.join("roots");
        let roots_stat = fs::symlink_metadata(&roots_path)?;
        if roots_stat.file_type().is_symlink() || !roots_stat.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "root registry {} is not a real directory",
                    roots_path.display()
                ),
            ));
        }
        let roots = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&roots_path)?;
        let name = entry.key.as_bytes();
        let expected = match stat_at(roots.as_raw_fd(), name) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if is_directory(&expected) {
            // A directory sitting at a key is not a record, but it still
            // occupies that key and still stops every sweep. Forgetting the
            // key has to clear it too, or the escape hatch fails at the
            // worst case (A-R6). The (dev, ino) recheck above is the guard:
            // what is removed is the entry the caller decoded.
            let path = roots_path.join(&entry.key);
            fs::remove_dir_all(&path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "root registry entry {} could not be removed as a directory: {error}",
                        entry.key
                    ),
                )
            })?;
            return roots.sync_all();
        }
        if !unlink_if_same(roots.as_raw_fd(), name, &expected, 0)? {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!(
                    "root registry entry {} changed during removal; retry later",
                    entry.key
                ),
            ));
        }
        roots.sync_all()
    }

    /// Look up one root record by its exact registry key without removing
    /// it. The key must match a record this store holds; the project itself
    /// is never touched, so lookups work while the project is unavailable.
    ///
    /// A record that cannot be trusted is reported on the entry instead of
    /// failing the lookup: `--forget` is the escape hatch every refusal
    /// points at, so it has to work when the registry is at its worst,
    /// including on the corrupt record itself (A-R6). The key is matched by
    /// exact directory-entry name, so a case-insensitive filesystem cannot
    /// answer with a neighbouring spelling's record (A-R1).
    pub fn lookup_root(&self, key: &str) -> io::Result<RootEntry> {
        Self::validate_root_key(key)?;
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        let path = roots.join(key);
        let metadata = match stat_at(roots_dir.as_raw_fd(), key.as_bytes()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "unknown root key {key}; `blanket store roots` lists the keys this \
                         store holds"
                    ),
                ))
            }
            Err(error) => return Err(error),
        };
        if is_symlink(&metadata) {
            // Exact-key forgetting is allowed to remove the registry link
            // itself, but it never follows the link or treats its target as
            // a root record.
            return Ok(RootEntry {
                key: key.into(),
                path: PathBuf::new(),
                registry_path: path,
                unusable: Some("the record is a symlink, not a registry file".into()),
                record: None,
            });
        }
        if !is_regular_file(&metadata) {
            // A directory or other non-record sitting at the key still
            // occupies it and still stops every sweep, so it must be
            // forgettable too (A-R6): report it instead of failing, and let
            // the removal clear it.
            return Ok(RootEntry {
                key: key.into(),
                path: PathBuf::new(),
                registry_path: path,
                unusable: Some("the record is not a regular file".into()),
                record: None,
            });
        }
        match self.read_root_entry_strict(key) {
            Ok(Some(entry)) => Ok(entry),
            Ok(None) => Ok(RootEntry {
                key: key.into(),
                path: PathBuf::new(),
                registry_path: path,
                unusable: None,
                record: None,
            }),
            // Any read failure (corrupt, unreadable, not a regular file)
            // still yields an entry: `--forget` is the escape hatch every
            // refusal points at, so a damaged record must stay forgettable
            // by its own key (A-R6).
            Err(error) => Ok(RootEntry {
                key: key.into(),
                path: PathBuf::new(),
                registry_path: path,
                unusable: Some(error.to_string()),
                record: None,
            }),
        }
    }

    /// Remove one project's protection record by its exact registry key.
    /// Only the record is removed: project files and store objects stay, so
    /// the project loses protection by explicit choice. Returns the removed
    /// entry.
    pub fn forget_root(&self, key: &str) -> io::Result<RootEntry> {
        let activity = self.activity(ActivityMode::Exclusive)?;
        self.forget_root_with_activity(&activity, key)
    }

    pub fn forget_root_with_activity(
        &self,
        activity: &StoreActivity,
        key: &str,
    ) -> io::Result<RootEntry> {
        self.require_exclusive_activity(activity, "root forgetting")?;
        let entry = self.lookup_root(key)?;
        self.remove_root_entry_with_activity(activity, &entry)?;
        Ok(entry)
    }

    fn validate_root_key(key: &str) -> io::Result<()> {
        if is_sha1(key) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid root key '{key}': expected 40 hex characters (`blanket store \
                     roots` prints keys)"
                ),
            ))
        }
    }

    /// The registry key a project directory would be registered under,
    /// without writing anything. Used to reject ambiguous register/forget
    /// combinations before either side mutates the registry.
    pub fn root_key(project_dir: &Path) -> io::Result<String> {
        let project_dir = project_dir.canonicalize()?;
        // Refuse up front what a record cannot hold back exactly (A-R3), so
        // the register/forget preflight never derives a key for a project
        // registration would reject. (The private `root_key` stays pure:
        // `root/2` records can hold such paths losslessly.)
        record_pathname(&project_dir)?;
        Ok(root_key(&project_dir))
    }

    /// Whether a project could be registered at all, without writing
    /// anything. A project blanket cannot record is a project it cannot
    /// protect from its own GC, so the work refuses up front instead of
    /// discovering it after an environment has been realized and projected.
    pub fn check_registrable(project_dir: &Path) -> io::Result<()> {
        // A `root/2` record can hold a non-UTF-8 pathname losslessly, but
        // the project-facing refusal (A-R3) is conservative on purpose: a
        // project whose path cannot be recorded exactly is refused before
        // sync or closure publication writes into it. The root/2 roundtrip
        // capability stays available for direct record registration.
        let project_dir = project_dir.canonicalize()?;
        record_pathname(&project_dir).map(|_| ())
    }

    /// Exclusive cross-process lock guarding publication and sweeping.
    /// Held only for the short rename/chmod/meta window, never during
    /// downloads or builds, so contention is negligible.
    pub(crate) fn publish_lock(&self) -> io::Result<fs::File> {
        let f = open_private_lock(&self.root.join("tmp/.publish.lock"), "publish")?;
        f.lock()?;
        Ok(f)
    }

    /// Exclusive lock shared by fetches and GC. A cache lease keeps this
    /// lock until its verified artifact has been extracted by the caller.
    pub(crate) fn gc_lock(&self) -> io::Result<fs::File> {
        let f = open_private_lock(&self.root.join("gc.lock"), "GC")?;
        f.lock()?;
        Ok(f)
    }

    /// Completeness check without sweeping (safe to call while holding the
    /// publish lock).
    fn is_complete(&self, id: &str) -> Option<bool> {
        let md = fs::symlink_metadata(self.object_path(id)).ok()?;
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(self.root.join("meta").join(format!("{id}.json")));
        Some(
            !md.file_type().is_symlink()
                && md.is_dir()
                && md.permissions().mode() & 0o222 == 0
                && meta
                    .as_ref()
                    .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file()),
        )
    }

    /// An object is valid only when fully published: directory present,
    /// root read-only, and metadata written (in that commit order). A
    /// crash mid-publication leaves an invalid object, which is swept and
    /// rebuilt instead of trusted.
    pub fn has(&self, id: &str) -> io::Result<bool> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.has_with_activity(&activity, id)
    }

    /// Activity-aware form used by long-lived operations. The compatibility
    /// `has` wrapper above is intentionally fallible too, so a lock failure
    /// cannot be mistaken for a cache miss.
    pub fn has_with_activity(&self, activity: &StoreActivity, id: &str) -> io::Result<bool> {
        self.require_activity(activity, "store object lookup")?;
        let _lock = self.publish_lock()?;
        match self.is_complete(id) {
            None => Ok(false),
            Some(true) => {
                // A cache hit is still active use. GC holds this same lock
                // while sweeping, so the touch and the sweep cannot cross.
                let _ = touch_path(&self.object_path(id));
                Ok(true)
            }
            Some(false) => {
                // Looks like a crashed publication. The parent descriptor and
                // inode check make this cleanup safe if an entry was replaced
                // between the completeness read and removal.
                let objects = open_store_directory(&self.root.join("objects"), "objects")?;
                let name = id.as_bytes();
                let expected = match stat_at(objects.as_raw_fd(), name) {
                    Ok(expected) => expected,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error),
                };
                if !remove_tree_entry_if_same(objects.as_raw_fd(), name, &expected)? {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        format!("incomplete object {id} changed during cleanup; retry later"),
                    ));
                }
                objects.sync_all()?;
                Ok(false)
            }
        }
    }

    /// Stage dir for building a new object; caller fills it, then calls commit.
    /// Collision-proof: SystemTime ticks in microseconds on macOS, so two
    /// threads can draw the same timestamp — create_dir (not _all) makes a
    /// collision an AlreadyExists we retry with a sequence number.
    pub fn stage(&self) -> io::Result<PathBuf> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.stage_with_activity(&activity)
    }

    pub fn stage_with_activity(&self, activity: &StoreActivity) -> io::Result<PathBuf> {
        self.require_activity(activity, "store staging")?;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        loop {
            let dir = self.root.join("tmp").join(format!(
                "stage-{}-{}-{}",
                std::process::id(),
                nanos(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Atomically move a staged dir into the store under `identity`, write
    /// metadata, and mark the tree read-only. Returns the object path and the
    /// exceptions stored with the object.
    /// If the object already exists the staged dir is discarded (cache hit).
    /// Publish an object with explicit dependency and cache evidence.
    ///
    /// This is the only publication entry point. There is deliberately no
    /// convenience form that infers a dependency set from the identity map:
    /// an inferred set is a guess, and `commit_internal_impl` stamps what it
    /// is given as `evidence: "explicit"`. Certifying a guess as explicit is
    /// exactly the defect the 2026-09-09 review rejected Package D for.
    pub fn commit_with_deps(
        &self,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.commit_with_activity_and_deps(&activity, identity, staged, exceptions, deps)
    }

    pub fn commit_with_activity_and_deps(
        &self,
        activity: &StoreActivity,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        self.commit_internal(activity, identity, staged, exceptions, deps)
    }

    fn commit_internal(
        &self,
        activity: &StoreActivity,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        self.commit_internal_impl(activity, identity, staged, exceptions, deps, true)
    }

    fn commit_internal_impl(
        &self,
        activity: &StoreActivity,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
        explicit: bool,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        self.require_activity(activity, "store publication")?;
        validate_object_deps(self, activity, deps)?;
        let id = identity.object_id();
        let dest = self.object_path(&id);
        if self.has_with_activity(activity, &id)? {
            return self.cache_hit(&id, &dest, staged, exceptions, deps);
        }
        // Read-only BEFORE publication (contents; APFS can't rename a
        // read-only dir, so the root is locked right after the rename —
        // the only window is top-level entry creation, never mutation).
        for entry in fs::read_dir(staged)? {
            make_read_only(&entry?.path())?;
        }
        // Publish under the cross-process lock so a concurrent has() never
        // mistakes the rename->chmod->meta window for a crashed object.
        let _lock = self.publish_lock()?;
        if self.is_complete(&id) == Some(true) {
            return self.cache_hit(&id, &dest, staged, exceptions, deps);
        }
        // Under the lock, anything at dest is a crashed leftover (a live
        // publication can't be mid-window, and a complete object returned
        // above): sweep it so the rename lands.
        let objects = open_store_directory(&self.root.join("objects"), "objects")?;
        if let Ok(expected) = stat_at(objects.as_raw_fd(), id.as_bytes()) {
            if !remove_tree_entry_if_same(objects.as_raw_fd(), id.as_bytes(), &expected)? {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    format!("object {id} changed during publication; retry later"),
                ));
            }
            objects.sync_all()?;
        }
        fs::rename(staged, &dest)
            .map_err(|e| io::Error::new(e.kind(), format!("publish {}: {e}", dest.display())))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(perms.mode() & !0o222);
            fs::set_permissions(&dest, perms)?;
        }
        let meta = if explicit {
            serde_json::json!({
                "schema": "object-meta/2",
                "id": id,
                "identity": identity,
                "created": unix_secs(),
                "exceptions": exceptions,
                "dependencies": deps.objects.iter().collect::<Vec<_>>(),
                "cache_digests": deps.cache.iter().map(|digest| {
                    serde_json::json!({"algo": digest.algo(), "hex": digest.hex()})
                }).collect::<Vec<_>>(),
                "evidence": "explicit",
            })
        } else {
            serde_json::json!({
                "id": id,
                "identity": identity,
                "created": unix_secs(),
                "exceptions": exceptions,
                "refs": object_refs(identity),
            })
        };
        // Meta is the completion marker: write via tmp + atomic rename so a
        // crash mid-write can never leave a partial file that has() would
        // accept as complete.
        let meta_tmp = self.root.join("tmp").join(format!("meta-{id}.json"));
        fs::write(&meta_tmp, serde_json::to_vec_pretty(&meta)?)?;
        fs::rename(&meta_tmp, self.root.join("meta").join(format!("{id}.json")))?;
        // The stage directory may have been built for hours. Refresh the
        // published object's activity marker while publication is still
        // protected by the lock, before GC can inspect it.
        touch_path(&dest)?;
        Ok((dest, exceptions.to_vec()))
    }

    fn cache_hit(
        &self,
        id: &str,
        dest: &Path,
        staged: &Path,
        candidate: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        validate_cached_dependency_evidence(&self.root, id, deps)?;
        let winner = self.exceptions(id)?;
        let result = crate::policy::check_exception_set(id, &winner).and_then(|_| {
            if winner != candidate {
                return Err(io::Error::other(format!(
                    "object {id} was published concurrently with different exceptions; winner: {winner:?}; staged: {candidate:?}; re-run sync"
                )));
            }
            Ok((dest.to_path_buf(), winner))
        });
        if result.is_ok() {
            let _ = touch_path(dest);
        }
        let _ = remove_tree(staged);
        result
    }

    pub fn exceptions(&self, id: &str) -> io::Result<Vec<Exception>> {
        let path = self.root.join("meta").join(format!("{id}.json"));
        let meta: serde_json::Value =
            serde_json::from_reader(fs::File::open(&path)?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse {}: {e}", path.display()),
                )
            })?;
        match meta.get("exceptions") {
            None => Ok(Vec::new()),
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse exceptions in {}: {e}", path.display()),
                )
            }),
        }
    }

    /// Replace one metadata record atomically. Callers must already own the
    /// exclusive maintenance/activity lease; keeping that requirement at the
    /// call site prevents a migration from upgrading a long-lived shared job.
    pub(crate) fn replace_metadata(&self, id: &str, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = self.root.join("tmp").join(format!(
            "meta-migrate-{id}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        let destination = self.root.join("meta").join(format!("{id}.json"));
        if let Err(error) = fs::rename(&tmp, &destination) {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        fs::File::open(self.root.join("meta"))?.sync_all()
    }

    pub fn cache_path(&self, algo: &str, hex: &str) -> PathBuf {
        self.root.join("cache").join(algo).join(hex)
    }

    pub(crate) fn projection_ref(
        &self,
        base: ProjectionBase,
        path: &Path,
    ) -> io::Result<ProjectionRef> {
        if !matches!(base, ProjectionBase::Forests | ProjectionBase::Backups) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new closure references may only name store-owned projections",
            ));
        }
        let prefix = match base {
            ProjectionBase::Forests => self.root.join("forests"),
            ProjectionBase::Backups => self.root.join("backups"),
            _ => unreachable!(),
        };
        let relative = path.strip_prefix(&prefix).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("projection {} is outside this store", path.display()),
            )
        })?;
        validate_projection_path(&prefix, path)?;
        let components = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "projection {} contains an invalid component",
                        path.display()
                    ),
                )),
            })
            .collect::<io::Result<Vec<_>>>()?;
        ProjectionRef::new(base, components)
    }

    /// Read one root record without failing. A record that cannot be
    /// trusted is reported on the entry (`unusable`), never skipped and
    /// never allowed to name a project: the record still exists, so some
    /// project may still be counting on it (A-R2). Only registry-wide I/O
    /// errors are fatal.
    fn read_root_entry_tolerant_at(&self, roots_fd: RawFd, key: &str, path: PathBuf) -> RootEntry {
        let outcome = (|| -> io::Result<RootEntry> {
            let stat = stat_at(roots_fd, key.as_bytes())?;
            if is_symlink(&stat) {
                return Err(io::Error::other(
                    "the record is a symlink, not a registry file",
                ));
            }
            if !is_regular_file(&stat) {
                return Err(io::Error::other("the record is not a regular file"));
            }
            let bytes = read_registry_file_at(roots_fd, key.as_bytes(), &path)?;
            parse_root_entry(key, &path, &bytes)
        })();
        match outcome {
            Ok(entry) => entry,
            Err(error) => RootEntry {
                key: key.into(),
                path: PathBuf::new(),
                registry_path: path,
                unusable: Some(error.to_string()),
                record: None,
            },
        }
    }

    fn read_root_entry_strict(&self, key: &str) -> io::Result<Option<RootEntry>> {
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        let path = roots.join(key);
        let metadata = match stat_at(roots_dir.as_raw_fd(), key.as_bytes()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !is_regular_file(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("root registry entry {key} is not a regular file"),
            ));
        }
        let bytes = read_registry_file_at(roots_dir.as_raw_fd(), key.as_bytes(), &path)?;
        parse_root_entry(key, &path, &bytes).map(Some)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PathWire {
    encoding: String,
    value: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionWire {
    base: String,
    components: Vec<PathWire>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RootWire {
    schema: String,
    key: String,
    project_path: PathWire,
    objects: Vec<String>,
    projections: Vec<ProjectionWire>,
    updated: u64,
}

fn path_wire(path: &Path) -> PathWire {
    let bytes = path.as_os_str().as_bytes();
    match std::str::from_utf8(bytes) {
        Ok(value) => PathWire {
            encoding: "utf8".into(),
            value: value.into(),
        },
        Err(_) => PathWire {
            encoding: "base64".into(),
            value: base64_encode(bytes),
        },
    }
}

fn path_from_wire(wire: &PathWire, label: &str) -> io::Result<PathBuf> {
    let bytes = match wire.encoding.as_str() {
        "utf8" => wire.value.as_bytes().to_vec(),
        "base64" => base64_decode(&wire.value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} contains invalid base64 path bytes"),
            )
        })?,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} has unknown path encoding {other}"),
            ))
        }
    };
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} contains a NUL byte"),
        ));
    }
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

fn projection_wire(reference: &ProjectionRef) -> ProjectionWire {
    ProjectionWire {
        base: reference.base.wire_name().into(),
        components: reference
            .components
            .iter()
            .map(|component| path_wire(Path::new(component)))
            .collect(),
    }
}

fn projection_from_wire(wire: ProjectionWire, label: &str) -> io::Result<ProjectionRef> {
    let base = match wire.base.as_str() {
        "forests" => ProjectionBase::Forests,
        "backups" => ProjectionBase::Backups,
        "legacy-forests" => ProjectionBase::LegacyForests,
        "legacy-backups" => ProjectionBase::LegacyBackups,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} has unknown projection base {other}"),
            ))
        }
    };
    let mut components = Vec::with_capacity(wire.components.len());
    for (index, component) in wire.components.iter().enumerate() {
        let path = path_from_wire(component, &format!("{label} component {index}"))?;
        let mut iter = path.components();
        let Some(std::path::Component::Normal(name)) = iter.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} component {index} is empty or not a name"),
            ));
        };
        if iter.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} component {index} contains a slash"),
            ));
        }
        components.push(name.to_os_string());
    }
    ProjectionRef::new(base, components)
}

fn root_wire(record: &RootRecord) -> RootWire {
    RootWire {
        schema: "root/2".into(),
        key: record.key.clone(),
        project_path: path_wire(&record.project_path),
        objects: record.objects.iter().cloned().collect(),
        projections: record.projections.iter().map(projection_wire).collect(),
        updated: record.updated,
    }
}

fn root_record_from_wire(wire: RootWire, filename: &str) -> io::Result<RootRecord> {
    if wire.schema != "root/2" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "root registry entry {filename} has unknown schema {}",
                wire.schema
            ),
        ));
    }
    if wire.key != filename || !is_sha1(&wire.key) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("root/2 key does not match registry filename {filename}"),
        ));
    }
    let project_path = path_from_wire(&wire.project_path, "root/2 project_path")?;
    if !project_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("root/2 {filename} project_path is not absolute"),
        ));
    }
    let mut objects = BTreeSet::new();
    for object in wire.objects {
        if !is_object_id(&object) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("root/2 {filename} contains malformed object id {object:?}"),
            ));
        }
        if !objects.insert(object.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("root/2 {filename} contains duplicate object id {object:?}"),
            ));
        }
    }
    let mut projections = BTreeSet::new();
    for (index, projection) in wire.projections.into_iter().enumerate() {
        let projection =
            projection_from_wire(projection, &format!("root/2 {filename} projection {index}"))?;
        if !projections.insert(projection) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("root/2 {filename} contains duplicate projection"),
            ));
        }
    }
    let record = RootRecord {
        key: wire.key,
        project_path,
        objects,
        projections,
        updated: wire.updated,
    };
    validate_root_record(&record)?;
    Ok(record)
}

fn parse_root_entry(key: &str, path: &Path, bytes: &[u8]) -> io::Result<RootEntry> {
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(bytes).trim_ascii();
    if trimmed.first() == Some(&b'{') {
        let json: serde_json::Value = serde_json::from_slice(trimmed).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "parse root registry entry {key}: {error}; use `blanket gc --forget {key}` to drop the record, then re-run sync in that project"
                ),
            )
        })?;
        let schema = json
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("root registry entry {key} has no schema"),
                )
            })?;
        if schema != "root/2" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "root registry entry {key} has unknown schema {schema}; this store was written by a newer Blanket, or the record is damaged — upgrade Blanket, or use `blanket gc --forget {key}`"
                ),
            ));
        }
        let wire: RootWire = serde_json::from_value(json).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "parse root registry entry {key}: {error}; use `blanket gc --forget {key}` to drop the record, then re-run sync in that project"
                ),
            )
        })?;
        let record = root_record_from_wire(wire, key)?;
        return Ok(RootEntry {
            key: key.into(),
            path: record.project_path.clone(),
            registry_path: path.to_path_buf(),
            unusable: None,
            record: Some(record),
        });
    }
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("root registry entry {key} is empty"),
        ));
    }
    // A legacy record is one pathname read back exactly as registered: a
    // padded or multi-line spelling names a different project than the one
    // that was registered (A-R3), so it is refused rather than trimmed into
    // shape — a trimmed record is protection that silently moves.
    let raw = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if raw != trimmed || raw.contains(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy root registry entry {key} is padded or spans lines, so it cannot be \
                 read back exactly; use `blanket gc --forget {key}` to drop the record"
            ),
        ));
    }
    let project_path = PathBuf::from(OsString::from_vec(trimmed.to_vec()));
    if !project_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy root registry entry {key} is not an absolute path"),
        ));
    }
    Ok(RootEntry {
        key: key.into(),
        path: project_path,
        registry_path: path.to_path_buf(),
        unusable: None,
        record: None,
    })
}

fn read_registry_file_at(dirfd: RawFd, name: &[u8], path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = open_file_at(
        dirfd,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read root record {}: {error}", path.display()),
        )
    })?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("root record {} is not a regular file", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    (&file).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_root_record(roots: &Path, record: &RootRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(&root_wire(record))?;
    write_registry_entry(roots, &record.key, &bytes)
}

/// Does this registry entry name look like one of our own interrupted
/// temporary writes (`.<key>.tmp.<pid>.<seq>`)?  Nothing else in the
/// registry is dot-prefixed.
fn is_own_registry_temp(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some((key, suffix)) = rest.split_once(".tmp.") else {
        return false;
    };
    if !is_sha1(key) {
        return false;
    }
    match suffix.split_once('.') {
        Some((pid, seq)) => {
            !pid.is_empty()
                && !seq.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && seq.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Atomically publish one registry entry while holding the registry
/// directory descriptor.  The descriptor-relative operations make a rename
/// of the `roots` path, or a symlink planted at that path, unable to redirect
/// the write after the namespace has been opened and checked.
fn write_registry_entry(roots: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let roots_dir = open_store_directory(roots, "roots")?;
    let name_bytes = name.as_bytes();
    let tmp_name = loop {
        let candidate = format!(
            ".{name}.tmp.{}.{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        match open_file_at(
            roots_dir.as_raw_fd(),
            candidate.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        ) {
            Ok(mut file) => {
                let result = (|| {
                    file.write_all(bytes)?;
                    file.sync_all()
                })();
                drop(file);
                if let Err(error) = result {
                    unlink_at(roots_dir.as_raw_fd(), candidate.as_bytes());
                    return Err(error);
                }
                break candidate;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };

    let result = (|| {
        rename_at(roots_dir.as_raw_fd(), tmp_name.as_bytes(), name_bytes)?;
        roots_dir.sync_all()?;

        // The marker is a regular file in the same descriptor-owned
        // namespace. O_NOFOLLOW prevents an existing symlink from turning
        // this compatibility marker into an arbitrary-file write.
        let mut marker = open_file_at(
            roots_dir.as_raw_fd(),
            ROOTS_INITIALIZED.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        if !marker.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "root registry initialization marker is not a regular file",
            ));
        }
        // SAFETY: marker is the descriptor just inspected and is owned here.
        if unsafe { libc::fchmod(marker.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        marker.write_all(b"1\n")?;
        marker.sync_all()?;
        roots_dir.sync_all()
    })();
    if result.is_err() {
        unlink_at(roots_dir.as_raw_fd(), tmp_name.as_bytes());
    }
    result
}

fn validate_root_record(record: &RootRecord) -> io::Result<()> {
    if !is_sha1(&record.key) || root_key(&record.project_path) != record.key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "root/2 key {} does not match its canonical project path",
                record.key
            ),
        ));
    }
    for object in &record.objects {
        if !is_object_id(object) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("root/2 contains malformed object id {object:?}"),
            ));
        }
    }
    for projection in &record.projections {
        validate_projection_components(&projection.components)?;
    }
    Ok(())
}

fn validate_projection_components(components: &[OsString]) -> io::Result<()> {
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "projection reference must contain at least one component",
        ));
    }
    for component in components {
        let bytes = component.as_os_str().as_bytes();
        if bytes.is_empty()
            || bytes.contains(&0)
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection reference contains an invalid component",
            ));
        }
    }
    Ok(())
}

/// Check existing projection path components without following symlinks. A
/// reserved destination may not exist yet, so the walk stops at the first
/// missing component and lets the producer create it later. Existing parent
/// components must be real directories inside the selected store namespace.
fn validate_projection_path(prefix: &Path, path: &Path) -> io::Result<()> {
    let relative = path.strip_prefix(prefix).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "projection {} is outside its store namespace",
                path.display()
            ),
        )
    })?;
    let mut current = prefix.to_path_buf();
    let prefix_metadata = fs::symlink_metadata(prefix)?;
    if prefix_metadata.file_type().is_symlink() || !prefix_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "projection namespace {} is not a real directory",
                prefix.display()
            ),
        ));
    }
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "projection {} contains an invalid component",
                    path.display()
                ),
            ));
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "projection {} contains a symlinked component {}",
                    path.display(),
                    current.display()
                ),
            ));
        }
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "projection {} contains a non-directory component {}",
                    path.display(),
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

fn invalid_root_import(path: &Path, detail: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cannot import closure {}: {detail}", path.display()),
    )
}

fn validate_closure_envelope<'a>(
    value: &'a serde_json::Value,
    path: &Path,
) -> io::Result<&'a serde_json::Value> {
    if value.get("schema").and_then(serde_json::Value::as_str) != Some("closure/1") {
        return Err(invalid_root_import(path, "unknown closure schema".into()));
    }
    let ecosystem = value
        .get("ecosystem")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_root_import(path, "missing closure ecosystem".into()))?;
    if !matches!(
        ecosystem,
        "python" | "node" | "cargo" | "go" | "ruby" | "elixir" | "dotnet" | "rustfmt"
    ) {
        return Err(invalid_root_import(
            path,
            format!("unknown closure ecosystem {ecosystem}"),
        ));
    }
    value
        .get("body")
        .ok_or_else(|| invalid_root_import(path, "missing closure body".into()))
}

/// How strictly a legacy closure import treats a reference it cannot
/// resolve inside this store.
///
/// An explicit `gc --register` is a request to import a specific project, so
/// an unresolvable reference is an error the user asked to hear about. An
/// import that happens automatically underneath an ordinary `sync` is not:
/// refusing there would permanently wedge the project, because the record
/// that would have to be forgotten is exactly the one that was never
/// written. A reference this store cannot resolve also protects nothing in
/// this store, so dropping it with a warning loses no retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportMode {
    Strict,
    DropUnresolvable,
}

fn import_existing_project_closures(
    store: &Store,
    project: &Path,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    let closures = project.join(".blanket/closures");
    let mut files: Vec<PathBuf> = fs::read_dir(&closures)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    files.sort();
    for path in files {
        if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let value: serde_json::Value = serde_json::from_reader(fs::File::open(&path)?)
            .map_err(|error| invalid_root_import(&path, error.to_string()))?;
        let body = validate_closure_envelope(&value, &path)?;
        import_closure_refs(store, project, body, record, mode)?;
    }
    Ok(())
}

fn import_closure_refs(
    store: &Store,
    project: &Path,
    body: &serde_json::Value,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    fn walk(
        store: &Store,
        value: &serde_json::Value,
        record: &mut RootRecord,
        mode: ImportMode,
    ) -> io::Result<()> {
        match value {
            serde_json::Value::String(text) => {
                import_absolute_reference(store, Path::new(text), record, mode)
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(store, value, record, mode)?;
                }
                Ok(())
            }
            serde_json::Value::Object(values) => {
                if let (Some(id), Some(path)) = (
                    values.get("id").and_then(serde_json::Value::as_str),
                    values.get("path").and_then(serde_json::Value::as_str),
                ) {
                    let path = Path::new(path);
                    if is_object_id(id) {
                        if unresolvable(validate_object_reference(store, id, path), mode)? {
                            record.objects.insert(id.into());
                        }
                    } else if path_under_objects(store, path) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("closure contains malformed object id {id:?}"),
                        ));
                    }
                }
                for value in values.values() {
                    walk(store, value, record, mode)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    walk(store, body, record, mode)?;
    if matches!(
        body["projection_schema"].as_str(),
        Some("node-forest/1" | "node-forest/2")
    ) {
        if let Some(projection_id) = body["projection_id"].as_str() {
            let key = short_project_key(project);
            let reference = ProjectionRef::new(
                ProjectionBase::LegacyForests,
                vec![OsString::from(key), OsString::from(projection_id)],
            )?;
            record.projections.insert(reference);
        }
    }
    Ok(())
}

/// Apply an import mode to one reference's validation result.  Returns
/// whether the reference may be recorded.
fn unresolvable(result: io::Result<()>, mode: ImportMode) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) => match mode {
            ImportMode::Strict => Err(error),
            ImportMode::DropUnresolvable => {
                eprintln!(
                    "blanket: dropping a historical closure reference this store cannot resolve: {error}"
                );
                Ok(false)
            }
        },
    }
}

fn import_absolute_reference(
    store: &Store,
    path: &Path,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    if !path.is_absolute() {
        return Ok(());
    }
    let components: Vec<_> = path.components().collect();
    for window in components.windows(2) {
        let (std::path::Component::Normal(objects), std::path::Component::Normal(id)) =
            (window[0], window[1])
        else {
            continue;
        };
        if objects == "objects" {
            let Some(id) = id.to_str() else {
                continue;
            };
            if is_object_id(id) && path != store.object_path(id) {
                let foreign = Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("closure object reference {path:?} belongs to another store"),
                ));
                unresolvable(foreign, mode)?;
                return Ok(());
            }
        }
    }
    if path_under_objects(store, path) {
        let relative = path.strip_prefix(store.root.join("objects")).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "object path is outside the store",
            )
        })?;
        let mut components = relative.components();
        let Some(std::path::Component::Normal(name)) = components.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object path has no object id",
            ));
        };
        if components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object reference must name an object root",
            ));
        }
        let id = name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "object id is not UTF-8"))?;
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("closure contains malformed object id {id:?}"),
            ));
        }
        if unresolvable(validate_object_reference(store, id, path), mode)? {
            record.objects.insert(id.into());
        }
        return Ok(());
    }
    if let Some(reference) = projection_reference_for_path(store, path)? {
        record.projections.insert(reference);
    }
    Ok(())
}

fn validate_object_reference(store: &Store, id: &str, path: &Path) -> io::Result<()> {
    if !is_object_id(id) || path != store.object_path(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure object reference {path:?} does not belong to object {id}"),
        ));
    }
    let object = fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("closure object reference {id} is unavailable: {error}"),
        )
    })?;
    if object.file_type().is_symlink() || !object.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure object reference {id} is not a real directory"),
        ));
    }
    let metadata = store.root.join("meta").join(format!("{id}.json"));
    let metadata_stat = fs::symlink_metadata(&metadata).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("closure object reference {id} has no metadata: {error}"),
        )
    })?;
    if metadata_stat.file_type().is_symlink() || !metadata_stat.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure object reference {id} metadata is not a regular file"),
        ));
    }
    Ok(())
}

fn path_under_objects(store: &Store, path: &Path) -> bool {
    path.starts_with(store.root.join("objects"))
}

fn projection_reference_for_path(store: &Store, path: &Path) -> io::Result<Option<ProjectionRef>> {
    let bases = [
        (ProjectionBase::Forests, store.root.join("forests")),
        (ProjectionBase::Backups, store.root.join("backups")),
        (
            ProjectionBase::LegacyForests,
            store.root.parent().unwrap_or(&store.root).join("forests"),
        ),
        (
            ProjectionBase::LegacyBackups,
            store.root.parent().unwrap_or(&store.root).join("backups"),
        ),
    ];
    for (base, prefix) in bases {
        let Ok(relative) = path.strip_prefix(&prefix) else {
            continue;
        };
        let components: Vec<OsString> = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("projection path {path:?} contains an invalid component"),
                )),
            })
            .collect::<io::Result<Vec<_>>>()?;
        return ProjectionRef::new(base, components).map(Some);
    }
    Ok(None)
}

fn short_project_key(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(project.as_os_str().as_bytes())[..16])
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let decode = |byte: u8| -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = decode(chunk[0])?;
        let b = decode(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            decode(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            decode(chunk[3])?
        };
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return None;
        }
        let joined = (a << 18) | (b << 12) | (c << 6) | d;
        output.push((joined >> 16) as u8);
        if chunk[2] != b'=' {
            output.push((joined >> 8) as u8);
        }
        if chunk[3] != b'=' {
            output.push(joined as u8);
        }
    }
    Some(output)
}

fn errno_location() -> *mut libc::c_int {
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

fn fd_set_cloexec(fd: RawFd) -> io::Result<()> {
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

fn fd_stat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: stat is initialized by fstat before it is read.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is borrowed for the duration of this call.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn is_regular_file(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
}

/// Create and validate a store-owned directory path one component at a
/// time. `create_dir_all` follows an existing symlink, which is not suitable
/// for a store namespace whose contents may later be deleted by GC.
fn ensure_directory_tree(root: &Path, relative: &Path) -> io::Result<()> {
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

fn open_file_at(
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

fn rename_at(dirfd: RawFd, old_name: &[u8], new_name: &[u8]) -> io::Result<()> {
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

fn unlink_at(dirfd: RawFd, name: &[u8]) {
    let Ok(name) = CString::new(name) else {
        return;
    };
    // SAFETY: dirfd is borrowed and name is a valid relative entry name.
    unsafe {
        let _ = libc::unlinkat(dirfd, name.as_ptr(), 0);
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

fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn is_directory(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

fn is_symlink(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

fn entry_names_at(dirfd: RawFd) -> io::Result<Vec<OsString>> {
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
    if is_symlink(&expected) || !is_directory(&expected) {
        return unlink_if_same(parentfd, name, &expected, 0);
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
    let child = unsafe { fs::File::from_raw_fd(childfd) };
    let actual = fd_stat(child.as_raw_fd())?;
    if !same_inode(&actual, &expected) {
        return Ok(false);
    }
    let mut mode = actual.st_mode;
    mode |= 0o200;
    // SAFETY: child is owned by this function.
    let _ = unsafe { libc::fchmod(child.as_raw_fd(), mode) };
    remove_tree_at(child.as_raw_fd())?;
    unlink_if_same(parentfd, name, &expected, libc::AT_REMOVEDIR)
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

/// Remove a possibly read-only staged tree (restore write bits first).
pub fn remove_tree(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) -> io::Result<()> {
        let md = fs::symlink_metadata(p)?;
        if md.file_type().is_symlink() {
            return Ok(());
        }
        let mut perms = md.permissions();
        perms.set_mode(perms.mode() | 0o200);
        let _ = fs::set_permissions(p, perms);
        if md.is_dir() {
            for entry in fs::read_dir(p)? {
                unlock(&entry?.path())?;
            }
        }
        Ok(())
    }
    let _ = unlock(path);
    fs::remove_dir_all(path)
}

/// Recursively remove write permission (files and dirs). Symlinks untouched.
fn make_read_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            make_read_only(&entry?.path())?;
        }
    }
    let mut perms = md.permissions();
    perms.set_mode(perms.mode() & !0o222);
    fs::set_permissions(path, perms)
        .map_err(|e| io::Error::new(e.kind(), format!("chmod {}: {e}", path.display())))
}

/// The object/cache mtime is the cheap activity marker used by GC. Opening
/// the path and setting its timestamp avoids a platform-specific touch
/// executable and also works for read-only published directories/files.
pub(crate) fn touch_path(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.set_modified(SystemTime::now())
}

pub(crate) fn object_id_token(value: &str) -> Option<String> {
    value
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'))
        .find(|token| is_object_id(token))
        .map(str::to_string)
}

/// Extract a complete object id from a store object path without accepting a
/// path-shaped string or a nested child as evidence. The caller still gets
/// the final existence/metadata check from `validate_object_deps` when the
/// id is published as a dependency.
pub(crate) fn object_id_from_path(path: &Path) -> io::Result<String> {
    let objects = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object path has no objects parent: {}", path.display()),
        )
    })?;
    if objects.file_name().and_then(|name| name.to_str()) != Some("objects") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "object path is not directly below an objects directory: {}",
                path.display()
            ),
        ));
    }
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("object path id is not UTF-8: {}", path.display()),
            )
        })?;
    if !is_object_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object path has an invalid object id {id:?}"),
        ));
    }
    Ok(id.to_string())
}

pub(crate) fn is_object_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 41
        && bytes[..40].iter().all(u8::is_ascii_hexdigit)
        && bytes[40] == b'-'
        && !value.contains("..")
        && bytes[41..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'_' || *b == b'-')
}

fn is_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn root_key(project_dir: &Path) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(project_dir.as_os_str().as_bytes()))
}

/// Open an advisory lock without ever following a replacement or symlink at
/// the lock pathname.  The descriptor is also the authority used for the
/// permission change, so a concurrent rename cannot redirect chmod(2).
fn open_private_lock(path: &Path, label: &str) -> io::Result<fs::File> {
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

fn open_store_directory(path: &Path, label: &str) -> io::Result<fs::File> {
    let metadata = fs::symlink_metadata(path)?;
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

/// The exact text a record holds for this project, or a refusal when the
/// pathname cannot be stored unambiguously.
///
/// A record is one line of text and the key hashes that same text, so a
/// pathname that does not survive the round trip is not merely cosmetic: a
/// trailing space or a byte that is not UTF-8 registers one project under
/// another project's identity, and GC then keeps the wrong project's objects
/// and sweeps the live ones. Refuse the registration instead of recording a
/// pathname that names a different directory when it is read back (A-R3).
fn record_pathname(project_dir: &Path) -> io::Result<&str> {
    let text = project_dir.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to register {}: the path is not valid UTF-8, so a registry record \
                 cannot name it exactly. A project blanket cannot record is a project it \
                 cannot protect from `blanket gc`",
                project_dir.display()
            ),
        )
    })?;
    if text.trim() != text || text.contains('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to register '{text}': the path is padded with whitespace or spans \
                 lines, so a registry record cannot name it exactly. A project blanket \
                 cannot record is a project it cannot protect from `blanket gc`"
            ),
        ));
    }
    Ok(text)
}

fn object_refs(identity: &Identity) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for value in identity.inputs.values() {
        if let Some(id) = object_id_token(value) {
            refs.insert(id);
        }
    }
    refs.into_iter().collect()
}

fn validate_object_deps(
    store: &Store,
    activity: &StoreActivity,
    deps: &ObjectDeps,
) -> io::Result<()> {
    for id in &deps.objects {
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed dependency object id {id:?}"),
            ));
        }
        store.validate_object_complete(activity, id)?;
    }
    for digest in &deps.cache {
        let path = store.cache_path(digest.algo(), digest.hex());
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cache dependency {}:{} is unavailable: {error}",
                    digest.algo(),
                    digest.hex()
                ),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cache dependency {}:{} is not a regular file",
                    digest.algo(),
                    digest.hex()
                ),
            ));
        }
    }
    Ok(())
}

/// Compare newly supplied evidence with an already-published object's
/// explicit metadata. A legacy record is deliberately left alone: a cache hit
/// cannot upgrade or certify it, and the maintenance adapter owns that
/// transition. An explicit record with different evidence is unsafe to reuse
/// because the winner's transitive closure would no longer be the candidate's
/// closure.
fn validate_cached_dependency_evidence(
    root: &Path,
    id: &str,
    candidate: &ObjectDeps,
) -> io::Result<()> {
    let path = root.join("meta").join(format!("{id}.json"));
    let bytes = fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse object metadata {}: {error}", path.display()),
        )
    })?;
    if let Some(schema_value) = value.get("schema") {
        let schema = schema_value.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has an invalid schema"),
            )
        })?;
        if schema != "object-meta/2" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} has unknown metadata schema {schema}"),
            ));
        }
    } else {
        return Ok(());
    }
    let mut objects = BTreeSet::new();
    for value in value
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has no explicit dependencies"),
            )
        })?
    {
        let value = value.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has a non-string dependency"),
            )
        })?;
        if !is_object_id(value) || !objects.insert(value.to_string()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has malformed or duplicate dependency"),
            ));
        }
    }
    let mut cache = BTreeSet::new();
    for value in value
        .get("cache_digests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has no explicit cache digests"),
            )
        })?
    {
        let object = value.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has a malformed cache digest"),
            )
        })?;
        let algo = object
            .get("algo")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object metadata {id} cache digest has no algorithm"),
                )
            })?;
        let hex = object
            .get("hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object metadata {id} cache digest has no hex"),
                )
            })?;
        let digest = match algo {
            "sha1" => crate::fetch::Digest::sha1(hex),
            "sha256" => crate::fetch::Digest::sha256(hex),
            "sha512" => crate::fetch::Digest::sha512(hex),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} uses unsupported cache algorithm {other}"),
            )),
        }?;
        if !cache.insert(format!("{}:{}", digest.algo(), digest.hex())) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has duplicate cache digest"),
            ));
        }
    }
    let candidate_cache: BTreeSet<_> = candidate
        .cache
        .iter()
        .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
        .collect();
    let winner_cache = cache;
    if objects != candidate.objects || winner_cache != candidate_cache {
        return Err(io::Error::other(format!(
            "object {id} was published concurrently with different dependency evidence; winner objects: {objects:?}, staged objects: {:?}, winner cache: {winner_cache:?}, staged cache: {candidate_cache:?}; re-run sync",
            candidate.objects
        )));
    }
    Ok(())
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME set"))
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::process::Command;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-store-test-{}-{}",
                std::process::id(),
                nanos()
            ));
            for sub in ["objects", "meta", "cache/sha256", "tmp"] {
                fs::create_dir_all(path.join(sub)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = remove_tree(&self.0);
        }
    }

    fn identity() -> Identity {
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

    #[test]
    fn roots_registry_adds_atomically_and_drops_entries() {
        let temp = TempDir::new();
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
        store.remove_root_entry(&root).unwrap();
        assert!(store.roots().unwrap().is_empty());
    }

    /// A project whose pathname a record cannot hold exactly is refused
    /// before anything is written: recording a lossy spelling files one
    /// project under another project's identity.
    #[test]
    fn registration_refuses_a_pathname_no_record_can_hold() {
        let temp = TempDir::new();
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
        let temp = TempDir::new();
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
        let temp = TempDir::new();
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

    /// A record that is not a regular file is refused on its metadata,
    /// before anything opens it. Removing that check does not make this test
    /// fail — it makes it hang: reading a FIFO nobody writes to blocks the
    /// listing, the sweep and `--forget` alike, which is the one registry
    /// failure there is no way to recover from.
    #[test]
    fn a_record_that_is_not_a_regular_file_is_never_opened() {
        let temp = TempDir::new();
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

        let records = store.roots().unwrap();
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

        let temp = TempDir::new();
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
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let exception = Exception {
            kind: crate::policy::FILE_COLLISION.into(),
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

    #[test]
    fn strict_policy_rejects_cached_exceptions() {
        if std::env::var_os("BLANKET_STORE_STRICT_CHILD").is_some() {
            let store = Store::open().unwrap();
            crate::policy::init(&store.root, false).unwrap();
            let error = store
                .commit_with_deps(&identity(), &staged(&store), &[], &ObjectDeps::new())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let exception = Exception {
            kind: crate::policy::FILE_COLLISION.into(),
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
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::tests::strict_policy_rejects_cached_exceptions",
                "--nocapture",
            ])
            .env("BLANKET_STORE", &store.root)
            .env("BLANKET_STORE_STRICT_CHILD", "1")
            .env("BLANKET_STRICT", "1")
            .env_remove("BLANKET_POLICY")
            .env("HOME", &temp.0)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "strict child failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
    }

    /// A lease is bound to the store that issued it. Presenting one store's
    /// token to another store's primitive must fail, and a shared token must
    /// not satisfy a check that requires exclusive protection.
    #[test]
    fn a_lease_only_authorizes_the_store_and_mode_it_was_taken_for() {
        let first = TempDir::new();
        let second = TempDir::new();
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
        let first = TempDir::new();
        let second = TempDir::new();
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
        let temp = TempDir::new();
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

    #[test]
    fn root2_rejects_unknown_schema_before_gc() {
        let temp = TempDir::new();
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
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

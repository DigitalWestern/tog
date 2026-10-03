//! The root registry (kernel store): `RootEntry` and `RootRecord`, their
//! on-disk wire form, registration, lookup, forgetting, and the crash-safe
//! registry file operations.

use super::*;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::ui;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDiagnostic {
    pub key: String,
    pub path: Option<PathBuf>,
    pub problem: Option<String>,
}

pub(super) const ROOTS_INITIALIZED: &str = ".initialized";

impl Store {
    /// Serialize registry/closure publication for one canonical project.
    /// Callers acquire the store activity lease first, then this transaction
    /// lock, then publish/cache locks.
    pub(crate) fn project_lock(&self, project_dir: &Path) -> io::Result<fs::File> {
        self.project_lock_canonical(&project_dir.canonicalize()?)
    }

    /// `project_lock` for a project held open as a `ProjectRoot`: keyed on
    /// the canonical path the root was opened at, never resolved again, so
    /// every step of one sync takes the same lock and records the same key
    /// even if the pathname has changed meanwhile.
    pub(crate) fn project_lock_in(&self, project: &ProjectRoot) -> io::Result<fs::File> {
        self.project_lock_canonical(project.path())
    }

    fn project_lock_canonical(&self, project_dir: &Path) -> io::Result<fs::File> {
        let locks = self.root.join("root-locks");
        ensure_directory_tree(&self.root, Path::new("root-locks"))?;
        let key = root_key(project_dir);
        let path = locks.join(format!("{key}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        // The descriptor is the object whose permissions were inspected;
        // applying chmod by pathname could target a replacement lock name.
        // SAFETY: `file` is the descriptor just opened and is owned here.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.lock()?;
        Ok(file)
    }

    /// Register a project whose closure was just written. Registry entries
    /// are keyed by the canonical project path, so moving a project creates a
    /// new root instead of accidentally retaining the old location.
    // Reviewed site (tests/architecture.rs): operation boundary: lease-free public API; production uses the `_with_activity` form.
    #[allow(clippy::disallowed_methods)]
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
        // The record must hold the project's pathname exactly: a trailing
        // space or a non-UTF-8 byte would register one project under
        // another project's identity. Refuse instead of recording a lossy
        // spelling.
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
    // Reviewed site (tests/architecture.rs): operation boundary: lease-free public API; production uses the `_with_activity` form.
    #[allow(clippy::disallowed_methods)]
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

    pub(super) fn register_root_record_locked(&self, record: RootRecord) -> io::Result<RootEntry> {
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

    /// Publish a producer's root parts for the project it holds open. The
    /// record is keyed on the canonical path the root was opened at, taken
    /// as it is rather than resolved again, and the project's existing
    /// closures are imported through the held descriptor.
    pub(crate) fn register_root_parts_with_project_lock(
        &self,
        activity: &StoreActivity,
        project: &ProjectRoot,
        objects: BTreeSet<String>,
        projections: BTreeSet<ProjectionRef>,
        _project_lock: &fs::File,
    ) -> io::Result<RootEntry> {
        self.require_activity(activity, "root publication")?;
        self.register_root_parts_locked(project, objects, projections)
    }

    pub(super) fn register_root_parts_locked(
        &self,
        project: &ProjectRoot,
        objects: BTreeSet<String>,
        projections: BTreeSet<ProjectionRef>,
    ) -> io::Result<RootEntry> {
        let project_dir = project.path();
        let key = root_key(project_dir);
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
        {
            import_existing_project_closures(
                self,
                project,
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
    // Reviewed site (tests/architecture.rs): operation boundary: lease-free public API; production uses the `_with_activity` form.
    #[allow(clippy::disallowed_methods)]
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
        let closures = project_dir.join(".tog/closures");
        if !closures.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has no .tog/closures directory", project_dir.display()),
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
            if !path.is_file() || !is_closure_file(&path) {
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
        project: &ProjectRoot,
        ecosystem: &str,
        body: &serde_json::Value,
    ) -> io::Result<RootEntry> {
        let project_dir = project.path().to_path_buf();
        let _project = self.project_lock_in(project)?;
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
                project,
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
    /// exist. `tog store roots` is an inspection command; GC validates
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
            if !is_sha1(key) {
                continue;
            }
            let path = roots.join(key);
            entries.push(self.read_root_entry_tolerant_at(roots_dir.as_raw_fd(), key, path));
        }
        entries.sort_by(|a, b| (&a.path, &a.key).cmp(&(&b.path, &b.key)));
        Ok(entries)
    }

    /// Diagnostic enumeration for `store roots`.  Unlike `roots()`, an entry
    /// whose name is not a root key is reported as a diagnostic instead of
    /// being skipped; this command is intentionally not a sweep authority.
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
            if !is_sha1(key) {
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
            // (gc::unusable_root) names the key and `--forget` uniformly.
            // The sweep still fails closed: collect_roots refuses on the
            // first unusable entry before anything is deleted.
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

    /// Whether this store's root registry has ever been written. A store
    /// created before the registry feature may have objects but no roots
    /// directory, so `Store::open` creating that directory is not sufficient.
    /// Any entry already in `roots/` counts as initialized, so stores written
    /// by the first registry implementation — before the marker existed — are
    /// accepted too.
    pub(crate) fn registry_initialized(&self) -> io::Result<bool> {
        let roots = self.root.join("roots");
        ensure_directory_tree(&self.root, Path::new("roots"))?;
        let roots_dir = open_store_directory(&roots, "roots")?;
        for name in read_dir_names_at(roots_dir.as_raw_fd())? {
            if name.as_os_str().as_bytes() == ROOTS_INITIALIZED.as_bytes() {
                // A malformed marker is still an initialized-but-corrupt
                // registry; roots_for_sweep will report the exact defect.
                return Ok(true);
            }
            let stat = stat_at(roots_dir.as_raw_fd(), name.as_os_str().as_bytes())?;
            if !is_regular_file(&stat) || !is_sha1(&name.to_string_lossy()) {
                // Not a record: a directory, a symlink, an interrupted
                // write's temporary, or anything else dropped into the
                // directory. A `roots/` holding only these has never had a
                // record written to it, and a sweep that trusted it would
                // delete objects no registry protects yet.
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }

    // Reviewed site (tests/architecture.rs): operation boundary: lease-free public API; production uses the `_with_activity` form.
    #[allow(clippy::disallowed_methods)]
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
            // worst case. The (dev, ino) recheck above is the guard: what is
            // removed is the entry the caller decoded.
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
    /// including on the corrupt record itself. The key is matched by exact
    /// directory-entry name, so a case-insensitive filesystem cannot answer
    /// with a neighbouring spelling's record.
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
                        "unknown root key {key}; `tog store roots` lists the keys this \
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
            // forgettable too: report it instead of failing, and let the
            // removal clear it.
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
            // by its own key.
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
    // Reviewed site (tests/architecture.rs): operation boundary: lease-free public API; production uses the `_with_activity` form.
    #[allow(clippy::disallowed_methods)]
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

    pub(super) fn validate_root_key(key: &str) -> io::Result<()> {
        if is_sha1(key) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid root key '{key}': expected 40 hex characters (`tog store \
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
        // Refuse up front what a record cannot hold back exactly, so the
        // register/forget preflight never derives a key for a project
        // registration would reject. (The private `root_key` stays pure:
        // `root/2` records can hold such paths losslessly.)
        record_pathname(&project_dir)?;
        Ok(root_key(&project_dir))
    }

    /// Whether a project could be registered at all, without writing
    /// anything. A project tog cannot record is a project it cannot
    /// protect from its own GC, so the work refuses up front instead of
    /// discovering it after an environment has been realized and projected.
    pub fn check_registrable(project_dir: &Path) -> io::Result<()> {
        // A `root/2` record can hold a non-UTF-8 pathname losslessly, but
        // the project-facing refusal is conservative on purpose: a project
        // whose path cannot be recorded exactly is refused before sync or
        // closure publication writes into it. The root/2 roundtrip
        // capability stays available for direct record registration.
        let project_dir = project_dir.canonicalize()?;
        record_pathname(&project_dir).map(|_| ())
    }

    /// `check_registrable` for a project held open: the canonical path the
    /// root was opened at is the one a record would hold, so it is checked
    /// as it is, not resolved again.
    pub fn check_registrable_in(project: &ProjectRoot) -> io::Result<()> {
        record_pathname(project.path()).map(|_| ())
    }

    /// Read one root record without failing. A record that cannot be
    /// trusted is reported on the entry (`unusable`), never skipped and
    /// never allowed to name a project: the record still exists, so some
    /// project may still be counting on it. Only registry-wide I/O errors
    /// are fatal.
    pub(super) fn read_root_entry_tolerant_at(
        &self,
        roots_fd: RawFd,
        key: &str,
        path: PathBuf,
    ) -> RootEntry {
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

    pub(super) fn read_root_entry_strict(&self, key: &str) -> io::Result<Option<RootEntry>> {
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
pub(super) struct PathWire {
    encoding: String,
    value: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootWire {
    schema: String,
    key: String,
    project_path: PathWire,
    objects: Vec<String>,
    projections: Vec<ProjectionWire>,
    updated: u64,
}

pub(super) fn path_wire(path: &Path) -> PathWire {
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

pub(super) fn path_from_wire(wire: &PathWire, label: &str) -> io::Result<PathBuf> {
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

pub(super) fn root_wire(record: &RootRecord) -> RootWire {
    RootWire {
        schema: "root/2".into(),
        key: record.key.clone(),
        project_path: path_wire(&record.project_path),
        objects: record.objects.iter().cloned().collect(),
        projections: record.projections.iter().map(projection_wire).collect(),
        updated: record.updated,
    }
}

pub(super) fn root_record_from_wire(wire: RootWire, filename: &str) -> io::Result<RootRecord> {
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

pub(super) fn parse_root_entry(key: &str, path: &Path, bytes: &[u8]) -> io::Result<RootEntry> {
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(bytes).trim_ascii();
    if trimmed.first() == Some(&b'{') {
        let json: serde_json::Value = serde_json::from_slice(trimmed).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "parse root registry entry {key}: {error}; use `tog gc --forget {key}` to drop the record, then re-run 'tog' in that project"
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
                    "root registry entry {key} has unknown schema {schema}; this store was written by a newer Tog, or the record is damaged — upgrade Tog, or use `tog gc --forget {key}`"
                ),
            ));
        }
        let wire: RootWire = serde_json::from_value(json).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "parse root registry entry {key}: {error}; use `tog gc --forget {key}` to drop the record, then re-run 'tog' in that project"
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
    // that was registered, so it is refused rather than trimmed into shape
    // — a trimmed record is protection that silently moves.
    let raw = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if raw != trimmed || raw.contains(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy root registry entry {key} is padded or spans lines, so it cannot be \
                 read back exactly; use `tog gc --forget {key}` to drop the record"
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

pub(super) fn read_registry_file_at(dirfd: RawFd, name: &[u8], path: &Path) -> io::Result<Vec<u8>> {
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

pub(super) fn write_root_record(roots: &Path, record: &RootRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(&root_wire(record))?;
    write_registry_entry(roots, &record.key, &bytes)
}

/// Does this registry entry name look like one of our own interrupted
/// temporary writes (`.<key>.tmp.<pid>.<seq>`)?  Nothing else in the
/// registry is dot-prefixed.
pub(super) fn is_own_registry_temp(name: &str) -> bool {
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
pub(super) fn write_registry_entry(roots: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
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

pub(super) fn validate_root_record(record: &RootRecord) -> io::Result<()> {
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

pub(super) fn invalid_root_import(path: &Path, detail: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cannot import closure {}: {detail}", path.display()),
    )
}

pub(super) fn validate_closure_envelope<'a>(
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
        "python" | "node" | "cargo" | "go" | "ruby" | "elixir" | "dotnet"
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

/// Import the closures a project already has, read through the held
/// project with the strict no-follow walk: a symlinked `.tog`,
/// `.tog/closures`, or closure file is refused rather than read through, so
/// a swapped entry cannot make this record protect another project's
/// objects. An absent closures directory imports nothing; a subdirectory
/// in it is skipped, as the pathname importer skipped it.
pub(super) fn import_existing_project_closures(
    store: &Store,
    project: &ProjectRoot,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    let closures = Path::new(".tog/closures");
    let Some(names) = project.read_dir(closures)? else {
        return Ok(());
    };
    for name in names {
        let relative = closures.join(&name);
        if !is_closure_file(&relative) {
            continue;
        }
        if project.entry(&relative)? == Entry::Directory {
            continue;
        }
        let path = project.path().join(&relative);
        let Some(bytes) = project.read_file(&relative)? else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| invalid_root_import(&path, error.to_string()))?;
        let body = validate_closure_envelope(&value, &path)?;
        import_closure_refs(store, project.path(), body, record, mode)?;
    }
    Ok(())
}

pub(super) fn import_closure_refs(
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
pub(super) fn unresolvable(result: io::Result<()>, mode: ImportMode) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) => match mode {
            ImportMode::Strict => Err(error),
            ImportMode::DropUnresolvable => {
                // Nothing for the user to do: the reference protects nothing
                // in this store, and this same sync records the references
                // the store does hold.
                ui::note(&format!(
                    "dropping a historical closure reference this store cannot resolve \
                     ({error}); this sync records the ones the store does hold"
                ));
                Ok(false)
            }
        },
    }
}

pub(super) fn import_absolute_reference(
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

pub(super) fn validate_object_reference(store: &Store, id: &str, path: &Path) -> io::Result<()> {
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

pub(super) fn path_under_objects(store: &Store, path: &Path) -> bool {
    path.starts_with(store.root.join("objects"))
}

pub(super) fn short_project_key(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(project.as_os_str().as_bytes())[..16])
}

pub(super) fn base64_encode(bytes: &[u8]) -> String {
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

pub(super) fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
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

pub(super) fn root_key(project_dir: &Path) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(project_dir.as_os_str().as_bytes()))
}

/// The exact text a record holds for this project, or a refusal when the
/// pathname cannot be stored unambiguously.
///
/// A record is one line of text and the key hashes that same text, so a
/// pathname that does not survive the round trip is not merely cosmetic: a
/// trailing space or a byte that is not UTF-8 registers one project under
/// another project's identity, and GC then keeps the wrong project's objects
/// and sweeps the live ones. Refuse the registration instead of recording a
/// pathname that names a different directory when it is read back.
pub(super) fn record_pathname(project_dir: &Path) -> io::Result<&str> {
    let text = project_dir.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to register {}: the path is not valid UTF-8, so a registry record \
                 cannot name it exactly. A project tog cannot record is a project it \
                 cannot protect from `tog gc`",
                project_dir.display()
            ),
        )
    })?;
    if text.trim() != text || text.contains('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to register '{text}': the path is padded with whitespace or spans \
                 lines, so a registry record cannot name it exactly. A project tog \
                 cannot record is a project it cannot protect from `tog gc`"
            ),
        ));
    }
    Ok(text)
}

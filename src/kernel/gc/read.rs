//! Sweep phase 1 (kernel gc): gather every root, record, and directory
//! entry the decision needs, holding a descriptor for each directory the
//! sweep may later delete from.

use super::*;

// ===========================================================================
// The four sweep phases.
//
// `read` gathers every root, record and directory entry the decision needs
// and holds a descriptor for each directory it may later delete from.
// `validate` turns that into a proven liveness set or a structured refusal.
// `plan` produces a fully-formed in-memory deletion plan. `execute` is the
// only phase that removes anything, under the same continuously held locks.
//
// A dry run stops after `plan` and prints it. That is what makes the preview
// and the real sweep agree: they are the same three phases over the same
// snapshot, with the same frozen decision time.
// ===========================================================================

#[derive(Debug, Default)]
pub(super) struct RootState {
    pub(super) object_ids: HashSet<String>,
    pub(super) project_paths: Vec<PathBuf>,
    pub(super) project_keep: Vec<PathBuf>,
    /// The `run-homes/` keys of every project a surviving root names.
    pub(super) run_home_keys: HashSet<String>,
}

pub(super) fn collect_roots(
    store: &Store,
    roots: &[RootEntry],
    options: &Options,
) -> io::Result<RootState> {
    let mut state = RootState::default();
    for root in roots {
        if options.forgotten.iter().any(|key| key == &root.key) {
            continue;
        }
        // A record this store cannot read is the same safety stop as a
        // project that cannot be resolved, and for the same reason: the
        // record exists, so some project is still counting on it, and there
        // is no way to tell which objects that project needs.
        if let Some(reason) = &root.unusable {
            return Err(unusable_root(root, reason));
        }
        if let Some(record) = &root.record {
            // root/2 is self-sufficient.  Its diagnostic project path is
            // intentionally never resolved during a sweep: a moved,
            // unmounted, or deleted project retains exactly the durable
            // references recorded here.
            state.object_ids.extend(record.objects.iter().cloned());
            state
                .run_home_keys
                .insert(Store::canonical_project_key(&record.project_path));
            state.project_keep.extend(
                record
                    .projections
                    .iter()
                    .map(|projection| projection.path(store)),
            );
            continue;
        }
        // A root whose project cannot be resolved is a safety stop, not a
        // cleanup candidate: with only a pathname record there is no way to
        // know what the project still needs, so dropping the record could
        // expose its objects to this very sweep. Refuse the whole sweep
        // until the record is usable, forgotten, or the project returns.
        if let Err(error) = fs::metadata(&root.path) {
            return Err(unresolvable_root(root, &error));
        }
        if !root.path.is_dir() {
            return Err(unresolvable_root(
                root,
                &io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the path exists but is not a directory",
                ),
            ));
        }
        let closures = root.path.join(".tog/closures");
        match fs::metadata(&closures) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(unresolvable_root(
                    root,
                    &io::Error::new(
                        io::ErrorKind::InvalidInput,
                        ".tog/closures is missing (never synced, or removed)",
                    ),
                ));
            }
            Err(error) => return Err(unresolvable_root(root, &error)),
        }
        let project = root
            .path
            .canonicalize()
            .map_err(|error| unresolvable_root(root, &error))?;
        state.project_paths.push(project.clone());
        state
            .run_home_keys
            .insert(Store::canonical_project_key(&project));
        // A registered project owns at least one closure: registration
        // happens when one is written. None at all means either that they
        // were removed, or that this pathname no longer resolves to the
        // project that was registered — unmounting a mount point exposes the
        // backing directory underneath, which can carry an empty
        // `.tog/closures` of its own and would otherwise be swept as if
        // the registered project had agreed it needed nothing.
        if read_closures(store, &project, &mut state)? == 0 {
            return Err(unresolvable_root(
                root,
                &io::Error::new(
                    io::ErrorKind::InvalidInput,
                    ".tog/closures holds no closure files: they were removed, or the \
                     path now resolves to a different directory than the one registered \
                     (the backing directory of an unmounted mount point, for example)",
                ),
            ));
        }
    }
    Ok(state)
}

pub(super) fn unresolvable_root(root: &RootEntry, error: &io::Error) -> io::Error {
    io::Error::other(format!(
        "refusing to sweep: root {} points at {}, which cannot be resolved ({}). Make the \
         project available at that path, or give up its protection explicitly with `tog \
         gc --forget {}`. Dry runs stop here too: the records decide what a real sweep \
         would keep.",
        root.key,
        root.path.display(),
        error,
        root.key
    ))
}

pub(super) fn unusable_root(root: &RootEntry, reason: &str) -> io::Error {
    io::Error::other(format!(
        "refusing to sweep: root {} has an unusable registry record at {} ({}). Repair the \
         record, or give up that project's protection explicitly with `tog gc --forget \
         {}`. Dry runs stop here too: the records decide what a real sweep would keep.",
        root.key,
        root.registry_path.display(),
        reason,
        root.key
    ))
}

/// Read a project's closures into the live set, returning how many closure
/// files it held.
pub(super) fn read_closures(
    store: &Store,
    project: &Path,
    state: &mut RootState,
) -> io::Result<usize> {
    let closures = project.join(".tog/closures");
    let mut found = 0usize;
    for entry in fs::read_dir(&closures)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|s| s.to_str()) != Some("json")
        {
            continue;
        }
        found += 1;
        let path = entry.path();
        let value: serde_json::Value =
            serde_json::from_reader(fs::File::open(&path)?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse closure {}: {e}", path.display()),
                )
            })?;
        let body = value.get("body").unwrap_or(&value);
        collect_object_ids(body, store, &mut state.object_ids);
        collect_project_paths(body, store, &mut state.project_keep);
        // Node forests do not record their full path, only the projection id;
        // reconstruct it from the canonical project path and the closure's
        // projection schema.
        if matches!(
            body["projection_schema"].as_str(),
            Some("node-forest/1" | "node-forest/2")
        ) {
            if let Some(projection_id) = body["projection_id"].as_str() {
                let key = Store::forest_project_key(project);
                state
                    .project_keep
                    .push(store.root.join("forests").join(&key).join(projection_id));
            }
        }
    }
    // A currently projected symlink is also an active forest, even when
    // the closure does not name it.
    for name in ["node_modules", ".venv"] {
        let path = project.join(name);
        if let Ok(target) = fs::read_link(&path) {
            let target = if target.is_absolute() {
                target
            } else {
                project.join(target)
            };
            if let Ok(target) = target.canonicalize() {
                collect_project_path(&target, store, &mut state.project_keep);
            }
        }
    }
    Ok(found)
}

pub(super) fn collect_object_ids(
    value: &serde_json::Value,
    store: &Store,
    ids: &mut HashSet<String>,
) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(id) = store::object_id_token(text) {
                ids.insert(id);
            }
            let objects = store.root.join("objects");
            let path = Path::new(text);
            if path.is_absolute() && path.starts_with(&objects) {
                if let Ok(relative) = path.strip_prefix(&objects) {
                    if let Some(component) = relative.components().next() {
                        let id = component.as_os_str().to_string_lossy();
                        if let Some(id) = store::object_id_token(&id) {
                            ids.insert(id);
                        }
                    }
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_object_ids(value, store, ids);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_object_ids(value, store, ids);
            }
        }
        _ => {}
    }
}

pub(super) fn collect_project_paths(
    value: &serde_json::Value,
    store: &Store,
    paths: &mut Vec<PathBuf>,
) {
    match value {
        serde_json::Value::String(text) => {
            let path = Path::new(text);
            if path.is_absolute() {
                collect_project_path(path, store, paths);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_project_paths(value, store, paths);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_project_paths(value, store, paths);
            }
        }
        _ => {}
    }
}

pub(super) fn collect_project_path(path: &Path, store: &Store, paths: &mut Vec<PathBuf>) {
    if path.starts_with(store.root.join("forests")) || path.starts_with(store.root.join("backups"))
    {
        paths.push(path.to_path_buf());
    }
}

/// A directory the sweep may delete from, held open from read through
/// execution so that every removal is relative to the inode that was
/// inspected rather than to a pathname that could have been replaced.
pub(super) struct HeldDir {
    pub(super) label: String,
    pub(super) file: fs::File,
}

/// Which held descriptor a candidate is named relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Parent {
    Objects,
    Cache(usize),
    Tmp,
    ForestProject(usize),
    Backups,
    RunHomes,
    RecordKind(usize),
    Meta,
}

pub(super) struct Dirs {
    pub(super) objects: HeldDir,
    pub(super) meta: HeldDir,
    pub(super) cache: Vec<(&'static str, HeldDir)>,
    pub(super) tmp: HeldDir,
    pub(super) forest_projects: Vec<HeldDir>,
    pub(super) backups: Option<HeldDir>,
    pub(super) run_homes: Option<HeldDir>,
    pub(super) record_kinds: Vec<HeldDir>,
}

impl Dirs {
    pub(super) fn get(&self, parent: Parent) -> &HeldDir {
        match parent {
            Parent::Objects => &self.objects,
            Parent::Cache(index) => &self.cache[index].1,
            Parent::Tmp => &self.tmp,
            Parent::Meta => &self.meta,
            Parent::ForestProject(index) => &self.forest_projects[index],
            Parent::Backups => self
                .backups
                .as_ref()
                .expect("a backup candidate implies a held backups descriptor"),
            Parent::RunHomes => self
                .run_homes
                .as_ref()
                .expect("a run home candidate implies a held run-homes descriptor"),
            Parent::RecordKind(index) => &self.record_kinds[index],
        }
    }
}

pub(super) struct ObjectEntry {
    pub(super) id: String,
    pub(super) name: std::ffi::OsString,
    pub(super) path: PathBuf,
    pub(super) stat: libc::stat,
    pub(super) meta_name: String,
    pub(super) meta_stat: libc::stat,
}

pub(super) struct CacheEntry {
    pub(super) algo: &'static str,
    pub(super) hex: String,
    pub(super) name: std::ffi::OsString,
    pub(super) path: PathBuf,
    pub(super) parent: Parent,
    pub(super) stat: libc::stat,
}

pub(super) struct DirEntrySnapshot {
    pub(super) name: std::ffi::OsString,
    pub(super) path: PathBuf,
    pub(super) parent: Parent,
    pub(super) stat: libc::stat,
}

/// Everything read before any decision is made. Reading never mutates: no
/// `Store::has`, no `store::touch_path`, and every timestamp comes from the
/// `fstatat` the candidate check will later be compared against.
pub struct Snapshot {
    pub(super) now: SystemTime,
    pub(super) state: RootState,
    /// Interrupted registry temporaries found by the read phase. Reading
    /// never mutates, so their removal happens in `execute` only, under the
    /// exclusive lease and after the plan has been validated — a dry run and
    /// a failed validation both leave them exactly as found.
    pub(super) crash_temps: Vec<OsString>,
    pub(super) meta: crate::kernel::objmeta::MetaIndex,
    pub(super) objects: Vec<ObjectEntry>,
    pub(super) cache: Vec<CacheEntry>,
    pub(super) stages: Vec<DirEntrySnapshot>,
    pub(super) forests: Vec<DirEntrySnapshot>,
    pub(super) backups: Vec<DirEntrySnapshot>,
    /// `run-homes/<project key>` directories.
    pub(super) run_homes: Vec<DirEntrySnapshot>,
    /// Store records about a project whose directory is gone.
    pub(super) orphan_records: Vec<DirEntrySnapshot>,
    /// Records whose object is gone. Under the exclusive lease nothing can
    /// be mid-publication (commit writes the object first), so each is the
    /// residue of a removal that stopped between the object and its record.
    pub(super) stray_records: Vec<DirEntrySnapshot>,
    pub(super) dirs: Dirs,
}

pub(super) const CACHE_ALGORITHMS: [(&str, usize); 3] =
    [("sha1", 40), ("sha256", 64), ("sha512", 128)];
/// Enumerate `objects/`, pairing every object with the record it must have.
/// Both stats come from the held descriptors, so what is measured here is
/// the inode the removal will later be relative to.
fn read_objects(
    objects_path: &Path,
    objects: &HeldDir,
    meta_dir: &HeldDir,
) -> io::Result<Vec<ObjectEntry>> {
    let mut object_entries = Vec::new();
    for entry in fs::read_dir(objects_path)? {
        let entry = entry?;
        let name = entry.file_name();
        let id = name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "object id is not UTF-8"))?
            .to_string();
        let stat = store::stat_at(objects.file.as_raw_fd(), name.as_bytes())?;
        if !store::is_object_id(&id) || (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("refusing to sweep: invalid object entry {:?}", entry.path()),
            ));
        }
        let meta_name = format!("{id}.json");
        let meta_stat =
            store::stat_at(meta_dir.file.as_raw_fd(), meta_name.as_bytes()).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "refusing to sweep: object {id} has no readable metadata: {error}; \
                         rebuild it or restore meta/{id}.json"
                    ),
                )
            })?;
        object_entries.push(ObjectEntry {
            id,
            name,
            path: entry.path(),
            stat,
            meta_name,
            meta_stat,
        });
    }
    Ok(object_entries)
}

/// Every readable record with no object under `objects/`, stated through
/// the held `meta/` descriptor the removal will be relative to.
fn read_stray_records(
    meta: &crate::kernel::objmeta::MetaIndex,
    objects: &[ObjectEntry],
    meta_dir: &HeldDir,
) -> io::Result<Vec<DirEntrySnapshot>> {
    let present: HashSet<&str> = objects.iter().map(|entry| entry.id.as_str()).collect();
    let mut strays = Vec::new();
    for (id, _) in meta.iter() {
        if present.contains(id.as_str()) {
            continue;
        }
        let name = OsString::from(format!("{id}.json"));
        let stat = store::stat_at(meta_dir.file.as_raw_fd(), name.as_bytes())?;
        strays.push(DirEntrySnapshot {
            path: Path::new("meta").join(&name),
            name,
            parent: Parent::Meta,
            stat,
        });
    }
    Ok(strays)
}

/// Enumerate every cache namespace, holding each one open. The returned
/// descriptors are the `Parent::Cache(index)` targets, so the push order
/// here is what the indexes recorded on the entries mean.
fn read_cache(store: &Store) -> io::Result<(Vec<(&'static str, HeldDir)>, Vec<CacheEntry>)> {
    let mut cache_dirs = Vec::new();
    let mut cache_entries = Vec::new();
    for (algo, width) in CACHE_ALGORITHMS {
        let path = store.root.join("cache").join(algo);
        match fs::symlink_metadata(&path) {
            Ok(stat) if stat.file_type().is_symlink() || !stat.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("refusing to sweep: cache/{algo} is not a real directory"),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let held = open_held(&path, &format!("cache/{algo}"))?;
        let index = cache_dirs.len();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let name = entry.file_name();
            let stat = store::stat_at(held.file.as_raw_fd(), name.as_bytes())?;
            let text = name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "cache digest is not UTF-8")
            })?;
            if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
                || text.len() != width
                || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("refusing to sweep: invalid cache entry {:?}", entry.path()),
                ));
            }
            cache_entries.push(CacheEntry {
                algo,
                hex: text.to_ascii_lowercase(),
                name,
                path: entry.path(),
                parent: Parent::Cache(index),
                stat,
            });
        }
        cache_dirs.push((algo, held));
    }
    Ok((cache_dirs, cache_entries))
}

/// Enumerate interrupted staging directories, and every other temporary a
/// killed tog leaves, under the already-held `tmp`.
fn read_stages(store: &Store, tmp: &HeldDir) -> io::Result<Vec<DirEntrySnapshot>> {
    let mut stages = Vec::new();
    for entry in fs::read_dir(store.root.join("tmp"))? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        let Some((_, expected)) = TMP_LEFTOVERS
            .iter()
            .find(|(prefix, _)| text.starts_with(prefix))
        else {
            continue;
        };
        let stat = store::stat_at(tmp.file.as_raw_fd(), name.as_bytes())?;
        if (stat.st_mode & libc::S_IFMT) != *expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "refusing to sweep: invalid {} entry {:?}",
                    tmp_kind(&name),
                    entry.path()
                ),
            ));
        }
        stages.push(DirEntrySnapshot {
            name,
            path: entry.path(),
            parent: Parent::Tmp,
            stat,
        });
    }
    Ok(stages)
}

/// What a leftover under `tmp/` is called in the sweep's output.
pub(super) fn tmp_kind(name: &std::ffi::OsStr) -> &'static str {
    if name.to_string_lossy().starts_with("stage-") {
        "stage"
    } else {
        "temporary"
    }
}

/// Every name tog gives a temporary under `tmp/`, with the file type it
/// writes there. A longer prefix comes before the shorter one it extends
/// (`resolve-meta-` is a file, `resolve-` a directory). GC holds the
/// exclusive lease, so any of these it sees was left by a process that died
/// before cleaning up, and the stage window still applies. `.publish.lock`
/// and any name not listed here are left alone.
pub(super) const TMP_LEFTOVERS: &[(&str, libc::mode_t)] = &[
    // Store::stage
    ("stage-", libc::S_IFDIR),
    // kernel::resolve::outputs
    ("resolve-out-", libc::S_IFDIR),
    // kernel::resolve::cache
    ("resolve-meta-", libc::S_IFREG),
    // kernel::resolve::snapshot
    ("resolve-", libc::S_IFDIR),
    // kernel::fetch: a download, and a local file being inserted
    ("dl-", libc::S_IFREG),
    ("ins-", libc::S_IFREG),
    // Store::commit's record before its rename
    ("meta-", libc::S_IFREG),
    // kernel::resolve::ledger
    ("diag-", libc::S_IFREG),
    // tailors::node::realize
    ("npm-archive-classification-", libc::S_IFREG),
    // Store record writes
    ("record-", libc::S_IFREG),
    // `tog doctor`'s writability probe
    (".doctor-", libc::S_IFREG),
];

/// The projection half of the snapshot. Default (everything empty, no
/// descriptors held) is what a sweep that will not touch projections reads.
#[derive(Default)]
struct Projections {
    forest_projects: Vec<HeldDir>,
    forests: Vec<DirEntrySnapshot>,
    backups_dir: Option<HeldDir>,
    backups: Vec<DirEntrySnapshot>,
    run_homes_dir: Option<HeldDir>,
    run_homes: Vec<DirEntrySnapshot>,
    record_kinds: Vec<HeldDir>,
    orphan_records: Vec<DirEntrySnapshot>,
}

/// Enumerate the project projections, holding each project directory, the
/// backups directory and the run-homes directory open. Only a `--project` sweep calls this: a sweep
/// that will not touch them must not hold their descriptors either.
fn read_projections(store: &Store) -> io::Result<Projections> {
    let mut read = Projections::default();
    let forests_path = store.root.join("forests");
    validate_projection_namespace(&forests_path, "forests")?;
    if forests_path.is_dir() {
        for project in fs::read_dir(&forests_path)? {
            let project = project?;
            let project_stat = fs::symlink_metadata(project.path())?;
            if project_stat.file_type().is_symlink() || !project_stat.is_dir() {
                continue;
            }
            let held = open_held(&project.path(), "forest project")?;
            let index = read.forest_projects.len();
            for projection in fs::read_dir(project.path())? {
                let projection = projection?;
                let name = projection.file_name();
                let stat = store::stat_at(held.file.as_raw_fd(), name.as_bytes())?;
                if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                    continue;
                }
                read.forests.push(DirEntrySnapshot {
                    name,
                    path: projection.path(),
                    parent: Parent::ForestProject(index),
                    stat,
                });
            }
            read.forest_projects.push(held);
        }
    }
    (read.backups_dir, read.backups) = read_directories(store, "backups", Parent::Backups)?;
    (read.run_homes_dir, read.run_homes) = read_directories(store, "run-homes", Parent::RunHomes)?;
    read_orphan_records(store, &mut read)?;
    Ok(read)
}

/// Every record under `records/<kind>/` that names a project (see
/// `Store::write_project_record`) whose directory no longer exists. Each
/// kind is held open and every record is opened relative to it, following
/// no symlink; one that names no project is never a candidate. Records are a
/// cache, so a kind or a record this cannot read is left alone rather than
/// failing the sweep.
fn read_orphan_records(store: &Store, read: &mut Projections) -> io::Result<()> {
    let records = store.root.join(store::RECORDS);
    validate_projection_namespace(&records, store::RECORDS)?;
    if !records.is_dir() {
        return Ok(());
    }
    let Ok(records_dir) = open_held(&records, store::RECORDS) else {
        return Ok(());
    };
    let Ok(kinds) = store::read_dir_names_at(records_dir.file.as_raw_fd()) else {
        return Ok(());
    };
    for kind in kinds {
        let Ok(kind_stat) = store::stat_at(records_dir.file.as_raw_fd(), kind.as_bytes()) else {
            continue;
        };
        if (kind_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            continue;
        }
        let Ok(file) = store::open_directory_at(records_dir.file.as_raw_fd(), kind.as_bytes())
        else {
            continue;
        };
        let held = HeldDir {
            label: "store record kind".to_string(),
            file,
        };
        let Ok(names) = store::read_dir_names_at(held.file.as_raw_fd()) else {
            continue;
        };
        let index = read.record_kinds.len();
        let kind_path = records.join(&kind);
        for name in names {
            let Some(stat) = orphan_record_at(&held, &name) else {
                continue;
            };
            read.orphan_records.push(DirEntrySnapshot {
                path: kind_path.join(&name),
                name,
                parent: Parent::RecordKind(index),
                stat,
            });
        }
        read.record_kinds.push(held);
    }
    Ok(())
}

/// The stat of the record `name` in the held kind directory when it names a
/// project whose directory is gone; `None` for any other record, or one
/// that cannot be read.
fn orphan_record_at(kind: &HeldDir, name: &std::ffi::OsStr) -> Option<libc::stat> {
    use std::io::Read as _;
    let stat = store::stat_at(kind.file.as_raw_fd(), name.as_bytes()).ok()?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || stat.st_size.max(0) as u64 > store::RECORD_CAP
    {
        return None;
    }
    let file = store::open_file_at(
        kind.file.as_raw_fd(),
        name.as_bytes(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
    .ok()?;
    let mut bytes = Vec::new();
    file.take(store::RECORD_CAP + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let project = store::record_project(&bytes)?;
    match fs::symlink_metadata(&project) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Some(stat),
        _ => None,
    }
}

/// Every directory directly under the store's `namespace`, with that
/// namespace held open; nothing when it does not exist.
fn read_directories(
    store: &Store,
    namespace: &str,
    parent: Parent,
) -> io::Result<(Option<HeldDir>, Vec<DirEntrySnapshot>)> {
    let path = store.root.join(namespace);
    validate_projection_namespace(&path, namespace)?;
    if !path.is_dir() {
        return Ok((None, Vec::new()));
    }
    let held = open_held(&path, namespace)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(&path)? {
        let entry = entry?;
        let name = entry.file_name();
        let stat = store::stat_at(held.file.as_raw_fd(), name.as_bytes())?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            continue;
        }
        entries.push(DirEntrySnapshot {
            name,
            path: entry.path(),
            parent,
            stat,
        });
    }
    Ok((Some(held), entries))
}

/// Phase 1. Read the whole deletion surface.
///
/// Root *resolution* happens here rather than in `validate` because it is an
/// I/O probe, not a structural check; either way it runs before anything can
/// be deleted, which is the safety property this phase protects.
pub(super) fn read(
    store: &Store,
    activity: &StoreActivity,
    options: &Options,
) -> io::Result<Snapshot> {
    store.require_exclusive_activity(activity, "garbage collection")?;
    let now = SystemTime::now();
    let (roots, crash_temps) = store.roots_for_sweep()?;
    let state = collect_roots(store, &roots, options)?;
    let meta = read_records(store)?;

    // Every descriptor below is held from here through execution, so the
    // acquisition order and the set held are part of the contract.
    let objects_path = store.root.join("objects");
    let objects = open_held(&objects_path, "objects")?;
    let meta_dir = open_held(&store.root.join("meta"), "meta")?;
    let tmp = open_held(&store.root.join("tmp"), "tmp")?;

    let object_entries = read_objects(&objects_path, &objects, &meta_dir)?;
    let stray_records = read_stray_records(&meta, &object_entries, &meta_dir)?;
    let (cache_dirs, cache_entries) = read_cache(store)?;
    let stages = read_stages(store, &tmp)?;
    let projections = if options.project {
        read_projections(store)?
    } else {
        Projections::default()
    };

    Ok(Snapshot {
        now,
        state,
        crash_temps,
        meta,
        objects: object_entries,
        cache: cache_entries,
        stages,
        forests: projections.forests,
        backups: projections.backups,
        run_homes: projections.run_homes,
        orphan_records: projections.orphan_records,
        stray_records,
        dirs: Dirs {
            objects,
            meta: meta_dir,
            cache: cache_dirs,
            tmp,
            forest_projects: projections.forest_projects,
            backups: projections.backups_dir,
            run_homes: projections.run_homes_dir,
            record_kinds: projections.record_kinds,
        },
    })
}

/// Read every metadata record, or refuse naming every record that cannot be
/// read.
///
/// A record nothing can parse cannot prove what the object it describes
/// still needs, so one is enough to stop the sweep. All of them are found in
/// the one pass and each is reported with the command that clears it, so a
/// store with several is repaired in one round rather than one refusal at a
/// time.
fn read_records(store: &Store) -> io::Result<crate::kernel::objmeta::MetaIndex> {
    let (meta, unusable) = crate::kernel::objmeta::MetaIndex::read_reporting_unusable(store)?;
    if unusable.is_empty() {
        return Ok(meta);
    }
    let blocked: Vec<String> = unusable
        .iter()
        .map(|(file, reason)| unusable_record_advice(store, file, reason))
        .collect();
    Err(blockage(&blocked))
}

/// What to do about one record the sweep cannot read: drop the object, or
/// remove the record by hand (and then drop the object that leaves behind).
fn unusable_record_advice(store: &Store, file: &str, reason: &str) -> String {
    let stem = file.strip_suffix(".json").unwrap_or(file);
    // The same rule drop applies: the id must be one drop accepts, and the
    // record a regular file or gone. Drop refuses a symlink or directory
    // under meta/, so naming it there would send the operator in a circle.
    let droppable = store::is_object_id(stem)
        && match fs::symlink_metadata(store.root.join("meta").join(file)) {
            Ok(metadata) => metadata.file_type().is_file(),
            Err(error) => error.kind() == io::ErrorKind::NotFound,
        };
    let advice = if droppable {
        format!(
            "drop it with `tog gc --drop-object {stem}` (the next sync that needs the object \
             rebuilds it), or restore the file from a backup"
        )
    } else if store::is_object_id(stem) && fs::symlink_metadata(store.object_path(stem)).is_ok() {
        // Removing the record alone leaves an object with no record, which
        // the sweep refuses; drop takes that object once the record is gone.
        format!(
            "remove it with `{}`, then drop the object it leaves behind with `tog gc \
             --drop-object {stem}`, or restore the file from a backup",
            remove_record_line(store, file)
        )
    } else {
        format!(
            "remove it with `{}`, or restore the file from a backup",
            remove_record_line(store, file)
        )
    };
    format!("metadata record meta/{file} is unusable ({reason}); {advice}")
}

/// The shell line that removes an unusable record: `rm`, or `rm -r` for a
/// directory (which `rm -r` removes; a symlink is removed, not followed).
pub(super) fn remove_record_line(store: &Store, file: &str) -> String {
    let path = store.root.join("meta").join(file);
    let is_dir = fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir());
    let path = path.display().to_string();
    if is_dir {
        crate::kernel::ui::shell_line(&["rm", "-r", &path])
    } else {
        crate::kernel::ui::shell_line(&["rm", &path])
    }
}

pub(super) fn open_held(path: &Path, label: &str) -> io::Result<HeldDir> {
    Ok(HeldDir {
        label: label.to_string(),
        file: open_real_directory(path, label)?,
    })
}

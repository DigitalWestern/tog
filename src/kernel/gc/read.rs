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
// snapshot, with the same frozen decision time, and the real sweep's
// maintenance phase has already run before the snapshot is taken.
// ===========================================================================

#[derive(Debug, Default)]
pub(super) struct RootState {
    pub(super) object_ids: HashSet<String>,
    pub(super) project_paths: Vec<PathBuf>,
    pub(super) project_keep: Vec<PathBuf>,
}

pub(super) fn collect_roots<W: Write>(
    store: &Store,
    roots: &[RootEntry],
    options: &Options,
    out: &mut W,
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
                .project_keep
                .extend(
                    record
                        .projections
                        .iter()
                        .map(|projection| match projection.base {
                            store::ProjectionBase::Forests
                            | store::ProjectionBase::Backups
                            | store::ProjectionBase::LegacyForests
                            | store::ProjectionBase::LegacyBackups => projection.path(store),
                        }),
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
        // A registered project owns at least one closure: registration
        // happens when one is written. None at all means either that they
        // were removed, or that this pathname no longer resolves to the
        // project that was registered — unmounting a mount point exposes the
        // backing directory underneath, which can carry an empty
        // `.tog/closures` of its own and would otherwise be swept as if
        // the registered project had agreed it needed nothing.
        if read_closures(store, &project, &mut state, out)? == 0 {
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
pub(super) fn read_closures<W: Write>(
    store: &Store,
    project: &Path,
    state: &mut RootState,
    out: &mut W,
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
                let key = short_sha256(project.as_os_str().as_bytes(), 32);
                state
                    .project_keep
                    .push(store.root.join("forests").join(&key).join(projection_id));
                // A legacy closure may still point at the sibling namespace;
                // retain that candidate too, but never make it sweepable.
                if let Some(home) = store.root.parent() {
                    state
                        .project_keep
                        .push(home.join("forests").join(key).join(projection_id));
                }
            }
        }
    }
    // A currently projected symlink is also an active forest even in a legacy
    // closure that predates projection_id.
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
    let _ = out;
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
            let Some(home) = store.root.parent() else {
                return;
            };
            let store_forests = store.root.join("forests");
            let store_backups = store.root.join("backups");
            let legacy_forests = home.join("forests");
            let legacy_backups = home.join("backups");
            if path.is_absolute()
                && (path.starts_with(&store_forests)
                    || path.starts_with(&store_backups)
                    || path.starts_with(&legacy_forests)
                    || path.starts_with(&legacy_backups))
            {
                paths.push(path.to_path_buf());
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
    let Some(home) = store.root.parent() else {
        return;
    };
    let store_forests = store.root.join("forests");
    let store_backups = store.root.join("backups");
    let legacy_forests = home.join("forests");
    let legacy_backups = home.join("backups");
    if path.starts_with(&store_forests)
        || path.starts_with(&store_backups)
        || path.starts_with(&legacy_forests)
        || path.starts_with(&legacy_backups)
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
}

pub(super) struct Dirs {
    pub(super) objects: HeldDir,
    pub(super) meta: HeldDir,
    pub(super) cache: Vec<(&'static str, HeldDir)>,
    pub(super) tmp: HeldDir,
    pub(super) forest_projects: Vec<HeldDir>,
    pub(super) backups: Option<HeldDir>,
}

impl Dirs {
    pub(super) fn get(&self, parent: Parent) -> &HeldDir {
        match parent {
            Parent::Objects => &self.objects,
            Parent::Cache(index) => &self.cache[index].1,
            Parent::Tmp => &self.tmp,
            Parent::ForestProject(index) => &self.forest_projects[index],
            Parent::Backups => self
                .backups
                .as_ref()
                .expect("a backup candidate implies a held backups descriptor"),
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
    /// Bytes the record occupies once maintenance has published it. For a
    /// dry run the record has not been written yet, so the size is taken
    /// from the overlay the real sweep would have written — otherwise the
    /// preview's freed-byte total would differ from the sweep's for exactly
    /// the records migration touched.
    pub(super) meta_size: u64,
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
    pub(super) dirs: Dirs,
    pub(super) legacy_projection_note: Option<String>,
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
    upgrades: &BTreeMap<String, serde_json::Value>,
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
        let meta_size = match upgrades.get(&id) {
            Some(value) => serde_json::to_vec_pretty(value)?.len() as u64,
            None => file_size_of(&meta_stat),
        };
        object_entries.push(ObjectEntry {
            id,
            name,
            path: entry.path(),
            stat,
            meta_name,
            meta_stat,
            meta_size,
        });
    }
    Ok(object_entries)
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

/// Enumerate interrupted staging directories under the already-held `tmp`.
fn read_stages(store: &Store, tmp: &HeldDir) -> io::Result<Vec<DirEntrySnapshot>> {
    let mut stages = Vec::new();
    for entry in fs::read_dir(store.root.join("tmp"))? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("stage-") {
            continue;
        }
        let stat = store::stat_at(tmp.file.as_raw_fd(), name.as_bytes())?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("refusing to sweep: invalid stage entry {:?}", entry.path()),
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

/// The projection half of the snapshot. Default (everything empty, no
/// descriptors held) is what a sweep that will not touch projections reads.
#[derive(Default)]
struct Projections {
    forest_projects: Vec<HeldDir>,
    forests: Vec<DirEntrySnapshot>,
    backups_dir: Option<HeldDir>,
    backups: Vec<DirEntrySnapshot>,
    legacy_projection_note: Option<String>,
}

/// Enumerate the project projections, holding each project directory and
/// the backups directory open. Only a `--project` sweep calls this: a sweep
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
    let backups_path = store.root.join("backups");
    validate_projection_namespace(&backups_path, "backups")?;
    if backups_path.is_dir() {
        let held = open_held(&backups_path, "backups")?;
        for entry in fs::read_dir(&backups_path)? {
            let entry = entry?;
            let name = entry.file_name();
            let stat = store::stat_at(held.file.as_raw_fd(), name.as_bytes())?;
            if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                continue;
            }
            read.backups.push(DirEntrySnapshot {
                name,
                path: entry.path(),
                parent: Parent::Backups,
                stat,
            });
        }
        read.backups_dir = Some(held);
    }
    if let Some(home) = store.root.parent() {
        if home.join("forests").is_dir() || home.join("backups").is_dir() {
            read.legacy_projection_note = Some(format!(
                "legacy project projections under {} are shared by sibling stores",
                home.display()
            ));
        }
    }
    Ok(read)
}

/// Phase 1. Read the whole deletion surface.
///
/// Root *resolution* happens here rather than in `validate` because it is an
/// I/O probe, not a structural check; either way it runs before anything can
/// be deleted, which is the safety property this phase protects.
pub(super) fn read<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    options: &Options,
    upgrades: &BTreeMap<String, serde_json::Value>,
    out: &mut W,
) -> io::Result<Snapshot> {
    store.require_exclusive_activity(activity, "garbage collection")?;
    let now = SystemTime::now();
    let (roots, crash_temps) = store.roots_for_sweep()?;
    let state = collect_roots(store, &roots, options, out)?;
    let mut meta = crate::kernel::objmeta::MetaIndex::read(store)?;
    meta.apply(upgrades)?;

    // Every descriptor below is held from here through execution, so the
    // acquisition order and the set held are part of the contract.
    let objects_path = store.root.join("objects");
    let objects = open_held(&objects_path, "objects")?;
    let meta_dir = open_held(&store.root.join("meta"), "meta")?;
    let tmp = open_held(&store.root.join("tmp"), "tmp")?;

    let object_entries = read_objects(&objects_path, &objects, &meta_dir, upgrades)?;
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
        dirs: Dirs {
            objects,
            meta: meta_dir,
            cache: cache_dirs,
            tmp,
            forest_projects: projections.forest_projects,
            backups: projections.backups_dir,
        },
        legacy_projection_note: projections.legacy_projection_note,
    })
}

pub(super) fn open_held(path: &Path, label: &str) -> io::Result<HeldDir> {
    Ok(HeldDir {
        label: label.to_string(),
        file: open_directory(path, label)?,
    })
}

//! Store garbage collection.
//!
//! GC is deliberately rooted in project closure files rather than in the
//! current working directory. A project becomes a root when a tailor writes a
//! closure. A root never stops protecting its project: an unavailable project
//! stops the sweep until it returns or its record is explicitly forgotten.

use crate::activity::StoreActivity;
use crate::store::{self, ObjectDeps, RootEntry, Store};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const ACTIVE_WINDOW: Duration = Duration::from_secs(10 * 60);
const STAGE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone)]
pub struct Options {
    pub dry_run: bool,
    pub keep_days: u64,
    pub project: bool,
    /// Explicit opt-in to collect objects written without reference
    /// metadata. They may belong to projects from before the roots registry.
    pub collect_legacy: bool,
    /// Root keys this sweep must ignore. A real `--forget` removed the
    /// record before the sweep, so this is a belt-and-braces repeat; a
    /// `--dry-run --forget` leaves the record in place and excludes it only
    /// here, so the sweep shows what the forgotten project would stop
    /// protecting.
    pub forgotten: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dry_run: false,
            keep_days: 30,
            project: false,
            collect_legacy: false,
            forgotten: Vec::new(),
        }
    }
}

impl Options {
    pub fn keep_days(days: u64) -> Self {
        Self {
            keep_days: days,
            ..Self::default()
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub freed_bytes: u64,
    pub objects: usize,
    pub cached_artifacts: usize,
    pub stages: usize,
    pub forests: usize,
    pub backups: usize,
}

#[derive(Debug, Default)]
struct RootState {
    object_ids: HashSet<String>,
    project_paths: Vec<PathBuf>,
    project_keep: Vec<PathBuf>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub upgraded: usize,
    pub unresolved: usize,
}

/// Sweep the store and optionally the blanket-home projections.
pub fn collect<W: Write>(store: &Store, options: Options, out: &mut W) -> io::Result<Report> {
    let Some(activity) = store.try_activity_exclusive()? else {
        writeln!(out, "cleanup skipped: a Blanket job is using this store")?;
        return Ok(Report::default());
    };
    collect_with_activity(store, &activity, options, out)
}

/// Run a sweep while the caller owns the store's exclusive activity lease.
/// This is kept separate from `collect` so a CLI invocation can validate and
/// apply register/forget mutations under the same lease without attempting
/// to reacquire its own exclusive lock.
pub fn collect_with_activity<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    options: Options,
    out: &mut W,
) -> io::Result<Report> {
    store.require_exclusive_activity(activity, "garbage collection")?;
    if !store.registry_initialized()? {
        return Err(io::Error::other(
            "refusing to sweep: the project-root registry is not initialized; register existing "
                .to_string()
                + "projects with `blanket gc --register <dir>...` or run `blanket sync` in each "
                + "project",
        ));
    }
    // The maintenance phase runs first, under the same exclusive token, and
    // before any deletion lock or snapshot. The migration opens the
    // publication lock itself, so taking it here first would be a recursive
    // acquisition through a second descriptor.
    //
    // A dry run does not write, so it carries the upgrades it *would* have
    // published forward as an in-memory overlay. The real sweep applies the
    // same overlay over records it has just written. Both paths therefore
    // plan from byte-identical evidence — the preview cannot show a deletion
    // the sweep would not make, and the sweep cannot make one the preview did
    // not show.
    let (migration, upgrades) =
        migrate_metadata_locked(store, activity, options.dry_run, out, false)?;
    if migration.unresolved != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to sweep: metadata maintenance left {} uncertified legacy record(s); \
                 nothing was deleted. Resolve the objects named above and run `blanket gc \
                 --migrate-metadata`",
                migration.unresolved
            ),
        ));
    }
    // GC has its own user-visible lock, and also holds the publication lock
    // across the liveness snapshot and removals. Store::has/commit use the
    // latter, so a sync either touches an object before this sweep or waits
    // until after it.
    let _gc_lock = store.gc_lock()?;
    let _publish_lock = store.publish_lock()?;

    let snapshot = read(store, activity, &options, &upgrades, out)?;
    let validated = validate(&snapshot, &options)?;
    let plan = plan(&validated, &options)?;
    if options.dry_run {
        report_plan(&plan, out)?;
        return Ok(plan.report());
    }
    execute(&plan, &snapshot, store, activity, out)
}

fn collect_roots<W: Write>(
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
                        .filter_map(|projection| match projection.base {
                            store::ProjectionBase::Forests
                            | store::ProjectionBase::Backups
                            | store::ProjectionBase::LegacyForests
                            | store::ProjectionBase::LegacyBackups => Some(projection.path(store)),
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
        let closures = root.path.join(".blanket/closures");
        match fs::metadata(&closures) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(unresolvable_root(
                    root,
                    &io::Error::new(
                        io::ErrorKind::InvalidInput,
                        ".blanket/closures is missing (never synced, or removed)",
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
        read_closures(store, &project, &mut state, out)?;
    }
    Ok(state)
}

fn unresolvable_root(root: &RootEntry, error: &io::Error) -> io::Error {
    io::Error::other(format!(
        "refusing to sweep: root {} points at {}, which cannot be resolved ({}). Make the \
         project available at that path, or give up its protection explicitly with `blanket \
         gc --forget {}`. Dry runs stop here too: the records decide what a real sweep \
         would keep.",
        root.key,
        root.path.display(),
        error,
        root.key
    ))
}

fn read_closures<W: Write>(
    store: &Store,
    project: &Path,
    state: &mut RootState,
    out: &mut W,
) -> io::Result<()> {
    let closures = project.join(".blanket/closures");
    for entry in fs::read_dir(&closures)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|s| s.to_str()) != Some("json")
        {
            continue;
        }
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
    Ok(())
}

fn collect_object_ids(value: &serde_json::Value, store: &Store, ids: &mut HashSet<String>) {
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

fn collect_project_paths(value: &serde_json::Value, store: &Store, paths: &mut Vec<PathBuf>) {
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

fn collect_project_path(path: &Path, store: &Store, paths: &mut Vec<PathBuf>) {
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

// ===========================================================================
// D.4 — the four sweep phases.
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

/// A directory the sweep may delete from, held open from read through
/// execution so that every removal is relative to the inode that was
/// inspected rather than to a pathname that could have been replaced.
struct HeldDir {
    label: String,
    file: fs::File,
}

/// Which held descriptor a candidate is named relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parent {
    Objects,
    Cache(usize),
    Tmp,
    ForestProject(usize),
    Backups,
}

struct Dirs {
    objects: HeldDir,
    meta: HeldDir,
    cache: Vec<(&'static str, HeldDir)>,
    tmp: HeldDir,
    forest_projects: Vec<HeldDir>,
    backups: Option<HeldDir>,
}

impl Dirs {
    fn get(&self, parent: Parent) -> &HeldDir {
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

struct ObjectEntry {
    id: String,
    name: std::ffi::OsString,
    path: PathBuf,
    stat: libc::stat,
    meta_name: String,
    meta_stat: libc::stat,
    /// Bytes the record occupies once maintenance has published it. For a
    /// dry run the record has not been written yet, so the size is taken
    /// from the overlay the real sweep would have written — otherwise the
    /// preview's freed-byte total would differ from the sweep's for exactly
    /// the records migration touched.
    meta_size: u64,
}

struct CacheEntry {
    algo: &'static str,
    hex: String,
    name: std::ffi::OsString,
    path: PathBuf,
    parent: Parent,
    stat: libc::stat,
}

struct DirEntrySnapshot {
    name: std::ffi::OsString,
    path: PathBuf,
    parent: Parent,
    stat: libc::stat,
}

/// Everything read before any decision is made. Reading never mutates: no
/// `Store::has`, no `store::touch_path`, and every timestamp comes from the
/// `fstatat` the candidate check will later be compared against.
pub struct Snapshot {
    now: SystemTime,
    state: RootState,
    /// Interrupted registry temporaries found by the read phase. Reading
    /// never mutates, so their removal happens in `execute` only, under the
    /// exclusive lease and after the plan has been validated — a dry run and
    /// a failed validation both leave them exactly as found.
    crash_temps: Vec<OsString>,
    meta: crate::objmeta::MetaIndex,
    objects: Vec<ObjectEntry>,
    cache: Vec<CacheEntry>,
    stages: Vec<DirEntrySnapshot>,
    forests: Vec<DirEntrySnapshot>,
    backups: Vec<DirEntrySnapshot>,
    dirs: Dirs,
    legacy_projection_note: Option<String>,
}

/// A validated snapshot: the complete retained set, proven from complete
/// evidence. There is no partially valid form of this type.
pub struct Validated<'a> {
    snapshot: &'a Snapshot,
    /// Everything the sweep must keep: durable roots, retention policy, and
    /// the transitive closure of both.
    live: HashSet<String>,
    /// The part of `live` a durable project root protects. An object in
    /// `live` but not here survives only because retention policy kept it,
    /// which is a decision a dry run reports as `skipped:` rather than
    /// leaving silent.
    root_live: HashSet<String>,
    /// Cache entries kept because a retained object names them.
    referenced_cache: BTreeSet<String>,
}

struct Removal {
    parent: Parent,
    name: std::ffi::OsString,
    stat: libc::stat,
    /// The object's `meta/<id>.json`, unlinked with it.
    companion: Option<(String, libc::stat)>,
    label: String,
    display: String,
    bytes: u64,
    counter: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counter {
    Objects,
    CachedArtifacts,
    Stages,
    Forests,
    Backups,
}

/// A fully-formed deletion plan plus everything retention deliberately kept.
pub struct SweepPlan {
    removals: Vec<Removal>,
    skips: Vec<String>,
    notes: Vec<String>,
}

impl SweepPlan {
    fn report(&self) -> Report {
        let mut report = Report::default();
        for removal in &self.removals {
            report.freed_bytes += removal.bytes;
            match removal.counter {
                Counter::Objects => report.objects += 1,
                Counter::CachedArtifacts => report.cached_artifacts += 1,
                Counter::Stages => report.stages += 1,
                Counter::Forests => report.forests += 1,
                Counter::Backups => report.backups += 1,
            }
        }
        report
    }
}

const CACHE_ALGORITHMS: [(&str, usize); 3] = [("sha1", 40), ("sha256", 64), ("sha512", 128)];

/// Phase 1. Read the whole deletion surface.
///
/// Root *resolution* happens here rather than in `validate` because it is an
/// I/O probe, not a structural check; either way it runs before anything can
/// be deleted, which is the property D.4 is protecting.
fn read<W: Write>(
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
    let mut meta = crate::objmeta::MetaIndex::read(store)?;
    meta.apply(upgrades)?;

    let objects_path = store.root.join("objects");
    let objects = open_held(&objects_path, "objects")?;
    let meta_dir = open_held(&store.root.join("meta"), "meta")?;
    let tmp = open_held(&store.root.join("tmp"), "tmp")?;

    let mut object_entries = Vec::new();
    for entry in fs::read_dir(&objects_path)? {
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

    // Projections are only enumerated for a `--project` sweep; a sweep that
    // will not touch them must not hold their descriptors either.
    let mut forest_projects: Vec<HeldDir> = Vec::new();
    let mut forests = Vec::new();
    let mut backups_dir = None;
    let mut backups = Vec::new();
    let mut legacy_projection_note = None;
    if options.project {
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
                let index = forest_projects.len();
                for projection in fs::read_dir(project.path())? {
                    let projection = projection?;
                    let name = projection.file_name();
                    let stat = store::stat_at(held.file.as_raw_fd(), name.as_bytes())?;
                    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                        continue;
                    }
                    forests.push(DirEntrySnapshot {
                        name,
                        path: projection.path(),
                        parent: Parent::ForestProject(index),
                        stat,
                    });
                }
                forest_projects.push(held);
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
                backups.push(DirEntrySnapshot {
                    name,
                    path: entry.path(),
                    parent: Parent::Backups,
                    stat,
                });
            }
            backups_dir = Some(held);
        }
        if let Some(home) = store.root.parent() {
            if home.join("forests").is_dir() || home.join("backups").is_dir() {
                legacy_projection_note = Some(format!(
                    "legacy project projections under {} are shared by sibling stores",
                    home.display()
                ));
            }
        }
    }

    Ok(Snapshot {
        now,
        state,
        crash_temps,
        meta,
        objects: object_entries,
        cache: cache_entries,
        stages,
        forests,
        backups,
        dirs: Dirs {
            objects,
            meta: meta_dir,
            cache: cache_dirs,
            tmp,
            forest_projects,
            backups: backups_dir,
        },
        legacy_projection_note,
    })
}

/// Phase 2. Prove the retained set, or refuse with every reason at once.
///
/// Missing or incomplete dependency information is never an empty dependency
/// list: it aborts the whole sweep. There is deliberately no partial-recovery
/// rule here.
fn validate<'a>(snapshot: &'a Snapshot, options: &Options) -> io::Result<Validated<'a>> {
    let mut blocked: Vec<String> = Vec::new();

    // Every object must have a record, and every record must have an object.
    for entry in &snapshot.objects {
        if snapshot.meta.get(&entry.id).is_none() {
            blocked.push(format!(
                "object {} has no usable metadata; rebuild it or restore meta/{}.json",
                entry.id, entry.id
            ));
        }
    }
    let present: HashSet<&str> = snapshot
        .objects
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    for (id, _) in snapshot.meta.iter() {
        if !present.contains(id.as_str()) {
            blocked.push(format!(
                "metadata for missing object {id}; remove meta/{id}.json with `blanket gc \
                 --migrate-metadata` after restoring the object, or delete the stray record"
            ));
        }
    }

    // Legacy evidence can never authorize a deletion. Maintenance runs before
    // this phase, so anything still legacy here could not be certified.
    for (id, record) in snapshot.meta.iter() {
        if record.evidence == crate::objmeta::Evidence::Legacy {
            blocked.push(format!(
                "object {id} ({}) still carries pre-object-meta/2 metadata; its dependencies are \
                 not proven, so no sweep can run. Run `blanket gc --migrate-metadata` and resolve \
                 the records it names",
                record.describe()
            ));
        }
    }
    if !blocked.is_empty() {
        return Err(blockage(&blocked));
    }

    // Marking roots: every durable root's objects, plus everything retention
    // policy keeps — whose dependencies must survive with it. The two are
    // traversed separately so the plan can tell "a project needs this" from
    // "policy is keeping this for now"; the union is what survives.
    let mut marking: HashSet<String> = snapshot.state.object_ids.clone();
    for entry in &snapshot.objects {
        let record = snapshot.meta.get(&entry.id).expect("presence proven above");
        if retained_by_policy(snapshot.now, entry, record, options) {
            marking.insert(entry.id.clone());
        }
    }
    let root_live = reachable(snapshot, &snapshot.state.object_ids);

    // BFS over proven dependencies. The visited set terminates cycles.
    let mut live: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, Option<String>)> =
        marking.into_iter().map(|id| (id, None)).collect();
    while let Some((id, referrer)) = queue.pop_front() {
        if !live.insert(id.clone()) {
            continue;
        }
        let Some(record) = snapshot.meta.get(&id) else {
            blocked.push(match referrer {
                Some(referrer) => format!(
                    "object {id}, reachable from {referrer}, has no metadata; rebuild {referrer} \
                     or restore meta/{id}.json"
                ),
                None => format!(
                    "root object {id} has no metadata; restore meta/{id}.json, or find the root \
                     that names it with `blanket store roots` and give up its protection with \
                     `blanket gc --forget <key>`"
                ),
            });
            continue;
        };
        for dependency in &record.dependencies {
            if !live.contains(dependency) {
                queue.push_back((dependency.clone(), Some(id.clone())));
            }
        }
    }
    if !blocked.is_empty() {
        return Err(blockage(&blocked));
    }

    // Cached artifacts are retained by explicit digests on retained objects.
    let mut referenced_cache = BTreeSet::new();
    for id in &live {
        if let Some(record) = snapshot.meta.get(id) {
            for digest in &record.cache {
                referenced_cache.insert(format!("{}:{}", digest.algo(), digest.hex()));
            }
        }
    }

    Ok(Validated {
        snapshot,
        live,
        root_live,
        referenced_cache,
    })
}

/// The transitive closure of `seeds` over proven dependencies. Only called
/// after the blocking checks above, so a missing record here is impossible
/// and is simply not traversed.
fn reachable(snapshot: &Snapshot, seeds: &HashSet<String>) -> HashSet<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = seeds.iter().cloned().collect();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(record) = snapshot.meta.get(&id) {
            for dependency in &record.dependencies {
                if !seen.contains(dependency) {
                    queue.push_back(dependency.clone());
                }
            }
        }
    }
    seen
}

fn blockage(reasons: &[String]) -> io::Error {
    let mut message = String::from("refusing to sweep: nothing was deleted");
    for reason in reasons {
        message.push_str("\n  blocked: ");
        message.push_str(reason);
    }
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Retention policy, evaluated against the frozen snapshot time so a dry run
/// and the sweep that follows it choose the same candidates.
fn retained_by_policy(
    now: SystemTime,
    entry: &ObjectEntry,
    record: &crate::objmeta::Record,
    options: &Options,
) -> bool {
    if recent_at(now, &entry.stat, ACTIVE_WINDOW) {
        return true;
    }
    // An object published before the roots registry existed carries no
    // reference metadata of its own. Migration proves such a record's
    // outgoing dependencies; it says nothing about whether some pre-registry
    // project still needs the object, so the opt-in boundary is preserved.
    !record.had_legacy_refs
        && (!options.collect_legacy
            || !older_than_at(now, &entry.stat, keep_age(options.keep_days)))
}

/// Phase 3. Build the complete deletion plan. Nothing is removed here.
fn plan(validated: &Validated, options: &Options) -> io::Result<SweepPlan> {
    let snapshot = validated.snapshot;
    let mut removals = Vec::new();
    let mut skips = Vec::new();
    let mut notes = Vec::new();

    for entry in &snapshot.objects {
        let record = snapshot
            .meta
            .get(&entry.id)
            .expect("validate proved every object has a record");
        // Protected by a project: not a decision, so not reported.
        if validated.root_live.contains(&entry.id) {
            continue;
        }
        // Kept by retention policy, or reachable from something that is.
        // This *is* a decision, and D.5 requires it to be visible next to
        // the deletion candidates rather than silently folded into them.
        if validated.live.contains(&entry.id) {
            let reason = if recent_at(snapshot.now, &entry.stat, ACTIVE_WINDOW) {
                "it was used within the active window".to_string()
            } else if !record.had_legacy_refs {
                if options.collect_legacy {
                    format!(
                        "it predates reference metadata and is younger than --keep-days {}",
                        options.keep_days
                    )
                } else {
                    "it predates reference metadata; `--collect-legacy` is required to collect it"
                        .to_string()
                }
            } else {
                "another object retention policy is keeping depends on it".to_string()
            };
            skips.push(format!(
                "object {} ([{}]) — {reason}",
                entry.id, record.identity.kind
            ));
            continue;
        }
        let bytes = tree_size(&entry.path)? + entry.meta_size;
        removals.push(Removal {
            parent: Parent::Objects,
            name: entry.name.clone(),
            stat: entry.stat,
            companion: Some((entry.meta_name.clone(), entry.meta_stat)),
            label: format!("object {}", entry.id),
            display: format!(
                "object {} ([{}] {})",
                entry.path.display(),
                record.identity.kind,
                size(bytes)
            ),
            bytes,
            counter: Counter::Objects,
        });
    }

    for entry in &snapshot.cache {
        let key = format!("{}:{}", entry.algo, entry.hex);
        if validated.referenced_cache.contains(&key) {
            continue;
        }
        if recent_at(snapshot.now, &entry.stat, ACTIVE_WINDOW)
            || !older_than_at(snapshot.now, &entry.stat, keep_age(options.keep_days))
        {
            skips.push(format!(
                "cached artifact {key} is younger than the keep window"
            ));
            continue;
        }
        let bytes = file_size_of(&entry.stat);
        removals.push(Removal {
            parent: entry.parent,
            name: entry.name.clone(),
            stat: entry.stat,
            companion: None,
            label: format!("cache artifact {}", entry.path.display()),
            display: format!("cached artifact {} ({})", entry.path.display(), size(bytes)),
            bytes,
            counter: Counter::CachedArtifacts,
        });
    }

    for entry in &snapshot.stages {
        if !older_than_at(snapshot.now, &entry.stat, STAGE_WINDOW) {
            continue;
        }
        let bytes = tree_size(&entry.path)?;
        removals.push(Removal {
            parent: entry.parent,
            name: entry.name.clone(),
            stat: entry.stat,
            companion: None,
            label: format!("stage {}", entry.path.display()),
            display: format!("stale stage {} ({})", entry.path.display(), size(bytes)),
            bytes,
            counter: Counter::Stages,
        });
    }

    if options.project {
        for entry in &snapshot.forests {
            if snapshot
                .state
                .project_keep
                .iter()
                .any(|keep| related(&entry.path, keep))
            {
                skips.push(format!(
                    "forest {} is claimed by a surviving root record",
                    entry.path.display()
                ));
                continue;
            }
            if !older_than_at(snapshot.now, &entry.stat, STAGE_WINDOW) {
                continue;
            }
            let bytes = tree_size(&entry.path)?;
            removals.push(Removal {
                parent: entry.parent,
                name: entry.name.clone(),
                stat: entry.stat,
                companion: None,
                label: format!("forest {}", entry.path.display()),
                display: format!("stale forest {} ({})", entry.path.display(), size(bytes)),
                bytes,
                counter: Counter::Forests,
            });
        }
        for entry in &snapshot.backups {
            if snapshot
                .state
                .project_keep
                .iter()
                .any(|keep| related(&entry.path, keep))
            {
                skips.push(format!(
                    "backup {} is claimed by a surviving root record",
                    entry.path.display()
                ));
                continue;
            }
            if !older_than_at(snapshot.now, &entry.stat, keep_age(options.keep_days)) {
                continue;
            }
            let bytes = tree_size(&entry.path)?;
            removals.push(Removal {
                parent: entry.parent,
                name: entry.name.clone(),
                stat: entry.stat,
                companion: None,
                label: format!("backup {}", entry.path.display()),
                display: format!("backup {} ({})", entry.path.display(), size(bytes)),
                bytes,
                counter: Counter::Backups,
            });
        }
        if let Some(note) = &snapshot.legacy_projection_note {
            notes.push(note.clone());
        }
    }

    Ok(SweepPlan {
        removals,
        skips,
        notes,
    })
}

/// Phase 4. The only phase that deletes.
///
/// Each candidate is re-`fstatat`ed relative to the descriptor held since
/// the read phase and compared with the `(dev, ino)` and file type recorded
/// in the plan. A replacement stops that deletion with an error; it is never
/// skipped silently. An error after deletion has begun reports what was
/// already removed — there is no filesystem rollback, and the zero-deletions
/// promise covers validation failures, not post-validation I/O errors.
fn execute<W: Write>(
    plan: &SweepPlan,
    snapshot: &Snapshot,
    store: &Store,
    activity: &StoreActivity,
    out: &mut W,
) -> io::Result<Report> {
    store.require_exclusive_activity(activity, "garbage collection")?;
    // Crash residue from the read phase is removed here and only here: after
    // the deletion plan has been validated, under the continuously held
    // exclusive lease. A dry run never reaches this, so it deletes nothing —
    // including crash residue.
    store.clear_crash_temps(&snapshot.crash_temps)?;
    let mut report = Report::default();
    for removal in &plan.removals {
        let parent = snapshot.dirs.get(removal.parent);
        let result = (|| -> io::Result<()> {
            confirm_unchanged(
                parent,
                removal.name.as_bytes(),
                &removal.stat,
                &removal.label,
            )?;
            if let Some((meta_name, meta_stat)) = &removal.companion {
                confirm_unchanged(
                    &snapshot.dirs.meta,
                    meta_name.as_bytes(),
                    meta_stat,
                    &format!("metadata for {}", removal.label),
                )?;
            }
            if (removal.stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                remove_snapshot_entry(
                    &parent.file,
                    removal.name.as_bytes(),
                    &removal.stat,
                    &removal.label,
                )?;
            } else {
                unlink_snapshot_entry(
                    &parent.file,
                    removal.name.as_bytes(),
                    &removal.stat,
                    &removal.label,
                )?;
            }
            // The candidate is gone. Account for it *before* touching its
            // companion record, so a companion unlink failure can never drop
            // a completed deletion from the report.
            report.freed_bytes += removal.bytes;
            match removal.counter {
                Counter::Objects => report.objects += 1,
                Counter::CachedArtifacts => report.cached_artifacts += 1,
                Counter::Stages => report.stages += 1,
                Counter::Forests => report.forests += 1,
                Counter::Backups => report.backups += 1,
            }
            if let Some((meta_name, meta_stat)) = &removal.companion {
                unlink_snapshot_entry(
                    &snapshot.dirs.meta.file,
                    meta_name.as_bytes(),
                    meta_stat,
                    &format!("metadata for {}", removal.label),
                )
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "{error}; the record meta/{meta_name} is orphaned and blocks the \
                             next sweep — restore the removed object or delete the stray record \
                             with `blanket gc --migrate-metadata`"
                        ),
                    )
                })?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if report != Report::default() {
                writeln!(
                    out,
                    "stopped after an error; deletions already completed: {} objects, {} cached \
                     artifacts, {} stages, {} forests, {} backups, {} freed",
                    report.objects,
                    report.cached_artifacts,
                    report.stages,
                    report.forests,
                    report.backups,
                    size(report.freed_bytes)
                )?;
            }
            return Err(io::Error::new(
                error.kind(),
                format!("{}: {error}", removal.label),
            ));
        }
    }
    for note in &plan.notes {
        writeln!(out, "skipped {note}")?;
    }
    Ok(report)
}

/// Compare a candidate with what the plan recorded, immediately before its
/// removal. A replaced name, or a name that changed file type, is an error.
fn confirm_unchanged(
    parent: &HeldDir,
    name: &[u8],
    expected: &libc::stat,
    label: &str,
) -> io::Result<()> {
    let actual = store::stat_at(parent.file.as_raw_fd(), name).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{label} disappeared from {} before removal", parent.label),
        )
    })?;
    if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!(
                "{label} was replaced after the deletion plan was made; nothing was removed for it"
            ),
        ));
    }
    if (actual.st_mode & libc::S_IFMT) != (expected.st_mode & libc::S_IFMT) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} changed file type after the deletion plan was made"),
        ));
    }
    Ok(())
}

fn report_plan<W: Write>(plan: &SweepPlan, out: &mut W) -> io::Result<()> {
    for removal in &plan.removals {
        writeln!(out, "would remove {}", removal.display)?;
    }
    for skip in &plan.skips {
        writeln!(out, "skipped: {skip}")?;
    }
    for note in &plan.notes {
        writeln!(out, "skipped: {note}")?;
    }
    Ok(())
}

fn open_held(path: &Path, label: &str) -> io::Result<HeldDir> {
    Ok(HeldDir {
        label: label.to_string(),
        file: open_directory(path, label)?,
    })
}

fn mtime_of(stat: &libc::stat) -> SystemTime {
    let secs = stat.st_mtime;
    let nanos = stat.st_mtime_nsec.clamp(0, 999_999_999) as u32;
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nanos)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0)
    }
}

fn age_at(now: SystemTime, stat: &libc::stat) -> Option<Duration> {
    now.duration_since(mtime_of(stat)).ok()
}

fn recent_at(now: SystemTime, stat: &libc::stat, window: Duration) -> bool {
    age_at(now, stat).is_some_and(|age| age < window)
}

fn older_than_at(now: SystemTime, stat: &libc::stat, age: Duration) -> bool {
    age_at(now, stat).is_some_and(|elapsed| elapsed > age)
}

fn file_size_of(stat: &libc::stat) -> u64 {
    stat.st_size.max(0) as u64
}

// ===========================================================================
// D.3 — automatic maintenance and legacy migration.
//
// Migration is additive maintenance, never a deletion permission. It runs
// under the exclusive activity lease and the publication lock, upgrades only
// records whose exact dependency set an adapter could reconstruct, and leaves
// everything else untouched. A store that still holds one unresolved record
// simply does not sweep — `validate` refuses on the legacy evidence itself.
// ===========================================================================

/// Upgrade provable legacy object metadata under an exclusive activity lease.
pub fn migrate_metadata<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    dry_run: bool,
    out: &mut W,
) -> io::Result<MigrationReport> {
    store.require_exclusive_activity(activity, "metadata migration")?;
    migrate_metadata_locked(store, activity, dry_run, out, false).map(|(report, _)| report)
}

/// The compatibility transition every eligible writable command runs before
/// it takes its long-lived shared token.
///
/// There is deliberately no shared preflight: a presence check is itself a
/// store read, and taking a shared token first would either have to be
/// dropped before the exclusive attempt anyway or become the lock upgrade
/// D.3 forbids. Going straight for the exclusive lease is the same decision
/// with one fewer window.
///
/// If another job owns the store the transition is announced as deferred and
/// the caller proceeds with ordinary non-destructive work; it never weakens
/// the sweep, which refuses on unresolved evidence regardless.
pub fn automatic_maintenance<W: Write>(store: &Store, out: &mut W) -> io::Result<MigrationReport> {
    let Some(activity) = store.try_activity_exclusive()? else {
        writeln!(
            out,
            "metadata maintenance deferred: a Blanket job is using this store"
        )?;
        return Ok(MigrationReport::default());
    };
    let report = match migrate_metadata_locked(store, &activity, false, out, true) {
        Ok((report, _)) => report,
        Err(error) => {
            // A malformed historical record must not stop a non-destructive
            // shared job from using an otherwise valid cached projection. The
            // destructive path stays fail-closed, and the explicit migration
            // command still surfaces this error.
            writeln!(
                out,
                "metadata maintenance deferred: {error}; retry after resolving the record"
            )?;
            return Ok(MigrationReport::default());
        }
    };
    if report.unresolved != 0 {
        writeln!(
            out,
            "metadata maintenance deferred: {} record(s) remain unresolved; GC stays blocked \
             until they are resolved",
            report.unresolved
        )?;
    }
    Ok(report)
}

fn migrate_metadata_locked<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    dry_run: bool,
    out: &mut W,
    automatic: bool,
) -> io::Result<(MigrationReport, BTreeMap<String, serde_json::Value>)> {
    store.require_exclusive_activity(activity, "metadata migration")?;
    let _publish = store.publish_lock()?;
    // Every migration input is re-read here, under the exclusive token. An
    // earlier probe is a hint about whether to bother, never a snapshot to
    // write from.
    let index = crate::objmeta::MetaIndex::read(store)?;
    let mut report = MigrationReport::default();
    if !index.has_legacy() {
        return Ok((report, BTreeMap::new()));
    }
    let cached = present_cache_entries(store)?;

    let mut proposals: BTreeMap<String, ObjectDeps> = BTreeMap::new();
    let mut unresolved: BTreeMap<String, String> = BTreeMap::new();
    for (id, record) in index.iter() {
        if record.evidence != crate::objmeta::Evidence::Legacy {
            continue;
        }
        match crate::objmeta::adapt(record, &index) {
            crate::objmeta::Adaptation::Proven(deps) => {
                proposals.insert(id.clone(), deps);
            }
            crate::objmeta::Adaptation::Unresolved(reason) => {
                unresolved.insert(id.clone(), reason);
            }
        }
    }

    // The containment guard. Migration may make retention more precise; it
    // may never make it narrower. A record whose certified closure would drop
    // something the pre-object-meta/2 reader retained stays legacy and keeps
    // its old protection, because certifying it would license a deletion the
    // evidence does not support.
    //
    // Dropping one record can change another's closure, so this runs to a
    // fixpoint. It is monotone — records only ever move to unresolved — so it
    // terminates in at most one round per legacy record.
    loop {
        let mut rejected = Vec::new();
        for (id, deps) in &proposals {
            let record = index.get(id).expect("proposals come from the index");
            if let Err(reason) =
                certification_covers_legacy_retention(record, deps, &proposals, &index, &cached)
            {
                rejected.push((id.clone(), format!("{}: {reason}", record.describe())));
            }
        }
        if rejected.is_empty() {
            break;
        }
        for (id, reason) in rejected {
            proposals.remove(&id);
            unresolved.insert(id, reason);
        }
    }

    let mut upgrades: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (id, deps) in &proposals {
        let record = index.get(id).expect("proposals come from the index");
        upgrades.insert(id.clone(), upgraded_record(record, deps)?);
    }
    for (id, reason) in &unresolved {
        writeln!(
            out,
            "metadata migration unresolved: object {id} — {reason}. The record keeps its \
             conservative legacy retention and no sweep will run until it is resolved."
        )?;
    }
    report.unresolved = unresolved.len();

    if dry_run {
        for id in upgrades.keys() {
            writeln!(out, "would migrate metadata for object {id}")?;
        }
        report.upgraded = upgrades.len();
    } else {
        // Only records actually written are reported as upgraded.
        for (id, value) in &upgrades {
            store.replace_metadata(id, &serde_json::to_vec_pretty(value)?)?;
            report.upgraded += 1;
        }
    }
    writeln!(
        out,
        "metadata migration: {} upgraded, {} unresolved{}",
        report.upgraded,
        report.unresolved,
        if dry_run {
            " (dry run)"
        } else if automatic && report.unresolved != 0 {
            " (deferred)"
        } else {
            ""
        }
    )?;
    Ok((report, upgrades))
}

/// Rewrite one legacy record as `object-meta/2`, preserving its identity, id,
/// creation timestamp and exceptions exactly as stored.
fn upgraded_record(
    record: &crate::objmeta::Record,
    deps: &ObjectDeps,
) -> io::Result<serde_json::Value> {
    let mut value = record.value.clone();
    let object = value.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("object {} metadata is not a JSON object", record.id),
        )
    })?;
    // The v1 `refs` array was a guess. It is dropped, never carried forward
    // and never treated as completeness evidence.
    object.remove("refs");
    object.insert("schema".into(), serde_json::json!("object-meta/2"));
    object.insert(
        "dependencies".into(),
        serde_json::Value::Array(
            deps.objects
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    object.insert(
        "cache_digests".into(),
        serde_json::Value::Array(
            deps.cache
                .iter()
                .map(|digest| serde_json::json!({"algo": digest.algo(), "hex": digest.hex()}))
                .collect(),
        ),
    );
    object.insert(
        "evidence".into(),
        serde_json::json!(format!(
            "adapted:{}@{}",
            record.identity.kind,
            crate::objmeta::adapter_version(&record.identity.kind)
        )),
    );
    if !record.had_legacy_refs {
        object.insert("legacy_retention".into(), serde_json::json!(true));
    }
    Ok(value)
}

/// Every `algo:hex` the cache actually holds. The containment guard needs to
/// tell a digest that names a retained file from one that names nothing: the
/// pre-D reader scanned identity inputs for any 64-hex token, and plenty of
/// those tokens — inner Hex checksums, manifest digests, content hashes —
/// were never cache addresses and so retained nothing at all.
fn present_cache_entries(store: &Store) -> io::Result<BTreeSet<String>> {
    let mut present = BTreeSet::new();
    for (algo, _) in CACHE_ALGORITHMS {
        let directory = store.root.join("cache").join(algo);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            present.insert(format!(
                "{algo}:{}",
                entry.file_name().to_string_lossy().to_ascii_lowercase()
            ));
        }
    }
    Ok(present)
}

/// The proposed post-migration dependency set for `id`: its own upgrade if it
/// has one, otherwise whatever it already proves.
fn effective_deps<'a>(
    id: &str,
    proposals: &'a BTreeMap<String, ObjectDeps>,
    index: &'a crate::objmeta::MetaIndex,
) -> Option<(&'a BTreeSet<String>, Vec<String>)> {
    if let Some(deps) = proposals.get(id) {
        return Some((
            &deps.objects,
            deps.cache
                .iter()
                .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                .collect(),
        ));
    }
    let record = index.get(id)?;
    Some((
        &record.dependencies,
        record
            .cache
            .iter()
            .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
            .collect(),
    ))
}

/// Does the proposed certification retain at least everything the pre-D
/// reader retained for this record?
///
/// The old sweep protected two things it found by scanning identity inputs:
/// any embedded object id, and any 64-hex token, which it treated as a
/// sha256 cache address. Both are checked against the *transitive* closure of
/// the proposed evidence, because retaining an object that itself retains the
/// artifact loses nothing — a Python environment now names the built wheel's
/// object, and that object names the sdist tarball the environment used to
/// name directly.
fn certification_covers_legacy_retention(
    record: &crate::objmeta::Record,
    deps: &ObjectDeps,
    proposals: &BTreeMap<String, ObjectDeps>,
    index: &crate::objmeta::MetaIndex,
    cached: &BTreeSet<String>,
) -> Result<(), String> {
    let identity_value = serde_json::to_value(&record.identity)
        .map_err(|error| format!("identity is not serializable: {error}"))?;
    let Some(inputs) = identity_value.get("inputs") else {
        return Ok(());
    };

    // Transitive closure of the proposed evidence.
    let mut reachable_objects: BTreeSet<String> = BTreeSet::new();
    let mut reachable_cache: BTreeSet<String> = deps
        .cache
        .iter()
        .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
        .collect();
    let mut queue: VecDeque<String> = deps.objects.iter().cloned().collect();
    while let Some(id) = queue.pop_front() {
        if !reachable_objects.insert(id.clone()) {
            continue;
        }
        if let Some((objects, cache)) = effective_deps(&id, proposals, index) {
            reachable_cache.extend(cache);
            for next in objects {
                if !reachable_objects.contains(next) {
                    queue.push_back(next.clone());
                }
            }
        }
    }

    let mut legacy_ids = BTreeSet::new();
    collect_object_ids_from_value(inputs, &mut legacy_ids);
    for id in &legacy_ids {
        if !reachable_objects.contains(id) {
            return Err(format!(
                "the pre-object-meta/2 reader retained object {id} through this record's identity \
                 inputs, and the reconstructed evidence does not reach it"
            ));
        }
    }
    for hash in legacy_cache_hashes(inputs) {
        let key = format!("sha256:{hash}");
        // A 64-hex token that addresses no cached file retained nothing, so
        // not carrying it forward narrows nothing.
        if !cached.contains(&key) {
            continue;
        }
        if !reachable_cache.contains(&key) {
            return Err(format!(
                "the pre-object-meta/2 reader retained cached artifact sha256:{hash} through this \
                 record's identity inputs, and the reconstructed evidence does not reach it"
            ));
        }
    }
    Ok(())
}

/// Object ids embedded anywhere in a legacy identity's inputs. This is the
/// pre-D `store::object_refs` scan, kept only to define what the old reader
/// retained; it is never used as evidence of completeness.
fn collect_object_ids_from_value(value: &serde_json::Value, ids: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(id) = store::object_id_token(text) {
                ids.insert(id);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_object_ids_from_value(value, ids);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_object_ids_from_value(value, ids);
            }
        }
        _ => {}
    }
}

/// The pre-D `gc::cache_hashes_from_value` heuristic: every 64-hex token in
/// the identity inputs, which the old sweep treated as a sha256 cache
/// address. Kept for the same reason as the scan above.
fn legacy_cache_hashes(value: &serde_json::Value) -> BTreeSet<String> {
    let mut hashes = BTreeSet::new();
    fn walk(value: &serde_json::Value, hashes: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::String(text) => {
                for token in text.split(|c: char| !c.is_ascii_hexdigit()) {
                    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
                        hashes.insert(token.to_ascii_lowercase());
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(value, hashes);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    walk(value, hashes);
                }
            }
            _ => {}
        }
    }
    walk(value, &mut hashes);
    hashes
}

fn validate_projection_namespace(path: &Path, name: &str) -> io::Result<()> {
    let stat = match fs::symlink_metadata(path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if stat.file_type().is_symlink() || !stat.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to sweep: {name} is not a real directory"),
        ));
    }
    Ok(())
}

/// Open a managed directory without following a symlink at its pathname. The
/// descriptor is held from the read phase through execution, so every
/// removal names an entry inside the directory that was actually inspected.
fn open_directory(path: &Path, label: &str) -> io::Result<fs::File> {
    let stat = fs::symlink_metadata(path)?;
    if stat.file_type().is_symlink() || !stat.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} is not a real directory", path.display()),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

fn remove_snapshot_entry(
    parent: &fs::File,
    name: &[u8],
    expected: &libc::stat,
    label: &str,
) -> io::Result<()> {
    if store::remove_tree_entry_if_same(parent.as_raw_fd(), name, expected)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("{label} changed during cleanup; retry later"),
        ))
    }
}

fn unlink_snapshot_entry(
    parent: &fs::File,
    name: &[u8],
    expected: &libc::stat,
    label: &str,
) -> io::Result<()> {
    if store::unlink_if_same(parent.as_raw_fd(), name, expected, 0)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("{label} changed during cleanup; retry later"),
        ))
    }
}

fn related(path: &Path, keep: &Path) -> bool {
    path == keep || path.starts_with(keep) || keep.starts_with(path)
}

#[cfg(test)]
fn recent(path: &Path, window: Duration) -> bool {
    modified(path)
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_some_and(|age| age < window)
}

fn keep_age(days: u64) -> Duration {
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
}

#[cfg(test)]
fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

fn tree_size(path: &Path) -> io::Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        let mut total = 0;
        for entry in fs::read_dir(path)? {
            total += tree_size(&entry?.path())?;
        }
        Ok(total)
    } else {
        Ok(metadata.len())
    }
}

fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

fn short_sha256(bytes: &[u8], hex_len: usize) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))[..hex_len].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::ActivityMode;
    use crate::types::Identity;
    use sha2::Digest;
    use std::collections::BTreeMap;

    struct TempStore {
        root: PathBuf,
    }

    impl TempStore {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "blanket-gc-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&root);
            for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            Self { root }
        }
        fn store(&self) -> Store {
            Store {
                root: self.root.canonicalize().unwrap(),
            }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = store::remove_tree(&self.root);
        }
    }

    fn test_identity(name: &str, input: Option<&str>) -> Identity {
        Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: input
                .map(|id| BTreeMap::from([("input".into(), id.into())]))
                .unwrap_or_default(),
        }
    }

    /// Publish a fully certified object whose only dependency is `input`.
    fn commit(store: &Store, name: &str, input: Option<&str>) -> String {
        let identity = test_identity(name, input);
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), name).unwrap();
        let mut deps = ObjectDeps::new();
        if let Some(input) = input {
            deps.object_id(input).unwrap();
        }
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();
        id
    }

    /// Publish an object and then rewrite its record into the pre-D shape, so
    /// the adapters and the containment guard have something real to work on.
    fn commit_legacy_fixture(store: &Store, identity: &Identity, refs: Option<&[&str]>) -> String {
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), &identity.name).unwrap();
        store
            .commit_with_deps(identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        let path = store.root.join("meta").join(format!("{id}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("schema");
        object.remove("dependencies");
        object.remove("cache_digests");
        object.remove("evidence");
        if let Some(refs) = refs {
            object.insert(
                "refs".into(),
                serde_json::json!(refs.iter().map(|r| r.to_string()).collect::<Vec<_>>()),
            );
        }
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        id
    }

    /// Read one record the way every phase reads it.
    fn record(store: &Store, id: &str) -> crate::objmeta::Record {
        crate::objmeta::read_record_at(&store.root.join("meta").join(format!("{id}.json"))).unwrap()
    }

    fn closure(project: &Path, object: &Path, extra: serde_json::Value) {
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        let body = serde_json::json!({
            "env_object": object.display().to_string(),
            "extra": extra,
        });
        fs::write(
            project.join(".blanket/closures/python.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// Materialise a verified cache artifact so a legacy fixture can name it.
    fn cached_artifact(store: &Store, hex: &str) {
        let path = store.root.join("cache/sha256").join(hex);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"artifact").unwrap();
    }

    /// `object-meta/2` records carry an evidence marker saying how their
    /// dependency set was established. A record without one, or with a
    /// marker nothing produced, is not usable evidence for a deletion.
    #[test]
    fn a_certified_record_without_a_usable_evidence_marker_is_refused() {
        let temp = TempStore::new("evidence-marker");
        let store = temp.store();
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::new(),
        };
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "cpython").unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        let meta_path = store.root.join("meta").join(format!("{id}.json"));

        for (label, marker) in [
            ("missing", None),
            ("invented", Some(serde_json::json!("assumed"))),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
            let object = value.as_object_mut().unwrap();
            object.remove("refs");
            object.insert("schema".into(), serde_json::json!("object-meta/2"));
            object.insert("dependencies".into(), serde_json::json!([]));
            object.insert("cache_digests".into(), serde_json::json!([]));
            match marker {
                Some(marker) => {
                    object.insert("evidence".into(), marker);
                }
                None => {
                    object.remove("evidence");
                }
            }
            fs::write(&meta_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            let error = crate::objmeta::read_record_at(&meta_path).unwrap_err();
            assert!(
                error.to_string().contains("evidence"),
                "{label} evidence marker was accepted: {error}"
            );
        }
    }

    /// A BEAM toolchain fixture plus the fingerprint a `hex-deps` record
    /// would use to name it. The fingerprint is not an object id, so the
    /// adapter has to find the object by recomputing it — which is exactly
    /// the indirect-reference case D.3 calls out.
    fn beam_fixture(store: &Store) -> (String, String) {
        let otp = "1".repeat(64);
        let elixir = "2".repeat(64);
        let hex_archive = "3".repeat(128);
        let rebar3 = "4".repeat(128);
        let identity = Identity {
            kind: "beam".into(),
            name: "beam".into(),
            version: "29.0.5-elixir1.20.4".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "beam-toolchain/1".into()),
                ("otp_sha256".into(), otp.clone()),
                ("elixir_sha256".into(), elixir.clone()),
                ("hex_sha512".into(), hex_archive.clone()),
                ("rebar3_sha512".into(), rebar3.clone()),
                ("versions".into(), "hex2.5.1:rebar3.25.1".into()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let fingerprint =
            crate::elixir::fingerprint_of_joined(&format!("{otp}:{elixir}:{hex_archive}:{rebar3}"));
        cached_artifact(store, &otp);
        cached_artifact(store, &elixir);
        let id = commit_legacy_fixture(store, &identity, Some(&[]));
        (id, fingerprint)
    }

    fn hex_deps_identity(fingerprint: &str, outer: &str, inner: &str) -> Identity {
        Identity {
            kind: "hex-deps".into(),
            name: "deps".into(),
            version: "1".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "hex-deps/1".into()),
                ("beam".into(), fingerprint.to_string()),
                (
                    "dep:jason".into(),
                    format!("jason@1.4.4:{outer}:{inner}:mix"),
                ),
            ]),
        }
    }

    /// The containment guard. A migration may make retention more precise,
    /// never narrower.
    ///
    /// A `hex-deps` record names two digests per dependency: the outer
    /// tarball, which is a real cache address, and the inner content
    /// checksum, which normally is not. The pre-D reader could not tell them
    /// apart and retained both. If a file happens to sit at the inner
    /// checksum's cache address, certifying only the outer digest would make
    /// the sweep free a file the old reader kept — so the record must stay
    /// legacy instead.
    #[test]
    fn migration_refuses_to_certify_less_than_the_legacy_reader_retained() {
        let temp = TempStore::new("narrow-migration");
        let store = temp.store();
        let (_beam, fingerprint) = beam_fixture(&store);
        let outer = "a".repeat(64);
        let inner = "b".repeat(64);
        cached_artifact(&store, &outer);
        // The artifact the old reader retained through the inner checksum.
        cached_artifact(&store, &inner);
        let identity = hex_deps_identity(&fingerprint, &outer, &inner);
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            report.unresolved, 1,
            "the narrower certification was accepted: {text}"
        );
        assert!(text.contains("kind hex-deps, schema hex-deps/1"), "{text}");
        assert!(text.contains(&inner), "the reason names no digest: {text}");
        assert!(
            record(&store, &id).evidence == crate::objmeta::Evidence::Legacy,
            "the record was rewritten despite the narrowing"
        );
        drop(activity);
    }

    /// The mutation check for the guard above: with nothing cached at the
    /// inner checksum's address, the old reader retained nothing there, the
    /// certification narrows nothing, and the same record migrates. A guard
    /// that simply refused every `hex-deps` record would fail this test.
    #[test]
    fn migration_certifies_a_record_whose_evidence_it_can_account_for() {
        let temp = TempStore::new("wide-migration");
        let store = temp.store();
        let (beam, fingerprint) = beam_fixture(&store);
        let outer = "a".repeat(64);
        let inner = "b".repeat(64);
        cached_artifact(&store, &outer);
        let identity = hex_deps_identity(&fingerprint, &outer, &inner);
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        assert_eq!(
            (report.upgraded, report.unresolved),
            (2, 0),
            "{}",
            String::from_utf8_lossy(&out)
        );
        let upgraded = record(&store, &id);
        assert_eq!(
            upgraded.evidence,
            crate::objmeta::Evidence::Adapted("hex-deps@1".into())
        );
        assert_eq!(upgraded.dependencies, BTreeSet::from([beam]));
        assert_eq!(
            upgraded
                .cache
                .iter()
                .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                .collect::<Vec<_>>(),
            vec![format!("sha256:{outer}")]
        );
        drop(activity);
    }

    /// Unresolved records do not cancel the upgrades that were proven, and
    /// the announced count is the number of records actually written.
    /// The store still refuses to sweep while one legacy record remains.
    #[test]
    fn a_cancelled_migration_does_not_report_upgrades_it_never_wrote() {
        let temp = TempStore::new("cancelled-migration");
        let store = temp.store();
        let digest = "e".repeat(64);
        cached_artifact(&store, &digest);
        let good = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let good_id = commit_legacy_fixture(&store, &good, Some(&[]));
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        let unknown_id = commit_legacy_fixture(&store, &unknown, Some(&[]));

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (1, 1), "{text}");
        assert_eq!(
            record(&store, &good_id).evidence,
            crate::objmeta::Evidence::Adapted("cpython@1".into())
        );
        assert_eq!(
            record(&store, &unknown_id).evidence,
            crate::objmeta::Evidence::Legacy,
            "an unknown kind was certified"
        );
        assert!(text.contains("kind not-a-known-kind"), "{text}");
        drop(activity);

        // One legacy record is enough to keep every sweep closed.
        let project = temp.root.join("project");
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        store.register_root(&project).unwrap();
        let mut out = Vec::new();
        let error = collect(&store, Options::default(), &mut out).unwrap_err();
        assert!(
            error.to_string().contains("uncertified legacy record"),
            "{error}"
        );
    }

    fn age(path: &Path) {
        let old = SystemTime::now()
            .checked_sub(Duration::from_secs(2 * 24 * 60 * 60))
            .unwrap();
        fs::File::open(path).unwrap().set_modified(old).unwrap();
    }

    #[test]
    fn liveness_walks_closure_and_transitive_refs() {
        let temp = TempStore::new("liveness");
        let store = temp.store();
        let child = commit(&store, "child", None);
        let parent = commit(&store, "parent", Some(&child));
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(
            &project,
            &store.object_path(&parent),
            serde_json::json!({"id": parent}),
        );
        store.register_root(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(store.object_path(&dead).is_dir());
        assert!(String::from_utf8(output).unwrap().contains(&dead));
    }

    #[test]
    fn collect_legacy_requires_explicit_opt_in() {
        let temp = TempStore::new("keep-days");
        let store = temp.store();
        let id = commit(&store, "new", None);
        let artifact = "a".repeat(64);
        let artifact_path = store.cache_path("sha256", &artifact);
        fs::write(&artifact_path, b"artifact").unwrap();
        age(&artifact_path);
        // An object published before the roots registry existed: certified,
        // but still carrying the opt-in retention boundary migration
        // preserves for a record that never had reference metadata.
        let meta_path = store.root.join("meta").join(format!("{id}.json"));
        let mut meta: serde_json::Value =
            serde_json::from_reader(fs::File::open(&meta_path).unwrap()).unwrap();
        let object = meta.as_object_mut().unwrap();
        object.insert("evidence".into(), serde_json::json!("adapted:test@1"));
        object.insert("legacy_retention".into(), serde_json::json!(true));
        fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        store.register_root(&project).unwrap();
        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 30,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 0);
        assert_eq!(report.cached_artifacts, 0);
        assert!(store.object_path(&id).exists());
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: true,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert_eq!(report.cached_artifacts, 1);
        assert!(!store.object_path(&id).exists());
        assert!(!artifact_path.exists());
    }

    #[test]
    fn dry_run_reports_sizes_without_removing() {
        let temp = TempStore::new("dry-run");
        let store = temp.store();
        let id = commit(&store, "dry", None);
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        store.register_root(&project).unwrap();
        let orphan = commit(&store, "orphan", None);
        age(&store.object_path(&orphan));
        let mut output = Vec::new();
        collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("would remove object"));
        assert!(output.contains("B)"));
        assert!(store.object_path(&orphan).exists());
    }

    #[test]
    fn node_forest_v2_workspace_kept_when_root_link_is_missing() {
        let temp = TempStore::new("forest-v2");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        let project = project.canonicalize().unwrap();
        let home = store.root.parent().unwrap();
        let project_key =
            &hex::encode(sha2::Sha256::digest(project.to_string_lossy().as_bytes()))[..32];
        let projection_id = "a".repeat(32);
        let forest = home.join("forests").join(project_key).join(&projection_id);
        let workspace_forest = forest.join("workspaces/packages%2Flib/node_modules");
        fs::create_dir_all(&workspace_forest).unwrap();
        fs::create_dir_all(project.join("packages/lib")).unwrap();
        std::os::unix::fs::symlink(&workspace_forest, project.join("packages/lib/node_modules"))
            .unwrap();
        fs::write(
            project.join(".blanket/closures/node.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "node",
                "body": {
                    "projection_schema": "node-forest/2",
                    "projection_id": projection_id,
                    "workspaces": ["packages/lib"]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        store.register_root(&project).unwrap();
        age(&forest);

        let mut output = Vec::new();
        let _report = collect(
            &store,
            Options {
                project: true,
                keep_days: 0,
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        assert!(
            workspace_forest.is_dir(),
            "{}",
            String::from_utf8_lossy(&output)
        );
    }

    #[test]
    fn root2_keeps_objects_after_the_project_disappears() {
        let temp = TempStore::new("root2-moved-project");
        let store = temp.store();
        let protected = commit(&store, "root2-protected", None);
        let dead = commit(&store, "root2-dead", None);
        age(&store.object_path(&protected));
        age(&store.object_path(&dead));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let record = store::RootRecord {
            key: store::Store::root_key(&project).unwrap(),
            project_path: project.clone(),
            objects: BTreeSet::from([protected.clone()]),
            projections: BTreeSet::new(),
            updated: 1,
        };
        store.register_root_record(record).unwrap();
        fs::remove_dir_all(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(store.object_path(&protected).exists());
        assert!(!store.object_path(&dead).exists());
    }

    #[test]
    fn retained_object_keeps_old_dependency() {
        let temp = TempStore::new("retained-dependency");
        let store = temp.store();
        let child = commit(&store, "old-child", None);
        age(&store.object_path(&child));
        let parent = commit(&store, "fresh-parent", Some(&child));
        let project = temp.root.join("project");
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        store.register_root(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 0);
        assert!(store.object_path(&parent).exists());
        assert!(store.object_path(&child).exists());
    }

    #[test]
    fn publication_refreshes_an_old_stage_mtime() {
        let temp = TempStore::new("publication-mtime");
        let store = temp.store();
        let identity = Identity {
            kind: "test".into(),
            name: "published".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), b"payload").unwrap();
        age(&staged);
        let id = identity.object_id();
        store
            .commit_with_deps(&identity, &staged, &[], &store::ObjectDeps::new())
            .unwrap();
        assert!(recent(&store.object_path(&id), ACTIVE_WINDOW));
    }

    /// A registered project whose directory disappears must stop the sweep
    /// and keep its record: with only a pathname record, GC cannot know what
    /// the project still protects.
    #[test]
    fn missing_project_blocks_sweep_and_preserves_record() {
        let temp = TempStore::new("missing-project");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(&project).unwrap();

        for dry_run in [false, true] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    keep_days: 0,
                    project: false,
                    collect_legacy: false,
                    forgotten: Vec::new(),
                },
                &mut output,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("refusing to sweep"), "{message}");
            assert!(message.contains(&entry.key), "{message}");
            assert!(message.contains("--forget"), "{message}");
        }
        assert!(store.object_path(&id).is_dir(), "sweep deleted the object");
        assert!(
            store
                .roots()
                .unwrap()
                .iter()
                .any(|root| root.key == entry.key),
            "sweep removed the record"
        );

        // Forgetting the record is the explicit way out; the next sweep then
        // collects the object nobody protects any more.
        store.forget_root(&entry.key).unwrap();
        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(!store.object_path(&id).exists());
    }

    #[test]
    fn dry_run_forget_ignores_only_the_requested_root_and_writes_nothing() {
        let temp = TempStore::new("dry-forget");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                forgotten: vec![entry.key.clone()],
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("would remove object"));
        assert!(store.object_path(&id).exists());
        assert!(store.lookup_root(&entry.key).is_ok());
    }

    #[test]
    fn missing_closures_directory_blocks_sweep() {
        let temp = TempStore::new("missing-closures");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        store.register_root(&project).unwrap();
        fs::remove_dir_all(project.join(".blanket/closures")).unwrap();

        let mut output = Vec::new();
        let error = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("closures"), "{error}");
        assert!(store.object_path(&id).is_dir());
    }

    /// An I/O error other than a clean miss (here: a symlink loop where the
    /// project used to be) must stop the sweep with the underlying error
    /// named, never silently delete the record.
    #[test]
    fn io_error_on_project_path_blocks_sweep() {
        let temp = TempStore::new("io-error");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(&project).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&project, &project).unwrap();

        let mut output = Vec::new();
        let error = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("refusing to sweep"), "{message}");
        assert!(message.contains(&entry.key), "{message}");
        assert!(store.object_path(&id).is_dir());
        assert!(store.roots().unwrap().len() == 1, "record was removed");
    }

    #[test]
    fn forget_rejects_unknown_and_malformed_keys() {
        let temp = TempStore::new("forget-keys");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(
            &project,
            &store.object_path(&commit(&store, "x", None)),
            serde_json::json!({}),
        );
        store.register_root(&project).unwrap();

        let error = store.forget_root(&"a".repeat(40)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let error = store.forget_root("not-a-key").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = store.forget_root(&"g".repeat(40)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(store.roots().unwrap().len(), 1);
    }

    // =======================================================================
    // D.10 acceptance tests.
    //
    // Each name below is one of the failure modes the GC-safety brief lists.
    // The x-cleanup pair lives with the code it covers, in `xrun::tests`.
    // =======================================================================

    /// Register `project` as a durable root/2 record naming `objects`.
    fn register_objects(store: &Store, project: &Path, objects: &[&str]) -> String {
        fs::create_dir_all(project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = store::Store::root_key(&project).unwrap();
        store
            .register_root_record(store::RootRecord {
                key: key.clone(),
                project_path: project,
                objects: objects.iter().map(|id| id.to_string()).collect(),
                projections: BTreeSet::new(),
                updated: 1,
            })
            .unwrap();
        key
    }

    /// Rewrite one record's JSON in place.
    fn edit_record(
        store: &Store,
        id: &str,
        edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) {
        let path = store.root.join("meta").join(format!("{id}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(value.as_object_mut().unwrap());
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn sweep(store: &Store, options: Options) -> (io::Result<Report>, String) {
        let mut out = Vec::new();
        let result = collect(store, options, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    /// Run the phases by hand so a test can mutate the store between the
    /// plan and its execution.
    fn planned<'a>(
        store: &Store,
        activity: &StoreActivity,
        options: &Options,
        snapshot: &'a mut Option<Snapshot>,
    ) -> SweepPlan {
        let mut out = Vec::new();
        *snapshot = Some(read(store, activity, options, &BTreeMap::new(), &mut out).unwrap());
        let taken = snapshot.as_ref().unwrap();
        let validated = validate(taken, options).unwrap();
        plan(&validated, options).unwrap()
    }

    #[test]
    fn shared_dependency_survives_forgetting_one_of_two_projects() {
        let temp = TempStore::new("shared-dep-one");
        let store = temp.store();
        let shared = commit(&store, "shared", None);
        let first = commit(&store, "first", Some(&shared));
        let second = commit(&store, "second", Some(&shared));
        for id in [&shared, &first, &second] {
            age(&store.object_path(id));
        }
        let one = register_objects(&store, &temp.root.join("one"), &[&first]);
        register_objects(&store, &temp.root.join("two"), &[&second]);
        store.forget_root(&one).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            store.object_path(&shared).is_dir(),
            "the surviving project's dependency was collected: {text}"
        );
        assert!(store.object_path(&second).is_dir(), "{text}");
        assert!(!store.object_path(&first).exists(), "{text}");
    }

    #[test]
    fn after_forgetting_both_the_shared_dependency_is_collectible_when_age_allows() {
        let temp = TempStore::new("shared-dep-both");
        let store = temp.store();
        let shared = commit(&store, "shared", None);
        let first = commit(&store, "first", Some(&shared));
        let second = commit(&store, "second", Some(&shared));
        for id in [&shared, &first, &second] {
            age(&store.object_path(id));
        }
        let one = register_objects(&store, &temp.root.join("one"), &[&first]);
        let two = register_objects(&store, &temp.root.join("two"), &[&second]);
        store.forget_root(&one).unwrap();
        store.forget_root(&two).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 3, "{text}");
        assert!(!store.object_path(&shared).exists(), "{text}");
    }

    /// Corrupt the *last* root record: nothing earlier may already be gone.
    #[test]
    fn corrupt_late_root_deletes_nothing_earlier() {
        let temp = TempStore::new("corrupt-late-root");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let mut keys = Vec::new();
        for name in ["alpha", "omega"] {
            keys.push(register_objects(&store, &temp.root.join(name), &[]));
        }
        keys.sort();
        let last = keys.last().unwrap();
        fs::write(store.root.join("roots").join(last), b"{ not json").unwrap();

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(
            result.is_err(),
            "a corrupt root record did not stop the sweep: {text}"
        );
        assert!(
            store.object_path(&dead).is_dir(),
            "an earlier candidate was deleted before the corrupt record was read: {text}"
        );
    }

    /// Corrupt the metadata of an object that sorts after a deletable one.
    #[test]
    fn corrupt_late_metadata_deletes_nothing_earlier() {
        let temp = TempStore::new("corrupt-late-meta");
        let store = temp.store();
        let mut ids = vec![commit(&store, "one", None), commit(&store, "two", None)];
        ids.sort();
        for id in &ids {
            age(&store.object_path(id));
        }
        register_objects(&store, &temp.root.join("project"), &[]);
        let last = ids.last().unwrap().clone();
        fs::write(
            store.root.join("meta").join(format!("{last}.json")),
            b"{ not json",
        )
        .unwrap();

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "{text}");
        for id in &ids {
            assert!(
                store.object_path(id).is_dir(),
                "a candidate was deleted before the corrupt record was read: {text}"
            );
        }
    }

    #[test]
    fn missing_transitive_metadata_aborts_the_sweep() {
        let temp = TempStore::new("missing-transitive");
        let store = temp.store();
        let child = commit(&store, "child", None);
        let parent = commit(&store, "parent", Some(&child));
        register_objects(&store, &temp.root.join("project"), &[&parent]);
        fs::remove_file(store.root.join("meta").join(format!("{child}.json"))).unwrap();

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(&child),
            "the missing id is not named: {error}"
        );
        assert!(store.object_path(&parent).is_dir());
        assert!(store.object_path(&child).is_dir());
    }

    #[test]
    fn dependency_cycle_terminates_and_retains_both() {
        let temp = TempStore::new("cycle");
        let store = temp.store();
        let one = commit(&store, "one", None);
        let two = commit(&store, "two", None);
        // Dependencies live in metadata, not in the identity hash, so a
        // cycle is representable even though object ids are input-addressed.
        edit_record(&store, &one, |record| {
            record.insert("dependencies".into(), serde_json::json!([two]));
        });
        edit_record(&store, &two, |record| {
            record.insert("dependencies".into(), serde_json::json!([one]));
        });
        age(&store.object_path(&one));
        age(&store.object_path(&two));
        register_objects(&store, &temp.root.join("project"), &[&one]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 0, "{text}");
        assert!(store.object_path(&one).is_dir());
        assert!(store.object_path(&two).is_dir());
    }

    #[test]
    fn unknown_metadata_schema_blocks_destructive_gc() {
        let temp = TempStore::new("unknown-schema");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        let odd = commit(&store, "odd", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        edit_record(&store, &odd, |record| {
            record.insert("schema".into(), serde_json::json!("object-meta/3"));
        });

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("unknown metadata schema object-meta/3"),
            "{error}"
        );
        assert!(store.object_path(&dead).is_dir(), "a sweep ran anyway");
    }

    #[test]
    fn invalid_reference_in_metadata_is_an_error() {
        let temp = TempStore::new("invalid-reference");
        let store = temp.store();
        let id = commit(&store, "broken", None);
        register_objects(&store, &temp.root.join("project"), &[]);
        edit_record(&store, &id, |record| {
            record.insert(
                "dependencies".into(),
                serde_json::json!(["not-an-object-id"]),
            );
        });

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("malformed or duplicate dependency"),
            "{error}"
        );
    }

    #[test]
    fn traversal_string_in_a_reference_is_rejected() {
        let temp = TempStore::new("traversal-reference");
        let store = temp.store();
        let id = commit(&store, "broken", None);
        register_objects(&store, &temp.root.join("project"), &[]);
        for traversal in [
            "../../../etc/passwd",
            &format!("{}-../escape", "a".repeat(40)),
        ] {
            edit_record(&store, &id, |record| {
                record.insert("dependencies".into(), serde_json::json!([traversal]));
            });
            let (result, _) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("malformed or duplicate dependency"),
                "{traversal:?} was accepted: {error}"
            );
        }
    }

    #[test]
    fn symlink_replacement_of_a_candidate_stops_that_deletion() {
        let temp = TempStore::new("symlink-replacement");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);
        assert_eq!(sweep_plan.removals.len(), 1);

        // Replace the planned candidate with a symlink to somewhere else.
        let elsewhere = temp.root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        store::remove_tree(&store.object_path(&dead)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.object_path(&dead)).unwrap();

        let mut out = Vec::new();
        let error = execute(
            &sweep_plan,
            held.as_ref().unwrap(),
            &store,
            &activity,
            &mut out,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("was replaced"),
            "the replacement was not detected: {error}"
        );
        assert!(
            elsewhere.is_dir(),
            "the symlink target was followed and deleted"
        );
        drop(activity);
    }

    #[test]
    fn type_change_of_a_candidate_stops_that_deletion() {
        let temp = TempStore::new("type-change");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);

        store::remove_tree(&store.object_path(&dead)).unwrap();
        fs::write(store.object_path(&dead), b"now a file").unwrap();

        let mut out = Vec::new();
        let error = execute(
            &sweep_plan,
            held.as_ref().unwrap(),
            &store,
            &activity,
            &mut out,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("was replaced") || text.contains("changed file type"),
            "a type change was not detected: {text}"
        );
        assert!(
            store.object_path(&dead).is_file(),
            "the replacement was deleted"
        );
        drop(activity);
    }

    #[test]
    fn partial_execution_error_reports_completed_deletions_honestly() {
        let temp = TempStore::new("partial-execution");
        let store = temp.store();
        let mut dead: Vec<String> = (0..2)
            .map(|index| commit(&store, &format!("dead{index}"), None))
            .collect();
        dead.sort();
        for id in &dead {
            age(&store.object_path(id));
        }
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);
        assert_eq!(sweep_plan.removals.len(), 2);
        // Break whichever candidate the plan removes second.
        let second = sweep_plan.removals[1].name.to_string_lossy().into_owned();
        store::remove_tree(&store.object_path(&second)).unwrap();
        fs::write(store.object_path(&second), b"replaced").unwrap();

        let mut out = Vec::new();
        let error = execute(
            &sweep_plan,
            held.as_ref().unwrap(),
            &store,
            &activity,
            &mut out,
        )
        .unwrap_err();
        let text = String::from_utf8(out).unwrap();
        assert!(error.to_string().contains(&second), "{error}");
        assert!(
            text.contains("deletions already completed: 1 objects"),
            "the completed deletion was not reported: {text}"
        );
        let first = sweep_plan.removals[0].name.to_string_lossy().into_owned();
        assert!(
            !store.object_path(&first).exists(),
            "the first deletion was rolled back"
        );
        drop(activity);
    }

    /// A crashed registry write leaves `.<key>.tmp.<pid>.<seq>` residue. The
    /// read phase must leave it exactly as found — including its containing
    /// directory's mtime — during a dry run.
    #[test]
    fn dry_run_leaves_crashed_registry_temporaries() {
        let temp = TempStore::new("dry-run-temp");
        let store = temp.store();
        register_objects(&store, &temp.root.join("project"), &[]);
        let key =
            store::Store::root_key(&temp.root.join("project").canonicalize().unwrap()).unwrap();
        let path = store.root.join("roots").join(format!(".{key}.tmp.1234.0"));
        fs::write(&path, b"crash between registry write and rename").unwrap();
        let before_roots = fs::metadata(store.root.join("roots"))
            .unwrap()
            .modified()
            .unwrap();

        let (result, text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..Options::default()
            },
        );
        result.unwrap();
        assert!(
            path.is_file(),
            "the read phase deleted a registry temporary during --dry-run: {text}"
        );
        assert_eq!(
            fs::metadata(store.root.join("roots"))
                .unwrap()
                .modified()
                .unwrap(),
            before_roots,
            "enumeration refreshed the roots directory timestamp"
        );

        // A real sweep with nothing else to do still cleans the residue,
        // under the exclusive lease, after validation.
        let (result, _) = sweep(&store, Options::default());
        result.unwrap();
        assert!(
            !path.exists(),
            "the execute phase did not clear the crashed temporary"
        );
    }

    /// A sweep that fails validation must not clean crash residue either:
    /// the zero-deletions promise covers every file the read phase saw,
    /// including temporaries.
    #[test]
    fn failed_validation_leaves_crashed_registry_temporaries() {
        let temp = TempStore::new("failed-validation-temp");
        let store = temp.store();
        register_objects(&store, &temp.root.join("project"), &[]);
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        commit_legacy_fixture(&store, &unknown, Some(&[]));
        let key =
            store::Store::root_key(&temp.root.join("project").canonicalize().unwrap()).unwrap();
        let path = store.root.join("roots").join(format!(".{key}.tmp.1234.0"));
        fs::write(&path, b"crash residue").unwrap();

        let (result, _) = sweep(&store, Options::default());
        assert!(result.is_err(), "a legacy record did not stop the sweep");
        assert!(
            path.is_file(),
            "a failed validation deleted a registry temporary"
        );
    }

    /// The object removal succeeds, the companion metadata unlink fails, and
    /// the sweep must still report the completed deletion — and name the
    /// recovery path for the orphaned record, which would otherwise wedge
    /// every future sweep.
    #[test]
    fn object_removed_but_metadata_unlink_fails_is_reported() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = TempStore::new("meta-unlink-fails");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);
        assert_eq!(sweep_plan.removals.len(), 1);

        let meta_dir = store.root.join("meta");
        let mut perms = fs::metadata(&meta_dir).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o555);
        fs::set_permissions(&meta_dir, perms).unwrap();
        let outcome = (|| {
            let mut out = Vec::new();
            let result = execute(
                &sweep_plan,
                held.as_ref().unwrap(),
                &store,
                &activity,
                &mut out,
            );
            (result, String::from_utf8(out).unwrap())
        })();
        // Restore before asserting, so a failed assertion cannot leave the
        // fixture store uncleanable.
        let mut perms = fs::metadata(&meta_dir).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&meta_dir, perms).unwrap();
        let (result, text) = outcome;

        let error = result.unwrap_err().to_string();
        assert!(
            !store.object_path(&dead).exists(),
            "the object was not removed: {error}"
        );
        assert!(
            text.contains("deletions already completed: 1 objects"),
            "the completed object deletion was not reported: {text}"
        );
        assert!(
            error.contains("orphaned") && error.contains("--migrate-metadata"),
            "the recovery path is not named: {error}"
        );

        // The leftover record does wedge the next sweep, but the named
        // recovery path clears it.
        drop(activity);
        let (result, _) = sweep(&store, Options::default());
        assert!(result.is_err(), "a stray record did not block the sweep");
        let meta_path = meta_dir.join(format!("{dead}.json"));
        fs::remove_file(&meta_path).unwrap();
        let (result, _) = sweep(&store, Options::default());
        result.unwrap();
    }

    /// A legacy store: the dry run must adapt in memory, migrate nothing on
    /// disk, remove no root, and refresh no timestamp.
    #[test]
    fn dry_run_removes_no_root_migrates_nothing_and_refreshes_no_timestamp() {
        let temp = TempStore::new("dry-run-immutable");
        let store = temp.store();
        let digest = "1".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));
        age(&store.object_path(&id));
        let key = register_objects(&store, &temp.root.join("project"), &[&id]);
        let meta_path = store.root.join("meta").join(format!("{id}.json"));
        let before_meta = fs::read(&meta_path).unwrap();
        let before_object = fs::metadata(store.object_path(&id))
            .unwrap()
            .modified()
            .unwrap();
        let before_roots = fs::read(store.root.join("roots").join(&key)).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(text.contains("would migrate metadata"), "{text}");
        assert_eq!(
            fs::read(&meta_path).unwrap(),
            before_meta,
            "a dry run wrote a record"
        );
        assert_eq!(
            fs::metadata(store.object_path(&id))
                .unwrap()
                .modified()
                .unwrap(),
            before_object,
            "a dry run refreshed an object timestamp"
        );
        assert_eq!(
            fs::read(store.root.join("roots").join(&key)).unwrap(),
            before_roots,
            "a dry run changed a root record"
        );
        assert_eq!(
            record(&store, &id).evidence,
            crate::objmeta::Evidence::Legacy
        );
    }

    /// Build a legacy store with one live object, one dead object and one
    /// unreferenced cached artifact.
    fn legacy_store(temp: &TempStore) -> (Store, String, String) {
        let store = temp.store();
        let live_digest = "1".repeat(64);
        let dead_digest = "2".repeat(64);
        cached_artifact(&store, &live_digest);
        cached_artifact(&store, &dead_digest);
        age(&store.cache_path("sha256", &live_digest));
        age(&store.cache_path("sha256", &dead_digest));
        let make = |version: &str, digest: &str| Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: version.into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.to_string()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let live = commit_legacy_fixture(&store, &make("3.11.9", &live_digest), Some(&[]));
        let dead = commit_legacy_fixture(&store, &make("3.12.7", &dead_digest), Some(&[]));
        age(&store.object_path(&live));
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[&live]);
        (store, live, dead)
    }

    #[test]
    fn dry_run_and_real_sweep_produce_the_same_plan() {
        let temp = TempStore::new("same-plan");
        let (store, live, dead) = legacy_store(&temp);
        let options = || Options {
            keep_days: 0,
            ..Options::default()
        };

        let (preview, text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..options()
            },
        );
        let preview = preview.unwrap();
        assert!(
            text.contains(&dead),
            "the dead object was not previewed: {text}"
        );
        assert!(!text.contains(&format!(
            "would remove object {}",
            store.object_path(&live).display()
        )));

        let (real, real_text) = sweep(&store, options());
        let real = real.unwrap();
        assert_eq!(preview, real, "preview {text}\nreal {real_text}");
        assert!(!store.object_path(&dead).exists(), "{real_text}");
        assert!(store.object_path(&live).is_dir(), "{real_text}");
    }

    /// The same property, stated the way D.10 names it: the dry run's
    /// in-memory adaptation and the real sweep's published one must agree.
    #[test]
    fn dry_run_adapts_in_memory_and_matches_real_plan_at_the_same_time() {
        let temp = TempStore::new("adapt-in-memory");
        let (store, _live, dead) = legacy_store(&temp);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };

        let (preview, preview_text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..options.clone()
            },
        );
        let preview = preview.unwrap();
        // Nothing was published, so the store is still legacy...
        assert_eq!(
            record(&store, &dead).evidence,
            crate::objmeta::Evidence::Legacy
        );
        // ...yet the preview planned a deletion, which is only possible if
        // the adaptation happened in memory.
        assert_eq!(preview.objects, 1, "{preview_text}");

        let (real, real_text) = sweep(&store, options);
        assert_eq!(preview, real.unwrap(), "{preview_text}\n{real_text}");
    }

    #[test]
    fn collect_legacy_cannot_override_incomplete_evidence() {
        let temp = TempStore::new("collect-legacy-override");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        commit_legacy_fixture(&store, &unknown, Some(&[]));
        register_objects(&store, &temp.root.join("project"), &[]);

        for collect_legacy in [false, true] {
            let (result, text) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    collect_legacy,
                    ..Options::default()
                },
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("uncertified legacy record"),
                "--collect-legacy={collect_legacy} authorized a sweep: {error} {text}"
            );
            assert!(store.object_path(&dead).is_dir());
        }
    }

    #[test]
    fn legacy_metadata_with_an_adapter_migrates_and_validates_the_id() {
        let temp = TempStore::new("adapter-validates-id");
        let store = temp.store();
        let digest = "3".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (1, 0));
        let upgraded = record(&store, &id);
        assert_eq!(
            upgraded.evidence,
            crate::objmeta::Evidence::Adapted("cpython@1".into())
        );
        assert_eq!(
            upgraded
                .cache
                .iter()
                .map(|d| d.hex().to_string())
                .collect::<Vec<_>>(),
            vec![digest]
        );
        drop(activity);

        // The id/identity relationship is validated on every read: a record
        // whose identity hashes to something else is refused, not adapted.
        edit_record(&store, &id, |record| {
            record.insert(
                "identity".into(),
                serde_json::json!({
                    "kind": "cpython",
                    "name": "cpython",
                    "version": "9.9.9",
                    "inputs": {},
                }),
            );
        });
        let error =
            crate::objmeta::read_record_at(&store.root.join("meta").join(format!("{id}.json")))
                .unwrap_err()
                .to_string();
        assert!(error.contains("hashes to a different object id"), "{error}");
    }

    #[test]
    fn legacy_metadata_with_an_unknown_kind_stays_blocked_and_is_named() {
        let temp = TempStore::new("unknown-kind-blocked");
        let store = temp.store();
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "7".into(),
            inputs: BTreeMap::from([("schema".into(), "mystery/4".into())]),
        };
        let id = commit_legacy_fixture(&store, &unknown, Some(&[]));
        register_objects(&store, &temp.root.join("project"), &[]);

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (0, 1));
        assert!(text.contains(&id), "the object id is not named: {text}");
        assert!(
            text.contains("kind not-a-known-kind, schema mystery/4"),
            "the kind and schema are not named: {text}"
        );
        drop(activity);

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "a store with an unknown kind swept anyway");
        assert_eq!(
            record(&store, &id).evidence,
            crate::objmeta::Evidence::Legacy
        );
    }

    #[test]
    fn cache_hit_does_not_certify_old_inferred_metadata() {
        let temp = TempStore::new("cache-hit-no-certify");
        let store = temp.store();
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([("artifact_sha256".into(), "4".repeat(64))]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));
        let before = fs::read(store.root.join("meta").join(format!("{id}.json"))).unwrap();

        // A newer binary publishes the same identity with real evidence and
        // finds the object already there. The cache hit must leave the old
        // record exactly as it was; upgrading it is migration's job alone.
        let digest = "4".repeat(64);
        cached_artifact(&store, &digest);
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "cpython").unwrap();
        let mut deps = ObjectDeps::new();
        deps.cache_digest(crate::fetch::Digest::sha256(&digest).unwrap());
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();

        assert_eq!(
            fs::read(store.root.join("meta").join(format!("{id}.json"))).unwrap(),
            before,
            "a cache hit rewrote a legacy record"
        );
        assert_eq!(
            record(&store, &id).evidence,
            crate::objmeta::Evidence::Legacy
        );
    }

    #[test]
    fn automatic_maintenance_precedes_shared_job_activity() {
        let temp = TempStore::new("maintenance-precedes");
        let store = temp.store();
        let digest = "5".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([("artifact_sha256".into(), digest)]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        // The shape main.rs uses: maintenance first, then the job's token.
        let mut out = Vec::new();
        let report = automatic_maintenance(&store, &mut out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (1, 0));
        assert_eq!(
            record(&store, &id).evidence,
            crate::objmeta::Evidence::Adapted("cpython@1".into())
        );
        let job = store.activity(ActivityMode::Shared).unwrap();
        store.require_activity(&job, "job").unwrap();
        drop(job);

        // Re-running it under no lease is an idempotent no-op.
        let mut out = Vec::new();
        let again = automatic_maintenance(&store, &mut out).unwrap();
        assert_eq!((again.upgraded, again.unresolved), (0, 0));
    }

    #[test]
    fn busy_automatic_maintenance_defers_without_lock_upgrade() {
        let temp = TempStore::new("maintenance-defers");
        let store = temp.store();
        let digest = "6".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([("artifact_sha256".into(), digest)]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        // A job already owns the store. Maintenance must report a deferral
        // and return, never wait for or upgrade the caller's own lease.
        let job = store.activity(ActivityMode::Shared).unwrap();
        let mut out = Vec::new();
        let report = automatic_maintenance(&store, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (0, 0));
        assert!(text.contains("metadata maintenance deferred"), "{text}");
        assert_eq!(
            record(&store, &id).evidence,
            crate::objmeta::Evidence::Legacy
        );
        // The caller's own lease is untouched and still usable.
        store.require_activity(&job, "job").unwrap();
        drop(job);
    }

    #[test]
    fn migration_failure_never_starts_deletion() {
        let temp = TempStore::new("migration-failure");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let artifact = "7".repeat(64);
        cached_artifact(&store, &artifact);
        age(&store.cache_path("sha256", &artifact));
        // A record whose adapter cannot resolve its indirect reference: the
        // Go toolchain it names has been collected by an older sweep.
        let unresolvable = Identity {
            kind: "go-modcache".into(),
            name: "modcache".into(),
            version: "0".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "go-modcache/1".into()),
                ("extractor".into(), format!("go1.25.3:{}", "8".repeat(64))),
            ]),
        };
        commit_legacy_fixture(&store, &unresolvable, Some(&[]));
        register_objects(&store, &temp.root.join("project"), &[]);

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "{text}");
        assert!(
            store.object_path(&dead).is_dir(),
            "an object was deleted: {text}"
        );
        assert!(
            store.cache_path("sha256", &artifact).is_file(),
            "a cached artifact was deleted: {text}"
        );
    }

    #[test]
    fn sha1_sha256_and_sha512_artifacts_follow_retained_object_digests() {
        let temp = TempStore::new("all-algorithms");
        let store = temp.store();
        for algo in ["sha1", "sha256", "sha512"] {
            fs::create_dir_all(store.root.join("cache").join(algo)).unwrap();
        }
        let widths = [("sha1", 40), ("sha256", 64), ("sha512", 128)];
        let mut deps = ObjectDeps::new();
        let mut kept = Vec::new();
        let mut dropped = Vec::new();
        for (algo, width) in widths {
            let keep: String = std::iter::repeat_n('a', width).collect();
            let drop_it: String = std::iter::repeat_n('b', width).collect();
            for hex in [&keep, &drop_it] {
                let path = store.cache_path(algo, hex);
                fs::write(&path, b"artifact").unwrap();
                age(&path);
            }
            let digest = match algo {
                "sha1" => crate::fetch::Digest::sha1(&keep),
                "sha256" => crate::fetch::Digest::sha256(&keep),
                _ => crate::fetch::Digest::sha512(&keep),
            }
            .unwrap();
            deps.cache_digest(digest);
            kept.push((algo, keep));
            dropped.push((algo, drop_it));
        }
        let identity = test_identity("all-algos", None);
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "all").unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();
        register_objects(&store, &temp.root.join("project"), &[&id]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().cached_artifacts, 3, "{text}");
        for (algo, hex) in kept {
            assert!(
                store.cache_path(algo, &hex).is_file(),
                "{algo}:{hex} was collected: {text}"
            );
        }
        for (algo, hex) in dropped {
            assert!(
                !store.cache_path(algo, &hex).exists(),
                "{algo}:{hex} survived: {text}"
            );
        }
    }

    #[test]
    fn hex_package_tarballs_remain_cached_for_a_retained_hex_object() {
        let temp = TempStore::new("hex-tarballs");
        let store = temp.store();
        let (beam, fingerprint) = beam_fixture(&store);
        let outer = "a".repeat(64);
        cached_artifact(&store, &outer);
        age(&store.cache_path("sha256", &outer));
        let stray = "f".repeat(64);
        cached_artifact(&store, &stray);
        age(&store.cache_path("sha256", &stray));
        let identity = hex_deps_identity(&fingerprint, &outer, &"b".repeat(64));
        let deps_id = commit_legacy_fixture(&store, &identity, Some(&[]));
        age(&store.object_path(&deps_id));
        age(&store.object_path(&beam));
        register_objects(&store, &temp.root.join("project"), &[&deps_id]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            store.cache_path("sha256", &outer).is_file(),
            "a retained hex object lost its package tarball: {text}"
        );
        assert!(
            store.object_path(&beam).is_dir(),
            "the BEAM object was collected: {text}"
        );
        assert!(!store.cache_path("sha256", &stray).exists(), "{text}");
    }

    #[test]
    fn retained_backup_and_nested_hex_projection_are_not_deleted() {
        let temp = TempStore::new("nested-projections");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = store::Store::root_key(&project).unwrap();

        // A hex deps projection nested below a swept forest ancestor, and a
        // backup directory. Both are claimed by the surviving root record.
        let forest_project = store.root.join("forests").join(&key);
        let projection = forest_project.join("hex-deps");
        let nested = projection.join("deps/jason/ebin");
        fs::create_dir_all(&nested).unwrap();
        let backup = store
            .root
            .join("backups")
            .join(format!("{key}-node_modules"));
        fs::create_dir_all(&backup).unwrap();
        let stale = forest_project.join("unclaimed");
        fs::create_dir_all(&stale).unwrap();
        for path in [&projection, &backup, &stale, &forest_project] {
            age(path);
        }

        // A second forest project whose whole directory the root claims:
        // the enumerated candidates below it are *descendants* of the claim,
        // which `related` must keep through prefix matching, not equality.
        let project2 = temp.root.join("project2");
        fs::create_dir_all(&project2).unwrap();
        let project2 = project2.canonicalize().unwrap();
        let key2 = store::Store::root_key(&project2).unwrap();
        let forest_project2 = store.root.join("forests").join(&key2);
        let nested2 = forest_project2.join("node_modules/left-pad");
        fs::create_dir_all(&nested2).unwrap();
        age(&nested2);
        age(&forest_project2);

        store
            .register_root_record(store::RootRecord {
                key: key.clone(),
                project_path: project,
                objects: BTreeSet::new(),
                projections: BTreeSet::from([
                    // A claim strictly *inside* the enumerated candidate:
                    // `hex-deps` itself is swept as a whole projection, but
                    // the record names a deeper path, so ancestor matching
                    // (`keep` is a descendant of the candidate) must keep it.
                    store::ProjectionRef::new(
                        store::ProjectionBase::Forests,
                        vec![
                            key.clone().into(),
                            "hex-deps".into(),
                            "deps".into(),
                            "jason".into(),
                        ],
                    )
                    .unwrap(),
                    // An ancestor claim: every candidate under forest_project2
                    // is protected by the record, not by being named exactly.
                    store::ProjectionRef::new(
                        store::ProjectionBase::Forests,
                        vec![key2.clone().into()],
                    )
                    .unwrap(),
                    store::ProjectionRef::new(
                        store::ProjectionBase::Backups,
                        vec![format!("{key}-node_modules").into()],
                    )
                    .unwrap(),
                ]),
                updated: 1,
            })
            .unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            nested.is_dir(),
            "a nested hex projection was deleted: {text}"
        );
        assert!(backup.is_dir(), "a retained backup was deleted: {text}");
        assert!(
            nested2.is_dir(),
            "a projection below a claimed ancestor was deleted: {text}"
        );
        assert!(!stale.exists(), "an unclaimed forest survived: {text}");
    }

    // =======================================================================
    // C.10 matrix items that Package D interacts with.
    //
    // These are root-record and projection retention cases whose behaviour D's
    // sweep now decides. The rest of C.10 belongs to Package C.
    // =======================================================================

    /// Publication writes the durable record before the closure. A crash in
    /// that window leaves a record naming objects no closure mentions yet —
    /// which must protect *more*, never less.
    #[test]
    fn crash_after_record_write_leaves_extra_protection() {
        let temp = TempStore::new("crash-after-record");
        let store = temp.store();
        let named = commit(&store, "named", None);
        let unnamed = commit(&store, "unnamed", None);
        age(&store.object_path(&named));
        age(&store.object_path(&unnamed));
        // The record landed naming both objects; the project has no closure
        // file yet, exactly as a crash between the two writes would leave it.
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut refs = crate::project::ClosureRefs::new();
        refs.object_id(&store, &activity, &named).unwrap();
        refs.object_id(&store, &activity, &unnamed).unwrap();
        crate::project::write_closure(
            &project,
            "python",
            serde_json::json!({"ok": true}),
            &store,
            &activity,
            refs,
        )
        .unwrap();
        drop(activity);
        // Crash window: the visible closure is gone, the durable record is not.
        fs::remove_dir_all(project.join(".blanket/closures")).unwrap();
        assert!(!project.join(".blanket/closures").exists());

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 0, "{text}");
        assert!(store.object_path(&named).is_dir(), "{text}");
        assert!(
            store.object_path(&unnamed).is_dir(),
            "a record written before its closure lost protection: {text}"
        );
    }

    /// A publication that fails before the record write leaves no record and
    /// no closure. The objects are simply unprotected: the sweep is not
    /// blocked, and it does not invent a root for them.
    #[test]
    fn crash_before_record_write_publishes_no_closure() {
        let temp = TempStore::new("crash-before-record");
        let store = temp.store();
        let orphan = commit(&store, "orphan", None);
        age(&store.object_path(&orphan));
        register_objects(&store, &temp.root.join("other"), &[]);
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        // Real publication with an unavailable reference: it must fail
        // before either durable write, so nothing is published.
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut refs = crate::project::ClosureRefs::new();
        refs.object_id(&store, &activity, &("0".repeat(40) + "-missing-1"))
            .unwrap_err();
        assert!(!project.join(".blanket/closures").exists());
        let roots = store.roots().unwrap();
        assert!(
            roots.iter().all(|root| root
                .record
                .as_ref()
                .map(|r| r.project_path != project)
                .unwrap_or(true)),
            "a failed publication wrote a durable record"
        );
        assert!(!project.join(".blanket/closures").exists());
        drop(activity);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 1, "{text}");
        assert!(!store.object_path(&orphan).exists(), "{text}");
    }

    /// A pathname-only record whose project is gone blocks every sweep. Both
    /// documented resolutions must actually clear it.
    #[test]
    fn legacy_record_still_blocks_until_registered_or_forgotten() {
        for resolution in ["forget", "restore"] {
            let temp = TempStore::new(&format!("legacy-blocks-{resolution}"));
            let store = temp.store();
            let dead = commit(&store, "dead", None);
            age(&store.object_path(&dead));
            let project = temp.root.join("project");
            fs::create_dir_all(project.join(".blanket/closures")).unwrap();
            let entry = store.register_root(&project).unwrap();
            fs::remove_dir_all(&project).unwrap();

            let (result, _) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            assert!(
                result.is_err(),
                "an unavailable pathname-only project did not block the sweep"
            );
            assert!(store.object_path(&dead).is_dir());

            match resolution {
                "forget" => {
                    store.forget_root(&entry.key).unwrap();
                }
                _ => {
                    fs::create_dir_all(project.join(".blanket/closures")).unwrap();
                }
            }
            let (report, text) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            assert_eq!(
                report.unwrap().objects,
                1,
                "{resolution} did not unblock the sweep: {text}"
            );
        }
    }

    /// Forests and backups beside the store are shared by sibling stores. A
    /// per-store activity lease cannot authorize deleting from them, so they
    /// are named as retained and never swept.
    #[test]
    fn legacy_shared_forests_and_backups_are_never_swept() {
        let temp = TempStore::new("legacy-shared");
        let store = temp.store();
        let home = store.root.parent().unwrap().to_path_buf();
        let shared_forest = home.join("forests/deadbeef/projection");
        let shared_backup = home.join("backups/deadbeef-node_modules");
        fs::create_dir_all(&shared_forest).unwrap();
        fs::create_dir_all(&shared_backup).unwrap();
        age(&shared_forest);
        age(&shared_backup);
        register_objects(&store, &temp.root.join("project"), &[]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            shared_forest.is_dir(),
            "a sibling-namespace forest was swept: {text}"
        );
        assert!(
            shared_backup.is_dir(),
            "a sibling-namespace backup was swept: {text}"
        );
        assert!(
            text.contains("shared by sibling stores"),
            "the retention was not narrated: {text}"
        );
    }

    /// A `root/2` record is self-sufficient: its projections stay protected
    /// even when the project directory it names no longer exists.
    #[test]
    fn forest_retention_works_with_the_project_directory_absent() {
        let temp = TempStore::new("forest-absent-project");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = store::Store::root_key(&project).unwrap();
        let projection = store.root.join("forests").join(&key).join("node_modules");
        fs::create_dir_all(projection.join("left-pad")).unwrap();
        age(&projection);
        store
            .register_root_record(store::RootRecord {
                key: key.clone(),
                project_path: project.clone(),
                objects: BTreeSet::new(),
                projections: BTreeSet::from([store::ProjectionRef::new(
                    store::ProjectionBase::Forests,
                    vec![key.into(), "node_modules".into()],
                )
                .unwrap()]),
                updated: 1,
            })
            .unwrap();
        fs::remove_dir_all(&project).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            projection.join("left-pad").is_dir(),
            "a forest lost its protection when the project directory vanished: {text}"
        );
    }

    /// D.5: a preview separates what it would delete from what retention kept
    /// and from what blocked it. The retention category is the one a sweep
    /// can silently fold into "nothing to do", so it is asserted explicitly.
    #[test]
    fn dry_run_reports_removals_skips_and_blocks_in_distinct_categories() {
        let temp = TempStore::new("dry-run-categories");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        let fresh = commit(&store, "fresh", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);

        let (report, text) = sweep(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 1, "{text}");
        assert!(
            text.contains(&format!(
                "would remove object {}",
                store.object_path(&dead).display()
            )),
            "the candidate was not previewed: {text}"
        );
        assert!(
            text.contains(&format!("skipped: object {fresh}")),
            "a retention decision was not reported: {text}"
        );
        assert!(
            text.contains("active window"),
            "the retention reason was not given: {text}"
        );

        // The same store with one legacy record reports a block instead, and
        // authorizes no deletion at all.
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        commit_legacy_fixture(&store, &unknown, Some(&[]));
        let (result, text) = sweep(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "{text}");
        assert!(
            !text.contains("would remove object"),
            "a blocked preview still authorized a deletion: {text}"
        );
    }
}

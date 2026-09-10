//! Store garbage collection.
//!
//! GC is deliberately rooted in project closure files rather than in the
//! current working directory. A project becomes a root when a tailor writes a
//! closure. A root never stops protecting its project: an unavailable project
//! stops the sweep until it returns or its record is explicitly forgotten.

use crate::store::{self, RootEntry, Store};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Write};
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

#[derive(Debug, Default, Clone)]
struct MetaInfo {
    refs: Vec<String>,
    has_refs: bool,
    cache_hashes: BTreeSet<String>,
    kind: String,
}

/// Sweep the store and optionally the blanket-home projections.
pub fn collect<W: Write>(store: &Store, options: Options, out: &mut W) -> io::Result<Report> {
    // GC has its own user-visible lock, and also holds the publication lock
    // across the liveness snapshot and removals. Store::has/commit use the
    // latter, so a sync either touches an object before this sweep or waits
    // until after it.
    let _gc_lock = store.gc_lock()?;
    let _publish_lock = store.publish_lock()?;

    if !store.registry_initialized()? {
        return Err(io::Error::other(
            "refusing to sweep: the project-root registry is not initialized; register existing "
                .to_string()
                + "projects with `blanket gc --register <dir>...` or run `blanket sync` in each "
                + "project",
        ));
    }
    let roots = store.roots()?;
    let state = collect_roots(store, &roots, &options, out)?;
    // Recency and keep-days are retention decisions, not just sweep skips:
    // every retained object is a marking root so its dependencies survive it.
    let mut marking_roots = state.object_ids.clone();
    marking_roots.extend(retained_object_ids(store, &options)?);
    let (live, metadata) = mark_live(store, &marking_roots)?;
    let mut report = sweep_objects(store, &live, &metadata, &options, out)?;
    report = add_report(
        report,
        sweep_cache(store, &state, &live, &metadata, &options, out)?,
    );
    report = add_report(report, sweep_stages(store, &options, out)?);
    if options.project {
        report = add_report(report, sweep_projects(store, &state, &options, out)?);
    }

    Ok(report)
}

fn add_report(mut left: Report, right: Report) -> Report {
    left.freed_bytes += right.freed_bytes;
    left.objects += right.objects;
    left.cached_artifacts += right.cached_artifacts;
    left.stages += right.stages;
    left.forests += right.forests;
    left.backups += right.backups;
    left
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
        // A record this store cannot read is the same safety stop as a
        // project that cannot be resolved, and for the same reason: the
        // record exists, so some project is still counting on it, and there
        // is no way to tell which objects that project needs.
        if let Some(reason) = &root.unusable {
            return Err(unusable_root(root, reason));
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
        // A registered project owns at least one closure: registration
        // happens when one is written. None at all means either that they
        // were removed, or that this pathname no longer resolves to the
        // project that was registered — unmounting a mount point exposes the
        // backing directory underneath, which can carry an empty
        // `.blanket/closures` of its own and would otherwise be swept as if
        // the registered project had agreed it needed nothing.
        if read_closures(store, &project, &mut state, out)? == 0 {
            return Err(unresolvable_root(
                root,
                &io::Error::new(
                    io::ErrorKind::InvalidInput,
                    ".blanket/closures holds no closure files: they were removed, or the \
                     path now resolves to a different directory than the one registered \
                     (the backing directory of an unmounted mount point, for example)",
                ),
            ));
        }
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

fn unusable_root(root: &RootEntry, reason: &str) -> io::Error {
    io::Error::other(format!(
        "refusing to sweep: root {} has an unusable registry record at {} ({}). Repair the \
         record, or give up that project's protection explicitly with `blanket gc --forget \
         {}`. Dry runs stop here too: the records decide what a real sweep would keep.",
        root.key,
        root.registry_path.display(),
        reason,
        root.key
    ))
}

/// Read a project's closures into the live set, returning how many closure
/// files it held.
fn read_closures<W: Write>(
    store: &Store,
    project: &Path,
    state: &mut RootState,
    out: &mut W,
) -> io::Result<usize> {
    let closures = project.join(".blanket/closures");
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
                let home = store
                    .root
                    .parent()
                    .ok_or_else(|| io::Error::other("cannot locate blanket home"))?;
                let key = short_sha256(project.to_string_lossy().as_bytes(), 32);
                state
                    .project_keep
                    .push(home.join("forests").join(key).join(projection_id));
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
            let forests = home.join("forests");
            let backups = home.join("backups");
            if path.is_absolute() && (path.starts_with(&forests) || path.starts_with(&backups)) {
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
    let forests = home.join("forests");
    let backups = home.join("backups");
    if path.starts_with(&forests) || path.starts_with(&backups) {
        paths.push(path.to_path_buf());
    }
}

fn mark_live(
    store: &Store,
    roots: &HashSet<String>,
) -> io::Result<(HashSet<String>, HashMap<String, MetaInfo>)> {
    let mut live = HashSet::new();
    let mut metadata = HashMap::new();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();
    while let Some(id) = queue.pop_front() {
        if !live.insert(id.clone()) {
            continue;
        }
        let Some(info) = read_meta(store, &id)? else {
            continue;
        };
        for reference in &info.refs {
            if !live.contains(reference) {
                queue.push_back(reference.clone());
            }
        }
        metadata.insert(id, info);
    }
    Ok((live, metadata))
}

fn retained_object_ids(store: &Store, options: &Options) -> io::Result<HashSet<String>> {
    let mut roots = HashSet::new();
    for entry in fs::read_dir(store.root.join("objects"))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        let info = read_meta(store, &id)?.unwrap_or_default();
        let retained = recent(&entry.path(), ACTIVE_WINDOW)
            || (!info.has_refs
                && (!options.collect_legacy
                    || !older_than(&entry.path(), keep_age(options.keep_days))));
        if retained {
            roots.insert(id);
        }
    }
    Ok(roots)
}

fn read_meta(store: &Store, id: &str) -> io::Result<Option<MetaInfo>> {
    let path = store.root.join("meta").join(format!("{id}.json"));
    if !path.is_file() {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_reader(fs::File::open(&path)?).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse object metadata {}: {e}", path.display()),
            )
        })?;
    let mut refs = BTreeSet::new();
    let has_refs = value.get("refs").is_some();
    if let Some(values) = value.get("refs").and_then(serde_json::Value::as_array) {
        for value in values {
            if let Some(text) = value.as_str() {
                if let Some(id) = store::object_id_token(text) {
                    refs.insert(id);
                }
            }
        }
    } else if let Some(inputs) = value.get("identity").and_then(|v| v.get("inputs")) {
        collect_object_ids_from_value(inputs, &mut refs);
    }
    let cache_hashes = value
        .get("identity")
        .and_then(|v| v.get("inputs"))
        .map(cache_hashes_from_value)
        .unwrap_or_default();
    let refs: Vec<String> = refs.into_iter().collect();
    Ok(Some(MetaInfo {
        // The explicit refs field is the schema boundary. Older metadata may
        // still let us infer dependencies from identity.inputs, and those
        // inferred refs are traversed, but the object remains legacy until
        // the user explicitly opts into collecting it.
        has_refs,
        refs,
        cache_hashes,
        kind: value["identity"]["kind"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    }))
}

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

fn cache_hashes_from_value(value: &serde_json::Value) -> BTreeSet<String> {
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

fn sweep_objects<W: Write>(
    store: &Store,
    live: &HashSet<String>,
    metadata: &HashMap<String, MetaInfo>,
    options: &Options,
    out: &mut W,
) -> io::Result<Report> {
    let mut report = Report::default();
    let objects = store.root.join("objects");
    for entry in fs::read_dir(&objects)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        if live.contains(&id) || recent(&entry.path(), ACTIVE_WINDOW) {
            continue;
        }
        let info = if let Some(info) = metadata.get(&id) {
            info.clone()
        } else {
            read_meta(store, &id)?.unwrap_or_default()
        };
        if !info.has_refs
            && (!options.collect_legacy || !older_than(&entry.path(), keep_age(options.keep_days)))
        {
            continue;
        }
        let bytes = tree_size(&entry.path())?
            + file_size(&store.root.join("meta").join(format!("{id}.json")));
        if options.dry_run {
            let kind = if info.kind.is_empty() {
                String::new()
            } else {
                format!("[{}] ", info.kind)
            };
            writeln!(
                out,
                "would remove object {} ({}{})",
                entry.path().display(),
                kind,
                size(bytes)
            )?;
        } else {
            store::remove_tree(&entry.path())?;
            let meta = store.root.join("meta").join(format!("{id}.json"));
            remove_file(&meta)?;
        }
        report.freed_bytes += bytes;
        report.objects += 1;
    }
    Ok(report)
}

fn sweep_cache<W: Write>(
    store: &Store,
    _state: &RootState,
    live: &HashSet<String>,
    metadata: &HashMap<String, MetaInfo>,
    options: &Options,
    out: &mut W,
) -> io::Result<Report> {
    let mut referenced = BTreeSet::new();
    for id in live {
        let info = if let Some(info) = metadata.get(id) {
            info.clone()
        } else {
            read_meta(store, id)?.unwrap_or_default()
        };
        referenced.extend(info.cache_hashes);
    }
    let mut report = Report::default();
    let cache = store.root.join("cache/sha256");
    if !cache.is_dir() {
        return Ok(report);
    }
    for entry in fs::read_dir(cache)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if referenced.contains(&name)
            || recent(&entry.path(), ACTIVE_WINDOW)
            || !older_than(&entry.path(), keep_age(options.keep_days))
        {
            continue;
        }
        let bytes = file_size(&entry.path());
        if options.dry_run {
            writeln!(
                out,
                "would remove cached artifact {} ({})",
                entry.path().display(),
                size(bytes)
            )?;
        } else {
            remove_file(&entry.path())?;
        }
        report.freed_bytes += bytes;
        report.cached_artifacts += 1;
    }
    Ok(report)
}

fn sweep_stages<W: Write>(store: &Store, options: &Options, out: &mut W) -> io::Result<Report> {
    let mut report = Report::default();
    for entry in fs::read_dir(store.root.join("tmp"))? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("stage-")
            || !entry.file_type()?.is_dir()
            || !older_than(&entry.path(), STAGE_WINDOW)
        {
            continue;
        }
        let bytes = tree_size(&entry.path())?;
        if options.dry_run {
            writeln!(
                out,
                "would remove stale stage {} ({})",
                entry.path().display(),
                size(bytes)
            )?;
        } else {
            store::remove_tree(&entry.path())?;
        }
        report.freed_bytes += bytes;
        report.stages += 1;
    }
    Ok(report)
}

fn sweep_projects<W: Write>(
    store: &Store,
    state: &RootState,
    options: &Options,
    out: &mut W,
) -> io::Result<Report> {
    let mut report = Report::default();
    let Some(home) = store.root.parent() else {
        return Ok(report);
    };
    let forests = home.join("forests");
    if forests.is_dir() {
        for project in fs::read_dir(&forests)? {
            let project = project?;
            if !project.file_type()?.is_dir() {
                continue;
            }
            for projection in fs::read_dir(project.path())? {
                let projection = projection?;
                if !projection.file_type()?.is_dir()
                    || state
                        .project_keep
                        .iter()
                        .any(|keep| related(&projection.path(), keep))
                    || !older_than(&projection.path(), STAGE_WINDOW)
                {
                    continue;
                }
                let bytes = tree_size(&projection.path())?;
                if options.dry_run {
                    writeln!(
                        out,
                        "would remove stale forest {} ({})",
                        projection.path().display(),
                        size(bytes)
                    )?;
                } else {
                    store::remove_tree(&projection.path())?;
                }
                report.freed_bytes += bytes;
                report.forests += 1;
            }
        }
    }
    let backups = home.join("backups");
    if backups.is_dir() {
        for backup in fs::read_dir(backups)? {
            let backup = backup?;
            if !backup.file_type()?.is_dir()
                || !older_than(&backup.path(), keep_age(options.keep_days))
            {
                continue;
            }
            let bytes = tree_size(&backup.path())?;
            if options.dry_run {
                writeln!(
                    out,
                    "would remove backup {} ({})",
                    backup.path().display(),
                    size(bytes)
                )?;
            } else {
                store::remove_tree(&backup.path())?;
            }
            report.freed_bytes += bytes;
            report.backups += 1;
        }
    }
    Ok(report)
}

fn related(path: &Path, keep: &Path) -> bool {
    path == keep || path.starts_with(keep) || keep.starts_with(path)
}

fn recent(path: &Path, window: Duration) -> bool {
    modified(path)
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_some_and(|age| age < window)
}

fn older_than(path: &Path, age: Duration) -> bool {
    modified(path)
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_some_and(|elapsed| elapsed > age)
}

fn keep_age(days: u64) -> Duration {
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
}

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

fn file_size(path: &Path) -> u64 {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn remove_file(path: &Path) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return fs::remove_file(path);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = metadata.permissions();
            permissions.set_mode(permissions.mode() | 0o200);
            fs::set_permissions(path, permissions)?;
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
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
fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
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
                unix_secs(SystemTime::now())
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

    fn commit(store: &Store, name: &str, input: Option<&str>) -> String {
        let identity = Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: input
                .map(|id| BTreeMap::from([("input".into(), id.into())]))
                .unwrap_or_default(),
        };
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), name).unwrap();
        store.commit(&identity, &staged, &[]).unwrap();
        id
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
        let meta_path = store.root.join("meta").join(format!("{id}.json"));
        let mut meta: serde_json::Value =
            serde_json::from_reader(fs::File::open(&meta_path).unwrap()).unwrap();
        meta.as_object_mut().unwrap().remove("refs");
        fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        // The project needs a closure of its own to be a resolvable root; it
        // names an object this test never commits, so the legacy object under
        // test stays unprotected.
        closure(
            &project,
            &store.object_path("0000000000000000000000000000000000000000-unrelated"),
            serde_json::json!({}),
        );
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
    fn retained_object_keeps_old_dependency() {
        let temp = TempStore::new("retained-dependency");
        let store = temp.store();
        let child = commit(&store, "old-child", None);
        age(&store.object_path(&child));
        let parent = commit(&store, "fresh-parent", Some(&child));
        let project = temp.root.join("project");
        // A resolvable root owns a closure; this one names an object the test
        // never commits, so nothing here is protected by the record itself.
        closure(
            &project,
            &store.object_path("0000000000000000000000000000000000000000-unrelated"),
            serde_json::json!({}),
        );
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
        store.commit(&identity, &staged, &[]).unwrap();
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

    /// A forget names one root, and the preview must exclude that root and
    /// no other. With a second registered project in the store, treating the
    /// request as "ignore every root" would offer up the live object that
    /// second project is still holding.
    #[test]
    fn dry_run_forget_excludes_only_the_named_root() {
        let temp = TempStore::new("dry-forget-two-roots");
        let store = temp.store();
        let released = commit(&store, "released", None);
        let held = commit(&store, "held", None);
        age(&store.object_path(&released));
        age(&store.object_path(&held));

        let gone = temp.root.join("gone");
        fs::create_dir_all(&gone).unwrap();
        closure(&gone, &store.object_path(&released), serde_json::json!({}));
        let gone_entry = store.register_root(&gone).unwrap();

        let present = temp.root.join("present");
        fs::create_dir_all(&present).unwrap();
        closure(&present, &store.object_path(&held), serde_json::json!({}));
        let present_entry = store.register_root(&present).unwrap();
        fs::remove_dir_all(&gone).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                forgotten: vec![gone_entry.key.clone()],
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        let preview = String::from_utf8(output).unwrap();
        assert!(preview.contains(&released), "{preview}");
        assert!(
            !preview.contains(&held),
            "the root that was not forgotten stopped protecting its object: {preview}"
        );
        assert_eq!(report.objects, 1, "{preview}");
        assert!(store.object_path(&held).is_dir());
        assert!(store.object_path(&released).is_dir(), "a dry run deleted");
        assert!(store.lookup_root(&present_entry.key).is_ok());
        assert!(store.lookup_root(&gone_entry.key).is_ok());
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

    /// A store from before the roots registry has no marker and no records,
    /// so a sweep there would run with no idea what any project needs. It
    /// must refuse from every entry, including `--project --collect-legacy`,
    /// the combination that exists to reach exactly those old objects. The
    /// end-to-end upgrade test covers this as well, but only in the ignored
    /// suite, which leaves the guard unwatched on an ordinary `cargo test`.
    #[test]
    fn an_uninitialized_registry_blocks_every_sweep() {
        let temp = TempStore::new("uninitialized-registry");
        let store = temp.store();
        let id = commit(&store, "legacy", None);
        age(&store.object_path(&id));
        assert!(!store.root.join("roots/.initialized").exists());

        for (dry_run, project, collect_legacy) in [
            (false, false, false),
            (true, false, false),
            (false, true, true),
        ] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    project,
                    collect_legacy,
                    keep_days: 0,
                    forgotten: Vec::new(),
                },
                &mut output,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("registry is not initialized"), "{message}");
        }
        assert!(store.object_path(&id).is_dir(), "sweep deleted the object");
    }

    /// A root that resolves to a directory holding no closures cannot say
    /// what it needs. The reachable version of this is a pathname that now
    /// names something else — the backing directory of an unmounted mount
    /// point — so it is a safety stop, not an empty contribution.
    #[test]
    fn empty_closures_directory_blocks_sweep() {
        let temp = TempStore::new("empty-closures");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        for closure in fs::read_dir(project.join(".blanket/closures")).unwrap() {
            fs::remove_file(closure.unwrap().path()).unwrap();
        }

        for dry_run in [false, true] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    keep_days: 0,
                    ..Options::default()
                },
                &mut output,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("refusing to sweep"), "{message}");
            assert!(message.contains(&entry.key), "{message}");
        }
        assert!(store.object_path(&id).is_dir(), "sweep deleted the object");
        assert_eq!(store.roots().unwrap().len(), 1, "sweep removed the record");
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
}

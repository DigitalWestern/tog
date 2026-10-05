//! `tog x --clean`: find the cached environments a request selects, each
//! under the no-follow rules the runner created it with, and remove them
//! with their registration in the store that owns them.

use super::*;

#[derive(Debug)]
pub(super) struct CleanFilter {
    pub(super) ecosystem: Option<String>,
    pub(super) package: Option<String>,
    pub(super) version: Option<String>,
}

pub(super) struct XCandidate {
    pub(super) path: PathBuf,
    pub(super) name: OsString,
    /// The shared `~/.tog/x` descriptor, not a per-candidate clone. It is
    /// the same directory for every candidate and is only ever read from, so
    /// cloning it per entry cost one extra descriptor each and put a large
    /// `~/.tog/x` against the process descriptor limit before cleanup had
    /// removed anything.
    pub(super) x_dir: Rc<fs::File>,
    pub(super) directory: fs::File,
    pub(super) identity: (u64, u64),
}

pub(super) fn clean_filter(request: CleanRequest) -> io::Result<CleanFilter> {
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
    let version = request_version(tool_version, from_version)?;
    Ok(CleanFilter {
        ecosystem: request.ecosystem,
        package: Some(package.to_string()),
        version: version.map(str::to_string),
    })
}

pub(super) fn safe_x_root(root: &Path, x_dir: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(root).ok()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    let metadata_dir = root.join(".tog");
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

/// Resolve a user-controlled ancestor of the cleanup anchor. `$HOME` and
/// `~/.tog` are routinely symlinks (the usual "move the cache off the
/// root disk" setup) and `tog x` follows them when it creates and
/// registers a root, so cleanup follows them too — otherwise it could never
/// remove what the runner just made. Containment is carried by the no-follow
/// component walk below the resolved anchor and by the descriptor identity
/// checks, not by refusing a symlinked ancestor.
pub(super) fn canonical_real_directory(path: &Path, label: &str) -> io::Result<Option<PathBuf>> {
    let canonical = match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(other(format!(
                "x: could not resolve {label} {}: {error}",
                path.display()
            )));
        }
    };
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        other(format!(
            "x: could not inspect {label} {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(other(format!(
            "x: {label} {} is not a directory; refusing to clean",
            path.display()
        )));
    }
    Ok(Some(canonical))
}

/// The final `x` component is checked without following it, matching the
/// runner's own `ensure_x_locks_dir` check, so both commands accept and
/// refuse exactly the same layouts.
pub(super) fn existing_real_directory(path: &Path, label: &str) -> io::Result<bool> {
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

/// A cleanup anchor that passed validation: its canonical path and an open
/// descriptor for that exact directory.
#[derive(Debug)]
pub(super) struct ValidatedXDir {
    pub(super) path: PathBuf,
    pub(super) directory: fs::File,
}

/// Return the canonical cleanup anchor. The home chain (`$HOME` and
/// `~/.tog`) is resolved the way the runner resolves it and the result
/// must be a real directory; the final `x` component is never followed.
/// Missing `.tog` or `x` means there is nothing to clean; an existing
/// unsafe component is an error.
pub(super) fn validated_x_dir(x_dir: &Path) -> io::Result<Option<ValidatedXDir>> {
    if !x_dir.is_absolute() {
        return Err(other(format!(
            "x: cleanup directory {} is not absolute; refusing to clean",
            x_dir.display()
        )));
    }
    let tog_dir = x_dir.parent().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no .tog parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let home_dir = tog_dir.parent().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no HOME parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let tog_name = tog_dir.file_name().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no .tog parent; refusing to clean",
            x_dir.display()
        ))
    })?;
    let x_name = x_dir.file_name().ok_or_else(|| {
        other(format!(
            "x: cleanup directory {} has no name; refusing to clean",
            x_dir.display()
        ))
    })?;
    let Some(home_canonical) = canonical_real_directory(home_dir, "HOME")? else {
        return Err(other(format!(
            "x: HOME directory {} does not exist; refusing to clean",
            home_dir.display()
        )));
    };
    let Some(tog_canonical) =
        canonical_real_directory(&home_canonical.join(tog_name), "$HOME/.tog")?
    else {
        return Ok(None);
    };
    // Below the resolved home chain nothing is followed: the `x` component
    // must be a real directory and `open_directory_path` walks the canonical
    // path one no-follow component at a time.
    let canonical = tog_canonical.join(x_name);
    if !existing_real_directory(&canonical, "$HOME/.tog/x")? {
        return Ok(None);
    }
    let expected = fs::symlink_metadata(&canonical)?;
    let directory = open_directory_path(&canonical)?;
    let actual = store::fd_identity(&directory)?;
    if actual != (expected.dev(), expected.ino()) {
        return Err(other(format!(
            "x: cleanup directory {} changed while it was being opened; retry later",
            canonical.display()
        )));
    }
    Ok(Some(ValidatedXDir {
        path: canonical,
        directory,
    }))
}

/// Whether the held root has a real `.tog/closures` directory.
pub(super) fn has_safe_closures(root: &fs::File) -> bool {
    store::open_directory_at(root.as_raw_fd(), b".tog")
        .and_then(|tog| store::stat_at(tog.as_raw_fd(), b"closures"))
        .is_ok_and(|stat| store::is_directory(&stat))
}

pub(super) fn x_candidates(x_dir: &Path) -> io::Result<Vec<XCandidate>> {
    let Some(validated) = validated_x_dir(x_dir)? else {
        return Ok(Vec::new());
    };
    let mut candidates = Vec::new();
    let shared_x_dir = Rc::new(validated.directory);
    for name in store::read_dir_names_at(shared_x_dir.as_raw_fd())? {
        if name.as_bytes().first() == Some(&b'.') {
            continue;
        }
        let path = validated.path.join(&name);
        let metadata = match store::stat_at(shared_x_dir.as_raw_fd(), name.as_bytes()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !store::is_directory(&metadata) {
            continue;
        }
        let Some(canonical) = safe_x_root(&path, &validated.path) else {
            continue;
        };
        let directory = match store::open_directory_at(shared_x_dir.as_raw_fd(), name.as_bytes()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => continue,
            Err(error) => return Err(error),
        };
        if store::fd_identity(&directory)? != store::stat_identity(&metadata) {
            continue;
        }
        let marker = match store::stat_at(directory.as_raw_fd(), b".tog") {
            Ok(marker) if store::is_directory(&marker) => true,
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
        if read_x_request_in(&directory).is_none() && !has_safe_closures(&directory) {
            continue;
        }
        candidates.push(XCandidate {
            path: canonical,
            name,
            x_dir: Rc::clone(&shared_x_dir),
            directory,
            identity: store::stat_identity(&metadata),
        });
    }
    Ok(candidates)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateMatch {
    Match,
    NoMatch,
}

/// The ecosystem whose registry tool names cache directories with the
/// prefix `name` starts with (`py-ruff-…`).
pub(super) fn ecosystem_from_name(name: &str) -> Option<&'static str> {
    registry_tools()
        .into_iter()
        .find(|(_, tool)| {
            name.strip_prefix(tool.cache_prefix())
                .is_some_and(|rest| rest.starts_with('-'))
        })
        .map(|(id, _)| id)
}

pub(super) fn record_matches(record: &XRecord, filter: &CleanFilter) -> bool {
    filter
        .ecosystem
        .as_deref()
        .is_none_or(|ecosystem| ecosystem == record.ecosystem)
        && filter
            .package
            .as_deref()
            .is_none_or(|package| package == record.package)
        && filter
            .version
            .as_deref()
            .is_none_or(|version| Some(version) == record.version.as_deref())
}

/// Best-effort ecosystem of a held root named `name`, used only to word the
/// summary. The recorded request wins, then the generated name prefix.
pub(super) fn candidate_ecosystem(root: &fs::File, name: &OsStr) -> Option<&'static str> {
    if let Some(record) = read_x_request_in(root) {
        return registry_tools()
            .into_iter()
            .map(|(id, _)| id)
            .find(|id| *id == record.ecosystem);
    }
    ecosystem_from_name(name.to_str()?)
}

/// Whether `filter` selects `candidate`. Only the request record says what
/// a root was made for, so a root without one matches only a clean with no
/// filter at all: a filtered clean leaves it alone, and the bare
/// `tog x --clean` removes it.
pub(super) fn candidate_matches(candidate: &XCandidate, filter: &CleanFilter) -> CandidateMatch {
    let matched = match read_x_request_in(&candidate.directory) {
        Some(record) => record_matches(&record, filter),
        None => filter.ecosystem.is_none() && filter.package.is_none() && filter.version.is_none(),
    };
    if matched {
        CandidateMatch::Match
    } else {
        CandidateMatch::NoMatch
    }
}
pub(super) enum Registration {
    Found {
        store: Store,
        // Boxed so the enum is not as large as its one big variant.
        entry: Box<RootEntry>,
    },
    /// The root's own entry exists and cannot be read. Removing the root
    /// would leave that entry behind, so cleanup skips it.
    Unusable {
        store: Store,
        key: String,
        why: String,
    },
    NotFound,
    #[cfg(test)]
    Unknown,
}

/// Which store owns an x root, as cleanup must know it to unregister the
/// root under that store's lease.
pub(super) enum Origin {
    /// The store the request record names, or else the one store every
    /// object the root's closures reference lives in.
    Store(Store),
    /// No closure at all: a shell a run left before it wrote one, which
    /// references nothing and was never registered with its objects.
    Empty,
    /// The closures name objects, but no single available store can be
    /// recovered from them. Removing the root would orphan its registration.
    Unknown(String),
}

/// The store that owns the held root `root` (shown as `display`): the
/// request record's `store_root` when it has one, otherwise the store its
/// closures' object references (`runtime_object`, `env_object`) live in.
/// Only cleanup asks this. A root without a request record is never a
/// cache hit, but deleting one under the wrong store would leave the
/// owner's registration keeping its objects forever. Every read goes
/// through `root`, the descriptor cleanup removes by, so a rename of the
/// pathname cannot make the ownership check read a different root.
pub(super) fn originating_store_in(root: &fs::File, display: &Path) -> io::Result<Origin> {
    let marker = display.join(X_REQUEST_FILE);
    let tog = match store::open_directory_at(root.as_raw_fd(), b".tog") {
        Ok(tog) => Some(tog),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let marker_present = match tog
        .as_ref()
        .map(|tog| store::stat_at(tog.as_raw_fd(), X_REQUEST_NAME.as_bytes()))
    {
        Some(Ok(stat)) => {
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(other(format!(
                    "x: explicit request marker {} is not a regular file",
                    marker.display()
                )));
            }
            true
        }
        Some(Err(error)) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Some(Err(_)) | None => false,
    };
    if marker_present {
        let record = read_x_request_in(root).ok_or_else(|| {
            other(format!(
                "x: explicit request marker {} is malformed",
                marker.display()
            ))
        })?;
        if let Some(store_root) = record.store_root {
            let store_root = store_root.canonicalize().map_err(|error| {
                other(format!(
                    "x: recorded originating store {} is unavailable: {error}",
                    store_root.display()
                ))
            })?;
            let root_stat = fs::symlink_metadata(&store_root)?;
            let objects = store_root.join("objects");
            let objects_stat = fs::symlink_metadata(&objects)?;
            if root_stat.file_type().is_symlink()
                || !root_stat.is_dir()
                || objects_stat.file_type().is_symlink()
                || !objects_stat.is_dir()
            {
                return Err(other(format!(
                    "x: recorded originating store {} is not a real store",
                    store_root.display()
                )));
            }
            // A handle only: `clean` takes the exclusive lease on it before
            // it reads or removes anything, and the lease validates the
            // store's format marker.
            return Ok(Origin::Store(Store::handle(store_root)));
        }
    }
    Ok(
        read_closure_owner(tog.as_ref(), display).unwrap_or_else(|error| {
            Origin::Unknown(format!("its closures could not be read: {error}"))
        }),
    )
}

/// [`originating_store_in`] for a root named by its path.
#[cfg(test)]
pub(super) fn originating_store(root: &Path) -> io::Result<Origin> {
    originating_store_in(&open_directory_path(root)?, root)
}

/// The one store every closure under the held `.tog` directory references
/// objects in, read with the same no-follow rules as the rest of the x
/// root. A closure directory or file that cannot be read leaves the owner
/// unknown, so cleanup skips that root and goes on with the rest.
fn read_closure_owner(tog: Option<&fs::File>, display: &Path) -> io::Result<Origin> {
    let closures_path = display.join(".tog/closures");
    let closures = match tog.map(|tog| store::open_directory_at(tog.as_raw_fd(), b"closures")) {
        Some(Ok(closures)) => closures,
        Some(Err(error)) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Some(Err(_)) | None => return Ok(Origin::Empty),
    };
    let mut names = store::read_dir_names_at(closures.as_raw_fd())?;
    names.sort();
    let mut found: Option<Store> = None;
    let mut any = false;
    for name in names {
        let path = closures_path.join(&name);
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let stat = store::stat_at(closures.as_raw_fd(), name.as_bytes())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Ok(Origin::Unknown(format!(
                "closure {} is not a regular file",
                path.display()
            )));
        }
        any = true;
        let file = store::open_file_at(
            closures.as_raw_fd(),
            name.as_bytes(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )?;
        if !file.metadata()?.is_file() {
            return Ok(Origin::Unknown(format!(
                "closure {} is not a regular file",
                path.display()
            )));
        }
        let Ok(value) = serde_json::from_reader::<_, serde_json::Value>(file) else {
            return Ok(Origin::Unknown(format!(
                "closure {} is unreadable",
                path.display()
            )));
        };
        let body = &value["body"];
        let mut objects: Vec<PathBuf> = Vec::new();
        let runtime = &body["runtime_object"];
        if !runtime.is_null() {
            match (runtime["id"].as_str(), runtime["path"].as_str()) {
                (Some(id), Some(object))
                    if store::is_object_id(id)
                        && Path::new(object).file_name() == Some(id.as_ref()) =>
                {
                    objects.push(PathBuf::from(object));
                }
                _ => {
                    return Ok(Origin::Unknown(format!(
                        "closure {} has a malformed runtime_object",
                        path.display()
                    )))
                }
            }
        }
        if let Some(env) = body["env_object"].as_str() {
            objects.push(PathBuf::from(env));
        }
        if objects.is_empty() {
            return Ok(Origin::Unknown(format!(
                "closure {} names no store object",
                path.display()
            )));
        }
        for object in objects {
            let Some(store) = comforter::store_from_object_path(&object) else {
                return Ok(Origin::Unknown(format!(
                    "the store holding {} is unavailable",
                    object.display()
                )));
            };
            match &found {
                Some(previous) if previous.root != store.root => {
                    return Ok(Origin::Unknown(
                        "its closures name objects in more than one store".into(),
                    ))
                }
                Some(_) => {}
                None => found = Some(store),
            }
        }
    }
    Ok(match found {
        Some(store) => Origin::Store(store),
        None if any => Origin::Unknown("its closures name no store object".into()),
        None => Origin::Empty,
    })
}

/// The registry entry of the root at the canonical path `root`, found by
/// the key that path registers under. Matching on each entry's recorded
/// path instead would read an unusable entry (which has no path) as "not
/// registered", and cleanup would delete the root that entry protects.
pub(super) fn registration_for_store(root: &Path, store: Store) -> io::Result<Registration> {
    let key = Store::canonical_root_key(root);
    let Some(entry) = store.roots()?.into_iter().find(|entry| entry.key == key) else {
        return Ok(Registration::NotFound);
    };
    if let Some(why) = entry.unusable.clone() {
        return Ok(Registration::Unusable { store, key, why });
    }
    Ok(Registration::Found {
        store,
        entry: Box::new(entry),
    })
}

#[cfg(test)]
pub(super) fn registration_for(root: &Path) -> io::Result<Registration> {
    match originating_store(root)? {
        Origin::Store(store) => registration_for_store(&root.canonicalize()?, store),
        Origin::Empty | Origin::Unknown(_) => Ok(Registration::Unknown),
    }
}

// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
/// The exclusive lease `clean` removes one environment under, or `None`
/// with the skip already printed. The lease validates the store's format
/// marker. A recorded store this tog does not read is not ours to change:
/// its registration stays, so the root that registration protects stays
/// too. It is a skip rather than a failure because the store named may not
/// be the configured one, and the fix belongs to that store.
pub(super) fn clean_lease(
    origin_store: &Store,
    environment: &Path,
) -> io::Result<Option<StoreActivity>> {
    match origin_store.try_activity_exclusive() {
        Ok(Some(activity)) => Ok(Some(activity)),
        Ok(None) => {
            println!(
                "tog: skipped x environment {} (in use by a running tool; retry later; originating store is busy)",
                environment.display()
            );
            Ok(None)
        }
        Err(error) => match store::refusal_fix(&error) {
            Some(fix) => {
                println!(
                    "tog: skipped x environment {} (its originating store is not one this tog reads: {error}; fix: {fix})",
                    environment.display()
                );
                Ok(None)
            }
            None => Err(error),
        },
    }
}

/// What became of a candidate [`unregister_and_remove`] was handed.
pub(super) enum Removal {
    /// Gone, with the note the summary line carries.
    Removed(&'static str),
    /// The directory was not the candidate any more, before or after its
    /// registration was dropped.
    Changed { unregistered: bool },
}

/// Unregister `candidate`, then delete it by its held descriptor. A crash
/// or failure between the two leaves an unregistered directory, which costs
/// disk space and which the next bare clean removes. The other order leaves
/// a registration for a root that is gone, and the owning store keeps its
/// objects or refuses to sweep.
pub(super) fn unregister_and_remove(
    candidate: &XCandidate,
    registration: Registration,
    activity: &StoreActivity,
) -> io::Result<Removal> {
    let still_candidate = || -> io::Result<Option<libc::stat>> {
        match store::stat_at(candidate.x_dir.as_raw_fd(), candidate.name.as_bytes()) {
            Ok(current)
                if store::stat_identity(&current) == candidate.identity
                    && store::is_directory(&current) =>
            {
                Ok(Some(current))
            }
            Ok(_) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    };
    if still_candidate()?.is_none() {
        return Ok(Removal::Changed {
            unregistered: false,
        });
    }
    let note = match registration {
        Registration::Found { store, entry } => {
            store.remove_root_entry_with_activity(activity, &entry)?;
            ""
        }
        Registration::NotFound => " (no matching registry entry in its originating store)",
        Registration::Unusable { .. } => unreachable!("an unusable entry is skipped first"),
        #[cfg(test)]
        Registration::Unknown => {
            " (registry entry could not be dropped: originating store not found)"
        }
    };
    let unregistered = note.is_empty();
    // The candidate descriptor belongs to the directory that passed the
    // containment checks. Removing by pathname here would let a rename
    // followed by a symlink replacement redirect deletion elsewhere.
    store::remove_tree_at(candidate.directory.as_raw_fd())?;
    let Some(current) = still_candidate()? else {
        return Ok(Removal::Changed { unregistered });
    };
    if !store::unlink_if_same(
        candidate.x_dir.as_raw_fd(),
        candidate.name.as_bytes(),
        &current,
        libc::AT_REMOVEDIR,
    )? {
        return Ok(Removal::Changed { unregistered });
    }
    Ok(Removal::Removed(note))
}

/// Remove cached x projections. The store objects remain available for the
/// ordinary GC pass; deleting a projection is deliberately not object GC.
/// The exit status is 1 when any matched environment was skipped, so a
/// script cannot read a partial clean as a full one.
pub fn clean(request: CleanRequest) -> io::Result<i32> {
    let filter = clean_filter(request)?;
    let x_dir = home()?.join(".tog/x");
    let candidates = x_candidates(&x_dir)?;
    let mut matched = 0usize;
    let mut removed = 0usize;
    let mut skipped = 0usize;
    let mut notes: Vec<&'static str> = Vec::new();
    for candidate in candidates {
        match candidate_matches(&candidate, &filter) {
            CandidateMatch::Match => {}
            CandidateMatch::NoMatch => continue,
        }
        matched += 1;
        let ecosystem = candidate_ecosystem(&candidate.directory, &candidate.name);
        // Origin metadata is only a hint until the originating store is
        // protected. The root is removed and unregistered under the store
        // that owns it, never the caller's: a root whose owner cannot be
        // recovered is skipped, because removing it would leave that store's
        // registration keeping its objects. An empty shell references
        // nothing, so the x-root lock below is its whole guard and the
        // caller's store only lends the lease.
        let origin = match originating_store_in(&candidate.directory, &candidate.path)? {
            Origin::Unknown(why) => {
                println!(
                    "tog: skipped x environment {} (its owning store could not be recovered: {why}; remove the directory yourself once you know nothing is using it)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
            origin => origin,
        };
        let origin_store = match &origin {
            Origin::Store(store) => store.clone(),
            Origin::Empty | Origin::Unknown(_) => Store::open()?,
        };
        let Some(activity) = clean_lease(&origin_store, &candidate.path)? else {
            skipped += 1;
            continue;
        };
        let Some(_lock) = lock_x_root_at(candidate.x_dir.as_raw_fd(), &candidate.name, true, true)?
        else {
            println!(
                "tog: skipped x environment {} (in use by a running tool; retry later)",
                candidate.path.display()
            );
            skipped += 1;
            continue;
        };
        let _project_lock = origin_store.project_lock(&candidate.path)?;
        // Re-read the untrusted origin after both guards. A changed marker or
        // closure is a race, not permission to remove the candidate. An
        // empty shell must still be empty: gaining a claim while it was
        // being locked is the same race.
        match (
            &origin,
            originating_store_in(&candidate.directory, &candidate.path)?,
        ) {
            (Origin::Store(_), Origin::Store(revalidated_store)) => {
                if revalidated_store.root != origin_store.root {
                    println!(
                        "tog: skipped x environment {} (originating store changed while it was being locked; retry later)",
                        candidate.path.display()
                    );
                    skipped += 1;
                    continue;
                }
            }
            (Origin::Empty, Origin::Empty) => {}
            _ => {
                println!(
                    "tog: skipped x environment {} (origin changed while it was being locked; retry later)",
                    candidate.path.display()
                );
                skipped += 1;
                continue;
            }
        }
        let registration = match registration_for_store(&candidate.path, origin_store.clone())? {
            Registration::Unusable { store, key, why } => {
                println!(
                    "tog: skipped x environment {} (its registry entry {key} in store {} is unusable: {why}; inspect it with `tog store roots`, drop it with `tog gc --forget {key}` under that store, then clean again)",
                    candidate.path.display(),
                    store.root.display()
                );
                skipped += 1;
                continue;
            }
            registration => registration,
        };
        let removed_note = match unregister_and_remove(&candidate, registration, &activity)? {
            Removal::Removed(note) => note,
            Removal::Changed { unregistered } => {
                if unregistered {
                    println!(
                        "tog: x environment {} was unregistered, then disappeared or changed before it was removed; delete what is left of it yourself",
                        candidate.path.display()
                    );
                } else {
                    println!(
                        "tog: skipped x environment {} (it disappeared or changed; retry later)",
                        candidate.path.display()
                    );
                }
                skipped += 1;
                continue;
            }
        };
        if let Some(note) = ecosystem
            .and_then(|ecosystem| registry_tool(ecosystem).ok())
            .and_then(|tool| tool.clean_note())
        {
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
        println!(
            "tog: removed x environment {}{removed_note}",
            candidate.path.display()
        );
        // Only now has the environment stopped existing anywhere: the tree is
        // gone and so is its registry entry. Unlinking the lock before the
        // registry removal left a window in which a fresh runner could take a
        // new lock on the same name while the originating store still listed
        // the environment as registered. This still runs under the exclusive
        // lock taken above, so `.locks` stays bounded; a later runner
        // recreates the file.
        remove_x_root_lock_at(candidate.x_dir.as_raw_fd(), &candidate.name)?;
        removed += 1;
    }
    if matched == 0 {
        println!("tog: x clean: nothing to clean");
    } else {
        // A removed node environment also orphans its
        // forests/<project-key>/<projection-id> node_modules forest in the
        // originating store, which plain `tog gc` never visits.
        let forests: String = notes.iter().map(|note| format!(", and {note}")).collect();
        println!(
            "tog: x clean removed {removed} environment(s), skipped {skipped}; store objects remain until the next 'tog gc'{forests}"
        );
    }
    Ok(i32::from(skipped > 0))
}

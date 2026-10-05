//! Sweep phases 2 and 3 (kernel gc): `validate` turns the snapshot into a
//! proven liveness set or a structured refusal; `plan` produces the
//! fully-formed in-memory deletion plan a dry run prints.

use super::*;

/// A validated snapshot: the complete retained set, proven from complete
/// evidence. There is no partially valid form of this type.
pub struct Validated<'a> {
    pub(super) snapshot: &'a Snapshot,
    /// Everything the sweep must keep: durable roots, retention policy, and
    /// the transitive closure of both.
    pub(super) live: HashSet<String>,
    /// The part of `live` a durable project root protects. An object in
    /// `live` but not here survives only because retention policy kept it,
    /// which is a decision a dry run reports as `skipped:` rather than
    /// leaving silent.
    pub(super) root_live: HashSet<String>,
    /// Cache entries kept because a retained object names them.
    pub(super) referenced_cache: BTreeSet<String>,
}

pub(super) struct Removal {
    pub(super) parent: Parent,
    pub(super) name: std::ffi::OsString,
    pub(super) stat: libc::stat,
    /// The object's `meta/<id>.json`, unlinked with it.
    pub(super) companion: Option<(String, libc::stat)>,
    pub(super) label: String,
    pub(super) display: String,
    pub(super) bytes: u64,
    pub(super) counter: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Counter {
    Objects,
    CachedArtifacts,
    Stages,
    Forests,
    Backups,
    RunHomes,
    ProjectRecords,
    Records,
}

/// A fully-formed deletion plan plus everything retention deliberately kept.
pub struct SweepPlan {
    pub(super) removals: Vec<Removal>,
    pub(super) skips: Vec<String>,
}

impl SweepPlan {
    pub(super) fn report(&self) -> Report {
        let mut report = Report::default();
        for removal in &self.removals {
            report.freed_bytes += removal.bytes;
            match removal.counter {
                Counter::Objects => report.objects += 1,
                Counter::CachedArtifacts => report.cached_artifacts += 1,
                Counter::Stages => report.stages += 1,
                Counter::Forests => report.forests += 1,
                Counter::Backups => report.backups += 1,
                Counter::RunHomes => report.run_homes += 1,
                Counter::ProjectRecords => report.project_records += 1,
                Counter::Records => report.records += 1,
            }
        }
        report
    }
}

/// Phase 2. Prove the retained set, or refuse with every reason at once.
///
/// Missing or incomplete dependency information is never an empty dependency
/// list: it aborts the whole sweep. There is deliberately no partial-recovery
/// rule here.
pub(super) fn validate<'a>(snapshot: &'a Snapshot) -> io::Result<Validated<'a>> {
    let mut blocked: Vec<String> = Vec::new();

    // Every object must have a record. A record without its object is
    // removed by the plan, unless something retained still needs that
    // object (checked after the marking walk below).
    for entry in &snapshot.objects {
        if snapshot.meta.get(&entry.id).is_none() {
            blocked.push(format!(
                "object {} has no usable metadata; restore meta/{}.json, or drop the object \
                 with `tog gc --drop-object {}` and let the next sync rebuild it",
                entry.id, entry.id, entry.id
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
        if retained_by_policy(snapshot.now, entry) {
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
                     that names it with `tog store roots` and give up its protection with \
                     `tog gc --forget <key>`"
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
    // The walk follows records, so a needed object that is gone but left
    // its record behind is only visible here.
    for stray in &snapshot.stray_records {
        let id = stray_id(stray);
        if live.contains(id) {
            blocked.push(format!(
                "metadata for missing object {id}, which a retained object or root still \
                 needs; restore the object, or rebuild what needs it"
            ));
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

/// Every leftover under `tmp/` past the stage window.
fn stale_temporaries(snapshot: &Snapshot) -> io::Result<Vec<Removal>> {
    let mut temporaries = Vec::new();
    for entry in &snapshot.stages {
        if !older_than_at(snapshot.now, &entry.stat, STAGE_WINDOW) {
            continue;
        }
        let (bytes, partial) = temporary_size_at(
            snapshot.dirs.get(entry.parent).file.as_raw_fd(),
            entry.name.as_bytes(),
        )?;
        let measured = if partial {
            format!("at least {}", size(bytes))
        } else {
            size(bytes)
        };
        temporaries.push(Removal {
            parent: entry.parent,
            name: entry.name.clone(),
            stat: entry.stat,
            companion: None,
            label: format!("stage {}", entry.path.display()),
            display: format!(
                "stale {} {} ({})",
                tmp_kind(&entry.name),
                entry.path.display(),
                measured
            ),
            bytes,
            counter: Counter::Stages,
        });
    }
    Ok(temporaries)
}

/// Size private trash without changing permissions during planning. An
/// unreadable branch contributes zero, making the result a lower bound.
/// Execution repairs permissions through verified descriptors before removal.
fn temporary_size_at(parent: std::os::fd::RawFd, name: &[u8]) -> io::Result<(u64, bool)> {
    let stat = store::stat_at(parent, name)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Ok((file_size_of(&stat), false));
    }
    let dir = match store::open_file_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok((0, true)),
        Err(error) => return Err(error),
    };
    if !store::same_inode(&stat, &store::fd_stat(dir.as_raw_fd())?) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "temporary directory changed while sizing",
        ));
    }
    let mut bytes = 0u64;
    let mut partial = false;
    for name in store::read_dir_names_at(dir.as_raw_fd())? {
        match temporary_size_at(dir.as_raw_fd(), name.as_bytes()) {
            Ok((child_bytes, child_partial)) => {
                bytes = bytes.saturating_add(child_bytes);
                partial |= child_partial;
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => partial = true,
            Err(error) => return Err(error),
        }
    }
    Ok((bytes, partial))
}

/// Every record whose object is gone. Validation proved no retained object
/// needs one.
fn stray_record_removals(snapshot: &Snapshot) -> impl Iterator<Item = Removal> + '_ {
    snapshot.stray_records.iter().map(|stray| Removal {
        parent: stray.parent,
        name: stray.name.clone(),
        stat: stray.stat,
        companion: None,
        label: format!("record meta/{}", stray.name.to_string_lossy()),
        display: format!(
            "record {} (its object is already gone)",
            stray.path.display()
        ),
        bytes: file_size_of(&stray.stat),
        counter: Counter::Records,
    })
}

/// The object id a stray record names: its file name without `.json`.
fn stray_id(stray: &DirEntrySnapshot) -> &str {
    let name = stray
        .name
        .to_str()
        .expect("record names are UTF-8 object ids");
    name.strip_suffix(".json").unwrap_or(name)
}

/// The transitive closure of `seeds` over proven dependencies. A seed or
/// dependency with no record is simply not traversed; the marking walk in
/// `validate` is what reports it as a blockage.
pub(super) fn reachable(snapshot: &Snapshot, seeds: &HashSet<String>) -> HashSet<String> {
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

pub(super) fn blockage(reasons: &[String]) -> io::Error {
    let mut message = String::from("refusing to sweep: nothing was deleted");
    for reason in reasons {
        message.push_str("\n  blocked: ");
        message.push_str(reason);
    }
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Retention policy, evaluated against the frozen snapshot time so a dry run
/// and the sweep that follows it choose the same candidates.
///
/// The one rule: an object used within the active window is kept, so a sync
/// that has published it and not yet written its root cannot lose it.
pub(super) fn retained_by_policy(now: SystemTime, entry: &ObjectEntry) -> bool {
    recent_at(now, &entry.stat, ACTIVE_WINDOW)
}

/// Phase 3. Build the complete deletion plan. Nothing is removed here.
pub(super) fn plan(validated: &Validated, options: &Options) -> io::Result<SweepPlan> {
    let snapshot = validated.snapshot;
    let mut removals: Vec<Removal> = stray_record_removals(snapshot).collect();
    let mut skips = Vec::new();

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
        // This *is* a decision, and it must be visible next to
        // the deletion candidates rather than silently folded into them.
        if validated.live.contains(&entry.id) {
            let reason = if recent_at(snapshot.now, &entry.stat, ACTIVE_WINDOW) {
                "it was used within the active window"
            } else {
                "another object retention policy is keeping depends on it"
            };
            skips.push(format!(
                "object {} ([{}]) — {reason}",
                entry.id, record.identity.kind
            ));
            continue;
        }
        let bytes = tree_size(&entry.path)? + file_size_of(&entry.meta_stat);
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

    removals.extend(stale_temporaries(snapshot)?);

    if options.project {
        plan_projections(snapshot, options, &mut removals, &mut skips)?;
    }

    Ok(SweepPlan { removals, skips })
}

/// What a `--project` sweep adds: old forests and backups no surviving root
/// claims, run homes of projects no root names, and store records about a
/// project whose directory is gone.
fn plan_projections(
    snapshot: &Snapshot,
    options: &Options,
    removals: &mut Vec<Removal>,
    skips: &mut Vec<String>,
) -> io::Result<()> {
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
    // A run home holds a project's Mix, Hex and NuGet caches. It is kept
    // while any surviving root names its project, however old, and
    // otherwise once it is older than the keep window.
    for entry in &snapshot.run_homes {
        let key = entry.name.to_string_lossy();
        if snapshot.state.run_home_keys.contains(key.as_ref()) {
            continue;
        }
        if !older_than_at(snapshot.now, &entry.stat, keep_age(options.keep_days)) {
            skips.push(format!(
                "run home {} is younger than the keep window",
                entry.path.display()
            ));
            continue;
        }
        let bytes = tree_size(&entry.path)?;
        removals.push(Removal {
            parent: entry.parent,
            name: entry.name.clone(),
            stat: entry.stat,
            companion: None,
            label: format!("run home {}", entry.path.display()),
            display: format!(
                "run home {} of a project no root names ({})",
                entry.path.display(),
                size(bytes)
            ),
            bytes,
            counter: Counter::RunHomes,
        });
    }
    // A project record is a cache of work tog did in that project (a
    // passing `mix deps.get --check-locked`), so removing it loses nothing
    // tog cannot redo: a project that comes back (a drive mounted again, a
    // directory restored) pays one more registry check and is recorded anew.
    for entry in &snapshot.orphan_records {
        let bytes = file_size_of(&entry.stat);
        removals.push(Removal {
            parent: entry.parent,
            name: entry.name.clone(),
            stat: entry.stat,
            companion: None,
            label: format!("store record {}", entry.path.display()),
            display: format!(
                "store record {} about a project that is gone ({})",
                entry.path.display(),
                size(bytes)
            ),
            bytes,
            counter: Counter::ProjectRecords,
        });
    }
    Ok(())
}

pub(super) fn report_plan<W: Write>(plan: &SweepPlan, out: &mut W) -> io::Result<()> {
    for removal in &plan.removals {
        writeln!(out, "would remove {}", removal.display)?;
    }
    for skip in &plan.skips {
        writeln!(out, "skipped: {skip}")?;
    }
    Ok(())
}

#[cfg(test)]
mod plan_tests {
    use super::super::tests::TempStore;
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use std::time::UNIX_EPOCH;

    /// Every fixture's mtime is a whole second counted from here, and every
    /// plan runs at a frozen `now` counted from the same place, so each age
    /// below is exact rather than "roughly a day, give or take the test".
    const T0: u64 = 1_700_000_000;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(T0 + seconds)
    }

    /// A directory holding one five-byte file, its mtime set last (writing
    /// the file would bump it) to `T0 + seconds`.
    fn entry(path: &Path, seconds: u64) -> PathBuf {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("payload"), b"bytes").unwrap();
        fs::File::open(path)
            .unwrap()
            .set_modified(at(seconds))
            .unwrap();
        path.to_path_buf()
    }

    fn forest(components: &[&str]) -> store::ProjectionRef {
        store::ProjectionRef::new(
            store::ProjectionBase::Forests,
            components.iter().map(|c| (*c).into()).collect(),
        )
        .unwrap()
    }

    fn backup(name: &str) -> store::ProjectionRef {
        store::ProjectionRef::new(store::ProjectionBase::Backups, vec![name.into()]).unwrap()
    }

    /// Register one durable root record claiming `projections`. A sweep
    /// needs a registry to read, so even an unclaimed fixture registers one.
    fn claim(temp: &TempStore, projections: Vec<store::ProjectionRef>) {
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        store
            .register_root_record(store::RootRecord {
                key: Store::root_key(&project).unwrap(),
                project_path: project,
                objects: BTreeSet::new(),
                projections: projections.into_iter().collect(),
                updated: 1,
            })
            .unwrap();
    }

    /// The real read and validate phases, with the snapshot's decision time
    /// frozen at `now`. `read_options` and `plan_options` differ only in the
    /// test of the `project` gate, which needs a snapshot that *has*
    /// projections planned by a sweep that must ignore them.
    fn plan_at(
        store: &Store,
        read_options: &Options,
        plan_options: &Options,
        now: SystemTime,
    ) -> SweepPlan {
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut snapshot = read(store, &activity, read_options).unwrap();
        snapshot.now = now;
        let validated = validate(&snapshot).unwrap();
        plan(&validated, plan_options).unwrap()
    }

    fn removed(plan: &SweepPlan, counter: Counter) -> Vec<String> {
        let mut displays: Vec<String> = plan
            .removals
            .iter()
            .filter(|removal| removal.counter == counter)
            .map(|removal| removal.display.clone())
            .collect();
        displays.sort();
        displays
    }

    fn sorted(mut lines: Vec<String>) -> Vec<String> {
        lines.sort();
        lines
    }

    fn project(keep_days: u64) -> Options {
        Options {
            keep_days,
            project: true,
            ..Options::default()
        }
    }

    const WINDOW: u64 = STAGE_WINDOW.as_secs();

    /// An interrupted stage is removed once it is older than the stage
    /// window, and not a second sooner: at exactly the window it is kept.
    /// `--keep-days` does not move that line in either direction.
    #[test]
    fn a_stage_older_than_the_stage_window_is_planned_and_a_younger_one_is_not() {
        let temp = TempStore::new("plan-stage");
        let store = temp.store();
        let stage = store.stage().unwrap();
        entry(&stage, 0);
        claim(&temp, Vec::new());
        let stale = format!("stale stage {} (5 B)", stage.display());

        for keep_days in [0, 30, 365] {
            let options = Options::keep_days(keep_days);
            let plan = plan_at(&store, &options, &options, at(WINDOW + 1));
            assert_eq!(
                removed(&plan, Counter::Stages),
                std::slice::from_ref(&stale)
            );
            assert_eq!(plan.removals.len(), 1);
            assert_eq!(plan.report().stages, 1);
            assert_eq!(plan.report().freed_bytes, 5);
            assert!(plan.skips.is_empty(), "{:?}", plan.skips);

            for now in [WINDOW, WINDOW - 1, 60 * 60, 0] {
                let plan = plan_at(&store, &options, &options, at(now));
                assert!(
                    plan.removals.is_empty(),
                    "a stage {now}s old was planned with --keep-days {keep_days}"
                );
                assert_eq!(plan.report(), Report::default());
            }
        }
    }

    /// Forest claims, in every direction `related` recognises, and the one
    /// it must not: a sibling that merely shares a name prefix.
    #[test]
    fn a_claimed_forest_is_skipped_and_only_a_stale_unclaimed_one_is_removed() {
        let temp = TempStore::new("plan-forests");
        let store = temp.store();
        let forests = store.root.join("forests");
        // Claimed exactly.
        let exact = entry(&forests.join("k1/exact"), 0);
        // Claimed through an ancestor: the record names the whole project.
        let below = entry(&forests.join("k2/node_modules"), 0);
        // Claimed through a descendant: the record names a path inside it.
        let above = entry(&forests.join("k3/hex-deps/deps/jason"), 0);
        let above = above.parent().unwrap().parent().unwrap().to_path_buf();
        fs::File::open(&above).unwrap().set_modified(at(0)).unwrap();
        // `proj` is claimed; `proj2` shares its name as a string prefix only.
        let proj = entry(&forests.join("k4/proj"), 0);
        let proj2 = entry(&forests.join("k4/proj2"), 0);
        // Unclaimed: stale, exactly at the window, and fresh.
        let stale = entry(&forests.join("k5/stale"), 0);
        let boundary = entry(&forests.join("k5/boundary"), 1);
        let fresh = entry(&forests.join("k5/fresh"), WINDOW - 60 * 60);
        claim(
            &temp,
            vec![
                forest(&["k1", "exact"]),
                forest(&["k2"]),
                forest(&["k3", "hex-deps", "deps"]),
                forest(&["k4", "proj"]),
            ],
        );

        // Forest age is the stage window, whatever `--keep-days` says.
        for keep_days in [0, 30] {
            let options = project(keep_days);
            let plan = plan_at(&store, &options, &options, at(WINDOW + 1));
            assert_eq!(
                removed(&plan, Counter::Forests),
                sorted(vec![
                    format!("stale forest {} (5 B)", proj2.display()),
                    format!("stale forest {} (5 B)", stale.display()),
                ]),
                "--keep-days {keep_days}"
            );
            assert_eq!(plan.report().forests, 2);
            assert_eq!(
                sorted(plan.skips.clone()),
                sorted(
                    [&exact, &below, &above, &proj]
                        .iter()
                        .map(|path| format!(
                            "forest {} is claimed by a surviving root record",
                            path.display()
                        ))
                        .collect()
                )
            );
            for kept in [&boundary, &fresh] {
                let name = kept.display().to_string();
                assert!(
                    !plan.removals.iter().any(|r| r.display.contains(&name))
                        && !plan.skips.iter().any(|s| s.contains(&name)),
                    "{name} was planned or narrated"
                );
            }
        }
    }

    /// Backups: claimed ones are skipped, and an unclaimed one goes only
    /// once it is older than `--keep-days`, which moves the line.
    #[test]
    fn an_unclaimed_backup_is_removed_only_past_keep_days_and_a_claimed_one_is_skipped() {
        let temp = TempStore::new("plan-backups");
        let store = temp.store();
        let backups = store.root.join("backups");
        const DAY: u64 = 24 * 60 * 60;
        let claimed = entry(&backups.join("key-node_modules"), 0);
        let sibling = entry(&backups.join("key-node_modules2"), 0);
        let old = entry(&backups.join("old"), 0);
        let boundary = entry(&backups.join("boundary"), 1);
        let young = entry(&backups.join("young"), 2 * DAY);
        claim(&temp, vec![backup("key-node_modules")]);
        let now = at(3 * DAY + 1);
        let gone = |paths: &[&PathBuf]| -> Vec<String> {
            sorted(
                paths
                    .iter()
                    .map(|path| format!("backup {} (5 B)", path.display()))
                    .collect(),
            )
        };
        let skip = format!(
            "backup {} is claimed by a surviving root record",
            claimed.display()
        );

        // keep_days 3: `old` is one second past it, `boundary` exactly at it.
        let plan = plan_at(&store, &project(3), &project(3), now);
        assert_eq!(removed(&plan, Counter::Backups), gone(&[&old, &sibling]));
        assert_eq!(plan.report().backups, 2);
        assert_eq!(plan.skips, std::slice::from_ref(&skip));

        // A longer keep window keeps them all; a shorter one takes `young`.
        let plan = plan_at(&store, &project(4), &project(4), now);
        assert_eq!(removed(&plan, Counter::Backups), Vec::<String>::new());
        assert_eq!(plan.skips, std::slice::from_ref(&skip));
        let plan = plan_at(&store, &project(1), &project(1), now);
        assert_eq!(
            removed(&plan, Counter::Backups),
            gone(&[&old, &sibling, &boundary, &young])
        );
        assert_eq!(plan.skips, [skip]);
        assert!(claimed.is_dir(), "planning removed something");
    }

    /// Forests and backups are the project sweep's business. A snapshot
    /// that has read them is still planned without them unless the sweep
    /// was asked for `--project`.
    #[test]
    fn forests_and_backups_are_planned_only_for_a_project_sweep() {
        let temp = TempStore::new("plan-project-gate");
        let store = temp.store();
        let forest = entry(&store.root.join("forests/k/stale"), 0);
        let backup = entry(&store.root.join("backups/stale"), 0);
        claim(&temp, Vec::new());
        let now = at(WINDOW + 1);

        let plan = plan_at(&store, &project(0), &Options::keep_days(0), now);
        assert!(
            plan.removals.is_empty(),
            "{:?}",
            removed(&plan, Counter::Forests)
        );
        assert!(plan.skips.is_empty(), "{:?}", plan.skips);
        assert_eq!(plan.report(), Report::default());

        let plan = plan_at(&store, &project(0), &project(0), now);
        assert_eq!(
            removed(&plan, Counter::Forests),
            [format!("stale forest {} (5 B)", forest.display())]
        );
        assert_eq!(
            removed(&plan, Counter::Backups),
            [format!("backup {} (5 B)", backup.display())]
        );
    }

    /// `read` already refuses an object whose record file is missing, so
    /// this guard has no way in through a real store. It stays because it
    /// is the last check before a sweep decides what to delete: a snapshot
    /// holding an object the index has no record for must be refused, with
    /// the fix named, whatever let it through.
    #[test]
    fn an_object_the_index_has_no_record_for_is_refused_with_the_fix() {
        let temp = TempStore::new("plan-no-record");
        let store = temp.store();
        let id = super::super::tests::commit(&store, "orphan", None);
        claim(&temp, Vec::new());
        let options = Options::keep_days(0);
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut snapshot = read(&store, &activity, &options).unwrap();
        assert!(validate(&snapshot).is_ok());

        snapshot.meta = crate::kernel::objmeta::MetaIndex::default();
        let error = validate(&snapshot).err().unwrap().to_string();
        assert!(
            error.contains(&format!("object {id} has no usable metadata"))
                && error.contains(&format!("tog gc --drop-object {id}")),
            "{error}"
        );
    }
}

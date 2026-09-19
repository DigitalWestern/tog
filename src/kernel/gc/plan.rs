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
}

/// A fully-formed deletion plan plus everything retention deliberately kept.
pub struct SweepPlan {
    pub(super) removals: Vec<Removal>,
    pub(super) skips: Vec<String>,
    pub(super) notes: Vec<String>,
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
pub(super) fn validate<'a>(snapshot: &'a Snapshot, options: &Options) -> io::Result<Validated<'a>> {
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
                "metadata for missing object {id}; remove meta/{id}.json with `tog gc \
                 --migrate-metadata` after restoring the object, or delete the stray record"
            ));
        }
    }

    // Legacy evidence can never authorize a deletion. Maintenance runs before
    // this phase, so anything still legacy here could not be certified.
    for (id, record) in snapshot.meta.iter() {
        if record.evidence == crate::kernel::objmeta::Evidence::Legacy {
            blocked.push(format!(
                "object {id} ({}) still carries pre-object-meta/2 metadata; its dependencies are \
                 not proven, so no sweep can run. Run `tog gc --migrate-metadata` and resolve \
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
pub(super) fn retained_by_policy(
    now: SystemTime,
    entry: &ObjectEntry,
    record: &crate::kernel::objmeta::Record,
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
pub(super) fn plan(validated: &Validated, options: &Options) -> io::Result<SweepPlan> {
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
        // This *is* a decision, and it must be visible next to
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

pub(super) fn report_plan<W: Write>(plan: &SweepPlan, out: &mut W) -> io::Result<()> {
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

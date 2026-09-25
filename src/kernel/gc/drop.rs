//! `tog gc --drop-object` (kernel gc): the one deletion that happens outside
//! the sweep, and the only way out of a store the sweep cannot read.
//!
//! The sweep is fail-closed by design: a record it cannot parse, or cannot
//! certify, stops every deletion. That is right — deleting through evidence
//! nothing can read is how a store loses an object something still needs.
//! But it leaves an operator with a store that refuses to sweep and no
//! command that changes the situation. This is that command.
//!
//! It is narrow on purpose. It removes only what the operator named, only
//! when that object is already unusable, already unproven, or already half
//! gone, and never when a record that *is* readable still proves it needed.
//! Everything it removes is content-addressed, so the next sync that needs
//! the object rebuilds it at the same id.
//!
//! Within one invocation it unlinks every record first and only then removes
//! the object trees, so an error partway through can leave bare objects —
//! which this same command drops again — but never a readable record
//! pointing at an id that no longer exists. See `drop_objects`.

use super::*;

/// Why one requested id may be removed. Printed with the removal so the
/// operator sees which rule applied, not just that something was deleted.
struct Droppable {
    id: String,
    reason: String,
}

/// Remove named objects and their records, outside the sweep.
///
/// Every id is checked before anything is removed: a half-applied drop would
/// leave exactly the orphaned-record state this command exists to clear.
/// Returns the number of objects dropped (or, on a dry run, that would be).
pub fn drop_objects<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    ids: &[String],
    dry_run: bool,
    out: &mut W,
) -> io::Result<usize> {
    store.require_exclusive_activity(activity, "dropping store objects")?;
    if ids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--drop-object needs at least one store object id",
        ));
    }
    for (index, id) in ids.iter().enumerate() {
        // The CLI already checks the shape, but this is the layer that turns
        // an id into a path under `objects/`, so it is the layer that must
        // never take one on trust.
        if !store::is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{id:?} is not a store object id"),
            ));
        }
        if ids[..index].contains(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to drop object {id} more than once in one invocation"),
            ));
        }
    }
    // Held across the whole check-and-remove window, so a sync cannot
    // publish something that depends on an id between the two.
    let _publish = store.publish_lock()?;
    let (index, unusable) = crate::kernel::objmeta::MetaIndex::read_reporting_unusable(store)?;

    let requested: BTreeSet<String> = ids.iter().cloned().collect();
    let droppable = eligible(store, &index, &unusable, ids)?;
    refuse_if_still_depended_on(&index, ids, &requested)?;

    let mut dropped = 0;
    if dry_run {
        for entry in &droppable {
            writeln!(
                out,
                "tog: would drop object {} ({})",
                entry.id, entry.reason
            )?;
            dropped += 1;
        }
        return Ok(dropped);
    }
    // Records first, objects second, across the whole batch rather than per
    // id. There is no rollback here, so the only thing that can be chosen is
    // what a crash or an I/O error in the middle leaves behind, and the two
    // orders are not equally survivable:
    //
    //   records first: some bare objects, each droppable again as "object
    //     without metadata", and every record that is still there still has
    //     its object.
    //   objects first: a readable record naming an id with nothing under
    //     `objects/`, which blocks the sweep and — if something else in the
    //     batch already proved it a dependency — cannot be rebuilt, because
    //     the dependent's id is unchanged and a sync would take the cache
    //     hit.
    //
    // Only the first is recoverable with the command the operator already
    // has, so removal runs in that order.
    for entry in &droppable {
        unlink_record(store, &entry.id)?;
    }
    for entry in &droppable {
        remove_object(store, &entry.id)?;
        writeln!(out, "tog: dropped object {} ({})", entry.id, entry.reason)?;
        dropped += 1;
    }
    if !dry_run {
        // The store just changed in the operator's favour. Whatever the last
        // deferral said, it is now stale, so the next command re-evaluates.
        clear_deferral_marker(store)?;
    }
    Ok(dropped)
}

/// Classify every requested id, or refuse.
///
/// The rules run in one fixed order, and the first that matches wins: an
/// unusable record, a legacy record migration could not prove, a record
/// whose object is gone, an object whose record is gone. A record that is
/// readable, certified and paired with its object is the one case this
/// command will not touch — the sweep is the thing that decides whether
/// such an object is still needed, and it can decide it.
fn eligible(
    store: &Store,
    index: &crate::kernel::objmeta::MetaIndex,
    unusable: &BTreeMap<String, String>,
    ids: &[String],
) -> io::Result<Vec<Droppable>> {
    let mut droppable: BTreeMap<String, String> = BTreeMap::new();
    // Ids whose only claim is "something else in this batch is going away".
    // They are settled after the base rules, because the batch is not known
    // until every base rule has run.
    let mut usable_and_present: Vec<&str> = Vec::new();
    for id in ids {
        let object_present = match fs::symlink_metadata(store.object_path(id)) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        // Checked here, in the phase that refuses before anything is
        // removed, because the removal itself unlinks by pathname: a symlink
        // or a directory at the record's name is a shape `fs::remove_file`
        // would either follow or fail on, halfway through a batch.
        match fs::symlink_metadata(record_path(store, id)) {
            Ok(stat) if stat.file_type().is_symlink() || !stat.is_file() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object {id} metadata is not a regular file"),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(reason) = unusable.get(&format!("{id}.json")) {
            droppable.insert(id.clone(), reason.clone());
            continue;
        }
        match index.get(id) {
            Some(record) if record.evidence == crate::kernel::objmeta::Evidence::Legacy => {
                droppable.insert(
                    id.clone(),
                    "pre-object-meta/2 metadata that migration could not prove".to_string(),
                );
            }
            Some(_) if !object_present => {
                droppable.insert(id.clone(), "metadata for a missing object".to_string());
            }
            Some(_) => usable_and_present.push(id),
            None if object_present => {
                droppable.insert(id.clone(), "object without metadata".to_string());
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such object {id}"),
                ));
            }
        }
    }

    // A usable object whose own dependency is being dropped is not usable
    // for much longer: its closure is about to lose a member, and the sweep
    // would wedge on exactly that. Cascading is transitive, so this runs to
    // a fixpoint; it only ever adds, so it terminates in at most one round
    // per requested id.
    loop {
        let mut added = false;
        usable_and_present.retain(|id| {
            let record = index.get(id).expect("classified from the index");
            let Some(dependency) = record
                .dependencies
                .iter()
                .find(|dependency| droppable.contains_key(*dependency))
            else {
                return true;
            };
            droppable.insert(
                (*id).to_string(),
                format!("depends on {dependency}, which is being dropped"),
            );
            added = true;
            false
        });
        if !added {
            break;
        }
    }

    if let Some(id) = usable_and_present.first() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "object {id} has usable metadata; the sweep decides whether it is needed. \
                 Forget the roots that protect it (`tog store roots`, `tog gc --forget \
                 <key>`) and run `tog gc`"
            ),
        ));
    }
    Ok(ids
        .iter()
        .map(|id| Droppable {
            id: id.clone(),
            reason: droppable
                .remove(id)
                .expect("every id is classified or refused above"),
        })
        .collect())
}

/// Refuse if a record that is still readable would be left naming an object
/// this invocation is about to remove.
///
/// This is not tidiness. A dangling dependency wedges the sweep the same way
/// the unusable record did, and a sync would not repair it: the dependent's
/// id is unchanged, so it is a cache hit and nothing rebuilds the dependency.
/// The whole affected set has to go together, and the refusal spells out the
/// command that does it.
fn refuse_if_still_depended_on(
    index: &crate::kernel::objmeta::MetaIndex,
    ids: &[String],
    requested: &BTreeSet<String>,
) -> io::Result<()> {
    let mut dependents_of: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (id, record) in index.iter() {
        for dependency in &record.dependencies {
            dependents_of
                .entry(dependency.as_str())
                .or_default()
                .insert(id.as_str());
        }
    }
    let transitive_dependents = |seed: &str| -> BTreeSet<String> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<String> = VecDeque::from([seed.to_string()]);
        while let Some(id) = queue.pop_front() {
            for dependent in dependents_of.get(id.as_str()).into_iter().flatten() {
                if seen.insert((*dependent).to_string()) {
                    queue.push_back((*dependent).to_string());
                }
            }
        }
        seen
    };

    let mut whole_set: BTreeSet<String> = requested.clone();
    let mut refusal: Option<(String, usize)> = None;
    for id in ids {
        let dependents = transitive_dependents(id);
        let outside = dependents
            .iter()
            .filter(|dependent| !requested.contains(*dependent))
            .count();
        if outside != 0 && refusal.is_none() {
            refusal = Some((id.clone(), outside));
        }
        whole_set.extend(dependents);
    }
    let Some((id, outside)) = refusal else {
        return Ok(());
    };
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "object {id} is a proven dependency of {outside} other object(s); drop the whole \
             set: `tog gc --drop-object {}`",
            whole_set.into_iter().collect::<Vec<_>>().join(" ")
        ),
    ))
}

/// The record half of a drop. `eligible` has already proved the path is a
/// regular file or absent, so this never unlinks through a symlink.
fn unlink_record(store: &Store, id: &str) -> io::Result<()> {
    match fs::remove_file(record_path(store, id)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The object half of a drop.
fn remove_object(store: &Store, id: &str) -> io::Result<()> {
    let object = store.object_path(id);
    match fs::symlink_metadata(&object) {
        // Published objects are read-only trees; `remove_tree` restores the
        // write bits before unlinking, which is how the store removes its
        // own staged and committed trees everywhere else.
        Ok(stat) if stat.is_dir() => store::remove_tree(&object),
        // Anything else at that name — a symlink, a stray file — is not an
        // object at all, but it still occupies the id, so it goes too.
        Ok(_) => fs::remove_file(&object),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn record_path(store: &Store, id: &str) -> PathBuf {
    store.root.join("meta").join(format!("{id}.json"))
}

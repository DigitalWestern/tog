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
    Ok(dropped)
}

/// Classify every requested id, or refuse.
///
/// The rules run in one fixed order, and the first that matches wins: an
/// unusable record, a record whose object is gone, an object whose record
/// is gone. A record that is readable and paired with its object is the one
/// case this
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

#[cfg(test)]
mod drop_tests {
    use super::super::tests::{register_objects, test_identity, wedge, TempStore};
    use super::*;
    use crate::kernel::activity::ActivityMode;

    fn run(
        store: &Store,
        activity: &StoreActivity,
        ids: &[String],
        dry_run: bool,
    ) -> (io::Result<usize>, String) {
        let mut out = Vec::new();
        let result = drop_objects(store, activity, ids, dry_run, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    fn exclusive(store: &Store, ids: &[String], dry_run: bool) -> (io::Result<usize>, String) {
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        run(store, &activity, ids, dry_run)
    }

    /// An object directory with no record: droppable, with a fixed reason.
    fn bare(store: &Store, name: &str) -> String {
        let id = test_identity(name, None).object_id();
        fs::create_dir_all(store.object_path(&id)).unwrap();
        fs::write(store.object_path(&id).join("payload"), name).unwrap();
        id
    }

    fn refusal(result: io::Result<usize>) -> (io::ErrorKind, String) {
        let error = result.expect_err("the drop was not refused");
        (error.kind(), error.to_string())
    }

    /// Both halves of a wedged object are still on disk.
    fn intact(store: &Store, id: &str) -> bool {
        store.object_path(id).join("payload").is_file() && record_path(store, id).is_file()
    }

    /// Every shape that would turn an id into a path outside `objects/`, or
    /// into more than one entry inside it, or that is not an object id: the
    /// prefix is 40 hex, byte 40 is `-`, and the label is `[A-Za-z0-9._-]`
    /// with no `..`.
    fn hostile() -> Vec<String> {
        let hex = "0".repeat(40);
        let valid = test_identity("valid", None).object_id();
        let short = "0".repeat(39);
        vec![
            String::new(),
            "..".into(),
            ".".into(),
            "../x".into(),
            "a/b".into(),
            "/abs".into(),
            format!("{hex}-../../x"),
            format!("{hex}-../x"),
            format!("{hex}-x/y"),
            format!("{valid}\0"),
            format!("{hex}-na\0me"),
            format!("{hex}-a..b\0"),
            hex.clone(),
            format!("{hex}-"),
            // The prefix: one non-hex digit, uppercase with a `..` label,
            // and one digit short.
            format!("g{short}-name-1"),
            format!("g{short}-a..b-1"),
            format!("{}-a..b-1", "A".repeat(40)),
            format!("{short}-name-1"),
            format!("{short}-a..b-1"),
            // Byte 40 is the separator, and nothing else is.
            format!("{hex}_name-1"),
            format!("{hex}.name-1"),
            format!("{hex}_a..b-1"),
            format!("{hex}0-name-1"),
            // The label.
            format!("{hex}-na me-1"),
            format!("{hex}-name-1\t"),
            format!("{hex}-a..b 1"),
            format!("{hex}-nam\u{e9}-1"),
            format!("{hex}-a..b-\u{e9}"),
            format!("{hex}-name..version"),
            format!("{valid}.."),
            format!("{hex}-a..b-1"),
            format!("{hex}-..."),
        ]
    }

    /// The reason `wedge`'s record is unusable, as the drop prints it.
    fn mismatch(id: &str) -> String {
        format!("object {id} identity hashes to a different object id")
    }

    fn sweep(store: &Store) -> (io::Result<Report>, String) {
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let result = collect_with_activity(store, &activity, Options::default(), &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    #[test]
    fn an_empty_id_list_is_refused() {
        let temp = TempStore::new("drop-empty");
        let store = temp.store();
        let id = bare(&store, "kept");

        let (result, text) = exclusive(&store, &[], false);
        assert_eq!(
            refusal(result),
            (
                io::ErrorKind::InvalidInput,
                "--drop-object needs at least one store object id".to_string()
            )
        );
        assert!(text.is_empty(), "{text}");
        assert!(store.object_path(&id).is_dir());
    }

    /// Checked alone, and last in a batch whose first id is really
    /// droppable: the shape check runs over every id before anything is
    /// removed, so neither half of the first object may go.
    #[test]
    fn a_hostile_id_is_refused_before_anything_is_removed() {
        let temp = TempStore::new("drop-hostile");
        let store = temp.store();
        let wedged = wedge(&store, "wedged");
        let objects = store.root.join("objects");
        for id in hostile() {
            let expected = (
                io::ErrorKind::InvalidInput,
                format!("{id:?} is not a store object id"),
            );
            for batch in [vec![id.clone()], vec![wedged.clone(), id.clone()]] {
                let (result, text) = exclusive(&store, &batch, false);
                assert_eq!(refusal(result), expected, "{batch:?}");
                assert!(text.is_empty(), "{batch:?}: {text}");
                assert!(
                    intact(&store, &wedged) && objects.is_dir(),
                    "{batch:?} removed something before its shape was refused"
                );
            }
        }
        // The control: the same first id, with nothing hostile after it,
        // does go. So the refusals above were the shape check, not a store
        // that could not drop it anyway.
        let (count, text) = exclusive(&store, std::slice::from_ref(&wedged), false);
        assert_eq!(count.unwrap(), 1, "{text}");
        assert!(!store.object_path(&wedged).exists(), "{text}");
    }

    #[test]
    fn a_duplicate_id_is_refused_before_anything_is_removed() {
        let temp = TempStore::new("drop-duplicate");
        let store = temp.store();
        let first = wedge(&store, "first");
        let second = bare(&store, "second");
        for batch in [
            vec![second.clone(), second.clone()],
            vec![first.clone(), second.clone(), first.clone()],
        ] {
            let repeated = batch.last().unwrap();
            let (result, text) = exclusive(&store, &batch, false);
            assert_eq!(
                refusal(result),
                (
                    io::ErrorKind::InvalidInput,
                    format!("refusing to drop object {repeated} more than once in one invocation")
                )
            );
            assert!(text.is_empty(), "{text}");
            assert!(intact(&store, &first));
            assert!(store.object_path(&second).is_dir());
        }
    }

    /// A shared lease, or another store's exclusive one, authorizes nothing.
    #[test]
    fn dropping_requires_this_stores_exclusive_lease() {
        let temp = TempStore::new("drop-lease");
        let store = temp.store();
        let other_temp = TempStore::new("drop-lease-other");
        let other = other_temp.store();
        let id = wedge(&store, "wedged");
        let expected = (
            io::ErrorKind::Other,
            format!(
                "dropping store objects requires an active exclusive lease for store {}",
                store.root.canonicalize().unwrap().display()
            ),
        );

        let shared = store.activity(ActivityMode::Shared).unwrap();
        let (result, text) = run(&store, &shared, std::slice::from_ref(&id), false);
        assert_eq!(refusal(result), expected);
        assert!(text.is_empty(), "{text}");
        drop(shared);

        let foreign = other.activity(ActivityMode::Exclusive).unwrap();
        let (result, text) = run(&store, &foreign, std::slice::from_ref(&id), false);
        assert_eq!(refusal(result), expected);
        assert!(text.is_empty(), "{text}");
        drop(foreign);

        assert!(intact(&store, &id), "a refused lease removed something");
    }

    /// Both objects keep every byte, and so do their records: a dry run
    /// that unlinked records before deciding it was a dry run would leave
    /// the objects and lose the records.
    #[test]
    fn a_dry_run_reports_and_removes_nothing() {
        let temp = TempStore::new("drop-dry-run");
        let store = temp.store();
        let wedged = wedge(&store, "wedged");
        let bare = bare(&store, "bare");
        let files = [
            store.object_path(&wedged).join("payload"),
            record_path(&store, &wedged),
            store.object_path(&bare).join("payload"),
        ];
        let before: Vec<Vec<u8>> = files.iter().map(|file| fs::read(file).unwrap()).collect();

        let batch = [wedged.clone(), bare.clone()];
        let (count, text) = exclusive(&store, &batch, true);
        assert_eq!(count.unwrap(), 2, "{text}");
        assert_eq!(
            text,
            format!(
                "tog: would drop object {wedged} ({})\n\
                 tog: would drop object {bare} (object without metadata)\n",
                mismatch(&wedged)
            )
        );
        let after: Vec<Vec<u8>> = files.iter().map(|file| fs::read(file).unwrap()).collect();
        assert_eq!(before, after);
    }

    /// A record that is a symlink or a directory is one drop refuses, so
    /// the advice must not send the operator to `--drop-object` alone. It
    /// removes the record first, then drops the object that removal leaves
    /// behind, and following it unwedges the sweep.
    #[test]
    fn a_record_drop_would_refuse_is_not_advised_as_a_drop() {
        let temp = TempStore::new("drop-advice");
        let store = temp.store();
        let id = wedge(&store, "wedged");
        register_objects(&store, &temp.root.join("project"), &[]);
        let record = record_path(&store, &id);
        let file = format!("{id}.json");
        let kept = temp.root.join("kept.json");
        fs::rename(&record, &kept).unwrap();
        for (shape, rm) in [("symlink", "rm"), ("directory", "rm -r")] {
            if shape == "symlink" {
                std::os::unix::fs::symlink(&kept, &record).unwrap();
            } else {
                fs::create_dir(&record).unwrap();
            }
            let (result, text) = sweep(&store);
            let error = result.expect_err(&text).to_string();
            let line = crate::kernel::ui::shell_line(
                &rm.split(' ')
                    .chain([record.display().to_string().as_str()])
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                super::super::remove_record_line(&store, &file),
                line,
                "{shape}"
            );
            assert!(
                error.contains(&format!(
                    "blocked: metadata record meta/{file} is unusable ("
                )),
                "{shape}: {error}"
            );
            assert!(
                error.contains(&format!(
                    "remove it with `{line}`, then drop the object it leaves behind with `tog \
                     gc --drop-object {id}`, or restore the file from a backup"
                )),
                "{shape}: {error}"
            );
            assert!(!error.contains("drop it with"), "{shape}: {error}");
            if shape == "symlink" {
                fs::remove_file(&record).unwrap();
            } else {
                fs::remove_dir(&record).unwrap();
            }
        }

        // The record is gone: the sweep refuses the object it left, the
        // advised drop takes it, and the sweep runs.
        assert!(sweep(&store).0.is_err());
        let (count, text) = exclusive(&store, std::slice::from_ref(&id), false);
        assert_eq!(count.unwrap(), 1, "{text}");
        let (report, text) = sweep(&store);
        report.unwrap_or_else(|error| panic!("{error}: {text}"));

        // With no object left behind, removing the record is the whole fix.
        fs::create_dir(&record).unwrap();
        let (result, text) = sweep(&store);
        let error = result.expect_err(&text).to_string();
        assert!(
            error.contains(&format!(
                "remove it with `{}`, or restore the file from a backup",
                super::super::remove_record_line(&store, &file)
            )),
            "{error}"
        );
        fs::remove_dir(&record).unwrap();
    }

    /// The passing control: a wedged object and its record both go, and a
    /// healthy neighbour is not touched.
    #[test]
    fn a_real_drop_removes_the_object_and_its_record() {
        let temp = TempStore::new("drop-control");
        let store = temp.store();
        let id = wedge(&store, "wedged");
        let neighbour = bare(&store, "neighbour");

        let (count, text) = exclusive(&store, std::slice::from_ref(&id), false);
        assert_eq!(count.unwrap(), 1, "{text}");
        assert_eq!(
            text,
            format!("tog: dropped object {id} ({})\n", mismatch(&id))
        );
        assert!(!store.object_path(&id).exists(), "{text}");
        assert!(!record_path(&store, &id).exists(), "{text}");
        assert!(store.object_path(&neighbour).is_dir(), "{text}");
    }
}

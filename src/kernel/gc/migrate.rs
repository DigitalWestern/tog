//! Automatic maintenance and legacy metadata migration (kernel gc):
//! additive upgrades under the exclusive lease, never a deletion permission.

use super::*;

// ===========================================================================
// Automatic maintenance and legacy migration.
//
// Migration is additive maintenance, never a deletion permission. It runs
// under the exclusive activity lease and the publication lock, upgrades only
// records whose exact dependency set an adapter could reconstruct, and leaves
// everything else untouched. A store that still holds one unresolved record
// simply does not sweep — `validate` refuses on the legacy evidence itself.
// ===========================================================================

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub upgraded: usize,
    pub unresolved: usize,
}

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
/// forbids. Going straight for the exclusive lease is the same decision
/// with one fewer window.
///
/// If another job owns the store the transition is announced as deferred and
/// the caller proceeds with ordinary non-destructive work; it never weakens
/// the sweep, which refuses on unresolved evidence regardless.
pub fn automatic_maintenance<W: Write>(store: &Store, out: &mut W) -> io::Result<MigrationReport> {
    let Some(activity) = store.try_activity_exclusive()? else {
        out.write_all(
            crate::kernel::ui::warning_line(
                "metadata maintenance deferred: a Tog job is using this store",
            )
            .as_bytes(),
        )?;
        return Ok(MigrationReport::default());
    };
    // Maintenance narration is captured rather than written straight out,
    // because a store that cannot finish maintenance cannot finish it on the
    // next command either: printed unconditionally, the same paragraph would
    // precede every single invocation forever. The marker below turns it
    // into news — printed when it first appears and whenever it changes.
    //
    // The narration itself is the short form (`automatic`): a person who
    // typed `tog run dev` gets one line per record that needs a decision
    // and one summary, not the migration's own accounting. The full
    // accounting is what `tog gc --migrate-metadata` prints.
    let mut buffer: Vec<u8> = Vec::new();
    let (report, deferral) =
        match migrate_metadata_locked(store, &activity, false, &mut buffer, true) {
            Ok((report, _)) if report.unresolved == 0 => {
                if !buffer.is_empty() {
                    write_advisories(out, &buffer)?;
                }
                clear_deferral_marker(store)?;
                return Ok(report);
            }
            Ok((report, _)) => {
                buffer.extend_from_slice(
                    plain_warning_line(&format!(
                        "metadata maintenance deferred: {} store record(s) unresolved, so \
                         'tog gc' cannot sweep; 'tog gc --migrate-metadata' explains each",
                        report.unresolved
                    ))
                    .as_bytes(),
                );
                (report, buffer)
            }
            Err(error) => {
                // A malformed historical record must not stop a non-destructive
                // shared job from using an otherwise valid cached projection. The
                // destructive path stays fail-closed, and the explicit migration
                // command still surfaces this error.
                buffer.extend_from_slice(
                    plain_warning_line(&format!("metadata maintenance deferred: {error}"))
                        .as_bytes(),
                );
                (MigrationReport::default(), buffer)
            }
        };
    // `--quiet` points stderr at /dev/null: nothing below would be seen, so
    // the once-per-store showing is not spent on it.
    if crate::kernel::ui::quiet() {
        return Ok(report);
    }
    // A byte-for-byte comparison, not a "have we warned before" flag: the
    // moment the store's problems change, the operator sees the new list.
    // The compared text is the plain form; color is added on the way out,
    // so a terminal and a pipe agree about what has been seen.
    let marker = deferral_marker(store);
    if fs::read(&marker).ok().as_deref() == Some(deferral.as_slice()) {
        return Ok(report);
    }
    // Print first, remember second. The marker's only job is to say "the
    // operator has already seen exactly this text", so it must not be
    // written until the text has actually reached them: a marker written
    // before a failing write would silence the warning on every later run.
    write_advisories(out, &deferral)?;
    // We hold the exclusive lease, so this write should not fail. If it
    // does, say nothing about printing once — the claim would be false.
    let recorded = write_deferral_marker(store, &marker, &deferral).is_ok();
    if recorded {
        out.write_all(
            crate::kernel::ui::warning_line(
                "this warning is shown once per store; 'tog gc --migrate-metadata' repeats it",
            )
            .as_bytes(),
        )?;
    }
    Ok(report)
}

/// The prefix every automatic-maintenance advisory carries before color is
/// applied. Kept plain so the deferral marker compares the same bytes
/// whether stderr was a terminal or a pipe.
const WARNING_PREFIX: &str = "tog: warning: ";

/// One advisory line in the plain form the deferral marker stores.
fn plain_warning_line(message: &str) -> String {
    format!("{WARNING_PREFIX}{message}\n")
}

/// Print captured plain advisories the way `ui::warning` prints them, the
/// word colored on a terminal. A line without the prefix (an upgrade
/// count) is written as it is.
fn write_advisories<W: Write>(out: &mut W, text: &[u8]) -> io::Result<()> {
    for line in String::from_utf8_lossy(text).lines() {
        match line.strip_prefix(WARNING_PREFIX) {
            Some(message) => out.write_all(crate::kernel::ui::warning_line(message).as_bytes())?,
            None => writeln!(out, "{line}")?,
        }
    }
    Ok(())
}

/// Where the last deferral text is remembered. A plain file at the store
/// root: the sweep enumerates named subdirectories only, so an extra regular
/// file here is inert.
pub(super) fn deferral_marker(store: &Store) -> PathBuf {
    store.root.join("maintenance-deferred")
}

/// Forget the remembered deferral, so the next one is announced again.
pub(super) fn clear_deferral_marker(store: &Store) -> io::Result<()> {
    match fs::remove_file(deferral_marker(store)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Write the marker through `tmp/` and rename, so a crash mid-write can
/// never leave a truncated marker that silences a warning it does not match.
fn write_deferral_marker(store: &Store, marker: &Path, text: &[u8]) -> io::Result<()> {
    let tmp = store
        .root
        .join("tmp")
        .join(format!("maintenance-deferred.{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    if let Err(error) = file.write_all(text).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&tmp, marker) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

pub(super) fn migrate_metadata_locked<W: Write>(
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
    // The lenient read is deliberate here, and only here. A record nothing
    // can parse is the one thing migration must still be able to *report*:
    // refusing to read the store would make the command the operator is
    // sent to by every other refusal refuse as well.
    let (index, unusable) = crate::kernel::objmeta::MetaIndex::read_reporting_unusable(store)?;
    let mut report = MigrationReport::default();
    for (file, reason) in &unusable {
        let stem = file.strip_suffix(".json").unwrap_or(file);
        if automatic {
            // One line, one decision: the id to drop, or the file to
            // restore. The reason is kept because it is what a backup or a
            // bug report needs.
            let advice = if store::is_object_id(stem) {
                format!("'tog gc --drop-object {stem}' drops it and the next sync rebuilds it")
            } else {
                format!("delete meta/{file} by hand or restore it from a backup")
            };
            out.write_all(
                plain_warning_line(&format!(
                    "store record meta/{file} is unusable ({reason}); {advice}"
                ))
                .as_bytes(),
            )?;
            continue;
        }
        let advice = if store::is_object_id(stem) {
            format!(
                "Drop it with `tog gc --drop-object {stem}` (the next sync that needs the \
                 object rebuilds it), or restore the file from a backup."
            )
        } else {
            format!("Delete meta/{file} by hand, or restore the file from a backup.")
        };
        writeln!(
            out,
            "metadata record unusable: meta/{file} — {reason}. {advice}"
        )?;
    }
    report.unresolved = unusable.len();
    if !unusable.is_empty() {
        // Nothing is adapted while a record is missing from the index.
        //
        // An adapter resolves an indirect reference by asking the index for
        // the *one* record whose identity produces a fingerprint, and both
        // "no match" and "more than one match" are refusals. A record that
        // was skipped is a record the index cannot offer as the second
        // candidate, so an ambiguity the strict reader would have refused
        // can come back as a confident unique match — and certify a
        // dependency set naming the wrong object, which is a licence to
        // delete the one actually in use.
        //
        // So migration stops at reporting. Every legacy record is counted as
        // unresolved, because none of them has been proven, and the store
        // stays exactly as it was found.
        let held = index
            .iter()
            .filter(|(_, record)| record.evidence == crate::kernel::objmeta::Evidence::Legacy)
            .count();
        report.unresolved += held;
        // The automatic caller prints its own one-line summary; the
        // accounting below is for the person who asked for it.
        if automatic {
            return Ok((report, BTreeMap::new()));
        }
        writeln!(
            out,
            "metadata migration held: {} unusable record(s) must be resolved before legacy \
             records can be proven",
            unusable.len()
        )?;
        writeln!(
            out,
            "metadata migration: 0 upgraded, {} unresolved{}",
            report.unresolved,
            if dry_run { " (dry run)" } else { "" }
        )?;
        return Ok((report, BTreeMap::new()));
    }
    if !index.has_legacy() {
        return Ok((report, BTreeMap::new()));
    }
    let cached = present_cache_entries(store)?;

    let mut proposals: BTreeMap<String, ObjectDeps> = BTreeMap::new();
    let mut unresolved: BTreeMap<String, String> = BTreeMap::new();
    for (id, record) in index.iter() {
        if record.evidence != crate::kernel::objmeta::Evidence::Legacy {
            continue;
        }
        match crate::kernel::objmeta::adapt(record, &index) {
            crate::kernel::objmeta::Adaptation::Proven(deps) => {
                proposals.insert(id.clone(), deps);
            }
            crate::kernel::objmeta::Adaptation::Unresolved(reason) => {
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
        if automatic {
            out.write_all(
                plain_warning_line(&format!(
                    "store record for object {id} cannot be migrated ({reason}); \
                     'tog gc --drop-object {id}' drops it and the next sync rebuilds it"
                ))
                .as_bytes(),
            )?;
            continue;
        }
        writeln!(
            out,
            "metadata migration unresolved: object {id} — {reason}. The record keeps its \
             conservative legacy retention and no sweep will run until it is resolved. Drop it \
             with `tog gc --drop-object {id}` (the next sync that needs the object rebuilds \
             it), or restore the file from a backup."
        )?;
    }
    report.unresolved = unresolved.len() + unusable.len();

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
    if automatic {
        // A silent upgrade that succeeded is worth one line; a deferral is
        // summarized by the caller.
        if report.unresolved == 0 && report.upgraded != 0 {
            writeln!(
                out,
                "tog: store metadata upgraded for {} object(s)",
                report.upgraded
            )?;
        }
        return Ok((report, upgrades));
    }
    writeln!(
        out,
        "metadata migration: {} upgraded, {} unresolved{}",
        report.upgraded,
        report.unresolved,
        if dry_run { " (dry run)" } else { "" }
    )?;
    Ok((report, upgrades))
}

/// Rewrite one legacy record as `object-meta/2`, preserving its identity, id,
/// creation timestamp and exceptions exactly as stored.
pub(super) fn upgraded_record(
    record: &crate::kernel::objmeta::Record,
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
            crate::kernel::objmeta::adapter_version(&record.identity.kind)
        )),
    );
    if !record.had_legacy_refs {
        object.insert("legacy_retention".into(), serde_json::json!(true));
    }
    Ok(value)
}

/// Every `algo:hex` the cache actually holds. The containment guard needs to
/// tell a digest that names a retained file from one that names nothing: the
/// old reader scanned identity inputs for any 64-hex token, and plenty of
/// those tokens — inner Hex checksums, manifest digests, content hashes —
/// were never cache addresses and so retained nothing at all.
pub(super) fn present_cache_entries(store: &Store) -> io::Result<BTreeSet<String>> {
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
pub(super) fn effective_deps<'a>(
    id: &str,
    proposals: &'a BTreeMap<String, ObjectDeps>,
    index: &'a crate::kernel::objmeta::MetaIndex,
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

/// Does the proposed certification retain at least everything the
/// pre-object-meta/2 reader retained for this record?
///
/// The old sweep protected two things it found by scanning identity inputs:
/// any embedded object id, and any 64-hex token, which it treated as a
/// sha256 cache address. Both are checked against the *transitive* closure of
/// the proposed evidence, because retaining an object that itself retains the
/// artifact loses nothing — a Python environment now names the built wheel's
/// object, and that object names the sdist tarball the environment used to
/// name directly.
pub(super) fn certification_covers_legacy_retention(
    record: &crate::kernel::objmeta::Record,
    deps: &ObjectDeps,
    proposals: &BTreeMap<String, ObjectDeps>,
    index: &crate::kernel::objmeta::MetaIndex,
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
/// `store::object_refs` scan the legacy writer used, kept only to define what
/// the old reader retained; it is never used as evidence of completeness.
pub(super) fn collect_object_ids_from_value(value: &serde_json::Value, ids: &mut BTreeSet<String>) {
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

/// The old sweep's cache heuristic: every 64-hex token in the identity
/// inputs, which it treated as a sha256 cache address. Kept for the same
/// reason as the scan above.
pub(super) fn legacy_cache_hashes(value: &serde_json::Value) -> BTreeSet<String> {
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

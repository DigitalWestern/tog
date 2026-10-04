//! `tog gc --reset` (kernel gc): empty the store and start it again in the
//! current format.
//!
//! This is the way out of a store this tog refuses to open: one written
//! before the format marker existed, or one whose marker it does not know.
//! There is no reader for those records, so nothing here reads one. It
//! removes the namespaces that hold records or point into them
//! (`store::RESET_REMOVES`), keeps the verified download cache the store is
//! rebuilt from, and writes the marker.
//!
//! No root survives a reset, so no project is protected afterwards and none
//! needs to be: there is nothing left to protect. A project's own
//! `.tog/closures/` still name the objects that are gone, and the next
//! `tog` there finds them missing and realizes them again, from the cache
//! where it can.

use super::*;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResetReport {
    pub freed_bytes: u64,
    /// Entries under `objects/`, whatever their names.
    pub objects: usize,
}

/// The publication lock's name under `tmp/`: the one entry a reset leaves
/// there, because it holds that lock while it works.
const PUBLISH_LOCK: &str = ".publish.lock";

/// Empty `store` and recreate it in the current format, under the exclusive
/// activity lease. `store` is a handle on the root only: it need not be a
/// store `Store::open` would accept, which is the point.
///
/// The marker goes first and comes back last. A reset that is interrupted
/// therefore leaves a store with no marker, which every command refuses
/// with this command as the fix, and never a marked store holding half of
/// its records.
pub fn reset<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    dry_run: bool,
    out: &mut W,
) -> io::Result<ResetReport> {
    store.require_exclusive_activity(activity, "resetting the store")?;
    let root = open_directory(&store.root, "store root")?;
    let mut report = ResetReport::default();

    // What is there, measured before anything is removed. A dry run stops
    // after printing it.
    let mut present: Vec<(&str, u64)> = Vec::new();
    for name in store::RESET_REMOVES {
        let path = store.root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => present.push((name, tree_size(&path)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let stages = staging_entries(store)?;
    let mut stage_bytes = 0;
    for name in &stages {
        stage_bytes += tree_size(&store.root.join("tmp").join(name))?;
    }
    // Not a directory, or not there: no objects to count.
    if let Ok(entries) = fs::read_dir(store.root.join("objects")) {
        report.objects = entries.count();
    }
    report.freed_bytes = present.iter().map(|(_, bytes)| bytes).sum::<u64>() + stage_bytes;

    let verb = if dry_run { "would remove" } else { "removed" };
    if dry_run {
        for (name, bytes) in &present {
            writeln!(
                out,
                "tog: {verb} {} ({})",
                store.root.join(name).display(),
                size(*bytes)
            )?;
        }
        report_stages(store, verb, stages.len(), stage_bytes, out)?;
        return Ok(report);
    }

    // The sweep's locks, in the sweep's order: no fetch and no publication
    // is in flight while the namespaces they write into are removed. The
    // lock files themselves are never unlinked, so a tog that arrives
    // meanwhile waits on the same inode this reset holds.
    let _gc_lock = store.gc_lock()?;
    store.ensure_namespace(Path::new("tmp"))?;
    let _publish_lock = store.publish_lock()?;

    store::remove_tree_entry_at(root.as_raw_fd(), store::FORMAT_FILE.as_bytes())?;
    for (name, bytes) in &present {
        store::remove_tree_entry_at(root.as_raw_fd(), name.as_bytes())?;
        writeln!(
            out,
            "tog: {verb} {} ({})",
            store.root.join(name).display(),
            size(*bytes)
        )?;
    }
    let tmp = open_directory(&store.root.join("tmp"), "tmp")?;
    for name in &stages {
        store::remove_tree_entry_at(tmp.as_raw_fd(), name.as_bytes())?;
    }
    report_stages(store, verb, stages.len(), stage_bytes, out)?;
    store.initialize()?;
    Ok(report)
}

/// The one line about `tmp/`, which is emptied rather than removed.
fn report_stages<W: Write>(
    store: &Store,
    verb: &str,
    count: usize,
    bytes: u64,
    out: &mut W,
) -> io::Result<()> {
    if count == 0 {
        return Ok(());
    }
    writeln!(
        out,
        "tog: {verb} {count} staging {} under {} ({})",
        if count == 1 { "entry" } else { "entries" },
        store.root.join("tmp").display(),
        size(bytes)
    )
}

/// Everything under `tmp/` but the publication lock. An absent `tmp` holds
/// nothing; one that is not a real directory is refused rather than
/// followed.
fn staging_entries(store: &Store) -> io::Result<Vec<OsString>> {
    let path = store.root.join("tmp");
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    let tmp = open_directory(&path, "tmp")?;
    let mut names: Vec<OsString> = store::read_dir_names_at(tmp.as_raw_fd())?
        .into_iter()
        .filter(|name| name.as_bytes() != PUBLISH_LOCK.as_bytes())
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod reset_tests {
    use super::super::tests::{register_objects, test_identity, TempStore};
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::store::{ObjectDeps, StoreFormat, FORMAT_FILE};

    fn run(store: &Store, dry_run: bool) -> (io::Result<ResetReport>, String) {
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let result = reset(store, &activity, dry_run, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    /// One published object, a root that protects it, a cached download, a
    /// backup, a stale stage and a file tog never wrote.
    fn populated(temp: &TempStore) -> (Store, String) {
        let store = temp.store();
        let identity = test_identity("kept", None);
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "payload").unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        register_objects(&store, &temp.root.join("project"), &[&id]);
        fs::write(store.cache_path("sha256", &"a".repeat(64)), b"download").unwrap();
        fs::create_dir_all(store.root.join("backups/backup-1")).unwrap();
        fs::write(store.root.join("backups/backup-1/mine"), b"mine").unwrap();
        fs::create_dir_all(store.root.join("forests/key/projection")).unwrap();
        fs::create_dir_all(store.root.join("records/kind")).unwrap();
        fs::create_dir_all(store.root.join("resolve/meta")).unwrap();
        fs::create_dir_all(store.root.join("tmp/stage-old")).unwrap();
        fs::write(store.root.join("maintenance-deferred"), b"old").unwrap();
        fs::write(store.root.join("notes.txt"), b"not tog's").unwrap();
        (store, id)
    }

    fn names(root: &Path) -> BTreeSet<String> {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn reset_empties_a_store_with_no_marker_and_leaves_a_fresh_one() {
        let temp = TempStore::new("reset");
        let (store, id) = populated(&temp);
        assert_eq!(
            Store::probe_at(&store.root).unwrap().unwrap().1,
            StoreFormat::PreEpoch
        );
        assert!(Store::open_at(&store.root).is_err());

        let (result, text) = run(&store, false);
        let report = result.unwrap();
        assert_eq!(report.objects, 1);
        assert!(report.freed_bytes > 0);
        assert!(
            text.contains(&format!(
                "tog: removed {}",
                store.root.join("objects").display()
            )),
            "{text}"
        );

        // The marker is back, and the store opens.
        assert_eq!(
            fs::read(store.root.join(FORMAT_FILE)).unwrap(),
            b"tog-store 1\n"
        );
        let reopened = Store::open_at(&store.root).unwrap();
        assert_eq!(reopened.root, store.root.canonicalize().unwrap());

        // Every record is gone, and nothing points at one.
        assert!(!store.object_path(&id).exists());
        for namespace in ["objects", "meta", "roots", "forests", "records"] {
            assert_eq!(
                fs::read_dir(store.root.join(namespace)).unwrap().count(),
                0,
                "{namespace}"
            );
        }
        assert!(!store.root.join("resolve").exists());
        assert!(!store.root.join("maintenance-deferred").exists());
        assert!(!store.root.join("tmp/stage-old").exists());
        assert!(store.roots().unwrap().is_empty());
        assert!(!store.registry_initialized().unwrap());

        // The download cache, the user's backup, the locks and the file tog
        // never wrote are all still there.
        assert_eq!(
            fs::read(store.cache_path("sha256", &"a".repeat(64))).unwrap(),
            b"download"
        );
        assert_eq!(
            fs::read(store.root.join("backups/backup-1/mine")).unwrap(),
            b"mine"
        );
        assert_eq!(
            fs::read(store.root.join("notes.txt")).unwrap(),
            b"not tog's"
        );
        assert!(store.root.join("activity.lock").is_file());
        assert!(store.root.join("gc.lock").is_file());
        assert!(store.root.join("tmp/.publish.lock").is_file());

        // The store is an ordinary one again: the same object publishes at
        // the same id.
        let identity = test_identity("kept", None);
        let staged = reopened.stage().unwrap();
        fs::write(staged.join("payload"), "payload").unwrap();
        reopened
            .commit_with_deps(&identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        assert!(reopened.object_path(&id).join("payload").is_file());
    }

    #[test]
    fn a_dry_run_reset_reports_and_changes_nothing() {
        let temp = TempStore::new("reset-dry");
        let (store, id) = populated(&temp);
        let mut before = names(&store.root);
        before.remove("activity.lock");

        let (result, text) = run(&store, true);
        let report = result.unwrap();
        assert_eq!(report.objects, 1);
        assert!(report.freed_bytes > 0);
        for namespace in ["objects", "meta", "roots", "forests", "records", "resolve"] {
            assert!(
                text.contains(&format!(
                    "tog: would remove {}",
                    store.root.join(namespace).display()
                )),
                "{namespace}: {text}"
            );
        }
        assert!(text.contains("would remove 1 staging entry"), "{text}");
        assert!(!text.contains("cache"), "{text}");
        assert!(!text.contains("backups"), "{text}");

        // Nothing moved: no marker was written, no lock taken beyond the
        // lease the caller already held, and every entry is where it was.
        let mut after = names(&store.root);
        after.remove("activity.lock");
        assert_eq!(after, before);
        assert!(store.object_path(&id).join("payload").is_file());
        assert!(store.root.join("tmp/stage-old").is_dir());
        assert_eq!(
            Store::probe_at(&store.root).unwrap().unwrap().1,
            StoreFormat::PreEpoch
        );
    }

    #[test]
    fn reset_replaces_a_marker_this_tog_does_not_know() {
        for marker in [&b"tog-store 2\n"[..], b"something else"] {
            let temp = TempStore::new("reset-marker");
            let (store, _) = populated(&temp);
            fs::write(store.root.join(FORMAT_FILE), marker).unwrap();
            assert!(Store::open_at(&store.root).is_err());
            run(&store, false).0.unwrap();
            assert_eq!(
                Store::probe_at(&store.root).unwrap().unwrap().1,
                StoreFormat::Current
            );
        }
        // A marker that is a directory is removed like any other.
        let temp = TempStore::new("reset-marker-dir");
        let (store, _) = populated(&temp);
        fs::create_dir(store.root.join(FORMAT_FILE)).unwrap();
        run(&store, false).0.unwrap();
        assert_eq!(
            fs::read(store.root.join(FORMAT_FILE)).unwrap(),
            b"tog-store 1\n"
        );
    }

    #[test]
    fn reset_of_a_current_store_starts_it_again() {
        let temp = TempStore::new("reset-current");
        let store = Store::open_at(&temp.root.join("fresh")).unwrap();
        let identity = test_identity("gone", None);
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "payload").unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        let (result, _) = run(&store, false);
        assert_eq!(result.unwrap().objects, 1);
        assert!(!store.object_path(&identity.object_id()).exists());
        assert_eq!(
            Store::probe_at(&store.root).unwrap().unwrap().1,
            StoreFormat::Current
        );
    }

    #[test]
    fn reset_needs_the_exclusive_lease() {
        let temp = TempStore::new("reset-lease");
        let (store, id) = populated(&temp);
        let shared = store.activity(ActivityMode::Shared).unwrap();
        let mut out = Vec::new();
        let error = reset(&store, &shared, false, &mut out).unwrap_err();
        assert!(error.to_string().contains("exclusive lease"), "{error}");
        assert!(store.object_path(&id).join("payload").is_file());
    }

    #[test]
    fn reset_refuses_a_namespace_it_would_have_to_follow() {
        // `tmp` as a symlink: emptying it would delete through the link.
        let temp = TempStore::new("reset-symlink");
        let (store, id) = populated(&temp);
        let elsewhere = temp.root.join("elsewhere");
        fs::create_dir_all(elsewhere.join("precious")).unwrap();
        store::remove_tree(&store.root.join("tmp")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.root.join("tmp")).unwrap();
        let (result, _) = run(&store, false);
        assert!(result.is_err());
        assert!(elsewhere.join("precious").is_dir());
        assert!(store.object_path(&id).join("payload").is_file());

        // A removed namespace that is a symlink is unlinked, never entered.
        let temp = TempStore::new("reset-symlink-ns");
        let (store, _) = populated(&temp);
        let elsewhere = temp.root.join("elsewhere");
        fs::create_dir_all(elsewhere.join("precious")).unwrap();
        store::remove_tree(&store.root.join("forests")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.root.join("forests")).unwrap();
        run(&store, false).0.unwrap();
        assert!(elsewhere.join("precious").is_dir());
        assert!(store.root.join("forests").is_dir());
        assert!(!fs::symlink_metadata(store.root.join("forests"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

//! The content-addressed object store (kernel layer): object paths, atomic
//! commit, root records, projection bases, and the `BLANKET_STORE` override.

use crate::kernel::activity::{ActivityMode, StoreActivity};
use crate::kernel::types::Identity;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

mod env;
mod fsops;
mod objects;
mod projection;
mod roots;

use env::home;
#[cfg(test)]
pub(crate) use env::STORE_ENV_LOCK;
pub use fsops::*;
pub use objects::*;
pub use projection::*;
pub use roots::*;

/// Content/input-addressed immutable store (the closet).
///
/// Layout:
///   <root>/objects/<object-id>/     immutable realized outputs
///   <root>/meta/<object-id>.json    identity + provenance
///   <root>/cache/sha256/<hash>      verified downloaded artifacts
///   <root>/tmp/                     staging for atomic renames
///
/// ponytail: store root defaults to ~/.blanket/store (BLANKET_STORE overrides).
/// The /opt/blanket/store decision only matters once binary-cache sharing
/// exists; identity format is machine-independent so migration is re-realize.
#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn open() -> io::Result<Store> {
        let root = std::env::var_os("BLANKET_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".blanket/store"));
        fs::create_dir_all(&root)?;
        let root = root.canonicalize()?;
        for sub in [
            "objects",
            "meta",
            "cache/sha1",
            "cache/sha256",
            "cache/sha512",
            "tmp",
            "roots",
            "forests",
            "backups",
            "root-locks",
        ] {
            ensure_directory_tree(&root, Path::new(sub))?;
        }
        Ok(Store { root })
    }

    /// Ensure a managed namespace exists without following an existing
    /// symlink. Producers use this for store-owned projection parents before
    /// creating or sweeping descendants.
    pub(crate) fn ensure_namespace(&self, relative: &Path) -> io::Result<()> {
        ensure_directory_tree(&self.root, relative)
    }

    pub fn object_path(&self, id: &str) -> PathBuf {
        self.root.join("objects").join(id)
    }

    /// Acquire operation-level protection for this store. The root is
    /// canonicalized before the lease is created so aliases cannot bypass
    /// the in-process coordinator or the on-disk lock.
    pub fn activity(&self, mode: ActivityMode) -> io::Result<StoreActivity> {
        StoreActivity::acquire(&self.root, mode)
    }

    /// Try to acquire exclusive activity without waiting. Maintenance and GC
    /// use this form so a running job can be reported as busy instead of
    /// making cleanup contend with an unbounded command.
    pub fn try_activity_exclusive(&self) -> io::Result<Option<StoreActivity>> {
        StoreActivity::try_exclusive(&self.root)
    }

    /// Verify that a caller is still holding an operation-owned lease for
    /// this exact store. An exclusive lease also satisfies a shared read.
    pub(crate) fn require_activity(&self, activity: &StoreActivity, what: &str) -> io::Result<()> {
        let expected = self.root.canonicalize()?;
        if activity.root() != expected || !activity.mode().satisfies(ActivityMode::Shared) {
            return Err(io::Error::other(format!(
                "{what} requires an active shared lease for store {}; the supplied lease belongs to {}",
                expected.display(),
                activity.root().display()
            )));
        }
        Ok(())
    }

    pub(crate) fn require_exclusive_activity(
        &self,
        activity: &StoreActivity,
        what: &str,
    ) -> io::Result<()> {
        let expected = self.root.canonicalize()?;
        if activity.root() != expected || activity.mode() != ActivityMode::Exclusive {
            return Err(io::Error::other(format!(
                "{what} requires an active exclusive lease for store {}",
                expected.display()
            )));
        }
        Ok(())
    }

    /// Exclusive lock shared by fetches and GC. A cache lease keeps this
    /// lock until its verified artifact has been extracted by the caller.
    pub(crate) fn gc_lock(&self) -> io::Result<fs::File> {
        let f = open_private_lock(&self.root.join("gc.lock"), "GC")?;
        f.lock()?;
        Ok(f)
    }

    pub fn cache_path(&self, algo: &str, hex: &str) -> PathBuf {
        self.root.join("cache").join(algo).join(hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::Exception;
    use std::collections::BTreeMap;
    use std::process::Command;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-store-test-{}-{}",
                std::process::id(),
                nanos()
            ));
            for sub in ["objects", "meta", "cache/sha256", "tmp"] {
                fs::create_dir_all(path.join(sub)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = remove_tree(&self.0);
        }
    }

    fn identity() -> Identity {
        Identity {
            kind: "test".into(),
            name: "object".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        }
    }

    fn staged(store: &Store) -> PathBuf {
        let path = store.stage().unwrap();
        fs::write(path.join("content"), b"content").unwrap();
        path
    }

    #[test]
    fn roots_registry_adds_atomically_and_drops_entries() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let root = store.register_root(&project).unwrap();
        assert_eq!(store.roots().unwrap(), vec![root.clone()]);
        assert_eq!(
            fs::read_to_string(&root.registry_path).unwrap().trim(),
            project.canonicalize().unwrap().display().to_string()
        );
        store.remove_root_entry(&root).unwrap();
        assert!(store.roots().unwrap().is_empty());
    }

    /// A project whose pathname a record cannot hold exactly is refused
    /// before anything is written: recording a lossy spelling files one
    /// project under another project's identity.
    #[test]
    fn registration_refuses_a_pathname_no_record_can_hold() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let padded = temp.0.join("project ");
        fs::create_dir_all(&padded).unwrap();
        assert_eq!(
            store.register_root(&padded).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            Store::root_key(&padded).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        // APFS refuses non-UTF-8 file names (EILSEQ), so the lossy case can
        // only be exercised on Linux.
        #[cfg(target_os = "linux")]
        {
            let mut raw = temp.0.canonicalize().unwrap().into_os_string().into_vec();
            raw.extend_from_slice(b"/project-\xff");
            let lossy = PathBuf::from(OsString::from_vec(raw));
            fs::create_dir_all(&lossy).unwrap();
            assert_eq!(
                store.register_root(&lossy).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(store.roots().unwrap().is_empty(), "a record was written");
    }

    /// A record that cannot be read is still a record. Reporting it keeps GC
    /// able to refuse; skipping it silently drops a project's protection.
    #[test]
    fn unreadable_records_are_reported_not_skipped() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let entry = store.register_root(&project).unwrap();

        for contents in [
            b"".as_slice(),
            b"\xff\n".as_slice(),
            b" /padded\n".as_slice(),
            b"relative/path\n".as_slice(),
            b"/one\n/two\n".as_slice(),
        ] {
            fs::write(&entry.registry_path, contents).unwrap();
            let roots = store.roots().unwrap();
            assert_eq!(roots.len(), 1, "record skipped: {contents:?}");
            assert_eq!(roots[0].key, entry.key);
            assert!(roots[0].unusable.is_some(), "record accepted: {contents:?}");
        }

        fs::remove_file(&entry.registry_path).unwrap();
        std::os::unix::fs::symlink(&project, &entry.registry_path).unwrap();
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "symlinked record skipped");
        assert!(roots[0].unusable.is_some(), "symlinked record accepted");
    }

    #[test]
    fn lookup_and_forget_work_off_registry_records_alone() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let entry = store.register_root(&project).unwrap();

        // Forgetting resolves the key against the registry only, so a record
        // stays forgettable after its project is gone.
        fs::remove_dir_all(&project).unwrap();
        let lookup = store.lookup_root(&entry.key).unwrap();
        assert_eq!(lookup.key, entry.key);

        assert_eq!(
            store.forget_root(&entry.key).unwrap().registry_path,
            entry.registry_path
        );
        assert!(store.roots().unwrap().is_empty());
        let error = store.forget_root(&entry.key).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    /// A record that is not a regular file is refused on its metadata,
    /// before anything opens it. Removing that check does not make this test
    /// fail — it makes it hang: reading a FIFO nobody writes to blocks the
    /// listing, the sweep and `--forget` alike, which is the one registry
    /// failure there is no way to recover from.
    #[test]
    fn a_record_that_is_not_a_regular_file_is_never_opened() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let roots = store.root.join("roots");
        fs::create_dir_all(&roots).unwrap();

        let fifo = roots.join("a".repeat(40));
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path in a directory this test owns.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        fs::create_dir(roots.join("b".repeat(40))).unwrap();

        let records = store.roots().unwrap();
        assert_eq!(records.len(), 2);
        for record in records {
            let reason = record.unusable.expect("read as a usable record");
            assert!(reason.contains("not a regular file"), "{reason}");
            // The escape hatch reaches these too, without opening them.
            store.forget_root(&record.key).unwrap();
        }
        assert!(store.roots().unwrap().is_empty());
    }

    /// Exact-key recovery reads one record. Every other record can be
    /// hostile — unreadable bytes, no permissions, a symlink, a directory,
    /// or far too large — and the requested key still resolves.
    #[test]
    fn exact_key_recovery_ignores_every_other_record() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let entry = store.register_root(&project).unwrap();
        let roots = store.root.join("roots");

        let broken = ["a", "b", "c", "d", "e"].map(|c| c.repeat(40));
        fs::write(roots.join(&broken[0]), b"\xff\n").unwrap();
        fs::write(roots.join(&broken[1]), b"unreadable\n").unwrap();
        fs::set_permissions(roots.join(&broken[1]), fs::Permissions::from_mode(0o000)).unwrap();
        std::os::unix::fs::symlink(&project, roots.join(&broken[2])).unwrap();
        fs::create_dir(roots.join(&broken[3])).unwrap();
        fs::write(roots.join(&broken[4]), vec![b'x'; 64 * 1024]).unwrap();

        let found = store.lookup_root(&entry.key).unwrap();
        assert_eq!(found.path, project.canonicalize().unwrap());
        assert!(found.unusable.is_none());
        assert_eq!(store.forget_root(&entry.key).unwrap().key, entry.key);

        // Each broken record is reachable by its own key, so the registry can
        // be emptied without deleting files by hand.
        for key in &broken {
            let entry = store.lookup_root(key).unwrap();
            assert!(entry.unusable.is_some(), "{key} read as a usable record");
            store.forget_root(key).unwrap();
        }
        assert!(store.roots().unwrap().is_empty());
    }

    #[test]
    fn commit_reconciles_cached_exceptions() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let exception = Exception {
            kind: crate::kernel::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        let (object, applied) = store
            .commit_with_deps(
                &identity,
                &staged(&store),
                std::slice::from_ref(&exception),
                &ObjectDeps::new(),
            )
            .unwrap();
        assert_eq!(object, store.object_path(&identity.object_id()));
        assert_eq!(applied, vec![exception.clone()]);

        let error = store
            .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("was published concurrently with different exceptions"));
        assert!(error.to_string().contains("winner:"));
        assert!(error.to_string().contains("staged: []"));

        let (same_object, applied) = store
            .commit_with_deps(
                &identity,
                &staged(&store),
                std::slice::from_ref(&exception),
                &ObjectDeps::new(),
            )
            .unwrap();
        assert_eq!(same_object, object);
        assert_eq!(applied, vec![exception]);
    }

    #[test]
    fn strict_policy_rejects_cached_exceptions() {
        if std::env::var_os("BLANKET_STORE_STRICT_CHILD").is_some() {
            let store = Store::open().unwrap();
            crate::kernel::policy::init(&store.root, false).unwrap();
            let error = store
                .commit_with_deps(&identity(), &staged(&store), &[], &ObjectDeps::new())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let exception = Exception {
            kind: crate::kernel::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        store
            .commit_with_deps(
                &identity(),
                &staged(&store),
                std::slice::from_ref(&exception),
                &ObjectDeps::new(),
            )
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::tests::strict_policy_rejects_cached_exceptions",
                "--nocapture",
            ])
            .env("BLANKET_STORE", &store.root)
            .env("BLANKET_STORE_STRICT_CHILD", "1")
            .env("BLANKET_STRICT", "1")
            .env_remove("BLANKET_POLICY")
            .env("HOME", &temp.0)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "strict child failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
    }

    /// A lease is bound to the store that issued it. Presenting one store's
    /// token to another store's primitive must fail, and a shared token must
    /// not satisfy a check that requires exclusive protection.
    #[test]
    fn a_lease_only_authorizes_the_store_and_mode_it_was_taken_for() {
        let first = TempDir::new();
        let second = TempDir::new();
        let one = Store {
            root: first.0.canonicalize().unwrap(),
        };
        let two = Store {
            root: second.0.canonicalize().unwrap(),
        };
        let foreign = two.activity(ActivityMode::Shared).unwrap();
        let error = one
            .require_activity(&foreign, "store object lookup")
            .unwrap_err();
        assert!(
            error.to_string().contains("the supplied lease belongs to"),
            "a foreign lease was accepted: {error}"
        );
        assert!(one.require_exclusive_activity(&foreign, "sweep").is_err());
        drop(foreign);

        let shared = one.activity(ActivityMode::Shared).unwrap();
        one.require_activity(&shared, "store object lookup")
            .unwrap();
        let error = one
            .require_exclusive_activity(&shared, "garbage collection")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an active exclusive lease"),
            "a shared lease satisfied an exclusive check: {error}"
        );
        drop(shared);

        // Exclusive stands in for shared, never the reverse.
        let exclusive = one.activity(ActivityMode::Exclusive).unwrap();
        one.require_activity(&exclusive, "store object lookup")
            .unwrap();
        one.require_exclusive_activity(&exclusive, "garbage collection")
            .unwrap();
    }

    /// The wrong-store case reaches a real protected primitive, not just the
    /// checker: `has_with_activity` must refuse rather than answer.
    #[test]
    fn a_foreign_lease_cannot_drive_a_store_lookup() {
        let first = TempDir::new();
        let second = TempDir::new();
        let one = Store {
            root: first.0.canonicalize().unwrap(),
        };
        let two = Store {
            root: second.0.canonicalize().unwrap(),
        };
        let foreign = two.activity(ActivityMode::Shared).unwrap();
        let error = one
            .has_with_activity(&foreign, "0000000000000000000000000000000000000000-thing-1")
            .unwrap_err();
        assert!(
            error.to_string().contains("store object lookup requires"),
            "{error}"
        );
    }

    // APFS refuses non-UTF-8 file names (EILSEQ); the root/2 lossless
    // roundtrip is only observable on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn root2_roundtrips_a_non_utf8_path() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join(OsString::from_vec(b"project-\xff".to_vec()));
        fs::create_dir_all(&project).unwrap();
        let record = RootRecord {
            key: root_key(&project.canonicalize().unwrap()),
            project_path: project.canonicalize().unwrap(),
            objects: BTreeSet::from([format!("{}-env", "a".repeat(40))]),
            projections: BTreeSet::from([ProjectionRef::new(
                ProjectionBase::Forests,
                vec![OsString::from("project"), OsString::from("projection")],
            )
            .unwrap()]),
            updated: 1,
        };
        let entry = store.register_root_record(record.clone()).unwrap();
        let (decoded, temps) = store.roots_for_sweep().unwrap();
        assert!(temps.is_empty());
        assert_eq!(decoded[0].record.as_ref(), Some(&record));
        assert_eq!(decoded[0].path, project.canonicalize().unwrap());
        assert!(fs::read_to_string(entry.registry_path)
            .unwrap()
            .contains("base64"));
    }

    #[test]
    fn root2_rejects_unknown_schema_before_gc() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let key = root_key(&project.canonicalize().unwrap());
        fs::create_dir_all(store.root.join("roots")).unwrap();
        fs::write(
            store.root.join("roots").join(&key),
            serde_json::json!({"schema": "root/3", "key": key}).to_string(),
        )
        .unwrap();
        let (entries, _) = store.roots_for_sweep().unwrap();
        let reason = entries[0].unusable.as_deref().expect("entry is unusable");
        assert!(reason.contains("unknown schema"), "{reason}");
        assert_eq!(entries[0].key, key);
    }
}

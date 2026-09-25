//! The content-addressed object store (kernel layer): object paths, atomic
//! commit, root records, projection bases, and the `TOG_STORE` override.

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
///   <root>/run-homes/<key>/<eco>/   private HOME for `tog run` children
///
/// ponytail: store root defaults to ~/.tog/store (TOG_STORE overrides).
/// The /opt/tog/store decision only matters once binary-cache sharing
/// exists; identity format is machine-independent so migration is re-realize.
#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

/// Why the store could not be created, in the user's terms: the path that
/// failed, the cause translated out of errno, and the one lever they have.
/// A bare `?` here surfaces as "Permission denied (os error 13)" with no
/// path and no hint that `TOG_STORE` exists.
fn open_error(path: &Path, from_env: bool, error: io::Error) -> io::Error {
    let lever = if from_env {
        "TOG_STORE names this path; point it at a writable directory"
    } else {
        "set TOG_STORE to a writable directory"
    };
    let cause = match error.raw_os_error() {
        Some(code) if code == libc::ENOSPC => "the filesystem is full".to_string(),
        Some(code) if code == libc::EROFS => "the filesystem is read-only".to_string(),
        Some(code) if code == libc::EDQUOT => "the disk quota is exhausted".to_string(),
        _ => match error.kind() {
            io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            io::ErrorKind::NotFound => "a parent directory does not exist".to_string(),
            _ => error.to_string(),
        },
    };
    io::Error::new(
        error.kind(),
        format!("create the store at {}: {cause}; {lever}", path.display()),
    )
}

impl Store {
    /// Where `open` puts the store, and whether `TOG_STORE` chose it.
    fn configured_root() -> (PathBuf, bool) {
        let explicit = std::env::var_os("TOG_STORE").map(PathBuf::from);
        let from_env = explicit.is_some();
        (
            explicit.unwrap_or_else(|| home().join(".tog/store")),
            from_env,
        )
    }

    /// The store `open` would use, without creating or changing anything:
    /// `None` when there is no store (or no `objects` namespace) there yet.
    /// The layout invariant is `open`'s: the canonical root, `objects` and
    /// `meta` must be real directories, never symlinks, and anything else
    /// is an error rather than an absent store. For readers that must leave
    /// the store exactly as they found it (legacy toolchain seeding);
    /// anything that commits, leases or sweeps uses `open`.
    pub fn existing() -> io::Result<Option<Store>> {
        let (root, _) = Self::configured_root();
        let root = match root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let real_directory = |path: &Path, absent_is_none: bool| -> io::Result<bool> {
            match fs::symlink_metadata(path) {
                Ok(stat) if !stat.file_type().is_symlink() && stat.is_dir() => Ok(true),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("store path {} is not a real directory", path.display()),
                )),
                Err(error) if absent_is_none && error.kind() == io::ErrorKind::NotFound => {
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        };
        real_directory(&root, false)?;
        if !real_directory(&root.join("objects"), true)? {
            return Ok(None);
        }
        // A missing `meta` only means nothing has finished publishing.
        real_directory(&root.join("meta"), true)?;
        Ok(Some(Store { root }))
    }

    pub fn open() -> io::Result<Store> {
        let (root, from_env) = Self::configured_root();
        fs::create_dir_all(&root).map_err(|error| open_error(&root, from_env, error))?;
        let root = root
            .canonicalize()
            .map_err(|error| open_error(&root, from_env, error))?;
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
            "run-homes",
        ] {
            ensure_directory_tree(&root, Path::new(sub))
                .map_err(|error| open_error(&root.join(sub), from_env, error))?;
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

    /// The short per-project key under `forests/` and `run-homes/`: hex of
    /// the first 8 bytes of SHA-256 over the canonical project path. Every
    /// store path derived from a project goes through here so the
    /// namespaces agree on which project a key names.
    pub fn project_key(project_dir: &Path) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        let canonical = project_dir.canonicalize()?;
        Ok(hex::encode(
            &Sha256::digest(canonical.as_os_str().as_bytes())[..8],
        ))
    }

    /// The HOME a `tog run` child of `ecosystem` gets for this project:
    /// `<root>/run-homes/<project key>/<ecosystem>`, created on demand.
    ///
    /// It lives in the store rather than the shared temp root because a
    /// world-writable parent lets another user create the directory first
    /// and plant startup files (`.erlang`, `.iex.exs`) that the child runs
    /// as this user. It is stable per project so `tog env` prints the same
    /// bytes on every call. Both levels under `run-homes` are private to
    /// this user: a symlink or a directory someone else owns is refused,
    /// and one of ours with wider permissions is narrowed to 0700.
    pub fn run_home(&self, project_dir: &Path, ecosystem: &str) -> io::Result<PathBuf> {
        let single = matches!(
            Path::new(ecosystem)
                .components()
                .collect::<Vec<_>>()
                .as_slice(),
            [std::path::Component::Normal(_)]
        );
        if !single || ecosystem.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("run home ecosystem {ecosystem:?} is not one path component"),
            ));
        }
        let key = Self::project_key(project_dir)?;
        let namespace = Path::new("run-homes");
        self.ensure_namespace(namespace)?;
        let mut path = self.root.join(namespace);
        for level in [key.as_str(), ecosystem] {
            path.push(level);
            ensure_private_directory(&path)?;
        }
        Ok(path)
    }

    /// Acquire operation-level protection for this store. The root is
    /// canonicalized before the lease is created so aliases cannot bypass
    /// the in-process coordinator or the on-disk lock.
    // Reviewed site (tests/architecture.rs): lease primitive (operation boundary).
    #[allow(clippy::disallowed_methods)]
    pub fn activity(&self, mode: ActivityMode) -> io::Result<StoreActivity> {
        StoreActivity::acquire(&self.root, mode)
    }

    /// Try to acquire exclusive activity without waiting. Maintenance and GC
    /// use this form so a running job can be reported as busy instead of
    /// making cleanup contend with an unbounded command.
    // Reviewed site (tests/architecture.rs): lease primitive (operation boundary).
    #[allow(clippy::disallowed_methods)]
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

/// Test support for producer tests: drop `project`'s root record and rebuild
/// it the way `gc --register` does, from the closures on disk alone. A
/// producer test compares the result with the record it published directly,
/// so a closure shape the importer cannot read back fails where it is made.
/// The caller must not hold an activity lease: registration takes the
/// exclusive one.
#[cfg(test)]
pub(crate) fn reimport_root_for_test(store: &Store, project: &Path) -> io::Result<RootRecord> {
    let key = Store::root_key(project)?;
    fs::remove_file(store.root.join("roots").join(&key))?;
    store
        .register_root_from_project(project)?
        .record
        .ok_or_else(|| io::Error::other("registration wrote no root/2 record"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::Exception;
    use crate::kernel::testutil::TempDir;
    use std::collections::BTreeMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::process::Command;

    /// A scratch directory laid out as an empty store.
    fn temp_store() -> TempDir {
        let temp = TempDir::named("store-test");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(temp.0.join(sub)).unwrap();
        }
        temp
    }

    fn identity() -> Identity {
        crate::kernel::objmeta::register_test_kinds();
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
        let temp = temp_store();
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
        let temp = temp_store();
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
        let temp = temp_store();
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
        let temp = temp_store();
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
        let temp = temp_store();
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

        let temp = temp_store();
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
        let temp = temp_store();
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
    #[cfg(debug_assertions)]
    fn commit_rejects_malformed_kernel_identity_before_publishing() {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let valid_identity = Identity {
            kind: "git-source".into(),
            name: "valid-example".into(),
            version: "1".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "git-source/2".into()),
                ("url".into(), "https://example.invalid/repo.git".into()),
                ("commit".into(), "a".repeat(40)),
            ]),
        };
        store
            .commit_with_deps(&valid_identity, &staged(&store), &[], &ObjectDeps::new())
            .expect("valid kernel identity is the control");
        let identity = Identity {
            kind: "git-source".into(),
            name: "example".into(),
            version: "1".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "git-source/2".into()),
                ("url".into(), "https://example.invalid/repo.git".into()),
            ]),
        };
        let id = identity.object_id();
        let result = catch_unwind(AssertUnwindSafe(|| {
            store
                .commit_with_deps(&identity, &staged(&store), &[], &ObjectDeps::new())
                .unwrap();
        }));
        let payload = result.expect_err("malformed kernel identity was published");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message.contains("object-kind grammar drift"), "{message}");
        assert!(
            !store.object_path(&id).exists(),
            "object directory was published"
        );
        assert!(
            !store.root.join("meta").join(format!("{id}.json")).exists(),
            "meta record was published"
        );
    }

    #[test]
    fn strict_policy_rejects_cached_exceptions() {
        if std::env::var_os("TOG_STORE_STRICT_CHILD").is_some() {
            let store = Store::open().unwrap();
            crate::kernel::policy::init(&store.root).unwrap();
            let error = store
                .commit_with_deps(&identity(), &staged(&store), &[], &ObjectDeps::new())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let temp = temp_store();
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
            .env("TOG_STORE", &store.root)
            .env("TOG_STORE_STRICT_CHILD", "1")
            .env("TOG_STRICT", "1")
            .env_remove("TOG_POLICY")
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
        let first = temp_store();
        let second = temp_store();
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
        let first = temp_store();
        let second = temp_store();
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
        let temp = temp_store();
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

    /// A store that cannot be created is the first thing a new user hits on
    /// a locked-down machine. The message names the path, says what errno
    /// meant, and names the variable that moves the store.
    #[test]
    fn store_creation_failures_name_the_path_the_cause_and_the_lever() {
        let denied = open_error(
            Path::new("/ro/home/.tog/store"),
            false,
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert_eq!(
            denied.to_string(),
            "create the store at /ro/home/.tog/store: permission denied; \
             set TOG_STORE to a writable directory"
        );
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);

        let full = open_error(
            Path::new("/mnt/small/store"),
            true,
            io::Error::from_raw_os_error(libc::ENOSPC),
        );
        assert!(
            full.to_string().contains("the filesystem is full"),
            "{full}"
        );
        assert!(
            full.to_string().contains("TOG_STORE names this path"),
            "{full}"
        );

        let read_only = open_error(
            Path::new("/store"),
            false,
            io::Error::from_raw_os_error(libc::EROFS),
        );
        assert!(
            read_only
                .to_string()
                .contains("the filesystem is read-only"),
            "{read_only}"
        );
    }

    #[test]
    fn root2_rejects_unknown_schema_before_gc() {
        let temp = temp_store();
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

    /// A complete object named `name`, published through the real commit so
    /// a closure import can validate it.
    fn named_object(store: &Store, name: &str) -> String {
        let mut identity = identity();
        identity.name = name.into();
        store
            .commit_with_deps(&identity, &staged(store), &[], &ObjectDeps::new())
            .unwrap();
        identity.object_id()
    }

    fn store_in(temp: &TempDir) -> Store {
        let root = temp.0.canonicalize().unwrap();
        for sub in ["roots", "forests", "backups"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        Store { root }
    }

    /// Write one `closure/1` envelope into a project, as a producer would.
    fn project_closure(project: &Path, ecosystem: &str, body: serde_json::Value) {
        let closures = project.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join(format!("{ecosystem}.json")),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": ecosystem,
                "body": body,
            })
            .to_string(),
        )
        .unwrap();
    }

    /// The `{"path", "id"}` shape most producers write for an object.
    fn object_ref(store: &Store, id: &str) -> serde_json::Value {
        serde_json::json!({"path": store.object_path(id), "id": id})
    }

    /// A projection reference is relative to a store-owned base. An absolute
    /// or `..`-bearing one would let a record claim, and a sweep walk, any
    /// path on the machine, so it is refused when built, when written, and
    /// when read back.
    #[test]
    fn root2_rejects_absolute_projection() {
        let temp = temp_store();
        let store = store_in(&temp);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = root_key(&project);

        for components in [
            vec![OsString::from("/etc")],
            vec![OsString::from(".."), OsString::from("etc")],
            vec![OsString::from("a/b")],
            vec![OsString::from("")],
            Vec::new(),
        ] {
            assert!(
                ProjectionRef::new(ProjectionBase::Forests, components.clone()).is_err(),
                "built a projection from {components:?}"
            );
            // The fields are public, so a writer can bypass `new`.
            let record = RootRecord {
                key: key.clone(),
                project_path: project.clone(),
                objects: BTreeSet::from([format!("{}-env", "a".repeat(40))]),
                projections: BTreeSet::from([ProjectionRef {
                    base: ProjectionBase::Forests,
                    components: components.clone(),
                }]),
                updated: 1,
            };
            assert!(
                store.register_root_record(record).is_err(),
                "wrote a projection of {components:?}"
            );
            assert!(store.roots().unwrap().is_empty(), "a record was written");
        }

        // Producers name projections by path. One outside the store's own
        // namespace, or climbing out of it, is refused.
        for path in [
            PathBuf::from("/etc/passwd"),
            store.root.join("forests/../objects"),
            store.root.join("../forests/escape"),
        ] {
            assert!(
                store
                    .projection_ref(ProjectionBase::Forests, &path)
                    .is_err(),
                "accepted projection {}",
                path.display()
            );
        }

        // A hand-written record is unusable, never a record that protects a
        // path outside the store.
        for component in ["/etc", "..", "."] {
            fs::write(
                store.root.join("roots").join(&key),
                serde_json::json!({
                    "schema": "root/2",
                    "key": key,
                    "project_path": {"encoding": "utf8", "value": project.display().to_string()},
                    "objects": [],
                    "projections": [{
                        "base": "forests",
                        "components": [{"encoding": "utf8", "value": component}],
                    }],
                    "updated": 1,
                })
                .to_string(),
            )
            .unwrap();
            let (entries, _) = store.roots_for_sweep().unwrap();
            assert_eq!(entries.len(), 1);
            assert!(
                entries[0].unusable.is_some() && entries[0].record.is_none(),
                "read a projection component {component:?} as usable"
            );
        }
    }

    /// A closure that names another store's object protects nothing here,
    /// and a record claiming it would be protection nobody can check. Both
    /// reference forms are refused at write, and nothing is registered.
    #[test]
    fn root2_rejects_cross_store_object() {
        let ours = temp_store();
        let theirs = temp_store();
        let store = store_in(&ours);
        let other = store_in(&theirs);
        let foreign = named_object(&other, "foreign");

        // The producer boundary.
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let error = crate::comforter::ClosureRefs::new()
            .object_path(&store, &activity, &other.object_path(&foreign))
            .map(|_| ())
            .unwrap_err();
        assert!(error.to_string().contains("outside this store"), "{error}");
        // The same id is not an object of this store either.
        assert!(crate::comforter::ClosureRefs::new()
            .object_id(&store, &activity, &foreign)
            .is_err());
        drop(activity);

        // The importer, for both shapes a shipped closure uses.
        for body in [
            serde_json::json!({"env_object": other.object_path(&foreign)}),
            serde_json::json!({"go_object": object_ref(&other, &foreign)}),
        ] {
            let project = ours.0.join("project");
            let _ = fs::remove_dir_all(&project);
            fs::create_dir_all(&project).unwrap();
            project_closure(&project, "go", body.clone());
            let error = store.root_record_from_project(&project).unwrap_err();
            assert!(
                error.to_string().contains("another store")
                    || error.to_string().contains("does not belong"),
                "{body}: {error}"
            );
            assert!(
                store.register_root_from_project(&project).is_err(),
                "{body}"
            );
            assert!(
                store.roots().unwrap().is_empty(),
                "{body}: a record was written"
            );
        }
    }

    /// Protection only grows. A second publication for the same project adds
    /// its references to the record; it never replaces what an earlier
    /// ecosystem or environment recorded, and neither does registration.
    #[test]
    fn root2_merge_is_a_union_never_a_replace() {
        let temp = temp_store();
        let store = store_in(&temp);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let held = crate::kernel::fsroot::ProjectRoot::open(&project).unwrap();
        let first = format!("{}-first", "a".repeat(40));
        let second = format!("{}-second", "b".repeat(40));
        let forest = |name: &str| {
            ProjectionRef::new(ProjectionBase::Forests, vec![OsString::from(name)]).unwrap()
        };

        store
            .register_root_parts_locked(
                &held,
                BTreeSet::from([first.clone()]),
                BTreeSet::from([forest("one")]),
            )
            .unwrap();
        let record = store
            .register_root_parts_locked(
                &held,
                BTreeSet::from([second.clone()]),
                BTreeSet::from([forest("two")]),
            )
            .unwrap()
            .record
            .unwrap();
        assert_eq!(
            record.objects,
            BTreeSet::from([first.clone(), second.clone()])
        );
        assert_eq!(
            record.projections,
            BTreeSet::from([forest("one"), forest("two")])
        );

        // Registration imports the project's closures into the same union.
        let third = named_object(&store, "third");
        project_closure(
            &project,
            "ruby",
            serde_json::json!({"ruby_object": object_ref(&store, &third)}),
        );
        let record = store
            .register_root_from_project(&project)
            .unwrap()
            .record
            .unwrap();
        assert_eq!(record.objects, BTreeSet::from([first, second, third]));
        assert_eq!(
            record.projections,
            BTreeSet::from([forest("one"), forest("two")])
        );
        assert_eq!(store.roots().unwrap().len(), 1);
    }

    /// Leave `identity` as a finished publication does, without the publish
    /// machinery: a read-only object root, then its metadata record.
    fn publish_bare(store: &Store, identity: &Identity) -> String {
        use std::os::unix::fs::PermissionsExt;
        let id = identity.object_id();
        let path = store.object_path(&id);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(
            store.root.join("meta").join(format!("{id}.json")),
            serde_json::to_vec(&serde_json::json!({"identity": identity})).unwrap(),
        )
        .unwrap();
        id
    }

    fn sweep_bare(store: &Store, id: &str) {
        let _ = fs::remove_file(store.root.join("meta").join(format!("{id}.json")));
        let _ = fs::remove_dir(store.object_path(id));
    }

    /// Run `published_identity` with `hook` interleaved at its failpoints.
    fn published_with(
        store: &Store,
        id: &str,
        hook: impl FnMut(&str) + 'static,
    ) -> io::Result<Option<Identity>> {
        objects::PUBLISHED_IDENTITY_FAILPOINT
            .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let result = store.published_identity(id);
        objects::PUBLISHED_IDENTITY_FAILPOINT.with(|slot| *slot.borrow_mut() = None);
        result
    }

    /// A sweep or a republish racing the read gives the validated identity
    /// or nothing, never another object's identity, and only absence (or a
    /// publication in flight) is `None`: a symlink or a file where an
    /// object or its record belongs is an error.
    #[test]
    fn published_identity_is_the_validated_identity_or_none() {
        use std::os::unix::fs::PermissionsExt;
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let published = identity();
        let seen_id =
            |seen: io::Result<Option<Identity>>| seen.unwrap().map(|found| found.object_id());
        let id = publish_bare(&store, &published);
        assert_eq!(seen_id(store.published_identity(&id)), Some(id.clone()));

        // Swept before the record is opened.
        let (s, i) = (store.clone(), id.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "before-metadata-open" {
                sweep_bare(&s, &i);
            }
        });
        assert_eq!(seen_id(seen), None);

        // Swept after the record was read: what was read was validated.
        let id = publish_bare(&store, &published);
        let (s, i) = (store.clone(), id.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "after-metadata-read" {
                sweep_bare(&s, &i);
            }
        });
        assert_eq!(seen_id(seen), Some(published.object_id()));

        // Swept and republished under the same id before the record opens.
        let id = publish_bare(&store, &published);
        let (s, i, again) = (store.clone(), id.clone(), published.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "before-metadata-open" {
                sweep_bare(&s, &i);
                publish_bare(&s, &again);
            }
        });
        assert_eq!(seen_id(seen), Some(published.object_id()));

        // A record swapped for another identity under this id is refused.
        let (s, i) = (store.clone(), id.clone());
        let seen = published_with(&store, &id, move |at| {
            if at == "before-metadata-open" {
                let mut other = identity();
                other.name = "other".into();
                fs::write(
                    s.root.join("meta").join(format!("{i}.json")),
                    serde_json::to_vec(&serde_json::json!({"identity": other})).unwrap(),
                )
                .unwrap();
            }
        });
        assert!(seen.is_err());

        // A publication in flight (writable root, then no record) is None.
        let mut flight = identity();
        flight.name = "flight".into();
        let flight_id = flight.object_id();
        fs::create_dir_all(store.object_path(&flight_id)).unwrap();
        assert!(store.published_identity(&flight_id).unwrap().is_none());
        fs::set_permissions(
            store.object_path(&flight_id),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(store.published_identity(&flight_id).unwrap().is_none());

        // Wrong types are errors, not misses.
        let mut linked = identity();
        linked.name = "linked".into();
        let linked_id = linked.object_id();
        std::os::unix::fs::symlink(store.object_path(&id), store.object_path(&linked_id)).unwrap();
        assert!(store.published_identity(&linked_id).is_err());
        let mut meta_link = identity();
        meta_link.name = "meta-link".into();
        let meta_link_id = publish_bare(&store, &meta_link);
        let record = store.root.join("meta").join(format!("{meta_link_id}.json"));
        fs::remove_file(&record).unwrap();
        std::os::unix::fs::symlink(store.root.join("meta").join(format!("{id}.json")), &record)
            .unwrap();
        assert!(store.published_identity(&meta_link_id).is_err());

        // A FIFO planted as the record is refused, not waited on: a
        // blocking open would hang `status` forever with no writer.
        let mut piped = identity();
        piped.name = "piped".into();
        let piped_id = publish_bare(&store, &piped);
        let record = store.root.join("meta").join(format!("{piped_id}.json"));
        fs::remove_file(&record).unwrap();
        let name = CString::new(record.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o644) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = store.clone();
        std::thread::spawn(move || {
            let _ = sender.send(reader.published_identity(&piped_id).map(|_| ()));
        });
        let error = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("published_identity blocked on a FIFO record")
            .unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    /// `existing` finds a store without creating one, and holds it to
    /// `open`'s layout: a symlinked or non-directory namespace is an error.
    #[test]
    fn existing_never_creates_and_refuses_a_bent_layout() {
        let _lock = STORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os("TOG_STORE");
        let temp = temp_store();
        let check = |root: &Path| {
            std::env::set_var("TOG_STORE", root);
            Store::existing()
        };
        let missing = temp.0.join("missing");
        let absent = check(&missing);
        let real = check(&temp.0);
        let bent = temp.0.join("bent");
        fs::create_dir_all(&bent).unwrap();
        std::os::unix::fs::symlink(temp.0.join("objects"), bent.join("objects")).unwrap();
        let linked = check(&bent);
        let flat = temp.0.join("flat");
        fs::create_dir_all(&flat).unwrap();
        fs::write(flat.join("objects"), b"").unwrap();
        let file = check(&flat);
        match old {
            Some(value) => std::env::set_var("TOG_STORE", value),
            None => std::env::remove_var("TOG_STORE"),
        }
        assert!(absent.unwrap().is_none());
        assert!(!missing.exists());
        assert_eq!(real.unwrap().unwrap().root, temp.0.canonicalize().unwrap());
        assert!(linked.is_err());
        assert!(file.is_err());
    }

    /// `gc --register` over a project holding one closure per ecosystem at
    /// once, each in its oldest, sparsest shape: bare object paths, the
    /// `{"path", "id"}` pair, and a Node forest known only by the legacy
    /// `projection_id` route, with no `forest_path`. Every object and
    /// projection lands in one record. Each producer's current closure is
    /// re-imported by its own `closure_refs_name_every_object_this_producer_created`
    /// test; this one covers the legacy shapes and the cross-ecosystem union.
    #[test]
    fn register_imports_legacy_closure_bodies_of_every_ecosystem_together() {
        let temp = temp_store();
        let store = store_in(&temp);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let mut expected = BTreeSet::new();
        let mut object = |name: &str| {
            let id = named_object(&store, name);
            expected.insert(id.clone());
            id
        };
        let python_env = object("python-env");
        let node_env = object("node-env");
        let (rust, vendor) = (object("rust"), object("vendor"));
        let (go, modcache) = (object("go"), object("modcache"));
        let (ruby, gems) = (object("ruby"), object("gems"));
        let (beam, deps) = (object("beam"), object("deps"));
        let (sdk, packages) = (object("sdk"), object("packages"));
        let rustfmt = object("rustfmt");
        let backup = store.root.join("backups/venv-backup");
        let deps_projection = store
            .root
            .join("forests/0123456789abcdef")
            .join(&deps)
            .join("hex-deps");

        for (ecosystem, body) in [
            (
                "python",
                serde_json::json!({
                    "env_object": store.object_path(&python_env),
                    "native_libs": null,
                    "backup_path": backup,
                }),
            ),
            (
                "node",
                serde_json::json!({
                    "env_object": store.object_path(&node_env),
                    "projection_schema": "node-forest/2",
                    "projection_id": "projection",
                }),
            ),
            (
                "cargo",
                serde_json::json!({
                    "rust_object": object_ref(&store, &rust),
                    "vendor_object": object_ref(&store, &vendor),
                }),
            ),
            (
                "go",
                serde_json::json!({
                    "go_object": object_ref(&store, &go),
                    "modcache_object": object_ref(&store, &modcache),
                }),
            ),
            (
                "ruby",
                serde_json::json!({
                    "ruby_object": object_ref(&store, &ruby),
                    "gems_object": object_ref(&store, &gems),
                }),
            ),
            (
                "elixir",
                serde_json::json!({
                    "beam_object": object_ref(&store, &beam),
                    "deps_object": object_ref(&store, &deps),
                    "deps_projection": deps_projection,
                }),
            ),
            (
                "dotnet",
                serde_json::json!({
                    "sdk_object": object_ref(&store, &sdk),
                    "packages_object": object_ref(&store, &packages),
                }),
            ),
            (
                "rustfmt",
                serde_json::json!({
                    "rust_object": object_ref(&store, &rust),
                    "rustfmt_object": object_ref(&store, &rustfmt),
                }),
            ),
        ] {
            project_closure(&project, ecosystem, body);
        }

        let record = store
            .register_root_from_project(&project)
            .unwrap()
            .record
            .unwrap();
        assert_eq!(record.objects, expected);
        let projections: BTreeSet<PathBuf> = record
            .projections
            .iter()
            .map(|projection| projection.path(&store))
            .collect();
        let node_forest = store
            .root
            .parent()
            .unwrap()
            .join("forests")
            .join(short_project_key(&project))
            .join("projection");
        assert_eq!(
            projections,
            BTreeSet::from([backup, deps_projection, node_forest])
        );
    }

    /// Keys hash the pathname's bytes. A UTF-8 pathname keeps the key every
    /// earlier registry gave it; a pathname that is not UTF-8 is keyed by its
    /// raw bytes, so it never collides with the UTF-8 path that displays the
    /// same way (U+FFFD standing in for the bad byte).
    #[test]
    fn utf8_keys_unchanged_and_non_utf8_keys_distinct() {
        use sha1::Digest as _;
        let temp = temp_store();
        let store = store_in(&temp);
        let utf8 = temp.0.join("projekt-\u{e9}");
        fs::create_dir_all(&utf8).unwrap();
        let utf8 = utf8.canonicalize().unwrap();
        let expected = hex::encode(sha1::Sha1::digest(utf8.to_str().unwrap().as_bytes()));
        assert_eq!(Store::root_key(&utf8).unwrap(), expected);
        assert_eq!(store.register_root(&utf8).unwrap().key, expected);

        let lossy = PathBuf::from(format!("{}/project-\u{fffd}", store.root.display()));
        let raw = PathBuf::from(OsString::from_vec(
            [store.root.as_os_str().as_bytes(), b"/project-\xff"].concat(),
        ));
        assert_eq!(raw.to_string_lossy(), lossy.to_string_lossy());
        assert_ne!(root_key(&lossy), root_key(&raw));

        // APFS refuses non-UTF-8 file names (EILSEQ), so the registered pair
        // is only observable on Linux.
        #[cfg(target_os = "linux")]
        {
            let object = format!("{}-env", "c".repeat(40));
            for path in [&lossy, &raw] {
                fs::create_dir_all(path).unwrap();
                store
                    .register_root_record(RootRecord {
                        key: root_key(path),
                        project_path: path.clone(),
                        objects: BTreeSet::from([object.clone()]),
                        projections: BTreeSet::new(),
                        updated: 1,
                    })
                    .unwrap();
            }
            let (entries, _) = store.roots_for_sweep().unwrap();
            assert_eq!(entries.len(), 3, "{entries:?}");
            for path in [&lossy, &raw] {
                let found: Vec<_> = entries.iter().filter(|entry| &entry.path == path).collect();
                assert_eq!(found.len(), 1, "{path:?} read back as {found:?}");
                assert_eq!(found[0].key, root_key(path));
                assert!(found[0].record.is_some(), "{found:?}");
            }
        }
    }

    /// A scratch store and a project directory beside it, for the run
    /// home tests.
    fn run_home_fixture(label: &str) -> (TempDir, Store, PathBuf) {
        let temp = temp_store();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join(label);
        fs::create_dir_all(&project).unwrap();
        (temp, store, project)
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A fresh run home is `run-homes/<key>/<ecosystem>` with both levels
    /// private, and asking again returns the same directory.
    #[test]
    fn run_home_is_private_and_stable() {
        let (_temp, store, project) = run_home_fixture("project");
        let home = store.run_home(&project, "elixir").unwrap();
        let key = Store::project_key(&project).unwrap();
        assert_eq!(home, store.root.join("run-homes").join(&key).join("elixir"));
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(home.parent().unwrap()), 0o700);
        assert_eq!(store.run_home(&project, "elixir").unwrap(), home);
    }

    /// The project key is the one the forest paths already use: 16 hex
    /// characters of SHA-256 over the canonical path, the same for any
    /// spelling of the project and different between projects.
    #[test]
    fn project_key_matches_the_forest_key_and_separates_projects() {
        use sha2::{Digest, Sha256};
        let (temp, store, project) = run_home_fixture("one");
        let other = temp.0.join("two");
        fs::create_dir_all(&other).unwrap();
        let canonical = project.canonicalize().unwrap();
        let expected = hex::encode(&Sha256::digest(canonical.as_os_str().as_bytes())[..8]);
        assert_eq!(Store::project_key(&project).unwrap(), expected);
        assert_eq!(
            Store::project_key(&project.join("../one")).unwrap(),
            expected
        );
        assert_ne!(Store::project_key(&other).unwrap(), expected);
        assert_ne!(
            store.run_home(&project, "dotnet").unwrap(),
            store.run_home(&other, "dotnet").unwrap()
        );
    }

    /// A symlink at any level of the run home is refused rather than
    /// followed: it would hand the child a HOME someone else chose.
    #[test]
    fn run_home_refuses_a_symlink_at_every_level() {
        let (temp, store, project) = run_home_fixture("project");
        let elsewhere = temp.0.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let key = Store::project_key(&project).unwrap();
        let namespace = store.root.join("run-homes");
        let levels = [
            namespace.clone(),
            namespace.join(&key),
            namespace.join(&key).join("elixir"),
        ];
        for (index, level) in levels.iter().enumerate() {
            let _ = crate::kernel::store::remove_tree(&namespace);
            for parent in &levels[..index] {
                fs::create_dir(parent).unwrap();
            }
            std::os::unix::fs::symlink(&elsewhere, level).unwrap();
            let error = store.run_home(&project, "elixir").unwrap_err();
            assert!(
                error.to_string().contains(&level.display().to_string()),
                "{}: {error}",
                level.display()
            );
            assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        }
    }

    /// A run home of ours that is readable by others is narrowed to 0700
    /// instead of refused: the contents are still only ours.
    #[test]
    fn run_home_tightens_a_wider_directory_of_ours() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, store, project) = run_home_fixture("project");
        let key = Store::project_key(&project).unwrap();
        let home = store.root.join("run-homes").join(&key).join("dotnet");
        fs::create_dir_all(&home).unwrap();
        for level in [home.parent().unwrap(), home.as_path()] {
            fs::set_permissions(level, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(store.run_home(&project, "dotnet").unwrap(), home);
        assert_eq!(mode(&home), 0o700);
        assert_eq!(mode(home.parent().unwrap()), 0o700);
    }

    /// An ecosystem name that is not a single path component cannot walk
    /// the run home out of its project's directory.
    #[test]
    fn run_home_refuses_an_ecosystem_that_is_not_one_component() {
        let (_temp, store, project) = run_home_fixture("project");
        for ecosystem in ["", ".", "..", "../elixir", "a/b", "/abs", "elixir/"] {
            let error = store.run_home(&project, ecosystem).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{ecosystem:?}");
        }
    }

    /// A file where a run home level belongs is refused by name.
    #[test]
    fn run_home_refuses_a_file_in_its_place() {
        let (_temp, store, project) = run_home_fixture("project");
        let key = Store::project_key(&project).unwrap();
        let level = store.root.join("run-homes").join(&key);
        fs::create_dir_all(level.parent().unwrap()).unwrap();
        fs::write(&level, b"").unwrap();
        let error = store.run_home(&project, "elixir").unwrap_err();
        assert!(error.to_string().contains("not a directory"), "{error}");
    }
}

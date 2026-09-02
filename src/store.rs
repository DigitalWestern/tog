use crate::policy::Exception;
use crate::types::Identity;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn open() -> io::Result<Store> {
        let root = std::env::var_os("BLANKET_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".blanket/store"));
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub))?;
        }
        // Canonical path: sandbox subpath rules and store identities must
        // never see /tmp-style symlinked prefixes (macOS: /tmp -> /private/tmp).
        let root = root.canonicalize()?;
        Ok(Store { root })
    }

    pub fn object_path(&self, id: &str) -> PathBuf {
        self.root.join("objects").join(id)
    }

    /// Exclusive cross-process lock guarding publication and sweeping.
    /// Held only for the short rename/chmod/meta window, never during
    /// downloads or builds, so contention is negligible.
    fn publish_lock(&self) -> io::Result<fs::File> {
        let f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(self.root.join("tmp/.publish.lock"))?;
        f.lock()?;
        Ok(f)
    }

    /// Completeness check without sweeping (safe to call while holding the
    /// publish lock).
    fn is_complete(&self, id: &str) -> Option<bool> {
        let md = fs::metadata(self.object_path(id)).ok()?;
        use std::os::unix::fs::PermissionsExt;
        Some(
            md.is_dir()
                && md.permissions().mode() & 0o222 == 0
                && self.root.join("meta").join(format!("{id}.json")).is_file(),
        )
    }

    /// An object is valid only when fully published: directory present,
    /// root read-only, and metadata written (in that commit order). A
    /// crash mid-publication leaves an invalid object, which is swept and
    /// rebuilt instead of trusted.
    pub fn has(&self, id: &str) -> bool {
        match self.is_complete(id) {
            None => false,
            Some(true) => true,
            Some(false) => {
                // Looks like a crashed publication — but a CONCURRENT commit
                // may be in its rename->chmod->meta window and must not be
                // swept. Re-check under the publish lock; sweep only what is
                // still incomplete once no publication is in flight.
                if let Ok(_lock) = self.publish_lock() {
                    match self.is_complete(id) {
                        Some(true) => return true,
                        Some(false) => {
                            let _ = remove_tree(&self.object_path(id));
                        }
                        None => {}
                    }
                }
                false
            }
        }
    }

    /// Stage dir for building a new object; caller fills it, then calls commit.
    /// Collision-proof: SystemTime ticks in microseconds on macOS, so two
    /// threads can draw the same timestamp — create_dir (not _all) makes a
    /// collision an AlreadyExists we retry with a sequence number.
    pub fn stage(&self) -> io::Result<PathBuf> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        loop {
            let dir = self.root.join("tmp").join(format!(
                "stage-{}-{}-{}",
                std::process::id(),
                nanos(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Atomically move a staged dir into the store under `identity`, write
    /// metadata, and mark the tree read-only. Returns the object path and the
    /// exceptions stored with the object.
    /// If the object already exists the staged dir is discarded (cache hit).
    pub fn commit(
        &self,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        let id = identity.object_id();
        let dest = self.object_path(&id);
        if self.has(&id) {
            return self.cache_hit(&id, &dest, staged, exceptions);
        }
        // Read-only BEFORE publication (contents; APFS can't rename a
        // read-only dir, so the root is locked right after the rename —
        // the only window is top-level entry creation, never mutation).
        for entry in fs::read_dir(staged)? {
            make_read_only(&entry?.path())?;
        }
        // Publish under the cross-process lock so a concurrent has() never
        // mistakes the rename->chmod->meta window for a crashed object.
        let _lock = self.publish_lock()?;
        if self.is_complete(&id) == Some(true) {
            return self.cache_hit(&id, &dest, staged, exceptions);
        }
        // Under the lock, anything at dest is a crashed leftover (a live
        // publication can't be mid-window, and a complete object returned
        // above): sweep it so the rename lands.
        if dest.is_dir() {
            remove_tree(&dest)?;
        }
        fs::rename(staged, &dest)
            .map_err(|e| io::Error::new(e.kind(), format!("publish {}: {e}", dest.display())))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(perms.mode() & !0o222);
            fs::set_permissions(&dest, perms)?;
        }
        let meta = serde_json::json!({
            "id": id,
            "identity": identity,
            "created": unix_secs(),
            "exceptions": exceptions,
        });
        // Meta is the completion marker: write via tmp + atomic rename so a
        // crash mid-write can never leave a partial file that has() would
        // accept as complete.
        let meta_tmp = self.root.join("tmp").join(format!("meta-{id}.json"));
        fs::write(&meta_tmp, serde_json::to_vec_pretty(&meta)?)?;
        fs::rename(&meta_tmp, self.root.join("meta").join(format!("{id}.json")))?;
        Ok((dest, exceptions.to_vec()))
    }

    fn cache_hit(
        &self,
        id: &str,
        dest: &Path,
        staged: &Path,
        candidate: &[Exception],
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        let winner = self.exceptions(id)?;
        let result = crate::policy::check_exception_set(id, &winner).and_then(|_| {
            if winner != candidate {
                return Err(io::Error::other(format!(
                    "object {id} was published concurrently with different exceptions; winner: {winner:?}; staged: {candidate:?}; re-run sync"
                )));
            }
            Ok((dest.to_path_buf(), winner))
        });
        let _ = remove_tree(staged);
        result
    }

    pub fn exceptions(&self, id: &str) -> io::Result<Vec<Exception>> {
        let path = self.root.join("meta").join(format!("{id}.json"));
        let meta: serde_json::Value =
            serde_json::from_reader(fs::File::open(&path)?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse {}: {e}", path.display()),
                )
            })?;
        match meta.get("exceptions") {
            None => Ok(Vec::new()),
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse exceptions in {}: {e}", path.display()),
                )
            }),
        }
    }

    pub fn cache_path(&self, algo: &str, hex: &str) -> PathBuf {
        self.root.join("cache").join(algo).join(hex)
    }
}

/// Remove a possibly read-only staged tree (restore write bits first).
pub fn remove_tree(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) -> io::Result<()> {
        let md = fs::symlink_metadata(p)?;
        if md.file_type().is_symlink() {
            return Ok(());
        }
        let mut perms = md.permissions();
        perms.set_mode(perms.mode() | 0o200);
        let _ = fs::set_permissions(p, perms);
        if md.is_dir() {
            for entry in fs::read_dir(p)? {
                unlock(&entry?.path())?;
            }
        }
        Ok(())
    }
    let _ = unlock(path);
    fs::remove_dir_all(path)
}

/// Recursively remove write permission (files and dirs). Symlinks untouched.
fn make_read_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            make_read_only(&entry?.path())?;
        }
    }
    let mut perms = md.permissions();
    perms.set_mode(perms.mode() & !0o222);
    fs::set_permissions(path, perms)
        .map_err(|e| io::Error::new(e.kind(), format!("chmod {}: {e}", path.display())))
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME set"))
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn commit_reconciles_cached_exceptions() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let exception = Exception {
            kind: crate::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        let (object, applied) = store
            .commit(&identity, &staged(&store), std::slice::from_ref(&exception))
            .unwrap();
        assert_eq!(object, store.object_path(&identity.object_id()));
        assert_eq!(applied, vec![exception.clone()]);

        let error = store
            .commit(&identity, &staged(&store), &[])
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("was published concurrently with different exceptions"));
        assert!(error.to_string().contains("winner:"));
        assert!(error.to_string().contains("staged: []"));

        let (same_object, applied) = store
            .commit(&identity, &staged(&store), std::slice::from_ref(&exception))
            .unwrap();
        assert_eq!(same_object, object);
        assert_eq!(applied, vec![exception]);
    }

    #[test]
    fn strict_policy_rejects_cached_exceptions() {
        if std::env::var_os("BLANKET_STORE_STRICT_CHILD").is_some() {
            let store = Store::open().unwrap();
            crate::policy::init(&store.root, false).unwrap();
            let error = store
                .commit(&identity(), &staged(&store), &[])
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let exception = Exception {
            kind: crate::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        store
            .commit(
                &identity(),
                &staged(&store),
                std::slice::from_ref(&exception),
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
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

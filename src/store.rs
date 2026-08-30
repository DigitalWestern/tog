use crate::types::Identity;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Content/input-addressed immutable store.
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

    pub fn has(&self, id: &str) -> bool {
        self.object_path(id).is_dir()
    }

    /// Stage dir for building a new object; caller fills it, then calls commit.
    pub fn stage(&self) -> io::Result<PathBuf> {
        let dir = self.root.join("tmp").join(format!(
            "stage-{}-{}",
            std::process::id(),
            nanos()
        ));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Atomically move a staged dir into the store under `identity`, write
    /// metadata, and mark the tree read-only. Returns the object path.
    /// If the object already exists the staged dir is discarded (cache hit).
    pub fn commit(&self, identity: &Identity, staged: &Path) -> io::Result<PathBuf> {
        let id = identity.object_id();
        let dest = self.object_path(&id);
        if dest.is_dir() {
            let _ = fs::remove_dir_all(staged);
            return Ok(dest);
        }
        match fs::rename(staged, &dest) {
            Ok(()) => {}
            // Lost a race to a concurrent build of the same object: fine.
            Err(_) if dest.is_dir() => {
                let _ = fs::remove_dir_all(staged);
                return Ok(dest);
            }
            Err(e) => return Err(e),
        }
        let meta = serde_json::json!({
            "id": id,
            "identity": identity,
            "created": unix_secs(),
        });
        fs::write(
            self.root.join("meta").join(format!("{id}.json")),
            serde_json::to_vec_pretty(&meta)?,
        )?;
        make_read_only(&dest)?;
        Ok(dest)
    }

    pub fn cache_path(&self, algo: &str, hex: &str) -> PathBuf {
        self.root.join("cache").join(algo).join(hex)
    }
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

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

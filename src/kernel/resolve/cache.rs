//! The proxy's metadata cache: `<store>/resolve/meta/<key>`, one file per
//! response, the last good copy of every metadata document a tool fetched.
//!
//! The key is `sha256(method, url, normalized Accept)`, because one URL can
//! serve different documents by `Accept` (npm's abbreviated and full
//! packuments). Each file is a one-line JSON header (the URL, the
//! validators `ETag` and `Last-Modified`, the kept response headers, and
//! the body's sha256) followed by the body, written to a temporary name and
//! renamed, so a reader sees a whole entry or none. A body that no longer
//! hashes to its header is a miss, and the file is removed.
//!
//! Online, every hit is revalidated upstream with a conditional request;
//! the copy is served without the network only as last-good (a transport
//! failure, or `--offline`). It is a cache under the store's GC rules:
//! entries unused for the retention window are swept, and losing one costs
//! only a refetch. Artifacts are not cached here; a claimed artifact lives
//! in the verified `cache/<algo>/` like every other artifact tog fetched.

use crate::kernel::store::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const META_DIR: &str = "resolve/meta";

/// The response headers a cached entry keeps and serves again.
pub const KEPT_HEADERS: &[&str] = &[
    "content-type",
    "etag",
    "last-modified",
    "cache-control",
    "content-disposition",
    "expires",
];

/// The cache key of one request. `credentials` is the identity of the
/// endpoint credentials the response may have been fetched with (see
/// `Route::credential_identity`, empty when there are none), so a response
/// fetched with a credential is never served to a configuration without
/// that same credential.
pub fn key(method: &str, url: &str, accept: Option<&str>, credentials: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [method, url, &normalize_accept(accept), credentials] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

/// `Accept` without the spelling differences that do not change what is
/// asked for: whitespace around items and parameters, and letter case.
/// Order is kept, since it can carry preference.
pub fn normalize_accept(accept: Option<&str>) -> String {
    accept
        .unwrap_or_default()
        .split(',')
        .map(|item| {
            item.split(';')
                .map(|part| part.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(";")
        })
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// One cached response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cached {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub sha256: String,
    #[serde(skip)]
    pub body: Vec<u8>,
}

impl Cached {
    pub fn new(url: &str, headers: &[(String, String)], body: Vec<u8>) -> Self {
        let headers = headers
            .iter()
            .filter(|(name, _)| KEPT_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
            .cloned()
            .collect();
        Self {
            url: url.to_string(),
            headers,
            sha256: hex::encode(Sha256::digest(&body)),
            body,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The metadata cache of one store.
#[derive(Debug, Clone)]
pub struct MetaCache {
    dir: PathBuf,
    tmp: PathBuf,
}

impl MetaCache {
    pub fn open(store: &Store) -> io::Result<Self> {
        store.ensure_namespace(Path::new(META_DIR))?;
        store.ensure_namespace(Path::new("tmp"))?;
        Ok(Self {
            dir: store.root.join(META_DIR),
            tmp: store.root.join("tmp"),
        })
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    /// The entry under `key`, verified. A corrupt entry is removed and is a
    /// miss. A hit refreshes the entry's age.
    pub fn load(&self, key: &str) -> io::Result<Option<Cached>> {
        let path = self.path(key);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let parsed = bytes
            .iter()
            .position(|&b| b == b'\n')
            .and_then(|newline| {
                let mut cached: Cached = serde_json::from_slice(&bytes[..newline]).ok()?;
                cached.body = bytes[newline + 1..].to_vec();
                Some(cached)
            })
            .filter(|cached| hex::encode(Sha256::digest(&cached.body)) == cached.sha256);
        match parsed {
            Some(cached) => {
                let _ = fs::File::options()
                    .write(true)
                    .open(&path)
                    .and_then(|file| file.set_modified(SystemTime::now()));
                Ok(Some(cached))
            }
            None => {
                let _ = fs::remove_file(&path);
                Ok(None)
            }
        }
    }

    /// Store `cached` under `key`, replacing any older entry atomically.
    pub fn save(&self, key: &str, cached: &Cached) -> io::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = self.tmp.join(format!(
            "resolve-meta-{}-{}-{key}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let write = || -> io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&serde_json::to_vec(cached)?)?;
            file.write_all(b"\n")?;
            file.write_all(&cached.body)?;
            file.sync_all()?;
            fs::rename(&tmp, self.path(key))
        };
        write().inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })
    }
}

/// What a sweep removed (or, dry, would remove).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    pub entries: usize,
    pub bytes: u64,
    pub index_entries: usize,
}

/// The GC hook: remove metadata entries unused for longer than `max_age`,
/// and sidecar index entries whose sidecar is gone. The caller holds the
/// store's exclusive lease, so no proxy is writing.
pub fn sweep(store: &Store, max_age: Duration, dry_run: bool) -> io::Result<Swept> {
    let mut swept = Swept {
        index_entries: super::ledger::sweep_index(store, dry_run)?,
        ..Swept::default()
    };
    let dir = store.root.join(META_DIR);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(swept),
        Err(error) => return Err(error),
    };
    let now = SystemTime::now();
    for entry in entries {
        let entry = entry?;
        let stat = fs::symlink_metadata(entry.path())?;
        let age = stat
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or_default();
        // A name that is not a key (a symlink, a directory, a stray file)
        // is not ours to keep either.
        let ours = stat.is_file()
            && entry.file_name().to_str().is_some_and(|name| {
                name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
            });
        if ours && age <= max_age {
            continue;
        }
        if !dry_run {
            if stat.is_dir() {
                crate::kernel::store::remove_tree(&entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        swept.entries += 1;
        swept.bytes += stat.len();
    }
    Ok(swept)
}

/// Read at most `cap` bytes of `reader`; more is an `InvalidData` error,
/// never a truncation. Any other error is the transport's.
pub fn read_capped(reader: &mut dyn Read, cap: u64) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    reader.take(cap + 1).read_to_end(&mut body)?;
    if body.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the response is over the {} MiB cap for metadata",
                cap >> 20
            ),
        ));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_cache_key_includes_accept() {
        let url = "https://registry.test/pkg";
        let full = key("GET", url, Some("application/json"), "");
        let abbreviated = key("GET", url, Some("application/vnd.npm.install-v1+json"), "");
        assert_ne!(full, abbreviated);
        assert_ne!(full, key("GET", url, None, ""));
        assert_ne!(full, key("HEAD", url, Some("application/json"), ""));
        assert_ne!(
            full,
            key(
                "GET",
                "https://registry.test/pkg2",
                Some("application/json"),
                ""
            )
        );
        // A credentialed configuration never shares an anonymous key, nor
        // another credential's.
        assert_ne!(full, key("GET", url, Some("application/json"), "cred-a"));
        assert_ne!(
            key("GET", url, Some("application/json"), "cred-a"),
            key("GET", url, Some("application/json"), "cred-b")
        );
        // Spelling differences that ask for the same thing share a key.
        assert_eq!(
            key(
                "GET",
                url,
                Some("application/vnd.pypi.simple.v1+json; q=0.9, text/html"),
                ""
            ),
            key(
                "GET",
                url,
                Some("Application/Vnd.PyPI.Simple.V1+JSON;q=0.9,text/html"),
                ""
            )
        );
        // Order is preference, so it is kept.
        assert_ne!(
            key("GET", url, Some("a/b, c/d"), ""),
            key("GET", url, Some("c/d, a/b"), "")
        );
    }

    #[test]
    fn entries_round_trip_and_corruption_is_a_miss() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("meta");
        let cache = MetaCache::open(&store).unwrap();
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("ETag".to_string(), "\"v1\"".to_string()),
            ("Set-Cookie".to_string(), "session=1".to_string()),
        ];
        let entry = Cached::new("https://registry.test/a", &headers, b"{\"a\":1}".to_vec());
        assert_eq!(entry.headers.len(), 2, "only kept headers are stored");
        let k = key("GET", "https://registry.test/a", None, "");
        cache.save(&k, &entry).unwrap();
        assert_eq!(cache.load(&k).unwrap(), Some(entry.clone()));
        assert_eq!(cache.load(&"0".repeat(64)).unwrap(), None);
        // A body edited in place no longer matches its header.
        let path = store.root.join(META_DIR).join(&k);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() = b'2';
        fs::write(&path, bytes).unwrap();
        assert_eq!(cache.load(&k).unwrap(), None);
        assert!(!path.exists(), "a corrupt entry is removed");
    }

    #[test]
    fn sweep_removes_old_entries_and_orphaned_index_entries() {
        let (_temp, store, _activity) = crate::kernel::resolve::testing::scratch_store("sweep");
        let cache = MetaCache::open(&store).unwrap();
        let (old, fresh) = (
            key("GET", "https://r.test/old", None, ""),
            key("GET", "https://r.test/new", None, ""),
        );
        cache
            .save(
                &old,
                &Cached::new("https://r.test/old", &[], b"old".to_vec()),
            )
            .unwrap();
        cache
            .save(
                &fresh,
                &Cached::new("https://r.test/new", &[], b"new".to_vec()),
            )
            .unwrap();
        let month_ago = SystemTime::now() - Duration::from_secs(40 * 24 * 3600);
        fs::File::options()
            .write(true)
            .open(store.root.join(META_DIR).join(&old))
            .unwrap()
            .set_modified(month_ago)
            .unwrap();
        fs::create_dir_all(store.root.join("resolve/diag")).unwrap();
        let ledger = format!("{}-fixture-1", "a".repeat(40));
        fs::write(
            store.root.join("resolve/diag").join(&ledger),
            format!("{}-fixture-1\n", "b".repeat(40)),
        )
        .unwrap();
        let window = Duration::from_secs(30 * 24 * 3600);
        let dry = sweep(&store, window, true).unwrap();
        assert_eq!((dry.entries, dry.index_entries), (1, 1));
        assert!(
            store.root.join(META_DIR).join(&old).exists(),
            "a dry run removes nothing"
        );
        let real = sweep(&store, window, false).unwrap();
        assert_eq!(real, dry);
        assert_eq!(cache.load(&old).unwrap(), None);
        assert!(cache.load(&fresh).unwrap().is_some());
        assert!(!store.root.join("resolve/diag").join(&ledger).exists());
    }
}

//! Verified downloads into the store (kernel layer): fetch a URL, check
//! its digest, and hold the bytes as a store object.

use crate::kernel::store::{self, Store};
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::{ffi::OsStr, ops::Deref};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

/// Content digest for artifact verification and cache addressing.
/// Fields are private: a Digest can only hold validated lowercase hex of
/// the exact right length, so it can never smuggle path components into
/// cache paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest {
    algo: Algo,
    hex: String,
}

/// A verified cache path with the GC lock held until the caller drops it.
/// Keeping this lease alive across extraction closes the verify-to-use race:
/// GC cannot unlink the artifact while an extractor is still consuming it.
pub(crate) struct CacheLease {
    path: PathBuf,
    // Keep operation protection with the verified path. A GC-lock-only
    // lease would allow the caller's store activity to end before extraction
    // or another cache consumer finishes using this path.
    _activity: crate::kernel::activity::StoreActivity,
    _gc_lock: Arc<fs::File>,
}

fn acquire_gc_lock(store: &Store) -> io::Result<Arc<fs::File>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<fs::File>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let locks = locks.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(lock) = locks.get(&store.root).and_then(Weak::upgrade) {
            return Ok(lock);
        }
    }
    // Never hold the process-global registry mutex while waiting for the OS
    // lock. Otherwise a blocked fetch for store A can prevent the thread
    // holding store B's entry from dropping it. Two contenders may briefly
    // open their own descriptors; the second map check below adopts the
    // first winner's descriptor and drops its redundant lock.
    let candidate = Arc::new(store.gc_lock()?);
    let mut locks = locks.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(lock) = locks.get(&store.root).and_then(Weak::upgrade) {
        drop(candidate);
        return Ok(lock);
    }
    locks.insert(store.root.clone(), Arc::downgrade(&candidate));
    Ok(candidate)
}

impl CacheLease {
    fn into_path(self) -> PathBuf {
        self.path
    }
}

impl Deref for CacheLease {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for CacheLease {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<OsStr> for CacheLease {
    fn as_ref(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

impl Digest {
    fn validated(algo: Algo, hex: &str) -> io::Result<Digest> {
        let want = match algo {
            Algo::Sha1 => 40,
            Algo::Sha256 => 64,
            Algo::Sha512 => 128,
        };
        let hex = hex.to_ascii_lowercase();
        if hex.len() != want || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed {} hex digest: {hex}", algo_name(algo)),
            ));
        }
        Ok(Digest { algo, hex })
    }
    pub fn sha256(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha256, hex)
    }
    pub fn sha1(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha1, hex)
    }
    pub fn sha512(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha512, hex)
    }
    pub fn algo(&self) -> &'static str {
        algo_name(self.algo)
    }
    pub fn hex(&self) -> &str {
        &self.hex
    }
    /// Parse an npm SRI string like "sha512-<base64>", "sha256-<base64>", or
    /// the legacy "sha1-<base64>" form.
    pub fn from_sri(sri: &str) -> io::Result<Digest> {
        let (algo, b64) = sri.split_once('-').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed integrity: {sri}"),
            )
        })?;
        let bytes = base64_decode(b64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad base64 in integrity: {sri}"),
            )
        })?;
        let hex = hex::encode(bytes);
        match algo {
            "sha1" => Digest::sha1(&hex),
            "sha256" => Digest::sha256(&hex),
            "sha512" => Digest::sha512(&hex),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported integrity algorithm: {other}"),
            )),
        }
    }
}

/// Fetch a cache entry by sha256, RE-VERIFYING its content (never trust a
/// cache hit: read-only bits stop accidents, not same-user replacement).
/// A poisoned entry is deleted and reported missing.
pub fn cache_verified(store: &Store, sha256: &str) -> io::Result<PathBuf> {
    let _activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    cache_verified_held(store, sha256).map(CacheLease::into_path)
}

pub(crate) fn cache_verified_held(store: &Store, sha256: &str) -> io::Result<CacheLease> {
    let digest = Digest::sha256(sha256)?;
    cache_verified_digest_held(store, &digest).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            io::Error::new(
                error.kind(),
                format!("cache entry {sha256} was corrupted or unreadable: {error}"),
            )
        } else {
            error
        }
    })
}

pub(crate) fn cache_verified_digest_held(store: &Store, digest: &Digest) -> io::Result<CacheLease> {
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let gc_lock = acquire_gc_lock(store)?;
    let path = store.cache_path(digest.algo(), digest.hex());
    match hash_file(&path, digest.algo) {
        Ok(h) if h == digest.hex() => {
            store::touch_path(&path)?;
            Ok(CacheLease {
                path,
                _activity: activity,
                _gc_lock: gc_lock,
            })
        }
        Ok(_) => {
            let _ = fs::remove_file(&path);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cache entry {}:{} was corrupted (removed)",
                    digest.algo(),
                    digest.hex()
                ),
            ))
        }
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "cache entry {}:{} is unreadable: {error}",
                digest.algo(),
                digest.hex()
            ),
        )),
    }
}

/// Read an integrity-addressed cache entry while retaining the verification
/// lease through the read, so GC cannot remove it between verification and
/// use.
pub(crate) fn read_cache_verified_digest(store: &Store, digest: &Digest) -> io::Result<Vec<u8>> {
    let lease = cache_verified_digest_held(store, digest)?;
    fs::read(&lease.path)
}

fn hash_file(path: &std::path::Path, algo: Algo) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut buf = [0u8; 65536];
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    let mut h1 = Sha1::new();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        match algo {
            Algo::Sha1 => h1.update(&buf[..n]),
            Algo::Sha256 => h256.update(&buf[..n]),
            Algo::Sha512 => h512.update(&buf[..n]),
        }
    }
    Ok(match algo {
        Algo::Sha1 => hex::encode(h1.finalize()),
        Algo::Sha256 => hex::encode(h256.finalize()),
        Algo::Sha512 => hex::encode(h512.finalize()),
    })
}

fn algo_name(a: Algo) -> &'static str {
    match a {
        Algo::Sha1 => "sha1",
        Algo::Sha256 => "sha256",
        Algo::Sha512 => "sha512",
    }
}

/// Minimal RFC 4648 base64 (standard alphabet, optional padding).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let n = chunk.len();
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
        if n == 1 {
            return None;
        }
    }
    Some(out)
}

/// Back-compat convenience for sha256 hex callers. Internal extraction paths
/// use `download_verified_held` so their lease lasts through consumption.
/// Fetch a small text file over HTTPS (a checksum manifest, for example).
///
/// There is no hash to check against — this IS the checksum source — so the
/// caller must treat it as trust-on-first-use and record it, exactly like the
/// pinned toolchain tables do. Capped so a hostile server cannot stream
/// forever.
pub fn fetch_text(url: &str) -> io::Result<String> {
    const MAX_TEXT: u64 = 8 << 20;
    let agent = ureq::AgentBuilder::new().https_only(true).build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| io::Error::other(format!("GET {url}: {e}")))?;
    let mut text = String::new();
    resp.into_reader()
        .take(MAX_TEXT)
        .read_to_string(&mut text)
        .map_err(|e| io::Error::new(e.kind(), format!("read {url}: {e}")))?;
    Ok(text)
}

pub fn download_verified(store: &Store, url: &str, sha256: &str) -> io::Result<PathBuf> {
    let _activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    download_verified_held(store, url, sha256).map(CacheLease::into_path)
}

pub(crate) fn download_verified_held(
    store: &Store,
    url: &str,
    sha256: &str,
) -> io::Result<CacheLease> {
    download_verified_digest_held(store, url, &Digest::sha256(sha256)?)
}

/// Insert a local file into the verified artifact cache by its computed
/// sha256 (for artifacts obtained through delegated tools and then verified
/// by blanket — e.g. Go module zips h1-checked by dirhash). Returns
/// (sha256 hex, cache path). Publication mirrors download_verified.
pub fn cache_insert(store: &Store, src: &std::path::Path) -> io::Result<(String, PathBuf)> {
    let _activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let hex = hash_file(src, Algo::Sha256)?;
    let _gc_lock = acquire_gc_lock(store)?;
    let dest = store.cache_path("sha256", &hex);
    if dest.is_file() {
        // Re-verify on hit, like download_verified: a same-user replacement
        // must never ride an old address (poisoned -> drop and re-insert).
        match hash_file(&dest, Algo::Sha256) {
            Ok(h) if h == hex => {
                store::touch_path(&dest)?;
                return Ok((hex, dest));
            }
            _ => {
                let _ = fs::remove_file(&dest);
            }
        }
    }
    fs::create_dir_all(dest.parent().unwrap())?;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = store.root.join("tmp").join(format!(
        "ins-{}-{}-{hex}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::copy(src, &tmp)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&tmp, perms)?;
    }
    match fs::rename(&tmp, &dest) {
        Ok(()) => {}
        Err(_) if dest.is_file() => {
            let _ = fs::remove_file(&tmp);
        }
        Err(e) => return Err(io::Error::new(e.kind(), format!("cache insert {hex}: {e}"))),
    }
    store::touch_path(&dest)?;
    Ok((hex, dest))
}

/// Download `url`, verify its digest, and place it in the store's artifact
/// cache (keyed by algo/hex). Idempotent; an existing entry short-circuits
/// (offline reconstruction). file:// URLs read local files (mirrors, tests).
pub fn download_verified_digest(store: &Store, url: &str, digest: &Digest) -> io::Result<PathBuf> {
    let _activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    download_verified_digest_held(store, url, digest).map(CacheLease::into_path)
}

pub(crate) fn download_verified_digest_held(
    store: &Store,
    url: &str,
    digest: &Digest,
) -> io::Result<CacheLease> {
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let gc_lock = acquire_gc_lock(store)?;
    let dest = store.cache_path(digest.algo(), digest.hex());
    if dest.is_file() {
        // Re-verify on every hit: read-only bits stop accidents, not disk
        // corruption or same-user replacement. A concurrent publisher can
        // replace/briefly unlink the entry, so a read race falls through
        // to a fresh download instead of failing.
        match hash_file(&dest, digest.algo) {
            Ok(h) if h == digest.hex() => {
                store::touch_path(&dest)?;
                return Ok(CacheLease {
                    path: dest,
                    _activity: activity.clone(),
                    _gc_lock: gc_lock,
                });
            }
            Ok(_) => {
                let _ = fs::remove_file(&dest); // poisoned/corrupt: refetch
            }
            Err(_) => {}
        }
    }
    fs::create_dir_all(dest.parent().unwrap())
        .map_err(|e| io::Error::new(e.kind(), format!("cache dir: {e}")))?;
    // Unique per attempt: two concurrent downloads of the same artifact
    // (even same-process threads) must never share a tmp file — the stream
    // hash would verify while the file holds interleaved garbage. A
    // process-wide sequence number breaks timestamp ties (SystemTime ticks
    // in microseconds on macOS; concurrent threads collide on it).
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = store.root.join("tmp").join(format!(
        "dl-{}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        digest.hex()
    ));

    let mut reader: Box<dyn Read> = if let Some(path) = url.strip_prefix("file://") {
        Box::new(
            fs::File::open(path)
                .map_err(|e| io::Error::new(e.kind(), format!("open {path}: {e}")))?,
        )
    } else {
        // https_only holds across redirects too — no downgrade-to-http.
        let agent = ureq::AgentBuilder::new().https_only(true).build();
        let resp = agent
            .get(url)
            .call()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("GET {url}: {e}")))?;
        Box::new(resp.into_reader())
    };

    // Cap the stream so a hostile server can't fill the disk before the
    // hash check fails. 8 GiB covers every real artifact class we handle.
    const MAX_ARTIFACT: u64 = 8 << 30;
    let mut file = fs::File::create(&tmp)
        .map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", tmp.display())))?;
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    let mut h1 = Sha1::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    let stream_result: io::Result<()> = loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        total += n as u64;
        if total > MAX_ARTIFACT {
            break Err(io::Error::other(format!(
                "{url}: exceeds the {} GiB artifact cap; refusing",
                MAX_ARTIFACT >> 30
            )));
        }
        match digest.algo {
            Algo::Sha1 => h1.update(&buf[..n]),
            Algo::Sha256 => h256.update(&buf[..n]),
            Algo::Sha512 => h512.update(&buf[..n]),
        }
        if let Err(e) = file.write_all(&buf[..n]) {
            break Err(e);
        }
    };
    if let Err(e) = stream_result.and_then(|_| file.flush()) {
        drop(file);
        let _ = fs::remove_file(&tmp); // never leave partial downloads
        return Err(e);
    }
    drop(file);

    let got = match digest.algo {
        Algo::Sha1 => hex::encode(h1.finalize()),
        Algo::Sha256 => hex::encode(h256.finalize()),
        Algo::Sha512 => hex::encode(h512.finalize()),
    };
    if got != digest.hex() {
        let _ = fs::remove_file(&tmp);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "hash mismatch for {url}\n  expected {} {}\n  got      {got}",
                digest.algo(),
                digest.hex()
            ),
        ));
    }
    // Publish read-only, atomically.
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)
            .map_err(|e| io::Error::new(e.kind(), format!("stat dl tmp: {e}")))?
            .permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&tmp, perms)
            .map_err(|e| io::Error::new(e.kind(), format!("chmod dl tmp: {e}")))?;
    }
    match fs::rename(&tmp, &dest) {
        Ok(()) => {}
        Err(_) if dest.is_file() => {
            let _ = fs::remove_file(&tmp);
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("cache publish {}: {e}", dest.display()),
            ))
        }
    }
    store::touch_path(&dest)?;
    Ok(CacheLease {
        path: dest,
        _activity: activity,
        _gc_lock: gc_lock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn sri_roundtrip() {
        // echo -n hello | shasum -a 512 -> base64 of raw digest
        let d = Digest::from_sri(
            "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==",
        )
        .unwrap();
        assert_eq!(d.algo(), "sha512");
        assert!(d.hex().starts_with("9b71d224bd62f378"));
        assert!(Digest::from_sri("md5-abc").is_err());
        assert!(Digest::from_sri("nodash").is_err());
    }

    #[test]
    fn sha1_integrity_accepts_and_rejects_at_verification() {
        let root = std::env::temp_dir().join(format!(
            "blanket-fetch-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for sub in ["objects", "meta", "cache/sha256", "cache/sha1", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let input = root.join("artifact");
        fs::write(&input, b"hello").unwrap();
        let expected = Digest::from_sri("sha1-qvTGHdzF6KLavt4PO0gs2a6pQ00=").unwrap();
        let url = format!("file://{}", input.display());
        assert!(download_verified_digest(&store, &url, &expected).is_ok());

        let wrong = Digest::from_sri("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let error = download_verified_digest(&store, &url, &wrong).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_lease_refreshes_mtime_and_blocks_gc() {
        let root = std::env::temp_dir().join(format!(
            "blanket-fetch-lease-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let input = root.join("artifact");
        fs::write(&input, b"hello").unwrap();
        let digest = hex::encode(Sha256::digest(b"hello"));
        let cache = store.cache_path("sha256", &digest);
        fs::write(&cache, b"hello").unwrap();
        let old = SystemTime::now()
            .checked_sub(Duration::from_secs(2 * 24 * 60 * 60))
            .unwrap();
        fs::File::open(&cache).unwrap().set_modified(old).unwrap();

        let lease = download_verified_digest_held(
            &store,
            &format!("file://{}", input.display()),
            &Digest::sha256(&digest).unwrap(),
        )
        .unwrap();
        assert!(
            SystemTime::now()
                .duration_since(fs::metadata(&cache).unwrap().modified().unwrap())
                .unwrap()
                < Duration::from_secs(60)
        );

        let probe = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(store.root.join("gc.lock"))
            .unwrap();
        assert!(probe.try_lock().is_err());
        drop(lease);
        // The lease is gone, so the lock must be released. On a loaded machine
        // the release can be observed a moment late, so retry briefly rather
        // than fail the suite for a scheduling artifact; a lock that is never
        // released still fails here.
        let mut released = false;
        for _ in 0..200 {
            if probe.try_lock().is_ok() {
                released = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            released,
            "the gc lock was not released when the lease was dropped"
        );
        let _ = fs::remove_dir_all(root);
    }
}

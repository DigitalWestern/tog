//! Verified downloads into the store (kernel layer): fetch a URL, check
//! its digest, and hold the bytes as a store object.

use crate::kernel::digest::Algo;
pub use crate::kernel::digest::Digest;
use crate::kernel::store::{self, Store};
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::{ffi::OsStr, ops::Deref};

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

/// Fetch a cache entry by sha256, RE-VERIFYING its content (never trust a
/// cache hit: read-only bits stop accidents, not same-user replacement).
/// A poisoned entry is deleted and the call fails.
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

/// The hex digest of a file under `algo`. This is the same read every
/// verification on a cache hit performs, exposed so a caller that holds a
/// lease across a long phase can re-verify the bytes immediately before it
/// uses them: the lease stops a sweep, not a same-user replacement.
pub(crate) fn hash_file(path: &std::path::Path, algo: Algo) -> io::Result<String> {
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

/// What a ureq failure means to someone waiting on a sync. ureq's own
/// Display already repeats the URL and reads like a library backtrace, so
/// every branch replaces it rather than wrapping it.
fn status_cause(code: u16) -> String {
    match code {
        401 | 403 => "the server refused the request (401/403); a private mirror needs \
                      credentials tog does not carry"
            .to_string(),
        404 | 410 => format!(
            "the server does not have this artifact ({code}); the index may have yanked it, or \
             the lockfile names a version that is gone"
        ),
        407 => "the proxy refused the request (407); set https_proxy with credentials, or unset it"
            .to_string(),
        429 => "the server is rate-limiting this host (429); wait and run the command again"
            .to_string(),
        code if code >= 500 => {
            format!("the server failed ({code}); this is the registry's side, try again later")
        }
        code => format!("the server replied {code}"),
    }
}

/// Does this transport failure mean "there is no network", as opposed to
/// "the network is there and something about this connection went wrong"?
/// Only the unreachable-network errnos and a DNS failure qualify; saying
/// "offline" about a rejected TLS handshake sends the user to check their
/// wifi over a bad certificate.
fn looks_offline(source: &str) -> bool {
    const OFFLINE: &[&str] = &[
        "Network is unreachable",
        "No route to host",
        "Host is down",
        "Temporary failure in name resolution",
        "failed to lookup address",
        "nodename nor servname provided",
        "No address associated with hostname",
    ];
    let source = source.to_ascii_lowercase();
    OFFLINE
        .iter()
        .any(|marker| source.contains(&marker.to_ascii_lowercase()))
}

/// `kind` alone, for the branches where the source adds nothing.
#[cfg(test)]
fn transport_cause(kind: ureq::ErrorKind) -> Option<String> {
    transport_cause_with(kind, "")
}

/// The user-facing text for a transport failure. `source` is ureq's own
/// message: `ErrorKind::Io` is its catch-all (a rejected TLS handshake, a
/// bad certificate behind a MITM proxy, a mid-stream reset or timeout), so
/// for the connection branches the source is the only thing that says
/// which, and it is appended rather than dropped.
fn transport_cause_with(kind: ureq::ErrorKind, source: &str) -> Option<String> {
    let detail = |text: &str| {
        if source.is_empty() {
            text.to_string()
        } else {
            format!("{text} ({source})")
        }
    };
    let text = match kind {
        ureq::ErrorKind::Dns => {
            return Some(detail(
                "the host name did not resolve; tog appears to be offline, or DNS is unreachable",
            ))
        }
        ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::Io => {
            return Some(detail(if looks_offline(source) {
                "the connection failed; tog appears to be offline (a cached artifact would have \
                 been used instead)"
            } else {
                "the connection failed"
            }))
        }
        ureq::ErrorKind::ProxyConnect | ureq::ErrorKind::InvalidProxyUrl => {
            "the proxy could not be reached; check https_proxy and no_proxy"
        }
        ureq::ErrorKind::ProxyUnauthorized => {
            "the proxy rejected the credentials; check https_proxy"
        }
        ureq::ErrorKind::InsecureRequestHttpsOnly | ureq::ErrorKind::UnknownScheme => {
            "tog fetches over https only; an http:// mirror is refused rather than downgraded"
        }
        ureq::ErrorKind::InvalidUrl => "the url could not be parsed",
        ureq::ErrorKind::TooManyRedirects => "the server redirected too many times",
        // BadStatus, BadHeader, HTTP: a malformed reply tog cannot explain
        // better than the library can.
        _ => return None,
    };
    Some(text.to_string())
}

/// What a `ureq::Transport` says beyond its URL and its kind.
///
/// ureq renders a transport failure as `{url}: {kind}: {message}: {source}`
/// with everything but the kind optional. tog names the URL itself and
/// translates the kind, so both are dropped; the rest is the only part that
/// distinguishes a rejected certificate from a reset connection, and it is
/// kept whole — splitting on the last `": "` would reduce
/// `invalid peer certificate: UnknownIssuer` to `UnknownIssuer`.
fn source_after_kind(text: &str, kind: &str) -> String {
    let marker = format!("{kind}: ");
    match text.find(&marker) {
        Some(at) => text[at + marker.len()..].trim().to_string(),
        // Only a URL and a kind: nothing further to say.
        None => String::new(),
    }
}

fn transport_source(transport: &ureq::Transport) -> String {
    source_after_kind(&transport.to_string(), &transport.kind().to_string())
}

fn network_cause(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Status(code, _) => status_cause(*code),
        ureq::Error::Transport(transport) => {
            let source = transport_source(transport);
            transport_cause_with(transport.kind(), &source).unwrap_or_else(|| transport.to_string())
        }
    }
}

fn network_error(verb: &str, url: &str, error: ureq::Error) -> io::Error {
    io::Error::other(format!("{verb} {url}: {}", network_cause(&error)))
}

/// The artifact's name for progress narration: the last path segment of
/// the URL, without a query string. A URL with no path segment has no name
/// to show — printing the host would label the line with the registry
/// rather than the file — so it falls back to a neutral word.
fn artifact_name(url: &str) -> &str {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let after_scheme = path.split_once("://").map(|(_, rest)| rest).unwrap_or(path);
    // Skip the authority: everything before the first '/' is the host.
    match after_scheme.split_once('/') {
        Some((_, tail)) => tail
            .rsplit('/')
            .find(|segment| !segment.is_empty())
            .unwrap_or("download"),
        None => "download",
    }
}

/// Open `url` for reading: a `file://` path (mirrors, tests) or an https
/// request. `https_only` holds across redirects too, so nothing ever
/// downgrades to http. The second value is the declared Content-Length,
/// when the server sent one, for progress narration. `timeout` bounds the
/// whole request, for the one-shot checks that must never hang a command
/// (the release lookup `doctor` makes); the store's downloads pass `None`.
fn open_url(
    url: &str,
    verb: &str,
    timeout: Option<std::time::Duration>,
) -> io::Result<(Box<dyn Read>, Option<u64>)> {
    if let Some(path) = url.strip_prefix("file://") {
        let file = fs::File::open(path)
            .map_err(|e| io::Error::new(e.kind(), format!("open {path}: {e}")))?;
        return Ok((Box::new(file), None));
    }
    let mut builder = ureq::AgentBuilder::new().https_only(true);
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    let resp = builder
        .build()
        .get(url)
        .call()
        .map_err(|e| network_error(verb, url, e))?;
    let declared = resp
        .header("Content-Length")
        .and_then(|value| value.trim().parse::<u64>().ok());
    Ok((Box::new(resp.into_reader()), declared))
}

/// Fetch a small text file over HTTPS (a checksum manifest, for example).
///
/// There is no hash to check against — this IS the checksum source — so the
/// caller must treat it as trust-on-first-use and record it, exactly like the
/// pinned toolchain tables do. Capped so a hostile server cannot stream
/// forever.
pub fn fetch_text(url: &str) -> io::Result<String> {
    fetch_text_within(url, None)
}

/// `fetch_text` with a deadline on the whole request. A `file://` URL reads
/// the file and ignores the deadline.
pub fn fetch_text_within(url: &str, timeout: Option<std::time::Duration>) -> io::Result<String> {
    const MAX_TEXT: u64 = 8 << 20;
    let (reader, _) = open_url(url, "fetch", timeout)?;
    let mut text = String::new();
    reader
        .take(MAX_TEXT)
        .read_to_string(&mut text)
        .map_err(|e| io::Error::new(e.kind(), format!("read {url}: {e}")))?;
    Ok(text)
}

/// Download `url` to `dest`, verifying its sha256 as it streams, without
/// the store: for the one artifact that is not a store object, tog's own
/// release binary. `dest` is written whole or not at all (a mismatch or a
/// short read removes it), and the stream is capped so a hostile server
/// cannot fill the disk before the hash check fails.
pub fn download_file(url: &str, dest: &Path, sha256: &str) -> io::Result<()> {
    const MAX_FILE: u64 = 256 << 20;
    let digest = Digest::sha256(sha256)?;
    let (mut reader, declared) = open_url(url, "download", None)?;
    let mut progress = crate::kernel::ui::Progress::start(artifact_name(url), declared);
    let mut file = fs::File::create(dest)
        .map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", dest.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    let streamed: io::Result<()> = loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) => break Err(io::Error::new(e.kind(), format!("read {url}: {e}"))),
        };
        total += n as u64;
        progress.advance(n as u64);
        if total > MAX_FILE {
            break Err(io::Error::other(format!(
                "{url}: exceeds the {} MiB cap for a tog release; refusing",
                MAX_FILE >> 20
            )));
        }
        hasher.update(&buf[..n]);
        if let Err(e) = file.write_all(&buf[..n]) {
            break Err(e);
        }
    };
    drop(progress);
    let outcome = streamed.and_then(|_| file.flush()).and_then(|_| {
        let got = hex::encode(hasher.finalize());
        if got == digest.hex() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "hash mismatch for {url}\n  expected sha256 {}\n  got      {got}",
                    digest.hex()
                ),
            ))
        }
    });
    drop(file);
    if outcome.is_err() {
        let _ = fs::remove_file(dest);
    }
    outcome
}

/// Sha256-hex convenience for callers outside the store. Internal extraction
/// paths use `download_verified_held` so their lease lasts through
/// consumption.
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
/// by tog — e.g. Go module zips h1-checked by dirhash). Returns
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

    let (mut reader, declared) = open_url(url, "download", None)?;
    // A first sync moves hundreds of MB. Narrate it, so the wait has a
    // visible cause. Inert off a terminal and under --quiet, and erased
    // when the download ends.
    let mut progress = crate::kernel::ui::Progress::start(artifact_name(url), declared);

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
        progress.advance(n as u64);
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
    drop(progress);
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

    /// The five user-facing network texts, and the one word a person
    /// stranded on a plane looks for.
    #[test]
    fn network_failures_say_what_went_wrong_not_what_ureq_saw() {
        let offline = transport_cause_with(
            ureq::ErrorKind::ConnectionFailed,
            "Network is unreachable (os error 101)",
        )
        .unwrap();
        assert!(offline.contains("offline"), "{offline}");
        assert!(offline.contains("os error 101"), "{offline}");
        let dns = transport_cause(ureq::ErrorKind::Dns).unwrap();
        assert!(
            dns.contains("did not resolve") && dns.contains("offline"),
            "{dns}"
        );
        let https = transport_cause(ureq::ErrorKind::InsecureRequestHttpsOnly).unwrap();
        assert!(https.contains("https only"), "{https}");
        let proxy = transport_cause(ureq::ErrorKind::ProxyUnauthorized).unwrap();
        assert!(proxy.contains("proxy"), "{proxy}");
        // A reply tog cannot read stays the library's own words.
        assert!(transport_cause(ureq::ErrorKind::BadHeader).is_none());

        assert!(status_cause(403).contains("credentials"));
        assert!(status_cause(404).contains("yanked"));
        assert!(status_cause(503).contains("registry's side"));
        assert_eq!(status_cause(418), "the server replied 418");
    }

    /// `ErrorKind::Io` is ureq's catch-all. A rejected certificate behind a
    /// corporate proxy is not "offline", and the reason it failed is the
    /// only thing that distinguishes it, so it must survive the wrapping.
    #[test]
    fn a_tls_failure_is_not_reported_as_being_offline() {
        let tls = transport_cause_with(
            ureq::ErrorKind::Io,
            "invalid peer certificate: UnknownIssuer",
        )
        .unwrap();
        assert!(!tls.contains("offline"), "{tls}");
        assert!(tls.starts_with("the connection failed"), "{tls}");
        assert!(tls.contains("UnknownIssuer"), "cause was dropped: {tls}");

        let reset = transport_cause_with(ureq::ErrorKind::Io, "Connection reset by peer").unwrap();
        assert!(!reset.contains("offline"), "{reset}");
        assert!(reset.contains("Connection reset by peer"), "{reset}");

        // The genuinely-offline errnos still say so.
        for source in [
            "Network is unreachable (os error 101)",
            "No route to host (os error 113)",
            "failed to lookup address information",
        ] {
            let message = transport_cause_with(ureq::ErrorKind::Io, source).unwrap();
            assert!(message.contains("offline"), "{source}: {message}");
        }
        assert!(looks_offline("Network is unreachable"));
        assert!(!looks_offline("invalid peer certificate"));
    }

    /// ureq renders `{url}: {kind}: {message}: {source}`. tog names the URL
    /// and translates the kind, so both come off; the remainder is kept
    /// whole, because it is often itself colon-separated and the tail alone
    /// ("UnknownIssuer") does not say what failed.
    #[test]
    fn a_transport_source_keeps_everything_past_the_kind() {
        assert_eq!(
            source_after_kind(
                "https://files.pythonhosted.org/a.whl: Network Error: \
                 invalid peer certificate: UnknownIssuer",
                "Network Error",
            ),
            "invalid peer certificate: UnknownIssuer"
        );
        assert_eq!(
            source_after_kind(
                "https://example.com/a.whl: Dns Failed: failed to lookup address information",
                "Dns Failed",
            ),
            "failed to lookup address information"
        );
        // No message and no source: the url and the kind are all there is,
        // and tog already says both in its own words.
        assert_eq!(
            source_after_kind(
                "https://example.com/a.whl: Connection Failed",
                "Connection Failed"
            ),
            ""
        );
        // That empty source must not produce a dangling "()".
        let bare = transport_cause_with(ureq::ErrorKind::ConnectionFailed, "").unwrap();
        assert!(!bare.contains('('), "{bare}");

        // The whole chain, as the user sees it.
        let full = source_after_kind(
            "https://files.pythonhosted.org/a.whl: Network Error: \
             invalid peer certificate: UnknownIssuer",
            "Network Error",
        );
        let message = transport_cause_with(ureq::ErrorKind::Io, &full).unwrap();
        assert_eq!(
            message,
            "the connection failed (invalid peer certificate: UnknownIssuer)"
        );
    }

    #[test]
    fn artifact_names_come_from_the_last_url_segment() {
        assert_eq!(
            artifact_name("https://files.pythonhosted.org/ab/cd/flask-3.0.0.whl"),
            "flask-3.0.0.whl"
        );
        assert_eq!(
            artifact_name("https://example.com/a.tar.gz?token=x"),
            "a.tar.gz"
        );
        // No path segment: the host is the registry, not the artifact, so
        // labelling the progress line with it would be misleading.
        assert_eq!(artifact_name("https://example.com/"), "download");
        assert_eq!(artifact_name("https://example.com"), "download");
        assert_eq!(artifact_name("file:///tmp/cache/x.whl"), "x.whl");
    }

    #[test]
    fn sha1_integrity_accepts_and_rejects_at_verification() {
        let root = std::env::temp_dir().join(format!(
            "tog-fetch-test-{}-{}",
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
            "tog-fetch-lease-test-{}-{}",
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

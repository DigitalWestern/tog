//! Verified downloads into the store (kernel layer): fetch a URL, check
//! its digest, and hold the bytes as a store object. A toolchain artifact
//! row also passes the source policy, on its URL and on every redirect
//! (`download_toolchain_artifact_held`).

use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Algo;
pub use crate::kernel::digest::Digest;
use crate::kernel::error;
use crate::kernel::store::{self, Store};
use crate::kernel::toolchain::SourcePolicy;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::{ffi::OsStr, ops::Deref};

pub mod pinned;

/// A verified cache path with the GC lock held shared until the caller
/// drops it.
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

fn acquire_cache_lock(store: &Store) -> io::Result<Arc<fs::File>> {
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
    let candidate = Arc::new(store.cache_lock()?);
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
pub(crate) fn cache_verified_held(
    store: &Store,
    activity: &StoreActivity,
    sha256: &str,
) -> io::Result<CacheLease> {
    let digest = Digest::sha256(sha256)?;
    cache_verified_digest_held(store, activity, &digest).map_err(|error| {
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

pub(crate) fn cache_verified_digest_held(
    store: &Store,
    activity: &StoreActivity,
    digest: &Digest,
) -> io::Result<CacheLease> {
    store.require_activity(activity, "a cache read")?;
    let activity = activity.clone();
    let gc_lock = acquire_cache_lock(store)?;
    let path = store.cache_path(digest.algo(), digest.hex());
    match hash_identified(&path, digest.algo) {
        Ok((h, _)) if h == digest.hex() => {
            store::touch_path(&path)?;
            Ok(CacheLease {
                path,
                _activity: activity,
                _gc_lock: gc_lock,
            })
        }
        Ok((_, seen)) => {
            remove_poisoned(store, &path, &seen);
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
pub(crate) fn read_cache_verified_digest(
    store: &Store,
    activity: &StoreActivity,
    digest: &Digest,
) -> io::Result<Vec<u8>> {
    let lease = cache_verified_digest_held(store, activity, digest)?;
    fs::read(&lease.path)
}

/// The hex digest of a file under `algo`. This is the same read every
/// verification on a cache hit performs, exposed so a caller that holds a
/// lease across a long phase can re-verify the bytes immediately before it
/// uses them: the lease stops a sweep, not a same-user replacement.
pub(crate) fn hash_file(path: &std::path::Path, algo: Algo) -> io::Result<String> {
    crate::kernel::digest::hash_reader(&mut fs::File::open(path)?, algo)
}

/// `path`'s digest and the file that was hashed, so a mismatch can be
/// removed with [`remove_poisoned`] without touching a replacement.
fn hash_identified(path: &Path, algo: Algo) -> io::Result<(String, fs::Metadata)> {
    let mut f = fs::File::open(path)?;
    let seen = f.metadata()?;
    Ok((crate::kernel::digest::hash_reader(&mut f, algo)?, seen))
}

/// The name a cache entry that failed verification is moved aside under,
/// in the store's `tmp/`. GC sweeps a crash leftover of it like any other
/// temporary (`gc::read::TMP_LEFTOVERS`), so a tog killed between the move
/// and the delete never leaves a name the cache directory refuses.
pub(crate) const POISONED_PREFIX: &str = "poisoned-";

/// Remove the cache entry at `path` that failed verification, but only if
/// it is still the file that was hashed (`seen`). Cache leases share
/// `gc.lock`, so another process may have published good bytes there since:
/// those are kept for the lease that holds them. A check and then an
/// unlink would leave a window in which such a publish is deleted, so the
/// entry is first renamed aside into `tmp/` in one step, and only what was
/// moved is judged: the poisoned file is deleted, good bytes are put back
/// (unless another verified copy, the same bytes, has landed since). In
/// that short window the entry is absent: a download fetches it again,
/// and a lease or a cache-only read fails as it would on an entry GC had
/// swept. Any entry that is still wrong is replaced by the next download's
/// rename either way.
fn remove_poisoned(store: &Store, path: &Path, seen: &fs::Metadata) {
    use std::os::unix::fs::MetadataExt;
    let Some(aside) = move_poisoned_aside(store, path) else {
        return;
    };
    let moved = fs::symlink_metadata(aside.tmp_path.join(&aside.name));
    if moved.is_ok_and(|now| now.dev() == seen.dev() && now.ino() == seen.ino()) {
        let _ = fs::remove_file(aside.tmp_path.join(&aside.name));
        return;
    }
    put_back(&aside);
}

/// A cache entry renamed from `dir`/`entry` to `tmp`/`name`.
struct Aside {
    tmp: fs::File,
    tmp_path: PathBuf,
    name: std::ffi::OsString,
    dir: fs::File,
    entry: std::ffi::OsString,
}

/// Rename the entry at `path` into `tmp/` under [`POISONED_PREFIX`]. None
/// when either directory cannot be opened or the rename fails (the entry
/// is gone already, or was never there).
fn move_poisoned_aside(store: &Store, path: &Path) -> Option<Aside> {
    let (dir_path, entry) = (path.parent()?, path.file_name()?);
    let tmp_path = store.root.join("tmp");
    let dir = fs::File::open(dir_path).ok()?;
    let tmp = fs::File::open(&tmp_path).ok()?;
    let name = format!(
        "{POISONED_PREFIX}{}",
        crate::kernel::fsroot::random_suffix().ok()?
    );
    fs::rename(path, tmp_path.join(&name)).ok()?;
    Some(Aside {
        tmp,
        tmp_path,
        name: name.into(),
        dir,
        entry: entry.to_os_string(),
    })
}

/// Put a moved entry that turned out to be good bytes back at its name,
/// unless something has been published there since: that copy, verified by
/// whoever wrote it, wins, and the moved one is deleted. Nothing is left in
/// `tmp/` either way.
fn put_back(aside: &Aside) {
    use std::os::unix::io::AsRawFd;
    let restored = crate::kernel::fsroot::rename_between_noreplace(
        aside.tmp.as_raw_fd(),
        aside.name.as_encoded_bytes(),
        aside.dir.as_raw_fd(),
        aside.entry.as_encoded_bytes(),
    );
    if restored.is_err() {
        let _ = fs::remove_file(aside.tmp_path.join(&aside.name));
    }
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
            // ureq's own Display leads with the URL, which `shown_url`
            // keeps out of messages: name the kind and the rest instead.
            transport_cause_with(transport.kind(), &source).unwrap_or_else(|| {
                if source.is_empty() {
                    transport.kind().to_string()
                } else {
                    format!("{}: {source}", transport.kind())
                }
            })
        }
    }
}

///
/// A transport failure (offline, DNS, a refused or reset connection, a
/// timeout) is the `Network` failure class, exit 6: running it again may
/// work. A status keeps its code for [`http_status`], and only a status a
/// retry can change (408, 429, 5xx) is `Network`, by [`retry_may_help`].
fn network_error(verb: &str, url: &str, error: ureq::Error) -> io::Error {
    let message = format!("{verb} {}: {}", shown_url(url), network_cause(&error));
    match error {
        ureq::Error::Status(code, _) => io::Error::other(StatusFailure { code, message }),
        ureq::Error::Transport(transport) if retryable_transport(transport.kind()) => {
            error::new(error::Class::Network, io::ErrorKind::Other, message)
        }
        // Invalid URLs, schemes, proxy credentials, HTTPS-only refusals,
        // redirect loops and malformed responses need an input or server fix.
        ureq::Error::Transport(_) => io::Error::other(message),
    }
}

fn retryable_transport(kind: ureq::ErrorKind) -> bool {
    matches!(
        kind,
        ureq::ErrorKind::Dns
            | ureq::ErrorKind::ConnectionFailed
            | ureq::ErrorKind::Io
            | ureq::ErrorKind::ProxyConnect
    )
}

/// A response body that broke off while it was read: a `Network` failure,
/// since a retry may finish it. A local file's read error (a `file://`
/// URL) is an ordinary one.
fn read_failure(url: &str, e: io::Error) -> io::Error {
    let message = format!("read {}: {e}", shown_url(url));
    if url.starts_with("file:") {
        io::Error::new(e.kind(), message)
    } else {
        error::new(error::Class::Network, e.kind(), message)
    }
}

/// Whether `error` is a server status a later retry can change: a timeout
/// (408), a rate limit (429), or a server error (5xx). A 404 or a 403 is
/// an answer and stays an ordinary failure.
pub(crate) fn retry_may_help(error: &io::Error) -> bool {
    http_status(error).is_some_and(|code| code == 408 || code == 429 || code >= 500)
}

/// A request the server answered with an error status. It prints as the
/// same sentence as every other network failure and keeps the status code,
/// so the one caller for whom a 404 means something else (the release
/// lookup: no release is there) can ask with [`http_status`].
#[derive(Debug)]
struct StatusFailure {
    code: u16,
    message: String,
}

impl std::fmt::Display for StatusFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StatusFailure {}

/// A fetch error for `code`, as a real request would return it.
#[cfg(test)]
pub(crate) fn status_failure(code: u16) -> io::Error {
    let response = ureq::Response::new(code, "status", "").unwrap();
    network_error(
        "fetch",
        "https://example.invalid/x",
        ureq::Error::Status(code, response),
    )
}

/// The HTTP status behind a fetch error, when the server answered with one.
pub fn http_status(error: &io::Error) -> Option<u16> {
    error
        .get_ref()?
        .downcast_ref::<StatusFailure>()
        .map(|failure| failure.code)
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

/// What tog calls itself in a request, for the registries that ask callers
/// to identify themselves (crates.io refuses an anonymous client).
const USER_AGENT: &str = "tog (https://github.com/DigitalWestern/tog)";

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
    let mut builder = ureq::AgentBuilder::new()
        .https_only(true)
        .user_agent(USER_AGENT);
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
    // Room for a registry's full package document (npm, PyPI), which ureq's
    // own reader capped at 10 MiB before every request came through here.
    const MAX_TEXT: u64 = 32 << 20;
    let (reader, _) = open_url(url, "fetch", timeout)?;
    read_text_capped(reader, MAX_TEXT, url)
}

/// Read a whole text body of at most `max` bytes. A longer body is an error
/// that says so, never a cut-off text that fails later as "not JSON".
fn read_text_capped(reader: impl Read, max: u64, url: &str) -> io::Result<String> {
    let mut body = Vec::new();
    reader
        .take(max + 1)
        .read_to_end(&mut body)
        .map_err(|e| read_failure(url, e))?;
    if body.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "read {}: the response is larger than {max} bytes",
                shown_url(url)
            ),
        ));
    }
    String::from_utf8(body).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read {}: not UTF-8: {e}", shown_url(url)),
        )
    })
}

/// Fetch a small text file that may not be there: `None` when the server
/// answers 404 (a registry asked about a name it has never heard of), the
/// text otherwise. Every other failure is an error, as from [`fetch_text`].
pub(crate) fn fetch_text_or_missing(
    url: &str,
    timeout: Option<std::time::Duration>,
) -> io::Result<Option<String>> {
    none_when_missing(fetch_text_within(url, timeout))
}

/// A fetched text, `None` when the failure was a 404.
fn none_when_missing(fetched: io::Result<String>) -> io::Result<Option<String>> {
    match fetched {
        Ok(text) => Ok(Some(text)),
        Err(error) if http_status(&error) == Some(404) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Download `url` to `dest` with no hash to check it against, for a file a
/// later step verifies some other way (a NuGet package, whose content hash
/// the locked restore checks). Capped at `max` bytes: a longer stream
/// refuses and removes `dest` rather than keep a truncated file.
pub(crate) fn download_unpinned(url: &str, dest: &Path, max: u64) -> io::Result<()> {
    let (reader, _) = open_url(url, "download", None)?;
    copy_unpinned(url, dest, max, reader)
}

/// The copy `download_unpinned` makes once `url` is open: at most `max`
/// bytes of `reader` into `dest`, which is removed on a longer stream or a
/// read error. Every message names `url` as `shown_url` shows it.
fn copy_unpinned(url: &str, dest: &Path, max: u64, reader: Box<dyn Read>) -> io::Result<()> {
    let mut file = fs::File::create(dest)?;
    let copied = io::copy(&mut reader.take(max + 1), &mut file);
    drop(file);
    let refusal = match copied {
        Ok(copied) if copied <= max => return Ok(()),
        Ok(_) => io::Error::other(format!(
            "download {}: longer than {max} bytes; refusing",
            shown_url(url)
        )),
        Err(e) => read_failure(url, e),
    };
    let _ = fs::remove_file(dest);
    Err(refusal)
}

/// `url` parsed the way the fetcher parses it (ureq, through the `url`
/// crate), so a check made on a URL and the download of it read one URL.
/// `None` when the fetcher could not request it at all.
pub(crate) fn request_url(url: &str) -> Option<url::Url> {
    ureq::get(url)
        .request_url()
        .ok()
        .map(|parsed| parsed.as_url().clone())
}

/// Download `url` to `dest`, verifying its sha256 as it streams, without
/// the store: for the one artifact that is not a store object, tog's own
/// release binary. `dest` is written whole or not at all (a mismatch or a
/// short read removes it), and the stream is capped so a hostile server
/// cannot fill the disk before the hash check fails.
pub fn download_file(url: &str, dest: &Path, sha256: &str) -> io::Result<()> {
    let digest = Digest::sha256(sha256)?;
    let (reader, declared) = open_url(url, "download", None)?;
    stream_to_file(url, dest, &digest, reader, declared, MAX_RELEASE_FILE)
}

/// The most `download_file` streams: tog's release binary is far smaller.
const MAX_RELEASE_FILE: u64 = 256 << 20;

/// The most one verified download streams into the cache. 8 GiB covers
/// every real artifact class tog handles.
const MAX_ARTIFACT: u64 = 8 << 30;

/// A stream cap as a refusal names it: whole GiB or MiB when it is one.
fn cap_text(max: u64) -> String {
    if max >= 1 << 30 && max.is_multiple_of(1 << 30) {
        format!("{} GiB", max >> 30)
    } else if max >= 1 << 20 && max.is_multiple_of(1 << 20) {
        format!("{} MiB", max >> 20)
    } else {
        format!("{max}-byte")
    }
}

/// `download_file` past opening the URL, with the cap a parameter so a
/// test can reach it.
fn stream_to_file(
    url: &str,
    dest: &Path,
    digest: &Digest,
    mut reader: Box<dyn Read>,
    declared: Option<u64>,
    max: u64,
) -> io::Result<()> {
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
            Err(e) => break Err(read_failure(url, e)),
        };
        total += n as u64;
        progress.advance(n as u64);
        if total > max {
            break Err(io::Error::other(format!(
                "{}: exceeds the {} cap for a tog release; refusing",
                shown_url(url),
                cap_text(max)
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
                    "hash mismatch for {}\n  expected sha256 {}\n  got      {got}",
                    shown_url(url),
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

pub(crate) fn download_verified_held(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    sha256: &str,
) -> io::Result<CacheLease> {
    download_verified_digest_held(store, activity, url, &Digest::sha256(sha256)?)
}

/// Insert a local file into the verified artifact cache by its computed
/// sha256 (for artifacts obtained through delegated tools and then verified
/// by tog — e.g. Go module zips h1-checked by dirhash). Returns
/// (sha256 hex, cache path). Publication mirrors download_verified_held.
pub fn cache_insert(
    store: &Store,
    activity: &StoreActivity,
    src: &std::path::Path,
) -> io::Result<(String, PathBuf)> {
    store.require_activity(activity, "a cache insert")?;
    let hex = hash_file(src, Algo::Sha256)?;
    let _gc_lock = acquire_cache_lock(store)?;
    let dest = store.cache_path("sha256", &hex);
    if dest.is_file() {
        // Re-verify on hit, like a download: a same-user replacement
        // must never ride an old address (poisoned -> drop and re-insert).
        match hash_identified(&dest, Algo::Sha256) {
            Ok((h, _)) if h == hex => {
                store::touch_path(&dest)?;
                return Ok((hex, dest));
            }
            Ok((_, seen)) => remove_poisoned(store, &dest, &seen),
            Err(_) => {}
        }
    }
    fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = store.root.join("tmp").join(format!(
        "ins-{}-{hex}",
        crate::kernel::fsroot::random_suffix()?
    ));
    // create_new: the name is random, and a file already there (a planted
    // entry, or a symlink) is refused rather than written through.
    let mut out = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&tmp)
            .map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", tmp.display())))?
    };
    // The create mode is masked by the umask; set it outright, as a
    // verified download's `publish_read_only` does, so both agree.
    let copied_read_only = |out: &fs::File| {
        use std::os::unix::fs::PermissionsExt;
        out.set_permissions(fs::Permissions::from_mode(0o444))
    };
    let copied = copy_and_rehash(src, &mut out)
        .and_then(|h| {
            if h == hex {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "cache insert {}: the file changed while it was copied",
                        src.display()
                    ),
                ))
            }
        })
        .and_then(|()| copied_read_only(&out));
    drop(out);
    if let Err(e) = copied {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    match fs::rename(&tmp, &dest) {
        Ok(()) => {}
        Err(_) if dest.is_file() => {
            let _ = fs::remove_file(&tmp);
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(io::Error::new(e.kind(), format!("cache insert {hex}: {e}")));
        }
    }
    store::touch_path(&dest)?;
    Ok((hex, dest))
}

/// Copy `src` into `out`, then hash what `out` now holds: the bytes that
/// will be published, which is what the cache address has to name.
fn copy_and_rehash(src: &Path, out: &mut fs::File) -> io::Result<String> {
    use std::io::Seek;
    io::copy(&mut fs::File::open(src)?, out)?;
    out.rewind()?;
    crate::kernel::digest::hash_reader(out, Algo::Sha256)
}

/// Download `url`, verify its digest, and place it in the store's artifact
/// cache (keyed by algo/hex). Idempotent; an existing entry short-circuits
/// (offline reconstruction). file:// URLs read local files (mirrors, tests).
pub fn download_verified_digest(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    digest: &Digest,
) -> io::Result<PathBuf> {
    download_verified_digest_held(store, activity, url, digest).map(CacheLease::into_path)
}

/// The same, holding a lease on the cache entry.
///
/// A cache hit is admitted by digest alone, whichever ecosystem or code
/// path wrote the entry (#476). That is sound because a digest names one
/// byte string: a hit yields exactly the bytes a download would have had
/// to match, so the cache grants nothing the digest's source did not
/// already grant. The trust decision is therefore the caller's, in where
/// its digest comes from: a toolchain row (tog's catalog or the project's
/// toolchain lock), a table compiled into tog, the publisher's listing read
/// over TLS, or the project's own pin (its committed lock or a declared
/// artifact), or the registry's claim for an artifact read through the
/// resolution proxy (`resolve::mirror`). The same rule covers the
/// cache-only reads (`cache_verified_held`, `cache_verified_digest_held`,
/// `read_cache_verified_digest`) and the proxy's `cache_from_reader_any`. Every
/// caller is listed under its source in `tests/architecture.rs`
/// (`DIGEST_SOURCES`), and a new one fails there until it is; the count is
/// per function, so a call replaced within a listed function is not seen.
pub(crate) fn download_verified_digest_held(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    digest: &Digest,
) -> io::Result<CacheLease> {
    cache_or_download(store, activity, url, digest, || {
        open_url(url, "download", None)
    })
}

/// The same for a digest list that allows several hashes (an SRI list with
/// more than one entry of its strongest algorithm, see
/// [`crate::kernel::digest::sri_candidates`]): the bytes are admitted when
/// they match any candidate, and the one they matched comes back, since
/// that is the cache entry the lease holds. Every candidate must share one
/// algorithm. The digest sources are the same as the single form's.
pub(crate) fn download_verified_any_held(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    candidates: &[Digest],
) -> io::Result<(CacheLease, Digest)> {
    cache_or_download_narrated(store, activity, url, candidates, true, MAX_ARTIFACT, || {
        open_url(url, "download", None)
    })
}

/// Download one toolchain artifact row: the bytes a catalog or lock row
/// names by `url` and `digest`, published by the row's `provider`. The
/// effective [`SourcePolicy`] must authorize `url` for `publisher` before
/// anything else happens, cache hit or not, so a row the policy refuses is
/// refused the same way online and offline. A network fetch then follows
/// redirects itself and authorizes every `Location` before requesting it.
/// No credential is sent: none is shipped, and sending one is not built yet
/// (policy decided in #72, work in #404).
pub(crate) fn download_toolchain_artifact_held(
    store: &Store,
    activity: &StoreActivity,
    publisher: &str,
    url: &str,
    digest: &Digest,
) -> io::Result<CacheLease> {
    download_toolchain_artifact_under(
        SourcePolicy::effective(),
        store,
        activity,
        publisher,
        url,
        digest,
    )
}

fn download_toolchain_artifact_under(
    policy: &SourcePolicy,
    store: &Store,
    activity: &StoreActivity,
    publisher: &str,
    url: &str,
    digest: &Digest,
) -> io::Result<CacheLease> {
    policy.authorize(publisher, url)?;
    cache_or_download(store, activity, url, digest, || {
        open_authorized(policy, publisher, url)
    })
}

/// `url` as an error message names it: scheme, host and path. A signed
/// CDN URL a redirect leads to carries its signature in the query string,
/// and a mirror URL may carry credentials before its host; neither belongs
/// in a message a user pastes into an issue (#348).
///
/// The credentials go first, on the raw string: a password may hold a `?`
/// or `#`, so cutting the query first would keep the part before it.
pub(crate) fn shown_url(url: &str) -> std::borrow::Cow<'_, str> {
    fn without_query(url: &str) -> &str {
        url.split(['?', '#']).next().unwrap_or(url)
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return without_query(url).into();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://{}", without_query(&rest[at + 1..])).into(),
        None => without_query(url).into(),
    }
}

/// The most redirects one toolchain download follows.
const MAX_REDIRECTS: usize = 10;

/// What one request answered: the body to stream, or where to go next.
enum Hop<B> {
    Body(B),
    Redirect(String),
}

/// Open a toolchain artifact over https, following redirects by hand so
/// that every hop is authorized for `publisher` before it is requested.
pub(crate) fn open_authorized(
    policy: &SourcePolicy,
    publisher: &str,
    url: &str,
) -> io::Result<(Box<dyn Read>, Option<u64>)> {
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(0)
        .build();
    follow_redirects(
        url,
        |next| policy.authorize(publisher, next).map(drop),
        |hop| {
            // With redirects off, ureq hands a 3xx back as a response.
            let resp = agent
                .get(hop)
                .call()
                .map_err(|e| network_error("download", hop, e))?;
            // Spelled as a path call: the architecture scan reads a bare
            // `.status()` as a child process.
            let status = ureq::Response::status(&resp);
            if (300..400).contains(&status) {
                let location = resp.header("Location").ok_or_else(|| {
                    io::Error::other(format!(
                        "download {}: redirect {status} names no Location",
                        shown_url(hop)
                    ))
                })?;
                return Ok(Hop::Redirect(location.to_string()));
            }
            let declared = resp
                .header("Content-Length")
                .and_then(|value| value.trim().parse::<u64>().ok());
            Ok(Hop::Body((
                Box::new(resp.into_reader()) as Box<dyn Read>,
                declared,
            )))
        },
    )
}

/// Request `url`, and each redirect after it, through `request` until one
/// answers with a body. `authorize` runs on every URL before it is
/// requested; a relative `Location` resolves against the URL that sent it;
/// a hop off `https://` or past [`MAX_REDIRECTS`] refuses.
fn follow_redirects<B>(
    url: &str,
    authorize: impl Fn(&str) -> io::Result<()>,
    mut request: impl FnMut(&str) -> io::Result<Hop<B>>,
) -> io::Result<B> {
    let mut current = url.to_string();
    authorize(&current)?;
    let mut followed = 0;
    loop {
        let location = match request(&current)? {
            Hop::Body(body) => return Ok(body),
            Hop::Redirect(location) => location,
        };
        if followed == MAX_REDIRECTS {
            return Err(io::Error::other(format!(
                "download {}: more than {MAX_REDIRECTS} redirects; refusing",
                shown_url(url)
            )));
        }
        followed += 1;
        let next = resolve_location(&current, &location);
        if !next.starts_with("https://") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "download {}: {} redirects to {}, which is not https://; refusing",
                    shown_url(url),
                    shown_url(&current),
                    shown_url(&next)
                ),
            ));
        }
        authorize(&next)?;
        current = next;
    }
}

/// A redirect `Location` as an absolute URL, resolved against `base` the
/// way RFC 3986 section 5.2 does: an absolute URL stands as it is, and a
/// network-path, absolute-path, query-only or relative-path reference takes
/// what it lacks from `base`, with `.` and `..` segments applied.
fn resolve_location(base: &str, location: &str) -> String {
    let location = location.trim();
    let has_scheme = location.split_once(':').is_some_and(|(scheme, _)| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    if has_scheme {
        return location.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    if let Some(network) = location.strip_prefix("//") {
        return format!("{scheme}://{network}");
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let origin = format!("{scheme}://{}", &rest[..authority_end]);
    let base_path = rest[authority_end..].split(['?', '#']).next().unwrap_or("");
    let base_path = if base_path.is_empty() { "/" } else { base_path };
    if location.is_empty() || location.starts_with('#') {
        return base.split('#').next().unwrap_or(base).to_string();
    }
    if location.starts_with('?') {
        return format!("{origin}{base_path}{location}");
    }
    let (path, tail) = location.split_at(location.find(['?', '#']).unwrap_or(location.len()));
    let merged = if path.starts_with('/') {
        path.to_string()
    } else {
        let directory = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
        format!("{directory}{path}")
    };
    format!("{origin}{}{tail}", remove_dot_segments(&merged))
}

/// An absolute path with its `.` and `..` segments applied.
fn remove_dot_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let mut out: Vec<&str> = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        match *segment {
            "." => {}
            ".." => {
                out.pop();
            }
            other => {
                out.push(other);
                continue;
            }
        }
        // A trailing `.` or `..` names a directory: keep its slash.
        if index + 1 == segments.len() {
            out.push("");
        }
    }
    format!("/{}", out.join("/"))
}

/// Downloaded bytes that did not hash to the digest naming them. It rides
/// inside the `InvalidData` error a verified download returns, so a caller
/// that must report both digests (the resolution proxy) can read them
/// without parsing the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    /// The URL as requested. The message names it through [`shown_url`].
    pub url: String,
    pub expected: Digest,
    /// The other digests the bytes were allowed to match, all of the
    /// expected one's algorithm: an SRI list may name several.
    pub alternatives: Vec<Digest>,
    /// The hex digest of the bytes received, under the expected algorithm.
    pub got: String,
}

impl std::fmt::Display for HashMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "hash mismatch for {}\n  expected {} {}",
            shown_url(&self.url),
            self.expected.algo(),
            self.expected.hex()
        )?;
        for alternative in &self.alternatives {
            write!(
                f,
                "\n  or       {} {}",
                alternative.algo(),
                alternative.hex()
            )?;
        }
        write!(f, "\n  got      {}", self.got)
    }
}

impl std::error::Error for HashMismatch {}

impl HashMismatch {
    /// The mismatch inside `error`, if that is what it is.
    pub fn of(error: &io::Error) -> Option<&HashMismatch> {
        error.get_ref()?.downcast_ref::<HashMismatch>()
    }
}

/// Stream `reader` into the verified artifact cache under whichever of
/// `candidates` (one or more digests of one algorithm) it matches, with no
/// progress narration: the resolution proxy's upstream fetches run while a
/// tool owns the terminal. A cache hit is served without reading `reader`.
/// The digest the bytes matched comes back with the lease. A mismatch is
/// an `InvalidData` error carrying [`HashMismatch`] and leaves nothing
/// behind.
pub(crate) fn cache_from_reader_any(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    candidates: &[Digest],
    open: impl FnOnce() -> io::Result<Box<dyn Read>>,
) -> io::Result<(CacheLease, Digest)> {
    cache_from_reader_within(store, activity, url, candidates, MAX_ARTIFACT, open)
}

/// `cache_from_reader_any` with its stream cap as a parameter, so a test
/// can feed the proxy's path a stream past a cap without several GiB.
fn cache_from_reader_within(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    candidates: &[Digest],
    max: u64,
    open: impl FnOnce() -> io::Result<Box<dyn Read>>,
) -> io::Result<(CacheLease, Digest)> {
    cache_or_download_narrated(store, activity, url, candidates, false, max, || {
        open().map(|reader| (reader, None))
    })
}

/// A verified cache entry for `digest`, fetched through `open` only when
/// the cache does not already hold good bytes.
fn cache_or_download(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    digest: &Digest,
    open: impl FnOnce() -> io::Result<(Box<dyn Read>, Option<u64>)>,
) -> io::Result<CacheLease> {
    let digests = std::slice::from_ref(digest);
    cache_or_download_narrated(store, activity, url, digests, true, MAX_ARTIFACT, open)
        .map(|(lease, _)| lease)
}

fn cache_or_download_narrated(
    store: &Store,
    activity: &StoreActivity,
    url: &str,
    candidates: &[Digest],
    narrate: bool,
    max: u64,
    open: impl FnOnce() -> io::Result<(Box<dyn Read>, Option<u64>)>,
) -> io::Result<(CacheLease, Digest)> {
    store.require_activity(activity, "a verified download")?;
    let digest = match candidates {
        [first, rest @ ..] if rest.iter().all(|other| other.algo == first.algo) => first,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{}: a verified download needs one or more digests of one algorithm",
                    shown_url(url)
                ),
            ))
        }
    };
    let activity = activity.clone();
    let gc_lock = acquire_cache_lock(store)?;
    for candidate in candidates {
        let dest = store.cache_path(candidate.algo(), candidate.hex());
        if !dest.is_file() {
            continue;
        }
        // Re-verify on every hit: read-only bits stop accidents, not disk
        // corruption or same-user replacement. A concurrent publisher can
        // replace/briefly unlink the entry, so a read race falls through
        // to a fresh download instead of failing.
        match hash_identified(&dest, candidate.algo) {
            Ok((h, _)) if h == candidate.hex() => {
                store::touch_path(&dest)?;
                let lease = CacheLease {
                    path: dest,
                    _activity: activity.clone(),
                    _gc_lock: gc_lock,
                };
                return Ok((lease, candidate.clone()));
            }
            Ok((_, seen)) => remove_poisoned(store, &dest, &seen), // corrupt: refetch
            Err(_) => {}
        }
    }
    let cache_dir = store.cache_path(digest.algo(), digest.hex());
    fs::create_dir_all(cache_dir.parent().unwrap())
        .map_err(|e| io::Error::new(e.kind(), format!("cache dir: {e}")))?;
    // Unique per attempt: two concurrent downloads of the same artifact
    // (other processes, or threads of this one) must never share a tmp
    // file, or the stream hash would verify while the file holds
    // interleaved garbage. The random suffix is fsroot's, so no pid or
    // clock tie can repeat it.
    let tmp = store.root.join("tmp").join(format!(
        "dl-{}-{}",
        crate::kernel::fsroot::random_suffix()?,
        digest.hex()
    ));

    let (mut reader, declared) = open()?;
    // A first sync moves hundreds of MB. Narrate it, so the wait has a
    // visible cause. Inert off a terminal and under --quiet, and erased
    // when the download ends.
    let mut progress =
        narrate.then(|| crate::kernel::ui::Progress::start(artifact_name(url), declared));

    // Cap the stream (`max`, `MAX_ARTIFACT` outside tests) so a hostile
    // server can't fill the disk before the hash check fails.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
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
        if let Some(progress) = progress.as_mut() {
            progress.advance(n as u64);
        }
        if total > max {
            break Err(io::Error::other(format!(
                "{}: exceeds the {} artifact cap; refusing",
                shown_url(url),
                cap_text(max)
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
    let Some(matched) = candidates.iter().find(|candidate| candidate.hex() == got) else {
        let _ = fs::remove_file(&tmp);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            HashMismatch {
                url: url.to_string(),
                expected: digest.clone(),
                alternatives: candidates[1..].to_vec(),
                got,
            },
        ));
    };
    let dest = store.cache_path(matched.algo(), matched.hex());
    publish_read_only(&tmp, &dest)?;
    let lease = CacheLease {
        path: dest,
        _activity: activity,
        _gc_lock: gc_lock,
    };
    Ok((lease, matched.clone()))
}

/// Publish a verified download at `dest`, read-only and atomically. A
/// concurrent publisher that got there first wins; its bytes were verified
/// under the same digest.
fn publish_read_only(tmp: &Path, dest: &Path) -> io::Result<()> {
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(tmp)
            .map_err(|e| io::Error::new(e.kind(), format!("stat dl tmp: {e}")))?
            .permissions();
        perms.set_mode(0o444);
        fs::set_permissions(tmp, perms)
            .map_err(|e| io::Error::new(e.kind(), format!("chmod dl tmp: {e}")))?;
    }
    match fs::rename(tmp, dest) {
        Ok(()) => {}
        Err(_) if dest.is_file() => {
            let _ = fs::remove_file(tmp);
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("cache publish {}: {e}", dest.display()),
            ))
        }
    }
    store::touch_path(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::time::{Duration, SystemTime};

    /// A body at the cap is read whole; one byte more is refused by name,
    /// even when the cut would land inside a multi-byte character.
    #[test]
    fn text_over_the_cap_is_refused_not_cut_off() {
        let url = "https://example.invalid/doc";
        assert_eq!(read_text_capped(&b"abcd"[..], 4, url).unwrap(), "abcd");
        let long = read_text_capped(&b"abcde"[..], 4, url).unwrap_err();
        assert_eq!(long.kind(), io::ErrorKind::InvalidData);
        assert!(long.to_string().contains("larger than 4 bytes"), "{long}");
        let split = read_text_capped("abcdé".as_bytes(), 4, url).unwrap_err();
        assert!(split.to_string().contains("larger than 4 bytes"), "{split}");
    }

    /// A status failure keeps its code behind the same sentence; anything
    /// else has no status to report.
    #[test]
    fn a_status_failure_keeps_its_code() {
        let missing = status_failure(404);
        assert_eq!(http_status(&missing), Some(404));
        assert_eq!(
            missing.to_string(),
            format!("fetch https://example.invalid/x: {}", status_cause(404))
        );
        assert_eq!(http_status(&status_failure(503)), Some(503));
        assert_eq!(http_status(&io::Error::other("offline")), None);
        let absent = fs::File::open("/nonexistent/tog-fetch-test").unwrap_err();
        assert_eq!(http_status(&absent), None);
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
        let scratch = TempDir::named("fetch-test");
        let root = scratch.0.clone();
        for sub in ["objects", "meta", "cache/sha256", "cache/sha1", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.clone());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let input = root.join("artifact");
        fs::write(&input, b"hello").unwrap();
        let expected = Digest::from_sri("sha1-qvTGHdzF6KLavt4PO0gs2a6pQ00=").unwrap();
        let url = format!("file://{}", input.display());
        assert!(download_verified_digest(&store, activity, &url, &expected).is_ok());

        let wrong = Digest::from_sri("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        let error = download_verified_digest(&store, activity, &url, &wrong).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// An SRI list naming two sha512 hashes admits bytes matching either,
    /// whichever order the list gives them in, and hands back the one they
    /// matched; bytes matching only a weaker entry are refused (#508).
    #[test]
    fn a_download_matching_any_strongest_candidate_is_admitted() {
        let scratch = TempDir::named("fetch-any");
        for sub in ["objects", "meta", "cache/sha512", "tmp"] {
            fs::create_dir_all(scratch.0.join(sub)).unwrap();
        }
        let store = Store::for_test(scratch.0.clone());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let sri = |bytes: &[u8]| {
            format!(
                "sha512-{}",
                crate::kernel::base64::encode(&Sha512::digest(bytes))
            )
        };
        let input = scratch.0.join("artifact");
        fs::write(&input, b"hello").unwrap();
        let url = format!("file://{}", input.display());
        let (real, other) = (sri(b"hello"), sri(b"other"));
        let want = Digest::from_sri(&real).unwrap();
        for list in [format!("{real} {other}"), format!("{other} {real}")] {
            let candidates = crate::kernel::digest::sri_candidates(&list).unwrap();
            assert_eq!(candidates.len(), 2);
            let (lease, matched) =
                download_verified_any_held(&store, activity, &url, &candidates).unwrap();
            assert_eq!(matched, want);
            assert_eq!(fs::read(&*lease).unwrap(), b"hello");
        }
        // The sha1 entry matches these bytes, but sha512 is the strongest
        // algorithm the list names, so only its entries count.
        let only_weak = format!("{other} sha1-qvTGHdzF6KLavt4PO0gs2a6pQ00=");
        let candidates = crate::kernel::digest::sri_candidates(&only_weak).unwrap();
        let input = scratch.0.join("fresh");
        fs::write(&input, b"hello").unwrap();
        let fresh = format!("file://{}", input.display());
        let error = download_verified_any_held(&store, activity, &fresh, &candidates)
            .map(drop)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // And two candidates that both miss name both in the mismatch.
        let both =
            crate::kernel::digest::sri_candidates(&format!("{other} {}", sri(b"third"))).unwrap();
        let error = download_verified_any_held(&store, activity, &fresh, &both)
            .map(drop)
            .unwrap_err();
        let mismatch = HashMismatch::of(&error).unwrap();
        assert_eq!(mismatch.alternatives.len(), 1);
        assert!(error.to_string().contains("\n  or       sha512 "));
        // Candidates of two algorithms are a caller's mistake.
        let mixed = [want.clone(), Digest::sha1(&"a".repeat(40)).unwrap()];
        let error = download_verified_any_held(&store, activity, &fresh, &mixed)
            .map(drop)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn cache_lease_refreshes_mtime_and_blocks_gc() {
        let scratch = TempDir::named("fetch-lease-test");
        let root = scratch.0.clone();
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.clone());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
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
            activity,
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
            .truncate(false)
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
    }

    const UV_RELEASE: &str = "https://github.com/astral-sh/uv/releases/download/0.9.0/uv.tar.gz";

    /// Walk `follow_redirects` over a fake network where each URL in `hops`
    /// redirects to its `Location` and any other URL answers with a body.
    /// Returns the outcome and every URL actually requested.
    fn walk(
        start: &str,
        hops: &[(&str, &str)],
        authorize: impl Fn(&str) -> io::Result<()>,
    ) -> (io::Result<String>, Vec<String>) {
        let mut requested = Vec::new();
        let outcome = follow_redirects(start, authorize, |url| {
            requested.push(url.to_string());
            Ok(match hops.iter().find(|(from, _)| *from == url) {
                Some((_, location)) => Hop::Redirect(location.to_string()),
                None => Hop::Body(url.to_string()),
            })
        });
        (outcome, requested)
    }

    fn as_uv(policy: &SourcePolicy) -> impl Fn(&str) -> io::Result<()> + '_ {
        |url| policy.authorize("uv", url).map(drop)
    }

    #[test]
    fn a_redirect_chain_inside_the_publishers_endpoints_is_followed() {
        let policy = SourcePolicy::shipped();
        let cdn = "https://objects.githubusercontent.com/release/1";
        let assets = "https://release-assets.githubusercontent.com/release/2";
        let (outcome, requested) = walk(
            UV_RELEASE,
            &[(UV_RELEASE, cdn), (cdn, assets)],
            as_uv(&policy),
        );
        assert_eq!(outcome.unwrap(), assets);
        assert_eq!(requested, [UV_RELEASE, cdn, assets]);
    }

    #[test]
    fn a_hop_off_the_publishers_endpoints_is_refused_before_it_is_requested() {
        let policy = SourcePolicy::shipped();
        for off in [
            "https://evil.example/uv.tar.gz",
            // Another publisher's endpoint is still off this publisher's.
            "https://github.com/astral-sh/python-build-standalone/releases/download/x/y.tar.gz",
        ] {
            let (outcome, requested) = walk(UV_RELEASE, &[(UV_RELEASE, off)], as_uv(&policy));
            let error = outcome.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            assert!(error.to_string().contains(off), "{error}");
            assert!(error.to_string().contains("for uv"), "{error}");
            assert_eq!(requested, [UV_RELEASE], "{off} was requested");
        }
        // The first URL is checked too: nothing is requested at all.
        let (outcome, requested) = walk("file:///tmp/uv.tar.gz", &[], as_uv(&policy));
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(requested.is_empty());
    }

    #[test]
    fn a_redirect_off_https_is_refused_whatever_the_policy_admits() {
        let anything = |_: &str| Ok(());
        let plain = "http://objects.githubusercontent.com/release/1";
        let (outcome, requested) = walk(UV_RELEASE, &[(UV_RELEASE, plain)], anything);
        let error = outcome.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("not https://"), "{error}");
        assert_eq!(requested, [UV_RELEASE]);
    }

    #[test]
    fn relative_locations_resolve_against_the_url_that_sent_them() {
        let policy = SourcePolicy::shipped();
        let moved = "https://github.com/astral-sh/uv/releases/download/0.9.1/uv.tar.gz";
        let sibling = "https://github.com/astral-sh/uv/releases/download/0.9.2/uv.tar.gz";
        let cdn = "https://objects.githubusercontent.com/release/3";
        let (outcome, requested) = walk(
            UV_RELEASE,
            &[
                (
                    UV_RELEASE,
                    "/astral-sh/uv/releases/download/0.9.1/uv.tar.gz",
                ),
                (moved, "../0.9.2/./uv.tar.gz"),
                (sibling, "//objects.githubusercontent.com/release/3"),
            ],
            as_uv(&policy),
        );
        assert_eq!(outcome.unwrap(), cdn);
        assert_eq!(requested, [UV_RELEASE, moved, sibling, cdn]);
        // A relative reference that climbs out of the publisher's prefix
        // resolves first and is then refused like any other foreign URL.
        let (outcome, requested) = walk(
            UV_RELEASE,
            &[(UV_RELEASE, "../../../../other/releases/download/x")],
            as_uv(&policy),
        );
        let error = outcome.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("https://github.com/astral-sh/other/releases/download/x"),
            "{error}"
        );
        assert_eq!(requested, [UV_RELEASE]);
    }

    #[test]
    fn resolve_location_follows_rfc_3986_reference_forms() {
        let base = "https://h.example/a/b/c?q=1#f";
        for (location, want) in [
            ("https://o.example/x", "https://o.example/x"),
            ("//o.example/x", "https://o.example/x"),
            ("/x/y", "https://h.example/x/y"),
            ("d", "https://h.example/a/b/d"),
            ("./d?z", "https://h.example/a/b/d?z"),
            ("../d", "https://h.example/a/d"),
            ("../../../../d", "https://h.example/d"),
            ("..", "https://h.example/a/"),
            ("?z=2", "https://h.example/a/b/c?z=2"),
            ("#g", "https://h.example/a/b/c?q=1"),
            ("", "https://h.example/a/b/c?q=1"),
        ] {
            assert_eq!(resolve_location(base, location), want, "{location:?}");
        }
        assert_eq!(
            resolve_location("https://h.example", "d"),
            "https://h.example/d"
        );
    }

    #[test]
    fn shown_urls_keep_scheme_host_and_path_alone() {
        for (url, shown) in [
            (
                "https://cdn.example/a/b.tar.gz?X-Amz-Signature=secret&X-Amz-Credential=key",
                "https://cdn.example/a/b.tar.gz",
            ),
            ("https://cdn.example/a#frag", "https://cdn.example/a"),
            (
                "https://user:pass@mirror.example/x?y",
                "https://mirror.example/x",
            ),
            ("https://user:p?ss@host.example/x", "https://host.example/x"),
            (
                "https://user:p#ss@host.example/x?sig=s",
                "https://host.example/x",
            ),
            ("https://u:a@b@host.example/x", "https://host.example/x"),
            ("https://user:p?ss@host.example", "https://host.example"),
            ("https://mirror.example/a@b", "https://mirror.example/a@b"),
            ("https://mirror.example", "https://mirror.example"),
            ("not a url?q", "not a url"),
        ] {
            assert_eq!(shown_url(url), shown, "{url}");
        }
    }

    /// A transport failure tog has no sentence for (a malformed reply)
    /// falls back to ureq's kind and detail, still without the URL ureq's
    /// own text leads with (#348).
    #[test]
    fn an_unexplained_transport_failure_names_no_url() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = io::Read::read(&mut stream, &mut request);
            let _ = stream.write_all(b"not an http reply\r\n\r\n");
        });
        let url =
            format!("http://user:secret@127.0.0.1:{port}/signed/path?X-Amz-Signature=s1gn4ture");
        let error = ureq::AgentBuilder::new()
            .build()
            .get(&url)
            .call()
            .unwrap_err();
        server.join().unwrap();
        let ureq::Error::Transport(transport) = &error else {
            panic!("not a transport failure: {error}");
        };
        assert!(
            transport.to_string().contains("/signed/path"),
            "{transport}"
        );
        assert!(transport_cause_with(transport.kind(), "").is_none());
        let cause = network_cause(&error);
        assert!(cause.starts_with(&transport.kind().to_string()), "{cause}");
        for leak in [
            "127.0.0.1",
            "/signed/path",
            "secret",
            "X-Amz-Signature",
            "s1gn4ture",
        ] {
            assert!(!cause.contains(leak), "{leak}: {cause}");
        }
    }

    /// A refused redirect names where it went by host and path: a signed
    /// CDN URL's signature stays out of the message (#348).
    #[test]
    fn a_refused_redirect_does_not_print_the_signature() {
        let signed = "http://cdn.example/release/1?X-Amz-Signature=secret";
        let anything = |_: &str| Ok(());
        let (outcome, _) = walk(UV_RELEASE, &[(UV_RELEASE, signed)], anything);
        let message = outcome.unwrap_err().to_string();
        assert!(
            message.contains("http://cdn.example/release/1"),
            "{message}"
        );
        assert!(!message.contains("secret"), "{message}");
        // The policy refusal of an off-endpoint hop says the same.
        let policy = SourcePolicy::shipped();
        let off = "https://evil.example/uv.tar.gz?token=secret";
        let (outcome, _) = walk(UV_RELEASE, &[(UV_RELEASE, off)], as_uv(&policy));
        let message = outcome.unwrap_err().to_string();
        assert!(
            message.contains("https://evil.example/uv.tar.gz"),
            "{message}"
        );
        assert!(!message.contains("secret"), "{message}");
        // And so does a redirect chain that runs too long.
        let looping = "https://objects.githubusercontent.com/hop?sig=secret";
        let (outcome, _) = walk(looping, &[(looping, looping)], anything);
        let message = outcome.unwrap_err().to_string();
        assert!(message.contains("more than 10 redirects"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    #[test]
    fn at_most_ten_redirects_are_followed() {
        let urls: Vec<String> = (0..=11)
            .map(|n| format!("https://objects.githubusercontent.com/hop/{n}"))
            .collect();
        let chain = |length: usize| -> Vec<(&str, &str)> {
            (0..length)
                .map(|n| (urls[n].as_str(), urls[n + 1].as_str()))
                .collect()
        };
        let anything = |_: &str| Ok(());
        let (outcome, requested) = walk(&urls[0], &chain(10), anything);
        assert_eq!(outcome.unwrap(), urls[10]);
        assert_eq!(requested.len(), 11);
        let (outcome, requested) = walk(&urls[0], &chain(11), anything);
        let error = outcome.unwrap_err();
        assert!(
            error.to_string().contains("more than 10 redirects"),
            "{error}"
        );
        assert_eq!(requested.len(), 11, "the eleventh redirect was followed");
    }

    #[test]
    fn a_cache_insert_steps_around_planted_temporaries_and_leaves_none() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = TempDir::named("fetch-insert-test");
        let root = scratch.0.clone();
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.clone());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        // What a crashed run, or someone guessing at names, leaves behind.
        let planted = ["dl-0-planted", "ins-0-planted"].map(|n| root.join("tmp").join(n));
        for path in &planted {
            fs::write(path, b"planted").unwrap();
        }
        let input = root.join("artifact");
        fs::write(&input, b"module zip").unwrap();
        let (hex, dest) = cache_insert(&store, activity, &input).unwrap();
        assert_eq!(
            hex,
            crate::kernel::digest::hash_reader(&mut &b"module zip"[..], Algo::Sha256).unwrap()
        );
        assert_eq!(fs::read(&dest).unwrap(), b"module zip");
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o444
        );
        for path in &planted {
            assert_eq!(fs::read(path).unwrap(), b"planted", "{}", path.display());
        }
        let mut left: Vec<_> = fs::read_dir(root.join("tmp"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["dl-0-planted", "ins-0-planted"]);
        // A second insert of the same bytes is a verified hit.
        assert_eq!(cache_insert(&store, activity, &input).unwrap().1, dest);
    }

    /// A rename that fails leaves no temporary behind, like every other
    /// failure of an insert (#555).
    #[test]
    fn a_cache_insert_whose_rename_fails_leaves_no_temporary() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = TempDir::named("fetch-insert-rename");
        let root = scratch.0.clone();
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.clone());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let input = root.join("artifact");
        fs::write(&input, b"blocked").unwrap();
        let cache = root.join("cache/sha256");
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o555)).unwrap();
        let outcome = cache_insert(&store, activity, &input);
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(outcome.is_err());
        assert_eq!(fs::read_dir(root.join("tmp")).unwrap().count(), 0);
    }

    /// A 404 is a missing text, and every other failure an error (#555).
    #[test]
    fn a_404_is_a_missing_text_and_other_failures_are_errors() {
        let status = |code| {
            Err(io::Error::other(StatusFailure {
                code,
                message: format!("status {code}"),
            }))
        };
        assert_eq!(none_when_missing(status(404)).unwrap(), None);
        assert!(none_when_missing(status(500)).is_err());
        assert_eq!(
            none_when_missing(Ok("text".into())).unwrap().as_deref(),
            Some("text")
        );
        let scratch = TempDir::named("fetch-missing");
        let file = scratch.0.join("text");
        fs::write(&file, "body").unwrap();
        let url = format!("file://{}", file.display());
        assert_eq!(
            fetch_text_or_missing(&url, None).unwrap().as_deref(),
            Some("body")
        );
        // A file:// URL has no status: a missing file is an error.
        let gone = format!("file://{}", scratch.0.join("gone").display());
        assert!(fetch_text_or_missing(&gone, None).is_err());
    }

    /// An unpinned download past its cap refuses and leaves no `dest`;
    /// one at the cap is kept whole (#555).
    #[test]
    fn an_unpinned_download_past_its_cap_is_refused_and_removed() {
        let scratch = TempDir::named("fetch-unpinned");
        let source = scratch.0.join("source");
        fs::write(&source, [7u8; 64]).unwrap();
        let url = format!("file://{}", source.display());
        let dest = scratch.0.join("dest");
        let error = download_unpinned(&url, &dest, 63).unwrap_err();
        assert!(
            error.to_string().contains("longer than 63 bytes"),
            "{error}"
        );
        assert!(!dest.exists());
        download_unpinned(&url, &dest, 64).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), [7u8; 64]);
    }

    #[test]
    fn a_toolchain_row_the_policy_refuses_is_refused_even_when_cached() {
        let scratch = TempDir::named("fetch-policy-test");
        let root = scratch.0.clone();
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.clone());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let input = root.join("artifact");
        fs::write(&input, b"toolchain").unwrap();
        let (hex, _) = cache_insert(&store, activity, &input).unwrap();
        let digest = Digest::sha256(&hex).unwrap();
        let mut policy = SourcePolicy::empty();
        policy
            .allow(
                "test",
                crate::kernel::toolchain::Endpoint::new("https://127.0.0.1:9/").unwrap(),
            )
            .unwrap();
        // The generic path would serve this file:// URL; a toolchain row
        // may not name one, cache hit or not.
        let local = format!("file://{}", input.display());
        assert!(download_verified_digest_held(&store, activity, &local, &digest).is_ok());
        let error =
            download_toolchain_artifact_under(&policy, &store, activity, "test", &local, &digest)
                .err()
                .expect("a file:// toolchain row was served");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        // Another publisher's row is refused on the same cache hit.
        let admitted = "https://127.0.0.1:9/artifact.tar.gz";
        let error = download_toolchain_artifact_under(
            &policy, &store, activity, "other", admitted, &digest,
        )
        .err()
        .expect("an unknown publisher's row was served");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        // An admitted row is served from the cache without the network:
        // nothing answers at that address.
        download_toolchain_artifact_under(&policy, &store, activity, "test", admitted, &digest)
            .unwrap();
    }
}

/// Offline tests for the cache and download integrity checks (#348). The
/// download path takes its network opener as a callback, so every branch
/// runs here against a scratch store with `file://` sources and readers
/// that fail on purpose.
#[cfg(test)]
mod integrity_tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::testutil::TempDir;

    fn scratch_store(label: &str) -> (TempDir, Store) {
        let scratch = TempDir::named(label);
        let root = scratch.0.clone();
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        (scratch, Store::for_test(root))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Everything left in the store's tmp dir. The scratch store is this
    /// test's own, so anything at all is a leak, whatever it is called.
    fn leftover_downloads(store: &Store) -> Vec<String> {
        fs::read_dir(store.root.join("tmp"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// A stream that serves `head` and then fails, like a connection that
    /// drops mid-download.
    struct DroppedStream {
        head: &'static [u8],
        served: usize,
    }

    impl Read for DroppedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let rest = &self.head[self.served..];
            if rest.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.served += n;
            Ok(n)
        }
    }

    #[test]
    fn a_corrupted_cache_entry_is_refused_and_removed() {
        let (_scratch, store) = scratch_store("fetch-corrupt");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let cache = store.cache_path("sha256", &hex);
        fs::write(&cache, b"hellp").unwrap();
        let digest = Digest::sha256(&hex).unwrap();

        let error = cache_verified_digest_held(&store, activity, &digest)
            .map(drop)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!("cache entry sha256:{hex} was corrupted (removed)")
        );
        assert!(!cache.exists(), "the corrupted entry must be removed");

        // Through the sha256-hex wrapper the cause is kept.
        fs::write(&cache, b"hellp").unwrap();
        let error = cache_verified_held(&store, activity, &hex)
            .map(drop)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "cache entry {hex} was corrupted or unreadable: \
                 cache entry sha256:{hex} was corrupted (removed)"
            )
        );
        assert!(!cache.exists());
    }

    /// A held lease takes `gc.lock` shared. Another tog process (here, a
    /// second open of the lock, which flock treats the same way) gets its own
    /// lease at once and downloads beside it, while GC's exclusive lock
    /// still has to wait for both.
    #[test]
    fn a_cache_lease_admits_another_process_but_not_gc() {
        let (_scratch, store) = scratch_store("fetch-shared-lease");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        fs::write(store.cache_path("sha256", &hex), b"hello").unwrap();
        let lease = cache_verified_held(&store, activity, &hex).unwrap();

        let other = store.cache_lock().expect("a second lease must not wait");
        let gc = fs::File::open(store.root.join("gc.lock")).unwrap();
        assert!(
            matches!(gc.try_lock(), Err(fs::TryLockError::WouldBlock)),
            "GC took gc.lock while leases were held"
        );
        drop(other);
        assert!(
            matches!(gc.try_lock(), Err(fs::TryLockError::WouldBlock)),
            "GC took gc.lock while a lease was held"
        );
        drop(lease);
        // A child another test forks in this process holds a copy of every
        // open descriptor until it execs, and with it the flock, so the
        // released lock can stay held for a moment. Retry briefly.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while let Err(error) = gc.try_lock() {
            assert!(
                std::time::Instant::now() < deadline,
                "GC must get gc.lock once every lease is gone: {error:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// A poisoned entry another process replaced with good bytes after it
    /// was hashed is not removed from under that process's lease.
    #[test]
    fn a_poisoned_entry_replaced_since_it_was_hashed_is_left_in_place() {
        let (_scratch, store) = scratch_store("fetch-poison-race");
        let hex = sha256_hex(b"hello");
        let cache = store.cache_path("sha256", &hex);
        fs::write(&cache, b"hellp").unwrap();
        let (got, seen) = hash_identified(&cache, Algo::Sha256).unwrap();
        assert_ne!(got, hex);
        let good = store.root.join("tmp").join("good");
        fs::write(&good, b"hello").unwrap();
        fs::rename(&good, &cache).unwrap();

        remove_poisoned(&store, &cache, &seen);
        assert_eq!(fs::read(&cache).unwrap(), b"hello");

        // Control: the file that was hashed is removed.
        let (_, seen) = hash_identified(&cache, Algo::Sha256).unwrap();
        remove_poisoned(&store, &cache, &seen);
        assert!(!cache.exists());
    }

    #[test]
    fn a_missing_cache_entry_is_unreadable_not_corrupted() {
        let (_scratch, store) = scratch_store("fetch-missing");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let digest = Digest::sha256(&hex).unwrap();
        let error = cache_verified_digest_held(&store, activity, &digest)
            .map(drop)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .starts_with(&format!("cache entry sha256:{hex} is unreadable: ")),
            "{error}"
        );
    }

    #[test]
    fn control_a_cache_entry_with_the_right_bytes_is_served() {
        let (_scratch, store) = scratch_store("fetch-good-entry");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let cache = store.cache_path("sha256", &hex);
        fs::write(&cache, b"hello").unwrap();
        let lease = cache_verified_held(&store, activity, &hex).unwrap();
        assert_eq!(&*lease, cache.as_path());
        assert_eq!(fs::read(&lease).unwrap(), b"hello");
        assert_eq!(
            read_cache_verified_digest(&store, activity, &Digest::sha256(&hex).unwrap()).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn a_poisoned_cache_entry_is_replaced_by_a_fresh_download() {
        let (_scratch, store) = scratch_store("fetch-poisoned");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let cache = store.cache_path("sha256", &hex);
        // Same length, different bytes: only the hash can tell.
        fs::write(&cache, b"hellp").unwrap();
        let source = store.root.join("source");
        fs::write(&source, b"hello").unwrap();
        let url = format!("file://{}", source.display());

        let lease = download_verified_held(&store, activity, &url, &hex).unwrap();
        assert_eq!(&*lease, cache.as_path());
        assert_eq!(fs::read(&cache).unwrap(), b"hello");
        assert!(leftover_downloads(&store).is_empty());
    }

    #[test]
    fn a_poisoned_cache_entry_is_removed_even_when_the_refetch_fails() {
        let (_scratch, store) = scratch_store("fetch-poisoned-offline");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let cache = store.cache_path("sha256", &hex);
        fs::write(&cache, b"hellp").unwrap();
        let digest = Digest::sha256(&hex).unwrap();

        let error = cache_or_download(&store, activity, "https://x/hello", &digest, || {
            Err(io::Error::other("no network"))
        })
        .map(drop)
        .unwrap_err();
        assert_eq!(error.to_string(), "no network");
        assert!(!cache.exists(), "the poisoned entry must not survive");
        assert!(leftover_downloads(&store).is_empty());
    }

    #[test]
    fn control_a_good_cache_entry_is_served_without_opening_the_source() {
        let (_scratch, store) = scratch_store("fetch-hit");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let cache = store.cache_path("sha256", &hex);
        fs::write(&cache, b"hello").unwrap();
        let digest = Digest::sha256(&hex).unwrap();
        let lease = cache_or_download(&store, activity, "https://x/hello", &digest, || {
            panic!("a cache hit must not open the source")
        })
        .unwrap();
        assert_eq!(fs::read(&lease).unwrap(), b"hello");
    }

    #[test]
    fn a_download_whose_hash_differs_is_refused_and_leaves_nothing_behind() {
        let (_scratch, store) = scratch_store("fetch-mismatch");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let source = store.root.join("source");
        fs::write(&source, b"hellp").unwrap();
        let url = format!("file://{}", source.display());
        let expected = sha256_hex(b"hello");
        let got = sha256_hex(b"hellp");

        let error = download_verified_held(&store, activity, &url, &expected)
            .map(drop)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!("hash mismatch for {url}\n  expected sha256 {expected}\n  got      {got}")
        );
        assert!(!store.cache_path("sha256", &expected).exists());
        assert!(
            !store.cache_path("sha256", &got).exists(),
            "the bytes must not be cached under their own hash either"
        );
        assert!(leftover_downloads(&store).is_empty());
    }

    /// A stream past the artifact cap is refused by name, and leaves no
    /// cache entry and no partial download; one at the cap is cached
    /// (#367). The cap is 1 KiB here, `MAX_ARTIFACT` in production.
    #[test]
    fn a_download_past_the_artifact_cap_is_refused_and_leaves_nothing() {
        let (_scratch, store) = scratch_store("fetch-cap");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let fetch = |body: Vec<u8>| {
            let digest = Digest::sha256(&sha256_hex(&body)).unwrap();
            let outcome = cache_or_download_narrated(
                &store,
                activity,
                "https://x/big?sig=secret",
                std::slice::from_ref(&digest),
                false,
                1024,
                || Ok((Box::new(io::Cursor::new(body)) as Box<dyn Read>, None)),
            )
            .map(drop);
            (outcome, digest)
        };
        let (outcome, digest) = fetch(vec![7; 2048]);
        let error = outcome.unwrap_err();
        assert_eq!(
            error.to_string(),
            "https://x/big: exceeds the 1024-byte artifact cap; refusing"
        );
        assert!(!store.cache_path("sha256", digest.hex()).exists());
        assert!(leftover_downloads(&store).is_empty());

        let (outcome, digest) = fetch(vec![7; 1024]);
        outcome.unwrap();
        assert!(store.cache_path("sha256", digest.hex()).is_file());
        assert!(leftover_downloads(&store).is_empty());
    }

    /// The production wrappers pass `MAX_ARTIFACT`, not the release cap
    /// beside it: a stream one byte past `MAX_RELEASE_FILE` goes through
    /// `cache_or_download` to the hash check rather than a cap refusal.
    #[test]
    fn a_verified_download_is_capped_at_the_artifact_cap_not_the_release_cap() {
        let (_scratch, store) = scratch_store("fetch-cap-pin");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let digest = Digest::sha256(&sha256_hex(b"hello")).unwrap();
        let error = cache_or_download(&store, activity, "https://x/big", &digest, || {
            let body = io::repeat(0).take(MAX_RELEASE_FILE + 1);
            Ok((Box::new(body) as Box<dyn Read>, None))
        })
        .map(drop)
        .unwrap_err();
        assert!(HashMismatch::of(&error).is_some(), "{error}");
        assert!(leftover_downloads(&store).is_empty());
    }

    /// The proxy's `cache_from_reader_any` passes the artifact cap too
    /// (#614): the same stream reaches the hash check, under either of two
    /// candidate digests.
    #[test]
    fn a_proxied_download_is_capped_at_the_artifact_cap_not_the_release_cap() {
        let (_scratch, store) = scratch_store("fetch-cap-proxy");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let candidates = [
            Digest::sha256(&sha256_hex(b"hello")).unwrap(),
            Digest::sha256(&sha256_hex(b"world")).unwrap(),
        ];
        let error = cache_from_reader_any(&store, activity, "https://x/big", &candidates, || {
            Ok(Box::new(io::repeat(0).take(MAX_RELEASE_FILE + 1)) as Box<dyn Read>)
        })
        .map(drop)
        .unwrap_err();
        assert!(HashMismatch::of(&error).is_some(), "{error}");
        assert!(leftover_downloads(&store).is_empty());
    }

    /// The proxy's path refuses a stream past its cap and leaves nothing
    /// behind, as the pinned path does (#620). The cap is 1 KiB here,
    /// `MAX_ARTIFACT` in `cache_from_reader_any`.
    #[test]
    fn a_proxied_download_past_its_cap_is_refused() {
        let (_scratch, store) = scratch_store("fetch-cap-proxy-refused");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let candidates = [Digest::sha256(&sha256_hex(b"hello")).unwrap()];
        let error =
            cache_from_reader_within(&store, activity, "https://x/big", &candidates, 1024, || {
                Ok(Box::new(io::repeat(0).take(1025)) as Box<dyn Read>)
            })
            .map(drop)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exceeds the 1024-byte artifact cap"),
            "{error}"
        );
        assert!(leftover_downloads(&store).is_empty());
    }

    /// A transport failure and a status a retry can change are the
    /// `Network` class (exit 6); a 404 is an answer, not a network
    /// failure, and a broken-off body is `Network` unless it was a local
    /// file (#258).
    #[test]
    fn network_failures_are_the_network_class() {
        use crate::kernel::error::{class_of, Class};
        // Nothing listens on port 1 of the loopback address.
        let refused = fetch_text("https://127.0.0.1:1/x").unwrap_err();
        assert_eq!(class_of(&refused), Some(Class::Network), "{refused}");
        for code in [408, 429, 500, 503] {
            assert_eq!(class_of(&status_failure(code)), Some(Class::Network));
        }
        for code in [403, 404] {
            let answer = status_failure(code);
            assert_eq!(class_of(&answer), None);
            assert_eq!(http_status(&answer), Some(code));
        }
        let reset = || io::Error::from(io::ErrorKind::ConnectionReset);
        let remote = read_failure("https://x/a", reset());
        assert_eq!(class_of(&remote), Some(Class::Network));
        assert_eq!(remote.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(class_of(&read_failure("file:///a", reset())), None);
    }

    #[test]
    fn permanent_request_errors_are_not_retryable_network_failures() {
        for url in [
            "https://[",
            "ftp://example.invalid/x",
            "http://example.invalid/x",
        ] {
            let error = fetch_text(url).unwrap_err();
            assert_eq!(
                crate::kernel::error::class_of(&error),
                None,
                "{url}: {error}"
            );
        }
        for kind in [
            ureq::ErrorKind::InvalidUrl,
            ureq::ErrorKind::UnknownScheme,
            ureq::ErrorKind::InsecureRequestHttpsOnly,
            ureq::ErrorKind::InvalidProxyUrl,
            ureq::ErrorKind::ProxyUnauthorized,
            ureq::ErrorKind::TooManyRedirects,
            ureq::ErrorKind::BadStatus,
            ureq::ErrorKind::BadHeader,
        ] {
            assert!(!retryable_transport(kind), "{kind:?}");
        }
    }

    /// An unpinned download stops reading one byte past its cap, so a
    /// hostile stream cannot fill the disk before it is refused, and the
    /// partial file is removed (#614).
    #[test]
    fn an_unpinned_download_stops_reading_past_its_cap() {
        struct Counting(std::rc::Rc<std::cell::Cell<u64>>);
        impl Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                buf.fill(7);
                self.0.set(self.0.get() + buf.len() as u64);
                Ok(buf.len())
            }
        }
        let (_scratch, store) = scratch_store("fetch-unpinned-cap");
        let dest = store.root.join("unpinned");
        let read = std::rc::Rc::new(std::cell::Cell::new(0));
        let reader = Box::new(Counting(read.clone()).take(1 << 20));
        let error = copy_unpinned("https://x/big", &dest, 4096, reader).unwrap_err();
        assert!(
            error.to_string().contains("longer than 4096 bytes"),
            "{error}"
        );
        assert!(
            read.get() <= 4097,
            "read {} bytes past a 4096-byte cap",
            read.get()
        );
        assert!(!dest.exists(), "a refused unpinned download is removed");
    }

    /// A hash mismatch names the URL without the credentials before its
    /// host or the signature in its query string (#348), from the cache
    /// and from `download_file` alike. So do an unpinned download's cap
    /// and read-error refusals, and a text read's cap, read-error and
    /// UTF-8 refusals (#614).
    #[test]
    fn a_hash_mismatch_does_not_print_credentials_or_a_signature() {
        let url = "https://user:token@x/hello?sig=secret";
        let digest = Digest::sha256(&sha256_hex(b"hello")).unwrap();
        let (_scratch, store) = scratch_store("fetch-mismatch-shown");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let cached = cache_or_download(&store, activity, url, &digest, || {
            Ok((Box::new(&b"hellp"[..]) as Box<dyn Read>, None))
        })
        .map(drop)
        .unwrap_err();
        let unpinned = store.root.join("unpinned");
        let unpinned_long = copy_unpinned(url, &unpinned, 4, Box::new(&b"hello"[..])).unwrap_err();
        assert!(!unpinned.exists(), "a refused unpinned download is removed");
        let unpinned_dropped = copy_unpinned(
            url,
            &unpinned,
            1024,
            Box::new(DroppedStream {
                head: b"hel",
                served: 0,
            }),
        )
        .unwrap_err();
        assert!(!unpinned.exists(), "a dropped unpinned download is removed");
        let dest = store.root.join("release");
        let release =
            stream_to_file(url, &dest, &digest, Box::new(&b"hellp"[..]), None, 1024).unwrap_err();
        let dropped = stream_to_file(
            url,
            &dest,
            &digest,
            Box::new(DroppedStream {
                head: b"hel",
                served: 0,
            }),
            None,
            1024,
        )
        .unwrap_err();
        let text = read_text_capped(&b"abcde"[..], 4, url).unwrap_err();
        let text_dropped = read_text_capped(
            DroppedStream {
                head: b"",
                served: 0,
            },
            4,
            url,
        )
        .unwrap_err();
        assert_eq!(text_dropped.kind(), io::ErrorKind::ConnectionReset);
        let text_binary = read_text_capped(&[0xff, b'a'][..], 4, url).unwrap_err();
        assert_eq!(text_binary.kind(), io::ErrorKind::InvalidData);
        assert!(
            text_binary.to_string().contains("not UTF-8"),
            "{text_binary}"
        );
        for error in [
            cached,
            unpinned_long,
            unpinned_dropped,
            release,
            dropped,
            text,
            text_dropped,
            text_binary,
        ] {
            let shown = error.to_string();
            assert!(shown.contains("https://x/hello"), "{shown}");
            for secret in ["user", "token", "sig=", "secret"] {
                assert!(!shown.contains(secret), "{secret} in {shown}");
            }
        }
    }

    /// `download_file`'s cap refuses the same way and removes its
    /// destination; at the cap the file is written (#367).
    #[test]
    fn a_release_download_past_its_cap_is_refused_and_removed() {
        let scratch = TempDir::named("fetch-release-cap");
        let dest = scratch.0.join("tog");
        let fetch = |body: Vec<u8>| {
            let digest = Digest::sha256(&sha256_hex(&body)).unwrap();
            stream_to_file(
                "https://x/tog",
                &dest,
                &digest,
                Box::new(io::Cursor::new(body)),
                None,
                1024,
            )
        };
        let error = fetch(vec![7; 2048]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "https://x/tog: exceeds the 1024-byte cap for a tog release; refusing"
        );
        assert!(!dest.exists());
        fetch(vec![7; 1024]).unwrap();
        assert_eq!(fs::read(&dest).unwrap().len(), 1024);
    }

    #[test]
    fn cap_text_names_whole_units() {
        assert_eq!(cap_text(MAX_ARTIFACT), "8 GiB");
        assert_eq!(cap_text(MAX_RELEASE_FILE), "256 MiB");
        assert_eq!(cap_text(1024), "1024-byte");
    }

    #[test]
    fn a_download_that_drops_mid_stream_leaves_no_partial_file() {
        let (_scratch, store) = scratch_store("fetch-dropped");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let digest = Digest::sha256(&hex).unwrap();
        let error = cache_or_download(&store, activity, "https://x/hello", &digest, || {
            Ok((
                Box::new(DroppedStream {
                    head: b"hel",
                    served: 0,
                }) as Box<dyn Read>,
                Some(5),
            ))
        })
        .map(drop)
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "connection reset by peer");
        assert!(!store.cache_path("sha256", &hex).exists());
        assert!(
            leftover_downloads(&store).is_empty(),
            "partial download left in tmp"
        );
    }

    #[test]
    fn a_download_that_ends_early_is_a_hash_mismatch_not_a_cache_entry() {
        // The declared length is narration only: a stream that ends clean
        // after three of five bytes is caught by the hash, not the count.
        let (_scratch, store) = scratch_store("fetch-short");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let digest = Digest::sha256(&hex).unwrap();
        let error = cache_or_download(&store, activity, "https://x/hello", &digest, || {
            Ok((Box::new(&b"hel"[..]) as Box<dyn Read>, Some(5)))
        })
        .map(drop)
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "hash mismatch for https://x/hello\n  expected sha256 {hex}\n  got      {}",
                sha256_hex(b"hel")
            )
        );
        assert!(!store.cache_path("sha256", &hex).exists());
        assert!(!store.cache_path("sha256", &sha256_hex(b"hel")).exists());
        assert!(leftover_downloads(&store).is_empty());
    }

    #[test]
    fn a_download_that_streams_the_right_bytes_is_cached_read_only() {
        let (_scratch, store) = scratch_store("fetch-stream-ok");
        let activity = &store.activity(ActivityMode::Shared).unwrap();
        let hex = sha256_hex(b"hello");
        let digest = Digest::sha256(&hex).unwrap();
        let lease = cache_or_download(&store, activity, "https://x/hello", &digest, || {
            Ok((Box::new(&b"hello"[..]) as Box<dyn Read>, Some(5)))
        })
        .unwrap();
        assert_eq!(fs::read(&lease).unwrap(), b"hello");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&lease).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert!(leftover_downloads(&store).is_empty());
    }

    #[test]
    fn an_http_url_is_refused_before_anything_is_requested() {
        // Port 9 answers nothing; a refusal that came from a connection
        // attempt would say so instead of naming the scheme.
        let url = "http://127.0.0.1:9/artifact.tar.gz";
        let refused = |verb: &str| {
            format!(
                "{verb} {url}: tog fetches over https only; \
                 an http:// mirror is refused rather than downgraded"
            )
        };
        let error = open_url(url, "download", None).map(drop).unwrap_err();
        assert_eq!(error.to_string(), refused("download"));
        // The same refusal reaches every caller, and no file is created.
        let scratch = TempDir::named("fetch-http");
        let dest = scratch.0.join("tog");
        let error = download_file(url, &dest, &sha256_hex(b"hello"))
            .map(drop)
            .unwrap_err();
        assert_eq!(error.to_string(), refused("download"));
        assert!(!dest.exists());
        let error = fetch_text(url).map(drop).unwrap_err();
        assert_eq!(error.to_string(), refused("fetch"));
    }

    #[test]
    fn download_file_removes_its_destination_on_a_hash_mismatch() {
        let scratch = TempDir::named("fetch-file-mismatch");
        let source = scratch.0.join("source");
        fs::write(&source, b"hellp").unwrap();
        let url = format!("file://{}", source.display());
        let dest = scratch.0.join("dest");
        let expected = sha256_hex(b"hello");
        let error = download_file(&url, &dest, &expected).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "hash mismatch for {url}\n  expected sha256 {expected}\n  got      {}",
                sha256_hex(b"hellp")
            )
        );
        assert!(
            !dest.exists(),
            "a mismatched download must not be left at dest"
        );
        // Control: the right bytes land at dest.
        download_file(&url, &dest, &sha256_hex(b"hellp")).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"hellp");
    }

    /// The names under `tmp/` a poisoned entry was moved aside to.
    fn moved_aside(store: &Store) -> Vec<String> {
        fs::read_dir(store.root.join("tmp"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(POISONED_PREFIX))
            .collect()
    }

    /// A poisoned entry is removed, but good bytes published at its name
    /// after it was hashed are kept, and nothing is left aside (#555).
    #[test]
    fn removing_a_poisoned_entry_keeps_a_publish_that_replaced_it() {
        let (_scratch, store) = scratch_store("fetch-poisoned");
        let entry = store.cache_path("sha256", &sha256_hex(b"good"));
        fs::write(&entry, b"poisoned").unwrap();
        let poisoned = fs::symlink_metadata(&entry).unwrap();
        // Good bytes renamed over the entry after it was hashed.
        let good = store.root.join("good");
        fs::write(&good, b"good").unwrap();
        fs::rename(&good, &entry).unwrap();
        remove_poisoned(&store, &entry, &poisoned);
        assert_eq!(fs::read(&entry).unwrap(), b"good");
        assert!(moved_aside(&store).is_empty());
        // The poisoned file itself goes.
        let still = fs::symlink_metadata(&entry).unwrap();
        remove_poisoned(&store, &entry, &still);
        assert!(!entry.exists());
        assert!(moved_aside(&store).is_empty());
    }

    /// A tog killed between moving a poisoned entry aside and deleting it
    /// leaves it under `tmp/`, where GC sweeps it as a stale temporary,
    /// never in `cache/<algo>/`, where GC refuses any name that is not a
    /// digest and every later `tog gc` would fail.
    #[test]
    fn a_poisoned_entry_moved_aside_by_a_killed_tog_is_left_in_tmp() {
        let (_scratch, store) = scratch_store("fetch-poisoned-crash");
        let entry = store.cache_path("sha256", &sha256_hex(b"good"));
        fs::write(&entry, b"poisoned").unwrap();
        // The process dies here: the aside is never judged.
        drop(move_poisoned_aside(&store, &entry).unwrap());
        let cache: Vec<_> = fs::read_dir(entry.parent().unwrap()).unwrap().collect();
        assert!(cache.is_empty(), "{cache:?}");
        let aside = moved_aside(&store);
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert_eq!(
            fs::read(store.root.join("tmp").join(&aside[0])).unwrap(),
            b"poisoned"
        );
    }

    /// Good bytes moved aside go back to their name, unless another copy
    /// has been published there since: that copy is kept, and the moved
    /// one is deleted rather than left in `tmp/` (#555).
    #[test]
    fn putting_back_a_moved_entry_never_replaces_a_newer_publish() {
        let (_scratch, store) = scratch_store("fetch-put-back");
        let entry = store.cache_path("sha256", &sha256_hex(b"good"));

        fs::write(&entry, b"good").unwrap();
        let aside = move_poisoned_aside(&store, &entry).unwrap();
        assert!(!entry.exists());
        put_back(&aside);
        assert_eq!(fs::read(&entry).unwrap(), b"good");
        assert!(moved_aside(&store).is_empty());

        let aside = move_poisoned_aside(&store, &entry).unwrap();
        fs::write(&entry, b"planted").unwrap();
        put_back(&aside);
        assert_eq!(fs::read(&entry).unwrap(), b"planted");
        assert!(moved_aside(&store).is_empty());
    }

    /// Set in the child `an_inserted_entry_is_read_only_under_umask_0077`
    /// runs: only there does this test set the umask, which is process-wide
    /// and would leak into every other test in this binary.
    const UMASK_CHILD: &str = "TOG_TEST_FETCH_UMASK_CHILD";

    /// An inserted entry is 0444 even under `umask 0077`, which leaves the
    /// mode it is created with at 0400: the explicit chmod is what makes it
    /// readable to every user of the store, as a download is. The umask is
    /// set in a child run of this test binary, which reports through its
    /// exit status.
    #[test]
    fn an_inserted_entry_is_read_only_under_umask_0077() {
        use std::os::unix::fs::PermissionsExt;
        const NAME: &str =
            "kernel::fetch::integrity_tests::an_inserted_entry_is_read_only_under_umask_0077";
        if std::env::var_os(UMASK_CHILD).is_some() {
            let (_scratch, store) = scratch_store("fetch-insert-umask");
            let activity = &store.activity(ActivityMode::Shared).unwrap();
            let input = store.root.join("artifact");
            fs::write(&input, b"module zip").unwrap();
            // SAFETY: umask has no preconditions; this process is the
            // child run, which runs this one test and nothing else.
            unsafe { libc::umask(0o077) };
            let (_, dest) = cache_insert(&store, activity, &input).unwrap();
            let mode = fs::metadata(&dest).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o444, "{}", dest.display());
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
            .env(UMASK_CHILD, "1")
            .output()
            .unwrap();
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{report}");
        // The child ran the test rather than filtering it out.
        assert!(report.contains("1 passed"), "{report}");
    }
}

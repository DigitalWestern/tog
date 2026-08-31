use crate::store::Store;
use sha2::{Digest as _, Sha256, Sha512};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    Sha256,
    Sha512,
}

/// Content digest for artifact verification and cache addressing.
/// Fields are private: a Digest can only hold validated lowercase hex of
/// the exact right length, so it can never smuggle path components into
/// cache paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    algo: Algo,
    hex: String,
}

impl Digest {
    fn validated(algo: Algo, hex: &str) -> io::Result<Digest> {
        let want = match algo {
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
    pub fn sha512(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha512, hex)
    }
    pub fn algo(&self) -> &'static str {
        algo_name(self.algo)
    }
    pub fn hex(&self) -> &str {
        &self.hex
    }
    /// Parse an npm SRI string like "sha512-<base64>" or "sha256-<base64>".
    pub fn from_sri(sri: &str) -> io::Result<Digest> {
        let (algo, b64) = sri.split_once('-').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("malformed integrity: {sri}"))
        })?;
        let bytes = base64_decode(b64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad base64 in integrity: {sri}"))
        })?;
        let hex = hex::encode(bytes);
        match algo {
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
    let digest = Digest::sha256(sha256)?;
    let path = store.cache_path("sha256", digest.hex());
    match hash_file(&path, Algo::Sha256) {
        Ok(h) if h == digest.hex() => Ok(path),
        Ok(_) => {
            let _ = fs::remove_file(&path);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cache entry {sha256} was corrupted (removed); re-run sync"),
            ))
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("cache entry {sha256} unreadable: {e}; re-run sync"),
        )),
    }
}

fn hash_file(path: &std::path::Path, algo: Algo) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut buf = [0u8; 65536];
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        match algo {
            Algo::Sha256 => h256.update(&buf[..n]),
            Algo::Sha512 => h512.update(&buf[..n]),
        }
    }
    Ok(match algo {
        Algo::Sha256 => hex::encode(h256.finalize()),
        Algo::Sha512 => hex::encode(h512.finalize()),
    })
}

fn algo_name(a: Algo) -> &'static str {
    match a {
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

/// Back-compat convenience for sha256 hex callers.
pub fn download_verified(store: &Store, url: &str, sha256: &str) -> io::Result<PathBuf> {
    download_verified_digest(store, url, &Digest::sha256(sha256)?)
}

/// Insert a local file into the verified artifact cache by its computed
/// sha256 (for artifacts obtained through delegated tools and then verified
/// by blanket — e.g. Go module zips h1-checked by dirhash). Returns
/// (sha256 hex, cache path). Publication mirrors download_verified.
pub fn cache_insert(store: &Store, src: &std::path::Path) -> io::Result<(String, PathBuf)> {
    let hex = hash_file(src, Algo::Sha256)?;
    let dest = store.cache_path("sha256", &hex);
    if dest.is_file() {
        // Re-verify on hit, like download_verified: a same-user replacement
        // must never ride an old address (poisoned -> drop and re-insert).
        match hash_file(&dest, Algo::Sha256) {
            Ok(h) if h == hex => return Ok((hex, dest)),
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
    Ok((hex, dest))
}

/// Download `url`, verify its digest, and place it in the store's artifact
/// cache (keyed by algo/hex). Idempotent; an existing entry short-circuits
/// (offline reconstruction). file:// URLs read local files (mirrors, tests).
pub fn download_verified_digest(store: &Store, url: &str, digest: &Digest) -> io::Result<PathBuf> {
    let dest = store.cache_path(digest.algo(), digest.hex());
    if dest.is_file() {
        // Re-verify on every hit: read-only bits stop accidents, not disk
        // corruption or same-user replacement. A concurrent publisher can
        // replace/briefly unlink the entry, so a read race falls through
        // to a fresh download instead of failing.
        match hash_file(&dest, digest.algo) {
            Ok(h) if h == digest.hex() => return Ok(dest),
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
        Box::new(fs::File::open(path).map_err(|e| {
            io::Error::new(e.kind(), format!("open {path}: {e}"))
        })?)
    } else {
        // https_only holds across redirects too — no downgrade-to-http.
        let agent = ureq::AgentBuilder::new().https_only(true).build();
        let resp = agent.get(url).call().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("GET {url}: {e}"))
        })?;
        Box::new(resp.into_reader())
    };

    // Cap the stream so a hostile server can't fill the disk before the
    // hash check fails. 8 GiB covers every real artifact class we handle.
    const MAX_ARTIFACT: u64 = 8 << 30;
    let mut file = fs::File::create(&tmp)
        .map_err(|e| io::Error::new(e.kind(), format!("create {}: {e}", tmp.display())))?;
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
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
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

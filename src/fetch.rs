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

/// Download `url`, verify its digest, and place it in the store's artifact
/// cache (keyed by algo/hex). Idempotent; an existing entry short-circuits
/// (offline reconstruction). file:// URLs read local files (mirrors, tests).
pub fn download_verified_digest(store: &Store, url: &str, digest: &Digest) -> io::Result<PathBuf> {
    let dest = store.cache_path(digest.algo(), digest.hex());
    if dest.is_file() {
        // Re-verify on every hit: read-only bits stop accidents, not disk
        // corruption or same-user replacement.
        if hash_file(&dest, digest.algo)? == digest.hex() {
            return Ok(dest);
        }
        let _ = fs::remove_file(&dest); // poisoned/corrupt: drop and refetch
    }
    fs::create_dir_all(dest.parent().unwrap())?;
    let tmp = store
        .root
        .join("tmp")
        .join(format!("dl-{}-{}", std::process::id(), digest.hex()));

    let mut reader: Box<dyn Read> = if let Some(path) = url.strip_prefix("file://") {
        Box::new(fs::File::open(path).map_err(|e| {
            io::Error::new(e.kind(), format!("open {path}: {e}"))
        })?)
    } else {
        let resp = ureq::get(url).call().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("GET {url}: {e}"))
        })?;
        Box::new(resp.into_reader())
    };

    let mut file = fs::File::create(&tmp)?;
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        match digest.algo {
            Algo::Sha256 => h256.update(&buf[..n]),
            Algo::Sha512 => h512.update(&buf[..n]),
        }
        file.write_all(&buf[..n])?;
    }
    file.flush()?;
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
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&tmp, perms)?;
    }
    match fs::rename(&tmp, &dest) {
        Ok(()) => {}
        Err(_) if dest.is_file() => {
            let _ = fs::remove_file(&tmp);
        }
        Err(e) => return Err(e),
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

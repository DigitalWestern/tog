use crate::store::Store;
use sha2::{Digest as _, Sha256, Sha512};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Content digest for artifact verification and cache addressing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Digest {
    Sha256(String), // lowercase hex
    Sha512(String), // lowercase hex
}

impl Digest {
    pub fn algo(&self) -> &'static str {
        match self {
            Digest::Sha256(_) => "sha256",
            Digest::Sha512(_) => "sha512",
        }
    }
    pub fn hex(&self) -> &str {
        match self {
            Digest::Sha256(h) | Digest::Sha512(h) => h,
        }
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
            "sha256" => Ok(Digest::Sha256(hex)),
            "sha512" => Ok(Digest::Sha512(hex)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported integrity algorithm: {other}"),
            )),
        }
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
    download_verified_digest(store, url, &Digest::Sha256(sha256.to_lowercase()))
}

/// Download `url`, verify its digest, and place it in the store's artifact
/// cache (keyed by algo/hex). Idempotent; an existing entry short-circuits
/// (offline reconstruction). file:// URLs read local files (mirrors, tests).
pub fn download_verified_digest(store: &Store, url: &str, digest: &Digest) -> io::Result<PathBuf> {
    let dest = store.cache_path(digest.algo(), digest.hex());
    if dest.is_file() {
        return Ok(dest);
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
        match digest {
            Digest::Sha256(_) => h256.update(&buf[..n]),
            Digest::Sha512(_) => h512.update(&buf[..n]),
        }
        file.write_all(&buf[..n])?;
    }
    file.flush()?;
    drop(file);

    let got = match digest {
        Digest::Sha256(_) => hex::encode(h256.finalize()),
        Digest::Sha512(_) => hex::encode(h512.finalize()),
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

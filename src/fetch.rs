use crate::store::Store;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Download `url`, verify its sha256, and place it in the store's artifact
/// cache. Returns the cached path. Idempotent: an existing verified cache
/// entry is returned without touching the network (offline reconstruction).
pub fn download_verified(store: &Store, url: &str, sha256: &str) -> io::Result<PathBuf> {
    let dest = store.cache_path(sha256);
    if dest.is_file() {
        return Ok(dest);
    }
    let tmp = store
        .root
        .join("tmp")
        .join(format!("dl-{}-{}", std::process::id(), sha256));

    let resp = ureq::get(url).call().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("GET {url}: {e}"))
    })?;
    let mut reader = resp.into_reader();
    let mut file = fs::File::create(&tmp)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }
    file.flush()?;
    drop(file);

    let got = hex::encode(hasher.finalize());
    if got != sha256.to_lowercase() {
        let _ = fs::remove_file(&tmp);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("hash mismatch for {url}\n  expected {sha256}\n  got      {got}"),
        ));
    }
    // rename is atomic; a concurrent identical download wins harmlessly.
    match fs::rename(&tmp, &dest) {
        Ok(()) => {}
        Err(_) if dest.is_file() => {
            let _ = fs::remove_file(&tmp);
        }
        Err(e) => return Err(e),
    }
    Ok(dest)
}

use crate::fetch::download_verified;
use crate::store::Store;
use crate::types::Identity;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Pinned CPython builds from astral-sh/python-build-standalone (release
/// 20260825, aarch64-apple-darwin, install_only). Checksums verified at
/// pin time (trust-on-first-use; a signed provider manifest replaces this
/// table post-MVP).
pub struct PinnedPython {
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const PYTHONS: &[PinnedPython] = &[
    PinnedPython {
        version: "3.12.14",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.12.14%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "62eef3fcf48fa4f792d0d6d267c140b81aaea0edca4ae0641d8021854314f966",
    },
    PinnedPython {
        version: "3.13.15",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.13.15%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "d681f7cebf4885637242cba807d22f476b9ea8555ac2dc7307172426dbf161e1",
    },
];

pub fn lookup(version: &str) -> Option<&'static PinnedPython> {
    // Accept "3.12" as a prefix match on "3.12.".
    PYTHONS
        .iter()
        .find(|p| p.version == version || p.version.starts_with(&format!("{version}.")))
}

/// Pinned uv (resolver delegation target). Single static binary; realized
/// like any toolchain so a bare machine needs nothing besides blanket.
const UV_VERSION: &str = "0.12.7";
const UV_URL: &str =
    "https://github.com/astral-sh/uv/releases/download/0.12.7/uv-aarch64-apple-darwin.tar.gz";
const UV_SHA256: &str = "127ebdda7ad953cdf198e964b570ea5771b85467ea93eb7cb6d6f8e6f55408f3";

/// Ensure uv is realized in the store (binary at <obj>/uv).
pub fn ensure_uv(store: &Store) -> io::Result<PathBuf> {
    let identity = Identity {
        kind: "uv".into(),
        name: "uv".into(),
        version: UV_VERSION.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), UV_SHA256.to_string()),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified(store, UV_URL, UV_SHA256)?;
    let staged = store.stage()?;
    // Tarball root is "uv-aarch64-apple-darwin/"; strip it.
    let status = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"])
        .status()?;
    if !status.success() || !staged.join("uv").is_file() {
        return Err(io::Error::other("uv tarball extraction failed"));
    }
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
}

/// Ensure the given CPython is realized in the store. Returns the object path
/// (interpreter at <path>/bin/python3).
pub fn ensure_python(store: &Store, pin: &PinnedPython) -> io::Result<PathBuf> {
    let identity = Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: pin.version.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let tarball = download_verified(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    // Tarball root is "python/"; strip it so the object root IS the prefix.
    let status = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"])
        .status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "tar extraction failed",
        ));
    }
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
}

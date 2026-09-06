use crate::fetch::download_verified;
use crate::platform::{no_pin, Platform};
use crate::store::Store;
use crate::types::Identity;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Pinned CPython builds from astral-sh/python-build-standalone (release
/// 20260825, per-platform rows, install_only). Checksums verified at pin
/// time (trust-on-first-use; a signed provider manifest replaces this table
/// post-MVP).
#[derive(Debug)]
pub struct PinnedPython {
    pub platform: Platform,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const PYTHONS: &[PinnedPython] = &[
    // Keep the existing Darwin rows byte-for-byte and append new rows after
    // them; their object ids are compatibility goldens.
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.12.14",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.12.14%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "62eef3fcf48fa4f792d0d6d267c140b81aaea0edca4ae0641d8021854314f966",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.13.15",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.13.15%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "d681f7cebf4885637242cba807d22f476b9ea8555ac2dc7307172426dbf161e1",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.10.21",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.10.21%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "7fedf2035ce497b0ce01643cc5e8ed2aabfb8cfa730440e97af0330b56ce0608",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.11.16",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.11.16%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "2e50ed6ec49d8714a83c093e9ce74e1b8b21a2c64a49c3b603471d9c4caac76b",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.14.7",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.14.7%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "4c4a4114bc35f9d76d194fd72f43d8375b2f30686ddfe6b40c9258cfe6c16e40",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.12.14",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.12.14%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "cbdd2f0cf02f941bc5c81e546f377275e322733abffe805ac29d2b7e8a58f7e3",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.13.15",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.13.15%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "8a70011ae25276a9925f89304cdc086466cd269ee6cfe68a9506694ca5ff4f9c",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.10.21",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.10.21%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "b3cfb164a81b8fb16125cc7703689a6181e06983db3220a1765da68ebe430aff",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.11.16",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.11.16%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "25844eb97cdc72cdc78addaad0969ce3b2133a4de54bfcfa4d57f8a6d095eaab",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.14.7",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.14.7%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "d68dfa9c5d37afec0a4c8ffbf5c20d05d34492bd4561c94d7c3c7578e21a7f71",
    },
];

pub fn lookup(platform: Platform, version: &str) -> Option<&'static PinnedPython> {
    // Accept "3.12" as a prefix match on "3.12.".
    PYTHONS
        .iter()
        .find(|p| {
            p.platform == platform
                && (p.version == version || p.version.starts_with(&format!("{version}.")))
        })
}

pub(crate) fn object_id_for(platform: Platform, version: &str) -> io::Result<String> {
    let pin = lookup(platform, version)
        .ok_or_else(|| no_pin(&format!("cpython {version}"), platform, "stage 2"))?;
    Ok(cpython_identity(pin).object_id())
}

pub fn preflight(platform: Platform, version: &str) -> io::Result<()> {
    crate::platform::require_host(platform, "CPython", "stage 2")?;
    lookup(platform, version)
        .map(|_| ())
        .ok_or_else(|| no_pin(&format!("cpython {version}"), platform, "stage 2"))
}

/// Pinned uv (resolver delegation target). Single static binary per platform;
/// realized like any toolchain so a bare machine needs nothing besides
/// blanket.
const UV_VERSION: &str = "0.12.7";
struct PinnedUv {
    platform: Platform,
    url: &'static str,
    sha256: &'static str,
}

const UV: &[PinnedUv] = &[
    PinnedUv {
        platform: Platform::Aarch64AppleDarwin,
        url: "https://github.com/astral-sh/uv/releases/download/0.12.7/uv-aarch64-apple-darwin.tar.gz",
        sha256: "127ebdda7ad953cdf198e964b570ea5771b85467ea93eb7cb6d6f8e6f55408f3",
    },
    PinnedUv {
        platform: Platform::X86_64UnknownLinuxGnu,
        url: "https://github.com/astral-sh/uv/releases/download/0.12.7/uv-x86_64-unknown-linux-gnu.tar.gz",
        sha256: "788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21",
    },
];

fn cpython_identity(pin: &PinnedPython) -> Identity {
    Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: pin.version.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), pin.platform.triple().to_string()),
        ]),
    }
}

fn uv_identity(pin: &PinnedUv) -> Identity {
    Identity {
        kind: "uv".into(),
        name: "uv".into(),
        version: UV_VERSION.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), pin.platform.triple().to_string()),
        ]),
    }
}

/// Ensure uv is realized in the store (binary at <obj>/uv).
pub fn ensure_uv(store: &Store) -> io::Result<PathBuf> {
    ensure_uv_for(store, Platform::host()?)
}

pub fn ensure_uv_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "uv", "stage 2")?;
    let pin = UV
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or_else(|| no_pin("uv", platform, "stage 2"))?;
    let identity = uv_identity(pin);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    // Tarball root is platform-specific; strip it.
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
    ensure_python_for(store, pin, Platform::host()?)
}

pub(crate) fn ensure_python_for(
    store: &Store,
    pin: &PinnedPython,
    platform: Platform,
) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "CPython", "stage 2")?;
    if pin.platform != platform {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "CPython pin {} is for {}, not host {} (LINUX_PORT.md stage 2)",
                pin.version,
                pin.platform.triple(),
                platform.triple()
            ),
        ));
    }
    let identity = cpython_identity(pin);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_tables_have_five_cpython_and_one_uv_row_per_platform() {
        let mut python_keys = std::collections::HashSet::new();
        let mut uv_keys = std::collections::HashSet::new();
        for &platform in Platform::ALL {
            let python_rows: Vec<_> = PYTHONS
                .iter()
                .filter(|pin| pin.platform == platform)
                .collect();
            assert_eq!(python_rows.len(), 5, "CPython rows for {platform:?}");
            for pin in python_rows {
                assert!(
                    python_keys.insert((pin.platform, pin.version)),
                    "duplicate CPython pin for {platform:?}: {}",
                    pin.version
                );
            }

            let uv_rows: Vec<_> = UV
                .iter()
                .filter(|pin| pin.platform == platform)
                .collect();
            assert_eq!(uv_rows.len(), 1, "uv rows for {platform:?}");
            for pin in uv_rows {
                assert!(
                    uv_keys.insert((pin.platform, UV_VERSION)),
                    "duplicate uv pin for {platform:?}"
                );
            }
        }
    }

    #[test]
    fn darwin_identity_unchanged() {
        let darwin_pins: Vec<_> = PYTHONS
            .iter()
            .filter(|pin| pin.platform == Platform::Aarch64AppleDarwin)
            .collect();
        assert_eq!(darwin_pins.len(), 5);
        for pin in darwin_pins {
            let identity = cpython_identity(pin);
            let expected = match pin.version {
                "3.12.14" => "a1a7472f00bcc8e7432dcaf8e088192eab9ddb63-cpython-3.12.14",
                "3.13.15" => "3d4cd599c6aa947638318fba6a27cdf922d71e91-cpython-3.13.15",
                "3.10.21" => "2d325d7de98a5ef468887be7a900ba353393e6d4-cpython-3.10.21",
                "3.11.16" => "4f5f15e85142c23c54ceb171e28eed8e37868d58-cpython-3.11.16",
                "3.14.7" => "a08604ddc4f60d6a41bfde528123267824647022-cpython-3.14.7",
                other => panic!("unexpected Darwin CPython pin {other}"),
            };
            assert_eq!(identity.object_id(), expected);
        }
        let uv = UV
            .iter()
            .find(|pin| pin.platform == Platform::Aarch64AppleDarwin)
            .expect("Darwin uv pin");
        let identity = uv_identity(uv);
        assert_eq!(
            identity.object_id(),
            "d43528ee22f3027d76f93b39716982e6cabcbe9f-uv-0.12.7"
        );
    }
}

//! The Python tailor: the pinned CPython toolchain (this file) and, in the
//! sibling modules, PyPI locking, wheel installs, manifest discovery, and
//! sandboxed sdist builds.

pub mod artifacts;
pub mod build;
pub(crate) mod build_requires;
pub mod env;
pub mod inputs;
pub mod manifest;
pub mod nativelibs;
pub mod objects;
pub mod pep440;
pub mod pypi;
pub mod pyselect;
pub mod tailor;
pub mod wheel;

use crate::kernel::fetch::{download_verified_held, Digest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
#[cfg(test)]
use crate::kernel::types::{ArtifactKind, LockedPackage, Plan};
use std::collections::BTreeMap;
#[cfg(test)]
use std::fs;
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
    lookup_in_pins(PYTHONS, platform, version)
}

/// Return the number of release components when `version` is written in the
/// canonical form accepted for CPython selection. Components are decimal and
/// cannot have leading zeroes; no suffixes, prefixes, or surrounding text are
/// accepted.
pub(crate) fn canonical_release_len(version: &str) -> Option<usize> {
    let pieces: Vec<_> = version.split('.').collect();
    if !(2..=3).contains(&pieces.len())
        || pieces.iter().any(|piece| {
            piece.is_empty()
                || (piece.len() > 1 && piece.starts_with('0'))
                || !piece.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some(pieces.len())
}

/// Match only a complete pinned version or a major.minor request. The slice
/// is supplied by the caller so matching remains independent of the table's
/// row order and can be tested with synthetic pin tables.
fn lookup_in_pins<'a>(
    pins: &'a [PinnedPython],
    platform: Platform,
    version: &str,
) -> Option<&'a PinnedPython> {
    let release_len = canonical_release_len(version)?;
    let requested = crate::tailors::python::pep440::Version::parse(version).ok()?;
    if requested.has_epoch() || requested.is_prerelease() || requested.has_local() {
        return None;
    }

    match release_len {
        3 => pins
            .iter()
            .find(|pin| pin.platform == platform && pin.version == version),
        2 => pins
            .iter()
            .filter(|pin| {
                pin.platform == platform
                    && parse_pinned_version(pin.version).is_some_and(|pinned| {
                        pinned.major() == requested.major() && pinned.minor() == requested.minor()
                    })
            })
            .max_by(|left, right| {
                parse_pinned_version(left.version)
                    .expect("pinned CPython version")
                    .cmp(&parse_pinned_version(right.version).expect("pinned CPython version"))
            }),
        _ => None,
    }
}

fn parse_pinned_version(version: &str) -> Option<crate::tailors::python::pep440::Version> {
    let parsed = crate::tailors::python::pep440::Version::parse(version).ok()?;
    (parsed.release_len() == 3
        && !parsed.has_epoch()
        && !parsed.is_prerelease()
        && !parsed.has_local())
    .then_some(parsed)
}

pub(crate) fn object_id_for(platform: Platform, version: &str) -> io::Result<String> {
    let pin =
        lookup(platform, version).ok_or_else(|| no_pin(&format!("cpython {version}"), platform))?;
    Ok(cpython_identity(pin).object_id())
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let cpython_pin = lookup(platform, "3.12.14").expect("pinned CPython for test platform");
    let cpython = cpython_identity(cpython_pin);
    let uv = uv_identity(
        UV.iter()
            .find(|pin| pin.platform == platform)
            .expect("pinned uv for test platform"),
    );
    let root = std::env::temp_dir().join(format!(
        "blanket-python-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        fs::create_dir_all(root.join(sub)).expect("Python identity fixture store");
    }
    let store = Store {
        root: root
            .canonicalize()
            .expect("canonical Python identity fixture store"),
    };
    let empty_plan = Plan {
        ecosystem: "python".into(),
        python_version: cpython_pin.version.into(),
        packages: Vec::new(),
    };
    let wheel_plan = Plan {
        packages: vec![LockedPackage {
            name: "example".into(),
            version: "1.0.0".into(),
            filename: "example-1.0.0-py3-none-any.whl".into(),
            url: "https://files.pythonhosted.org/example.whl".into(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Wheel,
            git: None,
        }],
        ..empty_plan.clone()
    };
    let env_empty = env::environment_identity(&store, platform, &empty_plan, &cpython.object_id())
        .expect("empty Python environment identity");
    let env_wheel = env::environment_identity(&store, platform, &wheel_plan, &cpython.object_id())
        .expect("Python wheel environment identity");
    let mut cases = vec![cpython.clone(), uv, env_empty, env_wheel];
    if platform == Platform::X86_64UnknownLinuxGnu {
        let native_pkg = build::local_native_sdist_for_test(&store, "matrix-python-native");
        let native_plan = Plan {
            packages: vec![native_pkg],
            ..empty_plan.clone()
        };
        let env_native =
            env::environment_identity(&store, platform, &native_plan, &cpython.object_id())
                .expect("Python native-sdist environment identity");
        cases.push(env_native);
        cases.push(
            nativelibs::live_identity_for_test(&store, platform)
                .expect("pinned native library identity"),
        );
    } else {
        // Native libraries are unsupported on Darwin, so the local native
        // sdist would take plan_sdist_identity_input's schema-2 fast path.
        // It is intentionally omitted here; the Darwin schema-3 matrix case
        // uses a Rust sdist whose Cargo.toml selects that path.
    }
    cases.extend(build::live_identity_cases(platform));
    let _ = crate::kernel::store::remove_tree(&store.root);
    cases
}

pub fn preflight(platform: Platform, version: &str) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "CPython")?;
    lookup(platform, version)
        .map(|_| ())
        .ok_or_else(|| no_pin(&format!("cpython {version}"), platform))
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
    crate::tailors::install_kinds();
    ensure_uv_for(store, Platform::host()?)
}

pub fn ensure_uv_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "uv")?;
    let pin = UV
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or_else(|| no_pin("uv", platform))?;
    let identity = uv_identity(pin);
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified_held(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    // Tarball root is platform-specific; strip it.
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status_owned(&mut command, store)?;
    if !status.success() || !staged.join("uv").is_file() {
        return Err(io::Error::other("uv tarball extraction failed"));
    }
    store
        .commit_with_deps(&identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(pin.sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

/// Ensure the given CPython is realized in the store. Returns the object path
/// (interpreter at <path>/bin/python3).
pub fn ensure_python(store: &Store, pin: &PinnedPython) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    ensure_python_for(store, pin, Platform::host()?)
}

pub(crate) fn ensure_python_for(
    store: &Store,
    pin: &PinnedPython,
    platform: Platform,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "CPython")?;
    if pin.platform != platform {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "CPython pin {} is for {}, not host {} (unsupported platform)",
                pin.version,
                pin.platform.triple(),
                platform.triple()
            ),
        ));
    }
    let identity = cpython_identity(pin);
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let tarball = download_verified_held(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    // Tarball root is "python/"; strip it so the object root IS the prefix.
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status_owned(&mut command, store)?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "tar extraction failed",
        ));
    }
    store
        .commit_with_deps(&identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(pin.sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit. If it does not, a migrated record stops
    /// matching what a re-sync publishes and every later cache hit becomes a
    /// hard error (`store::validate_cached_dependency_evidence`), which is
    /// what made a migrated store un-syncable in the rejected implementation.
    #[test]
    fn legacy_adapters_recover_the_pinned_cpython_and_uv_artifacts() {
        for platform in Platform::ALL {
            for pin in PYTHONS.iter().filter(|pin| pin.platform == *platform) {
                let expected = vec![format!("sha256:{}", pin.sha256)];
                assert_eq!(recovered_cache(cpython_identity(pin)), expected);
            }
            for pin in UV.iter().filter(|pin| pin.platform == *platform) {
                let expected = vec![format!("sha256:{}", pin.sha256)];
                assert_eq!(recovered_cache(uv_identity(pin)), expected);
            }
        }
    }

    fn recovered_cache(identity: crate::kernel::types::Identity) -> Vec<String> {
        match crate::kernel::objmeta::adapt_identity_for_test(identity, Vec::new()) {
            crate::kernel::objmeta::Adaptation::Proven(deps) => {
                assert!(
                    deps.objects.is_empty(),
                    "a pinned artifact has no object deps"
                );
                deps.cache
                    .iter()
                    .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                    .collect()
            }
            crate::kernel::objmeta::Adaptation::Unresolved(reason) => panic!("{reason}"),
        }
    }

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

            let uv_rows: Vec<_> = UV.iter().filter(|pin| pin.platform == platform).collect();
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

    #[test]
    fn lookup_rejects_bare_major_and_accepts_minor_and_exact_versions() {
        for &platform in Platform::ALL {
            assert!(lookup(platform, "3").is_none());
            assert!(lookup(platform, "3.1").is_none());
            assert!(lookup(platform, "not-a-version").is_none());
            assert!(lookup(platform, "3.12.post1").is_none());
            assert!(lookup(platform, "3.12-dev").is_none());
            for invalid in [
                "03.12",
                "3.12.014",
                "3.12.0",
                "3.12.14.0",
                "v3.12",
                "3.12.14 ",
                "3.12.",
            ] {
                assert!(lookup(platform, invalid).is_none(), "{invalid}");
            }
            assert_eq!(lookup(platform, "3.12").unwrap().version, "3.12.14");
            assert_eq!(lookup(platform, "3.12.14").unwrap().version, "3.12.14");
        }
    }

    #[test]
    fn lookup_uses_the_newest_numeric_patch_in_a_wrongly_ordered_table() {
        let pins = [
            PinnedPython {
                platform: Platform::X86_64UnknownLinuxGnu,
                version: "3.12.9",
                url: "https://example.invalid/3.12.9.tar.gz",
                sha256: "9",
            },
            PinnedPython {
                platform: Platform::X86_64UnknownLinuxGnu,
                version: "3.12.14",
                url: "https://example.invalid/3.12.14.tar.gz",
                sha256: "14",
            },
        ];
        assert_eq!(
            lookup_in_pins(&pins, Platform::X86_64UnknownLinuxGnu, "3.12")
                .unwrap()
                .version,
            "3.12.14"
        );
        assert_eq!(
            lookup_in_pins(&pins, Platform::X86_64UnknownLinuxGnu, "3.12.9")
                .unwrap()
                .version,
            "3.12.9"
        );
        assert!(lookup_in_pins(&pins, Platform::Aarch64AppleDarwin, "3.12").is_none());
        assert!(lookup_in_pins(&pins, Platform::X86_64UnknownLinuxGnu, "3.12.3").is_none());
    }
}

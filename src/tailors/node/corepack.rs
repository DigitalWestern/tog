//! Corepack's `packageManager` pin for the pnpm a Node edit runs: the exact
//! release it names, the optional `+<algo>.<hex>` hash suffix, and the
//! check that the pnpm tarball tog realized has that hash. The realized
//! tarball is whichever cached entry matched the lock's integrity, which
//! may allow several hashes (#508), so each candidate's entry is a witness.

use crate::comforter;
use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::sri_candidates;
use crate::kernel::fetch;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store::Store;
use crate::tailors::edit::{other, CachedTool, EditHost};
use sha2::{Digest, Sha224, Sha256, Sha512};
use std::io;
use std::path::Path;

/// The digest algorithms a Corepack `packageManager` hash suffix may name.
/// Corepack has written `+sha224.`, `+sha256.` and (currently) `+sha512.`;
/// the suffix is always lower-case hex, never base64 SRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorepackAlgo {
    Sha224,
    Sha256,
    Sha512,
}

impl CorepackAlgo {
    /// Named verbatim by every refusal that rejects an algorithm.
    pub(crate) const SUPPORTED: &'static str = "sha224, sha256, sha512";

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "sha224" => Some(Self::Sha224),
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Width of the hex digest the suffix must carry.
    pub(crate) fn hex_len(self) -> usize {
        match self {
            Self::Sha224 => 56,
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    fn hex_digest(self, bytes: &[u8]) -> String {
        match self {
            Self::Sha224 => hex::encode(Sha224::digest(bytes)),
            Self::Sha256 => hex::encode(Sha256::digest(bytes)),
            Self::Sha512 => hex::encode(Sha512::digest(bytes)),
        }
    }
}

/// A parsed Corepack hash suffix: the algorithm plus its lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CorepackHash {
    pub(crate) algo: CorepackAlgo,
    pub(crate) hex: String,
}

/// Realize the exact package-manager release `package@version` a Node
/// edit runs, in the same registered `~/.tog/x/` environment `tog x`
/// would use, so a delegate's second invocation is a normal cache hit.
/// With a Corepack hash, the realized tarball must have it.
pub(crate) fn realize_node_tool(
    host: &dyn EditHost,
    door: &mut ResolutionDoor<'_>,
    project: &Path,
    package: &str,
    version: &str,
    corepack_hash: Option<&CorepackHash>,
) -> io::Result<CachedTool> {
    validate_exact_version(version)?;
    let tool = host.cached_tool("node", project, package, version, door)?;
    if let Some(expected) = corepack_hash {
        verify_corepack_hash(
            door.store(),
            door.lease(),
            &tool.root,
            package,
            version,
            expected,
        )?;
    }
    Ok(tool)
}

/// Whether `version` is the exact release syntax accepted for a delegated
/// package-manager tool: MAJOR.MINOR.PATCH with an optional prerelease.
/// Build metadata is deliberately excluded because Corepack's hash suffix is
/// handled separately by the package-manager field parser.
pub(crate) fn is_exact_version(version: &str) -> bool {
    fn decimal_component(value: &str) -> bool {
        !value.is_empty()
            && (value.len() == 1 || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
    }

    let (release, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(a, b)| (a, Some(b)));
    let components: Vec<&str> = release.split('.').collect();
    if components.len() != 3 || !components.iter().all(|part| decimal_component(part)) {
        return false;
    }
    let Some(prerelease) = prerelease else {
        return true;
    };
    !prerelease.is_empty()
        && prerelease.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier.len() == 1
                    || !identifier.starts_with('0'))
        })
}

fn validate_exact_version(version: &str) -> io::Result<()> {
    if !is_exact_version(version) {
        return Err(other(format!(
            "x: node tool version must be an exact MAJOR.MINOR.PATCH release (a prerelease suffix is allowed), found {version:?}"
        )));
    }
    Ok(())
}

fn verify_corepack_hash(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    package: &str,
    version: &str,
    expected: &CorepackHash,
) -> io::Result<()> {
    let algo = expected.algo;
    let name = algo.name();
    if expected.hex.len() != algo.hex_len()
        || !expected.hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(other(format!(
            "x: packageManager has a malformed {name} hash for {package}@{version}"
        )));
    }
    let closure = comforter::read_closure(root, "node")?;
    let packages = closure["packages"].as_array().ok_or_else(|| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: realized node closure has no package list; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let pnpm = packages.iter().find(|entry| {
        entry["path"].as_str() == Some("node_modules/pnpm")
            && entry["version"].as_str() == Some(version)
    });
    let Some(pnpm) = pnpm else {
        return Err(other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: realized node closure has no reachable pnpm artifact; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        )));
    };
    let integrity = pnpm["integrity"].as_str().ok_or_else(|| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: pnpm artifact has no integrity and no reachable cache path; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    // The integrity may allow several hashes of its strongest algorithm
    // (#508), and the tarball tog realized matched one of them: that is the
    // cache entry the pnpm came from, so every candidate's entry is tried.
    let candidates = sri_candidates(integrity).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: pnpm artifact integrity is invalid ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let mut unreachable = Vec::new();
    let mut cached = Vec::new();
    for digest in &candidates {
        let cache_path = store.cache_path(digest.algo(), digest.hex());
        match fetch::read_cache_verified_digest(store, activity, digest) {
            Ok(bytes) => {
                let actual = algo.hex_digest(&bytes);
                if actual == expected.hex.to_ascii_lowercase() {
                    return Ok(());
                }
                cached.push(actual);
            }
            Err(error) => unreachable.push(format!("{} ({error})", cache_path.display())),
        }
    }
    if cached.is_empty() {
        return Err(other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: verified pnpm artifact cache {} is not reachable; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache",
            unreachable.join(", ")
        )));
    }
    Err(other(format!(
        "x: Corepack {name} mismatch for {package}@{version}: packageManager declares {}, cached pnpm tarball has {}; nothing runs",
        expected.hex,
        cached.join(" or ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    /// A store holding `cached` under its sha512 digest, and a project whose
    /// node closure lists pnpm@`version` with an integrity allowing both
    /// `cached` and the never-cached `other` bytes.
    fn two_hash_fixture(cached: &[u8], other: &[u8], version: &str) -> (TempDir, Store) {
        let scratch = TempDir::named("corepack-two-hash");
        let root = scratch.0.join("store");
        for subdir in ["objects", "meta", "cache/sha512", "tmp"] {
            fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let sri = |bytes: &[u8]| {
            format!(
                "sha512-{}",
                crate::kernel::base64::encode(&Sha512::digest(bytes))
            )
        };
        fs::write(
            store.cache_path("sha512", &hex::encode(Sha512::digest(cached))),
            cached,
        )
        .unwrap();
        let project = scratch.0.join("project");
        fs::create_dir_all(project.join(".tog/closures")).unwrap();
        let envelope = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "node",
            "body": {
                "packages": [{
                    "path": "node_modules/pnpm",
                    "name": "pnpm",
                    "version": version,
                    "integrity": format!("{} {}", sri(other), sri(cached)),
                }],
            },
        });
        fs::write(
            project.join(".tog/closures/node.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        (scratch, store)
    }

    #[test]
    fn corepack_hash_matches_whichever_allowed_tarball_is_cached() {
        let (scratch, store) = two_hash_fixture(b"the pnpm tarball", b"its other build", "9.12.3");
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let project = scratch.0.join("project");
        let expected = CorepackHash {
            algo: CorepackAlgo::Sha256,
            hex: hex::encode(Sha256::digest(b"the pnpm tarball")),
        };
        verify_corepack_hash(&store, &activity, &project, "pnpm", "9.12.3", &expected)
            .expect("the cached candidate carries the declared hash");

        let wrong = CorepackHash {
            hex: hex::encode(Sha256::digest(b"its other build")),
            ..expected.clone()
        };
        let mismatch = verify_corepack_hash(&store, &activity, &project, "pnpm", "9.12.3", &wrong)
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("sha256 mismatch"), "{mismatch}");
        assert!(mismatch.contains(&expected.hex), "{mismatch}");

        // With no candidate's tarball in the cache there is nothing to hash.
        let digest = fetch::Digest::from_sri(&format!(
            "sha512-{}",
            crate::kernel::base64::encode(&Sha512::digest(b"the pnpm tarball"))
        ))
        .unwrap();
        fs::remove_file(store.cache_path(digest.algo(), digest.hex())).unwrap();
        let unreachable =
            verify_corepack_hash(&store, &activity, &project, "pnpm", "9.12.3", &expected)
                .unwrap_err()
                .to_string();
        assert!(unreachable.contains("is not reachable"), "{unreachable}");
        assert!(unreachable.contains(digest.hex()), "{unreachable}");
    }

    #[test]
    fn exact_node_tool_versions_are_full_releases() {
        assert!(is_exact_version("9.1.2"));
        assert!(is_exact_version("9.1.2-rc.1"));
        assert!(is_exact_version("9.12.3-beta.0"));
        for version in [
            "9",
            "9.x",
            "^9.1.0",
            "latest",
            "9.01.2",
            "9.1.2+build",
            "9.12.3-beta.01",
        ] {
            assert!(
                !is_exact_version(version),
                "accepted floating version {version}"
            );
        }
    }
}

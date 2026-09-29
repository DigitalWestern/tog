//! Corepack's `packageManager` pin for the pnpm a Node edit runs: the exact
//! release it names, the optional `+<algo>.<hex>` hash suffix, and the
//! check that the pnpm tarball tog realized has that hash.

use crate::comforter;
use crate::kernel::activity::StoreActivity;
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
    let digest = fetch::Digest::from_sri(integrity).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: pnpm artifact integrity is invalid ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let cache_path = store.cache_path(digest.algo(), digest.hex());
    let bytes = fetch::read_cache_verified_digest(store, activity, &digest).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager {name} for {package}@{version}: verified pnpm artifact cache {} is not reachable ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache",
            cache_path.display()
        ))
    })?;
    let actual = algo.hex_digest(&bytes);
    if actual != expected.hex.to_ascii_lowercase() {
        return Err(other(format!(
            "x: Corepack {name} mismatch for {package}@{version}: packageManager declares {}, cached pnpm tarball has {actual}; nothing runs",
            expected.hex
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

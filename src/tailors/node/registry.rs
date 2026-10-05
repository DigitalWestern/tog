//! The npm registry protocol (node tailor), as tog's resolution proxy
//! serves it to npm and pnpm.
//!
//! Both tools reach the registry through TLS interception, not a mirror:
//! `package-lock.json` and `pnpm-lock.yaml` record the registry's own
//! tarball URLs (`resolved`), so the proxy terminates the tools' tunnels to
//! `registry.npmjs.org` and serves what they ask for there through this
//! route:
//!
//! - `/<name>` and `/@<scope>%2f<name>` (npm's spelling; pnpm and the
//!   plain `/@<scope>/<name>` are taken too): the packument, full or
//!   abbreviated (`application/vnd.npm.install-v1+json`, which pnpm asks
//!   for). Each version's `dist` names its tarball and its `integrity`
//!   (an SRI list, sha512 for anything published since 2017) or only a
//!   `shasum` (sha1). Those are the route's claims; a sha1-only claim is
//!   `weak-integrity`.
//! - `/<name>/-/<name>-<version>.tgz` and
//!   `/@<scope>/<name>/-/<name>-<version>.tgz`: the tarball, verified
//!   against its packument's claim.
//!
//! Anything else on the host is refused, which covers npm's audit `POST`
//! and update-notifier fetch should a flag ever fail to turn them off. A
//! scoped registry in `.npmrc`, a direct-URL dependency, and a git
//! dependency are not this route's: they reach the proxy as unattested
//! hosts or git fetches (see `kernel::resolve::intercept`).

use crate::kernel::digest::strongest_sri;
use crate::kernel::fetch::Digest;
use crate::kernel::resolve::routes::{
    Claim, Endpoint, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id the ledger and the diagnostics name.
pub const ROUTE_ID: &str = "npm";
/// The public registry, and the only host this route serves.
pub const REGISTRY_HOST: &str = "registry.npmjs.org";
/// The registry as the tools are told it, with the trailing slash npm's
/// own default carries.
pub const REGISTRY_URL: &str = "https://registry.npmjs.org/";

/// The longest package name npm accepts (scope included).
const MAX_NAME: usize = 214;
/// The longest version this grammar accepts.
const MAX_VERSION: usize = 256;

/// The npm registry protocol.
pub struct NpmRegistry;

pub static NPM_REGISTRY: NpmRegistry = NpmRegistry;

impl RegistryProtocol for NpmRegistry {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a registry request carries no query"));
        }
        check_path(path).map_err(|why| refused(path, &why))?;
        let endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.host() == REGISTRY_HOST)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the npm route has no {REGISTRY_HOST} endpoint"),
                )
            })?;
        Ok(Upstream::Fetch(endpoint.url(path)?))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        if is_tarball_path(url.path()) {
            RequestClass::Artifact
        } else {
            RequestClass::Metadata
        }
    }

    /// Each version's tarball on the registry host, claimed by its
    /// `integrity` (the strongest entry) or, failing that, its `shasum`.
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        if url.host_str() != Some(REGISTRY_HOST) || is_tarball_path(url.path()) {
            return Vec::new();
        }
        let Ok(packument) = serde_json::from_slice::<serde_json::Value>(body) else {
            return Vec::new();
        };
        let Some(versions) = packument.get("versions").and_then(|v| v.as_object()) else {
            return Vec::new();
        };
        versions
            .values()
            .filter_map(|version| {
                let dist = version.get("dist")?;
                let tarball = Url::parse(dist.get("tarball")?.as_str()?).ok()?;
                if tarball.host_str() != Some(REGISTRY_HOST) || !is_tarball_path(tarball.path()) {
                    return None;
                }
                let digest = dist_digest(dist)?;
                Some((tarball, Claim(digest)))
            })
            .collect()
    }

    /// The registry publishes a digest for every tarball.
    fn expects_claim(&self, url: &Url) -> bool {
        url.host_str() == Some(REGISTRY_HOST) && is_tarball_path(url.path())
    }

    /// Scoped packuments are spelled `/@scope%2fname`.
    fn encoded_slash(&self) -> bool {
        true
    }
}

/// The digest a `dist` object claims for its tarball: the strongest
/// `integrity` entry, else the sha1 `shasum`. `None` when it claims
/// nothing tog can read (an unknown algorithm, malformed hex).
fn dist_digest(dist: &serde_json::Value) -> Option<Digest> {
    if let Some(list) = dist.get("integrity").and_then(|i| i.as_str()) {
        if let Some(sri) = strongest_sri(list) {
            return Digest::from_sri(sri).ok();
        }
    }
    Digest::sha1(dist.get("shasum")?.as_str()?).ok()
}

/// Whether `path` is a tarball's (`/.../-/<file>.tgz`).
fn is_tarball_path(path: &str) -> bool {
    check_tarball_path(path).is_ok()
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("npm registry path {path:?} refused: {why}"),
    )
}

/// A packument or a tarball path, else why not.
fn check_path(path: &str) -> Result<(), String> {
    match check_packument_path(path) {
        Ok(()) => Ok(()),
        Err(packument_why) => check_tarball_path(path).map_err(|tarball_why| {
            format!("not a packument ({packument_why}) or a tarball ({tarball_why})")
        }),
    }
}

/// `/<name>`, `/@<scope>%2f<name>` (either case), or `/@<scope>/<name>`.
fn check_packument_path(path: &str) -> Result<(), String> {
    let rest = path.strip_prefix('/').ok_or("not an absolute path")?;
    if let Some(scoped) = rest.strip_prefix('@') {
        let (scope, name) = split_scope(scoped).ok_or("a scoped name is @scope/name")?;
        check_segment(scope, "scope")?;
        check_segment(name, "package name")?;
        if scoped.len() + 1 > MAX_NAME {
            return Err(format!("{rest:?} is longer than {MAX_NAME} characters"));
        }
        return Ok(());
    }
    check_segment(rest, "package name")?;
    if rest.len() > MAX_NAME {
        return Err(format!("{rest:?} is longer than {MAX_NAME} characters"));
    }
    Ok(())
}

/// A scoped name after its `@`, split at the first `/`, `%2f`, or `%2F`.
fn split_scope(scoped: &str) -> Option<(&str, &str)> {
    let slash = scoped.find('/');
    let encoded = scoped.find("%2f").or_else(|| scoped.find("%2F"));
    match (slash, encoded) {
        (Some(slash), Some(encoded)) if encoded < slash => {
            Some((&scoped[..encoded], &scoped[encoded + 3..]))
        }
        (Some(slash), _) => Some((&scoped[..slash], &scoped[slash + 1..])),
        (None, Some(encoded)) => Some((&scoped[..encoded], &scoped[encoded + 3..])),
        (None, None) => None,
    }
}

/// `/<name>/-/<name>-<version>.tgz` or `/@<scope>/<name>/-/<name>-<version>.tgz`.
fn check_tarball_path(path: &str) -> Result<(), String> {
    let rest = path.strip_prefix('/').ok_or("not an absolute path")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let (name, file) = match parts.as_slice() {
        [name, "-", file] => (*name, *file),
        [scope, name, "-", file] => {
            let scope = scope.strip_prefix('@').ok_or("a scope starts with @")?;
            check_segment(scope, "scope")?;
            (*name, *file)
        }
        _ => return Err("a tarball is /<name>/-/<name>-<version>.tgz".into()),
    };
    check_segment(name, "package name")?;
    let version = file
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('-'))
        .and_then(|rest| rest.strip_suffix(".tgz"))
        .ok_or_else(|| format!("{file:?} is not <name>-<version>.tgz for {name:?}"))?;
    check_version(version)
}

/// One name part (a scope without its `@`, or a package name): the
/// URL-safe characters npm accepts, not starting with a `.`.
fn check_segment(segment: &str, what: &str) -> Result<(), String> {
    let valid = !segment.is_empty()
        && !segment.starts_with('.')
        && segment.len() <= MAX_NAME
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'));
    if valid {
        Ok(())
    } else {
        Err(format!("{segment:?} is not a {what}"))
    }
}

/// A version as npm spells it in a tarball name: starting with a digit,
/// semver's characters.
fn check_version(version: &str) -> Result<(), String> {
    let valid = !version.is_empty()
        && version.len() <= MAX_VERSION
        && version.bytes().next().is_some_and(|b| b.is_ascii_digit())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    if valid {
        Ok(())
    } else {
        Err(format!("{version:?} is not a package version"))
    }
}

/// The npm route: the public registry.
pub fn route() -> io::Result<Route> {
    Route::new(&NPM_REGISTRY, vec![Endpoint::https(REGISTRY_HOST)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Vec<Endpoint> {
        vec![Endpoint::https(REGISTRY_HOST).unwrap()]
    }

    fn fetch(path: &str) -> String {
        match NPM_REGISTRY.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    #[test]
    fn packuments_and_tarballs_map_onto_the_registry_as_spelled() {
        for path in [
            "/is-odd",
            "/@types%2fnode",
            "/@types%2Fnode",
            "/@types/node",
            "/is-odd/-/is-odd-3.0.1.tgz",
            "/@types/node/-/node-20.1.0-beta.1.tgz",
            "/lodash.merge/-/lodash.merge-4.6.2.tgz",
            "/@babel%2fcore",
        ] {
            assert_eq!(fetch(path), format!("https://{REGISTRY_HOST}{path}"));
        }
        let packument = Url::parse("https://registry.npmjs.org/@types%2fnode").unwrap();
        let tarball = Url::parse("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz").unwrap();
        assert_eq!(NPM_REGISTRY.classify(&packument), RequestClass::Metadata);
        assert_eq!(NPM_REGISTRY.classify(&tarball), RequestClass::Artifact);
        assert!(NPM_REGISTRY.expects_claim(&tarball));
        assert!(!NPM_REGISTRY.expects_claim(&packument));
        assert!(NPM_REGISTRY.encoded_slash());
    }

    #[test]
    fn the_npm_grammar_refuses_everything_else() {
        for (path, needle) in [
            ("/is-odd?write=true", "no query"),
            ("/-/npm/v1/security/advisories/bulk", "not a packument"),
            ("/npm/-/npm-11.0.0.tgz/extra", "not a packument"),
            ("/.hidden", "not a package name"),
            ("/@scope", "@scope/name"),
            ("/@scope%2f", "not a package name"),
            ("/@/name", "not a scope"),
            ("/is-odd/-/is-even-3.0.1.tgz", "is not <name>-<version>.tgz"),
            ("/is-odd/-/is-odd-latest.tgz", "not a package version"),
            ("/is-odd/-/is-odd-3.0.1.tar", "is not <name>-<version>.tgz"),
            ("/a b", "not a package name"),
            ("is-odd", "not an absolute path"),
        ] {
            let error = NPM_REGISTRY
                .upstream(&endpoints(), path)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{path}: {error}");
        }
        assert!(NPM_REGISTRY
            .upstream(&endpoints(), &format!("/{}", "a".repeat(MAX_NAME + 1)))
            .is_err());
    }

    /// The recorded `is-odd` packument (npm's full form and pnpm's
    /// abbreviated form alike) claims the recorded tarball's sha512, and a
    /// version with only a `shasum` claims sha1, which is weak.
    #[test]
    fn packuments_claim_their_tarballs() {
        use sha2::{Digest as _, Sha512};
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy/registry");
        let tarball = Url::parse("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz").unwrap();
        let bytes =
            std::fs::read(fixtures.join("npm/registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz.body"))
                .unwrap();
        let assert_sha512 = |claim: &Claim| {
            assert_eq!(claim.0.algo(), "sha512");
            assert_eq!(claim.0.hex(), hex::encode(Sha512::digest(&bytes)));
        };
        for registry in ["npm", "pnpm"] {
            let body = std::fs::read(
                fixtures
                    .join(registry)
                    .join("registry.npmjs.org/is-odd.body"),
            )
            .unwrap();
            let url = Url::parse("https://registry.npmjs.org/is-odd").unwrap();
            let claims = NPM_REGISTRY.claims(&url, &body);
            let (_, claim) = claims
                .iter()
                .find(|(url, _)| *url == tarball)
                .unwrap_or_else(|| panic!("{registry}: no claim for the tarball"));
            assert_sha512(claim);
            assert!(!claim.is_weak());
            assert!(claims.len() > 1, "{registry}: every version is claimed");
        }
        let weak = serde_json::json!({
            "versions": {
                "0.1.0": {"dist": {
                    "tarball": "https://registry.npmjs.org/old/-/old-0.1.0.tgz",
                    "shasum": "4407a37a7fd8e4ef6e5b0a5a6b8a3b1e3c2d1f0e"}},
                "0.2.0": {"dist": {
                    "tarball": "https://elsewhere.test/old/-/old-0.2.0.tgz",
                    "integrity": "sha512-CQpnWPrDwmP1+SMHXZhtLtJv90yiyVfluGsX5iNCVkrhQtU3TQHsUWPG9wkdk9Lgd5yNpAg9jQEo90CBaXgWMA=="}},
                "0.3.0": {"dist": {
                    "tarball": "https://registry.npmjs.org/old/-/old-0.3.0.tgz",
                    "integrity": "md5-AAAA"}}
            }
        });
        let url = Url::parse("https://registry.npmjs.org/old").unwrap();
        let claims = NPM_REGISTRY.claims(&url, weak.to_string().as_bytes());
        assert_eq!(claims.len(), 1, "{claims:?}");
        assert_eq!(
            claims[0].0.as_str(),
            "https://registry.npmjs.org/old/-/old-0.1.0.tgz"
        );
        assert!(claims[0].1.is_weak());
        assert!(NPM_REGISTRY.claims(&tarball, b"not json").is_empty());
    }

    #[test]
    fn the_route_reaches_only_the_registry() {
        let route = route().unwrap();
        let hosts: Vec<&str> = route.endpoints.iter().map(Endpoint::host).collect();
        assert_eq!(hosts, vec![REGISTRY_HOST]);
        assert!(route.resolve("/@types%2fnode").is_ok());
        assert!(route.resolve("/@types%2f..").is_err());
    }
}

//! crates.io's sparse registry protocol, as tog's resolution proxy serves
//! it. It lives in the kernel because two tailors run cargo through the
//! door: the Cargo tailor, and Python for an sdist's Rust extension
//! ([`super::cargo_door`]).
//!
//! cargo reaches crates.io through TLS interception, not a mirror: its
//! lock records `registry+https://github.com/rust-lang/crates.io-index`
//! whatever the transport, so the proxy terminates cargo's tunnels to
//! `index.crates.io` and `static.crates.io` and serves what cargo asks
//! for there through this route:
//!
//! - `/config.json` on `index.crates.io`: the registry's configuration,
//!   whose `dl` sends downloads to `static.crates.io` (no `crates.io`
//!   redirect).
//! - `/1/<name>`, `/2/<name>`, `/3/<c>/<name>`, `/<ab>/<cd>/<name>` on
//!   `index.crates.io`: a crate's index file, one JSON line per version,
//!   each with the `cksum` (sha256) of its `.crate`. Those are the route's
//!   claims.
//! - `/crates/<name>/<version>/download` on `static.crates.io`: the
//!   `.crate` itself, verified against its index line's claim.
//!
//! Anything else on those two hosts is refused. Git dependencies and other
//! registries are not this route's: they reach the proxy as git fetches or
//! unattested hosts (see `kernel::resolve::intercept`).

use crate::kernel::fetch::Digest;
use crate::kernel::resolve::routes::{
    Claim, Endpoint, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id the ledger and the diagnostics name.
pub const ROUTE_ID: &str = "crates";
/// The sparse index and the download host its `config.json` names.
pub const INDEX_HOST: &str = "index.crates.io";
pub const DOWNLOAD_HOST: &str = "static.crates.io";

/// The longest crate name crates.io accepts.
const MAX_NAME: usize = 64;
/// The longest version this grammar accepts.
const MAX_VERSION: usize = 128;

/// crates.io's sparse index protocol.
pub struct CratesSparse;

pub static CRATES_SPARSE: CratesSparse = CratesSparse;

impl RegistryProtocol for CratesSparse {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a crates.io request carries no query"));
        }
        if path == "/config.json" || check_index_path(path).is_ok() {
            return Ok(Upstream::Fetch(endpoint(endpoints, INDEX_HOST)?.url(path)?));
        }
        if path.starts_with("/crates/") {
            check_download_path(path).map_err(|why| refused(path, &why))?;
            return Ok(Upstream::Fetch(
                endpoint(endpoints, DOWNLOAD_HOST)?.url(path)?,
            ));
        }
        let why = check_index_path(path).unwrap_err();
        Err(refused(path, &why))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        if url.host_str() == Some(DOWNLOAD_HOST) {
            RequestClass::Artifact
        } else if url.path() == "/config.json" {
            RequestClass::Metadata
        } else {
            RequestClass::Index
        }
    }

    /// Each index line's `cksum`, for the download of its version.
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        if url.host_str() != Some(INDEX_HOST) || url.path() == "/config.json" {
            return Vec::new();
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| {
                let entry: serde_json::Value = serde_json::from_str(line).ok()?;
                let name = entry.get("name")?.as_str()?;
                let version = entry.get("vers")?.as_str()?;
                let digest = Digest::sha256(entry.get("cksum")?.as_str()?).ok()?;
                let download = download_url(name, version)?;
                Some((download, Claim::one(digest)))
            })
            .collect()
    }

    /// crates.io publishes a sha256 for every `.crate`.
    fn expects_claim(&self, url: &Url) -> bool {
        url.host_str() == Some(DOWNLOAD_HOST)
    }
}

/// Where cargo downloads `name` at `version` from (`config.json`'s `dl`,
/// `https://static.crates.io/crates`, with cargo's default template).
fn download_url(name: &str, version: &str) -> Option<Url> {
    check_name(name).ok()?;
    check_version(version).ok()?;
    Url::parse(&format!(
        "https://{DOWNLOAD_HOST}/crates/{name}/{version}/download"
    ))
    .ok()
}

/// The route endpoint on `host`, which a crates route always has.
fn endpoint<'a>(endpoints: &'a [Endpoint], host: &str) -> io::Result<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.host() == host)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the crates route has no {host} endpoint"),
            )
        })
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("crates.io path {path:?} refused: {why}"),
    )
}

/// A sparse index file's path: the lowercased name under the prefix
/// directories its length decides.
fn check_index_path(path: &str) -> Result<(), String> {
    let parts: Vec<&str> = path
        .strip_prefix('/')
        .ok_or("not an absolute path")?
        .split('/')
        .collect();
    let name = *parts.last().unwrap_or(&"");
    check_name(name)?;
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!("{name:?}: index paths are lowercase"));
    }
    let expected: Vec<String> = match name.len() {
        1 => vec!["1".into()],
        2 => vec!["2".into()],
        3 => vec!["3".into(), name[..1].into()],
        _ => vec![name[..2].into(), name[2..4].into()],
    };
    let prefix = &parts[..parts.len() - 1];
    if prefix.len() != expected.len() || prefix.iter().zip(&expected).any(|(a, b)| a != b) {
        return Err(format!(
            "{path:?} is not config.json, an index file, or a download"
        ));
    }
    Ok(())
}

/// `/crates/<name>/<version>/download`.
fn check_download_path(path: &str) -> Result<(), String> {
    let rest = path.strip_prefix("/crates/").ok_or("not a download")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let [name, version, "download"] = parts.as_slice() else {
        return Err("a download is /crates/<name>/<version>/download".into());
    };
    check_name(name)?;
    check_version(version)
}

/// A crate name: ASCII letters, digits, `-` and `_`, starting with a
/// letter or `_`.
fn check_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(format!("{name:?} is not a crate name"))
    }
}

/// A semver version: ASCII letters, digits, `.`, `-` and `+`.
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
        Err(format!("{version:?} is not a crate version"))
    }
}

/// The crates.io route: the sparse index and its download host.
pub fn route() -> io::Result<Route> {
    Route::new(
        &CRATES_SPARSE,
        vec![
            Endpoint::https(INDEX_HOST)?,
            Endpoint::https(DOWNLOAD_HOST)?,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::https(INDEX_HOST).unwrap(),
            Endpoint::https(DOWNLOAD_HOST).unwrap(),
        ]
    }

    fn fetch(path: &str) -> String {
        match CRATES_SPARSE.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    #[test]
    fn sparse_paths_map_to_the_index_and_downloads_to_static() {
        for path in [
            "/config.json",
            "/1/a",
            "/2/cc",
            "/3/r/ryu",
            "/it/oa/itoa",
            "/se/rd/serde_json",
            "/_a/bc/_abc",
        ] {
            assert_eq!(fetch(path), format!("https://{INDEX_HOST}{path}"));
        }
        assert_eq!(
            fetch("/crates/itoa/1.0.18/download"),
            "https://static.crates.io/crates/itoa/1.0.18/download"
        );
    }

    #[test]
    fn the_crates_grammar_refuses_everything_else() {
        for (path, needle) in [
            ("/config.json?x=1", "no query"),
            ("/it/oa/Itoa", "lowercase"),
            ("/3/x/ryu", "not config.json"),
            ("/1/ab", "not config.json"),
            ("/it/itoa", "not config.json"),
            ("/api/v1/crates/itoa", "not config.json"),
            ("/crates/itoa/1.0.18", "a download is"),
            ("/crates/itoa/latest/download", "not a crate version"),
            ("/crates/-x/1.0.0/download", "not a crate name"),
        ] {
            let error = CRATES_SPARSE
                .upstream(&endpoints(), path)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{path}: {error}");
        }
    }

    /// Every index line's `cksum` claims its version's download; the
    /// recorded itoa index claims the recorded download's digest.
    #[test]
    fn index_lines_claim_their_downloads() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/registry/cargo");
        let body = std::fs::read(fixture.join("index.crates.io/it/oa/itoa.body")).unwrap();
        let index = Url::parse("https://index.crates.io/it/oa/itoa").unwrap();
        let claims = CRATES_SPARSE.claims(&index, &body);
        assert_eq!(
            claims.len(),
            body.split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .count()
        );
        let download = Url::parse("https://static.crates.io/crates/itoa/1.0.18/download").unwrap();
        let (_, claim) = claims.iter().find(|(url, _)| *url == download).unwrap();
        let crate_bytes =
            std::fs::read(fixture.join("static.crates.io/crates/itoa/1.0.18/download.body"))
                .unwrap();
        use sha2::{Digest as _, Sha256};
        assert_eq!(
            claim.digests()[0].hex(),
            hex::encode(Sha256::digest(&crate_bytes))
        );
        assert!(CRATES_SPARSE.expects_claim(&download));
        assert!(!CRATES_SPARSE.expects_claim(&index));
        let config = Url::parse("https://index.crates.io/config.json").unwrap();
        assert!(CRATES_SPARSE.claims(&config, b"{}").is_empty());
        assert_eq!(CRATES_SPARSE.classify(&config), RequestClass::Metadata);
        assert_eq!(CRATES_SPARSE.classify(&index), RequestClass::Index);
        assert_eq!(CRATES_SPARSE.classify(&download), RequestClass::Artifact);
    }

    #[test]
    fn the_route_reaches_only_the_two_crates_hosts() {
        let route = route().unwrap();
        let hosts: Vec<&str> = route.endpoints.iter().map(Endpoint::host).collect();
        assert_eq!(hosts, vec![INDEX_HOST, DOWNLOAD_HOST]);
    }
}

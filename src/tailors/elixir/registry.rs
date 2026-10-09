//! The Hex repository protocol, as tog's resolution proxy serves it to mix.
//!
//! Hex reaches repo.hex.pm through a mirror, not interception: `HEX_MIRROR`
//! names the session's route, and mix.lock records no repository URL, so
//! a mirror leaves the lock as it would be. Hex then asks the mirror for
//! these paths, each mapped to the same path on `https://repo.hex.pm`:
//!
//! - `/packages/<name>`: one package's signed release list (Metadata).
//! - `/tarballs/<name>-<version>.tar`: a release tarball (Artifact).
//! - `/names` and `/versions`: the signed listings (Index).
//! - `/installs/hex-1.x.csv`: Hex's own update check (Metadata). repo.hex.pm
//!   redirects it to builds.hex.pm, which no route permits, so the check
//!   fails closed and mix carries on with the Hex it has.
//!
//! Anything else is refused: a query string, an organization's
//! `/repos/<org>/...` (private packages need a key tog does not hand to a
//! resolver), `/docs/`, and any name outside Hex's package grammar. The
//! registry bodies are signed protobufs Hex verifies itself, so the route
//! makes no claim; tog verifies each tarball's checksums from mix.lock when
//! it realizes the dependencies.

use crate::kernel::resolve::routes::{
    Claim, Endpoint, ProxyAddress, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id in mirror URLs: `http://<relay>/<token>/hex/...`.
pub const ROUTE_ID: &str = "hex";
/// The Hex repository host.
pub const REPO_HOST: &str = "repo.hex.pm";

/// The longest package name or tarball stem the grammar accepts.
const MAX_WORD: usize = 256;

/// The Hex repository: registry reads and tarballs.
pub struct HexRepo;

pub static HEX_REPO: HexRepo = HexRepo;

impl RegistryProtocol for HexRepo {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a Hex request carries no query"));
        }
        let served = match path {
            "/names" | "/versions" | "/installs/hex-1.x.csv" => true,
            _ => {
                if let Some(name) = path.strip_prefix("/packages/") {
                    check_name(name).map_err(|why| refused(path, &why))?;
                    true
                } else if let Some(file) = path.strip_prefix("/tarballs/") {
                    let stem = file
                        .strip_suffix(".tar")
                        .ok_or_else(|| refused(path, "not a .tar file"))?;
                    check_tarball(stem).map_err(|why| refused(path, &why))?;
                    true
                } else {
                    false
                }
            }
        };
        if !served {
            return Err(refused(
                path,
                "only /packages/<name>, /tarballs/<name>-<version>.tar, /names, /versions and \
                 Hex's update check are served",
            ));
        }
        let endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.host() == REPO_HOST)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the Hex route has no {REPO_HOST} endpoint"),
                )
            })?;
        Ok(Upstream::Fetch(endpoint.url(path)?))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        let path = url.path();
        if path.starts_with("/tarballs/") {
            RequestClass::Artifact
        } else if path.starts_with("/packages/") || path.starts_with("/installs/") {
            RequestClass::Metadata
        } else {
            RequestClass::Index
        }
    }

    fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
        Vec::new()
    }
}

/// A Hex package name: `[a-z][a-z0-9_]*`, as Hex itself requires.
fn check_name(name: &str) -> Result<(), String> {
    let mut bytes = name.bytes();
    let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
    if !first_ok
        || name.len() > MAX_WORD
        || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(format!("{name:?} is not a Hex package name"));
    }
    Ok(())
}

/// A tarball stem: `<name>-<version>`, the version a semantic version's
/// characters.
fn check_tarball(stem: &str) -> Result<(), String> {
    let (name, version) = stem
        .split_once('-')
        .ok_or_else(|| format!("{stem:?} is not <name>-<version>"))?;
    check_name(name)?;
    if version.is_empty()
        || version.len() > MAX_WORD
        || !version.starts_with(|c: char| c.is_ascii_digit())
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(format!("{version:?} is not a Hex version"));
    }
    Ok(())
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("Hex path {path:?} refused: {why}"),
    )
}

/// What points Hex at a session: the repository mirrored to the route, and
/// the proxy (with the session token) for any other https source, which
/// the door refuses visibly. No `http_proxy`: the mirror is plain http on
/// the relay, and the proxy refuses an absolute-form request.
pub fn proxy_env(address: &ProxyAddress) -> Vec<(String, String)> {
    let base = address.route_base(ROUTE_ID);
    let mirror_host = Url::parse(&base)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    vec![
        (
            "HEX_MIRROR".to_string(),
            base.trim_end_matches('/').to_string(),
        ),
        ("https_proxy".to_string(), address.proxy_url()),
        ("no_proxy".to_string(), mirror_host),
    ]
}

/// The Hex route: repo.hex.pm alone.
pub fn route() -> io::Result<Route> {
    Route::new(&HEX_REPO, vec![Endpoint::https(REPO_HOST)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(path: &str) -> io::Result<String> {
        let endpoints = vec![Endpoint::https(REPO_HOST).unwrap()];
        match HEX_REPO.upstream(&endpoints, path)? {
            Upstream::Fetch(url) => Ok(url.to_string()),
            #[allow(unreachable_patterns)]
            _ => panic!("not a fetch"),
        }
    }

    #[test]
    fn registry_reads_and_tarballs_map_to_repo_hex_pm() {
        assert_eq!(
            upstream("/packages/jason").unwrap(),
            "https://repo.hex.pm/packages/jason"
        );
        assert_eq!(
            upstream("/tarballs/jason-1.4.5.tar").unwrap(),
            "https://repo.hex.pm/tarballs/jason-1.4.5.tar"
        );
        assert_eq!(
            upstream("/tarballs/plug_crypto-2.0.0-rc.1.tar").unwrap(),
            "https://repo.hex.pm/tarballs/plug_crypto-2.0.0-rc.1.tar"
        );
        assert_eq!(upstream("/names").unwrap(), "https://repo.hex.pm/names");
        assert_eq!(
            upstream("/installs/hex-1.x.csv").unwrap(),
            "https://repo.hex.pm/installs/hex-1.x.csv"
        );
    }

    #[test]
    fn everything_else_is_refused() {
        for path in [
            "/packages/jason?x=1",
            "/repos/acme/packages/secret",
            "/docs/jason-1.4.5.tar.gz",
            "/packages/Jason",
            "/packages/../names",
            "/packages/",
            "/tarballs/jason.tar",
            "/tarballs/jason-1.4.5.tar.gz",
            "/tarballs/jason-x.tar",
            "/installs/rebar3-1.x.csv",
            "/",
        ] {
            assert!(upstream(path).is_err(), "{path} was served");
        }
    }

    #[test]
    fn tarballs_are_artifacts_and_packages_metadata() {
        let class = |path: &str| {
            HEX_REPO.classify(&Url::parse(&format!("https://repo.hex.pm{path}")).unwrap())
        };
        assert!(matches!(
            class("/tarballs/jason-1.4.5.tar"),
            RequestClass::Artifact
        ));
        assert!(matches!(class("/packages/jason"), RequestClass::Metadata));
        assert!(matches!(class("/names"), RequestClass::Index));
    }
}

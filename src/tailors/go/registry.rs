//! Go's module proxy protocol, as tog's resolution proxy serves it.
//!
//! The store go is pointed at the proxy with
//! `GOPROXY=http://<relay>/<token>/go/` (no `direct`) and
//! `GOSUMDB=sum.golang.org`. It then asks for these paths, each mapped
//! here to its upstream:
//!
//! - `/<module>/@v/list`, `/<module>/@v/<version>.info`, `.mod`, `.zip`, and
//!   `/<module>/@latest` go to `https://proxy.golang.org` unchanged. The
//!   import-path prefixes `go get` probes (`/github.com/@v/list`) are the
//!   same grammar, and proxy.golang.org's 404 for them is passed through.
//! - `/sumdb/sum.golang.org/supported` is answered by the proxy itself with
//!   200. Both upstream hosts answer it 404, which would send go straight
//!   to sum.golang.org outside the proxy.
//! - `/sumdb/sum.golang.org/<rest>` (`latest`, `lookup/...`, `tile/...`) goes
//!   to `https://sum.golang.org/<rest>` byte-for-byte. go verifies the
//!   signed tree note itself, so the proxy claims nothing about it.
//!
//! Anything else is refused: another checksum database, a query string, a
//! module or version outside go's escaped spelling, and the
//! `golang.org/toolchain` module (the forced `GOTOOLCHAIN=local` means go
//! never asks for it; a request for it is a broken setting, not a lookup).
//! go checks every module it fetches against go.sum and the checksum
//! database, so the protocol publishes no claims.

use crate::kernel::resolve::routes::{
    Claim, Endpoint, LocalAnswer, ProxyAddress, RegistryProtocol, RequestClass, Upstream,
};
use std::io;
use url::Url;

/// The route id in mirror URLs: `http://<relay>/<token>/go/...`.
pub const ROUTE_ID: &str = "go";
/// The module proxy and the checksum database go is pointed at.
pub const PROXY_HOST: &str = "proxy.golang.org";
pub const SUMDB_HOST: &str = "sum.golang.org";
/// The only checksum database the route serves; `GOSUMDB` names it.
pub const SUMDB_NAME: &str = "sum.golang.org";

/// The longest module path or version the grammar accepts.
const MAX_WORD: usize = 512;

/// Go's module proxy protocol.
pub struct GoProxy;

pub static GO_PROXY: GoProxy = GoProxy;

impl RegistryProtocol for GoProxy {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a Go proxy request carries no query"));
        }
        let sumdb_prefix = format!("/sumdb/{SUMDB_NAME}/");
        if let Some(rest) = path.strip_prefix(&sumdb_prefix) {
            let sumdb = endpoint(endpoints, SUMDB_HOST)?;
            if rest == "supported" {
                return Ok(Upstream::Local(LocalAnswer {
                    url: sumdb.url("/supported")?,
                    status: 200,
                    content_type: "text/plain; charset=utf-8".into(),
                    body: Vec::new(),
                }));
            }
            check_sumdb_path(rest).map_err(|why| refused(path, &why))?;
            return Ok(Upstream::Fetch(sumdb.url(&format!("/{rest}"))?));
        }
        if path.starts_with("/sumdb/") {
            return Err(refused(
                path,
                &format!("the only checksum database is {SUMDB_NAME}"),
            ));
        }
        check_module_path(path).map_err(|why| refused(path, &why))?;
        Ok(Upstream::Fetch(endpoint(endpoints, PROXY_HOST)?.url(path)?))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        let path = url.path();
        if url.host_str() == Some(SUMDB_HOST) {
            RequestClass::Sumdb
        } else if path.ends_with("/@v/list") {
            RequestClass::Index
        } else if path.ends_with(".zip") {
            RequestClass::Artifact
        } else {
            RequestClass::Metadata
        }
    }

    fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
        Vec::new()
    }
}

/// The route endpoint on `host`, which a Go route always has.
fn endpoint<'a>(endpoints: &'a [Endpoint], host: &str) -> io::Result<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.host() == host)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the Go route has no {host} endpoint"),
            )
        })
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("Go proxy path {path:?} refused: {why}"),
    )
}

/// `<module>/@v/list`, `<module>/@v/<version>.(info|mod|zip)`, or
/// `<module>/@latest`, with a leading `/`.
fn check_module_path(path: &str) -> Result<(), String> {
    let path = path
        .strip_prefix('/')
        .ok_or("not an absolute path".to_string())?;
    let (module, tail) = if let Some(module) = path.strip_suffix("/@latest") {
        (module, None)
    } else {
        let (module, rest) = path
            .split_once("/@v/")
            .ok_or("not a module proxy request (no /@v/ or /@latest)".to_string())?;
        (module, Some(rest))
    };
    check_module(module)?;
    match tail {
        None | Some("list") => Ok(()),
        Some(file) => {
            let version = [".info", ".mod", ".zip"]
                .iter()
                .find_map(|suffix| file.strip_suffix(suffix))
                .ok_or(format!("{file:?} is not list, .info, .mod or .zip"))?;
            check_version(version)
        }
    }
}

/// A module path in go's escaped spelling (`module.EscapePath`): lowercase
/// letters, digits, `.`, `-`, `_`, `~`, and `!` before a lowercase letter
/// for each uppercase one, in `/`-separated elements that neither start nor
/// end with a dot.
fn check_module(module: &str) -> Result<(), String> {
    if module.is_empty() || module.len() > MAX_WORD {
        return Err("an empty or overlong module path".into());
    }
    for element in module.split('/') {
        if element.is_empty() || element.starts_with('.') || element.ends_with('.') {
            return Err(format!("module path element {element:?} is not allowed"));
        }
        check_escaped(element, |b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'~')
        })?;
    }
    if module == "golang.org/toolchain" || module.starts_with("golang.org/toolchain/") {
        return Err(
            "a Go toolchain download; tog forces GOTOOLCHAIN=local and provides go itself".into(),
        );
    }
    Ok(())
}

/// A version in go's escaped spelling: `v`, then lowercase letters,
/// digits, `.`, `-`, `+`, and `!`-escapes.
fn check_version(version: &str) -> Result<(), String> {
    if !version.starts_with('v') || version.len() > MAX_WORD {
        return Err(format!("{version:?} is not a module version"));
    }
    check_escaped(version, |b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+')
    })
}

/// Every byte is `plain`, or `!` followed by a lowercase letter.
fn check_escaped(word: &str, plain: impl Fn(u8) -> bool) -> Result<(), String> {
    let bytes = word.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'!' {
            match bytes.get(index + 1) {
                Some(next) if next.is_ascii_lowercase() => index += 2,
                _ => return Err(format!("{word:?} has a bad ! escape")),
            }
            continue;
        }
        if !plain(byte) {
            return Err(format!("{word:?} has a byte outside go's escaped spelling"));
        }
        index += 1;
    }
    Ok(())
}

/// What go asks a checksum database for: `latest`,
/// `lookup/<module>@<version>`, or a tile
/// `tile/<height>/<level|data>/<x000/>...<000>[.p/<width>]`.
fn check_sumdb_path(rest: &str) -> Result<(), String> {
    if rest == "latest" {
        return Ok(());
    }
    if let Some(lookup) = rest.strip_prefix("lookup/") {
        let (module, version) = lookup
            .rsplit_once('@')
            .ok_or("a lookup names module@version".to_string())?;
        check_module(module)?;
        return check_version(version);
    }
    let tile = rest
        .strip_prefix("tile/")
        .ok_or(format!("{rest:?} is not latest, a lookup, or a tile"))?;
    check_tile(tile)
}

fn check_tile(tile: &str) -> Result<(), String> {
    let bad = || format!("tile/{tile} is not a checksum database tile");
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let tile = match tile.split_once(".p/") {
        Some((tile, width)) if digits(width) => tile,
        Some(_) => return Err(bad()),
        None => tile,
    };
    let parts: Vec<&str> = tile.split('/').collect();
    let [height, level, index @ ..] = parts.as_slice() else {
        return Err(bad());
    };
    if !digits(height) || !(digits(level) || *level == "data") {
        return Err(bad());
    }
    let Some((last, prefix)) = index.split_last() else {
        return Err(bad());
    };
    let three = |part: &str| part.len() == 3 && digits(part);
    let prefix_ok = prefix
        .iter()
        .all(|part| part.strip_prefix('x').is_some_and(three));
    if !prefix_ok || !three(last) {
        return Err(bad());
    }
    Ok(())
}

/// The environment that points the store go at a proxy session: the
/// session's Go mirror, the one checksum database, no VCS.
pub fn proxy_env(address: &ProxyAddress) -> Vec<(String, String)> {
    let base = address.route_base(ROUTE_ID);
    vec![
        (
            "GOPROXY".to_string(),
            base.trim_end_matches('/').to_string(),
        ),
        ("GOSUMDB".to_string(), SUMDB_NAME.to_string()),
        ("GOVCS".to_string(), "*:off".to_string()),
    ]
}

/// The Go route: the module proxy and the checksum database.
pub fn route() -> io::Result<crate::kernel::resolve::routes::Route> {
    crate::kernel::resolve::routes::Route::new(
        &GO_PROXY,
        vec![Endpoint::https(PROXY_HOST)?, Endpoint::https(SUMDB_HOST)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::https(PROXY_HOST).unwrap(),
            Endpoint::https(SUMDB_HOST).unwrap(),
        ]
    }

    fn fetch(path: &str) -> String {
        match GO_PROXY.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    fn refusal(path: &str) -> String {
        GO_PROXY
            .upstream(&endpoints(), path)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn module_proxy_paths_map_to_proxy_golang_org_unchanged() {
        for path in [
            "/github.com/google/uuid/@v/list",
            "/github.com/google/uuid/@v/v1.6.0.info",
            "/github.com/google/uuid/@v/v1.6.0.mod",
            "/github.com/google/uuid/@v/v1.6.0.zip",
            "/github.com/google/uuid/@latest",
            "/github.com/!burnt!sushi/toml/@v/v1.4.0.info",
            "/github.com/@v/list",
            "/golang.org/x/@v/v0.10.0.info",
            "/gopkg.in/yaml.v3/@v/v3.0.1+incompatible.mod",
        ] {
            assert_eq!(fetch(path), format!("https://proxy.golang.org{path}"));
        }
    }

    #[test]
    fn sumdb_paths_forward_to_sum_golang_org_and_supported_is_local() {
        for rest in [
            "latest",
            "lookup/github.com/google/uuid@v1.6.0",
            "tile/8/0/x086/534",
            "tile/8/1/989.p/52",
            "tile/8/0/x253/236.p/25",
            "tile/8/data/x001/234",
        ] {
            assert_eq!(
                fetch(&format!("/sumdb/sum.golang.org/{rest}")),
                format!("https://sum.golang.org/{rest}")
            );
        }
        match GO_PROXY
            .upstream(&endpoints(), "/sumdb/sum.golang.org/supported")
            .unwrap()
        {
            Upstream::Local(answer) => {
                assert_eq!(answer.status, 200);
                assert_eq!(answer.url.as_str(), "https://sum.golang.org/supported");
                assert!(answer.body.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn go_grammar_refuses_everything_else() {
        for (path, needle) in [
            ("/sumdb/sum.example.org/latest", "only checksum database"),
            (
                "/sumdb/sum.golang.org/tile/8/0/86/534",
                "not a checksum database tile",
            ),
            (
                "/sumdb/sum.golang.org/tile/8/0/x086/53",
                "not a checksum database tile",
            ),
            (
                "/sumdb/sum.golang.org/lookup/github.com/x",
                "module@version",
            ),
            (
                "/sumdb/sum.golang.org/other",
                "not latest, a lookup, or a tile",
            ),
            ("/github.com/google/uuid/@v/list?go-get=1", "no query"),
            ("/github.com/Google/uuid/@v/list", "escaped spelling"),
            (
                "/github.com/google/uuid/@v/1.6.0.info",
                "not a module version",
            ),
            ("/github.com/google/uuid/@v/v1.6.0.tar", "not list"),
            ("/github.com/google/uuid", "no /@v/"),
            ("/.hidden/mod/@v/list", "is not allowed"),
            ("/github.com/a!/b/@v/list", "bad ! escape"),
            (
                "/golang.org/toolchain/@v/v0.0.1-go1.99.0.linux-amd64.zip",
                "toolchain",
            ),
        ] {
            let error = refusal(path);
            assert!(error.contains(needle), "{path}: {error}");
        }
    }

    #[test]
    fn requests_are_classified_by_what_they_fetch() {
        let class = |url: &str| GO_PROXY.classify(&Url::parse(url).unwrap());
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@v/list"),
            RequestClass::Index
        );
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip"),
            RequestClass::Artifact
        );
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.mod"),
            RequestClass::Metadata
        );
        assert_eq!(
            class("https://proxy.golang.org/github.com/google/uuid/@latest"),
            RequestClass::Metadata
        );
        assert_eq!(
            class("https://sum.golang.org/tile/8/1/338"),
            RequestClass::Sumdb
        );
        assert!(GO_PROXY
            .claims(
                &Url::parse("https://proxy.golang.org/x/@v/v1.0.0.mod").unwrap(),
                b"module x"
            )
            .is_empty());
    }

    #[test]
    fn the_route_reaches_only_the_two_go_hosts() {
        let route = route().unwrap();
        let hosts: Vec<&str> = route.endpoints.iter().map(Endpoint::host).collect();
        assert_eq!(hosts, vec![PROXY_HOST, SUMDB_HOST]);
        assert!(route.resolve("/github.com/google/uuid/@v/list").is_ok());
        assert!(route.resolve("/github.com/google/../uuid/@v/list").is_err());
    }
}

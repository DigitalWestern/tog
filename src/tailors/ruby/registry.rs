//! The RubyGems protocol, as tog's resolution proxy serves it to Bundler.
//!
//! Bundler reaches rubygems.org through a registry mirror, not
//! interception: `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/` names the
//! session's route, and `Gemfile.lock` keeps `remote: https://rubygems.org/`
//! because a mirror is transparent to the lock. Bundler then asks the
//! mirror for these paths, each mapped here to its upstream:
//!
//! - `/versions` and `/names` (the compact index listings) and
//!   `/info/<gem>` (one gem's versions, dependencies and checksums) go to
//!   `https://index.rubygems.org`, where rubygems.org's own compact index
//!   redirects.
//! - `/gems/<name>-<version>[-<platform>].gem` goes to
//!   `https://rubygems.org`. Lock-only Bundler (`bundle lock`, `bundle add
//!   --skip-install`) never asks for one; the path is served so an edit
//!   that does is verified rather than refused.
//!
//! Anything else is refused: a query string, the old dependency API, the
//! full Marshal index, and any name outside the gem grammar. Every
//! `/info/<gem>` line carries the gem's `checksum:<sha256>`, which is the
//! route's claim for that `.gem`.

use crate::kernel::fetch::Digest;
use crate::kernel::resolve::routes::{
    Claim, Endpoint, ProxyAddress, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id in mirror URLs: `http://<relay>/<token>/rubygems/...`.
pub const ROUTE_ID: &str = "rubygems";
/// The compact index host and the gem host.
pub const INDEX_HOST: &str = "index.rubygems.org";
pub const GEMS_HOST: &str = "rubygems.org";
/// The Bundler setting that points rubygems.org at a mirror. Bundler reads
/// it from the environment even under tog's `BUNDLE_IGNORE_CONFIG=1`.
pub const MIRROR_VARIABLE: &str = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/";

/// The longest gem name or file name the grammar accepts.
const MAX_WORD: usize = 256;

/// The RubyGems compact index and gem downloads.
pub struct RubyGems;

pub static RUBYGEMS: RubyGems = RubyGems;

impl RegistryProtocol for RubyGems {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a RubyGems request carries no query"));
        }
        if path == "/versions" || path == "/names" {
            return Ok(Upstream::Fetch(endpoint(endpoints, INDEX_HOST)?.url(path)?));
        }
        if let Some(name) = path.strip_prefix("/info/") {
            check_word(name).map_err(|why| refused(path, &why))?;
            return Ok(Upstream::Fetch(endpoint(endpoints, INDEX_HOST)?.url(path)?));
        }
        if let Some(file) = path.strip_prefix("/gems/") {
            let stem = file
                .strip_suffix(".gem")
                .ok_or_else(|| refused(path, "not a .gem file"))?;
            check_word(stem).map_err(|why| refused(path, &why))?;
            return Ok(Upstream::Fetch(endpoint(endpoints, GEMS_HOST)?.url(path)?));
        }
        Err(refused(
            path,
            "only the compact index (/versions, /names, /info/<gem>) and /gems/<file>.gem are served",
        ))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        let path = url.path();
        if path.starts_with("/gems/") {
            RequestClass::Artifact
        } else if path.starts_with("/info/") {
            RequestClass::Metadata
        } else {
            RequestClass::Index
        }
    }

    fn expects_claim(&self, url: &Url) -> bool {
        matches!(self.classify(url), RequestClass::Artifact)
    }

    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        let Some(name) = url.path().strip_prefix("/info/") else {
            return Vec::new();
        };
        if url.host_str() != Some(INDEX_HOST) || check_word(name).is_err() {
            return Vec::new();
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return Vec::new();
        };
        info_checksums(text)
            .filter_map(|(version, sha256)| {
                let file = format!("{name}-{version}");
                check_word(&file).ok()?;
                let mut gem = Url::parse(&format!("https://{GEMS_HOST}/gems/{file}.gem")).ok()?;
                // The claim names the gem on the same port as the index it
                // came from: 443 in use, the fixture's port in tests.
                gem.set_port(url.port()).ok()?;
                Some((gem, Claim::one(Digest::sha256(sha256).ok()?)))
            })
            .collect()
    }
}

/// `(version[-platform], sha256)` for every line of an `/info/<gem>` body
/// that carries a checksum. A line is `<version> <deps>|<requirements>`,
/// the requirements a comma list holding `checksum:<hex>`; the lines
/// before `---` are a header.
fn info_checksums(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .skip_while(|line| *line != "---")
        .skip(1)
        .filter_map(|line| {
            let (version, rest) = line.split_once(' ')?;
            let (_, requirements) = rest.split_once('|')?;
            let sha256 = requirements
                .split(',')
                .find_map(|part| part.strip_prefix("checksum:"))?;
            Some((version, sha256))
        })
}

/// A gem name, or a gem's file stem: RubyGems' own character set, no
/// leading dot or dash.
fn check_word(word: &str) -> Result<(), String> {
    if word.is_empty() || word.len() > MAX_WORD {
        return Err("an empty or overlong name".into());
    }
    if word.starts_with('.') || word.starts_with('-') {
        return Err(format!("{word:?} starts with a dot or a dash"));
    }
    if !word
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!("{word:?} has a byte outside the gem name grammar"));
    }
    Ok(())
}

/// The route endpoint on `host`, which a RubyGems route always has.
fn endpoint<'a>(endpoints: &'a [Endpoint], host: &str) -> io::Result<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.host() == host)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the RubyGems route has no {host} endpoint"),
            )
        })
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("RubyGems path {path:?} refused: {why}"),
    )
}

/// What points Bundler at a session: rubygems.org mirrored to the route,
/// and the proxy (with the session token) for any other source, which the
/// door refuses visibly. The mirror's own host is `no_proxy`: Bundler's
/// HTTP client sends a plain-http URL through `http_proxy` (it has no
/// loopback exception), and the proxy refuses an absolute-form request.
pub fn proxy_env(address: &ProxyAddress) -> Vec<(String, String)> {
    let proxy = address.proxy_url();
    let base = address.route_base(ROUTE_ID);
    let mirror_host = Url::parse(&base)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_default();
    vec![
        (MIRROR_VARIABLE.to_string(), base),
        ("https_proxy".to_string(), proxy.clone()),
        ("http_proxy".to_string(), proxy),
        ("no_proxy".to_string(), mirror_host.clone()),
        ("NO_PROXY".to_string(), mirror_host),
    ]
}

/// The RubyGems route: the compact index and the gem host.
pub fn route() -> io::Result<Route> {
    Route::new(
        &RUBYGEMS,
        vec![Endpoint::https(INDEX_HOST)?, Endpoint::https(GEMS_HOST)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::https(INDEX_HOST).unwrap(),
            Endpoint::https(GEMS_HOST).unwrap(),
        ]
    }

    fn fetch(path: &str) -> String {
        match RUBYGEMS.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    fn refusal(path: &str) -> String {
        RUBYGEMS
            .upstream(&endpoints(), path)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn the_compact_index_goes_to_the_index_host_and_gems_to_rubygems_org() {
        assert_eq!(fetch("/versions"), "https://index.rubygems.org/versions");
        assert_eq!(fetch("/names"), "https://index.rubygems.org/names");
        assert_eq!(fetch("/info/rake"), "https://index.rubygems.org/info/rake");
        assert_eq!(
            fetch("/info/net-http_persistent.x"),
            "https://index.rubygems.org/info/net-http_persistent.x"
        );
        assert_eq!(
            fetch("/gems/rake-13.4.2.gem"),
            "https://rubygems.org/gems/rake-13.4.2.gem"
        );
        assert_eq!(
            fetch("/gems/nokogiri-1.18.0-x86_64-linux-gnu.gem"),
            "https://rubygems.org/gems/nokogiri-1.18.0-x86_64-linux-gnu.gem"
        );
    }

    #[test]
    fn everything_else_is_refused() {
        for path in [
            "/api/v1/dependencies?gems=rake",
            "/versions?x=1",
            "/specs.4.8.gz",
            "/quick/Marshal.4.8/rake-13.4.2.gemspec.rz",
            "/info/",
            "/info/.hidden",
            "/info/-rf",
            "/info/a%20b",
            "/info/rake/extra",
            "/gems/rake-13.4.2.tar",
            "/gems/.gem",
            "/",
        ] {
            let why = refusal(path);
            assert!(why.contains("refused"), "{path}: {why}");
        }
    }

    #[test]
    fn requests_are_classified_by_what_they_fetch() {
        let class = |url: &str| RUBYGEMS.classify(&Url::parse(url).unwrap());
        assert_eq!(
            class("https://index.rubygems.org/versions"),
            RequestClass::Index
        );
        assert_eq!(
            class("https://index.rubygems.org/info/rake"),
            RequestClass::Metadata
        );
        assert_eq!(
            class("https://rubygems.org/gems/rake-13.4.2.gem"),
            RequestClass::Artifact
        );
    }

    #[test]
    fn an_info_body_claims_each_gem_by_its_checksum() {
        let body = "---\n\
            0.4.11 |checksum:ceab46efc69e21259f97393a92d1f4ec29582ec1137545183abbd11b26459e94,ruby:> 0.0.0\n\
            1.0.0-java a:>= 1&< 2,b:~> 3|checksum:0e0d9357893053a369e7f9f3fc13eb4a61aff3058dd419fcb61f73d762e0b9ed\n\
            2.0.0 |ruby:>= 2.0\n";
        let url = Url::parse("https://index.rubygems.org/info/rake").unwrap();
        let claims = RUBYGEMS.claims(&url, body.as_bytes());
        let found: Vec<(String, String)> = claims
            .iter()
            .map(|(url, claim)| (url.to_string(), claim.describe()))
            .collect();
        assert_eq!(
            found,
            [
                (
                    "https://rubygems.org/gems/rake-0.4.11.gem".to_string(),
                    "sha256:ceab46efc69e21259f97393a92d1f4ec29582ec1137545183abbd11b26459e94"
                        .to_string()
                ),
                (
                    "https://rubygems.org/gems/rake-1.0.0-java.gem".to_string(),
                    "sha256:0e0d9357893053a369e7f9f3fc13eb4a61aff3058dd419fcb61f73d762e0b9ed"
                        .to_string()
                ),
            ]
        );
        let on_port = Url::parse("https://index.rubygems.org:4443/info/rake").unwrap();
        assert!(RUBYGEMS
            .claims(&on_port, body.as_bytes())
            .iter()
            .all(|(url, _)| url.port() == Some(4443)));
        let versions = Url::parse("https://index.rubygems.org/versions").unwrap();
        assert!(RUBYGEMS.claims(&versions, body.as_bytes()).is_empty());
    }

    #[test]
    fn the_route_reaches_only_the_two_rubygems_hosts() {
        let route = route().unwrap();
        let hosts: Vec<&str> = route.endpoints.iter().map(|e| e.host()).collect();
        assert_eq!(hosts, [INDEX_HOST, GEMS_HOST]);
    }
}

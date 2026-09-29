//! Where the proxy may forward, and how a registry-mirror path maps to an
//! upstream URL.
//!
//! The kernel never names an ecosystem. Each ecosystem's registry protocol
//! implements [`RegistryProtocol`] in its tailor folder; a door hands the
//! proxy [`Route`]s pairing a protocol with the [`Endpoint`]s it may reach.
//! The kernel checks everything the protocol returns: the upstream origin
//! must be one of the route's endpoints, every endpoint must be in the
//! permitted set, and the request path must parse in the route grammar
//! before the protocol ever sees it.

use crate::kernel::fetch::Digest;
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use url::Url;

/// The upstream hosts the proxy may reach: the public registries tog
/// already fetches from, plus the GitHub hosts resolvers use for git
/// dependencies. A registry that lives elsewhere is refused until it is
/// configured as a permitted endpoint in machine policy.
pub const PERMITTED_HOSTS: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "index.crates.io",
    "static.crates.io",
    "crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "rubygems.org",
    "index.rubygems.org",
    "repo.hex.pm",
    "api.nuget.org",
    "api.github.com",
    "raw.githubusercontent.com",
];

/// What kind of thing a request fetches. Metadata-like classes (index,
/// metadata, sumdb) are cached, revalidated, and may be served last-good;
/// an artifact is served only as verified bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestClass {
    /// A listing of what exists (Go's `@v/list`, a compact index).
    Index,
    /// A document describing packages (a packument, a `.mod`, a service
    /// index). Its digests feed claims.
    Metadata,
    /// Package bytes: a tarball, a wheel, a module zip.
    Artifact,
    /// A checksum-database answer the tool verifies itself.
    Sumdb,
}

impl RequestClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestClass::Index => "index",
            RequestClass::Metadata => "metadata",
            RequestClass::Artifact => "artifact",
            RequestClass::Sumdb => "sumdb",
        }
    }

    /// Cached in the metadata cache and eligible for last-good.
    pub fn is_metadata(self) -> bool {
        !matches!(self, RequestClass::Artifact)
    }
}

/// A digest a registry published for an artifact URL, read from metadata
/// the proxy served. The bytes of that URL must hash to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim(pub Digest);

impl Claim {
    /// `sha512:<hex>`: how the ledger writes a claim.
    pub fn describe(&self) -> String {
        format!("{}:{}", self.0.algo(), self.0.hex())
    }

    /// A SHA-1 claim pins nothing collision-resistant: `weak-integrity`.
    pub fn is_weak(&self) -> bool {
        self.0.algo() == "sha1"
    }
}

/// Hosts (with port) the proxy may reach, for route endpoints and every
/// redirect hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permitted {
    origins: BTreeSet<(String, u16)>,
}

impl Permitted {
    /// The compiled-in set, all on 443.
    pub fn compiled() -> Self {
        Self {
            origins: PERMITTED_HOSTS
                .iter()
                .map(|host| (host.to_string(), 443))
                .collect(),
        }
    }

    /// Whether `url` is an https URL on a permitted host and port, with no
    /// userinfo.
    pub fn allows(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && match (url.host_str(), url.port_or_known_default()) {
                (Some(host), Some(port)) => self.origins.contains(&(host.to_string(), port)),
                _ => false,
            }
    }

    /// Tests only: a fixture host on its ephemeral port.
    #[cfg(test)]
    pub(crate) fn with_origin(mut self, host: &str, port: u16) -> Self {
        self.origins.insert((host.to_string(), port));
        self
    }
}

/// One upstream origin a route may reach, and the credential tog attaches
/// to requests for that origin. A credential never follows a redirect to
/// another origin, and the tool never sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    authorization: Option<String>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("authorization", &self.authorization.as_ref().map(|_| "…"))
            .finish()
    }
}

impl Endpoint {
    /// `https://<host>/`, which must be a compiled-in permitted host.
    pub fn https(host: &str) -> io::Result<Endpoint> {
        let host = host.to_ascii_lowercase();
        if !PERMITTED_HOSTS.contains(&host.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{host} is not a permitted resolution endpoint"),
            ));
        }
        Ok(Endpoint {
            host,
            port: 443,
            authorization: None,
        })
    }

    /// Tests only: a fixture host on any port, outside the compiled set. A
    /// session still refuses it unless its permitted set names it.
    #[cfg(test)]
    pub(crate) fn for_test(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.to_string(),
            port,
            authorization: None,
        }
    }

    /// Attach an `Authorization` value to requests for this origin only.
    pub fn with_authorization(mut self, value: &str) -> Endpoint {
        self.authorization = Some(value.to_string());
        self
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// `https://host[:port]`.
    pub fn origin(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }

    /// The URL of `path` (starting with `/`, query allowed) on this origin.
    pub fn url(&self, path: &str) -> io::Result<Url> {
        Url::parse(&format!("{}{path}", self.origin())).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}{path}: {error}", self.origin()),
            )
        })
    }

    /// Whether `url` is on this endpoint's origin.
    pub fn serves(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.host_str() == Some(self.host.as_str())
            && url.port_or_known_default() == Some(self.port)
    }

    pub(crate) fn authorization(&self) -> Option<&str> {
        self.authorization.as_deref()
    }

    pub(crate) fn permitted_by(&self, permitted: &Permitted) -> bool {
        permitted.origins.contains(&(self.host.clone(), self.port))
    }
}

/// Where the tool reaches this session's proxy, as the tool sees it. Inside
/// a sandbox that is the relay's fixed address, not the host listener's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddress {
    pub address: SocketAddr,
    token: String,
}

impl ProxyAddress {
    pub(crate) fn new(address: SocketAddr, token: &str) -> Self {
        Self {
            address,
            token: token.to_string(),
        }
    }

    /// The forward-proxy URL with the session token as credentials:
    /// `http://tog:<token>@<address>`.
    pub fn proxy_url(&self) -> String {
        format!("http://tog:{}@{}", self.token, self.address)
    }

    /// The registry-mirror base of one route:
    /// `http://<address>/<token>/<route>/`.
    pub fn route_base(&self, route_id: &str) -> String {
        format!("http://{}/{}/{route_id}/", self.address, self.token)
    }

    /// The session token, for the output checks that make sure it never
    /// reaches a published file.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// What a mirror path maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// Fetch this URL, which must be on one of the route's endpoints.
    Fetch(Url),
    /// Answer from the proxy itself, without contacting upstream. The URL
    /// is what the ledger records the answer as, and is held to the same
    /// origin rule as a fetch.
    Local(LocalAnswer),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAnswer {
    pub url: Url,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// One registry's protocol, implemented in its tailor folder. Every method
/// is pure: no I/O, no network.
pub trait RegistryProtocol: Sync {
    /// The route segment in mirror URLs (`/<token>/<route_id>/...`):
    /// lowercase letters, digits, and `-`.
    fn route_id(&self) -> &'static str;

    /// Map a mirror path (starting with `/`, query included) to where it
    /// is served from. `endpoints` are the route's; the answer's origin must
    /// be one of them. The kernel has already refused `..`, encoded `/`,
    /// and absolute URLs in `path`; a protocol refuses whatever else its
    /// grammar does not allow, with an `InvalidInput` error.
    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream>;

    /// What `url` fetches.
    fn classify(&self, url: &Url) -> RequestClass;

    /// The artifact digests the metadata `body`, fetched from `url`,
    /// promises.
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)>;

    /// Whether this protocol publishes a claim for every artifact like
    /// `url`, so an unclaimed one is `weak-integrity`.
    fn expects_claim(&self, _url: &Url) -> bool {
        false
    }

    /// Query keys that identify content, kept by redaction; every other
    /// query value is recorded as `REDACTED`.
    fn content_query_keys(&self) -> &'static [&'static str] {
        &[]
    }

    /// Rewrite a metadata body before it is served (absolute URLs that
    /// must point back at the proxy). The ledger always records the
    /// upstream bytes, never the rewritten ones.
    fn rewrite(&self, _url: &Url, body: Vec<u8>, _base: &ProxyAddress) -> io::Result<Vec<u8>> {
        Ok(body)
    }
}

/// A mirror route: a protocol and the endpoints it may reach.
#[derive(Clone)]
pub struct Route {
    pub protocol: &'static dyn RegistryProtocol,
    pub endpoints: Vec<Endpoint>,
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route")
            .field("route_id", &self.protocol.route_id())
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

impl Route {
    pub fn new(
        protocol: &'static dyn RegistryProtocol,
        endpoints: Vec<Endpoint>,
    ) -> io::Result<Route> {
        let id = protocol.route_id();
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("route id {id:?} must be lowercase letters, digits, and -"),
            ));
        }
        if endpoints.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("route {id} has no endpoint"),
            ));
        }
        Ok(Route {
            protocol,
            endpoints,
        })
    }

    /// Where `path` goes, after the kernel's grammar check and the origin
    /// check on the protocol's answer.
    pub fn resolve(&self, path: &str) -> Result<Upstream, String> {
        check_route_path(path)?;
        let upstream = self
            .protocol
            .upstream(&self.endpoints, path)
            .map_err(|error| error.to_string())?;
        let url = match &upstream {
            Upstream::Fetch(url) => url,
            Upstream::Local(answer) => &answer.url,
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!(
                "route {} produced a URL with userinfo",
                self.protocol.route_id()
            ));
        }
        if !self.endpoints.iter().any(|endpoint| endpoint.serves(url)) {
            return Err(format!(
                "route {} mapped {path} to {}, which is not one of its endpoints",
                self.protocol.route_id(),
                url.origin().ascii_serialization()
            ));
        }
        Ok(upstream)
    }

    /// The endpoint serving `url`, for its credential.
    pub(crate) fn endpoint_for(&self, url: &Url) -> Option<&Endpoint> {
        self.endpoints.iter().find(|endpoint| endpoint.serves(url))
    }
}

/// The grammar every mirror path must satisfy before a protocol sees it:
/// an absolute path, no empty, `.`, or `..` segment (percent-encoded or
/// not), no percent-encoded `/`, `\`, or NUL, no backslash, and no URL
/// inside it. The query is not restricted beyond well-formed escapes.
pub fn check_route_path(path_and_query: &str) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("mirror path {path_and_query:?} refused: {why}"));
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    if !path.starts_with('/') {
        return refuse("not an absolute path");
    }
    if path.contains('\\') {
        return refuse("a backslash");
    }
    if path.contains("://") {
        return refuse("an absolute URL inside the route");
    }
    for part in [Some(path), query].into_iter().flatten() {
        if !escapes_well_formed(part) {
            return refuse("a malformed percent-escape");
        }
    }
    let lower = path.to_ascii_lowercase();
    for encoded in ["%2f", "%5c", "%00"] {
        if lower.contains(encoded) {
            return refuse("a percent-encoded /, \\, or NUL");
        }
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        if segment.is_empty() && !last {
            return refuse("an empty segment");
        }
        let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
        if decoded == "." || decoded == ".." {
            return refuse("a . or .. segment");
        }
    }
    Ok(())
}

fn escapes_well_formed(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod testing {
    //! A registry protocol for kernel tests, over the fixture registry in
    //! `tests/fixtures/proxy/registry/kernel/`. Mirror paths map one to one
    //! onto the first endpoint; `/meta/...` is metadata whose JSON body
    //! lists artifact claims, `/art/...` is an artifact, `/index/...` an
    //! index, `/sumdb/...` sumdb, and `/local/supported` is answered by the
    //! proxy itself.

    use super::*;

    pub struct TestProtocol;

    pub static TEST_PROTOCOL: TestProtocol = TestProtocol;

    impl RegistryProtocol for TestProtocol {
        fn route_id(&self) -> &'static str {
            "fixture"
        }

        fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
            if path.starts_with("/forbidden/") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the fixture grammar forbids /forbidden/",
                ));
            }
            if path == "/local/supported" {
                return Ok(Upstream::Local(LocalAnswer {
                    url: endpoints[0].url("/supported")?,
                    status: 200,
                    content_type: "text/plain".into(),
                    body: Vec::new(),
                }));
            }
            if let Some(rest) = path.strip_prefix("/elsewhere") {
                // A protocol bug the kernel must catch: an origin that is
                // not one of the route's endpoints.
                let url = Url::parse(&format!("https://not-an-endpoint.test{rest}")).unwrap();
                return Ok(Upstream::Fetch(url));
            }
            if let Some(rest) = path.strip_prefix("/second") {
                return Ok(Upstream::Fetch(endpoints[1].url(rest)?));
            }
            Ok(Upstream::Fetch(endpoints[0].url(path)?))
        }

        fn classify(&self, url: &Url) -> RequestClass {
            let path = url.path();
            if path.starts_with("/art/") {
                RequestClass::Artifact
            } else if path.starts_with("/index/") {
                RequestClass::Index
            } else if path.starts_with("/sumdb/") {
                RequestClass::Sumdb
            } else {
                RequestClass::Metadata
            }
        }

        /// A metadata body `{"claims": {"<url>": "<algo>:<hex>"}}`, each
        /// URL relative to the metadata's own (the fixture's port changes
        /// every run).
        fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                return Vec::new();
            };
            let Some(claims) = value.get("claims").and_then(|c| c.as_object()) else {
                return Vec::new();
            };
            claims
                .iter()
                .filter_map(|(target, digest)| {
                    let (algo, hex) = digest.as_str()?.split_once(':')?;
                    let digest = match algo {
                        "sha1" => Digest::sha1(hex),
                        "sha256" => Digest::sha256(hex),
                        "sha512" => Digest::sha512(hex),
                        _ => return None,
                    }
                    .ok()?;
                    Some((url.join(target).ok()?, Claim(digest)))
                })
                .collect()
        }

        fn expects_claim(&self, url: &Url) -> bool {
            url.path().starts_with("/art/claimed-")
        }

        fn content_query_keys(&self) -> &'static [&'static str] {
            &["format"]
        }

        fn rewrite(&self, url: &Url, body: Vec<u8>, base: &ProxyAddress) -> io::Result<Vec<u8>> {
            if url.path() != "/meta/rewritten.json" {
                return Ok(body);
            }
            let text =
                String::from_utf8_lossy(&body).replace("{BASE}", &base.route_base("fixture"));
            Ok(text.into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TEST_PROTOCOL;
    use super::*;

    #[test]
    fn route_paths_follow_the_grammar() {
        for good in [
            "/",
            "/github.com/google/uuid/@v/list",
            "/a/b.json?format=json&x=%2F",
            "/a%20b/c",
            "/dir/",
        ] {
            assert_eq!(check_route_path(good), Ok(()), "{good}");
        }
        for (bad, why) in [
            ("a/b", "absolute path"),
            ("/a/../b", ". or .."),
            ("/a/%2e%2E/b", ". or .."),
            ("/a/./b", ". or .."),
            ("/..", ". or .."),
            ("/a%2Fb", "percent-encoded"),
            ("/a%5cb", "percent-encoded"),
            ("/a%00", "percent-encoded"),
            ("/a\\b", "backslash"),
            ("/http://evil.test/x", "absolute URL"),
            ("//evil.test/x", "empty segment"),
            ("/a//b", "empty segment"),
            ("/a%zz", "malformed"),
            ("/a%2", "malformed"),
        ] {
            let error = check_route_path(bad).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn endpoints_come_only_from_the_permitted_set() {
        assert_eq!(
            Endpoint::https("proxy.golang.org").unwrap().origin(),
            "https://proxy.golang.org"
        );
        let error = Endpoint::https("evil.example").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let permitted = Permitted::compiled();
        for (url, allowed) in [
            ("https://proxy.golang.org/x", true),
            ("https://PROXY.golang.org/x", true),
            ("http://proxy.golang.org/x", false),
            ("https://proxy.golang.org:8443/x", false),
            ("https://user:pw@proxy.golang.org/x", false),
            ("https://builds.hex.pm/x", false),
            ("https://127.0.0.1/x", false),
        ] {
            assert_eq!(
                permitted.allows(&Url::parse(url).unwrap()),
                allowed,
                "{url}"
            );
        }
    }

    #[test]
    fn a_route_answer_must_stay_on_its_endpoints() {
        let route = Route::new(
            &TEST_PROTOCOL,
            vec![
                Endpoint::for_test("fixture.test", 8443),
                Endpoint::for_test("other.test", 8443),
            ],
        )
        .unwrap();
        assert_eq!(
            route.resolve("/meta/a.json").unwrap(),
            Upstream::Fetch(Url::parse("https://fixture.test:8443/meta/a.json").unwrap())
        );
        assert!(matches!(
            route.resolve("/second/x").unwrap(),
            Upstream::Fetch(url) if url.host_str() == Some("other.test")
        ));
        let error = route.resolve("/elsewhere/x").unwrap_err();
        assert!(error.contains("not one of its endpoints"), "{error}");
        let error = route.resolve("/forbidden/x").unwrap_err();
        assert!(error.contains("forbids"), "{error}");
        let error = route.resolve("/a/../b").unwrap_err();
        assert!(error.contains(". or .."), "{error}");
    }
}

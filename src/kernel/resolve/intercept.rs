//! TLS interception: serving the requests inside an authenticated tunnel.
//!
//! A tool told to use the proxy for https (cargo, git, and later npm and
//! uv) sends `CONNECT host:443` with the session token, which
//! `proxy::connect` checks once. The proxy answers 200, terminates TLS
//! with a leaf for `host` signed by the process's certificate authority
//! ([`super::ca`]), and reads plain HTTP requests inside. Those carry no
//! token and need none: the tunnel belongs to its session. Each request is
//! for `https://<host>[:port]<target>`, and is served one of three ways:
//!
//! - **A route serves the host** (`index.crates.io` for cargo): exactly
//!   like a mirror request of that route, through the same exchange (the
//!   metadata cache, claim verification, the ledger, redirects inside the
//!   permitted set).
//! - **A git fetch** (smart HTTP `info/refs?service=git-upload-pack` and
//!   `POST .../git-upload-pack`, and GitHub's commit lookup
//!   `api.github.com/repos/<owner>/<repo>/commits/<ref>`): any public https
//!   host may serve git, so the host need not be permitted. The fetch is
//!   refused when policy denies `git-dependency`, and is otherwise not
//!   recorded as an exception (the lock shows the dependency, and sync
//!   records it from there). It streams through uncached. Pushing
//!   (`git-receive-pack`) is refused.
//! - **Anything else** is a host outside the door's routes (an alternative
//!   registry, a direct URL): `unattested-index`. Refused when policy
//!   denies the kind; otherwise forwarded uncached and recorded, so the
//!   resolution record names the host.
//!
//! The `Host` header must name the tunnel's host (421 otherwise), and the
//! path passes the same grammar as a mirror path. Every address is still
//! resolved once and validated by the SSRF rule, and a redirect may only
//! stay on the origin it started from, unless a route serves the host.

use super::http::{self, Headers, Request};
use super::mirror::{self, Exchange, Record};
use super::proxy::{next_request, Context, Stream, Timed, Transport, Tunnel};
use super::redact;
use super::routes::{
    check_route_path_with, Claim, Endpoint, Permitted, RegistryProtocol, RequestClass, Route,
    Upstream,
};
use crate::kernel::policy;
use rustls::{ServerConnection, StreamOwned};
use std::io::{self, BufReader, Read, Write};
use std::time::Instant;
use url::Url;

/// The methods a git fetch uses.
const GIT_METHODS: &[&str] = &["GET", "HEAD", "POST"];

/// The methods a registry read uses.
const READ_METHODS: &[&str] = &["GET", "HEAD"];

/// The tool's side of the tunnel under TLS: the connection's buffered
/// reader (it may already hold the client's first TLS bytes) and its
/// writer.
pub(super) struct Plain<'a, S: Stream> {
    inner: &'a mut BufReader<Timed<S>>,
}

impl<S: Stream> Read for Plain<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Stream> Write for Plain<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.get_mut().flush()
    }
}

type Tls<'a, S> = StreamOwned<ServerConnection, Plain<'a, S>>;

impl<S: Stream> Transport for Tls<'_, S> {
    fn set_deadline(&mut self, at: Instant) {
        self.sock.inner.get_mut().set_deadline(at);
    }

    fn start_response(&mut self) {
        self.sock.inner.get_mut().start_response();
    }
}

/// Where an intercepted tunnel leads.
struct Target<'a> {
    host: &'a str,
    port: u16,
    /// `https://host[:port]`, as URLs inside the tunnel are spelled.
    origin: String,
}

/// Serve an authenticated tunnel: answer 200, terminate TLS, and serve the
/// requests inside until the tool closes it or goes idle while other
/// connections wait for a worker. `record` describes the `CONNECT`, for a
/// tunnel refused before TLS starts.
pub(super) fn serve_tunnel<S: Stream>(
    context: &Context,
    tunnel: &Tunnel<'_>,
    record: Record,
    reader: &mut BufReader<Timed<S>>,
) {
    let state = &*context.state;
    let config = match context.shared.authority.server_config(tunnel.host) {
        Ok(config) => config,
        Err(error) => {
            let reason = format!("refused CONNECT {}: {error}", tunnel.authority);
            let _ = mirror::refuse(
                state,
                reader.get_mut(),
                record,
                400,
                &reason,
                &Headers::new(),
                false,
            );
            return;
        }
    };
    let established = reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .and_then(|()| reader.get_mut().flush());
    let Ok(conn) =
        established.and_then(|()| ServerConnection::new(config).map_err(io::Error::other))
    else {
        return;
    };
    let mut tls = BufReader::new(StreamOwned::new(conn, Plain { inner: reader }));
    if let Err(error) = handshake(context, tls.get_mut()) {
        state.note_refusal(format!(
            "TLS handshake in the tunnel to {} failed: {error}",
            tunnel.authority
        ));
        return;
    }
    let target = Target {
        host: tunnel.host,
        port: tunnel.port,
        origin: Endpoint::intercepted(tunnel.host, tunnel.port).origin(),
    };
    let mut first = true;
    while let Some(request) = next_request(&mut tls, context, first, |head| body_cap(&target, head))
    {
        first = false;
        tls.get_mut().start_response();
        let served = serve(context, &target, &request, tls.get_mut());
        let flushed = tls.get_mut().flush();
        match (served, flushed) {
            (Ok(true), Ok(())) if request.keep_alive => {}
            _ => break,
        }
    }
    let stream = tls.get_mut();
    stream.conn.send_close_notify();
    let _ = stream.conn.complete_io(&mut stream.sock);
}

/// Complete the TLS handshake within the request timeout. A client that
/// names another server than the tunnel's host gets no certificate, so the
/// handshake fails.
fn handshake<S: Stream>(context: &Context, stream: &mut Tls<'_, S>) -> io::Result<()> {
    stream.set_deadline(Instant::now() + context.shared.request_timeout);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(())
}

/// How many body bytes to read for a request inside the tunnel: a git
/// negotiation's, up to the absolute cap, and none for anything else.
fn body_cap(target: &Target<'_>, head: &http::Head) -> u64 {
    if head.method != "POST" || !head.target.starts_with('/') {
        return 0;
    }
    match Url::parse(&format!("{}{}", target.origin, head.target)) {
        Ok(url) if matches!(git_fetch(&url, "POST"), Some(Ok(_))) => http::MAX_BODY,
        _ => 0,
    }
}

/// Serve one request inside the tunnel. `Ok(true)`: the tunnel may carry
/// another.
fn serve(
    context: &Context,
    target: &Target<'_>,
    request: &Request,
    out: &mut dyn Write,
) -> io::Result<bool> {
    let state = &*context.state;
    let keep_alive = request.keep_alive;
    let refuse = |out: &mut dyn Write, shown: String, status: u16, why: &str, keep: bool| {
        let record = Record::new("refused", &request.method, shown);
        mirror::refuse(state, out, record, status, why, &Headers::new(), keep).map(|()| keep)
    };
    if !request.target.starts_with('/') {
        let shown = redact::url(&request.target, &[]);
        let why = format!(
            "inside the tunnel to {}, only origin-form requests are served",
            target.origin
        );
        return refuse(out, shown, 400, &why, false);
    }
    let shown = redact::url(&format!("{}{}", target.origin, request.target), &[]);
    if !host_matches(request.headers.get("host"), target) {
        let why = format!(
            "the Host header does not name {}, the host this tunnel was opened to",
            target.origin
        );
        return refuse(out, shown, 421, &why, false);
    }
    // A route that serves this host may take an encoded slash in a
    // segment (npm's scoped packuments); its own grammar is still applied
    // by `Route::resolve` below. Every other host gets the strict grammar.
    let encoded_slash = state.config.routes.iter().any(|route| {
        route.protocol.encoded_slash()
            && route
                .endpoints
                .iter()
                .any(|endpoint| endpoint.origin() == target.origin)
    });
    if let Err(why) = check_route_path_with(&request.target, encoded_slash) {
        return refuse(out, shown, 403, &why, keep_alive);
    }
    let Ok(url) = Url::parse(&format!("{}{}", target.origin, request.target)) else {
        return refuse(out, shown, 400, "not a URL", false);
    };
    if let Some(route) = state
        .config
        .routes
        .iter()
        .find(|route| route.endpoints.iter().any(|endpoint| endpoint.serves(&url)))
    {
        if !READ_METHODS.contains(&request.method.as_str()) {
            let why = format!("{} is not served by registry routes", request.method);
            return refuse(out, shown, 405, &why, keep_alive);
        }
        // The route's own grammar still decides what it serves: a path its
        // protocol refuses, or maps to another endpoint, is refused here
        // as it would be on the mirror.
        let upstream = match route.resolve(&request.target) {
            Ok(upstream) => upstream,
            Err(why) => return refuse(out, shown, 403, &why, keep_alive),
        };
        let mapped = match &upstream {
            Upstream::Fetch(mapped) => mapped,
            Upstream::Local(answer) => &answer.url,
        };
        if *mapped != url {
            let why = format!(
                "route {} serves this path from {}, not from {}",
                route.protocol.route_id(),
                redact::url(mapped.as_str(), &[]),
                target.origin
            );
            return refuse(out, shown, 403, &why, keep_alive);
        }
        let check = |next: &Url, method: &str| hop_allowed(state, &Class::Route, next, method);
        let exchange = exchange(context, route, &state.config.permitted, request, &check);
        match upstream {
            Upstream::Local(answer) => exchange.local(answer, out)?,
            Upstream::Fetch(url) => exchange.serve(&url, out)?,
        }
        return Ok(!request.http10);
    }
    let only = Permitted::only(url.host_str().unwrap_or(target.host), target.port);
    match git_fetch(&url, &request.method) {
        Some(Err(why)) => return refuse(out, shown, 403, &why, keep_alive),
        Some(Ok(repository)) => {
            if !GIT_METHODS.contains(&request.method.as_str()) {
                let why = format!("{} is not part of a git fetch", request.method);
                return refuse(out, shown, 405, &why, keep_alive);
            }
            let detail = "a git fetch through the resolution proxy";
            if let Err(refusal) =
                state.refuse_if_denied(policy::GIT_DEPENDENCY, &repository, detail)
            {
                return refuse(out, shown, 403, &refusal, keep_alive);
            }
            let route = intercepted_route(&GIT_FETCH, target)?;
            let first = Class::Git { repository };
            let check = |next: &Url, method: &str| hop_allowed(state, &first, next, method);
            exchange(context, &route, &only, request, &check).serve(&url, out)?;
        }
        None => {
            if !READ_METHODS.contains(&request.method.as_str()) {
                let why = format!(
                    "{} to {} is not a registry read",
                    request.method, target.origin
                );
                return refuse(out, shown, 405, &why, keep_alive);
            }
            let detail = format!(
                "{} is not one of this door's registries; the request was forwarded through \
                 interception and recorded",
                target.origin
            );
            if let Err(refusal) = state.check(policy::UNATTESTED_INDEX, &target.origin, &detail) {
                return refuse(out, shown, 403, &refusal, keep_alive);
            }
            let route = intercepted_route(&UNATTESTED, target)?;
            let check =
                |next: &Url, method: &str| hop_allowed(state, &Class::Unattested, next, method);
            exchange(context, &route, &only, request, &check).serve(&url, out)?;
        }
    }
    Ok(!request.http10)
}

/// What an intercepted request is, as [`serve`] decides it: the class
/// that sets its methods and the policy it answers to.
#[derive(Debug, PartialEq, Eq)]
enum Class {
    /// A host one of the door's routes serves.
    Route,
    /// A git fetch from `repository`.
    Git { repository: String },
    /// Anything else: `unattested-index`.
    Unattested,
}

/// Classify `url` requested with `method` as `serve` does: a push is
/// refused on any host, a route host takes only reads, a git fetch only
/// git's methods, and anything else only reads.
fn classify(routes: &[Route], url: &Url, method: &str) -> Result<Class, String> {
    let fetch = git_fetch(url, method);
    if let Some(Err(why)) = fetch {
        return Err(why);
    }
    let read = READ_METHODS.contains(&method);
    let routed = routes
        .iter()
        .any(|route| route.endpoints.iter().any(|endpoint| endpoint.serves(url)));
    match fetch {
        _ if routed && read => Ok(Class::Route),
        _ if routed => Err(format!("{method} is not served by registry routes")),
        Some(Ok(repository)) if GIT_METHODS.contains(&method) => Ok(Class::Git { repository }),
        _ if read => Ok(Class::Unattested),
        _ => Err(format!(
            "{method} to {} is not a registry read",
            url.origin().ascii_serialization()
        )),
    }
}

/// Authorize one redirect hop of a request that started as `first`: the
/// hop is classified again with the method it would be sent with, and when
/// its class differs from the first request's, the new class's policy
/// decides (a git fetch answers to `git-dependency`, anything else to
/// `unattested-index`, which is recorded like the first request's would
/// be). A hop to a route host was allowed by the permitted set already.
fn hop_allowed(
    state: &super::session::State,
    first: &Class,
    next: &Url,
    method: &str,
) -> Result<(), String> {
    let class = classify(&state.config.routes, next, method)
        .map_err(|why| format!("redirect to {}: {why}", redact::url(next.as_str(), &[])))?;
    if std::mem::discriminant(&class) == std::mem::discriminant(first) {
        return Ok(());
    }
    let origin = next.origin().ascii_serialization();
    match &class {
        Class::Route => Ok(()),
        Class::Git { repository } => state.refuse_if_denied(
            policy::GIT_DEPENDENCY,
            repository,
            "a redirect to a git fetch through the resolution proxy",
        ),
        Class::Unattested => state.check(
            policy::UNATTESTED_INDEX,
            &origin,
            &format!(
                "a redirect led to {}, which is not one of this door's registries; it was \
                 forwarded through interception and recorded",
                redact::url(next.as_str(), &[])
            ),
        ),
    }
}

fn exchange<'a>(
    context: &'a Context,
    route: &'a Route,
    permitted: &'a Permitted,
    request: &'a Request,
    hop: &'a mirror::HopCheck<'a>,
) -> Exchange<'a> {
    Exchange {
        state: &context.state,
        client: &context.shared.client,
        route,
        address: &context.address,
        method: &request.method,
        request: &request.headers,
        body: (request.method == "POST").then_some(request.body.as_slice()),
        permitted,
        hop: Some(hop),
        // A streamed body is delimited by the close for HTTP/1.0.
        keep_alive: request.keep_alive && !request.http10,
        http10: request.http10,
    }
}

fn intercepted_route(
    protocol: &'static dyn RegistryProtocol,
    target: &Target<'_>,
) -> io::Result<Route> {
    Route::new(
        protocol,
        vec![Endpoint::intercepted(target.host, target.port)],
    )
}

/// Whether the `Host` header names the tunnel's host (and its port, when
/// it names one).
fn host_matches(header: Option<&str>, target: &Target<'_>) -> bool {
    let Some(header) = header.map(str::trim) else {
        return false;
    };
    let Ok(parsed) = Url::parse(&format!("https://{header}/")) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or_default();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case(target.host)
        && parsed.port_or_known_default() == Some(target.port)
        && parsed.path() == "/"
        && parsed.username().is_empty()
}

/// What a git fetch request asks for: `Some(Ok(repository))` for a fetch,
/// named as the repository's URL; `Some(Err(why))` for a push; `None` for
/// anything that is not git.
fn git_fetch(url: &Url, method: &str) -> Option<Result<String, String>> {
    let path = url.path();
    let service = url
        .query_pairs()
        .find(|(key, _)| key == "service")
        .map(|(_, value)| value.into_owned());
    let origin = url.origin().ascii_serialization();
    if path.ends_with("/git-receive-pack")
        || (path.ends_with("/info/refs") && service.as_deref() == Some("git-receive-pack"))
    {
        return Some(Err(
            "git-receive-pack (a push) is not part of resolving dependencies".into(),
        ));
    }
    if let Some(repository) = path.strip_suffix("/info/refs") {
        if service.as_deref() == Some("git-upload-pack") && method != "POST" {
            return Some(Ok(format!("{origin}{repository}")));
        }
        return None;
    }
    if let Some(repository) = path.strip_suffix("/git-upload-pack") {
        if method == "POST" && url.query().is_none() {
            return Some(Ok(format!("{origin}{repository}")));
        }
        return None;
    }
    // GitHub's commit lookup, which cargo and uv make before cloning a
    // GitHub dependency: `/repos/<owner>/<repo>/commits/<ref>`.
    if url.host_str() == Some("api.github.com") && matches!(method, "GET" | "HEAD") {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if let ["repos", owner, repo, "commits", reference] = parts.as_slice() {
            if [owner, repo, reference].iter().all(|part| !part.is_empty()) {
                return Some(Ok(format!("https://github.com/{owner}/{repo}")));
            }
        }
    }
    None
}

/// Git's smart HTTP, as served through a tunnel: streamed, never cached,
/// its `service` query named as content, and an `upload-pack`
/// negotiation body read up to the absolute cap.
struct GitFetch;

static GIT_FETCH: GitFetch = GitFetch;

impl RegistryProtocol for GitFetch {
    fn route_id(&self) -> &'static str {
        "git"
    }

    fn upstream(&self, _endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        Err(not_a_mirror(path))
    }

    fn classify(&self, _url: &Url) -> RequestClass {
        RequestClass::Git
    }

    fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
        Vec::new()
    }

    fn request_body_cap(&self) -> u64 {
        http::MAX_BODY
    }

    /// Kept by redaction, in the URL a refusal shows and in the ledger.
    fn content_query_keys(&self) -> &'static [&'static str] {
        &["service"]
    }
}

/// A host outside every route of the door: forwarded uncached as an
/// unclaimed artifact, since nothing vouches for it.
struct Unattested;

static UNATTESTED: Unattested = Unattested;

impl RegistryProtocol for Unattested {
    fn route_id(&self) -> &'static str {
        "unattested"
    }

    fn upstream(&self, _endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        Err(not_a_mirror(path))
    }

    fn classify(&self, _url: &Url) -> RequestClass {
        RequestClass::Artifact
    }

    fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
        Vec::new()
    }
}

fn not_a_mirror(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{path}: an intercepted host has no mirror route"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::Policy;
    use crate::kernel::resolve::ledger::Entry;
    use crate::kernel::resolve::proxy::Session;
    use crate::kernel::resolve::routes::ProxyAddress;
    use crate::kernel::resolve::session::{Intercept, Mode, SessionReport};
    use crate::kernel::resolve::testing::{
        open_tunnel, tunnel_request, Harness, Reach, TEST_ORIGIN_PUBLIC,
    };
    use crate::kernel::testutil::upstream::{Behavior, Reply};

    fn intercepting(harness: &Harness, policy: Policy) -> (Session, ProxyAddress) {
        let mut config = harness.config(policy, Mode::Online);
        config.intercept = Intercept::Tls;
        harness.open(config)
    }

    fn deny(kind: &str) -> Policy {
        Policy {
            deny: [kind.to_string()].into(),
            ..Policy::default()
        }
    }

    fn entries(report: &SessionReport) -> Vec<Entry> {
        report.ledger.entries().cloned().collect()
    }

    fn get(host: &str, path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n")
    }

    /// The token is checked once, at `CONNECT`; the requests inside carry
    /// none, are served like a routed request, and are recorded under
    /// their upstream URL. One tunnel carries several requests.
    #[test]
    fn inner_requests_of_an_authenticated_tunnel_need_no_token() {
        let harness = Harness::new("intercept-inner");
        let (session, address) = intercepting(&harness, Policy::default());
        let authority = format!("registry.test:{}", harness.upstream.port());
        let roots = harness.proxy.authority().roots();
        let mut tunnel =
            open_tunnel(&address, &authority, "registry.test", roots, &[b"http/1.1"]).unwrap();
        assert_eq!(tunnel.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
        let first = tunnel_request(&mut tunnel, &get(&authority, "/meta/pkg.json"), b"");
        assert_eq!(first.status, 200, "{}", first.text());
        let second = tunnel_request(&mut tunnel, &get(&authority, "/index/pkg"), b"");
        assert_eq!(second.status, 200, "{}", second.text());
        drop(tunnel);
        let report = session.finish();
        let urls: Vec<(String, String)> = entries(&report)
            .into_iter()
            .map(|entry| (entry.class, entry.url))
            .collect();
        assert!(
            urls.contains(&("metadata".into(), harness.upstream_url("/meta/pkg.json")))
                && urls.contains(&("index".into(), harness.upstream_url("/index/pkg"))),
            "{urls:?}"
        );
        assert!(report.facts.exceptions.is_empty(), "{:?}", report.facts);
        // The upstream saw the real host, never the token.
        let seen = harness.upstream.seen();
        assert!(seen
            .iter()
            .all(|request| request.headers.get("proxy-authorization").is_none()));
    }

    /// An intercepting session still answers a credential-less `CONNECT`
    /// with 407 and the Basic challenge git needs to retry with its
    /// credentials, and a token from another session is a wrong token.
    #[test]
    fn an_intercepting_session_challenges_a_connect_without_its_token() {
        let harness = Harness::new("intercept-407");
        let (session, address) = intercepting(&harness, Policy::default());
        let (_other, elsewhere) = intercepting(&harness, Policy::default());
        let authority = format!("registry.test:{}", harness.upstream.port());
        let bare = crate::kernel::resolve::testing::send(
            &address,
            &format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"),
        );
        assert_eq!(bare.status, 407);
        assert_eq!(
            bare.headers.get("proxy-authenticate"),
            Some("Basic realm=\"tog\"")
        );
        let crossed = crate::kernel::resolve::testing::send(
            &address,
            &format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{}",
                crate::kernel::resolve::testing::proxy_authorization(elsewhere.token())
            ),
        );
        assert_eq!(crossed.status, 407);
        let report = session.finish();
        assert!(entries(&report).is_empty());
        assert_eq!(report.diagnostics.unauthenticated, 2);
    }

    /// A tunnel is bound to the host it was opened for: a handshake naming
    /// another server gets no certificate, and the leaf it does serve
    /// verifies only for the tunnel's host.
    #[test]
    fn a_tunnel_serves_no_certificate_for_another_server_name() {
        let harness = Harness::new("intercept-sni");
        let (session, address) = intercepting(&harness, Policy::default());
        let authority = format!("registry.test:{}", harness.upstream.port());
        let roots = || harness.proxy.authority().roots();
        assert!(open_tunnel(&address, &authority, "other.test", roots(), &[]).is_err());
        // A tool that trusts some other authority refuses the leaf.
        let stranger = crate::kernel::resolve::ca::Authority::new().unwrap();
        assert!(open_tunnel(&address, &authority, "registry.test", stranger.roots(), &[]).is_err());
        open_tunnel(&address, &authority, "registry.test", roots(), &[]).unwrap();
        let report = session.finish();
        assert!(
            report
                .diagnostics
                .refusals
                .iter()
                .any(|refusal| refusal.contains("TLS handshake")),
            "{:?}",
            report.diagnostics.refusals
        );
    }

    /// Only HTTP/1.1 is offered: a client that also offers h2 is answered
    /// with http/1.1, and one that offers only h2 cannot complete the
    /// handshake.
    #[test]
    fn interception_offers_only_http_1_1() {
        let harness = Harness::new("intercept-alpn");
        let (_session, address) = intercepting(&harness, Policy::default());
        let authority = format!("registry.test:{}", harness.upstream.port());
        let roots = || harness.proxy.authority().roots();
        let both = open_tunnel(
            &address,
            &authority,
            "registry.test",
            roots(),
            &[b"h2", b"http/1.1"],
        )
        .unwrap();
        assert_eq!(both.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
        assert!(open_tunnel(&address, &authority, "registry.test", roots(), &[b"h2"]).is_err());
    }

    /// Inside a tunnel the `Host` must name the tunnel's host, and only
    /// origin-form requests are served.
    #[test]
    fn a_request_naming_another_host_is_misdirected() {
        let harness = Harness::new("intercept-host");
        let (session, address) = intercepting(&harness, Policy::default());
        let port = harness.upstream.port();
        let authority = format!("registry.test:{port}");
        let roots = || harness.proxy.authority().roots();
        let mut tunnel = open_tunnel(&address, &authority, "registry.test", roots(), &[]).unwrap();
        let other = format!("other.test:{port}");
        let misdirected = tunnel_request(&mut tunnel, &get(&other, "/meta/pkg.json"), b"");
        assert_eq!(misdirected.status, 421, "{}", misdirected.text());
        let mut tunnel = open_tunnel(&address, &authority, "registry.test", roots(), &[]).unwrap();
        let absolute = tunnel_request(
            &mut tunnel,
            &get(&authority, &format!("https://{other}/meta/pkg.json")),
            b"",
        );
        assert_eq!(absolute.status, 400, "{}", absolute.text());
        let report = session.finish();
        assert!(entries(&report)
            .iter()
            .all(|entry| entry.class == "refused"));
        assert!(harness.upstream.seen().is_empty());
    }

    /// A host no route serves is `unattested-index`: forwarded and recorded
    /// under permissive policy, refused when the kind is denied.
    #[test]
    fn an_unrouted_host_is_unattested_forwarded_or_refused() {
        for (policy, served) in [
            (Policy::default(), true),
            (deny(policy::UNATTESTED_INDEX), false),
        ] {
            let harness = Harness::new("intercept-unattested");
            let (session, address) = intercepting(&harness, policy);
            let authority = format!("third.test:{}", harness.upstream.port());
            let roots = harness.proxy.authority().roots();
            let mut tunnel = open_tunnel(&address, &authority, "third.test", roots, &[]).unwrap();
            let answer = tunnel_request(&mut tunnel, &get(&authority, "/meta/pkg.json"), b"");
            let report = session.finish();
            let origin = format!("https://{authority}");
            if served {
                assert_eq!(answer.status, 200, "{}", answer.text());
                let facts: Vec<_> = report.facts.exceptions.iter().collect();
                assert_eq!(facts.len(), 1, "{facts:?}");
                assert_eq!(facts[0].kind, policy::UNATTESTED_INDEX);
                assert_eq!(facts[0].subject, origin);
                assert!(entries(&report)
                    .iter()
                    .any(|entry| entry.class == "artifact"
                        && entry.url == format!("{origin}/meta/pkg.json")
                        && entry.status == 200));
            } else {
                assert_eq!(answer.status, 403, "{}", answer.text());
                assert!(report.facts.exceptions.is_empty());
                assert_eq!(report.facts.refusals.len(), 1, "{:?}", report.facts);
                assert!(harness.upstream.seen().is_empty());
            }
        }
    }

    /// The same `git ls-remote` against the recorded GitHub answers, first
    /// permitted and then with `git-dependency` denied, through the git
    /// row's settings: the first `CONNECT` carries no credentials and gets
    /// 407, git retries with the proxy URL's, and the smart-HTTP exchange
    /// (a `POST` with a body) is served from the tunnel and recorded as
    /// `git`. A permitted git fetch records no exception: the lock shows
    /// the dependency, and sync records it.
    #[test]
    fn git_fetches_through_interception_with_the_git_row() {
        if !std::path::Path::new("/usr/bin/git").is_file() {
            eprintln!("skip: no /usr/bin/git");
            return;
        }
        for denied in [false, true] {
            let harness = Harness::serving(
                "intercept-git",
                Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]),
                &["github.com"],
                "git",
            );
            // The negotiation must arrive: an exchange that dropped the POST
            // body gets 400 here, and ls-remote fails.
            harness.upstream.require_body(
                "/dtolnay/itoa/git-upload-pack",
                &[b"command=ls-refs", b"symrefs"],
            );
            let policy = if denied {
                deny(policy::GIT_DEPENDENCY)
            } else {
                Policy::default()
            };
            let mut config = harness.config(policy, Mode::Online);
            config.intercept = Intercept::Tls;
            config.routes = Vec::new();
            let (session, address) = harness.open(config);
            let temp = crate::kernel::testutil::TempDir::named("intercept-git-ca");
            let ca = temp.0.join("ca.pem");
            std::fs::write(&ca, harness.proxy.authority().pem()).unwrap();
            let forced = crate::kernel::resolve::confine::forced_settings(
                "git",
                &Default::default(),
                &crate::kernel::resolve::door::git_row(&address, &ca),
            )
            .unwrap();
            let mut command = std::process::Command::new("/usr/bin/git");
            command
                .args(["ls-remote", "https://github.com/dtolnay/itoa", "HEAD"])
                .env_clear()
                .env("HOME", &temp.0)
                .env("PATH", "/usr/bin:/bin");
            for (key, value) in &forced.env {
                command.env(key, value);
            }
            let output = command.output().unwrap();
            let report = session.finish();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if denied {
                assert!(!output.status.success(), "{stderr}");
                assert_eq!(report.facts.refusals.len(), 1, "{:?}", report.facts);
                assert!(report.facts.refusals[0].contains("https://github.com/dtolnay/itoa"));
                continue;
            }
            let bodies: Vec<String> = harness
                .upstream
                .seen()
                .iter()
                .map(|seen| String::from_utf8_lossy(&seen.body).into_owned())
                .collect();
            assert!(output.status.success(), "{stderr}\n{bodies:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("\tHEAD"),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(report.facts.exceptions.is_empty(), "{:?}", report.facts);
            let git: Vec<(String, String, u16)> = entries(&report)
                .into_iter()
                .filter(|entry| entry.class == "git")
                .map(|entry| (entry.method, entry.url, entry.status))
                .collect();
            assert!(
                git.contains(&(
                    "GET".into(),
                    // `service` names content for the git row, so the
                    // ledger keeps its value.
                    "https://github.com/dtolnay/itoa/info/refs?service=git-upload-pack".into(),
                    200
                )) && git.contains(&(
                    "POST".into(),
                    "https://github.com/dtolnay/itoa/git-upload-pack".into(),
                    200
                )),
                "{git:?}"
            );
            assert!(
                report.diagnostics.unauthenticated >= 1,
                "git's first CONNECT carries no credentials"
            );
        }
    }

    /// A git `POST` inside a tunnel to `third.test` (no route serves it).
    fn post(authority: &str, path: &str, body: &[u8], gzip: bool) -> String {
        let encoding = if gzip {
            "Content-Encoding: gzip\r\n"
        } else {
            ""
        };
        format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\n\
             Content-Type: application/x-git-upload-pack-request\r\n{encoding}\
             Content-Length: {}\r\n",
            body.len()
        )
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// A git negotiation reaches upstream byte for byte, gzip-encoded and
    /// after a 307 to another `git-upload-pack` on the same host: the
    /// fixture answers only a body holding the negotiation, the encoding
    /// is forwarded, and the ledger entry names the hop it was served from.
    #[test]
    fn a_redirected_git_post_keeps_its_gzip_body() {
        let harness = Harness::new("intercept-git-post");
        let (session, address) = intercepting(&harness, Policy::default());
        let authority = format!("third.test:{}", harness.upstream.port());
        let negotiation = b"0014command=ls-refs\n0009peel\n0000".to_vec();
        let body = gzip(&negotiation);
        let (from, to) = ("/a/repo.git/git-upload-pack", "/b/repo.git/git-upload-pack");
        harness.upstream.set(
            from,
            Behavior::Reply(Reply::new(307, b"").header("location", to)),
        );
        harness
            .upstream
            .set(to, Behavior::Reply(Reply::new(200, b"0000")));
        harness.upstream.require_body(to, &[&body]);
        let roots = harness.proxy.authority().roots();
        let mut tunnel = open_tunnel(&address, &authority, "third.test", roots, &[]).unwrap();
        let answer = tunnel_request(&mut tunnel, &post(&authority, from, &body, true), &body);
        assert_eq!(answer.status, 200, "{}", answer.text());
        drop(tunnel);
        let report = session.finish();
        let seen = harness.upstream.seen();
        let at = |target: &str| {
            seen.iter()
                .find(|request| request.target == target)
                .unwrap()
        };
        for target in [from, to] {
            assert_eq!(at(target).method, "POST");
            assert_eq!(at(target).body, body, "{target}");
            assert_eq!(at(target).headers.get("content-encoding"), Some("gzip"));
        }
        let origin = format!("https://{authority}");
        assert!(
            entries(&report).iter().any(|entry| entry.class == "git"
                && entry.url == format!("{origin}{from}")
                && entry.redirected_to.as_deref() == Some(&format!("{origin}{to}"))
                && entry.status == 200),
            "{:?}",
            entries(&report)
        );

        // The same POST with the negotiation dropped is not answered.
        let harness = Harness::new("intercept-git-post-empty");
        let (_session, address) = intercepting(&harness, Policy::default());
        let authority = format!("third.test:{}", harness.upstream.port());
        harness
            .upstream
            .set(from, Behavior::Reply(Reply::new(200, b"0000")));
        harness.upstream.require_body(from, &[&body]);
        let roots = harness.proxy.authority().roots();
        let mut tunnel = open_tunnel(&address, &authority, "third.test", roots, &[]).unwrap();
        let answer = tunnel_request(&mut tunnel, &post(&authority, from, b"", true), b"");
        assert_eq!(answer.status, 400, "{}", answer.text());
    }

    /// A 307 from `git-upload-pack` to `git-receive-pack` would forward the
    /// POST and its body to a push endpoint: every hop is classified
    /// again, and a push is refused on any hop.
    #[test]
    fn a_redirect_cannot_turn_a_fetch_into_a_push() {
        let harness = Harness::new("intercept-git-push");
        let (session, address) = intercepting(&harness, Policy::default());
        let authority = format!("third.test:{}", harness.upstream.port());
        let (from, to) = (
            "/a/repo.git/git-upload-pack",
            "/a/repo.git/git-receive-pack",
        );
        harness.upstream.set(
            from,
            Behavior::Reply(Reply::new(307, b"").header("location", to)),
        );
        harness
            .upstream
            .set(to, Behavior::Reply(Reply::new(200, b"pushed")));
        let roots = harness.proxy.authority().roots();
        let mut tunnel = open_tunnel(&address, &authority, "third.test", roots, &[]).unwrap();
        let body = b"0000".to_vec();
        let answer = tunnel_request(&mut tunnel, &post(&authority, from, &body, false), &body);
        assert_eq!(answer.status, 403, "{}", answer.text());
        assert!(
            answer.text().contains("git-receive-pack"),
            "{}",
            answer.text()
        );
        drop(tunnel);
        let report = session.finish();
        assert_eq!(
            harness.upstream.hits(to),
            0,
            "the push endpoint was reached"
        );
        assert!(entries(&report).iter().all(|entry| entry.status != 200));
    }

    /// A git discovery request that redirects, on the same host, to a path
    /// that is not git changes class: the hop answers to `unattested-index`
    /// as a first request would, refused when the kind is denied and
    /// recorded as the exception when it is not.
    #[test]
    fn a_redirect_out_of_a_git_fetch_answers_to_the_new_class_policy() {
        for (policy, served) in [
            (Policy::default(), true),
            (deny(policy::UNATTESTED_INDEX), false),
        ] {
            let harness = Harness::new("intercept-git-class");
            let (session, address) = intercepting(&harness, policy);
            let authority = format!("third.test:{}", harness.upstream.port());
            let from = "/a/repo.git/info/refs?service=git-upload-pack";
            harness.upstream.set(
                from,
                Behavior::Reply(Reply::new(302, b"").header("location", "/meta/pkg.json")),
            );
            let roots = harness.proxy.authority().roots();
            let mut tunnel = open_tunnel(&address, &authority, "third.test", roots, &[]).unwrap();
            let answer = tunnel_request(&mut tunnel, &get(&authority, from), b"");
            drop(tunnel);
            let report = session.finish();
            let origin = format!("https://{authority}");
            if served {
                assert_eq!(answer.status, 200, "{}", answer.text());
                let facts: Vec<_> = report.facts.exceptions.iter().collect();
                assert_eq!(facts.len(), 1, "{facts:?}");
                assert_eq!(facts[0].kind, policy::UNATTESTED_INDEX);
                assert_eq!(facts[0].subject, origin);
                assert!(entries(&report).iter().any(|entry| entry.class == "git"
                    && entry.redirected_to.as_deref() == Some(&format!("{origin}/meta/pkg.json"))));
            } else {
                assert_eq!(answer.status, 403, "{}", answer.text());
                assert_eq!(harness.upstream.hits("/meta/pkg.json"), 0);
                assert!(report.facts.exceptions.is_empty(), "{:?}", report.facts);
                assert_eq!(report.facts.refusals.len(), 1, "{:?}", report.facts);
            }
        }
    }

    /// A route whose protocol takes an encoded slash (npm's scoped
    /// packuments): `/@s%2fn` inside the tunnel reaches the route and is
    /// forwarded as spelled, while the strict grammar still refuses it on
    /// a host no such route serves, and `..` behind the encoded slash
    /// stays refused on the route host.
    #[test]
    fn a_route_may_take_an_encoded_slash_inside_the_tunnel() {
        struct Encoded;
        impl RegistryProtocol for Encoded {
            fn route_id(&self) -> &'static str {
                "fixture"
            }
            fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
                crate::kernel::resolve::routes::testing::TEST_PROTOCOL.upstream(endpoints, path)
            }
            fn classify(&self, url: &Url) -> RequestClass {
                crate::kernel::resolve::routes::testing::TEST_PROTOCOL.classify(url)
            }
            fn claims(&self, _url: &Url, _body: &[u8]) -> Vec<(Url, Claim)> {
                Vec::new()
            }
            fn encoded_slash(&self) -> bool {
                true
            }
        }
        static ENCODED: Encoded = Encoded;
        let harness = Harness::new("intercept-encoded-slash");
        harness.upstream.set(
            "/meta/@s%2fn.json",
            Behavior::Reply(Reply::new(200, b"{}").header("Content-Type", "application/json")),
        );
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.intercept = Intercept::Tls;
        config.routes = vec![Route::new(
            &ENCODED,
            vec![Endpoint::for_test("registry.test", harness.upstream.port())],
        )
        .unwrap()];
        let (session, address) = harness.open(config);
        let authority = format!("registry.test:{}", harness.upstream.port());
        let roots = harness.proxy.authority().roots();
        let mut tunnel =
            open_tunnel(&address, &authority, "registry.test", roots.clone(), &[]).unwrap();
        let scoped = tunnel_request(&mut tunnel, &get(&authority, "/meta/@s%2fn.json"), b"");
        assert_eq!(scoped.status, 200, "{}", scoped.text());
        let dotdot = tunnel_request(&mut tunnel, &get(&authority, "/meta/@s%2f../x.json"), b"");
        assert_eq!(dotdot.status, 403, "{}", dotdot.text());
        assert!(dotdot.text().contains(". or .."), "{}", dotdot.text());
        drop(tunnel);
        // The same path on an unrouted host meets the strict grammar.
        let other = format!("other.test:{}", harness.upstream.port());
        let mut tunnel = open_tunnel(&address, &other, "other.test", roots, &[]).unwrap();
        let strict = tunnel_request(&mut tunnel, &get(&other, "/meta/@s%2fn.json"), b"");
        assert_eq!(strict.status, 403, "{}", strict.text());
        assert!(
            strict.text().contains("percent-encoded"),
            "{}",
            strict.text()
        );
        drop(tunnel);
        let report = session.finish();
        assert_eq!(harness.upstream.hits("/meta/@s%2fn.json"), 1);
        assert!(entries(&report).iter().any(|entry| entry.url
            == harness.upstream_url("/meta/@s%2fn.json")
            && entry.status == 200));
    }

    fn fetch(url: &str, method: &str) -> Option<Result<String, String>> {
        git_fetch(&Url::parse(url).unwrap(), method)
    }

    #[test]
    fn git_fetches_are_recognized_by_their_smart_http_paths() {
        let repo = Some(Ok("https://github.com/dtolnay/itoa".to_string()));
        assert_eq!(
            fetch(
                "https://github.com/dtolnay/itoa/info/refs?service=git-upload-pack",
                "GET"
            ),
            repo
        );
        assert_eq!(
            fetch("https://github.com/dtolnay/itoa/git-upload-pack", "POST"),
            repo
        );
        assert_eq!(
            fetch(
                "https://api.github.com/repos/dtolnay/ryu/commits/1.0.18",
                "GET"
            ),
            Some(Ok("https://github.com/dtolnay/ryu".to_string()))
        );
        assert!(matches!(
            fetch("https://github.com/a/b/git-receive-pack", "POST"),
            Some(Err(_))
        ));
        assert!(matches!(
            fetch(
                "https://github.com/a/b/info/refs?service=git-receive-pack",
                "GET"
            ),
            Some(Err(_))
        ));
        for (url, method) in [
            ("https://github.com/a/b/info/refs", "GET"),
            ("https://github.com/a/b/git-upload-pack", "GET"),
            ("https://api.github.com/repos/a/b", "GET"),
            ("https://api.github.com/repos/a/b/commits/x", "POST"),
            ("https://index.crates.io/config.json", "GET"),
        ] {
            assert_eq!(fetch(url, method), None, "{method} {url}");
        }
    }

    #[test]
    fn the_host_header_must_name_the_tunnel() {
        let target = Target {
            host: "index.crates.io",
            port: 443,
            origin: "https://index.crates.io".into(),
        };
        for good in ["index.crates.io", "INDEX.crates.io", "index.crates.io:443"] {
            assert!(host_matches(Some(good), &target), "{good}");
        }
        for bad in [
            "static.crates.io",
            "index.crates.io:8443",
            "index.crates.io/x",
            "u@index.crates.io",
            "",
        ] {
            assert!(!host_matches(Some(bad), &target), "{bad}");
        }
        assert!(!host_matches(None, &target));
    }
}

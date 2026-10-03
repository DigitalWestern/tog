//! Test-only helpers for the resolution proxy. The module is declared under
//! `cfg(test)`, and each item carries its own `cfg(test)` too, because the
//! architecture scans read one file at a time and cannot see the gate on
//! the `mod` line.

#[cfg(test)]
use crate::kernel::activity::{ActivityMode, StoreActivity};
#[cfg(test)]
use crate::kernel::store::Store;
#[cfg(test)]
use crate::kernel::testutil::TempDir;

/// A scratch store with every namespace `Store::open` makes, and a shared
/// lease on it. Everything is removed when the `TempDir` drops.
#[cfg(test)]
pub(crate) fn scratch_store(label: &str) -> (TempDir, Store, StoreActivity) {
    let temp = TempDir::named(label);
    let root = temp.0.clone();
    for sub in [
        "objects",
        "meta",
        "cache/sha1",
        "cache/sha256",
        "cache/sha512",
        "tmp",
        "roots",
        "records",
        "root-locks",
    ] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    let activity = StoreActivity::acquire(&root, ActivityMode::Shared).unwrap();
    (temp, Store { root }, activity)
}

#[cfg(test)]
use super::http::Headers;
#[cfg(test)]
use super::proxy::{Proxy, ProxyConfig, Session};
#[cfg(test)]
use super::routes::testing::TEST_PROTOCOL;
#[cfg(test)]
use super::routes::{Endpoint, Permitted, ProxyAddress, Route};
#[cfg(test)]
use super::session::{Intercept, Mode, SessionConfig};
#[cfg(test)]
use super::ssrf::Lookup;
#[cfg(test)]
use crate::kernel::policy::Policy;
#[cfg(test)]
use crate::kernel::testutil::upstream::{FixtureCa, FixtureUpstream};
#[cfg(test)]
use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;

/// A globally routable address (TEST-NET would be refused) the SSRF tests
/// answer lookups with; `connect_to` lands it on the fixture listener.
#[cfg(test)]
pub(crate) const TEST_ORIGIN_PUBLIC: &str = "93.184.216.34";

/// The hosts the fixture upstream's certificate names. The first two are
/// the fixture route's endpoints; `third.test` is on the certificate but in
/// no permitted set, for redirect tests.
#[cfg(test)]
pub(crate) const FIXTURE_HOSTS: &[&str] = &["registry.test", "other.test", "third.test"];

/// A name lookup that answers from a function of (call number, host) and
/// counts its calls.
#[cfg(test)]
pub(crate) struct Answers {
    pub calls: AtomicUsize,
    hosts: std::sync::Mutex<Vec<String>>,
    answer: Box<dyn Fn(usize, &str) -> Vec<IpAddr> + Send + Sync>,
}

#[cfg(test)]
impl Answers {
    pub(crate) fn new(answer: impl Fn(usize, &str) -> Vec<IpAddr> + Send + Sync + 'static) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            hosts: std::sync::Mutex::new(Vec::new()),
            answer: Box::new(answer),
        }
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Every host looked up, in order.
    pub(crate) fn hosts(&self) -> Vec<String> {
        self.hosts.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Lookup for Answers {
    fn lookup(&self, host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.hosts.lock().unwrap().push(host.to_string());
        Ok((self.answer)(call, host))
    }
}

/// How a harness proxy reaches the fixture.
#[cfg(test)]
pub(crate) struct Reach {
    pub lookup: Arc<Answers>,
    /// The loopback exception. Off in the SSRF tests.
    pub allow_loopback: bool,
    /// Land every validated address on the fixture listener.
    pub redirect_to_fixture: bool,
    /// Connection threads in the proxy's pool.
    pub workers: usize,
    /// The slowest a tool may read a response (bytes/s).
    pub min_response_rate: u64,
    pub request_timeout: Duration,
}

#[cfg(test)]
impl Reach {
    /// Every fixture host is `127.0.0.1`, reachable through the test-only
    /// loopback exception.
    pub(crate) fn loopback() -> Self {
        Self {
            lookup: Arc::new(Answers::new(|_, _| vec!["127.0.0.1".parse().unwrap()])),
            allow_loopback: true,
            redirect_to_fixture: false,
            workers: 8,
            min_response_rate: 16 * 1024,
            request_timeout: Duration::from_secs(1),
        }
    }

    /// The SSRF setting: the loopback exception off, `answer` deciding
    /// what each lookup returns, and every validated address landing on
    /// the fixture listener.
    pub(crate) fn public(
        answer: impl Fn(usize, &str) -> Vec<IpAddr> + Send + Sync + 'static,
    ) -> Self {
        Self {
            lookup: Arc::new(Answers::new(answer)),
            allow_loopback: false,
            redirect_to_fixture: true,
            workers: 8,
            min_response_rate: 16 * 1024,
            request_timeout: Duration::from_secs(1),
        }
    }
}

#[cfg(test)]
pub(crate) use host::relay;

/// A scratch store, a fixture upstream serving the kernel registry, and a
/// proxy that trusts only the fixture's CA.
#[cfg(test)]
pub(crate) struct Harness {
    pub store: Store,
    pub activity: StoreActivity,
    pub upstream: FixtureUpstream,
    pub proxy: Proxy,
    pub lookup: Arc<Answers>,
    _ca: FixtureCa,
    _temp: TempDir,
}

#[cfg(test)]
impl Harness {
    pub(crate) fn new(label: &str) -> Self {
        Self::with(label, Reach::loopback())
    }

    pub(crate) fn with(label: &str, reach: Reach) -> Self {
        Self::serving(label, reach, FIXTURE_HOSTS, "kernel")
    }

    /// A harness whose upstream answers for `hosts` from the recorded
    /// registry `tests/fixtures/proxy/registry/<registry>`.
    pub(crate) fn serving(label: &str, reach: Reach, hosts: &[&str], registry: &str) -> Self {
        let (temp, store, activity) = scratch_store(label);
        let ca = FixtureCa::new();
        let upstream = FixtureUpstream::start(&ca, hosts);
        upstream.load_registry(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/proxy/registry")
                .join(registry),
        );
        let fixture = upstream.address();
        let connect_to: Option<Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>> =
            if reach.redirect_to_fixture {
                Some(Arc::new(move |_| fixture))
            } else {
                None
            };
        let proxy = Proxy::new(ProxyConfig {
            roots: ca.roots(),
            lookup: reach.lookup.clone(),
            workers: reach.workers,
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            request_timeout: reach.request_timeout,
            min_response_rate: reach.min_response_rate,
            allow_loopback: reach.allow_loopback,
            connect_to,
        })
        .unwrap();
        Self {
            store,
            activity,
            upstream,
            proxy,
            lookup: reach.lookup,
            _ca: ca,
            _temp: temp,
        }
    }

    /// The fixture route: `registry.test` and `other.test` on the fixture
    /// port, both permitted.
    pub(crate) fn route(&self) -> Route {
        let port = self.upstream.port();
        Route::new(
            &TEST_PROTOCOL,
            vec![
                Endpoint::for_test("registry.test", port),
                Endpoint::for_test("other.test", port),
            ],
        )
        .unwrap()
    }

    pub(crate) fn permitted(&self) -> Permitted {
        let port = self.upstream.port();
        Permitted::compiled()
            .with_origin("registry.test", port)
            .with_origin("other.test", port)
    }

    pub(crate) fn config(&self, policy: Policy, mode: Mode) -> SessionConfig {
        SessionConfig {
            ecosystem: "fixture".into(),
            door: "edit".into(),
            routes: vec![self.route()],
            intercept: Intercept::RefuseVisibly,
            policy,
            mode,
            store: self.store.clone(),
            activity: self.activity.clone(),
            permitted: self.permitted(),
        }
    }

    pub(crate) fn open(&self, config: SessionConfig) -> (Session, ProxyAddress) {
        let mut session = self.proxy.open_session(config).unwrap();
        let address = session.listen_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        (session, address)
    }

    /// A session with the fixture route, an empty policy, online.
    pub(crate) fn session(&self) -> (Session, ProxyAddress) {
        self.open(self.config(Policy::default(), Mode::Online))
    }

    /// The upstream URL of a fixture path, as the ledger records it.
    pub(crate) fn upstream_url(&self, path: &str) -> String {
        format!("https://registry.test:{}{path}", self.upstream.port())
    }
}

/// The mirror path of a fixture route path.
#[cfg(test)]
pub(crate) fn mirror(address: &ProxyAddress, path: &str) -> String {
    format!("/{}/fixture{path}", address.token())
}

/// A response as a tool reads it.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

#[cfg(test)]
impl Response {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Send `head` (a request head without its final blank line; `Connection:
/// close` is added) and read the whole answer.
#[cfg(test)]
pub(crate) fn send(address: &ProxyAddress, head: &str) -> Response {
    let mut stream = TcpStream::connect(address.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(stream, "{head}Connection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    parse_response(&raw)
}

/// `GET <path>` with `extra` header lines (each ending in CRLF).
#[cfg(test)]
pub(crate) fn get(address: &ProxyAddress, path: &str, extra: &str) -> Response {
    send(
        address,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{extra}",
            address.address
        ),
    )
}

#[cfg(test)]
fn parse_response(raw: &[u8]) -> Response {
    let end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response head in {:?}", String::from_utf8_lossy(raw)));
    let head = std::str::from_utf8(&raw[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = Headers::new();
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        headers.push(name.trim(), value.trim());
    }
    let rest = &raw[end + 4..];
    // A head read on its own (its body still on the wire) has no body yet.
    let body = if rest.is_empty() {
        Vec::new()
    } else if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        dechunk(rest)
    } else {
        let length = headers
            .get("content-length")
            .map_or(rest.len(), |value| value.parse().unwrap());
        rest[..length.min(rest.len())].to_vec()
    };
    Response {
        status,
        headers,
        body,
    }
}

#[cfg(test)]
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).unwrap(), 16).unwrap();
        raw = &raw[line_end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

/// A TLS client inside an intercepted tunnel, playing the tool.
#[cfg(test)]
pub(crate) type TlsTunnel = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// `CONNECT authority` with `token`, then a TLS handshake naming
/// `server_name`, trusting `roots` and offering `alpn`. The error is the
/// refused `CONNECT`'s status or the handshake's failure.
#[cfg(test)]
pub(crate) fn open_tunnel(
    address: &ProxyAddress,
    authority: &str,
    server_name: &str,
    roots: rustls::RootCertStore,
    alpn: &[&[u8]],
) -> io::Result<TlsTunnel> {
    let mut stream = TcpStream::connect(address.address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
        proxy_authorization(address.token())
    )?;
    let head = read_head_bytes(&mut stream)?;
    let status = std::str::from_utf8(&head)
        .ok()
        .and_then(|head| head.split(' ').nth(1))
        .and_then(|status| status.parse::<u16>().ok());
    if status != Some(200) {
        return Err(io::Error::other(format!(
            "CONNECT answered {}",
            String::from_utf8_lossy(&head)
        )));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(io::Error::other)?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(io::Error::other)?;
    let mut tunnel = rustls::StreamOwned::new(conn, stream);
    while tunnel.conn.is_handshaking() {
        tunnel.conn.complete_io(&mut tunnel.sock)?;
    }
    Ok(tunnel)
}

/// Send `head` (without its final blank line) and `body` inside `tunnel`,
/// and read exactly one response, so the tunnel can carry the next.
#[cfg(test)]
pub(crate) fn tunnel_request(tunnel: &mut TlsTunnel, head: &str, body: &[u8]) -> Response {
    tunnel.write_all(format!("{head}\r\n").as_bytes()).unwrap();
    tunnel.write_all(body).unwrap();
    tunnel.flush().unwrap();
    let raw_head = read_head_bytes(tunnel).unwrap();
    let mut response = parse_response(&raw_head);
    let mut body = Vec::new();
    if response
        .headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let line = read_line_bytes(tunnel);
            let size = usize::from_str_radix(line.trim(), 16).unwrap();
            let mut chunk = vec![0u8; size + 2];
            tunnel.read_exact(&mut chunk).unwrap();
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = response.headers.get("content-length") {
        body = vec![0u8; length.parse().unwrap()];
        tunnel.read_exact(&mut body).unwrap();
    }
    response.body = body;
    response
}

/// Bytes up to and including the blank line that ends a head, read one at
/// a time so nothing after it is consumed.
#[cfg(test)]
fn read_head_bytes(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("closed after {:?}", String::from_utf8_lossy(&head)),
            ));
        }
        head.push(byte[0]);
    }
    Ok(head)
}

#[cfg(test)]
fn read_line_bytes(stream: &mut impl Read) -> String {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "closed mid-chunk");
        line.push(byte[0]);
    }
    String::from_utf8(line).unwrap()
}

/// `Proxy-Authorization` carrying `token`.
#[cfg(test)]
pub(crate) fn proxy_authorization(token: &str) -> String {
    let encoded = crate::kernel::dirhash::base64_encode(format!("tog:{token}").as_bytes());
    format!("Proxy-Authorization: Basic {encoded}\r\n")
}

/// The sandbox-host checks. A module of its own, last in the file, so the
/// architecture test reads it as test code: a skip message is for whoever
/// ran the suite.
#[cfg(test)]
mod host {
    /// `TOG_SANDBOX_TESTS=required` (any non-empty value) turns a skip into
    /// a panic, so CI cannot report a skipped check as passed.
    fn skip_or_panic(test: &str, reason: impl std::fmt::Display) {
        if matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty()) {
            panic!("required Linux sandbox test {test} unavailable: {reason}");
        }
        eprintln!("skip {test}: {reason}");
    }

    /// The tog binary cargo built beside this test binary, which the
    /// sandbox binds as the relay; `None` (after a skip) when the host
    /// cannot run a confined door.
    pub(crate) fn relay(test: &str) -> Option<std::path::PathBuf> {
        if !matches!(
            crate::kernel::platform::Platform::host(),
            Ok(crate::kernel::platform::Platform::X86_64UnknownLinuxGnu)
        ) {
            skip_or_panic(test, "not a supported Linux host");
            return None;
        }
        if let Err(error) = crate::kernel::sandbox::bwrap_preflight_with_activity(None) {
            skip_or_panic(test, format!("bubblewrap preflight failed: {error}"));
            return None;
        }
        let exe = std::env::current_exe().unwrap();
        let tog = exe
            .parent()
            .and_then(std::path::Path::parent)
            .map(|dir| dir.join("tog"));
        match tog {
            Some(tog) if tog.is_file() => Some(tog),
            _ => {
                skip_or_panic(
                    test,
                    format!(
                        "no tog binary beside {} (run `cargo test`, which builds it)",
                        exe.display()
                    ),
                );
                None
            }
        }
    }
}

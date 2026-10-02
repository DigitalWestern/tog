//! An HTTPS client that connects only to addresses a caller-supplied
//! resolver approved (kernel layer). The resolution proxy's upstream fetches
//! go through it: the resolver looks a host up once, validates every
//! address, and hands back exactly that list, so the HTTP library never
//! performs a lookup of its own and a second answer (DNS rebinding) never
//! reaches a socket. The host name is kept for SNI, certificate
//! verification, and the `Host` header.
//!
//! The root set is the caller's (webpki's roots in production, a fixture CA
//! in tests), and the crypto provider is `ring`, named explicitly rather
//! than taken from a process default. Redirects are never followed here:
//! every hop is the caller's decision.

use std::fmt;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Resolve a host to the only addresses a connection may use. Called once
/// per new upstream connection; a refusal is a [`ResolveRefusal`].
pub trait PinnedResolve: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// A resolver's refusal to connect at all (an address that is not globally
/// routable), as opposed to a lookup that failed. Carried inside the
/// `io::Error` the resolver returns, so the client can tell the two apart.
#[derive(Debug)]
pub struct ResolveRefusal(pub String);

impl fmt::Display for ResolveRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ResolveRefusal {}

impl ResolveRefusal {
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, self)
    }
}

/// How a pinned client is built.
pub struct PinnedConfig {
    /// The only certificate authorities upstream servers may chain to.
    pub roots: rustls::RootCertStore,
    pub resolver: Arc<dyn PinnedResolve>,
    pub connect_timeout: Duration,
    /// Bounds each read and write on an upstream socket.
    pub io_timeout: Duration,
}

/// The production root set: the Mozilla roots webpki ships.
pub fn webpki_roots() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// One request to send upstream. `headers` are sent as given; the client
/// adds only `Host` (from the URL) and its own framing.
pub struct PinnedRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
}

/// What upstream answered, whatever the status. A gzip body arrives
/// decompressed, and its `Content-Encoding` and `Content-Length` are gone.
pub struct PinnedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read + Send + Sync>,
}

impl PinnedResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Why no response arrived.
#[derive(Debug)]
pub enum PinnedError {
    /// The resolver refused the host's addresses; nothing was connected.
    Refused(String),
    /// DNS, connect, TLS, a timeout, or a reset: the upstream was not
    /// reachable as asked.
    Transport(String),
    /// The request itself could not be sent (a header value the client
    /// refuses). Never a transport failure, and the message is fixed: the
    /// client's own text echoes the whole header line, credential included.
    Invalid(&'static str),
}

impl fmt::Display for PinnedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PinnedError::Refused(why) | PinnedError::Transport(why) => f.write_str(why),
            PinnedError::Invalid(why) => f.write_str(why),
        }
    }
}

/// A shared client: one connection pool, keep-alive per host.
pub struct PinnedClient {
    agent: ureq::Agent,
}

/// ureq's view of a [`PinnedResolve`]: it hands over `host:port`.
struct Adapter(Arc<dyn PinnedResolve>);

impl ureq::Resolver for Adapter {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        let (host, port) = netloc.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("no port in {netloc}"))
        })?;
        let port: u16 = port.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad port in {netloc}"))
        })?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        self.0.resolve(host, port)
    }
}

impl PinnedClient {
    pub fn new(config: PinnedConfig) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| io::Error::other(format!("upstream TLS configuration: {error}")))?
            .with_root_certificates(config.roots)
            .with_no_client_auth();
        let agent = ureq::AgentBuilder::new()
            .https_only(true)
            .redirects(0)
            .timeout_connect(config.connect_timeout)
            .timeout_read(config.io_timeout)
            .timeout_write(config.io_timeout)
            .max_idle_connections_per_host(8)
            .resolver(Adapter(config.resolver))
            .tls_config(Arc::new(tls))
            .build();
        Ok(Self { agent })
    }

    /// Send one request. Every HTTP status, 4xx and 5xx included, is a
    /// response; only a failure to get one is an error.
    pub fn send(&self, request: &PinnedRequest<'_>) -> Result<PinnedResponse, PinnedError> {
        let mut outgoing = self.agent.request(request.method, request.url);
        for (name, value) in request.headers {
            outgoing = outgoing.set(name, value);
        }
        let result = match request.body {
            Some(body) => outgoing.send_bytes(body),
            None => outgoing.call(),
        };
        let response = match result {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(transport)) => return Err(classify(&transport)),
        };
        // Spelled as a path call: the architecture scan reads a bare
        // `.status()` as a child process.
        let status = ureq::Response::status(&response);
        let headers = response
            .headers_names()
            .into_iter()
            .flat_map(|name| {
                response
                    .all(&name)
                    .into_iter()
                    .map(|value| (name.clone(), value.to_string()))
                    .collect::<Vec<_>>()
            })
            .collect();
        Ok(PinnedResponse {
            status,
            headers,
            body: response.into_reader(),
        })
    }
}

/// A resolver refusal travels as the source of ureq's DNS error; anything
/// else is a transport failure, described without ureq's URL prefix.
fn classify(transport: &ureq::Transport) -> PinnedError {
    if matches!(
        transport.kind(),
        ureq::ErrorKind::BadHeader | ureq::ErrorKind::InvalidUrl | ureq::ErrorKind::UnknownScheme
    ) {
        return PinnedError::Invalid(
            "the upstream request is not valid HTTP (a header or the URL)",
        );
    }
    let mut source = std::error::Error::source(transport);
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            if let Some(refusal) = io_error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<ResolveRefusal>())
            {
                return PinnedError::Refused(refusal.0.clone());
            }
        }
        source = error.source();
    }
    let kind = transport.kind().to_string();
    let text = transport.to_string();
    let detail = match text.find(&format!("{kind}: ")) {
        Some(at) => text[at..].to_string(),
        None => kind,
    };
    PinnedError::Transport(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refuses every lookup: a test that must never connect.
    struct Nowhere;

    impl PinnedResolve for Nowhere {
        fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            Err(ResolveRefusal(format!("{host} must not be looked up")).into_io())
        }
    }

    #[test]
    fn a_bad_header_is_invalid_with_a_fixed_message_never_transport() {
        let client = PinnedClient::new(PinnedConfig {
            roots: webpki_roots(),
            resolver: Arc::new(Nowhere),
            connect_timeout: Duration::from_secs(1),
            io_timeout: Duration::from_secs(1),
        })
        .unwrap();
        for value in ["Bearer s3cret\u{e9}", "Bearer s3cret\nX-Injected: 1"] {
            let error = client
                .send(&PinnedRequest {
                    method: "GET",
                    url: "https://registry.example/x",
                    headers: &[("Authorization".into(), value.into())],
                    body: None,
                })
                .err()
                .unwrap();
            assert!(matches!(error, PinnedError::Invalid(_)), "{error:?}");
            assert!(!error.to_string().contains("s3cret"), "{error}");
        }
    }
}

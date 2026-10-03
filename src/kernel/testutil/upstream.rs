//! A fixture upstream for resolution-proxy tests: a local HTTPS server with
//! its own certificate authority, serving a miniature registry from
//! `tests/fixtures/proxy/registry/<ecosystem>/` (the `index.json` that lists
//! each URL's status, headers, sha256, and body `file`) plus whatever a test
//! sets by hand. It records every request it answers, with the TLS server
//! name the client sent, so tests can check SNI, `Host`, and which headers
//! reached upstream.
//!
//! The CA and leaf are minted per run (`rcgen`, ring backend), so no private
//! key is checked in. TLS is real: the proxy's upstream client trusts only
//! this CA, exactly as production trusts only the webpki roots.

use crate::kernel::resolve::http::{self, Headers};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// A certificate authority minted for one test run.
pub(crate) struct FixtureCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl FixtureCa {
    pub(crate) fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "tog fixture upstream CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    /// The CA certificate as PEM, for a tool that trusts it directly.
    pub(crate) fn pem(&self) -> String {
        self.cert.pem()
    }

    /// The root set that trusts this CA and nothing else.
    pub(crate) fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        roots
    }

    /// A leaf for `names` (DNS names or IP literals), signed by this CA.
    fn leaf(&self, names: &[&str]) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

/// One canned answer.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub(crate) fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// What the server does for one path.
#[derive(Clone)]
pub(crate) enum Behavior {
    Reply(Reply),
    /// Accept the request, then drop the connection without an answer: a
    /// transport failure as the proxy sees it.
    Drop,
}

/// One request the server received.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub method: String,
    pub target: String,
    pub headers: Headers,
    /// The TLS server name the client sent (SNI).
    pub sni: Option<String>,
}

type Routes = Arc<Mutex<HashMap<String, Behavior>>>;

/// A running fixture upstream. Stops when dropped.
pub(crate) struct FixtureUpstream {
    address: SocketAddr,
    routes: Routes,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl FixtureUpstream {
    /// Listen on `127.0.0.1:<ephemeral>` with a leaf for `names`.
    pub(crate) fn start(ca: &FixtureCa, names: &[&str]) -> Self {
        let (chain, key) = ca.leaf(names);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let routes: Routes = Arc::default();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let (routes, seen, stop) = (routes.clone(), seen.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (config, routes, seen) = (config.clone(), routes.clone(), seen.clone());
                    std::thread::spawn(move || serve(stream, config, routes, seen));
                }
            })
        };
        Self {
            address,
            routes,
            seen,
            stop,
            accept: Some(accept),
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.address.port()
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Serve `behavior` for the request target `target` (path and query).
    pub(crate) fn set(&self, target: &str, behavior: Behavior) {
        self.routes
            .lock()
            .unwrap()
            .insert(target.to_string(), behavior);
    }

    /// Serve every response `dir/index.json` lists, by path and query. Each
    /// body is checked against its listed sha256 first, so an edited fixture
    /// fails here rather than as a confusing proxy result.
    pub(crate) fn load_registry(&self, dir: &Path) {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
        for row in index.as_array().unwrap() {
            let url = url::Url::parse(row["url"].as_str().unwrap()).unwrap();
            let body = match row["file"].as_str() {
                Some(file) => std::fs::read(dir.join(file)).unwrap(),
                None => Vec::new(),
            };
            let digest = hex::encode(Sha256::digest(&body));
            assert_eq!(
                Some(digest.as_str()),
                row["sha256"].as_str(),
                "fixture body for {url} does not match its index sha256"
            );
            let mut reply = Reply::new(row["status"].as_u64().unwrap() as u16, &body);
            if let Some(headers) = row["headers"].as_object() {
                for (name, value) in headers {
                    reply = reply.header(name, value.as_str().unwrap());
                }
            }
            let target = match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_string(),
            };
            self.set(&target, Behavior::Reply(reply));
        }
    }

    /// Every request received so far.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Requests received for `target`.
    pub(crate) fn hits(&self, target: &str) -> usize {
        self.seen()
            .iter()
            .filter(|seen| seen.target == target)
            .count()
    }
}

impl Drop for FixtureUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

/// Serve one connection: finish the handshake, then answer requests until
/// the client closes.
fn serve(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    routes: Routes,
    seen: Arc<Mutex<Vec<Seen>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(connection) = rustls::ServerConnection::new(config) else {
        return;
    };
    let mut tls = rustls::StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        if tls.conn.complete_io(&mut tls.sock).is_err() {
            return;
        }
    }
    let sni = tls.conn.server_name().map(str::to_string);
    let mut reader = BufReader::new(tls);
    loop {
        let Ok(request) = http::read_request(&mut reader) else {
            return;
        };
        let record = Seen {
            method: request.method.clone(),
            target: request.target.clone(),
            headers: request.headers.clone(),
            sni: sni.clone(),
        };
        seen.lock().unwrap().push(record);
        let behavior = routes.lock().unwrap().get(&request.target).cloned();
        let reply = match behavior {
            Some(Behavior::Reply(reply)) => reply,
            Some(Behavior::Drop) => return,
            None => Reply::new(404, b"no such fixture"),
        };
        let reply = conditional(&request.headers, reply);
        let mut headers = Headers::new();
        for (name, value) in &reply.headers {
            headers.push(name, value);
        }
        let head_only = request.method == "HEAD";
        let out = reader.get_mut();
        if http::write_response(out, reply.status, &headers, &reply.body, true, head_only).is_err()
        {
            return;
        }
    }
}

/// Answer 304 when the request's validator matches the reply's.
fn conditional(request: &Headers, reply: Reply) -> Reply {
    let find = |name: &str| {
        reply
            .headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let matches = match (request.get("if-none-match"), find("etag")) {
        (Some(sent), Some(etag)) => sent == etag,
        _ => match (request.get("if-modified-since"), find("last-modified")) {
            (Some(sent), Some(modified)) => sent == modified,
            _ => false,
        },
    };
    if reply.status == 200 && matches {
        Reply {
            status: 304,
            headers: reply.headers,
            body: Vec::new(),
        }
    } else {
        reply
    }
}

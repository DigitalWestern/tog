//! The proxy server: listeners, the worker pool, and the two dialects a
//! tool speaks to it.
//!
//! One proxy per tog process ([`proxy`]), started on the first door. It
//! owns the upstream client (one connection pool, the validating resolver)
//! and a pool of at most 64 connection threads shared by every session.
//! A listener takes a pool slot before it accepts, so a connection beyond
//! the pool waits in the kernel's accept backlog instead of being refused
//! (uv opens up to 50 downloads at once). Threads, not async: tog has no
//! async runtime.
//!
//! Sessions ([`Session`]) are per door run. Each has its own listeners,
//! token, and ledger, so a request is always judged by the session whose
//! listener it arrived on, and a token from another session is just a
//! wrong token.
//!
//! The dialects:
//!
//! - **Forward proxy.** `CONNECT host:port` carries the token as the
//!   password of `Proxy-Authorization: Basic`, checked once per tunnel.
//!   Without it the answer is 407. With it, the tunnel belongs to this
//!   session. A session that intercepts ([`Intercept::Tls`]) terminates
//!   the tunnel with a leaf from the process's own authority
//!   ([`super::ca`]) and serves the requests inside it
//!   ([`super::intercept`]). A session that does not refuses it visibly
//!   (403, a body naming the host and the reason, a `refused` ledger
//!   entry, and an `unattested-index` or, for `git://`'s port,
//!   `git-dependency` fact). `git://`'s port is refused either way.
//!   Absolute-form requests
//!   (`GET http://...`, `git://...`) are refused the same way: every
//!   registry is https.
//! - **Registry mirror.** `GET http://127.0.0.1:<port>/<token>/<route>/...`
//!   is routed through the route's protocol and served by
//!   [`super::mirror`].

use super::ca::Authority;
use super::http::{self, Headers, ParseError, Request};
use super::mirror::{self, Exchange, Record};
use super::redact::{self, REDACTED};
use super::routes::{ProxyAddress, Upstream};
use super::session::{Intercept, SessionConfig, SessionReport, State};
use super::ssrf::{Lookup, SystemLookup, ValidatingResolver};
use crate::kernel::fetch::pinned::{self, PinnedClient, PinnedConfig};
use crate::kernel::policy;
use std::collections::{HashMap, VecDeque};
use std::io::BufRead;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The git protocol's port: a `CONNECT` there is a `git://` fetch.
const GIT_PORT: u16 = 9418;

/// How the process's proxy is built.
pub struct ProxyConfig {
    /// The certificate authorities upstream registries may chain to.
    pub roots: rustls::RootCertStore,
    pub lookup: Arc<dyn Lookup>,
    /// Connection threads, shared by every session.
    pub workers: usize,
    pub connect_timeout: Duration,
    /// Bounds each upstream read and write.
    pub io_timeout: Duration,
    /// How long a kept-alive tool connection may sit idle between
    /// requests. It is closed sooner when the pool is full.
    pub idle_timeout: Duration,
    /// How long a tool has to send one whole request (head and body) once
    /// it has started, and to start the first one on a new connection. A
    /// client trickling bytes cannot hold a worker past it.
    pub request_timeout: Duration,
    /// The slowest a tool may read a response once the first `io_timeout`
    /// has passed (bytes per second), so a tool reading one byte a minute
    /// cannot hold a worker forever.
    pub min_response_rate: u64,
    /// Tests only: see [`ValidatingResolver`].
    #[cfg(test)]
    pub(crate) allow_loopback: bool,
    #[cfg(test)]
    pub(crate) connect_to: Option<Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>>,
}

impl ProxyConfig {
    /// Production: webpki roots and the system resolver.
    pub fn system() -> ProxyConfig {
        ProxyConfig {
            roots: pinned::webpki_roots(),
            lookup: Arc::new(SystemLookup),
            workers: 64,
            connect_timeout: Duration::from_secs(15),
            io_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(30),
            min_response_rate: 16 * 1024,
            #[cfg(test)]
            allow_loopback: false,
            #[cfg(test)]
            connect_to: None,
        }
    }
}

/// The resolution proxy.
pub struct Proxy {
    shared: Arc<Shared>,
}

pub(super) struct Shared {
    pub(super) client: PinnedClient,
    /// The process's certificate authority, which signs the leaf of every
    /// intercepted tunnel.
    pub(super) authority: Authority,
    pool: Arc<Pool>,
    idle_timeout: Duration,
    pub(super) request_timeout: Duration,
    /// Bounds each write to a tool.
    write_timeout: Duration,
    response_grace: Duration,
    min_response_rate: u64,
    drain_timeout: Duration,
}

/// The process's proxy, started on first use.
pub fn proxy() -> io::Result<&'static Proxy> {
    static PROXY: OnceLock<Proxy> = OnceLock::new();
    static START: Mutex<()> = Mutex::new(());
    if let Some(proxy) = PROXY.get() {
        return Ok(proxy);
    }
    let _starting = START.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(proxy) = PROXY.get() {
        return Ok(proxy);
    }
    let started = Proxy::new(ProxyConfig::system())?;
    Ok(PROXY.get_or_init(|| started))
}

impl Proxy {
    pub fn new(config: ProxyConfig) -> io::Result<Proxy> {
        if config.workers == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the proxy needs at least one worker",
            ));
        }
        #[allow(unused_mut)]
        let mut resolver = ValidatingResolver::new(config.lookup);
        #[cfg(test)]
        {
            resolver.allow_loopback = config.allow_loopback;
            resolver.connect_to = config.connect_to;
        }
        let client = PinnedClient::new(PinnedConfig {
            roots: config.roots,
            resolver: Arc::new(resolver),
            connect_timeout: config.connect_timeout,
            io_timeout: config.io_timeout,
        })?;
        Ok(Proxy {
            shared: Arc::new(Shared {
                client,
                authority: Authority::new()?,
                pool: Arc::new(Pool::new(config.workers)),
                idle_timeout: config.idle_timeout,
                request_timeout: config.request_timeout,
                write_timeout: config.io_timeout,
                response_grace: config.io_timeout,
                min_response_rate: config.min_response_rate,
                drain_timeout: config.connect_timeout + config.io_timeout * 2,
            }),
        })
    }

    /// The certificate authority intercepted tunnels are signed by: its
    /// certificate is what an intercepting door tells the tool to trust.
    pub fn authority(&self) -> &Authority {
        &self.shared.authority
    }

    /// Open a session for one door run. Every route endpoint must be in
    /// the session's permitted set.
    pub fn open_session(&self, config: SessionConfig) -> io::Result<Session> {
        Ok(Session {
            state: Arc::new(State::new(config)?),
            shared: self.shared.clone(),
            listeners: Vec::new(),
            addresses: Vec::new(),
            live: Arc::new(Live::default()),
            stopped: false,
        })
    }
}

/// One door run's proxy session. Stops its listeners and connections when
/// finished or dropped.
pub struct Session {
    state: Arc<State>,
    shared: Arc<Shared>,
    listeners: Vec<Listening>,
    addresses: Vec<ProxyAddress>,
    live: Arc<Live>,
    stopped: bool,
}

struct Listening {
    stop: Arc<AtomicBool>,
    /// A Unix socket's path, removed when the session stops.
    unix_path: Option<PathBuf>,
    thread: Option<JoinHandle<()>>,
}

impl Session {
    /// The session token. Every output check looks for it.
    pub fn token(&self) -> &str {
        self.state.token()
    }

    /// Every address this session was advertised at.
    pub fn addresses(&self) -> &[ProxyAddress] {
        &self.addresses
    }

    /// Listen on TCP at `bind` (normally `127.0.0.1:0`). The tool reaches
    /// the proxy at the bound address.
    pub fn listen_tcp(&mut self, bind: SocketAddr) -> io::Result<ProxyAddress> {
        let listener = TcpListener::bind(bind)?;
        let bound = listener.local_addr()?;
        let address = ProxyAddress::new(bound, self.state.token());
        self.state.note_port(bound.port());
        self.start(listener, None, address.clone())?;
        Ok(address)
    }

    /// Listen on a Unix socket at `path`, for a relay that forwards a
    /// sandbox's TCP connections. `advertised` is where the tool sees the
    /// proxy, which rewritten responses point back at.
    pub fn listen_unix(&mut self, path: &Path, advertised: SocketAddr) -> io::Result<ProxyAddress> {
        let listener = UnixListener::bind(path)?;
        let address = ProxyAddress::new(advertised, self.state.token());
        self.start(listener, Some(path.to_path_buf()), address.clone())?;
        Ok(address)
    }

    fn start<L: Accept>(
        &mut self,
        listener: L,
        unix_path: Option<PathBuf>,
        address: ProxyAddress,
    ) -> io::Result<()> {
        // Nonblocking, so the accept loop polls with a timeout and sees
        // `stop` without anyone having to connect to wake it.
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let context = Context {
            state: self.state.clone(),
            shared: self.shared.clone(),
            address: address.clone(),
            live: self.live.clone(),
        };
        let thread = {
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("tog-proxy-accept".into())
                .spawn(move || accept_loop(listener, &stop, &context))?
        };
        self.listeners.push(Listening {
            stop,
            unix_path,
            thread: Some(thread),
        });
        self.addresses.push(address);
        Ok(())
    }

    /// Stop serving and hand back everything the session recorded.
    pub fn finish(mut self) -> SessionReport {
        self.stop();
        self.state.take_report()
    }

    fn stop(&mut self) {
        if std::mem::replace(&mut self.stopped, true) {
            return;
        }
        for listening in &self.listeners {
            listening.stop.store(true, Ordering::SeqCst);
        }
        self.shared.pool.wake_waiters();
        // Joining the accept loops closes the listeners (each loop owns
        // its listener) and guarantees no connection registers after the
        // sweep below.
        for listening in &mut self.listeners {
            if let Some(thread) = listening.thread.take() {
                let _ = thread.join();
            }
            if let Some(path) = &listening.unix_path {
                let _ = std::fs::remove_file(path);
            }
        }
        self.live.close_all(self.shared.drain_timeout);
        // Anything still running past the drain records nothing: the
        // report is taken, and the state refuses further facts.
        self.state.close();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What every connection of one listener shares.
#[derive(Clone)]
pub(super) struct Context {
    pub(super) state: Arc<State>,
    pub(super) shared: Arc<Shared>,
    pub(super) address: ProxyAddress,
    live: Arc<Live>,
}

/// A listener the accept loop can drive.
trait Accept: AsRawFd + Send + 'static {
    type Stream: Stream;
    fn accept_one(&self) -> io::Result<Self::Stream>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
    fn handle(stream: &Self::Stream) -> io::Result<Conn>;
}

/// A tool connection.
pub(super) trait Stream: Read + Write + Send + 'static {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }
}

impl Stream for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        UnixStream::set_nonblocking(self, nonblocking)
    }
}

impl Accept for TcpListener {
    type Stream = TcpStream;

    fn accept_one(&self) -> io::Result<TcpStream> {
        let (stream, _) = self.accept()?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpListener::set_nonblocking(self, nonblocking)
    }

    fn handle(stream: &TcpStream) -> io::Result<Conn> {
        stream.try_clone().map(Conn::Tcp)
    }
}

impl Accept for UnixListener {
    type Stream = UnixStream;

    fn accept_one(&self) -> io::Result<UnixStream> {
        self.accept().map(|(stream, _)| stream)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        UnixListener::set_nonblocking(self, nonblocking)
    }

    fn handle(stream: &UnixStream) -> io::Result<Conn> {
        stream.try_clone().map(Conn::Unix)
    }
}

/// A live connection, kept so `finish` can shut it down.
enum Conn {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Conn {
    fn shutdown(&self) {
        let _ = match self {
            Conn::Tcp(stream) => stream.shutdown(Shutdown::Both),
            Conn::Unix(stream) => stream.shutdown(Shutdown::Both),
        };
    }
}

/// A session's live connections.
#[derive(Default)]
struct Live {
    conns: Mutex<HashMap<u64, Conn>>,
    next: AtomicU64,
    drained: Condvar,
}

impl Live {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Conn>> {
        self.conns.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn register(&self, conn: Conn) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(id, conn);
        id
    }

    fn unregister(&self, id: u64) {
        self.lock().remove(&id);
        self.drained.notify_all();
    }

    /// Shut every connection down, then wait (bounded) for the threads
    /// serving them to record what they were doing.
    fn close_all(&self, bound: Duration) {
        let deadline = Instant::now() + bound;
        let mut conns = self.lock();
        for conn in conns.values() {
            conn.shutdown();
        }
        while !conns.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            conns = self
                .drained
                .wait_timeout(conns, left)
                .unwrap_or_else(|error| error.into_inner())
                .0;
        }
    }
}

/// A live connection's registration, removed when the serving job ends,
/// panic or not.
struct Registered {
    live: Arc<Live>,
    id: u64,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.live.unregister(self.id);
    }
}

/// Whether `listener` has a connection to accept within `wait`.
fn readable(listener: &impl AsRawFd, wait: Duration) -> bool {
    let mut poll = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for a descriptor this thread owns.
    let ready = unsafe { libc::poll(&mut poll, 1, wait.as_millis() as libc::c_int) };
    ready > 0
}

const ACCEPT_POLL: Duration = Duration::from_millis(100);

fn accept_loop<L: Accept>(listener: L, stop: &AtomicBool, context: &Context) {
    let pool = &context.shared.pool;
    loop {
        // The slot is taken before `accept`: while every worker is busy,
        // new connections wait in the backlog.
        let Some(permit) = pool.acquire(stop) else {
            return;
        };
        let stream = loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            if !readable(&listener, ACCEPT_POLL) {
                continue;
            }
            match listener.accept_one() {
                Ok(stream) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                // Out of descriptors, or an aborted handshake: back off
                // rather than spin.
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let shared = &context.shared;
        // BSD sockets inherit the listener's nonblocking flag.
        let configured = stream
            .set_nonblocking(false)
            .and_then(|()| stream.set_write_timeout(Some(shared.write_timeout)));
        let Ok(handle) = configured.and_then(|()| L::handle(&stream)) else {
            continue;
        };
        let registered = Registered {
            live: context.live.clone(),
            id: context.live.register(handle),
        };
        let context = context.clone();
        pool.submit(permit, move || {
            let _registered = registered;
            serve_connection(stream, &context);
        });
    }
}

/// A tool connection whose reads end at a deadline, however slowly the
/// bytes arrive, and whose responses must keep a minimum rate, however
/// slowly the tool reads.
pub(super) struct Timed<S> {
    inner: S,
    deadline: Instant,
    /// When the current response started, and what it has written since.
    response_start: Instant,
    written: u64,
    /// Time allowed before the rate applies, and the rate (bytes/s).
    grace: Duration,
    min_rate: u64,
}

impl<S> Timed<S> {
    fn start_response(&mut self) {
        self.response_start = Instant::now();
        self.written = 0;
    }

    /// When the response written so far must have been written by.
    fn write_deadline(&self) -> Instant {
        let earned = Duration::from_secs_f64(self.written as f64 / self.min_rate.max(1) as f64);
        self.response_start + self.grace + earned
    }
}

/// What the request loop reads requests from and answers on: a tool's TCP
/// or Unix connection, or the TLS stream inside a tunnel the proxy
/// intercepts.
pub(super) trait Transport: Read + Write {
    /// Reads fail with `TimedOut` once `at` has passed.
    fn set_deadline(&mut self, at: Instant);
    /// A response starts now: the minimum-rate clock restarts.
    fn start_response(&mut self);
}

impl<S: Stream> Transport for Timed<S> {
    fn set_deadline(&mut self, at: Instant) {
        self.deadline = at;
    }

    fn start_response(&mut self) {
        Timed::start_response(self);
    }
}

impl<S: Stream> Read for Timed<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline passed",
            ));
        }
        self.inner.set_read_timeout(Some(left))?;
        self.inner.read(buf)
    }
}

impl<S: Stream> Write for Timed<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self
            .write_deadline()
            .saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the tool reads the response too slowly",
            ));
        }
        self.inner.set_write_timeout(Some(left))?;
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// How often an idle connection checks whether it should give its worker
/// back.
const IDLE_POLL: Duration = Duration::from_millis(100);

/// How long a new connection may stay silent while other connections wait
/// for a worker.
const FIRST_REQUEST_GRACE: Duration = Duration::from_millis(500);

/// Wait for the next request to start. `false`: close the connection, the
/// client is gone, too slow, or idle while other connections wait for a
/// worker. An intercepted tunnel waits the same way, so a kept-alive tunnel
/// gives its worker back too.
fn next_request_starts<T: Transport>(
    reader: &mut BufReader<T>,
    context: &Context,
    first: bool,
) -> bool {
    let shared = &context.shared;
    let patience = if first {
        shared.request_timeout
    } else {
        shared.idle_timeout
    };
    let started = Instant::now();
    loop {
        if context.state.is_closed() {
            return false;
        }
        reader.get_mut().set_deadline(Instant::now() + IDLE_POLL);
        match reader.fill_buf() {
            Ok(buffered) => return !buffered.is_empty(),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // A kept-alive connection gives its worker back as soon as
                // another connection is waiting for one.
                // A fresh connection gets a short grace to send its first
                // bytes before it yields too, so silent connections cannot
                // hold every worker for the whole request timeout.
                let yields = !first || started.elapsed() >= FIRST_REQUEST_GRACE;
                if started.elapsed() >= patience || (yields && shared.pool.saturated()) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
}

/// Wait for the next request on `reader` and read it, answering one that
/// does not parse itself. `None`: close the connection. The body is read
/// only once the head is admitted, and only up to what `cap` allows for
/// that head: an unauthenticated request cannot make the proxy buffer
/// anything. A client that asked to be told to go on (`Expect:
/// 100-continue`) is, when a body will be read at all.
pub(super) fn next_request<T: Transport>(
    reader: &mut BufReader<T>,
    context: &Context,
    first: bool,
    cap: impl Fn(&http::Head) -> u64,
) -> Option<Request> {
    if !next_request_starts(reader, context, first) {
        return None;
    }
    reader
        .get_mut()
        .set_deadline(Instant::now() + context.shared.request_timeout);
    let read = http::read_head(reader).and_then(|head| {
        let cap = cap(&head);
        let expects = head
            .headers
            .get("expect")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("100-continue"));
        if expects && cap > 0 {
            let out = reader.get_mut();
            out.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .and_then(|()| out.flush())
                .map_err(ParseError::Io)?;
        }
        head.read_body(reader, cap)
    });
    let error = match read {
        Ok(request) => return Some(request),
        Err(ParseError::Closed | ParseError::Io(_)) => return None,
        Err(error) => error,
    };
    let status = match error {
        ParseError::TooLarge { head: true } => 431,
        ParseError::TooLarge { head: false } => 413,
        _ => 400,
    };
    context.state.note_refusal(error.to_string());
    let mut headers = Headers::new();
    headers.set("Content-Type", "text/plain; charset=utf-8");
    let body = format!("tog: {}\n", context.state.clean(&error.to_string()));
    let _ = http::write_response(
        reader.get_mut(),
        status,
        &headers,
        body.as_bytes(),
        false,
        false,
    );
    None
}

/// Answer requests on one connection until it closes. A `CONNECT` ends the
/// request loop: the connection becomes the tunnel, or is refused.
fn serve_connection<S: Stream>(stream: S, context: &Context) {
    let mut reader = BufReader::new(Timed {
        inner: stream,
        deadline: Instant::now(),
        response_start: Instant::now(),
        written: 0,
        grace: context.shared.response_grace,
        min_rate: context.shared.min_response_rate,
    });
    let mut first = true;
    while let Some(request) =
        next_request(&mut reader, context, first, |head| body_cap(context, head))
    {
        first = false;
        reader.get_mut().start_response();
        if request.method == "CONNECT" {
            connect(context, &request, &mut reader);
            return;
        }
        match dispatch(context, &request, reader.get_mut()) {
            Ok(true) if request.keep_alive => {}
            _ => return,
        }
    }
}

/// A mirror target's parts: token, route id, and the route path (with a
/// leading `/`), plus everything after the token for display.
fn mirror_parts(target: &str) -> (&str, &str, String, &str) {
    let after = &target[1..];
    let (token, rest) = after.split_once('/').unwrap_or((after, ""));
    let (route_id, path) = match rest.split_once('/') {
        Some((route_id, path)) => (route_id, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    (token, route_id, path, rest)
}

/// How many body bytes the proxy will read for `head`: the route's cap for
/// a mirror request with this session's token, a known route, and a method
/// it serves, and nothing for anything else (every other request is
/// refused from its head).
fn body_cap(context: &Context, head: &http::Head) -> u64 {
    if !head.target.starts_with('/') || !MIRROR_METHODS.contains(&head.method.as_str()) {
        return 0;
    }
    let (token, route_id, _, _) = mirror_parts(&head.target);
    match context.state.route(route_id) {
        Some(route) if context.state.token_matches(token) => route.protocol.request_body_cap(),
        _ => 0,
    }
}

/// The methods registry routes serve.
const MIRROR_METHODS: &[&str] = &["GET", "HEAD"];

/// Serve one request. `Ok(true)`: the connection may carry another.
fn dispatch(context: &Context, request: &Request, out: &mut dyn Write) -> io::Result<bool> {
    if request.target.starts_with('/') {
        return mirror_request(context, request, out);
    }
    absolute_form(context, request, out)?;
    Ok(false)
}

/// Whether `headers` carry this session's token as the password of
/// `Proxy-Authorization: Basic`. The user name is ignored.
fn authenticated(state: &State, headers: &Headers) -> bool {
    let Some(value) = headers.get("proxy-authorization") else {
        return false;
    };
    let Some((scheme, encoded)) = value.trim().split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Some(decoded) = crate::kernel::base64::decode(encoded.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    text.split_once(':')
        .is_some_and(|(_, token)| state.token_matches(token))
}

fn proxy_auth_challenge() -> Headers {
    let mut headers = Headers::new();
    headers.set("Proxy-Authenticate", "Basic realm=\"tog\"");
    headers
}

/// A tunnel whose token was checked: it belongs to this session.
pub(super) struct Tunnel<'a> {
    /// `host:port` as the tool sent it, userinfo removed.
    pub(super) authority: &'a str,
    /// Lowercase, without an IPv6 literal's brackets.
    pub(super) host: &'a str,
    pub(super) port: u16,
}

/// A `CONNECT`. Its token is checked once, here: every request inside an
/// intercepted tunnel belongs to this session without one.
fn connect<S: Stream>(context: &Context, request: &Request, reader: &mut BufReader<Timed<S>>) {
    let state = &*context.state;
    let out = reader.get_mut();
    // Userinfo in a CONNECT target is dropped before anything names it.
    let shown = redact::url(&request.target, &[]);
    let authority = shown.as_str();
    let record = Record::new("refused", "CONNECT", shown.clone());
    if !authenticated(state, &request.headers) {
        let reason = format!("CONNECT {authority} without this session's proxy token");
        let _ = mirror::refuse_unauthenticated(
            state,
            out,
            record,
            407,
            &reason,
            &proxy_auth_challenge(),
        );
        return;
    }
    let parsed = authority
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
        .filter(|(host, _)| !host.is_empty());
    let Some((host, port)) = parsed else {
        let reason = format!("CONNECT target {authority} is not host:port");
        let _ = mirror::refuse(state, out, record, 400, &reason, &Headers::new(), false);
        return;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let tunnel = Tunnel {
        authority,
        host: &host,
        port,
    };
    let _ = match state.config.intercept {
        Intercept::Tls if port != GIT_PORT => {
            super::intercept::serve_tunnel(context, &tunnel, record, reader);
            Ok(())
        }
        Intercept::Tls | Intercept::RefuseVisibly => refuse_tunnel(state, &tunnel, record, out),
    };
}

/// Refuse an authenticated tunnel, naming the host and why, and record the
/// fact the refusal establishes.
fn refuse_tunnel(
    state: &State,
    tunnel: &Tunnel<'_>,
    record: Record,
    out: &mut dyn Write,
) -> io::Result<()> {
    let (kind, why) = if tunnel.port == GIT_PORT {
        (
            policy::GIT_DEPENDENCY,
            "git:// is unauthenticated; use https://".to_string(),
        )
    } else {
        (
            policy::UNATTESTED_INDEX,
            format!(
                "{} is not reachable from this door; it reaches registries only through its \
                 mirror routes",
                tunnel.host
            ),
        )
    };
    let reason = match state.check(kind, tunnel.authority, &why) {
        Ok(()) => format!("refused CONNECT {}: {why}", tunnel.authority),
        Err(refusal) => format!("refused CONNECT {}: {why}; {refusal}", tunnel.authority),
    };
    mirror::refuse(state, out, record, 403, &reason, &Headers::new(), false)
}

/// `GET http://host/...` or `git://host/...`: every registry is https and
/// reached through the mirror routes, so these are refused visibly.
fn absolute_form(context: &Context, request: &Request, out: &mut dyn Write) -> io::Result<()> {
    let state = &*context.state;
    let shown = redact::url(&request.target, &[]);
    let record = Record::new("refused", &request.method, shown.clone());
    if !authenticated(state, &request.headers) {
        let reason = format!(
            "{} {shown} without this session's proxy token",
            request.method
        );
        return mirror::refuse_unauthenticated(
            state,
            out,
            record,
            407,
            &reason,
            &proxy_auth_challenge(),
        );
    }
    let Ok(url) = url::Url::parse(&request.target) else {
        let reason = format!("{shown} is not a URL");
        return mirror::refuse(state, out, record, 400, &reason, &Headers::new(), false);
    };
    let host = url.host_str().unwrap_or("no host");
    let (kind, why) = match url.scheme() {
        "git" => (
            policy::GIT_DEPENDENCY,
            "git:// is unauthenticated; use https://".to_string(),
        ),
        "https" => (
            policy::UNATTESTED_INDEX,
            format!(
                "absolute-form requests are not forwarded; {host} is not reachable from this \
                 door"
            ),
        ),
        scheme => (
            policy::UNATTESTED_INDEX,
            format!(
                "plain {scheme}:// to {host} is not permitted; registries are reached over https"
            ),
        ),
    };
    let reason = match state.check(kind, &shown, &why) {
        Ok(()) => format!("refused {shown}: {why}"),
        Err(refusal) => format!("refused {shown}: {why}; {refusal}"),
    };
    mirror::refuse(state, out, record, 403, &reason, &Headers::new(), false)
}

/// `/<token>/<route>/<path>`: a registry-mirror request.
fn mirror_request(context: &Context, request: &Request, out: &mut dyn Write) -> io::Result<bool> {
    let state = &*context.state;
    let (token, route_id, path, rest) = mirror_parts(&request.target);
    let route = state.route(route_id);
    let keys = route.map_or(&[][..], |route| route.protocol.content_query_keys());
    // The token never enters the ledger, right or wrong.
    let shown = redact::url(&format!("/{REDACTED}/{rest}"), keys);
    let record = Record::new("refused", &request.method, shown.clone());
    if !state.token_matches(token) {
        let reason = format!("{shown} does not carry this session's token");
        mirror::refuse_unauthenticated(state, out, record, 403, &reason, &Headers::new())?;
        return Ok(false);
    }
    let Some(route) = route else {
        let reason = format!("this session has no route for {shown}");
        mirror::refuse(
            state,
            out,
            record,
            403,
            &reason,
            &Headers::new(),
            request.keep_alive,
        )?;
        return Ok(true);
    };
    if !MIRROR_METHODS.contains(&request.method.as_str()) {
        let mut allow = Headers::new();
        allow.set("Allow", "GET, HEAD");
        let reason = format!("{} is not served by registry routes", request.method);
        mirror::refuse(state, out, record, 405, &reason, &allow, request.keep_alive)?;
        return Ok(true);
    }
    let upstream = match route.resolve(&path) {
        Ok(upstream) => upstream,
        Err(why) => {
            mirror::refuse(
                state,
                out,
                record,
                403,
                &why,
                &Headers::new(),
                request.keep_alive,
            )?;
            return Ok(true);
        }
    };
    let exchange = Exchange {
        state,
        client: &context.shared.client,
        route,
        address: &context.address,
        method: &request.method,
        request: &request.headers,
        body: None,
        permitted: &state.config.permitted,
        hop: None,
        // A streamed body is delimited by the close for HTTP/1.0, so an
        // HTTP/1.0 connection ends after each mirror response.
        keep_alive: request.keep_alive && !request.http10,
        http10: request.http10,
    };
    match upstream {
        Upstream::Local(answer) => exchange.local(answer, out)?,
        Upstream::Fetch(url) => exchange.serve(&url, out)?,
    }
    Ok(!request.http10)
}

type Job = Box<dyn FnOnce() + Send>;

/// The bounded connection pool: at most `max` connections served at once,
/// by threads started on demand and kept for the process.
struct Pool {
    max: usize,
    state: Mutex<PoolState>,
    freed: Condvar,
    queued: Condvar,
}

#[derive(Default)]
struct PoolState {
    in_use: usize,
    /// Accept loops waiting for a slot.
    waiting: usize,
    jobs: VecDeque<Job>,
    spawned: usize,
    idle: usize,
}

/// One pool slot, returned when dropped.
struct Permit(Arc<Pool>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.lock().in_use -= 1;
        self.0.freed.notify_all();
    }
}

impl Pool {
    fn new(max: usize) -> Pool {
        Pool {
            max,
            state: Mutex::new(PoolState::default()),
            freed: Condvar::new(),
            queued: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Wait for a free slot, or `None` once `stop` is set.
    fn acquire(self: &Arc<Self>, stop: &AtomicBool) -> Option<Permit> {
        let mut state = self.lock();
        loop {
            if stop.load(Ordering::SeqCst) {
                return None;
            }
            if state.in_use < self.max {
                state.in_use += 1;
                return Some(Permit(self.clone()));
            }
            state.waiting += 1;
            state = self
                .freed
                .wait_timeout(state, Duration::from_millis(200))
                .unwrap_or_else(|error| error.into_inner())
                .0;
            state.waiting -= 1;
        }
    }

    #[cfg(test)]
    fn try_acquire_for_test(self: &Arc<Self>) -> Option<Permit> {
        let mut state = self.lock();
        (state.in_use < self.max).then(|| {
            state.in_use += 1;
            Permit(self.clone())
        })
    }

    /// Every slot is taken and an accept loop is waiting for one.
    fn saturated(&self) -> bool {
        let state = self.lock();
        state.in_use >= self.max && state.waiting > 0
    }

    fn wake_waiters(&self) {
        self.freed.notify_all();
    }

    /// Run `job` on a pool thread, holding `permit` until it returns.
    fn submit(self: &Arc<Self>, permit: Permit, job: impl FnOnce() + Send + 'static) {
        let mut state = self.lock();
        state.jobs.push_back(Box::new(move || {
            job();
            drop(permit);
        }));
        if state.jobs.len() > state.idle && state.spawned < self.max {
            let pool = self.clone();
            let spawned = std::thread::Builder::new()
                .name("tog-proxy".into())
                .spawn(move || pool.work());
            match spawned {
                Ok(_) => state.spawned += 1,
                // No thread will ever run the job: drop it, which closes
                // the connection and returns its slot.
                Err(_) if state.spawned == 0 => {
                    let job = state.jobs.pop_back();
                    drop(state);
                    drop(job);
                    return;
                }
                Err(_) => {}
            }
        }
        drop(state);
        self.queued.notify_one();
    }

    fn work(&self) {
        loop {
            let job = {
                let mut state = self.lock();
                state.idle += 1;
                while state.jobs.is_empty() {
                    state = self
                        .queued
                        .wait(state)
                        .unwrap_or_else(|error| error.into_inner());
                }
                state.idle -= 1;
                state.jobs.pop_front()
            };
            if let Some(job) = job {
                // A panicking connection must not take the thread with it:
                // the pool counts its threads. Its permit is returned by
                // the unwind.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::Policy;
    use crate::kernel::resolve::ledger::Entry;
    use crate::kernel::resolve::routes::{Endpoint, Permitted, Route};
    use crate::kernel::resolve::session::Mode;
    use crate::kernel::resolve::testing::{
        get, mirror, proxy_authorization, send, Harness, Reach, TEST_ORIGIN_PUBLIC,
    };

    fn deny(kinds: &[&str]) -> Policy {
        Policy {
            deny: kinds.iter().map(|kind| kind.to_string()).collect(),
            ..Policy::default()
        }
    }

    fn entries(report: &SessionReport) -> Vec<Entry> {
        report.ledger.entries().cloned().collect()
    }

    fn connect(
        address: &ProxyAddress,
        authority: &str,
        token: Option<&str>,
    ) -> super::super::testing::Response {
        let auth = token.map(proxy_authorization).unwrap_or_default();
        send(
            address,
            &format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}"),
        )
    }

    #[test]
    fn proxy_refuses_requests_without_the_session_token() {
        let harness = Harness::new("proxy-token");
        let (one, first) = harness.session();
        let (two, second) = harness.session();
        assert_ne!(first.token(), second.token());

        // Another session's token, no token, and a truncated token.
        let other = get(&first, &mirror(&second, "/meta/pkg.json"), "");
        assert_eq!(other.status, 403, "{}", other.text());
        assert!(other.text().contains("does not carry this session's token"));
        assert!(!other.text().contains(second.token()));
        assert_eq!(get(&first, "/fixture/meta/pkg.json", "").status, 403);
        let truncated = format!("/{}/fixture/meta/pkg.json", &first.token()[..63]);
        assert_eq!(get(&first, &truncated, "").status, 403);

        let bare = connect(&first, "registry.npmjs.org:443", None);
        assert_eq!(bare.status, 407);
        assert_eq!(
            bare.headers.get("proxy-authenticate"),
            Some("Basic realm=\"tog\"")
        );
        assert_eq!(
            connect(&first, "registry.npmjs.org:443", Some(second.token())).status,
            407
        );
        let absolute = get(&first, "http://registry.npmjs.org/pkg", "");
        assert_eq!(absolute.status, 407);

        assert_eq!(
            harness.upstream.hits("/meta/pkg.json"),
            0,
            "nothing was forwarded"
        );
        let report = one.finish();
        // Six requests without the token: diagnostics rows and a count,
        // never portable entries (they are not the tool's session).
        assert_eq!(report.diagnostics.requests.len(), 6);
        assert_eq!(report.diagnostics.unauthenticated, 6);
        assert_eq!(report.diagnostics.refusals.len(), 6);
        assert!(report
            .diagnostics
            .requests
            .iter()
            .all(|row| row.disposition == "refused"));
        let recorded = entries(&report);
        assert!(recorded.is_empty(), "{recorded:#?}");
        assert!(report.facts.failure().is_none(), "{:?}", report.facts);
        let bytes = String::from_utf8(report.ledger.bytes()).unwrap();
        assert!(!bytes.contains(first.token()) && !bytes.contains(second.token()));
        assert!(
            entries(&two.finish()).is_empty(),
            "each session records only its own"
        );
    }

    #[test]
    fn unauthenticated_floods_stay_out_of_the_ledger_and_are_capped() {
        let harness = Harness::new("proxy-flood");
        let (session, address) = harness.session();
        let long = "a".repeat(4096);
        for index in 0..3 {
            let target = format!("/not-the-token/{long}/{index}");
            assert_eq!(get(&address, &target, "").status, 403);
        }
        let report = session.finish();
        assert!(entries(&report).is_empty());
        assert_eq!(report.diagnostics.unauthenticated, 3);
        for row in &report.diagnostics.requests {
            assert!(row.url.len() <= 515, "{}", row.url.len());
            assert!(row
                .detail
                .as_ref()
                .is_some_and(|detail| detail.len() <= 515));
        }
        for refusal in &report.diagnostics.refusals {
            assert!(refusal.len() < 1100, "{}", refusal.len());
        }
    }

    #[test]
    fn connect_tunnel_is_authenticated_once_and_bound_to_its_session() {
        let harness = Harness::new("proxy-tunnel");
        let (one, first) = harness.session();
        let (two, second) = harness.session();

        // The token is checked at CONNECT, and the tunnel belongs to the
        // session whose token and listener it came with.
        let own = connect(&first, "pypi.org:443", Some(first.token()));
        assert_eq!(
            own.status, 403,
            "an authenticated tunnel reaches the intercept decision"
        );
        let crossed = connect(&second, "pypi.org:443", Some(first.token()));
        assert_eq!(
            crossed.status, 407,
            "a token is valid only on its own session's listener"
        );

        let one = one.finish();
        let two = two.finish();
        assert_eq!(
            entries(&one)
                .iter()
                .map(|entry| (entry.method.as_str(), entry.url.as_str(), entry.status))
                .collect::<Vec<_>>(),
            [("CONNECT", "pypi.org:443", 403)]
        );
        assert_eq!(
            one.facts
                .exceptions
                .iter()
                .map(|fact| (fact.kind, fact.subject.as_str()))
                .collect::<Vec<_>>(),
            [(policy::UNATTESTED_INDEX, "pypi.org:443")]
        );
        assert!(entries(&two).is_empty(), "the 407 is diagnostics only");
        assert_eq!(two.diagnostics.unauthenticated, 1);
        assert_eq!(two.diagnostics.requests[0].status, 407);
        assert!(
            two.facts.exceptions.is_empty(),
            "an unauthenticated CONNECT establishes nothing"
        );
    }

    #[test]
    fn connect_without_interception_is_a_visible_refusal() {
        let harness = Harness::new("proxy-visible");
        let (session, address) = harness.session();
        let refused = connect(&address, "evil.example:443", Some(address.token()));
        assert_eq!(refused.status, 403);
        assert_eq!(
            refused.headers.get("content-type"),
            Some("text/plain; charset=utf-8")
        );
        let body = refused.text();
        assert!(
            body.starts_with("tog: refused CONNECT evil.example:443"),
            "{body}"
        );
        assert!(
            body.contains("reaches registries only through its mirror routes"),
            "{body}"
        );
        let report = session.finish();
        assert_eq!(
            entries(&report),
            [Entry {
                class: "refused".into(),
                method: "CONNECT".into(),
                url: "evil.example:443".into(),
                status: 403,
                sha256: None,
                claimed: None,
                verified: false,
                freshness: None,
                redirected_to: None,
            }]
        );
        assert_eq!(
            report.facts.failure(),
            None,
            "a recorded refusal alone does not fail the door"
        );

        // Denied, the same refusal carries the policy text and fails the door.
        let (session, address) =
            harness.open(harness.config(deny(&[policy::UNATTESTED_INDEX]), Mode::Online));
        let body = connect(&address, "evil.example:443", Some(address.token())).text();
        assert!(body.contains("policy denies unattested-index"), "{body}");
        let report = session.finish();
        assert!(report.facts.exceptions.is_empty());
        assert!(report.facts.failure().unwrap().contains("unattested-index"));
    }

    #[test]
    fn git_scheme_is_refused_as_git_dependency() {
        let harness = Harness::new("proxy-git");
        let (session, address) = harness.session();
        let tunnel = connect(&address, "github.com:9418", Some(address.token()));
        assert_eq!(tunnel.status, 403);
        assert!(tunnel
            .text()
            .contains("git:// is unauthenticated; use https://"));
        let auth = proxy_authorization(address.token());
        let absolute = get(&address, "git://github.com/owner/repo.git", &auth);
        assert_eq!(absolute.status, 403);
        assert!(absolute
            .text()
            .contains("git:// is unauthenticated; use https://"));
        let report = session.finish();
        let kinds: Vec<_> = report
            .facts
            .exceptions
            .iter()
            .map(|fact| fact.kind)
            .collect();
        assert_eq!(kinds, [policy::GIT_DEPENDENCY, policy::GIT_DEPENDENCY]);

        let (session, address) =
            harness.open(harness.config(deny(&[policy::GIT_DEPENDENCY]), Mode::Online));
        connect(&address, "github.com:9418", Some(address.token()));
        let failure = session.finish().facts.failure().unwrap();
        assert!(failure.contains("git-dependency"), "{failure}");
    }

    #[test]
    fn proxy_routes_only_to_permitted_endpoints() {
        let harness = Harness::new("proxy-routes");
        let (session, address) = harness.session();
        for (path, why) in [
            ("/forbidden/x", "the fixture grammar forbids"),
            ("/elsewhere/x", "not one of its endpoints"),
            ("/meta/../art/x", ".."),
            ("/meta/%2e%2e/art/x", ".."),
            ("/meta/a%2Fb", "encoded"),
            ("/meta/https://evil.example/x", "URL"),
        ] {
            let answer = get(&address, &mirror(&address, path), "");
            assert_eq!(answer.status, 403, "{path}: {}", answer.text());
            assert!(answer.text().contains(why), "{path}: {}", answer.text());
        }
        let unknown = get(
            &address,
            &format!("/{}/nosuch/meta/pkg.json", address.token()),
            "",
        );
        assert_eq!(unknown.status, 403);
        let auth = proxy_authorization(address.token());
        let plain = get(&address, "http://registry.test/meta/pkg.json", &auth);
        assert_eq!(plain.status, 403);
        assert!(plain.text().contains("plain http://"), "{}", plain.text());
        let post = send(
            &address,
            &format!(
                "POST {} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n",
                mirror(&address, "/meta/pkg.json")
            ),
        );
        assert_eq!(post.status, 405);
        assert!(
            harness.upstream.seen().is_empty(),
            "nothing refused reached upstream"
        );
        // Control: the route itself works.
        assert_eq!(
            get(&address, &mirror(&address, "/meta/pkg.json"), "").status,
            200
        );
        let report = session.finish();
        assert_eq!(report.diagnostics.requests.len(), 10);
        assert_eq!(
            report.ledger.len(),
            10,
            "{:#?}",
            report.ledger.entries().collect::<Vec<_>>()
        );

        // A route whose endpoint is not in the session's permitted set
        // cannot even be opened.
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.permitted = Permitted::compiled();
        let refused = harness.proxy.open_session(config).err().unwrap();
        assert!(
            refused.to_string().contains("not a permitted endpoint"),
            "{refused}"
        );
    }

    #[test]
    fn proxy_strips_tool_authorization_and_cookies() {
        let harness = Harness::new("proxy-strip");
        let port = harness.upstream.port();
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.routes = vec![Route::new(
            &crate::kernel::resolve::routes::testing::TEST_PROTOCOL,
            vec![
                Endpoint::for_test("registry.test", port)
                    .with_authorization("Bearer endpoint-credential")
                    .unwrap(),
                Endpoint::for_test("other.test", port),
            ],
        )
        .unwrap()];
        let (session, address) = harness.open(config);
        let answer = get(
            &address,
            &mirror(&address, "/meta/pkg.json"),
            &format!(
                "Authorization: Bearer tool-secret\r\nCookie: session=tool-cookie\r\n{}\
                 Accept: application/json\r\nIf-None-Match: \"tool-etag\"\r\nX-Tool: 1\r\n",
                proxy_authorization(address.token())
            ),
        );
        assert_eq!(answer.status, 200);
        assert_eq!(
            answer.headers.get("set-cookie"),
            None,
            "upstream cookies stay upstream"
        );
        assert_eq!(answer.headers.get("etag"), Some("\"pkg-v1\""));
        let seen = harness.upstream.seen();
        assert_eq!(seen.len(), 1);
        let headers = &seen[0].headers;
        assert_eq!(
            headers.get("authorization"),
            Some("Bearer endpoint-credential")
        );
        assert_eq!(headers.count("authorization"), 1);
        for stripped in ["cookie", "proxy-authorization", "if-none-match", "x-tool"] {
            assert_eq!(headers.get(stripped), None, "{stripped} reached upstream");
        }
        assert_eq!(headers.get("accept"), Some("application/json"));
        session.finish();
    }

    #[test]
    fn proxy_connects_only_to_the_validated_address() {
        // A rebinding resolver: public first, loopback on every later call.
        let harness = Harness::with(
            "proxy-rebind",
            Reach::public(|call, _| {
                vec![if call == 0 {
                    TEST_ORIGIN_PUBLIC
                } else {
                    "127.0.0.1"
                }
                .parse()
                .unwrap()]
            }),
        );
        let (session, address) = harness.session();
        let answer = get(&address, &mirror(&address, "/meta/pkg.json"), "");
        assert_eq!(answer.status, 200, "{}", answer.text());
        assert_eq!(
            harness.upstream.hits("/meta/pkg.json"),
            1,
            "the public answer was used"
        );
        assert_eq!(
            harness.lookup.calls(),
            1,
            "the name was looked up once, by the proxy"
        );
        session.finish();
    }

    #[test]
    fn proxy_refuses_when_any_resolved_address_is_private() {
        let answers: [&[&str]; 4] = [
            &[TEST_ORIGIN_PUBLIC, "10.0.0.1"],
            &["169.254.169.254"],
            &["127.0.0.1"],
            &["::ffff:127.0.0.1"],
        ];
        let harness = Harness::with(
            "proxy-private",
            Reach::public(move |call, _| {
                answers[call.min(3)]
                    .iter()
                    .map(|a| a.parse().unwrap())
                    .collect()
            }),
        );
        let (session, address) = harness.session();
        for expected in [
            "10.0.0.0/8",
            "169.254.0.0/16",
            "127.0.0.0/8",
            "::ffff:0:0/96",
        ] {
            let answer = get(&address, &mirror(&address, "/meta/pkg.json"), "");
            assert_eq!(answer.status, 403, "{}", answer.text());
            assert!(
                answer.text().contains(expected),
                "{expected}: {}",
                answer.text()
            );
        }
        assert!(
            harness.upstream.seen().is_empty(),
            "no refused address was connected to"
        );
        let report = session.finish();
        assert_eq!(
            report.facts.hard_failures.len(),
            4,
            "{:?}",
            report.facts.hard_failures
        );
    }

    #[test]
    fn proxy_keeps_the_hostname_for_sni_and_host() {
        let harness = Harness::with(
            "proxy-sni",
            Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]),
        );
        let (session, address) = harness.session();
        let answer = get(&address, &mirror(&address, "/meta/pkg.json"), "");
        assert_eq!(answer.status, 200, "{}", answer.text());
        let seen = harness.upstream.seen();
        assert_eq!(seen[0].sni.as_deref(), Some("registry.test"));
        assert_eq!(
            seen[0].headers.get("host"),
            Some(format!("registry.test:{}", harness.upstream.port()).as_str())
        );
        session.finish();
    }

    #[test]
    fn malformed_requests_are_answered_and_noted() {
        let harness = Harness::new("proxy-malformed");
        let (session, address) = harness.session();
        let smuggled = send(
            &address,
            "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        );
        assert_eq!(smuggled.status, 400);
        let report = session.finish();
        assert!(report.ledger.is_empty());
        assert_eq!(report.diagnostics.refusals.len(), 1);
    }

    #[test]
    fn connections_beyond_the_pool_wait_for_a_slot() {
        let pool = Arc::new(Pool::new(2));
        let stop = AtomicBool::new(false);
        let first = pool.acquire(&stop).unwrap();
        let _second = pool.acquire(&stop).unwrap();
        let waiting = {
            let pool = pool.clone();
            std::thread::spawn(move || {
                let stop = AtomicBool::new(false);
                pool.acquire(&stop).is_some()
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiting.is_finished(),
            "a third connection waits while both slots are busy"
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        pool.submit(first, move || sender.send(()).unwrap());
        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            waiting.join().unwrap(),
            "the slot freed by the finished job goes to the waiter"
        );
        let stopped = AtomicBool::new(true);
        assert!(pool.acquire(&stopped).is_none());
    }

    #[test]
    fn finishing_a_session_closes_its_listeners() {
        let harness = Harness::new("proxy-finish");
        let (session, address) = harness.session();
        let idle = TcpStream::connect(address.address).unwrap();
        session.finish();
        assert!(
            TcpStream::connect(address.address).is_err(),
            "the listener is closed"
        );
        let mut buf = [0u8; 1];
        let mut idle = idle;
        idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(
            idle.read(&mut buf).unwrap_or(0),
            0,
            "a live connection is shut down"
        );
    }

    #[test]
    fn unix_listeners_serve_the_same_session() {
        let harness = Harness::new("proxy-unix");
        let mut session = harness
            .proxy
            .open_session(harness.config(Policy::default(), Mode::Online))
            .unwrap();
        let path = harness.store.root.join("tmp/proxy.sock");
        let advertised: SocketAddr = "127.0.0.1:8119".parse().unwrap();
        let address = session.listen_unix(&path, advertised).unwrap();
        assert_eq!(address.address, advertised);
        let mut stream = UnixStream::connect(&path).unwrap();
        write!(
            stream,
            "GET {} HTTP/1.1\r\nHost: {advertised}\r\nConnection: close\r\n\r\n",
            mirror(&address, "/meta/rewritten.json")
        )
        .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw}");
        assert!(
            raw.contains(&format!(
                "http://127.0.0.1:8119/{}/fixture/meta/pkg.json",
                address.token()
            )),
            "rewrites point at the advertised address: {raw}"
        );
        session.finish();
        assert!(!path.exists(), "the socket is removed");
    }

    /// Secrets a tool puts in a URL (userinfo, a query value) never reach a
    /// response body, the ledger, the diagnostics, or a fact, on any path:
    /// refusals, route errors, transport failures, redirects, malformed
    /// requests.
    #[test]
    fn no_secret_in_a_request_reaches_a_body_diagnostic_or_fact() {
        use crate::kernel::testutil::upstream::{Behavior, Reply};
        let harness = Harness::new("proxy-secret-errors");
        let port = harness.upstream.port();
        let (session, address) =
            harness.open(harness.config(deny(&[policy::UNATTESTED_INDEX]), Mode::Online));
        let auth = proxy_authorization(address.token());
        harness
            .upstream
            .set("/index/drop?token=hunter2", Behavior::Drop);
        harness.upstream.set(
            "/meta/away?token=hunter2",
            Behavior::Reply(Reply::new(302, b"").header(
                "Location",
                &format!("https://u:hunter2@third.test:{port}/x?sig=hunter2"),
            )),
        );
        let mut answers = vec![
            connect(
                &address,
                "u:hunter2@evil.example:443",
                Some(address.token()),
            ),
            connect(&address, "u:hunter2@evil.example:443", None),
            get(
                &address,
                "http://u:hunter2@x.example/p?token=hunter2",
                &auth,
            ),
        ];
        // A malformed request line: the proxy answers 400 and closes with
        // the rest of the head unread, which may reset the connection, so
        // only what it recorded is checked.
        {
            let mut stream = TcpStream::connect(address.address).unwrap();
            let _ = stream.write_all(b"GET /a?token=hunter2 HTTP/1.1 extra\r\nHost: x\r\n\r\n");
            let _ = stream.read_to_end(&mut Vec::new());
        }
        for path in [
            "/elsewhere/x?token=hunter2",
            "/forbidden/x?token=hunter2",
            "/meta/../x?token=hunter2",
            "/index/drop?token=hunter2",
            "/meta/away?token=hunter2",
        ] {
            answers.push(get(&address, &mirror(&address, path), ""));
        }
        answers.push(get(
            &address,
            &format!("/{}/nosuch?token=hunter2", address.token()),
            "",
        ));
        for answer in &answers {
            assert!(answer.status >= 400, "{answer:?}");
            assert!(!answer.text().contains("hunter2"), "{}", answer.text());
            assert!(
                !answer.text().contains(address.token()),
                "{}",
                answer.text()
            );
        }
        let report = session.finish();
        let everything = format!(
            "{}{}{:?}",
            String::from_utf8(report.ledger.bytes()).unwrap(),
            String::from_utf8(report.diagnostics.bytes()).unwrap(),
            report.facts
        );
        assert!(!everything.contains("hunter2"), "{everything}");
        assert!(!everything.contains(address.token()), "{everything}");
        assert!(
            everything.contains("evil.example:443"),
            "the host is still named"
        );
    }

    /// Read one keep-alive response: the head, then `Content-Length` bytes.
    fn read_kept_alive(stream: &mut TcpStream) -> u16 {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        stream.read_exact(&mut vec![0u8; length]).unwrap();
        head[9..12].parse().unwrap()
    }

    /// How long until the proxy closes `stream`, feeding it `trickle`
    /// every 100 ms meanwhile.
    fn time_to_close(mut stream: TcpStream, trickle: &[u8]) -> Duration {
        let started = Instant::now();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 256];
        while started.elapsed() < Duration::from_secs(10) {
            let _ = stream.write_all(trickle);
            match stream.read(&mut buf) {
                Ok(_) => return started.elapsed(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => return started.elapsed(),
            }
        }
        panic!("the proxy never closed the connection");
    }

    #[test]
    fn a_slow_or_silent_client_cannot_hold_a_worker() {
        let harness = Harness::new("proxy-slowloris");
        let (session, address) = harness.session();
        // Silent: never sends a byte. Trickling: one byte per 100 ms, a
        // head that would never finish. Both lose their worker at the
        // 1 s request timeout, not the idle one or never.
        let silent = TcpStream::connect(address.address).unwrap();
        let mut trickling = TcpStream::connect(address.address).unwrap();
        trickling.write_all(b"GET /").unwrap();
        for (stream, trickle) in [(silent, &b""[..]), (trickling, &b"a"[..])] {
            let waited = time_to_close(stream, trickle);
            assert!(waited < Duration::from_secs(3), "{waited:?}");
        }
        session.finish();
    }

    #[test]
    fn idle_kept_alive_connections_yield_their_worker_to_waiting_ones() {
        let harness = Harness::with(
            "proxy-yield",
            Reach {
                workers: 2,
                ..Reach::loopback()
            },
        );
        let (session, address) = harness.session();
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: x\r\n\r\n",
            mirror(&address, "/local/supported")
        );
        let mut kept = Vec::new();
        for _ in 0..2 {
            let mut stream = TcpStream::connect(address.address).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            assert_eq!(read_kept_alive(&mut stream), 200);
            kept.push(stream);
        }
        // Both workers now hold idle keep-alive connections; a third
        // connection is answered well before their 2 s idle timeout.
        let started = Instant::now();
        let third = get(&address, &mirror(&address, "/local/supported"), "");
        assert_eq!(third.status, 200);
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );
        session.finish();
    }

    #[test]
    fn a_panicking_job_returns_its_slot_and_its_registration() {
        let pool = Arc::new(Pool::new(1));
        let stop = AtomicBool::new(false);
        let live = Arc::new(Live::default());
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let registered = Registered {
            live: live.clone(),
            id: live.register(Conn::Unix(a)),
        };
        let permit = pool.acquire(&stop).unwrap();
        pool.submit(permit, move || {
            let _registered = registered;
            panic!("a connection handler bug");
        });
        let started = Instant::now();
        let again = loop {
            if let Some(permit) = pool.try_acquire_for_test() {
                break permit;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the slot leaked"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        drop(again);
        assert!(live.lock().is_empty(), "the registration leaked");
        // The pool thread survived the panic and runs the next job.
        let (sender, receiver) = std::sync::mpsc::channel();
        pool.submit(pool.acquire(&stop).unwrap(), move || {
            sender.send(()).unwrap()
        });
        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    #[test]
    fn nothing_is_recorded_after_a_session_finishes() {
        let harness = Harness::new("proxy-closed");
        let state = State::new(harness.config(Policy::default(), Mode::Online)).unwrap();
        state.close();
        state.record(
            Entry {
                class: "metadata".into(),
                method: "GET".into(),
                url: "https://registry.test/late".into(),
                status: 200,
                sha256: None,
                claimed: None,
                verified: false,
                freshness: None,
                redirected_to: None,
            },
            crate::kernel::resolve::ledger::DiagRequest {
                seq: 0,
                class: "metadata".into(),
                method: "GET".into(),
                url: "https://registry.test/late".into(),
                status: 200,
                served_status: 200,
                disposition: "miss".into(),
                bytes: 1,
                hops: Vec::new(),
                detail: None,
            },
        );
        assert!(state
            .check(policy::UNATTESTED_INDEX, "late", "late")
            .is_err());
        state.hard_failure("late".into());
        let report = state.take_report();
        assert!(report.ledger.is_empty());
        assert!(report.diagnostics.requests.is_empty());
        assert_eq!(report.facts, Default::default());
    }

    #[test]
    fn bodies_are_read_only_after_the_head_is_admitted() {
        let harness = Harness::new("proxy-body-cap");
        let (session, address) = harness.session();
        let started = Instant::now();
        // A wrong token declaring 60 MB, with no body sent: refused from
        // the head at once, not after waiting for (or buffering) the body.
        let wrong = send(
            &address,
            "GET /0000/fixture/meta/pkg.json HTTP/1.1\r\nHost: x\r\nContent-Length: 60000000\r\n",
        );
        assert_eq!(wrong.status, 413, "{}", wrong.text());
        let tunnel = send(
            &address,
            "CONNECT pypi.org:443 HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n",
        );
        assert_eq!(tunnel.status, 413);
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
        // With the token, a registry route still reads no body at all:
        // declared, or chunked.
        let path = mirror(&address, "/meta/pkg.json");
        let admitted = send(
            &address,
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"),
        );
        assert_eq!(admitted.status, 413);
        let mut stream = TcpStream::connect(address.address).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        )
        .unwrap();
        let mut raw = String::new();
        let _ = stream.read_to_string(&mut raw);
        assert!(raw.starts_with("HTTP/1.1 413 "), "{raw}");
        assert!(harness.upstream.seen().is_empty());
        session.finish();
    }

    #[test]
    fn silent_new_connections_yield_their_worker_under_saturation() {
        let harness = Harness::with(
            "proxy-silent-yield",
            Reach {
                workers: 1,
                request_timeout: Duration::from_secs(10),
                ..Reach::loopback()
            },
        );
        let (session, address) = harness.session();
        let _silent = TcpStream::connect(address.address).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        let answer = get(&address, &mirror(&address, "/local/supported"), "");
        assert_eq!(answer.status, 200);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        session.finish();
    }

    #[test]
    fn a_tool_reading_too_slowly_loses_its_worker() {
        use crate::kernel::testutil::upstream::{Behavior, Reply};
        let harness = Harness::with(
            "proxy-slow-reader",
            Reach {
                workers: 1,
                min_response_rate: 1 << 30,
                ..Reach::loopback()
            },
        );
        harness.upstream.set(
            "/art/huge.tgz",
            Behavior::Reply(Reply::new(200, &vec![7u8; 48 << 20])),
        );
        let (session, address) = harness.session();
        let mut stalled = TcpStream::connect(address.address).unwrap();
        write!(
            stalled,
            "GET {} HTTP/1.1\r\nHost: x\r\n\r\n",
            mirror(&address, "/art/huge.tgz")
        )
        .unwrap();
        // The tool reads 64 KiB every 100 ms: steady progress, so a
        // per-write timeout never fires, but far below the minimum rate.
        // Past the grace (the 2 s I/O timeout) the worker is released for
        // the next tool.
        let stop = Arc::new(AtomicBool::new(false));
        let trickle = {
            let stop = stop.clone();
            let mut reader = stalled.try_clone().unwrap();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 64 * 1024];
                while !stop.load(Ordering::SeqCst) {
                    if matches!(reader.read(&mut buf), Ok(0) | Err(_)) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
        };
        let started = Instant::now();
        let answer = get(&address, &mirror(&address, "/local/supported"), "");
        assert_eq!(answer.status, 200);
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "{:?}",
            started.elapsed()
        );
        stop.store(true, Ordering::SeqCst);
        let _ = trickle.join();
        drop(stalled);
        let report = session.finish();
        assert!(
            report
                .diagnostics
                .requests
                .iter()
                .any(|r| r.disposition == "failed"),
            "{:?}",
            report.diagnostics.requests
        );
    }
}

//! Serving one routed request: metadata through the cache, artifacts
//! through verification, and every outcome into the ledger.
//!
//! - **Metadata** (index, metadata, sumdb) is revalidated upstream with a
//!   conditional request whenever a copy is cached, stored on a 200, and
//!   served with the protocol's rewrite applied. Its claims are learned
//!   from the upstream bytes. A transport failure or a 5xx serves the
//!   last-good copy marked `last-good` (or 504 when `stale-resolution` is
//!   denied, or when there is no copy). A 4xx is passed through.
//! - **A claimed artifact** is served from the verified cache on a hit and
//!   otherwise downloaded into it, verified, and only then served: claimed
//!   bytes are never streamed unverified. A mismatch is a 502, caches
//!   nothing, and is a hard failure naming both digests.
//! - **An unclaimed artifact** streams through while being hashed and is
//!   not cached, since nothing vouches for it.
//!
//! Only an allowlist of request headers reaches upstream (never the tool's
//! `Authorization`, `Proxy-Authorization`, `Cookie`, or conditional
//! headers), and only an allowlist of response headers reaches the tool.
//! Redirects are followed here, never by the tool: each hop must be https
//! on a permitted host, goes through the validating resolver again, and
//! carries an endpoint credential only on that endpoint's own origin.

use super::cache::{self, Cached};
use super::http::{self, Headers};
use super::ledger::{DiagRequest, Entry, Freshness};
use super::redact;
use super::routes::{Claim, LocalAnswer, ProxyAddress, RequestClass, Route};
use super::session::{Claimed, Mode, State};
use crate::kernel::digest::Algo;
use crate::kernel::fetch::pinned::{PinnedClient, PinnedError, PinnedRequest, PinnedResponse};
use crate::kernel::fetch::{self, HashMismatch};
use crate::kernel::policy;
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use url::Url;

/// Request headers a tool may send upstream. Everything else is dropped:
/// credentials, cookies, the tool's own conditional headers (the proxy
/// revalidates its own copy), and `Accept-Encoding` (the client decodes).
const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "user-agent",
    "content-type",
    "git-protocol",
];

/// Response headers a tool is sent. Framing is the proxy's own, and
/// `Set-Cookie`, `Location`, and the rest never reach the tool.
const SERVED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "etag",
    "last-modified",
    "cache-control",
    "content-disposition",
    "expires",
    "vary",
];

const MAX_REDIRECTS: usize = 10;

/// The same cap the verified download path applies.
const MAX_ARTIFACT: u64 = 8 << 30;

const TEXT: &str = "text/plain; charset=utf-8";

/// One request's ledger entry and diagnostics row, built up as it is
/// served.
pub(crate) struct Record {
    pub class: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub sha256: Option<String>,
    pub claimed: Option<String>,
    pub verified: bool,
    pub freshness: Option<Freshness>,
    /// What the tool was sent, when it differs from `status`.
    pub served: Option<u16>,
    pub disposition: &'static str,
    pub bytes: u64,
    pub hops: Vec<String>,
    pub detail: Option<String>,
}

impl Record {
    pub(crate) fn new(class: &str, method: &str, url: String) -> Record {
        Record {
            class: class.to_string(),
            method: method.to_string(),
            url,
            status: 0,
            sha256: None,
            claimed: None,
            verified: false,
            freshness: None,
            served: None,
            disposition: "failed",
            bytes: 0,
            hops: Vec::new(),
            detail: None,
        }
    }

    pub(crate) fn commit(self, state: &State) {
        let entry = Entry {
            class: self.class.clone(),
            method: self.method.clone(),
            url: self.url.clone(),
            status: self.status,
            sha256: self.sha256,
            claimed: self.claimed,
            verified: self.verified,
            freshness: self.freshness,
        };
        let diag = DiagRequest {
            seq: 0,
            class: self.class,
            method: self.method,
            url: self.url,
            status: self.status,
            served_status: self.served.unwrap_or(self.status),
            disposition: self.disposition.to_string(),
            bytes: self.bytes,
            hops: self.hops,
            detail: self.detail,
        };
        state.record(entry, diag);
    }
}

/// Record a refusal and answer it with a tog body naming the reason.
pub(crate) fn refuse(
    state: &State,
    out: &mut dyn Write,
    mut record: Record,
    status: u16,
    reason: &str,
    extra: &Headers,
    keep_alive: bool,
) -> io::Result<()> {
    record.class = "refused".into();
    record.status = status;
    record.disposition = "refused";
    record.detail = Some(reason.to_string());
    record.commit(state);
    let mut headers = extra.clone();
    headers.set("Content-Type", TEXT);
    let body = format!("tog: {}\n", state.clean(reason));
    http::write_response(
        &mut Out(out),
        status,
        &headers,
        body.as_bytes(),
        keep_alive,
        false,
    )
}

/// `&mut dyn Write` as a sized writer for the `http` helpers.
struct Out<'a>(&'a mut dyn Write);

impl Write for Out<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Why an upstream fetch produced no usable response.
enum Failure {
    /// DNS, connect, TLS, a timeout, a reset: last-good may answer.
    Transport(String),
    /// The validating resolver refused every address the name has.
    Address(String),
    /// A redirect left the permitted set, or there were too many.
    Redirect(String),
    /// The request could not be sent as built: never "unreachable", so
    /// never last-good.
    Invalid(&'static str),
}

struct Fetched {
    response: PinnedResponse,
    hops: Vec<String>,
}

/// What stopped a claimed artifact download before any bytes were hashed.
enum Problem {
    Offline,
    Failed(Failure),
    Status(PinnedResponse),
}

/// Hashes what passes through it, so a mismatch can name the sha256 of
/// the bytes that were actually received.
struct Hashing {
    inner: Box<dyn Read + Send + Sync>,
    sha: Arc<Mutex<Sha256>>,
}

impl Read for Hashing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sha
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .update(&buf[..n]);
        Ok(n)
    }
}

/// One tool request on one route.
pub(crate) struct Exchange<'a> {
    pub state: &'a State,
    pub client: &'a PinnedClient,
    pub route: &'a Route,
    pub address: &'a ProxyAddress,
    pub method: &'a str,
    pub request: &'a Headers,
    pub keep_alive: bool,
}

impl Exchange<'_> {
    fn redacted(&self, url: &Url) -> String {
        redact::url(url.as_str(), self.route.protocol.content_query_keys())
    }

    fn head_only(&self) -> bool {
        self.method == "HEAD"
    }

    fn reply(
        &self,
        out: &mut dyn Write,
        status: u16,
        headers: &Headers,
        body: &[u8],
    ) -> io::Result<()> {
        http::write_response(
            &mut Out(out),
            status,
            headers,
            body,
            self.keep_alive,
            self.head_only(),
        )
    }

    /// Record `record` as failed with `status` and tell the tool why.
    fn fail(
        &self,
        out: &mut dyn Write,
        mut record: Record,
        status: u16,
        reason: String,
    ) -> io::Result<()> {
        record.status = status;
        record.disposition = "failed";
        record.detail = Some(reason.clone());
        record.commit(self.state);
        let mut headers = Headers::new();
        headers.set("Content-Type", TEXT);
        let body = format!("tog: {}\n", self.state.clean(&reason));
        self.reply(out, status, &headers, body.as_bytes())
    }

    fn refuse(
        &self,
        out: &mut dyn Write,
        record: Record,
        status: u16,
        reason: &str,
    ) -> io::Result<()> {
        refuse(
            self.state,
            out,
            record,
            status,
            reason,
            &Headers::new(),
            self.keep_alive,
        )
    }

    /// Answer a request the protocol answers itself.
    pub(crate) fn local(&self, answer: LocalAnswer, out: &mut dyn Write) -> io::Result<()> {
        let mut record = Record::new("local", self.method, self.redacted(&answer.url));
        record.status = answer.status;
        record.sha256 = Some(hex::encode(Sha256::digest(&answer.body)));
        record.freshness = Some(Freshness::Live);
        record.disposition = "local";
        record.bytes = answer.body.len() as u64;
        record.commit(self.state);
        let mut headers = Headers::new();
        headers.set("Content-Type", &answer.content_type);
        self.reply(out, answer.status, &headers, &answer.body)
    }

    /// Serve `url`, which the route resolved and checked.
    pub(crate) fn serve(&self, url: &Url, out: &mut dyn Write) -> io::Result<()> {
        // One value per forwarded header: the metadata cache keys on the
        // `Accept` it reads, so upstream must see exactly that one.
        if let Some(name) = FORWARDED_REQUEST_HEADERS
            .iter()
            .find(|name| self.request.count(name) > 1)
        {
            let record = Record::new("refused", self.method, self.redacted(url));
            let reason = format!("the request repeats {name}, which is forwarded only once");
            return refuse(
                self.state,
                out,
                record,
                400,
                &reason,
                &Headers::new(),
                false,
            );
        }
        // A value the upstream client would refuse must not look like an
        // unreachable registry (which serves last-good): refuse it here.
        if let Some((name, _)) = self.request.iter().find(|(name, value)| {
            FORWARDED_REQUEST_HEADERS.contains(&name.to_ascii_lowercase().as_str())
                && !http::is_field_value(value)
        }) {
            let record = Record::new("refused", self.method, self.redacted(url));
            let reason = format!("{name} holds bytes outside visible ASCII");
            return refuse(
                self.state,
                out,
                record,
                400,
                &reason,
                &Headers::new(),
                false,
            );
        }
        let class = self.route.protocol.classify(url);
        if class == RequestClass::Artifact {
            return self.artifact(url, out);
        }
        self.metadata(url, class, out)
    }

    /// The headers sent upstream for `url`: the tool's allowlisted ones,
    /// `extra`, and the endpoint's own credential when `url` is on it.
    fn upstream_headers(&self, url: &Url, extra: &[(String, String)]) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = self
            .request
            .iter()
            .filter(|(name, _)| {
                FORWARDED_REQUEST_HEADERS.contains(&name.to_ascii_lowercase().as_str())
            })
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        headers.extend(extra.iter().cloned());
        if let Some(credential) = self.route.endpoint_for(url).and_then(|e| e.authorization()) {
            headers.push(("Authorization".into(), credential.to_string()));
        }
        headers
    }

    /// Fetch `start`, following redirects inside the permitted set. The
    /// hops are returned on failure too, for the diagnostics.
    fn fetch(
        &self,
        start: &Url,
        extra: &[(String, String)],
        method: &str,
    ) -> Result<Fetched, (Failure, Vec<String>)> {
        let mut url = start.clone();
        let mut method = method.to_string();
        let mut hops = Vec::new();
        for _ in 0..=MAX_REDIRECTS {
            let headers = self.upstream_headers(&url, extra);
            let sent = self.client.send(&PinnedRequest {
                method: &method,
                url: url.as_str(),
                headers: &headers,
                body: None,
            });
            let response = match sent {
                Ok(response) => response,
                Err(PinnedError::Refused(why)) => return Err((Failure::Address(why), hops)),
                Err(PinnedError::Transport(why)) => return Err((Failure::Transport(why), hops)),
                Err(PinnedError::Invalid(why)) => return Err((Failure::Invalid(why), hops)),
            };
            let redirect = matches!(response.status, 301 | 302 | 303 | 307 | 308);
            let Some(location) = response.header("location").filter(|_| redirect) else {
                return Ok(Fetched { response, hops });
            };
            let next = match url.join(location) {
                Ok(next) => next,
                Err(error) => {
                    let why = format!("redirect to an unparsable location: {error}");
                    return Err((Failure::Redirect(why), hops));
                }
            };
            hops.push(self.redacted(&next));
            if !self.state.config.permitted.allows(&next) {
                let why = format!(
                    "redirect to {} is not a permitted endpoint",
                    next.origin().ascii_serialization()
                );
                return Err((Failure::Redirect(why), hops));
            }
            if response.status == 303 && method != "HEAD" {
                method = "GET".into();
            }
            url = next;
        }
        let why = format!("more than {MAX_REDIRECTS} redirects");
        Err((Failure::Redirect(why), hops))
    }

    /// An upstream refusal (an address or a redirect). A refused address is
    /// also a hard failure: something tried to reach a place it may not.
    fn refuse_upstream(
        &self,
        out: &mut dyn Write,
        record: Record,
        failure: Failure,
    ) -> io::Result<()> {
        match failure {
            Failure::Address(why) => {
                self.state.hard_failure(format!("{}: {why}", record.url));
                self.refuse(out, record, 403, &why)
            }
            Failure::Redirect(why) => self.refuse(out, record, 403, &why),
            Failure::Invalid(why) => self.fail(out, record, 400, why.to_string()),
            Failure::Transport(why) => {
                self.fail(out, record, 504, format!("upstream unreachable: {why}"))
            }
        }
    }

    fn metadata(&self, url: &Url, class: RequestClass, out: &mut dyn Write) -> io::Result<()> {
        let mut record = Record::new(class.as_str(), self.method, self.redacted(url));
        let key = cache::key(
            self.method,
            url.as_str(),
            self.request.get("accept"),
            &self.route.credential_identity(),
        );
        let cached = self.state.meta.load(&key).unwrap_or_else(|error| {
            record.detail = Some(format!("metadata cache unreadable: {error}"));
            None
        });
        if self.state.config.mode == Mode::Offline {
            return self.last_good(url, cached, record, "offline".into(), out);
        }
        let mut extra = Vec::new();
        if let Some(cached) = &cached {
            if let Some(etag) = cached.header("etag") {
                extra.push(("If-None-Match".to_string(), etag.to_string()));
            }
            if let Some(modified) = cached.header("last-modified") {
                extra.push(("If-Modified-Since".to_string(), modified.to_string()));
            }
        }
        let Fetched { mut response, hops } = match self.fetch(url, &extra, self.method) {
            Ok(fetched) => fetched,
            Err((Failure::Transport(why), hops)) => {
                record.hops = hops;
                return self.last_good(url, cached, record, why, out);
            }
            Err((failure, hops)) => {
                record.hops = hops;
                return self.refuse_upstream(out, record, failure);
            }
        };
        record.hops = hops;
        let status = response.status;
        if status == 304 {
            return match cached {
                Some(cached) => {
                    record.served = Some(200);
                    self.serve_metadata(
                        out,
                        url,
                        200,
                        &cached,
                        Freshness::Live,
                        "revalidated",
                        record,
                    )
                }
                None => {
                    let why = "upstream answered 304 to an unconditional request".to_string();
                    self.last_good(url, None, record, why, out)
                }
            };
        }
        if status >= 500 {
            return self.last_good(
                url,
                cached,
                record,
                format!("upstream answered {status}"),
                out,
            );
        }
        let body = match cache::read_capped(&mut response.body, http::MAX_BODY) {
            Ok(body) => body,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                return self.fail(out, record, 502, error.to_string());
            }
            Err(error) => return self.last_good(url, cached, record, error.to_string(), out),
        };
        let fresh = Cached::new(url.as_str(), &response.headers, body);
        if status == 200 {
            if let Err(error) = self.state.meta.save(&key, &fresh) {
                record.detail = Some(format!("metadata cache not written: {error}"));
            }
        }
        self.serve_metadata(out, url, status, &fresh, Freshness::Live, "miss", record)
    }

    /// The upstream is unreachable: serve last-good if policy allows and a
    /// copy exists, else 504.
    fn last_good(
        &self,
        url: &Url,
        cached: Option<Cached>,
        mut record: Record,
        why: String,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let offline = self.state.config.mode == Mode::Offline;
        let endpoint = url.origin().ascii_serialization();
        match cached {
            Some(cached) => {
                if let Err(refusal) = self.state.stale_allowed(&endpoint, &record.url) {
                    record.served = Some(504);
                    return self.refuse(out, record, 504, &refusal);
                }
                self.state.stale_served(&endpoint);
                record.detail = Some(why);
                self.serve_metadata(
                    out,
                    url,
                    200,
                    &cached,
                    Freshness::LastGood,
                    "last-good",
                    record,
                )
            }
            None if offline => self.offline_miss(out, record),
            None => {
                let reason = format!(
                    "{} is unreachable ({why}) and no earlier copy is cached",
                    record.url
                );
                self.fail(out, record, 504, reason)
            }
        }
    }

    fn offline_miss(&self, out: &mut dyn Write, mut record: Record) -> io::Result<()> {
        self.state.offline_miss(&record.url);
        let reason = format!("offline, and {} is not cached", record.url);
        record.class = "offline-miss".into();
        record.status = 504;
        record.disposition = "offline-miss";
        record.detail = Some(reason.clone());
        record.commit(self.state);
        let mut headers = Headers::new();
        headers.set("Content-Type", TEXT);
        self.reply(out, 504, &headers, format!("tog: {reason}\n").as_bytes())
    }

    /// Serve a metadata body: learn its claims, apply the protocol's
    /// rewrite, record the upstream bytes.
    #[allow(clippy::too_many_arguments)]
    fn serve_metadata(
        &self,
        out: &mut dyn Write,
        url: &Url,
        status: u16,
        cached: &Cached,
        freshness: Freshness,
        disposition: &'static str,
        mut record: Record,
    ) -> io::Result<()> {
        let protocol = self.route.protocol;
        let success = (200..300).contains(&status);
        let body = if success && !self.head_only() {
            self.state.add_claims(protocol.claims(url, &cached.body));
            match protocol.rewrite(url, cached.body.clone(), self.address) {
                Ok(body) => body,
                Err(error) => {
                    let reason = format!(
                        "{}: the response could not be rewritten: {error}",
                        record.url
                    );
                    self.state.hard_failure(reason.clone());
                    return self.fail(out, record, 502, reason);
                }
            }
        } else {
            cached.body.clone()
        };
        record.status = status;
        record.sha256 = (!self.head_only()).then(|| cached.sha256.clone());
        record.freshness = Some(freshness);
        record.disposition = disposition;
        record.bytes = if self.head_only() {
            0
        } else {
            body.len() as u64
        };
        record.commit(self.state);
        let mut headers = Headers::new();
        for (name, value) in &cached.headers {
            if SERVED_RESPONSE_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                headers.push(name, value);
            }
        }
        self.reply(out, status, &headers, &body)
    }

    fn artifact(&self, url: &Url, out: &mut dyn Write) -> io::Result<()> {
        let record = Record::new(
            RequestClass::Artifact.as_str(),
            self.method,
            self.redacted(url),
        );
        match self.state.claimed(url) {
            Claimed::Conflict(why) => {
                self.state.hard_failure(why.clone());
                self.fail(out, record, 502, why)
            }
            Claimed::One(claim) => self.claimed_artifact(url, claim, record, out),
            Claimed::None => self.unclaimed_artifact(url, record, out),
        }
    }

    fn claimed_artifact(
        &self,
        url: &Url,
        claim: Claim,
        mut record: Record,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        record.claimed = Some(claim.describe());
        if claim.is_weak() {
            let detail = "the registry claims only a SHA-1 digest";
            if let Err(refusal) = self
                .state
                .check(policy::WEAK_INTEGRITY, &record.url, detail)
            {
                return self.refuse(out, record, 403, &refusal);
            }
        }
        let config = &self.state.config;
        let sha = Arc::new(Mutex::new(Sha256::new()));
        let mut problem = None;
        let mut hops = Vec::new();
        let mut opened = false;
        // Claimed bytes are always fetched whole, even for a HEAD: they are
        // verified before anything is served.
        let downloaded = fetch::cache_from_reader(
            &config.store,
            &config.activity,
            // Only named in error text, so it is the redacted form.
            &record.url,
            &claim.0,
            || -> io::Result<Box<dyn Read>> {
                opened = true;
                if config.mode == Mode::Offline {
                    problem = Some(Problem::Offline);
                    return Err(io::Error::other("offline"));
                }
                match self.fetch(url, &[], "GET") {
                    Ok(fetched) if fetched.response.status == 200 => {
                        hops = fetched.hops;
                        let inner = fetched.response.body;
                        Ok(Box::new(Hashing {
                            inner,
                            sha: sha.clone(),
                        }))
                    }
                    Ok(fetched) => {
                        hops = fetched.hops;
                        problem = Some(Problem::Status(fetched.response));
                        Err(io::Error::other("upstream status"))
                    }
                    Err((failure, failed_hops)) => {
                        hops = failed_hops;
                        problem = Some(Problem::Failed(failure));
                        Err(io::Error::other("upstream failure"))
                    }
                }
            },
        );
        record.hops = hops;
        let lease = match downloaded {
            Ok(lease) => lease,
            Err(error) => {
                let received = hex::encode(
                    sha.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                        .finalize(),
                );
                return self.claimed_failure(out, record, &claim, error, problem, received);
            }
        };
        // The verified entry, opened under the lease. A failure here still
        // answers the tool and records the request.
        let opened_entry = (|| -> io::Result<(String, std::fs::File, u64)> {
            let sha256 = match claim.0.algo {
                Algo::Sha256 => claim.0.hex().to_string(),
                _ => fetch::hash_file(&lease, Algo::Sha256)?,
            };
            let file = std::fs::File::open(&*lease)?;
            let length = file.metadata()?.len();
            Ok((sha256, file, length))
        })();
        let (sha256, mut file, length) = match opened_entry {
            Ok(opened) => opened,
            Err(error) => {
                return self.fail(
                    out,
                    record,
                    502,
                    format!("verified cache entry unreadable: {error}"),
                )
            }
        };
        record.status = 200;
        record.sha256 = Some(sha256);
        record.verified = true;
        record.freshness = Some(Freshness::Live);
        record.disposition = if opened { "miss" } else { "hit" };
        record.bytes = if self.head_only() { 0 } else { length };
        record.commit(self.state);
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/octet-stream");
        let mut out = Out(out);
        http::write_sized_head(&mut out, 200, &headers, length, self.keep_alive)?;
        if !self.head_only() {
            io::copy(&mut file, &mut out)?;
        }
        out.flush()
    }

    /// A claimed artifact that could not be served verified.
    fn claimed_failure(
        &self,
        out: &mut dyn Write,
        mut record: Record,
        claim: &Claim,
        error: io::Error,
        problem: Option<Problem>,
        received: String,
    ) -> io::Result<()> {
        if let Some(mismatch) = HashMismatch::of(&error) {
            let reason = format!(
                "{}: the registry claimed {} but upstream sent {}:{} (sha256:{received}); \
                 nothing was cached",
                record.url,
                claim.describe(),
                mismatch.expected.algo(),
                mismatch.got
            );
            self.state.hard_failure(reason.clone());
            record.sha256 = Some(received);
            return self.fail(out, record, 502, reason);
        }
        match problem {
            Some(Problem::Offline) => self.offline_miss(out, record),
            Some(Problem::Failed(failure)) => self.refuse_upstream(out, record, failure),
            Some(Problem::Status(response)) => self.pass_through(out, record, response),
            None => self.fail(out, record, 502, error.to_string()),
        }
    }

    /// A non-2xx artifact answer: a 4xx reaches the tool as it is, a 5xx
    /// is a 504 (artifacts have no last-good).
    fn pass_through(
        &self,
        out: &mut dyn Write,
        mut record: Record,
        mut response: PinnedResponse,
    ) -> io::Result<()> {
        let status = response.status;
        if status >= 500 || (200..300).contains(&status) {
            return self.fail(out, record, 504, format!("upstream answered {status}"));
        }
        let body = match cache::read_capped(&mut response.body, http::MAX_BODY) {
            Ok(body) => body,
            Err(error) => return self.fail(out, record, 502, error.to_string()),
        };
        record.status = status;
        record.sha256 = Some(hex::encode(Sha256::digest(&body)));
        record.freshness = Some(Freshness::Live);
        record.disposition = "miss";
        record.bytes = body.len() as u64;
        record.commit(self.state);
        let mut headers = Headers::new();
        for (name, value) in &response.headers {
            if SERVED_RESPONSE_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                headers.push(name, value);
            }
        }
        self.reply(out, status, &headers, &body)
    }

    fn unclaimed_artifact(
        &self,
        url: &Url,
        mut record: Record,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        if self.route.protocol.expects_claim(url) {
            let detail = "the registry publishes no digest for this artifact";
            if let Err(refusal) = self
                .state
                .check(policy::WEAK_INTEGRITY, &record.url, detail)
            {
                return self.refuse(out, record, 403, &refusal);
            }
        }
        if self.state.config.mode == Mode::Offline {
            // Nothing vouches for an unclaimed artifact, so none is cached.
            return self.offline_miss(out, record);
        }
        let Fetched { mut response, hops } = match self.fetch(url, &[], self.method) {
            Ok(fetched) => fetched,
            Err((failure, hops)) => {
                record.hops = hops;
                return self.refuse_upstream(out, record, failure);
            }
        };
        record.hops = hops;
        if !(200..300).contains(&response.status) {
            return self.pass_through(out, record, response);
        }
        let mut headers = Headers::new();
        for (name, value) in &response.headers {
            if SERVED_RESPONSE_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                headers.push(name, value);
            }
        }
        record.status = response.status;
        record.freshness = Some(Freshness::Live);
        record.disposition = "stream";
        let mut out = Out(out);
        if self.head_only() {
            record.commit(self.state);
            return http::write_response(
                &mut out,
                response.status,
                &headers,
                &[],
                self.keep_alive,
                true,
            );
        }
        let mut body =
            http::ChunkedBody::start(&mut out, response.status, &headers, self.keep_alive)?;
        let (streamed, sha) = stream_hashed(&mut response.body, &mut body);
        record.bytes = streamed.as_ref().map_or(0, |total| *total);
        match streamed {
            Ok(_) => {
                record.sha256 = Some(sha);
                record.commit(self.state);
                body.finish()
            }
            Err(error) => {
                // The status is already sent: cut the stream short, so the
                // tool sees a truncated body rather than a complete one.
                record.status = 502;
                record.freshness = None;
                record.disposition = "failed";
                record.detail = Some(format!("stream interrupted: {error}"));
                record.commit(self.state);
                Err(error)
            }
        }
    }
}

/// Copy `reader` into `body` chunk by chunk, hashing it, up to the artifact
/// cap. Returns the byte count (or the error) and the sha256 so far.
fn stream_hashed<W: Write>(
    reader: &mut dyn Read,
    body: &mut http::ChunkedBody<'_, W>,
) -> (io::Result<u64>, String) {
    let mut sha = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let result = loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break Ok(total),
            Ok(n) => n,
            Err(error) => break Err(error),
        };
        total += n as u64;
        if total > MAX_ARTIFACT {
            break Err(io::Error::other(format!(
                "over the {} GiB artifact cap",
                MAX_ARTIFACT >> 30
            )));
        }
        sha.update(&buf[..n]);
        if let Err(error) = body.chunk(&buf[..n]) {
            break Err(error);
        }
    };
    (result, hex::encode(sha.finalize()))
}

#[cfg(test)]
mod tests {
    use crate::kernel::policy::{self, Policy};
    use crate::kernel::resolve::ledger::{Entry, Freshness};
    use crate::kernel::resolve::proxy::Session;
    use crate::kernel::resolve::routes::testing::TEST_PROTOCOL;
    use crate::kernel::resolve::routes::{Endpoint, ProxyAddress, Route};
    use crate::kernel::resolve::session::{Mode, SessionReport};
    use crate::kernel::resolve::testing::{get, mirror, Harness, Response};
    use crate::kernel::testutil::upstream::{Behavior, Reply};
    use sha2::{Digest as _, Sha256};
    use std::fs;

    const KERNEL: &str = "tests/fixtures/proxy/registry/kernel";

    fn fixture(path: &str) -> Vec<u8> {
        fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(KERNEL)
                .join(path),
        )
        .unwrap()
    }

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn fetch(address: &ProxyAddress, path: &str) -> Response {
        get(address, &mirror(address, path), "")
    }

    fn entries_for(report: &SessionReport, url: &str) -> Vec<Entry> {
        report
            .ledger
            .entries()
            .filter(|entry| entry.url == url)
            .cloned()
            .collect()
    }

    fn deny(kind: &str) -> Policy {
        Policy {
            deny: [kind.to_string()].into(),
            ..Policy::default()
        }
    }

    fn redirect(to: &str) -> Behavior {
        Behavior::Reply(Reply::new(302, b"").header("Location", to))
    }

    /// Warm the metadata cache for the fixture metadata in one session.
    fn warm(harness: &Harness, paths: &[&str]) {
        let (session, address) = harness.session();
        for path in paths {
            assert_eq!(fetch(&address, path).status, 200, "{path}");
        }
        session.finish();
    }

    #[test]
    fn proxy_rechecks_every_redirect_hop_and_drops_credentials_across_origins() {
        let harness = Harness::new("mirror-redirect");
        let port = harness.upstream.port();
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.routes = vec![Route::new(
            &TEST_PROTOCOL,
            vec![
                Endpoint::for_test("registry.test", port)
                    .with_authorization("Bearer registry-only")
                    .unwrap(),
                Endpoint::for_test("other.test", port),
            ],
        )
        .unwrap()];
        let (session, address) = harness.open(config);
        harness.upstream.set(
            "/meta/hop",
            redirect(&format!("https://other.test:{port}/meta/landed")),
        );
        harness
            .upstream
            .set("/meta/landed", Behavior::Reply(Reply::new(200, b"landed")));
        let answer = fetch(&address, "/meta/hop");
        assert_eq!(answer.status, 200, "{}", answer.text());
        assert_eq!(answer.body, b"landed");
        let seen = harness.upstream.seen();
        assert_eq!(
            seen[0].headers.get("authorization"),
            Some("Bearer registry-only")
        );
        assert_eq!(
            seen[1].headers.get("host"),
            Some(format!("other.test:{port}").as_str())
        );
        assert_eq!(seen[1].sni.as_deref(), Some("other.test"));
        assert_eq!(
            seen[1].headers.get("authorization"),
            None,
            "no credential crosses origins"
        );
        assert_eq!(
            harness.lookup.hosts(),
            ["registry.test", "other.test"],
            "every hop is resolved and validated again"
        );

        // A hop off the permitted set, or off https, is refused before it
        // is requested.
        harness.upstream.set(
            "/meta/off",
            redirect(&format!("https://third.test:{port}/meta/pkg.json")),
        );
        harness.upstream.set(
            "/meta/plain",
            redirect(&format!("http://registry.test:{port}/meta/pkg.json")),
        );
        for (path, host) in [
            ("/meta/off", "third.test"),
            ("/meta/plain", "http://registry.test"),
        ] {
            let refused = fetch(&address, path);
            assert_eq!(refused.status, 403, "{}", refused.text());
            assert!(
                refused.text().contains("is not a permitted endpoint"),
                "{}",
                refused.text()
            );
            assert!(refused.text().contains(host), "{}", refused.text());
        }
        assert_eq!(harness.upstream.hits("/meta/pkg.json"), 0);
        let report = session.finish();
        let hops: Vec<Vec<String>> = report
            .diagnostics
            .requests
            .iter()
            .map(|r| r.hops.clone())
            .collect();
        assert_eq!(hops[0], [format!("https://other.test:{port}/meta/landed")]);
        assert_eq!(
            entries_for(&report, &harness.upstream_url("/meta/off"))[0].class,
            "refused"
        );
        assert_eq!(
            report.facts.failure(),
            None,
            "a refused redirect is recorded, not a policy denial"
        );
    }

    #[test]
    fn claimed_digest_mismatch_is_a_hard_failure_and_caches_nothing() {
        let harness = Harness::new("mirror-mismatch");
        let (session, address) = harness.session();
        assert_eq!(fetch(&address, "/meta/pkg.json").status, 200);
        let bad = fixture("art/claimed-bad-1.0.tgz");
        let claimed = sha256(b"what the registry published");
        let answer = fetch(&address, "/art/claimed-bad-1.0.tgz");
        assert_eq!(answer.status, 502);
        assert!(answer.text().contains(&claimed), "{}", answer.text());
        assert!(answer.text().contains(&sha256(&bad)), "{}", answer.text());
        let cache = harness.store.root.join("cache/sha256");
        assert!(!cache.join(&claimed).exists() && !cache.join(sha256(&bad)).exists());
        assert_eq!(
            fs::read_dir(harness.store.root.join("tmp"))
                .unwrap()
                .count(),
            0,
            "no partial file"
        );

        // Control: bytes that match are cached, and served from the cache
        // the second time without contacting upstream.
        let good = fixture("art/claimed-pkg-1.0.tgz");
        for _ in 0..2 {
            let served = fetch(&address, "/art/claimed-pkg-1.0.tgz");
            assert_eq!(
                (served.status, served.body.as_slice()),
                (200, good.as_slice())
            );
        }
        assert_eq!(harness.upstream.hits("/art/claimed-pkg-1.0.tgz"), 1);
        assert!(cache.join(sha256(&good)).is_file());
        let strong = fetch(&address, "/art/strong-pkg-1.0.tgz");
        assert_eq!(
            strong.body,
            fixture("art/strong-pkg-1.0.tgz"),
            "sha512 claims verify too"
        );

        let report = session.finish();
        let failure = report.facts.failure().unwrap();
        assert!(failure.contains(&format!("sha256:{claimed}")), "{failure}");
        assert!(failure.contains(&sha256(&bad)), "{failure}");
        let entry = &entries_for(&report, &harness.upstream_url("/art/claimed-bad-1.0.tgz"))[0];
        assert_eq!((entry.status, entry.verified), (502, false));
        assert_eq!(
            entry.claimed.as_deref(),
            Some(format!("sha256:{claimed}").as_str())
        );
        assert_eq!(entry.sha256.as_deref(), Some(sha256(&bad).as_str()));
        let good_entries = entries_for(&report, &harness.upstream_url("/art/claimed-pkg-1.0.tgz"));
        assert_eq!(
            good_entries.len(),
            1,
            "a cache hit is the same portable entry as the miss"
        );
        assert!(good_entries[0].verified);
    }

    #[test]
    fn unclaimed_artifacts_stream_hashed_and_weak_claims_are_weak_integrity() {
        let harness = Harness::new("mirror-unclaimed");
        let (session, address) = harness.session();
        assert_eq!(fetch(&address, "/meta/pkg.json").status, 200);
        let free = fixture("art/free-pkg-1.0.tgz");
        let streamed = fetch(&address, "/art/free-pkg-1.0.tgz");
        assert_eq!(streamed.headers.get("transfer-encoding"), Some("chunked"));
        assert_eq!(streamed.body, free);
        assert!(!harness
            .store
            .root
            .join("cache/sha256")
            .join(sha256(&free))
            .exists());
        assert_eq!(fetch(&address, "/art/weak-pkg-1.0.tgz").status, 200);
        // The protocol publishes a claim for every `claimed-` artifact, so
        // one without is weak too; with no metadata it is refused below.
        let report = session.finish();
        let entry = &entries_for(&report, &harness.upstream_url("/art/free-pkg-1.0.tgz"))[0];
        assert_eq!(entry.sha256.as_deref(), Some(sha256(&free).as_str()));
        assert!(!entry.verified && entry.claimed.is_none());
        let weak: Vec<_> = report
            .facts
            .exceptions
            .iter()
            .map(|f| (f.kind, f.subject.clone()))
            .collect();
        assert_eq!(
            weak,
            [(
                policy::WEAK_INTEGRITY,
                harness.upstream_url("/art/weak-pkg-1.0.tgz")
            )]
        );

        let (session, address) =
            harness.open(harness.config(deny(policy::WEAK_INTEGRITY), Mode::Online));
        let refused = fetch(&address, "/art/claimed-pkg-1.0.tgz");
        assert_eq!(
            refused.status,
            403,
            "no metadata claimed it: {}",
            refused.text()
        );
        assert!(
            refused.text().contains("publishes no digest"),
            "{}",
            refused.text()
        );
        assert!(session.finish().facts.failure().is_some());
    }

    #[test]
    fn transport_failure_serves_last_good_metadata_marked_last_good() {
        let harness = Harness::new("mirror-lastgood");
        warm(&harness, &["/meta/pkg.json"]);
        let (session, address) = harness.session();
        harness.upstream.set("/meta/pkg.json", Behavior::Drop);
        let dropped = fetch(&address, "/meta/pkg.json");
        assert_eq!(
            (dropped.status, dropped.body.clone()),
            (200, fixture("meta/pkg.json"))
        );
        harness
            .upstream
            .set("/meta/pkg.json", Behavior::Reply(Reply::new(503, b"down")));
        assert_eq!(
            fetch(&address, "/meta/pkg.json").body,
            fixture("meta/pkg.json")
        );
        // Claims still come from the last-good body.
        assert_eq!(fetch(&address, "/art/claimed-pkg-1.0.tgz").status, 200);
        // No copy: 504 naming the URL.
        harness.upstream.set("/index/pkg", Behavior::Drop);
        let missing = fetch(&address, "/index/pkg");
        assert_eq!(missing.status, 504);
        assert!(
            missing.text().contains(&harness.upstream_url("/index/pkg")),
            "{}",
            missing.text()
        );
        let report = session.finish();
        let served = entries_for(&report, &harness.upstream_url("/meta/pkg.json"));
        assert_eq!(
            served.len(),
            1,
            "both last-good answers are one portable entry"
        );
        assert_eq!(served[0].freshness, Some(Freshness::LastGood));
        assert_eq!(
            served[0].sha256.as_deref(),
            Some(sha256(&fixture("meta/pkg.json")).as_str())
        );
        let dispositions: Vec<_> = report
            .diagnostics
            .requests
            .iter()
            .map(|r| r.disposition.as_str())
            .collect();
        assert_eq!(dispositions, ["last-good", "last-good", "miss", "failed"]);
    }

    #[test]
    fn last_good_records_stale_resolution_per_endpoint() {
        let harness = Harness::new("mirror-stale");
        warm(&harness, &["/meta/pkg.json", "/second/meta/pkg.json"]);
        harness.upstream.set("/meta/pkg.json", Behavior::Drop);
        let (session, address) = harness.session();
        for path in ["/meta/pkg.json", "/meta/pkg.json", "/second/meta/pkg.json"] {
            assert_eq!(fetch(&address, path).status, 200, "{path}");
        }
        let report = session.finish();
        let port = harness.upstream.port();
        let stale: Vec<_> = report
            .facts
            .exceptions
            .iter()
            .map(|fact| (fact.kind, fact.subject.clone(), fact.detail.clone()))
            .collect();
        assert_eq!(
            stale,
            [
                (
                    policy::STALE_RESOLUTION,
                    format!("https://other.test:{port}"),
                    "1 metadata response served from the last-good cache; registry unreachable"
                        .into()
                ),
                (
                    policy::STALE_RESOLUTION,
                    format!("https://registry.test:{port}"),
                    "2 metadata responses served from the last-good cache; registry unreachable"
                        .into()
                ),
            ]
        );
        assert_eq!(
            report.facts.failure(),
            None,
            "stale-resolution is recorded, not denied, by default"
        );
    }

    #[test]
    fn denied_stale_resolution_turns_last_good_into_504() {
        let harness = Harness::new("mirror-stale-denied");
        warm(&harness, &["/meta/pkg.json"]);
        harness.upstream.set("/meta/pkg.json", Behavior::Drop);
        let (session, address) =
            harness.open(harness.config(deny(policy::STALE_RESOLUTION), Mode::Online));
        let answer = fetch(&address, "/meta/pkg.json");
        assert_eq!(answer.status, 504);
        assert!(
            answer.text().contains("policy denies stale-resolution"),
            "{}",
            answer.text()
        );
        let report = session.finish();
        assert!(
            report.facts.exceptions.is_empty(),
            "nothing stale was served"
        );
        let url = harness.upstream_url("/meta/pkg.json");
        assert_eq!(
            report.facts.first_stale_refused.as_deref(),
            Some(url.as_str())
        );
        assert!(report.facts.failure().unwrap().contains(&url));
        let entry = &entries_for(&report, &url)[0];
        assert_eq!(
            (entry.class.as_str(), entry.status, entry.freshness),
            ("refused", 504, None)
        );
    }

    #[test]
    fn http_4xx_is_passed_through_not_served_stale() {
        let harness = Harness::new("mirror-4xx");
        warm(&harness, &["/meta/pkg.json"]);
        let (session, address) = harness.session();
        for status in [404, 410] {
            harness.upstream.set(
                "/meta/pkg.json",
                Behavior::Reply(Reply::new(status, b"gone upstream")),
            );
            let answer = fetch(&address, "/meta/pkg.json");
            assert_eq!(
                (answer.status, answer.body.as_slice()),
                (status, &b"gone upstream"[..])
            );
        }
        let report = session.finish();
        assert!(report.facts.exceptions.is_empty(), "a 4xx is not stale");
        let statuses: Vec<_> = entries_for(&report, &harness.upstream_url("/meta/pkg.json"))
            .iter()
            .map(|entry| (entry.status, entry.freshness))
            .collect();
        assert_eq!(
            statuses,
            [(404, Some(Freshness::Live)), (410, Some(Freshness::Live))]
        );
        // A 4xx is not cached either: the good copy is still there.
        harness.upstream.set("/meta/pkg.json", Behavior::Drop);
        let (session, address) = harness.session();
        assert_eq!(
            fetch(&address, "/meta/pkg.json").body,
            fixture("meta/pkg.json")
        );
        session.finish();
    }

    #[test]
    fn offline_mode_serves_cache_only_and_names_the_first_miss() {
        let harness = Harness::new("mirror-offline");
        warm(&harness, &["/meta/pkg.json", "/art/claimed-pkg-1.0.tgz"]);
        let before = harness.upstream.seen().len();
        let lookups = harness.lookup.calls();
        let (session, address): (Session, _) =
            harness.open(harness.config(Policy::default(), Mode::Offline));
        assert_eq!(
            fetch(&address, "/meta/pkg.json").body,
            fixture("meta/pkg.json")
        );
        assert_eq!(
            fetch(&address, "/art/claimed-pkg-1.0.tgz").body,
            fixture("art/claimed-pkg-1.0.tgz")
        );
        let first = fetch(&address, "/index/pkg");
        assert_eq!(first.status, 504);
        assert!(first.text().contains("offline"), "{}", first.text());
        assert_eq!(fetch(&address, "/art/free-pkg-1.0.tgz").status, 504);
        assert_eq!(
            harness.upstream.seen().len(),
            before,
            "offline makes no upstream connection"
        );
        assert_eq!(harness.lookup.calls(), lookups, "offline looks nothing up");
        let report = session.finish();
        let index = harness.upstream_url("/index/pkg");
        assert_eq!(
            report.facts.first_offline_miss.as_deref(),
            Some(index.as_str())
        );
        assert!(report.facts.failure().unwrap().contains(&index));
        let classes: Vec<_> = report
            .ledger
            .entries()
            .map(|entry| entry.class.as_str())
            .collect();
        assert_eq!(
            classes
                .iter()
                .filter(|class| **class == "offline-miss")
                .count(),
            2
        );
        let stale = report.facts.exceptions.iter().next().unwrap();
        assert_eq!(stale.kind, policy::STALE_RESOLUTION);
    }

    #[test]
    fn local_answers_and_rewrites_record_the_upstream_bytes() {
        let harness = Harness::new("mirror-local");
        let (session, address) = harness.session();
        let local = fetch(&address, "/local/supported");
        assert_eq!(local.status, 200);
        let rewritten = fetch(&address, "/meta/rewritten.json");
        let base = address.route_base("fixture");
        assert_eq!(
            rewritten.text(),
            format!("{{\"next\": \"{base}meta/pkg.json\"}}\n")
        );
        assert!(harness
            .upstream
            .seen()
            .iter()
            .all(|seen| seen.target != "/supported"));
        let report = session.finish();
        let local = &entries_for(&report, &harness.upstream_url("/supported"))[0];
        assert_eq!(local.class, "local");
        let upstream = &entries_for(&report, &harness.upstream_url("/meta/rewritten.json"))[0];
        assert_eq!(
            upstream.sha256.as_deref(),
            Some(sha256(&fixture("meta/rewritten.json")).as_str()),
            "the ledger records what upstream sent, not the rewrite"
        );
        let ledger = String::from_utf8(report.ledger.bytes()).unwrap();
        assert!(!ledger.contains(address.token()));
    }

    #[test]
    fn metadata_is_revalidated_with_the_cached_validator() {
        let harness = Harness::new("mirror-revalidate");
        warm(&harness, &["/meta/pkg.json", "/index/pkg"]);
        let (session, address) = harness.session();
        assert_eq!(
            fetch(&address, "/meta/pkg.json").body,
            fixture("meta/pkg.json")
        );
        assert_eq!(fetch(&address, "/index/pkg").body, fixture("index/pkg"));
        let seen = harness.upstream.seen();
        let revalidated: Vec<_> = seen[2..]
            .iter()
            .map(|seen| {
                (
                    seen.headers.get("if-none-match").map(str::to_string),
                    seen.headers.get("if-modified-since").map(str::to_string),
                )
            })
            .collect();
        assert_eq!(
            revalidated,
            [
                (Some("\"pkg-v1\"".to_string()), None),
                (None, Some("Tue, 01 Sep 2026 00:00:00 GMT".to_string())),
            ]
        );
        let report = session.finish();
        let dispositions: Vec<_> = report
            .diagnostics
            .requests
            .iter()
            .map(|r| r.disposition.as_str())
            .collect();
        assert_eq!(dispositions, ["revalidated", "revalidated"]);
        let entry = &entries_for(&report, &harness.upstream_url("/meta/pkg.json"))[0];
        assert_eq!(
            (entry.status, entry.freshness),
            (200, Some(Freshness::Live))
        );
    }

    #[test]
    fn head_requests_send_no_body_and_claimed_heads_are_verified_first() {
        let harness = Harness::new("mirror-head");
        let (session, address) = harness.session();
        let head = |path: &str| {
            crate::kernel::resolve::testing::send(
                &address,
                &format!("HEAD {} HTTP/1.1\r\nHost: x\r\n", mirror(&address, path)),
            )
        };
        let meta = head("/meta/pkg.json");
        assert_eq!(meta.status, 200);
        assert!(meta.body.is_empty());
        assert_eq!(fetch(&address, "/meta/pkg.json").status, 200);
        let artifact = head("/art/claimed-pkg-1.0.tgz");
        let length = fixture("art/claimed-pkg-1.0.tgz").len().to_string();
        assert_eq!(
            artifact.headers.get("content-length"),
            Some(length.as_str())
        );
        assert!(artifact.body.is_empty());
        let methods: Vec<(String, String)> = harness
            .upstream
            .seen()
            .into_iter()
            .map(|seen| (seen.method, seen.target))
            .collect();
        assert_eq!(
            methods,
            [
                ("HEAD".to_string(), "/meta/pkg.json".to_string()),
                ("GET".to_string(), "/meta/pkg.json".to_string()),
                ("GET".to_string(), "/art/claimed-pkg-1.0.tgz".to_string()),
            ],
            "a claimed artifact is fetched whole and verified even for a HEAD"
        );
        session.finish();
    }

    #[test]
    fn a_repeated_accept_is_refused_so_the_cache_key_matches_upstream() {
        let harness = Harness::new("mirror-accept");
        let (session, address) = harness.session();
        let answer = get(
            &address,
            &mirror(&address, "/meta/pkg.json"),
            "Accept: application/json\r\nAccept: application/vnd.npm.install-v1+json\r\n",
        );
        assert_eq!(answer.status, 400, "{}", answer.text());
        assert!(
            answer.text().contains("repeats accept"),
            "{}",
            answer.text()
        );
        assert!(
            harness.upstream.seen().is_empty(),
            "nothing was fetched or cached"
        );
        session.finish();
    }

    #[test]
    fn credentialed_metadata_is_never_served_to_another_credential_configuration() {
        let harness = Harness::new("mirror-cred-cache");
        let port = harness.upstream.port();
        let open = |credential: Option<&str>| {
            let mut registry = Endpoint::for_test("registry.test", port);
            if let Some(credential) = credential {
                registry = registry.with_authorization(credential).unwrap();
            }
            let mut config = harness.config(Policy::default(), Mode::Online);
            config.routes = vec![Route::new(
                &TEST_PROTOCOL,
                vec![registry, Endpoint::for_test("other.test", port)],
            )
            .unwrap()];
            harness.open(config)
        };
        let (session, address) = open(Some("Bearer private"));
        assert_eq!(fetch(&address, "/meta/pkg.json").status, 200);
        session.finish();
        harness.upstream.set("/meta/pkg.json", Behavior::Drop);
        for credential in [None, Some("Bearer someone-else")] {
            let (session, address) = open(credential);
            let answer = fetch(&address, "/meta/pkg.json");
            assert_eq!(
                answer.status,
                504,
                "{credential:?} got a copy: {}",
                answer.text()
            );
            session.finish();
        }
        // Control: the same credentials find their own last-good copy.
        let (session, address) = open(Some("Bearer private"));
        assert_eq!(
            fetch(&address, "/meta/pkg.json").body,
            fixture("meta/pkg.json")
        );
        session.finish();
    }

    #[test]
    fn a_non_ascii_forwarded_header_is_a_400_never_a_stale_resolution() {
        let harness = Harness::new("mirror-non-ascii");
        warm(&harness, &["/meta/pkg.json"]);
        let seen = harness.upstream.seen().len();
        let (session, address) = harness.session();
        let answer = get(
            &address,
            &mirror(&address, "/meta/pkg.json"),
            "User-Agent: tool/1.0 caf\u{e9}\r\n",
        );
        assert_eq!(answer.status, 400, "{}", answer.text());
        assert_eq!(
            harness.upstream.seen().len(),
            seen,
            "nothing was sent upstream"
        );
        let report = session.finish();
        assert!(
            report.facts.exceptions.is_empty(),
            "no stale-resolution was forged"
        );
    }
}

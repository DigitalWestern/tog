//! One door run's view of the proxy: its token, its routes, its policy, and
//! everything it recorded.
//!
//! A session is opened per door run. Its token is 32 random bytes, so a
//! tool of another session (or anything else on the machine) cannot guess
//! it, and every listener belongs to exactly one session, so a request is
//! judged and recorded where it arrived even when its token is wrong.
//!
//! The proxy never writes a policy record. It holds a copy of the run's
//! `Policy`, asks the pure [`policy::denied`] per request, and collects
//! facts: the exceptions to record, the refusals that fail the door, and
//! the hard failures (integrity) that fail it under every policy. The door
//! turns the [`SessionReport`] into records on its own thread.

use super::cache::MetaCache;
use super::ledger::{DiagRequest, Diagnostics, Entry, PortableLedger};
use super::redact;
use super::routes::{Claim, Permitted, Route};
use crate::kernel::activity::StoreActivity;
use crate::kernel::policy::{self, Policy};
use crate::kernel::store::Store;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::sync::Mutex;
use url::Url;

/// The most rows each diagnostics list keeps per session. Past it, rows
/// are counted, not kept: a tool (or anything else that can reach the
/// port) cannot grow a sidecar without bound.
pub(crate) const MAX_DIAGNOSTIC_ROWS: usize = 10_000;

/// What the proxy does with an authenticated `CONNECT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intercept {
    /// Answer 403 with a body naming the host and the reason, and record
    /// the refusal. The tool sees why it failed. Mirror-dialect tools (Go,
    /// Bundler, Hex, NuGet) reach registries only through their routes.
    RefuseVisibly,
    /// Terminate TLS with a leaf for the tunnel's host signed by the
    /// proxy's certificate authority, and serve each request inside like a
    /// routed one (see [`super::intercept`]). `git://`'s port is still
    /// refused. For tools whose locks record upstream URLs (cargo, git,
    /// npm, pnpm, uv).
    Tls,
}

/// Whether the proxy may contact upstream at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Online,
    /// Cache only: metadata from last-good, artifacts from the verified
    /// cache, and every miss a 504 plus a ledger `offline-miss`.
    Offline,
}

/// Everything a door hands the proxy when it opens a session.
pub struct SessionConfig {
    /// Lowercase ecosystem name, recorded in the portable ledger.
    pub ecosystem: String,
    /// The door kind (`edit`, `missing-lock`, `planner`, `x`).
    pub door: String,
    pub routes: Vec<Route>,
    pub intercept: Intercept,
    /// The run's effective policy, copied: the proxy only reads it.
    pub policy: Policy,
    pub mode: Mode,
    pub store: Store,
    /// The door's lease, held by the session for its cache writes.
    pub activity: StoreActivity,
    /// Where route endpoints and redirect hops may lead.
    pub permitted: Permitted,
}

/// One exception the door records when policy does not deny it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fact {
    pub kind: &'static str,
    pub subject: String,
    pub detail: String,
}

/// What a session established, for the door to act on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Exceptions to record (their kind was not denied).
    pub exceptions: BTreeSet<Fact>,
    /// Policy refusal texts: a denied kind refused a request. Each fails
    /// the door even when the tool exits 0.
    pub refusals: Vec<String>,
    /// Failures no policy permits (integrity, an address the SSRF rule
    /// refused). Each fails the door.
    pub hard_failures: Vec<String>,
    /// The first request offline mode could not serve: the thing to fetch
    /// online.
    pub first_offline_miss: Option<String>,
    /// The first request answered 504 because `stale-resolution` is denied.
    pub first_stale_refused: Option<String>,
}

impl Facts {
    /// Why the door fails, if it does: a hard failure first (it is never
    /// a policy question), then a policy refusal, then an offline miss.
    pub fn failure(&self) -> Option<String> {
        if let Some(failure) = self.hard_failures.first() {
            return Some(failure.clone());
        }
        if let Some(refusal) = self.refusals.first() {
            return Some(refusal.clone());
        }
        self.first_offline_miss
            .as_ref()
            .map(|url| format!("offline, and {url} is not cached; run once online to fetch it"))
    }
}

/// A finished session.
#[derive(Debug, Clone)]
pub struct SessionReport {
    pub ledger: PortableLedger,
    pub diagnostics: Diagnostics,
    pub facts: Facts,
}

/// A session's live state, shared by the connections serving it.
pub(crate) struct State {
    pub(crate) config: SessionConfig,
    token: String,
    pub(crate) meta: MetaCache,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    ledger: Option<PortableLedger>,
    diagnostics: Diagnostics,
    facts: Facts,
    /// Artifact claims learned from served metadata, by URL without its
    /// fragment.
    claims: HashMap<String, BTreeSet<ClaimKey>>,
    /// The last portable entry per (method, url), to count retries.
    last: HashMap<(String, String), Entry>,
    /// Last-good responses per endpoint origin.
    stale: BTreeMap<String, u64>,
    /// Endpoints whose stale refusal was already reported.
    stale_refused: BTreeSet<String>,
    /// Every (method, url) that was answered (something was served).
    answered: HashSet<(String, String)>,
    /// Failed portable entries per (method, url), taken out of the ledger
    /// when the same request is answered.
    failed: HashMap<(String, String), Vec<Entry>>,
    /// The texts already in `facts.refusals` and `facts.hard_failures`.
    refusal_texts: HashSet<String>,
    failure_texts: HashSet<String>,
    seq: u64,
    /// The session finished: nothing more is recorded or allowed.
    closed: bool,
}

/// A claim, ordered so the strongest algorithm sorts last.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClaimKey(u8, String, String);

impl ClaimKey {
    fn new(claim: &Claim) -> Self {
        let rank = match claim.0.algo() {
            "sha512" => 3,
            "sha256" => 2,
            _ => 1,
        };
        ClaimKey(rank, claim.0.algo().to_string(), claim.0.hex().to_string())
    }
}

/// What a URL's claims say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Claimed {
    None,
    /// The strongest claim, the one the bytes are verified against.
    One(Claim),
    /// Two metadata documents disagree about the same algorithm.
    Conflict(String),
}

fn claim_key(url: &Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    url.to_string()
}

/// A fresh session token: 32 random bytes as hex.
fn new_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random source failed"))?;
    Ok(hex::encode(bytes))
}

/// Byte comparison whose time does not depend on where the inputs differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

impl State {
    pub(crate) fn new(config: SessionConfig) -> io::Result<State> {
        for route in &config.routes {
            if let Some(endpoint) = route
                .endpoints
                .iter()
                .find(|endpoint| !endpoint.permitted_by(&config.permitted))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "route {} names {}, which is not a permitted endpoint",
                        route.protocol.route_id(),
                        endpoint.origin()
                    ),
                ));
            }
        }
        let ids: BTreeSet<&str> = config
            .routes
            .iter()
            .map(|r| r.protocol.route_id())
            .collect();
        if ids.len() != config.routes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "two routes share one route id",
            ));
        }
        config
            .store
            .require_activity(&config.activity, "a resolution proxy session")?;
        let ledger = PortableLedger::new(&config.ecosystem, &config.door)?;
        let meta = MetaCache::open(&config.store)?;
        Ok(State {
            token: new_token()?,
            meta,
            inner: Mutex::new(Inner {
                ledger: Some(ledger),
                ..Inner::default()
            }),
            config,
        })
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// `text` as it may be shown or stored: embedded URLs redacted and the
    /// session token removed.
    pub(crate) fn clean(&self, text: &str) -> String {
        redact::text(text).replace(&self.token, redact::REDACTED)
    }

    pub(crate) fn token_matches(&self, candidate: &str) -> bool {
        constant_time_eq(candidate.as_bytes(), self.token.as_bytes())
    }

    pub(crate) fn route(&self, id: &str) -> Option<&Route> {
        self.config
            .routes
            .iter()
            .find(|route| route.protocol.route_id() == id)
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panicking connection thread must not take the evidence with it.
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Stop recording. A connection still running after its session
    /// finished changes nothing, and its policy checks refuse.
    pub(crate) fn close(&self) {
        self.inner().closed = true;
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner().closed
    }

    /// Record one request: its portable entry and its diagnostics row.
    pub(crate) fn record(&self, mut entry: Entry, mut diag: DiagRequest) {
        entry.url = self.clean(&entry.url);
        entry.redirected_to = entry.redirected_to.map(|hop| self.clean(&hop));
        diag.url = self.clean(&diag.url);
        diag.detail = diag.detail.map(|detail| self.clean(&detail));
        diag.hops = diag.hops.iter().map(|hop| self.clean(hop)).collect();
        let mut inner = self.inner();
        if inner.closed {
            return;
        }
        inner.seq += 1;
        diag.seq = inner.seq;
        let key = (entry.method.clone(), entry.url.clone());
        match inner.last.get(&key) {
            Some(previous) if previous != &entry => inner.diagnostics.retries += 1,
            _ => {}
        }
        inner.last.insert(key.clone(), entry.clone());
        // The portable set describes outcomes: a failed attempt at a
        // request the session also answered was transient, so it stays
        // in diagnostics only, whichever order the two arrived in. A
        // digest mismatch (a claim and the received digest) is evidence of
        // tampering and stays.
        let mismatch = entry.claimed.is_some() && entry.sha256.is_some() && !entry.verified;
        let failed = diag.disposition == "failed" && !mismatch;
        if failed && inner.answered.contains(&key) {
            inner.diagnostics.superseded += 1;
        } else {
            let fresh = inner
                .ledger
                .as_mut()
                .is_some_and(|ledger| ledger.insert(entry.clone()));
            if !fresh {
                inner.diagnostics.duplicates += 1;
            } else if failed {
                inner
                    .failed
                    .entry(key.clone())
                    .or_default()
                    .push(entry.clone());
            }
        }
        if entry.freshness.is_some() && inner.answered.insert(key.clone()) {
            let superseded = inner.failed.remove(&key).unwrap_or_default();
            if let Some(ledger) = inner.ledger.as_mut() {
                for failure in &superseded {
                    ledger.remove(failure);
                }
            }
            inner.diagnostics.superseded += superseded.len() as u64;
        }
        inner.diagnostics.bytes += diag.bytes;
        push_row(&mut inner.diagnostics, diag);
    }

    /// Record a request that did not carry the session token. It is not
    /// the tool's session, so it never enters the portable ledger (which
    /// is signed evidence of the tool's traffic): it is a diagnostics row
    /// and a count.
    pub(crate) fn record_unauthenticated(&self, mut diag: DiagRequest) {
        diag.url = shorten(self.clean(&diag.url));
        diag.detail = diag.detail.map(|detail| shorten(self.clean(&detail)));
        let mut inner = self.inner();
        if inner.closed {
            return;
        }
        inner.seq += 1;
        diag.seq = inner.seq;
        inner.diagnostics.unauthenticated += 1;
        push_row(&mut inner.diagnostics, diag);
    }

    /// Apply policy to `kind`. Denied: the refusal text, which also fails
    /// the door. Otherwise the fact is recorded and the request proceeds.
    pub(crate) fn check(
        &self,
        kind: &'static str,
        subject: &str,
        detail: &str,
    ) -> Result<(), String> {
        let (subject, detail) = (&self.clean(subject), &self.clean(detail));
        let mut inner = self.inner();
        if inner.closed {
            return Err("the proxy session has finished".into());
        }
        if policy::denied(&self.config.policy, kind) {
            let text = policy::refusal(&self.config.policy, kind, subject, detail);
            if inner.refusal_texts.insert(text.clone()) {
                inner.facts.refusals.push(text.clone());
            }
            return Err(text);
        }
        inner.facts.exceptions.insert(Fact {
            kind,
            subject: subject.to_string(),
            detail: detail.to_string(),
        });
        Ok(())
    }

    /// Apply policy to `kind` for real-time denial only: denied, the
    /// refusal text (which fails the door); otherwise nothing is recorded.
    /// For facts the lock itself shows (a git dependency), which the tailor
    /// records from the lock at sync, so the record does not count them
    /// twice.
    pub(crate) fn refuse_if_denied(
        &self,
        kind: &'static str,
        subject: &str,
        detail: &str,
    ) -> Result<(), String> {
        if self.is_closed() {
            return Err("the proxy session has finished".into());
        }
        if !policy::denied(&self.config.policy, kind) {
            return Ok(());
        }
        let text = policy::refusal(
            &self.config.policy,
            kind,
            &self.clean(subject),
            &self.clean(detail),
        );
        let mut inner = self.inner();
        if inner.refusal_texts.insert(text.clone()) {
            inner.facts.refusals.push(text.clone());
        }
        Err(text)
    }

    /// A refusal with no request to attach it to (bytes that never parsed
    /// as a request). Diagnostics only: there is no method or URL to put in
    /// portable evidence.
    pub(crate) fn note_refusal(&self, text: String) {
        let text = self.clean(&text);
        let mut inner = self.inner();
        if !inner.closed {
            push_refusal(&mut inner.diagnostics, text);
        }
    }

    #[cfg(test)]
    pub(crate) fn note_port(&self, port: u16) {
        self.inner().diagnostics.port.get_or_insert(port);
    }

    pub(crate) fn hard_failure(&self, text: String) {
        let text = self.clean(&text);
        let mut inner = self.inner();
        if !inner.closed && inner.failure_texts.insert(text.clone()) {
            inner.facts.hard_failures.push(text);
        }
    }

    pub(crate) fn offline_miss(&self, url: &str) {
        let url = self.clean(url);
        let mut inner = self.inner();
        if !inner.closed && inner.facts.first_offline_miss.is_none() {
            inner.facts.first_offline_miss = Some(url);
        }
    }

    /// Whether last-good may be served for `endpoint`. When
    /// `stale-resolution` is denied it may not: the refusal is recorded
    /// once per endpoint, naming the first refused URL, why its upstream
    /// fetch failed (`why`), and the host to retry.
    pub(crate) fn stale_allowed(&self, endpoint: &str, url: &str, why: &str) -> Result<(), String> {
        let policy = &self.config.policy;
        if !policy::denied(policy, policy::STALE_RESOLUTION) {
            return Ok(());
        }
        let host = Url::parse(endpoint)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_string))
            .unwrap_or_else(|| endpoint.to_string());
        let text = policy::refusal(
            policy,
            policy::STALE_RESOLUTION,
            endpoint,
            &format!(
                "{url} could not be fetched ({why}) and the last-good copy from the cache was \
                 not used; retry when {host} is reachable"
            ),
        );
        let mut inner = self.inner();
        if inner.closed {
            return Err(text);
        }
        if inner.stale_refused.insert(endpoint.to_string())
            && inner.refusal_texts.insert(text.clone())
        {
            inner.facts.refusals.push(text.clone());
        }
        if inner.facts.first_stale_refused.is_none() {
            inner.facts.first_stale_refused = Some(self.clean(url));
        }
        Err(text)
    }

    /// Count one last-good response for `endpoint`.
    pub(crate) fn stale_served(&self, endpoint: &str) {
        let mut inner = self.inner();
        if !inner.closed {
            *inner.stale.entry(endpoint.to_string()).or_default() += 1;
        }
    }

    pub(crate) fn add_claims(&self, claims: Vec<(Url, Claim)>) {
        let mut inner = self.inner();
        for (url, claim) in claims {
            inner
                .claims
                .entry(claim_key(&url))
                .or_default()
                .insert(ClaimKey::new(&claim));
        }
    }

    pub(crate) fn claimed(&self, url: &Url) -> Claimed {
        let inner = self.inner();
        let Some(claims) = inner.claims.get(&claim_key(url)) else {
            return Claimed::None;
        };
        let Some(strongest) = claims.last() else {
            return Claimed::None;
        };
        let rivals: Vec<&ClaimKey> = claims
            .iter()
            .filter(|claim| claim.1 == strongest.1)
            .collect();
        if rivals.len() > 1 {
            return Claimed::Conflict(format!(
                "registry metadata claims {} different {} digests for {}",
                rivals.len(),
                strongest.1,
                claim_key(url)
            ));
        }
        let digest = match strongest.1.as_str() {
            "sha512" => crate::kernel::fetch::Digest::sha512(&strongest.2),
            "sha256" => crate::kernel::fetch::Digest::sha256(&strongest.2),
            _ => crate::kernel::fetch::Digest::sha1(&strongest.2),
        };
        match digest {
            Ok(digest) => Claimed::One(Claim(digest)),
            Err(error) => Claimed::Conflict(error.to_string()),
        }
    }

    /// Everything recorded, taken out of the session. Connections still
    /// running afterwards record into nothing.
    pub(crate) fn take_report(&self) -> SessionReport {
        let mut inner = self.inner();
        let ledger = inner.ledger.take().unwrap_or_else(|| {
            PortableLedger::new(&self.config.ecosystem, &self.config.door)
                .expect("the ecosystem and door were validated at open")
        });
        let mut facts = std::mem::take(&mut inner.facts);
        for (endpoint, count) in std::mem::take(&mut inner.stale) {
            facts.exceptions.insert(Fact {
                kind: policy::STALE_RESOLUTION,
                subject: endpoint,
                detail: format!(
                    "{count} metadata response{} served from the last-good cache; registry \
                     unreachable",
                    if count == 1 { "" } else { "s" }
                ),
            });
        }
        SessionReport {
            ledger,
            diagnostics: std::mem::take(&mut inner.diagnostics),
            facts,
        }
    }
}

/// The longest URL or detail an unauthenticated row keeps, in bytes.
const MAX_UNAUTHENTICATED_TEXT: usize = 512;

/// `text` cut to [`MAX_UNAUTHENTICATED_TEXT`] bytes on a character
/// boundary, marked when cut: anything on the machine chooses these.
fn shorten(mut text: String) -> String {
    if text.len() > MAX_UNAUTHENTICATED_TEXT {
        let mut end = MAX_UNAUTHENTICATED_TEXT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    text
}

/// Keep `diag` (and its refusal text, for a refusal or failure) unless
/// the list is full, then count it.
fn push_row(diagnostics: &mut Diagnostics, diag: DiagRequest) {
    if matches!(diag.disposition.as_str(), "refused" | "failed") {
        let detail = diag.detail.clone().unwrap_or_default();
        push_refusal(
            diagnostics,
            format!("{} {}: {detail}", diag.method, diag.url),
        );
    }
    if diagnostics.requests.len() < MAX_DIAGNOSTIC_ROWS {
        diagnostics.requests.push(diag);
    } else {
        diagnostics.requests_dropped += 1;
    }
}

fn push_refusal(diagnostics: &mut Diagnostics, text: String) {
    if diagnostics.refusals.len() < MAX_DIAGNOSTIC_ROWS {
        diagnostics.refusals.push(text);
    } else {
        diagnostics.refusals_dropped += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(disposition: &str) -> DiagRequest {
        DiagRequest {
            seq: 0,
            class: "refused".into(),
            method: "GET".into(),
            url: "/x".into(),
            status: 403,
            served_status: 403,
            disposition: disposition.into(),
            bytes: 0,
            hops: Vec::new(),
            detail: Some("why".into()),
        }
    }

    #[test]
    fn diagnostics_lists_stop_growing_at_their_cap_and_count_the_rest() {
        let mut diagnostics = Diagnostics::default();
        for _ in 0..MAX_DIAGNOSTIC_ROWS + 5 {
            push_row(&mut diagnostics, row("refused"));
        }
        push_row(&mut diagnostics, row("hit"));
        assert_eq!(diagnostics.requests.len(), MAX_DIAGNOSTIC_ROWS);
        assert_eq!(diagnostics.requests_dropped, 6);
        assert_eq!(diagnostics.refusals.len(), MAX_DIAGNOSTIC_ROWS);
        assert_eq!(diagnostics.refusals_dropped, 5);
    }

    #[test]
    fn unauthenticated_text_is_cut_on_a_character_boundary() {
        assert_eq!(shorten("short".into()), "short");
        let long = format!(
            "{}é{}",
            "a".repeat(MAX_UNAUTHENTICATED_TEXT - 1),
            "b".repeat(10)
        );
        let cut = shorten(long);
        assert_eq!(
            cut,
            format!("{}...", "a".repeat(MAX_UNAUTHENTICATED_TEXT - 1))
        );
    }

    #[test]
    fn tokens_are_long_random_and_compared_whole() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(constant_time_eq(a.as_bytes(), a.as_bytes()));
        assert!(!constant_time_eq(a.as_bytes(), b.as_bytes()));
        assert!(!constant_time_eq(a.as_bytes(), &a.as_bytes()[..63]));
        assert!(!constant_time_eq(b"", a.as_bytes()));
    }
}

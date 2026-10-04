//! `tog audit` — the admission gate over closure records: the CI gate when
//! the machine policy trusts signing keys, and the solo user's "does my
//! environment pass my policy?" when it does not.
//!
//! Every sync records the exceptions it waved through in the project's
//! `.tog/closures/<ecosystem>.json` (`body.exceptions[]`, kinds in
//! `policy::KINDS`) and, with `TOG_SIGNING_KEY` set, signs the envelope.
//! This module answers "would those closures pass policy P?" from the
//! records alone: no rebuild, no store access, no network, no sandbox. It is
//! read-only over the project directory (plus the same read-only
//! object-liveness probes `tog status` makes).
//!
//! What a pass proves: every detected ecosystem has its primary closure;
//! each record is current for the inputs on disk and the committed
//! toolchain lock; no recorded exception is denied or unknown; and, when
//! the machine policy has a `[signing]` table, every closure file's
//! canonical bytes carry a valid signature from a key it trusts. It does
//! not prove the signer's sync was honest or safe to run.
//!
//! The rules that keep the answer honest, in evaluation order:
//!
//! - With a `[signing]` table at machine scope, a record is authenticated
//!   before anything in it is believed. The signature is verified over the
//!   complete envelope as parsed from the one file read
//!   (`ClosureFile::envelope`), then the key is checked against the
//!   effective trusted set. A bad signature, an untrusted key, or no
//!   signature short-circuits: freshness is not computed and no exception is
//!   judged, because nothing in the record can be believed. The three stay
//!   distinct because their fixes differ.
//! - Without a `[signing]` table, signatures are not checked: an unsigned
//!   record and a signed one are judged alike, the report says so on every
//!   line that could be mistaken for a trust claim (`signatures: not
//!   checked`, `signature.state: "not-checked"`), and an explicit
//!   `trusted = []` is still the other thing, a decision to trust nobody.
//!   A signature that is present and does not verify is still
//!   `bad-signature`: tampering is evidence, whoever the signer was.
//! - A verdict is only computed over a record that still describes the
//!   project. Freshness reuses `inspect::locked_closure_state`, the check
//!   behind `tog status`, applied to every closure file from its own body
//!   and to the committed `tog-toolchain.toml` beside it: a closure whose
//!   inputs changed, whose projection is missing, that was synced on
//!   another platform, or whose inputs are no longer found here is reported
//!   `stale`, and so is one whose toolchain lock is missing, has no section
//!   for the ecosystem, has stale rows, or names a different bundle than
//!   the one the closure was built from, or whose joined resolution record
//!   no longer describes the lock files on disk; one that predates input, platform,
//!   toolchain, or exception recording is reported `outdated`. Neither
//!   passes.
//! - Every ecosystem detected in the directory must have its primary
//!   closure: deleting a denied record is not a way past the gate.
//! - The policy under test is the ordinary chain (`policy::load_with_sources`)
//!   merged with the optional `--policy` file: denials only add, and the
//!   trusted-key set only narrows, so the supplied policy can never loosen
//!   what the machine or project policy says.
//! - An exception kind this binary does not know (a record written by a
//!   newer tog, or by hand) is `unknown`, never permitted: no policy
//!   file can name it, so no policy file can be said to have allowed it.
//!   A kind tog retired (`policy::retired_kind`) is known, and old: the
//!   record predates the change that retired it, so the closure is
//!   `outdated` with that reason and the fix, a fresh sync.
//! - A closure that joined a resolution record carries it as
//!   `body.resolution`. The join already recorded the record's exceptions
//!   into `body.exceptions`; the gate judges the record's own list as well,
//!   so a hand-made body that dropped one from `exceptions` is still judged
//!   on it, and a kind this binary does not know is `unknown` either way.

use crate::cli;
use crate::commands::inspect::{self, ClosureFile, State};
use crate::commands::shared::project_dir;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{self, Exception, Policy, PolicySource, SourceOrigin};
use crate::kernel::signing::{self, KeySet, PublicKey, Verification};
use crate::kernel::toolchain::lock::LOCK_PATH;
use crate::kernel::ui;
use crate::tailors;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// Whether the record a verdict was computed over still describes the
/// project. Only `Current` records can pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// Recorded inputs match the files on disk and the projection is in place.
    Current,
    /// Inputs changed, projection missing, synced on another platform, or
    /// the toolchain lock does not describe the record.
    Stale(String),
    /// The record predates a field the gate needs (inputs, platform,
    /// toolchain, or the exception record); the detail names the refresh
    /// command.
    Outdated(String),
    /// Not computed: the record is unsigned, untrusted, or tampered, so its
    /// contents cannot be believed.
    NotEvaluated,
}

/// What the record's signature proves, judged before anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Verifies under a key in the effective trusted set.
    Trusted(PublicKey),
    /// No `signature` field: a record from before signing, or from a sync
    /// with no key configured.
    Unsigned,
    /// Verifies under `key`, which the effective trusted set does not
    /// contain. `excluded_by` names every policy scope whose declared list
    /// omits it, so the operator can see which file to review.
    Untrusted {
        key: PublicKey,
        excluded_by: Vec<String>,
    },
    /// A `signature` field is present and does not verify: tampered record,
    /// malformed field, or unknown algorithm. Never a warning.
    Bad {
        key: Option<PublicKey>,
        reason: String,
    },
    /// The machine policy has no `[signing]` table, so trust was not
    /// judged: the record is evaluated on its contents alone. `key` is the
    /// key a present signature verified under, kept so the report can still
    /// say who signed, without claiming that anyone trusts them.
    NotChecked { key: Option<PublicKey> },
}

impl Signature {
    /// The JSON `signature.state` word.
    pub fn state(&self) -> &'static str {
        match self {
            Signature::Trusted(_) => "trusted",
            Signature::Unsigned => "unsigned",
            Signature::Untrusted { .. } => "untrusted",
            Signature::Bad { .. } => "bad",
            Signature::NotChecked { .. } => "not-checked",
        }
    }

    /// The public key the record names, when one could be decoded.
    pub fn key(&self) -> Option<PublicKey> {
        match self {
            Signature::Trusted(key) | Signature::Untrusted { key, .. } => Some(*key),
            Signature::Bad { key, .. } | Signature::NotChecked { key } => *key,
            Signature::Unsigned => None,
        }
    }

    /// Whether the record's contents were evaluated: trusted, or trust was
    /// not the question.
    pub fn evaluated(&self) -> bool {
        matches!(self, Signature::Trusted(_) | Signature::NotChecked { .. })
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub ecosystem: String,
    /// sha256 of the closure envelope bytes: the exact record audited.
    pub record_sha256: String,
    pub path: std::path::PathBuf,
    pub signature: Signature,
    pub freshness: Freshness,
    /// Recorded exceptions the policy refuses, in recorded order. `None`
    /// when the record was not evaluated.
    pub denied: Option<Vec<Exception>>,
    /// Recorded exceptions of a kind this binary does not know, in recorded
    /// order. Never permitted: the gate cannot judge them.
    pub unknown: Option<Vec<Exception>>,
    /// Recorded exceptions the policy permits, counted by kind.
    pub permitted: Option<BTreeMap<String, usize>>,
}

impl Verdict {
    /// Passes only when the signature is trusted (or signatures were not
    /// checked), the record is current, and no recorded exception is denied
    /// or unknown.
    pub fn passes(&self) -> bool {
        self.signature.evaluated()
            && self.freshness == Freshness::Current
            && self.denied.as_ref().is_some_and(Vec::is_empty)
            && self.unknown.as_ref().is_some_and(Vec::is_empty)
    }

    /// The verdict word on the text line: the first failure in evaluation
    /// order, or `clean`.
    pub fn word(&self) -> &'static str {
        match (&self.signature, &self.freshness) {
            (Signature::Bad { .. }, _) => "bad-signature",
            (Signature::Untrusted { .. }, _) => "untrusted",
            (Signature::Unsigned, _) => "outdated",
            // An evaluated record always has a freshness; the pair with
            // `NotEvaluated` is unreachable and folds into the nearest
            // failing word rather than inventing one the report does not
            // define.
            (
                Signature::Trusted(_) | Signature::NotChecked { .. },
                Freshness::Outdated(_) | Freshness::NotEvaluated,
            ) => "outdated",
            (Signature::Trusted(_) | Signature::NotChecked { .. }, Freshness::Stale(_)) => "stale",
            (Signature::Trusted(_) | Signature::NotChecked { .. }, Freshness::Current) => {
                if self
                    .denied
                    .as_ref()
                    .is_some_and(|denied| !denied.is_empty())
                {
                    "denied"
                } else if self
                    .unknown
                    .as_ref()
                    .is_some_and(|unknown| !unknown.is_empty())
                {
                    "unknown"
                } else {
                    "clean"
                }
            }
        }
    }

    fn not_evaluated(closure: &ClosureFile, signature: Signature) -> Self {
        Self {
            ecosystem: closure.ecosystem.clone(),
            record_sha256: closure.record_sha256.clone(),
            path: closure.path.clone(),
            signature,
            freshness: Freshness::NotEvaluated,
            denied: None,
            unknown: None,
            permitted: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub policy: Policy,
    /// The policies that were merged into `policy`, in merge order, so the
    /// report can say which file denied a kind or excluded a key rather
    /// than only that something did.
    pub sources: Vec<PolicySource>,
    pub verdicts: Vec<Verdict>,
    /// Ecosystems detected in the directory whose primary closure is
    /// absent, in detection order. Each fails the report.
    pub missing: Vec<String>,
    /// Whether the machine policy had a `[signing]` table, so every verdict
    /// above was computed after authenticating its record. `false` is not
    /// a failure: it is the report saying what it did not do.
    pub signatures_checked: bool,
}

impl Report {
    pub fn passes(&self) -> bool {
        self.missing.is_empty() && self.verdicts.iter().all(Verdict::passes)
    }
}

/// Read and validate a `--policy` file on its own, before it is merged in,
/// so the dispatcher can report a missing or malformed file as a usage
/// error rather than a failed audit.
pub fn read_policy_file(path: &Path) -> io::Result<Policy> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        io::Error::new(error.kind(), format!("read {}: {error}", path.display()))
    })?;
    policy::parse_file(path, &text)
}

/// The policy an audit judges against: the ordinary chain for `dir`
/// (TOG_POLICY or ~/.tog/policy.toml, every ancestor's
/// .tog/policy.toml, TOG_STRICT) merged with `extra`, the parsed
/// `--policy` file and the path it came from. The file can add denials or
/// strictness and drop trusted keys, never the reverse. Returns the
/// contributing policies alongside the merged one, in merge order.
pub fn effective_policy(
    dir: &Path,
    extra: Option<(&Path, &Policy)>,
) -> io::Result<(Policy, Vec<PolicySource>)> {
    let (mut policy, mut sources) = policy::load_with_sources(dir, false)?;
    if let Some((path, extra)) = extra {
        policy::merge(&mut policy, extra, SourceOrigin::Flag);
        sources.push(PolicySource::from_file(SourceOrigin::Flag, path, extra));
    }
    Ok((policy, sources))
}

/// The effective trusted set, or `None` when no machine-scope policy
/// declared one. Absent is not empty: an explicit `trusted = []` is a
/// decision (every signed record is `untrusted`); no table at all means
/// signatures are not checked, and the report says so.
pub fn trusted_keys(policy: &Policy) -> Option<&KeySet> {
    policy.signing.as_ref().map(|signing| &signing.trusted)
}

/// The words a fix line adds when signatures are checked: the record that
/// replaces this one has to be signed by a trusted key, or it will be
/// `outdated` again. Nothing when they are not.
fn under_key(checked: bool) -> &'static str {
    if checked {
        " under a trusted key"
    } else {
        ""
    }
}

/// The name of a policy scope as the untrusted-key message cites it.
fn scope_name(source: &PolicySource) -> String {
    match &source.path {
        Some(path) => format!("{} {:?}", source.origin, path.to_string_lossy()),
        None => source.origin.to_string(),
    }
}

/// Verify the record's own signature over the complete envelope, then check
/// the key against the effective set. Trust is the policy's question; the
/// kernel only says whether the bytes verify. With no trusted set the
/// question is not asked: unsigned and signed records are both
/// `NotChecked`, and only a signature that fails to verify still counts.
fn judge_signature(
    closure: &ClosureFile,
    trusted: Option<&KeySet>,
    sources: &[PolicySource],
) -> Signature {
    match (signing::verify(&closure.envelope), trusted) {
        (Verification::Bad { key, reason }, _) => Signature::Bad { key, reason },
        (Verification::Unsigned, None) => Signature::NotChecked { key: None },
        (Verification::Valid(key), None) => Signature::NotChecked { key: Some(key) },
        (Verification::Unsigned, Some(_)) => Signature::Unsigned,
        (Verification::Valid(key), Some(trusted)) if trusted.contains(&key) => {
            Signature::Trusted(key)
        }
        (Verification::Valid(key), Some(_)) => Signature::Untrusted {
            key,
            excluded_by: sources
                .iter()
                .filter(|source| {
                    source
                        .trusted
                        .as_ref()
                        .is_some_and(|declared| !declared.contains(&key))
                })
                .map(scope_name)
                .collect(),
        },
    }
}

/// The envelope shape the gate interprets, checked after authentication and
/// before any field is read: `schema` is `closure/1`, `ecosystem` is a
/// string, `body` is an object, and `platform` / `projected_at`, when
/// present, are a string and an integer. Anything else is refused as an
/// error (exit 1), never judged.
fn check_shape(closure: &ClosureFile) -> io::Result<()> {
    let refuse = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{:?}: {what}; the record is refused, not judged: run 'tog'",
                closure.path.to_string_lossy()
            ),
        )
    };
    let Some(envelope) = closure.envelope.as_object() else {
        return Err(refuse("closure envelope is not a JSON object"));
    };
    match envelope.get("schema").and_then(Value::as_str) {
        Some("closure/1") => {}
        Some(other) => return Err(refuse(&format!("unsupported closure schema '{other}'"))),
        None => return Err(refuse("closure envelope has no schema")),
    }
    if !envelope.get("ecosystem").is_some_and(Value::is_string) {
        return Err(refuse("closure envelope has no ecosystem string"));
    }
    if !envelope.get("body").is_some_and(Value::is_object) {
        return Err(refuse("closure body is not a JSON object"));
    }
    if envelope
        .get("platform")
        .is_some_and(|platform| !platform.is_string())
    {
        return Err(refuse("closure platform is not a string"));
    }
    if envelope
        .get("projected_at")
        .is_some_and(|stamp| !stamp.is_u64())
    {
        return Err(refuse("closure projected_at is not an integer"));
    }
    Ok(())
}

/// Freshness of one closure file, from its own record. `present` is what
/// `inspect::detected` found in the directory: a closure for an ecosystem
/// whose inputs are gone describes a project that no longer exists here.
/// `key` is `under_key` for the mode, spliced into the fix line.
fn freshness(
    platform: Platform,
    project: Option<&ProjectRoot>,
    closure: &ClosureFile,
    present: &[&str],
    key: &str,
) -> io::Result<Freshness> {
    // A closure is judged against the inputs of the ecosystem that owns it.
    let owner = closure.ecosystem.as_str();
    if !present.contains(&owner) {
        return Ok(Freshness::Stale(format!(
            "no {owner} inputs found here; the closure is orphaned"
        )));
    }
    if closure.platform.is_none() {
        // Envelopes without a platform predate the Linux port; `status`
        // cannot tell whether such a record was made on this host.
        return Ok(Freshness::Outdated(format!(
            "closure records no platform; run 'tog' once{key}, then commit"
        )));
    }
    let Some(project) = project else {
        return Ok(Freshness::Stale(
            "the project directory is gone; the closure is orphaned".into(),
        ));
    };
    Ok(freshness_from_state(inspect::locked_closure_state(
        platform, project, closure,
    )?))
}

/// The `status` state of a record, as the gate reads it: only `Synced` is
/// current; every other state fails.
fn freshness_from_state(state: State) -> Freshness {
    match state {
        State::Synced => Freshness::Current,
        State::NotSynced => Freshness::Stale("no closure for these inputs".into()),
        // A toolchain-lock finding names its own next step, as in `status`.
        State::Changed(files) if inspect::only_lock_findings(&files) => {
            Freshness::Stale(files.join(", "))
        }
        State::Changed(files) => {
            Freshness::Stale(format!("{} changed since the last sync", files.join(", ")))
        }
        State::ProjectionMissing(what) => {
            Freshness::Stale(format!("{what} is not the synced projection"))
        }
        State::ForeignPlatform(platform) => {
            Freshness::Stale(format!("synced on {platform}, not this host"))
        }
        State::Unchecked(why) => Freshness::Outdated(why),
    }
}

/// A closure file must be named for the ecosystem it claims, as
/// `project::read_closure` requires; a mismatch is a record `sync` would
/// refuse, and the gate refuses it too rather than judging it under either
/// name.
fn check_name(closure: &ClosureFile) -> io::Result<()> {
    let stem = closure
        .path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if stem != closure.ecosystem {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{:?}: closure claims ecosystem {:?} but is named {stem:?}; a stray or renamed file under .tog/closures is refused, not judged: remove it or run 'tog'",
                closure.path.to_string_lossy(),
                closure.ecosystem
            ),
        ));
    }
    Ok(())
}

/// Whether `closure` belongs to an ecosystem whose lock the resolution
/// join covers, one of whose lock files exists in `dir`, and yet carries
/// neither a joined record nor an `unrecorded-resolution` exception. A
/// closure written since the join always has one of the two, so this one
/// was written before it: "no evidence" must not pass as "attested".
fn lacks_resolution_evidence(dir: &Path, closure: &ClosureFile) -> io::Result<bool> {
    if closure.body.get("resolution").is_some() {
        return Ok(false);
    }
    let Some(tailor) = tailors::by_id(&closure.ecosystem) else {
        return Ok(false);
    };
    let project = crate::kernel::fsroot::ProjectRoot::open(dir)?;
    let Some(files) = tailors::resolution_files(tailor, &project)? else {
        return Ok(false);
    };
    if !files.outputs.iter().any(|output| dir.join(output).exists()) {
        return Ok(false);
    }
    let recorded = inspect::recorded_exceptions(closure)?.unwrap_or_default();
    Ok(!recorded
        .iter()
        .any(|exception| policy::canonical_kind(&exception.kind) == "unrecorded-resolution"))
}

/// Judge every closure file against `policy`, each from its own record:
/// signature first, then shape, then freshness and exceptions. `sources`
/// are the policies behind `policy`, cited when a key is excluded.
/// `present` is what `inspect::detected` found in `dir`. With no trusted
/// set in `policy`, signatures are not checked and every fix line drops
/// "under a trusted key".
pub fn evaluate(
    platform: Platform,
    dir: &Path,
    policy: &Policy,
    sources: &[PolicySource],
    closures: &[ClosureFile],
    present: &[&str],
) -> io::Result<Vec<Verdict>> {
    let trusted = trusted_keys(policy);
    let key = under_key(trusted.is_some());
    // Held once: every freshness read is of this one directory.
    let project = inspect::open_project(dir)?;
    let mut verdicts = Vec::new();
    for closure in closures {
        let signature = judge_signature(closure, trusted, sources);
        check_shape(closure)?;
        check_name(closure)?;
        if !signature.evaluated() {
            verdicts.push(Verdict::not_evaluated(closure, signature));
            continue;
        }
        let mut freshness = freshness(platform, project.as_ref(), closure, present, key)?;
        let mut denied = Vec::new();
        let mut unknown = Vec::new();
        let mut permitted = BTreeMap::new();
        let mut retired = None;
        let listed = inspect::exceptions(closure)?;
        match listed.recorded {
            true => {
                for exception in listed.exceptions {
                    if let Some(why) = policy::retired_kind(&exception.kind) {
                        retired.get_or_insert((why, exception.kind));
                    } else if !policy::KINDS.contains(&exception.kind.as_str()) {
                        unknown.push(exception);
                    } else if policy::denied(policy, &exception.kind) {
                        denied.push(exception);
                    } else {
                        *permitted.entry(exception.kind).or_insert(0) += 1;
                    }
                }
            }
            false => {
                if !matches!(freshness, Freshness::Stale(_)) {
                    freshness = Freshness::Outdated(format!(
                        "no exception record in this closure; run 'tog' once{key}, then commit"
                    ));
                }
            }
        }
        if !matches!(freshness, Freshness::Stale(_)) && lacks_resolution_evidence(dir, closure)? {
            freshness = Freshness::Outdated(format!(
                "no resolution record and no unrecorded-resolution exception (the closure predates \
                 the resolution join); run 'tog' once{key}, then commit"
            ));
        }
        // A retired kind is not judged against the policy: the record is
        // older than what retired it, and a fresh sync replaces it.
        if let Some((why, kind)) = retired {
            if !matches!(freshness, Freshness::Stale(_)) {
                freshness = Freshness::Outdated(format!(
                    "{why} (it records the retired {kind} exception); run 'tog' once{key}, then commit"
                ));
            }
        }
        verdicts.push(Verdict {
            ecosystem: closure.ecosystem.clone(),
            record_sha256: closure.record_sha256.clone(),
            path: closure.path.clone(),
            signature,
            freshness,
            denied: Some(denied),
            unknown: Some(unknown),
            permitted: Some(permitted),
        });
    }
    Ok(verdicts)
}

/// The detected ecosystems with no closure file: each is a record the gate
/// needs and cannot judge.
pub fn missing_closures(closures: &[ClosureFile], present: &[&str]) -> Vec<String> {
    present
        .iter()
        .filter(|ecosystem| {
            !closures
                .iter()
                .any(|closure| closure.ecosystem == **ecosystem)
        })
        .map(|ecosystem| ecosystem.to_string())
        .collect()
}

/// Audit the project in `dir` under an already-merged policy and its
/// sources. `Err(NotFound)` when nothing is synced. Read-only: no store
/// open, no lease, no process, no network.
pub fn audit_under(
    platform: Platform,
    dir: &Path,
    policy: Policy,
    sources: Vec<PolicySource>,
) -> io::Result<Report> {
    let signatures_checked = trusted_keys(&policy).is_some();
    let closures = inspect::closures(dir)?;
    if closures.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("nothing synced in {}; run 'tog' first", dir.display()),
        ));
    }
    let present = inspect::detected(dir)?;
    let verdicts = evaluate(platform, dir, &policy, &sources, &closures, &present)?;
    let missing = missing_closures(&closures, &present);
    Ok(Report {
        policy,
        sources,
        verdicts,
        missing,
        signatures_checked,
    })
}

/// Audit the project in `dir` under the policy chain merged with `extra`
/// (an already-parsed `--policy` file). The command itself splits the two
/// steps so an unreadable `--policy` file is a usage error; tests use this.
#[cfg(test)]
pub fn audit(
    platform: Platform,
    dir: &Path,
    extra: Option<(&Path, &Policy)>,
) -> io::Result<Report> {
    let (policy, sources) = effective_policy(dir, extra)?;
    audit_under(platform, dir, policy, sources)
}

/// A report line as the text report prints it: control characters (a
/// closure file name can carry them, `ecosystem` must equal that name, and
/// exception subjects come from the record) are escaped so a record cannot
/// rewrite the terminal lines above it. Ordinary text prints unchanged.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn key_list(keys: &KeySet) -> String {
    keys.iter()
        .map(PublicKey::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// One contributing policy as the text report shows it: origin, the file
/// (absent for strictness-only sources), and what it asked for.
fn source_line(source: &PolicySource) -> String {
    let mut line = format!("policy: {}", source.origin);
    if let Some(path) = &source.path {
        let lossy = path.to_string_lossy();
        line.push_str(&format!(" {:?}", lossy));
    }
    if !source.deny.is_empty() {
        line.push_str(&format!(
            " denies {}",
            source.deny.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if source.strict {
        line.push_str(" (strict)");
    }
    match &source.trusted {
        Some(keys) if keys.is_empty() => line.push_str(" trusts nobody"),
        Some(keys) => line.push_str(&format!(" trusts {}", key_list(keys))),
        None => {}
    }
    line
}

/// JSON cannot serialize a non-UTF-8 `PathBuf`. Keep the public policy model
/// platform-native, but make every report path an explicit lossy string. On
/// Unix, the byte field makes a lossy path reversible when its raw bytes are
/// not valid UTF-8.
struct JsonPath {
    lossy: String,
    bytes: Option<String>,
}

fn json_path(path: &Path) -> JsonPath {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;

        path.to_str()
            .is_none()
            .then(|| hex::encode(path.as_os_str().as_bytes()))
    };
    #[cfg(not(unix))]
    let bytes = None;

    JsonPath {
        lossy: path.to_string_lossy().into_owned(),
        bytes,
    }
}

#[derive(serde::Serialize)]
struct JsonPolicySource {
    origin: SourceOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_bytes: Option<String>,
    strict: bool,
    deny: std::collections::BTreeSet<String>,
    /// `null` when the scope declared no `[signing]` table, `[]` when it
    /// explicitly trusts nobody.
    trusted: Option<KeySet>,
}

fn json_sources(sources: &[PolicySource]) -> Vec<JsonPolicySource> {
    sources
        .iter()
        .map(|source| {
            let path = source.path.as_deref().map(json_path);
            JsonPolicySource {
                origin: source.origin,
                path: path.as_ref().map(|path| path.lossy.clone()),
                path_bytes: path.and_then(|path| path.bytes),
                strict: source.strict,
                deny: source.deny.clone(),
                trusted: source.trusted.clone(),
            }
        })
        .collect()
}

fn json_signature(signature: &Signature) -> Value {
    let mut value = json!({ "state": signature.state() });
    if let Some(key) = signature.key() {
        value["key"] = json!(key.to_string());
    }
    let detail = match signature {
        Signature::Bad { reason, .. } => json!(reason),
        Signature::Untrusted { excluded_by, .. } => json!(excluded_by),
        Signature::Trusted(_) | Signature::Unsigned | Signature::NotChecked { .. } => Value::Null,
    };
    value["detail"] = detail;
    value
}

pub fn render(dir: &Path, report: &Report, json: bool) -> io::Result<String> {
    if json {
        let JsonPath {
            lossy: project,
            bytes: project_bytes,
        } = json_path(dir);
        let closures = report
            .verdicts
            .iter()
            .map(|verdict| {
                let JsonPath {
                    lossy: path,
                    bytes: path_bytes,
                } = json_path(&verdict.path);
                let (freshness, detail): (&str, Value) = match &verdict.freshness {
                    Freshness::Current => ("current", Value::Null),
                    Freshness::Stale(why) => ("stale", json!(why)),
                    Freshness::Outdated(why) => ("outdated", json!(why)),
                    Freshness::NotEvaluated => ("not-evaluated", Value::Null),
                };
                let mut closure = json!({
                    "ecosystem": verdict.ecosystem,
                    "record_sha256": verdict.record_sha256,
                    "path": path,
                    "passed": verdict.passes(),
                    "verdict": verdict.word(),
                    "signature": json_signature(&verdict.signature),
                    "freshness": freshness,
                    "freshness_detail": detail,
                    "denied": verdict.denied,
                    "unknown": verdict.unknown,
                    "permitted": verdict.permitted,
                });
                if let Some(path_bytes) = path_bytes {
                    closure["path_bytes"] = json!(path_bytes);
                }
                closure
            })
            .collect::<Vec<_>>();
        let trusted = report
            .policy
            .signing
            .as_ref()
            .map(|signing| signing.trusted.clone());
        let value = json!({
            "project": project,
            "policy": {
                "strict": report.policy.strict,
                "deny": report.policy.deny,
                "trusted": trusted,
                "sources": json_sources(&report.sources),
            },
            "signatures_checked": report.signatures_checked,
            "passed": report.passes(),
            "closures": closures,
            "missing": report.missing,
        });
        let mut value = value;
        if let Some(project_bytes) = project_bytes {
            value["project_bytes"] = json!(project_bytes);
        }
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let width = report
        .verdicts
        .iter()
        .map(|verdict| printable(&verdict.ecosystem).len())
        .chain(report.missing.iter().map(String::len))
        .max()
        .unwrap_or(0);
    let key = under_key(report.signatures_checked);
    let mut out = preamble(report);
    for verdict in &report.verdicts {
        let record = &verdict.record_sha256[..16];
        let word = verdict.word();
        let refresh = "tog";
        let line = match &verdict.signature {
            Signature::Bad { reason, .. } => format!(
                "{word:<13} closure {record}: {reason}; find out who changed it, then regenerate with '{refresh}'{key} and commit (not evaluated)"
            ),
            Signature::Untrusted { key, excluded_by } => {
                let excluded = if excluded_by.is_empty() {
                    String::new()
                } else {
                    format!(" (excluded by {})", excluded_by.join(", "))
                };
                format!(
                    "{word:<13} closure {record}: signed by {key}, which is not in the trusted set{excluded}; re-sync under an allowed key, or have the operator review those scopes (not evaluated)"
                )
            }
            Signature::Unsigned => format!(
                "{word:<13} closure {record}: no signature; run '{refresh}' once under a trusted key, then commit (not evaluated)"
            ),
            Signature::Trusted(_) | Signature::NotChecked { .. } => {
                // What the policy says about the record's exceptions,
                // independent of whether the record is current; shown on
                // every evaluated line so a stale record's denials are not
                // hidden behind its staleness.
                let denied = verdict.denied.as_deref().unwrap_or_default();
                let unknown = verdict.unknown.as_deref().unwrap_or_default();
                let permitted = match verdict.permitted.as_ref() {
                    Some(permitted) if !permitted.is_empty() => permitted
                        .iter()
                        .map(|(kind, count)| format!("{kind} {count}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    _ => "no exceptions".to_string(),
                };
                let judged = match (denied.len(), unknown.len()) {
                    (0, 0) => format!("permitted: {permitted}"),
                    (denied, 0) => format!("{denied} denied; permitted: {permitted}"),
                    (0, unknown) => format!("{unknown} of unknown kind; permitted: {permitted}"),
                    (denied, unknown) => format!(
                        "{denied} denied, {unknown} of unknown kind; permitted: {permitted}"
                    ),
                };
                match &verdict.freshness {
                    // A toolchain-lock finding already names the verb that
                    // moves the lock, which is not always the bare `tog`.
                    Freshness::Stale(why) if why.starts_with(LOCK_PATH) => format!(
                        "{word:<13} closure {record}: {why}, then audit again ({judged})"
                    ),
                    Freshness::Stale(why) => format!(
                        "{word:<13} closure {record}: {why}; run '{refresh}', then audit again ({judged})"
                    ),
                    Freshness::Outdated(why) => {
                        format!("{word:<13} closure {record}: {why} ({judged})")
                    }
                    Freshness::NotEvaluated => {
                        format!("{word:<13} closure {record}: not evaluated")
                    }
                    Freshness::Current => format!("{word:<13} closure {record}: {judged}"),
                }
            }
        };
        out.push_str(&printable(&format!(
            "{:width$}  {line}",
            printable(&verdict.ecosystem)
        )));
        out.push('\n');
        for exception in verdict.denied.as_deref().unwrap_or_default() {
            out.push_str(&printable(&format!(
                "{:width$}    denied   {}  {}  {}",
                "", exception.kind, exception.subject, exception.detail
            )));
            out.push('\n');
        }
        for exception in verdict.unknown.as_deref().unwrap_or_default() {
            out.push_str(&printable(&format!(
                "{:width$}    unknown  {}  {}  {}",
                "", exception.kind, exception.subject, exception.detail
            )));
            out.push('\n');
        }
    }
    for ecosystem in &report.missing {
        out.push_str(&format!(
            "{ecosystem:width$}  {:<13} no closure for the {ecosystem} inputs found here; run 'tog'{key}, then commit\n",
            "missing"
        ));
    }
    Ok(out)
}

/// What the text report says before any verdict: policy provenance (a
/// report result on stdout, kept ahead of the verdicts and never
/// suppressed by `--quiet`), and what this report did not do, printed where
/// the verdicts are read so a `clean` line is never mistaken for a trust
/// claim.
fn preamble(report: &Report) -> String {
    let mut out = String::new();
    for source in &report.sources {
        out.push_str(&source_line(source));
        out.push('\n');
    }
    if !report.signatures_checked {
        out.push_str(SIGNATURES_NOT_CHECKED);
        out.push('\n');
    }
    out
}

/// The text report's line for a run with no `[signing]` table: what was
/// not checked, and the one command that turns the check on.
pub const SIGNATURES_NOT_CHECKED: &str =
    "signatures: not checked (no [signing] table in the machine policy; \
'tog keygen <path>' prints one to paste into ~/.tog/policy.toml)";

/// The gate is misconfigured: an unreadable `--policy` file, or `--signed`
/// with no trusted set at machine scope. The command has already started
/// and, under
/// `--json`, already promised that stdout is the document and a failure is
/// a JSON object, so the promise holds here too; only the exit status says
/// "operator mistake" (2) rather than "denied" (1).
fn misconfigured(message: &str, json: bool) {
    if json {
        ui::error_json(message);
    } else {
        eprint!("{}", cli::render_usage_error(message, Some("audit")));
    }
}

/// The words `--signed` refuses with: the table to add, where, and the
/// command that prints it.
pub const NO_TRUSTED_KEYS: &str = "no trusted signing keys configured: add a [signing] table with \
trusted = [\"ed25519:<64 hex>\"] to the machine policy (TOG_POLICY, or ~/.tog/policy.toml); a project \
or --policy list can only narrow it. 'tog keygen <path>' prints the table to paste";

/// The command: judge the recorded closures against the policy chain plus
/// an optional `--policy` file. `signed` is the CI form: it refuses to run
/// (exit 2, before any record is read) unless the machine policy trusts
/// signing keys, so a gate whose policy file lost its `[signing]` table
/// fails loudly instead of passing with signatures unchecked. Needs the
/// host platform only to tell a foreign-platform closure from a current
/// one, as `status` does.
pub fn run(command: cli::Command) -> io::Result<i32> {
    let cli::Command::Audit {
        policy,
        signed,
        json,
    } = command
    else {
        unreachable!("dispatch hands audit only its own command");
    };
    let policy = policy.as_deref();
    let platform = Platform::host()?;
    let dir = project_dir();
    // A --policy file that cannot be read or parsed is an operator
    // mistake (exit 2), so CI can tell it from a denied build (exit 1).
    let extra = match policy {
        Some(path) => match read_policy_file(path) {
            Ok(extra) => Some((path, extra)),
            Err(error) => {
                misconfigured(&format!("audit: {error}"), json);
                return Ok(cli::EXIT_USAGE);
            }
        },
        None => None,
    };
    let (policy, sources) =
        effective_policy(&dir, extra.as_ref().map(|(path, extra)| (*path, extra)))?;
    if signed && trusted_keys(&policy).is_none() {
        misconfigured(
            &format!("audit: {NO_TRUSTED_KEYS} (--signed asked for the check)"),
            json,
        );
        return Ok(cli::EXIT_USAGE);
    }
    let report = audit_under(platform, &dir, policy, sources)?;
    let trusted = match trusted_keys(&report.policy) {
        Some(trusted) => format!("trusted=[{}]", key_list(trusted)),
        None => "signatures=not-checked".to_string(),
    };
    ui::note(&format!(
        "audit: policy strict={} deny=[{}] {trusted}",
        report.policy.strict,
        report
            .policy
            .deny
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
    ));
    print!("{}", render(&dir, &report, json)?);
    Ok(if report.passes() {
        0
    } else {
        cli::EXIT_FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::Signing;
    use crate::kernel::policy::{
        GIT_DEPENDENCY, INSTALL_SCRIPT_FAILED, SKIPPED_OPTIONAL, WEAK_INTEGRITY,
    };
    use crate::kernel::resolve::record;
    use crate::kernel::signing::SigningKey;
    use crate::kernel::testutil::TempDir;
    use std::collections::BTreeSet;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    /// A key generated once per test process; every fixture is signed
    /// with it and every test policy trusts it unless a test says otherwise.
    fn test_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| generated_key("test-key"))
    }

    /// A second key no test policy trusts by default.
    fn other_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| generated_key("other-key"))
    }

    fn generated_key(label: &str) -> SigningKey {
        let temp = TempDir::named(label);
        let path = temp.0.join("key");
        signing::generate(&path).unwrap();
        SigningKey::load(&path).unwrap()
    }

    fn trusting(keys: &[&SigningKey]) -> Option<Signing> {
        Some(Signing {
            trusted: keys.iter().map(|key| key.public_key()).collect(),
        })
    }

    /// A policy that denies nothing and trusts the test key.
    fn permissive() -> Policy {
        deny(&[])
    }

    /// The audit's own guard for tests that read the policy chain: point
    /// the machine scope at a file that trusts the test key, so the chain
    /// on the developer's machine cannot leak in.
    struct MachinePolicy {
        previous: Option<std::ffi::OsString>,
        _dir: TempDir,
    }

    impl MachinePolicy {
        fn trusting(label: &str, keys: &[&SigningKey]) -> Self {
            let dir = TempDir::named(label);
            let path = dir.0.join("machine.toml");
            let entries: Vec<String> = keys
                .iter()
                .map(|key| format!("\"{}\"", key.public_key()))
                .collect();
            fs::write(
                &path,
                format!("[signing]\ntrusted = [{}]\n", entries.join(", ")),
            )
            .unwrap();
            let previous = std::env::var_os("TOG_POLICY");
            std::env::set_var("TOG_POLICY", &path);
            Self {
                previous,
                _dir: dir,
            }
        }
    }

    impl Drop for MachinePolicy {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("TOG_POLICY", value),
                None => std::env::remove_var("TOG_POLICY"),
            }
        }
    }

    fn exception(kind: &str, subject: &str) -> Exception {
        Exception {
            kind: kind.into(),
            subject: subject.into(),
            detail: format!("{kind} on {subject}"),
        }
    }

    /// A python project with a projection and recorded inputs, so a closure
    /// written from `python_body` is current until `requirements.txt`
    /// changes.
    fn python_project(label: &str) -> TempDir {
        let temp = TempDir::named(label);
        let dir = &temp.0;
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let env = dir.join("env-object");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        temp
    }

    /// The body `python_project`'s closure needs to be current.
    fn python_body(dir: &Path) -> Value {
        json!({
            "env_object": dir.join("env-object"),
            "python": {"version": "3.12.14"},
            "plan": {"packages": []},
            "inputs": [{
                "path": "requirements.txt",
                "sha256": inspect::sha256_file(&dir.join("requirements.txt")).unwrap(),
            }],
        })
    }

    /// Write `.tog/closures/<name>.json`, signed with the test key, and
    /// return it as `closures` would read it.
    fn write_closure(
        dir: &Path,
        name: &str,
        ecosystem: &str,
        platform: Option<&str>,
        body: Value,
    ) -> ClosureFile {
        write_closure_with(
            dir,
            name,
            ecosystem,
            platform,
            body,
            Some(test_key()),
            |_| {},
        )
    }

    /// `write_closure` with a chosen key (`None` writes unsigned) and an
    /// edit applied to the envelope after signing, for tampering tests.
    /// A primary closure is written the way a lock-aware sync writes it:
    /// with the matching `tog-toolchain.toml` beside it and the bundle id
    /// recorded in its body.
    fn write_closure_with(
        dir: &Path,
        name: &str,
        ecosystem: &str,
        platform: Option<&str>,
        mut body: Value,
        key: Option<&SigningKey>,
        after_signing: impl FnOnce(&mut Value),
    ) -> ClosureFile {
        if body.is_object() {
            body = inspect::with_toolchain_lock(dir, ecosystem, body);
        }
        let closures = dir.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        let mut envelope = json!({
            "schema": "closure/1",
            "ecosystem": ecosystem,
            "projected_at": 1,
            "body": body,
        });
        if let Some(platform) = platform {
            envelope["platform"] = json!(platform);
        }
        if let Some(key) = key {
            key.sign(&mut envelope).unwrap();
        }
        after_signing(&mut envelope);
        let path = closures.join(format!("{name}.json"));
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        read_closure(dir, &path)
    }

    fn read_closure(dir: &Path, path: &Path) -> ClosureFile {
        inspect::closures(dir)
            .unwrap()
            .into_iter()
            .find(|closure| closure.path == path)
            .unwrap()
    }

    fn with_exceptions(dir: &Path, exceptions: &[Exception]) -> ClosureFile {
        let mut body = python_body(dir);
        body["exceptions"] = serde_json::to_value(exceptions).unwrap();
        write_closure(dir, "python", "python", Some(host().triple()), body)
    }

    fn deny(kinds: &[&str]) -> Policy {
        Policy {
            strict: false,
            deny: kinds.iter().map(|kind| kind.to_string()).collect(),
            signing: trusting(&[test_key()]),
            ..Policy::default()
        }
    }

    fn judge(dir: &Path, policy: &Policy, closures: &[ClosureFile]) -> Vec<Verdict> {
        judge_with_sources(dir, policy, &[], closures)
    }

    fn judge_with_sources(
        dir: &Path,
        policy: &Policy,
        sources: &[PolicySource],
        closures: &[ClosureFile],
    ) -> Vec<Verdict> {
        let present = inspect::detected(dir).unwrap();
        evaluate(host(), dir, policy, sources, closures, &present).unwrap()
    }

    fn report(policy: Policy, verdicts: Vec<Verdict>) -> Report {
        Report {
            policy,
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        }
    }

    fn record(verdict: &Verdict) -> String {
        verdict.record_sha256[..16].to_string()
    }

    #[test]
    fn clean_when_every_recorded_exception_is_permitted() {
        let temp = python_project("clean");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception(SKIPPED_OPTIONAL, "dev"),
                exception(SKIPPED_OPTIONAL, "docs"),
            ],
        )];
        let verdicts = judge(&temp.0, &deny(&[GIT_DEPENDENCY]), &closures);
        assert_eq!(verdicts.len(), 1);
        assert!(verdicts[0].passes());
        assert!(verdicts[0].denied.as_deref().unwrap().is_empty());
        assert!(verdicts[0].unknown.as_deref().unwrap().is_empty());
        assert_eq!(
            verdicts[0]
                .permitted
                .as_ref()
                .unwrap()
                .get(SKIPPED_OPTIONAL),
            Some(&2)
        );
        assert_eq!(verdicts[0].freshness, Freshness::Current);
        assert_eq!(verdicts[0].record_sha256.len(), 64);
        let record = record(&verdicts[0]);
        let report = Report {
            policy: deny(&[GIT_DEPENDENCY]),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        assert!(report.passes());
        let text = render(&temp.0, &report, false).unwrap();
        assert_eq!(
            text,
            format!("python  clean         closure {record}: permitted: skipped-optional 2\n")
        );
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], true);
        assert_eq!(value["closures"][0]["passed"], true);
        assert_eq!(value["closures"][0]["freshness"], "current");
        assert_eq!(value["closures"][0]["permitted"][SKIPPED_OPTIONAL], 2);
        assert_eq!(
            value["closures"][0]["record_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(value["policy"]["deny"][0], GIT_DEPENDENCY);
        assert_eq!(value["policy"]["strict"], false);
    }

    /// A report is the conjunction of its verdicts, not the disjunction:
    /// one failing closure fails the whole audit however many clean ones
    /// sit beside it, and in either order. Every other test here judges a
    /// single closure, where "all pass" and "any passes" agree.
    #[test]
    fn one_failing_closure_fails_the_whole_report() {
        let temp = python_project("mixed");
        let dir = &temp.0;
        let clean = with_exceptions(dir, &[]);
        let failing = with_exceptions(dir, &[exception(GIT_DEPENDENCY, "left-pad")]);
        let policy = deny(&[GIT_DEPENDENCY]);
        for closures in [
            vec![clean.clone(), failing.clone()],
            vec![failing, clean.clone()],
        ] {
            let verdicts = judge(dir, &policy, &closures);
            assert_eq!(
                verdicts.iter().filter(|verdict| verdict.passes()).count(),
                1,
                "{verdicts:?}"
            );
            let report = Report {
                policy: policy.clone(),
                sources: Vec::new(),
                verdicts,
                missing: Vec::new(),
                signatures_checked: true,
            };
            assert!(!report.passes(), "one denied closure must fail the report");
            let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
            assert_eq!(value["passed"], false);
        }
        // Not vacuous: the same machinery passes when every verdict does.
        let report = Report {
            policy: policy.clone(),
            sources: Vec::new(),
            verdicts: judge(dir, &policy, &[clean.clone(), clean]),
            missing: Vec::new(),
            signatures_checked: true,
        };
        assert!(report.passes());
    }

    #[cfg(unix)]
    #[test]
    fn json_preserves_non_utf8_project_and_closure_path_bytes() {
        use std::os::unix::ffi::OsStrExt;

        // Rendering does not need filesystem access, so this also covers
        // hosts whose filesystem cannot create a name containing 0xff.
        let project = PathBuf::from(std::ffi::OsString::from_vec(b"project-\xff".to_vec()));
        let path = project.join(".tog/closures/python.json");
        let report = report(
            permissive(),
            vec![Verdict {
                ecosystem: "python".into(),
                record_sha256: "0".repeat(64),
                path: path.clone(),
                signature: Signature::Unsigned,
                freshness: Freshness::NotEvaluated,
                denied: None,
                unknown: None,
                permitted: None,
            }],
        );
        let value: Value = serde_json::from_str(&render(&project, &report, true).unwrap()).unwrap();
        assert_eq!(value["project"], "project-\u{fffd}");
        assert_eq!(
            value["project_bytes"],
            hex::encode(project.as_os_str().as_bytes())
        );
        assert_eq!(
            value["closures"][0]["path"],
            "project-\u{fffd}/.tog/closures/python.json"
        );
        assert_eq!(
            value["closures"][0]["path_bytes"],
            hex::encode(path.as_os_str().as_bytes())
        );
    }

    #[cfg(unix)]
    #[test]
    fn json_policy_source_lossily_serializes_non_utf8_paths() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'p', b'o', b'l', b'i', b'c', b'y', b'-', 0xff, b'.', b't', b'o', b'm', b'l',
        ]));
        let report = Report {
            policy: permissive(),
            sources: vec![PolicySource {
                origin: SourceOrigin::Machine,
                path: Some(path),
                strict: false,
                deny: BTreeSet::new(),
                trusted: None,
            }],
            verdicts: Vec::new(),
            missing: Vec::new(),
            signatures_checked: true,
        };

        let output = render(Path::new("project"), &report, true).unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            value["policy"]["sources"][0]["path"],
            "policy-\u{fffd}.toml"
        );
        assert_eq!(
            value["policy"]["sources"][0]["path_bytes"],
            "706f6c6963792dff2e746f6d6c"
        );

        let output = render(Path::new("project"), &report, false).unwrap();
        assert_eq!(output, "policy: machine \"policy-\u{fffd}.toml\"\n");
    }

    #[test]
    fn text_policy_source_quotes_control_characters_in_paths() {
        let report = Report {
            policy: permissive(),
            sources: vec![PolicySource {
                origin: SourceOrigin::Machine,
                path: Some(PathBuf::from("policy-\n.toml")),
                strict: false,
                deny: BTreeSet::new(),
                trusted: None,
            }],
            verdicts: Vec::new(),
            missing: Vec::new(),
            signatures_checked: true,
        };

        let output = render(Path::new("project"), &report, false).unwrap();
        assert_eq!(output, "policy: machine \"policy-\\n.toml\"\n");
    }

    #[test]
    fn text_policy_source_quotes_grammar_significant_paths() {
        let temp = TempDir::named("quoted-policy");
        let path = temp.0.join("policy denies git-dependency (strict).toml");
        fs::write(&path, "strict = true\ndeny = [\"git-dependency\"]\n").unwrap();
        let policy = read_policy_file(&path).unwrap();
        let report = Report {
            policy: policy.clone(),
            sources: vec![PolicySource::from_file(SourceOrigin::Flag, &path, &policy)],
            verdicts: Vec::new(),
            missing: Vec::new(),
            signatures_checked: true,
        };

        let output = render(Path::new("project"), &report, false).unwrap();
        assert_eq!(
            output,
            format!(
                "policy: flag {:?} denies git-dependency (strict)\n",
                path.to_string_lossy()
            )
        );
    }

    #[test]
    fn denied_exceptions_are_listed_with_subject_and_detail() {
        let temp = python_project("denied");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception(INSTALL_SCRIPT_FAILED, "sharp@0.33.0"),
                exception(SKIPPED_OPTIONAL, "fsevents"),
                exception(WEAK_INTEGRITY, "left-pad@1.0.0"),
            ],
        )];
        let policy = deny(&[INSTALL_SCRIPT_FAILED, WEAK_INTEGRITY]);
        let verdicts = judge(&temp.0, &policy, &closures);
        assert!(!verdicts[0].passes());
        assert_eq!(
            verdicts[0].denied.as_deref().unwrap(),
            vec![
                exception(INSTALL_SCRIPT_FAILED, "sharp@0.33.0"),
                exception(WEAK_INTEGRITY, "left-pad@1.0.0"),
            ]
        );
        assert_eq!(
            verdicts[0]
                .permitted
                .as_ref()
                .unwrap()
                .get(SKIPPED_OPTIONAL),
            Some(&1)
        );
        let record = record(&verdicts[0]);
        let report = Report {
            policy,
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        assert!(!report.passes());
        let text = render(&temp.0, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  denied        closure {record}: 2 denied; permitted: skipped-optional 1\n"
            )),
            "{text}"
        );
        assert!(
            text.contains("    denied   install-script-failed  sharp@0.33.0  install-script-failed on sharp@0.33.0\n"),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(value["closures"][0]["denied"][1]["kind"], WEAK_INTEGRITY);
        assert_eq!(
            value["closures"][0]["denied"][1]["subject"],
            "left-pad@1.0.0"
        );
    }

    #[test]
    fn strict_policy_denies_every_kind() {
        let temp = python_project("strict");
        let closures = [with_exceptions(
            &temp.0,
            &[exception(SKIPPED_OPTIONAL, "dev")],
        )];
        let strict = Policy {
            strict: true,
            deny: BTreeSet::new(),
            signing: trusting(&[test_key()]),
            ..Policy::default()
        };
        let verdicts = judge(&temp.0, &strict, &closures);
        assert_eq!(verdicts[0].denied.as_deref().unwrap().len(), 1);
        assert!(!verdicts[0].passes());
    }

    #[test]
    fn unknown_kind_is_never_permitted_and_no_policy_can_name_it() {
        let temp = python_project("unknown");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception("kind-from-a-newer-tog", "left-pad"),
                exception(SKIPPED_OPTIONAL, "dev"),
            ],
        )];
        // Neither an empty policy nor one that denies everything it knows
        // permits it; only strict catches it, by denying everything.
        for policy in [permissive(), deny(policy::KINDS)] {
            let verdicts = judge(&temp.0, &policy, &closures);
            assert!(!verdicts[0].passes(), "{policy:?}");
            assert_eq!(
                verdicts[0].unknown.as_deref().unwrap(),
                vec![exception("kind-from-a-newer-tog", "left-pad")]
            );
            assert!(!verdicts[0]
                .permitted
                .as_ref()
                .unwrap()
                .contains_key("kind-from-a-newer-tog"));
        }
        let verdicts = judge(&temp.0, &permissive(), &closures);
        assert!(verdicts[0].denied.as_deref().unwrap().is_empty());
        let record = record(&verdicts[0]);
        let report = Report {
            policy: permissive(),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        let text = render(&temp.0, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  unknown       closure {record}: 1 of unknown kind; permitted: skipped-optional 1\n"
            )),
            "{text}"
        );
        assert!(
            text.contains("    unknown  kind-from-a-newer-tog  left-pad  "),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(
            value["closures"][0]["unknown"][0]["kind"],
            "kind-from-a-newer-tog"
        );
        // And a policy file cannot name it, so it cannot be "allowed" either.
        assert!(
            policy::parse_file(Path::new("p.toml"), "deny = [\"kind-from-a-newer-tog\"]").is_err()
        );
    }

    #[test]
    fn a_retired_kind_is_an_outdated_closure_not_an_unknown_one() {
        let temp = python_project("retired");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception("toolchain-component-unavailable", "clippy"),
                exception(SKIPPED_OPTIONAL, "dev"),
            ],
        )];
        for policy in [permissive(), deny(policy::KINDS)] {
            let verdicts = judge(&temp.0, &policy, &closures);
            let verdict = &verdicts[0];
            assert!(!verdict.passes(), "{policy:?}");
            assert!(
                matches!(
                    verdict.freshness,
                    Freshness::Outdated(ref why) if why.starts_with(
                        "closure predates component provisioning (it records the retired toolchain-component-unavailable exception); run 'tog' once"
                    )
                ),
                "{verdict:?}"
            );
            // Not unknown (it is no newer tog's kind), and not permitted.
            assert!(verdict.unknown.as_deref().unwrap().is_empty());
            assert!(!verdict
                .permitted
                .as_ref()
                .unwrap()
                .contains_key("toolchain-component-unavailable"));
        }
        let verdicts = judge(&temp.0, &permissive(), &closures);
        let record = record(&verdicts[0]);
        let report = Report {
            policy: permissive(),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        let text = render(&temp.0, &report, false).unwrap();
        assert!(text.contains("python  outdated"), "{text}");
        assert!(text.contains(&record), "{text}");
        assert!(
            text.contains("closure predates component provisioning"),
            "{text}"
        );
        assert!(!text.contains("unknown kind"), "{text}");
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
    }

    #[test]
    fn extra_policy_denies_what_the_chain_permits() {
        let temp = python_project("extra");
        let extra = temp.0.join("company.toml");
        fs::write(&extra, "deny = [\"install-script-failed\"]\n").unwrap();
        let closures = [with_exceptions(
            &temp.0,
            &[exception(INSTALL_SCRIPT_FAILED, "sharp@0.33.0")],
        )];
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("extra-machine", &[test_key()]);
        let (chain, _) = effective_policy(&temp.0, None).unwrap();
        assert!(judge(&temp.0, &chain, &closures)[0].passes());
        let file = read_policy_file(&extra).unwrap();
        let (policy, _) = effective_policy(&temp.0, Some((extra.as_path(), &file))).unwrap();
        let verdicts = judge(&temp.0, &policy, &closures);
        assert!(!verdicts[0].passes());
        assert_eq!(
            verdicts[0].denied.as_deref().unwrap()[0].kind,
            INSTALL_SCRIPT_FAILED
        );
    }

    /// A `--policy` file that denies nothing and is not strict leaves a
    /// strict machine policy's denial and strictness in force.
    #[test]
    fn extra_policy_cannot_loosen_the_chain() {
        let temp = python_project("loosen");
        let extra = temp.0.join("permissive.toml");
        fs::write(&extra, "strict = false\ndeny = []\n").unwrap();
        let closures = [with_exceptions(
            &temp.0,
            &[exception(GIT_DEPENDENCY, "left-pad")],
        )];
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("loosen-machine", &[test_key()]);
        fs::write(
            std::env::var_os("TOG_POLICY").unwrap(),
            format!(
                "strict = true\ndeny = [\"git-dependency\"]\n[signing]\ntrusted = [\"{}\"]\n",
                test_key().public_key()
            ),
        )
        .unwrap();
        let permissive = read_policy_file(&extra).unwrap();
        let (policy, _) = effective_policy(&temp.0, Some((extra.as_path(), &permissive))).unwrap();
        assert!(policy.deny.contains(GIT_DEPENDENCY));
        assert!(policy.strict);
        assert!(!judge(&temp.0, &policy, &closures)[0].passes());
        // A file with an unknown kind is refused, not silently ignored; so
        // is a missing one, so the gate never runs under a policy the
        // caller did not get.
        fs::write(&extra, "deny = [\"typo\"]\n").unwrap();
        assert!(read_policy_file(&extra).is_err());
        assert!(read_policy_file(&temp.0.join("absent.toml")).is_err());
    }

    /// Only the machine scope vouches for keys. A `--policy` file's
    /// `[signing]` list intersects with the machine's, so it can drop the
    /// machine's key A but never add its own key B.
    #[test]
    fn extra_policy_can_drop_trusted_keys_but_never_add_one() {
        let temp = python_project("extra-trust");
        let extra = temp.0.join("company.toml");
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("extra-trust-machine", &[test_key()]);
        let trusted_after = |keys: &[&SigningKey]| {
            let entries: Vec<String> = keys
                .iter()
                .map(|key| format!("\"{}\"", key.public_key()))
                .collect();
            fs::write(
                &extra,
                format!("[signing]\ntrusted = [{}]\n", entries.join(", ")),
            )
            .unwrap();
            let file = read_policy_file(&extra).unwrap();
            let (policy, _) = effective_policy(&temp.0, Some((extra.as_path(), &file))).unwrap();
            trusted_keys(&policy).unwrap().clone()
        };
        let only_b = trusted_after(&[other_key()]);
        assert!(!only_b.contains(&other_key().public_key()), "{only_b:?}");
        assert!(only_b.is_empty(), "{only_b:?}");
        let both = trusted_after(&[test_key(), other_key()]);
        assert_eq!(both, trusting(&[test_key()]).unwrap().trusted);
    }

    #[test]
    fn effective_policy_unions_the_project_chain_with_the_extra_file() {
        // The chain also reads TOG_POLICY or $HOME, which other tests
        // and the developer's machine own; assert only that this project's
        // ancestor policy and the extra file both land (superset), never
        // that nothing else did.
        let temp = python_project("chain");
        let root = temp.0.join("workspace");
        let member = root.join("member");
        fs::create_dir_all(root.join(".tog")).unwrap();
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.join(".tog/policy.toml"),
            "deny = [\"weak-integrity\"]\n",
        )
        .unwrap();
        let extra = Policy {
            strict: false,
            deny: [GIT_DEPENDENCY.to_string()].into_iter().collect(),
            signing: None,
            ..Policy::default()
        };
        let policy_file = temp.0.join("company.toml");
        let _env = policy::test_env_lock();
        let (policy, sources) =
            effective_policy(&member, Some((policy_file.as_path(), &extra))).unwrap();
        assert!(policy.deny.contains(WEAK_INTEGRITY));
        assert!(policy.deny.contains(GIT_DEPENDENCY));
        // Each denial is attributable: the workspace root asked for one, the
        // --policy file for the other, and that source is merged last.
        let ancestor = sources
            .iter()
            .find(|source| source.path.as_deref() == Some(root.join(".tog/policy.toml").as_path()))
            .expect("the workspace-root policy is a source");
        assert_eq!(ancestor.origin, SourceOrigin::Project);
        assert!(ancestor.deny.contains(WEAK_INTEGRITY));
        let last = sources.last().expect("the --policy file is a source");
        assert_eq!(last.origin, SourceOrigin::Flag);
        assert_eq!(last.path, Some(policy_file));
        assert!(last.deny.contains(GIT_DEPENDENCY));
        let (without, sources) = effective_policy(&member, None).unwrap();
        assert!(without.deny.contains(WEAK_INTEGRITY));
        assert!(!sources
            .iter()
            .any(|source| source.origin == SourceOrigin::Flag));
        // A file that does not exist is not a source: the member directory
        // has no policy of its own.
        assert!(!sources.iter().any(|source| {
            source.path.as_deref() == Some(member.join(".tog/policy.toml").as_path())
        }));
    }

    #[test]
    fn stale_closure_never_audits_clean() {
        let temp = python_project("stale");
        let dir = &temp.0;
        // Inputs changed since the record was written.
        let closures = [with_exceptions(dir, &[])];
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale("requirements.txt changed since the last sync".into())
        );
        assert!(!verdicts[0].passes());
        // Projection missing.
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::remove_file(dir.join(".venv")).unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale(".venv is not the synced projection".into())
        );
        assert!(!verdicts[0].passes());
        std::os::unix::fs::symlink(dir.join("env-object"), dir.join(".venv")).unwrap();
        // Synced on another platform.
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let foreign = [write_closure(
            dir,
            "python",
            "python",
            Some("other-platform"),
            body,
        )];
        let verdicts = judge(dir, &permissive(), &foreign);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale("synced on other-platform, not this host".into())
        );
        assert!(!verdicts[0].passes());
        // Inputs gone from the directory: the closure is orphaned.
        let closures = [with_exceptions(dir, &[])];
        fs::remove_file(dir.join("requirements.txt")).unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale("no python inputs found here; the closure is orphaned".into())
        );
        assert!(!verdicts[0].passes());
        let record = record(&verdicts[0]);
        let report = Report {
            policy: permissive(),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        assert!(!report.passes());
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  stale         closure {record}: no python inputs"
            )),
            "{text}"
        );
        assert!(
            text.contains("run 'tog', then audit again (permitted: no exceptions)"),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(value["closures"][0]["freshness"], "stale");
        // A stale record's denials are still shown, not hidden behind the
        // staleness.
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let closures = [with_exceptions(
            dir,
            &[exception(GIT_DEPENDENCY, "left-pad")],
        )];
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let verdicts = judge(dir, &deny(&[GIT_DEPENDENCY]), &closures);
        assert!(matches!(verdicts[0].freshness, Freshness::Stale(_)));
        assert_eq!(verdicts[0].denied.as_deref().unwrap().len(), 1);
        let report = Report {
            policy: deny(&[GIT_DEPENDENCY]),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains("(1 denied; permitted: no exceptions)"),
            "{text}"
        );
        assert!(
            text.contains("    denied   git-dependency  left-pad"),
            "{text}"
        );
    }

    /// A gate that passes must not be running a toolchain the committed
    /// lock no longer names: the audit reads the same lock verdicts
    /// `status` reports, over a record that is otherwise current.
    #[test]
    fn a_closure_the_toolchain_lock_does_not_describe_never_audits_clean() {
        use crate::kernel::fsroot::ProjectRoot;
        use crate::kernel::toolchain::input;
        use crate::kernel::toolchain::lock::ToolchainLock;
        let temp = python_project("lock");
        let dir = &temp.0;
        // `write_closure` publishes the matching lock, so this starts clean.
        let closures = [with_exceptions(dir, &[])];
        assert_eq!(
            judge(dir, &permissive(), &closures)[0].freshness,
            Freshness::Current
        );
        let lock = fs::read(dir.join(LOCK_PATH)).unwrap();
        let stale = |verdicts: &[Verdict], expected: &str| {
            assert_eq!(
                verdicts[0].freshness,
                Freshness::Stale(expected.into()),
                "{verdicts:?}"
            );
            assert!(!verdicts[0].passes());
        };

        // No lock at all: the next sync would create one.
        fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        stale(
            &verdicts,
            "tog-toolchain.toml (missing; run 'tog' to create it)",
        );
        // The lock line carries its own next step and is not wrapped in
        // the dependency-input sentence.
        let record = record(&verdicts[0]);
        let text = render(dir, &report(permissive(), verdicts), false).unwrap();
        assert_eq!(
            text,
            format!(
                "python  stale         closure {record}: tog-toolchain.toml (missing; run 'tog' \
                 to create it), then audit again (permitted: no exceptions)\n"
            )
        );
        fs::write(dir.join(LOCK_PATH), &lock).unwrap();

        // A toolchain source moved since the lock was written: only
        // `tog update --toolchain` moves it, and the gate says so.
        fs::write(dir.join(".python-version"), "3.13.15\n").unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        let Freshness::Stale(why) = &verdicts[0].freshness else {
            panic!("{verdicts:?}");
        };
        assert!(why.starts_with("tog-toolchain.toml stale: "), "{why}");
        assert!(why.contains("recorded absent, now 3.13.15"), "{why}");
        assert!(
            why.ends_with("run 'tog update --toolchain python'"),
            "{why}"
        );
        assert!(!verdicts[0].passes());
        let text = render(dir, &report(permissive(), verdicts), false).unwrap();
        assert!(
            text.contains("run 'tog update --toolchain python', then audit again"),
            "{text}"
        );
        assert!(!text.contains("run 'tog', then audit again"), "{text}");
        fs::remove_file(dir.join(".python-version")).unwrap();

        // A lock that describes some other ecosystem but not this one.
        let mut other = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
        let go = tailors::by_id("go").unwrap();
        let root = ProjectRoot::open(dir).unwrap();
        let go_rows = input::discover(&root, "go").unwrap();
        let go_catalog = go.toolchain_catalog().unwrap();
        let go_bundle = crate::kernel::toolchain::select_for(&go_catalog, "go", &go_rows).unwrap();
        other.set_ecosystem("go", go_bundle, &go_rows).unwrap();
        fs::write(dir.join(LOCK_PATH), other.canonical_bytes()).unwrap();
        stale(
            &judge(dir, &permissive(), &closures),
            "tog-toolchain.toml (no [toolchain.python] section; run 'tog update --toolchain python')",
        );
        fs::write(dir.join(LOCK_PATH), &lock).unwrap();

        // A signed record built from a different bundle than the lock names.
        let rebuilt = |edit: fn(&mut Value)| {
            [write_closure_with(
                dir,
                "python",
                "python",
                Some(host().triple()),
                closures[0].body.clone(),
                Some(test_key()),
                |envelope| {
                    edit(&mut envelope["body"]);
                    test_key().sign(envelope).unwrap();
                },
            )]
        };
        let foreign = rebuilt(|body| {
            body["toolchain"]["bundle_id"] = json!(format!("sha256:{}", "0".repeat(64)));
        });
        assert!(matches!(foreign[0].body["toolchain"]["bundle_id"].as_str(),
                         Some(id) if id.ends_with(&"0".repeat(64))));
        stale(
            &judge(dir, &permissive(), &foreign),
            "tog-toolchain.toml (toolchain changed since the last sync; run 'tog')",
        );

        // A record from before the bundle was recorded cannot be compared,
        // which is the answer every other unrecorded field gets: outdated.
        let unrecorded = rebuilt(|body| {
            body.as_object_mut().unwrap().remove("toolchain");
        });
        let verdicts = judge(dir, &permissive(), &unrecorded);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Outdated("toolchain not recorded by this sync; run 'tog' once".into()),
            "{verdicts:?}"
        );
        assert!(!verdicts[0].passes());

        // A closure whose own inputs changed still says so when the lock
        // has nothing a plain sync would refuse over.
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        stale(
            &judge(dir, &permissive(), &closures),
            "requirements.txt changed since the last sync",
        );
    }

    #[test]
    fn every_status_state_but_synced_fails() {
        // The mapping the gate applies to a record's `status` state:
        // `NotSynced` is unreachable per record, and must still not pass.
        assert_eq!(freshness_from_state(State::Synced), Freshness::Current);
        for state in [
            State::NotSynced,
            State::Changed(vec!["a".into()]),
            State::ProjectionMissing("x".into()),
            State::ForeignPlatform("p".into()),
            State::Unchecked("why".into()),
        ] {
            let freshness = freshness_from_state(state.clone());
            // Exhaustive on purpose (no `_` arm): a new `State` variant must
            // fail to compile here, not silently skip the mapping check.
            match state {
                State::Synced => unreachable!("asserted above, outside the loop"),
                State::Unchecked(_) => assert!(matches!(freshness, Freshness::Outdated(_))),
                State::NotSynced
                | State::Changed(_)
                | State::ProjectionMissing(_)
                | State::ForeignPlatform(_) => {
                    assert!(matches!(freshness, Freshness::Stale(_)), "{state:?}")
                }
            }
            let verdict = Verdict {
                ecosystem: "python".into(),
                record_sha256: "0".repeat(64),
                path: PathBuf::from("python.json"),
                signature: Signature::Trusted(test_key().public_key()),
                freshness,
                denied: Some(Vec::new()),
                unknown: Some(Vec::new()),
                permitted: Some(BTreeMap::new()),
            };
            assert!(!verdict.passes(), "{verdict:?}");
        }
    }

    #[test]
    fn outdated_closure_is_reported_outdated_not_clean() {
        let temp = python_project("outdated");
        let dir = &temp.0;
        // Pre-field closure: no recorded inputs, status says synced (unchecked).
        let mut body = python_body(dir);
        body.as_object_mut().unwrap().remove("inputs");
        body["exceptions"] = json!([]);
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
        )];
        assert_eq!(
            inspect::closure_state(host(), &ProjectRoot::open(dir).unwrap(), &closures[0]).unwrap(),
            State::Unchecked(
                "inputs were not recorded by this sync; run 'tog' once to enable checks".into()
            )
        );
        let verdicts = judge(dir, &permissive(), &closures);
        assert!(
            matches!(verdicts[0].freshness, Freshness::Outdated(ref why) if why.contains("inputs were not recorded")),
            "{:?}",
            verdicts[0]
        );
        assert!(!verdicts[0].passes());
        // No recorded platform: status cannot tell which host made it.
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let closures = [write_closure(dir, "python", "python", None, body)];
        let verdicts = judge(dir, &permissive(), &closures);
        assert!(
            matches!(verdicts[0].freshness, Freshness::Outdated(ref why) if why.contains("records no platform")),
            "{:?}",
            verdicts[0]
        );
        assert!(!verdicts[0].passes());
        // A current closure without an exception record is unchecked too:
        // absence of the record is not evidence of a clean sync.
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            python_body(dir),
        )];
        let verdicts = judge(dir, &permissive(), &closures);
        assert!(
            matches!(verdicts[0].freshness, Freshness::Outdated(ref why) if why.contains("no exception record")),
            "{:?}",
            verdicts[0]
        );
        assert!(!verdicts[0].passes());
        let record = record(&verdicts[0]);
        let report = Report {
            policy: permissive(),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  outdated      closure {record}: no exception record"
            )),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["closures"][0]["freshness"], "outdated");
        assert_eq!(value["passed"], false);
        // A stale closure without a record stays stale (the stronger verdict).
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        assert!(matches!(verdicts[0].freshness, Freshness::Stale(_)));
    }

    #[test]
    fn closure_named_for_another_ecosystem_is_refused() {
        let temp = python_project("mismatch");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        // Named python.json, claims node: `sync` would refuse to read it,
        // and the gate must not judge it under either name.
        let closures = [write_closure(
            dir,
            "python",
            "node",
            Some(host().triple()),
            body,
        )];
        let present = inspect::detected(dir).unwrap();
        let error = evaluate(host(), dir, &permissive(), &[], &closures, &present).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("claims ecosystem \"node\" but is named \"python\""),
            "{error}"
        );
    }

    #[test]
    fn malformed_exception_record_is_an_error() {
        let temp = python_project("malformed");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([{"kind": "x"}]);
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
        )];
        let present = inspect::detected(dir).unwrap();
        let error = evaluate(host(), dir, &permissive(), &[], &closures, &present).unwrap_err();
        assert!(
            error.to_string().contains("malformed exception record"),
            "{error}"
        );
    }

    #[test]
    fn audit_reads_the_project_without_a_store() {
        let temp = python_project("audit");
        let dir = &temp.0;
        with_exceptions(dir, &[exception(GIT_DEPENDENCY, "left-pad")]);
        let extra = deny(&[GIT_DEPENDENCY]);
        // The chain part of the policy is whatever this machine has (see
        // `effective_policy_unions...`); the extra file is under test here.
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("audit-machine", &[test_key()]);
        let flag = dir.join("company.toml");
        let report = audit(host(), dir, Some((flag.as_path(), &extra))).unwrap();
        assert_eq!(report.verdicts.len(), 1);
        assert_eq!(report.verdicts[0].denied.as_deref().unwrap().len(), 1);
        assert!(!report.passes());
        assert!(!dir.join("store").exists());
        // Nothing synced: a NotFound with a next step.
        let empty = TempDir::named("empty");
        let error = audit(host(), &empty.0, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("run 'tog' first"));
        // No trusted set anywhere in the chain: the records are judged on
        // their contents, the report says signatures were not checked, and
        // the denial still fails it. The fix lines stop asking for a key.
        drop(_machine);
        let _home = MachinePolicy::trusting("audit-machine-none", &[]);
        fs::write(std::env::var_os("TOG_POLICY").unwrap(), "deny = []\n").unwrap();
        let report = audit(host(), dir, Some((flag.as_path(), &extra))).unwrap();
        assert!(!report.signatures_checked);
        assert_eq!(report.verdicts.len(), 1);
        assert!(
            matches!(
                report.verdicts[0].signature,
                Signature::NotChecked { key: Some(_) }
            ),
            "{:?}",
            report.verdicts[0].signature
        );
        assert_eq!(report.verdicts[0].word(), "denied");
        assert!(!report.passes());
        let text = render(dir, &report, false).unwrap();
        assert!(text.contains(SIGNATURES_NOT_CHECKED), "{text}");
        assert!(text.contains("python  denied        closure "), "{text}");
        assert!(!text.contains("trusted key"), "{text}");
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["signatures_checked"], false);
        assert_eq!(value["policy"]["trusted"], Value::Null);
        assert_eq!(value["closures"][0]["signature"]["state"], "not-checked");
        assert_eq!(
            value["closures"][0]["signature"]["key"],
            test_key().public_key().to_string()
        );
        assert_eq!(value["closures"][0]["verdict"], "denied");
        assert!(!dir.join("store").exists());
    }

    #[test]
    fn company_policy_template_parses_and_names_only_known_kinds() {
        let text = include_str!("../../docs/human/policy-company.toml");
        let template = policy::parse_file(Path::new("docs/human/policy-company.toml"), text)
            .expect("the shipped template must parse against policy::KINDS");
        assert!(!template.strict, "the template must not set strict");
        let expected: BTreeSet<String> = [
            INSTALL_SCRIPT_FAILED,
            WEAK_INTEGRITY,
            policy::UNATTESTED_MUTABLE_STATE,
            policy::UNATTESTED_INDEX,
            GIT_DEPENDENCY,
            policy::LOCK_DISAGREEMENT,
            policy::ARTIFACT_NOT_PROVISIONED,
            policy::EXTERNAL_TOOLCHAIN,
            policy::UNRECORDED_RESOLUTION,
            policy::UNCONFINED_RESOLUTION,
        ]
        .iter()
        .map(|kind| kind.to_string())
        .collect();
        assert_eq!(template.deny, expected);
        // Every kind the template deliberately leaves permitted is named in
        // its comments, so the file cannot silently fall behind KINDS.
        for kind in policy::KINDS {
            assert!(text.contains(kind), "template does not mention {kind}");
        }
    }

    #[test]
    fn a_tampered_record_is_a_bad_signature_and_nothing_in_it_is_believed() {
        let temp = python_project("tampered");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([exception(GIT_DEPENDENCY, "left-pad")]);
        let tampered = |edit: fn(&mut Value)| {
            write_closure_with(
                dir,
                "python",
                "python",
                Some(host().triple()),
                body.clone(),
                Some(test_key()),
                edit,
            )
        };
        // Under a denying policy: a tampered record must not even report
        // the denial, because nothing in it can be believed.
        let policy = deny(&[GIT_DEPENDENCY]);
        for (label, closure) in [
            (
                "exceptions edited",
                tampered(|v| v["body"]["exceptions"] = json!([])),
            ),
            (
                "platform edited",
                tampered(|v| {
                    let foreign = Platform::ALL
                        .iter()
                        .copied()
                        .find(|p| *p != host())
                        .unwrap();
                    v["platform"] = json!(foreign.triple());
                }),
            ),
            (
                "unknown envelope field added",
                tampered(|v| v["note"] = json!("hand-added")),
            ),
            ("null signature", tampered(|v| v["signature"] = Value::Null)),
            (
                "string signature",
                tampered(|v| v["signature"] = json!("ed25519")),
            ),
            (
                "unknown algorithm",
                tampered(|v| v["signature"]["alg"] = json!("rsa")),
            ),
            (
                "another key named",
                tampered(|v| v["signature"]["key"] = json!(other_key().public_key().hex())),
            ),
        ] {
            let verdicts = judge(dir, &policy, &[closure]);
            let verdict = &verdicts[0];
            assert!(
                matches!(verdict.signature, Signature::Bad { .. }),
                "{label}: {verdict:?}"
            );
            assert!(!verdict.passes(), "{label}");
            assert_eq!(verdict.freshness, Freshness::NotEvaluated, "{label}");
            assert!(
                verdict.denied.is_none()
                    && verdict.unknown.is_none()
                    && verdict.permitted.is_none(),
                "{label}: {verdict:?}"
            );
            assert_eq!(verdict.word(), "bad-signature", "{label}");
            let record = record(verdict);
            let report = report(policy.clone(), verdicts);
            let text = render(dir, &report, false).unwrap();
            assert!(
                text.contains(&format!("python  bad-signature closure {record}: ")),
                "{label}: {text}"
            );
            assert!(
                text.contains("find out who changed it") && text.contains("(not evaluated)"),
                "{label}: {text}"
            );
            assert!(
                !text.contains("no exceptions") && !text.contains("denied "),
                "{label}: {text}"
            );
            let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
            assert_eq!(value["passed"], false, "{label}");
            assert_eq!(value["closures"][0]["passed"], false, "{label}");
            assert_eq!(value["closures"][0]["verdict"], "bad-signature", "{label}");
            assert_eq!(value["closures"][0]["signature"]["state"], "bad", "{label}");
            assert_eq!(
                value["closures"][0]["freshness"], "not-evaluated",
                "{label}"
            );
            assert_eq!(
                value["closures"][0]["freshness_detail"],
                Value::Null,
                "{label}"
            );
            assert_eq!(value["closures"][0]["denied"], Value::Null, "{label}");
            assert_eq!(value["closures"][0]["unknown"], Value::Null, "{label}");
            assert_eq!(value["closures"][0]["permitted"], Value::Null, "{label}");
        }
        // The key is reported when it can be decoded, and omitted otherwise.
        let closure = tampered(|v| v["body"]["exceptions"] = json!([]));
        let verdicts = judge(dir, &policy, &[closure]);
        assert_eq!(verdicts[0].signature.key(), Some(test_key().public_key()));
        let value: Value =
            serde_json::from_str(&render(dir, &report(policy.clone(), verdicts), true).unwrap())
                .unwrap();
        assert_eq!(
            value["closures"][0]["signature"]["key"],
            test_key().public_key().to_string()
        );
        assert_eq!(
            value["closures"][0]["signature"]["detail"],
            "record does not match its signature"
        );
        let closure = tampered(|v| v["signature"] = Value::Null);
        let verdicts = judge(dir, &policy, &[closure]);
        assert_eq!(verdicts[0].signature.key(), None);
        let value: Value =
            serde_json::from_str(&render(dir, &report(policy, verdicts), true).unwrap()).unwrap();
        assert!(
            value["closures"][0]["signature"].get("key").is_none(),
            "{value}"
        );
    }

    /// A closure with no top-level exception record is outdated whatever
    /// the joined resolution record lists: the join always writes both, so
    /// a body with only the joined list was edited, and nothing in it is
    /// judged as permitted or denied.
    #[test]
    fn a_joined_list_without_a_recorded_one_is_outdated_and_not_judged() {
        let temp = python_project("joined-only");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body.as_object_mut().unwrap().remove("exceptions");
        body["resolution"] = json!({
            "exceptions": [exception(GIT_DEPENDENCY, "left-pad"), exception("made-up-kind", "x")]
        });
        let closure = write_closure(dir, "python", "python", Some(host().triple()), body);
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("joined-only-machine", &[test_key()]);
        let verdicts = judge(dir, &deny(&[GIT_DEPENDENCY]), &[closure]);
        assert_eq!(verdicts[0].word(), "outdated");
        assert!(matches!(
            &verdicts[0].freshness,
            Freshness::Outdated(why) if why.contains("no exception record")
        ));
        assert_eq!(verdicts[0].denied, Some(Vec::new()));
        assert_eq!(verdicts[0].unknown, Some(Vec::new()));
        assert!(!verdicts[0].passes());
    }

    /// Without a `[signing]` table the fix for a record with no platform
    /// drops "under a trusted key", in the text and in the JSON.
    #[test]
    fn the_no_platform_fix_follows_the_signing_mode() {
        let temp = python_project("no-platform-mode");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let closure = write_closure(dir, "python", "python", None, body);
        let unsigned = judge(dir, &Policy::default(), std::slice::from_ref(&closure));
        assert_eq!(unsigned[0].word(), "outdated");
        let Freshness::Outdated(why) = &unsigned[0].freshness else {
            panic!("{:?}", unsigned[0].freshness);
        };
        assert_eq!(
            why,
            "closure records no platform; run 'tog' once, then commit"
        );
        let report = Report {
            policy: Policy::default(),
            sources: Vec::new(),
            verdicts: unsigned,
            missing: Vec::new(),
            signatures_checked: false,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(!text.contains("trusted key"), "{text}");
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert!(!value["closures"][0]["freshness_detail"]
            .as_str()
            .unwrap()
            .contains("trusted key"));
        let signed = judge(dir, &permissive(), &[closure]);
        let Freshness::Outdated(why) = &signed[0].freshness else {
            panic!("{:?}", signed[0].freshness);
        };
        assert!(
            why.ends_with("once under a trusted key, then commit"),
            "{why}"
        );
    }

    #[test]
    fn an_unsigned_record_is_outdated_and_not_evaluated() {
        let temp = python_project("unsigned");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([exception(GIT_DEPENDENCY, "left-pad")]);
        // Stripped after signing, and never signed: the same verdict.
        let stripped = write_closure_with(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body.clone(),
            Some(test_key()),
            |v| {
                v.as_object_mut().unwrap().remove("signature");
            },
        );
        let never = write_closure_with(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body.clone(),
            None,
            |_| {},
        );
        for closure in [stripped, never] {
            let verdicts = judge(dir, &deny(&[GIT_DEPENDENCY]), &[closure]);
            assert_eq!(verdicts[0].signature, Signature::Unsigned);
            assert_eq!(verdicts[0].freshness, Freshness::NotEvaluated);
            assert!(verdicts[0].denied.is_none());
            assert!(!verdicts[0].passes());
            assert_eq!(verdicts[0].word(), "outdated");
            let record = record(&verdicts[0]);
            let report = report(deny(&[GIT_DEPENDENCY]), verdicts);
            let text = render(dir, &report, false).unwrap();
            assert!(
                text.contains(&format!(
                    "python  outdated      closure {record}: no signature; run 'tog' once under a trusted key, then commit (not evaluated)\n"
                )),
                "{text}"
            );
            let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
            assert_eq!(
                value["closures"][0]["signature"],
                json!({"state": "unsigned", "detail": null})
            );
            assert_eq!(value["closures"][0]["freshness"], "not-evaluated");
            assert_eq!(value["closures"][0]["verdict"], "outdated");
            assert_eq!(value["closures"][0]["denied"], Value::Null);
        }
        // The pre-`platform` fixture: signed, it is outdated for the missing
        // field with the refresh command in the detail; unsigned, it is
        // outdated for the signature first and nothing else is evaluated.
        let mut old = python_body(dir);
        old["exceptions"] = json!([]);
        let signed_old = write_closure(dir, "python", "python", None, old.clone());
        let verdicts = judge(dir, &permissive(), &[signed_old]);
        assert!(
            matches!(&verdicts[0].freshness, Freshness::Outdated(why) if why.contains("records no platform") && why.contains("under a trusted key")),
            "{verdicts:?}"
        );
        assert_eq!(verdicts[0].word(), "outdated");
        assert_eq!(verdicts[0].permitted.as_ref().map(BTreeMap::len), Some(0));
        let unsigned_old = write_closure_with(dir, "python", "python", None, old, None, |_| {});
        let verdicts = judge(dir, &permissive(), &[unsigned_old]);
        assert_eq!(verdicts[0].signature, Signature::Unsigned);
        assert_eq!(verdicts[0].freshness, Freshness::NotEvaluated);
    }

    #[test]
    fn an_unlisted_key_is_untrusted_and_only_the_machine_scope_can_add_one() {
        let temp = python_project("untrusted");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let by_other = write_closure_with(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body.clone(),
            Some(other_key()),
            |_| {},
        );
        let verdicts = judge(dir, &permissive(), std::slice::from_ref(&by_other));
        assert_eq!(
            verdicts[0].signature,
            Signature::Untrusted {
                key: other_key().public_key(),
                excluded_by: Vec::new(),
            }
        );
        assert_eq!(verdicts[0].freshness, Freshness::NotEvaluated);
        assert!(verdicts[0].denied.is_none());
        assert!(!verdicts[0].passes());
        let record = record(&verdicts[0]);
        let report = report(permissive(), verdicts);
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  untrusted     closure {record}: signed by {}, which is not in the trusted set; re-sync under an allowed key",
                other_key().public_key()
            )),
            "{text}"
        );
        assert!(text.contains("(not evaluated)"), "{text}");
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["closures"][0]["signature"]["state"], "untrusted");
        assert_eq!(
            value["closures"][0]["signature"]["key"],
            other_key().public_key().to_string()
        );
        assert_eq!(value["closures"][0]["signature"]["detail"], json!([]));
        assert_eq!(value["closures"][0]["verdict"], "untrusted");
        assert_eq!(
            value["policy"]["trusted"],
            json!([test_key().public_key().to_string()])
        );

        // A project policy that names the other key cannot add it: the
        // machine scope introduced {test}, so the intersection stays {test}.
        let widening = Policy {
            signing: trusting(&[test_key(), other_key()]),
            ..Policy::default()
        };
        let mut chain = permissive();
        policy::merge(&mut chain, &widening, SourceOrigin::Project);
        let verdicts = judge(dir, &chain, std::slice::from_ref(&by_other));
        assert!(matches!(verdicts[0].signature, Signature::Untrusted { .. }));
        // Nor can the --policy file.
        let mut chain = permissive();
        policy::merge(&mut chain, &widening, SourceOrigin::Flag);
        let verdicts = judge(dir, &chain, &[by_other]);
        assert!(matches!(verdicts[0].signature, Signature::Untrusted { .. }));

        // A project policy that omits the test key removes it: the record
        // the machine alone would trust is untrusted, and the excluding
        // scope is named in the verdict, the JSON, and the policy lines.
        let by_test = write_closure(dir, "python", "python", Some(host().triple()), body.clone());
        let mut chain = permissive();
        let narrowing = Policy {
            signing: trusting(&[other_key()]),
            ..Policy::default()
        };
        policy::merge(&mut chain, &narrowing, SourceOrigin::Project);
        assert_eq!(chain.signing, Some(Signing::default()));
        let sources = vec![
            PolicySource {
                origin: SourceOrigin::Machine,
                path: Some(PathBuf::from("/m/policy.toml")),
                strict: false,
                deny: BTreeSet::new(),
                trusted: Some([test_key().public_key()].into_iter().collect()),
            },
            PolicySource {
                origin: SourceOrigin::Project,
                path: Some(PathBuf::from("/p/.tog/policy.toml")),
                strict: false,
                deny: BTreeSet::new(),
                trusted: Some([other_key().public_key()].into_iter().collect()),
            },
            PolicySource {
                origin: SourceOrigin::Flag,
                path: Some(PathBuf::from("/f/company.toml")),
                strict: false,
                deny: BTreeSet::new(),
                trusted: Some(KeySet::new()),
            },
            PolicySource {
                origin: SourceOrigin::Env,
                path: None,
                strict: true,
                deny: BTreeSet::new(),
                trusted: None,
            },
        ];
        let verdicts = judge_with_sources(dir, &chain, &sources, std::slice::from_ref(&by_test));
        assert_eq!(
            verdicts[0].signature,
            Signature::Untrusted {
                key: test_key().public_key(),
                excluded_by: vec![
                    "project \"/p/.tog/policy.toml\"".into(),
                    "flag \"/f/company.toml\"".into()
                ],
            }
        );
        let report = Report {
            policy: chain.clone(),
            sources,
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains(
                "(excluded by project \"/p/.tog/policy.toml\", flag \"/f/company.toml\")"
            ),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "policy: machine \"/m/policy.toml\" trusts {}\n",
                test_key().public_key()
            )),
            "{text}"
        );
        assert!(
            text.contains("policy: flag \"/f/company.toml\" trusts nobody\n"),
            "{text}"
        );
        assert!(text.contains("policy: env (strict)\n"), "{text}");
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(
            value["closures"][0]["signature"]["detail"],
            json!([
                "project \"/p/.tog/policy.toml\"",
                "flag \"/f/company.toml\""
            ])
        );
        assert_eq!(value["policy"]["trusted"], json!([]));
        assert_eq!(
            value["policy"]["sources"][0]["trusted"],
            json!([test_key().public_key().to_string()])
        );
        assert_eq!(value["policy"]["sources"][2]["trusted"], json!([]));
        assert_eq!(value["policy"]["sources"][3]["trusted"], Value::Null);

        // An explicitly empty machine set is a decision: every valid
        // signature is untrusted, and a bad one is still bad-signature.
        let nobody = Policy {
            signing: Some(Signing::default()),
            ..Policy::default()
        };
        let verdicts = judge(dir, &nobody, std::slice::from_ref(&by_test));
        assert!(matches!(verdicts[0].signature, Signature::Untrusted { .. }));
        let tampered = write_closure_with(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body.clone(),
            Some(test_key()),
            |v| v["body"]["exceptions"] = json!([exception(GIT_DEPENDENCY, "x")]),
        );
        let verdicts = judge(dir, &nobody, std::slice::from_ref(&tampered));
        assert!(matches!(verdicts[0].signature, Signature::Bad { .. }));

        // Trust that was never configured is not asked about: a signed
        // record and an unsigned one are both `not-checked` and judged on
        // their contents, a tampered one is still `bad-signature`, and a
        // project or flag list cannot turn the check on.
        let mut chain = Policy::default();
        policy::merge(&mut chain, &widening, SourceOrigin::Project);
        policy::merge(&mut chain, &widening, SourceOrigin::Flag);
        assert_eq!(chain.signing, None);
        let unsigned = write_closure_with(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
            None,
            |_| {},
        );
        let verdicts = judge(dir, &chain, &[by_test, unsigned, tampered]);
        assert_eq!(
            verdicts[0].signature,
            Signature::NotChecked {
                key: Some(test_key().public_key())
            }
        );
        assert_eq!(verdicts[0].word(), "clean");
        assert!(verdicts[0].passes());
        assert_eq!(verdicts[1].signature, Signature::NotChecked { key: None });
        assert_eq!(verdicts[1].word(), "clean");
        assert!(matches!(verdicts[2].signature, Signature::Bad { .. }));
        assert_eq!(verdicts[2].word(), "bad-signature");
        assert!(!verdicts[2].passes());
        let report = audit_under(host(), dir, chain, Vec::new()).unwrap();
        assert!(!report.signatures_checked);
    }

    #[test]
    fn a_missing_primary_closure_fails_the_report() {
        // A python + cargo project: a deleted closure is missing however
        // clean the records beside it are.
        let temp = python_project("missing");
        let dir = &temp.0;
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"m\"\n").unwrap();
        let python = with_exceptions(dir, &[]);
        let present = inspect::detected(dir).unwrap();
        assert_eq!(present, ["python", "cargo"]);
        assert_eq!(
            missing_closures(std::slice::from_ref(&python), &present),
            vec!["cargo".to_string()]
        );
        assert_eq!(
            missing_closures(&[], &present),
            vec!["python".to_string(), "cargo".to_string()]
        );
        assert!(missing_closures(std::slice::from_ref(&python), &["python"]).is_empty());
        let verdicts = judge(dir, &permissive(), std::slice::from_ref(&python));
        assert!(verdicts.iter().all(Verdict::passes), "{verdicts:?}");
        let report = Report {
            policy: permissive(),
            sources: Vec::new(),
            verdicts,
            missing: missing_closures(std::slice::from_ref(&python), &present),
            signatures_checked: true,
        };
        assert!(!report.passes());
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains("cargo   missing       no closure for the cargo inputs found here; run 'tog' under a trusted key, then commit\n"),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(value["missing"], json!(["cargo"]));
        assert_eq!(value["closures"][0]["passed"], true);
        // Through the directory.
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("missing-machine", &[test_key()]);
        let report = audit(host(), dir, None).unwrap();
        assert_eq!(report.missing, vec!["cargo".to_string()]);
        assert_eq!(report.verdicts.len(), 1);
        assert!(report.verdicts[0].passes());
        assert!(!report.passes());
    }

    /// An older `tog fmt` left `.tog/closures/rustfmt.json` at a Cargo
    /// workspace root. It is not a closure any more: the audit neither
    /// judges it (no orphaned or unknown verdict) nor counts it as the
    /// cargo record, and with nothing else beside it nothing is synced.
    #[test]
    fn a_leftover_rustfmt_record_is_not_audited() {
        let temp = python_project("leftover-fmt");
        let dir = &temp.0;
        let _python = with_exceptions(dir, &[]);
        fs::write(
            dir.join(".tog/closures/rustfmt.json"),
            serde_json::to_vec_pretty(&json!({
                "schema": "closure/1",
                "ecosystem": "rustfmt",
                "platform": host().triple(),
                "projected_at": 1,
                "body": {"rust_version": "1.96.1", "exceptions": []},
            }))
            .unwrap(),
        )
        .unwrap();
        let _env = policy::test_env_lock();
        let _machine = MachinePolicy::trusting("leftover-rustfmt-machine", &[test_key()]);
        let report = audit(host(), dir, None).unwrap();
        assert_eq!(report.verdicts.len(), 1, "{:?}", report.verdicts);
        assert_eq!(report.verdicts[0].ecosystem, "python");
        assert!(report.missing.is_empty(), "{:?}", report.missing);
        assert!(report.passes());
        let rendered = render(dir, &report, false).unwrap();
        assert!(!rendered.contains("rustfmt.json"), "{rendered}");
        // A Cargo project with only the leftover: cargo is unsynced, and
        // the leftover is not mistaken for its record.
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"m\"\n").unwrap();
        let report = audit(host(), dir, None).unwrap();
        assert_eq!(report.missing, vec!["cargo".to_string()]);
        fs::remove_file(dir.join(".tog/closures/python.json")).unwrap();
        let error = audit(host(), dir, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    }

    #[test]
    fn the_record_judged_is_the_one_read_not_the_path() {
        let temp = python_project("replaced");
        let dir = &temp.0;
        let closure = with_exceptions(dir, &[]);
        // Replace the file after the read: a hand edit, unsigned, denied.
        let mut body = python_body(dir);
        body["exceptions"] = json!([exception(GIT_DEPENDENCY, "x")]);
        write_closure_with(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
            None,
            |_| {},
        );
        let verdicts = judge(
            dir,
            &deny(&[GIT_DEPENDENCY]),
            std::slice::from_ref(&closure),
        );
        assert!(verdicts[0].passes(), "{verdicts:?}");
        assert_eq!(verdicts[0].record_sha256, closure.record_sha256);
        // Reading again judges the new file, under its own digest.
        let reread = read_closure(dir, &closure.path);
        assert_ne!(reread.record_sha256, closure.record_sha256);
        let verdicts = judge(dir, &deny(&[GIT_DEPENDENCY]), &[reread]);
        assert_eq!(verdicts[0].signature, Signature::Unsigned);
    }

    #[test]
    fn a_malformed_envelope_is_refused_not_judged() {
        let temp = python_project("shape");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let body = inspect::with_toolchain_lock(dir, "python", body);
        let present = inspect::detected(dir).unwrap();
        let write = |edit: fn(&mut Value), sign_after: bool| {
            let mut envelope = json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "platform": host().triple(),
                "projected_at": 1,
                "body": body.clone(),
            });
            if !sign_after {
                test_key().sign(&mut envelope).unwrap();
            }
            edit(&mut envelope);
            if sign_after {
                test_key().sign(&mut envelope).unwrap();
            }
            let closures = dir.join(".tog/closures");
            fs::create_dir_all(&closures).unwrap();
            let path = closures.join("python.json");
            fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
            read_closure(dir, &path)
        };
        let cases: [(&str, fn(&mut Value), &str); 6] = [
            (
                "schema",
                |v| v["schema"] = json!("closure/2"),
                "unsupported closure schema",
            ),
            (
                "no schema",
                |v| {
                    v.as_object_mut().unwrap().remove("schema");
                },
                "no schema",
            ),
            (
                "ecosystem",
                |v| v["ecosystem"] = json!(1),
                "no ecosystem string",
            ),
            (
                "body",
                |v| v["body"] = json!([]),
                "body is not a JSON object",
            ),
            (
                "platform",
                |v| v["platform"] = json!(7),
                "platform is not a string",
            ),
            (
                "projected_at",
                |v| v["projected_at"] = json!("yesterday"),
                "projected_at is not an integer",
            ),
        ];
        for (label, edit, expected) in cases {
            // Signed over the malformed shape by a trusted key: still refused.
            let closure = write(edit, true);
            assert!(
                matches!(signing::verify(&closure.envelope), Verification::Valid(_)),
                "{label}"
            );
            let error =
                evaluate(host(), dir, &permissive(), &[], &[closure], &present).unwrap_err();
            assert!(
                error.to_string().contains(expected) && error.to_string().contains("refused"),
                "{label} (signed): {error}"
            );
            // Edited after signing: an error too, never a verdict.
            let closure = write(edit, false);
            let error =
                evaluate(host(), dir, &permissive(), &[], &[closure], &present).unwrap_err();
            assert!(error.to_string().contains(expected), "{label}: {error}");
        }
        // The well-formed envelope from the same helper passes.
        let closure = write(|_| {}, true);
        assert!(judge(dir, &permissive(), &[closure])[0].passes());
        // A file that is valid JSON but not an object at all.
        let path = dir.join(".tog/closures/python.json");
        fs::write(&path, "[1, 2]").unwrap();
        let closure = read_closure(dir, &path);
        let error = evaluate(host(), dir, &permissive(), &[], &[closure], &present).unwrap_err();
        assert!(error.to_string().contains("not a JSON object"), "{error}");
    }

    #[test]
    fn control_characters_in_a_closure_name_are_escaped_in_the_report() {
        let temp = python_project("escape");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        // A stray closure whose name and ecosystem carry an escape sequence:
        // orphaned (no such ecosystem), and printed without the raw bytes.
        let name = "\u{1b}[2Kpwned";
        let closure = write_closure(dir, name, name, Some(host().triple()), body);
        let verdicts = judge(dir, &permissive(), &[closure]);
        assert!(!verdicts[0].passes());
        let text = render(dir, &report(permissive(), verdicts), false).unwrap();
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(text.contains("\\u{1b}[2Kpwned  stale"), "{text:?}");
        // The refusal message for a renamed file is quoted the same way.
        let renamed = write_closure(dir, name, "python", Some(host().triple()), python_body(dir));
        let present = inspect::detected(dir).unwrap();
        let error = evaluate(host(), dir, &permissive(), &[], &[renamed], &present).unwrap_err();
        assert!(!error.to_string().contains('\u{1b}'), "{error:?}");
    }

    /// The joined resolution record, as `write_closure` places it in a
    /// closure body: signed on its own, and covered again by the closure
    /// signature. Audit reads its exception list and compares its digests
    /// with the files in `dir`, which it describes as they are now.
    fn resolution(dir: &Path, exceptions: &[Exception]) -> Value {
        let digest = |name: &str| match fs::read(dir.join(name)) {
            Ok(bytes) => record::sha256_hex(&bytes),
            Err(_) => "0".repeat(64),
        };
        json!({
            "schema": "resolution/1",
            "ecosystem": "python",
            "door": "edit",
            "tool": {"name": "uv", "version": "0.9.0"},
            "command": ["add", "six"],
            "outputs": {"requirements.txt": digest("requirements.txt")},
            "inputs": {},
            "ledger": {
                "object": format!("{}-python-1", "2".repeat(40)),
                "portable_sha256": "3".repeat(64),
                "endpoints": ["pypi.org"],
                "entries": 1,
                "refused": 0,
            },
            "isolation": "confined",
            "exceptions": exceptions,
            "signature": {"alg": "ed25519", "key": "4".repeat(64), "sig": "5".repeat(128)},
        })
    }

    fn with_resolution(dir: &Path, body_exceptions: &[Exception], joined: Value) -> ClosureFile {
        let mut body = python_body(dir);
        body["exceptions"] = serde_json::to_value(body_exceptions).unwrap();
        body["resolution"] = joined;
        write_closure(dir, "python", "python", Some(host().triple()), body)
    }

    fn company() -> Policy {
        let template = policy::parse_file(
            Path::new("docs/human/policy-company.toml"),
            include_str!("../../docs/human/policy-company.toml"),
        )
        .unwrap();
        Policy {
            signing: trusting(&[test_key()]),
            ..template
        }
    }

    #[test]
    fn audit_denies_unconfined_resolution_under_company_policy() {
        let temp = python_project("audit-unconfined");
        let finding = exception(policy::UNCONFINED_RESOLUTION, "uv");
        let closures = [with_resolution(
            &temp.0,
            &[],
            resolution(&temp.0, std::slice::from_ref(&finding)),
        )];
        let verdicts = judge(&temp.0, &company(), &closures);
        assert!(!verdicts[0].passes());
        assert_eq!(
            verdicts[0].denied.as_deref().unwrap(),
            vec![finding.clone()]
        );
        // The same finding recorded by the sync and by the record counts once.
        let closures = [with_resolution(
            &temp.0,
            std::slice::from_ref(&finding),
            resolution(&temp.0, std::slice::from_ref(&finding)),
        )];
        let verdicts = judge(&temp.0, &company(), &closures);
        assert_eq!(verdicts[0].denied.as_deref().unwrap(), vec![finding]);
        // Unrecorded locks are denied by the same template.
        let closures = [with_exceptions(
            &temp.0,
            &[exception(policy::UNRECORDED_RESOLUTION, "uv.lock")],
        )];
        let verdicts = judge(&temp.0, &company(), &closures);
        assert!(!verdicts[0].passes());
    }

    /// A closure of an ecosystem the join covers, written before the join
    /// existed, carries neither a record nor `unrecorded-resolution`: that
    /// is missing evidence, not attestation. Either one clears it, and an
    /// ecosystem the join does not cover never needs one.
    #[test]
    fn a_joined_ecosystem_closure_without_resolution_evidence_is_outdated() {
        let temp = TempDir::named("audit-no-evidence");
        let dir = &temp.0;
        let go = |body: Value| write_closure(dir, "go", "go", Some(host().triple()), body);
        // No lock file yet: nothing for a record to cover.
        assert!(!lacks_resolution_evidence(dir, &go(json!({"exceptions": []}))).unwrap());
        fs::write(dir.join("go.mod"), "module example.com/m\n\ngo 1.22\n").unwrap();
        fs::write(dir.join("go.sum"), "").unwrap();
        assert!(lacks_resolution_evidence(dir, &go(json!({"exceptions": []}))).unwrap());
        assert!(lacks_resolution_evidence(dir, &go(json!({}))).unwrap());
        let unrecorded = exception(policy::UNRECORDED_RESOLUTION, "go.sum");
        assert!(!lacks_resolution_evidence(dir, &go(json!({"exceptions": [unrecorded]}))).unwrap());
        assert!(!lacks_resolution_evidence(
            dir,
            &go(json!({"exceptions": [], "resolution": resolution(dir, &[])}))
        )
        .unwrap());
        let python = write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            json!({"exceptions": []}),
        );
        assert!(!lacks_resolution_evidence(dir, &python).unwrap());
    }

    /// A Go record over `dir`'s go.mod and go.sum as they are now.
    fn go_resolution(dir: &Path) -> Value {
        let mut outputs = serde_json::Map::new();
        for name in ["go.mod", "go.sum"] {
            if let Ok(bytes) = fs::read(dir.join(name)) {
                outputs.insert(name.into(), json!(record::sha256_hex(&bytes)));
            }
        }
        let mut joined = resolution(dir, &[]);
        joined["ecosystem"] = json!("go");
        joined["outputs"] = Value::Object(outputs);
        joined
    }

    /// The record a Go closure joined is compared with go.mod and go.sum:
    /// a dependency added to go.mod alone (same `go` directive, same
    /// go.sum) is invisible to the toolchain-input check, and stale here.
    #[test]
    fn a_joined_record_that_no_longer_describes_the_lock_is_stale() {
        let temp = TempDir::named("audit-record-stale");
        let dir = &temp.0;
        fs::write(dir.join("go.mod"), "module example.com/m\n\ngo 1.22\n").unwrap();
        fs::write(dir.join("go.sum"), "").unwrap();
        let go = |joined: Value| {
            write_closure(
                dir,
                "go",
                "go",
                Some(host().triple()),
                json!({"exceptions": [], "resolution": joined}),
            )
        };
        let closure = go(go_resolution(dir));
        assert_eq!(
            inspect::resolution_state(&ProjectRoot::open(dir).unwrap(), &closure),
            None
        );
        fs::write(
            dir.join("go.mod"),
            "module example.com/m\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n",
        )
        .unwrap();
        assert_eq!(
            inspect::resolution_state(&ProjectRoot::open(dir).unwrap(), &closure),
            Some(State::Changed(vec!["go.mod".into()]))
        );
        // A lock file the record never named is a change too.
        fs::remove_file(dir.join("go.sum")).unwrap();
        let closure = go(go_resolution(dir));
        assert_eq!(
            inspect::resolution_state(&ProjectRoot::open(dir).unwrap(), &closure),
            None
        );
        fs::write(dir.join("go.sum"), "golang.org/x/text v0.14.0 h1:x=\n").unwrap();
        assert_eq!(
            inspect::resolution_state(&ProjectRoot::open(dir).unwrap(), &closure),
            Some(State::Changed(vec!["go.sum".into()]))
        );
        // A record whose digests cannot be read is unchecked for this
        // closure alone, not an error for the whole audit.
        let mut broken = go_resolution(dir);
        broken["outputs"] = json!({"go.mod": "not a digest"});
        let Some(State::Unchecked(why)) =
            inspect::resolution_state(&ProjectRoot::open(dir).unwrap(), &go(broken))
        else {
            panic!("a malformed record is unchecked");
        };
        assert!(why.contains("malformed resolution record"), "{why}");
    }

    /// Through the whole gate: a current closure whose joined record names
    /// a file its own freshness check never reads turns stale, with the
    /// refresh hint, once that file changes.
    #[test]
    fn audit_reports_a_stale_joined_record_with_the_refresh_hint() {
        let temp = python_project("audit-record-hint");
        let dir = &temp.0;
        fs::write(dir.join("extra.lock"), "one\n").unwrap();
        let mut joined = resolution(dir, &[]);
        joined["outputs"]["extra.lock"] = json!(record::sha256_hex(b"one\n"));
        let closures = [with_resolution(dir, &[], joined)];
        let verdicts = judge(dir, &permissive(), &closures);
        assert_eq!(verdicts[0].freshness, Freshness::Current);
        fs::write(dir.join("extra.lock"), "two\n").unwrap();
        let verdicts = judge(dir, &permissive(), &closures);
        let Freshness::Stale(why) = &verdicts[0].freshness else {
            panic!("{:?}", verdicts[0].freshness);
        };
        assert!(
            why.starts_with("extra.lock changed since the last sync"),
            "{why}"
        );
        assert!(!verdicts[0].passes());
        let report = Report {
            policy: permissive(),
            sources: Vec::new(),
            verdicts,
            missing: Vec::new(),
            signatures_checked: true,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains("extra.lock changed since the last sync"),
            "{text}"
        );
        assert!(text.contains("run 'tog', then audit again"), "{text}");
        // `tog status` reads the same check and agrees.
        assert_eq!(
            inspect::locked_closure_state(host(), &ProjectRoot::open(dir).unwrap(), &closures[0])
                .unwrap(),
            State::Changed(vec!["extra.lock".into()])
        );
    }

    /// A stale record does not replace an `outdated` verdict and its hint,
    /// and a record that cannot be compared is one closure's verdict, not
    /// an error for the whole audit.
    #[test]
    fn a_stale_record_keeps_an_outdated_verdict_and_a_broken_one_is_per_closure() {
        let temp = python_project("audit-record-precedence");
        let dir = &temp.0;
        fs::write(dir.join("extra.lock"), "one\n").unwrap();
        let mut joined = resolution(dir, &[]);
        joined["outputs"]["extra.lock"] = json!(record::sha256_hex(b"two\n"));
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        body["resolution"] = joined;
        let closures = [write_closure(dir, "python", "python", None, body.clone())];
        let verdicts = judge(dir, &permissive(), &closures);
        let Freshness::Outdated(why) = &verdicts[0].freshness else {
            panic!("{:?}", verdicts[0].freshness);
        };
        assert!(why.contains("records no platform"), "{why}");
        assert!(why.contains("run 'tog' once"), "{why}");
        body["resolution"]["outputs"] = json!({"extra.lock": "not a digest"});
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
        )];
        let verdicts = judge(dir, &permissive(), &closures);
        let Freshness::Outdated(why) = &verdicts[0].freshness else {
            panic!("{:?}", verdicts[0].freshness);
        };
        assert!(why.contains("malformed resolution record"), "{why}");
        assert!(!verdicts[0].passes());
    }

    #[test]
    fn audit_fails_closed_on_an_unknown_resolution_kind() {
        let temp = python_project("audit-resolution-unknown");
        let closures = [with_resolution(
            &temp.0,
            &[],
            resolution(&temp.0, &[exception("kind-from-a-newer-tog", "uv")]),
        )];
        let verdicts = judge(&temp.0, &permissive(), &closures);
        assert!(!verdicts[0].passes());
        assert_eq!(
            verdicts[0].unknown.as_deref().unwrap(),
            vec![exception("kind-from-a-newer-tog", "uv")]
        );
        for broken in [json!("not a record"), json!({"schema": "resolution/1"})] {
            let closures = [with_resolution(&temp.0, &[], broken)];
            let present = inspect::detected(&temp.0).unwrap();
            let error =
                evaluate(host(), &temp.0, &permissive(), &[], &closures, &present).unwrap_err();
            assert!(
                error.to_string().contains("malformed resolution record"),
                "{error}"
            );
        }
    }

    #[test]
    fn closure_readers_accept_the_resolution_field() {
        let temp = python_project("audit-readers");
        let dir = &temp.0;
        let plain = with_exceptions(dir, &[]);
        let plain_state =
            inspect::closure_state(host(), &ProjectRoot::open(dir).unwrap(), &plain).unwrap();
        let store_dir = TempDir::named("audit-readers-store");
        let store = crate::kernel::store::Store::for_test(store_dir.0.clone());
        let plain_root = format!("{:?}", store.root_record_from_project(dir));
        let plain_sbom = format!("{:?}", crate::commands::sbom::generate(dir));
        let joined = with_resolution(
            dir,
            &[],
            resolution(dir, &[exception(policy::UNCONFINED_RESOLUTION, "uv")]),
        );
        assert_eq!(joined.body["resolution"]["door"], "edit");
        assert_eq!(inspect::closures(dir).unwrap().len(), 1);
        assert_eq!(
            inspect::closure_state(host(), &ProjectRoot::open(dir).unwrap(), &joined).unwrap(),
            plain_state
        );
        inspect::status(host(), dir).unwrap();
        inspect::ls(dir, None, false, true).unwrap();
        inspect::ls(dir, None, true, false).unwrap();
        assert_eq!(
            format!("{:?}", crate::commands::sbom::generate(dir)),
            plain_sbom
        );
        assert_eq!(
            format!("{:?}", store.root_record_from_project(dir)),
            plain_root
        );
        let verdicts = judge(dir, &permissive(), &[joined]);
        assert!(verdicts[0].passes(), "{:?}", verdicts[0]);
        assert_eq!(
            verdicts[0]
                .permitted
                .as_ref()
                .unwrap()
                .get(policy::UNCONFINED_RESOLUTION),
            Some(&1)
        );
    }
}

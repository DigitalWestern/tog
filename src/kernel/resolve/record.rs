//! The signed resolution record (kernel layer): the receipt a resolution
//! door leaves in `.tog/resolution/<ecosystem>.json`, how it is built and
//! signed, how a candidate record is judged against the files on disk, and
//! the identity math of the ledger object it names.
//!
//! A record says: this tool, run with this command in this isolation tier,
//! read these inputs, wrote these outputs, and fetched what this ledger
//! lists, with these exceptions. It uses the closure envelope form: the
//! signature covers the canonical bytes of the whole record minus its
//! top-level `signature` field (`kernel::signing`), and `signature.key` is
//! the bare 64-hex public key. It carries no timestamp, port, token,
//! platform, isolation engine, or store object id other than the ledger's,
//! which is portable: the same portable ledger bytes give the same object id
//! on every machine.
//!
//! Judging a candidate runs in a fixed order, and nothing in a record is
//! believed before the step that earns it:
//!
//! 1. authenticate the raw envelope (signature, then the trusted set);
//! 2. read `schema`, `isolation` and every exception `kind` as plain
//!    strings, and refuse outright a value this tog cannot judge, under
//!    every policy, so an older tog never publishes a closure from a newer
//!    record and silently drops a finding it cannot read;
//! 3. parse the typed `resolution/1` shape;
//! 4. check that every path is one the tailor lists, that every existing
//!    listed file is covered, and that every digest matches the disk.

use super::door::{PublishFacts, ReceiptProducer};
use super::ledger::{self, Diagnostics, LedgerObjects, PortableLedger};
use super::{redact, DoorKind};
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::policy::{self, Exception};
use crate::kernel::signing::{self, KeySet, PublicKey, SigningKey, Verification};
use crate::kernel::store::{self, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

/// The one record schema this tog reads and writes.
pub const SCHEMA: &str = "resolution/1";
const SCHEMA_PREFIX: &str = "resolution/";
/// The version segment of every ledger object id (`PortableLedger::identity`).
const LEDGER_ID_VERSION: &str = "1";

pub use super::transaction::{receipt_path, RESOLUTION_DIR};

/// The committed receipt's bytes, read with the strict no-follow walk
/// (`ProjectRoot::read_file`): the receipt is tog state under `.tog`, so a
/// symlink anywhere on its path is refused as tampering rather than read
/// through. `None` when there is no receipt.
pub fn read_receipt(project: &ProjectRoot, ecosystem: &str) -> io::Result<Option<Vec<u8>>> {
    project.read_file(&receipt_path(ecosystem))
}

/// The doors that leave a record. Planner and `x` doors resolve without a
/// project lock to vouch for, so they write none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDoor {
    /// `add`, `remove`, `update`: a manifest edit and its re-lock.
    Edit,
    /// A lock generated because the project had none.
    MissingLock,
    /// `tog attest`: the tool's lock check, which leaves the lock unchanged.
    Attest,
}

impl RecordDoor {
    pub const ALL: [RecordDoor; 3] = [
        RecordDoor::Edit,
        RecordDoor::MissingLock,
        RecordDoor::Attest,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordDoor::Edit => "edit",
            RecordDoor::MissingLock => "missing-lock",
            RecordDoor::Attest => "attest",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|door| door.as_str() == text)
    }
}

/// The isolation tier a door ran in. There are only two: no resolver runs
/// without isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Network fenced to the proxy, plus filesystem isolation.
    Confined,
    /// Filesystem and process isolation under a per-run identity, without a
    /// network fence (`unconfined-resolution`).
    Isolated,
}

impl Isolation {
    pub const ALL: [Isolation; 2] = [Isolation::Confined, Isolation::Isolated];

    pub fn as_str(self) -> &'static str {
        match self {
            Isolation::Confined => "confined",
            Isolation::Isolated => "isolated",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tier| tier.as_str() == text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

/// What the record says about its ledger: portable values only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerSummary {
    /// The ledger's store object id (`PortableLedger::identity`).
    pub object: String,
    /// sha256 of the ledger's portable bytes.
    pub portable_sha256: String,
    /// The permitted endpoints the resolution reached.
    pub endpoints: Vec<String>,
    /// How many portable entries the ledger holds, and how many of them
    /// were refused requests.
    pub entries: u64,
    pub refused: u64,
}

/// One exception the door recorded, as the record carries it. The same
/// three fields as `policy::Exception`, and nothing else: a field this tog
/// does not know makes the record malformed rather than silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedException {
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

/// The typed `resolution/1` record, without its signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRecord {
    pub schema: String,
    pub ecosystem: String,
    pub door: String,
    pub tool: Tool,
    /// The redacted tog verb and operands.
    pub command: Vec<String>,
    /// Project-relative path to sha256, for every file the door published.
    pub outputs: BTreeMap<String, String>,
    /// Project-relative path to sha256, for every resolution input the tool
    /// read but did not write.
    pub inputs: BTreeMap<String, String>,
    pub ledger: LedgerSummary,
    pub isolation: String,
    pub exceptions: Vec<RecordedException>,
}

/// What a door knows when it writes its record.
#[derive(Debug, Clone)]
pub struct RecordFacts {
    pub ecosystem: String,
    pub door: RecordDoor,
    pub tool: Tool,
    pub command: Vec<String>,
    pub outputs: BTreeMap<String, String>,
    pub inputs: BTreeMap<String, String>,
    pub ledger: LedgerSummary,
    pub isolation: Isolation,
    /// The ledger-only exceptions, recorded on the door's thread. Kinds are
    /// canonicalized; exact duplicates are dropped.
    pub exceptions: Vec<Exception>,
}

impl ResolutionRecord {
    /// Build a record from the door's facts. Refuses anything the join
    /// would call malformed, so a door can never sign a record no tog can
    /// attest.
    pub fn new(facts: RecordFacts) -> io::Result<Self> {
        let mut exceptions: Vec<RecordedException> = facts
            .exceptions
            .into_iter()
            .map(|exception| RecordedException {
                kind: policy::canonical_kind(&exception.kind).to_string(),
                subject: exception.subject,
                detail: exception.detail,
            })
            .collect();
        exceptions.sort();
        exceptions.dedup();
        let record = Self {
            schema: SCHEMA.to_string(),
            ecosystem: facts.ecosystem,
            door: facts.door.as_str().to_string(),
            tool: facts.tool,
            command: facts.command,
            outputs: facts.outputs,
            inputs: facts.inputs,
            ledger: facts.ledger,
            isolation: facts.isolation.as_str().to_string(),
            exceptions,
        };
        record.validate().map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("resolution record for {}: {reason}", record.ecosystem),
            )
        })?;
        Ok(record)
    }

    /// The exceptions as `policy` records them.
    pub fn exceptions(&self) -> Vec<Exception> {
        self.exceptions
            .iter()
            .map(|exception| Exception {
                kind: exception.kind.clone(),
                subject: exception.subject.clone(),
                detail: exception.detail.clone(),
            })
            .collect()
    }

    /// The envelope: the record as a JSON object, signed with `key` when
    /// one is loaded. With no key the record has no `signature` field (the
    /// unsigned closure convention): honest, and unattested.
    pub fn envelope(&self, key: Option<&SigningKey>) -> io::Result<Value> {
        let mut envelope = serde_json::to_value(self)?;
        if let Some(key) = key {
            key.sign(&mut envelope)?;
        }
        Ok(envelope)
    }

    /// Every rule the typed shape does not already enforce. The reason names
    /// the field, for the `malformed` detail.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!("schema is {:?}, not {SCHEMA:?}", self.schema));
        }
        if self.ecosystem.is_empty() {
            return Err("ecosystem is empty".into());
        }
        if RecordDoor::parse(&self.door).is_none() {
            return Err(format!(
                "door {:?} is not a door that writes a record",
                self.door
            ));
        }
        if self.tool.name.is_empty() || self.tool.version.is_empty() {
            return Err("tool name or version is empty".into());
        }
        if self.outputs.is_empty() {
            return Err("outputs is empty".into());
        }
        for (field, map) in [("outputs", &self.outputs), ("inputs", &self.inputs)] {
            for (path, digest) in map {
                if !valid_record_path(path) {
                    return Err(format!(
                        "{field} names {path:?}, which is not a plain relative path"
                    ));
                }
                if !is_sha256_hex(digest) {
                    return Err(format!("{field}[{path:?}] is not a sha256"));
                }
            }
        }
        if let Some(path) = self
            .inputs
            .keys()
            .find(|path| self.outputs.contains_key(*path))
        {
            return Err(format!("{path:?} is both an output and an input"));
        }
        self.validate_ledger()?;
        if Isolation::parse(&self.isolation).is_none() {
            return Err(format!("isolation {:?} is not a tier", self.isolation));
        }
        if let Some(exception) = self
            .exceptions
            .iter()
            .find(|exception| !known_kind(&exception.kind))
        {
            return Err(format!("exception kind {:?} is unknown", exception.kind));
        }
        Ok(())
    }

    fn validate_ledger(&self) -> Result<(), String> {
        let ledger = &self.ledger;
        // The id is `ledger_identity`'s: the hash, then the ecosystem and
        // the ledger version, as `Identity::object_id` spells them.
        let suffix = format!("-{}-{LEDGER_ID_VERSION}", id_word(&self.ecosystem));
        if !store::is_object_id(&ledger.object) || !ledger.object.ends_with(&suffix) {
            return Err(format!(
                "ledger object {:?} is not a {} ledger id",
                ledger.object, self.ecosystem
            ));
        }
        if !is_sha256_hex(&ledger.portable_sha256) {
            return Err("ledger portable_sha256 is not a sha256".into());
        }
        if ledger.endpoints.iter().any(String::is_empty) {
            return Err("ledger names an empty endpoint".into());
        }
        if ledger.refused > ledger.entries {
            return Err("ledger refused more requests than it holds".into());
        }
        Ok(())
    }
}

/// The pretty-printed envelope, as the receipt file and `--record-out`
/// hold it.
pub fn envelope_bytes(envelope: &Value) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(envelope)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn known_kind(kind: &str) -> bool {
    policy::KINDS.contains(&policy::canonical_kind(kind))
}

/// The word `Identity::object_id` makes of a name or version.
fn id_word(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A record path: relative, `/`-separated, with no empty, `.` or `..`
/// component and no backslash. One spelling per file, so a path can be
/// compared as a string.
fn valid_record_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// The record spelling of a project-relative path, or `None` for a path
/// that is absolute, climbs with `..`, or is not UTF-8.
pub fn record_path(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::CurDir => {}
            _ => return None,
        }
    }
    let joined = parts.join("/");
    valid_record_path(&joined).then_some(joined)
}

/// The sha256 of each project file in `paths` that exists, keyed by its
/// record path: what a door puts in `outputs` or `inputs`. Files are read as
/// project inputs (`ProjectRoot::read_input`).
pub fn file_digests(
    project: &ProjectRoot,
    paths: &[PathBuf],
) -> io::Result<BTreeMap<String, String>> {
    let mut digests = BTreeMap::new();
    for path in paths {
        let key = record_path(path).ok_or_else(|| not_a_record_path(path))?;
        if project.input_entry(Path::new(&key))? != Entry::Regular {
            continue;
        }
        if let Some(bytes) = project.read_input(Path::new(&key))? {
            digests.insert(key, sha256_hex(&bytes));
        }
    }
    Ok(digests)
}

fn not_a_record_path(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} is not a plain project-relative path; a resolution file must be",
            path.display()
        ),
    )
}

/// The files a tailor names for one ecosystem, relative to the closure's
/// project directory: `outputs` a door would produce (the lock and the
/// manifest), `inputs` the tool reads but does not write (workspace member
/// manifests, tool configuration).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionFiles {
    pub outputs: Vec<PathBuf>,
    pub inputs: Vec<PathBuf>,
}

impl ResolutionFiles {
    /// Both lists in record spelling. A tailor that lists a path no record
    /// could name is a bug, refused rather than skipped.
    fn keys(&self) -> io::Result<(BTreeSet<String>, BTreeSet<String>)> {
        let spell = |paths: &[PathBuf]| -> io::Result<BTreeSet<String>> {
            paths
                .iter()
                .map(|path| record_path(path).ok_or_else(|| not_a_record_path(path)))
                .collect()
        };
        Ok((spell(&self.outputs)?, spell(&self.inputs)?))
    }

    /// The listed outputs that exist in `project`, in record spelling: the
    /// files an `unrecorded-resolution` finding is about.
    pub fn existing_outputs(&self, project: &ProjectRoot) -> io::Result<Vec<String>> {
        let (outputs, _) = self.keys()?;
        Ok(outputs
            .into_iter()
            .filter(|path| project.is_input_file(Path::new(path)))
            .collect())
    }
}

/// Why a candidate record does not attest. The words are the ones the
/// `unrecorded-resolution` detail and the strict remedy print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Missing,
    Unsigned,
    UntrustedKey,
    BadSignature,
    Malformed,
    Incomplete,
    StaleOutputs,
    StaleInputs,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Missing => "missing",
            Reason::Unsigned => "unsigned",
            Reason::UntrustedKey => "untrusted-key",
            Reason::BadSignature => "bad-signature",
            Reason::Malformed => "malformed",
            Reason::Incomplete => "incomplete",
            Reason::StaleOutputs => "stale-outputs",
            Reason::StaleInputs => "stale-inputs",
        }
    }
}

/// A candidate that does not attest: the reason, whether a trusted key had
/// already vouched for it (so the fix is a fresh `tog attest`, not a new
/// key), and what the reason is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub reason: Reason,
    pub authenticated: bool,
    pub detail: Option<String>,
}

impl Finding {
    fn unauthenticated(reason: Reason, detail: Option<String>) -> Self {
        Self {
            reason,
            authenticated: false,
            detail,
        }
    }

    fn authenticated(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            authenticated: true,
            detail: Some(detail.into()),
        }
    }

    /// No candidate at all.
    pub fn missing() -> Self {
        Self::unauthenticated(Reason::Missing, None)
    }

    /// `reason` or `reason (detail)`.
    pub fn describe(&self) -> String {
        match &self.detail {
            Some(detail) => format!("{} ({detail})", self.reason.as_str()),
            None => self.reason.as_str().to_string(),
        }
    }
}

/// A record that attests: its typed form, the envelope exactly as read (what
/// the closure body carries), and the trusted key that signed it.
#[derive(Debug, Clone)]
pub struct Attested {
    pub record: ResolutionRecord,
    pub envelope: Value,
    pub key: PublicKey,
}

#[derive(Debug, Clone)]
pub enum Judgment {
    Attests(Box<Attested>),
    Unrecorded(Finding),
}

/// Judge one candidate record for `ecosystem` in `project`. `origin` names
/// the candidate in a hard failure. `Err` is a hard failure (a value this
/// tog cannot judge in an authenticated record) or an I/O error reading the
/// project; either fails the caller whatever the policy.
pub fn judge(
    origin: &str,
    bytes: &[u8],
    ecosystem: &str,
    trusted: &KeySet,
    files: &ResolutionFiles,
    project: &ProjectRoot,
) -> io::Result<Judgment> {
    let (envelope, key) = match authenticate(bytes, trusted) {
        Ok(authenticated) => authenticated,
        Err(finding) => return Ok(Judgment::Unrecorded(finding)),
    };
    check_vocabulary(origin, &envelope)?;
    let record = match parse_typed(&envelope, ecosystem) {
        Ok(record) => record,
        Err(finding) => return Ok(Judgment::Unrecorded(finding)),
    };
    let (outputs, inputs) = files.keys()?;
    if let Err(finding) = check_listed(&record, &outputs, &inputs) {
        return Ok(Judgment::Unrecorded(finding));
    }
    if let Some(finding) = check_disk(&record, &outputs, &inputs, project)? {
        return Ok(Judgment::Unrecorded(finding));
    }
    Ok(Judgment::Attests(Box::new(Attested {
        record,
        envelope,
        key,
    })))
}

/// Step 1: the raw envelope's signature, then its key against `trusted`.
/// Nothing but `signature` is interpreted here.
fn authenticate(bytes: &[u8], trusted: &KeySet) -> Result<(Value, PublicKey), Finding> {
    let envelope: Value = serde_json::from_slice(bytes).map_err(|error| {
        Finding::unauthenticated(Reason::Malformed, Some(format!("not JSON: {error}")))
    })?;
    if !envelope.is_object() {
        return Err(Finding::unauthenticated(
            Reason::Malformed,
            Some("not a JSON object".into()),
        ));
    }
    match signing::verify(&envelope) {
        Verification::Unsigned => Err(Finding::unauthenticated(Reason::Unsigned, None)),
        Verification::Bad { reason, .. } => {
            Err(Finding::unauthenticated(Reason::BadSignature, Some(reason)))
        }
        Verification::Valid(key) if trusted.contains(&key) => Ok((envelope, key)),
        Verification::Valid(key) => Err(Finding::unauthenticated(
            Reason::UntrustedKey,
            Some(key.to_string()),
        )),
    }
}

/// Step 2: the three vocabularies, read as plain strings from the
/// authenticated object. A value outside them is a hard failure under every
/// policy. A field that is missing or not a string is left to the typed
/// parse, which calls it malformed.
fn check_vocabulary(origin: &str, envelope: &Value) -> io::Result<()> {
    let cannot_read = |what: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{origin}: the resolution record uses {what}, which this tog cannot read; upgrade tog"),
        )
    };
    if let Some(schema) = envelope.get("schema").and_then(Value::as_str) {
        if schema.starts_with(SCHEMA_PREFIX) && schema != SCHEMA {
            return Err(cannot_read(format!("schema `{schema}`")));
        }
    }
    if let Some(tier) = envelope.get("isolation").and_then(Value::as_str) {
        if Isolation::parse(tier).is_none() {
            return Err(cannot_read(format!("isolation tier `{tier}`")));
        }
    }
    let exceptions = envelope.get("exceptions").and_then(Value::as_array);
    for exception in exceptions.into_iter().flatten() {
        if let Some(kind) = exception.get("kind").and_then(Value::as_str) {
            if !known_kind(kind) {
                return Err(cannot_read(format!("exception kind `{kind}`")));
            }
        }
    }
    Ok(())
}

/// Step 3: the typed shape, minus the signature, for `ecosystem`.
fn parse_typed(envelope: &Value, ecosystem: &str) -> Result<ResolutionRecord, Finding> {
    let mut object: Map<String, Value> = envelope.as_object().cloned().unwrap_or_default();
    object.remove("signature");
    let record: ResolutionRecord = serde_json::from_value(Value::Object(object))
        .map_err(|error| Finding::authenticated(Reason::Malformed, error.to_string()))?;
    record
        .validate()
        .map_err(|reason| Finding::authenticated(Reason::Malformed, reason))?;
    if record.ecosystem != ecosystem {
        return Err(Finding::authenticated(
            Reason::Malformed,
            format!("it is a {} record", record.ecosystem),
        ));
    }
    Ok(record)
}

/// Every path the record names must be one the tailor lists.
fn check_listed(
    record: &ResolutionRecord,
    outputs: &BTreeSet<String>,
    inputs: &BTreeSet<String>,
) -> Result<(), Finding> {
    let unlisted = record
        .outputs
        .keys()
        .chain(record.inputs.keys())
        .find(|path| !outputs.contains(*path) && !inputs.contains(*path));
    match unlisted {
        Some(path) => Err(Finding::authenticated(
            Reason::Malformed,
            format!("{path} is not a resolution file of this ecosystem"),
        )),
        None => Ok(()),
    }
}

/// Step 4: coverage, then freshness, against the files in `project`.
fn check_disk(
    record: &ResolutionRecord,
    outputs: &BTreeSet<String>,
    inputs: &BTreeSet<String>,
    project: &ProjectRoot,
) -> io::Result<Option<Finding>> {
    let exists = |path: &str| project.is_input_file(Path::new(path));
    if let Some(path) = outputs
        .iter()
        .find(|path| exists(path) && !record.outputs.contains_key(*path))
    {
        return Ok(Some(Finding::authenticated(
            Reason::Incomplete,
            format!("{path} is not covered"),
        )));
    }
    if let Some(path) = inputs.iter().find(|path| {
        exists(path) && !record.outputs.contains_key(*path) && !record.inputs.contains_key(*path)
    }) {
        return Ok(Some(Finding::authenticated(
            Reason::Incomplete,
            format!("{path} is not covered"),
        )));
    }
    for (map, reason) in [
        (&record.outputs, Reason::StaleOutputs),
        (&record.inputs, Reason::StaleInputs),
    ] {
        for (path, digest) in map {
            let current = if exists(path) {
                project
                    .read_input(Path::new(path))?
                    .map(|bytes| sha256_hex(&bytes))
            } else {
                None
            };
            match current {
                None => {
                    return Ok(Some(Finding::authenticated(
                        reason,
                        format!("{path} no longer exists"),
                    )))
                }
                Some(current) if current != *digest => {
                    return Ok(Some(Finding::authenticated(
                        reason,
                        format!("{path} changed"),
                    )))
                }
                Some(_) => {}
            }
        }
    }
    Ok(None)
}

/// The typed record in `bytes` for `ecosystem`, signature unchecked: for
/// reading the ledger id a receipt names (`tog attest --ledger-export`),
/// which the ledger's own digest then proves.
pub fn parse_unverified(bytes: &[u8], ecosystem: &str) -> Result<ResolutionRecord, String> {
    let envelope: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if !envelope.is_object() {
        return Err("not a JSON object".into());
    }
    parse_typed(&envelope, ecosystem).map_err(|finding| finding.describe())
}

/// What a tailor tells a door about the record its run leaves.
pub struct RecordSpec {
    pub tool: Tool,
    /// The command as it ran; the producer redacts it.
    pub command: Vec<String>,
    /// The tailor's resolution files, which the record's paths must be.
    pub files: ResolutionFiles,
    /// The process signing key. `None` writes the record unsigned, which no
    /// sync attests.
    pub key: Option<Arc<SigningKey>>,
    /// A lock check (`tog attest`): the run must leave every output
    /// byte-unchanged, or nothing is published.
    pub require_unchanged: bool,
    /// Publish the record as the project's receipt. `false` (`tog attest
    /// --record-out`) leaves the held receipt as it was, and the record
    /// goes only to the slot.
    pub publish_receipt: bool,
}

/// Where a producer leaves the record it signed, and its bytes.
pub type RecordSlot = Rc<RefCell<Option<(ResolutionRecord, Vec<u8>)>>>;

/// The receipt producer for a door run: build the record from what the run
/// established, sign it, and hand it to the transaction and to `slot`.
pub fn producer<'a>(spec: RecordSpec, slot: RecordSlot) -> ReceiptProducer<'a> {
    Box::new(move |facts: &PublishFacts<'_>| {
        let record = ResolutionRecord::from_publish(facts, &spec)?;
        let bytes = envelope_bytes(&record.envelope(spec.key.as_deref())?)?;
        let receipt = spec.publish_receipt.then(|| bytes.clone());
        *slot.borrow_mut() = Some((record, bytes));
        Ok(receipt)
    })
}

impl ResolutionRecord {
    /// The record of one confined run. Outputs the run changed carry their
    /// new digests; listed outputs it left alone carry their pre-run ones,
    /// since the record vouches for the whole pair. Inputs carry their
    /// pre-run digests.
    pub fn from_publish(facts: &PublishFacts<'_>, spec: &RecordSpec) -> io::Result<Self> {
        let bad = |why: String| io::Error::new(io::ErrorKind::InvalidInput, why);
        let door = match facts.door {
            DoorKind::Edit => RecordDoor::Edit,
            DoorKind::MissingLock => RecordDoor::MissingLock,
            DoorKind::Attest => RecordDoor::Attest,
            other => {
                return Err(bad(format!(
                    "a {} door leaves no resolution record",
                    other.as_str()
                )))
            }
        };
        let (listed_outputs, _) = spec.files.keys()?;
        let mut changed = BTreeMap::new();
        for file in facts.outputs {
            let key =
                record_path(&file.relative).ok_or_else(|| not_a_record_path(&file.relative))?;
            if !listed_outputs.contains(&key) {
                return Err(bad(format!(
                    "the {} door published {key}, which its tailor does not list as a \
                     resolution output",
                    facts.ecosystem
                )));
            }
            changed.insert(key, hex::encode(file.sha256));
        }
        if spec.require_unchanged && !changed.is_empty() {
            let names: Vec<&str> = changed.keys().map(String::as_str).collect();
            return Err(io::Error::other(format!(
                "{}'s lock check would change {}; the committed files are not what {} accepts, \
                 so nothing is attested (run `tog` to bring them up to date)",
                spec.tool.name,
                names.join(", "),
                spec.tool.name
            )));
        }
        let pre_run = |paths: &[PathBuf]| -> io::Result<BTreeMap<String, String>> {
            let mut digests = BTreeMap::new();
            for path in paths {
                let key = record_path(path).ok_or_else(|| not_a_record_path(path))?;
                if let Some(digest) = facts.input_digest(Path::new(&key)) {
                    digests.insert(key, hex::encode(digest));
                }
            }
            Ok(digests)
        };
        let mut outputs = pre_run(&spec.files.outputs)?;
        outputs.extend(changed);
        if facts.portable.sha256() != facts.ledger_sha256 {
            return Err(io::Error::other(
                "the run's portable ledger does not hash to the digest it was committed under",
            ));
        }
        let isolation = Isolation::parse(facts.isolation).ok_or_else(|| {
            bad(format!(
                "isolation tier {:?} has no record spelling",
                facts.isolation
            ))
        })?;
        ResolutionRecord::new(RecordFacts {
            ecosystem: facts.ecosystem.to_string(),
            door,
            tool: spec.tool.clone(),
            command: redact::command(&spec.command, &[]),
            outputs,
            inputs: pre_run(&spec.files.inputs)?,
            ledger: LedgerSummary::of(&facts.ledger.ledger, facts.portable),
            isolation,
            exceptions: facts
                .exceptions
                .iter()
                .map(|fact| Exception {
                    kind: fact.kind.to_string(),
                    subject: fact.subject.clone(),
                    detail: fact.detail.clone(),
                })
                .collect(),
        })
    }
}

/// sha256 of a ledger's portable bytes: the record's `portable_sha256`.
pub fn portable_sha256(portable: &[u8]) -> String {
    sha256_hex(portable)
}

impl LedgerSummary {
    /// What a record says about `ledger`, committed as `object`: the
    /// distinct upstream origins its entries reached, how many entries it
    /// holds, and how many of them were refused.
    pub fn of(object: &str, ledger: &PortableLedger) -> Self {
        let endpoints: BTreeSet<String> = ledger
            .entries()
            .filter_map(|entry| url::Url::parse(&entry.url).ok())
            .filter_map(|url| {
                let host = url.host_str()?.to_string();
                Some(match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host,
                })
            })
            .collect();
        LedgerSummary {
            object: object.to_string(),
            portable_sha256: ledger.sha256(),
            endpoints: endpoints.into_iter().collect(),
            entries: ledger.len() as u64,
            refused: ledger
                .entries()
                .filter(|entry| entry.class == "refused")
                .count() as u64,
        }
    }
}

/// Do these portable bytes parse as a canonical ledger for the record's
/// ecosystem that hashes to exactly the digest and object id the record
/// names?
pub fn describes_ledger(record: &ResolutionRecord, portable: &[u8]) -> bool {
    let Ok(ledger) = PortableLedger::parse(portable) else {
        return false;
    };
    ledger.ecosystem() == record.ecosystem
        && record.ledger.portable_sha256 == portable_sha256(portable)
        && record.ledger.object == ledger.identity().object_id()
}

/// Is the ledger object `id` complete in the active store? A malformed id is
/// simply absent: a record's id is validated before it gets here, and a
/// closure must not fail on a machine that never had the ledger.
pub fn ledger_present(store: &Store, activity: &StoreActivity, id: &str) -> io::Result<bool> {
    if !store::is_object_id(id) {
        return Ok(false);
    }
    store.has_with_activity(activity, id)
}

/// The portable bytes of the ledger `record` names, from the local store,
/// checked against the record's digest and id before they are returned.
pub fn read_ledger(
    store: &Store,
    activity: &StoreActivity,
    record: &ResolutionRecord,
) -> io::Result<Vec<u8>> {
    let id = &record.ledger.object;
    if !ledger_present(store, activity, id)? {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "the {} ledger {id} is not in the store at {}; export it on the machine that \
                 ran the resolution",
                record.ecosystem,
                store.root.display()
            ),
        ));
    }
    let bytes = ledger::read_portable(store, id)?;
    if !describes_ledger(record, &bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the ledger {id} in the store is not the one the {} record names; the store \
                 object is damaged",
                record.ecosystem
            ),
        ));
    }
    Ok(bytes)
}

/// Commit portable ledger bytes that `record` names, as imported from
/// another machine: the portable object, plus a sidecar that says only that
/// it was imported (the run's diagnostics never leave the machine that ran
/// it). Bytes the record does not name exactly are refused before anything
/// is written.
pub fn commit_ledger(
    store: &Store,
    activity: &StoreActivity,
    record: &ResolutionRecord,
    portable: &[u8],
) -> io::Result<LedgerObjects> {
    if !describes_ledger(record, portable) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "these bytes are not the {} ledger the record names (sha256 {})",
                record.ecosystem,
                portable_sha256(portable)
            ),
        ));
    }
    let ledger = PortableLedger::parse(portable)?;
    let mut diagnostics = Diagnostics::default();
    diagnostics
        .extra
        .insert("imported".to_string(), Value::Bool(true));
    ledger::commit(store, activity, &ledger, &diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::testutil::TempDir;
    use serde_json::json;
    use std::fs;

    const ECO: &str = "resolvetest";

    fn key(label: &str) -> SigningKey {
        let temp = TempDir::named(label);
        let path = temp.0.join("key");
        signing::generate(&path).unwrap();
        SigningKey::load(&path).unwrap()
    }

    fn facts() -> RecordFacts {
        RecordFacts {
            ecosystem: ECO.into(),
            door: RecordDoor::MissingLock,
            tool: Tool {
                name: "testpm".into(),
                version: "2.1.0".into(),
            },
            command: vec!["lock".into()],
            outputs: BTreeMap::from([("test.lock".into(), sha256_hex(b"lock"))]),
            inputs: BTreeMap::from([("test.toml".into(), sha256_hex(b"manifest"))]),
            ledger: LedgerSummary::of(&portable().identity().object_id(), &portable()),
            isolation: Isolation::Isolated,
            exceptions: Vec::new(),
        }
    }

    fn entry(class: &str, url: &str) -> ledger::Entry {
        ledger::Entry {
            class: class.into(),
            method: "GET".into(),
            url: url.into(),
            status: if class == "refused" { 403 } else { 200 },
            sha256: None,
            claimed: None,
            verified: false,
            freshness: None,
        }
    }

    /// Two fetches from one registry and a refused request elsewhere.
    fn portable() -> PortableLedger {
        let mut ledger = PortableLedger::new(ECO, "missing-lock").unwrap();
        ledger.insert(entry("metadata", "https://registry.example/a"));
        ledger.insert(entry("artifact", "https://registry.example/a.tgz"));
        ledger.insert(entry("refused", "https://evil.example:8443/x"));
        ledger
    }

    fn store(label: &str) -> (TempDir, Store) {
        let temp = TempDir::named(&format!("{label}-store"));
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(temp.0.join(sub)).unwrap();
        }
        let store = Store {
            root: temp.0.clone(),
        };
        (temp, store)
    }

    #[test]
    fn record_signature_uses_bare_hex_key_and_verifies() {
        let signer = key("record-bare-hex");
        let envelope = ResolutionRecord::new(facts())
            .unwrap()
            .envelope(Some(&signer))
            .unwrap();
        let named = envelope["signature"]["key"].as_str().unwrap();
        assert_eq!(named.len(), 64);
        assert!(
            named.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{named}"
        );
        match signing::verify(&envelope) {
            Verification::Valid(found) => assert_eq!(found, signer.public_key()),
            _ => panic!("the envelope does not verify"),
        }
    }

    #[test]
    fn unsigned_envelope_has_no_signature_field() {
        let envelope = ResolutionRecord::new(facts())
            .unwrap()
            .envelope(None)
            .unwrap();
        assert!(envelope.get("signature").is_none());
        assert!(matches!(signing::verify(&envelope), Verification::Unsigned));
    }

    #[test]
    fn record_holds_no_timestamp_port_platform_or_engine() {
        let envelope = ResolutionRecord::new(facts())
            .unwrap()
            .envelope(None)
            .unwrap();
        let fields: BTreeSet<&str> = envelope
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "schema",
                "ecosystem",
                "door",
                "tool",
                "command",
                "outputs",
                "inputs",
                "ledger",
                "isolation",
                "exceptions",
            ])
        );
        let ledger: BTreeSet<&str> = envelope["ledger"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            ledger,
            BTreeSet::from([
                "object",
                "portable_sha256",
                "endpoints",
                "entries",
                "refused"
            ])
        );
    }

    #[test]
    fn builder_canonicalizes_sorts_and_dedups_exceptions() {
        let mut input = facts();
        let later = Exception {
            kind: policy::UNCONFINED_RESOLUTION.into(),
            subject: "z".into(),
            detail: "d".into(),
        };
        let earlier = Exception {
            kind: policy::GIT_DEPENDENCY.into(),
            subject: "a".into(),
            detail: "d".into(),
        };
        input.exceptions = vec![later.clone(), earlier.clone(), later.clone()];
        let record = ResolutionRecord::new(input).unwrap();
        assert_eq!(record.exceptions(), vec![earlier, later]);
    }

    #[test]
    fn builder_refuses_what_the_join_would_call_malformed() {
        let cases: Vec<(&str, Box<dyn Fn(&mut RecordFacts)>)> = vec![
            ("outputs is empty", Box::new(|facts| facts.outputs.clear())),
            (
                "not a plain relative path",
                Box::new(|facts| {
                    facts.inputs.insert("../escape".into(), sha256_hex(b"x"));
                }),
            ),
            (
                "not a plain relative path",
                Box::new(|facts| {
                    facts.outputs.insert("/abs.lock".into(), sha256_hex(b"x"));
                }),
            ),
            (
                "is not a sha256",
                Box::new(|facts| {
                    facts.outputs.insert("test.lock".into(), "abc".into());
                }),
            ),
            (
                "both an output and an input",
                Box::new(|facts| {
                    facts.inputs.insert("test.lock".into(), sha256_hex(b"x"));
                }),
            ),
            (
                "is not a resolvetest ledger id",
                Box::new(|facts| {
                    facts.ledger.object = PortableLedger::new("go", "edit")
                        .unwrap()
                        .identity()
                        .object_id()
                }),
            ),
            (
                "refused more requests",
                Box::new(|facts| facts.ledger.refused = 9),
            ),
            (
                "tool name or version is empty",
                Box::new(|facts| facts.tool.version.clear()),
            ),
            (
                "exception kind",
                Box::new(|facts| {
                    facts.exceptions.push(Exception {
                        kind: "quantum-dependency".into(),
                        subject: "x".into(),
                        detail: "y".into(),
                    })
                }),
            ),
        ];
        for (needle, edit) in cases {
            let mut input = facts();
            edit(&mut input);
            let error = ResolutionRecord::new(input).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains(needle), "{needle}: {error}");
        }
    }

    #[test]
    fn record_paths_have_one_spelling() {
        for good in ["go.mod", "sub/go.mod", ".npmrc"] {
            assert!(valid_record_path(good), "{good}");
        }
        for bad in [
            "", "/go.mod", "./go.mod", "a//b", "a/./b", "a/../b", "..", "a\\b", "a\0b",
        ] {
            assert!(!valid_record_path(bad), "{bad:?}");
        }
        assert_eq!(
            record_path(Path::new("sub/go.mod")).as_deref(),
            Some("sub/go.mod")
        );
        assert_eq!(record_path(Path::new("/etc/passwd")), None);
    }

    #[test]
    fn unknown_fields_are_malformed_not_ignored() {
        let mut envelope = ResolutionRecord::new(facts())
            .unwrap()
            .envelope(None)
            .unwrap();
        envelope["waiver"] = json!("trust me");
        let bytes = envelope_bytes(&envelope).unwrap();
        let reason = parse_unverified(&bytes, ECO).unwrap_err();
        assert!(reason.contains("unknown field `waiver`"), "{reason}");
        let mut envelope = ResolutionRecord::new(facts())
            .unwrap()
            .envelope(None)
            .unwrap();
        envelope["ledger"]["cost"] = json!(1);
        let reason = parse_unverified(&envelope_bytes(&envelope).unwrap(), ECO).unwrap_err();
        assert!(reason.contains("unknown field `cost`"), "{reason}");
    }

    #[test]
    fn a_record_for_another_ecosystem_does_not_parse_as_this_one() {
        let bytes = envelope_bytes(
            &ResolutionRecord::new(facts())
                .unwrap()
                .envelope(None)
                .unwrap(),
        )
        .unwrap();
        assert!(parse_unverified(&bytes, ECO).is_ok());
        let reason = parse_unverified(&bytes, "go").unwrap_err();
        assert!(reason.contains("resolvetest"), "{reason}");
    }

    #[test]
    fn ledger_summary_counts_endpoints_entries_and_refusals() {
        let ledger = portable();
        let summary = LedgerSummary::of("id", &ledger);
        assert_eq!(
            summary.endpoints,
            vec![
                "evil.example:8443".to_string(),
                "registry.example".to_string()
            ]
        );
        assert_eq!((summary.entries, summary.refused), (3, 1));
        assert_eq!(summary.portable_sha256, portable_sha256(&ledger.bytes()));
        let identity = ledger.identity();
        assert_eq!(identity.version, LEDGER_ID_VERSION);
        assert!(identity.object_id().ends_with("-resolvetest-1"));
        assert_eq!(identity.object_id(), portable().identity().object_id());
    }

    #[test]
    fn describes_ledger_rejects_mismatched_bytes() {
        let record = ResolutionRecord::new(facts()).unwrap();
        let bytes = portable().bytes();
        assert!(describes_ledger(&record, &bytes));
        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert!(!describes_ledger(&record, &noncanonical));
        let mut other = portable();
        other.insert(entry("metadata", "https://registry.example/b"));
        assert!(!describes_ledger(&record, &other.bytes()));
        let elsewhere = PortableLedger::new("go", "missing-lock").unwrap();
        assert!(!describes_ledger(&record, &elsewhere.bytes()));
    }

    #[test]
    fn read_ledger_names_the_missing_object() {
        let (_temp, store) = store("record-read-missing");
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let record = ResolutionRecord::new(facts()).unwrap();
        let error = read_ledger(&store, &activity, &record).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains(&record.ledger.object), "{error}");
        assert!(!ledger_present(&store, &activity, "../escape").unwrap());
    }

    #[test]
    fn ledger_export_import_round_trips_and_rejects_mismatched_bytes() {
        let (_temp, store, activity) = super::super::testing::scratch_store("record-ledger-trip");
        let record = ResolutionRecord::new(facts()).unwrap();
        let mut other = portable();
        other.insert(entry("metadata", "https://registry.example/b"));
        let error = commit_ledger(&store, &activity, &record, &other.bytes()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!ledger_present(&store, &activity, &other.identity().object_id()).unwrap());
        let objects = commit_ledger(&store, &activity, &record, &portable().bytes()).unwrap();
        assert_eq!(objects.ledger, record.ledger.object);
        let exported = read_ledger(&store, &activity, &record).unwrap();
        assert_eq!(exported, portable().bytes());
        // Importing the exported bytes again is a cache hit on the same id.
        let again = commit_ledger(&store, &activity, &record, &exported).unwrap();
        assert_eq!(again.ledger, objects.ledger);
        let mut wrong = facts();
        wrong.ledger.portable_sha256 = portable_sha256(b"different");
        let mismatched = ResolutionRecord::new(wrong).unwrap();
        let error = read_ledger(&store, &activity, &mismatched).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_symlinked_receipt_is_an_error_not_a_record() {
        let temp = TempDir::named("record-receipt-symlink");
        fs::write(temp.0.join("elsewhere.json"), "{}").unwrap();
        fs::create_dir_all(temp.0.join(RESOLUTION_DIR)).unwrap();
        std::os::unix::fs::symlink(
            temp.0.join("elsewhere.json"),
            temp.0.join(receipt_path(ECO)),
        )
        .unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        assert!(read_receipt(&project, ECO).is_err());
        assert_eq!(read_receipt(&project, "absent").unwrap(), None);
    }
}

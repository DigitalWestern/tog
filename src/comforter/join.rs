//! The resolution join: where the closure writer decides whether the
//! project's lock carries an attesting resolution record, before it claims
//! the attribution.
//!
//! For an ecosystem whose tailor names resolution files (the command layer
//! installs that lookup once per process, `install_resolution_files`), the
//! candidates are every record supplied with `--resolution-record` whose
//! `ecosystem` names this one, in command-line order, then the committed
//! receipt `.tog/resolution/<ecosystem>.json`. Each is judged by
//! `kernel::resolve::record::judge`. The first that attests is joined: the
//! closure body gains `"resolution": <envelope>`, the record's exceptions
//! are recorded into the attribution on the writer's thread, and its ledger
//! is retained only when the object is in the active store. When none
//! attests, `unrecorded-resolution` is recorded with the committed
//! receipt's reason (or `missing`). Recording goes through the policy, so a
//! denied kind refuses publication; the join itself writes nothing into the
//! project, and never touches a receipt.

use crate::comforter::ClosureRefs;
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy::{self, Policy, UNRECORDED_RESOLUTION};
use crate::kernel::resolve::record::{self, Attested, Finding, Judgment, ResolutionFiles};
use crate::kernel::signing::KeySet;
use crate::kernel::store::Store;
use crate::kernel::ui;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The lookup from a closure's ecosystem to its tailor's resolution files.
/// `Ok(None)` means the ecosystem declares no resolvable lock, so there is
/// no join.
pub type ResolutionFilesLookup =
    dyn Fn(&str, &ProjectRoot) -> io::Result<Option<ResolutionFiles>> + Send + Sync;

static LOOKUP: Mutex<Option<Arc<ResolutionFilesLookup>>> = Mutex::new(None);

/// Install the lookup for this process. The command layer calls it once,
/// before any verb that writes a project closure; the first install wins,
/// like the object-kind rows. A process that never installs one (`tog x`,
/// whose closures describe cache roots, not projects) joins nothing.
pub fn install_resolution_files(lookup: Arc<ResolutionFilesLookup>) {
    let mut slot = LOOKUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(lookup);
    }
}

fn lookup() -> Option<Arc<ResolutionFilesLookup>> {
    LOOKUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Replace the lookup. Tests that set one hold `attribution_test_lock`
/// across the set, the writes, and the reset, as every closure-writing test
/// does, so none can observe another's lookup.
#[cfg(test)]
pub(crate) fn set_resolution_files_for_test(lookup: Option<Arc<ResolutionFilesLookup>>) {
    *LOOKUP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = lookup;
}

/// One record handed to this process with `--resolution-record`: evidence
/// only, never written into the project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppliedRecord {
    /// The file it was read from, for messages.
    pub origin: PathBuf,
    /// Its top-level `ecosystem` string.
    pub ecosystem: String,
    pub bytes: Vec<u8>,
}

static SUPPLIED: Mutex<Vec<SuppliedRecord>> = Mutex::new(Vec::new());

/// The largest record file read. A real record is a few kilobytes.
const MAX_RECORD_BYTES: u64 = 16 << 20;

/// Read every `--resolution-record` path, in command-line order: a file is
/// one record, a directory is each `*.json` in it in name order (not
/// recursive). A path that cannot be read, or a file that is not a JSON
/// object with an `ecosystem` string, is an error: the caller pointed at it
/// as evidence, and evidence that silently vanished would read as `missing`.
pub fn read_supplied(paths: &[PathBuf]) -> io::Result<Vec<SuppliedRecord>> {
    let mut records = Vec::new();
    for path in paths {
        let metadata = fs::metadata(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("--resolution-record {}: {error}", path.display()),
            )
        })?;
        if metadata.is_dir() {
            let mut names: Vec<PathBuf> = fs::read_dir(path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<io::Result<_>>()?;
            names.sort();
            for file in names {
                let is_json = file.extension().is_some_and(|ext| ext == "json");
                if is_json && file.is_file() {
                    records.push(read_supplied_file(&file)?);
                }
            }
        } else {
            records.push(read_supplied_file(path)?);
        }
    }
    Ok(records)
}

fn read_supplied_file(path: &Path) -> io::Result<SuppliedRecord> {
    let refuse = |detail: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("--resolution-record {}: {detail}", path.display()),
        )
    };
    let metadata = fs::metadata(path).map_err(|error| refuse(format!("{error}")))?;
    if !metadata.is_file() {
        return Err(refuse("not a regular file".into()));
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return Err(refuse(format!(
            "{} bytes is too large for a record",
            metadata.len()
        )));
    }
    let bytes = fs::read(path).map_err(|error| refuse(format!("{error}")))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|error| refuse(format!("not JSON: {error}")))?;
    let ecosystem = value
        .get("ecosystem")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse("not a resolution record: no ecosystem string".into()))?
        .to_string();
    Ok(SuppliedRecord {
        origin: path.to_path_buf(),
        ecosystem,
        bytes,
    })
}

/// Hand this process's supplied records to every later join. Called once
/// by `tog sync` before it syncs; the records are read now, so a bad path
/// fails before anything is realized.
pub fn supply_records(paths: &[PathBuf]) -> io::Result<()> {
    let records = read_supplied(paths)?;
    *SUPPLIED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = records;
    Ok(())
}

fn supplied_for(ecosystem: &str) -> Vec<SuppliedRecord> {
    SUPPLIED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|record| record.ecosystem == ecosystem)
        .cloned()
        .collect()
}

#[cfg(test)]
pub(crate) fn set_supplied_for_test(records: Vec<SuppliedRecord>) {
    *SUPPLIED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = records;
}

/// The process policy is set once per process, so a unit test that needs a
/// trusting, strict, or denying policy at the closure writer sets one here,
/// under `attribution_test_lock`.
#[cfg(test)]
static POLICY_FOR_TEST: Mutex<Option<Policy>> = Mutex::new(None);

#[cfg(test)]
pub(crate) fn set_policy_for_test(policy: Option<Policy>) {
    *POLICY_FOR_TEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = policy;
}

#[cfg(test)]
fn policy_for_test() -> Option<Policy> {
    POLICY_FOR_TEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(not(test))]
fn policy_for_test() -> Option<Policy> {
    None
}

/// The trusted keys a record's signature is checked against: the policy's
/// effective `[signing]` set (the machine's, narrowed by project files).
/// With no `[signing]` table nobody is trusted, so every signed record is
/// `untrusted-key`.
pub fn trusted_keys(policy: &Policy) -> KeySet {
    policy
        .signing
        .as_ref()
        .map(|signing| signing.trusted.clone())
        .unwrap_or_default()
}

/// Run the join for one closure about to be published. Removes any
/// `resolution` field the producer set (the name belongs to the join), then,
/// when the ecosystem declares resolution files, joins or records. `refs`
/// is `None` only for the test-only legacy writer, which retains nothing.
pub(crate) fn join_for_closure(
    project: &ProjectRoot,
    ecosystem: &str,
    body: &mut Value,
    store: &Store,
    activity: &StoreActivity,
    refs: Option<&mut ClosureRefs>,
) -> io::Result<()> {
    let object = body
        .as_object_mut()
        .expect("the closure writer validated the body object");
    object.remove("resolution");
    let Some(lookup) = lookup() else {
        return Ok(());
    };
    let Some(files) = lookup(ecosystem, project)? else {
        return Ok(());
    };
    let basis = read_basis(object, ecosystem)?;
    let supplied = supplied_for(ecosystem);
    let joined = match policy_for_test() {
        Some(policy) => join(&policy, project, ecosystem, &supplied, &files, &basis)?,
        None => join(
            &policy::effective(),
            project,
            ecosystem,
            &supplied,
            &files,
            &basis,
        )?,
    };
    let Some(attested) = joined else {
        return Ok(());
    };
    let ledger = attested.record.ledger.object.clone();
    object.insert("resolution".into(), attested.envelope);
    if let Some(refs) = refs {
        if record::ledger_present(store, activity, &ledger)? {
            refs.object_id(store, activity, &ledger)?;
        } else {
            ui::trace(&format!(
                "resolution: {ecosystem} ledger {ledger} is not in this store; the closure joins the record without it"
            ));
        }
    }
    Ok(())
}

/// The closure-body field in which a producer names the resolution files
/// its plan read: each file's record path mapped to the sha256 of the exact
/// bytes the plan was built from (a file that did not exist is omitted).
/// Every producer of an ecosystem with resolution files sets it; the join
/// binds the record it joins to these digests, not only to the files on
/// disk, so a closure never carries a record for a lock generation other
/// than the one it was planned from.
pub const BASIS_FIELD: &str = "resolution_basis";

/// Record path to sha256: what a plan read, or what is on disk now.
pub type Digests = BTreeMap<String, String>;

/// The `resolution_basis` value for a closure body.
pub fn basis_value(digests: &Digests) -> Value {
    serde_json::to_value(digests).expect("a string map serializes")
}

/// The producer's `resolution_basis`. A closure of an ecosystem with
/// resolution files that lacks one is a producer bug: without it the join
/// cannot tell which lock generation the closure was planned from.
fn read_basis(object: &serde_json::Map<String, Value>, ecosystem: &str) -> io::Result<Digests> {
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the {ecosystem} closure {why}, so the resolution join cannot bind a record \
                 to the lock files its plan read; this is a tog bug"
            ),
        )
    };
    let value = object
        .get(BASIS_FIELD)
        .ok_or_else(|| refuse(&format!("names no `{BASIS_FIELD}`")))?;
    let digests: Digests = serde_json::from_value(value.clone()).map_err(|_| {
        refuse(&format!(
            "has a `{BASIS_FIELD}` that is not a path-to-digest map"
        ))
    })?;
    if let Some((path, _)) = digests.iter().find(|(path, digest)| {
        record::record_path(Path::new(path)).as_deref() != Some(path.as_str())
            || !record::is_sha256_hex(digest)
    }) {
        return Err(refuse(&format!(
            "has a `{BASIS_FIELD}` entry for {path:?} that is not a record path and a sha256"
        )));
    }
    Ok(digests)
}

/// Refuse a closure whose plan read resolution files that no longer read
/// that way. The closure writer holds the project lock, which every door
/// holds while it publishes, so the files cannot change again before the
/// closure is visible; a difference here means another command (or an
/// editor) changed them after this sync planned, and whatever record now
/// sits beside them describes a lock the closure was not built from.
fn check_basis(
    project: &ProjectRoot,
    ecosystem: &str,
    files: &ResolutionFiles,
    basis: &Digests,
) -> io::Result<()> {
    let mut listed = files.outputs.clone();
    listed.extend(files.inputs.iter().cloned());
    let current = record::file_digests(project, &listed)?;
    let changed = differing(basis, &current);
    if changed.is_empty() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{} changed in {} after this {ecosystem} sync planned from {}; another tog command or \
         an editor wrote {} meanwhile, so nothing was published; run `tog` again",
        changed.join(", "),
        project.path().display(),
        if changed.len() == 1 { "it" } else { "them" },
        if changed.len() == 1 { "it" } else { "them" },
    )))
}

/// The paths whose digests differ between `left` and `right`, including a
/// path only one of them names.
fn differing(left: &Digests, right: &Digests) -> Vec<String> {
    let paths: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
    paths
        .into_iter()
        .filter(|path| left.get(*path) != right.get(*path))
        .cloned()
        .collect()
}

/// The record's own digests must be the plan's: every file the record
/// names at the version the plan read, and every file the plan read named
/// by the record. `judge` already compared the record with the disk, and
/// `check_basis` the disk with the plan, so this holds unless one of those
/// changes meaning; it is checked here so the binding never depends on it.
fn check_record_basis(
    origin: &str,
    ecosystem: &str,
    record: &record::ResolutionRecord,
    basis: &Digests,
) -> io::Result<()> {
    let mut named = record.outputs.clone();
    named.extend(record.inputs.clone());
    let changed = differing(basis, &named);
    if changed.is_empty() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{origin}: the {ecosystem} resolution record describes {} at a different version than \
         this sync planned from; another tog command changed the lock meanwhile, so nothing was \
         published; run `tog` again",
        changed.join(", ")
    )))
}

/// The join proper, with the policy passed in. `basis` is what the
/// closure's plan read (`BASIS_FIELD`): the files must still read that way,
/// and a joined record must describe exactly them. Returns the attested
/// record after recording its exceptions, or `None` after recording
/// `unrecorded-resolution`; `Err` on a hard failure, an I/O error, a lock
/// that changed since the plan, or a refusal by the policy. Nothing is
/// recorded unless every candidate was judged without a hard failure.
pub(crate) fn join(
    policy: &Policy,
    project: &ProjectRoot,
    ecosystem: &str,
    supplied: &[SuppliedRecord],
    files: &ResolutionFiles,
    basis: &Digests,
) -> io::Result<Option<Attested>> {
    check_basis(project, ecosystem, files, basis)?;
    let locks = files.existing_outputs(project)?;
    // Nothing a door would produce exists here, so there is no lock to
    // vouch for and nothing to find.
    if locks.is_empty() {
        return Ok(None);
    }
    let trusted = trusted_keys(policy);
    let mut judged = Vec::new();
    for candidate in supplied {
        let origin = candidate.origin.display().to_string();
        let judgment = record::judge(
            &origin,
            &candidate.bytes,
            ecosystem,
            &trusted,
            files,
            project,
        )?;
        judged.push((Some(candidate.origin.clone()), judgment));
    }
    let receipt_origin = project
        .path()
        .join(record::receipt_path(ecosystem))
        .display()
        .to_string();
    let committed = match record::read_receipt(project, ecosystem)? {
        Some(bytes) => Some(record::judge(
            &receipt_origin,
            &bytes,
            ecosystem,
            &trusted,
            files,
            project,
        )?),
        None => None,
    };
    judged.extend(committed.map(|judgment| (None, judgment)));
    let mut findings = Vec::new();
    for (origin, judgment) in judged {
        match judgment {
            Judgment::Attests(attested) => {
                let shown = origin
                    .as_ref()
                    .map(|origin| origin.display().to_string())
                    .unwrap_or_else(|| receipt_origin.clone());
                check_record_basis(&shown, ecosystem, &attested.record, basis)?;
                let subject = locks.join(", ");
                for exception in attested.record.exceptions() {
                    policy::record_with(
                        policy,
                        &exception.kind,
                        &exception.subject,
                        &exception.detail,
                    )?;
                }
                ui::trace(&format!(
                    "resolution: {subject} attested by a {} record signed by {}",
                    attested.record.door, attested.key
                ));
                return Ok(Some(*attested));
            }
            Judgment::Unrecorded(finding) => findings.push((origin, finding)),
        }
    }
    record_unrecorded(policy, ecosystem, &locks, &findings)?;
    Ok(None)
}

/// Record `unrecorded-resolution`: the committed receipt's reason, or
/// `missing`, with each supplied record's reason after it.
fn record_unrecorded(
    policy: &Policy,
    ecosystem: &str,
    locks: &[String],
    findings: &[(Option<PathBuf>, Finding)],
) -> io::Result<()> {
    let primary = findings
        .iter()
        .find(|(origin, _)| origin.is_none())
        .map(|(_, finding)| finding.clone())
        .unwrap_or_else(Finding::missing);
    let mut detail = primary.describe();
    for (origin, finding) in findings {
        if let Some(origin) = origin {
            detail.push_str(&format!(
                "; supplied {}: {}",
                origin.display(),
                finding.describe()
            ));
        }
    }
    let subject = locks.join(", ");
    let fix = remedy(policy, ecosystem, locks, &primary);
    policy::record_with_fix(policy, UNRECORDED_RESOLUTION, &subject, &detail, Some(&fix))
}

/// What a refusal of `unrecorded-resolution` tells the reader to do. A
/// record whose trusted signature already verified only needs a fresh `tog
/// attest`; anything short of that also needs a key the machine trusts.
/// The last sentence names the knob that refused, as every refusal does.
fn remedy(policy: &Policy, ecosystem: &str, locks: &[String], finding: &Finding) -> String {
    let named: Vec<String> = locks.iter().map(|lock| format!("`{lock}`")).collect();
    let has = if named.len() == 1 { "has" } else { "have" };
    let what = format!(
        "{} {has} none (`{}`)",
        named.join(", "),
        finding.reason.as_str()
    );
    let steps = if finding.authenticated {
        format!(
            "To create one: run `tog attest {ecosystem}` with `TOG_SIGNING_KEY` set to a key \
             your machine policy trusts."
        )
    } else {
        format!(
            "To create one: run `tog keygen <path>`, set `TOG_SIGNING_KEY=<path>`, add the \
             printed public key to the `[signing] trusted` list in your machine policy \
             (`TOG_POLICY`, else `~/.tog/policy.toml`), then run `tog attest {ecosystem}`."
        )
    };
    if policy.strict {
        let lift = match &policy.strict_source {
            Some(source) => source.lift(),
            None => "use a policy that is not strict".to_string(),
        };
        return format!(
            "`tog --strict` requires every lock to carry a signed resolution record. {what}. \
             {steps} Or {lift}."
        );
    }
    let knob = match policy::deny_source(policy, UNRECORDED_RESOLUTION) {
        Some(path) => format!(
            "remove '{UNRECORDED_RESOLUTION}' from the deny list in {} to allow it",
            path.display()
        ),
        None => format!("remove '{UNRECORDED_RESOLUTION}' from the policy deny list to allow it"),
    };
    format!(
        "this policy requires every lock to carry a signed resolution record. {what}. {steps} \
         Or {knob}."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comforter::tests::{complete_object, test_store};
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::policy::{
        Attribution, Exception, Signing, StrictSource, GIT_DEPENDENCY, UNCONFINED_RESOLUTION,
    };
    use crate::kernel::resolve::record::{
        file_digests, Isolation, LedgerSummary, RecordDoor, RecordFacts, ResolutionRecord, Tool,
    };
    use crate::kernel::signing::{self, SigningKey};
    use crate::kernel::testutil::TempDir;
    use serde_json::json;
    use std::sync::OnceLock;

    /// An ecosystem no tailor has, so a concurrent closure write for a real
    /// one never meets this lookup.
    const ECO: &str = "resolvetest";

    fn generated_key(label: &str) -> SigningKey {
        let temp = TempDir::named(label);
        let path = temp.0.join("key");
        signing::generate(&path).unwrap();
        SigningKey::load(&path).unwrap()
    }

    /// The key a CI attest job would hold.
    fn ci_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| generated_key("join-ci-key"))
    }

    /// A key no test policy trusts unless the test says so.
    fn other_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| generated_key("join-other-key"))
    }

    fn trusting(keys: &[&SigningKey]) -> Policy {
        Policy {
            signing: Some(Signing {
                trusted: keys.iter().map(|key| key.public_key()).collect(),
            }),
            ..Policy::default()
        }
    }

    fn strict(mut policy: Policy) -> Policy {
        policy.strict = true;
        policy.strict_source = Some(StrictSource::Flag);
        policy
    }

    /// The lock and manifest a door produces, and the files it reads.
    fn files() -> ResolutionFiles {
        ResolutionFiles {
            outputs: vec!["test.lock".into(), "test.toml".into()],
            inputs: vec!["member/test.toml".into(), ".testrc".into()],
        }
    }

    /// A project with a lock, a manifest, and a workspace member manifest.
    fn project(label: &str) -> TempDir {
        let temp = TempDir::named(label);
        fs::write(temp.0.join("test.toml"), "[deps]\nleft-pad = \"1\"\n").unwrap();
        fs::write(temp.0.join("test.lock"), "left-pad 1.3.0 sha256:ab\n").unwrap();
        fs::create_dir_all(temp.0.join("member")).unwrap();
        fs::write(temp.0.join("member/test.toml"), "[deps]\n").unwrap();
        temp
    }

    fn open(dir: &Path) -> ProjectRoot {
        ProjectRoot::open(dir).unwrap()
    }

    fn ledger(portable: &[u8]) -> LedgerSummary {
        let mut ledger = crate::kernel::resolve::ledger::PortableLedger::new(ECO, "edit").unwrap();
        ledger.insert(crate::kernel::resolve::ledger::Entry {
            class: "metadata".into(),
            method: "GET".into(),
            url: "https://registry.example/left-pad".into(),
            status: 200,
            sha256: Some(record::sha256_hex(portable)),
            claimed: None,
            verified: false,
            freshness: None,
        });
        LedgerSummary::of(&ledger.identity().object_id(), &ledger)
    }

    /// The record a door run in `dir` would write, describing the files as
    /// they are now.
    fn record_for(dir: &Path, exceptions: Vec<Exception>) -> ResolutionRecord {
        let project = open(dir);
        ResolutionRecord::new(RecordFacts {
            ecosystem: ECO.into(),
            door: RecordDoor::Edit,
            tool: Tool {
                name: "testpm".into(),
                version: "1.0.0".into(),
            },
            command: vec!["add".into(), "left-pad".into()],
            outputs: file_digests(&project, &files().outputs).unwrap(),
            inputs: file_digests(&project, &files().inputs).unwrap(),
            ledger: ledger(b"portable ledger"),
            isolation: Isolation::Confined,
            exceptions,
        })
        .unwrap()
    }

    fn signed(record: &ResolutionRecord, key: Option<&SigningKey>) -> Vec<u8> {
        record::envelope_bytes(&record.envelope(key).unwrap()).unwrap()
    }

    /// Sign an envelope that was edited as JSON, the way a newer tog or a
    /// hand would write it.
    fn resigned(mut envelope: Value, key: &SigningKey) -> Vec<u8> {
        key.sign(&mut envelope).unwrap();
        record::envelope_bytes(&envelope).unwrap()
    }

    fn envelope_of(record: &ResolutionRecord) -> Value {
        record.envelope(None).unwrap()
    }

    fn commit_receipt(dir: &Path, bytes: &[u8]) {
        fs::create_dir_all(dir.join(RECEIPT_DIR_FOR_TESTS)).unwrap();
        fs::write(dir.join(record::receipt_path(ECO)), bytes).unwrap();
    }

    const RECEIPT_DIR_FOR_TESTS: &str = record::RESOLUTION_DIR;

    fn supplied(origin: &Path, bytes: Vec<u8>) -> SuppliedRecord {
        SuppliedRecord {
            origin: origin.to_path_buf(),
            ecosystem: ECO.into(),
            bytes,
        }
    }

    /// Run the join in `dir` under `policy` on a frame of its own, and return
    /// the outcome and what it recorded.
    fn run_join(
        policy: &Policy,
        dir: &Path,
        supplied: &[SuppliedRecord],
    ) -> (io::Result<Option<Attested>>, Vec<Exception>) {
        let attribution = Attribution::open(ECO).unwrap();
        let result = join(
            policy,
            &open(dir),
            ECO,
            supplied,
            &files(),
            &disk_basis(dir),
        );
        let recorded = attribution.recorded();
        attribution.discard();
        (result, recorded)
    }

    /// The basis a plan reading `dir` now would record: every listed
    /// resolution file as it is on disk.
    fn disk_basis(dir: &Path) -> Digests {
        let mut listed = files().outputs;
        listed.extend(files().inputs);
        file_digests(&open(dir), &listed).unwrap()
    }

    /// A producer's closure body, planned from `dir` as it is now.
    fn planned_body(dir: &Path, mut body: Value) -> Value {
        body[BASIS_FIELD] = basis_value(&disk_basis(dir));
        body
    }

    fn unrecorded(recorded: &[Exception]) -> &Exception {
        let found: Vec<&Exception> = recorded
            .iter()
            .filter(|exception| exception.kind == UNRECORDED_RESOLUTION)
            .collect();
        assert_eq!(found.len(), 1, "{recorded:?}");
        found[0]
    }

    fn exception(kind: &str, subject: &str) -> Exception {
        Exception {
            kind: kind.into(),
            subject: subject.into(),
            detail: format!("{kind} on {subject}"),
        }
    }

    #[test]
    fn signed_record_joins_when_outputs_match_and_records_its_exceptions() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-match");
        let record = record_for(&temp.0, vec![exception(UNCONFINED_RESOLUTION, "host")]);
        commit_receipt(&temp.0, &signed(&record, Some(ci_key())));
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        let attested = result.unwrap().expect("the record attests");
        assert_eq!(attested.record, record);
        assert_eq!(attested.key, ci_key().public_key());
        assert_eq!(recorded, vec![exception(UNCONFINED_RESOLUTION, "host")]);
    }

    #[test]
    fn deleted_record_yields_unrecorded_resolution() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-deleted");
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        let finding = unrecorded(&recorded);
        assert_eq!(finding.subject, "test.lock, test.toml");
        assert_eq!(finding.detail, "missing");
    }

    #[test]
    fn edited_record_yields_unrecorded_resolution() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-edited");
        let record = record_for(&temp.0, vec![exception(UNCONFINED_RESOLUTION, "host")]);
        let mut envelope: Value = serde_json::from_slice(&signed(&record, Some(ci_key()))).unwrap();
        // Removing the finding a policy would deny breaks the signature.
        envelope["exceptions"] = json!([]);
        commit_receipt(&temp.0, &record::envelope_bytes(&envelope).unwrap());
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert!(unrecorded(&recorded).detail.starts_with("bad-signature"));
        assert_eq!(recorded.len(), 1, "{recorded:?}");
    }

    #[test]
    fn record_signed_by_untrusted_key_yields_unrecorded_resolution() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-untrusted");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(other_key())),
        );
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        let detail = &unrecorded(&recorded).detail;
        assert!(detail.starts_with("untrusted-key"), "{detail}");
        assert!(
            detail.contains(&other_key().public_key().to_string()),
            "{detail}"
        );
    }

    #[test]
    fn unsigned_record_yields_unrecorded_resolution_and_is_kept() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-unsigned");
        let bytes = signed(&record_for(&temp.0, vec![]), None);
        commit_receipt(&temp.0, &bytes);
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert_eq!(unrecorded(&recorded).detail, "unsigned");
        assert_eq!(
            fs::read(temp.0.join(record::receipt_path(ECO))).unwrap(),
            bytes
        );
    }

    #[test]
    fn stale_record_yields_unrecorded_resolution_and_is_left_untouched() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-stale");
        let bytes = signed(&record_for(&temp.0, vec![]), Some(ci_key()));
        commit_receipt(&temp.0, &bytes);
        fs::write(temp.0.join("test.lock"), "left-pad 1.3.1 sha256:cd\n").unwrap();
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert_eq!(
            unrecorded(&recorded).detail,
            "stale-outputs (test.lock changed)"
        );
        assert_eq!(
            fs::read(temp.0.join(record::receipt_path(ECO))).unwrap(),
            bytes
        );
    }

    #[test]
    fn edited_workspace_member_manifest_is_stale_inputs() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-member");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        );
        fs::write(temp.0.join("member/test.toml"), "[deps]\nextra = \"2\"\n").unwrap();
        let (_, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert_eq!(
            unrecorded(&recorded).detail,
            "stale-inputs (member/test.toml changed)"
        );
    }

    #[test]
    fn a_new_input_file_the_record_never_saw_is_incomplete() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-new-input");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        );
        fs::write(temp.0.join(".testrc"), "registry=https://evil.example\n").unwrap();
        let (_, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert_eq!(
            unrecorded(&recorded).detail,
            "incomplete (.testrc is not covered)"
        );
    }

    #[test]
    fn record_not_covering_the_lock_is_unrecorded() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-uncovered");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope["outputs"]
            .as_object_mut()
            .unwrap()
            .remove("test.lock");
        commit_receipt(&temp.0, &resigned(envelope, ci_key()));
        let (_, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert_eq!(
            unrecorded(&recorded).detail,
            "incomplete (test.lock is not covered)"
        );
    }

    #[test]
    fn record_with_empty_outputs_is_malformed() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-empty");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope["outputs"] = json!({});
        commit_receipt(&temp.0, &resigned(envelope, ci_key()));
        let (_, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert_eq!(unrecorded(&recorded).detail, "malformed (outputs is empty)");
    }

    #[test]
    fn record_naming_a_path_outside_the_tailor_lists_is_malformed() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-outside");
        for path in ["notes.txt", "../test.lock", "/etc/passwd", "./test.lock"] {
            let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
            envelope["inputs"][path] = json!(record::sha256_hex(b"x"));
            commit_receipt(&temp.0, &resigned(envelope, ci_key()));
            let (_, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
            let detail = &unrecorded(&recorded).detail;
            assert!(detail.starts_with("malformed ("), "{path}: {detail}");
        }
    }

    #[test]
    fn record_for_another_project_with_the_same_lock_is_unrecorded() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-other-project");
        let bytes = signed(&record_for(&temp.0, vec![]), Some(ci_key()));
        let other = project("join-other-project-b");
        fs::write(
            other.0.join("test.toml"),
            "[deps]\nleft-pad = \"1\"\nx = \"9\"\n",
        )
        .unwrap();
        commit_receipt(&other.0, &bytes);
        let (_, recorded) = run_join(&trusting(&[ci_key()]), &other.0, &[]);
        let detail = &unrecorded(&recorded).detail;
        assert!(
            detail.starts_with("stale-outputs") || detail.starts_with("stale-inputs"),
            "{detail}"
        );
    }

    #[test]
    fn join_hard_fails_an_unknown_exception_kind_under_permissive_policy() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-unknown-kind");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope["exceptions"] =
            json!([{"kind": "quantum-dependency", "subject": "x", "detail": "y"}]);
        commit_receipt(&temp.0, &resigned(envelope, ci_key()));
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains(
                "exception kind `quantum-dependency`, which this tog cannot read; upgrade tog"
            ),
            "{error}"
        );
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn join_hard_fails_an_unsupported_schema_in_an_authenticated_record() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-schema");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope["schema"] = json!("resolution/2");
        commit_receipt(&temp.0, &resigned(envelope, ci_key()));
        let (result, _) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(
                "the resolution record uses schema `resolution/2`, which this tog cannot read; upgrade tog"
            ),
            "{error}"
        );
    }

    #[test]
    fn join_hard_fails_an_unknown_isolation_value_in_an_authenticated_record() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-isolation");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope["isolation"] = json!("none");
        commit_receipt(&temp.0, &resigned(envelope, ci_key()));
        let (result, _) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        let error = result.unwrap_err().to_string();
        assert!(error.contains("isolation tier `none`"), "{error}");
    }

    #[test]
    fn unauthenticated_record_with_an_unknown_schema_is_unrecorded_not_fatal() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-unauth-schema");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope["schema"] = json!("resolution/9");
        envelope["isolation"] = json!("teleported");
        commit_receipt(&temp.0, &resigned(envelope, other_key()));
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert!(unrecorded(&recorded).detail.starts_with("untrusted-key"));
    }

    #[test]
    fn signed_supported_record_missing_a_field_is_malformed_not_fatal() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-missing-field");
        let mut envelope = envelope_of(&record_for(&temp.0, vec![]));
        envelope.as_object_mut().unwrap().remove("tool");
        commit_receipt(&temp.0, &resigned(envelope, ci_key()));
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        let detail = &unrecorded(&recorded).detail;
        assert!(
            detail.starts_with("malformed (missing field `tool`"),
            "{detail}"
        );
    }

    #[test]
    fn unattested_record_exceptions_are_ignored() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-ignored");
        let record = record_for(&temp.0, vec![exception(GIT_DEPENDENCY, "left-pad")]);
        commit_receipt(&temp.0, &signed(&record, Some(other_key())));
        let mut policy = trusting(&[ci_key()]);
        policy.deny.insert(GIT_DEPENDENCY.to_string());
        let (result, recorded) = run_join(&policy, &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].kind, UNRECORDED_RESOLUTION);
    }

    #[test]
    fn company_policy_denies_unrecorded_resolution_under_frozen_sync() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-company");
        let template = policy::parse_file(
            Path::new("docs/human/policy-company.toml"),
            include_str!("../../docs/human/policy-company.toml"),
        )
        .unwrap();
        let mut company = trusting(&[ci_key()]);
        company.deny = template.deny;
        company.deny_sources.insert(
            UNRECORDED_RESOLUTION.into(),
            PathBuf::from("/etc/tog/policy.toml"),
        );
        let (result, recorded) = run_join(&company, &temp.0, &[]);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let message = error.to_string();
        assert!(
            message.starts_with(
                "policy denies unrecorded-resolution: test.lock, test.toml: missing; "
            ),
            "{message}"
        );
        assert!(
            message.contains(&format!("run `tog attest {ECO}`")),
            "{message}"
        );
        assert!(
            message.contains(
                "remove 'unrecorded-resolution' from the deny list in /etc/tog/policy.toml"
            ),
            "{message}"
        );
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn strict_sync_refuses_unrecorded_lock_with_keygen_and_attest_remedy() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-strict-missing");
        let (result, _) = run_join(&strict(trusting(&[ci_key()])), &temp.0, &[]);
        let message = result.unwrap_err().to_string();
        assert_eq!(
            message,
            format!(
                "policy denies unrecorded-resolution: test.lock, test.toml: missing; `tog --strict` \
                 requires every lock to carry a signed resolution record. `test.lock`, `test.toml` \
                 have none (`missing`). To create one: run `tog keygen <path>`, set \
                 `TOG_SIGNING_KEY=<path>`, add the printed public key to the `[signing] trusted` \
                 list in your machine policy (`TOG_POLICY`, else `~/.tog/policy.toml`), then run \
                 `tog attest {ECO}`. Or rerun without --strict."
            )
        );
    }

    #[test]
    fn strict_sync_with_stale_record_says_attest_not_keygen() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-strict-stale");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        );
        fs::write(temp.0.join("test.toml"), "[deps]\n").unwrap();
        let mut policy = strict(trusting(&[ci_key()]));
        policy.strict_source = Some(StrictSource::Env);
        let (result, _) = run_join(&policy, &temp.0, &[]);
        let message = result.unwrap_err().to_string();
        assert!(message.contains("(`stale-outputs`)"), "{message}");
        assert!(
            message.contains(&format!("run `tog attest {ECO}` with")),
            "{message}"
        );
        assert!(!message.contains("tog keygen"), "{message}");
        assert!(message.ends_with("Or unset TOG_STRICT."), "{message}");
    }

    #[test]
    fn developer_key_record_attests_when_trusted() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-dev-trusted");
        let laptop = generated_key("join-laptop");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(&laptop)),
        );
        // A machine policy that trusts both the CI key and this laptop.
        let (result, recorded) = run_join(&trusting(&[ci_key(), &laptop]), &temp.0, &[]);
        assert_eq!(result.unwrap().unwrap().key, laptop.public_key());
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn developer_key_record_is_unrecorded_when_not_trusted() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-dev-untrusted");
        let laptop = generated_key("join-laptop-untrusted");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(&laptop)),
        );
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert!(unrecorded(&recorded).detail.starts_with("untrusted-key"));
    }

    #[test]
    fn ci_record_artifact_attests_through_resolution_record_flag() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-artifact");
        let artifact = TempDir::named("join-artifact-dir");
        fs::write(
            artifact.0.join(format!("{ECO}.json")),
            signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        )
        .unwrap();
        fs::write(artifact.0.join("README"), "not a record").unwrap();
        let supplied = read_supplied(std::slice::from_ref(&artifact.0)).unwrap();
        assert_eq!(supplied.len(), 1, "{supplied:?}");
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &supplied);
        assert!(result.unwrap().is_some());
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn supplied_records_come_first_and_their_reasons_follow_the_committed_one() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-order");
        let stale = signed(&record_for(&temp.0, vec![]), Some(ci_key()));
        fs::write(temp.0.join("test.toml"), "[deps]\nleft-pad = \"2\"\n").unwrap();
        let fresh = signed(&record_for(&temp.0, vec![]), Some(ci_key()));
        commit_receipt(&temp.0, &stale);
        let first = supplied(Path::new("/ci/first.json"), fresh);
        let (result, _) = run_join(&trusting(&[ci_key()]), &temp.0, &[first]);
        assert!(result.unwrap().is_some(), "a fresh supplied record attests");
        let untrusted = signed(&record_for(&temp.0, vec![]), Some(other_key()));
        let second = supplied(Path::new("/ci/second.json"), untrusted);
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[second]);
        assert!(result.unwrap().is_none());
        let detail = &unrecorded(&recorded).detail;
        assert!(detail.starts_with("stale-outputs"), "{detail}");
        assert!(
            detail.contains("; supplied /ci/second.json: untrusted-key"),
            "{detail}"
        );
    }

    #[test]
    fn a_hard_failure_in_any_candidate_fails_even_when_another_attests() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-any-hard");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        );
        let mut newer = envelope_of(&record_for(&temp.0, vec![]));
        newer["schema"] = json!("resolution/2");
        let candidate = supplied(Path::new("/ci/newer.json"), resigned(newer, ci_key()));
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[candidate]);
        assert!(result.unwrap_err().to_string().contains("/ci/newer.json"));
        assert!(recorded.is_empty());
    }

    #[test]
    fn supplied_record_for_another_project_is_incomplete_or_stale() {
        let _attribution = policy::attribution_test_lock();
        let other = project("join-supplied-other");
        fs::write(other.0.join("test.lock"), "other 9.9.9 sha256:ff\n").unwrap();
        let foreign = signed(&record_for(&other.0, vec![]), Some(ci_key()));
        let temp = project("join-supplied-here");
        let candidate = supplied(Path::new("/ci/foreign.json"), foreign);
        let (result, recorded) = run_join(&trusting(&[ci_key()]), &temp.0, &[candidate]);
        assert!(result.unwrap().is_none());
        let detail = &unrecorded(&recorded).detail;
        assert!(
            detail.starts_with("missing; supplied /ci/foreign.json: stale-outputs")
                || detail.starts_with("missing; supplied /ci/foreign.json: incomplete"),
            "{detail}"
        );
    }

    #[test]
    fn committed_record_from_bot_flow_attests_without_flag() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-bot");
        let mut record = record_for(&temp.0, vec![]);
        record.door = RecordDoor::Attest.as_str().into();
        commit_receipt(&temp.0, &signed(&record, Some(ci_key())));
        let (result, _) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        assert_eq!(result.unwrap().unwrap().record.door, "attest");
    }

    #[test]
    fn a_project_without_any_resolution_output_has_nothing_to_judge() {
        let _attribution = policy::attribution_test_lock();
        let temp = TempDir::named("join-no-lock");
        let (result, recorded) = run_join(&strict(trusting(&[ci_key()])), &temp.0, &[]);
        assert!(result.unwrap().is_none());
        assert!(recorded.is_empty());
    }

    #[test]
    fn a_symlinked_receipt_is_refused_as_tampering() {
        let _attribution = policy::attribution_test_lock();
        let temp = project("join-symlink");
        let elsewhere = temp.0.join("elsewhere.json");
        fs::write(
            &elsewhere,
            signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        )
        .unwrap();
        fs::create_dir_all(temp.0.join(record::RESOLUTION_DIR)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join(record::receipt_path(ECO))).unwrap();
        let (result, _) = run_join(&trusting(&[ci_key()]), &temp.0, &[]);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    }

    #[test]
    fn read_supplied_refuses_a_file_that_is_not_a_record() {
        let temp = TempDir::named("join-bad-supplied");
        let path = temp.0.join("go.json");
        fs::write(&path, "[1, 2]").unwrap();
        let error = read_supplied(std::slice::from_ref(&path))
            .unwrap_err()
            .to_string();
        assert!(error.contains("no ecosystem string"), "{error}");
        let missing = temp.0.join("absent.json");
        assert_eq!(
            read_supplied(&[missing]).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    /// Everything the closure writer's side of the join needs: the lookup,
    /// the policy, and the supplied records, reset when the test ends.
    struct Writer {
        _supervision: std::sync::MutexGuard<'static, ()>,
        _attribution: std::sync::MutexGuard<'static, ()>,
    }

    impl Writer {
        fn new(policy: Policy, supplied: Vec<SuppliedRecord>) -> Self {
            let supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let attribution = policy::attribution_test_lock();
            set_resolution_files_for_test(Some(Arc::new(|ecosystem: &str, _: &ProjectRoot| {
                Ok((ecosystem == ECO).then(files))
            })));
            set_policy_for_test(Some(policy));
            set_supplied_for_test(supplied);
            Self {
                _supervision: supervision,
                _attribution: attribution,
            }
        }
    }

    impl Drop for Writer {
        fn drop(&mut self) {
            set_resolution_files_for_test(None);
            set_policy_for_test(None);
            set_supplied_for_test(Vec::new());
        }
    }

    /// An exclusive lease and references naming one installed tool object,
    /// which every published closure needs.
    fn tool_refs(store: &Store) -> (crate::kernel::activity::StoreActivity, ClosureRefs) {
        let tool = complete_object(store, "testpm");
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut refs = ClosureRefs::new();
        refs.object_id(store, &activity, &tool).unwrap();
        (activity, refs)
    }

    /// Publish a `resolvetest` closure for `dir` through the real writer,
    /// planned from the files as they are now.
    fn publish(dir: &Path, store: &Store) -> io::Result<Value> {
        let body = planned_body(dir, json!({"resolution": "a producer may not set this"}));
        publish_planned(dir, store, body)
    }

    /// Publish `body`, planned earlier, for `dir` through the real writer.
    fn publish_planned(dir: &Path, store: &Store, body: Value) -> io::Result<Value> {
        let (activity, refs) = tool_refs(store);
        let mut attribution = Attribution::open(ECO).unwrap();
        let result = crate::comforter::write_closure(
            &open(dir),
            ECO,
            body,
            store,
            &activity,
            refs,
            &mut attribution,
        );
        match result {
            Ok(()) => {
                attribution.finish(true).unwrap();
                let bytes = fs::read(dir.join(format!(".tog/closures/{ECO}.json"))).unwrap();
                Ok(serde_json::from_slice(&bytes).unwrap())
            }
            Err(error) => {
                attribution.discard();
                Err(error)
            }
        }
    }

    fn root_objects(store: &Store, dir: &Path) -> BTreeSet<String> {
        let canonical = dir.canonicalize().unwrap();
        store
            .roots()
            .unwrap()
            .into_iter()
            .find(|entry| entry.path == canonical)
            .and_then(|entry| entry.record)
            .map(|record| record.objects)
            .unwrap_or_default()
    }

    use std::collections::BTreeSet;

    #[test]
    fn signed_record_joins_closure_when_outputs_match() {
        let temp = project("join-writer");
        let record = record_for(&temp.0, vec![exception(UNCONFINED_RESOLUTION, "host")]);
        let bytes = signed(&record, Some(ci_key()));
        commit_receipt(&temp.0, &bytes);
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-writer");
        let closure = publish(&temp.0, &store).unwrap();
        let envelope: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(closure["body"]["resolution"], envelope);
        assert_eq!(
            closure["body"]["exceptions"],
            json!([exception(UNCONFINED_RESOLUTION, "host")])
        );
    }

    #[test]
    fn join_retains_ledger_only_when_present_locally() {
        let temp = project("join-ledger");
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-ledger");
        // An object whose id has a ledger's shape for this ecosystem.
        let present = complete_object(&store, ECO);
        let mut record = record_for(&temp.0, vec![]);
        record.ledger.object = present.clone();
        commit_receipt(&temp.0, &signed(&record, Some(ci_key())));
        let closure = publish(&temp.0, &store).unwrap();
        assert_eq!(
            closure["body"]["resolution"]["ledger"]["object"],
            json!(present)
        );
        assert!(root_objects(&store, &temp.0).contains(&present));

        // The same record on a machine that never had the ledger still
        // joins; nothing is retained for it.
        let fresh = project("join-ledger-fresh");
        let mut record = record_for(&fresh.0, vec![]);
        record.ledger.object = present.clone();
        commit_receipt(&fresh.0, &signed(&record, Some(ci_key())));
        let (_other_dir, other) = test_store("join-ledger-fresh");
        let closure = publish(&fresh.0, &other).unwrap();
        assert_eq!(
            closure["body"]["resolution"]["ledger"]["object"],
            json!(present)
        );
        assert!(!root_objects(&other, &fresh.0).contains(&present));
    }

    #[test]
    fn denied_unrecorded_resolution_leaves_the_checkout_unchanged() {
        let temp = project("join-denied");
        let stale = signed(&record_for(&temp.0, vec![]), Some(other_key()));
        commit_receipt(&temp.0, &stale);
        let _writer = Writer::new(strict(trusting(&[ci_key()])), Vec::new());
        let (_store_dir, store) = test_store("join-denied");
        let error = publish(&temp.0, &store).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(!temp.0.join(".tog/closures").exists());
        assert_eq!(
            fs::read(temp.0.join(record::receipt_path(ECO))).unwrap(),
            stale
        );
        assert!(root_objects(&store, &temp.0).is_empty());
    }

    #[test]
    fn supplied_record_is_never_written_into_the_project() {
        let temp = project("join-supplied-writer");
        let bytes = signed(&record_for(&temp.0, vec![]), Some(ci_key()));
        let candidate = supplied(Path::new("/ci/artifact.json"), bytes.clone());
        let _writer = Writer::new(trusting(&[ci_key()]), vec![candidate]);
        let (_store_dir, store) = test_store("join-supplied-writer");
        let closure = publish(&temp.0, &store).unwrap();
        assert_eq!(
            closure["body"]["resolution"],
            serde_json::from_slice::<Value>(&bytes).unwrap()
        );
        assert!(!temp.0.join(record::RESOLUTION_DIR).exists());
    }

    #[test]
    fn joined_exceptions_are_not_duplicated_by_sync() {
        let temp = project("join-duplicates");
        let fact = exception(GIT_DEPENDENCY, "left-pad");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![fact.clone()]), Some(ci_key())),
        );
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-duplicates");
        let (activity, refs) = tool_refs(&store);
        let mut attribution = Attribution::open(ECO).unwrap();
        // The tailor recorded the same lock fact during its sync.
        policy::record_with(&Policy::default(), &fact.kind, &fact.subject, &fact.detail).unwrap();
        crate::comforter::write_closure(
            &open(&temp.0),
            ECO,
            planned_body(&temp.0, json!({})),
            &store,
            &activity,
            refs,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();
        let closure: Value = serde_json::from_slice(
            &fs::read(temp.0.join(format!(".tog/closures/{ECO}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(closure["body"]["exceptions"], json!([fact]));
    }

    #[test]
    fn an_unjoined_closure_carries_no_resolution_field() {
        let temp = project("join-unrecorded-writer");
        let _writer = Writer::new(Policy::default(), Vec::new());
        let (_store_dir, store) = test_store("join-unrecorded-writer");
        let closure = publish(&temp.0, &store).unwrap();
        assert!(closure["body"].get("resolution").is_none(), "{closure}");
        let exceptions = &closure["body"]["exceptions"];
        assert_eq!(exceptions[0]["kind"], UNRECORDED_RESOLUTION, "{exceptions}");
        assert_eq!(exceptions[0]["detail"], "missing");
    }

    /// Race one: the lock changed after the sync planned and before its
    /// closure was written. The closure would describe the old lock; it is
    /// refused, with a rerun hint, instead of recorded as unrecorded or
    /// joined to anything.
    #[test]
    fn a_lock_changed_after_planning_fails_the_sync_and_publishes_nothing() {
        let temp = project("join-race-edit");
        commit_receipt(
            &temp.0,
            &signed(&record_for(&temp.0, vec![]), Some(ci_key())),
        );
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-race-edit");
        let planned = planned_body(&temp.0, json!({}));
        // A concurrent `tog add` publishes a new lock between the plan and
        // the closure write.
        fs::write(temp.0.join("test.lock"), "left-pad 1.3.1 sha256:cd\n").unwrap();
        let error = publish_planned(&temp.0, &store, planned).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("test.lock changed"), "{message}");
        assert!(message.contains("run `tog` again"), "{message}");
        assert!(!temp.0.join(".tog/closures").exists());
        assert!(root_objects(&store, &temp.0).is_empty());
    }

    /// Race two: another command published a new lock and its matching,
    /// trusted receipt after this sync planned. The receipt attests the
    /// files on disk, but not the plan this closure was built from, so it
    /// is never joined to it.
    #[test]
    fn a_record_published_after_planning_is_never_joined_to_the_old_plan() {
        let temp = project("join-race-receipt");
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-race-receipt");
        let planned = planned_body(&temp.0, json!({}));
        fs::write(
            temp.0.join("test.toml"),
            "[deps]\nleft-pad = \"1\"\nextra = \"2\"\n",
        )
        .unwrap();
        fs::write(temp.0.join("test.lock"), "left-pad 1.3.0\nextra 2.0.0\n").unwrap();
        let fresh = signed(&record_for(&temp.0, vec![]), Some(ci_key()));
        commit_receipt(&temp.0, &fresh);
        let error = publish_planned(&temp.0, &store, planned).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("test.lock, test.toml changed"),
            "{message}"
        );
        assert!(!temp.0.join(".tog/closures").exists());
        // The same record joins a closure planned from the new lock.
        let closure = publish(&temp.0, &store).unwrap();
        assert_eq!(
            closure["body"]["resolution"],
            serde_json::from_slice::<Value>(&fresh).unwrap()
        );
        assert_eq!(
            closure["body"][BASIS_FIELD],
            basis_value(&disk_basis(&temp.0))
        );
    }

    /// The record itself is bound to the plan, not only through the disk:
    /// a record describing any file at another version than the plan read
    /// is refused even when `judge` would let it through.
    #[test]
    fn a_record_that_differs_from_the_plan_is_refused() {
        let temp = project("join-record-basis");
        let record = record_for(&temp.0, vec![]);
        let basis = disk_basis(&temp.0);
        check_record_basis("r", ECO, &record, &basis).unwrap();
        let mut older = basis.clone();
        older.insert("test.lock".into(), "0".repeat(64));
        let error = check_record_basis("r", ECO, &record, &older).unwrap_err();
        assert!(error.to_string().contains("test.lock"), "{error}");
        let mut wider = basis;
        wider.insert(".testrc".into(), "1".repeat(64));
        assert!(check_record_basis("r", ECO, &record, &wider).is_err());
    }

    #[test]
    fn a_closure_without_its_plan_basis_is_refused() {
        let temp = project("join-no-basis");
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-no-basis");
        let error = publish_planned(&temp.0, &store, json!({})).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains(BASIS_FIELD), "{error}");
        let error = publish_planned(
            &temp.0,
            &store,
            json!({BASIS_FIELD: {"../x": "0".repeat(64)}}),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(!temp.0.join(".tog/closures").exists());
    }

    /// The join runs under the project lock that every door's transaction
    /// takes to publish, so no writer can change the lock between the join
    /// and the closure becoming visible.
    #[test]
    fn the_join_runs_under_the_project_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let temp = project("join-locked");
        let _writer = Writer::new(trusting(&[ci_key()]), Vec::new());
        let (_store_dir, store) = test_store("join-locked");
        let root = store.root.clone();
        let blocked = Arc::new(AtomicBool::new(false));
        let waiter: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::default();
        let (seen, handle) = (blocked.clone(), waiter.clone());
        set_resolution_files_for_test(Some(Arc::new(
            move |ecosystem: &str, project: &ProjectRoot| {
                if ecosystem == ECO {
                    let (sender, receiver) = std::sync::mpsc::channel();
                    let store = Store { root: root.clone() };
                    let project = project.try_clone()?;
                    *handle.lock().unwrap() = Some(std::thread::spawn(move || {
                        let lock = store.project_lock_in(&project).unwrap();
                        let _ = sender.send(());
                        drop(lock);
                    }));
                    let timed_out = receiver
                        .recv_timeout(std::time::Duration::from_millis(300))
                        .is_err();
                    seen.store(timed_out, Ordering::SeqCst);
                }
                Ok((ecosystem == ECO).then(files))
            },
        )));
        publish(&temp.0, &store).unwrap();
        waiter.lock().unwrap().take().unwrap().join().unwrap();
        assert!(
            blocked.load(Ordering::SeqCst),
            "another writer took the project lock while the join ran"
        );
    }
}

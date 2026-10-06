//! The resolution ledger: what a door's tool fetched through the proxy, as
//! two store objects.
//!
//! The **portable ledger** (kind `resolution-ledger`) is the evidence: a
//! set of entries `{class, method, url, status, sha256, claimed, verified,
//! freshness}`, with the ecosystem and the door kind. Exact duplicates
//! collapse, and entries sort by their canonical bytes, so the same fetches
//! give the same bytes in any arrival order, however often a tool retried,
//! on any machine, warm cache or cold. Its identity hashes only those
//! bytes, so two machines holding the same evidence compute one object id.
//!
//! The **diagnostics sidecar** (kind `resolution-diagnostics`) holds what
//! varies by run: cache dispositions, arrival order, duplicate and retry
//! counts, byte counts, the engine, the platform, tool object ids, the
//! port, and refusal details. It names its ledger; nothing portable names
//! it. It is found through the index `<store>/resolve/diag/<ledger id>` and
//! never leaves the machine.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::store::{self, ObjectDeps, Store};
use crate::kernel::types::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

pub const LEDGER_KIND: &str = "resolution-ledger";
pub const DIAGNOSTICS_KIND: &str = "resolution-diagnostics";
pub const LEDGER_SCHEMA: &str = "resolution-ledger/1";
pub const DIAGNOSTICS_SCHEMA: &str = "resolution-diagnostics/1";
/// The one file in a ledger object.
pub const PORTABLE_FILE: &str = "portable.json";
/// The one file in a sidecar object.
pub const DIAGNOSTICS_FILE: &str = "diagnostics.json";

/// Whether a served body was fetched just now or is the last copy that was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    Live,
    LastGood,
}

/// One request, as portable evidence. `url` is already redacted.
///
/// Entries describe outcomes: a failed attempt at a request the session
/// also answered is not one (the session drops it).
///
/// `class` is the request class (`index`, `metadata`, `artifact`, `sumdb`,
/// `git` for a git fetch through an intercepted tunnel), `local` for an answer the proxy gave itself, `refused` for a request the
/// proxy would not forward, or `offline-miss` for one it could not serve
/// without the network. `sha256` is the digest of the upstream bytes (never
/// the rewritten body a tool may have been served), present only for a 2xx
/// body or a claimed artifact. `claimed` is the
/// registry's digest (`sha512:<hex>`), and `verified` says the bytes matched
/// it. `freshness` is absent when nothing was served (a refusal, an
/// offline miss, a failure).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub class: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub sha256: Option<String>,
    pub claimed: Option<String>,
    pub verified: bool,
    pub freshness: Option<Freshness>,
    /// Where the answer came from when upstream redirected (the last hop,
    /// redacted): `url` stays what the tool asked for. Absent, and left out
    /// of the bytes, when there was no redirect, so a ledger without one
    /// keeps its bytes and its id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirected_to: Option<String>,
}

impl Entry {
    fn canonical(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("a ledger entry serializes");
        crate::kernel::signing::canonical_bytes(&value).expect("a ledger entry is an object")
    }
}

/// The portable evidence of one door run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableLedger {
    ecosystem: String,
    door: String,
    /// Keyed by each entry's canonical bytes: the set and its order at once.
    entries: BTreeMap<Vec<u8>, Entry>,
}

/// Names that go into an object id and a record: lowercase letters,
/// digits, and `-`.
fn check_name(what: &str, name: &str) -> io::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} {name:?} must be lowercase letters, digits, and -"),
        ));
    }
    Ok(())
}

impl PortableLedger {
    /// An empty ledger for `ecosystem`'s door of kind `door` (`edit`,
    /// `missing-lock`, `planner`, `x`, `attest`).
    pub fn new(ecosystem: &str, door: &str) -> io::Result<Self> {
        check_name("ecosystem", ecosystem)?;
        check_name("door kind", door)?;
        Ok(Self {
            ecosystem: ecosystem.to_string(),
            door: door.to_string(),
            entries: BTreeMap::new(),
        })
    }

    /// Add one entry. Returns false when an identical entry was already in
    /// the set.
    pub fn insert(&mut self, entry: Entry) -> bool {
        self.entries.insert(entry.canonical(), entry).is_none()
    }

    /// Take `entry` out of the set. Returns false when it was not there.
    pub fn remove(&mut self, entry: &Entry) -> bool {
        self.entries.remove(&entry.canonical()).is_some()
    }

    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }

    /// The entries in their canonical order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    // Kept beside `len`, as clippy's len_without_is_empty asks, though
    // nothing calls it yet.
    #[cfg_attr(tog_dead_code, allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The canonical bytes: `kernel::signing`'s canonical JSON of
    /// `{schema, ecosystem, door, entries}`.
    pub fn bytes(&self) -> Vec<u8> {
        let value = json!({
            "schema": LEDGER_SCHEMA,
            "ecosystem": self.ecosystem,
            "door": self.door,
            "entries": self.entries.values().collect::<Vec<_>>(),
        });
        crate::kernel::signing::canonical_bytes(&value).expect("the ledger is an object")
    }

    /// The sha256 of [`Self::bytes`]: the value the signed record carries.
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.bytes()))
    }

    /// Parse portable bytes back, refusing anything that is not exactly
    /// what [`Self::bytes`] writes (an import must re-serialize to the same
    /// digest).
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let bad = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema: String,
            ecosystem: String,
            door: String,
            entries: Vec<Entry>,
        }
        let wire: Wire = serde_json::from_slice(bytes)
            .map_err(|error| bad(format!("portable ledger: {error}")))?;
        if wire.schema != LEDGER_SCHEMA {
            return Err(bad(format!(
                "portable ledger schema {} is not {LEDGER_SCHEMA}",
                wire.schema
            )));
        }
        let mut ledger = PortableLedger::new(&wire.ecosystem, &wire.door)?;
        for entry in wire.entries {
            ledger.insert(entry);
        }
        if ledger.bytes() != bytes {
            return Err(bad(
                "portable ledger bytes are not in canonical form".to_string()
            ));
        }
        Ok(ledger)
    }

    /// The store identity: a pure function of the portable bytes.
    pub fn identity(&self) -> Identity {
        Identity {
            kind: LEDGER_KIND.into(),
            name: self.ecosystem.clone(),
            version: "1".into(),
            inputs: BTreeMap::from([("portable".to_string(), self.sha256())]),
        }
    }
}

/// One request as the diagnostics sidecar sees it, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagRequest {
    pub seq: u64,
    pub class: String,
    pub method: String,
    pub url: String,
    /// What upstream (or the cache) answered.
    pub status: u16,
    /// What the tool was sent, when it differs (a 304 to its own
    /// conditional request).
    pub served_status: u16,
    /// `hit`, `miss`, `revalidated`, `last-good`, `stream`, `local`,
    /// `refused`, `offline-miss`, or `failed`.
    pub disposition: String,
    pub bytes: u64,
    /// The redirect hops followed, redacted.
    pub hops: Vec<String>,
    /// Why a refusal or failure happened.
    pub detail: Option<String>,
}

/// The run-local half of a door's evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostics {
    /// The isolation engine that ran the tool (`bwrap`, `seatbelt`, ...).
    pub engine: Option<String>,
    pub platform: Option<String>,
    /// Store object ids of the tool and what it ran with.
    pub tools: Vec<String>,
    /// The host port the proxy listened on, when it was TCP.
    pub port: Option<u16>,
    pub requests: Vec<DiagRequest>,
    /// Requests whose portable entry was identical to an earlier one.
    pub duplicates: u64,
    /// Requests for a URL already requested, with a different outcome.
    pub retries: u64,
    /// Upstream bytes the tool was sent, in total.
    pub bytes: u64,
    /// Every refusal, in words.
    pub refusals: Vec<String>,
    /// Requests without the session token. They are not the tool's
    /// traffic, so they are rows here and never portable entries.
    pub unauthenticated: u64,
    /// Rows not kept once `requests` reached its cap.
    pub requests_dropped: u64,
    /// Refusal texts not kept once `refusals` reached its cap.
    pub refusals_dropped: u64,
    /// Failed attempts left out of the portable ledger because the same
    /// method and URL was answered in the session (their rows stay here).
    pub superseded: u64,
    /// Further run-local facts a door records (the Linux exec log).
    pub extra: BTreeMap<String, Value>,
}

impl Diagnostics {
    /// The sidecar's bytes: canonical JSON with its schema.
    pub fn bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("diagnostics serialize");
        value["schema"] = json!(DIAGNOSTICS_SCHEMA);
        crate::kernel::signing::canonical_bytes(&value).expect("diagnostics are an object")
    }
}

/// The sidecar's identity: the ledger it describes and its own bytes.
pub fn diagnostics_identity(ledger_id: &str, ecosystem: &str, bytes: &[u8]) -> Identity {
    Identity {
        kind: DIAGNOSTICS_KIND.into(),
        name: ecosystem.to_string(),
        version: "1".into(),
        inputs: BTreeMap::from([
            ("ledger".to_string(), ledger_id.to_string()),
            (
                "diagnostics".to_string(),
                hex::encode(Sha256::digest(bytes)),
            ),
        ]),
    }
}

/// The two objects a door run committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerObjects {
    pub ledger: String,
    pub diagnostics: String,
}

#[cfg(test)]
thread_local! {
    /// The file (`PORTABLE_FILE` or `DIAGNOSTICS_FILE`) whose commit fails on
    /// this thread, for the door's failure tests.
    pub(crate) static COMMIT_FAULT: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Write one file into a fresh stage and commit it under `identity`.
fn commit_file(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
    file: &str,
    bytes: &[u8],
    deps: &ObjectDeps,
) -> io::Result<String> {
    #[cfg(test)]
    if COMMIT_FAULT.with(|fault| fault.get() == Some(file)) {
        return Err(io::Error::other(format!(
            "injected commit failure for {file}"
        )));
    }
    let staged = store.stage_with_activity(activity)?;
    let written = fs::write(staged.join(file), bytes);
    if let Err(error) = written {
        let _ = store::remove_tree(&staged);
        return Err(error);
    }
    store.commit_with_activity_and_deps(activity, identity, &staged, &[], deps)?;
    Ok(identity.object_id())
}

/// Commit the ledger and its sidecar, and point the sidecar index at the
/// sidecar. Committing the same portable evidence again is a cache hit on
/// the ledger.
pub fn commit(
    store: &Store,
    activity: &StoreActivity,
    ledger: &PortableLedger,
    diagnostics: &Diagnostics,
) -> io::Result<LedgerObjects> {
    let ledger_id = commit_file(
        store,
        activity,
        &ledger.identity(),
        PORTABLE_FILE,
        &ledger.bytes(),
        &ObjectDeps::new(),
    )?;
    let bytes = diagnostics.bytes();
    let identity = diagnostics_identity(&ledger_id, ledger.ecosystem(), &bytes);
    let mut deps = ObjectDeps::new();
    deps.object_id(&ledger_id)?;
    let diagnostics_id = commit_file(store, activity, &identity, DIAGNOSTICS_FILE, &bytes, &deps)?;
    write_index(store, &ledger_id, &diagnostics_id)?;
    Ok(LedgerObjects {
        ledger: ledger_id,
        diagnostics: diagnostics_id,
    })
}

/// Root both objects in `project`'s root record, so GC keeps them from the
/// moment they exist.
pub fn root(
    store: &Store,
    activity: &StoreActivity,
    project: &ProjectRoot,
    objects: &LedgerObjects,
) -> io::Result<()> {
    let lock = store.project_lock_in(project)?;
    store.register_root_parts_with_project_lock(
        activity,
        project,
        BTreeSet::from([objects.ledger.clone(), objects.diagnostics.clone()]),
        BTreeSet::new(),
        &lock,
    )?;
    Ok(())
}

/// The portable bytes of a committed ledger, re-verified against its id.
pub fn read_portable(store: &Store, ledger_id: &str) -> io::Result<Vec<u8>> {
    if !store::is_object_id(ledger_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("malformed ledger id {ledger_id:?}"),
        ));
    }
    let bytes = fs::read(store.object_path(ledger_id).join(PORTABLE_FILE))?;
    let ledger = PortableLedger::parse(&bytes)?;
    if ledger.identity().object_id() != ledger_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ledger {ledger_id} does not hash to its own id"),
        ));
    }
    Ok(bytes)
}

const DIAG_INDEX: &str = "resolve/diag";

/// The sidecar recorded for `ledger_id` on this machine, if any.
pub fn diagnostics_for(store: &Store, ledger_id: &str) -> io::Result<Option<String>> {
    if !store::is_object_id(ledger_id) {
        return Ok(None);
    }
    match fs::read_to_string(store.root.join(DIAG_INDEX).join(ledger_id)) {
        Ok(text) => {
            let id = text.trim().to_string();
            Ok(store::is_object_id(&id).then_some(id))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_index(store: &Store, ledger_id: &str, diagnostics_id: &str) -> io::Result<()> {
    store.ensure_namespace(Path::new(DIAG_INDEX))?;
    let tmp =
        store
            .root
            .join("tmp")
            .join(format!("diag-{}-{}", std::process::id(), diagnostics_id));
    fs::write(&tmp, format!("{diagnostics_id}\n"))?;
    fs::rename(&tmp, store.root.join(DIAG_INDEX).join(ledger_id)).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Remove index entries whose sidecar object is gone. Runs under GC's
/// exclusive lease, so no commit races it. Returns how many went.
pub(crate) fn sweep_index(store: &Store, dry_run: bool) -> io::Result<usize> {
    let dir = store.root.join(DIAG_INDEX);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = diagnostics_for(store, &name)?;
        let live = target.is_some_and(|id| store.object_path(&id).is_dir());
        if !live {
            if !dry_run {
                fs::remove_file(entry.path())?;
            }
            removed += 1;
        }
    }
    Ok(removed)
}

/// The kernel's rows for the two kinds, so GC can certify them.
pub(crate) static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: LEDGER_KIND,
        schema: None,
        live_required: &["portable"],
        live_optional: &[],
        live_contract: Some(ledger_contract),
    },
    ObjectKind {
        kind: DIAGNOSTICS_KIND,
        schema: None,
        live_required: &["ledger", "diagnostics"],
        live_optional: &[],
        live_contract: Some(diagnostics_contract),
    },
];

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn ledger_contract(identity: &Identity) -> Result<(), String> {
    let portable = identity.inputs.get("portable").map(String::as_str);
    if !portable.is_some_and(is_sha256_hex) || identity.version != "1" {
        return Err(
            "a resolution ledger identity is version 1 with a sha256 portable input".into(),
        );
    }
    Ok(())
}

fn diagnostics_contract(identity: &Identity) -> Result<(), String> {
    let ledger = identity.inputs.get("ledger").map(String::as_str);
    let digest = identity.inputs.get("diagnostics").map(String::as_str);
    if !ledger.is_some_and(store::is_object_id)
        || !digest.is_some_and(is_sha256_hex)
        || identity.version != "1"
    {
        return Err(
            "a resolution diagnostics identity is version 1 with a ledger object id and a \
             sha256 diagnostics input"
                .into(),
        );
    }
    Ok(())
}

/// One live identity per row, for the object-kind table's tests.
#[cfg(test)]
pub(crate) fn live_identities_for_test() -> Vec<Identity> {
    let ledger = PortableLedger::new("fixture", "edit").unwrap();
    let ledger_id = ledger.identity().object_id();
    vec![
        ledger.identity(),
        diagnostics_identity(&ledger_id, "fixture", &Diagnostics::default().bytes()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::objmeta;
    use crate::kernel::testutil::TempDir;

    fn entry(class: &str, url: &str, status: u16) -> Entry {
        Entry {
            class: class.into(),
            method: "GET".into(),
            url: url.into(),
            status,
            sha256: Some("ab".repeat(32)),
            claimed: None,
            verified: false,
            freshness: Some(Freshness::Live),
            redirected_to: None,
        }
    }

    fn sample() -> PortableLedger {
        let mut ledger = PortableLedger::new("fixture", "edit").unwrap();
        ledger.insert(entry("metadata", "https://registry.test/meta/a.json", 200));
        ledger.insert(Entry {
            claimed: Some(format!("sha512:{}", "cd".repeat(64))),
            verified: true,
            ..entry("artifact", "https://registry.test/art/a-1.0.tgz", 200)
        });
        ledger.insert(Entry {
            freshness: Some(Freshness::LastGood),
            ..entry("index", "https://registry.test/index/a", 200)
        });
        ledger.insert(Entry {
            sha256: None,
            freshness: None,
            ..entry("refused", "https://evil.test", 403)
        });
        ledger
    }

    #[test]
    fn portable_ledger_bytes_are_stable() {
        let text = String::from_utf8(sample().bytes()).unwrap();
        let expected = concat!(
            r#"{"door":"edit","ecosystem":"fixture","entries":["#,
            r#"{"claimed":null,"class":"artifact","freshness":"live","method":"GET","sha256":"abababababababababababababababababababababababababababababababab","status":200,"url":"https://registry.test/art/a-1.0.tgz","verified":true},"#,
            r#"{"claimed":null,"class":"index","freshness":"last-good","method":"GET","sha256":"abababababababababababababababababababababababababababababababab","status":200,"url":"https://registry.test/index/a","verified":false},"#,
            r#"{"claimed":null,"class":"metadata","freshness":"live","method":"GET","sha256":"abababababababababababababababababababababababababababababababab","status":200,"url":"https://registry.test/meta/a.json","verified":false},"#,
            r#"{"claimed":null,"class":"refused","freshness":null,"method":"GET","sha256":null,"status":403,"url":"https://evil.test","verified":false}"#,
            r#"],"schema":"resolution-ledger/1"}"#
        );
        assert_eq!(
            text,
            expected.replace(
                r#"{"claimed":null,"class":"artifact""#,
                &format!(
                    r#"{{"claimed":"sha512:{}","class":"artifact""#,
                    "cd".repeat(64)
                )
            )
        );
        assert_eq!(
            sample().sha256(),
            hex::encode(Sha256::digest(text.as_bytes()))
        );
        assert_eq!(PortableLedger::parse(text.as_bytes()).unwrap(), sample());
    }

    #[test]
    fn portable_ledger_is_independent_of_arrival_order_and_duplicates() {
        let a = sample();
        let mut entries: Vec<Entry> = a.entries().cloned().collect();
        entries.reverse();
        let mut b = PortableLedger::new("fixture", "edit").unwrap();
        for entry in entries.iter().chain(entries.iter()) {
            b.insert(entry.clone());
        }
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.identity().object_id(), b.identity().object_id());
        // A different ecosystem or door kind is different evidence.
        let mut other = PortableLedger::new("fixture", "attest").unwrap();
        for entry in a.entries() {
            other.insert(entry.clone());
        }
        assert_ne!(a.bytes(), other.bytes());
    }

    #[test]
    fn portable_ledger_excludes_cache_state_and_platform() {
        let text = String::from_utf8(sample().bytes()).unwrap();
        for word in [
            "hit",
            "miss",
            "revalidated",
            "disposition",
            "platform",
            "engine",
            "port",
            "seq",
            "bytes",
        ] {
            assert!(
                !text.contains(&format!("\"{word}\"")),
                "portable bytes carry {word}: {text}"
            );
        }
        let fields: BTreeSet<String> = serde_json::from_slice::<Value>(&sample().bytes()).unwrap()
            ["entries"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            fields,
            [
                "class",
                "claimed",
                "freshness",
                "method",
                "sha256",
                "status",
                "url",
                "verified"
            ]
            .iter()
            .map(|s| s.to_string())
            .collect()
        );
    }

    #[test]
    fn resolution_ledger_identity_golden() {
        let identity = sample().identity();
        assert_eq!(
            serde_json::to_string(&identity).unwrap(),
            format!(
                r#"{{"kind":"resolution-ledger","name":"fixture","version":"1","inputs":{{"portable":"{}"}}}}"#,
                sample().sha256()
            )
        );
        assert_eq!(sample().sha256(), GOLDEN_SHA256);
        assert_eq!(identity.object_id(), GOLDEN_ID);
    }

    const GOLDEN_SHA256: &str = "942d35b035d0daf3ee428ee68968667661904a0b051db528fd19bae43d44f73a";
    const GOLDEN_ID: &str = "0bcbf9185aff6a76973cccd1fa26c25ac268b445-fixture-1";

    fn scratch() -> (TempDir, Store, StoreActivity) {
        crate::kernel::resolve::testing::scratch_store("ledger")
    }

    #[test]
    fn ledger_identity_depends_only_on_portable_bytes() {
        let (_temp, store, activity) = scratch();
        let first = Diagnostics {
            engine: Some("bwrap".into()),
            port: Some(40000),
            ..Diagnostics::default()
        };
        let second = Diagnostics {
            engine: Some("seatbelt".into()),
            port: Some(50000),
            duplicates: 3,
            ..Diagnostics::default()
        };
        let a = commit(&store, &activity, &sample(), &first).unwrap();
        let b = commit(&store, &activity, &sample(), &second).unwrap();
        assert_eq!(a.ledger, b.ledger);
        assert_ne!(a.diagnostics, b.diagnostics);
        assert_eq!(a.ledger, sample().identity().object_id());
        // The index names the latest sidecar for the ledger.
        assert_eq!(
            diagnostics_for(&store, &a.ledger).unwrap(),
            Some(b.diagnostics.clone())
        );
        assert_eq!(read_portable(&store, &a.ledger).unwrap(), sample().bytes());
    }

    #[test]
    fn diagnostics_sidecar_is_a_separate_object_never_named_by_the_record() {
        let (_temp, store, activity) = scratch();
        let diagnostics = Diagnostics {
            engine: Some("bwrap".into()),
            ..Diagnostics::default()
        };
        let objects = commit(&store, &activity, &sample(), &diagnostics).unwrap();
        let portable = fs::read(store.object_path(&objects.ledger).join(PORTABLE_FILE)).unwrap();
        let text = String::from_utf8(portable.clone()).unwrap();
        assert!(!text.contains(&objects.diagnostics), "{text}");
        assert!(!text.contains("bwrap"), "{text}");
        // The ledger object holds only the portable bytes.
        let names: Vec<String> = fs::read_dir(store.object_path(&objects.ledger))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [PORTABLE_FILE]);
        // The sidecar names the ledger, and keeps it alive.
        let record = objmeta::read_record_at(
            &store
                .root
                .join("meta")
                .join(format!("{}.json", objects.diagnostics)),
        )
        .unwrap();
        assert_eq!(record.identity.inputs["ledger"], objects.ledger);
        assert!(record.dependencies.contains(&objects.ledger));
        let sidecar = fs::read(
            store
                .object_path(&objects.diagnostics)
                .join(DIAGNOSTICS_FILE),
        )
        .unwrap();
        assert!(String::from_utf8(sidecar).unwrap().contains("bwrap"));
    }

    #[test]
    fn resolution_ledger_kind_is_registered_for_gc() {
        let (_temp, store, activity) = scratch();
        let objects = commit(&store, &activity, &sample(), &Diagnostics::default()).unwrap();
        let (index, unusable) = objmeta::MetaIndex::read_reporting_unusable(&store).unwrap();
        assert!(unusable.is_empty(), "{unusable:?}");
        for id in [&objects.ledger, &objects.diagnostics] {
            let record = index.get(id).unwrap();
            assert_eq!(objmeta::check_identity_grammar(&record.identity), Ok(()));
            // The sidecar's record names the ledger, so GC keeps the pair.
            if record.identity.kind == DIAGNOSTICS_KIND {
                assert!(record.dependencies.contains(&objects.ledger));
            }
        }
        // A malformed identity is refused at publication.
        let mut bad = sample().identity();
        bad.inputs.insert("portable".into(), "not-a-digest".into());
        assert!(objmeta::check_identity_grammar(&bad).is_err());
        let mut extra = sample().identity();
        extra.inputs.insert("platform".into(), "x".into());
        assert!(objmeta::check_identity_grammar(&extra).is_err());
    }

    #[test]
    fn parse_refuses_non_canonical_bytes() {
        let bytes = sample().bytes();
        let mut pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&bytes).unwrap()).unwrap();
        assert!(PortableLedger::parse(&pretty).is_err());
        pretty = bytes.clone();
        pretty.push(b' ');
        assert!(PortableLedger::parse(&pretty).is_err());
        assert!(PortableLedger::new("Fixture", "edit").is_err());
        assert!(PortableLedger::new("fixture", "../x").is_err());
    }
}

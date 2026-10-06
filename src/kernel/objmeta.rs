//! Object metadata: the `object-meta/2` record, its read-only index, and the
//! per-kind identity grammar every publication is checked against.
//!
//! A record says for itself what its object needs: the realization caller
//! supplies the dependency set at commit (`store::ObjectDeps`) and the store
//! writes it down as `evidence: "explicit"`. Nothing here infers a
//! dependency from an identity, and there is no other record format: the
//! store format marker (`store::format`) keeps a store written before
//! `object-meta/2` from being opened at all, so a record this module cannot
//! read is a damaged record, never an old one.
//!
//! Each kind also has a row (`ObjectKind`) describing the identity inputs
//! its producer writes. Debug builds check every commit against its row.

use crate::kernel::fetch::Digest;
use crate::kernel::platform::Platform;
use crate::kernel::store;
use crate::kernel::types::Identity;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::OnceLock;

/// One parsed metadata record. Reading never touches object mtimes.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: String,
    pub identity: Identity,
    /// The objects this one needs, as its producer supplied them at commit.
    pub dependencies: BTreeSet<String>,
    /// The cached artifacts this one was realized from.
    pub cache: BTreeSet<Digest>,
    /// The policy exceptions recorded at commit. A record without the
    /// field carries none: producers that allow nothing write no field.
    pub exceptions: Vec<crate::kernel::policy::Exception>,
}

/// The `schema` input an identity dispatches on, if it wrote one. Every
/// lookup of a (kind, schema) pair goes through this one reader.
pub(crate) fn schema_input_of(identity: &Identity) -> Option<&str> {
    identity.inputs.get("schema").map(String::as_str)
}

/// Parse the platform identity input once for live contracts. A malformed
/// platform is a producer bug even when the row only uses it to choose a
/// conditional input shape.
pub(crate) fn platform_of(identity: &Identity) -> Result<Option<Platform>, String> {
    let Some(value) = identity.inputs.get("platform") else {
        return Ok(None);
    };
    Platform::ALL
        .iter()
        .copied()
        .find(|platform| platform.triple() == value)
        .map(Some)
        .ok_or_else(|| format!("identity has an unparseable platform input {value:?}"))
}

/// A read-only index of every metadata record in the store.
#[derive(Debug, Default, Clone)]
pub struct MetaIndex {
    entries: BTreeMap<String, Record>,
}

impl MetaIndex {
    /// Read every `meta/<id>.json`, skipping the ones that are structurally
    /// unusable and reporting them as `meta file name -> reason`. Purely a
    /// read: no mtime is refreshed and no object directory is opened.
    ///
    /// The sweep and `--drop-object` both have to *talk about* a record
    /// nothing can parse: the sweep refuses, naming every one, and the drop
    /// removes the ones it is given. Neither may treat a skipped record as
    /// absent. A record that cannot be read cannot prove what its object
    /// still needs, so the sweep stops while one exists.
    pub fn read_reporting_unusable(
        store: &store::Store,
    ) -> io::Result<(MetaIndex, BTreeMap<String, String>)> {
        let meta_dir = store.root.join("meta");
        let stat = fs::symlink_metadata(&meta_dir)?;
        if stat.file_type().is_symlink() || !stat.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "meta is not a real directory",
            ));
        }
        let held = store::open_real_directory(&meta_dir, "object metadata directory")?;
        let mut entries = BTreeMap::new();
        let mut unusable = BTreeMap::new();
        for entry in fs::read_dir(&meta_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            match read_record_in(&held, &path) {
                Ok(record) => {
                    entries.insert(record.id.clone(), record);
                }
                // A record whose content is wrong, or that is over the
                // size cap, is one an operator can drop, so it is reported.
                // A read that failed for another reason (a permission, a
                // vanished file, a `meta` that cannot be listed) is not
                // about a record at all, and stops the read.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::InvalidData | io::ErrorKind::FileTooLarge
                    ) =>
                {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    unusable.insert(name, error.to_string());
                }
                Err(error) => return Err(error),
            }
        }
        Ok((MetaIndex { entries }, unusable))
    }

    pub fn get(&self, id: &str) -> Option<&Record> {
        self.entries.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Record)> {
        self.entries.iter()
    }
}

/// Parse and validate one metadata file. Shared by the index and by the
/// sweep reader so a record can never be understood two different ways.
/// The directory is opened as a real one and the file under it, so neither
/// a symlinked `meta/` nor a symlinked record redirects the read.
#[cfg(test)]
pub fn read_record_at(path: &Path) -> io::Result<Record> {
    let (Some(parent), Some(_)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object metadata path {} names no file", path.display()),
        ));
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let dir = store::open_real_directory(parent, "object metadata directory")?;
    read_record_in(&dir, path)
}

/// [`read_record_at`] for a record in `dir`, a held descriptor of the
/// directory `path` is in.
fn read_record_in(dir: &fs::File, path: &Path) -> io::Result<Record> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::io::AsRawFd as _;
    let name = path.file_name().unwrap_or_default();
    read_opened_record(
        store::open_meta_file_at(dir.as_raw_fd(), name.as_bytes())?,
        path,
    )
}

/// The record of `id` in `store`, opened from the store's held `meta/`
/// descriptor.
pub fn read_store_record(store: &store::Store, id: &str) -> io::Result<Record> {
    let (id, value) = read_store_body(store, id)?;
    read_record_value(&id, value)
}

/// The parsed body of `id`'s record in `store`, opened and parsed the way
/// [`read_store_record`] does, before the record's own fields are checked.
fn read_store_body(store: &store::Store, id: &str) -> io::Result<(String, serde_json::Value)> {
    let path = store.root.join("meta").join(format!("{id}.json"));
    read_opened_value(store.open_object_meta(id)?, &path)
}

fn read_opened_record(opened: store::MetaFile, path: &Path) -> io::Result<Record> {
    let (id, value) = read_opened_value(opened, path)?;
    read_record_value(&id, value)
}

/// The id a record's file name gives and the record's parsed body, not yet
/// validated.
fn read_opened_value(
    opened: store::MetaFile,
    path: &Path,
) -> io::Result<(String, serde_json::Value)> {
    let file = match opened {
        store::MetaFile::File(file) => file,
        store::MetaFile::NotRegular => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {} is not a regular file", path.display()),
            ))
        }
        store::MetaFile::Missing => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("object metadata {} is missing", path.display()),
            ))
        }
    };
    let id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata name {} is not UTF-8", path.display()),
            )
        })?
        .to_string();
    if !store::is_object_id(&id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("object metadata id {id:?} is malformed"),
        ));
    }
    // A failed read, or a record over the cap, is a storage problem, not
    // malformed metadata.
    let value = store::read_meta_json(&file)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse object metadata {}: {error}", path.display()),
            )
        })?;
    Ok((id, value))
}

/// Validate an already-parsed record body against its id.
///
/// `object-meta/2` with explicit evidence is the only record there is. One
/// with no schema, another schema or another evidence marker is refused,
/// which is what keeps the sweep closed over it: a record whose
/// dependencies this tog cannot read is never treated as having none.
pub fn read_record_value(id: &str, value: serde_json::Value) -> io::Result<Record> {
    let bad = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    let identity_value = value
        .get("identity")
        .cloned()
        .ok_or_else(|| bad(format!("object {id} metadata has no identity")))?;
    let identity: Identity = serde_json::from_value(identity_value)
        .map_err(|error| bad(format!("object {id} has malformed identity: {error}")))?;
    if identity.kind.is_empty() {
        return Err(bad(format!("object {id} metadata has no identity kind")));
    }
    if identity.object_id() != id {
        return Err(bad(format!(
            "object {id} identity hashes to a different object id"
        )));
    }
    if let Some(stored) = value.get("id") {
        if stored.as_str() != Some(id) {
            return Err(bad(format!("object metadata {id} has a mismatched id")));
        }
    }

    let schema = value
        .get("schema")
        .ok_or_else(|| bad(format!("object {id} metadata has no schema")))?
        .as_str()
        .ok_or_else(|| bad(format!("object {id} has an invalid metadata schema")))?;
    if schema != "object-meta/2" {
        return Err(bad(format!(
            "object {id} has unknown metadata schema {schema}"
        )));
    }
    let mut dependencies = BTreeSet::new();
    for dependency in value
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| bad(format!("object {id} metadata has no explicit dependencies")))?
    {
        let dependency = dependency
            .as_str()
            .ok_or_else(|| bad(format!("object {id} has a non-string dependency")))?;
        if !store::is_object_id(dependency) || !dependencies.insert(dependency.to_string()) {
            return Err(bad(format!(
                "object {id} has a malformed or duplicate dependency {dependency:?}"
            )));
        }
    }
    let mut cache = BTreeSet::new();
    for digest in value
        .get("cache_digests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            bad(format!(
                "object {id} metadata has no explicit cache digests"
            ))
        })?
    {
        let object = digest
            .as_object()
            .ok_or_else(|| bad(format!("object {id} has a malformed cache digest")))?;
        let algo = object
            .get("algo")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| bad(format!("object {id} cache digest has no algorithm")))?;
        let hex = object
            .get("hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| bad(format!("object {id} cache digest has no hex")))?;
        let digest = parse_digest(algo, hex)
            .map_err(|reason| bad(format!("object {id} cache digest: {reason}")))?;
        if !cache.insert(digest) {
            return Err(bad(format!("object {id} has a duplicate cache digest")));
        }
    }
    let evidence = value
        .get("evidence")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad(format!("object {id} metadata has no evidence marker")))?;
    if evidence != "explicit" {
        return Err(bad(format!(
            "object {id} has unknown evidence marker {evidence}"
        )));
    }
    let exceptions = match value.get("exceptions") {
        None => Vec::new(),
        Some(list) => serde_json::from_value(list.clone())
            .map_err(|error| bad(format!("object {id} has malformed exceptions: {error}")))?,
    };
    Ok(Record {
        id: id.to_string(),
        identity,
        dependencies,
        cache,
        exceptions,
    })
}

pub(crate) fn parse_digest(algo: &str, hex: &str) -> Result<Digest, String> {
    if !matches!(algo, "sha1" | "sha256" | "sha512") {
        return Err(format!("unsupported cache algorithm {algo}"));
    }
    Digest::from_parts(algo, hex).map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// Object kinds
//
// One row per (kind, schema) pair a producer writes, naming the identity
// inputs that producer commits. Tailors own their rows
// (`Tailor::object_kinds`); the kernel owns the kinds it realizes itself.
// ---------------------------------------------------------------------------

/// One (kind, schema) pair a producer writes, and the identity inputs it
/// writes for it.
pub struct ObjectKind {
    pub kind: &'static str,
    pub schema: Option<&'static str>,
    /// Inputs required from the producer at every commit.
    pub live_required: &'static [&'static str],
    /// Inputs the producer may add conditionally. Entries ending in `:` are
    /// recognized prefixes, such as `pkg:` for variable package keys.
    pub live_optional: &'static [&'static str],
    /// The full producer-owned identity contract. It runs after the generic
    /// required-name, whitelist, unknown-kind and schema checks.
    pub live_contract: Option<fn(&Identity) -> Result<(), String>>,
}

/// The kernel's own kinds: sources realized by the kernel, not a tailor.
/// The resolution proxy's ledger kinds and the toolchain providers' kinds
/// live beside their producers (`resolve::ledger::KINDS`,
/// `provider::objects::KINDS`) and are chained in by `registered_kinds`.
static KERNEL_KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "git-source",
        schema: Some("git-source/2"),
        live_required: &["schema", "url", "commit"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        // The project files a resolution transaction may replace, copied
        // before the run so a failed or interrupted publication can restore
        // them. `run` makes each transaction's copy its own object; each
        // `target:<i>` names a project-relative path and its `digest:<i>` the
        // sha256 of its bytes, or `absent`.
        kind: "resolution-originals",
        schema: Some("resolution-originals/1"),
        live_required: &["schema", "run"],
        live_optional: &["target:", "digest:"],
        live_contract: None,
    },
];

/// Synthetic objects are useful to kernel and comforter unit tests, but an
/// arbitrary kind must never pass the live publication check. Keep their
/// registration test-only so production can only commit a shipped row.
#[cfg(test)]
static TEST_KINDS: &[ObjectKind] = &[ObjectKind {
    kind: "test",
    schema: None,
    live_required: &[],
    live_optional: &["input"],
    live_contract: None,
}];

/// Every registered row. Kinds whose producer never wrote a `schema` input
/// match only `None`, so an identity that carries an unexpected schema value
/// can never share a row with one that does not.
///
/// The kernel never names a tailor: the layer above installs the tailors'
/// rows once at startup (`tailors::install_kinds`, called by
/// `commands::dispatch`). A kind that was never installed has no row, and
/// publishing it is refused.
fn registered_kinds() -> impl Iterator<Item = &'static ObjectKind> {
    let rows = KERNEL_KINDS
        .iter()
        .chain(crate::kernel::resolve::ledger::KINDS)
        .chain(crate::kernel::provider::objects::KINDS)
        .chain(installed_kinds().iter().copied());
    #[cfg(test)]
    {
        rows.chain(TEST_KINDS.iter())
    }
    #[cfg(not(test))]
    {
        rows
    }
}

fn kind_for(kind: &str, schema: Option<&str>) -> Option<&'static ObjectKind> {
    registered_kinds().find(|row| row.kind == kind && row.schema == schema)
}

static INSTALLED_KINDS: OnceLock<Vec<&'static ObjectKind>> = OnceLock::new();

fn kind_schema_set(rows: &[&'static ObjectKind]) -> BTreeSet<(&'static str, Option<&'static str>)> {
    rows.iter().map(|row| (row.kind, row.schema)).collect()
}

/// Install the object-kind rows the kernel checks beyond its own. The
/// first call wins. A repeated identical installation is a no-op, while a
/// different (kind, schema) set is a programming error.
pub(crate) fn install_kinds(rows: impl IntoIterator<Item = &'static ObjectKind>) {
    let rows: Vec<_> = rows.into_iter().collect();
    let installed = INSTALLED_KINDS.get_or_init(|| rows.clone());
    let installed_pairs = kind_schema_set(installed);
    let new_pairs = kind_schema_set(&rows);
    if installed_pairs != new_pairs {
        panic!(
            "object-kind rows already installed with a different (kind, schema) set: installed={installed_pairs:?}, new={new_pairs:?}"
        );
    }
}

fn installed_kinds() -> &'static [&'static ObjectKind] {
    #[cfg(test)]
    tests::install_shipped_kinds();
    INSTALLED_KINDS.get().map(Vec::as_slice).unwrap_or(&[])
}

/// Enforce a row's grammar: every required input present, and no input the
/// row does not list. Optional entries may be exact keys or dynamic
/// prefixes.
fn enforce_live_grammar(identity: &Identity, row: &ObjectKind) -> Result<(), String> {
    let inputs = &identity.inputs;
    for key in row.live_required {
        if !inputs.contains_key(*key) {
            return Err(format!(
                "identity has no live-required {key} input; the current producer writes it on every commit"
            ));
        }
    }
    for key in inputs.keys() {
        let allowed = row.live_required.contains(&key.as_str())
            || row.live_optional.contains(&key.as_str())
            || row
                .live_optional
                .iter()
                .any(|prefix| prefix.ends_with(':') && key.starts_with(prefix));
        if !allowed {
            return Err(format!(
                "unrecognized live identity input {key}; the current producer's live grammar does not write it"
            ));
        }
    }
    platform_of(identity)?;
    Ok(())
}

/// Check a *live* identity against its producer's grammar row.
///
/// Each row describes what its producer builds today. The row is checked at
/// commit time so that a producer which starts writing a new input, or stops
/// writing a required one, fails its first commit: a dropped input such as
/// `artifact_sha256` would otherwise let distinct artifacts share an object
/// id, and nothing would notice.
///
/// A kind absent from every row is refused, so a producer cannot commit a
/// misspelled kind such as `cpythno` that has no grammar at all.
pub(crate) fn check_identity_grammar(identity: &Identity) -> Result<(), String> {
    let schema = schema_input_of(identity);
    match kind_for(&identity.kind, schema) {
        Some(row) => {
            enforce_live_grammar(identity, row)?;
            if let Some(contract) = row.live_contract {
                contract(identity)?;
            }
            Ok(())
        }
        None => {
            let rows: Vec<&ObjectKind> = registered_kinds()
                .filter(|row| row.kind == identity.kind)
                .collect();
            if !rows.is_empty() {
                let schemas: Vec<Option<&str>> = rows.iter().map(|row| row.schema).collect();
                return Err(format!(
                    "identity kind {} has schema {:?}, but its grammar rows list schemas {:?}",
                    identity.kind, schema, schemas
                ));
            }
            Err(format!(
                "identity kind {} has no registered object-kind grammar row",
                identity.kind
            ))
        }
    }
}

#[cfg(test)]
pub(crate) fn register_test_kinds() {
    tests::register_test_kinds();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;

    /// Unit tests never pass through `commands::dispatch`, so the shipped
    /// table is installed on first use. The non-test kernel names no tailor
    /// (tests/architecture.rs checks that).
    pub(super) fn install_shipped_kinds() {
        crate::tailors::install_kinds();
    }

    /// Register the synthetic kind used by kernel and comforter unit tests.
    /// `TEST_KINDS` is included by `registered_kinds` only in test builds.
    pub(crate) fn register_test_kinds() {
        install_shipped_kinds();
    }

    fn ident(kind: &str, name: &str, version: &str, inputs: &[(&str, &str)]) -> Identity {
        Identity {
            kind: kind.into(),
            name: name.into(),
            version: version.into(),
            inputs: inputs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn hex(byte: char, len: usize) -> String {
        std::iter::repeat_n(byte, len).collect()
    }

    fn sha256(byte: char) -> String {
        hex(byte, 64)
    }

    fn sha1(byte: char) -> String {
        hex(byte, 40)
    }

    // -- commit-time grammar drift -------------------------------------------

    /// A producer that drifts from its row fails at the commit that drifts.
    #[test]
    fn commit_time_grammar_check_matches_the_listed_row() {
        let good = ident(
            "git-source",
            "example",
            "abc123",
            &[
                ("schema", "git-source/2"),
                ("url", "https://example.invalid/repo.git"),
                ("commit", &sha1('c')),
            ],
        );
        assert_eq!(check_identity_grammar(&good), Ok(()));

        let mut missing = good.clone();
        missing.inputs.remove("commit");
        let reason = check_identity_grammar(&missing).unwrap_err();
        assert!(reason.contains("commit"), "{reason}");

        let mut extra = good.clone();
        extra.inputs.insert("depth".to_string(), "1".to_string());
        let reason = check_identity_grammar(&extra).unwrap_err();
        assert!(reason.contains("depth"), "{reason}");
    }

    #[test]
    fn commit_time_grammar_check_rejects_schema_drift() {
        let mut schema_removed = ident(
            "git-source",
            "example",
            "abc123",
            &[
                ("schema", "git-source/2"),
                ("url", "https://example.invalid/repo.git"),
                ("commit", &sha1('c')),
            ],
        );
        schema_removed.inputs.remove("schema");
        let reason = check_identity_grammar(&schema_removed).unwrap_err();
        assert!(reason.contains("git-source"), "{reason}");
        assert!(reason.contains("None"), "{reason}");
        assert!(reason.contains("git-source/2"), "{reason}");

        let schemaless_with_schema = ident(
            "cpython",
            "cpython",
            "3.12.14",
            &[
                ("artifact_sha256", &sha256('a')),
                ("platform", "x86_64-unknown-linux-gnu"),
                ("schema", "cpython/1"),
            ],
        );
        let reason = check_identity_grammar(&schemaless_with_schema).unwrap_err();
        assert!(reason.contains("cpython"), "{reason}");
        assert!(reason.contains("Some(\"cpython/1\")"), "{reason}");
        assert!(reason.contains("None"), "{reason}");

        // A kind absent from every row is rejected at commit time, with or
        // without a schema, including after the shipped tailor rows have
        // been installed.
        for inputs in [[("schema", "future/1")], [("anything", "goes")]] {
            let unknown = ident("not-a-shipped-kind", "x", "1", &inputs);
            let reason = check_identity_grammar(&unknown).unwrap_err();
            assert!(
                reason.contains("no registered object-kind grammar row"),
                "{inputs:?}: {reason}"
            );
        }
    }

    #[test]
    fn every_row_rejects_each_missing_live_required_input() {
        register_test_kinds();
        for platform in [
            Platform::X86_64UnknownLinuxGnu,
            Platform::Aarch64AppleDarwin,
        ] {
            let cases = live_identity_cases(platform);
            for row in registered_kinds() {
                // `test` exists only to support unrelated kernel and
                // comforter unit tests. It has no real producer constructor.
                if row.kind == "test" {
                    continue;
                }
                // The native-library producer has no Darwin pin and refuses
                // before constructing an identity on that platform.
                if row.kind == "native-libs" && platform.is_macos() {
                    continue;
                }
                let row_cases: Vec<_> = cases
                    .iter()
                    .filter(|identity| {
                        identity.kind == row.kind && schema_input_of(identity) == row.schema
                    })
                    .collect();
                assert!(
                    !row_cases.is_empty(),
                    "no real producer identity for {}, {:?}, {}",
                    row.kind,
                    row.schema,
                    platform.triple()
                );
                for identity in row_cases {
                    assert_eq!(
                        check_identity_grammar(identity),
                        Ok(()),
                        "real producer identity rejected for {}, {:?}, {}",
                        row.kind,
                        row.schema,
                        platform.triple()
                    );
                    for key in row.live_required {
                        let mut missing = identity.clone();
                        missing.inputs.remove(*key);
                        let reason = check_identity_grammar(&missing).unwrap_err();
                        assert!(
                            reason.contains(key),
                            "missing {key} was accepted for {}, {:?}, {}: {reason}",
                            row.kind,
                            row.schema,
                            platform.triple()
                        );
                    }
                }
            }
        }
    }

    pub(super) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
        let mut cases = vec![
            crate::kernel::gitsrc::live_identity_for_test(),
            crate::kernel::resolve::transaction::live_identity_for_test(),
        ];
        cases.extend(crate::kernel::resolve::ledger::live_identities_for_test());
        cases.extend(crate::tailors::live_identity_cases(platform));
        cases
    }

    fn case_with_input(
        cases: &[Identity],
        kind: &str,
        schema: Option<&str>,
        key: &str,
    ) -> Identity {
        cases
            .iter()
            .find(|identity| {
                identity.kind == kind
                    && schema_input_of(identity) == schema
                    && identity.inputs.contains_key(key)
            })
            .cloned()
            .unwrap_or_else(|| panic!("no {kind}/{schema:?} case has {key}"))
    }

    fn assert_relation_breaks(identity: &Identity, removals: &[&str], relation: &str) {
        assert_eq!(check_identity_grammar(identity), Ok(()));
        for remove in removals {
            let mut broken = identity.clone();
            assert!(
                broken.inputs.remove(*remove).is_some(),
                "missing fixture key {remove}"
            );
            let reason = check_identity_grammar(&broken).unwrap_err();
            assert!(
                reason.contains(relation),
                "relation {relation} was not named after removing {remove}: {reason}"
            );
        }
    }

    fn assert_count_breaks(identity: &Identity, prefix: &str, relation: &str) {
        assert_eq!(check_identity_grammar(identity), Ok(()));
        let remove = identity
            .inputs
            .keys()
            .find(|key| key.starts_with(prefix))
            .cloned()
            .unwrap_or_else(|| panic!("no {prefix} fixture key"));
        let mut broken = identity.clone();
        broken.inputs.remove(&remove);
        let reason = check_identity_grammar(&broken).unwrap_err();
        assert!(
            reason.contains(relation),
            "count relation {relation} was not named after removing {remove}: {reason}"
        );
    }

    #[test]
    fn producer_relations_reject_partial_live_outputs() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let darwin = live_identity_cases(Platform::Aarch64AppleDarwin);

        let nuget = case_with_input(
            &linux,
            "nuget-packages",
            Some("nuget-packages/1"),
            "pkg:newtonsoft.json@13.0.3",
        );
        assert_relation_breaks(
            &nuget,
            &["pkg:newtonsoft.json@13.0.3", "raw:newtonsoft.json@13.0.3"],
            "NuGet pkg/raw relation",
        );

        let go = case_with_input(
            &linux,
            "go-modcache",
            Some("go-modcache/1"),
            "mod:example.com/lib@v1.2.3",
        );
        assert_relation_breaks(
            &go,
            &[
                "mod:example.com/lib@v1.2.3",
                "modfile:example.com/lib@v1.2.3",
                "info:example.com/lib@v1.2.3",
            ],
            "Go module triplet relation",
        );

        let beam = case_with_input(&linux, "beam", Some("beam-toolchain/1"), "store_root");
        assert_relation_breaks(
            &beam,
            &["relocation_schema", "store_root"],
            "BEAM relocation relation",
        );

        let node_empty = case_with_input(&linux, "node-env", Some("node-env/5"), "layout");
        assert_relation_breaks(&node_empty, &["layout"], "Node layout/package relation");
        let node_packages = case_with_input(
            &linux,
            "node-env",
            Some("node-env/5"),
            "pkg:node_modules/example",
        );
        assert_relation_breaks(
            &node_packages,
            &["pkg:node_modules/example"],
            "Node layout/package relation",
        );
        let node_native = case_with_input(&linux, "node-env", Some("node-env/5"), "native_libs");
        assert_relation_breaks(
            &node_native,
            &["pkg:node_modules/example"],
            "Node native_libs/pkg relation",
        );
        let node_provisioned = case_with_input(
            &linux,
            "node-env",
            Some("node-env/5"),
            "provisioned:node_modules/electron",
        );
        assert_relation_breaks(
            &node_provisioned,
            &["pkg:node_modules/electron"],
            "Node provisioned/pkg relation",
        );
        let mut orphan_provisioned = node_packages.clone();
        orphan_provisioned.inputs.insert(
            "provisioned:node_modules/orphan".into(),
            "electron-v39.0.0-linux-x64.zip:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        );
        let reason = check_identity_grammar(&orphan_provisioned).unwrap_err();
        assert!(reason.contains("Node provisioned/pkg relation"), "{reason}");
        let mut node_darwin_native = case_with_input(
            &darwin,
            "node-env",
            Some("node-env/5"),
            "pkg:node_modules/example",
        );
        node_darwin_native
            .inputs
            .insert("native_libs".into(), "native-libs-object".into());
        let reason = check_identity_grammar(&node_darwin_native).unwrap_err();
        assert!(reason.contains("Node native platform relation"), "{reason}");

        let python_env = case_with_input(&linux, "python-env", Some("python-env/3"), "native_libs");
        assert_relation_breaks(
            &python_env,
            &["pkg:matrix-python-native"],
            "Python environment native_libs/pkg relation",
        );
        let mut orphan_native =
            case_with_input(&linux, "python-env", Some("python-env/3"), "pkg:example");
        orphan_native
            .inputs
            .insert("native_libs".into(), "native-libs-object".into());
        let reason = check_identity_grammar(&orphan_native).unwrap_err();
        assert!(
            reason.contains("Python environment native_libs/pkg relation"),
            "{reason}"
        );
        let mut python_darwin_native =
            case_with_input(&darwin, "python-env", Some("python-env/3"), "pkg:example");
        python_darwin_native
            .inputs
            .insert("pkg:example".into(), "Sdist:fixture".into());
        python_darwin_native
            .inputs
            .insert("native_libs".into(), "native-libs-object".into());
        let reason = check_identity_grammar(&python_darwin_native).unwrap_err();
        assert!(
            reason.contains("Python environment native platform relation"),
            "{reason}"
        );

        let native_libs = case_with_input(&linux, "native-libs", None, "platform");
        let mut native_libs_darwin = native_libs;
        native_libs_darwin.inputs.insert(
            "platform".into(),
            Platform::Aarch64AppleDarwin.triple().into(),
        );
        let reason = check_identity_grammar(&native_libs_darwin).unwrap_err();
        assert!(reason.contains("native-libs platform contract"), "{reason}");

        let sdist_rust = case_with_input(&linux, "sdist-build", Some("sdist-build/5"), "rust");
        assert_relation_breaks(
            &sdist_rust,
            &["rust", "vendor"],
            "sdist Rust/vendor relation",
        );
        let sdist_native = case_with_input(
            &linux,
            "sdist-build",
            Some("sdist-build/4"),
            "native_linker",
        );
        assert_relation_breaks(
            &sdist_native,
            &["native_libs", "native_linker"],
            "sdist native_libs/native_linker relation",
        );
        let mut sdist_darwin_native =
            case_with_input(&darwin, "sdist-build", Some("sdist-build/4"), "build_env");
        sdist_darwin_native
            .inputs
            .insert("native_libs".into(), "native-libs-object".into());
        sdist_darwin_native
            .inputs
            .insert("native_linker".into(), "native-libs-rpath/1".into());
        let reason = check_identity_grammar(&sdist_darwin_native).unwrap_err();
        assert!(
            reason.contains("sdist native platform relation"),
            "{reason}"
        );

        // Darwin's real BEAM constructor is the other conditional shape and
        // must pass without the Linux relocation pair.
        let beam_darwin = case_with_input(&darwin, "beam", Some("beam-toolchain/1"), "platform");
        assert_eq!(check_identity_grammar(&beam_darwin), Ok(()));
        let mut beam_darwin_relocated = beam_darwin;
        beam_darwin_relocated
            .inputs
            .insert("relocation_schema".into(), "store-relocation/1".into());
        beam_darwin_relocated
            .inputs
            .insert("store_root".into(), "/fixture/tog-store".into());
        let reason = check_identity_grammar(&beam_darwin_relocated).unwrap_err();
        assert!(reason.contains("BEAM relocation relation"), "{reason}");
    }

    /// The first drift `python-env/3` detects: a one-wheel plan that drops
    /// its only `pkg:` key. Under `/2` the result is the legitimate empty
    /// environment, byte for byte. `/3` writes `package_digest`
    /// unconditionally, so the two are different identities and the
    /// contract names the mismatch.
    #[test]
    fn python_env_one_wheel_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let empty = linux
            .iter()
            .find(|identity| {
                identity.kind == "python-env"
                    && schema_input_of(identity) == Some("python-env/3")
                    && !identity.inputs.keys().any(|key| key.starts_with("pkg:"))
            })
            .expect("empty Python environment matrix case");
        let one_wheel = linux
            .iter()
            .find(|identity| {
                identity.kind == "python-env"
                    && schema_input_of(identity) == Some("python-env/3")
                    && identity
                        .inputs
                        .values()
                        .any(|value| value.starts_with("Wheel:"))
            })
            .expect("one-wheel Python environment matrix case");
        let mut dropped = one_wheel.clone();
        let package_key = dropped
            .inputs
            .keys()
            .find(|key| key.starts_with("pkg:"))
            .cloned()
            .expect("one-wheel Python package input");
        dropped.inputs.remove(&package_key);

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(
            reason.contains("Python environment package digest"),
            "{reason}"
        );
        assert_ne!(dropped.object_id(), empty.object_id());
        assert_eq!(check_identity_grammar(empty), Ok(()));
        assert_eq!(check_identity_grammar(one_wheel), Ok(()));
    }

    /// The second drift `python-env/3` detects: an inspected native sdist
    /// that drops its `native_libs` key. Under `/2` every native check was
    /// conditional on that key. The `native` input says what the producer
    /// decided, so its absence is a contradiction rather than a silence.
    #[test]
    fn python_env_native_libs_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let native = case_with_input(&linux, "python-env", Some("python-env/3"), "native_libs");
        let mut dropped = native.clone();
        dropped.inputs.remove("native_libs");

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(
            reason.contains("Python environment native decision"),
            "{reason}"
        );
        assert_eq!(check_identity_grammar(&native), Ok(()));
    }

    /// The first drift `node-env/4` detects: one package dropped from a
    /// multi-package plan. Under `/3` another `pkg:` key remained, so every
    /// presence check passed. `plan_digest` covers the whole set.
    #[test]
    fn node_env_package_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let multi_package = linux
            .iter()
            .find(|identity| {
                identity.kind == "node-env"
                    && schema_input_of(identity) == Some("node-env/5")
                    && identity
                        .inputs
                        .keys()
                        .filter(|key| key.starts_with("pkg:"))
                        .count()
                        >= 2
            })
            .expect("multi-package Node environment matrix case");
        let mut dropped = multi_package.clone();
        let package_key = dropped
            .inputs
            .keys()
            .find(|key| key.starts_with("pkg:"))
            .cloned()
            .expect("multi-package Node package input");
        dropped.inputs.remove(&package_key);

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(reason.contains("Node plan digest"), "{reason}");
        assert_eq!(check_identity_grammar(multi_package), Ok(()));
    }

    /// The second drift `node-env/4` detects: a declared `artifact:` key
    /// dropped. Under `/3` the artifact group was optional, so nothing
    /// could prove one had been kept. `plan_digest` spans artifacts too.
    #[test]
    fn node_env_artifact_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let declared = case_with_input(
            &linux,
            "node-env",
            Some("node-env/5"),
            "artifact:.npm/tool.tar.gz",
        );
        let mut dropped = declared.clone();
        dropped.inputs.remove("artifact:.npm/tool.tar.gz");

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(reason.contains("Node plan digest"), "{reason}");
        assert_eq!(check_identity_grammar(&declared), Ok(()));
    }

    #[test]
    fn node_env_provisioned_dropped_is_detected_under_the_current_schema() {
        for platform in Platform::ALL {
            let cases = live_identity_cases(*platform);
            let provisioned = case_with_input(
                &cases,
                "node-env",
                Some("node-env/5"),
                "provisioned:node_modules/electron",
            );
            let mut dropped = provisioned.clone();
            dropped.inputs.remove("provisioned:node_modules/electron");

            // The pkg: value names electron, and the producer's provisioning
            // decision says electron always carries a provisioned: key, so
            // no schema change is needed to catch this drift.
            let reason = check_identity_grammar(&dropped).unwrap_err();
            assert!(
                reason.contains("Node pkg/provisioned relation"),
                "{}: {reason}",
                platform.triple()
            );
        }
    }

    /// The third drift `node-env/4` detects: a Linux `native_libs` key
    /// dropped. Under `/3` the native checks were conditional on that key.
    #[test]
    fn node_env_native_libs_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let native = case_with_input(&linux, "node-env", Some("node-env/5"), "native_libs");
        let mut dropped = native.clone();
        dropped.inputs.remove("native_libs");

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(reason.contains("Node native decision"), "{reason}");
        assert_eq!(check_identity_grammar(&native), Ok(()));
    }

    /// The first drift `sdist-build/4` detects: both halves of the
    /// `rust`/`vendor` pair dropped together. Under `/3` only a one-sided
    /// pair was rejected, so the drifted build looked like a build that
    /// never had a Rust extension at all.
    #[test]
    fn sdist_build_rust_vendor_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let rust = case_with_input(&linux, "sdist-build", Some("sdist-build/5"), "rust");
        let mut dropped = rust.clone();
        dropped.inputs.remove("rust");
        dropped.inputs.remove("vendor");

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(reason.contains("sdist build_mode relation"), "{reason}");
        assert_eq!(check_identity_grammar(&rust), Ok(()));
    }

    /// The second drift `sdist-build/4` detects: both halves of the
    /// `native_libs`/`native_linker` pair dropped together.
    #[test]
    fn sdist_build_native_pair_dropped_is_detected() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let native = case_with_input(
            &linux,
            "sdist-build",
            Some("sdist-build/4"),
            "native_linker",
        );
        let mut dropped = native.clone();
        dropped.inputs.remove("native_libs");
        dropped.inputs.remove("native_linker");

        let reason = check_identity_grammar(&dropped).unwrap_err();
        assert!(reason.contains("sdist native_mode relation"), "{reason}");
        assert_eq!(check_identity_grammar(&native), Ok(()));
    }

    #[test]
    fn producer_count_contracts_reject_dropped_dynamic_keys() {
        let linux = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        assert_count_breaks(
            linux
                .iter()
                .find(|identity| {
                    identity.kind == "cargo-vendor"
                        && schema_input_of(identity) == Some("cargo-vendor/2")
                        && identity
                            .inputs
                            .keys()
                            .filter(|key| key.starts_with("crate:"))
                            .count()
                            >= 2
                })
                .expect("multi-crate cargo-vendor matrix case"),
            "crate:",
            "Cargo crate count/version relation",
        );
        assert_count_breaks(
            &case_with_input(
                &linux,
                "nuget-packages",
                Some("nuget-packages/1"),
                "pkg:newtonsoft.json@13.0.3",
            ),
            "pkg:",
            "NuGet package count/version relation",
        );
        assert_count_breaks(
            &case_with_input(
                &linux,
                "go-modcache",
                Some("go-modcache/1"),
                "mod:example.com/lib@v1.2.3",
            ),
            "mod:",
            "Go module count/version relation",
        );
        assert_count_breaks(
            &case_with_input(&linux, "hex-deps", Some("hex-deps/1"), "dep:jason"),
            "dep:",
            "Hex dependency count/version relation",
        );
        assert_count_breaks(
            &case_with_input(&linux, "ruby-gems", Some("ruby-gems/1"), "gem:rake-13.2.1"),
            "gem:",
            "Ruby gem count/version relation",
        );
    }

    /// Cheap structural drift: a row whose `required` and `optional` lists
    /// overlap, or repeat a key, is a copy-paste error that would make the
    /// grammar say two different things about one input.
    #[test]
    fn every_installed_row_has_a_well_formed_grammar() {
        install_shipped_kinds();
        let rows = registered_kinds();
        let mut seen_pairs: BTreeSet<(&str, Option<&str>)> = BTreeSet::new();
        for row in rows {
            let where_ = format!("kind {}, schema {:?}", row.kind, row.schema);
            assert!(
                seen_pairs.insert((row.kind, row.schema)),
                "{where_} is listed twice; kind_for would silently take the first"
            );
            for list in [row.live_required, row.live_optional] {
                let unique: BTreeSet<&str> = list.iter().copied().collect();
                assert_eq!(
                    unique.len(),
                    list.len(),
                    "{where_} repeats a live input key"
                );
            }
            for key in row.live_required {
                assert!(
                    !row.live_optional.contains(key),
                    "{where_} lists {key} as both live-required and live-optional"
                );
            }
            // A prefix covers its keys: naming one of them as well would
            // say two different things about one input.
            for prefix in row.live_optional.iter().filter(|key| key.ends_with(':')) {
                for key in row.live_required.iter().chain(row.live_optional) {
                    assert!(
                        key == prefix || !key.starts_with(prefix),
                        "{where_} names {key} explicitly and also covers it with prefix {prefix}"
                    );
                }
            }
        }
    }

    /// The drift `cargo-vendor/2` detects: a one-crate plan that drops its
    /// only `crate:` key. `version` is `max(1, crate_count)`, so under `/1`
    /// the drifted plan hashed to the empty plan's object id. The explicit
    /// `crates` count separates them.
    #[test]
    fn cargo_vendor_one_crate_dropped_is_detected() {
        let cases = live_identity_cases(Platform::X86_64UnknownLinuxGnu);
        let empty = cases
            .iter()
            .find(|identity| {
                identity.kind == "cargo-vendor"
                    && schema_input_of(identity) == Some("cargo-vendor/2")
                    && !identity.inputs.keys().any(|key| key.starts_with("crate:"))
            })
            .expect("empty cargo-vendor matrix case");
        let one_crate = cases
            .iter()
            .find(|identity| {
                identity.kind == "cargo-vendor"
                    && identity
                        .inputs
                        .keys()
                        .filter(|key| key.starts_with("crate:"))
                        .count()
                        == 1
            })
            .expect("one-crate cargo-vendor matrix case");
        let multi_crate = cases
            .iter()
            .find(|identity| {
                identity.kind == "cargo-vendor"
                    && identity
                        .inputs
                        .keys()
                        .filter(|key| key.starts_with("crate:"))
                        .count()
                        >= 2
            })
            .expect("multi-crate cargo-vendor matrix case");
        // The version relation is unchanged: it still cannot tell an empty
        // plan from a one-crate plan, which is exactly why `crates` exists.
        assert_eq!(empty.version, "1");
        assert_eq!(empty.inputs["crates"], "0");
        assert_eq!(one_crate.version, "1");
        assert_eq!(one_crate.inputs["crates"], "1");
        assert_eq!(multi_crate.version, "2");
        assert_eq!(multi_crate.inputs["crates"], "2");
        let mut dropped_one_crate = one_crate.clone();
        let dropped_key = dropped_one_crate
            .inputs
            .keys()
            .find(|key| key.starts_with("crate:"))
            .cloned()
            .expect("one-crate identity input");
        dropped_one_crate.inputs.remove(&dropped_key);
        let reason = check_identity_grammar(&dropped_one_crate).unwrap_err();
        assert!(reason.contains("Cargo crate count relation"), "{reason}");
        assert_ne!(dropped_one_crate.object_id(), empty.object_id());
        assert_eq!(check_identity_grammar(empty), Ok(()));
        assert_eq!(check_identity_grammar(one_crate), Ok(()));
        assert_eq!(check_identity_grammar(multi_crate), Ok(()));
    }

    #[test]
    fn installing_a_different_kind_schema_set_panics() {
        install_shipped_kinds();
        let result = std::panic::catch_unwind(|| install_kinds(TEST_KINDS.iter()));
        let payload = result.expect_err("a different kind/schema set was accepted");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            message.contains("different (kind, schema) set"),
            "{message}"
        );
    }
}

/// Object metadata is read back from disk on every cache hit and gc. Each
/// malformed shape below is refused with its own message; none may turn
/// into a record with invented evidence.
#[cfg(test)]
mod record_value_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use serde_json::json;
    use std::fs;

    fn identity() -> Identity {
        tests::register_test_kinds();
        Identity {
            kind: "test".into(),
            name: "record".into(),
            version: "1".into(),
            inputs: Default::default(),
        }
    }

    fn explicit(id: &str) -> serde_json::Value {
        json!({
            "id": id,
            "identity": identity(),
            "schema": "object-meta/2",
            "dependencies": [],
            "cache_digests": [],
            "evidence": "explicit",
        })
    }

    fn refusal(id: &str, value: serde_json::Value) -> String {
        let error = read_record_value(id, value).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        error.to_string()
    }

    fn with(id: &str, edit: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
        let mut value = explicit(id);
        edit(&mut value);
        value
    }

    #[test]
    fn a_malformed_identity_is_refused() {
        let id = identity().object_id();
        let other = Identity {
            name: "other".into(),
            ..identity()
        };
        let cases = [
            (
                with(&id, |v| drop(v.as_object_mut().unwrap().remove("identity"))),
                format!("object {id} metadata has no identity"),
            ),
            (
                with(&id, |v| v["identity"]["kind"] = json!("")),
                format!("object {id} metadata has no identity kind"),
            ),
            (
                with(&id, |v| v["identity"] = json!(other)),
                format!("object {id} identity hashes to a different object id"),
            ),
            (
                with(&id, |v| {
                    v["id"] = json!("0000000000000000000000000000000000000000-x-1")
                }),
                format!("object metadata {id} has a mismatched id"),
            ),
            (
                with(&id, |v| v["id"] = json!(7)),
                format!("object metadata {id} has a mismatched id"),
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(refusal(&id, value), expected);
        }
        let reason = refusal(&id, with(&id, |v| v["identity"] = json!("text")));
        assert!(
            reason.starts_with(&format!("object {id} has malformed identity: ")),
            "{reason}"
        );
    }

    #[test]
    fn a_malformed_object_meta_2_body_is_refused() {
        let id = identity().object_id();
        let dep = "0000000000000000000000000000000000000000-dep-1";
        let sha = "a".repeat(64);
        let cases: Vec<(serde_json::Value, String)> = vec![
            (
                with(&id, |v| v["schema"] = json!(2)),
                format!("object {id} has an invalid metadata schema"),
            ),
            (
                with(&id, |v| v["schema"] = json!("object-meta/3")),
                format!("object {id} has unknown metadata schema object-meta/3"),
            ),
            (
                with(&id, |v| {
                    drop(v.as_object_mut().unwrap().remove("dependencies"))
                }),
                format!("object {id} metadata has no explicit dependencies"),
            ),
            (
                with(&id, |v| v["dependencies"] = json!(dep)),
                format!("object {id} metadata has no explicit dependencies"),
            ),
            (
                with(&id, |v| v["dependencies"] = json!([1])),
                format!("object {id} has a non-string dependency"),
            ),
            (
                with(&id, |v| v["dependencies"] = json!(["../escape"])),
                format!("object {id} has a malformed or duplicate dependency \"../escape\""),
            ),
            (
                with(&id, |v| v["dependencies"] = json!([dep, dep])),
                format!("object {id} has a malformed or duplicate dependency {dep:?}"),
            ),
            (
                with(&id, |v| {
                    drop(v.as_object_mut().unwrap().remove("cache_digests"))
                }),
                format!("object {id} metadata has no explicit cache digests"),
            ),
            (
                with(&id, |v| v["cache_digests"] = json!(["sha256:aa"])),
                format!("object {id} has a malformed cache digest"),
            ),
            (
                with(&id, |v| v["cache_digests"] = json!([{"hex": sha}])),
                format!("object {id} cache digest has no algorithm"),
            ),
            (
                with(&id, |v| v["cache_digests"] = json!([{"algo": "sha256"}])),
                format!("object {id} cache digest has no hex"),
            ),
            (
                with(&id, |v| {
                    v["cache_digests"] = json!([{"algo": "md5", "hex": sha}])
                }),
                format!("object {id} cache digest: unsupported cache algorithm md5"),
            ),
            (
                with(
                    &id,
                    |v| {
                        v["cache_digests"] =
                            json!([{"algo": "sha256", "hex": sha}, {"algo": "sha256", "hex": sha}])
                    },
                ),
                format!("object {id} has a duplicate cache digest"),
            ),
            (
                with(&id, |v| drop(v.as_object_mut().unwrap().remove("evidence"))),
                format!("object {id} metadata has no evidence marker"),
            ),
            // An older tog's migration wrote this marker. No store this
            // tog opens holds one, so it is no more known than any other.
            (
                with(&id, |v| v["evidence"] = json!("adapted:test@1")),
                format!("object {id} has unknown evidence marker adapted:test@1"),
            ),
            (
                with(&id, |v| v["evidence"] = json!("trusted")),
                format!("object {id} has unknown evidence marker trusted"),
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(refusal(&id, value), expected);
        }
        // A digest of the wrong length is refused through the digest parser.
        let reason = refusal(
            &id,
            with(&id, |v| {
                v["cache_digests"] = json!([{"algo": "sha256", "hex": "aa"}])
            }),
        );
        assert!(
            reason.starts_with(&format!("object {id} cache digest: ")),
            "{reason}"
        );
    }

    /// A record from before `object-meta/2` has no `schema`. It carries no
    /// dependency evidence, so it is refused like any other unreadable
    /// record, and never read as an object that needs nothing: that reading
    /// would let a sweep delete what the object depends on.
    #[test]
    fn a_record_with_no_schema_is_refused_not_read_as_dependency_free() {
        let id = identity().object_id();
        for value in [
            json!({"identity": identity()}),
            json!({"identity": identity(), "refs": []}),
            json!({"id": id, "identity": identity(), "refs": ["a"], "created": 1}),
        ] {
            assert_eq!(
                refusal(&id, value),
                format!("object {id} metadata has no schema")
            );
        }
    }

    /// Control: the one accepted shape reads back with what it recorded.
    #[test]
    fn well_formed_records_read_back() {
        let id = identity().object_id();
        let dep = "0000000000000000000000000000000000000000-dep-1";
        let sha = "b".repeat(64);
        let record = read_record_value(
            &id,
            with(&id, |v| {
                v["dependencies"] = json!([dep]);
                v["cache_digests"] = json!([{"algo": "sha256", "hex": sha}]);
            }),
        )
        .unwrap();
        assert!(record.dependencies.contains(dep));
        assert_eq!(record.cache.len(), 1);
        // An absent `id` field is allowed; the file name is the id.
        let record = read_record_value(
            &id,
            with(&id, |v| drop(v.as_object_mut().unwrap().remove("id"))),
        )
        .unwrap();
        assert_eq!(record.id, id);
    }

    #[test]
    fn read_record_at_refuses_what_is_not_a_regular_metadata_file() {
        // Short label: the socket case below needs a path under 108 bytes.
        let temp = TempDir::named("om");
        let id = identity().object_id();
        let meta = temp.0.join(format!("{id}.json"));

        fs::create_dir(&meta).unwrap();
        let error = read_record_at(&meta).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert_eq!(
            error.to_string(),
            format!("object metadata {} is not a regular file", meta.display())
        );
        fs::remove_dir(&meta).unwrap();

        let target = temp.0.join("target.json");
        fs::write(&target, explicit(&id).to_string()).unwrap();
        std::os::unix::fs::symlink(&target, &meta).unwrap();
        let error = read_record_at(&meta).map(drop).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("object metadata {} is not a regular file", meta.display())
        );
        fs::remove_file(&meta).unwrap();

        let malformed = temp.0.join("not-an-id.json");
        fs::write(&malformed, explicit(&id).to_string()).unwrap();
        let error = read_record_at(&malformed).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert_eq!(
            error.to_string(),
            "object metadata id \"not-an-id\" is malformed"
        );

        // A socket cannot be opened at all. The socket lives at `meta` and
        // is read there, however long TMPDIR makes that path.
        {
            let listener = crate::kernel::testutil::bind_socket(&meta);
            let error = read_record_at(&meta).map(drop).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
            assert_eq!(
                error.to_string(),
                format!("object metadata {} is not a regular file", meta.display())
            );
            drop(listener);
            fs::remove_file(&meta).unwrap();
        }

        // An unreadable directory is still reported as what it is, not as a
        // permission error (root reads it regardless).
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt as _;
            fs::create_dir(&meta).unwrap();
            fs::set_permissions(&meta, fs::Permissions::from_mode(0o000)).unwrap();
            let result = read_record_at(&meta).map(drop);
            fs::set_permissions(&meta, fs::Permissions::from_mode(0o755)).unwrap();
            fs::remove_dir(&meta).unwrap();
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
            assert_eq!(
                error.to_string(),
                format!("object metadata {} is not a regular file", meta.display())
            );
        }

        // A FIFO is refused without waiting for a writer.
        let fifo = std::ffi::CString::new(meta.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (send, receive) = std::sync::mpsc::channel();
        let reader = meta.clone();
        std::thread::spawn(move || {
            let _ = send.send(read_record_at(&reader).map(drop).map_err(|e| e.to_string()));
        });
        let answer = receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("reading a FIFO metadata file blocked");
        assert_eq!(
            answer,
            Err(format!(
                "object metadata {} is not a regular file",
                meta.display()
            ))
        );
        fs::remove_file(&meta).unwrap();

        let error = read_record_at(&meta).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");

        fs::write(&meta, b"{not json").unwrap();
        let error = read_record_at(&meta).map(drop).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error
                .to_string()
                .starts_with(&format!("parse object metadata {}: ", meta.display())),
            "{error}"
        );

        fs::write(&meta, explicit(&id).to_string()).unwrap();
        assert_eq!(read_record_at(&meta).unwrap().id, id);
    }

    /// A platform input must name a platform tog knows; the live grammar
    /// check refuses a producer that writes anything else.
    #[test]
    fn a_junk_platform_input_is_refused() {
        let mut identity = identity();
        assert_eq!(platform_of(&identity), Ok(None));
        for platform in Platform::ALL {
            identity
                .inputs
                .insert("platform".into(), platform.triple().into());
            assert_eq!(platform_of(&identity), Ok(Some(*platform)));
        }
        for junk in [
            "",
            "linux",
            "x86_64-unknown-linux-gnu ",
            "X86_64-UNKNOWN-LINUX-GNU",
        ] {
            identity.inputs.insert("platform".into(), junk.into());
            assert_eq!(
                platform_of(&identity),
                Err(format!(
                    "identity has an unparseable platform input {junk:?}"
                ))
            );
        }

        let live = tests::live_identity_cases(Platform::X86_64UnknownLinuxGnu)
            .into_iter()
            .find(|identity| identity.inputs.contains_key("platform"))
            .expect("a live producer identity with a platform input");
        assert_eq!(check_identity_grammar(&live), Ok(()));
        let mut junk = live.clone();
        junk.inputs.insert("platform".into(), "junk".into());
        assert_eq!(
            check_identity_grammar(&junk),
            Err("identity has an unparseable platform input \"junk\"".to_string())
        );
    }
}

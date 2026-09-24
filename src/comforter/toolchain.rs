//! Project toolchain resolution, publication, and the guard that keeps a
//! sync honest about what it read.
//!
//! `resolve` answers one question with no writes at all: which toolchain
//! does this project use, and where did that answer come from. Frozen and
//! strict validation run here, before a store is opened, so a refusal
//! leaves no trace. `commit` is the only writer: it takes the
//! toolchain-input lock, re-reads `tog-toolchain.toml` under it, publishes
//! a pending lock, and installs a process-global guard. Every closure
//! writer calls `recheck_before_publication` through that guard, so a
//! source file edited while a long sync ran aborts instead of pairing new
//! inputs with old outputs.

use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Digest;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::store::{self, Store};
use crate::kernel::toolchain::input::{self, InputRow};
use crate::kernel::toolchain::lock::{self, ToolchainLock};
use crate::kernel::toolchain::{
    seed, select_for, Bundle, Catalog, LegacyEvidence, ProvedArtifact, Selected, Source,
};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use crate::tailors::Tailor;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Project-relative path of the toolchain-input lock. It is advisory and
/// lives inside the ignored `.tog/`: it coordinates writers, it is never
/// the guarantee (the byte comparison before publication is).
pub const INPUT_LOCK_PATH: &str = ".tog/toolchain-input.lock";

/// What a command is allowed to do about the lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Ordinary sync: create a lock when there is none, never rewrite one.
    Writable,
    /// `--frozen`: validate the committed lock and never create one.
    Frozen,
    /// Read-only consumers (`plan`, `build`, `fmt`): honor a lock, fall
    /// back to selection, write nothing.
    ReadOnly,
    /// `tog update --toolchain [<ecosystem>]`: re-select and replace.
    Update { only: Option<String> },
}

/// Where a toolchain that is not a catalog release comes from: given the
/// host, the canonical project directory and the rows discovery found, the
/// bundle a new or updated lock records in place of a catalog selection, or
/// `None` when the rows name no such toolchain. Probing and hashing happen
/// only when a lock section is being written.
pub type ExternalToolchain = fn(Platform, &Path, &[InputRow]) -> io::Result<Option<Bundle>>;

/// One ecosystem `resolve` should answer for. The command layer fills it
/// from the ecosystem's tailor, so resolution never looks a tailor up.
#[derive(Debug)]
pub struct EcosystemInput {
    /// The `[toolchain.<name>]` section key, which is also the name
    /// `input::discover` knows.
    pub lock_ecosystem: String,
    /// The shipped catalog selection reads.
    pub catalog: Catalog,
    /// What a closure written before the lock existed proves, when there is
    /// one.
    pub legacy: Option<LegacyEvidence>,
    /// The local-toolchain reader of this ecosystem, when it has one
    /// (`toolchain.path` for Rust). It is consulted before the catalog.
    pub external: Option<ExternalToolchain>,
    /// The helper lock ecosystems this ecosystem builds with
    /// (`Tailor::helpers`): the only names its section may pin.
    pub declared_helpers: Vec<String>,
    /// The helper releases a section written now pins (`rust` for a Python
    /// project's sdists), by helper lock ecosystem.
    pub helper_pins: BTreeMap<String, String>,
    /// The helper releases this ecosystem's builds used before sections
    /// pinned them: what a section with no pin, or a selection seeded from a
    /// pre-lock closure, gets, so neither moves when the catalog does.
    pub legacy_helper_pins: BTreeMap<String, String>,
}

impl EcosystemInput {
    /// A committed section's helper pins, refused when one names a helper
    /// this ecosystem does not build with: nothing would read it, so the
    /// line is an edit or another tog's, and honoring the rest silently
    /// would hide that.
    fn pinned_helpers(&self, section: &lock::EcoLock) -> io::Result<BTreeMap<String, String>> {
        let ecosystem = self.lock_ecosystem.as_str();
        for helper in section.helpers().keys() {
            if !self.declared_helpers.contains(helper) {
                let builds_with = if self.declared_helpers.is_empty() {
                    format!("{ecosystem} builds with no helper toolchain")
                } else {
                    format!(
                        "{ecosystem} builds with only {}",
                        self.declared_helpers.join(", ")
                    )
                };
                return Err(invalid(format!(
                    "tog-toolchain.toml [toolchain.{ecosystem}.helpers] pins {helper:?}, \
                     which is not a helper toolchain ({builds_with}); \
                     run `tog update --toolchain {ecosystem}` to rewrite the section"
                )));
            }
        }
        Ok(section.helpers().clone())
    }

    /// The helper pins a section written now records: the legacy ones when
    /// the selection was seeded from a pre-lock closure (that closure's
    /// builds used them), today's otherwise.
    fn pins_to_write(&self, seeded: bool) -> &BTreeMap<String, String> {
        if seeded {
            &self.legacy_helper_pins
        } else {
            &self.helper_pins
        }
    }
}

/// The project's resolved toolchains and everything publication needs.
#[derive(Debug)]
pub struct ProjectToolchain {
    /// One selection per lock ecosystem.
    pub entries: BTreeMap<String, Selected>,
    /// The rows discovery found, per lock ecosystem, in precedence order.
    pub inputs: Vec<(String, Vec<InputRow>)>,
    /// The lock bytes as read at resolution; `None` when there was no file.
    pub lock_bytes: Option<Vec<u8>>,
    /// A lock to publish at commit, for a `Created` or `Updated` selection.
    pub pending: Option<ToolchainLock>,
}

impl ProjectToolchain {
    pub fn get(&self, lock_ecosystem: &str) -> io::Result<&Selected> {
        self.entries.get(lock_ecosystem).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no toolchain selection for {lock_ecosystem}; run `tog update --toolchain {lock_ecosystem}`"
                ),
            )
        })
    }
}

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn rows_of<'a>(discovered: &'a [(String, Vec<InputRow>)], ecosystem: &str) -> &'a [InputRow] {
    discovered
        .iter()
        .find(|(name, _)| name == ecosystem)
        .map_or(&[][..], |(_, rows)| rows.as_slice())
}

/// The bundle a new or updated lock records for `ecosystem`: the local
/// toolchain the rows name, when the entry has a reader for one
/// ([`EcosystemInput::external`]) and it finds one; otherwise the pre-lock
/// closure's seed when there is one, and the catalog's selection for the
/// rows when not.
fn choose(
    root: &ProjectRoot,
    platform: Platform,
    entry: &EcosystemInput,
    rows: &[InputRow],
    seed_from_legacy: bool,
) -> io::Result<(Bundle, bool)> {
    let ecosystem = entry.lock_ecosystem.as_str();
    if let Some(external) = entry.external {
        if let Some(bundle) = external(platform, root.path(), rows)? {
            return Ok((bundle, false));
        }
    }
    match (&entry.legacy, seed_from_legacy) {
        (Some(evidence), true) => Ok((seed(&entry.catalog, evidence)?.clone(), true)),
        _ => Ok((select_for(&entry.catalog, ecosystem, rows)?.clone(), false)),
    }
}

/// One selection read from a committed section, checked against the host.
fn from_section(
    entry: &EcosystemInput,
    section: &lock::EcoLock,
    platform: Platform,
    lock_sha256: Option<String>,
    source: Source,
) -> io::Result<Selected> {
    let ecosystem = entry.lock_ecosystem.as_str();
    let bundle = section.bundle()?;
    if !bundle.complete_for(platform) {
        return Err(invalid(format!(
            "tog-toolchain.toml [{ecosystem}]: release {} has no artifact rows for {}; \
             run `tog update --toolchain {ecosystem}`",
            bundle.release,
            platform.triple()
        )));
    }
    Ok(Selected {
        helpers: entry.pinned_helpers(section)?,
        ecosystem: ecosystem.to_string(),
        bundle,
        lock_sha256,
        source,
    })
}

/// What one closure envelope proves about `tailor`'s toolchain, for
/// `resolve` to seed a missing lock from. A closure that already records a
/// `toolchain` body key was written by a lock-aware sync and needs no
/// seeding; one for a foreign platform still yields evidence, carrying its
/// own platform, because the seed refuses on that platform rather than
/// guessing from the host.
///
/// `store` is the active store, opened read-only ([`Store::existing`]):
/// the tailor proves artifacts from the runtime object the closure names
/// only when that store holds it. `None` (no store yet) proves nothing.
pub fn legacy_evidence(
    tailor: &dyn Tailor,
    envelope: &serde_json::Value,
    store: Option<&Store>,
) -> Option<LegacyEvidence> {
    let body = &envelope["body"];
    if !needs_seeding(envelope) {
        return None;
    }
    let platform = envelope["platform"]
        .as_str()
        .and_then(Platform::from_triple);
    Some(tailor.legacy_toolchain_evidence(tailor.id(), platform, body, store))
}

/// Whether `envelope` predates the toolchain lock, so [`legacy_evidence`]
/// has something to say about it. Callers use this to leave the store
/// unlooked-up when no closure needs it.
pub fn needs_seeding(envelope: &serde_json::Value) -> bool {
    envelope["body"].get("toolchain").is_none()
}

/// [`legacy_evidence`] for the closure `tailor` wrote in `project`, if any:
/// what a read-only answer (`tog doctor`, `tog status`) passes `resolve`
/// so it seeds exactly as the next sync would. This lookup itself only
/// reads the store; the command around it may already hold it open. The
/// closure is tog's own state, read through the held project with the
/// strict no-follow walk.
pub fn legacy_evidence_in(
    project: &ProjectRoot,
    tailor: &dyn Tailor,
) -> io::Result<Option<LegacyEvidence>> {
    let relative = PathBuf::from(format!(".tog/closures/{}.json", tailor.id()));
    let path = project.path().join(&relative);
    let Some(bytes) = project.read_file(&relative)? else {
        return Ok(None);
    };
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{}: {error}; run 'tog'", path.display())))?;
    if !needs_seeding(&envelope) {
        return Ok(None);
    }
    let store = Store::existing()?;
    Ok(legacy_evidence(tailor, &envelope, store.as_ref()))
}

/// Why a closure's runtime object proves no artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofGap {
    /// Nothing to read: the closure names no object, there is no store,
    /// the reference was recorded in another store, or this store does not
    /// hold the object. Seeding may still go on from the versions.
    Unproved(String),
    /// The reference is malformed, or the store holds the object and it
    /// disagrees with the closure or cannot be read as the tailor's
    /// identity (another kind, platform or version, a missing or malformed
    /// digest, recipe or next-object input, unusable metadata). Seeding
    /// refuses.
    Contradicted(String),
}

/// Where a tailor's pre-lock closure names its runtime object.
#[derive(Clone, Copy, Debug)]
pub struct LegacyRuntime<'a> {
    /// Body-relative JSON pointer of the reference: an `{id, path}` object
    /// or a bare object path.
    pub pointer: &'a str,
    /// Objects between the reference and the runtime, in order: the kind
    /// each one must be and the identity input naming the next (a Python
    /// closure names its environment, whose `cpython` input is the
    /// interpreter).
    pub via: &'a [(&'a str, &'a str)],
    /// The runtime object's identity kind.
    pub kind: &'a str,
}

/// Prove the artifacts a pre-lock closure's runtime object was built from.
/// The reference is only a name: the object must be a complete, published
/// object of `runtime.kind` in `store` whose metadata identity hashes to
/// that name, and whose platform, when it records one, is the closure's.
/// `artifacts` reads that identity (checking the version the closure
/// records against it) into proved rows; once the object is found, any
/// field it lacks or spells wrong is a contradiction. Nothing here writes,
/// leases or touches the store. The outcome lands in `evidence`: proved rows, or the
/// gap `seed` refuses or explains with.
pub fn prove_legacy_runtime(
    evidence: &mut LegacyEvidence,
    store: Option<&Store>,
    body: &serde_json::Value,
    runtime: LegacyRuntime<'_>,
    artifacts: impl FnOnce(&Identity, &LegacyEvidence) -> Result<Vec<ProvedArtifact>, ProofGap>,
) {
    let outcome = legacy_runtime_identity(evidence, store, body, runtime)
        .and_then(|identity| artifacts(&identity, evidence));
    match outcome {
        Ok(proved) => evidence.artifacts.extend(proved),
        Err(ProofGap::Unproved(why)) => evidence.unproved.push(why),
        Err(ProofGap::Contradicted(why)) => evidence.contradicted.push(why),
    }
}

fn legacy_runtime_identity(
    evidence: &LegacyEvidence,
    store: Option<&Store>,
    body: &serde_json::Value,
    runtime: LegacyRuntime<'_>,
) -> Result<Identity, ProofGap> {
    let first_kind = runtime.via.first().map_or(runtime.kind, |(kind, _)| kind);
    let reference = match body.pointer(runtime.pointer) {
        None | Some(serde_json::Value::Null) => {
            return Err(ProofGap::Unproved(format!(
                "the closure names no {first_kind} object"
            )))
        }
        Some(reference) => reference,
    };
    // The reference is validated before any store is consulted: a
    // malformed one contradicts the closure whether or not a store exists.
    let malformed = |why: String| {
        ProofGap::Contradicted(format!(
            "the closure's {first_kind} object reference is malformed: {why}"
        ))
    };
    let path_id = |path: &Path| {
        store::object_id_from_path(path).map_err(|error| malformed(error.to_string()))
    };
    let (id, path) = match reference {
        serde_json::Value::String(path) => {
            let path = PathBuf::from(path);
            (path_id(&path)?, path)
        }
        serde_json::Value::Object(fields) => match (
            fields.get("id").and_then(serde_json::Value::as_str),
            fields.get("path").and_then(serde_json::Value::as_str),
        ) {
            (Some(id), Some(path)) => {
                let path = PathBuf::from(path);
                let named = path_id(&path)?;
                if named != id {
                    return Err(malformed(format!(
                        "its id {id:?} is not the object its path names ({named})"
                    )));
                }
                (named, path)
            }
            _ => return Err(malformed("it needs a string id and path".into())),
        },
        _ => {
            return Err(malformed(
                "it is neither an object path nor an {id, path} pair".into(),
            ))
        }
    };
    let Some(store) = store else {
        return Err(ProofGap::Unproved(format!(
            "there is no store to find the closure's {first_kind} object in"
        )));
    };
    // The recorded path only has to name this store's object; it never
    // decides what is read.
    if path != store.object_path(&id) {
        return Err(ProofGap::Unproved(format!(
            "the closure's {first_kind} object {id} was recorded in another store, not {}",
            store.root.display()
        )));
    }
    let mut id = id;
    let chain = runtime
        .via
        .iter()
        .map(|(kind, input)| (*kind, Some(*input)))
        .chain(std::iter::once((runtime.kind, None)));
    let mut identity = None;
    for (kind, next) in chain {
        let found = store
            .published_identity(&id)
            .map_err(|error| {
                ProofGap::Contradicted(format!(
                    "the closure's {kind} object {id} has unusable store metadata: {error}"
                ))
            })?
            .ok_or_else(|| {
                ProofGap::Unproved(format!(
                    "the closure's {kind} object {id} is not in the store at {}",
                    store.root.display()
                ))
            })?;
        if found.kind != kind {
            return Err(ProofGap::Contradicted(format!(
                "the closure's {kind} object {id} is a {} object",
                found.kind
            )));
        }
        if let (Some(recorded), Some(platform)) = (evidence.platform, found.inputs.get("platform"))
        {
            if platform != recorded.triple() {
                return Err(ProofGap::Contradicted(format!(
                    "the closure was realized on {} but its {kind} object {id} was built for {platform}",
                    recorded.triple()
                )));
            }
        }
        match next {
            Some(input) => {
                id = found
                    .inputs
                    .get(input)
                    .filter(|next| store::is_object_id(next))
                    .cloned()
                    .ok_or_else(|| {
                        ProofGap::Contradicted(format!(
                            "the closure's {kind} object {id} names no well-formed {input} object id"
                        ))
                    })?;
            }
            None => identity = Some(found),
        }
    }
    Ok(identity.expect("the chain ends at the runtime object"))
}

/// The recorded `component` version must be the one `identity` was built
/// as: an edited version string next to an untouched object contradicts it.
pub fn expect_legacy_version(
    identity: &Identity,
    evidence: &LegacyEvidence,
    component: &str,
    built: &str,
) -> Result<(), ProofGap> {
    match evidence.version(component) {
        Some(recorded) if recorded != built => Err(ProofGap::Contradicted(format!(
            "the closure records {component} {recorded} but its {} object {} is {component} {built}",
            identity.kind,
            identity.object_id()
        ))),
        _ => Ok(()),
    }
}

/// One proved row from a runtime identity: `component` was fetched as the
/// artifact whose `algo` digest is the identity's `input`, and laid out
/// under `recipe`.
pub fn proved_from_identity(
    identity: &Identity,
    component: &str,
    input: &str,
    algo: &str,
    recipe: &str,
) -> Result<ProvedArtifact, ProofGap> {
    let hex = identity.inputs.get(input).ok_or_else(|| {
        ProofGap::Contradicted(format!(
            "the closure's {} object {} records no {input}",
            identity.kind,
            identity.object_id()
        ))
    })?;
    let digest = match algo {
        "sha256" => Digest::sha256(hex),
        "sha512" => Digest::sha512(hex),
        other => unreachable!("no {other} artifact digests"),
    }
    .map_err(|error| {
        ProofGap::Contradicted(format!(
            "the closure's {} object {} has a malformed {input}: {error}",
            identity.kind,
            identity.object_id()
        ))
    })?;
    Ok(ProvedArtifact {
        component: component.to_string(),
        recipe: recipe.to_string(),
        digest,
    })
}

/// The recipe an identity commits to in its `schema` input, for runtime
/// kinds whose layout recipe is that input.
pub fn schema_recipe(identity: &Identity) -> Result<&str, ProofGap> {
    identity
        .inputs
        .get("schema")
        .map(String::as_str)
        .ok_or_else(|| {
            ProofGap::Contradicted(format!(
                "the closure's {} object {} records no recipe",
                identity.kind,
                identity.object_id()
            ))
        })
}

/// Which toolchain this project uses, and where the answer came from.
/// Writes nothing: frozen and strict validation both fail here, before the
/// store is opened and before any tailor runs.
pub fn resolve(
    root: &ProjectRoot,
    platform: Platform,
    inputs: Vec<EcosystemInput>,
    mode: Mode,
    strict: bool,
) -> io::Result<ProjectToolchain> {
    let discovered = input::discover_many(
        root,
        inputs.iter().map(|entry| entry.lock_ecosystem.as_str()),
    )?;
    let lock_bytes = ToolchainLock::read_bytes_via(root)?;
    let committed = match &lock_bytes {
        Some(bytes) => Some(ToolchainLock::parse(bytes)?),
        None => None,
    };
    let committed_sha = lock_bytes.as_deref().map(sha256_hex);

    let mut entries: BTreeMap<String, Selected> = BTreeMap::new();
    let mut pending: Option<ToolchainLock> = None;

    if let Mode::Update { only } = &mode {
        if let Some(name) = only {
            if !inputs.iter().any(|entry| &entry.lock_ecosystem == name) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "no {name} project found here; `tog update --toolchain {name}` needs one"
                    ),
                ));
            }
        }
        let mut next = committed
            .clone()
            .unwrap_or_else(|| ToolchainLock::new(env!("CARGO_PKG_VERSION")));
        for entry in &inputs {
            let ecosystem = entry.lock_ecosystem.as_str();
            let rows = rows_of(&discovered, ecosystem);
            if only.as_deref().is_some_and(|named| named != ecosystem) {
                if let Some(section) = committed.as_ref().and_then(|l| l.ecosystem(ecosystem)) {
                    entries.insert(
                        ecosystem.to_string(),
                        from_section(entry, section, platform, None, Source::Lock)?,
                    );
                }
                continue;
            }
            let (bundle, _) = choose(root, platform, entry, rows, false)?;
            next.set_ecosystem(ecosystem, &bundle, rows)?;
            next.set_helpers(ecosystem, entry.pins_to_write(false))?;
            entries.insert(
                ecosystem.to_string(),
                Selected {
                    helpers: entry.pins_to_write(false).clone(),
                    ecosystem: ecosystem.to_string(),
                    bundle,
                    lock_sha256: None,
                    source: Source::Updated,
                },
            );
        }
        if !next.ecosystems().is_empty() {
            let sha = sha256_hex(&next.canonical_bytes());
            for selected in entries.values_mut() {
                selected.lock_sha256 = Some(sha.clone());
            }
            pending = Some(next);
        }
    } else if let Some(committed) = &committed {
        for entry in &inputs {
            let ecosystem = entry.lock_ecosystem.as_str();
            let section = committed.ecosystem(ecosystem).ok_or_else(|| {
                invalid(format!(
                    "tog-toolchain.toml has no [toolchain.{ecosystem}] section for the \
                     {ecosystem} project found here; run `tog update --toolchain {ecosystem}`"
                ))
            })?;
            let stale = lock::stale_rows(&section.inputs(), rows_of(&discovered, ecosystem));
            if !stale.is_empty() {
                let rows: Vec<String> = stale.iter().map(ToString::to_string).collect();
                return Err(invalid(format!(
                    "tog-toolchain.toml is stale for {ecosystem}: {}; \
                     run `tog update --toolchain {ecosystem}`",
                    rows.join("; ")
                )));
            }
            entries.insert(
                ecosystem.to_string(),
                from_section(
                    entry,
                    section,
                    platform,
                    committed_sha.clone(),
                    Source::Lock,
                )?,
            );
        }
    } else {
        match &mode {
            Mode::Frozen => {
                return Err(invalid(
                    "tog-toolchain.toml is missing and --frozen never creates it; run `tog` \
                     (or `tog update --toolchain`) once without --frozen and commit the file",
                ))
            }
            Mode::Writable if strict => {
                return Err(invalid(
                    "tog-toolchain.toml is missing and strict policy never creates it; run \
                     `tog` (or `tog update --toolchain`) once and commit the file",
                ))
            }
            Mode::ReadOnly => {
                for entry in &inputs {
                    let ecosystem = entry.lock_ecosystem.as_str();
                    let rows = rows_of(&discovered, ecosystem);
                    let (bundle, seeded) = choose(root, platform, entry, rows, true)?;
                    let source = if seeded {
                        Source::Seeded
                    } else {
                        Source::Shipped
                    };
                    entries.insert(
                        ecosystem.to_string(),
                        // No section is written, so none is pinned: the
                        // builds supply what such a section would pin (the
                        // catalog's default, or the release a seeded
                        // closure's builds used), and the id stays the
                        // bundle's own, as it always was here.
                        Selected {
                            helpers: BTreeMap::new(),
                            ecosystem: ecosystem.to_string(),
                            bundle,
                            lock_sha256: None,
                            source,
                        },
                    );
                }
            }
            Mode::Writable => {
                let mut next = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
                for entry in &inputs {
                    let ecosystem = entry.lock_ecosystem.as_str();
                    let rows = rows_of(&discovered, ecosystem);
                    let (bundle, seeded) = choose(root, platform, entry, rows, true)?;
                    next.set_ecosystem(ecosystem, &bundle, rows)?;
                    next.set_helpers(ecosystem, entry.pins_to_write(seeded))?;
                    entries.insert(
                        ecosystem.to_string(),
                        Selected {
                            helpers: entry.pins_to_write(seeded).clone(),
                            ecosystem: ecosystem.to_string(),
                            bundle,
                            lock_sha256: None,
                            source: Source::Created,
                        },
                    );
                }
                if !next.ecosystems().is_empty() {
                    let sha = sha256_hex(&next.canonical_bytes());
                    for selected in entries.values_mut() {
                        selected.lock_sha256 = Some(sha.clone());
                    }
                    pending = Some(next);
                }
            }
            Mode::Update { .. } => unreachable!("update is handled above"),
        }
    }

    Ok(ProjectToolchain {
        entries,
        inputs: discovered,
        lock_bytes,
        pending,
    })
}

/// What the process-global guard remembers: enough to prove, immediately
/// before any project write, that the lock and the inputs are still the
/// ones this command resolved from.
struct GuardState {
    /// A duplicate of the descriptor the command resolved through: the
    /// recheck reads the directory it held, never whatever the project's
    /// path names by publication time.
    root: ProjectRoot,
    lock_bytes: Option<Vec<u8>>,
    inputs: Vec<(String, Vec<InputRow>)>,
}

static INPUT_GUARD: Mutex<Option<GuardState>> = Mutex::new(None);

/// Holds the toolchain-input flock for the whole command. Dropping it
/// releases the lock and clears the process-global guard, so a later
/// command in the same process cannot inherit a stale snapshot.
#[derive(Debug)]
pub struct InputLockGuard {
    _file: File,
}

impl Drop for InputLockGuard {
    fn drop(&mut self) {
        *INPUT_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

/// Take the toolchain-input lock, publish a pending lock under it, and
/// install the guard. Called after the store activity lease and before any
/// tailor runs, so the lock file is settled before dependency planning
/// starts.
pub fn commit(
    root: &ProjectRoot,
    toolchain: &mut ProjectToolchain,
    mode: &Mode,
) -> io::Result<InputLockGuard> {
    let file = root.open_lock_file(Path::new(INPUT_LOCK_PATH))?;
    if toolchain.pending.is_some() {
        file.lock()?;
    } else {
        file.lock_shared()?;
    }
    match toolchain.pending.as_ref() {
        Some(candidate) => {
            let bytes = candidate.canonical_bytes();
            let published = match ToolchainLock::read_bytes_via(root)? {
                None => {
                    candidate.publish_via(root)?;
                    narrate(toolchain, false);
                    bytes
                }
                // A concurrent writer chose the same bundle: its file is
                // this file, so the race is a cache hit, not a conflict.
                Some(existing) if existing == bytes => existing,
                // An update is the one writer allowed to replace a lock.
                Some(_) if matches!(mode, Mode::Update { .. }) => {
                    candidate.publish_via(root)?;
                    narrate(toolchain, true);
                    bytes
                }
                Some(existing) => return Err(conflict(&existing, toolchain)),
            };
            toolchain.lock_bytes = Some(published);
        }
        None => {
            if ToolchainLock::read_bytes_via(root)? != toolchain.lock_bytes {
                return Err(invalid(
                    "tog-toolchain.toml changed during sync (update --toolchain race)",
                ));
            }
        }
    }
    *INPUT_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(GuardState {
        root: root.try_clone()?,
        lock_bytes: toolchain.lock_bytes.clone(),
        inputs: toolchain.inputs.clone(),
    });
    Ok(InputLockGuard { _file: file })
}

/// What a created or updated lock says on stderr: the selection first, so
/// the file name is the last thing read and the next step is obvious.
fn narrate(toolchain: &ProjectToolchain, replaced: bool) {
    for selected in toolchain.entries.values() {
        ui::note(&format!("selected {}", selected.describe()));
    }
    if replaced {
        ui::note("updated tog-toolchain.toml; commit it");
    } else {
        ui::note("wrote tog-toolchain.toml; commit it");
    }
}

/// Two syncs, two different selections, one file. Name both so the reader
/// can tell which one they wanted before rerunning anything.
fn conflict(existing: &[u8], toolchain: &ProjectToolchain) -> io::Error {
    let theirs = ToolchainLock::parse(existing).ok();
    let mut lines = Vec::new();
    for (ecosystem, selected) in &toolchain.entries {
        let on_disk = theirs
            .as_ref()
            .and_then(|lock| lock.ecosystem(ecosystem))
            .and_then(|section| section.bundle().ok())
            .map(|bundle| {
                Selected {
                    helpers: Default::default(),
                    ecosystem: ecosystem.clone(),
                    bundle,
                    lock_sha256: None,
                    source: Source::Lock,
                }
                .describe()
            })
            .unwrap_or_else(|| "no section".to_string());
        lines.push(format!(
            "{ecosystem}: on disk {on_disk}, this sync selected {}",
            selected.describe()
        ));
    }
    invalid(format!(
        "another sync wrote tog-toolchain.toml with a different selection ({}); \
         keep the one you want and run `tog update --toolchain`",
        lines.join("; ")
    ))
}

/// Prove the lock and the source inputs are still the ones this command
/// resolved from, and that the project's path still names the directory it
/// resolved them in. Called at the top of the one closure writer, so every
/// project write is covered without each producer remembering to ask.
///
/// Everything is read through the descriptor the command held since
/// preflight, so a project renamed away and replaced by another at the same
/// path is refused here rather than rechecked in the replacement. Nothing
/// to prove when no sync guard is installed (a command outside sync).
pub fn recheck_before_publication() -> io::Result<()> {
    let guard = INPUT_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(state) = guard.as_ref() else {
        return Ok(());
    };
    let root = &state.root;
    root.check_still_named()?;
    if ToolchainLock::read_bytes_via(root)? != state.lock_bytes {
        return Err(invalid(
            "tog-toolchain.toml changed during sync (update --toolchain race)",
        ));
    }
    for (ecosystem, recorded) in &state.inputs {
        let current = input::discover(root, ecosystem)?;
        for row in recorded {
            let now = current
                .iter()
                .find(|other| other.path == row.path && other.field == row.field);
            let changed = match now {
                None => true,
                Some(now) => now.value != row.value || now.sha256 != row.sha256,
            };
            if changed {
                return Err(invalid(format!(
                    "project toolchain inputs changed during sync ({} {}); run `tog` again",
                    row.path.display(),
                    row.field
                )));
            }
        }
    }
    Ok(())
}

/// The two closure-body entries every producer records about its toolchain:
/// which bundle it used, and which store object it realized from it.
pub fn closure_record(selected: &Selected, runtime_object: &Path) -> serde_json::Value {
    let mut versions = serde_json::Map::new();
    for component in &selected.bundle.components {
        versions.insert(
            component.name.clone(),
            serde_json::Value::String(component.version.clone()),
        );
    }
    serde_json::json!({
        "toolchain": {
            "ecosystem": selected.ecosystem,
            "release": selected.bundle.release,
            "bundle_id": selected.bundle_id(),
            "lock_sha256": selected.lock_sha256,
            "versions": serde_json::Value::Object(versions),
        },
        "runtime_object": {
            "id": runtime_object
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default(),
            "path": runtime_object,
        },
    })
}

/// The runtime object a closure recorded, resolved against the active
/// store exactly as every other closure object reference is.
pub fn runtime_object(
    store: &Store,
    activity: &StoreActivity,
    closure_body: &serde_json::Value,
    probe: &str,
) -> io::Result<PathBuf> {
    super::closure_object(store, activity, closure_body, "runtime_object", probe)
}

/// An `{id, path}` closure reference to `id` in `store`, as closure writers
/// record one.
#[cfg(test)]
pub(crate) fn object_ref_for_test(store: &Store, id: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "path": store.object_path(id)})
}

/// Leave `identity` in `store` as a finished publication does: a read-only
/// object root and a metadata record naming the identity. Returns its id.
#[cfg(test)]
pub(crate) fn publish_for_test(store: &Store, identity: &Identity) -> String {
    use std::os::unix::fs::PermissionsExt;
    let id = identity.object_id();
    let path = store.object_path(&id);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::create_dir_all(store.root.join("meta")).unwrap();
    std::fs::write(
        store.root.join("meta").join(format!("{id}.json")),
        serde_json::to_vec(&serde_json::json!({"identity": identity})).unwrap(),
    )
    .unwrap();
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use crate::kernel::toolchain::lock::LOCK_PATH;
    use crate::tailors::Tailor;

    /// The process-global guard `commit` installs is read by every closure
    /// writer, so these tests take the same two locks the one signing-key
    /// test takes, in the order sync's tests document: supervision, then
    /// attribution. No closure writer can run beside them.
    struct Serialized {
        _supervision: std::sync::MutexGuard<'static, ()>,
        _attribution: std::sync::MutexGuard<'static, ()>,
    }

    fn serialized() -> Serialized {
        Serialized {
            _supervision: crate::kernel::supervise::SUPERVISION_TEST_LOCK
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            _attribution: crate::kernel::policy::attribution_test_lock(),
        }
    }

    fn project(temp: &TempDir) -> PathBuf {
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(dir.join(".python-version"), "3.12.14\n").unwrap();
        dir
    }

    fn tailor(id: &str) -> &'static dyn Tailor {
        crate::tailors::by_id(id).unwrap()
    }

    /// The real wiring: the catalog and legacy evidence the command layer
    /// would hand `resolve` for these tailors.
    fn inputs_for(dir: &Path, ids: &[&str]) -> Vec<EcosystemInput> {
        let tailors: Vec<&dyn Tailor> = ids.iter().map(|id| tailor(id)).collect();
        crate::commands::shared::ecosystem_inputs(dir, &tailors).unwrap()
    }

    fn resolve_python(root: &ProjectRoot, dir: &Path, mode: Mode) -> io::Result<ProjectToolchain> {
        resolve(
            root,
            Platform::host().unwrap(),
            inputs_for(dir, &["python"]),
            mode,
            false,
        )
    }

    #[test]
    fn writable_creates_a_stable_lock_that_the_next_resolve_honors() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();

        let mut first = resolve_python(&root, &dir, Mode::Writable).unwrap();
        let second = resolve_python(&root, &dir, Mode::Writable).unwrap();
        let bytes = first.pending.as_ref().unwrap().canonical_bytes();
        assert_eq!(second.pending.as_ref().unwrap().canonical_bytes(), bytes);
        let created = first.get("python").unwrap();
        assert_eq!(created.source, Source::Created);
        assert_eq!(created.version("cpython").unwrap(), "3.12.14");
        assert_eq!(
            created.lock_sha256.as_deref(),
            Some(sha256_hex(&bytes).as_str())
        );
        let chosen = created.bundle_id();
        // Resolution writes nothing at all.
        assert!(!dir.join(LOCK_PATH).exists());
        assert!(!dir.join(".tog").exists());

        drop(commit(&root, &mut first, &Mode::Writable).unwrap());
        assert_eq!(std::fs::read(dir.join(LOCK_PATH)).unwrap(), bytes);
        assert_eq!(first.lock_bytes.as_deref(), Some(bytes.as_slice()));
        assert!(dir.join(INPUT_LOCK_PATH).is_file());

        let mut third = resolve_python(&root, &dir, Mode::Writable).unwrap();
        let honored = third.get("python").unwrap();
        assert_eq!(honored.source, Source::Lock);
        assert_eq!(honored.bundle_id(), chosen);
        assert!(third.pending.is_none());
        // A sync that honors a lock takes the shared lock and writes nothing.
        drop(commit(&root, &mut third, &Mode::Writable).unwrap());
        assert_eq!(std::fs::read(dir.join(LOCK_PATH)).unwrap(), bytes);
    }

    #[test]
    fn a_changed_input_is_stale_and_names_both_values() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let mut created = resolve_python(&root, &dir, Mode::Writable).unwrap();
        drop(commit(&root, &mut created, &Mode::Writable).unwrap());

        std::fs::write(dir.join(".python-version"), "3.13.15\n").unwrap();
        let error = resolve_python(&root, &dir, Mode::Writable)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is stale for python"), "{error}");
        assert!(error.contains(".python-version version"), "{error}");
        assert!(error.contains("recorded 3.12.14, now 3.13.15"), "{error}");
        assert!(error.contains("tog update --toolchain python"), "{error}");
        // A comment-only edit changes the digest and nothing else.
        std::fs::write(dir.join(".python-version"), "# pinned\n3.12.14\n").unwrap();
        let fresh = resolve_python(&root, &dir, Mode::Writable).unwrap();
        assert_eq!(fresh.get("python").unwrap().source, Source::Lock);
    }

    fn resolve_rust(root: &ProjectRoot, dir: &Path, mode: Mode) -> io::Result<ProjectToolchain> {
        resolve(
            root,
            Platform::host().unwrap(),
            inputs_for(dir, &["cargo"]),
            mode,
            false,
        )
    }

    /// `targets` and `components` are lock rows: editing either stales the
    /// lock, an update records it, and an equivalent spelling (reordered,
    /// duplicated) is the same row. A file that asks for neither gives the
    /// lock it always gave, and a malformed file is refused, never read as
    /// one that asks for nothing.
    #[test]
    fn rust_targets_and_components_are_lock_rows() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = temp.0.join("crate");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let toolchain = |extra: &str| {
            std::fs::write(
                dir.join("rust-toolchain.toml"),
                format!("[toolchain]\nchannel = \"1.96.1\"\n{extra}"),
            )
            .unwrap();
        };
        let root = ProjectRoot::open(&dir).unwrap();
        toolchain("");
        let mut created = resolve_rust(&root, &dir, Mode::Writable).unwrap();
        drop(commit(&root, &mut created, &Mode::Writable).unwrap());
        let plain = std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap();
        // Exactly the two channel rows a lock always recorded for Rust.
        assert_eq!(plain.matches("[[toolchain.rust.inputs]]").count(), 2);
        assert!(!plain.contains("toolchain.components"), "{plain}");
        assert!(!plain.contains("toolchain.targets"), "{plain}");

        toolchain("components = [\"rustfmt\", \"clippy\"]\n");
        let error = resolve_rust(&root, &dir, Mode::Writable)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is stale for rust"), "{error}");
        assert!(
            error.contains(
                "rust-toolchain.toml toolchain.components: recorded absent, now clippy,rustfmt"
            ),
            "{error}"
        );
        let mode = Mode::Update {
            only: Some("rust".into()),
        };
        let mut updated = resolve_rust(&root, &dir, mode.clone()).unwrap();
        drop(commit(&root, &mut updated, &mode).unwrap());
        let listed = std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap();
        assert!(
            listed.contains("field = \"toolchain.components\"\nvalue = \"clippy,rustfmt\"\n"),
            "{listed}"
        );

        // Reordering, duplicating, or reformatting the list is no edit.
        toolchain("components = [\n  \"clippy\",\n  \"rustfmt\",\n  \"clippy\",\n]\n");
        let honored = resolve_rust(&root, &dir, Mode::Writable).unwrap();
        assert_eq!(honored.get("rust").unwrap().source, Source::Lock);

        // A target is a row of its own; dropping the components is stale too.
        toolchain(
            "components = [\"clippy\", \"rustfmt\"]\ntargets = [\"wasm32-unknown-unknown\"]\n",
        );
        let error = resolve_rust(&root, &dir, Mode::Frozen)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("toolchain.targets: recorded absent, now wasm32-unknown-unknown"),
            "{error}"
        );
        // A profile is a row too.
        toolchain("components = [\"clippy\", \"rustfmt\"]\nprofile = \"default\"\n");
        let error = resolve_rust(&root, &dir, Mode::Writable)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("toolchain.profile: recorded absent, now default"),
            "{error}"
        );
        toolchain("");
        let error = resolve_rust(&root, &dir, Mode::Writable)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("toolchain.components: recorded clippy,rustfmt, now absent"),
            "{error}"
        );

        // A malformed file is refused on every path, update included.
        for (bad, words) in [
            (
                "components = \"clippy\"\n",
                "rust-toolchain.toml: toolchain.components must be an array",
            ),
            (
                "profile = \"everything\"\n",
                "rust-toolchain.toml: toolchain.profile must be one of minimal, default, complete",
            ),
        ] {
            std::fs::write(
                dir.join("rust-toolchain.toml"),
                format!("[toolchain]\n{bad}"),
            )
            .unwrap();
            for mode in [Mode::Writable, Mode::ReadOnly, mode.clone()] {
                let error = resolve_rust(&root, &dir, mode).unwrap_err().to_string();
                assert!(error.contains(words), "{error}");
            }
        }
        assert_eq!(
            std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap(),
            listed
        );
    }

    #[test]
    fn frozen_refuses_a_missing_lock_and_so_does_strict() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let error = resolve_python(&root, &dir, Mode::Frozen)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--frozen never creates it"), "{error}");
        assert!(error.contains("commit the file"), "{error}");

        let error = resolve(
            &root,
            Platform::host().unwrap(),
            inputs_for(&dir, &["python"]),
            Mode::Writable,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("strict policy never creates it"), "{error}");
        assert!(!error.contains("--frozen"), "{error}");
        assert!(!dir.join(LOCK_PATH).exists());

        // Read-only consumers neither refuse nor write: they select.
        let read_only = resolve_python(&root, &dir, Mode::ReadOnly).unwrap();
        assert_eq!(read_only.get("python").unwrap().source, Source::Shipped);
        assert!(read_only.pending.is_none());
        assert!(!dir.join(LOCK_PATH).exists());
    }

    /// Every path under `root` with its mtime: what a read-only caller must
    /// leave exactly as it found it.
    fn tree(root: &Path) -> Vec<(PathBuf, std::time::SystemTime)> {
        let mut out = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    pending.push(path.clone());
                }
                out.push((path, metadata.modified().unwrap()));
            }
        }
        out.sort();
        out
    }

    /// `legacy_evidence_in` (the seeding lookup `status` and `doctor` use)
    /// proves the closure's Go object through the store `TOG_STORE` names
    /// without itself taking a lease, a lock file, a touch or creating a
    /// directory, and metadata that
    /// does not describe the recorded id is a contradiction, not a proof.
    #[test]
    fn legacy_evidence_reads_the_active_store_and_writes_nothing() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("TOG_STORE", value),
                    None => std::env::remove_var("TOG_STORE"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("TOG_STORE"));
        let temp = TempDir::new();
        let platform = Platform::host().unwrap();
        let go = tailor("go");
        let selected = crate::kernel::toolchain::shipped(&go.toolchain_catalog().unwrap()).unwrap();

        let root = temp.0.join("store");
        for sub in ["objects", "meta"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let (refs, objects) =
            crate::tailors::go::legacy_runtime_for_test(platform, &selected, &store);
        for object in &objects {
            publish_for_test(&store, object);
        }
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        let mut body = serde_json::json!({"plan": {"go_version": selected.version("go").unwrap()}});
        body["go_object"] = refs["go_object"].clone();
        std::fs::write(
            dir.join(".tog/closures/go.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "go",
                "platform": platform.triple(),
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();

        std::env::set_var("TOG_STORE", &store.root);
        let before = tree(&store.root);
        let evidence = legacy_evidence_in(&ProjectRoot::open(&dir).unwrap(), go)
            .unwrap()
            .unwrap();
        assert_eq!(tree(&store.root), before);
        assert!(evidence.unproved.is_empty(), "{:?}", evidence.unproved);
        assert!(
            evidence.contradicted.is_empty(),
            "{:?}",
            evidence.contradicted
        );
        let row = selected.artifact(platform, "go").unwrap();
        assert_eq!(
            evidence.artifacts,
            vec![ProvedArtifact {
                component: "go".into(),
                recipe: row.recipe,
                digest: row.digest,
            }]
        );

        // Metadata that hashes to another id describes some other object.
        let id = objects[0].object_id();
        let mut forged = objects[0].clone();
        forged.version = "0.0.1".into();
        std::fs::write(
            store.root.join("meta").join(format!("{id}.json")),
            serde_json::to_vec(&serde_json::json!({"identity": forged})).unwrap(),
        )
        .unwrap();
        let evidence = legacy_evidence_in(&ProjectRoot::open(&dir).unwrap(), go)
            .unwrap()
            .unwrap();
        assert!(evidence.artifacts.is_empty());
        assert!(
            evidence.contradicted[0].contains("has unusable store metadata"),
            "{:?}",
            evidence.contradicted
        );

        // No store yet: nothing proved, and nothing created.
        let missing = temp.0.join("no-store");
        std::env::set_var("TOG_STORE", &missing);
        let evidence = legacy_evidence_in(&ProjectRoot::open(&dir).unwrap(), go)
            .unwrap()
            .unwrap();
        assert!(evidence.artifacts.is_empty());
        assert!(
            evidence.unproved[0].contains("there is no store"),
            "{:?}",
            evidence.unproved
        );
        assert!(!missing.exists());
    }

    #[test]
    fn a_pre_lock_closure_seeds_the_version_it_recorded() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        // A project with no pin at all: without the closure this would take
        // the newest shipped release.
        std::fs::remove_file(dir.join(".python-version")).unwrap();
        std::fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        std::fs::write(
            dir.join(".tog/closures/python.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "platform": Platform::host().unwrap().triple(),
                "body": {"python": {"version": "3.11.16"}},
            }))
            .unwrap(),
        )
        .unwrap();
        let root = ProjectRoot::open(&dir).unwrap();

        let shipped_newest = resolve(
            &root,
            Platform::host().unwrap(),
            vec![EcosystemInput {
                lock_ecosystem: "python".into(),
                catalog: tailor("python").toolchain_catalog().unwrap(),
                legacy: None,
                external: None,
                helper_pins: BTreeMap::new(),
                legacy_helper_pins: BTreeMap::new(),
                declared_helpers: Vec::new(),
            }],
            Mode::Writable,
            false,
        )
        .unwrap();
        assert_ne!(
            shipped_newest
                .get("python")
                .unwrap()
                .version("cpython")
                .unwrap(),
            "3.11.16"
        );

        let mut seeded = resolve_python(&root, &dir, Mode::Writable).unwrap();
        assert_eq!(
            seeded.get("python").unwrap().version("cpython").unwrap(),
            "3.11.16"
        );
        // The pre-lock closure's sdists built on the Rust tog shipped then,
        // and the seeded section pins that one.
        assert_eq!(
            seeded.get("python").unwrap().helpers["rust"],
            crate::tailors::python::build::LEGACY_SDIST_RUST
        );
        drop(commit(&root, &mut seeded, &Mode::Writable).unwrap());
        let text = std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap();
        assert!(text.contains("version = \"3.11.16\""), "{text}");

        // Read-only seeding names the same release and writes nothing.
        std::fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let read_only = resolve_python(&root, &dir, Mode::ReadOnly).unwrap();
        assert_eq!(read_only.get("python").unwrap().source, Source::Seeded);
    }

    /// A Python section pins the Rust its sdists build on when it is
    /// written, and a section written before pins keeps the Rust those
    /// builds used, so neither moves when the catalog's default does.
    #[test]
    fn the_python_section_pins_the_rust_its_sdists_build_on() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let default = crate::kernel::toolchain::shipped(
            &crate::kernel::provider::rust::toolchain_catalog().unwrap(),
        )
        .unwrap()
        .version("rustc")
        .unwrap()
        .to_string();
        let legacy = crate::tailors::python::build::LEGACY_SDIST_RUST;
        assert_ne!(default, legacy);
        let mut created = resolve_python(&root, &dir, Mode::Writable).unwrap();
        assert_eq!(created.get("python").unwrap().helpers["rust"], default);
        drop(commit(&root, &mut created, &Mode::Writable).unwrap());
        let text = std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap();
        let pin = format!("[toolchain.python.helpers]\nrust = \"{default}\"\n");
        assert!(text.contains(&pin), "{text}");
        for mode in [Mode::ReadOnly, Mode::Frozen, Mode::Writable] {
            let honored = resolve_python(&root, &dir, mode).unwrap();
            let python = honored.get("python").unwrap();
            assert_eq!(python.source, Source::Lock);
            assert_eq!(python.helpers["rust"], default);
        }
        // The lock as a tog before pins wrote it: no pin, and the bundle's
        // own id.
        let mut old = ToolchainLock::parse(text.as_bytes()).unwrap();
        old.set_helpers("python", &BTreeMap::new()).unwrap();
        let old = old.canonical_bytes();
        assert_eq!(
            String::from_utf8(old.clone()).unwrap(),
            text.replace(&pin, "").replace(
                created.get("python").unwrap().bundle_id().as_str(),
                created.get("python").unwrap().bundle.bundle_id().as_str(),
            )
        );
        std::fs::write(dir.join(LOCK_PATH), &old).unwrap();
        for mode in [Mode::ReadOnly, Mode::Frozen, Mode::Writable] {
            let honored = resolve_python(&root, &dir, mode).unwrap();
            let python = honored.get("python").unwrap();
            // It pins nothing, so its id is the bundle's own, as before
            // pins; the sdist builds supply the legacy release.
            assert!(python.helpers.is_empty());
            assert_eq!(python.bundle_id(), python.bundle.bundle_id());
            assert!(honored.pending.is_none(), "an old lock was rewritten");
        }
        // An update pins today's default.
        let updated = resolve_python(&root, &dir, Mode::Update { only: None }).unwrap();
        assert_eq!(updated.get("python").unwrap().helpers["rust"], default);
        let written = updated.pending.as_ref().unwrap().canonical_bytes();
        assert!(String::from_utf8(written).unwrap().contains(&pin));

        // A pin for a helper Python does not build with is refused by
        // every read, even under a consistent id; an update rewrites it.
        let mut odd = ToolchainLock::parse(text.as_bytes()).unwrap();
        odd.set_helpers(
            "python",
            &BTreeMap::from([("node".to_string(), "24.20.0".to_string())]),
        )
        .unwrap();
        std::fs::write(dir.join(LOCK_PATH), odd.canonical_bytes()).unwrap();
        for mode in [Mode::ReadOnly, Mode::Frozen, Mode::Writable] {
            let error = resolve_python(&root, &dir, mode).unwrap_err().to_string();
            assert!(
                error.contains(
                    "[toolchain.python.helpers] pins \"node\", which is not a helper \
                     toolchain (python builds with only rust)"
                ),
                "{error}"
            );
        }
        let repaired = resolve_python(&root, &dir, Mode::Update { only: None }).unwrap();
        assert_eq!(
            repaired.get("python").unwrap().helpers,
            BTreeMap::from([("rust".to_string(), default.clone())])
        );
    }

    #[test]
    fn update_reselects_from_the_inputs_and_replaces_the_section() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let mut created = resolve_python(&root, &dir, Mode::Writable).unwrap();
        drop(commit(&root, &mut created, &Mode::Writable).unwrap());
        let before = std::fs::read(dir.join(LOCK_PATH)).unwrap();

        std::fs::write(dir.join(".python-version"), "3.13.15\n").unwrap();
        let mode = Mode::Update { only: None };
        let mut updated = resolve_python(&root, &dir, mode.clone()).unwrap();
        let selection = updated.get("python").unwrap();
        assert_eq!(selection.source, Source::Updated);
        assert_eq!(selection.version("cpython").unwrap(), "3.13.15");
        drop(commit(&root, &mut updated, &mode).unwrap());
        let after = std::fs::read(dir.join(LOCK_PATH)).unwrap();
        assert_ne!(after, before);
        assert_eq!(
            resolve_python(&root, &dir, Mode::Writable)
                .unwrap()
                .get("python")
                .unwrap()
                .version("cpython")
                .unwrap(),
            "3.13.15"
        );

        // Naming an ecosystem the project does not have is an error.
        let error = resolve(
            &root,
            Platform::host().unwrap(),
            inputs_for(&dir, &["python"]),
            Mode::Update {
                only: Some("node".into()),
            },
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no node project found here"), "{error}");
    }

    #[test]
    fn a_newly_present_ecosystem_has_no_section_and_is_refused() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let mut created = resolve_python(&root, &dir, Mode::Writable).unwrap();
        drop(commit(&root, &mut created, &Mode::Writable).unwrap());

        std::fs::write(dir.join("package.json"), "{\"name\": \"p\"}\n").unwrap();
        let error = resolve(
            &root,
            Platform::host().unwrap(),
            inputs_for(&dir, &["python", "node"]),
            Mode::Writable,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("has no [toolchain.node] section for the node project"),
            "{error}"
        );
        assert!(error.contains("tog update --toolchain node"), "{error}");

        // The update that adds the section keeps python's bytes untouched.
        let mode = Mode::Update {
            only: Some("node".into()),
        };
        let mut updated = resolve(
            &root,
            Platform::host().unwrap(),
            inputs_for(&dir, &["python", "node"]),
            mode.clone(),
            false,
        )
        .unwrap();
        assert_eq!(updated.get("node").unwrap().source, Source::Updated);
        assert_eq!(updated.get("python").unwrap().source, Source::Lock);
        drop(commit(&root, &mut updated, &mode).unwrap());
        let text = std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap();
        assert!(text.contains("[toolchain.node]"), "{text}");
        assert!(text.contains("version = \"3.12.14\""), "{text}");
    }

    #[test]
    fn a_concurrent_writer_with_another_selection_stops_the_commit() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let mut mine = resolve_python(&root, &dir, Mode::Writable).unwrap();

        // Another sync published a lock for a different release in between.
        let catalog = tailor("python").toolchain_catalog().unwrap();
        let other = catalog.release("cpython-3.13.15").unwrap();
        let mut theirs = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
        let rows = input::discover(&root, "python").unwrap();
        theirs.set_ecosystem("python", other, &rows).unwrap();
        theirs.publish_via(&root).unwrap();

        let error = commit(&root, &mut mine, &Mode::Writable)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("another sync wrote tog-toolchain.toml"),
            "{error}"
        );
        assert!(error.contains("on disk cpython 3.13.15"), "{error}");
        assert!(
            error.contains("this sync selected cpython 3.12.14"),
            "{error}"
        );
        assert!(error.contains("tog update --toolchain"), "{error}");
        // The loser leaves the winner's file exactly as it found it.
        assert_eq!(
            std::fs::read(dir.join(LOCK_PATH)).unwrap(),
            theirs.canonical_bytes()
        );

        // Byte-identical candidates are a cache hit, not a conflict.
        std::fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let mut again = resolve_python(&root, &dir, Mode::Writable).unwrap();
        again.pending.as_ref().unwrap().publish_via(&root).unwrap();
        drop(commit(&root, &mut again, &Mode::Writable).unwrap());
    }

    #[test]
    fn the_guard_refuses_a_lock_or_an_input_that_moved_during_the_sync() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let mut created = resolve_python(&root, &dir, Mode::Writable).unwrap();
        let guard = commit(&root, &mut created, &Mode::Writable).unwrap();
        recheck_before_publication().unwrap();

        std::fs::write(dir.join(".python-version"), "3.13.15\n").unwrap();
        let error = recheck_before_publication().unwrap_err().to_string();
        assert!(
            error.contains("project toolchain inputs changed during sync"),
            "{error}"
        );
        assert!(error.contains(".python-version version"), "{error}");
        std::fs::write(dir.join(".python-version"), "3.12.14\n").unwrap();
        recheck_before_publication().unwrap();

        std::fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let error = recheck_before_publication().unwrap_err().to_string();
        assert!(
            error.contains("tog-toolchain.toml changed during sync"),
            "{error}"
        );
        // Dropping the guard puts the process back to having no snapshot.
        drop(guard);
        recheck_before_publication().unwrap();
    }

    /// #132: the guard holds the descriptor preflight resolved through. A
    /// project renamed away between preflight and publication, with another
    /// project installed at its path, is refused rather than rechecked in
    /// the replacement, and the guard never reads the replacement.
    #[test]
    fn the_guard_refuses_a_project_renamed_and_replaced_before_publication() {
        let _serialized = serialized();
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let mut created = resolve_python(&root, &dir, Mode::Writable).unwrap();
        let guard = commit(&root, &mut created, &Mode::Writable).unwrap();
        drop(root);
        recheck_before_publication().unwrap();

        // Rename the checked project away and put a byte-identical copy at
        // its path: identical lock and inputs, a different directory. A
        // recheck that reopened the path would read the copy and pass.
        let moved = temp.0.join("moved");
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["pyproject.toml", ".python-version", LOCK_PATH] {
            std::fs::copy(moved.join(name), dir.join(name)).unwrap();
        }
        let error = recheck_before_publication().unwrap_err().to_string();
        assert!(error.contains("moved or replaced during sync"), "{error}");

        // The guard reads the directory it held, wherever it now is: an
        // input edited in the moved original is caught once it is back.
        std::fs::write(moved.join(".python-version"), "3.13.15\n").unwrap();

        // Putting the original back is the only way to publish again.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::rename(&moved, &dir).unwrap();
        let error = recheck_before_publication().unwrap_err().to_string();
        assert!(
            error.contains("project toolchain inputs changed during sync"),
            "{error}"
        );
        std::fs::write(dir.join(".python-version"), "3.12.14\n").unwrap();
        recheck_before_publication().unwrap();
        drop(guard);
    }

    #[test]
    fn a_closure_record_names_the_bundle_and_the_runtime_object() {
        let temp = TempDir::new();
        let dir = project(&temp);
        let root = ProjectRoot::open(&dir).unwrap();
        let resolved = resolve_python(&root, &dir, Mode::ReadOnly).unwrap();
        let selected = resolved.get("python").unwrap();
        let object = Path::new("/store/objects/cpython-3.12.14-abc");
        let record = closure_record(selected, object);
        assert_eq!(record["toolchain"]["ecosystem"], "python");
        assert_eq!(record["toolchain"]["release"], selected.bundle.release);
        assert_eq!(record["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(record["toolchain"]["lock_sha256"], serde_json::Value::Null);
        assert_eq!(record["toolchain"]["versions"]["cpython"], "3.12.14");
        assert_eq!(record["runtime_object"]["id"], "cpython-3.12.14-abc");
        assert_eq!(record["runtime_object"]["path"], object.to_str().unwrap());
    }
}

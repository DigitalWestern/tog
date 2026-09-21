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

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::toolchain::input::{self, InputRow};
use crate::kernel::toolchain::lock::{self, ToolchainLock};
use crate::kernel::toolchain::{seed, select_for, Catalog, LegacyEvidence, Selected, Source};
use crate::kernel::ui;
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

/// One ecosystem `resolve` should answer for.
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

/// One selection read from a committed section, checked against the host.
fn from_section(
    ecosystem: &str,
    section: &lock::EcoLock,
    platform: Platform,
    lock_sha256: Option<String>,
    source: Source,
) -> io::Result<Selected> {
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
        ecosystem: ecosystem.to_string(),
        bundle,
        lock_sha256,
        source,
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
                        from_section(ecosystem, section, platform, None, Source::Lock)?,
                    );
                }
                continue;
            }
            let bundle = select_for(&entry.catalog, ecosystem, rows)?.clone();
            next.set_ecosystem(ecosystem, &bundle, rows)?;
            entries.insert(
                ecosystem.to_string(),
                Selected {
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
                    ecosystem,
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
                    "tog-toolchain.toml is missing and --frozen never creates it; run `tog sync` \
                     (or `tog update --toolchain`) once without --frozen and commit the file",
                ))
            }
            Mode::Writable if strict => {
                return Err(invalid(
                    "tog-toolchain.toml is missing and strict policy never creates it; run \
                     `tog sync` (or `tog update --toolchain`) once and commit the file",
                ))
            }
            Mode::ReadOnly => {
                for entry in &inputs {
                    let ecosystem = entry.lock_ecosystem.as_str();
                    let rows = rows_of(&discovered, ecosystem);
                    let (bundle, source) = match &entry.legacy {
                        Some(evidence) => (seed(&entry.catalog, evidence)?.clone(), Source::Seeded),
                        None => (
                            select_for(&entry.catalog, ecosystem, rows)?.clone(),
                            Source::Shipped,
                        ),
                    };
                    entries.insert(
                        ecosystem.to_string(),
                        Selected {
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
                    let bundle = match &entry.legacy {
                        Some(evidence) => seed(&entry.catalog, evidence)?.clone(),
                        None => select_for(&entry.catalog, ecosystem, rows)?.clone(),
                    };
                    next.set_ecosystem(ecosystem, &bundle, rows)?;
                    entries.insert(
                        ecosystem.to_string(),
                        Selected {
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
    root: PathBuf,
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
        root: root.path().to_path_buf(),
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
/// resolved from. Called at the top of the one closure writer, so every
/// project write is covered without each producer remembering to ask.
pub fn recheck_before_publication() -> io::Result<()> {
    let guard = INPUT_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(state) = guard.as_ref() else {
        return Ok(());
    };
    let root = ProjectRoot::open(&state.root)?;
    if ToolchainLock::read_bytes_via(&root)? != state.lock_bytes {
        return Err(invalid(
            "tog-toolchain.toml changed during sync (update --toolchain race)",
        ));
    }
    for (ecosystem, recorded) in &state.inputs {
        let current = input::discover(&root, ecosystem)?;
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
                    "project toolchain inputs changed during sync ({} {}); run `tog sync` again",
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
    closure_body: &serde_json::Value,
    probe: &str,
) -> io::Result<PathBuf> {
    super::closure_object(store, closure_body, "runtime_object", probe)
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
        drop(commit(&root, &mut seeded, &Mode::Writable).unwrap());
        let text = std::fs::read_to_string(dir.join(LOCK_PATH)).unwrap();
        assert!(text.contains("version = \"3.11.16\""), "{text}");

        // Read-only seeding names the same release and writes nothing.
        std::fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let read_only = resolve_python(&root, &dir, Mode::ReadOnly).unwrap();
        assert_eq!(read_only.get("python").unwrap().source, Source::Seeded);
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

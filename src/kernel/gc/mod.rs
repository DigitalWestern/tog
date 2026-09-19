//! Store garbage collection.
//!
//! GC is deliberately rooted in project closure files rather than in the
//! current working directory. A project becomes a root when a tailor writes a
//! closure. A root never stops protecting its project: an unavailable project
//! stops the sweep until it returns or its record is explicitly forgotten.

use crate::kernel::activity::StoreActivity;
use crate::kernel::store::{self, ObjectDeps, RootEntry, Store};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

mod migrate;
mod plan;
mod read;
mod sweep;

pub use migrate::*;
pub use plan::*;
pub use read::*;
use sweep::*;

const ACTIVE_WINDOW: Duration = Duration::from_secs(10 * 60);
const STAGE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone)]
pub struct Options {
    pub dry_run: bool,
    pub keep_days: u64,
    pub project: bool,
    /// Explicit opt-in to collect objects written without reference
    /// metadata. They may belong to projects from before the roots registry.
    pub collect_legacy: bool,
    /// Root keys this sweep must ignore. A real `--forget` removed the
    /// record before the sweep, so this is a belt-and-braces repeat; a
    /// `--dry-run --forget` leaves the record in place and excludes it only
    /// here, so the sweep shows what the forgotten project would stop
    /// protecting.
    pub forgotten: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dry_run: false,
            keep_days: 30,
            project: false,
            collect_legacy: false,
            forgotten: Vec::new(),
        }
    }
}

impl Options {
    pub fn keep_days(days: u64) -> Self {
        Self {
            keep_days: days,
            ..Self::default()
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub freed_bytes: u64,
    pub objects: usize,
    pub cached_artifacts: usize,
    pub stages: usize,
    pub forests: usize,
    pub backups: usize,
}

/// Sweep the store, and its forest and backup projections when
/// `options.project` is set.
pub fn collect<W: Write>(store: &Store, options: Options, out: &mut W) -> io::Result<Report> {
    let Some(activity) = store.try_activity_exclusive()? else {
        writeln!(out, "cleanup skipped: a Blanket job is using this store")?;
        return Ok(Report::default());
    };
    collect_with_activity(store, &activity, options, out)
}

/// Run a sweep while the caller owns the store's exclusive activity lease.
/// This is kept separate from `collect` so a CLI invocation can validate and
/// apply register/forget mutations under the same lease without attempting
/// to reacquire its own exclusive lock.
pub fn collect_with_activity<W: Write>(
    store: &Store,
    activity: &StoreActivity,
    options: Options,
    out: &mut W,
) -> io::Result<Report> {
    store.require_exclusive_activity(activity, "garbage collection")?;
    if !store.registry_initialized()? {
        return Err(io::Error::other(
            "refusing to sweep: the project-root registry is not initialized; register existing "
                .to_string()
                + "projects with `blanket gc --register <dir>...` or run `blanket sync` in each "
                + "project",
        ));
    }
    // The maintenance phase runs first, under the same exclusive token, and
    // before any deletion lock or snapshot. The migration opens the
    // publication lock itself, so taking it here first would be a recursive
    // acquisition through a second descriptor.
    //
    // A dry run does not write, so it carries the upgrades it *would* have
    // published forward as an in-memory overlay. The real sweep applies the
    // same overlay over records it has just written. Both paths therefore
    // plan from byte-identical evidence — the preview cannot show a deletion
    // the sweep would not make, and the sweep cannot make one the preview did
    // not show.
    let (migration, upgrades) =
        migrate_metadata_locked(store, activity, options.dry_run, out, false)?;
    if migration.unresolved != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to sweep: metadata maintenance left {} uncertified legacy record(s); \
                 nothing was deleted. Resolve the objects named above and run `blanket gc \
                 --migrate-metadata`",
                migration.unresolved
            ),
        ));
    }
    // GC has its own user-visible lock, and also holds the publication lock
    // across the liveness snapshot and removals. Store::has/commit use the
    // latter, so a sync either touches an object before this sweep or waits
    // until after it.
    let _gc_lock = store.gc_lock()?;
    let _publish_lock = store.publish_lock()?;

    let snapshot = read(store, activity, &options, &upgrades, out)?;
    let validated = validate(&snapshot, &options)?;
    let plan = plan(&validated, &options)?;
    if options.dry_run {
        report_plan(&plan, out)?;
        return Ok(plan.report());
    }
    execute(&plan, &snapshot, store, activity, out)
}

fn mtime_of(stat: &libc::stat) -> SystemTime {
    let secs = stat.st_mtime;
    let nanos = stat.st_mtime_nsec.clamp(0, 999_999_999) as u32;
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nanos)
    } else {
        SystemTime::UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0)
    }
}

fn age_at(now: SystemTime, stat: &libc::stat) -> Option<Duration> {
    now.duration_since(mtime_of(stat)).ok()
}

fn recent_at(now: SystemTime, stat: &libc::stat, window: Duration) -> bool {
    age_at(now, stat).is_some_and(|age| age < window)
}

fn older_than_at(now: SystemTime, stat: &libc::stat, age: Duration) -> bool {
    age_at(now, stat).is_some_and(|elapsed| elapsed > age)
}

fn file_size_of(stat: &libc::stat) -> u64 {
    stat.st_size.max(0) as u64
}

fn validate_projection_namespace(path: &Path, name: &str) -> io::Result<()> {
    let stat = match fs::symlink_metadata(path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if stat.file_type().is_symlink() || !stat.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to sweep: {name} is not a real directory"),
        ));
    }
    Ok(())
}

/// Open a managed directory without following a symlink at its pathname. The
/// descriptor is held from the read phase through execution, so every
/// removal names an entry inside the directory that was actually inspected.
fn open_directory(path: &Path, label: &str) -> io::Result<fs::File> {
    let stat = fs::symlink_metadata(path)?;
    if stat.file_type().is_symlink() || !stat.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} is not a real directory", path.display()),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

fn related(path: &Path, keep: &Path) -> bool {
    path == keep || path.starts_with(keep) || keep.starts_with(path)
}

#[cfg(test)]
fn recent(path: &Path, window: Duration) -> bool {
    modified(path)
        .and_then(|time| SystemTime::now().duration_since(time).ok())
        .is_some_and(|age| age < window)
}

fn keep_age(days: u64) -> Duration {
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
}

#[cfg(test)]
fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

fn tree_size(path: &Path) -> io::Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        let mut total = 0;
        for entry in fs::read_dir(path)? {
            total += tree_size(&entry?.path())?;
        }
        Ok(total)
    } else {
        Ok(metadata.len())
    }
}

fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

fn short_sha256(bytes: &[u8], hex_len: usize) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))[..hex_len].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::types::Identity;
    use sha2::Digest;
    use std::collections::BTreeMap;

    struct TempStore {
        root: PathBuf,
    }

    impl TempStore {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "blanket-gc-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&root);
            for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            Self { root }
        }
        fn store(&self) -> Store {
            Store {
                root: self.root.canonicalize().unwrap(),
            }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = store::remove_tree(&self.root);
        }
    }

    fn test_identity(name: &str, input: Option<&str>) -> Identity {
        crate::kernel::objmeta::register_test_kinds();
        Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: input
                .map(|id| BTreeMap::from([("input".into(), id.into())]))
                .unwrap_or_default(),
        }
    }

    /// Publish a fully certified object whose only dependency is `input`.
    fn commit(store: &Store, name: &str, input: Option<&str>) -> String {
        let identity = test_identity(name, input);
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), name).unwrap();
        let mut deps = ObjectDeps::new();
        if let Some(input) = input {
            deps.object_id(input).unwrap();
        }
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();
        id
    }

    /// Publish an object and then rewrite its record into the pre-object-meta/2
    /// shape, so the adapters and the containment guard have something real to
    /// work on.
    fn commit_legacy_fixture(store: &Store, identity: &Identity, refs: Option<&[&str]>) -> String {
        let id = identity.object_id();
        if identity.kind == "not-a-known-kind" {
            // Unknown-kind fixtures are historical records. Publish this
            // legacy-shaped object by hand because the live commit guard must
            // reject the same unknown kind.
            let object = store.object_path(&id);
            fs::create_dir_all(&object).unwrap();
            fs::write(object.join("payload"), &identity.name).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::json!({
                    "schema": "object-meta/2",
                    "id": id,
                    "identity": identity,
                    "created": 0,
                    "exceptions": [],
                    "dependencies": [],
                    "cache_digests": [],
                    "evidence": "explicit",
                })
                .to_string(),
            )
            .unwrap();
        } else {
            let staged = store.stage().unwrap();
            fs::write(staged.join("payload"), &identity.name).unwrap();
            store
                .commit_with_deps(identity, &staged, &[], &ObjectDeps::new())
                .unwrap();
        }
        let path = store.root.join("meta").join(format!("{id}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("schema");
        object.remove("dependencies");
        object.remove("cache_digests");
        object.remove("evidence");
        if let Some(refs) = refs {
            object.insert(
                "refs".into(),
                serde_json::json!(refs.iter().map(|r| r.to_string()).collect::<Vec<_>>()),
            );
        }
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        id
    }

    /// Read one record the way every phase reads it.
    fn record(store: &Store, id: &str) -> crate::kernel::objmeta::Record {
        crate::kernel::objmeta::read_record_at(&store.root.join("meta").join(format!("{id}.json")))
            .unwrap()
    }

    fn closure(project: &Path, object: &Path, extra: serde_json::Value) {
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        let body = serde_json::json!({
            "env_object": object.display().to_string(),
            "extra": extra,
        });
        fs::write(
            project.join(".blanket/closures/python.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// Materialise a verified cache artifact so a legacy fixture can name it.
    fn cached_artifact(store: &Store, hex: &str) {
        let path = store.root.join("cache/sha256").join(hex);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"artifact").unwrap();
    }

    /// `object-meta/2` records carry an evidence marker saying how their
    /// dependency set was established. A record without one, or with a
    /// marker nothing produced, is not usable evidence for a deletion.
    #[test]
    fn a_certified_record_without_a_usable_evidence_marker_is_refused() {
        let temp = TempStore::new("evidence-marker");
        let store = temp.store();
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            // The real cpython producer's input shape; the commit-time
            // grammar check refuses anything else.
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), "a".repeat(64)),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "cpython").unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        let meta_path = store.root.join("meta").join(format!("{id}.json"));

        for (label, marker) in [
            ("missing", None),
            ("invented", Some(serde_json::json!("assumed"))),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
            let object = value.as_object_mut().unwrap();
            object.remove("refs");
            object.insert("schema".into(), serde_json::json!("object-meta/2"));
            object.insert("dependencies".into(), serde_json::json!([]));
            object.insert("cache_digests".into(), serde_json::json!([]));
            match marker {
                Some(marker) => {
                    object.insert("evidence".into(), marker);
                }
                None => {
                    object.remove("evidence");
                }
            }
            fs::write(&meta_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            let error = crate::kernel::objmeta::read_record_at(&meta_path).unwrap_err();
            assert!(
                error.to_string().contains("evidence"),
                "{label} evidence marker was accepted: {error}"
            );
        }
    }

    /// A BEAM toolchain fixture plus the fingerprint a `hex-deps` record
    /// would use to name it. The fingerprint is not an object id, so the
    /// adapter has to find the object by recomputing it — which is exactly
    /// the indirect-reference case covered by this adapter.
    fn beam_fixture(store: &Store) -> (String, String) {
        let otp = "1".repeat(64);
        let elixir = "2".repeat(64);
        let hex_archive = "3".repeat(128);
        let rebar3 = "4".repeat(128);
        let identity = Identity {
            kind: "beam".into(),
            name: "beam".into(),
            version: "29.0.5-elixir1.20.4".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "beam-toolchain/1".into()),
                ("otp_sha256".into(), otp.clone()),
                ("elixir_sha256".into(), elixir.clone()),
                ("hex_sha512".into(), hex_archive.clone()),
                ("rebar3_sha512".into(), rebar3.clone()),
                ("versions".into(), "hex2.5.1:rebar3.25.1".into()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
                (
                    "relocation_schema".into(),
                    "otp-install-cross-minimal/1".into(),
                ),
                ("store_root".into(), "/fixture/blanket-store".into()),
            ]),
        };
        let fingerprint = crate::tailors::elixir::fingerprint_of_joined(&format!(
            "{otp}:{elixir}:{hex_archive}:{rebar3}:otp-install-cross-minimal/1"
        ));
        cached_artifact(store, &otp);
        cached_artifact(store, &elixir);
        let id = commit_legacy_fixture(store, &identity, Some(&[]));
        (id, fingerprint)
    }

    fn hex_deps_identity(fingerprint: &str, outer: &str, inner: &str) -> Identity {
        Identity {
            kind: "hex-deps".into(),
            name: "deps".into(),
            version: "1".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "hex-deps/1".into()),
                ("beam".into(), fingerprint.to_string()),
                (
                    "dep:jason".into(),
                    format!("jason@1.4.4:{outer}:{inner}:mix"),
                ),
            ]),
        }
    }

    /// The containment guard. A migration may make retention more precise,
    /// never narrower.
    ///
    /// A `hex-deps` record names two digests per dependency: the outer
    /// tarball, which is a real cache address, and the inner content
    /// checksum, which normally is not. The old reader could not tell them
    /// apart and retained both. If a file happens to sit at the inner
    /// checksum's cache address, certifying only the outer digest would make
    /// the sweep free a file the old reader kept — so the record must stay
    /// legacy instead.
    #[test]
    fn migration_refuses_to_certify_less_than_the_legacy_reader_retained() {
        let temp = TempStore::new("narrow-migration");
        let store = temp.store();
        let (_beam, fingerprint) = beam_fixture(&store);
        let outer = "a".repeat(64);
        let inner = "b".repeat(64);
        cached_artifact(&store, &outer);
        // The artifact the old reader retained through the inner checksum.
        cached_artifact(&store, &inner);
        let identity = hex_deps_identity(&fingerprint, &outer, &inner);
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            report.unresolved, 1,
            "the narrower certification was accepted: {text}"
        );
        assert!(text.contains("kind hex-deps, schema hex-deps/1"), "{text}");
        assert!(text.contains(&inner), "the reason names no digest: {text}");
        assert!(
            record(&store, &id).evidence == crate::kernel::objmeta::Evidence::Legacy,
            "the record was rewritten despite the narrowing"
        );
        drop(activity);
    }

    /// The mutation check for the guard above: with nothing cached at the
    /// inner checksum's address, the old reader retained nothing there, the
    /// certification narrows nothing, and the same record migrates. A guard
    /// that simply refused every `hex-deps` record would fail this test.
    #[test]
    fn migration_certifies_a_record_whose_evidence_it_can_account_for() {
        let temp = TempStore::new("wide-migration");
        let store = temp.store();
        let (beam, fingerprint) = beam_fixture(&store);
        let outer = "a".repeat(64);
        let inner = "b".repeat(64);
        cached_artifact(&store, &outer);
        let identity = hex_deps_identity(&fingerprint, &outer, &inner);
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        assert_eq!(
            (report.upgraded, report.unresolved),
            (2, 0),
            "{}",
            String::from_utf8_lossy(&out)
        );
        let upgraded = record(&store, &id);
        assert_eq!(
            upgraded.evidence,
            crate::kernel::objmeta::Evidence::Adapted("hex-deps@1".into())
        );
        assert_eq!(upgraded.dependencies, BTreeSet::from([beam]));
        assert_eq!(
            upgraded
                .cache
                .iter()
                .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                .collect::<Vec<_>>(),
            vec![format!("sha256:{outer}")]
        );
        drop(activity);
    }

    /// Unresolved records do not cancel the upgrades that were proven, and
    /// the announced count is the number of records actually written.
    /// The store still refuses to sweep while one legacy record remains.
    #[test]
    fn a_cancelled_migration_does_not_report_upgrades_it_never_wrote() {
        let temp = TempStore::new("cancelled-migration");
        let store = temp.store();
        let digest = "e".repeat(64);
        cached_artifact(&store, &digest);
        let good = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let good_id = commit_legacy_fixture(&store, &good, Some(&[]));
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        let unknown_id = commit_legacy_fixture(&store, &unknown, Some(&[]));

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (1, 1), "{text}");
        assert_eq!(
            record(&store, &good_id).evidence,
            crate::kernel::objmeta::Evidence::Adapted("cpython@1".into())
        );
        assert_eq!(
            record(&store, &unknown_id).evidence,
            crate::kernel::objmeta::Evidence::Legacy,
            "an unknown kind was certified"
        );
        assert!(text.contains("kind not-a-known-kind"), "{text}");
        drop(activity);

        // One legacy record is enough to keep every sweep closed.
        let project = temp.root.join("project");
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        store.register_root(&project).unwrap();
        let mut out = Vec::new();
        let error = collect(&store, Options::default(), &mut out).unwrap_err();
        assert!(
            error.to_string().contains("uncertified legacy record"),
            "{error}"
        );
    }

    fn age(path: &Path) {
        let old = SystemTime::now()
            .checked_sub(Duration::from_secs(2 * 24 * 60 * 60))
            .unwrap();
        fs::File::open(path).unwrap().set_modified(old).unwrap();
    }

    #[test]
    fn liveness_walks_closure_and_transitive_refs() {
        let temp = TempStore::new("liveness");
        let store = temp.store();
        let child = commit(&store, "child", None);
        let parent = commit(&store, "parent", Some(&child));
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(
            &project,
            &store.object_path(&parent),
            serde_json::json!({"id": parent}),
        );
        store.register_root(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(store.object_path(&dead).is_dir());
        assert!(String::from_utf8(output).unwrap().contains(&dead));
    }

    #[test]
    fn collect_legacy_requires_explicit_opt_in() {
        let temp = TempStore::new("keep-days");
        let store = temp.store();
        let id = commit(&store, "new", None);
        let artifact = "a".repeat(64);
        let artifact_path = store.cache_path("sha256", &artifact);
        fs::write(&artifact_path, b"artifact").unwrap();
        age(&artifact_path);
        // An object published before the roots registry existed: certified,
        // but still carrying the opt-in retention boundary migration
        // preserves for a record that never had reference metadata.
        let meta_path = store.root.join("meta").join(format!("{id}.json"));
        let mut meta: serde_json::Value =
            serde_json::from_reader(fs::File::open(&meta_path).unwrap()).unwrap();
        let object = meta.as_object_mut().unwrap();
        object.insert("evidence".into(), serde_json::json!("adapted:test@1"));
        object.insert("legacy_retention".into(), serde_json::json!(true));
        fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        // The project needs a closure of its own to be a resolvable root; it
        // names a real committed object (an unresolvable reference is what
        // the sweep refuses), which the root record then protects — so the
        // legacy object under test stays unprotected.
        let anchor = commit(&store, "anchor", None);
        closure(&project, &store.object_path(&anchor), serde_json::json!({}));
        store.register_root(&project).unwrap();
        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 30,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 0);
        assert_eq!(report.cached_artifacts, 0);
        assert!(store.object_path(&id).exists());
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: true,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert_eq!(report.cached_artifacts, 1);
        assert!(!store.object_path(&id).exists());
        assert!(!artifact_path.exists());
    }

    #[test]
    fn dry_run_reports_sizes_without_removing() {
        let temp = TempStore::new("dry-run");
        let store = temp.store();
        let id = commit(&store, "dry", None);
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        store.register_root(&project).unwrap();
        let orphan = commit(&store, "orphan", None);
        age(&store.object_path(&orphan));
        let mut output = Vec::new();
        collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("would remove object"));
        assert!(output.contains("B)"));
        assert!(store.object_path(&orphan).exists());
    }

    #[test]
    fn node_forest_v2_workspace_kept_when_root_link_is_missing() {
        let temp = TempStore::new("forest-v2");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(project.join(".blanket/closures")).unwrap();
        let project = project.canonicalize().unwrap();
        let home = store.root.parent().unwrap();
        let project_key =
            &hex::encode(sha2::Sha256::digest(project.to_string_lossy().as_bytes()))[..32];
        let projection_id = "a".repeat(32);
        let forest = home.join("forests").join(project_key).join(&projection_id);
        let workspace_forest = forest.join("workspaces/packages%2Flib/node_modules");
        fs::create_dir_all(&workspace_forest).unwrap();
        fs::create_dir_all(project.join("packages/lib")).unwrap();
        std::os::unix::fs::symlink(&workspace_forest, project.join("packages/lib/node_modules"))
            .unwrap();
        fs::write(
            project.join(".blanket/closures/node.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "node",
                "body": {
                    "projection_schema": "node-forest/2",
                    "projection_id": projection_id,
                    "workspaces": ["packages/lib"]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        store.register_root(&project).unwrap();
        age(&forest);

        let mut output = Vec::new();
        let _report = collect(
            &store,
            Options {
                project: true,
                keep_days: 0,
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        assert!(
            workspace_forest.is_dir(),
            "{}",
            String::from_utf8_lossy(&output)
        );
    }

    #[test]
    fn root2_keeps_objects_after_the_project_disappears() {
        let temp = TempStore::new("root2-moved-project");
        let store = temp.store();
        let protected = commit(&store, "root2-protected", None);
        let dead = commit(&store, "root2-dead", None);
        age(&store.object_path(&protected));
        age(&store.object_path(&dead));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let record = store::RootRecord {
            key: store::Store::root_key(&project).unwrap(),
            project_path: project.clone(),
            objects: BTreeSet::from([protected.clone()]),
            projections: BTreeSet::new(),
            updated: 1,
        };
        store.register_root_record(record).unwrap();
        fs::remove_dir_all(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(store.object_path(&protected).exists());
        assert!(!store.object_path(&dead).exists());
    }

    #[test]
    fn retained_object_keeps_old_dependency() {
        let temp = TempStore::new("retained-dependency");
        let store = temp.store();
        let child = commit(&store, "old-child", None);
        age(&store.object_path(&child));
        let parent = commit(&store, "fresh-parent", Some(&child));
        let project = temp.root.join("project");
        // A resolvable root owns a closure naming a real object (an
        // unresolvable reference is exactly what the sweep refuses); the
        // object it names is the fresh parent, which retention keeps anyway.
        closure(&project, &store.object_path(&parent), serde_json::json!({}));
        store.register_root(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 0);
        assert!(store.object_path(&parent).exists());
        assert!(store.object_path(&child).exists());
    }

    #[test]
    fn publication_refreshes_an_old_stage_mtime() {
        let temp = TempStore::new("publication-mtime");
        let store = temp.store();
        let identity = Identity {
            kind: "test".into(),
            name: "published".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), b"payload").unwrap();
        age(&staged);
        let id = identity.object_id();
        store
            .commit_with_deps(&identity, &staged, &[], &store::ObjectDeps::new())
            .unwrap();
        assert!(recent(&store.object_path(&id), ACTIVE_WINDOW));
    }

    /// A registered project whose directory disappears must stop the sweep
    /// and keep its record: with only a pathname record, GC cannot know what
    /// the project still protects.
    #[test]
    fn missing_project_blocks_sweep_and_preserves_record() {
        let temp = TempStore::new("missing-project");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(&project).unwrap();

        for dry_run in [false, true] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    keep_days: 0,
                    project: false,
                    collect_legacy: false,
                    forgotten: Vec::new(),
                },
                &mut output,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("refusing to sweep"), "{message}");
            assert!(message.contains(&entry.key), "{message}");
            assert!(message.contains("--forget"), "{message}");
        }
        assert!(store.object_path(&id).is_dir(), "sweep deleted the object");
        assert!(
            store
                .roots()
                .unwrap()
                .iter()
                .any(|root| root.key == entry.key),
            "sweep removed the record"
        );

        // Forgetting the record is the explicit way out; the next sweep then
        // collects the object nobody protects any more.
        store.forget_root(&entry.key).unwrap();
        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(!store.object_path(&id).exists());
    }

    #[test]
    fn dry_run_forget_ignores_only_the_requested_root_and_writes_nothing() {
        let temp = TempStore::new("dry-forget");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                forgotten: vec![entry.key.clone()],
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("would remove object"));
        assert!(store.object_path(&id).exists());
        assert!(store.lookup_root(&entry.key).is_ok());
    }

    /// A forget names one root, and the preview must exclude that root and
    /// no other. With a second registered project in the store, treating the
    /// request as "ignore every root" would offer up the live object that
    /// second project is still holding.
    #[test]
    fn dry_run_forget_excludes_only_the_named_root() {
        let temp = TempStore::new("dry-forget-two-roots");
        let store = temp.store();
        let released = commit(&store, "released", None);
        let held = commit(&store, "held", None);
        age(&store.object_path(&released));
        age(&store.object_path(&held));

        let gone = temp.root.join("gone");
        fs::create_dir_all(&gone).unwrap();
        closure(&gone, &store.object_path(&released), serde_json::json!({}));
        let gone_entry = store.register_root(&gone).unwrap();

        let present = temp.root.join("present");
        fs::create_dir_all(&present).unwrap();
        closure(&present, &store.object_path(&held), serde_json::json!({}));
        let present_entry = store.register_root(&present).unwrap();
        fs::remove_dir_all(&gone).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                forgotten: vec![gone_entry.key.clone()],
                ..Options::default()
            },
            &mut output,
        )
        .unwrap();
        let preview = String::from_utf8(output).unwrap();
        assert!(preview.contains(&released), "{preview}");
        assert!(
            !preview.contains(&held),
            "the root that was not forgotten stopped protecting its object: {preview}"
        );
        assert_eq!(report.objects, 1, "{preview}");
        assert!(store.object_path(&held).is_dir());
        assert!(store.object_path(&released).is_dir(), "a dry run deleted");
        assert!(store.lookup_root(&present_entry.key).is_ok());
        assert!(store.lookup_root(&gone_entry.key).is_ok());
    }

    #[test]
    fn missing_closures_directory_blocks_sweep() {
        let temp = TempStore::new("missing-closures");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        store.register_root(&project).unwrap();
        fs::remove_dir_all(project.join(".blanket/closures")).unwrap();

        let mut output = Vec::new();
        let error = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("closures"), "{error}");
        assert!(store.object_path(&id).is_dir());
    }

    /// A store from before the roots registry has no marker and no records,
    /// so a sweep there would run with no idea what any project needs. It
    /// must refuse from every entry, including `--project --collect-legacy`,
    /// the combination that exists to reach exactly those old objects. The
    /// end-to-end upgrade test covers this as well, but only in the ignored
    /// suite, which leaves the guard unwatched on an ordinary `cargo test`.
    #[test]
    fn an_uninitialized_registry_blocks_every_sweep() {
        let temp = TempStore::new("uninitialized-registry");
        let store = temp.store();
        let id = commit(&store, "legacy", None);
        age(&store.object_path(&id));
        assert!(!store.root.join("roots/.initialized").exists());

        for (dry_run, project, collect_legacy) in [
            (false, false, false),
            (true, false, false),
            (false, true, true),
        ] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    project,
                    collect_legacy,
                    keep_days: 0,
                    forgotten: Vec::new(),
                },
                &mut output,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("registry is not initialized"), "{message}");
        }
        assert!(store.object_path(&id).is_dir(), "sweep deleted the object");
    }

    /// A root that resolves to a directory holding no closures cannot say
    /// what it needs. The reachable version of this is a pathname that now
    /// names something else — the backing directory of an unmounted mount
    /// point — so it is a safety stop, not an empty contribution.
    #[test]
    fn empty_closures_directory_blocks_sweep() {
        let temp = TempStore::new("empty-closures");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        for closure in fs::read_dir(project.join(".blanket/closures")).unwrap() {
            fs::remove_file(closure.unwrap().path()).unwrap();
        }

        for dry_run in [false, true] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    keep_days: 0,
                    ..Options::default()
                },
                &mut output,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("refusing to sweep"), "{message}");
            assert!(message.contains(&entry.key), "{message}");
        }
        assert!(store.object_path(&id).is_dir(), "sweep deleted the object");
        assert_eq!(store.roots().unwrap().len(), 1, "sweep removed the record");
    }

    /// An I/O error other than a clean miss (here: a symlink loop where the
    /// project used to be) must stop the sweep with the underlying error
    /// named, never silently delete the record.
    #[test]
    fn io_error_on_project_path_blocks_sweep() {
        let temp = TempStore::new("io-error");
        let store = temp.store();
        let id = commit(&store, "protected", None);
        age(&store.object_path(&id));
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(&project, &store.object_path(&id), serde_json::json!({}));
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(&project).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&project, &project).unwrap();

        let mut output = Vec::new();
        let error = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                collect_legacy: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("refusing to sweep"), "{message}");
        assert!(message.contains(&entry.key), "{message}");
        assert!(store.object_path(&id).is_dir());
        assert!(store.roots().unwrap().len() == 1, "record was removed");
    }

    #[test]
    fn forget_rejects_unknown_and_malformed_keys() {
        let temp = TempStore::new("forget-keys");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        closure(
            &project,
            &store.object_path(&commit(&store, "x", None)),
            serde_json::json!({}),
        );
        store.register_root(&project).unwrap();

        let error = store.forget_root(&"a".repeat(40)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let error = store.forget_root("not-a-key").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = store.forget_root(&"g".repeat(40)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(store.roots().unwrap().len(), 1);
    }

    // =======================================================================
    // GC safety acceptance tests.
    //
    // Each name below covers one GC-safety failure mode. The x-cleanup pair
    // lives with the code it covers, in `commands::x`.
    // =======================================================================

    /// Register `project` as a durable root/2 record naming `objects`.
    fn register_objects(store: &Store, project: &Path, objects: &[&str]) -> String {
        fs::create_dir_all(project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = store::Store::root_key(&project).unwrap();
        store
            .register_root_record(store::RootRecord {
                key: key.clone(),
                project_path: project,
                objects: objects.iter().map(|id| id.to_string()).collect(),
                projections: BTreeSet::new(),
                updated: 1,
            })
            .unwrap();
        key
    }

    /// Rewrite one record's JSON in place.
    fn edit_record(
        store: &Store,
        id: &str,
        edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) {
        let path = store.root.join("meta").join(format!("{id}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(value.as_object_mut().unwrap());
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn sweep(store: &Store, options: Options) -> (io::Result<Report>, String) {
        let mut out = Vec::new();
        let result = collect(store, options, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    /// Run the phases by hand so a test can mutate the store between the
    /// plan and its execution.
    fn planned<'a>(
        store: &Store,
        activity: &StoreActivity,
        options: &Options,
        snapshot: &'a mut Option<Snapshot>,
    ) -> SweepPlan {
        let mut out = Vec::new();
        *snapshot = Some(read(store, activity, options, &BTreeMap::new(), &mut out).unwrap());
        let taken = snapshot.as_ref().unwrap();
        let validated = validate(taken, options).unwrap();
        plan(&validated, options).unwrap()
    }

    #[test]
    fn shared_dependency_survives_forgetting_one_of_two_projects() {
        let temp = TempStore::new("shared-dep-one");
        let store = temp.store();
        let shared = commit(&store, "shared", None);
        let first = commit(&store, "first", Some(&shared));
        let second = commit(&store, "second", Some(&shared));
        for id in [&shared, &first, &second] {
            age(&store.object_path(id));
        }
        let one = register_objects(&store, &temp.root.join("one"), &[&first]);
        register_objects(&store, &temp.root.join("two"), &[&second]);
        store.forget_root(&one).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            store.object_path(&shared).is_dir(),
            "the surviving project's dependency was collected: {text}"
        );
        assert!(store.object_path(&second).is_dir(), "{text}");
        assert!(!store.object_path(&first).exists(), "{text}");
    }

    #[test]
    fn after_forgetting_both_the_shared_dependency_is_collectible_when_age_allows() {
        let temp = TempStore::new("shared-dep-both");
        let store = temp.store();
        let shared = commit(&store, "shared", None);
        let first = commit(&store, "first", Some(&shared));
        let second = commit(&store, "second", Some(&shared));
        for id in [&shared, &first, &second] {
            age(&store.object_path(id));
        }
        let one = register_objects(&store, &temp.root.join("one"), &[&first]);
        let two = register_objects(&store, &temp.root.join("two"), &[&second]);
        store.forget_root(&one).unwrap();
        store.forget_root(&two).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 3, "{text}");
        assert!(!store.object_path(&shared).exists(), "{text}");
    }

    /// Corrupt the *last* root record: nothing earlier may already be gone.
    #[test]
    fn corrupt_late_root_deletes_nothing_earlier() {
        let temp = TempStore::new("corrupt-late-root");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let mut keys = Vec::new();
        for name in ["alpha", "omega"] {
            keys.push(register_objects(&store, &temp.root.join(name), &[]));
        }
        keys.sort();
        let last = keys.last().unwrap();
        fs::write(store.root.join("roots").join(last), b"{ not json").unwrap();

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(
            result.is_err(),
            "a corrupt root record did not stop the sweep: {text}"
        );
        assert!(
            store.object_path(&dead).is_dir(),
            "an earlier candidate was deleted before the corrupt record was read: {text}"
        );
    }

    /// Corrupt the metadata of an object that sorts after a deletable one.
    #[test]
    fn corrupt_late_metadata_deletes_nothing_earlier() {
        let temp = TempStore::new("corrupt-late-meta");
        let store = temp.store();
        let mut ids = vec![commit(&store, "one", None), commit(&store, "two", None)];
        ids.sort();
        for id in &ids {
            age(&store.object_path(id));
        }
        register_objects(&store, &temp.root.join("project"), &[]);
        let last = ids.last().unwrap().clone();
        fs::write(
            store.root.join("meta").join(format!("{last}.json")),
            b"{ not json",
        )
        .unwrap();

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "{text}");
        for id in &ids {
            assert!(
                store.object_path(id).is_dir(),
                "a candidate was deleted before the corrupt record was read: {text}"
            );
        }
    }

    #[test]
    fn missing_transitive_metadata_aborts_the_sweep() {
        let temp = TempStore::new("missing-transitive");
        let store = temp.store();
        let child = commit(&store, "child", None);
        let parent = commit(&store, "parent", Some(&child));
        register_objects(&store, &temp.root.join("project"), &[&parent]);
        fs::remove_file(store.root.join("meta").join(format!("{child}.json"))).unwrap();

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(&child),
            "the missing id is not named: {error}"
        );
        assert!(store.object_path(&parent).is_dir());
        assert!(store.object_path(&child).is_dir());
    }

    #[test]
    fn dependency_cycle_terminates_and_retains_both() {
        let temp = TempStore::new("cycle");
        let store = temp.store();
        let one = commit(&store, "one", None);
        let two = commit(&store, "two", None);
        // Dependencies live in metadata, not in the identity hash, so a
        // cycle is representable even though object ids are input-addressed.
        edit_record(&store, &one, |record| {
            record.insert("dependencies".into(), serde_json::json!([two]));
        });
        edit_record(&store, &two, |record| {
            record.insert("dependencies".into(), serde_json::json!([one]));
        });
        age(&store.object_path(&one));
        age(&store.object_path(&two));
        register_objects(&store, &temp.root.join("project"), &[&one]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 0, "{text}");
        assert!(store.object_path(&one).is_dir());
        assert!(store.object_path(&two).is_dir());
    }

    #[test]
    fn unknown_metadata_schema_blocks_destructive_gc() {
        let temp = TempStore::new("unknown-schema");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        let odd = commit(&store, "odd", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        edit_record(&store, &odd, |record| {
            record.insert("schema".into(), serde_json::json!("object-meta/3"));
        });

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("unknown metadata schema object-meta/3"),
            "{error}"
        );
        assert!(store.object_path(&dead).is_dir(), "a sweep ran anyway");
    }

    #[test]
    fn invalid_reference_in_metadata_is_an_error() {
        let temp = TempStore::new("invalid-reference");
        let store = temp.store();
        let id = commit(&store, "broken", None);
        register_objects(&store, &temp.root.join("project"), &[]);
        edit_record(&store, &id, |record| {
            record.insert(
                "dependencies".into(),
                serde_json::json!(["not-an-object-id"]),
            );
        });

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("malformed or duplicate dependency"),
            "{error}"
        );
    }

    #[test]
    fn traversal_string_in_a_reference_is_rejected() {
        let temp = TempStore::new("traversal-reference");
        let store = temp.store();
        let id = commit(&store, "broken", None);
        register_objects(&store, &temp.root.join("project"), &[]);
        for traversal in [
            "../../../etc/passwd",
            &format!("{}-../escape", "a".repeat(40)),
        ] {
            edit_record(&store, &id, |record| {
                record.insert("dependencies".into(), serde_json::json!([traversal]));
            });
            let (result, _) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("malformed or duplicate dependency"),
                "{traversal:?} was accepted: {error}"
            );
        }
    }

    #[test]
    fn symlink_replacement_of_a_candidate_stops_that_deletion() {
        let temp = TempStore::new("symlink-replacement");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);
        assert_eq!(sweep_plan.removals.len(), 1);

        // Replace the planned candidate with a symlink to somewhere else.
        let elsewhere = temp.root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        store::remove_tree(&store.object_path(&dead)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.object_path(&dead)).unwrap();

        let mut out = Vec::new();
        let error = execute(
            &sweep_plan,
            held.as_ref().unwrap(),
            &store,
            &activity,
            &mut out,
        )
        .unwrap_err();
        // A filesystem that reuses the inode number reports the type change
        // instead of the replacement; both refuse the deletion.
        let text = error.to_string();
        assert!(
            text.contains("was replaced") || text.contains("changed file type"),
            "the replacement was not detected: {error}"
        );
        assert!(
            elsewhere.is_dir(),
            "the symlink target was followed and deleted"
        );
        drop(activity);
    }

    #[test]
    fn type_change_of_a_candidate_stops_that_deletion() {
        let temp = TempStore::new("type-change");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);

        store::remove_tree(&store.object_path(&dead)).unwrap();
        fs::write(store.object_path(&dead), b"now a file").unwrap();

        let mut out = Vec::new();
        let error = execute(
            &sweep_plan,
            held.as_ref().unwrap(),
            &store,
            &activity,
            &mut out,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("was replaced") || text.contains("changed file type"),
            "a type change was not detected: {text}"
        );
        assert!(
            store.object_path(&dead).is_file(),
            "the replacement was deleted"
        );
        drop(activity);
    }

    #[test]
    fn partial_execution_error_reports_completed_deletions_honestly() {
        let temp = TempStore::new("partial-execution");
        let store = temp.store();
        let mut dead: Vec<String> = (0..2)
            .map(|index| commit(&store, &format!("dead{index}"), None))
            .collect();
        dead.sort();
        for id in &dead {
            age(&store.object_path(id));
        }
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);
        assert_eq!(sweep_plan.removals.len(), 2);
        // Break whichever candidate the plan removes second.
        let second = sweep_plan.removals[1].name.to_string_lossy().into_owned();
        store::remove_tree(&store.object_path(&second)).unwrap();
        fs::write(store.object_path(&second), b"replaced").unwrap();

        let mut out = Vec::new();
        let error = execute(
            &sweep_plan,
            held.as_ref().unwrap(),
            &store,
            &activity,
            &mut out,
        )
        .unwrap_err();
        let text = String::from_utf8(out).unwrap();
        assert!(error.to_string().contains(&second), "{error}");
        assert!(
            text.contains("deletions already completed: 1 objects"),
            "the completed deletion was not reported: {text}"
        );
        let first = sweep_plan.removals[0].name.to_string_lossy().into_owned();
        assert!(
            !store.object_path(&first).exists(),
            "the first deletion was rolled back"
        );
        drop(activity);
    }

    /// A crashed registry write leaves `.<key>.tmp.<pid>.<seq>` residue. The
    /// read phase must leave it exactly as found — including its containing
    /// directory's mtime — during a dry run.
    #[test]
    fn dry_run_leaves_crashed_registry_temporaries() {
        let temp = TempStore::new("dry-run-temp");
        let store = temp.store();
        register_objects(&store, &temp.root.join("project"), &[]);
        let key =
            store::Store::root_key(&temp.root.join("project").canonicalize().unwrap()).unwrap();
        let path = store.root.join("roots").join(format!(".{key}.tmp.1234.0"));
        fs::write(&path, b"crash between registry write and rename").unwrap();
        let before_roots = fs::metadata(store.root.join("roots"))
            .unwrap()
            .modified()
            .unwrap();

        let (result, text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..Options::default()
            },
        );
        result.unwrap();
        assert!(
            path.is_file(),
            "the read phase deleted a registry temporary during --dry-run: {text}"
        );
        assert_eq!(
            fs::metadata(store.root.join("roots"))
                .unwrap()
                .modified()
                .unwrap(),
            before_roots,
            "enumeration refreshed the roots directory timestamp"
        );

        // A real sweep with nothing else to do still cleans the residue,
        // under the exclusive lease, after validation.
        let (result, _) = sweep(&store, Options::default());
        result.unwrap();
        assert!(
            !path.exists(),
            "the execute phase did not clear the crashed temporary"
        );
    }

    /// A sweep that fails validation must not clean crash residue either:
    /// the zero-deletions promise covers every file the read phase saw,
    /// including temporaries.
    #[test]
    fn failed_validation_leaves_crashed_registry_temporaries() {
        let temp = TempStore::new("failed-validation-temp");
        let store = temp.store();
        register_objects(&store, &temp.root.join("project"), &[]);
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        commit_legacy_fixture(&store, &unknown, Some(&[]));
        let key =
            store::Store::root_key(&temp.root.join("project").canonicalize().unwrap()).unwrap();
        let path = store.root.join("roots").join(format!(".{key}.tmp.1234.0"));
        fs::write(&path, b"crash residue").unwrap();

        let (result, _) = sweep(&store, Options::default());
        assert!(result.is_err(), "a legacy record did not stop the sweep");
        assert!(
            path.is_file(),
            "a failed validation deleted a registry temporary"
        );
    }

    /// The object removal succeeds, the companion metadata unlink fails, and
    /// the sweep must still report the completed deletion — and name the
    /// recovery path for the orphaned record, which would otherwise wedge
    /// every future sweep.
    #[test]
    fn object_removed_but_metadata_unlink_fails_is_reported() {
        // Root ignores the read-only directory mode this test relies on.
        // SAFETY: geteuid takes no arguments and always succeeds.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = TempStore::new("meta-unlink-fails");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut held = None;
        let sweep_plan = planned(&store, &activity, &options, &mut held);
        assert_eq!(sweep_plan.removals.len(), 1);

        let meta_dir = store.root.join("meta");
        let mut perms = fs::metadata(&meta_dir).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o555);
        fs::set_permissions(&meta_dir, perms).unwrap();
        let outcome = (|| {
            let mut out = Vec::new();
            let result = execute(
                &sweep_plan,
                held.as_ref().unwrap(),
                &store,
                &activity,
                &mut out,
            );
            (result, String::from_utf8(out).unwrap())
        })();
        // Restore before asserting, so a failed assertion cannot leave the
        // fixture store uncleanable.
        let mut perms = fs::metadata(&meta_dir).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&meta_dir, perms).unwrap();
        let (result, text) = outcome;

        let error = result.unwrap_err().to_string();
        assert!(
            !store.object_path(&dead).exists(),
            "the object was not removed: {error}"
        );
        assert!(
            text.contains("deletions already completed: 1 objects"),
            "the completed object deletion was not reported: {text}"
        );
        assert!(
            error.contains("orphaned") && error.contains("--migrate-metadata"),
            "the recovery path is not named: {error}"
        );

        // The leftover record does wedge the next sweep, but the named
        // recovery path clears it.
        drop(activity);
        let (result, _) = sweep(&store, Options::default());
        assert!(result.is_err(), "a stray record did not block the sweep");
        let meta_path = meta_dir.join(format!("{dead}.json"));
        fs::remove_file(&meta_path).unwrap();
        let (result, _) = sweep(&store, Options::default());
        result.unwrap();
    }

    /// A legacy store: the dry run must adapt in memory, migrate nothing on
    /// disk, remove no root, and refresh no timestamp.
    #[test]
    fn dry_run_removes_no_root_migrates_nothing_and_refreshes_no_timestamp() {
        let temp = TempStore::new("dry-run-immutable");
        let store = temp.store();
        let digest = "1".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));
        age(&store.object_path(&id));
        let key = register_objects(&store, &temp.root.join("project"), &[&id]);
        let meta_path = store.root.join("meta").join(format!("{id}.json"));
        let before_meta = fs::read(&meta_path).unwrap();
        let before_object = fs::metadata(store.object_path(&id))
            .unwrap()
            .modified()
            .unwrap();
        let before_roots = fs::read(store.root.join("roots").join(&key)).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(text.contains("would migrate metadata"), "{text}");
        assert_eq!(
            fs::read(&meta_path).unwrap(),
            before_meta,
            "a dry run wrote a record"
        );
        assert_eq!(
            fs::metadata(store.object_path(&id))
                .unwrap()
                .modified()
                .unwrap(),
            before_object,
            "a dry run refreshed an object timestamp"
        );
        assert_eq!(
            fs::read(store.root.join("roots").join(&key)).unwrap(),
            before_roots,
            "a dry run changed a root record"
        );
        assert_eq!(
            record(&store, &id).evidence,
            crate::kernel::objmeta::Evidence::Legacy
        );
    }

    /// Build a legacy store with one live object, one dead object and one
    /// unreferenced cached artifact.
    fn legacy_store(temp: &TempStore) -> (Store, String, String) {
        let store = temp.store();
        let live_digest = "1".repeat(64);
        let dead_digest = "2".repeat(64);
        cached_artifact(&store, &live_digest);
        cached_artifact(&store, &dead_digest);
        age(&store.cache_path("sha256", &live_digest));
        age(&store.cache_path("sha256", &dead_digest));
        let make = |version: &str, digest: &str| Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: version.into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.to_string()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let live = commit_legacy_fixture(&store, &make("3.11.9", &live_digest), Some(&[]));
        let dead = commit_legacy_fixture(&store, &make("3.12.7", &dead_digest), Some(&[]));
        age(&store.object_path(&live));
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[&live]);
        (store, live, dead)
    }

    #[test]
    fn dry_run_and_real_sweep_produce_the_same_plan() {
        let temp = TempStore::new("same-plan");
        let (store, live, dead) = legacy_store(&temp);
        let options = || Options {
            keep_days: 0,
            ..Options::default()
        };

        let (preview, text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..options()
            },
        );
        let preview = preview.unwrap();
        assert!(
            text.contains(&dead),
            "the dead object was not previewed: {text}"
        );
        assert!(!text.contains(&format!(
            "would remove object {}",
            store.object_path(&live).display()
        )));

        let (real, real_text) = sweep(&store, options());
        let real = real.unwrap();
        assert_eq!(preview, real, "preview {text}\nreal {real_text}");
        assert!(!store.object_path(&dead).exists(), "{real_text}");
        assert!(store.object_path(&live).is_dir(), "{real_text}");
    }

    /// The dry run's
    /// in-memory adaptation and the real sweep's published one must agree.
    #[test]
    fn dry_run_adapts_in_memory_and_matches_real_plan_at_the_same_time() {
        let temp = TempStore::new("adapt-in-memory");
        let (store, _live, dead) = legacy_store(&temp);
        let options = Options {
            keep_days: 0,
            ..Options::default()
        };

        let (preview, preview_text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..options.clone()
            },
        );
        let preview = preview.unwrap();
        // Nothing was published, so the store is still legacy...
        assert_eq!(
            record(&store, &dead).evidence,
            crate::kernel::objmeta::Evidence::Legacy
        );
        // ...yet the preview planned a deletion, which is only possible if
        // the adaptation happened in memory.
        assert_eq!(preview.objects, 1, "{preview_text}");

        let (real, real_text) = sweep(&store, options);
        assert_eq!(preview, real.unwrap(), "{preview_text}\n{real_text}");
    }

    #[test]
    fn collect_legacy_cannot_override_incomplete_evidence() {
        let temp = TempStore::new("collect-legacy-override");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        commit_legacy_fixture(&store, &unknown, Some(&[]));
        register_objects(&store, &temp.root.join("project"), &[]);

        for collect_legacy in [false, true] {
            let (result, text) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    collect_legacy,
                    ..Options::default()
                },
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("uncertified legacy record"),
                "--collect-legacy={collect_legacy} authorized a sweep: {error} {text}"
            );
            assert!(store.object_path(&dead).is_dir());
        }
    }

    #[test]
    fn legacy_metadata_with_an_adapter_migrates_and_validates_the_id() {
        let temp = TempStore::new("adapter-validates-id");
        let store = temp.store();
        let digest = "3".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest.clone()),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (1, 0));
        let upgraded = record(&store, &id);
        assert_eq!(
            upgraded.evidence,
            crate::kernel::objmeta::Evidence::Adapted("cpython@1".into())
        );
        assert_eq!(
            upgraded
                .cache
                .iter()
                .map(|d| d.hex().to_string())
                .collect::<Vec<_>>(),
            vec![digest]
        );
        drop(activity);

        // The id/identity relationship is validated on every read: a record
        // whose identity hashes to something else is refused, not adapted.
        edit_record(&store, &id, |record| {
            record.insert(
                "identity".into(),
                serde_json::json!({
                    "kind": "cpython",
                    "name": "cpython",
                    "version": "9.9.9",
                    "inputs": {},
                }),
            );
        });
        let error = crate::kernel::objmeta::read_record_at(
            &store.root.join("meta").join(format!("{id}.json")),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("hashes to a different object id"), "{error}");
    }

    #[test]
    fn legacy_metadata_with_an_unknown_kind_stays_blocked_and_is_named() {
        let temp = TempStore::new("unknown-kind-blocked");
        let store = temp.store();
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "7".into(),
            inputs: BTreeMap::from([("schema".into(), "mystery/4".into())]),
        };
        let id = commit_legacy_fixture(&store, &unknown, Some(&[]));
        register_objects(&store, &temp.root.join("project"), &[]);

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let report = migrate_metadata(&store, &activity, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (0, 1));
        assert!(text.contains(&id), "the object id is not named: {text}");
        assert!(
            text.contains("kind not-a-known-kind, schema mystery/4"),
            "the kind and schema are not named: {text}"
        );
        drop(activity);

        let (result, _) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "a store with an unknown kind swept anyway");
        assert_eq!(
            record(&store, &id).evidence,
            crate::kernel::objmeta::Evidence::Legacy
        );
    }

    #[test]
    fn cache_hit_does_not_certify_old_inferred_metadata() {
        let temp = TempStore::new("cache-hit-no-certify");
        let store = temp.store();
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), "4".repeat(64)),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));
        let before = fs::read(store.root.join("meta").join(format!("{id}.json"))).unwrap();

        // A newer binary publishes the same identity with real evidence and
        // finds the object already there. The cache hit must leave the old
        // record exactly as it was; upgrading it is migration's job alone.
        let digest = "4".repeat(64);
        cached_artifact(&store, &digest);
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "cpython").unwrap();
        let mut deps = ObjectDeps::new();
        deps.cache_digest(crate::kernel::fetch::Digest::sha256(&digest).unwrap());
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();

        assert_eq!(
            fs::read(store.root.join("meta").join(format!("{id}.json"))).unwrap(),
            before,
            "a cache hit rewrote a legacy record"
        );
        assert_eq!(
            record(&store, &id).evidence,
            crate::kernel::objmeta::Evidence::Legacy
        );
    }

    #[test]
    fn automatic_maintenance_precedes_shared_job_activity() {
        let temp = TempStore::new("maintenance-precedes");
        let store = temp.store();
        let digest = "5".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        // The shape `Context::open` uses: maintenance first, then the job's
        // token.
        let mut out = Vec::new();
        let report = automatic_maintenance(&store, &mut out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (1, 0));
        assert_eq!(
            record(&store, &id).evidence,
            crate::kernel::objmeta::Evidence::Adapted("cpython@1".into())
        );
        let job = store.activity(ActivityMode::Shared).unwrap();
        store.require_activity(&job, "job").unwrap();
        drop(job);

        // Re-running it under no lease is an idempotent no-op.
        let mut out = Vec::new();
        let again = automatic_maintenance(&store, &mut out).unwrap();
        assert_eq!((again.upgraded, again.unresolved), (0, 0));
    }

    #[test]
    fn busy_automatic_maintenance_defers_without_lock_upgrade() {
        let temp = TempStore::new("maintenance-defers");
        let store = temp.store();
        let digest = "6".repeat(64);
        cached_artifact(&store, &digest);
        let identity = Identity {
            kind: "cpython".into(),
            name: "cpython".into(),
            version: "3.11.9".into(),
            inputs: BTreeMap::from([
                ("artifact_sha256".into(), digest),
                ("platform".into(), "x86_64-unknown-linux-gnu".into()),
            ]),
        };
        let id = commit_legacy_fixture(&store, &identity, Some(&[]));

        // A job already owns the store. Maintenance must report a deferral
        // and return, never wait for or upgrade the caller's own lease.
        let job = store.activity(ActivityMode::Shared).unwrap();
        let mut out = Vec::new();
        let report = automatic_maintenance(&store, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!((report.upgraded, report.unresolved), (0, 0));
        assert!(text.contains("metadata maintenance deferred"), "{text}");
        assert_eq!(
            record(&store, &id).evidence,
            crate::kernel::objmeta::Evidence::Legacy
        );
        // The caller's own lease is untouched and still usable.
        store.require_activity(&job, "job").unwrap();
        drop(job);
    }

    #[test]
    fn migration_failure_never_starts_deletion() {
        let temp = TempStore::new("migration-failure");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
        let artifact = "7".repeat(64);
        cached_artifact(&store, &artifact);
        age(&store.cache_path("sha256", &artifact));
        // A record whose adapter cannot resolve its indirect reference: the
        // Go toolchain it names has been collected by an older sweep.
        let unresolvable = Identity {
            kind: "go-modcache".into(),
            name: "modcache".into(),
            version: "0".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "go-modcache/1".into()),
                ("extractor".into(), format!("go1.25.3:{}", "8".repeat(64))),
            ]),
        };
        commit_legacy_fixture(&store, &unresolvable, Some(&[]));
        register_objects(&store, &temp.root.join("project"), &[]);

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "{text}");
        assert!(
            store.object_path(&dead).is_dir(),
            "an object was deleted: {text}"
        );
        assert!(
            store.cache_path("sha256", &artifact).is_file(),
            "a cached artifact was deleted: {text}"
        );
    }

    #[test]
    fn sha1_sha256_and_sha512_artifacts_follow_retained_object_digests() {
        let temp = TempStore::new("all-algorithms");
        let store = temp.store();
        for algo in ["sha1", "sha256", "sha512"] {
            fs::create_dir_all(store.root.join("cache").join(algo)).unwrap();
        }
        let widths = [("sha1", 40), ("sha256", 64), ("sha512", 128)];
        let mut deps = ObjectDeps::new();
        let mut kept = Vec::new();
        let mut dropped = Vec::new();
        for (algo, width) in widths {
            let keep: String = std::iter::repeat_n('a', width).collect();
            let drop_it: String = std::iter::repeat_n('b', width).collect();
            for hex in [&keep, &drop_it] {
                let path = store.cache_path(algo, hex);
                fs::write(&path, b"artifact").unwrap();
                age(&path);
            }
            let digest = match algo {
                "sha1" => crate::kernel::fetch::Digest::sha1(&keep),
                "sha256" => crate::kernel::fetch::Digest::sha256(&keep),
                _ => crate::kernel::fetch::Digest::sha512(&keep),
            }
            .unwrap();
            deps.cache_digest(digest);
            kept.push((algo, keep));
            dropped.push((algo, drop_it));
        }
        let identity = test_identity("all-algos", None);
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "all").unwrap();
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();
        register_objects(&store, &temp.root.join("project"), &[&id]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().cached_artifacts, 3, "{text}");
        for (algo, hex) in kept {
            assert!(
                store.cache_path(algo, &hex).is_file(),
                "{algo}:{hex} was collected: {text}"
            );
        }
        for (algo, hex) in dropped {
            assert!(
                !store.cache_path(algo, &hex).exists(),
                "{algo}:{hex} survived: {text}"
            );
        }
    }

    #[test]
    fn hex_package_tarballs_remain_cached_for_a_retained_hex_object() {
        let temp = TempStore::new("hex-tarballs");
        let store = temp.store();
        let (beam, fingerprint) = beam_fixture(&store);
        let outer = "a".repeat(64);
        cached_artifact(&store, &outer);
        age(&store.cache_path("sha256", &outer));
        let stray = "f".repeat(64);
        cached_artifact(&store, &stray);
        age(&store.cache_path("sha256", &stray));
        let identity = hex_deps_identity(&fingerprint, &outer, &"b".repeat(64));
        let deps_id = commit_legacy_fixture(&store, &identity, Some(&[]));
        age(&store.object_path(&deps_id));
        age(&store.object_path(&beam));
        register_objects(&store, &temp.root.join("project"), &[&deps_id]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            store.cache_path("sha256", &outer).is_file(),
            "a retained hex object lost its package tarball: {text}"
        );
        assert!(
            store.object_path(&beam).is_dir(),
            "the BEAM object was collected: {text}"
        );
        assert!(!store.cache_path("sha256", &stray).exists(), "{text}");
    }

    #[test]
    fn retained_backup_and_nested_hex_projection_are_not_deleted() {
        let temp = TempStore::new("nested-projections");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = store::Store::root_key(&project).unwrap();

        // A hex deps projection nested below a swept forest ancestor, and a
        // backup directory. Both are claimed by the surviving root record.
        let forest_project = store.root.join("forests").join(&key);
        let projection = forest_project.join("hex-deps");
        let nested = projection.join("deps/jason/ebin");
        fs::create_dir_all(&nested).unwrap();
        let backup = store
            .root
            .join("backups")
            .join(format!("{key}-node_modules"));
        fs::create_dir_all(&backup).unwrap();
        let stale = forest_project.join("unclaimed");
        fs::create_dir_all(&stale).unwrap();
        for path in [&projection, &backup, &stale, &forest_project] {
            age(path);
        }

        // A second forest project whose whole directory the root claims:
        // the enumerated candidates below it are *descendants* of the claim,
        // which `related` must keep through prefix matching, not equality.
        let project2 = temp.root.join("project2");
        fs::create_dir_all(&project2).unwrap();
        let project2 = project2.canonicalize().unwrap();
        let key2 = store::Store::root_key(&project2).unwrap();
        let forest_project2 = store.root.join("forests").join(&key2);
        let nested2 = forest_project2.join("node_modules/left-pad");
        fs::create_dir_all(&nested2).unwrap();
        age(&nested2);
        age(&forest_project2);

        store
            .register_root_record(store::RootRecord {
                key: key.clone(),
                project_path: project,
                objects: BTreeSet::new(),
                projections: BTreeSet::from([
                    // A claim strictly *inside* the enumerated candidate:
                    // `hex-deps` itself is swept as a whole projection, but
                    // the record names a deeper path, so ancestor matching
                    // (`keep` is a descendant of the candidate) must keep it.
                    store::ProjectionRef::new(
                        store::ProjectionBase::Forests,
                        vec![
                            key.clone().into(),
                            "hex-deps".into(),
                            "deps".into(),
                            "jason".into(),
                        ],
                    )
                    .unwrap(),
                    // An ancestor claim: every candidate under forest_project2
                    // is protected by the record, not by being named exactly.
                    store::ProjectionRef::new(
                        store::ProjectionBase::Forests,
                        vec![key2.clone().into()],
                    )
                    .unwrap(),
                    store::ProjectionRef::new(
                        store::ProjectionBase::Backups,
                        vec![format!("{key}-node_modules").into()],
                    )
                    .unwrap(),
                ]),
                updated: 1,
            })
            .unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            nested.is_dir(),
            "a nested hex projection was deleted: {text}"
        );
        assert!(backup.is_dir(), "a retained backup was deleted: {text}");
        assert!(
            nested2.is_dir(),
            "a projection below a claimed ancestor was deleted: {text}"
        );
        assert!(!stale.exists(), "an unclaimed forest survived: {text}");
    }

    // =======================================================================
    // Cross-component retention cases that this sweep interacts with.
    //
    // These are root-record and projection retention cases whose behaviour
    // this sweep decides. Other retention cases belong with their owners.
    // =======================================================================

    /// Publication writes the durable record before the closure. A crash in
    /// that window leaves a record naming objects no closure mentions yet —
    /// which must protect *more*, never less.
    #[test]
    fn crash_after_record_write_leaves_extra_protection() {
        let temp = TempStore::new("crash-after-record");
        let store = temp.store();
        let named = commit(&store, "named", None);
        let unnamed = commit(&store, "unnamed", None);
        age(&store.object_path(&named));
        age(&store.object_path(&unnamed));
        // The record landed naming both objects; the project has no closure
        // file yet, exactly as a crash between the two writes would leave it.
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut refs = crate::comforter::ClosureRefs::new();
        refs.object_id(&store, &activity, &named).unwrap();
        refs.object_id(&store, &activity, &unnamed).unwrap();
        crate::comforter::write_closure(
            &project,
            "python",
            serde_json::json!({"ok": true}),
            &store,
            &activity,
            refs,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();
        drop(activity);
        // Crash window: the visible closure is gone, the durable record is not.
        fs::remove_dir_all(project.join(".blanket/closures")).unwrap();
        assert!(!project.join(".blanket/closures").exists());

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 0, "{text}");
        assert!(store.object_path(&named).is_dir(), "{text}");
        assert!(
            store.object_path(&unnamed).is_dir(),
            "a record written before its closure lost protection: {text}"
        );
    }

    /// A publication that fails before the record write leaves no record and
    /// no closure. The objects are simply unprotected: the sweep is not
    /// blocked, and it does not invent a root for them.
    #[test]
    fn crash_before_record_write_publishes_no_closure() {
        let temp = TempStore::new("crash-before-record");
        let store = temp.store();
        let orphan = commit(&store, "orphan", None);
        age(&store.object_path(&orphan));
        register_objects(&store, &temp.root.join("other"), &[]);
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        // Real publication with an unavailable reference: it must fail
        // before either durable write, so nothing is published.
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut refs = crate::comforter::ClosureRefs::new();
        refs.object_id(&store, &activity, &("0".repeat(40) + "-missing-1"))
            .unwrap_err();
        assert!(!project.join(".blanket/closures").exists());
        let roots = store.roots().unwrap();
        assert!(
            roots.iter().all(|root| root
                .record
                .as_ref()
                .map(|r| r.project_path != project)
                .unwrap_or(true)),
            "a failed publication wrote a durable record"
        );
        assert!(!project.join(".blanket/closures").exists());
        drop(activity);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 1, "{text}");
        assert!(!store.object_path(&orphan).exists(), "{text}");
    }

    /// A pathname-only record whose project is gone blocks every sweep. Both
    /// documented resolutions must actually clear it.
    #[test]
    fn legacy_record_still_blocks_until_registered_or_forgotten() {
        for resolution in ["forget", "restore"] {
            let temp = TempStore::new(&format!("legacy-blocks-{resolution}"));
            let store = temp.store();
            let dead = commit(&store, "dead", None);
            age(&store.object_path(&dead));
            let project = temp.root.join("project");
            fs::create_dir_all(project.join(".blanket/closures")).unwrap();
            let entry = store.register_root(&project).unwrap();
            fs::remove_dir_all(&project).unwrap();

            let (result, _) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            assert!(
                result.is_err(),
                "an unavailable pathname-only project did not block the sweep"
            );
            assert!(store.object_path(&dead).is_dir());

            match resolution {
                "forget" => {
                    store.forget_root(&entry.key).unwrap();
                }
                _ => {
                    // Restore the project to a state a sweep may run over:
                    // an empty closures directory does not count — a
                    // registered project owns at least one closure.
                    let closure = project.join(".blanket/closures/python.json");
                    fs::create_dir_all(closure.parent().unwrap()).unwrap();
                    fs::write(
                        closure,
                        serde_json::json!({
                            "schema": "closure/1",
                            "ecosystem": "python",
                            "body": {"ok": true}
                        })
                        .to_string(),
                    )
                    .unwrap();
                }
            }
            let (report, text) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            assert_eq!(
                report.unwrap().objects,
                1,
                "{resolution} did not unblock the sweep: {text}"
            );
        }
    }

    /// Forests and backups beside the store are shared by sibling stores. A
    /// per-store activity lease cannot authorize deleting from them, so they
    /// are named as retained and never swept.
    #[test]
    fn legacy_shared_forests_and_backups_are_never_swept() {
        let temp = TempStore::new("legacy-shared");
        let store = temp.store();
        let home = store.root.parent().unwrap().to_path_buf();
        let shared_forest = home.join("forests/deadbeef/projection");
        let shared_backup = home.join("backups/deadbeef-node_modules");
        fs::create_dir_all(&shared_forest).unwrap();
        fs::create_dir_all(&shared_backup).unwrap();
        age(&shared_forest);
        age(&shared_backup);
        register_objects(&store, &temp.root.join("project"), &[]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            shared_forest.is_dir(),
            "a sibling-namespace forest was swept: {text}"
        );
        assert!(
            shared_backup.is_dir(),
            "a sibling-namespace backup was swept: {text}"
        );
        assert!(
            text.contains("shared by sibling stores"),
            "the retention was not narrated: {text}"
        );
    }

    /// A `root/2` record is self-sufficient: its projections stay protected
    /// even when the project directory it names no longer exists.
    #[test]
    fn forest_retention_works_with_the_project_directory_absent() {
        let temp = TempStore::new("forest-absent-project");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let key = store::Store::root_key(&project).unwrap();
        let projection = store.root.join("forests").join(&key).join("node_modules");
        fs::create_dir_all(projection.join("left-pad")).unwrap();
        age(&projection);
        store
            .register_root_record(store::RootRecord {
                key: key.clone(),
                project_path: project.clone(),
                objects: BTreeSet::new(),
                projections: BTreeSet::from([store::ProjectionRef::new(
                    store::ProjectionBase::Forests,
                    vec![key.into(), "node_modules".into()],
                )
                .unwrap()]),
                updated: 1,
            })
            .unwrap();
        fs::remove_dir_all(&project).unwrap();

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        report.unwrap();
        assert!(
            projection.join("left-pad").is_dir(),
            "a forest lost its protection when the project directory vanished: {text}"
        );
    }

    /// A preview separates what it would delete from what retention kept
    /// and from what blocked it. The retention category is the one a sweep
    /// can silently fold into "nothing to do", so it is asserted explicitly.
    #[test]
    fn dry_run_reports_removals_skips_and_blocks_in_distinct_categories() {
        let temp = TempStore::new("dry-run-categories");
        let store = temp.store();
        let dead = commit(&store, "dead", None);
        let fresh = commit(&store, "fresh", None);
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[]);

        let (report, text) = sweep(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 1, "{text}");
        assert!(
            text.contains(&format!(
                "would remove object {}",
                store.object_path(&dead).display()
            )),
            "the candidate was not previewed: {text}"
        );
        assert!(
            text.contains(&format!("skipped: object {fresh}")),
            "a retention decision was not reported: {text}"
        );
        assert!(
            text.contains("active window"),
            "the retention reason was not given: {text}"
        );

        // The same store with one legacy record reports a block instead, and
        // authorizes no deletion at all.
        let unknown = Identity {
            kind: "not-a-known-kind".into(),
            name: "mystery".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        };
        commit_legacy_fixture(&store, &unknown, Some(&[]));
        let (result, text) = sweep(
            &store,
            Options {
                dry_run: true,
                keep_days: 0,
                ..Options::default()
            },
        );
        assert!(result.is_err(), "{text}");
        assert!(
            !text.contains("would remove object"),
            "a blocked preview still authorized a deletion: {text}"
        );
    }
    /// Characterization: the read phase's structural refusals. Every other
    /// gc test drives `read` through a healthy store; these pin the
    /// "refusing to sweep" stops that guard the object, metadata, cache and
    /// stage enumerations, so an extraction cannot quietly drop one.
    fn read_refusal(label: &str, plant: impl FnOnce(&Store)) -> String {
        let temp = TempStore::new(label);
        let store = temp.store();
        let id = commit(&store, "kept", None);
        assert!(store.object_path(&id).is_dir());
        plant(&store);
        let activity = store.try_activity_exclusive().unwrap().unwrap();
        let mut out = Vec::new();
        match read(
            &store,
            &activity,
            &Options::default(),
            &BTreeMap::new(),
            &mut out,
        ) {
            Ok(_) => panic!("the read phase accepted a malformed store"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn read_refuses_an_object_entry_that_is_not_an_object() {
        let message = read_refusal("read-bad-object", |store| {
            fs::write(store.root.join("objects").join("not-an-id"), b"x").unwrap();
        });
        assert!(
            message.contains("refusing to sweep: invalid object entry"),
            "{message}"
        );
    }

    #[test]
    fn read_refuses_an_object_without_readable_metadata() {
        let message = read_refusal("read-no-meta", |store| {
            let id = commit(store, "orphan", None);
            fs::remove_file(store.root.join("meta").join(format!("{id}.json"))).unwrap();
        });
        assert!(message.contains("has no readable metadata"), "{message}");
        assert!(message.contains("rebuild it or restore meta/"), "{message}");
    }

    #[test]
    fn read_refuses_a_cache_namespace_that_is_not_a_real_directory() {
        let message = read_refusal("read-cache-symlink", |store| {
            let path = store.root.join("cache").join("sha256");
            fs::remove_dir_all(&path).unwrap();
            std::os::unix::fs::symlink(store.root.join("objects"), &path).unwrap();
        });
        assert!(
            message.contains("refusing to sweep: cache/sha256 is not a real directory"),
            "{message}"
        );
    }

    #[test]
    fn read_refuses_a_cache_entry_that_is_not_a_digest() {
        let message = read_refusal("read-bad-cache", |store| {
            fs::write(store.root.join("cache/sha256").join("nothex"), b"x").unwrap();
        });
        assert!(
            message.contains("refusing to sweep: invalid cache entry"),
            "{message}"
        );
    }

    #[test]
    fn read_refuses_a_stage_entry_that_is_not_a_directory() {
        let message = read_refusal("read-bad-stage", |store| {
            fs::write(store.root.join("tmp").join("stage-bogus"), b"x").unwrap();
        });
        assert!(
            message.contains("refusing to sweep: invalid stage entry"),
            "{message}"
        );
    }
}

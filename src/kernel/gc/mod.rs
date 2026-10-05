//! Store garbage collection.
//!
//! GC is deliberately rooted in project closure files rather than in the
//! current working directory. A project becomes a root when a tailor writes a
//! closure. A root never stops protecting its project: an unavailable project
//! stops the sweep until it returns or its record is explicitly forgotten.

use crate::kernel::activity::StoreActivity;
use crate::kernel::store::{self, open_real_directory, RootEntry, Store};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

mod drop;
mod plan;
mod read;
mod reset;
mod sweep;

pub use self::drop::*;
pub use plan::*;
pub use read::*;
pub use reset::*;
use sweep::*;

const ACTIVE_WINDOW: Duration = Duration::from_secs(10 * 60);
const STAGE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone)]
pub struct Options {
    pub dry_run: bool,
    pub keep_days: u64,
    pub project: bool,
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
    /// `run-homes/<project key>` directories no surviving root names.
    pub run_homes: usize,
    /// Store records about a project whose directory is gone.
    pub project_records: usize,
    /// Records left without their object by an interrupted removal.
    pub records: usize,
    /// Resolution-proxy metadata cache entries unused for the retention
    /// window (and sidecar index entries whose sidecar is gone).
    pub resolve_metadata: usize,
}

/// Sweep the store, and its forest and backup projections when
/// `options.project` is set.
// Reviewed site (tests/architecture.rs): operation boundary: public GC for callers holding no lease.
#[allow(clippy::disallowed_methods)]
pub fn collect<W: Write>(store: &Store, options: Options, out: &mut W) -> io::Result<Report> {
    let Some(activity) = store.try_activity_exclusive()? else {
        writeln!(out, "cleanup skipped: a Tog job is using this store")?;
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
                + "projects with `tog gc --register <dir>...` or run `tog` in each "
                + "project",
        ));
    }
    // GC has its own user-visible lock, and also holds the publication lock
    // across the liveness snapshot and removals. Store::has/commit use the
    // latter, so a sync either touches an object before this sweep or waits
    // until after it.
    let _gc_lock = store.gc_lock()?;
    let _publish_lock = store.publish_lock()?;

    let snapshot = read(store, activity, &options)?;
    let validated = validate(&snapshot)?;
    let plan = plan(&validated, &options)?;
    let window = keep_age(options.keep_days);
    if options.dry_run {
        report_plan(&plan, out)?;
        let mut report = plan.report();
        sweep_resolve_cache(store, window, true, &mut report, out)?;
        return Ok(report);
    }
    let mut report = execute(&plan, &snapshot, store, activity, out)?;
    sweep_resolve_cache(store, window, false, &mut report, out)?;
    Ok(report)
}

/// The resolution proxy's metadata cache is a cache: entries unused for the
/// retention window go, and losing one costs only a refetch. It runs after
/// the object sweep, so the sidecar index loses the entries whose sidecar
/// that sweep removed.
fn sweep_resolve_cache<W: Write>(
    store: &Store,
    window: Duration,
    dry_run: bool,
    report: &mut Report,
    out: &mut W,
) -> io::Result<()> {
    let swept = crate::kernel::resolve::cache::sweep(store, window, dry_run)?;
    if swept.entries > 0 {
        let verb = if dry_run { "would remove" } else { "removed" };
        writeln!(
            out,
            "{verb} {} resolution metadata cache entries",
            swept.entries
        )?;
    }
    report.resolve_metadata += swept.entries + swept.index_entries;
    report.freed_bytes += swept.bytes;
    Ok(())
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

fn related(path: &Path, keep: &Path) -> bool {
    path == keep || path.starts_with(keep) || keep.starts_with(path)
}

fn keep_age(days: u64) -> Duration {
    Duration::from_secs(days.saturating_mul(24 * 60 * 60))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::store::ObjectDeps;
    use crate::kernel::testutil::TempDir;
    use crate::kernel::types::Identity;
    use sha2::Digest;
    use std::collections::BTreeMap;

    pub(super) struct TempStore {
        pub(super) root: PathBuf,
        _dir: TempDir,
    }

    impl TempStore {
        pub(super) fn new(label: &str) -> Self {
            let dir = TempDir::named(&format!("gc-{label}"));
            // One level down, so the store's parent is private to the test
            // and removed with it, never the system temp directory.
            let root = dir.0.join("store");
            for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            Self { root, _dir: dir }
        }
        pub(super) fn store(&self) -> Store {
            Store::for_test(self.root.clone())
        }
    }

    pub(super) fn test_identity(name: &str, input: Option<&str>) -> Identity {
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
    pub(super) fn commit(store: &Store, name: &str, input: Option<&str>) -> String {
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

    fn closure(project: &Path, object: &Path, extra: serde_json::Value) {
        fs::create_dir_all(project.join(".tog/closures")).unwrap();
        let body = serde_json::json!({
            "env_object": object.display().to_string(),
            "extra": extra,
        });
        fs::write(
            project.join(".tog/closures/python.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// Materialise a verified cache artifact so a fixture can name it.
    fn cached_artifact(store: &Store, hex: &str) {
        let path = store.root.join("cache/sha256").join(hex);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"artifact").unwrap();
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
        // All three are past the active window, so only the walk from the
        // closure to the parent and on to the child keeps those two.
        for id in [&child, &parent, &dead] {
            age(&store.object_path(id));
        }
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
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(store.object_path(&dead).is_dir());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&dead), "{output}");
        // Project protection is silent; an object kept any other way (by
        // policy, or by depending on something policy keeps) is narrated.
        // So neither the parent nor the child may appear.
        assert!(!output.contains(&parent), "{output}");
        assert!(!output.contains(&child), "{output}");
    }

    /// A record says for itself what its object needs, so the sweep reads
    /// it without a kind row: an object whose kind or schema this tog no
    /// longer produces is ordinary garbage once nothing roots it, and is
    /// kept while something does. Needing the row would instead block every
    /// sweep on a store that holds one, after any schema bump. What such a
    /// record says it depends on is followed like any other record's: a
    /// rooted object keeps its dependencies, and theirs.
    #[test]
    fn an_object_of_a_kind_with_no_row_is_swept_or_kept_like_any_other() {
        let temp = TempStore::new("retired-kind");
        let store = temp.store();
        let publish = |name: &str, dependencies: &[&str]| {
            let identity = Identity {
                kind: "retired-kind".into(),
                name: name.into(),
                version: "1".into(),
                inputs: BTreeMap::from([("schema".into(), "retired-kind/1".into())]),
            };
            assert!(crate::kernel::objmeta::check_identity_grammar(&identity).is_err());
            let id = identity.object_id();
            let object = store.object_path(&id);
            fs::create_dir_all(&object).unwrap();
            fs::write(object.join("payload"), name).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "schema": "object-meta/2",
                    "id": id,
                    "identity": identity,
                    "created": 0,
                    "exceptions": [],
                    "dependencies": dependencies,
                    "cache_digests": [],
                    "evidence": "explicit",
                }))
                .unwrap(),
            )
            .unwrap();
            age(&object);
            id
        };
        // rooted -> needed -> needed-below, and orphan -> orphan-needed.
        let below = publish("needed-below", &[]);
        let needed = publish("needed", &[&below]);
        let rooted = publish("rooted", &[&needed]);
        let orphan_needed = publish("orphan-needed", &[]);
        let orphan = publish("orphan", &[&orphan_needed]);
        register_objects(&store, &temp.root.join("project"), &[&rooted]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 2, "{text}");
        assert!(!store.object_path(&orphan).exists(), "{text}");
        assert!(!store.object_path(&orphan_needed).exists(), "{text}");
        for kept in [&rooted, &needed, &below] {
            assert!(store.object_path(kept).is_dir(), "{kept}: {text}");
            assert!(
                store
                    .root
                    .join("meta")
                    .join(format!("{kept}.json"))
                    .is_file(),
                "{kept}: {text}"
            );
        }
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
        fs::create_dir_all(project.join(".tog/closures")).unwrap();
        let project = project.canonicalize().unwrap();
        let project_key =
            &hex::encode(sha2::Sha256::digest(project.to_string_lossy().as_bytes()))[..32];
        let projection_id = "a".repeat(32);
        // The store's own `forests/`, the namespace the sweep reads: only
        // the closure's projection id, rebuilt into this path, keeps it.
        let forest = store
            .root
            .join("forests")
            .join(project_key)
            .join(&projection_id);
        let workspace_forest = forest.join("workspaces/packages%2Flib/node_modules");
        fs::create_dir_all(&workspace_forest).unwrap();
        fs::create_dir_all(project.join("packages/lib")).unwrap();
        std::os::unix::fs::symlink(&workspace_forest, project.join("packages/lib/node_modules"))
            .unwrap();
        fs::write(
            project.join(".tog/closures/node.json"),
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
    fn a_project_sweep_reclaims_old_run_homes_no_root_names() {
        let temp = TempStore::new("run-homes");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let kept = store.run_home(&project, "elixir").unwrap();
        store
            .register_root_record(store::RootRecord {
                key: store::Store::root_key(&project).unwrap(),
                project_path: project.clone(),
                objects: BTreeSet::new(),
                projections: BTreeSet::new(),
                updated: 1,
            })
            .unwrap();
        // The record keeps its run home even once the project is gone, as it
        // keeps the project's objects.
        fs::remove_dir_all(&project).unwrap();
        let run_homes = store.root.join("run-homes");
        let orphan = run_homes.join("0123456789abcdef");
        let young = run_homes.join("fedcba9876543210");
        fs::create_dir_all(orphan.join("dotnet/.nuget")).unwrap();
        fs::write(orphan.join("dotnet/.nuget/cache"), b"cache").unwrap();
        fs::create_dir_all(young.join("elixir")).unwrap();
        age(kept.parent().unwrap());
        age(&orphan);
        let sweep = |project| {
            let mut output = Vec::new();
            let report = collect(
                &store,
                Options {
                    dry_run: false,
                    project,
                    keep_days: 1,
                    ..Options::default()
                },
                &mut output,
            )
            .unwrap();
            (report, String::from_utf8(output).unwrap())
        };
        let (report, text) = sweep(false);
        assert_eq!(report.run_homes, 0, "{text}");
        assert!(orphan.is_dir(), "only a project sweep reads run homes");
        let (report, text) = sweep(true);
        assert_eq!(report.run_homes, 1, "{text}");
        assert!(!orphan.exists(), "{text}");
        assert!(young.is_dir(), "{text}");
        assert!(kept.is_dir(), "{text}");
    }

    #[test]
    fn a_project_sweep_removes_records_about_projects_that_are_gone() {
        let temp = TempStore::new("project-records");
        let store = temp.store();
        let gone = temp.root.join("gone");
        let here = temp.root.join("here");
        fs::create_dir_all(&gone).unwrap();
        fs::create_dir_all(&here).unwrap();
        let (gone, here) = (gone.canonicalize().unwrap(), here.canonicalize().unwrap());
        store
            .register_root_record(store::RootRecord {
                key: store::Store::root_key(&here).unwrap(),
                project_path: here.clone(),
                objects: BTreeSet::new(),
                projections: BTreeSet::new(),
                updated: 1,
            })
            .unwrap();
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let value = serde_json::json!({"input_hash": "x"});
        for project in [&gone, &here] {
            store
                .write_project_record(&activity, "demo-check", project, &value)
                .unwrap();
        }
        // A fact about something immutable names no project and stays.
        store
            .write_record(&activity, "demo-digest", "gem@1.0.0", &value)
            .unwrap();
        drop(activity);
        fs::remove_dir_all(&gone).unwrap();
        let sweep = |project| {
            let mut output = Vec::new();
            let report = collect(
                &store,
                Options {
                    dry_run: false,
                    project,
                    ..Options::default()
                },
                &mut output,
            )
            .unwrap();
            (report, String::from_utf8(output).unwrap())
        };
        let (report, text) = sweep(false);
        assert_eq!(report.project_records, 0, "{text}");
        assert!(store
            .read_project_record("demo-check", &gone)
            .unwrap()
            .is_some());
        let (report, text) = sweep(true);
        assert_eq!(report.project_records, 1, "{text}");
        assert_eq!(
            store.read_project_record("demo-check", &gone).unwrap(),
            None
        );
        assert_eq!(
            store.read_project_record("demo-check", &here).unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            store.read_record("demo-digest", "gem@1.0.0").unwrap(),
            Some(value)
        );
    }

    /// A record or a record kind the sweep cannot read is left alone: records
    /// are a cache, and before them `tog gc --project` never read records/.
    #[test]
    fn an_unreadable_record_does_not_fail_a_project_sweep() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempStore::new("unreadable-records");
        let store = temp.store();
        let gone = temp.root.join("gone");
        fs::create_dir_all(&gone).unwrap();
        let gone = gone.canonicalize().unwrap();
        store
            .register_root_record(store::RootRecord {
                key: store::Store::root_key(&temp.root).unwrap(),
                project_path: temp.root.canonicalize().unwrap(),
                objects: BTreeSet::new(),
                projections: BTreeSet::new(),
                updated: 1,
            })
            .unwrap();
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let value = serde_json::json!({"input_hash": "x"});
        for kind in ["demo-locked", "demo-sealed", "demo-check"] {
            store
                .write_project_record(&activity, kind, &gone, &value)
                .unwrap();
        }
        drop(activity);
        fs::remove_dir_all(&gone).unwrap();
        let records = store.root.join(store::RECORDS);
        let locked = fs::read_dir(records.join("demo-locked"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mode = |path: &Path, mode| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(&locked, 0o000);
        mode(&records.join("demo-sealed"), 0o000);
        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                project: true,
                ..Options::default()
            },
            &mut output,
        );
        mode(&records.join("demo-sealed"), 0o700);
        mode(&locked, 0o600);
        let text = String::from_utf8(output).unwrap();
        assert_eq!(report.unwrap().project_records, 1, "{text}");
        assert!(locked.is_file(), "{text}");
        assert!(store
            .read_project_record("demo-sealed", &gone)
            .unwrap()
            .is_some());
        assert_eq!(
            store.read_project_record("demo-check", &gone).unwrap(),
            None
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
        // unresolvable reference is exactly what the sweep refuses). It
        // names an unrelated anchor, so neither the parent nor the child is
        // root-live: the parent survives on retention policy alone, and the
        // child only through the policy walk over the parent's dependencies.
        let anchor = commit(&store, "anchor", None);
        closure(&project, &store.object_path(&anchor), serde_json::json!({}));
        store.register_root(&project).unwrap();

        let mut output = Vec::new();
        let report = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 0);
        assert!(store.object_path(&parent).exists());
        assert!(store.object_path(&child).exists());
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
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(report.objects, 1);
        assert!(!store.object_path(&id).exists());
    }

    /// A forget names one root, and the preview must exclude that root and
    /// no other, and write nothing: both roots stay registered. With a second registered project in the store, treating the
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
        assert!(preview.contains("would remove object"), "{preview}");
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
        let entry = store.register_root(&project).unwrap();
        fs::remove_dir_all(project.join(".tog/closures")).unwrap();

        let mut output = Vec::new();
        let error = collect(
            &store,
            Options {
                dry_run: false,
                keep_days: 0,
                project: false,
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap_err();
        // The refusal names the root and the miss itself. Matching
        // "closures" would also match the scratch directory's name.
        let message = error.to_string();
        let missing = io::Error::from_raw_os_error(libc::ENOENT).to_string();
        assert!(message.contains(&entry.key), "{message}");
        assert!(message.contains(&missing), "{message}");
        assert!(store.object_path(&id).is_dir());
    }

    /// A registry no root was ever written to has no `.initialized` marker
    /// and no records, so a sweep there would run with no idea what any
    /// project needs. It must refuse from every entry, `--project`
    /// included.
    #[test]
    fn an_uninitialized_registry_blocks_every_sweep() {
        let temp = TempStore::new("uninitialized-registry");
        let store = temp.store();
        let id = commit(&store, "unrooted", None);
        age(&store.object_path(&id));
        assert!(!store.root.join("roots/.initialized").exists());

        for (dry_run, project) in [(false, false), (true, false), (false, true)] {
            let mut output = Vec::new();
            let error = collect(
                &store,
                Options {
                    dry_run,
                    project,
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
        for closure in fs::read_dir(project.join(".tog/closures")).unwrap() {
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
                forgotten: Vec::new(),
            },
            &mut output,
        )
        .unwrap_err();
        let message = error.to_string();
        let symlink_loop = io::Error::from_raw_os_error(libc::ELOOP).to_string();
        assert!(message.contains("refusing to sweep"), "{message}");
        assert!(message.contains(&entry.key), "{message}");
        assert!(message.contains(&symlink_loop), "{message}");
        assert!(store.object_path(&id).is_dir());
        assert!(store.roots().unwrap().len() == 1, "record was removed");
    }

    // =======================================================================
    // GC safety acceptance tests.
    //
    // Each name below covers one GC-safety failure mode. The x-cleanup pair
    // lives with the code it covers, in `commands::x`.
    // =======================================================================

    /// Register `project` as a durable root/2 record naming `objects`.
    pub(super) fn register_objects(store: &Store, project: &Path, objects: &[&str]) -> String {
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
    fn planned(
        store: &Store,
        activity: &StoreActivity,
        options: &Options,
        snapshot: &mut Option<Snapshot>,
    ) -> SweepPlan {
        *snapshot = Some(read(store, activity, options).unwrap());
        let taken = snapshot.as_ref().unwrap();
        let validated = validate(taken).unwrap();
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
        let error = result.expect_err("a corrupt root record did not stop the sweep");
        assert!(
            error
                .to_string()
                .contains(&format!("root {last} has an unusable registry record")),
            "{error}\n{text}"
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
        let error = result.expect_err("corrupt metadata did not stop the sweep");
        assert!(
            error.to_string().contains(&format!(
                "blocked: metadata record meta/{last}.json is unusable"
            )),
            "{error}\n{text}"
        );
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
        // The child is gone entirely, object and record. With its directory
        // left behind the read phase would refuse the orphan first; this way
        // only the parent's dependency names it, and the refusal can only
        // come from the transitive walk.
        store::remove_tree(&store.object_path(&child)).unwrap();
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
            error.contains(&format!(
                "object {child}, reachable from {parent}, has no metadata"
            )),
            "the missing id is not named by the walk: {error}"
        );
        assert!(store.object_path(&parent).is_dir());
    }

    /// The marking walk seeds from root objects as well as from retention
    /// policy. `root_live` alone keeps a root's objects, but the cached
    /// artifacts they name are kept only through the marked set: an aged,
    /// root-protected object must keep its artifacts too.
    #[test]
    fn a_root_protected_object_keeps_its_cached_artifacts() {
        let temp = TempStore::new("root-cache");
        let store = temp.store();
        let kept: String = std::iter::repeat_n('a', 64).collect();
        let unnamed: String = std::iter::repeat_n('b', 64).collect();
        for hex in [&kept, &unnamed] {
            cached_artifact(&store, hex);
            age(&store.cache_path("sha256", hex));
        }
        let identity = test_identity("cache-holder", None);
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), "cache-holder").unwrap();
        let mut deps = ObjectDeps::new();
        deps.cache_digest(crate::kernel::fetch::Digest::sha256(&kept).unwrap());
        store
            .commit_with_deps(&identity, &staged, &[], &deps)
            .unwrap();
        age(&store.object_path(&id));
        register_objects(&store, &temp.root.join("project"), &[&id]);

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let report = report.unwrap();
        assert_eq!(report.objects, 0, "{text}");
        assert_eq!(report.cached_artifacts, 1, "{text}");
        assert!(store.object_path(&id).is_dir(), "{text}");
        assert!(
            store.cache_path("sha256", &kept).is_file(),
            "a root-protected object lost its cached artifact: {text}"
        );
        assert!(!store.cache_path("sha256", &unnamed).exists(), "{text}");
    }

    /// A root naming an object the store no longer has, directly or through
    /// a dependency, is incomplete evidence, and only the marking walk can
    /// see it: `root_live` skips an id with no record. The sweep must refuse
    /// rather than treat the missing object as protecting nothing.
    #[test]
    fn a_root_naming_an_absent_object_blocks_the_sweep() {
        for shape in ["root", "dependency"] {
            let temp = TempStore::new(&format!("absent-{shape}"));
            let store = temp.store();
            let dead = commit(&store, "dead", None);
            age(&store.object_path(&dead));
            let (named, absent) = match shape {
                "root" => {
                    let absent = format!("{}-absent-1", "0".repeat(40));
                    (absent.clone(), absent)
                }
                _ => {
                    let child = commit(&store, "child", None);
                    let parent = commit(&store, "parent", Some(&child));
                    age(&store.object_path(&parent));
                    store::remove_tree(&store.object_path(&child)).unwrap();
                    fs::remove_file(store.root.join("meta").join(format!("{child}.json"))).unwrap();
                    (parent, child)
                }
            };
            register_objects(&store, &temp.root.join("project"), &[&named]);

            let (result, text) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            let error = result.unwrap_err().to_string();
            assert!(error.contains("refusing to sweep"), "{shape}: {error}");
            assert!(
                error.contains(&format!("{absent} has no metadata"))
                    || error.contains(&format!("object {absent}, reachable from")),
                "{shape}: the absent object is not named: {error}"
            );
            assert!(
                store.object_path(&dead).is_dir(),
                "{shape}: a refused sweep deleted an unprotected object: {text}"
            );
        }
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

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        // The refusal names the record and the way out.
        assert!(
            error.contains("unknown metadata schema object-meta/3")
                && error.contains("--drop-object"),
            "{error}\n{text}"
        );
        assert!(store.object_path(&dead).is_dir(), "a sweep ran anyway");
    }

    /// A dependency that is not an object id, including one that tries to
    /// walk out of the store, makes the record unusable and names the
    /// repair.
    #[test]
    fn invalid_reference_in_metadata_is_an_error() {
        let temp = TempStore::new("invalid-reference");
        let store = temp.store();
        let id = commit(&store, "broken", None);
        register_objects(&store, &temp.root.join("project"), &[]);
        for reference in [
            "not-an-object-id".to_string(),
            "../../../etc/passwd".to_string(),
            format!("{}-../escape", "a".repeat(40)),
        ] {
            edit_record(&store, &id, |record| {
                record.insert("dependencies".into(), serde_json::json!([reference]));
            });
            let (result, text) = sweep(
                &store,
                Options {
                    keep_days: 0,
                    ..Options::default()
                },
            );
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("malformed or duplicate dependency")
                    && error.contains("--drop-object"),
                "{reference:?} was accepted: {error}\n{text}"
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
        let wedged = wedge(&store, "mystery");
        let key =
            store::Store::root_key(&temp.root.join("project").canonicalize().unwrap()).unwrap();
        let path = store.root.join("roots").join(format!(".{key}.tmp.1234.0"));
        fs::write(&path, b"crash residue").unwrap();

        let (result, text) = sweep(&store, Options::default());
        let error = result.expect_err("an unreadable record did not stop the sweep");
        assert!(
            error
                .to_string()
                .contains(&format!("metadata record meta/{wedged}.json is unusable")),
            "{error}\n{text}"
        );
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
        let outcome = {
            let mut out = Vec::new();
            let result = execute(
                &sweep_plan,
                held.as_ref().unwrap(),
                &store,
                &activity,
                &mut out,
            );
            (result, String::from_utf8(out).unwrap())
        };
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
            error.contains("orphaned") && error.contains("--drop-object"),
            "the recovery path is not named: {error}"
        );

        // The next sweep clears the leftover record on its own.
        drop(activity);
        let (result, text) = sweep(&store, Options::default());
        assert_eq!(result.unwrap().records, 1, "{text}");
        assert!(
            !meta_dir.join(format!("{dead}.json")).exists(),
            "the stray record survived: {text}"
        );
    }

    /// A record whose object is gone is the residue of a removal that
    /// stopped halfway. Nothing needs it, so the sweep removes it (a dry run
    /// only reports it) rather than refusing until an operator drops it.
    #[test]
    fn a_record_without_its_object_is_swept_when_nothing_needs_it() {
        let temp = TempStore::new("stray-record");
        let store = temp.store();
        let gone = commit(&store, "gone", None);
        store::remove_tree(&store.object_path(&gone)).unwrap();
        let record = store.root.join("meta").join(format!("{gone}.json"));
        register_objects(&store, &temp.root.join("project"), &[]);

        let dry = Options {
            dry_run: true,
            ..Options::default()
        };
        let (result, text) = sweep(&store, dry);
        assert_eq!(result.unwrap().records, 1, "{text}");
        assert!(record.is_file(), "a dry run removed the record: {text}");

        let (result, text) = sweep(&store, Options::default());
        assert_eq!(result.unwrap().records, 1, "{text}");
        assert!(!record.exists(), "the stray record survived: {text}");
    }

    #[test]
    fn a_directory_replacing_a_parsed_orphan_record_is_never_swept() {
        let temp = TempStore::new("orphan-directory-replacement");
        let store = temp.store();
        let gone = commit(&store, "gone", None);
        store::remove_tree(&store.object_path(&gone)).unwrap();
        let (index, unusable) =
            crate::kernel::objmeta::MetaIndex::read_reporting_unusable(&store).unwrap();
        assert!(unusable.is_empty());
        let record = store.root.join("meta").join(format!("{gone}.json"));
        fs::remove_file(&record).unwrap();
        fs::create_dir(&record).unwrap();
        fs::write(record.join("user-data"), "keep").unwrap();
        let held = read::open_held(&store.root.join("meta"), "meta").unwrap();
        assert!(read::read_stray_records(&index, &[], &held).is_err());
        assert_eq!(
            fs::read_to_string(record.join("user-data")).unwrap(),
            "keep"
        );
    }

    /// A record whose object is gone while a rooted object still depends on
    /// it is a real loss, not residue: the sweep refuses and keeps it.
    #[test]
    fn a_record_without_its_object_blocks_the_sweep_while_something_needs_it() {
        let temp = TempStore::new("needed-stray-record");
        let store = temp.store();
        let child = commit(&store, "child", None);
        let parent = commit(&store, "parent", Some(&child));
        register_objects(&store, &temp.root.join("project"), &[&parent]);
        store::remove_tree(&store.object_path(&child)).unwrap();

        let (result, text) = sweep(&store, Options::default());
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(&format!("metadata for missing object {child}")),
            "{error}\n{text}"
        );
        assert!(store
            .root
            .join("meta")
            .join(format!("{child}.json"))
            .is_file());
    }

    /// A tog killed mid-write leaves a temporary under `tmp/`. Every kind tog
    /// writes is swept once it is past the stage window. A fresh one, the
    /// publish lock, and a name tog never writes are left alone.
    #[test]
    fn every_kind_of_crashed_temporary_is_swept_once_stale() {
        let temp = TempStore::new("tmp-leftovers");
        let store = temp.store();
        register_objects(&store, &temp.root.join("project"), &[]);
        let tmp = store.root.join("tmp");
        let make = |name: &str, kind: libc::mode_t| {
            let path = tmp.join(name);
            if kind == libc::S_IFDIR {
                fs::create_dir(&path).unwrap();
                fs::write(path.join("partial"), b"x").unwrap();
            } else {
                fs::write(&path, b"x").unwrap();
            }
            path
        };
        let mut stale = Vec::new();
        let mut fresh = Vec::new();
        for (prefix, kind) in read::TMP_LEFTOVERS {
            let old = make(&format!("{prefix}0-0-crashed"), *kind);
            age(&old);
            stale.push(old);
            fresh.push(make(&format!("{prefix}0-0-running"), *kind));
        }
        let foreign = make("not-a-tog-temporary", libc::S_IFREG);
        age(&foreign);
        fresh.push(foreign);
        fresh.push(tmp.join(".publish.lock"));
        store.publish_lock().unwrap();

        let (result, text) = sweep(&store, Options::default());
        let report = result.unwrap();
        assert_eq!(report.stages, stale.len(), "{text}");
        for path in &stale {
            assert!(!path.exists(), "{} survived: {text}", path.display());
        }
        for path in &fresh {
            assert!(path.exists(), "{} was removed: {text}", path.display());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restricted_resolution_trash_is_removed_without_mutating_a_dry_run() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempStore::new("restricted-resolution-trash");
        let store = temp.store();
        register_objects(&store, &temp.root.join("project"), &[]);
        let stage = store.root.join("tmp/resolve-0-0-crashed");
        let blocked = stage.join("blocked");
        let search_only = stage.join("search-only");
        fs::create_dir_all(&blocked).unwrap();
        fs::create_dir_all(&search_only).unwrap();
        fs::write(blocked.join("payload"), "trash").unwrap();
        fs::write(search_only.join("payload"), "trash").unwrap();
        let outside = temp.root.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), "user data").unwrap();
        std::os::unix::fs::symlink(&outside, blocked.join("escape")).unwrap();
        let held_root = fs::File::open(&stage).unwrap();
        let held_blocked = fs::File::open(&blocked).unwrap();
        let held_search = fs::File::open(&search_only).unwrap();
        age(&stage);
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o0)).unwrap();
        fs::set_permissions(&search_only, fs::Permissions::from_mode(0o100)).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o0)).unwrap();
        let (dry, text) = sweep(
            &store,
            Options {
                dry_run: true,
                ..Options::default()
            },
        );
        assert_eq!(dry.unwrap().stages, 1, "{text}");
        assert!(text.contains("at least"), "{text}");
        assert_eq!(
            held_root.metadata().unwrap().permissions().mode() & 0o777,
            0
        );
        assert_eq!(
            held_blocked.metadata().unwrap().permissions().mode() & 0o777,
            0
        );
        assert_eq!(
            held_search.metadata().unwrap().permissions().mode() & 0o777,
            0o100
        );
        let (real, text) = sweep(&store, Options::default());
        assert_eq!(real.unwrap().stages, 1, "{text}");
        assert!(!stage.exists(), "{text}");
        assert_eq!(
            fs::read_to_string(outside.join("keep")).unwrap(),
            "user data"
        );
    }

    /// A dry run writes nothing: no record, no root, no timestamp.
    #[test]
    fn dry_run_removes_no_root_rewrites_no_record_and_refreshes_no_timestamp() {
        let temp = TempStore::new("dry-run-immutable");
        let store = temp.store();
        let id = commit(&store, "kept", None);
        age(&store.object_path(&id));
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&dead));
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
        assert_eq!(report.unwrap().objects, 1, "{text}");
        assert!(store.object_path(&dead).is_dir(), "a dry run removed it");
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
    }

    /// The dry run and the real sweep must agree: same plan, and the
    /// preview removes nothing.
    #[test]
    fn dry_run_and_real_sweep_produce_the_same_plan() {
        let temp = TempStore::new("same-plan");
        let store = temp.store();
        let live = commit(&store, "live", None);
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&live));
        age(&store.object_path(&dead));
        register_objects(&store, &temp.root.join("project"), &[&live]);
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
        assert!(store.object_path(&dead).is_dir(), "the preview removed it");
        assert_eq!(preview.objects, 1, "{text}");

        let (real, real_text) = sweep(&store, options());
        let real = real.unwrap();
        assert_eq!(preview, real, "preview {text}\nreal {real_text}");
        assert!(!store.object_path(&dead).exists(), "{real_text}");
        assert!(store.object_path(&live).is_dir(), "{real_text}");
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
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
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
        fs::remove_dir_all(project.join(".tog/closures")).unwrap();
        assert!(!project.join(".tog/closures").exists());

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
        // Real publication with an unavailable reference: the reference is
        // refused, and publishing what is left must fail before either
        // durable write, so nothing is published.
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut refs = crate::comforter::ClosureRefs::new();
        refs.object_id(&store, &activity, &("0".repeat(40) + "-missing-1"))
            .unwrap_err();
        let error = crate::comforter::write_closure(
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            "python",
            serde_json::json!({"ok": true}),
            &store,
            &activity,
            refs,
            &mut attribution,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("no object references"),
            "{error}"
        );
        // The frame knows the claimed closure never landed.
        let unfinished = attribution.finish(false).unwrap_err();
        assert!(
            unfinished.to_string().contains("did not complete"),
            "{unfinished}"
        );
        let project = project.canonicalize().unwrap();
        assert!(!project.join(".tog/closures/python.json").exists());
        let roots = store.roots().unwrap();
        assert!(
            roots.iter().all(|root| root
                .record
                .as_ref()
                .map(|r| r.project_path != project)
                .unwrap_or(true)),
            "a failed publication wrote a durable record"
        );
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
            fs::create_dir_all(project.join(".tog/closures")).unwrap();
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
                    let closure = project.join(".tog/closures/python.json");
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
    fn forests_and_backups_beside_the_store_are_never_swept() {
        let temp = TempStore::new("beside-store");
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

    /// One project synced with two ecosystems, each resynced once: the
    /// visible closures name only the newest environments, but the durable
    /// record is a union, so all four stay protected.
    #[test]
    fn two_ecosystems_and_two_environments_all_stay_protected() {
        let temp = TempStore::new("two-ecosystems");
        let store = temp.store();
        let project = temp.root.join("project");
        fs::create_dir_all(&project).unwrap();
        let dead = commit(&store, "dead", None);
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut published = Vec::new();
        for (ecosystem, generation) in [
            ("python", "old"),
            ("node", "old"),
            ("python", "new"),
            ("node", "new"),
        ] {
            let id = commit(&store, &format!("{ecosystem}-{generation}-env"), None);
            let mut attribution = crate::kernel::policy::Attribution::open(ecosystem).unwrap();
            let activity = store.activity(ActivityMode::Exclusive).unwrap();
            let mut refs = crate::comforter::ClosureRefs::new();
            refs.object_id(&store, &activity, &id).unwrap();
            crate::comforter::write_closure(
                &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
                ecosystem,
                serde_json::json!({"env_object": store.object_path(&id)}),
                &store,
                &activity,
                refs,
                &mut attribution,
            )
            .unwrap();
            attribution.finish(true).unwrap();
            published.push(id);
        }
        for id in published.iter().chain([&dead]) {
            age(&store.object_path(id));
        }

        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 1, "{text}");
        for id in &published {
            assert!(
                store.object_path(id).is_dir(),
                "{id} lost its protection: {text}"
            );
        }
        assert!(!store.object_path(&dead).exists(), "{text}");
    }

    /// New projections live under the store's own root, so two stores that
    /// share a home never share a forest: the same reference names a
    /// different directory in each, neither can claim the other's, and a
    /// sweep of one never reaches into the other.
    #[test]
    fn sibling_stores_have_disjoint_new_projection_namespaces() {
        let temp = TempStore::new("sibling-stores");
        let home = temp.root.join("home");
        let [ours, theirs] = ["store-a", "store-b"].map(|name| {
            let root = home.join(name);
            for sub in [
                "objects",
                "meta",
                "cache/sha256",
                "tmp",
                "roots",
                "forests",
                "backups",
            ] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            Store::for_test(root.canonicalize().unwrap())
        });
        let reference = store::ProjectionRef::new(
            store::ProjectionBase::Forests,
            vec!["0123456789abcdef".into(), "node_modules".into()],
        )
        .unwrap();
        let (our_forest, their_forest) = (reference.path(&ours), reference.path(&theirs));
        assert_ne!(our_forest, their_forest);
        assert!(our_forest.starts_with(ours.root.join("forests")));
        assert!(their_forest.starts_with(theirs.root.join("forests")));
        assert!(
            ours.projection_ref(store::ProjectionBase::Forests, &their_forest)
                .is_err(),
            "a store claimed its sibling's forest"
        );

        for forest in [&our_forest, &their_forest] {
            fs::create_dir_all(forest.join("left-pad")).unwrap();
            age(forest);
        }
        register_objects(&ours, &temp.root.join("project"), &[]);
        let (report, text) = sweep(
            &ours,
            Options {
                keep_days: 0,
                project: true,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().forests, 1, "{text}");
        assert!(!our_forest.exists(), "{text}");
        assert!(
            their_forest.join("left-pad").is_dir(),
            "a sweep reached into a sibling store: {text}"
        );
    }

    /// A project whose path is not UTF-8 may once have been recorded under
    /// its lossy spelling (U+FFFD for the bad byte), and so under the lossy
    /// spelling's key. Registering the real path writes its own key; the
    /// old record is neither merged into it nor re-keyed. It stays as it
    /// was, both keys are listed, and the sweep refuses until the old key is
    /// forgotten explicitly.
    // APFS refuses non-UTF-8 file names (EILSEQ), so the real path can only
    // exist on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_lossy_key_is_not_silently_reassigned() {
        use sha1::Digest as _;
        use std::os::unix::ffi::OsStringExt;
        let key = |path: &Path| hex::encode(sha1::Sha1::digest(path.as_os_str().as_bytes()));
        let temp = TempStore::new("lossy-key");
        let store = temp.store();
        let protected = commit(&store, "protected", None);
        let dead = commit(&store, "dead", None);
        age(&store.object_path(&protected));
        age(&store.object_path(&dead));
        let raw = PathBuf::from(std::ffi::OsString::from_vec(
            [store.root.as_os_str().as_bytes(), b"/project-\xff"].concat(),
        ));
        fs::create_dir_all(&raw).unwrap();
        let lossy = PathBuf::from(raw.to_string_lossy().into_owned());
        let (raw_key, lossy_key) = (key(&raw), key(&lossy));
        assert_ne!(raw_key, lossy_key);

        let legacy = store.root.join("roots").join(&lossy_key);
        fs::write(&legacy, format!("{}\n", lossy.display())).unwrap();
        let legacy_bytes = fs::read(&legacy).unwrap();
        store
            .register_root_record(store::RootRecord {
                key: raw_key.clone(),
                project_path: raw.clone(),
                objects: BTreeSet::from([protected.clone()]),
                projections: BTreeSet::new(),
                updated: 1,
            })
            .unwrap();

        let roots = store.roots().unwrap();
        let keys: BTreeSet<&str> = roots.iter().map(|root| root.key.as_str()).collect();
        assert_eq!(keys, BTreeSet::from([raw_key.as_str(), lossy_key.as_str()]));
        assert_eq!(fs::read(&legacy).unwrap(), legacy_bytes);

        let (result, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(&format!("--forget {lossy_key}")),
            "the old key is not named for recovery: {error}"
        );
        assert!(store.object_path(&dead).is_dir(), "{text}");
        assert_eq!(fs::read(&legacy).unwrap(), legacy_bytes);

        store.forget_root(&lossy_key).unwrap();
        let (report, text) = sweep(
            &store,
            Options {
                keep_days: 0,
                ..Options::default()
            },
        );
        assert_eq!(report.unwrap().objects, 1, "{text}");
        assert!(store.object_path(&protected).is_dir(), "{text}");
        assert!(!store.object_path(&dead).exists(), "{text}");
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

        // The same store with one unreadable record reports a block instead,
        // and authorizes no deletion at all.
        wedge(&store, "mystery");
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
        match read(&store, &activity, &Options::default()) {
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

    // =======================================================================
    // Issue #101: a record that no longer hashes to its own id.
    //
    // The store this models came from a text rewrite of an identity input
    // (`~/.blanket/store` -> `~/.tog/store`), which left the stored id as the
    // hash of the old text. Nothing can read the record, so the fail-closed
    // sweep refuses — correctly — and before `--drop-object` existed there
    // was no command that changed the situation.
    // =======================================================================

    /// Move one hex digit of an id, so the identity inside no longer hashes
    /// to the name the record is filed under.
    fn mismatched_id(real: &str) -> String {
        let mut bytes = real.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("ascii hex")
    }

    /// Publish an object under an id its own identity does not produce.
    /// The object directory is read-only exactly as a real commit leaves it,
    /// so another object can still name this one as a dependency.
    pub(super) fn wedge(store: &Store, name: &str) -> String {
        let identity = test_identity(name, None);
        let id = mismatched_id(&identity.object_id());
        let object = store.object_path(&id);
        fs::create_dir_all(&object).unwrap();
        fs::write(object.join("payload"), name).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&object).unwrap().permissions();
        permissions.set_mode(permissions.mode() & !0o222);
        fs::set_permissions(&object, permissions).unwrap();
        fs::write(
            store.root.join("meta").join(format!("{id}.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema": "object-meta/2",
                "id": id,
                "identity": identity,
                "created": 0,
                "exceptions": [],
                "dependencies": [],
                "cache_digests": [],
                "evidence": "explicit",
            }))
            .unwrap(),
        )
        .unwrap();
        id
    }

    fn dropped(store: &Store, ids: &[String], dry_run: bool) -> (io::Result<usize>, String) {
        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let result = drop_objects(store, &activity, ids, dry_run, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    /// The whole issue, end to end: the sweep refuses and names the recovery
    /// command, and `--drop-object` is the thing that unwedges the store.
    #[test]
    fn an_unreadable_record_is_reported_droppable_and_unwedges_the_sweep() {
        let temp = TempStore::new("wedged-record");
        let store = temp.store();
        let id = wedge(&store, "wedged");
        register_objects(&store, &temp.root.join("project"), &[]);

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        let error = collect_with_activity(&store, &activity, Options::default(), &mut out)
            .unwrap_err()
            .to_string();
        drop(activity);
        assert!(
            error.contains(&format!("--drop-object {id}")),
            "the recovery command is not named: {error}"
        );
        assert!(
            store.object_path(&id).is_dir(),
            "the fail-closed sweep deleted something"
        );

        let (count, text) = dropped(&store, std::slice::from_ref(&id), true);
        assert_eq!(count.unwrap(), 1, "{text}");
        assert!(text.contains(&format!("would drop object {id}")), "{text}");
        assert!(store.object_path(&id).is_dir(), "a dry run removed it");

        let (count, text) = dropped(&store, std::slice::from_ref(&id), false);
        assert_eq!(count.unwrap(), 1, "{text}");
        assert!(text.contains(&format!("dropped object {id}")), "{text}");
        assert!(!store.object_path(&id).exists(), "{text}");
        assert!(
            !store.root.join("meta").join(format!("{id}.json")).exists(),
            "{text}"
        );

        let activity = store.activity(ActivityMode::Exclusive).unwrap();
        let mut out = Vec::new();
        collect_with_activity(&store, &activity, Options::default(), &mut out).unwrap();
    }

    /// The boundary that keeps `--drop-object` from becoming a second,
    /// unproven sweep: a record that says for itself what it needs is the
    /// sweep's business, not this command's.
    #[test]
    fn dropping_refuses_an_object_with_usable_metadata() {
        let temp = TempStore::new("drop-usable");
        let store = temp.store();
        let id = commit(&store, "healthy", None);

        let (result, text) = dropped(&store, std::slice::from_ref(&id), false);
        let error = result.unwrap_err().to_string();
        assert!(error.contains("has usable metadata"), "{error}");
        assert!(error.contains("--forget"), "{error}");
        assert!(text.is_empty(), "{text}");
        assert!(store.object_path(&id).is_dir(), "{error}");
    }

    /// Dropping a dependency out from under a readable dependent would wedge
    /// the sweep again, and a sync would not repair it: the dependent's id is
    /// unchanged, so it is a cache hit and nothing rebuilds the dependency.
    #[test]
    fn dropping_a_proven_dependency_requires_dropping_its_dependents() {
        let temp = TempStore::new("drop-dependents");
        let store = temp.store();
        let wedged = wedge(&store, "wedged");
        let dependent = commit(&store, "dependent", Some(&wedged));
        let mut whole_set = [wedged.clone(), dependent.clone()];
        whole_set.sort();

        let (result, text) = dropped(&store, std::slice::from_ref(&wedged), false);
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(&format!("--drop-object {} {}", whole_set[0], whole_set[1])),
            "the whole set is not named: {error}"
        );
        assert!(text.is_empty(), "{text}");
        assert!(store.object_path(&wedged).is_dir(), "{error}");

        let (count, text) = dropped(&store, &whole_set, false);
        assert_eq!(count.unwrap(), 2, "{text}");
        assert!(
            text.contains(&format!(
                "dropped object {dependent} (depends on {wedged}, which is being dropped)"
            )),
            "the cascade reason is not named: {text}"
        );
        assert!(!store.object_path(&wedged).exists(), "{text}");
        assert!(!store.object_path(&dependent).exists(), "{text}");
    }

    /// The two half-gone shapes. Neither has any evidence left worth
    /// protecting, so drop takes both.
    #[test]
    fn a_record_without_its_object_and_an_object_without_its_record_are_droppable() {
        let temp = TempStore::new("drop-halves");
        let store = temp.store();
        let stray_record = commit(&store, "stray-record", None);
        store::remove_tree(&store.object_path(&stray_record)).unwrap();
        let bare_object = test_identity("bare-object", None).object_id();
        fs::create_dir_all(store.object_path(&bare_object)).unwrap();

        let (count, text) = dropped(&store, &[stray_record.clone(), bare_object.clone()], false);
        assert_eq!(count.unwrap(), 2, "{text}");
        assert!(
            text.contains(&format!(
                "dropped object {stray_record} (metadata for a missing object)"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "dropped object {bare_object} (object without metadata)"
            )),
            "{text}"
        );
        assert!(
            !store
                .root
                .join("meta")
                .join(format!("{stray_record}.json"))
                .exists(),
            "{text}"
        );
        assert!(!store.object_path(&bare_object).exists(), "{text}");
    }

    #[test]
    fn dropping_an_id_the_store_does_not_have_is_an_error() {
        let temp = TempStore::new("drop-missing");
        let store = temp.store();
        let absent = test_identity("absent", None).object_id();

        let (result, text) = dropped(&store, std::slice::from_ref(&absent), false);
        let error = result.unwrap_err().to_string();
        assert_eq!(error, format!("no such object {absent}"), "{text}");
    }

    /// Removal order is a durability choice, not tidiness. A batch that
    /// fails partway must never leave a readable record naming an id with
    /// nothing under `objects/`, so the shape checks all happen first.
    #[test]
    fn a_record_that_is_not_a_regular_file_refuses_before_any_removal() {
        let temp = TempStore::new("drop-bad-record");
        let store = temp.store();
        let first = wedge(&store, "wedged");
        // A second id whose record name is a directory: `remove_file` would
        // fail on it, and it must do so before the first id is touched.
        let second = test_identity("directory-record", None).object_id();
        fs::create_dir_all(store.object_path(&second)).unwrap();
        fs::create_dir_all(store.root.join("meta").join(format!("{second}.json"))).unwrap();

        let (result, text) = dropped(&store, &[first.clone(), second.clone()], false);
        let error = result.unwrap_err().to_string();
        assert_eq!(
            error,
            format!("object {second} metadata is not a regular file"),
            "{text}"
        );
        assert!(text.is_empty(), "{text}");
        assert!(
            store.object_path(&first).is_dir()
                && store
                    .root
                    .join("meta")
                    .join(format!("{first}.json"))
                    .is_file(),
            "the refusal removed part of the batch: {error}"
        );
    }
}

//! Registry-record safety at the CLI boundary.
//!
//! Every case builds a disposable store by hand — the shapes the independent
//! adversarial review used — and drives the real binary, so record parsing,
//! the register/forget preflight and the sweep refusals are covered together.
//! No network, no toolchains: the store holds one hand-written object.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, SystemTime};

mod common;

use common::{command, TempDir};

/// The one hand-written object. Its id must be the real hash of its identity:
/// the sweep's metadata reader refuses any record whose identity hashes to a
/// different id, and a legacy (schemaless) record of an unknown kind can
/// never be certified, so the fixture publishes a complete `object-meta/2`
/// record the way `tests/cli.rs::publish_certified_object` does.
fn protected_identity() -> tog::kernel::types::Identity {
    tog::kernel::types::Identity {
        kind: "test".into(),
        name: "protected".into(),
        version: "1".into(),
        inputs: Default::default(),
    }
}

struct Fixture {
    temp: TempDir,
    store: PathBuf,
    protected: String,
}

impl Fixture {
    /// A store with one aged, referenced object and an initialized registry.
    fn new(label: &str) -> Self {
        let temp = TempDir::new(&format!("gc-roots-{label}"));
        let store = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store.join(sub)).unwrap();
        }
        fs::write(store.join("roots/.initialized"), b"1\n").unwrap();
        let identity = protected_identity();
        let protected = identity.object_id();
        let object = store.join("objects").join(&protected);
        fs::create_dir_all(&object).unwrap();
        fs::write(object.join("payload"), b"live data\n").unwrap();
        fs::write(
            store.join("meta").join(format!("{protected}.json")),
            serde_json::json!({
                "schema": "object-meta/2",
                "id": protected,
                "identity": identity,
                "created": 1,
                "exceptions": [],
                "dependencies": [],
                "cache_digests": [],
                "evidence": "explicit",
            })
            .to_string(),
        )
        .unwrap();
        age(&object);
        Self {
            temp,
            store,
            protected,
        }
    }

    /// The scratch root: the binary's cwd and HOME, and the parent of the
    /// store and every project.
    fn base(&self) -> &Path {
        self.temp.path()
    }

    fn object(&self) -> PathBuf {
        self.store.join("objects").join(&self.protected)
    }

    fn roots(&self) -> PathBuf {
        self.store.join("roots")
    }

    /// A project directory; `live` gives it a closure holding the object.
    fn project(&self, name: &str, live: bool) -> PathBuf {
        let project = self.base().join(name);
        self.make_project(&project, live);
        project
    }

    fn make_project(&self, project: &Path, live: bool) {
        let closures = project.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        if live {
            fs::write(
                closures.join("python.json"),
                serde_json::json!({
                    "schema": "closure/1",
                    "ecosystem": "python",
                    "body": {"env_object": self.object().display().to_string()},
                })
                .to_string(),
            )
            .unwrap();
        }
    }

    /// Write a registry record by hand, exactly as `register_root` would.
    fn record(&self, project: &Path) -> String {
        let key = tog::kernel::store::Store::root_key(project).unwrap();
        self.record_as(&key, format!("{}\n", project.display()).as_bytes());
        key
    }

    fn record_as(&self, key: &str, contents: &[u8]) {
        fs::write(self.roots().join(key), contents).unwrap();
    }

    /// Every record's name and contents, for before/after comparison.
    fn record_snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let mut records: Vec<(String, Vec<u8>)> = fs::read_dir(self.roots())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap_or_default(),
                )
            })
            .collect();
        records.sort();
        records
    }

    fn record_names(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.roots())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != ".initialized")
            .collect();
        names.sort();
        names
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Output {
        self.run_in(self.base(), args)
    }

    fn run_in<S: AsRef<OsStr>, P: AsRef<Path>>(&self, cwd: P, args: &[S]) -> Output {
        command(cwd.as_ref(), self.base(), &self.store)
            .args(args)
            .output()
            .unwrap()
    }
}

/// Objects younger than the active window are never swept; age them past it.
fn age(path: &Path) {
    let old = SystemTime::now() - Duration::from_secs(40 * 24 * 60 * 60);
    fs::File::open(path).unwrap().set_modified(old).unwrap();
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A registry key names exactly one file. Two records whose names differ only
/// in case are two different projects' protection, so forgetting the key the
/// user typed must never remove the other spelling's record.
#[test]
fn forget_removes_only_the_exact_key_that_was_asked_for() {
    let fixture = Fixture::new("case");
    let lower = "abcdef0123456789abcdef0123456789abcdef01";
    let upper = lower.to_ascii_uppercase();
    let lower_project = fixture.project("lower", true);
    let upper_project = fixture.project("upper", true);
    fixture.record_as(lower, format!("{}\n", lower_project.display()).as_bytes());
    fixture.record_as(&upper, format!("{}\n", upper_project.display()).as_bytes());
    if fixture.record_names().len() < 2 {
        // A case-insensitive filesystem (default APFS on macOS) folds the two
        // spellings into one file, so there is no second record to protect.
        eprintln!("skipped: the registry filesystem is case-insensitive");
        return;
    }

    let listing = fixture.run(&["store", "roots"]);
    assert!(listing.status.success(), "{}", stderr(&listing));
    assert!(stdout(&listing).contains(lower), "{}", stdout(&listing));
    assert!(stdout(&listing).contains(&upper), "{}", stdout(&listing));

    let forget = fixture.run(&["gc", "--forget", &upper]);
    assert!(forget.status.success(), "{}", stderr(&forget));
    assert!(
        stderr(&forget).contains(&upper) && stderr(&forget).contains("upper"),
        "forgot a record the user did not name: {}",
        stderr(&forget)
    );
    assert_eq!(
        fixture.record_names(),
        vec![lower.to_string()],
        "--forget removed the wrong record"
    );
}

/// A record the store cannot read must stop the sweep, not disappear from the
/// registry's own listing. The review replaced a working record with a
/// symlink, a dangling symlink and an empty file: each time `store roots`
/// went quiet and the next sweep deleted the live object that record had been
/// protecting a moment earlier.
#[test]
fn unreadable_records_block_the_sweep_instead_of_disappearing() {
    for shape in [
        "symlink",
        "dangling-symlink",
        "empty",
        "not-utf8",
        "directory",
        "padded-pathname",
        "relative-pathname",
    ] {
        let fixture = Fixture::new(shape);
        let project = fixture.project("project", true);
        let key = fixture.record(&project);
        let record = fixture.roots().join(&key);

        // Control: while the record is readable it keeps the aged object.
        let control = fixture.run(&["gc", "--keep-days=0"]);
        assert!(control.status.success(), "{}", stderr(&control));
        assert!(
            fixture.object().is_dir(),
            "control sweep deleted the object"
        );

        fs::remove_file(&record).unwrap();
        match shape {
            "symlink" => {
                let saved = fixture.base().join("saved-record");
                fs::write(&saved, format!("{}\n", project.display())).unwrap();
                symlink(&saved, &record).unwrap();
            }
            "dangling-symlink" => symlink(fixture.base().join("absent"), &record).unwrap(),
            "empty" => fs::write(&record, b"").unwrap(),
            "not-utf8" => fs::write(&record, b"\xff\n").unwrap(),
            "directory" => fs::create_dir(&record).unwrap(),
            "padded-pathname" => fs::write(&record, format!(" {}\n", project.display())).unwrap(),
            _ => fs::write(&record, b"project\n").unwrap(),
        }

        let listing = fixture.run(&["store", "roots"]);
        assert!(listing.status.success(), "{}", stderr(&listing));
        assert!(
            stdout(&listing).contains(&key) && stdout(&listing).contains("unusable record"),
            "{shape}: the listing hid the broken record: {}",
            stdout(&listing)
        );

        for args in [
            vec!["gc", "--project", "--keep-days=0"],
            vec!["gc", "--dry-run", "--keep-days=0"],
            vec!["gc", "--keep-days=0"],
        ] {
            let sweep = fixture.run(&args);
            assert!(
                !sweep.status.success(),
                "{shape}: swept past an unreadable record: {}",
                stdout(&sweep)
            );
            let message = stderr(&sweep);
            assert!(
                message.contains("refusing to sweep")
                    && message.contains(&key)
                    && message.contains("--forget"),
                "{shape}: unexpected refusal: {message}"
            );
            // The refusal has to say the record is the problem. Falling
            // through to the pathname checks would also stop the sweep, but
            // it would report an empty path and point the user at a project
            // that was never the trouble.
            assert!(
                message.contains("unusable registry record"),
                "{shape}: the refusal did not name the record: {message}"
            );
        }
        assert!(
            fixture.object().is_dir(),
            "{shape}: the sweep deleted the live object"
        );
        assert!(
            fs::symlink_metadata(&record).is_ok(),
            "{shape}: the sweep dropped the record"
        );
    }
}

/// A registry record is one line of text and the key hashes that same text.
/// A pathname that does not survive the round trip has to be refused at
/// registration: the review registered `<base>/project ` and watched the
/// record read back as `<base>/project`, a different project, whose empty
/// closures left the first project's live object collectible.
#[test]
fn a_pathname_a_record_cannot_hold_exactly_is_refused() {
    let fixture = Fixture::new("padded-path");
    let padded = fixture.project("project ", true);
    let neighbour = fixture.project("project", false);
    assert!(padded.is_dir() && neighbour.is_dir());

    let register = fixture.run(&[
        OsStr::new("gc"),
        OsStr::new("--register"),
        padded.as_os_str(),
        OsStr::new("--keep-days=0"),
    ]);
    assert!(
        !register.status.success(),
        "registered a pathname no record can hold: {}",
        stdout(&register)
    );
    assert!(
        stderr(&register).contains("refusing to register"),
        "unexpected refusal: {}",
        stderr(&register)
    );
    assert!(
        fixture.record_names().is_empty(),
        "a record was written anyway: {:?}",
        fixture.record_names()
    );
    assert!(
        fixture.object().is_dir(),
        "the sweep deleted the live object"
    );
}

/// The same identity loss without any whitespace: a directory named with a
/// byte that is not UTF-8 hashes to the key of its lossy spelling, so the
/// registration lands on the neighbouring project's identity.
#[test]
fn a_pathname_that_is_not_utf8_is_refused() {
    let fixture = Fixture::new("lossy-path");
    let mut raw = fixture.base().as_os_str().as_bytes().to_vec();
    raw.extend_from_slice(b"/project-\xff");
    let raw_project = PathBuf::from(OsString::from_vec(raw));
    match fs::create_dir_all(&raw_project) {
        Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => {
            // APFS refuses non-UTF-8 file names, so the pathname under test
            // cannot exist on macOS.
            eprintln!("skipped: the filesystem cannot hold a non-UTF-8 name");
            return;
        }
        result => result.unwrap(),
    }
    fixture.make_project(&raw_project, true);
    let lossy_twin = fixture.project("project-\u{fffd}", false);
    let twin_key = tog::kernel::store::Store::root_key(&lossy_twin).unwrap();

    // argv stays UTF-8; the child canonicalizes `.` into the raw pathname.
    let register = fixture.run_in(&raw_project, &["gc", "--register", ".", "--keep-days=0"]);
    assert!(
        !register.status.success(),
        "registered a pathname that is not UTF-8: {}",
        stdout(&register)
    );
    assert!(
        !fixture.roots().join(&twin_key).exists(),
        "registered under the neighbouring project's key"
    );
    assert!(
        fixture.record_names().is_empty(),
        "a record was written anyway: {:?}",
        fixture.record_names()
    );
    assert!(
        fixture.object().is_dir(),
        "the sweep deleted the live object"
    );
}

/// A registered project always owns a closure — registration happens when
/// one is written. A root that resolves to a directory with none is a
/// pathname that no longer names the project that was registered, which is
/// how the review's unmounted mount point deleted a live object: the backing
/// directory underneath carried an empty `.tog/closures` of its own.
#[test]
fn a_root_that_resolves_to_no_closures_blocks_the_sweep() {
    let fixture = Fixture::new("no-closures");
    let project = fixture.project("project", true);
    let key = fixture.record(&project);

    let control = fixture.run(&["gc", "--keep-days=0"]);
    assert!(control.status.success(), "{}", stderr(&control));
    assert!(
        fixture.object().is_dir(),
        "control sweep deleted the object"
    );

    fs::remove_file(project.join(".tog/closures/python.json")).unwrap();
    for args in [
        vec!["gc", "--project", "--keep-days=0"],
        vec!["gc", "--dry-run", "--keep-days=0"],
        vec!["gc", "--keep-days=0"],
    ] {
        let sweep = fixture.run(&args);
        assert!(
            !sweep.status.success(),
            "swept a root that protects nothing: {}",
            stdout(&sweep)
        );
        let message = stderr(&sweep);
        assert!(
            message.contains("refusing to sweep")
                && message.contains(&key)
                && message.contains("--forget"),
            "unexpected refusal: {message}"
        );
    }
    assert!(
        fixture.object().is_dir(),
        "the sweep deleted the live object"
    );
    assert_eq!(
        fixture.record_names(),
        vec![key],
        "the sweep dropped the record"
    );
}

/// `--dry-run` writes nothing. The review combined it with `--register` and
/// watched the new record land on disk beside the old one while the forget
/// was only previewed, so the preview mutated the registry it was previewing.
#[test]
fn dry_run_never_writes_a_record() {
    let fixture = Fixture::new("dry-register");
    let old = fixture.project("old", true);
    let key = fixture.record(&old);
    fs::remove_dir_all(&old).unwrap();
    let new = fixture.project("new", true);
    let new_key = tog::kernel::store::Store::root_key(&new).unwrap();

    let before = fixture.record_names();
    let combined = fixture.run(&[
        OsStr::new("gc"),
        OsStr::new("--dry-run"),
        OsStr::new("--forget"),
        OsStr::new(&key),
        OsStr::new("--register"),
        new.as_os_str(),
    ]);
    assert!(
        !combined.status.success(),
        "a dry run registered a root: {}",
        stdout(&combined)
    );
    assert!(
        stderr(&combined).contains("--dry-run") && stderr(&combined).contains("--register"),
        "unexpected refusal: {}",
        stderr(&combined)
    );
    assert_eq!(fixture.record_names(), before, "the dry run wrote a record");
    assert!(!fixture.roots().join(&new_key).exists());

    // The refusal is narrow: previewing a forget on its own still works and
    // still leaves the record alone, and registering for real still writes.
    let preview = fixture.run(&["gc", "--dry-run", "--forget", &key]);
    assert!(preview.status.success(), "{}", stderr(&preview));
    assert!(
        stderr(&preview).contains("would forget root"),
        "{}",
        stderr(&preview)
    );
    assert_eq!(
        fixture.record_names(),
        before,
        "the preview forgot the record"
    );

    let forget = fixture.run(&["gc", "--forget", &key]);
    assert!(forget.status.success(), "{}", stderr(&forget));
    let register = fixture.run(&[OsStr::new("gc"), OsStr::new("--register"), new.as_os_str()]);
    assert!(register.status.success(), "{}", stderr(&register));
    assert!(
        fixture.roots().join(&new_key).exists(),
        "--register wrote nothing"
    );
}

/// `--forget` is the escape hatch every refusal points at, so one corrupt
/// record must not disable it. The review found the opposite: with an
/// unrelated 40-hex record holding a stray byte, forgetting the healthy key
/// and forgetting the corrupt key both failed with "stream did not contain
/// valid UTF-8", and neither record could be removed.
#[test]
fn a_corrupt_record_never_blocks_forgetting_a_key() {
    let fixture = Fixture::new("corrupt-record");
    let project = fixture.project("project", true);
    let healthy = fixture.record(&project);
    let corrupt = "e".repeat(40);
    fixture.record_as(&corrupt, b"\xff\n");
    let hostile = "d".repeat(40);
    fixture.record_as(&hostile, &vec![b'x'; 64 * 1024]);

    // The unrelated key is forgettable while the broken records sit there.
    let forget = fixture.run(&["gc", "--forget", &healthy]);
    assert!(forget.status.success(), "{}", stderr(&forget));
    assert!(stderr(&forget).contains(&healthy), "{}", stderr(&forget));
    assert_eq!(
        fixture.record_names(),
        vec![hostile.clone(), corrupt.clone()]
    );

    // So is the broken record itself, by its own key.
    for key in [&corrupt, &hostile] {
        let forget = fixture.run(&["gc", "--forget", key]);
        assert!(forget.status.success(), "{}", stderr(&forget));
        assert!(
            stderr(&forget).contains("unusable record"),
            "{}",
            stderr(&forget)
        );
    }
    assert!(fixture.record_names().is_empty());

    // And the sweep the broken records were blocking runs again afterwards.
    let sweep = fixture.run(&["gc", "--keep-days=0"]);
    assert!(sweep.status.success(), "{}", stderr(&sweep));
    assert!(
        !fixture.object().exists(),
        "nothing protects the object any more, but it survived"
    );
}

/// A `roots/` holding only strays has never had a record written to it, so
/// the gate must still refuse. The shape that matters is a crashed write's
/// own temporary: every other stray is stopped a step later by the sweep's
/// reader, but `.<key>.tmp.<pid>.<seq>` is a name that reader knows and
/// skips, so a registry holding one and nothing else has no records at all.
/// Reading it as initialized sweeps with zero roots and deletes every aged
/// object. The compatibility path is the other half of the same gate: one
/// real record and no marker is the shape the first registry implementation
/// left behind, and that store is initialized.
#[test]
fn a_crashed_write_does_not_make_the_registry_look_initialized() {
    let fixture = Fixture::new("crashed-write");
    let project = fixture.project("project", true);
    fs::remove_file(fixture.roots().join(".initialized")).unwrap();
    let temp = format!(".{}.tmp.1.0", "a".repeat(40));
    fixture.record_as(&temp, b"/interrupted\n");

    let refused = fixture.run(&["gc", "--keep-days=0"]);
    assert!(
        !refused.status.success(),
        "the sweep ran with no records: {}",
        stdout(&refused)
    );
    assert!(
        stderr(&refused).contains("registry is not initialized"),
        "{}",
        stderr(&refused)
    );
    assert!(
        fixture.object().is_dir(),
        "the refused sweep deleted the object anyway"
    );
    // The refused read changed nothing, so the interrupted write is still
    // there for the sweep that eventually runs.
    assert!(fixture.roots().join(&temp).is_file());

    // One real record, still no marker: the gate opens, the record protects
    // the object, and the sweep clears the interrupted write itself.
    fixture.record(&project);
    let swept = fixture.run(&["gc", "--keep-days=0"]);
    assert!(swept.status.success(), "{}", stderr(&swept));
    assert!(
        fixture.object().is_dir(),
        "the record did not protect the object"
    );
    assert!(
        !fixture.roots().join(&temp).exists(),
        "the sweep left the interrupted write behind"
    );
}

/// The gate only asks whether anything was ever written. Once the marker is
/// there it opens, and a stray beside it is refused by the reader that runs
/// next: a name that is not a root key at all stops the read, and a
/// key-shaped entry that is not a record is reported as unusable. Neither
/// deletes anything, so the two guards do not have to overlap.
#[test]
fn a_stray_beside_the_marker_is_refused_by_the_reader_not_the_gate() {
    for (shape, needle) in [
        ("plain-name", "unexpected root registry entry README"),
        ("key-shaped-directory", "unusable registry record"),
    ] {
        let fixture = Fixture::new(shape);
        let project = fixture.project("project", true);
        fixture.record(&project);
        assert!(fixture.roots().join(".initialized").is_file());
        match shape {
            "plain-name" => fs::write(fixture.roots().join("README"), b"notes\n").unwrap(),
            _ => fs::create_dir(fixture.roots().join("c".repeat(40))).unwrap(),
        }

        let refused = fixture.run(&["gc", "--keep-days=0"]);
        assert!(
            !refused.status.success(),
            "{shape}: swept past a stray: {}",
            stdout(&refused)
        );
        let message = stderr(&refused);
        assert!(message.contains(needle), "{shape}: {message}");
        assert!(
            !message.contains("registry is not initialized"),
            "{shape}: the gate refused instead of the reader: {message}"
        );
        assert!(
            fixture.object().is_dir(),
            "{shape}: the refused sweep deleted the object"
        );
    }
}

/// The register/forget preflight resolves every key before the registry
/// changes, so an ambiguous or partly wrong request loses no record. The
/// review found that removing the whole preflight kept the full suite and
/// the end-to-end GC test green, so each branch is pinned here: the registry
/// must come back byte for byte unchanged.
#[test]
fn an_ambiguous_or_partly_unknown_request_changes_no_record() {
    for shape in ["same-root", "alias", "duplicate", "unknown"] {
        let fixture = Fixture::new(shape);
        let project = fixture.project("project", true);
        let key = fixture.record(&project);
        let other = fixture.project("other", true);
        let before = fixture.record_snapshot();

        let alias = fixture.base().join("alias");
        let args: Vec<OsString> = match shape {
            // Registering and forgetting one root in a single invocation is
            // ambiguous in either order, including through a symlink that
            // canonicalizes onto the same project.
            "same-root" => vec![
                "gc".into(),
                "--register".into(),
                project.clone().into(),
                "--forget".into(),
                key.clone().into(),
            ],
            "alias" => {
                symlink(&project, &alias).unwrap();
                vec![
                    "gc".into(),
                    "--forget".into(),
                    key.clone().into(),
                    "--register".into(),
                    alias.clone().into(),
                ]
            }
            "duplicate" => vec![
                "gc".into(),
                "--register".into(),
                other.clone().into(),
                "--forget".into(),
                key.clone().into(),
                key.clone().into(),
            ],
            // An unknown key must stop the whole request, including the
            // registration that was asked for in the same invocation.
            _ => vec![
                "gc".into(),
                "--register".into(),
                other.clone().into(),
                "--forget".into(),
                key.clone().into(),
                "f".repeat(40).into(),
            ],
        };

        let result = fixture.run(&args);
        assert!(
            !result.status.success(),
            "{shape}: applied an ambiguous request: {}",
            stdout(&result)
        );
        assert_eq!(
            fixture.record_snapshot(),
            before,
            "{shape}: the registry changed before the request was refused"
        );
        assert!(
            fixture.object().is_dir(),
            "{shape}: the live object was swept"
        );
    }
}

/// A `root/2` record the sweep cannot trust takes the same refusal as an
/// unreadable pathname record: the sweep's reader reports it on the entry,
/// and the refusal names the key, the record, and `--forget`. Without that
/// routing each shape would surface as its own parse error, with no key to
/// forget, or would be skipped. Forgetting the key named in the refusal
/// clears it.
#[test]
fn an_unusable_root2_record_is_refused_by_name_and_forgettable() {
    for shape in [
        "malformed-json",
        "unknown-schema",
        "key-mismatch",
        "malformed-object-id",
        "absolute-projection",
        "unknown-field",
        "uppercase-key",
    ] {
        let fixture = Fixture::new(shape);
        let project = fixture.project("project", false);
        let key = tog::kernel::store::Store::root_key(&project).unwrap();
        let record = |key: &str, objects: serde_json::Value, projections: serde_json::Value| {
            serde_json::json!({
                "schema": "root/2",
                "key": key,
                "project_path": {"encoding": "utf8", "value": project.display().to_string()},
                "objects": objects,
                "projections": projections,
                "updated": 1,
            })
        };
        let objects = serde_json::json!([fixture.protected]);
        fixture.record_as(
            &key,
            record(&key, objects.clone(), serde_json::json!([]))
                .to_string()
                .as_bytes(),
        );

        // Control: the well-formed record protects the aged object on its
        // own, with no closure in the project.
        let control = fixture.run(&["gc", "--keep-days=0"]);
        assert!(control.status.success(), "{shape}: {}", stderr(&control));
        assert!(
            fixture.object().is_dir(),
            "{shape}: control sweep deleted the object"
        );

        let mut named = key.clone();
        let body = match shape {
            "malformed-json" => b"{ \"schema\": \"root/2\", ".to_vec(),
            "unknown-schema" => {
                let mut value = record(&key, objects.clone(), serde_json::json!([]));
                value["schema"] = "root/3".into();
                value.to_string().into_bytes()
            }
            "key-mismatch" => record(&"f".repeat(40), objects.clone(), serde_json::json!([]))
                .to_string()
                .into_bytes(),
            "malformed-object-id" => record(
                &key,
                serde_json::json!(["not-an-id"]),
                serde_json::json!([]),
            )
            .to_string()
            .into_bytes(),
            "absolute-projection" => record(
                &key,
                objects.clone(),
                serde_json::json!([{
                    "base": "forests",
                    "components": [{"encoding": "utf8", "value": "/etc"}],
                }]),
            )
            .to_string()
            .into_bytes(),
            "unknown-field" => {
                let mut value = record(&key, objects.clone(), serde_json::json!([]));
                value["protects_everything"] = true.into();
                value.to_string().into_bytes()
            }
            // An uppercase spelling of the key is still key-shaped, so it is
            // read; its body names the lowercase key, so it is refused. A
            // case-insensitive filesystem folds the two names into one file.
            _ => {
                named = key.to_ascii_uppercase();
                record(&key, objects.clone(), serde_json::json!([]))
                    .to_string()
                    .into_bytes()
            }
        };
        if shape == "uppercase-key" {
            fs::remove_file(fixture.roots().join(&key)).unwrap();
            fixture.record_as(&named, &body);
            if fixture.roots().join(&key).exists() {
                eprintln!("skipped {shape}: the registry filesystem is case-insensitive");
                continue;
            }
        } else {
            fixture.record_as(&key, &body);
        }

        for args in [
            vec!["gc", "--project", "--keep-days=0"],
            vec!["gc", "--dry-run", "--keep-days=0"],
            vec!["gc", "--keep-days=0"],
        ] {
            let sweep = fixture.run(&args);
            assert!(
                !sweep.status.success(),
                "{shape}: swept past an unusable record: {}",
                stdout(&sweep)
            );
            let message = stderr(&sweep);
            assert!(
                message.contains("refusing to sweep")
                    && message.contains("unusable registry record")
                    && message.contains(&format!("--forget {named}")),
                "{shape}: the refusal did not name the record and its key: {message}"
            );
        }
        assert!(
            fixture.object().is_dir(),
            "{shape}: a refused sweep deleted the object"
        );

        let forget = fixture.run(&["gc", "--forget", &named]);
        assert!(forget.status.success(), "{shape}: {}", stderr(&forget));
        assert!(
            fixture.record_names().is_empty(),
            "{shape}: forgetting the named key left {:?}",
            fixture.record_names()
        );
        let sweep = fixture.run(&["gc", "--keep-days=0"]);
        assert!(sweep.status.success(), "{shape}: {}", stderr(&sweep));
        assert!(
            !fixture.object().exists(),
            "{shape}: nothing protects the object any more, but it survived"
        );
    }
}

/// `gc --register` validates every closure before it replaces the record.
/// One it cannot read (an unknown ecosystem or schema, bad JSON, no body)
/// refuses the whole import and leaves the record that was there, pathname
/// or durable, byte for byte.
#[test]
fn register_refuses_an_unknown_closure_and_keeps_the_old_record() {
    let fixture = Fixture::new("register-unknown");
    let project = fixture.project("project", true);
    fixture.record(&project);
    let extra = project.join(".tog/closures/extra.json");
    let shapes = [
        (
            "unknown-ecosystem",
            serde_json::json!({"schema": "closure/1", "ecosystem": "zig", "body": {}}).to_string(),
        ),
        (
            "unknown-schema",
            serde_json::json!({"schema": "closure/2", "ecosystem": "python", "body": {}})
                .to_string(),
        ),
        (
            "no-body",
            serde_json::json!({"schema": "closure/1", "ecosystem": "python"}).to_string(),
        ),
        ("malformed-json", "{ \"schema\": ".to_string()),
    ];
    let register = || {
        fixture.run(&[
            OsStr::new("gc"),
            OsStr::new("--register"),
            project.as_os_str(),
        ])
    };

    // Once over the pathname record, and once more after a clean import has
    // replaced it with a durable one.
    for generation in ["pathname", "durable"] {
        let before = fixture.record_snapshot();
        for (shape, contents) in &shapes {
            fs::write(&extra, contents).unwrap();
            let refused = register();
            assert!(
                !refused.status.success(),
                "{generation}/{shape}: imported an unreadable closure: {}",
                stderr(&refused)
            );
            assert!(
                stderr(&refused).contains("cannot import closure"),
                "{generation}/{shape}: {}",
                stderr(&refused)
            );
            assert_eq!(
                fixture.record_snapshot(),
                before,
                "{generation}/{shape}: the refused import changed the registry"
            );
        }
        fs::remove_file(&extra).unwrap();
        if generation == "pathname" {
            let imported = register();
            assert!(imported.status.success(), "{}", stderr(&imported));
            assert_ne!(fixture.record_snapshot(), before, "nothing was imported");
        }
    }
}

/// Registration reads closure files and nothing else: it never runs a
/// planner, a package manager, or anything the project ships. The tools a
/// project could reach through those are planted on PATH and in the
/// project, and none may run.
#[test]
fn register_runs_no_project_code() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new("register-no-code");
    let project = fixture.project("project", true);
    let marker = fixture.base().join("ran");
    let script = format!("#!/bin/sh\necho \"$0\" >> {}\n", marker.display());
    let fake_bin = fixture.base().join("bin");
    fs::create_dir_all(&fake_bin).unwrap();
    for tool in [
        "sh", "bash", "python", "python3", "pip", "uv", "node", "npm", "npx", "pnpm", "yarn",
        "cargo", "rustc", "go", "ruby", "gem", "bundle", "mix", "elixir", "erl", "dotnet", "git",
        "make",
    ] {
        let path = fake_bin.join(tool);
        fs::write(&path, &script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (name, contents) in [
        (
            "setup.py",
            format!("open('{}', 'a').write('setup.py')\n", marker.display()),
        ),
        (
            "package.json",
            serde_json::json!({
                "name": "p",
                "scripts": {"preinstall": format!("echo package.json >> {}", marker.display())},
            })
            .to_string(),
        ),
        (
            "build.rs",
            "fn main() { std::fs::write(\"ran\", \"\").unwrap(); }\n".into(),
        ),
        ("mix.exs", "File.write!(\"ran\", \"mix.exs\")\n".into()),
        ("Gemfile", "File.write('ran', 'Gemfile')\n".into()),
        (".envrc", format!("echo .envrc >> {}\n", marker.display())),
    ] {
        fs::write(project.join(name), contents).unwrap();
    }

    let register = command(&project, fixture.base(), &fixture.store)
        .env("PATH", &fake_bin)
        .args([
            OsStr::new("gc"),
            OsStr::new("--register"),
            project.as_os_str(),
        ])
        .output()
        .unwrap();
    assert!(register.status.success(), "{}", stderr(&register));
    assert_eq!(fixture.record_names().len(), 1, "nothing was registered");
    assert!(
        !marker.exists() && !project.join("ran").exists(),
        "registration ran project code: {}",
        fs::read_to_string(&marker).unwrap_or_default()
    );
}

/// `--forget` removes the registry entry it was asked for. When that entry
/// is a symlink, the link goes and whatever it points at stays: another
/// file, the project itself, or another project's record.
#[test]
fn forget_registry_symlink_never_touches_its_target() {
    for shape in ["file", "directory", "other-record"] {
        let fixture = Fixture::new(&format!("forget-symlink-{shape}"));
        let project = fixture.project("project", true);
        let key = fixture.record(&project);
        let link = fixture.roots().join(&key);
        let other = fixture.project("other", true);
        let other_key = fixture.record(&other);
        let target = match shape {
            "file" => {
                let saved = fixture.base().join("saved-record");
                fs::rename(&link, &saved).unwrap();
                saved
            }
            "directory" => {
                fs::remove_file(&link).unwrap();
                project.clone()
            }
            _ => {
                fs::remove_file(&link).unwrap();
                fixture.roots().join(&other_key)
            }
        };
        symlink(&target, &link).unwrap();
        let target_bytes = fs::read(&target).ok();
        let closure = project.join(".tog/closures/python.json");
        let closure_bytes = fs::read(&closure).unwrap();

        let forget = fixture.run(&["gc", "--forget", &key]);
        assert!(forget.status.success(), "{shape}: {}", stderr(&forget));
        assert!(
            fs::symlink_metadata(&link).is_err(),
            "{shape}: the link is still there"
        );
        assert!(
            fs::symlink_metadata(&target).is_ok_and(|meta| !meta.file_type().is_symlink()),
            "{shape}: the link's target was removed"
        );
        assert_eq!(
            fs::read(&target).ok(),
            target_bytes,
            "{shape}: the link's target was changed"
        );
        assert_eq!(fs::read(&closure).unwrap(), closure_bytes, "{shape}");
        assert_eq!(fixture.record_names(), vec![other_key], "{shape}");
    }
}

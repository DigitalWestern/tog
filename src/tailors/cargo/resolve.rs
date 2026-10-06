//! The Cargo resolution doors: `tog add`/`remove`/`update`, a missing
//! `Cargo.lock`, and `tog attest`'s lock check, each the store cargo
//! confined through the kernel's cargo door (TLS interception, the
//! crates.io route, the git row) at the workspace root.
//!
//! The workspace root is where cargo runs and what the door snapshots and
//! publishes: `Cargo.lock` lives there, and so do the closure and the
//! resolution record. An edit made in a member names the member's manifest
//! with `--manifest-path`.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::provider::cargo_door::{self, CargoPublish, CargoRun};
use crate::kernel::resolve::record;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use std::io;
use std::path::{Path, PathBuf};

/// The cargo a resolution record names: the selected Rust release.
pub(crate) fn cargo_tool(toolchain: &Selected) -> io::Result<record::Tool> {
    Ok(record::Tool {
        name: "cargo".to_string(),
        version: toolchain.version("rustc")?.to_string(),
    })
}

/// `Tailor::resolution_outputs` for Cargo: the workspace root's
/// `Cargo.toml` and `Cargo.lock`, and every manifest inside the root cargo
/// reads to resolve it: each member `[workspace] members` names, and each
/// path dependency (also `[patch]` and `[replace]`) of the root package and
/// of those, transitively. A path dependency inside the workspace is an
/// implicit member, so an edit there writes its manifest and a change to it
/// can change resolution while `Cargo.lock` stays the same; both need it
/// named. One outside the root, path dependency or member, is not listed
/// (a record names files inside the workspace only): [`refuse_external_inputs`].
pub(crate) fn resolution_outputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut outputs = vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")];
    let real_root = std::fs::canonicalize(root.path())?;
    let mut queue: Vec<PathBuf> = cargo_door::member_dirs(root)?.listed;
    queue.push(PathBuf::new());
    let mut seen: Vec<PathBuf> = Vec::new();
    while let Some(dir) = queue.pop() {
        if seen.contains(&dir) {
            continue;
        }
        seen.push(dir.clone());
        let manifest = dir.join("Cargo.toml");
        if !root.is_input_file(&manifest) {
            continue;
        }
        if !outputs.contains(&manifest) {
            outputs.push(manifest.clone());
        }
        for path in cargo_door::manifest_path_dependencies(&root.path().join(&manifest))? {
            let Ok(found) = std::fs::canonicalize(root.path().join(&dir).join(&path)) else {
                continue;
            };
            if let Ok(relative) = found.strip_prefix(&real_root) {
                queue.push(relative.to_path_buf());
            }
        }
    }
    outputs[2..].sort();
    Ok(outputs)
}

/// Refuse to attest a workspace that reads path dependencies or members
/// outside its root: a record names files inside the workspace only, so it could not
/// cover them, and a change there would leave the record attesting.
pub(crate) fn refuse_external_inputs(root: &Path) -> io::Result<()> {
    let outside = cargo_door::path_dependency_roots(root)?;
    if outside.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = outside
        .iter()
        .map(|dir| dir.display().to_string())
        .collect();
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "the Cargo workspace at {} reads path dependencies or members outside it ({}); a \
             resolution record names files inside the workspace only, so it cannot cover them \
             and is not written. Move them into the workspace to attest it",
            root.display(),
            named.join(", ")
        ),
    ))
}

/// `Tailor::resolution_inputs` for Cargo: the configuration cargo reads at
/// the workspace root (its registries, source replacement, `net` settings),
/// with every file it includes, so an edit to an included file makes the
/// record stale like an edit to the config itself.
pub(crate) fn resolution_inputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut inputs: Vec<PathBuf> = cargo_door::CONFIG_FILES.iter().map(PathBuf::from).collect();
    let bound = cargo_door::Bound::new(root.path())?;
    let real_root = std::fs::canonicalize(root.path())?;
    for file in cargo_door::config_files(root.path(), &bound)? {
        let relative = file
            .real
            .strip_prefix(&real_root)
            .map_err(|_| io::Error::other("a cargo config file left the bound"))?
            .to_path_buf();
        if !inputs.contains(&relative) {
            inputs.push(relative);
        }
    }
    Ok(inputs)
}

/// `cargo generate-lockfile` at the workspace root `root` (held as
/// `workspace`), through `door` (a missing-lock door): the lock and the
/// signed resolution record are published together.
pub(crate) fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    workspace: &ProjectRoot,
    rust_obj: &Path,
    toolchain: &Selected,
) -> io::Result<()> {
    cargo_door::refuse_unlisted_members(workspace)?;
    let args = ["generate-lockfile"];
    let tailor = super::tailor::Cargo;
    let spec = crate::tailors::record_spec(&tailor, workspace, cargo_tool(toolchain)?, &args)?;
    cargo_door::run_cargo_checked(
        door,
        CargoRun {
            rust_obj,
            lock_root: workspace.path(),
            args: &args,
            publish: CargoPublish::Project {
                outputs: resolution_outputs(workspace)?,
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )
    .map(drop)
}

/// `tog attest` for Cargo: `cargo metadata --locked` at the workspace root
/// through `door`'s transaction with the record's producer. `--locked`
/// fails when `Cargo.lock` is not what the manifests resolve to, and the
/// run downloads every crate (cargo reads each one's manifest), each
/// verified against its index checksum by the proxy. The check publishes
/// nothing, not even the receipt: `tog attest` publishes every record only
/// once every check passed.
pub(crate) fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    rust_obj: &Path,
    root: &Path,
    toolchain: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    let err = |text: String| io::Error::other(text);
    if project.relative(root).map(|rel| rel.as_os_str().is_empty()) != Some(true) {
        return Err(err(format!(
            "{} is a member of the Cargo workspace at {}; its Cargo.lock and resolution record \
             live there, so run `tog attest cargo` in {}",
            project.path().display(),
            root.display(),
            root.display()
        )));
    }
    refuse_external_inputs(project.path())?;
    cargo_door::refuse_unlisted_members(project)?;
    let args = ["metadata", "--locked", "--format-version", "1"];
    let tailor = super::tailor::Cargo;
    let mut spec = crate::tailors::record_spec(&tailor, project, cargo_tool(toolchain)?, &args)?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = cargo_door::run_cargo(
        door,
        CargoRun {
            rust_obj,
            lock_root: project.path(),
            args: &args,
            publish: CargoPublish::Project {
                outputs: resolution_outputs(project)?,
                receipt: Some(record::producer(spec, slot.clone())),
            },
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "Cargo.lock in {} is not what cargo resolves the manifests to, so it is not \
             attested; run `tog` to bring it up to date and commit the result\n{}",
            project.path().display(),
            crate::kernel::resolve::confine::scrub_signing_key(
                String::from_utf8_lossy(&report.stderr).trim()
            )
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("cargo's lock check published no record".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    fn package(dir: &Path, name: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n"),
        )
        .unwrap();
    }

    /// Path dependencies inside the workspace are implicit members: their
    /// manifests are outputs (an edit there publishes, and a change there
    /// stales the record), found transitively from the root package and
    /// the listed members, `[patch]` included. One outside the root is not
    /// an output, and attesting such a workspace is refused, naming it.
    #[test]
    fn implicit_members_are_outputs_and_external_inputs_refuse_attest() {
        let temp = TempDir::named("cargo-implicit");
        let root = temp.0.join("ws");
        let write = |relative: &str, text: &str| {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write(
            "Cargo.toml",
            "[package]\nname = \"root\"\n[dependencies]\ncore = { path = \"libs/core\" }\n\
             [workspace]\nmembers = [\"app\"]\n[patch.crates-io]\nitoa = { path = \"vendor/itoa\" }\n",
        );
        write(
            "app/Cargo.toml",
            "[package]\nname = \"app\"\n[dev-dependencies]\ntesty = { path = \"../libs/testy\" }\n",
        );
        write(
            "libs/core/Cargo.toml",
            "[package]\nname = \"core\"\n[dependencies]\ndeep = { path = \"../deep\" }\n",
        );
        write("libs/deep/Cargo.toml", "[package]\nname = \"deep\"\n");
        write("libs/testy/Cargo.toml", "[package]\nname = \"testy\"\n");
        write("vendor/itoa/Cargo.toml", "[package]\nname = \"itoa\"\n");
        write("unrelated/Cargo.toml", "[package]\nname = \"unrelated\"\n");
        let held = ProjectRoot::open(&root).unwrap();
        let mut outputs = resolution_outputs(&held).unwrap();
        outputs.sort();
        assert_eq!(
            outputs,
            [
                "Cargo.lock",
                "Cargo.toml",
                "app/Cargo.toml",
                "libs/core/Cargo.toml",
                "libs/deep/Cargo.toml",
                "libs/testy/Cargo.toml",
                "vendor/itoa/Cargo.toml",
            ]
            .map(PathBuf::from)
            .to_vec()
        );
        refuse_external_inputs(&root).unwrap();

        // A path dependency outside the workspace.
        fs::create_dir_all(temp.0.join("shared")).unwrap();
        fs::write(
            temp.0.join("shared/Cargo.toml"),
            "[package]\nname = \"shared\"\n",
        )
        .unwrap();
        write(
            "libs/deep/Cargo.toml",
            "[package]\nname = \"deep\"\n[dependencies]\nshared = { path = \"../../../shared\" }\n",
        );
        let outputs = resolution_outputs(&held).unwrap();
        assert!(
            outputs.iter().all(|path| !path.starts_with("..")),
            "{outputs:?}"
        );
        let error = refuse_external_inputs(&root).unwrap_err().to_string();
        assert!(
            error.contains("shared") && error.contains("cannot cover"),
            "{error}"
        );
    }

    /// The inputs are both config spellings and every file they include,
    /// so the record covers, and goes stale with, an included file.
    #[test]
    fn inputs_name_every_included_config_file() {
        let temp = TempDir::named("cargo-inputs");
        let root = temp.0.join("ws");
        fs::create_dir_all(root.join(".cargo/sub")).unwrap();
        fs::write(
            root.join(".cargo/config.toml"),
            "include = [\"sub/registries.toml\"]\n",
        )
        .unwrap();
        fs::write(
            root.join(".cargo/sub/registries.toml"),
            "[registries.evil]\nindex = \"sparse+https://evil.test/\"\n",
        )
        .unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        assert_eq!(
            resolution_inputs(&held).unwrap(),
            [
                ".cargo/config.toml",
                ".cargo/config",
                ".cargo/sub/registries.toml"
            ]
            .map(PathBuf::from)
            .to_vec()
        );
    }

    /// The outputs are the root's manifest and lock and every member's
    /// manifest the `[workspace]` names, by path or glob, less `exclude`
    /// (which an explicit member, or one under it, overrides), as cargo
    /// 1.98.1 lists them (checked against `cargo metadata`): a
    /// wildcard matches a hidden directory and `target`, a class matches
    /// its letters (`[**]` a class of `*`, not a recursive wildcard), `**`
    /// reaches any depth. An absolute entry or one with `.` or `..` is
    /// placed lexically. One outside the root is not an output and refuses
    /// attest, like a path dependency there. A directory with no manifest
    /// is not listed.
    /// An absolute member written through another spelling of the root (a
    /// symlink to it, or to a directory above it) is the member inside the
    /// root it names, as cargo places it: listed, an output, and no
    /// external input. The rest of the entry stays a pattern.
    #[test]
    fn an_absolute_member_through_a_symlinked_root_spelling_is_inside() {
        let temp = TempDir::named("cargo-root-spelling");
        let root = temp.0.join("ws");
        package(&root.join("app"), "app");
        package(&root.join("crates/a"), "a");
        std::os::unix::fs::symlink(&root, temp.0.join("alias")).unwrap();
        std::os::unix::fs::symlink(&temp.0, temp.0.join("above")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[workspace]\nmembers = [\"{}\", \"{}\"]\n",
                temp.0.join("alias/app").display(),
                temp.0.join("above/ws/crates/*").display()
            ),
        )
        .unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        assert_eq!(
            cargo_door::member_dirs(&held).unwrap().listed,
            ["app", "crates/a"].map(PathBuf::from).to_vec()
        );
        assert_eq!(
            resolution_outputs(&held).unwrap(),
            [
                "Cargo.toml",
                "Cargo.lock",
                "app/Cargo.toml",
                "crates/a/Cargo.toml"
            ]
            .map(PathBuf::from)
            .to_vec()
        );
        refuse_external_inputs(&root).unwrap();
    }

    #[test]
    fn outputs_name_every_member_manifest_inside_the_root() {
        let temp = TempDir::named("cargo-outputs");
        let root = temp.0.join("ws");
        let deep = "nested/1/2/3/4/5/6/7/8/9/10/c";
        for (dir, name) in [
            ("app", "app"),
            ("crates/a", "a"),
            ("crates/b", "b"),
            ("crates/skipped", "skipped"),
            ("kept", "kept"),
            ("stars/*", "star"),
            ("stars/x", "notstar"),
            (
                "deepest/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/m",
                "m",
            ),
            ("abs", "abs"),
            ("dotdot", "dotdot"),
            ("dot/inner", "dotinner"),
            ("sub", "sub"),
            ("sub/inner", "inner"),
            ("crates/.hidden", "hidden"),
            ("letters/a", "la"),
            ("letters/b", "lb"),
            ("letters/c", "lc"),
            ("target/t", "t"),
            (deep, "c"),
        ] {
            package(&root.join(dir), name);
        }
        fs::create_dir_all(root.join("crates/empty")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[workspace]\nmembers = [\"./app/\", \"crates/*\", \"letters/[ab]\", \
                 \"nested/**/c\", \"target/*\", \"kept\", \"sub\", \"sub/i*\", \
                 \"{}/abs\", \"x/../dotdot\", \"dot/./inner\", \"../ws/app\", \"stars/[**]\", \
                 \"deepest/**/m\"]\n\
                 exclude = [\"crates/skipped\", \"kept\", \"sub/inner\"]\n",
                root.display()
            ),
        )
        .unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let outputs: Vec<String> = resolution_outputs(&held)
            .unwrap()
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        assert_eq!(
            outputs,
            vec![
                "Cargo.toml".to_string(),
                "Cargo.lock".to_string(),
                "abs/Cargo.toml".to_string(),
                "app/Cargo.toml".to_string(),
                "crates/.hidden/Cargo.toml".to_string(),
                "crates/a/Cargo.toml".to_string(),
                "crates/b/Cargo.toml".to_string(),
                "deepest/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/m/Cargo.toml"
                    .to_string(),
                "dot/inner/Cargo.toml".to_string(),
                "dotdot/Cargo.toml".to_string(),
                "kept/Cargo.toml".to_string(),
                "letters/a/Cargo.toml".to_string(),
                "letters/b/Cargo.toml".to_string(),
                format!("{deep}/Cargo.toml"),
                "stars/*/Cargo.toml".to_string(),
                "sub/Cargo.toml".to_string(),
                "sub/inner/Cargo.toml".to_string(),
                "target/t/Cargo.toml".to_string(),
            ]
        );
        cargo_door::refuse_unlisted_members(&held).unwrap();
        // A member through a symlinked directory is not seen by a confined
        // cargo nor named by a record: confined runs are refused, by name.
        package(&temp.0.join("elsewhere/linked"), "linked");
        std::os::unix::fs::symlink(temp.0.join("elsewhere/linked"), root.join("crates/linked"))
            .unwrap();
        let error = cargo_door::refuse_unlisted_members(&held)
            .unwrap_err()
            .to_string();
        assert!(error.contains("crates/linked"), "{error}");
        // A pattern the glob crate refuses is refused here too.
        assert!(cargo_door::expand(&root, "crates/[ab").is_err());
        assert!(cargo_door::expand(&root, "crates/a**").is_err());
        assert!(cargo_door::expand(&root, "crates/***").is_err());
        // A member outside the root is not an output (a record names files
        // inside the workspace only): it is handled like an out-of-root path
        // dependency, so the outputs and a sync work, and attest refuses it
        // by name. A `..` after a wildcard is refused everywhere.
        std::fs::create_dir_all(root.join("../.git")).unwrap();
        package(&temp.0.join("outside"), "outside");
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"../outside\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolution_outputs(&held).unwrap(),
            ["Cargo.toml", "Cargo.lock", "app/Cargo.toml"]
                .map(PathBuf::from)
                .to_vec()
        );
        let error = refuse_external_inputs(&root).unwrap_err().to_string();
        assert!(error.contains("members outside it"), "{error}");
        assert!(error.contains("outside"), "{error}");
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"crates/*/../a\"]\n",
        )
        .unwrap();
        for result in [
            cargo_door::member_dirs(&held).map(|_| ()),
            cargo_door::refuse_unlisted_members(&held),
            resolution_outputs(&held).map(|_| ()),
        ] {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("\"crates/*/../a\" (a `..` after a wildcard)"),
                "{error}"
            );
        }
        // A single package has just its manifest and lock.
        package(&temp.0.join("single"), "single");
        let single = ProjectRoot::open(&temp.0.join("single")).unwrap();
        assert_eq!(
            resolution_outputs(&single).unwrap(),
            vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")]
        );
        assert_eq!(
            resolution_inputs(&single).unwrap(),
            vec![
                PathBuf::from(".cargo/config.toml"),
                PathBuf::from(".cargo/config")
            ]
        );
    }

    /// The superset rule: every members entry's glob matches and its
    /// literal path are both covered, so coverage is never smaller than
    /// cargo's member set (cargo takes the literal path when the glob's
    /// unfiltered result is empty). `crates/a[1]/` names the directory
    /// `crates/a[1]` although the file `crates/a1` matches the glob (the
    /// trailing slash keeps cargo to directories, so it falls back).
    /// `crates/b[2]` names `crates/b2`, which cargo lists, and the literal
    /// `crates/b[2]` as well, which it does not: over-covering can only
    /// make a receipt stale early. A literal member is an output: a receipt
    /// signed over the workspace goes stale when its manifest changes.
    #[test]
    fn every_members_entry_covers_its_glob_matches_and_its_literal_path() {
        use crate::kernel::resolve::record::{
            self, file_digests, Isolation, Judgment, LedgerSummary, RecordDoor, RecordFacts,
            ResolutionFiles, ResolutionRecord, Tool,
        };
        let temp = TempDir::named("cargo-literal-member");
        let root = temp.0.join("ws");
        for (dir, name) in [
            ("crates/a[1]", "alit"),
            ("crates/b[2]", "blit"),
            ("crates/b2", "btwo"),
        ] {
            package(&root.join(dir), name);
        }
        fs::write(root.join("crates/a1"), "").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/a[1]/\", \"crates/b[2]\"]\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let outputs = resolution_outputs(&held).unwrap();
        assert_eq!(
            outputs,
            [
                "Cargo.toml",
                "Cargo.lock",
                "crates/a[1]/Cargo.toml",
                "crates/b2/Cargo.toml",
                "crates/b[2]/Cargo.toml"
            ]
            .map(PathBuf::from)
            .to_vec()
        );

        // A receipt over the workspace as it is attests it, and goes stale
        // when the literal member's manifest changes.
        let files = ResolutionFiles {
            outputs,
            inputs: resolution_inputs(&held).unwrap(),
        };
        let key_path = temp.0.join("key");
        crate::kernel::signing::generate(&key_path).unwrap();
        let key = crate::kernel::signing::SigningKey::load(&key_path).unwrap();
        let mut ledger =
            crate::kernel::resolve::ledger::PortableLedger::new("cargo", "edit").unwrap();
        ledger.insert(crate::kernel::resolve::ledger::Entry {
            class: "metadata".into(),
            method: "GET".into(),
            url: "https://index.crates.io/3/i/itoa".into(),
            status: 200,
            sha256: Some(record::sha256_hex(b"index")),
            claimed: None,
            verified: false,
            freshness: None,
            redirected_to: None,
        });
        let record = ResolutionRecord::new(RecordFacts {
            ecosystem: "cargo".into(),
            door: RecordDoor::Edit,
            tool: Tool {
                name: "cargo".into(),
                version: "1.98.1".into(),
            },
            command: vec!["add".into(), "itoa".into()],
            outputs: file_digests(&held, &files.outputs).unwrap(),
            inputs: file_digests(&held, &files.inputs).unwrap(),
            ledger: LedgerSummary::of(&ledger.identity().object_id(), &ledger),
            isolation: Isolation::Confined,
            exceptions: vec![],
        })
        .unwrap();
        let bytes = record::envelope_bytes(&record.envelope(Some(&key)).unwrap()).unwrap();
        let trusted: crate::kernel::signing::KeySet = [key.public_key()].into_iter().collect();
        let judge = || record::judge("receipt", &bytes, "cargo", &trusted, &files, &held).unwrap();
        assert!(matches!(judge(), Judgment::Attests(_)));
        fs::write(
            root.join("crates/a[1]/Cargo.toml"),
            "[package]\nname = \"alit\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        match judge() {
            Judgment::Unrecorded(finding) => {
                let detail = finding.describe();
                assert!(
                    detail.contains("stale-outputs") && detail.contains("crates/a[1]/Cargo.toml"),
                    "{detail}"
                );
            }
            Judgment::Attests(_) => panic!("an edited member manifest still attests"),
        }

        // The literal path follows the walk's rules: through a symlinked
        // directory it is refused by name.
        fs::rename(root.join("crates/a[1]"), temp.0.join("moved")).unwrap();
        std::os::unix::fs::symlink(temp.0.join("moved"), root.join("crates/a[1]")).unwrap();
        let error = cargo_door::refuse_unlisted_members(&held)
            .unwrap_err()
            .to_string();
        assert!(error.contains("crates/a[1]"), "{error}");
    }

    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception, Policy};
    use crate::kernel::provider::crates_index::{DOWNLOAD_HOST, INDEX_HOST};
    use crate::kernel::resolve::door::RELAY_FOR_TEST;
    use crate::kernel::resolve::ledger::{self, Entry};
    use crate::kernel::resolve::testing::{
        blind_forwarder, relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC,
    };
    use crate::kernel::resolve::{DelegateReport, DoorKind};

    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const ITOA_CKSUM: &str = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682";

    /// The recorded crates.io answers behind a harness proxy that every
    /// host reaches (`evil.test` too, for an unattested registry), and the
    /// store Rust realized in its store. `None` after a skip.
    fn crates_harness(label: &str) -> Option<(Harness, PathBuf)> {
        let registry = stored_rows("cargo", label);
        harness_serving(
            label,
            &registry.0.to_string_lossy(),
            &[INDEX_HOST, DOWNLOAD_HOST, "evil.test"],
        )
    }

    /// The recorded `registry` (a path under the fixture registries, or an
    /// absolute one) answering for `hosts` behind a harness proxy, and the
    /// store Rust realized in its store. `None` after a skip.
    fn harness_serving(label: &str, registry: &str, hosts: &[&str]) -> Option<(Harness, PathBuf)> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(10);
        let harness = Harness::serving(label, reach, hosts, registry);
        let selected = crate::kernel::provider::rust::shipped_selection(
            crate::kernel::provider::rust::RUST_VERSION,
        )
        .unwrap();
        let rust_obj = super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap();
        Some((harness, rust_obj))
    }

    /// A library package in `dir` with `dependencies` (TOML lines).
    fn library(dir: &Path, dependencies: &str) -> PathBuf {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"spike\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
                 [dependencies]\n{dependencies}"
            ),
        )
        .unwrap();
        fs::write(dir.join("src/lib.rs"), "").unwrap();
        dir.canonicalize().unwrap()
    }

    /// The store cargo `args` in `project` through a door of `kind` on the
    /// harness proxy (policy empty), publishing the manifest and the lock.
    fn through_door(
        harness: &Harness,
        rust_obj: &Path,
        project: &Path,
        kind: DoorKind,
        args: &[&str],
    ) -> (io::Result<DelegateReport>, Vec<Exception>) {
        let mut attribution = Attribution::open("cargo").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            kind,
            &mut attribution,
        )
        .unwrap();
        let outputs = vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")];
        let run = CargoRun {
            rust_obj,
            lock_root: project,
            args,
            publish: CargoPublish::Project {
                outputs: Vec::new(),
                receipt: None,
            },
        };
        let registries = cargo_door::configured_registries(project).unwrap();
        let mut confined = cargo_door::cargo_confined(
            &run,
            CargoPublish::Project {
                outputs,
                receipt: None,
            },
            &registries,
        )
        .unwrap();
        confined.proxy = Some(&harness.proxy);
        confined.policy = Some(Policy::default());
        let spec = cargo_door::cargo_spec(rust_obj, project, args);
        let report = door.run_confined(spec, confined);
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        (report, recorded)
    }

    fn ledger_entries(harness: &Harness, report: &DelegateReport) -> Vec<Entry> {
        let objects = report.ledger.as_ref().expect("a ledger");
        let portable = ledger::PortableLedger::parse(
            &ledger::read_portable(&harness.store, &objects.ledger).unwrap(),
        )
        .unwrap();
        portable.entries().cloned().collect()
    }

    fn stderr(report: &DelegateReport) -> String {
        String::from_utf8_lossy(&report.stderr).into_owned()
    }

    /// `cargo add` confined, its crates.io traffic intercepted and answered
    /// by the recorded registry: the lock records crates.io as the source
    /// (the transport leaves no trace in it), with the index's checksum, and
    /// every request went to the two crates.io hosts through the route.
    ///
    /// Ignored: it realizes the store Rust toolchain, which is fetched over
    /// the network. The resolution itself is offline.
    #[test]
    #[ignore = "realizes the store Rust toolchain over the network"]
    fn cargo_add_through_interception_keeps_crates_io_source_in_lock() {
        let _serial = policy::attribution_test_lock();
        let Some((harness, rust_obj)) =
            crates_harness("cargo_add_through_interception_keeps_crates_io_source_in_lock")
        else {
            return;
        };
        let temp = TempDir::named("cargo-add-project");
        let project = library(&temp.0.join("project"), "");
        let (report, recorded) = through_door(
            &harness,
            &rust_obj,
            &project,
            DoorKind::Edit,
            &["add", "itoa@1.0.18"],
        );
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert!(recorded.is_empty(), "{recorded:?}");
        let manifest = fs::read_to_string(project.join("Cargo.toml")).unwrap();
        assert!(manifest.contains("itoa = \"1.0.18\""), "{manifest}");
        let lock = fs::read_to_string(project.join("Cargo.lock")).unwrap();
        assert!(
            lock.contains(&format!(
                "name = \"itoa\"\nversion = \"1.0.18\"\nsource = \"{CRATES_IO}\"\n\
                 checksum = \"{ITOA_CKSUM}\""
            )),
            "{lock}"
        );
        let entries = ledger_entries(&harness, &report);
        let has = |class: &str, url: &str| {
            entries
                .iter()
                .any(|entry| entry.class == class && entry.url == url && entry.status == 200)
        };
        assert!(
            has("metadata", "https://index.crates.io/config.json"),
            "{entries:?}"
        );
        assert!(
            has("index", "https://index.crates.io/it/oa/itoa"),
            "{entries:?}"
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.url.starts_with("https://index.crates.io/")
                    || entry.url.starts_with("https://static.crates.io/")),
            "{entries:?}"
        );
        // The upstream never saw the session's credentials.
        assert!(harness
            .upstream
            .seen()
            .iter()
            .all(|seen| seen.headers.get("proxy-authorization").is_none()));
    }

    /// A git dependency resolved confined and offline: cargo's git CLI
    /// fetch (`net.git-fetch-with-cli`) goes through the git row to the
    /// generated `cargo-git` fixture (`tools/git_fixture.py`), whose
    /// protocol v2 `ls-refs` and `fetch` share one URL. The lock pins the
    /// fixture's commit, both POSTs reached upstream with their bodies, and
    /// the ledger records the exchange as `git`.
    ///
    /// Ignored: it realizes the store Rust toolchain, which is fetched over
    /// the network. The resolution itself is offline.
    #[test]
    #[ignore = "realizes the store Rust toolchain over the network"]
    fn cargo_git_dependency_resolves_through_the_proxy_offline() {
        const LEAF: &str = "https://github.com/tog-fixtures/leaf";
        const COMMIT: &str = "d7cb160e541496c4db48210eab4114354bc40543";
        let _serial = policy::attribution_test_lock();
        let label = "cargo_git_dependency_resolves_through_the_proxy_offline";
        let Some((harness, rust_obj)) =
            harness_serving(label, "cargo-git", &["github.com", "api.github.com"])
        else {
            return;
        };
        let temp = TempDir::named("cargo-git-project");
        let project = library(
            &temp.0.join("project"),
            &format!("leaf = {{ git = \"{LEAF}\" }}\n"),
        );
        let (report, recorded) = through_door(
            &harness,
            &rust_obj,
            &project,
            DoorKind::MissingLock,
            &["generate-lockfile"],
        );
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(project.join("Cargo.lock")).unwrap();
        assert!(
            lock.contains(&format!(
                "name = \"leaf\"\nversion = \"0.1.0\"\nsource = \"git+{LEAF}#{COMMIT}\""
            )),
            "{lock}"
        );
        let bodies: Vec<String> = harness
            .upstream
            .seen()
            .iter()
            .filter(|seen| seen.target == "/tog-fixtures/leaf/git-upload-pack")
            .map(|seen| String::from_utf8_lossy(&seen.body).into_owned())
            .collect();
        assert!(
            bodies.iter().any(|body| body.contains("command=ls-refs"))
                && bodies
                    .iter()
                    .any(|body| body.contains("command=fetch") && body.contains(COMMIT)),
            "{bodies:?}"
        );
        let entries = ledger_entries(&harness, &report);
        assert!(
            entries.iter().any(|entry| entry.class == "git"
                && entry.method == "POST"
                && entry.url == format!("{LEAF}/git-upload-pack")
                && entry.status == 200),
            "{entries:?}"
        );
    }

    /// Contract 8: the lock cargo writes through interception is
    /// byte-identical to the one the same cargo writes reaching the same
    /// registry directly (through a forwarder that never looks inside the
    /// tunnel, trusting the registry's own certificate).
    #[test]
    #[ignore = "realizes the store Rust toolchain over the network"]
    fn cargo_lock_through_interception_matches_direct_run() {
        let _serial = policy::attribution_test_lock();
        let Some((harness, rust_obj)) =
            crates_harness("cargo_lock_through_interception_matches_direct_run")
        else {
            return;
        };
        let temp = TempDir::named("cargo-lock-identical");
        let dependency = "itoa = \"=1.0.18\"\n";
        let intercepted = library(&temp.0.join("intercepted"), dependency);
        let direct = library(&temp.0.join("direct"), dependency);
        let (report, _) = through_door(
            &harness,
            &rust_obj,
            &intercepted,
            DoorKind::MissingLock,
            &["generate-lockfile"],
        );
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));

        let forwarder = blind_forwarder(harness.upstream.address());
        let ca = temp.0.join("fixture-ca.pem");
        fs::write(&ca, harness.upstream_ca_pem()).unwrap();
        let output = std::process::Command::new(rust_obj.join("bin/cargo"))
            .args([
                "--config",
                &format!("http.proxy=\"http://{forwarder}\""),
                "--config",
                &format!("http.cainfo=\"{}\"", ca.display()),
                "generate-lockfile",
            ])
            .current_dir(&direct)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", rust_obj.join("bin").display()),
            )
            .env("HOME", temp.0.join("home"))
            .env("CARGO_HOME", temp.0.join("cargo-home"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let through = fs::read(intercepted.join("Cargo.lock")).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&through),
            String::from_utf8_lossy(&fs::read(direct.join("Cargo.lock")).unwrap())
        );
        assert!(String::from_utf8_lossy(&through).contains(CRATES_IO));
    }

    /// The project's `.cargo/config.toml` names a marker program for every
    /// program-naming setting cargo has (`build.rustc` and its wrappers,
    /// `build.rustdoc`, a target runner and linker, both credential-provider
    /// forms), and none runs: `cargo metadata` (which asks rustc for target
    /// information) succeeds on the store rustc, and a dependency from a
    /// registry whose `config.json` says `auth-required` fails on the
    /// forced `cargo:token` provider, which has no token.
    #[test]
    #[ignore = "realizes the store Rust toolchain over the network"]
    fn cargo_forced_settings_never_run_project_wrappers_or_credential_providers() {
        use crate::kernel::testutil::upstream::{Behavior, Reply};
        let _serial = policy::attribution_test_lock();
        let label = "cargo_forced_settings_never_run_project_wrappers_or_credential_providers";
        let Some((harness, rust_obj)) = crates_harness(label) else {
            return;
        };
        harness.upstream.set(
            "/fakecargo/config.json",
            Behavior::Reply(
                Reply::new(
                    200,
                    br#"{"dl":"https://evil.test/fakecargo/dl","api":"https://evil.test/fakecargo","auth-required":true}"#,
                )
                .header("Content-Type", "application/json"),
            ),
        );
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy/forced/cargo");
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.join("settings.json")).unwrap()).unwrap();
        let temp = TempDir::named("cargo-forced");
        let project = temp.0.join("project");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::create_dir_all(project.join("markers")).unwrap();
        fs::create_dir_all(project.join(".cargo")).unwrap();
        fs::copy(fixture.join("src/lib.rs"), project.join("src/lib.rs")).unwrap();
        let project = project.canonicalize().unwrap();
        let mut config = settings["base_config"]
            .as_str()
            .unwrap()
            .replace("@MIRROR@", "https://evil.test")
            + "\n";
        let mut providers = String::new();
        let mut manifest_append = String::new();
        for setting in settings["settings"].as_array().unwrap() {
            let name = setting["name"].as_str().unwrap();
            let marker = project.join("markers").join(name);
            fs::write(
                &marker,
                format!("#!/bin/sh\necho tog-marker-ran:{name} >&2\nexit 97\n"),
            )
            .unwrap();
            fs::set_permissions(&marker, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            let line = setting["line"]
                .as_str()
                .unwrap()
                .replace(&format!("@M:{name}@"), &marker.display().to_string());
            // The provider settings get runs of their own below: in a
            // config file as arrays they stop cargo outright.
            let into = if name.contains("credential") {
                &mut providers
            } else {
                &mut config
            };
            into.push_str(&line);
            into.push('\n');
            if let Some(append) = setting["manifest_append"].as_str() {
                if !manifest_append.contains(append) {
                    manifest_append.push_str(append);
                }
            }
        }
        fs::write(project.join(".cargo/config.toml"), &config).unwrap();
        let manifest = fs::read_to_string(fixture.join("Cargo.toml")).unwrap();
        fs::write(project.join("Cargo.toml"), &manifest).unwrap();
        let assert_no_marker = |report: &DelegateReport| {
            let text = stderr(report);
            assert!(
                !text.contains("tog-marker-ran") && !text.contains("/markers/"),
                "a project-named program ran: {text}"
            );
        };

        // `cargo metadata` resolves, downloads, and asks rustc for target
        // information: the store rustc answers, and the download is
        // verified against its index checksum.
        let (report, _) = through_door(
            &harness,
            &rust_obj,
            &project,
            DoorKind::Attest,
            &["metadata", "--format-version", "1"],
        );
        let report = report.unwrap();
        assert_no_marker(&report);
        assert!(report.status.success(), "{}", stderr(&report));
        let download = "https://static.crates.io/crates/itoa/1.0.18/download";
        let entries = ledger_entries(&harness, &report);
        assert!(
            entries.iter().any(|entry| entry.url == download
                && entry.class == "artifact"
                && entry.verified
                && entry.claimed.as_deref() == Some(&format!("sha256:{ITOA_CKSUM}")[..])),
            "{entries:?}"
        );

        // The authenticated registry, with each provider setting in each
        // form a config file can write it: as the fixture's arrays (which
        // the forced strings refuse to merge with, so cargo stops before
        // any provider runs), as strings (which the forced strings
        // replace), and through an alias named like the built-in. Cargo
        // must not run a marker in any of them, and each fails: the only
        // provider left, `cargo:token`, has no token.
        fs::write(project.join("Cargo.toml"), manifest + &manifest_append).unwrap();
        let marker = |name: &str| project.join("markers").join(name).display().to_string();
        let base = settings["base_config"]
            .as_str()
            .unwrap()
            .replace("@MIRROR@", "https://evil.test");
        let global = format!(
            "{base}\nregistry.global-credential-providers = [\"{}\"]\n",
            marker("registry.global-credential-providers"),
        );
        let string = format!(
            "{base}\nregistries.evil.credential-provider = \"{}\"\n",
            marker("registries.evil.credential-provider"),
        );
        let alias = format!(
            "{base}\nregistries.evil.credential-provider = \"cargo:token\"\n\
             [credential-alias]\n\"cargo:token\" = [\"{}\"]\n",
            marker("registries.evil.credential-provider"),
        );
        // The registry and its provider declared only in an included file:
        // tog finds it there and forces its provider like any other.
        fs::write(project.join(".cargo/evil.toml"), &string).unwrap();
        for (form, text) in [
            ("arrays", format!("{config}{providers}")),
            ("global array", global),
            ("string", string),
            ("alias", alias),
            ("included", "include = [\"evil.toml\"]\n".to_string()),
        ] {
            fs::write(project.join(".cargo/config.toml"), &text).unwrap();
            let _ = fs::remove_file(project.join("Cargo.lock"));
            let (report, _) = through_door(
                &harness,
                &rust_obj,
                &project,
                DoorKind::MissingLock,
                &["generate-lockfile"],
            );
            let report = report.unwrap();
            assert_no_marker(&report);
            assert!(!report.status.success(), "{form}: {}", stderr(&report));
            if form != "arrays" {
                assert!(
                    stderr(&report).contains("token"),
                    "{form}: {}",
                    stderr(&report)
                );
            }
        }
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        assert!(harness.upstream.hits("/fakecargo/config.json") >= 1);
    }
}

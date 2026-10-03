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
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use std::io;
use std::path::{Component, Path, PathBuf};

/// How deep a `[workspace] members` glob is expanded.
const MAX_MEMBER_DEPTH: usize = 8;

/// The cargo a resolution record names: the selected Rust release.
pub(crate) fn cargo_tool(toolchain: &Selected) -> io::Result<record::Tool> {
    Ok(record::Tool {
        name: "cargo".to_string(),
        version: toolchain.version("rustc")?.to_string(),
    })
}

/// `Tailor::resolution_outputs` for Cargo: the workspace root's
/// `Cargo.toml` and `Cargo.lock`, and the manifest of every member its
/// `[workspace] members` names (an edit in a member writes that member's
/// manifest).
pub(crate) fn resolution_outputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut outputs = vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")];
    for member in member_dirs(root)? {
        let manifest = member.join("Cargo.toml");
        if !outputs.contains(&manifest) {
            outputs.push(manifest);
        }
    }
    Ok(outputs)
}

/// `Tailor::resolution_inputs` for Cargo: the configuration cargo reads at
/// the workspace root (its registries, source replacement, `net` settings).
pub(crate) fn resolution_inputs(_root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    Ok(cargo_door::CONFIG_FILES.iter().map(PathBuf::from).collect())
}

/// The member directories (relative to `root`) its `[workspace]` names:
/// each `members` entry, a path or a glob, that holds a `Cargo.toml` and is
/// not under an `exclude` entry. A member outside the root (`../x`) is not
/// listed: the door publishes only inside its lock root.
fn member_dirs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let Some(text) = root.read_input_string(Path::new("Cargo.toml"))? else {
        return Ok(Vec::new());
    };
    let manifest: toml::Table = toml::from_str(&text).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {error}", root.path().join("Cargo.toml").display()),
        )
    })?;
    let workspace = manifest.get("workspace").and_then(|w| w.as_table());
    let list = |key: &str| -> Vec<String> {
        workspace
            .and_then(|w| w.get(key))
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .filter_map(relative_pattern)
                    .collect()
            })
            .unwrap_or_default()
    };
    let exclude: Vec<PathBuf> = list("exclude").iter().map(PathBuf::from).collect();
    let mut found = Vec::new();
    for pattern in list("members") {
        let candidates = if pattern.contains(['*', '?', '[']) {
            expand(root.path(), &pattern)?
        } else {
            vec![PathBuf::from(&pattern)]
        };
        for dir in candidates {
            let excluded = exclude.iter().any(|ex| dir.starts_with(ex));
            if !excluded && root.is_input_file(&dir.join("Cargo.toml")) && !found.contains(&dir) {
                found.push(dir);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// A members or exclude entry as a path under the root: `./` and a
/// trailing `/` dropped, `None` for one that leaves the root.
fn relative_pattern(entry: &str) -> Option<String> {
    let trimmed = entry.trim_start_matches("./").trim_end_matches('/');
    let path = Path::new(trimmed);
    let inside = !trimmed.is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    inside.then(|| trimmed.to_string())
}

/// The directories under `root` a members glob matches, at its depth (any
/// depth up to [`MAX_MEMBER_DEPTH`] for `**`). Hidden directories and
/// `target` are skipped, and symlinks are not followed.
fn expand(root: &Path, pattern: &str) -> io::Result<Vec<PathBuf>> {
    let glob = PathGlob::new(pattern)?;
    let depth = pattern.split('/').count();
    let any_depth = pattern.split('/').any(|part| part == "**");
    let mut found = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(relative) = stack.pop() {
        let level = relative.components().count();
        if level > 0 && (level == depth || any_depth) && glob.matches(&relative) {
            found.push(relative.clone());
        }
        if level >= MAX_MEMBER_DEPTH || (!any_depth && level >= depth) {
            continue;
        }
        let entries = match std::fs::read_dir(root.join(&relative)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let skip = name.to_string_lossy().starts_with('.') || name == "target";
            if !skip && entry.file_type()?.is_dir() {
                stack.push(relative.join(name));
            }
        }
    }
    Ok(found)
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
            String::from_utf8_lossy(&report.stderr).trim()
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

    /// The outputs are the root's manifest and lock and every member's
    /// manifest the `[workspace]` names, by path or glob, less `exclude`;
    /// a member outside the root and a directory with no manifest are not.
    #[test]
    fn outputs_name_every_member_manifest_inside_the_root() {
        let temp = TempDir::named("cargo-outputs");
        let root = temp.0.join("ws");
        for (dir, name) in [
            ("app", "app"),
            ("crates/a", "a"),
            ("crates/b", "b"),
            ("crates/skipped", "skipped"),
            ("crates/.hidden", "hidden"),
            ("nested/deep/c", "c"),
        ] {
            package(&root.join(dir), name);
        }
        fs::create_dir_all(root.join("crates/empty")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"./app/\", \"crates/*\", \"nested/**\", \"../outside\"]\n\
             exclude = [\"crates/skipped\"]\n",
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
                "Cargo.toml",
                "Cargo.lock",
                "app/Cargo.toml",
                "crates/a/Cargo.toml",
                "crates/b/Cargo.toml",
                "nested/deep/c/Cargo.toml",
            ]
        );
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
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(10);
        let registry = stored_rows("cargo", label);
        let harness = Harness::serving(
            label,
            reach,
            &[INDEX_HOST, DOWNLOAD_HOST, "evil.test"],
            &registry.0.to_string_lossy(),
        );
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
        for (form, text) in [
            ("arrays", format!("{config}{providers}")),
            ("global array", global),
            ("string", string),
            ("alias", alias),
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

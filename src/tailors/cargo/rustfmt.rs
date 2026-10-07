//! The pinned Rust formatting component used by `tog fmt`.
//!
//! A catalog toolchain's rustfmt is its release's own `rustfmt` row, realized
//! as a separate object beside the Rust object. A local toolchain
//! (`toolchain.path`) is used as it is, so its rustfmt is the one in its
//! tree, and the imported Rust object is also the formatter object.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::download_toolchain_artifact_held;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::toolchain::{ArtifactSpec, Selected};
use crate::kernel::types::Identity;
use crate::tailors::cargo;
use cargo::unpack::stage_rustfmt;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::kernel::provider::rust::RUSTFMT_RECIPE;
#[cfg(test)]
use crate::kernel::provider::rust::{shipped_selection, RUST_VERSION};
use crate::kernel::provider::rust_path;

/// The shipped release's rustfmt row for Rust `rust_version`: every release
/// in the catalog carries the rustfmt of the same version.
#[cfg(test)]
fn shipped_row(platform: Platform, rust_version: &str) -> io::Result<ArtifactSpec> {
    let selected = shipped_selection(rust_version)?;
    rustfmt_row(platform, &selected).map_err(|_| no_pin("rustfmt component", platform))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "rustfmt component")?;
    let catalog = cargo::toolchain_catalog()?;
    catalog
        .default_release()
        .and_then(|default| default.artifact(platform, "rustfmt"))
        .map(|_| ())
        .ok_or_else(|| no_pin("rustfmt component", platform))
}

/// The identity of the shipped rustfmt paired with `rust_object`, for the
/// drift and golden checks below.
#[cfg(test)]
fn rustfmt_identity(
    platform: Platform,
    rust_version: &str,
    rust_object: &Path,
) -> io::Result<Identity> {
    let row = shipped_row(platform, rust_version)?;
    identity_from(platform, rust_version, row.digest.hex(), rust_object)
}

/// The rustfmt object's identity, from the component digest that went into
/// it and the Rust object it is published beside. A pin row and a locked
/// bundle row reach this with the same bytes.
fn identity_from(
    platform: Platform,
    version: &str,
    rustfmt_sha256: &str,
    rust_object: &Path,
) -> io::Result<Identity> {
    let rust_object = rust_object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Rust object has no UTF-8 id"))?;
    Ok(Identity {
        kind: "rustfmt".into(),
        name: "rustfmt".into(),
        version: version.into(),
        inputs: BTreeMap::from([
            ("platform".into(), platform.triple().into()),
            ("rust_object".into(), rust_object.into()),
            ("rustfmt_sha256".into(), rustfmt_sha256.into()),
            ("schema".into(), RUSTFMT_RECIPE.into()),
        ]),
    })
}

/// The formatter row of `selected`, checked before it is fetched: it rides
/// in the same release bundle as the compiler, under its own recipe.
fn rustfmt_row(platform: Platform, selected: &Selected) -> io::Result<ArtifactSpec> {
    selected.checked_artifact(platform, "rustfmt", RUSTFMT_RECIPE, "sha256")
}

/// Where tog 0.x wrote the `rustfmt` closure, relative to the workspace root.
/// `tog fmt` no longer writes one: the lock's Rust row pins the rustfmt
/// archive by sha256, so the formatter that runs is the pinned one by
/// construction, and a record of it proved nothing the lock did not.
const LEGACY_RECORD: &str = ".tog/closures/rustfmt.json";

/// Delete a `rustfmt` record an older `tog fmt` left in `project`, so the
/// workspace heals itself on the next run. The record was a single envelope
/// (its signature is inside it), so there is nothing beside it to remove.
/// An absent record is fine; a symlink or directory in its place is refused
/// rather than followed, like every other write under `.tog`.
///
/// It stays when it is the project's only closure (a directory or symlink
/// under a closure name is not one, since gc skips it too) and the project
/// is still `registered`: the older `tog fmt` also registered a gc root for
/// the project, and a root whose closures directory is empty stops every
/// `tog gc` sweep. Forgetting that root needs the store's exclusive lease,
/// which a formatter run does not take. `tog gc` forgets a root whose only
/// closures are retired when it protects nothing they do not name, so the
/// next run after that sweep removes the file.
pub fn remove_legacy_record(project: &ProjectRoot, registered: bool) -> io::Result<()> {
    let closures = Path::new(".tog/closures");
    let Some(names) = project.read_dir(closures)? else {
        return Ok(());
    };
    let legacy = Path::new(LEGACY_RECORD);
    let others = names.iter().any(|name| {
        let path = closures.join(name);
        path != legacy
            && crate::kernel::store::is_closure_file(&path)
            && matches!(project.entry(&path), Ok(Entry::Regular))
    });
    if !others && registered {
        return Ok(());
    }
    project.remove_file(legacy)
}

/// The identity realization builds from a selection's row, for the drift
/// check that holds it to the identity the pin produces.
#[cfg(test)]
pub(super) fn identity_for_test(
    platform: Platform,
    selected: &Selected,
    rust_object: &Path,
) -> io::Result<Identity> {
    let row = rustfmt_row(platform, selected)?;
    identity_from(platform, &row.version, row.digest.hex(), rust_object)
}

#[cfg(test)]
pub(crate) fn live_identity_for_test(
    platform: Platform,
    rust_object_id: &str,
) -> io::Result<Identity> {
    rustfmt_identity(platform, RUST_VERSION, Path::new(rust_object_id))
}

#[cfg(test)]
fn object_id_for(
    platform: Platform,
    rust_version: &str,
    rust_object_id: &str,
) -> io::Result<String> {
    rustfmt_identity(platform, rust_version, Path::new(rust_object_id))
        .map(|identity| identity.object_id())
}

/// The formatter binaries `tog fmt` runs.
const FORMATTER_BINARIES: [&str; 2] = ["rustfmt", "cargo-fmt"];

/// Ensure the rustfmt and cargo-fmt binaries paired with `rust_object` exist.
/// The component is a separate immutable object so the existing Rust object
/// and its identity remain unchanged. A local toolchain brings its own: the
/// imported tree must hold them, and is itself the formatter object.
pub fn ensure_rustfmt(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
    rust_object: &Path,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "rustfmt component")?;
    let expected_rust_id = cargo::runtime_object_id(platform, selected)?;
    let rust_object = rust_object.canonicalize()?;
    if rust_object != store.object_path(&expected_rust_id).canonicalize()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rustfmt was paired with an unexpected Rust object; run `tog` first",
        ));
    }
    if rust_path::is_path(selected) {
        for binary in FORMATTER_BINARIES {
            if !rust_object.join("bin").join(binary).is_file() {
                let tree = selected.artifact(platform, "rustc")?.url;
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "the local Rust toolchain {tree} has no bin/{binary}; add rustfmt to it \
                         (for a rustup toolchain, `rustup component add rustfmt`), then run \
                         `tog update --toolchain rust`"
                    ),
                ));
            }
        }
        return Ok(rust_object);
    }
    let row = rustfmt_row(platform, selected)?;
    let identity = identity_from(platform, &row.version, row.digest.hex(), &rust_object)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    if !store
        .cache_path(row.digest.algo(), row.digest.hex())
        .is_file()
    {
        crate::kernel::ui::note(&format!(
            "fetching rustfmt {} for {}",
            row.version,
            platform.triple()
        ));
    }
    let archive =
        download_toolchain_artifact_held(store, activity, &row.provider, &row.url, &row.digest)?;
    let staged = store.stage_with_activity(activity)?;
    if let Err(error) = stage_rustfmt(
        activity,
        &staged,
        platform,
        &row.version,
        archive.as_ref(),
        &rust_object,
    ) {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }

    let scratch = probe_scratch(&store.root.join("tmp"))?;
    // The staged object is under store/tmp, so its committed relative lib
    // link cannot resolve until publication beside the Rust object. The stage
    // carries an absolute link for this probe, so protected macOS binaries do
    // not need a DYLD_* or LD_* environment override.
    let probe = BuildSpec {
        argv: vec![
            staged.join("bin/rustfmt").display().to_string(),
            "--version".into(),
        ],
        cwd: scratch.clone(),
        env: vec![],
        read: vec![staged.clone(), rust_object.clone()],
        write: vec![],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", staged.join("bin").display()),
        host_view: crate::kernel::sandbox::HostView::Full,
    };
    let probe_result = crate::kernel::sandbox::run_build_spec_on(platform, &probe, Some(activity));
    let _ = crate::kernel::store::remove_tree(&scratch);
    if let Err(error) = probe_result {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(io::Error::new(
            error.kind(),
            format!("rustfmt probe failed before publication: {error}"),
        ));
    }

    // The probe used the absolute link above. Publish only the relocatable
    // sibling-relative form, and verify the exact link text before commit.
    let lib = staged.join("lib");
    fs::remove_file(&lib)?;
    let committed_link = rust_object_lib_link(&rust_object)?;
    std::os::unix::fs::symlink(&committed_link, &lib)?;
    let actual_link = fs::read_link(&lib)?;
    if actual_link.is_absolute() || actual_link != committed_link {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rustfmt publication link is not the expected relative Rust lib link",
        ));
    }

    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.object_id(
                rust_object
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Rust object has no id")
                    })?,
            )?;
            deps.cache_digest(row.digest.clone());
            deps
        })
        .map(|(path, _)| path)
        .map_err(|error| io::Error::new(error.kind(), format!("commit rustfmt object: {error}")))
}

/// The `store/tmp` scratch names for the pre-publication `rustfmt --version`
/// probe and for a sandboxed `cargo fmt` run. Both carry the `stage-` prefix
/// `gc::collect` sweeps, so a run killed before its cleanup leaks nothing
/// permanent.
const PROBE_SCRATCH_PREFIX: &str = "stage-rustfmt-probe";
const RUN_SCRATCH_PREFIX: &str = "stage-rustfmt-run";

/// The scratch directory the publication probe runs in. The probe goes
/// through here, so the gc sweep test covers the name it really uses.
fn probe_scratch(store_tmp: &Path) -> io::Result<PathBuf> {
    super::unique_dir(store_tmp, PROBE_SCRATCH_PREFIX)
}

/// The scratch directory one sandboxed `cargo fmt` runs in.
fn run_scratch(store_tmp: &Path) -> io::Result<PathBuf> {
    super::unique_dir(store_tmp, RUN_SCRATCH_PREFIX)
}

/// Sandboxed `cargo fmt`: the workspace `workspace` holds is the one
/// writable root, and cargo-fmt starts in the directory `invocation`
/// holds. Both are named by the canonical path they were opened at, which
/// the sandbox resolves through the held descriptors (#612), so a project
/// renamed or replaced since tog opened it is not what gets formatted.
/// Neither is canonicalized again: that would follow whatever sits at the
/// path now.
pub fn run_sandboxed(
    platform: Platform,
    invocation: &ProjectRoot,
    workspace: &ProjectRoot,
    rust_object: &Path,
    rustfmt_object: &Path,
    activity: &StoreActivity,
    check: bool,
    args: &[String],
) -> io::Result<std::process::ExitStatus> {
    let scratch = run_scratch(
        &rustfmt_object
            .parent()
            .and_then(Path::parent)
            .map(|path| path.join("tmp"))
            .ok_or_else(|| io::Error::other("cannot locate store tmp for rustfmt"))?,
    )?;
    let cargo = rust_object.join("bin/cargo");
    let cargo_fmt = rustfmt_object.join("bin/cargo-fmt");
    let mut argv = vec![cargo_fmt.display().to_string()];
    if check {
        argv.push("--check".into());
    }
    argv.extend(args.iter().cloned());
    let invocation_dir = invocation.path();
    let mut trace = Command::new(&argv[0]);
    trace.args(&argv[1..]).current_dir(invocation_dir);
    crate::kernel::ui::trace_command(&trace);
    let spec = BuildSpec {
        argv,
        cwd: invocation_dir.to_path_buf(),
        env: vec![
            ("CARGO".into(), cargo.display().to_string()),
            (
                "CARGO_HOME".into(),
                scratch.join("cargo-home").display().to_string(),
            ),
            (
                "RUSTC".into(),
                rust_object.join("bin/rustc").display().to_string(),
            ),
        ],
        read: vec![rust_object.to_path_buf(), rustfmt_object.to_path_buf()],
        write: vec![workspace.path().to_path_buf()],
        scratch: scratch.clone(),
        path: format!(
            "{}:{}:/usr/bin:/bin",
            rustfmt_object.join("bin").display(),
            rust_object.join("bin").display()
        ),
        host_view: crate::kernel::sandbox::HostView::Full,
    };
    let result = crate::kernel::sandbox::run_build_spec_status_on(platform, &spec, Some(activity));
    let _ = crate::kernel::store::remove_tree(&scratch);
    result
}

fn rust_object_lib_link(rust_object: &Path) -> io::Result<PathBuf> {
    let rust_object_id = rust_object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Rust object has no UTF-8 id"))?;
    Ok(PathBuf::from(format!("../{rust_object_id}/lib")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::collections::BTreeSet;

    /// The shipped rustfmt row of the fixture release.
    fn component(platform: Platform) -> io::Result<ArtifactSpec> {
        shipped_row(platform, RUST_VERSION)
    }

    #[test]
    fn pins_are_platform_specific_and_verified() {
        let darwin = component(Platform::Aarch64AppleDarwin).unwrap();
        assert_eq!(
            darwin.url,
            "https://static.rust-lang.org/dist/rustfmt-1.96.1-aarch64-apple-darwin.tar.xz"
        );
        assert_eq!(
            darwin.digest.hex(),
            "ed0cc9d72c04e7c3c4b7a82ab7f1ce5e33132017d062d8f9be6adf6472e8f165"
        );
        let linux = component(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(
            linux.url,
            "https://static.rust-lang.org/dist/rustfmt-1.96.1-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            linux.digest.hex(),
            "dcee5627f709f387cdca416a1d2ae9e6c2581cd117cdb4fd097c56c196384662"
        );
    }

    /// `tog fmt` calls this before opening the store, so an unpinned or
    /// foreign platform is refused ahead of the toolchain download.
    #[test]
    fn preflight_accepts_the_host_and_refuses_a_foreign_platform() {
        let host = Platform::host().unwrap();
        assert!(preflight_platform(host).is_ok());
        for platform in Platform::ALL.iter().copied().filter(|p| *p != host) {
            let error = preflight_platform(platform).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
        }
    }

    #[test]
    fn darwin_identity_unchanged_style_golden() {
        let id = object_id_for(
            Platform::Aarch64AppleDarwin,
            RUST_VERSION,
            "b8418440835c4ec1f591381a17ae60ab12d1c727-rust-1.96.1",
        )
        .unwrap();
        assert_eq!(
            id,
            "ce2ba748066606d57d165a0ef794abeb5af18dc9-rustfmt-1.96.1"
        );
    }

    /// A probe or `cargo fmt` run killed before its own cleanup leaves its
    /// scratch under `store/tmp`. `gc::collect` reclaims exactly
    /// `store/tmp/stage-*`, so both scratch names have to live there.
    #[test]
    fn leftover_rustfmt_scratches_are_swept_by_gc() {
        super::super::tests::with_temp_store(|store, root| {
            // Through the helpers the probe and the run use, so a prefix that
            // drifts out of the swept namespace fails here.
            let tmp = store.root.join("tmp");
            let scratches = [probe_scratch(&tmp).unwrap(), run_scratch(&tmp).unwrap()];
            // Only stages older than a day are stale; a live run's scratch is
            // never swept out from under it.
            let old = std::time::SystemTime::now()
                .checked_sub(std::time::Duration::from_secs(2 * 24 * 60 * 60))
                .unwrap();
            for scratch in &scratches {
                fs::write(scratch.join("leftover"), b"leftover").unwrap();
                fs::File::open(scratch).unwrap().set_modified(old).unwrap();
            }
            // A registered, resolvable root: the sweep refuses outright when
            // the root registry is empty or a project cannot be resolved.
            let project = root.join("project");
            fs::create_dir_all(project.join(".tog/closures")).unwrap();
            fs::write(
                project.join(".tog/closures/cargo.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schema": "closure/1",
                    "ecosystem": "cargo",
                    "body": {},
                }))
                .unwrap(),
            )
            .unwrap();
            crate::kernel::store::register_empty_root_for_test(store, &project).unwrap();
            let mut out = Vec::new();
            let report =
                crate::kernel::gc::collect(store, crate::kernel::gc::Options::default(), &mut out)
                    .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(report.stages, 2, "{text}");
            for scratch in &scratches {
                assert!(!scratch.exists(), "{}: {text}", scratch.display());
            }
        });
    }

    #[test]
    fn rustfmt_object_lib_link_is_relative_to_paired_rust_object() {
        let scratch = TempDir::named("rustfmt-link");
        let root = scratch.0.clone();
        let staged = root.join("staged");
        fs::create_dir_all(&staged).unwrap();
        let rust_id = "b8418440835c4ec1f591381a17ae60ab12d1c727-rust-1.96.1";
        let rust_object = Path::new("/store/objects").join(rust_id);
        std::os::unix::fs::symlink(
            rust_object_lib_link(&rust_object).unwrap(),
            staged.join("lib"),
        )
        .unwrap();

        let link = fs::read_link(staged.join("lib")).unwrap();
        assert!(!link.is_absolute());
        assert_eq!(link, PathBuf::from(format!("../{rust_id}/lib")));
    }

    /// `tog fmt` writes no closure and registers no root: the pinned
    /// formatter is guaranteed by the lock, not by a record. A
    /// `.tog/closures/rustfmt.json` left by an older tog is deleted on the
    /// run, so the workspace heals itself; `--check` leaves it, since a
    /// check changes no file. Both objects are cache hits with
    /// stub `cargo` and `cargo-fmt` scripts, so nothing is downloaded.
    #[test]
    fn fmt_publishes_nothing_and_removes_a_legacy_record_unless_checking() {
        use crate::tailors::Formatter;
        use std::os::unix::fs::PermissionsExt;
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let scratch = TempDir::named("rustfmt-no-record");
        let root = scratch.0.clone();
        let previous_store = std::env::var_os("TOG_STORE");
        std::env::set_var("TOG_STORE", root.join("store"));
        let platform = Platform::host().unwrap();
        let ctx = crate::kernel::context::Context::open(platform);
        match previous_store {
            Some(value) => std::env::set_var("TOG_STORE", value),
            None => std::env::remove_var("TOG_STORE"),
        }
        let ctx = ctx.unwrap();
        let store = ctx.store.clone();

        let selected =
            crate::kernel::toolchain::shipped(&cargo::toolchain_catalog().unwrap()).unwrap();
        let rust_identity = crate::kernel::provider::rust::identity_of(
            platform,
            &crate::kernel::provider::rust::runtime_rows(platform, &selected).unwrap(),
        );
        let rust_id = rust_identity.object_id();
        assert_eq!(
            rust_id,
            cargo::runtime_object_id(platform, &selected).unwrap()
        );
        let row = rustfmt_row(platform, &selected).unwrap();
        let rustfmt_identity = identity_from(
            platform,
            &row.version,
            row.digest.hex(),
            &store.object_path(&rust_id),
        )
        .unwrap();
        // tog finds the workspace itself; `cargo-fmt` formats nothing and
        // succeeds.
        for (identity, script, body) in [
            (&rust_identity, "cargo", "#!/bin/sh\nexit 1\n"),
            (&rustfmt_identity, "cargo-fmt", "#!/bin/sh\nexit 0\n"),
        ] {
            store.publish_bare_with(identity, |object| {
                fs::create_dir_all(object.join("bin")).unwrap();
                let bin = object.join("bin").join(script);
                fs::write(&bin, body).unwrap();
                fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).unwrap();
            });
        }
        let project = root.join("project");
        fs::create_dir_all(project.join(".tog/closures")).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let legacy = project.join(".tog/closures/rustfmt.json");
        fs::write(
            &legacy,
            br#"{"schema":"closure/1","ecosystem":"rustfmt","body":{}}"#,
        )
        .unwrap();
        fs::write(
            project.join(".tog/closures/cargo.json"),
            br#"{"schema":"closure/1","ecosystem":"cargo","body":{}}"#,
        )
        .unwrap();

        // The legacy record is removed before the formatter runs, so this
        // holds whatever the sandboxed stub run returns on this host.
        let _ = cargo::tailor::Rustfmt.run(&ctx, &project, true, &[], &selected);
        assert!(legacy.is_file(), "fmt --check changed the checkout");
        let _ = cargo::tailor::Rustfmt.run(&ctx, &project, false, &[], &selected);
        assert!(
            !legacy.exists(),
            "the legacy rustfmt record was left behind"
        );
        assert!(
            project.join(".tog/closures").is_dir(),
            "only the record goes, not the closures directory"
        );
        assert!(store.roots().unwrap().is_empty(), "fmt registered a root");
    }

    /// cargo-fmt runs in the workspace and the invocation directory tog
    /// holds: with the project renamed and another directory put at its
    /// path after both were opened, a stub cargo-fmt still writes into the
    /// held member directory, and nothing appears at the old path (#612).
    #[test]
    fn fmt_runs_in_the_held_workspace_after_a_rename() {
        use std::os::unix::fs::PermissionsExt;
        if !crate::kernel::sandbox::linux_ready("fmt_runs_in_the_held_workspace_after_a_rename") {
            return;
        }
        let temp = TempDir::named("rustfmt-held");
        let store = temp.0.join("store");
        fs::create_dir_all(store.join("tmp")).unwrap();
        let rust_object = store.join("objects/rust");
        let rustfmt_object = store.join("objects/rustfmt");
        for (object, script, body) in [
            (&rust_object, "cargo", "#!/bin/sh\nexit 1\n"),
            (
                &rustfmt_object,
                "cargo-fmt",
                "#!/bin/sh\necho \"formatted $*\" > formatted\n",
            ),
        ] {
            fs::create_dir_all(object.join("bin")).unwrap();
            let bin = object.join("bin").join(script);
            fs::write(&bin, body).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).unwrap();
        }
        let project = temp.0.join("project");
        fs::create_dir_all(project.join("member")).unwrap();
        let invocation = ProjectRoot::open(&project.join("member")).unwrap();
        let workspace = ProjectRoot::open(&project).unwrap();
        let moved = temp.0.join("moved");
        fs::rename(&project, &moved).unwrap();
        fs::create_dir_all(project.join("member")).unwrap();
        let (_lease, activity) = crate::kernel::testutil::detached_lease();
        let status = run_sandboxed(
            Platform::host().unwrap(),
            &invocation,
            &workspace,
            &rust_object,
            &rustfmt_object,
            &activity,
            true,
            &[],
        )
        .unwrap();
        assert!(status.success(), "{status}");
        assert_eq!(
            fs::read_to_string(moved.join("member/formatted")).unwrap(),
            "formatted --check\n"
        );
        assert!(project.join("member/formatted").symlink_metadata().is_err());
    }

    /// The legacy record is removed through the held project when another
    /// closure stays beside it: an absent one is fine, and a symlink in its
    /// place is refused rather than followed.
    #[test]
    fn removing_the_legacy_record_keeps_a_lone_one_and_refuses_a_symlink() {
        let temp = TempDir::named("rustfmt-legacy-remove");
        let project = temp.0.join("project");
        fs::create_dir_all(project.join(".tog/closures")).unwrap();
        let held = crate::kernel::fsroot::ProjectRoot::open(&project).unwrap();
        remove_legacy_record(&held, true).unwrap();
        let legacy = project.join(".tog/closures/rustfmt.json");
        fs::write(&legacy, b"{}").unwrap();
        // The only closure stays: removing it would leave the old root
        // record over an empty closures directory.
        remove_legacy_record(&held, true).unwrap();
        assert!(legacy.is_file());
        fs::write(project.join(".tog/closures/cargo.json"), b"{}").unwrap();
        remove_legacy_record(&held, true).unwrap();
        assert!(!legacy.exists());
        assert!(project.join(".tog/closures/cargo.json").is_file());
        let outside = temp.0.join("outside.json");
        fs::write(&outside, b"{}").unwrap();
        std::os::unix::fs::symlink(&outside, &legacy).unwrap();
        assert!(remove_legacy_record(&held, true).is_err());
        assert!(outside.is_file());
    }

    /// A directory or symlink under a closure name is no closure (gc skips
    /// it), so the legacy record beside one is still the only closure and
    /// stays, and the project's root keeps sweeping.
    #[test]
    fn a_sibling_that_is_not_a_regular_file_keeps_the_legacy_record() {
        super::super::tests::with_temp_store(|store, root| {
            let project = root.join("project");
            let closures = project.join(".tog/closures");
            fs::create_dir_all(&closures).unwrap();
            let legacy = closures.join("rustfmt.json");
            fs::write(
                &legacy,
                br#"{"schema":"closure/1","ecosystem":"rustfmt","body":{}}"#,
            )
            .unwrap();
            crate::kernel::store::register_empty_root_for_test(store, &project).unwrap();
            let held = crate::kernel::fsroot::ProjectRoot::open(&project).unwrap();
            fs::create_dir(closures.join("cargo.json")).unwrap();
            remove_legacy_record(&held, true).unwrap();
            assert!(legacy.is_file(), "a directory sibling counted as a closure");
            fs::remove_dir(closures.join("cargo.json")).unwrap();
            let outside = root.join("outside.json");
            fs::write(&outside, b"{}").unwrap();
            std::os::unix::fs::symlink(&outside, closures.join("cargo.json")).unwrap();
            remove_legacy_record(&held, true).unwrap();
            assert!(legacy.is_file(), "a symlink sibling counted as a closure");
            let mut out = Vec::new();
            crate::kernel::gc::collect(store, crate::kernel::gc::Options::default(), &mut out)
                .unwrap();
        });
    }

    /// A project an older `tog fmt` registered and never synced holds only
    /// the legacy record (#416). fmt keeps it while the root is registered,
    /// since an empty closures directory would stop the sweep. The sweep
    /// forgets a root whose only closures are retired (a dry run only says
    /// so), and the next fmt run then removes the file.
    #[test]
    fn a_lone_legacy_record_is_forgotten_by_gc_then_removed_by_fmt() {
        super::super::tests::with_temp_store(|store, root| {
            let project = root.join("project");
            fs::create_dir_all(project.join(".tog/closures")).unwrap();
            let legacy = project.join(".tog/closures/rustfmt.json");
            fs::write(
                &legacy,
                br#"{"schema":"closure/1","ecosystem":"rustfmt","body":{}}"#,
            )
            .unwrap();
            let entry =
                crate::kernel::store::register_empty_root_for_test(store, &project).unwrap();
            let key =
                crate::kernel::store::Store::canonical_root_key(&project.canonicalize().unwrap());
            assert_eq!(entry.key, key);
            let held = crate::kernel::fsroot::ProjectRoot::open(&project).unwrap();
            remove_legacy_record(&held, store.has_root_entry(&key).unwrap()).unwrap();
            assert!(legacy.is_file());

            let mut out = Vec::new();
            let dry = crate::kernel::gc::Options {
                dry_run: true,
                ..crate::kernel::gc::Options::default()
            };
            crate::kernel::gc::collect(store, dry, &mut out).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(
                text.contains(&format!("would forget root {key} (")),
                "{text}"
            );
            assert!(store.has_root_entry(&key).unwrap(), "a dry run forgot");

            let mut out = Vec::new();
            crate::kernel::gc::collect(store, crate::kernel::gc::Options::default(), &mut out)
                .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(
                text.contains(&format!(
                    "forgot root {key} ({}): its only closures are retired records \
                     (rustfmt.json)",
                    project.canonicalize().unwrap().display()
                )),
                "{text}"
            );
            assert!(!store.has_root_entry(&key).unwrap());

            remove_legacy_record(&held, store.has_root_entry(&key).unwrap()).unwrap();
            assert!(!legacy.exists());
            let mut out = Vec::new();
            crate::kernel::gc::collect(store, crate::kernel::gc::Options::default(), &mut out)
                .unwrap();
        });
    }

    /// `gc --register` on a project whose only closure is the retired
    /// record says why it found nothing, and what writes a current one.
    #[test]
    fn registering_a_project_with_only_a_retired_record_names_it() {
        super::super::tests::with_temp_store(|store, root| {
            let project = root.join("project");
            fs::create_dir_all(project.join(".tog/closures")).unwrap();
            fs::write(project.join(".tog/closures/rustfmt.json"), b"{}").unwrap();
            let error = store.root_record_from_project(&project).unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains(
                    "contains no supported closure records: rustfmt.json is a retired record"
                ) && message.contains("run `tog sync` in the project"),
                "{message}"
            );
        });
    }

    /// The validated extractor unpacks the whole component into a scratch
    /// directory and carries only the two binaries into the object: the
    /// object holds `bin/` and the `lib` link, the scratch tree is gone, and
    /// the executable bit survives the copy.
    #[test]
    fn staging_keeps_only_the_two_binaries_with_their_modes() {
        use std::os::unix::fs::PermissionsExt;
        // Staging extracts through a supervised child, and the supervisor
        // owns process-wide signal dispositions: one supervised child at a
        // time, as in every other test that can reach one.
        let platform = Platform::host().unwrap();
        let version = "1.0.0";
        let root = format!("rustfmt-{version}-{}", platform.triple());
        let temp = crate::kernel::testutil::TempDir::named("rustfmt-stage");
        let tree = temp.0.join("tree");
        let bin = tree.join(&root).join("rustfmt-preview/bin");
        fs::create_dir_all(&bin).unwrap();
        for name in ["rustfmt", "cargo-fmt"] {
            fs::write(bin.join(name), format!("#!{name}\n")).unwrap();
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(tree.join(&root).join("version"), "1.0.0\n").unwrap();
        let archive = temp.0.join("rustfmt.tar.xz");
        let status = Command::new("/usr/bin/tar")
            .arg("-cJf")
            .arg(&archive)
            .arg("--no-recursion")
            .arg("-C")
            .arg(&tree)
            // Files only: GNU tar would store directories as `name/`, which
            // the real dist archives (and so the allow-list) never do.
            .args(
                [
                    "version",
                    "rustfmt-preview/bin/rustfmt",
                    "rustfmt-preview/bin/cargo-fmt",
                ]
                .map(|entry| format!("{root}/{entry}")),
            )
            .status()
            .unwrap();
        assert!(status.success());
        let staged = temp.0.join("staged");
        fs::create_dir(&staged).unwrap();
        let rust_object = temp.0.join(format!("{}-rust", "b".repeat(40)));
        fs::create_dir_all(rust_object.join("lib")).unwrap();
        let (_store, activity) = crate::kernel::testutil::detached_lease();
        stage_rustfmt(
            &activity,
            &staged,
            platform,
            version,
            &archive,
            &rust_object,
        )
        .unwrap();
        let top: BTreeSet<String> = fs::read_dir(&staged)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(top, BTreeSet::from(["bin".into(), "lib".into()]));
        for name in ["rustfmt", "cargo-fmt"] {
            let path = staged.join("bin").join(name);
            assert_eq!(fs::read_to_string(&path).unwrap(), format!("#!{name}\n"));
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "{name} lost its executable bit");
        }
    }
}

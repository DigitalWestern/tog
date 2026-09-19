//! The pinned Rust formatting component used by `blanket fmt`.

use crate::comforter::status::State;
use crate::kernel::fetch::{download_verified_held, Digest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
use crate::tailors::cargo;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) const RUSTFMT_VERSION: &str = "1.96.1";

pub(super) struct RustfmtComponent {
    pub(super) platform: Platform,
    pub(super) url: &'static str,
    pub(super) sha256: &'static str,
}

pub(super) const RUSTFMT_COMPONENTS: &[RustfmtComponent] = &[
    RustfmtComponent {
        platform: Platform::Aarch64AppleDarwin,
        url: "https://static.rust-lang.org/dist/rustfmt-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "ed0cc9d72c04e7c3c4b7a82ab7f1ce5e33132017d062d8f9be6adf6472e8f165",
    },
    RustfmtComponent {
        platform: Platform::X86_64UnknownLinuxGnu,
        url: "https://static.rust-lang.org/dist/rustfmt-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
        sha256: "dcee5627f709f387cdca416a1d2ae9e6c2581cd117cdb4fd097c56c196384662",
    },
];

fn component(platform: Platform) -> io::Result<&'static RustfmtComponent> {
    RUSTFMT_COMPONENTS
        .iter()
        .find(|component| component.platform == platform)
        .ok_or_else(|| no_pin("rustfmt component", platform))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "rustfmt component")?;
    component(platform).map(|_| ())
}

fn rustfmt_identity(
    platform: Platform,
    rust_version: &str,
    rust_object: &Path,
) -> io::Result<Identity> {
    if rust_version != RUSTFMT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "internal: resolved Rust {rust_version} but rustfmt {RUSTFMT_VERSION} is the only pinned component"
            ),
        ));
    }
    let rust_object = rust_object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Rust object has no UTF-8 id"))?;
    let pin = component(platform)?;
    Ok(Identity {
        kind: "rustfmt".into(),
        name: "rustfmt".into(),
        version: RUSTFMT_VERSION.into(),
        inputs: BTreeMap::from([
            ("platform".into(), platform.triple().into()),
            ("rust_object".into(), rust_object.into()),
            ("rustfmt_sha256".into(), pin.sha256.into()),
            ("schema".into(), "rustfmt/1".into()),
        ]),
    })
}

/// The `inputs` a `rustfmt` closure records. `rustfmt_object` is the id of
/// the rustfmt object the run formatted with: it hashes the rustfmt version,
/// the pinned component sha256, the platform, and the paired Rust object,
/// and ends in the version. `resolved_from` is the directory the toolchain
/// file was looked up from, relative to the workspace root the closure is
/// written in, and `unavailable_components` is what that file asked for that
/// blanket does not provide (the run's `toolchain-component-unavailable`
/// exception, when non-empty).
pub fn record_inputs(rustfmt_object: &str, resolved_from: &str, unavailable: &[String]) -> Value {
    json!({
        "rustfmt_object": rustfmt_object,
        "resolved_from": resolved_from,
        "unavailable_components": unavailable,
    })
}

/// The fields of a `rustfmt` closure that say which rustfmt made it, as
/// this binary would write them for a run in `root.join(resolved_from)` now.
/// Computed from the pins alone: no store, no network, no policy record.
pub fn pinned_record(platform: Platform, root: &Path, resolved_from: &str) -> io::Result<Value> {
    let choice = cargo::resolve_toolchain_quiet(platform, &root.join(resolved_from))?;
    let rust_object = cargo::rust_object_id(platform, choice.version)?;
    let rustfmt_object =
        rustfmt_identity(platform, choice.version, Path::new(&rust_object))?.object_id();
    Ok(json!({
        "rust_version": choice.version,
        "rust_object": { "id": rust_object },
        "rustfmt_object": { "id": rustfmt_object },
        "inputs": record_inputs(&rustfmt_object, resolved_from, &choice.unavailable),
    }))
}

/// Whether a `rustfmt` closure in `dir` was made by the rustfmt this binary
/// would use for the same run now. A record without inputs predates them and
/// is unchecked. A record has changed when any field `pinned_record` writes
/// disagrees, when the directory it was resolved from is not a plain
/// subdirectory of `dir`, or when this binary pins no rustfmt for it.
pub fn closure_state(platform: Platform, dir: &Path, body: &Value) -> io::Result<State> {
    if body.get("inputs").is_none() {
        return Ok(State::Unchecked(
            "rustfmt inputs were not recorded by this run; run 'blanket fmt' once to record them"
                .into(),
        ));
    }
    let field = |value: &Value, pointer: &str| value.pointer(pointer).cloned().unwrap_or_default();
    // `fmt` records the canonical invocation directory relative to the
    // canonical workspace root, so only that exact spelling of a directory
    // inside `dir` (no symlink out, no `..`, no extra separators) is accepted.
    let resolved_from = body["inputs"]["resolved_from"].as_str();
    let resolved_from = resolved_from.filter(|recorded| {
        let (Ok(root), Ok(target)) = (dir.canonicalize(), dir.join(recorded).canonicalize()) else {
            return false;
        };
        target.is_dir()
            && target
                .strip_prefix(&root)
                .ok()
                .and_then(Path::to_str)
                .is_some_and(|relative| relative == *recorded)
    });
    let Some(resolved_from) = resolved_from else {
        return Ok(State::Changed(vec![format!(
            "rustfmt record /inputs/resolved_from ({} is not a directory of this workspace)",
            field(body, "/inputs/resolved_from")
        )]));
    };
    let pinned = match pinned_record(platform, dir, resolved_from) {
        Ok(pinned) => pinned,
        Err(error) => {
            return Ok(State::Changed(vec![format!(
                "rustfmt pin (recorded {}, but this blanket pins none here: {error})",
                field(body, "/inputs/rustfmt_object")
            )]))
        }
    };
    let changed: Vec<String> = [
        "/inputs",
        "/rustfmt_object/id",
        "/rust_object/id",
        "/rust_version",
    ]
    .into_iter()
    .filter(|pointer| field(body, pointer) != field(&pinned, pointer))
    .map(|pointer| {
        format!(
            "rustfmt record {pointer} (recorded {}, this blanket uses {})",
            field(body, pointer),
            field(&pinned, pointer)
        )
    })
    .collect();
    Ok(if changed.is_empty() {
        State::Synced
    } else {
        State::Changed(changed)
    })
}

#[cfg(test)]
pub(crate) fn live_identity_for_test(
    platform: Platform,
    rust_object_id: &str,
) -> io::Result<Identity> {
    rustfmt_identity(platform, RUSTFMT_VERSION, Path::new(rust_object_id))
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

/// Ensure the rustfmt and cargo-fmt binaries paired with `rust_object` exist.
/// The component is a separate immutable object so the existing Rust object
/// and its identity remain unchanged.
pub fn ensure_rustfmt(
    store: &Store,
    platform: Platform,
    rust_version: &str,
    rust_object: &Path,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "rustfmt component")?;
    let expected_rust_id = cargo::rust_object_id(platform, rust_version)?;
    let rust_object = rust_object.canonicalize()?;
    if rust_object != store.object_path(&expected_rust_id).canonicalize()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rustfmt was paired with an unexpected Rust object; run `blanket sync` first",
        ));
    }
    let pin = component(platform)?;
    let identity = rustfmt_identity(platform, rust_version, &rust_object)?;
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    if !store.cache_path("sha256", pin.sha256).is_file() {
        crate::kernel::ui::note(&format!(
            "fetching rustfmt {rust_version} for {}",
            platform.triple()
        ));
    }
    let archive = download_verified_held(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    if let Err(error) = stage_rustfmt(store, &staged, platform, archive.as_ref(), &rust_object) {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }

    let scratch = unique_dir(&store.root.join("tmp"), "stage-rustfmt-probe")?;
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
    };
    let probe_result = crate::kernel::sandbox::run_build_spec_on_for_store(platform, &probe, store);
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
        .commit_with_deps(&identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.object_id(
                rust_object
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Rust object has no id")
                    })?,
            )?;
            deps.cache_digest(Digest::sha256(pin.sha256)?);
            deps
        })
        .map(|(path, _)| path)
        .map_err(|error| io::Error::new(error.kind(), format!("commit rustfmt object: {error}")))
}

pub fn run_sandboxed(
    platform: Platform,
    invocation_dir: &Path,
    workspace_root: &Path,
    rust_object: &Path,
    rustfmt_object: &Path,
    store: &Store,
    check: bool,
    args: &[String],
) -> io::Result<std::process::ExitStatus> {
    let scratch = unique_dir(
        &rustfmt_object
            .parent()
            .and_then(Path::parent)
            .map(|path| path.join("tmp"))
            .ok_or_else(|| io::Error::other("cannot locate store tmp for rustfmt"))?,
        "stage-rustfmt-run",
    )?;
    let cargo = rust_object.join("bin/cargo");
    let cargo_fmt = rustfmt_object.join("bin/cargo-fmt");
    let mut argv = vec![cargo_fmt.display().to_string()];
    if check {
        argv.push("--check".into());
    }
    argv.extend(args.iter().cloned());
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
        write: vec![workspace_root.to_path_buf()],
        scratch: scratch.clone(),
        path: format!(
            "{}:{}:/usr/bin:/bin",
            rustfmt_object.join("bin").display(),
            rust_object.join("bin").display()
        ),
    };
    let result = crate::kernel::sandbox::run_build_spec_status_on_for_store(platform, &spec, store);
    let _ = crate::kernel::store::remove_tree(&scratch);
    result
}

fn stage_rustfmt(
    store: &Store,
    staged: &Path,
    platform: Platform,
    archive: &Path,
    rust_object: &Path,
) -> io::Result<()> {
    let root = format!("rustfmt-{RUSTFMT_VERSION}-{}", platform.triple());
    let entries = archive_entries(store, archive)?;
    let allowed: BTreeSet<String> = allowed_entries(&root).into_iter().collect();
    for entry in entries {
        if !allowed.contains(&entry) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("rustfmt archive contains unexpected entry {entry:?}"),
            ));
        }
    }
    let cargo_fmt = format!("{root}/rustfmt-preview/bin/cargo-fmt");
    let rustfmt = format!("{root}/rustfmt-preview/bin/rustfmt");
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xJf"])
        .arg(archive)
        .args(["-C"])
        .arg(staged)
        .args(["--strip-components", "2"])
        .arg(&cargo_fmt)
        .arg(&rustfmt);
    let status = crate::kernel::supervise::status_owned(&mut command, store)
        .map_err(|error| io::Error::new(error.kind(), format!("spawn tar for rustfmt: {error}")))?;
    if !status.success() {
        return Err(io::Error::other("rustfmt archive extraction failed"));
    }
    let bin = staged.join("bin");
    if !bin.join("rustfmt").is_file() || !bin.join("cargo-fmt").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rustfmt archive extraction has an unexpected layout; refusing to commit",
        ));
    }
    let actual: BTreeSet<String> = fs::read_dir(&bin)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    if actual != BTreeSet::from(["cargo-fmt".into(), "rustfmt".into()]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rustfmt archive extraction created unexpected bin entries",
        ));
    }
    for name in ["rustfmt", "cargo-fmt"] {
        if fs::symlink_metadata(bin.join(name))?
            .file_type()
            .is_symlink()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("rustfmt archive entry {name} is not a regular file"),
            ));
        }
    }
    std::os::unix::fs::symlink(rust_object.join("lib"), staged.join("lib"))?;
    Ok(())
}

fn rust_object_lib_link(rust_object: &Path) -> io::Result<PathBuf> {
    let rust_object_id = rust_object
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Rust object has no UTF-8 id"))?;
    Ok(PathBuf::from(format!("../{rust_object_id}/lib")))
}

fn archive_entries(store: &Store, archive: &Path) -> io::Result<Vec<String>> {
    let mut command = Command::new("/usr/bin/tar");
    command.args(["-tJf"]).arg(archive);
    let output = crate::kernel::supervise::output_owned(&mut command, store)
        .map_err(|error| io::Error::new(error.kind(), format!("list rustfmt archive: {error}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "list rustfmt archive failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

fn allowed_entries(root: &str) -> Vec<String> {
    [
        "rustfmt-preview",
        "rustfmt-preview/bin",
        "rustfmt-preview/bin/cargo-fmt",
        "rustfmt-preview/bin/rustfmt",
        "rustfmt-preview/share",
        "rustfmt-preview/share/doc",
        "rustfmt-preview/share/doc/rustfmt",
        "rustfmt-preview/share/doc/rustfmt/LICENSE-APACHE",
        "rustfmt-preview/share/doc/rustfmt/LICENSE-MIT",
        "rustfmt-preview/share/doc/rustfmt/README.md",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "README.md",
        "builder-config",
        "install.sh",
        "git-commit-hash",
        "rustfmt-preview/manifest.in",
        "rust-installer-version",
        "version",
        "git-commit-info",
        "components",
    ]
    .into_iter()
    .map(|entry| format!("{root}/{entry}"))
    .chain(std::iter::once(root.to_string()))
    .collect()
}

/// A scratch directory under `store/tmp`. The name is a `stage-` prefix on
/// purpose: `gc::sweep_stages` only reclaims `store/tmp/stage-*`, so a run
/// killed by a signal before its `remove_tree` still gets collected. Sweeping
/// only touches stages older than a day, so a live run's scratch (created
/// moments ago, and written to throughout) is never swept out from under it.
fn unique_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(parent)?;
    for attempt in 0..100 {
        let path = parent.join(format!(
            "{prefix}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            attempt
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other(format!(
        "could not create a {prefix} scratch directory under {}",
        parent.display()
    )))
}

#[cfg(test)]
mod tests {

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_paired_rust_object_and_component() {
        for platform in Platform::ALL {
            let pin = component(*platform).unwrap();
            let rust_object = format!("{}-rust-{RUSTFMT_VERSION}", "b".repeat(40));
            let identity =
                rustfmt_identity(*platform, RUSTFMT_VERSION, Path::new(&rust_object)).unwrap();
            let stub = crate::kernel::objmeta::legacy_record(crate::kernel::types::Identity {
                kind: "rust".into(),
                name: "rust".into(),
                version: RUSTFMT_VERSION.into(),
                inputs: std::collections::BTreeMap::new(),
            });
            let mut stub = stub;
            stub.id = rust_object.clone();
            match crate::kernel::objmeta::adapt_identity_for_test(identity, vec![stub]) {
                crate::kernel::objmeta::Adaptation::Proven(deps) => {
                    assert_eq!(
                        deps.objects.iter().cloned().collect::<Vec<_>>(),
                        vec![rust_object]
                    );
                    assert_eq!(
                        deps.cache
                            .iter()
                            .map(|d| format!("{}:{}", d.algo(), d.hex()))
                            .collect::<Vec<_>>(),
                        vec![format!("sha256:{}", pin.sha256)]
                    );
                }
                crate::kernel::objmeta::Adaptation::Unresolved(reason) => panic!("{reason}"),
            }
        }
    }
    use super::*;

    #[test]
    fn pins_are_platform_specific_and_verified() {
        let darwin = component(Platform::Aarch64AppleDarwin).unwrap();
        assert_eq!(
            darwin.url,
            "https://static.rust-lang.org/dist/rustfmt-1.96.1-aarch64-apple-darwin.tar.xz"
        );
        assert_eq!(
            darwin.sha256,
            "ed0cc9d72c04e7c3c4b7a82ab7f1ce5e33132017d062d8f9be6adf6472e8f165"
        );
        let linux = component(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(
            linux.url,
            "https://static.rust-lang.org/dist/rustfmt-1.96.1-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            linux.sha256,
            "dcee5627f709f387cdca416a1d2ae9e6c2581cd117cdb4fd097c56c196384662"
        );
    }

    /// `run_fmt` calls this before opening the store, so an unpinned or
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
            RUSTFMT_VERSION,
            "b8418440835c4ec1f591381a17ae60ab12d1c727-rust-1.96.1",
        )
        .unwrap();
        assert_eq!(
            id,
            "ce2ba748066606d57d165a0ef794abeb5af18dc9-rustfmt-1.96.1"
        );
    }

    #[test]
    fn scratch_directories_are_named_so_gc_can_sweep_them() {
        let parent = std::env::temp_dir().join(format!(
            "blanket-rustfmt-scratch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for prefix in ["stage-rustfmt-run", "stage-rustfmt-probe"] {
            let dir = unique_dir(&parent, prefix).unwrap();
            let name = dir.file_name().unwrap().to_str().unwrap().to_string();
            // `gc::sweep_stages` reclaims exactly `store/tmp/stage-*`, so a
            // run interrupted before its cleanup is still collectable.
            assert!(name.starts_with("stage-"), "{name}");
            assert!(name.starts_with(prefix), "{name}");
        }
        let _ = crate::kernel::store::remove_tree(&parent);
    }

    #[test]
    fn rustfmt_object_lib_link_is_relative_to_paired_rust_object() {
        let root = std::env::temp_dir().join(format!(
            "blanket-rustfmt-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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

        let _ = crate::kernel::store::remove_tree(&root);
    }
}

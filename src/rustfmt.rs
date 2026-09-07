//! The pinned Rust formatting component used by `blanket fmt`.

use crate::cargo;
use crate::fetch::download_verified_held;
use crate::platform::{no_pin, Platform};
use crate::sandbox::BuildSpec;
use crate::store::Store;
use crate::types::Identity;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const RUSTFMT_VERSION: &str = "1.96.1";

struct RustfmtComponent {
    platform: Platform,
    url: &'static str,
    sha256: &'static str,
}

const RUSTFMT_COMPONENTS: &[RustfmtComponent] = &[
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
        .ok_or_else(|| no_pin("rustfmt component", platform, "stage 4"))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::platform::require_host(platform, "rustfmt component", "stage 4")?;
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
    crate::platform::require_host(platform, "rustfmt component", "stage 4")?;
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
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    if !store.cache_path("sha256", pin.sha256).is_file() {
        crate::ui::note(&format!(
            "fetching rustfmt {rust_version} for {}",
            platform.triple()
        ));
    }
    let archive = download_verified_held(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    if let Err(error) = stage_rustfmt(&staged, platform, archive.as_ref(), &rust_object) {
        let _ = crate::store::remove_tree(&staged);
        return Err(error);
    }

    let scratch = unique_dir(&store.root.join("tmp"), "rustfmt-probe")?;
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
    let probe_result = crate::sandbox::run_build_spec_on(platform, &probe);
    let _ = crate::store::remove_tree(&scratch);
    probe_result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("rustfmt probe failed before publication: {error}"),
        )
    })?;

    // The probe used the absolute link above. Publish only the relocatable
    // sibling-relative form, and verify the exact link text before commit.
    let lib = staged.join("lib");
    fs::remove_file(&lib)?;
    let committed_link = rust_object_lib_link(&rust_object)?;
    std::os::unix::fs::symlink(&committed_link, &lib)?;
    let actual_link = fs::read_link(&lib)?;
    if actual_link.is_absolute() || actual_link != committed_link {
        let _ = crate::store::remove_tree(&staged);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rustfmt publication link is not the expected relative Rust lib link",
        ));
    }

    store
        .commit(&identity, &staged, &[])
        .map(|(path, _)| path)
        .map_err(|error| io::Error::new(error.kind(), format!("commit rustfmt object: {error}")))
}

pub fn run_sandboxed(
    platform: Platform,
    invocation_dir: &Path,
    workspace_root: &Path,
    rust_object: &Path,
    rustfmt_object: &Path,
    check: bool,
    args: &[String],
) -> io::Result<std::process::ExitStatus> {
    let scratch = unique_dir(
        &rustfmt_object
            .parent()
            .and_then(Path::parent)
            .map(|path| path.join("tmp"))
            .ok_or_else(|| io::Error::other("cannot locate store tmp for rustfmt"))?,
        "rustfmt-run",
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
    crate::ui::trace_command(&trace);
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
    let result = crate::sandbox::run_build_spec_status_on(platform, &spec);
    let _ = crate::store::remove_tree(&scratch);
    result
}

fn stage_rustfmt(
    staged: &Path,
    platform: Platform,
    archive: &Path,
    rust_object: &Path,
) -> io::Result<()> {
    let root = format!("rustfmt-{RUSTFMT_VERSION}-{}", platform.triple());
    let entries = archive_entries(archive)?;
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
    let status = Command::new("/usr/bin/tar")
        .args(["-xJf"])
        .arg(archive)
        .args(["-C"])
        .arg(staged)
        .args(["--strip-components", "2"])
        .arg(&cargo_fmt)
        .arg(&rustfmt)
        .status()
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

fn archive_entries(archive: &Path) -> io::Result<Vec<String>> {
    let output = Command::new("/usr/bin/tar")
        .args(["-tJf"])
        .arg(archive)
        .output()
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

fn unique_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(parent)?;
    for attempt in 0..100 {
        let path = parent.join(format!(
            ".{prefix}.{}.{}.{}",
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
    Err(io::Error::other(
        "could not create rustfmt probe scratch directory",
    ))
}

#[cfg(test)]
mod tests {
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

        let _ = crate::store::remove_tree(&root);
    }
}

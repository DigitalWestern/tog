//! Cargo's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.

use super::*;
use std::collections::BTreeSet;

pub(super) fn stage_rustfmt(
    activity: &StoreActivity,
    staged: &Path,
    platform: Platform,
    version: &str,
    archive: &Path,
    rust_object: &Path,
) -> io::Result<()> {
    // The archive's single root directory is named after the component the
    // selection asked for, so the version comes from its row, not the pin.
    let root = format!("rustfmt-{version}-{}", platform.triple());
    let listed = crate::kernel::archive::list_with_activity(
        activity,
        archive,
        crate::kernel::archive::Compression::Xz,
    )
    .map_err(|error| io::Error::new(error.kind(), format!("list rustfmt archive: {error}")))?;
    let allowed: BTreeSet<String> = allowed_entries(&root).into_iter().collect();
    for entry in &listed {
        if !allowed.contains(&entry.name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("rustfmt archive contains unexpected entry {:?}", entry.name),
            ));
        }
    }
    // The validated extractor writes whole archives, not named members, so
    // the full component tree lands in a scratch directory and only the two
    // binaries are carried into the object, modes included: tar restores the
    // archived modes, and the object's identity covers the executable bit.
    // The scratch directory sits inside `staged`, so it must be gone before
    // commit: a failed cleanup is an error, never a stray tree in the object.
    let full = staged.join(".tog-rustfmt-full");
    let extracted = (|| -> io::Result<()> {
        fs::create_dir_all(&full)?;
        crate::kernel::archive::extract_validated_with_activity_and_options(
            activity,
            archive,
            &full,
            &crate::kernel::archive::ExtractOptions::platform_build(2),
            crate::kernel::archive::Compression::Xz,
            &listed,
        )
        .map_err(|error| {
            io::Error::new(error.kind(), format!("extract rustfmt archive: {error}"))
        })?;
        let bin = staged.join("bin");
        fs::create_dir_all(&bin)?;
        for name in ["rustfmt", "cargo-fmt"] {
            let source = full.join("bin").join(name);
            if fs::symlink_metadata(&source)
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("rustfmt archive entry {name} is missing: {error}"),
                    )
                })?
                .file_type()
                .is_symlink()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("rustfmt archive entry {name} is not a regular file"),
                ));
            }
            let permissions = fs::metadata(&source)?.permissions();
            fs::copy(&source, bin.join(name))?;
            fs::set_permissions(bin.join(name), permissions)?;
        }
        Ok(())
    })();
    let cleaned = match crate::kernel::store::remove_tree(&full) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(io::Error::new(
            error.kind(),
            format!("remove rustfmt scratch {}: {error}", full.display()),
        )),
        _ => Ok(()),
    };
    extracted?;
    cleaned?;
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

pub(super) fn allowed_entries(root: &str) -> Vec<String> {
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

//! Node's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.

use super::*;

pub(super) fn tarball_has_binding_gyp(activity: &StoreActivity, path: &Path) -> io::Result<bool> {
    let entries = crate::kernel::archive::list_with_activity(
        activity,
        path,
        crate::kernel::archive::Compression::Gzip,
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("list npm tarball {}: {e}", path.display()),
        )
    })?;
    Ok(entries.iter().any(|entry| {
        let trimmed = entry.name.trim_end_matches('/');
        trimmed == "binding.gyp" || trimmed.ends_with("/binding.gyp")
    }))
}

/// Unpack a Node distribution tarball into `staged`, past its one
/// top-level `node-v<version>-<platform>/` directory.
pub(super) fn extract_node_dist(
    activity: &StoreActivity,
    tarball: &Path,
    staged: &Path,
) -> io::Result<()> {
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        tarball,
        staged,
        &crate::kernel::archive::ExtractOptions::platform_build(1),
        crate::kernel::archive::Compression::Gzip,
    )
    .map(|_| ())
    .map_err(|e| io::Error::new(e.kind(), format!("extract node tarball: {e}")))
}

/// Unpack one registry tarball into `dest`, past its `package/` root.
pub(super) fn extract_npm_package(
    activity: &StoreActivity,
    platform: Platform,
    tarball: &Path,
    dest: &Path,
) -> io::Result<()> {
    // Registry tarballs are packed by arbitrary publishers; some
    // (pngjs, eta 1.x) carry directories with mode 0666. bsdtar
    // (macOS) descends into them anyway; GNU tar creates the
    // directory 0666 and then cannot open its children unless
    // directory modes are applied after extraction. The caller's
    // normalize_modes rewrites every mode afterwards, so the store
    // content is identical either way.
    let options = crate::kernel::archive::ExtractOptions {
        delay_directory_restore: !platform.is_macos(),
        ..crate::kernel::archive::ExtractOptions::stripped(1)
    };
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        tarball,
        dest,
        &options,
        crate::kernel::archive::Compression::Gzip,
    )
    .map(|_| ())
}

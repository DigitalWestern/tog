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

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry tarball whose `package/sub/b` is a hard link to
    /// `package/a` unpacks with both names on the same bytes, past the
    /// `package/` root (#556; crates got the same check in #542).
    #[test]
    fn an_npm_tarball_with_a_contained_hard_link_unpacks_both_names() {
        use std::os::unix::fs::MetadataExt;
        let temp = crate::kernel::testutil::TempDir::named("npm-hard-link");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("package/sub")).unwrap();
        fs::write(source.join("package/a"), "shared bytes").unwrap();
        fs::hard_link(source.join("package/a"), source.join("package/sub/b")).unwrap();
        let tarball = temp.0.join("pkg.tgz");
        let status = crate::kernel::testutil::tar_create()
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&source)
            .arg("package")
            .status()
            .unwrap();
        assert!(status.success());
        let (_store_dir, _store, activity) =
            crate::kernel::resolve::testing::scratch_store("npm-hard-link-store");
        let dest = temp.0.join("dest");
        fs::create_dir_all(&dest).unwrap();
        extract_npm_package(&activity, Platform::host().unwrap(), &tarball, &dest).unwrap();
        assert_eq!(fs::read(dest.join("sub/b")).unwrap(), b"shared bytes");
        let (a, b) = (
            fs::metadata(dest.join("a")).unwrap(),
            fs::metadata(dest.join("sub/b")).unwrap(),
        );
        assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    }
}

//! Ruby's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.

use super::*;

pub(super) fn extract_ruby_bottle(
    activity: &StoreActivity,
    tarball: &Path,
    staged: &Path,
) -> io::Result<()> {
    // The verified Linux and Darwin bottles both use
    // portable-ruby/<version>/<tree>; this is deliberately not Node's
    // strip count. The archive remains unchanged in the verified cache.
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        tarball,
        staged,
        &crate::kernel::archive::ExtractOptions::platform_build(2),
        crate::kernel::archive::Compression::Gzip,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("extract portable-ruby bottle: {e}")))?;
    validate_ruby_layout(staged)
}

#[cfg(test)]
pub(super) fn extract_ruby_bottle_for_test(tarball: &Path, staged: &Path) -> io::Result<()> {
    crate::kernel::archive::extract_with_options(
        tarball,
        staged,
        &crate::kernel::archive::ExtractOptions::platform_build(2),
        crate::kernel::archive::Compression::Gzip,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("extract portable-ruby bottle: {e}")))?;
    validate_ruby_layout(staged)
}

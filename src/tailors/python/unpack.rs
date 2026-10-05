//! Python's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.
//! Zip sdists are read with the `zip` crate in `build_requires`.

use crate::kernel::activity::StoreActivity;
use crate::kernel::archive::{self, Compression, Entry};
use std::io;
use std::path::Path;

/// Every member of a `.tar.gz` sdist, validated by the header reader.
pub(super) fn list_sdist(path: &Path, activity: Option<&StoreActivity>) -> io::Result<Vec<Entry>> {
    match activity {
        Some(activity) => archive::list_with_activity(activity, path, Compression::Gzip),
        None => archive::list(path, Compression::Gzip),
    }
}

/// Extract a `.tar.gz` sdist that `list_sdist` listed as `listed` into
/// `destination`, past its one top-level directory.
pub(super) fn extract_sdist(
    path: &Path,
    destination: &Path,
    activity: Option<&StoreActivity>,
    listed: &[Entry],
) -> io::Result<()> {
    match activity {
        Some(activity) => archive::extract_validated_with_activity(
            activity,
            path,
            destination,
            1,
            Compression::Gzip,
            listed,
        ),
        None => archive::extract_validated(path, destination, 1, Compression::Gzip, listed),
    }
}

/// One member of a `.tar.gz` sdist, at most `cap` bytes, read in process.
pub(super) fn read_sdist_member(path: &Path, member: &str, cap: u64) -> io::Result<Vec<u8>> {
    archive::read_member(path, Compression::Gzip, member, cap)
}

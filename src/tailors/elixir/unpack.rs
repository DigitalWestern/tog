//! Elixir's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.

use super::*;
use crate::kernel::archive::{extract_with_activity_and_options, Compression, ExtractOptions};

pub(super) fn extract_otp(
    activity: Option<&StoreActivity>,
    archive: &Path,
    destination: &Path,
    platform: Platform,
) -> io::Result<()> {
    let options = ExtractOptions::platform_build(otp_strip_components(platform) as usize);
    let extracted = match activity {
        Some(activity) => extract_with_activity_and_options(
            activity,
            archive,
            destination,
            &options,
            Compression::Gzip,
        ),
        None => crate::kernel::archive::extract_with_options(
            archive,
            destination,
            &options,
            Compression::Gzip,
        ),
    };
    extracted.map(|_| ()).map_err(|e| {
        err(format!(
            "OTP extraction failed for {} into {}: {e}",
            archive.display(),
            destination.display()
        ))
    })
}

/// Unpack one layer of a Hex package, the outer tar (`gzip` false) or its
/// `contents.tar.gz` (`gzip` true), with every name kept as written.
pub(super) fn extract_hex_tar(
    activity: &StoreActivity,
    archive: &Path,
    dest: &Path,
    gzip: bool,
) -> io::Result<()> {
    let compression = if gzip {
        Compression::Gzip
    } else {
        Compression::None
    };
    extract_with_activity_and_options(
        activity,
        archive,
        dest,
        &ExtractOptions::stripped(0),
        compression,
    )
    .map(|_| ())
}

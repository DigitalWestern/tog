//! Elixir's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`, and the two `unzip` runs. heavy.yml's `gate` watches
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

/// Unpack the pinned Elixir zip into `staged/elixir` and the Hex `.ez`
/// into `staged/archives/hex-<version>` (MIX_ARCHIVES holds unpacked `.ez`
/// directories, and the `.ez` root is `hex-<version>/`, which unzip keeps).
pub(super) fn extract_elixir_and_hex(
    activity: &StoreActivity,
    elixir_zip: &Path,
    hex_ez: &Path,
    staged: &Path,
    hex_version: &str,
) -> io::Result<()> {
    let unzip = |zip: &Path, dest: PathBuf| -> io::Result<bool> {
        fs::create_dir_all(&dest)?;
        let mut command = Command::new("/usr/bin/unzip");
        command.args(["-oq"]).arg(zip).args(["-d"]).arg(dest);
        Ok(crate::kernel::supervise::local_status(&mut command, activity)?.success())
    };
    if !unzip(elixir_zip, staged.join("elixir"))? || !staged.join("elixir/bin/mix").is_file() {
        return Err(err("Elixir extraction failed or has unexpected layout"));
    }
    fs::create_dir_all(staged.join("archives"))?;
    if !unzip(hex_ez, staged.join(format!("archives/hex-{hex_version}")))? {
        return Err(err("Hex archive extraction failed"));
    }
    Ok(())
}

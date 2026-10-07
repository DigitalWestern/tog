//! Python's archive reads and extraction: every call this tailor makes
//! into `kernel::archive` or the `zip` crate, and the wheel installer in
//! `wheel`. heavy.yml's `gate` watches each tailor's `unpack.rs` and
//! `unpack/`, so a change here runs the heavy suite against real archives
//! (#325, #557). `tests/architecture.rs` keeps the calls here.

pub(super) mod wheel;

use crate::kernel::activity::StoreActivity;
use crate::kernel::archive::{self, Compression, Entry};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

fn open_zip(path: &Path) -> io::Result<ZipArchive<File>> {
    ZipArchive::new(File::open(path)?).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read {} as zip: {e}", path.display()),
        )
    })
}

fn zip_entry_error(index: usize, error: zip::result::ZipError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("read zip entry {index}: {error}"),
    )
}

/// Every member name of a zip sdist, in archive order.
pub(super) fn zip_sdist_names(path: &Path) -> io::Result<Vec<String>> {
    let mut archive = open_zip(path)?;
    (0..archive.len())
        .map(|index| {
            archive
                .by_index(index)
                .map(|entry| entry.name().to_string())
                .map_err(|e| zip_entry_error(index, e))
        })
        .collect()
}

/// One member of a zip sdist, by its exact stored name.
pub(super) fn read_zip_sdist_member(path: &Path, member: &str) -> io::Result<Vec<u8>> {
    let mut archive = open_zip(path)?;
    let mut entry = archive.by_name(member).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read {member} from zip: {e}"),
        )
    })?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Write a zip sdist's members into `destination`. `place` maps a member
/// name to its path under `destination`, or `None` to skip it, and
/// refuses a name it does not accept. A symlink member is refused.
pub(super) fn extract_zip_sdist(
    path: &Path,
    destination: &Path,
    place: impl Fn(&str) -> io::Result<Option<String>>,
) -> io::Result<()> {
    let mut archive = open_zip(path)?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|e| zip_entry_error(index, e))?;
        if entry.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sdist archive contains a symlink entry: {}", entry.name()),
            ));
        }
        let Some(relative) = place(entry.name())? else {
            continue;
        };
        let output: PathBuf = destination.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&output)?;
            continue;
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        fs::write(output, bytes)?;
    }
    Ok(())
}

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

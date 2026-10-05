//! Go's archive reads and extraction: every call this tailor makes
//! into `kernel::archive`. heavy.yml's `gate` watches
//! `src/tailors/*/unpack.rs`, so a change here runs the heavy suite against
//! real archives (#325). `tests/architecture.rs` keeps the calls here.

use super::*;
use crate::kernel::archive::Compression;

pub(super) fn extract_go_toolchain_inner(
    archive: &Path,
    staged: &Path,
    activity: Option<&StoreActivity>,
) -> io::Result<()> {
    // List first: the layout check below and the containment rules both
    // run before tar writes anything.
    let entries = match activity {
        Some(activity) => {
            crate::kernel::archive::list_with_activity(activity, archive, Compression::Gzip)
        }
        None => crate::kernel::archive::list(archive, Compression::Gzip),
    }
    .map_err(|e| err(format!("could not inspect Go archive layout: {e}")))?;
    let mut saw_entry = false;
    for entry in &entries {
        let raw = entry.name.as_str();
        let entry = raw.trim_end_matches('/');
        if entry.is_empty() {
            continue;
        }
        let mut components = entry.split('/');
        if components.next() != Some("go")
            || components
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(err(format!(
                "go archive has unexpected layout entry {raw:?}; expected a single top-level go/ root"
            )));
        }
        saw_entry = true;
    }
    if !saw_entry {
        return Err(err("go archive has unexpected empty layout"));
    }

    match activity {
        Some(activity) => crate::kernel::archive::extract_validated_with_activity_and_options(
            activity,
            archive,
            staged,
            &crate::kernel::archive::ExtractOptions::platform_build(1),
            Compression::Gzip,
            &entries,
        )?,
        None => crate::kernel::archive::extract_validated_with_options(
            archive,
            staged,
            &crate::kernel::archive::ExtractOptions::platform_build(1),
            Compression::Gzip,
            &entries,
        )?,
    }
    if !staged.join("bin/go").is_file() {
        return Err(err("go tarball extraction failed or has unexpected layout"));
    }
    Ok(())
}

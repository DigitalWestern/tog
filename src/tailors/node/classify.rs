//! npm tarballs for the node env (node tailor): fetching each registry
//! package's tarball against its integrity, and the persisted record of
//! whether an archive carries a `binding.gyp`, which decides whether the
//! env's identity names the native libraries.

use super::unpack::tarball_has_binding_gyp;
use super::*;
use crate::kernel::digest::sri_candidates;
use crate::kernel::fetch::download_verified_any_held;

pub(super) const ARCHIVE_CLASSIFICATION_SCHEMA: &str = "npm-archive-classification/1";

pub(super) fn archive_classification_path(store: &Store, digest: &Digest) -> PathBuf {
    store.cache_path(
        "npm-archive-classification",
        &format!("{}-{}.json", digest.algo(), digest.hex()),
    )
}

/// Read the verified archive inspection result without requiring the archive
/// itself to remain in the download cache. The digest and schema are checked
/// because this file participates in derivation planning.
pub(super) fn read_archive_classification(
    store: &Store,
    digest: &Digest,
) -> io::Result<Option<bool>> {
    let path = archive_classification_path(store, digest);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "read npm archive classification {}: {error}",
                    path.display()
                ),
            ))
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "parse npm archive classification {}: {error}",
                path.display()
            ),
        )
    })?;
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some(ARCHIVE_CLASSIFICATION_SCHEMA)
        || value.get("digest").and_then(serde_json::Value::as_str)
            != Some(&format!("{}:{}", digest.algo(), digest.hex()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "npm archive classification {} has the wrong identity",
                path.display()
            ),
        ));
    }
    value
        .get("binding_gyp")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "npm archive classification {} has no binding_gyp result",
                    path.display()
                ),
            )
        })
        .map(Some)
}

pub(super) fn write_archive_classification(
    store: &Store,
    digest: &Digest,
    binding_gyp: bool,
) -> io::Result<()> {
    if let Some(existing) = read_archive_classification(store, digest)? {
        if existing != binding_gyp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "npm archive classification changed for {}:{}",
                    digest.algo(),
                    digest.hex()
                ),
            ));
        }
        return Ok(());
    }

    let destination = archive_classification_path(store, digest);
    fs::create_dir_all(destination.parent().expect("classification cache parent"))?;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let temporary = store.root.join("tmp").join(format!(
        "npm-archive-classification-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let value = serde_json::json!({
        "schema": ARCHIVE_CLASSIFICATION_SCHEMA,
        "digest": format!("{}:{}", digest.algo(), digest.hex()),
        "binding_gyp": binding_gyp,
    });
    fs::write(&temporary, serde_json::to_vec(&value)?)?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
    }
    match fs::rename(&temporary, &destination) {
        Ok(()) => Ok(()),
        Err(_) if destination.is_file() => {
            let _ = fs::remove_file(&temporary);
            match read_archive_classification(store, digest)? {
                Some(existing) if existing == binding_gyp => Ok(()),
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "npm archive classification changed for {}:{}",
                        digest.algo(),
                        digest.hex()
                    ),
                )),
                None => Err(io::Error::other(
                    "npm archive classification disappeared during publication",
                )),
            }
        }
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "publish npm archive classification {}: {error}",
                destination.display()
            ),
        )),
    }
}

pub(super) fn persisted_archive_classification(
    store: &Store,
    packages: &[NpmPackage],
) -> io::Result<Option<bool>> {
    let mut has_native = false;
    for package in packages {
        // A git package is realized from its commit, not a tarball: its
        // binding.gyp is visible in the object once realized, and until then
        // the classification is unknown.
        if let Some(source) = &package.git {
            let object = store.object_path(&crate::kernel::gitsrc::object_id(source));
            if !object.is_dir() {
                return Ok(None);
            }
            has_native |= object.join("binding.gyp").is_file();
            continue;
        }
        // The archive matched one of the integrity's candidates, and its
        // classification is filed under that one.
        let mut found = None;
        for digest in sri_candidates(&package.integrity)? {
            found = read_archive_classification(store, &digest)?;
            if found.is_some() {
                break;
            }
        }
        let Some(binding_gyp) = found else {
            return Ok(None);
        };
        has_native |= binding_gyp;
    }
    Ok(Some(has_native))
}

pub(super) fn classify_downloaded_archives(
    store: &Store,
    activity: &StoreActivity,
    tarballs: &[FetchedTarball<'_>],
) -> io::Result<bool> {
    let mut has_native = false;
    for (_, tarball, digest) in tarballs {
        // The tarball was returned by download_verified_digest, so inspect the
        // verified bytes and persist the result before planning the identity.
        let binding_gyp = tarball_has_binding_gyp(activity, tarball)?;
        write_archive_classification(store, digest, binding_gyp)?;
        has_native |= binding_gyp;
    }
    Ok(has_native)
}

/// A registry package's tarball under its cache lease, with the integrity
/// candidate the bytes matched.
pub(super) type FetchedTarball<'a> = (&'a NpmPackage, crate::kernel::fetch::CacheLease, Digest);

/// Download `package`'s tarball, admitting bytes that match any hash of its
/// integrity's strongest algorithm.
pub(super) fn fetch_tarball(
    store: &Store,
    activity: &StoreActivity,
    package: &NpmPackage,
) -> io::Result<(crate::kernel::fetch::CacheLease, Digest)> {
    let candidates = sri_candidates(&package.integrity)?;
    download_verified_any_held(store, activity, &package.url, &candidates).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: fetch {}: {e}", package.path, package.url),
        )
    })
}

pub(super) fn fetch_npm_tarballs<'a>(
    store: &Store,
    activity: &StoreActivity,
    packages: &'a [NpmPackage],
) -> io::Result<Vec<FetchedTarball<'a>>> {
    packages
        .iter()
        .filter(|p| p.git.is_none())
        .map(|p| {
            let (tarball, digest) = fetch_tarball(store, activity, p)?;
            Ok((p, tarball, digest))
        })
        .collect()
}

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

/// The plan's native decision and the archive each registry package's
/// share of it was read from: the integrity candidate (see
/// [`sri_candidates`]) whose tarball was classified. A cold realization
/// extracts whatever candidate the fetch lands on, so it confirms that is
/// the same archive with [`confirm_classified_sources`].
pub(super) struct NativeDecision {
    pub(super) has_native: bool,
    /// Lockfile path to the classified candidate, registry packages only.
    pub(super) classified_from: BTreeMap<String, Digest>,
}

/// Whether `digest`'s archive is in the download cache with the bytes it
/// names. The same re-hash a fetch's cache hit performs, so the candidate
/// found here is the one the fetch would serve; a missing or poisoned
/// entry is simply not there.
fn archive_is_cached(store: &Store, activity: &StoreActivity, digest: &Digest) -> io::Result<bool> {
    match crate::kernel::fetch::cache_verified_digest_held(store, activity, digest) {
        Ok(_lease) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn persisted_archive_classification(
    store: &Store,
    activity: &StoreActivity,
    packages: &[NpmPackage],
) -> io::Result<Option<NativeDecision>> {
    let mut has_native = false;
    let mut classified_from = BTreeMap::new();
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
        // classification is filed under that one. With one candidate the
        // filing is the archive's. With several, a classification says what
        // its own archive holds and nothing about the others, and the fetch
        // below lands on whichever candidate the cache holds (or, with none
        // cached, whatever the registry serves now): so only the cached
        // candidate's filing may decide, and with none cached the fetch
        // classifies what it gets.
        let candidates = sri_candidates(&package.integrity)?;
        let digest = match candidates.as_slice() {
            [only] => only.clone(),
            _ => {
                let mut cached = None;
                for candidate in &candidates {
                    if archive_is_cached(store, activity, candidate)? {
                        cached = Some(candidate.clone());
                        break;
                    }
                }
                let Some(cached) = cached else {
                    return Ok(None);
                };
                cached
            }
        };
        let Some(binding_gyp) = read_archive_classification(store, &digest)? else {
            return Ok(None);
        };
        has_native |= binding_gyp;
        classified_from.insert(package.path.clone(), digest);
    }
    Ok(Some(NativeDecision {
        has_native,
        classified_from,
    }))
}

pub(super) fn classify_downloaded_archives(
    store: &Store,
    activity: &StoreActivity,
    tarballs: &[FetchedTarball<'_>],
) -> io::Result<NativeDecision> {
    let mut has_native = false;
    let mut classified_from = BTreeMap::new();
    for (package, tarball, digest) in tarballs {
        // The tarball came back from `fetch_tarball` as the candidate
        // `digest` of the package's integrity, so inspect the verified bytes
        // and persist the result under that candidate before planning the
        // identity.
        let binding_gyp = tarball_has_binding_gyp(activity, tarball)?;
        write_archive_classification(store, digest, binding_gyp)?;
        has_native |= binding_gyp;
        classified_from.insert(package.path.clone(), digest.clone());
    }
    Ok(NativeDecision {
        has_native,
        classified_from,
    })
}

/// The archives a cold realization fetched (`tarballs`, each package with
/// the cache path its bytes came from) are the ones the native decision was
/// read from. The decision's leases are released before the realization
/// fetches again, so between the two a sweep can take an archive and the
/// registry can serve another allowed candidate: the identity would then
/// name one tarball's classification for an env built from another, and
/// the realization stops instead. A retry classifies what is served now.
pub(super) fn confirm_classified_sources(
    classified_from: &BTreeMap<String, Digest>,
    tarballs: &[(NpmPackage, PathBuf)],
) -> io::Result<()> {
    for (package, path) in tarballs {
        let Some(digest) = classified_from.get(&package.path) else {
            continue;
        };
        if path.file_name().and_then(|name| name.to_str()) != Some(digest.hex()) {
            return Err(io::Error::other(format!(
                "{}: the archive classified for the environment ({}:{}) is not the one fetched for it ({}); retry the sync",
                package.path,
                digest.algo(),
                digest.hex(),
                path.display()
            )));
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn registry_package(integrity: &str) -> NpmPackage {
        NpmPackage {
            path: "node_modules/addon".into(),
            name: "addon".into(),
            version: "1.0.0".into(),
            url: "https://127.0.0.1:9/never-requested.tgz".into(),
            integrity: integrity.into(),
            bin: Vec::new(),
            foreign_platform: false,
            needs_workspace: false,
            patch: None,
            git: None,
        }
    }

    fn sha512_of(bytes: &[u8]) -> Digest {
        use sha2::Digest as _;
        Digest::sha512(&hex::encode(sha2::Sha512::digest(bytes))).unwrap()
    }

    fn sri_of(digest: &Digest) -> String {
        format!(
            "sha512-{}",
            crate::kernel::base64::encode(&hex::decode(digest.hex()).unwrap())
        )
    }

    /// Two allowed tarballs: the classification is filed under one whose
    /// archive is gone, and the cache holds the other, which (unlike the
    /// filed one) carries a `binding.gyp`. The filing must not decide.
    #[test]
    fn a_filed_classification_decides_only_for_the_cached_candidate() {
        let scratch = TempDir::named("npm-classify-two");
        let root = scratch.0.join("store");
        for subdir in ["objects", "meta", "cache/sha512", "tmp"] {
            fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();

        let src = scratch.0.join("src");
        fs::create_dir_all(src.join("package")).unwrap();
        fs::write(
            src.join("package/package.json"),
            r#"{"name":"addon","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(src.join("package/binding.gyp"), "{}").unwrap();
        let tarball = scratch.0.join("addon.tgz");
        assert!(crate::kernel::testutil::tar_create()
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&src)
            .arg("package")
            .status()
            .unwrap()
            .success());
        let served = fs::read(&tarball).unwrap();
        let cached = sha512_of(&served);
        let gone = sha512_of(b"the build without the addon");
        fs::write(store.cache_path(cached.algo(), cached.hex()), &served).unwrap();
        write_archive_classification(&store, &gone, false).unwrap();

        let packages = [registry_package(&format!(
            "{} {}",
            sri_of(&gone),
            sri_of(&cached)
        ))];
        assert!(
            persisted_archive_classification(&store, activity, &packages)
                .unwrap()
                .is_none(),
            "the absent candidate's filing decided"
        );

        // The fetch lands on the cached candidate (a hit, no network) and
        // classifies that archive: native, from its own binding.gyp.
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: packages.to_vec(),
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let mut leases = Vec::new();
        let (native_libs_id, classified_from) = resolve_native_libs_id(
            &store,
            activity,
            Platform::X86_64UnknownLinuxGnu,
            &plan,
            &mut leases,
        )
        .unwrap();
        assert!(
            native_libs_id.is_some(),
            "the cached tarball has a binding.gyp"
        );
        assert_eq!(
            classified_from.get("node_modules/addon"),
            Some(&cached),
            "the decision names the archive it came from"
        );
        assert_eq!(
            read_archive_classification(&store, &cached).unwrap(),
            Some(true)
        );
        assert_eq!(
            read_archive_classification(&store, &gone).unwrap(),
            Some(false),
            "the other candidate's filing is untouched"
        );
        drop(leases);

        // Now filed for the cached candidate too: the warm path uses that
        // filing, and only that one.
        let decision = persisted_archive_classification(&store, activity, &packages)
            .unwrap()
            .expect("the cached candidate is filed");
        assert!(decision.has_native);
        assert_eq!(
            decision.classified_from.get("node_modules/addon"),
            Some(&cached)
        );

        // Once the cached archive is gone too, no filing may decide.
        fs::remove_file(store.cache_path(cached.algo(), cached.hex())).unwrap();
        assert!(
            persisted_archive_classification(&store, activity, &packages)
                .unwrap()
                .is_none()
        );
    }

    /// The cold fetch must extract the archive the decision was read from.
    #[test]
    fn a_cold_fetch_of_another_candidate_than_the_classified_one_stops() {
        let store = Store::for_test(PathBuf::from("/nonexistent/tog-test-store"));
        let classified = sha512_of(b"classified");
        let fetched = sha512_of(b"fetched instead");
        let package = registry_package(&format!("{} {}", sri_of(&classified), sri_of(&fetched)));
        let from: BTreeMap<String, Digest> = [(package.path.clone(), classified.clone())]
            .into_iter()
            .collect();

        let same = vec![(
            package.clone(),
            store.cache_path(classified.algo(), classified.hex()),
        )];
        confirm_classified_sources(&from, &same).unwrap();

        let other = vec![(
            package.clone(),
            store.cache_path(fetched.algo(), fetched.hex()),
        )];
        let error = confirm_classified_sources(&from, &other)
            .unwrap_err()
            .to_string();
        assert!(error.contains("node_modules/addon"), "{error}");
        assert!(error.contains(classified.hex()), "{error}");
        assert!(error.contains("retry"), "{error}");

        // A package the decision did not classify (a git one, or one
        // planned after the decision) is not held to it.
        let mut unclassified = package.clone();
        unclassified.path = "node_modules/other".into();
        confirm_classified_sources(&from, &[(unclassified, PathBuf::from("/x"))]).unwrap();
    }
}

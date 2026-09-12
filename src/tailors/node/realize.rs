//! node env realization (node tailor): tarball fetch and classification,
//! the env object's identity, staging, and the sandboxed install scripts.

use super::*;

pub(super) fn tarball_has_binding_gyp(store: &Store, path: &Path) -> io::Result<bool> {
    let mut command = Command::new("/usr/bin/tar");
    command.args(["-tzf"]).arg(path);
    let output = crate::kernel::supervise::output_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("list npm tarball {}: {e}", path.display()),
        )
    })?;
    if !output.status.success() {
        return Err(err(format!(
            "list npm tarball {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|entry| entry.trim_end_matches('/'))
        .any(|entry| entry == "binding.gyp" || entry.ends_with("/binding.gyp")))
}

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
        let digest = Digest::from_sri(&package.integrity)?;
        let Some(binding_gyp) = read_archive_classification(store, &digest)? else {
            return Ok(None);
        };
        has_native |= binding_gyp;
    }
    Ok(Some(has_native))
}

pub(super) fn classify_downloaded_archives(
    store: &Store,
    tarballs: &[(&NpmPackage, crate::kernel::fetch::CacheLease)],
) -> io::Result<bool> {
    let mut has_native = false;
    for (package, tarball) in tarballs {
        let digest = Digest::from_sri(&package.integrity)?;
        // The tarball was returned by download_verified_digest, so inspect the
        // verified bytes and persist the result before planning the identity.
        let binding_gyp = tarball_has_binding_gyp(store, tarball)?;
        write_archive_classification(store, &digest, binding_gyp)?;
        has_native |= binding_gyp;
    }
    Ok(has_native)
}

pub(super) fn fetch_npm_tarballs<'a>(
    store: &Store,
    packages: &'a [NpmPackage],
) -> io::Result<Vec<(&'a NpmPackage, crate::kernel::fetch::CacheLease)>> {
    packages
        .iter()
        .filter(|p| p.git.is_none())
        .map(|p| {
            let digest = Digest::from_sri(&p.integrity)?;
            let tarball = download_verified_digest_held(store, &p.url, &digest).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: fetch {}: {e}", p.path, p.url))
            })?;
            Ok((p, tarball))
        })
        .collect()
}

pub(super) fn native_libs_identity_id(
    store: &Store,
    platform: Platform,
    has_native: bool,
) -> io::Result<Option<String>> {
    if has_native && matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        Ok(Some(crate::tailors::python::nativelibs::object_id_for(
            store, platform,
        )?))
    } else {
        Ok(None)
    }
}

/// Realize the node_modules tree as an immutable store object.
/// Object content root contains exactly `node_modules/`.
pub fn realize_node_env(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "node environment", "stage 2")?;
    let node_obj = ensure_node_for(store, platform).map_err(wrap_ensure_node_error)?;
    realize_node_env_with_node_object(store, platform, plan, artifacts, &node_obj)
}

pub(super) fn node_env_identity(
    store: &Store,
    platform: Platform,
    node_obj: &Path,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    native_libs_id: Option<&str>,
) -> io::Result<Identity> {
    let mut inputs = BTreeMap::new();
    // /3: install scripts run sandboxed; name@version joined the per-pkg
    // identity (they reach scripts as npm_package_* env). Remaining known
    // impurity, documented: host Xcode/SDK version is not fingerprinted
    // (same standing as python sdist builds).
    inputs.insert("schema".to_string(), "node-env/3".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert(
        "nodejs".to_string(),
        node_obj.file_name().unwrap().to_string_lossy().into_owned(),
    );
    add_node_env_layout_input(&mut inputs, &plan.packages);
    let workspaces = workspace_set(plan);
    inputs.insert("workspaces".into(), workspaces.join("|"));
    for p in &plan.packages {
        // A git package has no registry tarball: its content is the realized
        // commit, so the git object id takes the digest's place.
        let content = match &p.git {
            Some(source) => format!("git:{}", crate::kernel::gitsrc::object_id(source)),
            None => {
                let digest = Digest::from_sri(&p.integrity)?;
                format!("{}:{}", digest.algo(), digest.hex())
            }
        };
        // bin mappings change the realized tree, so they are identity inputs.
        let mut bins: Vec<String> = p.bin.iter().map(|(k, v)| format!("{k}={v}")).collect();
        bins.sort();
        if inputs
            .insert(
                format!("pkg:{}", p.path),
                format!(
                    "{}:{}@{}:patch[{}]:bin[{}]",
                    content,
                    p.name,
                    p.version,
                    p.patch
                        .as_ref()
                        .map(|patch| patch.hash.as_str())
                        .unwrap_or(""),
                    bins.join(",")
                ),
            )
            .is_some()
        {
            return Err(err(format!("duplicate lockfile path: {}", p.path)));
        }
    }
    // A provisioned artifact is a build input too: a GitHub release asset can
    // be replaced, so the package version alone does not determine the bytes
    // that reach the install script.
    for p in &plan.packages {
        if let Some(input) = crate::tailors::python::artifacts::provisioned_identity_input(
            store, platform, &p.name, &p.version,
        )? {
            inputs.insert(format!("provisioned:{}", p.path), input);
        }
    }
    // Declared artifacts are build inputs: they change what install
    // scripts produce, so they are part of the identity.
    for a in artifacts {
        if inputs
            .insert(format!("artifact:{}", a.path), a.sha256.clone())
            .is_some()
        {
            return Err(err(format!("duplicate artifact path: {}", a.path)));
        }
    }
    if let Some(native_libs_id) = native_libs_id {
        inputs.insert("native_libs".into(), native_libs_id.into());
    }
    Ok(Identity {
        kind: "node-env".into(),
        name: "env".into(),
        version: plan.node_version.clone(),
        inputs,
    })
}

pub(super) fn realize_node_env_with_node_object(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    node_obj: &Path,
) -> io::Result<PathBuf> {
    // Linux needs archive inspection to decide whether node-gyp will mount the
    // native library set. The inspection result is persisted by archive
    // digest, so a warm environment can be identified before its tarballs are
    // fetched. Darwin deliberately does not mount this Linux-only set.
    let mut classification_tarballs: Vec<(&NpmPackage, crate::kernel::fetch::CacheLease)> =
        Vec::new();
    let native_libs_id = if platform.is_macos() {
        None
    } else {
        let has_native = match persisted_archive_classification(store, &plan.packages)? {
            Some(has_native) => has_native,
            None => {
                classification_tarballs = fetch_npm_tarballs(store, &plan.packages)?;
                classify_downloaded_archives(store, &classification_tarballs)?
            }
        };
        native_libs_identity_id(store, platform, has_native)?
    };
    let identity = node_env_identity(
        store,
        platform,
        node_obj,
        plan,
        artifacts,
        native_libs_id.as_deref(),
    )?;
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let workspaces = workspace_set(plan);
    // A warm sync returned at the cache lookup above, so reaching here means a
    // cold realization. Take a lease on every tarball so gc cannot collect the
    // cached bytes mid-extraction; peer snapshots are separate graph nodes that
    // normally share one registry tarball, so deduplicate the byte fetch while
    // keeping extraction and placement per physical lockfile path.
    drop(classification_tarballs);
    let mut leases: Vec<crate::kernel::fetch::CacheLease> = Vec::new();
    let mut tarballs: Vec<(NpmPackage, PathBuf)> = Vec::new();
    let mut git_objects: Vec<(NpmPackage, PathBuf)> = Vec::new();
    let mut downloaded = BTreeMap::<(String, String), PathBuf>::new();
    for p in &plan.packages {
        // Git dependencies are realized as their own store objects; the loop
        // below extracts tarballs, so they are collected separately.
        if let Some(source) = &p.git {
            let object = crate::kernel::gitsrc::ensure_git_source(store, source).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: git source {}: {e}", p.path, source.url),
                )
            })?;
            crate::kernel::policy::record(
                crate::kernel::policy::GIT_DEPENDENCY,
                &format!("{}@{}", p.name, p.version),
                &format!("{} at {}", source.url, source.commit),
            )?;
            git_objects.push((p.clone(), object));
            continue;
        }
        let digest = Digest::from_sri(&p.integrity)?;
        let cache_key = (p.url.clone(), p.integrity.clone());
        let t = if let Some(t) = downloaded.get(&cache_key) {
            t.clone()
        } else {
            let lease = download_verified_digest_held(store, &p.url, &digest).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: fetch {}: {e}", p.path, p.url))
            })?;
            let path = lease.to_path_buf();
            leases.push(lease);
            downloaded.insert(cache_key, path.clone());
            path
        };
        tarballs.push((p.clone(), t));
    }

    let native_libs = if native_libs_id.is_some() {
        Some(crate::tailors::python::nativelibs::ensure_native_libs(
            store, platform,
        )?)
    } else {
        None
    };

    let staged = store.stage()?;
    fs::create_dir_all(staged.join("node_modules"))?;
    for workspace in &workspaces {
        fs::create_dir_all(
            staged
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules"),
        )?;
    }
    // Parents before children (path depth = lexicographic prefix ordering
    // already holds after sort, since "a/node_modules/b" sorts after "a").
    for (p, tarball) in &mut tarballs {
        let dest = env_package_path(&staged, &p.path);
        fs::create_dir_all(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: create dir: {e}", p.path)))?;
        let mut tar = Command::new("/usr/bin/tar");
        tar.arg("-xzf")
            .arg(tarball)
            .arg("-C")
            .arg(&dest)
            .args(["--strip-components", "1"]);
        if !platform.is_macos() {
            // Registry tarballs are packed by arbitrary publishers; some
            // (pngjs, eta 1.x) carry directories with mode 0666. bsdtar
            // (macOS) descends into them anyway; GNU tar creates the
            // directory 0666 and then cannot open its children unless
            // directory modes are applied after extraction. normalize_modes
            // below rewrites every mode afterwards, so the store content is
            // identical either way (LINUX_PORT.md, stage 5 follow-up).
            tar.arg("--delay-directory-restore");
        }
        let status = crate::kernel::supervise::status_owned(&mut tar, store)?;
        if !status.success() {
            return Err(err(format!("{}: tarball extraction failed", p.path)));
        }
        normalize_modes(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: normalize modes: {e}", p.path)))?;
        if let Some(patch) = &p.patch {
            let patch_path = Path::new(&patch.path);
            let patch_bytes = fs::read(patch_path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: read verified patch {}: {e}", p.path, patch.path),
                )
            })?;
            use sha2::Digest as _;
            let actual = hex::encode(sha2::Sha256::digest(&patch_bytes));
            let expected = patch.hash.strip_prefix("sha256-").unwrap_or(&patch.hash);
            if expected.len() != 64 || !expected.eq_ignore_ascii_case(&actual) {
                return Err(err(format!(
                    "{}: patch {} changed after lock verification (expected {}, got {})",
                    p.path, patch.path, patch.hash, actual
                )));
            }
            let file = fs::File::open(patch_path)?;
            let mut command = Command::new("/usr/bin/patch");
            command
                .args(["-p1", "--batch", "--forward"])
                .current_dir(&dest)
                .stdin(file);
            let status =
                crate::kernel::supervise::status_owned(&mut command, store).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("{}: spawn /usr/bin/patch for {}: {e}", p.path, patch.path),
                    )
                })?;
            if !status.success() {
                return Err(err(format!(
                    "{}: applying patch {} failed",
                    p.path, patch.path
                )));
            }
            normalize_modes(&dest).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: normalize patched modes: {e}", p.path),
                )
            })?;
        }
        if p.bin.is_empty() {
            if let Ok(manifest) = fs::read_to_string(dest.join("package.json")) {
                p.bin = discover_package_bins(&manifest, &p.name, &dest)?;
            }
        }
        // ponytail: post-extraction size cap (1 GiB/package) — catches
        // decompression bombs after the fact; a streaming extractor with
        // preflight limits is the M5 upgrade. Lockfiles are trusted inputs.
        if dir_size(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: size walk: {e}", p.path)))?
            > 1 << 30
        {
            return Err(err(format!(
                "{}: package expands past 1 GiB; refusing",
                p.path
            )));
        }
    }

    // Git packages: the realized commit IS the package content. npm would run
    // the package's `prepare` script here (git deps are installed from source);
    // blanket does not, because that script is unsandboxed build logic with its
    // own dependency needs — the exception says so rather than pretending.
    for (p, object) in &mut git_objects {
        let dest = env_package_path(&staged, &p.path);
        let source_root = match &p.git.as_ref().and_then(|g| g.subdirectory.clone()) {
            Some(subdir) => {
                crate::tailors::node::validate_lock_path(subdir).map_err(|e| {
                    io::Error::new(e.kind(), format!("{}: subdirectory {subdir}: {e}", p.path))
                })?;
                object.join(subdir)
            }
            None => object.clone(),
        };
        if !source_root.is_dir() {
            return Err(err(format!(
                "{}: {} is not a directory in the git source",
                p.path,
                source_root.display()
            )));
        }
        // `cp -a src dest` copies INTO dest when dest already exists, which it
        // does whenever this package has nested dependencies (their directories
        // are created first). Copy into a fresh sibling and move it into place.
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&dest)?;
        let staging = dest.with_file_name(format!(
            ".blanket-git-{}",
            dest.file_name().and_then(|n| n.to_str()).unwrap_or("pkg")
        ));
        let _ = crate::kernel::store::remove_tree(&staging);
        crate::comforter::clone_tree_for_store(store, &source_root, &staging, platform)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: copy git source: {e}", p.path)))?;
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            fs::rename(entry.path(), dest.join(entry.file_name()))?;
        }
        let _ = crate::kernel::store::remove_tree(&staging);
        normalize_modes(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: normalize modes: {e}", p.path)))?;
        let manifest = fs::read_to_string(dest.join("package.json")).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{}: git source has no package.json: {e}", p.path),
            )
        })?;
        if serde_json::from_str::<serde_json::Value>(&manifest)
            .ok()
            .and_then(|value| value["scripts"]["prepare"].as_str().map(str::to_string))
            .is_some()
        {
            crate::kernel::policy::record(
                crate::kernel::policy::GIT_DEPENDENCY,
                &format!("{}@{}", p.name, p.version),
                "package has a `prepare` script; blanket does not run it for git sources",
            )?;
        }
        if p.bin.is_empty() {
            p.bin = discover_package_bins(&manifest, &p.name, &dest)?;
        }
    }
    // Capture provenance before the package vectors are merged and dropped.
    // Registry packages retain their exact SRI digest; git packages retain
    // the realized source object; lifecycle inputs are explicit cache
    // digests rather than guesses from the identity map.
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(node_obj)?)?;
    if let Some(native_libs_id) = native_libs_id.as_deref() {
        deps.object_id(native_libs_id)?;
    }
    for package in &plan.packages {
        if package.git.is_some() {
            let (_, object) = git_objects
                .iter()
                .find(|(candidate, _)| candidate.path == package.path)
                .ok_or_else(|| err(format!("missing realized git source for {}", package.path)))?;
            deps.object_id(&crate::kernel::store::object_id_from_path(object)?)?;
        } else {
            deps.cache_digest(Digest::from_sri(&package.integrity)?);
        }
        if let Some(input) = crate::tailors::python::artifacts::provisioned_identity_input(
            store,
            platform,
            &package.name,
            &package.version,
        )? {
            let (_, sha256) = input.rsplit_once(':').ok_or_else(|| {
                err(format!(
                    "provisioned artifact identity for {} has no sha256",
                    package.name
                ))
            })?;
            deps.cache_digest(Digest::sha256(sha256)?);
        }
    }
    for artifact in artifacts {
        deps.cache_digest(Digest::sha256(&artifact.sha256)?);
    }

    let mut tarballs = tarballs;
    tarballs.append(&mut git_objects);

    // .bin launchers for physically top-level (hoisted) packages, which is
    // what node_modules/.bin holds in npm's own layout.
    for (p, _) in &tarballs {
        if !is_importer_top_level(&p.path) || p.bin.is_empty() {
            continue;
        }
        let bin_dir = env_node_modules_path(&staged, &p.path).join(".bin");
        fs::create_dir_all(&bin_dir)?;
        for (bin_name, rel) in &p.bin {
            // bin metadata comes from the lockfile (attacker-editable), so
            // it is validated hard: single normal name component, relative
            // target with only normal components, canonical target inside
            // the package directory, not a symlink.
            let name_ok = !bin_name.is_empty()
                && !bin_name.starts_with('.')
                && !bin_name.contains('/')
                && !bin_name.contains('\\');
            let rel_path = normalized_bin_path(rel);
            if !name_ok || rel_path.is_err() {
                return Err(err(format!(
                    "{}: unsafe bin entry {bin_name:?} -> {rel:?}",
                    p.path
                )));
            }
            let rel_path = rel_path.unwrap();
            let pkg_dir = env_package_path(&staged, &p.path);
            let target_file = pkg_dir.join(&rel_path);
            let md = match fs::symlink_metadata(&target_file) {
                Ok(md) => md,
                Err(_) => continue, // bin target genuinely absent: npm tolerates this
            };
            if !md.is_file() {
                return Err(err(format!(
                    "{}: bin target {rel} is not a regular file",
                    p.path
                )));
            }
            let canon = target_file.canonicalize()?;
            if !canon.starts_with(pkg_dir.canonicalize()?) {
                return Err(err(format!(
                    "{}: bin target {rel} escapes the package directory",
                    p.path
                )));
            }
            // Relative link: node_modules/.bin/x -> ../<name>/<rel>
            // Relative link: <importer>/node_modules/.bin/x -> ../<name>/<rel>.
            let link_target = bin_link_target(&p.path, &rel_path.to_string_lossy());
            let link = bin_dir.join(bin_name);
            if link.symlink_metadata().is_ok() {
                // Real graphs collide (playwright + @playwright/test both
                // declare `playwright`). npm keeps the first hoisted claim;
                // plan order is sorted, so first-wins is deterministic.
                eprintln!(
                    "blanket: warning: bin {bin_name:?} already claimed; \
                     skipping the one from {}",
                    p.path
                );
                continue;
            }
            std::os::unix::fs::symlink(&link_target, &link)?;
            use std::os::unix::fs::PermissionsExt;
            let mut perms = md.permissions();
            perms.set_mode(perms.mode() | 0o755);
            fs::set_permissions(&target_file, perms)?;
        }
    }

    // Lifecycle setup may fetch declared artifacts and a pinned Python for
    // node-gyp; the package tarballs have already been fully extracted.
    drop(tarballs);
    run_install_scripts(
        store,
        platform,
        &staged,
        &node_obj,
        plan,
        artifacts,
        native_libs.as_ref().map(|set| set.path.as_path()),
    )?;

    let candidate = crate::kernel::policy::object_exceptions();
    let (object, applied) = store
        .commit_with_deps(&identity, &staged, &candidate, &deps)
        .map_err(|e| io::Error::new(e.kind(), format!("commit env: {e}")))?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// npm lifecycle install scripts, run hermetically: network denied, writes
/// confined to the package's own directory and a scratch dir, reads limited
/// to the staged tree + node toolchain + system. This is what makes native
/// addons (better-sqlite3, bcrypt) work: prebuilt-binary downloads fail
/// closed and the node-gyp source fallback compiles offline against the
/// store's node headers.
///
/// npm semantics mirrored: preinstall/install/postinstall in that order;
/// packages with a binding.gyp and no install script get the default
/// `node-gyp rebuild`. A failure is an exception by default, while strict
/// policy preserves the fail-closed behavior. Isolation per package: a fresh
/// scratch HOME each, tool shims in a directory scripts cannot write,
/// declared artifacts planted per consuming HOME.
pub(super) enum LifecycleFailure {
    SandboxUnavailable(io::Error),
    Script(io::Error),
}

pub(super) fn classify_lifecycle_result(result: io::Result<()>) -> Result<(), LifecycleFailure> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            Err(LifecycleFailure::SandboxUnavailable(error))
        }
        Err(error) => Err(LifecycleFailure::Script(error)),
    }
}

pub(super) fn run_install_scripts(
    store: &Store,
    platform: Platform,
    staged: &Path,
    node_obj: &Path,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    native_libs: Option<&Path>,
) -> io::Result<()> {
    // Scratch stage dirs (tool shims, per-package HOMEs, snapshots) are
    // removed on every exit, including the fatal Unsupported paths (missing
    // Linux pin, unavailable sandbox backend) that return early.
    let mut cleanup: Vec<PathBuf> = Vec::new();
    let result = run_install_scripts_staged(
        store,
        platform,
        staged,
        node_obj,
        plan,
        artifacts,
        native_libs,
        &mut cleanup,
    );
    for t in cleanup {
        let _ = crate::kernel::store::remove_tree(&t);
    }
    result
}

pub(super) fn run_install_scripts_staged(
    store: &Store,
    platform: Platform,
    staged: &Path,
    node_obj: &Path,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    native_libs: Option<&Path>,
    cleanup: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    // Deepest first: nested deps build before their dependents.
    let mut pkgs: Vec<&NpmPackage> = plan.packages.iter().collect();
    pkgs.sort_by_key(|p| std::cmp::Reverse(p.path.matches("node_modules/").count()));

    // Tools live in their own stage dir which is NOT in the sandbox write
    // list — a script can execute the node-gyp shim but never replace it.
    let mut tools: Option<PathBuf> = None;
    // node-gyp needs a Python; the store's pinned CPython keeps builds off
    // the system toolchain drift. Realized lazily, only when needed.
    let mut python_obj: Option<PathBuf> = None;
    for p in &pkgs {
        let pkg_dir = env_package_path(staged, &p.path);
        let manifest = match fs::read_to_string(pkg_dir.join("package.json")) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let manifest: serde_json::Value = match serde_json::from_str(&manifest) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let scripts = &manifest["scripts"];
        let has = |k: &str| scripts[k].as_str().is_some();
        let default_gyp =
            !has("install") && !has("preinstall") && pkg_dir.join("binding.gyp").exists();
        if !has("preinstall") && !has("install") && !has("postinstall") && !default_gyp {
            continue;
        }

        let tools_dir = match &tools {
            Some(t) => t.clone(),
            None => {
                // A store stage dir: collision-proof and already canonical
                // (Seatbelt matches real paths).
                let t = store.stage()?;
                // node-gyp shim: npm normally injects this into PATH.
                let bin = t.join("bin");
                fs::create_dir_all(&bin)?;
                let gyp_js =
                    node_obj.join("lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js");
                fs::write(
                    bin.join("node-gyp"),
                    format!(
                        "#!/bin/sh\nexec \"{}\" \"{}\" \"$@\"\n",
                        node_obj.join("bin/node").display(),
                        gyp_js.display()
                    ),
                )?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(bin.join("node-gyp"), fs::Permissions::from_mode(0o755))?;
                cleanup.push(t.clone());
                tools.insert(t).clone()
            }
        };
        // Fresh scratch HOME per package: no shared writable state between
        // one package's scripts and the next.
        let tmp = store.stage()?;
        cleanup.push(tmp.clone());
        // Plant declared artifacts where this package's installer looks
        // (paths are HOME-relative; HOME is this scratch dir).
        for a in artifacts {
            let src = download_verified_held(store, &a.url, &a.sha256).map_err(|e| {
                io::Error::new(e.kind(), format!("declared artifact {}: {e}", a.url))
            })?;
            let dest = tmp.join(&a.path);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::copy(&src, &dest).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("placing declared artifact {}: {e}", a.path),
                )
            })?;
        }

        let phases: Vec<(&str, String)> = ["preinstall", "install", "postinstall"]
            .iter()
            .filter_map(|ph| match scripts[*ph].as_str() {
                Some(s) => Some((*ph, s.to_string())),
                None if *ph == "install" && default_gyp => {
                    Some((*ph, "node-gyp rebuild".to_string()))
                }
                None => None,
            })
            .collect();

        // Snapshot lives in its own stage dir: neither readable nor writable
        // inside the sandbox, so a failing script cannot tamper with what
        // gets restored (Sol, item 3 round 2).
        let snapshot_root = store.stage()?;
        cleanup.push(snapshot_root.clone());
        let snapshot = snapshot_root.join("package");
        crate::comforter::clone_tree_for_store(store, &pkg_dir, &snapshot, platform)?;

        let python = match &python_obj {
            Some(p) => p.clone(),
            None => {
                let pin = crate::tailors::python::lookup(platform, "3.12").ok_or_else(|| {
                    crate::kernel::platform::no_pin("cpython 3.12", platform, "stage 2")
                })?;
                let p = crate::tailors::python::ensure_python_for(store, pin, platform).map_err(
                    |e| io::Error::new(e.kind(), format!("ensure python for node-gyp: {e}")),
                )?;
                python_obj.insert(p).clone()
            }
        };
        let python_bin = python.join("bin/python3");

        let nearest_bin = env_node_modules_path(staged, &p.path).join(".bin");
        let root_bin = staged.join("node_modules/.bin");
        let mut path_entries = vec![
            tools_dir.join("bin").display().to_string(),
            node_obj.join("bin").display().to_string(),
            nearest_bin.display().to_string(),
        ];
        if nearest_bin != root_bin {
            path_entries.push(root_bin.display().to_string());
        }
        path_entries.extend([
            "/usr/bin".into(),
            "/bin".into(),
            "/usr/sbin".into(),
            "/sbin".into(),
        ]);
        let path_env = path_entries.join(":");
        let mut envs: Vec<(String, String)> = vec![
            ("PYTHON".into(), python_bin.display().to_string()),
            ("npm_config_python".into(), python_bin.display().to_string()),
            ("npm_config_nodedir".into(), node_obj.display().to_string()),
            (
                "npm_config_node_gyp".into(),
                node_obj
                    .join("lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js")
                    .display()
                    .to_string(),
            ),
            // NOTE: npm_config_build_from_source is not set globally here: it
            // would make packages like sharp skip their local-cache lookup
            // (where declared artifacts land). It is set per package, below,
            // only for prebuilt-binary downloaders with no declared artifacts
            // (NEXT.md item 5).
            // Deterministic npm cache location inside the scratch HOME —
            // also where declared artifacts under .npm/ land.
            (
                "npm_config_cache".into(),
                tmp.join(".npm").display().to_string(),
            ),
            ("npm_package_name".into(), p.name.clone()),
            ("npm_package_version".into(), p.version.clone()),
        ];
        if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            // python-build-standalone's sysconfig may name clang even though
            // Linux node-gyp is intentionally built with the host toolchain.
            // The sandbox cleared the inherited environment, so these are the
            // only compiler selections visible to the lifecycle process.
            envs.push(("CC".into(), "gcc".into()));
            envs.push(("CXX".into(), "g++".into()));
        }
        // NEXT.md item 5: packages whose installers download at install time.
        // A documented skip switch turns a doomed fetch into a recorded
        // exception naming what the user runs later; a prebuilt-binary
        // downloader is told to compile instead, which is the path it would
        // have fallen back to anyway once the network denied it.
        let script_text = phases
            .iter()
            .map(|(_, script)| script.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        // Only artifacts planted for THIS package suppress the source build:
        // one declared artifact anywhere must not silently change how every
        // other package installs.
        let declared_here = artifacts.iter().any(|a| {
            a.path.split('/').any(|segment| segment == p.name)
                || a.url.contains(&format!("/{}/", p.name))
        });
        // Provisioning comes first: if blanket can supply the artifact, the
        // package is really installed rather than skipped.
        match crate::tailors::python::artifacts::provision(
            store, platform, &p.name, &p.version, &tmp,
        ) {
            Ok(Some(provisioning)) => {
                envs.extend(provisioning.envs);
                for (subject, detail) in &provisioning.records {
                    crate::kernel::policy::record(
                        crate::kernel::policy::ARTIFACT_PROVISIONED,
                        subject,
                        detail,
                    )?;
                }
            }
            Ok(None) => {}
            Err(error) => {
                // A provisioning failure is not fatal: the install script still
                // runs and fails loudly on its own if it needs the artifact.
                eprintln!(
                    "blanket: {}: could not provision its artifact: {error}",
                    p.name
                );
                crate::kernel::policy::record(
                    crate::kernel::policy::ARTIFACT_NOT_PROVISIONED,
                    &format!("{}@{}", p.name, p.version),
                    &format!("provisioning failed: {error}"),
                )?;
            }
        }
        if let Some(skip) = crate::tailors::python::artifacts::skip_download_for(&p.name) {
            for (key, value) in skip.envs {
                envs.push(((*key).to_string(), (*value).to_string()));
            }
            crate::kernel::policy::record(
                crate::kernel::policy::ARTIFACT_NOT_PROVISIONED,
                &format!("{}@{}", p.name, p.version),
                &format!("install-time download skipped; run: {}", skip.hint),
            )?;
        } else if crate::tailors::python::artifacts::wants_source_build(&script_text, declared_here)
        {
            envs.extend(crate::tailors::python::artifacts::source_build_envs());
            crate::kernel::policy::record(
                crate::kernel::policy::BUILT_FROM_SOURCE,
                &format!("{}@{}", p.name, p.version),
                "prebuilt binary not downloaded; compiled from source in the sandbox",
            )?;
        }
        envs.push(("PATH".into(), path_env.clone()));
        if let Some(native_libs) = native_libs {
            envs = crate::tailors::python::nativelibs::compose_env(native_libs, &envs);
        }
        let path_env = envs
            .iter()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value.as_str())
            .unwrap_or("/usr/bin:/bin");
        // Tools dir is readable+executable but NOT writable in-sandbox.
        let sandbox = crate::kernel::sandbox::Sandbox {
            read: vec![staged, node_obj, &python, &tools_dir]
                .into_iter()
                .chain(native_libs)
                .collect(),
            write: vec![&pkg_dir, &tmp],
        };
        for (phase, script) in &phases {
            eprintln!("blanket: {} {}: {phase} (sandboxed)", p.name, p.version);
            let envs_phase: Vec<(String, String)> = envs
                .iter()
                .cloned()
                .chain([("npm_lifecycle_event".to_string(), phase.to_string())])
                .collect();
            let result = sandbox.run_in_on_with_activity(
                platform,
                &["/bin/sh", "-c", script],
                &path_env,
                &tmp,
                &pkg_dir,
                &envs_phase,
                &activity,
            );
            // A missing sandbox backend is never a script failure: it must
            // not become a permissive install-script-failed exception.
            let e = match classify_lifecycle_result(result) {
                Ok(()) => continue,
                Err(LifecycleFailure::SandboxUnavailable(e)) => return Err(e),
                Err(LifecycleFailure::Script(e)) => e,
            };
            let hint = "If this package downloads files at install time, declare them as verified inputs in package.json — \
                        \"blanket\": {\"artifacts\": [{\"url\", \"sha256\", \"path\"}]} — \
                        placed where the package's downloader caches them (see README).";
            let error = e.to_string();
            let detail = format!(
                "{phase}: {}. {hint}",
                error.chars().take(300).collect::<String>()
            );
            if let Err(policy_error) = crate::kernel::policy::record(
                crate::kernel::policy::INSTALL_SCRIPT_FAILED,
                &p.path,
                &detail,
            ) {
                return Err(err(format!(
                    "{}: {phase} script failed under the network-denied build \
                     sandbox: {e}. {hint} ({policy_error})",
                    p.path
                )));
            }
            crate::kernel::store::remove_tree(&pkg_dir)?;
            fs::rename(&snapshot, &pkg_dir)?;
            remove_dangling_bin_links(staged, plan)?;
            break;
        }
    }
    Ok(())
}

pub(super) fn remove_dangling_bin_links(staged: &Path, plan: &NpmPlan) -> io::Result<()> {
    let mut bin_dirs = vec![staged.join("node_modules/.bin")];
    bin_dirs.extend(workspace_set(plan).into_iter().map(|workspace| {
        staged
            .join("workspaces")
            .join(encode_workspace_path(&workspace))
            .join("node_modules/.bin")
    }));
    for bin_dir in bin_dirs {
        let entries = match fs::read_dir(&bin_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.file_type().is_symlink() && !path.exists() {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

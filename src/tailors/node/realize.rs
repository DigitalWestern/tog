//! node env realization (node tailor): tarball fetch and classification,
//! the env object's identity, staging, and the sandboxed install scripts.

use super::*;
use sha2::Digest as _;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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

/// Realize the node_modules tree as an immutable store object. The object
/// content root holds `node_modules/` plus one
/// `workspaces/<encoded importer>/node_modules` per workspace importer.
pub fn realize_node_env(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "node environment")?;
    let node_obj = ensure_node_for(store, platform).map_err(wrap_ensure_node_error)?;
    realize_node_env_with_node_object(store, platform, plan, artifacts, &node_obj)
}

/// The producer's provisioning decision, exposed to the `node-env` identity
/// contract in `objects.rs` so both consult the same rule. Lives here because
/// this file is the documented node-to-python-artifacts seam
/// (tests/architecture.rs allow-list).
pub(crate) fn provisioned_version<'a>(name: &str, version: &'a str) -> Option<&'a str> {
    crate::tailors::python::artifacts::provisioned_version(name, version)
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
        let patch_identity = match p.patch.as_ref() {
            None => "patch[]".to_string(),
            Some(patch) => match patch.content_sha256.as_deref() {
                Some(content_sha256) => {
                    format!("patch[{};sha256:{content_sha256}]", patch.hash)
                }
                None => format!("patch[{}]", patch.hash),
            },
        };
        if inputs
            .insert(
                format!("pkg:{}", p.path),
                format!(
                    "{}:{}@{}:{patch_identity}:bin[{}]",
                    content,
                    p.name,
                    p.version,
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

/// The native library set this plan needs, as an identity input.
///
/// Linux needs archive inspection to decide whether node-gyp will mount the
/// native library set. The inspection result is persisted by archive digest,
/// so a warm environment can be identified before its tarballs are fetched.
/// Darwin deliberately does not mount this Linux-only set.
///
/// Any tarballs fetched for the inspection are appended to `classification`;
/// the caller keeps those leases until it no longer needs the cached bytes.
fn resolve_native_libs_id<'a>(
    store: &Store,
    platform: Platform,
    plan: &'a NpmPlan,
    classification: &mut Vec<(&'a NpmPackage, crate::kernel::fetch::CacheLease)>,
) -> io::Result<Option<String>> {
    if platform.is_macos() {
        return Ok(None);
    }
    let has_native = match persisted_archive_classification(store, &plan.packages)? {
        Some(has_native) => has_native,
        None => {
            *classification = fetch_npm_tarballs(store, &plan.packages)?;
            classify_downloaded_archives(store, classification)?
        }
    };
    native_libs_identity_id(store, platform, has_native)
}

/// The byte sources for a cold realization: one held cache lease per distinct
/// registry tarball, plus the realized object for every git dependency.
///
/// Peer snapshots are separate graph nodes that normally share one registry
/// tarball, so the byte fetch is deduplicated while extraction and placement
/// stay per physical lockfile path. The leases must outlive extraction so gc
/// cannot collect the cached bytes mid-flight, so they are returned rather
/// than dropped here.
#[allow(clippy::type_complexity)]
fn fetch_plan_sources(
    store: &Store,
    plan: &NpmPlan,
) -> io::Result<(
    Vec<crate::kernel::fetch::CacheLease>,
    Vec<(NpmPackage, PathBuf)>,
    Vec<(NpmPackage, PathBuf)>,
)> {
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
    Ok((leases, tarballs, git_objects))
}

/// The staged env skeleton: the root node_modules plus one per workspace.
fn stage_env_skeleton(store: &Store, workspaces: &[String]) -> io::Result<PathBuf> {
    let staged = store.stage()?;
    fs::create_dir_all(staged.join("node_modules"))?;
    for workspace in workspaces {
        fs::create_dir_all(
            staged
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules"),
        )?;
    }
    Ok(staged)
}

/// A pnpm patch, re-verified against the hash the lock attested before it is
/// applied: the file on disk can have changed since lock verification. A
/// normalized match also rechecks the raw-byte identity binding.
fn read_verified_patch(package_path: &str, patch: &NpmPatch) -> io::Result<Vec<u8>> {
    let patch_path = Path::new(&patch.path);
    let patch_bytes = fs::read(patch_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: read verified patch {}: {e}", package_path, patch.path),
        )
    })?;
    // Same acceptance set as the lock-time check, from the same function, so a
    // pnpm 9 base32 hash cannot pass one gate and fail the other.
    let matched =
        super::lock_import::check_patch_hash(&patch.hash, &patch_bytes).map_err(|actual| {
            err(format!(
                "{}: patch {} changed after lock verification (expected {}, got {})",
                package_path, patch.path, patch.hash, actual
            ))
        })?;
    match patch.content_sha256.as_deref() {
        // The lock matched the raw bytes, so the identity carries no separate
        // raw digest: the declared hash is the only binding, and it only binds
        // raw bytes when the match is raw. A file rewritten so that it matches
        // only after lossy UTF-8 normalization (a U+FFFD sequence replaced by
        // the invalid byte it stands for) would otherwise reach `patch` with
        // different bytes under an unchanged object id.
        None => {
            if matched != super::lock_import::PatchMatch::Raw {
                return Err(err(format!(
                    "{}: patch {} changed after lock verification (the lock hash matched the \
                     raw bytes at lock time but only their normalized form now)",
                    package_path, patch.path
                )));
            }
        }
        Some(expected) => {
            let actual = hex::encode(sha2::Sha256::digest(&patch_bytes));
            if actual != expected {
                return Err(err(format!(
                    "{}: patch {} changed after lock verification (expected sha256 {}, got {})",
                    package_path, patch.path, expected, actual
                )));
            }
        }
    }
    Ok(patch_bytes)
}

struct PatchSnapshot {
    root: PathBuf,
    path: PathBuf,
    source: PathBuf,
}

impl PatchSnapshot {
    fn open(&self) -> io::Result<fs::File> {
        fs::File::open(&self.path)
    }
}

impl Drop for PatchSnapshot {
    fn drop(&mut self) {
        let _ = crate::kernel::store::remove_tree(&self.root);
    }
}

/// Write the verified bytes to a fresh private stage directory under
/// `store/tmp`. If a process is killed before the guard runs, the leftover
/// `stage-*` directory is enumerated by `kernel::gc::read::read_stages` and
/// reclaimed by the stale-stage plan; ordinary success and error paths remove
/// the whole directory through `PatchSnapshot::drop`.
fn snapshot_verified_patch(
    store: &Store,
    package_path: &str,
    patch: &NpmPatch,
) -> io::Result<PatchSnapshot> {
    let patch_bytes = read_verified_patch(package_path, patch)?;
    let root = store.stage()?;
    let path = root.join("patch");
    let snapshot = PatchSnapshot {
        root,
        path,
        source: PathBuf::from(&patch.path),
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&snapshot.path)?;
    file.write_all(&patch_bytes)?;
    drop(file);
    Ok(snapshot)
}

fn apply_verified_patch(
    store: &Store,
    package_path: &str,
    snapshot: &PatchSnapshot,
    dest: &Path,
) -> io::Result<()> {
    let snapshot_file = snapshot.open().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "{}: open patch snapshot for {}: {e}",
                package_path,
                snapshot.source.display()
            ),
        )
    })?;
    let mut command = Command::new("/usr/bin/patch");
    command
        .args(["-p1", "--batch", "--forward"])
        .current_dir(dest)
        .stdin(snapshot_file);
    let status = crate::kernel::supervise::status_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "{}: spawn /usr/bin/patch for {}: {e}",
                package_path,
                snapshot.source.display()
            ),
        )
    })?;
    if !status.success() {
        return Err(err(format!(
            "{}: applying patch {} failed",
            package_path,
            snapshot.source.display()
        )));
    }
    normalize_modes(dest).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}: normalize patched modes: {e}", package_path),
        )
    })
}

/// Extract every registry tarball into its lockfile path, applying patches
/// and discovering bins on the way.
///
/// Parents before children (path depth = lexicographic prefix ordering
/// already holds after sort, since "a/node_modules/b" sorts after "a").
fn extract_tarball_packages(
    store: &Store,
    platform: Platform,
    staged: &Path,
    tarballs: &mut [(NpmPackage, PathBuf)],
) -> io::Result<()> {
    for (p, tarball) in tarballs {
        let dest = env_package_path(staged, &p.path);
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
            // identical either way.
            tar.arg("--delay-directory-restore");
        }
        let status = crate::kernel::supervise::status_owned(&mut tar, store)?;
        if !status.success() {
            return Err(err(format!("{}: tarball extraction failed", p.path)));
        }
        normalize_modes(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: normalize modes: {e}", p.path)))?;
        if let Some(patch) = &p.patch {
            let snapshot = snapshot_verified_patch(store, &p.path, patch)?;
            apply_verified_patch(store, &p.path, &snapshot, &dest)?;
        }
        if p.bin.is_empty() {
            if let Ok(manifest) = fs::read_to_string(dest.join("package.json")) {
                p.bin = discover_package_bins(&manifest, &p.name, &dest)?;
            }
        }
        // Post-extraction size cap (1 GiB/package): catches decompression
        // bombs after the fact, not before. Lockfiles are trusted inputs, so
        // this is a backstop rather than the primary defence.
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
    Ok(())
}

/// Git packages: the realized commit IS the package content. npm would run
/// the package's `prepare` script here (git deps are installed from source);
/// blanket does not, because that script is unsandboxed build logic with its
/// own dependency needs — the exception says so rather than pretending.
fn place_git_packages(
    store: &Store,
    platform: Platform,
    staged: &Path,
    git_objects: &mut [(NpmPackage, PathBuf)],
) -> io::Result<()> {
    for (p, object) in git_objects {
        let dest = env_package_path(staged, &p.path);
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
    Ok(())
}

/// Provenance for the committed env object.
///
/// Registry packages retain their exact SRI digest; git packages retain the
/// realized source object; lifecycle inputs are explicit cache digests rather
/// than guesses from the identity map. Called before the package vectors are
/// merged and dropped.
fn env_object_deps(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    node_obj: &Path,
    native_libs_id: Option<&str>,
    git_objects: &[(NpmPackage, PathBuf)],
) -> io::Result<crate::kernel::store::ObjectDeps> {
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(node_obj)?)?;
    if let Some(native_libs_id) = native_libs_id {
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
    Ok(deps)
}

/// .bin launchers for physically top-level (hoisted) packages, which is what
/// node_modules/.bin holds in npm's own layout.
fn link_package_bins(staged: &Path, packages: &[(NpmPackage, PathBuf)]) -> io::Result<()> {
    for (p, _) in packages {
        if !is_importer_top_level(&p.path) || p.bin.is_empty() {
            continue;
        }
        let bin_dir = env_node_modules_path(staged, &p.path).join(".bin");
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
            let pkg_dir = env_package_path(staged, &p.path);
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
            // Relative link: [<importer>/]node_modules/.bin/x -> ../<name>/<rel>.
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
    Ok(())
}

/// Publish the staged tree, recording any exception the commit applied that
/// was not already a candidate.
fn commit_env_object(
    store: &Store,
    identity: &Identity,
    staged: &Path,
    deps: &crate::kernel::store::ObjectDeps,
) -> io::Result<PathBuf> {
    let candidate = crate::kernel::policy::object_exceptions();
    let (object, applied) = store
        .commit_with_deps(identity, staged, &candidate, deps)
        .map_err(|e| io::Error::new(e.kind(), format!("commit env: {e}")))?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

pub(super) fn realize_node_env_with_node_object(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    node_obj: &Path,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    let mut classification_tarballs: Vec<(&NpmPackage, crate::kernel::fetch::CacheLease)> =
        Vec::new();
    let native_libs_id =
        resolve_native_libs_id(store, platform, plan, &mut classification_tarballs)?;
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
    // cached bytes mid-extraction; `leases` is held to the end of this
    // function for exactly that reason.
    drop(classification_tarballs);
    let (_leases, mut tarballs, mut git_objects) = fetch_plan_sources(store, plan)?;

    let native_libs = if native_libs_id.is_some() {
        Some(crate::tailors::python::nativelibs::ensure_native_libs(
            store, platform,
        )?)
    } else {
        None
    };

    let staged = stage_env_skeleton(store, &workspaces)?;
    extract_tarball_packages(store, platform, &staged, &mut tarballs)?;
    place_git_packages(store, platform, &staged, &mut git_objects)?;
    // Capture provenance before the package vectors are merged and dropped.
    let deps = env_object_deps(
        store,
        platform,
        plan,
        artifacts,
        node_obj,
        native_libs_id.as_deref(),
        &git_objects,
    )?;

    let mut tarballs = tarballs;
    tarballs.append(&mut git_objects);
    link_package_bins(&staged, &tarballs)?;

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

    commit_env_object(store, &identity, &staged, &deps)
}

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

/// npm lifecycle install scripts, run hermetically: network denied, writes
/// confined to the package's own directory and a scratch dir, reads limited
/// to the staged tree + node toolchain + system. This is what makes native
/// addons (better-sqlite3, bcrypt) work: prebuilt-binary downloads fail
/// closed and the node-gyp source fallback compiles offline against the
/// store's node headers.
///
/// npm semantics mirrored: preinstall/install/postinstall in that order;
/// packages with a binding.gyp and neither an install nor a preinstall
/// script get the default `node-gyp rebuild`. A failure is an exception by
/// default, while strict policy preserves the fail-closed behavior. Isolation
/// per package: a fresh scratch HOME each, tool shims in a directory scripts
/// cannot write, declared artifacts planted per consuming HOME.
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

/// The lifecycle scripts this staged package runs, in npm's order.
///
/// `None` means the package has no lifecycle work at all: no readable
/// manifest, or no preinstall/install/postinstall and no binding.gyp. A
/// package with a binding.gyp and neither an install nor a preinstall script
/// gets npm's default `node-gyp rebuild`.
fn package_lifecycle_phases(pkg_dir: &Path) -> Option<Vec<(&'static str, String)>> {
    let manifest = fs::read_to_string(pkg_dir.join("package.json")).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest).ok()?;
    let scripts = &manifest["scripts"];
    let has = |k: &str| scripts[k].as_str().is_some();
    let default_gyp = !has("install") && !has("preinstall") && pkg_dir.join("binding.gyp").exists();
    if !has("preinstall") && !has("install") && !has("postinstall") && !default_gyp {
        return None;
    }
    Some(
        ["preinstall", "install", "postinstall"]
            .iter()
            .filter_map(|ph| match scripts[*ph].as_str() {
                Some(s) => Some((*ph, s.to_string())),
                None if *ph == "install" && default_gyp => {
                    Some((*ph, "node-gyp rebuild".to_string()))
                }
                None => None,
            })
            .collect(),
    )
}

/// The shared tool stage dir, created on first use.
///
/// Tools live in their own stage dir which is NOT in the sandbox write list —
/// a script can execute the node-gyp shim but never replace it.
fn ensure_lifecycle_tools(
    store: &Store,
    node_obj: &Path,
    tools: &mut Option<PathBuf>,
    cleanup: &mut Vec<PathBuf>,
) -> io::Result<PathBuf> {
    if let Some(t) = tools {
        return Ok(t.clone());
    }
    // A store stage dir: collision-proof and already canonical
    // (Seatbelt matches real paths).
    let t = store.stage()?;
    // node-gyp shim: npm normally injects this into PATH.
    let bin = t.join("bin");
    fs::create_dir_all(&bin)?;
    let gyp_js = node_obj.join("lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js");
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
    Ok(tools.insert(t).clone())
}

/// Plant declared artifacts where this package's installer looks (paths are
/// HOME-relative; HOME is this scratch dir).
fn plant_declared_artifacts(
    store: &Store,
    artifacts: &[DeclaredArtifact],
    tmp: &Path,
) -> io::Result<()> {
    for a in artifacts {
        let src = download_verified_held(store, &a.url, &a.sha256)
            .map_err(|e| io::Error::new(e.kind(), format!("declared artifact {}: {e}", a.url)))?;
        let dest = tmp.join(&a.path);
        fs::create_dir_all(dest.parent().unwrap())?;
        fs::copy(&src, &dest).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("placing declared artifact {}: {e}", a.path),
            )
        })?;
    }
    Ok(())
}

/// node-gyp needs a Python; the store's pinned CPython keeps builds off the
/// system toolchain drift. Realized lazily, only when needed.
fn ensure_gyp_python(
    store: &Store,
    platform: Platform,
    python_obj: &mut Option<PathBuf>,
) -> io::Result<PathBuf> {
    if let Some(p) = python_obj {
        return Ok(p.clone());
    }
    let pin = crate::tailors::python::lookup(platform, "3.12")
        .ok_or_else(|| crate::kernel::platform::no_pin("cpython 3.12", platform))?;
    let p = crate::tailors::python::ensure_python_for(store, pin, platform)
        .map_err(|e| io::Error::new(e.kind(), format!("ensure python for node-gyp: {e}")))?;
    Ok(python_obj.insert(p).clone())
}

/// PATH for one package's lifecycle scripts: the tool shims first, then the
/// node toolchain, then the nearest and root .bin dirs, then the system.
fn lifecycle_path_env(
    tools_dir: &Path,
    node_obj: &Path,
    staged: &Path,
    package_path: &str,
) -> String {
    let nearest_bin = env_node_modules_path(staged, package_path).join(".bin");
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
    path_entries.join(":")
}

/// The environment every lifecycle phase of this package starts from, before
/// artifact policy and PATH are appended.
fn lifecycle_base_envs(
    platform: Platform,
    node_obj: &Path,
    python_bin: &Path,
    tmp: &Path,
    p: &NpmPackage,
) -> Vec<(String, String)> {
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
        // only for prebuilt-binary downloaders with no declared artifacts.
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
    envs
}

/// Packages whose installers download at install time.
///
/// A documented skip switch turns a doomed fetch into a recorded exception
/// naming what the user runs later; a prebuilt-binary downloader is told to
/// compile instead, which is the path it would have fallen back to anyway
/// once the network denied it. Provisioning comes first: if blanket can
/// supply the artifact, the package is really installed rather than skipped.
fn apply_artifact_policy(
    store: &Store,
    platform: Platform,
    p: &NpmPackage,
    tmp: &Path,
    artifacts: &[DeclaredArtifact],
    phases: &[(&str, String)],
    envs: &mut Vec<(String, String)>,
) -> io::Result<()> {
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
    match crate::tailors::python::artifacts::provision(store, platform, &p.name, &p.version, tmp) {
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
    } else if crate::tailors::python::artifacts::wants_source_build(&script_text, declared_here) {
        envs.extend(crate::tailors::python::artifacts::source_build_envs());
        crate::kernel::policy::record(
            crate::kernel::policy::BUILT_FROM_SOURCE,
            &format!("{}@{}", p.name, p.version),
            "prebuilt binary not downloaded; compiled from source in the sandbox",
        )?;
    }
    Ok(())
}

/// Run one package's lifecycle phases in the sandbox, stopping at the first
/// failure. A failure restores the package from the snapshot and is recorded
/// as an exception; strict policy turns the record into a hard error.
#[allow(clippy::too_many_arguments)]
fn run_package_phases(
    platform: Platform,
    staged: &Path,
    plan: &NpmPlan,
    p: &NpmPackage,
    pkg_dir: &Path,
    snapshot: &Path,
    tmp: &Path,
    phases: &[(&str, String)],
    envs: &[(String, String)],
    path_env: &str,
    sandbox: &crate::kernel::sandbox::Sandbox,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<()> {
    for (phase, script) in phases {
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
            tmp,
            pkg_dir,
            &envs_phase,
            activity,
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
        crate::kernel::store::remove_tree(pkg_dir)?;
        fs::rename(snapshot, pkg_dir)?;
        remove_dangling_bin_links(staged, plan)?;
        break;
    }
    Ok(())
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

    // The shared tool stage dir and the pinned node-gyp Python are realized
    // lazily, on the first package that actually has lifecycle work.
    let mut tools: Option<PathBuf> = None;
    let mut python_obj: Option<PathBuf> = None;
    for p in &pkgs {
        let pkg_dir = env_package_path(staged, &p.path);
        let Some(phases) = package_lifecycle_phases(&pkg_dir) else {
            continue;
        };

        let tools_dir = ensure_lifecycle_tools(store, node_obj, &mut tools, cleanup)?;
        // Fresh scratch HOME per package: no shared writable state between
        // one package's scripts and the next.
        let tmp = store.stage()?;
        cleanup.push(tmp.clone());
        plant_declared_artifacts(store, artifacts, &tmp)?;

        // Snapshot lives in its own stage dir: neither readable nor writable
        // inside the sandbox, so a failing script cannot tamper with what
        // gets restored.
        let snapshot_root = store.stage()?;
        cleanup.push(snapshot_root.clone());
        let snapshot = snapshot_root.join("package");
        crate::comforter::clone_tree_for_store(store, &pkg_dir, &snapshot, platform)?;

        let python = ensure_gyp_python(store, platform, &mut python_obj)?;
        let python_bin = python.join("bin/python3");

        let path_env = lifecycle_path_env(&tools_dir, node_obj, staged, &p.path);
        let mut envs = lifecycle_base_envs(platform, node_obj, &python_bin, &tmp, p);
        apply_artifact_policy(store, platform, p, &tmp, artifacts, &phases, &mut envs)?;
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
        run_package_phases(
            platform, staged, plan, p, &pkg_dir, &snapshot, &tmp, &phases, &envs, path_env,
            &sandbox, &activity,
        )?;
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

#[cfg(test)]
mod patch_snapshot_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    struct StoreEnv(Option<std::ffi::OsString>);

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("BLANKET_STORE", value),
                None => std::env::remove_var("BLANKET_STORE"),
            }
        }
    }

    /// A raw-sha256 lock match binds the raw bytes only through the declared
    /// hash. If the file is rewritten so that the same declaration matches
    /// only after lossy UTF-8 normalization, the bytes `patch` would apply
    /// have changed while the object id has not, so realization must refuse.
    #[test]
    fn raw_lock_match_refuses_a_normalized_only_match_at_realization() {
        let temp = crate::kernel::testutil::TempDir::new();
        let path = temp.0.join("swap.patch");
        // U+FFFD encoded, then the invalid byte that normalizes to it.
        let original: &[u8] = b"diff --git a/x b/x\n+\xef\xbf\xbd\n";
        let swapped: &[u8] = b"diff --git a/x b/x\n+\xff\n";
        fs::write(&path, original).unwrap();
        let patch = NpmPatch {
            path: path.to_string_lossy().into_owned(),
            hash: hex::encode(sha2::Sha256::digest(original)),
            content_sha256: None,
        };
        assert_eq!(
            read_verified_patch("node_modules/example", &patch).unwrap(),
            original
        );
        fs::write(&path, swapped).unwrap();
        // The declared hash still matches after normalization ...
        assert_eq!(
            super::super::lock_import::check_patch_hash(&patch.hash, swapped),
            Ok(super::super::lock_import::PatchMatch::Normalized)
        );
        // ... and that is exactly what realization must not accept.
        let error = read_verified_patch("node_modules/example", &patch).unwrap_err();
        assert!(
            error.to_string().contains("only their normalized form now"),
            "{error}"
        );
        // A patch whose identity does carry the raw digest is judged by it.
        let bound = NpmPatch {
            content_sha256: Some(hex::encode(sha2::Sha256::digest(swapped))),
            ..patch.clone()
        };
        assert_eq!(
            read_verified_patch("node_modules/example", &bound).unwrap(),
            swapped
        );
        // ... and the reverse swap under that binding is caught by the digest
        // comparison, not by the match mode: the declaration matches the
        // original bytes raw, but the bound raw digest is the swapped file's.
        fs::write(&path, original).unwrap();
        let error = read_verified_patch("node_modules/example", &bound).unwrap_err();
        assert!(error.to_string().contains("expected sha256"), "{error}");
    }

    #[test]
    fn production_patch_snapshot_survives_in_place_source_overwrite() {
        if !Path::new("/usr/bin/patch").is_file() {
            eprintln!("skipping production patch snapshot test: /usr/bin/patch is absent");
            return;
        }
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _store_lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let temp = crate::kernel::testutil::TempDir::new();
        let old_store = std::env::var_os("BLANKET_STORE");
        std::env::set_var("BLANKET_STORE", temp.0.join("store"));
        let _store_env = StoreEnv(old_store);
        let store = Store::open().unwrap();

        let dest = temp.0.join("dest/node_modules/example");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("index.js"), b"before\n").unwrap();

        let original_path = temp.0.join("original.patch");
        let original_patch = b"diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-before\n+after verified\n";
        fs::write(&original_path, original_patch).unwrap();
        let original_inode = fs::metadata(&original_path).unwrap().ino();
        let patch = NpmPatch {
            path: original_path.to_string_lossy().into_owned(),
            hash: hex::encode(sha2::Sha256::digest(original_patch)),
            content_sha256: None,
        };

        let snapshot_root;
        {
            let snapshot = snapshot_verified_patch(&store, "node_modules/example", &patch).unwrap();
            snapshot_root = snapshot.root.clone();

            let tampered_patch =
                b"diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-before\n+after tampered\n";
            let mut original = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&original_path)
                .unwrap();
            original.write_all(tampered_patch).unwrap();
            original.flush().unwrap();
            drop(original);
            assert_eq!(fs::metadata(&original_path).unwrap().ino(), original_inode);

            apply_verified_patch(&store, "node_modules/example", &snapshot, &dest).unwrap();
        }
        assert!(!snapshot_root.exists(), "snapshot stage leaked");
        assert_eq!(
            fs::read(dest.join("index.js")).unwrap(),
            b"after verified\n"
        );
    }
}

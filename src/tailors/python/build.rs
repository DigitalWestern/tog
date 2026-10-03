//! Sandboxed sdist to wheel builds. PEP 517 build dependencies are inspected
//! without execution and, when needed, realized as a separate Python env.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_verified_held, Digest};
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DelegateSpec, DoorKind, ResolutionDoor};
use crate::kernel::sandbox::Sandbox;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::types::{ArtifactKind, Identity, LockedPackage, Plan};
use crate::tailors::python::build_requires::{self, ArchiveInfo};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) const BUILD_TOOLCHAIN: &[(&str, &str, &str, &str, &str)] = &[
    (
        "pip",
        "26.2.1",
        "pip-26.2.1-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/pip-26.2.1-py3-none-any.whl",
        "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e",
    ),
    (
        "setuptools",
        "84.0.0",
        "setuptools-84.0.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/95/9c/c510029fc6ef33a6275cd2c5d3cecd6613dfd6aa401d57c54f1c18852ccf/setuptools-84.0.0-py3-none-any.whl",
        "51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670",
    ),
    (
        "wheel",
        "0.48.0",
        "wheel-0.48.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/2e/29/69cfbb602cd91690c55d38ba9fe53e6a7e76a6fa647bf38f19c138d25449/wheel-0.48.0-py3-none-any.whl",
        "3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab",
    ),
];

fn build_toolchain_fingerprint() -> String {
    BUILD_TOOLCHAIN
        .iter()
        .map(|tool| tool.4)
        .collect::<Vec<_>>()
        .join(",")
}

// The native library set is mounted into sdist builds through environment
// flags. Keep that interface versioned in the identity: changing linker flags
// changes the produced extension bytes even when the mounted object is the
// same one.
const NATIVE_LINKER_CONFIG: &str = "native-libs-rpath/1";

fn sdist_build_env(platform: Platform) -> Vec<(String, String)> {
    if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        vec![
            ("CC".into(), "gcc".into()),
            ("CXX".into(), "g++".into()),
            ("LDSHARED".into(), "gcc -shared".into()),
        ]
    } else {
        Vec::new()
    }
}

/// Kept unchanged so parent environment identities and schema-2 objects
/// retain their historical byte identity.
pub fn derivation_fingerprint() -> String {
    format!("sdist-build/2;toolchain:{}", build_toolchain_fingerprint())
}

/// `python` is the `<version>:<artifact sha256>` the selected CPython row
/// states: the identity names the interpreter's bytes, not its table row.
fn sdist_identity(platform: Platform, pkg: &LockedPackage, python: &str) -> Identity {
    Identity {
        kind: "sdist-build".into(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        inputs: BTreeMap::from([
            ("schema".into(), "sdist-build/2".into()),
            ("sdist_sha256".into(), pkg.sha256.clone()),
            ("python".into(), python.to_string()),
            ("platform".into(), platform.triple().into()),
            ("toolchain".into(), build_toolchain_fingerprint()),
        ]),
    }
}

fn object_id(path: &Path, label: &str) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} has no object id"),
            )
        })
}

/// The four spellings of the `sdist-build/4` mode fields. The producer
/// writes one of each on every commit, so dropping a whole `rust`/`vendor`
/// or `native_libs`/`native_linker` pair never leaves a valid identity.
pub(super) const BUILD_MODE_RUST: &str = "rust-vendor";
pub(super) const BUILD_MODE_PLAIN: &str = "plain";
pub(super) const NATIVE_MODE_LIBS: &str = "native-libs";
pub(super) const NATIVE_MODE_NONE: &str = "none";

fn isolated_sdist_identity_from_ids(
    platform: Platform,
    pkg: &LockedPackage,
    python: &str,
    build_env_id: &str,
    rust_id: Option<&str>,
    vendor_id: Option<&str>,
    native_libs_id: Option<&str>,
) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".into(), "sdist-build/4".into()),
        ("sdist_sha256".into(), pkg.sha256.clone()),
        ("python".into(), python.to_string()),
        ("platform".into(), platform.triple().into()),
        ("build_env".into(), build_env_id.into()),
        (
            "build_mode".into(),
            match rust_id {
                Some(_) => BUILD_MODE_RUST,
                None => BUILD_MODE_PLAIN,
            }
            .into(),
        ),
        (
            "native_mode".into(),
            match native_libs_id {
                Some(_) => NATIVE_MODE_LIBS,
                None => NATIVE_MODE_NONE,
            }
            .into(),
        ),
    ]);
    if let Some(rust_id) = rust_id {
        inputs.insert("rust".into(), rust_id.into());
    }
    if let Some(vendor_id) = vendor_id {
        inputs.insert("vendor".into(), vendor_id.into());
    }
    if let Some(native_libs_id) = native_libs_id {
        inputs.insert("native_libs".into(), native_libs_id.into());
        inputs.insert("native_linker".into(), NATIVE_LINKER_CONFIG.into());
    }
    Identity {
        kind: "sdist-build".into(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        inputs,
    }
}

#[cfg(test)]
fn wrap_sandbox_build_error(pkg: &LockedPackage, error: io::Error) -> io::Error {
    wrap_sandbox_build_error_with_tail(pkg, error, None)
}

fn wrap_sandbox_build_error_with_tail(
    pkg: &LockedPackage,
    error: io::Error,
    stderr_tail: Option<String>,
) -> io::Error {
    let diagnostics = stderr_tail
        .filter(|tail| !tail.trim().is_empty())
        .map(|tail| format!("\nfirst 40 lines of build stderr tail:\n{tail}"))
        .unwrap_or_else(|| {
            "\nbuild stderr was relayed by the sandbox API and was not available for inclusion"
                .into()
        });
    io::Error::new(
        error.kind(),
        format!(
            "sandboxed build of {}=={} failed: {error}\n\
             (network is denied during builds; setup_requires in legacy setup.py \
             is not handled){diagnostics}",
            pkg.name, pkg.version
        ),
    )
}

fn build_toolchain_plan(python_version: &str) -> Plan {
    Plan {
        ecosystem: "python".into(),
        python_version: python_version.into(),
        packages: BUILD_TOOLCHAIN
            .iter()
            .map(|(name, version, filename, url, sha)| LockedPackage {
                name: (*name).into(),
                version: (*version).into(),
                filename: (*filename).into(),
                url: (*url).into(),
                sha256: (*sha).into(),
                kind: ArtifactKind::Wheel,
                git: None,
            })
            .collect(),
    }
}

fn has_package(plan: &Plan, wanted: &str) -> bool {
    plan.packages.iter().any(|pkg| {
        pkg.name
            .chars()
            .map(|ch| if ch == '_' || ch == '.' { '-' } else { ch })
            .collect::<String>()
            .eq_ignore_ascii_case(wanted)
    })
}

fn native_libs_identity_id(
    store: &Store,
    platform: Platform,
    native_build: bool,
    fast_requirements: bool,
) -> io::Result<Option<String>> {
    if (native_build || !fast_requirements) && native_libs_supported(platform) {
        Ok(Some(crate::kernel::provider::nativelibs::object_id_for(
            store, platform,
        )?))
    } else {
        Ok(None)
    }
}

fn native_libs_supported(platform: Platform) -> bool {
    matches!(platform, Platform::X86_64UnknownLinuxGnu)
}

pub(crate) struct SdistIdentityPlan {
    pub input: String,
    pub native_libs_id: Option<String>,
    #[cfg(test)]
    pub identity: Identity,
}

#[cfg(test)]
fn test_store(label: &str) -> (crate::kernel::testutil::TempDir, Store) {
    let dir = crate::kernel::testutil::TempDir::named(&format!("build-identity-{label}"));
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        fs::create_dir_all(dir.0.join(sub)).expect("create Python identity fixture store");
    }
    let root = dir.0.clone();
    (dir, Store { root })
}

/// A byte-identical `.tar.gz` for a fixture tree, with no dependence on
/// the host's tar, gzip, clock, uid, or directory order: ustar headers with
/// mtime 0 and uid/gid 0 in sorted entry order, wrapped in a gzip stream of
/// stored deflate blocks with a zero mtime header. Fixture identities that
/// hash the archive are therefore reproducible across runs and platforms.
#[cfg(test)]
pub(crate) fn deterministic_tar_gz(root: &str, files: &[(&str, &str)]) -> Vec<u8> {
    fn header(name: &str, size: usize, typeflag: u8, mode: &[u8; 8]) -> [u8; 512] {
        let mut block = [0u8; 512];
        assert!(name.len() < 100, "fixture entry name too long: {name}");
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..108].copy_from_slice(mode);
        block[108..116].copy_from_slice(b"0000000\0");
        block[116..124].copy_from_slice(b"0000000\0");
        block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        block[136..148].copy_from_slice(b"00000000000\0");
        block[148..156].copy_from_slice(b"        ");
        block[156] = typeflag;
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    }
    let mut tar = Vec::new();
    tar.extend_from_slice(&header(&format!("{root}/"), 0, b'5', b"0000755\0"));
    let mut entries: Vec<(&str, &str)> = files.to_vec();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (name, text) in entries {
        let bytes = text.as_bytes();
        tar.extend_from_slice(&header(
            &format!("{root}/{name}"),
            bytes.len(),
            b'0',
            b"0000644\0",
        ));
        tar.extend_from_slice(bytes);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);

    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let crc = !tar.iter().fold(0xFFFF_FFFFu32, |acc, &b| {
        table[((acc ^ u32::from(b)) & 0xFF) as usize] ^ (acc >> 8)
    });

    let mut gz = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
    let mut chunks = tar.chunks(0xFFFF).peekable();
    while let Some(chunk) = chunks.next() {
        let len = chunk.len() as u16;
        gz.push(u8::from(chunks.peek().is_none()));
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&(!len).to_le_bytes());
        gz.extend_from_slice(chunk);
    }
    gz.extend_from_slice(&crc.to_le_bytes());
    gz.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    gz
}

#[cfg(test)]
pub(crate) fn local_native_sdist_for_test(store: &Store, name: &str) -> LockedPackage {
    use sha2::Digest as _;

    let archive = store.root.join(format!("{name}-1.0.tar.gz"));
    let bytes = deterministic_tar_gz(
        &format!("{name}-1.0"),
        &[
            (
                "pyproject.toml",
                "[build-system]\nrequires = [\"setuptools>=40.8\"]\nbuild-backend = \"setuptools.build_meta\"\n",
            ),
            ("binding.gyp", "{}"),
        ],
    );
    fs::write(&archive, &bytes).expect("write local native sdist");
    let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    LockedPackage {
        name: name.into(),
        version: "1.0".into(),
        filename: format!("{name}-1.0.tar.gz"),
        url: format!("file://{}", archive.display()),
        sha256,
        kind: ArtifactKind::Sdist,
        git: None,
    }
}

#[cfg(test)]
pub(crate) fn local_rust_sdist_for_test(store: &Store, name: &str) -> LockedPackage {
    use sha2::Digest as _;

    let archive = store.root.join(format!("{name}-1.0.tar.gz"));
    let bytes = deterministic_tar_gz(
        &format!("{name}-1.0"),
        &[
            (
                "pyproject.toml",
                "[build-system]\nrequires = [\"setuptools>=40.8\"]\nbuild-backend = \"setuptools.build_meta\"\n",
            ),
            (
                "Cargo.toml",
                "[package]\nname = \"matrix-rust\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "Cargo.lock",
                "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"matrix-rust\"\nversion = \"0.1.0\"\n",
            ),
        ],
    );
    fs::write(&archive, &bytes).expect("write local Rust sdist");
    let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    LockedPackage {
        name: name.into(),
        version: "1.0".into(),
        filename: format!("{name}-1.0.tar.gz"),
        url: format!("file://{}", archive.display()),
        sha256,
        kind: ArtifactKind::Sdist,
        git: None,
    }
}

/// Return the exact package input used by a parent Python environment. This
/// performs only archive inspection plus deterministic input planning; the
/// actual wheel build still happens in `build_sdist_wheel_at_depth`.
pub(crate) fn plan_sdist_identity_input(
    door: &mut ResolutionDoor<'_>,
    pkg: &LockedPackage,
    selected: &Selected,
    rust: Option<&Selected>,
    runtime_plan: Option<&Plan>,
) -> io::Result<SdistIdentityPlan> {
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    let python = crate::tailors::python::cpython_identity_input(selected, platform)?;
    // One lease for the whole plan: the archive children, the staged work
    // directory and the Cargo run all borrow it.
    let sdist = download_verified_held(store, activity, &pkg.url, &pkg.sha256)?;
    let info = build_requires::inspect_sdist_for(activity, &sdist)?;
    let fast_requirements = build_requires::fast_path(&info.build_requires);
    let fast_sdist = fast_requirements
        && !info.rust_build
        && (!info.native_build || !native_libs_supported(platform));
    if fast_sdist {
        return Ok(SdistIdentityPlan {
            input: format!("Sdist:{}:{}", pkg.sha256, derivation_fingerprint()),
            native_libs_id: None,
            #[cfg(test)]
            identity: sdist_identity(platform, pkg, &python),
        });
    }

    let build_plan = if fast_requirements {
        build_toolchain_plan(selected.version("cpython")?)
    } else {
        build_requires::resolve_build_plan(door, selected, &info.build_requires, runtime_plan)?
    };
    // Planning the nested environment may inspect more sdists and acquire
    // the same GC lock.
    drop(sdist);
    let build_env_id = super::env::planned_env_object_id(door, &build_plan, selected, rust)?;
    let native_libs_id =
        native_libs_identity_id(store, platform, info.native_build, fast_requirements)?;
    let identity = if info.rust_build {
        let work = store.stage_with_activity(activity)?;
        let result: io::Result<Identity> = (|| {
            let sdist = download_verified_held(store, activity, &pkg.url, &pkg.sha256)?;
            let source =
                build_requires::extract_sdist_for(activity, &sdist, &work.join("source"), &info)?;
            drop(sdist);
            let rust = rust_plan_inputs(
                door,
                rust,
                sdist_rust_default(selected),
                &pkg.sha256,
                &source,
                &info,
                &work,
            )?;
            Ok(isolated_sdist_identity_from_ids(
                platform,
                pkg,
                &python,
                &build_env_id,
                Some(&rust.rust_id),
                Some(&rust.vendor_id),
                native_libs_id.as_deref(),
            ))
        })();
        let _ = crate::kernel::store::remove_tree(&work);
        result?
    } else {
        isolated_sdist_identity_from_ids(
            platform,
            pkg,
            &python,
            &build_env_id,
            None,
            None,
            native_libs_id.as_deref(),
        )
    };
    Ok(SdistIdentityPlan {
        input: format!("Sdist:{}:{}", pkg.sha256, identity.object_id()),
        native_libs_id,
        #[cfg(test)]
        identity,
    })
}

#[cfg(test)]
pub(crate) fn sdist_identity_input(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    selected: &Selected,
    runtime_plan: Option<&Plan>,
) -> io::Result<String> {
    let activity = &store
        .activity(crate::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let mut scope = crate::kernel::testutil::DoorScope::new();
    let mut door = scope.door(
        store,
        activity,
        platform,
        crate::kernel::resolve::DoorKind::Planner,
    );
    Ok(plan_sdist_identity_input(&mut door, pkg, selected, None, runtime_plan)?.input)
}

fn stderr_tail(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let lines: Vec<_> = text.lines().collect();
    Some(lines[lines.len().saturating_sub(40)..].join("\n"))
}

fn cargo_lock_for(source: &Path, manifest: &Path) -> Option<PathBuf> {
    [
        manifest.parent().map(|parent| parent.join("Cargo.lock")),
        Some(source.join("Cargo.lock")),
    ]
    .into_iter()
    .flatten()
    .find(|path| path.is_file())
}

fn cargo_lock_cache_key(sdist_sha256: &str, rust_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("{sdist_sha256}\0{rust_id}").as_bytes(),
    ))
}

fn generated_cargo_lock_path(source: &Path, manifest: &Path) -> PathBuf {
    source
        .join(manifest.parent().unwrap_or_else(|| Path::new("")))
        .join("Cargo.lock")
}

fn generate_cargo_lock(
    door: &mut ResolutionDoor<'_>,
    rust_obj: &Path,
    manifest: &Path,
    source: &Path,
    cargo_home: &Path,
) -> io::Result<PathBuf> {
    fs::create_dir_all(cargo_home)?;
    let cargo = rust_obj.join("bin/cargo");
    let path_var = format!("{}:/usr/bin:/bin", rust_obj.join("bin").display());
    let mut spec = DelegateSpec::new(&cargo);
    spec.args(["generate-lockfile", "--manifest-path"])
        .arg(manifest)
        .lock_root(source)
        .env("CARGO_HOME", cargo_home)
        .env("PATH", path_var)
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    // The sdist ships no Cargo.lock: this is its missing-lock door, whatever
    // the planning door it runs under.
    let report = door.reopen(DoorKind::MissingLock).run(spec).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("run store cargo to generate Cargo.lock: {e}"),
        )
    })?;
    if !report.status.success() {
        return Err(io::Error::other(
            "store cargo generate-lockfile failed for the sdist",
        ));
    }
    cargo_lock_for(source, manifest).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "store cargo generated no Cargo.lock next to the sdist manifest",
        )
    })
}

/// The Rust an sdist with no toolchain file of its own built with before a
/// project's lock pinned one: the newest release tog shipped then. A Python
/// section with no `helpers.rust` pin keeps it, so its wheels keep their ids.
pub(crate) const LEGACY_SDIST_RUST: &str = "1.96.1";

struct RustPlanInputs {
    /// The Rust this build compiles with: the project's locked selection, or
    /// the shipped release the sdist's toolchain file resolves to.
    rust: Selected,
    /// The components and cross targets the sdist's own toolchain file asks
    /// for, assembled onto that Rust.
    extras: crate::kernel::provider::rust::Extras,
    rust_version: String,
    rust_id: String,
    vendor_id: String,
    lock_text: String,
    generated_lock: bool,
}

/// The Rust an sdist with no channel of its own builds on under the Python
/// selection `selected`: its section's pin; [`LEGACY_SDIST_RUST`] for a
/// section written before pins, or a selection seeded from a closure
/// written before the lock (those builds used it); `None` (the catalog's
/// default, which is what a section written now pins) otherwise.
fn sdist_rust_default(selected: &Selected) -> Option<&str> {
    use crate::kernel::toolchain::Source;
    match selected.helpers.get("rust") {
        Some(pin) => Some(pin),
        None if matches!(selected.source, Source::Lock | Source::Seeded) => Some(LEGACY_SDIST_RUST),
        None => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_plan_inputs(
    door: &mut ResolutionDoor<'_>,
    project_rust: Option<&Selected>,
    sdist_default: Option<&str>,
    sdist_sha256: &str,
    source: &Path,
    info: &ArchiveInfo,
    work: &Path,
) -> io::Result<RustPlanInputs> {
    let manifest_rel = info.cargo_manifest.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Rust build trigger found, but the sdist has no Cargo.toml",
        )
    })?;
    let manifest = source.join(manifest_rel);
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    let rust = match project_rust {
        // The project's lock decides the compiler, as it does for a cargo
        // project; the sdist's channel is not read, because the lock already
        // answered it.
        Some(selected) => selected.clone(),
        // Otherwise the sdist's own channel, and failing one the Rust the
        // Python section pins for sdists (`sdist_default`).
        None => crate::kernel::provider::rust::shipped_selection(
            crate::kernel::provider::rust::resolve_toolchain_within_or(
                platform,
                source,
                sdist_default,
            )?,
        )?,
    };
    // What the sdist's own toolchain file asks for beyond the compiler is
    // provisioned like a project's: a component or target the pinned release
    // does not publish refuses the build.
    let extras = crate::kernel::provider::rust::toolchain_file_extras_within(source)?;
    let rust_version = rust.version("rustc")?.to_string();
    let rust_id = crate::kernel::provider::rust::toolchain_object_id(
        store, activity, platform, &rust, &extras,
    )?;
    let generated_path =
        store.cache_path("cargo-lock", &cargo_lock_cache_key(sdist_sha256, &rust_id));
    let (lock_text, generated_lock) = if let Some(path) = cargo_lock_for(source, &manifest) {
        (fs::read_to_string(path)?, false)
    } else if let Ok(text) = fs::read_to_string(&generated_path) {
        let lock_path = generated_cargo_lock_path(source, manifest_rel);
        if fs::symlink_metadata(&lock_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cached Cargo.lock would overwrite an extracted symlink: {}",
                    lock_path.display()
                ),
            ));
        }
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&lock_path, &text)?;
        (text, true)
    } else {
        // This is the one cold path that must invoke Cargo. Persist the lock
        // before any later wheel-cache lookup so warm rebuilds stay offline.
        let rust_obj = crate::kernel::provider::rust::realize_toolchain(
            store, activity, platform, &rust, &extras,
        )?;
        let plan_home = work.join("cargo-plan-home");
        let lock = generate_cargo_lock(door, &rust_obj, &manifest, source, &plan_home)?;
        let text = fs::read_to_string(lock)?;
        fs::create_dir_all(generated_path.parent().expect("cache parent"))?;
        fs::write(&generated_path, &text)?;
        (text, true)
    };
    let cargo_plan = crate::kernel::provider::crates::plan_cargo(&lock_text, &rust_version)?;
    let vendor_id = crate::kernel::provider::crates::vendor_object_id(&cargo_plan)?;
    Ok(RustPlanInputs {
        rust,
        extras,
        rust_version,
        rust_id,
        vendor_id,
        lock_text,
        generated_lock,
    })
}

fn prepare_rust(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    info: &ArchiveInfo,
    work: &Path,
    inputs: &RustPlanInputs,
) -> io::Result<(PathBuf, PathBuf)> {
    let _manifest_rel = info.cargo_manifest.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Rust build trigger found, but the sdist has no Cargo.toml",
        )
    })?;
    let rust_obj = crate::kernel::provider::rust::realize_toolchain(
        store,
        activity,
        platform,
        &inputs.rust,
        &inputs.extras,
    )?;
    let cargo_plan =
        crate::kernel::provider::crates::plan_cargo(&inputs.lock_text, &inputs.rust_version)?;
    let vendor_obj = crate::kernel::provider::crates::realize_vendor(store, activity, &cargo_plan)?;
    let cargo_home = work.join("cargo-home");
    fs::create_dir_all(&cargo_home)?;
    // An sdist's vendored crates can themselves come from git sources.
    fs::write(
        cargo_home.join("config.toml"),
        crate::kernel::provider::crates::tog_config_text_for(
            &vendor_obj,
            &crate::kernel::provider::crates::plan_git_sources(&cargo_plan),
        )?,
    )?;
    Ok((rust_obj, vendor_obj))
}

fn run_sdist_build(
    activity: &crate::kernel::activity::StoreActivity,
    platform: Platform,
    pkg: &LockedPackage,
    build_env: &Path,
    cpython_obj: &Path,
    input: &Path,
    work: &Path,
    outdir: &Path,
    rust: Option<&Path>,
    vendor: Option<&Path>,
    cargo_home: Option<&Path>,
    native_libs: Option<&Path>,
    build_plan: &Plan,
) -> io::Result<()> {
    let py = build_env.join("bin/python");
    let log = work.join("pip-build.log");
    let argv = vec![
        py.to_string_lossy().into_owned(),
        "-m".into(),
        "pip".into(),
        "--log".into(),
        log.to_string_lossy().into_owned(),
        "wheel".into(),
        "--no-deps".into(),
        "--no-build-isolation".into(),
        "--no-index".into(),
        "-w".into(),
        outdir.to_string_lossy().into_owned(),
        input.to_string_lossy().into_owned(),
    ];
    let mut envs = sdist_build_env(platform);
    let cores = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    envs.push(("MAKEFLAGS".into(), format!("-j{cores}")));
    if has_package(build_plan, "ninja") {
        envs.push(("CMAKE_GENERATOR".into(), "Ninja".into()));
    }
    let base_path = {
        let mut path = format!("{}:", build_env.join("bin").display());
        if let Some(rust) = rust {
            path.push_str(&format!("{}:", rust.join("bin").display()));
        }
        path.push_str("/usr/bin:/bin");
        path
    };
    if let Some(cargo_home) = cargo_home {
        envs.push(("CARGO_HOME".into(), cargo_home.display().to_string()));
        envs.push(("CARGO_NET_OFFLINE".into(), "true".into()));
    }
    if rust.is_some() {
        envs.push(("PYO3_PYTHON".into(), py.display().to_string()));
        // Required by pyo3 0.18 in tokenizers 0.13.x when the selected
        // interpreter is CPython 3.12.
        envs.push(("PYO3_USE_ABI3_FORWARD_COMPATIBILITY".into(), "1".into()));
    }
    envs.push(("PATH".into(), base_path));
    if let Some(native_libs) = native_libs {
        envs = crate::kernel::provider::nativelibs::compose_env(native_libs, &envs);
    }
    let path = envs
        .iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "/usr/bin:/bin".to_string());
    let sb = Sandbox {
        read: vec![build_env, cpython_obj]
            .into_iter()
            .chain(rust)
            .chain(vendor)
            .chain(native_libs)
            .collect(),
        write: vec![work],
        host_view: crate::kernel::sandbox::HostView::Full,
    };
    crate::kernel::sandbox::run_build_spec_on_with_activity(
        platform,
        &crate::kernel::sandbox::BuildSpec {
            argv,
            cwd: work.to_path_buf(),
            env: envs,
            read: sb.read.iter().map(|path| path.to_path_buf()).collect(),
            write: sb.write.iter().map(|path| path.to_path_buf()).collect(),
            scratch: work.to_path_buf(),
            path,
            host_view: crate::kernel::sandbox::HostView::Full,
        },
        activity,
    )
    .map_err(|error| wrap_sandbox_build_error_with_tail(pkg, error, stderr_tail(&log)))
}

/// Build the wheel for an sdist without a runtime numpy constraint. Normal
/// project realization calls the depth-aware form with its complete Plan.
pub fn build_sdist_wheel(
    door: &mut ResolutionDoor<'_>,
    pkg: &LockedPackage,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    build_sdist_wheel_at_depth(door, pkg, selected, None, None, 0)
}

/// Public runtime-aware entry point for callers that are building one sdist
/// outside a complete environment realization (for example, an integration
/// test). Normal project sync supplies this automatically from its Plan.
pub fn build_sdist_wheel_with_runtime_plan(
    door: &mut ResolutionDoor<'_>,
    pkg: &LockedPackage,
    selected: &Selected,
    runtime_plan: &Plan,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    build_sdist_wheel_at_depth(door, pkg, selected, None, Some(runtime_plan), 0)
}

/// Turn a git dependency into an ordinary sdist package: realize the commit,
/// pack the (sub)directory deterministically, and put it in the artifact cache
/// so `download_verified_held` finds it without touching the network.
///
/// Everything after this is the normal sdist path — build-system inspection,
/// isolated build environments, native libraries, derivation identity — and
/// the archive's hash is a pure function of the tree, so the same commit
/// always produces the same wheel identity.
pub(crate) fn git_sdist_package(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    pkg: &LockedPackage,
) -> io::Result<LockedPackage> {
    let source = pkg.git.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not a git dependency", pkg.name),
        )
    })?;
    let object = crate::kernel::gitsrc::ensure_git_source(store, activity, source)?;
    let root = match &source.subdirectory {
        Some(subdir) => {
            if subdir.contains("..") || subdir.starts_with('/') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: unsafe subdirectory {subdir:?}", pkg.name),
                ));
            }
            object.join(subdir)
        }
        None => object,
    };
    if !root.join("pyproject.toml").is_file()
        && !root.join("setup.py").is_file()
        && !root.join("setup.cfg").is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: git source at {} has no pyproject.toml, setup.py or setup.cfg",
                pkg.name, source.commit
            ),
        ));
    }
    let (sha256, filename) = crate::kernel::gitsrc::pack_checkout(
        store,
        activity,
        platform,
        &root,
        &pkg.name,
        &pkg.version,
    )?;
    Ok(LockedPackage {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        filename,
        // Informational: the bytes are already cached under their hash, so the
        // fetch path never dials out for this URL.
        url: format!("git+{}@{}", source.url, source.commit),
        sha256,
        kind: crate::kernel::types::ArtifactKind::Sdist,
        git: None,
    })
}

pub(crate) fn build_sdist_wheel_at_depth(
    door: &mut ResolutionDoor<'_>,
    pkg: &LockedPackage,
    selected: &Selected,
    rust: Option<&Selected>,
    runtime_plan: Option<&Plan>,
    depth: usize,
) -> io::Result<PathBuf> {
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    crate::tailors::install_kinds();
    admit_sdist_build(platform, pkg, depth)?;
    let python = crate::tailors::python::cpython_identity_input(selected, platform)?;

    // One lease for the whole build: the archive children, the staged work
    // directory and the Cargo run all borrow it.
    let sdist = download_verified_held(store, activity, &pkg.url, &pkg.sha256)?;
    let info = build_requires::inspect_sdist_for(activity, &sdist)?;
    // A Rust source needs the new schema even if its Python backend only
    // declares setuptools/wheel, because rust/vendor are identity inputs.
    let fast_requirements = build_requires::fast_path(&info.build_requires);
    let fast_sdist = fast_requirements
        && !info.rust_build
        && (!info.native_build || !native_libs_supported(platform));
    let fast_identity = sdist_identity(platform, pkg, &python);
    if fast_sdist {
        let fast_id = fast_identity.object_id();
        if store.has_with_activity(activity, &fast_id)? {
            crate::kernel::policy::check_cached_with_activity(store, activity, &fast_id)?;
            return find_wheel(&store.object_path(&fast_id));
        }
    }
    let build_plan = if fast_requirements {
        build_toolchain_plan(selected.version("cpython")?)
    } else {
        build_requires::resolve_build_plan(door, selected, &info.build_requires, runtime_plan)?
    };
    // The nested build environment may fetch its own artifacts. Do not hold
    // this sdist's cache lease while it acquires the same GC lock.
    drop(sdist);
    let build_env = super::env::realize_env_at_depth(door, &build_plan, selected, rust, depth)?;
    // Native library identity is pure. Realization is deferred until after
    // the wheel cache lookup, so planning never downloads the libset.
    let native_libs_id =
        native_libs_identity_id(store, platform, info.native_build, fast_requirements)?;
    // Re-verify and reacquire the lease for the actual copy/extraction below,
    // so gc cannot collect the cached artifact while it is being used.
    let sdist = download_verified_held(store, activity, &pkg.url, &pkg.sha256)?;

    let work = store.stage_with_activity(activity)?;
    let outdir = work.join("out");
    fs::create_dir_all(&outdir)?;
    let sdist_named = stage_sdist_copy(&sdist, &work, pkg)?;

    let source = if info.rust_build {
        Some(build_requires::extract_sdist_for(
            activity,
            &sdist,
            &work.join("source"),
            &info,
        )?)
    } else {
        None
    };
    // The archive has been copied/extracted. Toolchain realization below can
    // fetch more cache entries, so release this lease before it starts.
    drop(sdist);
    let rust_inputs = if let Some(source) = &source {
        Some(rust_plan_inputs(
            door,
            rust,
            sdist_rust_default(selected),
            &pkg.sha256,
            source,
            &info,
            &work,
        )?)
    } else {
        None
    };
    let identity = sdist_build_identity(
        platform,
        pkg,
        &python,
        &build_env,
        rust_inputs.as_ref(),
        fast_sdist,
        fast_identity,
        native_libs_id.as_deref(),
    )?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        let _ = crate::kernel::store::remove_tree(&work);
        return find_wheel(&store.object_path(&id));
    }

    let native_libs = if native_libs_id.is_some() {
        Some(crate::kernel::provider::nativelibs::ensure_native_libs(
            store, activity, platform,
        )?)
    } else {
        None
    };

    record_generated_cargo_lock(&info, rust_inputs.as_ref())?;

    let (rust, vendor, cargo_home) = if let Some(inputs) = &rust_inputs {
        let (rust, vendor) = prepare_rust(store, activity, platform, &info, &work, inputs)?;
        (Some(rust), Some(vendor), Some(work.join("cargo-home")))
    } else {
        (None, None, None)
    };

    let cpython_obj = crate::tailors::python::realize_runtime(store, activity, platform, selected)?;
    let input = source.as_deref().unwrap_or(&sdist_named);
    run_sdist_build(
        activity,
        platform,
        pkg,
        &build_env,
        &cpython_obj,
        input,
        &work,
        &outdir,
        rust.as_deref(),
        vendor.as_deref(),
        cargo_home.as_deref(),
        native_libs.as_ref().map(|set| set.path.as_path()),
        &build_plan,
    )?;

    let built = single_built_wheel(&outdir, pkg)?;
    commit_built_wheel(
        store,
        activity,
        &identity,
        &built,
        &work,
        &cpython_obj,
        &build_env,
        pkg,
        rust_inputs.as_ref(),
        native_libs.as_ref().map(|set| set.path.as_path()),
    )
}

/// Everything that must hold before the build touches the network: the
/// recursion cap and the host check.
fn admit_sdist_build(platform: Platform, pkg: &LockedPackage, depth: usize) -> io::Result<()> {
    if depth > 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sdist build requirement recursion depth exceeded 3 while building {}=={}",
                pkg.name, pkg.version
            ),
        ));
    }
    crate::kernel::platform::require_host(platform, "sdist build")
}

/// Copy the verified archive into the work tree under its locked filename.
fn stage_sdist_copy(sdist: &Path, work: &Path, pkg: &LockedPackage) -> io::Result<PathBuf> {
    if pkg.filename.contains('/')
        || pkg.filename.contains('\\')
        || pkg.filename.contains("..")
        || pkg.filename.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsafe sdist filename: {:?}", pkg.filename),
        ));
    }
    let sdist_named = work.join(&pkg.filename);
    fs::copy(sdist, &sdist_named)?;
    Ok(sdist_named)
}

/// The identity of the wheel this build will produce. A Rust source adds
/// the toolchain and vendor ids; a fast-path source reuses the identity the
/// caller already probed the cache with, which deliberately does not name
/// the build environment.
#[allow(clippy::too_many_arguments)]
fn sdist_build_identity(
    platform: Platform,
    pkg: &LockedPackage,
    python: &str,
    build_env: &Path,
    rust_inputs: Option<&RustPlanInputs>,
    fast_sdist: bool,
    fast_identity: Identity,
    native_libs_id: Option<&str>,
) -> io::Result<Identity> {
    if let Some(rust) = rust_inputs {
        return Ok(isolated_sdist_identity_from_ids(
            platform,
            pkg,
            python,
            &object_id(build_env, "build environment")?,
            Some(&rust.rust_id),
            Some(&rust.vendor_id),
            native_libs_id,
        ));
    }
    if fast_sdist {
        return Ok(fast_identity);
    }
    Ok(isolated_sdist_identity_from_ids(
        platform,
        pkg,
        python,
        &object_id(build_env, "build environment")?,
        None,
        None,
        native_libs_id,
    ))
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let pin = crate::tailors::python::lookup(platform, "3.12.14")
        .expect("pinned CPython for test platform");
    let pkg = LockedPackage {
        name: "example".into(),
        version: "1.0.0".into(),
        filename: "example-1.0.0.tar.gz".into(),
        url: "https://files.pythonhosted.org/example.tar.gz".into(),
        sha256: "a".repeat(64),
        kind: ArtifactKind::Sdist,
        git: None,
    };
    let python = format!("{}:{}", pin.version, pin.sha256);
    let selected = crate::tailors::python::shipped_selection(pin.version)
        .expect("shipped release for the pinned CPython");
    let schema_two = sdist_identity(platform, &pkg, &python);
    let isolated = sdist_build_identity(
        platform,
        &pkg,
        &python,
        Path::new("build-env-object"),
        None,
        false,
        schema_two.clone(),
        None,
    )
    .expect("generic isolated sdist identity");
    let rust_inputs = RustPlanInputs {
        rust: crate::kernel::provider::rust::shipped_selection("1.96.1")
            .expect("shipped Rust release"),
        extras: Default::default(),
        rust_version: "1.96.1".into(),
        rust_id: "rust-object".into(),
        vendor_id: "vendor-object".into(),
        lock_text: String::new(),
        generated_lock: false,
    };
    let isolated_rust = sdist_build_identity(
        platform,
        &pkg,
        &python,
        Path::new("build-env-object"),
        Some(&rust_inputs),
        false,
        schema_two.clone(),
        None,
    )
    .expect("Rust isolated sdist identity");
    let mut cases = vec![schema_two, isolated, isolated_rust];
    if platform == Platform::X86_64UnknownLinuxGnu {
        let (_store_dir, store) = test_store("matrix-native");
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let native_pkg = local_native_sdist_for_test(&store, "matrix-native");
        let planned = plan_sdist_identity_input(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                activity,
                platform,
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &native_pkg,
            &selected,
            None,
            None,
        )
        .expect("native sdist identity plan");
        cases.push(planned.identity);
    } else if platform.is_macos() {
        let (_store_dir, store) = test_store("matrix-rust-darwin");
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let rust_pkg = local_rust_sdist_for_test(&store, "matrix-rust-darwin");
        let planned = plan_sdist_identity_input(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                activity,
                platform,
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &rust_pkg,
            &selected,
            None,
            None,
        )
        .expect("Darwin Rust sdist identity plan");
        // Cargo.toml makes info.rust_build true, so plan_sdist_identity_input
        // takes the isolated-build path even though Darwin has no native-libs pin.
        assert_eq!(planned.identity.inputs["schema"], "sdist-build/4");
        cases.push(planned.identity);
    }
    cases
}

/// A Cargo.lock we generated ourselves is not what the sdist attested to.
fn record_generated_cargo_lock(
    info: &ArchiveInfo,
    rust_inputs: Option<&RustPlanInputs>,
) -> io::Result<()> {
    let Some(rust) = rust_inputs else {
        return Ok(());
    };
    if !rust.generated_lock {
        return Ok(());
    }
    let manifest = info
        .cargo_manifest
        .as_ref()
        .expect("Rust source has a Cargo manifest");
    crate::kernel::policy::record(
        crate::kernel::policy::UNATTESTED_CARGO_LOCK,
        &manifest.display().to_string(),
        "Cargo.lock was generated by store Cargo outside the build sandbox",
    )
}

/// The one wheel the build was supposed to leave in `outdir`.
fn single_built_wheel(outdir: &Path, pkg: &LockedPackage) -> io::Result<PathBuf> {
    let wheels: Vec<_> = fs::read_dir(outdir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|ext| ext == "whl").unwrap_or(false))
        .collect();
    if wheels.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}=={}: expected exactly 1 built wheel, found {}",
                pkg.name,
                pkg.version,
                wheels.len()
            ),
        ));
    }
    Ok(wheels[0].clone())
}

/// Stage the built wheel, drop the work tree, and commit the object with
/// everything the build read as a dependency.
#[allow(clippy::too_many_arguments)]
fn commit_built_wheel(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
    built: &Path,
    work: &Path,
    cpython_obj: &Path,
    build_env: &Path,
    pkg: &LockedPackage,
    rust_inputs: Option<&RustPlanInputs>,
    native_libs: Option<&Path>,
) -> io::Result<PathBuf> {
    let staged = store.stage_with_activity(activity)?;
    fs::copy(built, staged.join(built.file_name().unwrap()))?;
    let _ = crate::kernel::store::remove_tree(work);
    let candidate = crate::kernel::policy::object_exceptions();
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(cpython_obj)?)?;
    deps.object_id(&crate::kernel::store::object_id_from_path(build_env)?)?;
    deps.cache_digest(Digest::sha256(&pkg.sha256)?);
    if let Some(inputs) = rust_inputs {
        deps.object_id(&inputs.rust_id)?;
        deps.object_id(&inputs.vendor_id)?;
    }
    if let Some(native_libs) = native_libs {
        deps.object_id(&crate::kernel::store::object_id_from_path(native_libs)?)?;
    }
    let (object, _) =
        store.commit_with_activity_and_deps(activity, identity, &staged, &candidate, &deps)?;
    find_wheel(&object)
}

fn find_wheel(dir: &Path) -> io::Result<PathBuf> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().map(|ext| ext == "whl").unwrap_or(false) {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no wheel found in {}", dir.display()),
    ))
}

/// Realize the pinned setuptools/pip/wheel environment used by sandboxed
/// metadata probes such as `setup.py egg_info`.
pub fn ensure_build_environment(
    door: &mut ResolutionDoor<'_>,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    super::env::realize_env_for(
        door,
        &build_toolchain_plan(selected.version("cpython")?),
        selected,
    )
}

#[cfg(test)]
mod tests {
    /// A project that locks Rust builds its sdists' Rust extensions on that
    /// selection: the `rust` input is the locked object's id, not the one the
    /// shipped pin would give. A lock naming the shipped release changes
    /// nothing, so every existing `sdist-build/4` id is kept.
    #[test]
    fn a_locked_rust_selection_is_the_rust_an_sdist_builds_with() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        crate::tailors::install_kinds();
        let platform = crate::kernel::platform::Platform::host().unwrap();
        let (_store_dir, store) = super::test_store("locked-rust");
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let pkg = super::local_rust_sdist_for_test(&store, "locked-rust");
        let python =
            crate::tailors::python::shipped_selection("3.12.14").expect("shipped CPython release");
        let plan = |rust: Option<&crate::kernel::toolchain::Selected>| {
            super::plan_sdist_identity_input(
                &mut crate::kernel::testutil::DoorScope::new().door(
                    &store,
                    activity,
                    platform,
                    crate::kernel::resolve::DoorKind::Planner,
                ),
                &pkg,
                &python,
                rust,
                None,
            )
            .expect("Rust sdist identity plan")
            .identity
        };
        let rust_id = |selected: &crate::kernel::toolchain::Selected| {
            crate::kernel::provider::rust::runtime_object_id(platform, selected).unwrap()
        };

        // With no lock and no toolchain file, the sdist builds with the
        // shipped default.
        let shipped_rust = crate::kernel::toolchain::shipped(
            &crate::kernel::provider::rust::toolchain_catalog().unwrap(),
        )
        .unwrap();
        let unlocked = plan(None);
        assert_eq!(unlocked.inputs["schema"], "sdist-build/4");
        assert_eq!(unlocked.inputs["rust"], rust_id(&shipped_rust));
        assert_eq!(plan(Some(&shipped_rust)).inputs, unlocked.inputs);

        // Under a Python lock that locks no Rust, an sdist with no channel
        // of its own builds on the Rust the Python section pins. A section
        // from before the pin keeps 1.96.1, the Rust its wheels were built
        // with, so their ids do not move with the catalog's default.
        let pinned = |version: &str| {
            let mut locked_python = python.clone();
            locked_python
                .helpers
                .insert("rust".into(), version.to_string());
            super::plan_sdist_identity_input(
                &mut crate::kernel::testutil::DoorScope::new().door(
                    &store,
                    activity,
                    platform,
                    crate::kernel::resolve::DoorKind::Planner,
                ),
                &pkg,
                &locked_python,
                None,
                None,
            )
            .expect("Rust sdist identity plan")
            .identity
        };
        let legacy = pinned(super::LEGACY_SDIST_RUST);
        assert_eq!(
            legacy.inputs["rust"],
            crate::kernel::provider::rust::rust_object_id(platform, "1.96.1").unwrap()
        );
        assert!(legacy.inputs["rust"].ends_with("-rust-1.96.1"));
        assert_ne!(legacy.object_id(), unlocked.object_id());

        // A lock written before pins pins nothing, and the wheel it builds
        // keeps the id the tog before pins gave it, byte for byte. The
        // literal is what main (df5650e) computes for this fixture, where
        // every sdist built on 1.96.1, with the one store-dependent input
        // (the build environment's id covers the store root) fixed.
        let mut pinless = python.clone();
        pinless.source = crate::kernel::toolchain::Source::Lock;
        assert!(pinless.helpers.is_empty());
        let pinless = super::plan_sdist_identity_input(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                activity,
                platform,
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &pkg,
            &pinless,
            None,
            None,
        )
        .expect("Rust sdist identity plan")
        .identity;
        assert_eq!(pinless.object_id(), legacy.object_id());
        if platform == crate::kernel::platform::Platform::X86_64UnknownLinuxGnu {
            let mut fixed = pinless.clone();
            fixed
                .inputs
                .insert("build_env".into(), "store-independent".into());
            assert_eq!(
                fixed.object_id(),
                "5582557b082e53e3a8d47b1ec286cc51867bd86c-locked-rust-1.0"
            );
        }
        let today = pinned(shipped_rust.version("rustc").unwrap());
        assert_eq!(today.inputs, unlocked.inputs);

        // A lock whose rustc row names other bytes than today's pin.
        let mut locked = shipped_rust.clone();
        locked.source = crate::kernel::toolchain::Source::Lock;
        for row in &mut locked.bundle.artifacts {
            if row.component == "rustc" && row.platform == platform {
                row.digest = crate::kernel::fetch::Digest::sha256(&"e".repeat(64)).unwrap();
            }
        }
        let planned = plan(Some(&locked));
        assert_eq!(planned.inputs["rust"], rust_id(&locked));
        assert_ne!(planned.inputs["rust"], unlocked.inputs["rust"]);
        assert_ne!(planned.object_id(), unlocked.object_id());
        assert_eq!(
            crate::kernel::objmeta::check_identity_grammar(&planned),
            Ok(())
        );
    }

    /// The local sdist fixtures are byte-identical across stores and runs,
    /// so every identity derived from them is reproducible; on Linux the
    /// planned native sdist identity is checked input for input.
    #[test]
    fn local_sdist_fixtures_are_reproducible_across_stores() {
        // Planning inspects the archive through a supervised child; the
        // process supervises one child at a time.
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_first_dir, first_store) = super::test_store("repro-first");
        let first_store_activity = &first_store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let (_second_dir, second_store) = super::test_store("repro-second");
        let second_store_activity = &second_store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let first = super::local_native_sdist_for_test(&first_store, "matrix-native");
        let second = super::local_native_sdist_for_test(&second_store, "matrix-native");
        assert_eq!(
            first.sha256, second.sha256,
            "native sdist archive bytes differ"
        );
        let first_rust = super::local_rust_sdist_for_test(&first_store, "matrix-rust");
        let second_rust = super::local_rust_sdist_for_test(&second_store, "matrix-rust");
        assert_eq!(
            first_rust.sha256, second_rust.sha256,
            "Rust sdist archive bytes differ"
        );
        assert_eq!(
            super::deterministic_tar_gz("x-1.0", &[("b", "2"), ("a", "1")]),
            super::deterministic_tar_gz("x-1.0", &[("a", "1"), ("b", "2")]),
            "entry order leaked into the archive"
        );
        if let Ok(platform @ crate::kernel::platform::Platform::X86_64UnknownLinuxGnu) =
            crate::kernel::platform::Platform::host()
        {
            let selected = crate::tailors::python::shipped_selection("3.12.14")
                .expect("shipped CPython release");
            let planned_first = super::plan_sdist_identity_input(
                &mut crate::kernel::testutil::DoorScope::new().door(
                    &first_store,
                    first_store_activity,
                    platform,
                    crate::kernel::resolve::DoorKind::Planner,
                ),
                &first,
                &selected,
                None,
                None,
            )
            .expect("first native sdist plan");
            let planned_again = super::plan_sdist_identity_input(
                &mut crate::kernel::testutil::DoorScope::new().door(
                    &first_store,
                    first_store_activity,
                    platform,
                    crate::kernel::resolve::DoorKind::Planner,
                ),
                &first,
                &selected,
                None,
                None,
            )
            .expect("repeated native sdist plan");
            assert_eq!(planned_first.identity.inputs, planned_again.identity.inputs);
            assert_eq!(planned_first.input, planned_again.input);
            // The build-env and native-libs object ids are store-root
            // addressed, so only the archive-derived input is expected to
            // agree across two different stores.
            let planned_elsewhere = super::plan_sdist_identity_input(
                &mut crate::kernel::testutil::DoorScope::new().door(
                    &second_store,
                    second_store_activity,
                    platform,
                    crate::kernel::resolve::DoorKind::Planner,
                ),
                &second,
                &selected,
                None,
                None,
            )
            .expect("second-store native sdist plan");
            assert_eq!(
                planned_first.identity.inputs["sdist_sha256"],
                planned_elsewhere.identity.inputs["sdist_sha256"]
            );
        }
    }

    use super::*;

    #[test]
    fn darwin_identity_unchanged() {
        assert_eq!(
            derivation_fingerprint(),
            "sdist-build/2;toolchain:71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e,51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670,3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab"
        );
    }

    #[test]
    fn darwin_sdist_identity_unchanged() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pkg = LockedPackage {
            name: "docopt".into(),
            version: "0.6.2".into(),
            filename: "docopt-0.6.2.tar.gz".into(),
            url: "https://files.pythonhosted.org/packages/a2/55/8f8cab2afd404cf578136ef2cc5dfb50baa1761b68c9da1fb1e4eed343c9/docopt-0.6.2.tar.gz".into(),
            sha256: "49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491".into(),
            kind: ArtifactKind::Sdist,
                git: None,
        };
        let pin = crate::tailors::python::lookup(Platform::Aarch64AppleDarwin, "3.12.14").unwrap();
        let identity = sdist_identity(
            Platform::Aarch64AppleDarwin,
            &pkg,
            &format!("{}:{}", pin.version, pin.sha256),
        );
        assert_eq!(
            identity.object_id(),
            "a26c6aa7246296eac77249f89a9faed77175eb16-docopt-0.6.2"
        );
    }

    #[test]
    fn darwin_native_sdist_identity_does_not_realize_native_libs() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (_store_dir, store) = test_store("darwin-native");
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let pkg = local_native_sdist_for_test(&store, "darwin-native");
        let planned = plan_sdist_identity_input(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                activity,
                Platform::Aarch64AppleDarwin,
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &pkg,
            &crate::tailors::python::shipped_selection("3.12.14").unwrap(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            sdist_identity_input(
                &store,
                Platform::Aarch64AppleDarwin,
                &pkg,
                &crate::tailors::python::shipped_selection("3.12.14").unwrap(),
                None,
            )
            .unwrap(),
            planned.input
        );
        assert!(planned.native_libs_id.is_none());
        assert_eq!(
            planned.input,
            format!("Sdist:{}:{}", pkg.sha256, derivation_fingerprint())
        );
    }

    #[test]
    fn isolated_identity_has_schema_four_and_build_env() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
            git: None,
        };
        let pin = crate::tailors::python::lookup(Platform::Aarch64AppleDarwin, "3.12.14").unwrap();
        let identity = isolated_sdist_identity_from_ids(
            Platform::Aarch64AppleDarwin,
            &pkg,
            &format!("{}:{}", pin.version, pin.sha256),
            "build-env-id",
            None,
            None,
            None,
        );
        assert_eq!(
            identity.object_id(),
            "680f5a153ffb1ff5a87d00bf0b051031f22072c0-example-1.0"
        );
        assert_eq!(identity.inputs["schema"], "sdist-build/4");
        assert_eq!(identity.inputs["build_env"], "build-env-id");
        assert_eq!(identity.inputs["build_mode"], BUILD_MODE_PLAIN);
        assert_eq!(identity.inputs["native_mode"], NATIVE_MODE_NONE);
    }

    /// `sdist-build/4` golden, on both platforms, from fixed inputs. The
    /// identity constructor is a pure function of its platform argument, so
    /// the Darwin value is computed here and the macOS gate only confirms
    /// it. The `/3` spelling of the same build is a different object id, so
    /// the bump reissues every isolated build; and the drift `/3` could not
    /// see — losing both halves of a pair — is a contract error under `/4`.
    #[test]
    fn isolated_identity_goldens_and_dropped_pairs() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        crate::tailors::install_kinds();
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
            git: None,
        };
        for (platform, native, golden) in [
            (
                Platform::X86_64UnknownLinuxGnu,
                Some("native-libs-object"),
                "875ff008bc85acd29b9c84db443abf7661be73bd-example-1.0",
            ),
            (
                Platform::Aarch64AppleDarwin,
                None,
                "cd380e0c765b7051f9521fae34ba072efe78641c-example-1.0",
            ),
        ] {
            let pin = crate::tailors::python::lookup(platform, "3.12.14").unwrap();
            let identity = isolated_sdist_identity_from_ids(
                platform,
                &pkg,
                &format!("{}:{}", pin.version, pin.sha256),
                "build-env-object",
                Some("rust-object"),
                Some("vendor-object"),
                native,
            );
            assert_eq!(identity.inputs["schema"], "sdist-build/4");
            assert_eq!(identity.inputs["build_mode"], BUILD_MODE_RUST);
            assert_eq!(
                identity.inputs["native_mode"],
                match native {
                    Some(_) => NATIVE_MODE_LIBS,
                    None => NATIVE_MODE_NONE,
                }
            );
            assert_eq!(identity.object_id(), golden, "{}", platform.triple());
            assert_eq!(
                crate::kernel::objmeta::check_identity_grammar(&identity),
                Ok(())
            );

            // The same build under `sdist-build/3`: a different object id,
            // which is the store-wide rebuild this bump accepts.
            let mut old = identity.clone();
            old.inputs.insert("schema".into(), "sdist-build/3".into());
            old.inputs.remove("build_mode");
            old.inputs.remove("native_mode");
            assert_ne!(old.object_id(), identity.object_id());

            // The drift `/3` could not see, in both spellings.
            let mut no_rust = identity.clone();
            no_rust.inputs.remove("rust");
            no_rust.inputs.remove("vendor");
            let reason = crate::kernel::objmeta::check_identity_grammar(&no_rust).unwrap_err();
            assert!(reason.contains("sdist build_mode relation"), "{reason}");
            if native.is_some() {
                let mut no_native = identity.clone();
                no_native.inputs.remove("native_libs");
                no_native.inputs.remove("native_linker");
                let reason =
                    crate::kernel::objmeta::check_identity_grammar(&no_native).unwrap_err();
                assert!(reason.contains("sdist native_mode relation"), "{reason}");
            }
        }
    }

    #[test]
    fn recursion_cap_is_loud() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
            git: None,
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        let error = build_sdist_wheel_at_depth(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &Store {
                    root: PathBuf::from("/does/not/matter"),
                },
                activity,
                Platform::Aarch64AppleDarwin,
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &pkg,
            &crate::tailors::python::shipped_selection("3.12.14").unwrap(),
            None,
            None,
            4,
        )
        .unwrap_err();
        assert!(error.to_string().contains("recursion depth exceeded 3"));
    }

    /// The host check comes before the pin lookup and before any fetch, so a
    /// cross-platform build fails without touching the store or the network.
    #[test]
    fn a_foreign_platform_is_refused_before_any_fetch() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let host = Platform::host().unwrap();
        let foreign = if host == Platform::Aarch64AppleDarwin {
            Platform::X86_64UnknownLinuxGnu
        } else {
            Platform::Aarch64AppleDarwin
        };
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: "https://example.invalid/example-1.0.tar.gz".into(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
            git: None,
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        let error = build_sdist_wheel_at_depth(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &Store {
                    root: PathBuf::from("/does/not/matter"),
                },
                activity,
                foreign,
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &pkg,
            &crate::tailors::python::shipped_selection("3.12.14").unwrap(),
            None,
            None,
            0,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error.to_string().starts_with("cannot realize sdist build"),
            "{error}"
        );
    }

    #[test]
    fn build_sdist_preserves_unsupported_kind() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: "https://example.invalid/example.tar.gz".into(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
            git: None,
        };
        let error = wrap_sandbox_build_error(
            &pkg,
            io::Error::new(io::ErrorKind::Unsupported, "injected sandbox failure"),
        );
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("sandboxed build"));
    }

    #[test]
    fn linux_sdist_build_uses_host_compilers() {
        assert_eq!(
            sdist_build_env(Platform::X86_64UnknownLinuxGnu),
            vec![
                ("CC".into(), "gcc".into()),
                ("CXX".into(), "g++".into()),
                ("LDSHARED".into(), "gcc -shared".into()),
            ]
        );
        assert!(sdist_build_env(Platform::Aarch64AppleDarwin).is_empty());
    }
}

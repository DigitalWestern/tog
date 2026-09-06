//! Sandboxed sdist to wheel builds. PEP 517 build dependencies are inspected
//! without execution and, when needed, realized as a separate Python env.

use crate::build_requires::{self, ArchiveInfo};
use crate::fetch::download_verified_held;
use crate::platform::{no_pin, Platform};
use crate::project;
use crate::sandbox::Sandbox;
use crate::store::Store;
use crate::types::{ArtifactKind, Identity, LockedPackage, Plan};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    BUILD_TOOLCHAIN.iter().map(|tool| tool.4).collect::<Vec<_>>().join(",")
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

fn sdist_identity(platform: Platform, pkg: &LockedPackage, pin: &crate::python::PinnedPython) -> Identity {
    Identity {
        kind: "sdist-build".into(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        inputs: BTreeMap::from([
            ("schema".into(), "sdist-build/2".into()),
            ("sdist_sha256".into(), pkg.sha256.clone()),
            ("python".into(), format!("{}:{}", pin.version, pin.sha256)),
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{label} has no object id")))
}

fn isolated_sdist_identity_from_ids(
    platform: Platform,
    pkg: &LockedPackage,
    pin: &crate::python::PinnedPython,
    build_env_id: &str,
    rust_id: Option<&str>,
    vendor_id: Option<&str>,
    native_libs_id: Option<&str>,
) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".into(), "sdist-build/3".into()),
        ("sdist_sha256".into(), pkg.sha256.clone()),
        ("python".into(), format!("{}:{}", pin.version, pin.sha256)),
        ("platform".into(), platform.triple().into()),
        ("build_env".into(), build_env_id.into()),
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
        packages: BUILD_TOOLCHAIN.iter().map(|(name, version, filename, url, sha)| LockedPackage {
            name: (*name).into(),
            version: (*version).into(),
            filename: (*filename).into(),
            url: (*url).into(),
            sha256: (*sha).into(),
            kind: ArtifactKind::Wheel,
        }).collect(),
    }
}

fn has_package(plan: &Plan, wanted: &str) -> bool {
    plan.packages.iter().any(|pkg| {
        pkg.name.chars()
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
        Ok(Some(crate::nativelibs::object_id_for(store, platform)?))
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
}

/// Return the exact package input used by a parent Python environment. This
/// performs only archive inspection plus deterministic input planning; the
/// actual wheel build still happens in `build_sdist_wheel_at_depth`.
pub(crate) fn plan_sdist_identity_input(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    python_version: &str,
    runtime_plan: Option<&Plan>,
) -> io::Result<SdistIdentityPlan> {
    let pin = crate::python::lookup(platform, python_version)
        .ok_or_else(|| no_pin(&format!("cpython {python_version}"), platform, "stage 2"))?;
    let sdist = download_verified_held(store, &pkg.url, &pkg.sha256)?;
    let info = build_requires::inspect_sdist(&sdist)?;
    let fast_requirements = build_requires::fast_path(&info.build_requires);
    let fast_sdist = fast_requirements
        && !info.rust_build
        && (!info.native_build || !native_libs_supported(platform));
    if fast_sdist {
        return Ok(SdistIdentityPlan {
            input: format!("Sdist:{}:{}", pkg.sha256, derivation_fingerprint()),
            native_libs_id: None,
        });
    }

    let build_plan = if fast_requirements {
        build_toolchain_plan(&pin.version)
    } else {
        build_requires::resolve_build_plan(
            store,
            platform,
            &pin.version,
            &info.build_requires,
            runtime_plan,
        )?
    };
    // Planning the nested environment may inspect more sdists and acquire
    // the same GC lock.
    drop(sdist);
    let build_env_id = crate::project::planned_env_object_id(store, platform, &build_plan)?;
    let native_libs_id = native_libs_identity_id(store, platform, info.native_build, fast_requirements)?;
    let identity = if info.rust_build {
        let work = store.stage()?;
        let result: io::Result<Identity> = (|| {
            let sdist = download_verified_held(store, &pkg.url, &pkg.sha256)?;
            let source = build_requires::extract_sdist(&sdist, &work.join("source"), &info)?;
            drop(sdist);
            let rust = rust_plan_inputs(store, platform, &pkg.sha256, &source, &info, &work)?;
            Ok(isolated_sdist_identity_from_ids(
                platform,
                pkg,
                pin,
                &build_env_id,
                Some(&rust.rust_id),
                Some(&rust.vendor_id),
                native_libs_id.as_deref(),
            ))
        })();
        let _ = crate::store::remove_tree(&work);
        result?
    } else {
        isolated_sdist_identity_from_ids(
            platform,
            pkg,
            pin,
            &build_env_id,
            None,
            None,
            native_libs_id.as_deref(),
        )
    };
    Ok(SdistIdentityPlan {
        input: format!("Sdist:{}:{}", pkg.sha256, identity.object_id()),
        native_libs_id,
    })
}

#[cfg(test)]
pub(crate) fn sdist_identity_input(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    python_version: &str,
    runtime_plan: Option<&Plan>,
) -> io::Result<String> {
    Ok(plan_sdist_identity_input(store, platform, pkg, python_version, runtime_plan)?.input)
}

fn stderr_tail(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let lines: Vec<_> = text.lines().collect();
    Some(lines[lines.len().saturating_sub(40)..].join("\n"))
}

fn cargo_lock_for(source: &Path, manifest: &Path) -> Option<PathBuf> {
    [manifest.parent().map(|parent| parent.join("Cargo.lock")), Some(source.join("Cargo.lock"))]
        .into_iter().flatten().find(|path| path.is_file())
}

fn cargo_lock_cache_key(sdist_sha256: &str, rust_id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{sdist_sha256}\0{rust_id}").as_bytes()))
}

fn generated_cargo_lock_path(source: &Path, manifest: &Path) -> PathBuf {
    source
        .join(manifest.parent().unwrap_or_else(|| Path::new("")))
        .join("Cargo.lock")
}

fn generate_cargo_lock(
    rust_obj: &Path,
    manifest: &Path,
    source: &Path,
    cargo_home: &Path,
) -> io::Result<PathBuf> {
    fs::create_dir_all(cargo_home)?;
    let cargo = rust_obj.join("bin/cargo");
    let path_var = format!("{}:/usr/bin:/bin", rust_obj.join("bin").display());
    let status = Command::new(&cargo)
        .args(["generate-lockfile", "--manifest-path"]).arg(manifest)
        .current_dir(source)
        .env("CARGO_HOME", cargo_home)
        .env("PATH", path_var)
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN")
        .status()
        .map_err(|e| io::Error::new(e.kind(), format!("run store cargo to generate Cargo.lock: {e}")))?;
    if !status.success() {
        return Err(io::Error::other("store cargo generate-lockfile failed for the sdist"));
    }
    cargo_lock_for(source, manifest).ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData,
        "store cargo generated no Cargo.lock next to the sdist manifest",
    ))
}

struct RustPlanInputs {
    rust_version: String,
    rust_id: String,
    vendor_id: String,
    lock_text: String,
    generated_lock: bool,
}

fn rust_plan_inputs(
    store: &Store,
    platform: Platform,
    sdist_sha256: &str,
    source: &Path,
    info: &ArchiveInfo,
    work: &Path,
) -> io::Result<RustPlanInputs> {
    let manifest_rel = info.cargo_manifest.as_ref().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData,
        "Rust build trigger found, but the sdist has no Cargo.toml",
    ))?;
    let manifest = source.join(manifest_rel);
    let rust_version = crate::cargo::resolve_toolchain(platform, source)?.to_string();
    let rust_id = crate::cargo::rust_object_id(platform, &rust_version)?;
    let generated_path = store.cache_path(
        "cargo-lock",
        &cargo_lock_cache_key(sdist_sha256, &rust_id),
    );
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
        let rust_obj = crate::cargo::ensure_rust_for(store, platform, &rust_version)?;
        let plan_home = work.join("cargo-plan-home");
        let lock = generate_cargo_lock(&rust_obj, &manifest, source, &plan_home)?;
        let text = fs::read_to_string(lock)?;
        fs::create_dir_all(generated_path.parent().expect("cache parent"))?;
        fs::write(&generated_path, &text)?;
        (text, true)
    };
    let cargo_plan = crate::cargo::plan_cargo(&lock_text, &rust_version)?;
    let vendor_id = crate::cargo::vendor_object_id(&cargo_plan)?;
    Ok(RustPlanInputs {
        rust_version,
        rust_id,
        vendor_id,
        lock_text,
        generated_lock,
    })
}

fn prepare_rust(
    store: &Store,
    platform: Platform,
    info: &ArchiveInfo,
    work: &Path,
    inputs: &RustPlanInputs,
) -> io::Result<(PathBuf, PathBuf)> {
    let _manifest_rel = info.cargo_manifest.as_ref().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData,
        "Rust build trigger found, but the sdist has no Cargo.toml",
    ))?;
    let rust_obj = crate::cargo::ensure_rust_for(store, platform, &inputs.rust_version)?;
    let cargo_plan = crate::cargo::plan_cargo(&inputs.lock_text, &inputs.rust_version)?;
    let vendor_obj = crate::cargo::realize_vendor(store, &cargo_plan)?;
    let cargo_home = work.join("cargo-home");
    fs::create_dir_all(&cargo_home)?;
    fs::write(cargo_home.join("config.toml"), crate::cargo::blanket_config_text(&vendor_obj)?)?;
    Ok((rust_obj, vendor_obj))
}

fn run_sdist_build(
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
    let cores = std::thread::available_parallelism().map(|value| value.get()).unwrap_or(1);
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
        envs = crate::nativelibs::compose_env(native_libs, &envs);
    }
    let path = envs
        .iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.as_str())
        .unwrap_or("/usr/bin:/bin");
    let sb = Sandbox {
        read: vec![build_env, cpython_obj]
            .into_iter()
            .chain(rust)
            .chain(vendor)
            .chain(native_libs)
            .collect(),
        write: vec![work],
    };
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    sb.run_in_on(platform, &refs, &path, work, work, &envs)
        .map_err(|error| wrap_sandbox_build_error_with_tail(pkg, error, stderr_tail(&log)))
}

/// Build the wheel for an sdist without a runtime numpy constraint. Normal
/// project realization calls the depth-aware form with its complete Plan.
pub fn build_sdist_wheel(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    python_version: &str,
) -> io::Result<PathBuf> {
    build_sdist_wheel_at_depth(store, platform, pkg, python_version, None, 0)
}

/// Public runtime-aware entry point for callers that are building one sdist
/// outside a complete environment realization (for example, an integration
/// test). Normal project sync supplies this automatically from its Plan.
pub fn build_sdist_wheel_with_runtime_plan(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    python_version: &str,
    runtime_plan: &Plan,
) -> io::Result<PathBuf> {
    build_sdist_wheel_at_depth(
        store,
        platform,
        pkg,
        python_version,
        Some(runtime_plan),
        0,
    )
}

pub(crate) fn build_sdist_wheel_at_depth(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    python_version: &str,
    runtime_plan: Option<&Plan>,
    depth: usize,
) -> io::Result<PathBuf> {
    if depth > 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sdist build requirement recursion depth exceeded 3 while building {}=={}",
                pkg.name, pkg.version
            ),
        ));
    }
    crate::platform::require_host(platform, "sdist build", "stage 3")?;
    let pin = crate::python::lookup(platform, python_version)
        .ok_or_else(|| no_pin(&format!("cpython {python_version}"), platform, "stage 2"))?;

    let sdist = download_verified_held(store, &pkg.url, &pkg.sha256)?;
    let info = build_requires::inspect_sdist(&sdist)?;
    // A Rust source needs the new schema even if its Python backend only
    // declares setuptools/wheel, because rust/vendor are identity inputs.
    let fast_requirements = build_requires::fast_path(&info.build_requires);
    let fast_sdist = fast_requirements
        && !info.rust_build
        && (!info.native_build || !native_libs_supported(platform));
    let fast_identity = sdist_identity(platform, pkg, pin);
    if fast_sdist {
        let fast_id = fast_identity.object_id();
        if store.has(&fast_id) {
            crate::policy::check_cached(store, &fast_id)?;
            return find_wheel(&store.object_path(&fast_id));
        }
    }
    let build_plan = if fast_requirements {
        build_toolchain_plan(&pin.version)
    } else {
        build_requires::resolve_build_plan(
            store,
            platform,
            &pin.version,
            &info.build_requires,
            runtime_plan,
        )?
    };
    // The nested build environment may fetch its own artifacts. Do not hold
    // this sdist's cache lease while it acquires the same GC lock.
    drop(sdist);
    let build_env = project::realize_env_at_depth(store, platform, &build_plan, depth)?;
    // Native library identity is pure. Realization is deferred until after
    // the wheel cache lookup, so planning never downloads the libset.
    let native_libs_id =
        native_libs_identity_id(store, platform, info.native_build, fast_requirements)?;
    // Re-verify and reacquire the lease for the actual copy/extraction below,
    // so gc cannot collect the cached artifact while it is being used.
    let sdist = download_verified_held(store, &pkg.url, &pkg.sha256)?;

    let work = store.stage()?;
    let outdir = work.join("out");
    fs::create_dir_all(&outdir)?;
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
    fs::copy(&sdist, &sdist_named)?;

    let source = if info.rust_build {
        Some(build_requires::extract_sdist(
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
            store,
            platform,
            &pkg.sha256,
            source,
            &info,
            &work,
        )?)
    } else {
        None
    };
    let identity = if let Some(rust) = &rust_inputs {
        isolated_sdist_identity_from_ids(
            platform,
            pkg,
            pin,
            &object_id(&build_env, "build environment")?,
            Some(&rust.rust_id),
            Some(&rust.vendor_id),
            native_libs_id.as_deref(),
        )
    } else if fast_sdist {
        fast_identity
    } else {
        isolated_sdist_identity_from_ids(
            platform,
            pkg,
            pin,
            &object_id(&build_env, "build environment")?,
            None,
            None,
            native_libs_id.as_deref(),
        )
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        let _ = crate::store::remove_tree(&work);
        return find_wheel(&store.object_path(&id));
    }

    let native_libs = if native_libs_id.is_some() {
        Some(crate::nativelibs::ensure_native_libs(store, platform)?)
    } else {
        None
    };

    if let Some(rust) = &rust_inputs {
        if rust.generated_lock {
            let manifest = info
                .cargo_manifest
                .as_ref()
                .expect("Rust source has a Cargo manifest");
            crate::policy::record(
                crate::policy::UNATTESTED_CARGO_LOCK,
                &manifest.display().to_string(),
                "Cargo.lock was generated by store Cargo outside the build sandbox",
            )?;
        }
    }

    let (rust, vendor, cargo_home) = if let Some(inputs) = &rust_inputs {
        let (rust, vendor) = prepare_rust(store, platform, &info, &work, inputs)?;
        (Some(rust), Some(vendor), Some(work.join("cargo-home")))
    } else {
        (None, None, None)
    };

    let cpython_obj = crate::python::ensure_python_for(store, pin, platform)?;
    let input = source.as_deref().unwrap_or(&sdist_named);
    run_sdist_build(
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

    let wheels: Vec<_> = fs::read_dir(&outdir)?
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
    let built = wheels[0].clone();
    let staged = store.stage()?;
    fs::copy(&built, staged.join(built.file_name().unwrap()))?;
    let _ = crate::store::remove_tree(&work);
    let candidate = crate::policy::object_exceptions();
    let (object, _) = store.commit(&identity, &staged, &candidate)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn test_store(label: &str) -> Store {
        let root = std::env::temp_dir().join(format!(
            "blanket-build-identity-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        Store {
            root: root.canonicalize().unwrap(),
        }
    }

    fn local_native_sdist(store: &Store, name: &str) -> LockedPackage {
        let source = store.root.join(format!("{name}-source"));
        let root = source.join(format!("{name}-1.0"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            "[build-system]\nrequires = [\"setuptools>=40.8\"]\nbuild-backend = \"setuptools.build_meta\"\n",
        )
        .unwrap();
        fs::write(root.join("binding.gyp"), "{}").unwrap();
        let archive = store.root.join(format!("{name}-1.0.tar.gz"));
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg(format!("{name}-1.0"))
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = fs::read(&archive).unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(bytes));
        let _ = fs::remove_dir_all(source);
        LockedPackage {
            name: name.into(),
            version: "1.0".into(),
            filename: format!("{name}-1.0.tar.gz"),
            url: format!("file://{}", archive.display()),
            sha256,
            kind: ArtifactKind::Sdist,
        }
    }

    #[test]
    fn darwin_identity_unchanged() {
        assert_eq!(
            derivation_fingerprint(),
            "sdist-build/2;toolchain:71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e,51a52592b3b99e102b609654876bd65f19f999935166d1352678931132b0c670,3217dcc807155e45db462d7ef2431f5ddda0d7273b700d05a67b271ceb1287ab"
        );
    }

    #[test]
    fn darwin_sdist_identity_unchanged() {
        let pkg = LockedPackage {
            name: "docopt".into(),
            version: "0.6.2".into(),
            filename: "docopt-0.6.2.tar.gz".into(),
            url: "https://files.pythonhosted.org/packages/a2/55/8f8cab2afd404cf578136ef2cc5dfb50baa1761b68c9da1fb1e4eed343c9/docopt-0.6.2.tar.gz".into(),
            sha256: "49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491".into(),
            kind: ArtifactKind::Sdist,
        };
        let pin = crate::python::lookup(Platform::Aarch64AppleDarwin, "3.12.14").unwrap();
        let identity = sdist_identity(Platform::Aarch64AppleDarwin, &pkg, pin);
        assert_eq!(
            identity.object_id(),
            "a26c6aa7246296eac77249f89a9faed77175eb16-docopt-0.6.2"
        );
    }

    #[test]
    fn darwin_native_sdist_identity_does_not_realize_native_libs() {
        let store = test_store("darwin-native");
        let pkg = local_native_sdist(&store, "darwin-native");
        let planned = plan_sdist_identity_input(
            &store,
            Platform::Aarch64AppleDarwin,
            &pkg,
            "3.12.14",
            None,
        )
        .unwrap();
        assert_eq!(
            sdist_identity_input(
                &store,
                Platform::Aarch64AppleDarwin,
                &pkg,
                "3.12.14",
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
        let _ = fs::remove_dir_all(&store.root);
    }

    #[test]
    fn isolated_identity_has_schema_three_and_build_env() {
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
        };
        let pin = crate::python::lookup(Platform::Aarch64AppleDarwin, "3.12.14").unwrap();
        let identity = isolated_sdist_identity_from_ids(
            Platform::Aarch64AppleDarwin,
            &pkg,
            pin,
            "build-env-id",
            None,
            None,
            None,
        );
        assert_eq!(
            identity.object_id(),
            "bbd092b50e11e7b3c04c0ebfd449d03e87baeded-example-1.0"
        );
        assert_eq!(identity.inputs["schema"], "sdist-build/3");
        assert_eq!(identity.inputs["build_env"], "build-env-id");
    }

    #[test]
    fn native_sdist_identity_records_linker_configuration() {
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
        };
        let pin = crate::python::lookup(Platform::X86_64UnknownLinuxGnu, "3.12.14").unwrap();
        let identity = isolated_sdist_identity_from_ids(
            Platform::X86_64UnknownLinuxGnu,
            &pkg,
            pin,
            "build-env-id",
            Some("rust-id"),
            Some("vendor-id"),
            Some("native-libs-id"),
        );
        assert_eq!(identity.inputs["native_libs"], "native-libs-id");
        assert_eq!(identity.inputs["native_linker"], NATIVE_LINKER_CONFIG);
    }

    #[test]
    fn recursion_cap_is_loud() {
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
        };
        let error = build_sdist_wheel_at_depth(
            &Store { root: PathBuf::from("/does/not/matter") },
            Platform::Aarch64AppleDarwin,
            &pkg,
            "3.12.14",
            None,
            4,
        )
        .unwrap_err();
        assert!(error.to_string().contains("recursion depth exceeded 3"));
    }

    #[test]
    fn build_sdist_preserves_unsupported_kind() {
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0".into(),
            filename: "example-1.0.tar.gz".into(),
            url: "https://example.invalid/example.tar.gz".into(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Sdist,
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

/// Realize the pinned setuptools/pip/wheel environment used by sandboxed
/// metadata probes such as `setup.py egg_info`. The rest of this branch's
/// former copies of the build helpers were dropped in favour of main's
/// restructured versions.
pub fn ensure_build_environment(
    store: &Store,
    platform: Platform,
    python_version: &str,
) -> io::Result<PathBuf> {
    project::realize_env(store, platform, &build_toolchain_plan(python_version))
}

//! Sandboxed sdist to wheel builds. PEP 517 build dependencies are inspected
//! without execution and, when needed, realized as a separate Python env.

use crate::build_requires::{self, ArchiveInfo};
use crate::fetch::download_verified;
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

fn isolated_sdist_identity(
    platform: Platform,
    pkg: &LockedPackage,
    pin: &crate::python::PinnedPython,
    build_env: &Path,
    rust: Option<&Path>,
    vendor: Option<&Path>,
    native_libs: Option<&Path>,
) -> io::Result<Identity> {
    let mut inputs = BTreeMap::from([
        ("schema".into(), "sdist-build/3".into()),
        ("sdist_sha256".into(), pkg.sha256.clone()),
        ("python".into(), format!("{}:{}", pin.version, pin.sha256)),
        ("platform".into(), platform.triple().into()),
        ("build_env".into(), object_id(build_env, "build environment")?),
    ]);
    if let Some(rust) = rust {
        inputs.insert("rust".into(), object_id(rust, "Rust object")?);
    }
    if let Some(vendor) = vendor {
        inputs.insert("vendor".into(), object_id(vendor, "Cargo vendor object")?);
    }
    if let Some(native_libs) = native_libs {
        inputs.insert(
            "native_libs".into(),
            object_id(native_libs, "native library object")?,
        );
    }
    Ok(Identity {
        kind: "sdist-build".into(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        inputs,
    })
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

fn stderr_tail(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let lines: Vec<_> = text.lines().collect();
    Some(lines[lines.len().saturating_sub(40)..].join("\n"))
}

fn cargo_lock_for(source: &Path, manifest: &Path) -> Option<PathBuf> {
    [manifest.parent().map(|parent| parent.join("Cargo.lock")), Some(source.join("Cargo.lock"))]
        .into_iter().flatten().find(|path| path.is_file())
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

fn prepare_rust(
    store: &Store,
    platform: Platform,
    source: &Path,
    info: &ArchiveInfo,
    work: &Path,
) -> io::Result<(PathBuf, PathBuf)> {
    let manifest_rel = info.cargo_manifest.as_ref().ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData,
        "Rust build trigger found, but the sdist has no Cargo.toml",
    ))?;
    let manifest = source.join(manifest_rel);
    let rust_version = crate::cargo::resolve_toolchain(platform, source)?;
    let rust_obj = crate::cargo::ensure_rust_for(store, platform, rust_version)?;
    let plan_home = work.join("cargo-plan-home");
    let lock = match cargo_lock_for(source, &manifest) {
        Some(path) => path,
        None => {
            let path = generate_cargo_lock(&rust_obj, &manifest, source, &plan_home)?;
            crate::policy::record(
                crate::policy::UNATTESTED_CARGO_LOCK,
                &manifest.display().to_string(),
                "Cargo.lock was generated by store Cargo outside the build sandbox",
            )?;
            path
        }
    };
    let lock_text = fs::read_to_string(&lock)?;
    let cargo_plan = crate::cargo::plan_cargo(&lock_text, rust_version)?;
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

    let fast_identity = sdist_identity(platform, pkg, pin);
    let fast_id = fast_identity.object_id();

    let sdist = download_verified(store, &pkg.url, &pkg.sha256)?;
    let info = build_requires::inspect_sdist(&sdist)?;
    // A Rust source needs the new schema even if its Python backend only
    // declares setuptools/wheel, because rust/vendor are identity inputs.
    let fast_requirements = build_requires::fast_path(&info.build_requires);
    if fast_requirements && !info.native_build && store.has(&fast_id) {
        crate::policy::check_cached(store, &fast_id)?;
        return find_wheel(&store.object_path(&fast_id));
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
    let build_env = project::realize_env_at_depth(store, platform, &build_plan, depth)?;
    // Non-fast builds are isolated PEP 517 builds; they may generate C/C++
    // sources during the backend step, so give every one the same pinned
    // native set. The fast setuptools path stays lean unless its archive
    // visibly contains a native source/binding.gyp.
    let native_libs = if info.native_build || !fast_requirements {
        Some(crate::nativelibs::ensure_native_libs(store, platform)?)
    } else {
        None
    };

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
    let (rust, vendor, cargo_home) = if let Some(source) = &source {
        let (rust, vendor) = prepare_rust(store, platform, source, &info, &work)?;
        (Some(rust), Some(vendor), Some(work.join("cargo-home")))
    } else {
        (None, None, None)
    };
    let identity = if let Some((rust, vendor)) = rust.as_ref().zip(vendor.as_ref()) {
        isolated_sdist_identity(
            platform,
            pkg,
            pin,
            &build_env,
            Some(rust),
            Some(vendor),
            native_libs.as_ref().map(|set| set.path.as_path()),
        )?
    } else if let Some(native_libs) = native_libs.as_ref() {
        isolated_sdist_identity(
            platform,
            pkg,
            pin,
            &build_env,
            None,
            None,
            Some(native_libs.path.as_path()),
        )?
    } else if fast_requirements {
        fast_identity
    } else {
        isolated_sdist_identity(platform, pkg, pin, &build_env, None, None, None)?
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        let _ = crate::store::remove_tree(&work);
        return find_wheel(&store.object_path(&id));
    }

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
        let identity = isolated_sdist_identity(
            Platform::Aarch64AppleDarwin,
            &pkg,
            pin,
            Path::new("build-env-id"),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            identity.object_id(),
            "bbd092b50e11e7b3c04c0ebfd449d03e87baeded-example-1.0"
        );
        assert_eq!(identity.inputs["schema"], "sdist-build/3");
        assert_eq!(identity.inputs["build_env"], "build-env-id");
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

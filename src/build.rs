//! Sandboxed sdist → wheel builds (M3).
//!
//! An sdist is built into a wheel inside a network-denied sandbox, using a
//! hermetic build environment (pinned pip/setuptools/wheel realized through
//! the same kernel as any other env). The built wheel is itself a store
//! object whose identity commits to the sdist hash, the interpreter, and
//! the build toolchain — a derivation, in Nix terms.
//!
//! v0 scope (per design review): setuptools-family sdists only. Build
//! backends that need other build dependencies fail loudly in the sandbox.

use crate::fetch::download_verified;
use crate::platform::{no_pin, Platform};
use crate::project;
use crate::sandbox::Sandbox;
use crate::store::Store;
use crate::types::{ArtifactKind, Identity, LockedPackage, Plan};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Pinned build toolchain (universal wheels, hashes pinned from PyPI).
const BUILD_TOOLCHAIN: &[(&str, &str, &str, &str, &str)] = &[
    // (name, version, filename, url, sha256)
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

/// Everything (besides the sdist bytes and interpreter) that determines a
/// built wheel: schema + build-toolchain hashes. Parent env identities must
/// include this so a toolchain upgrade re-derives dependents.
fn build_toolchain_fingerprint() -> String {
    BUILD_TOOLCHAIN
        .iter()
        .map(|t| t.4)
        .collect::<Vec<_>>()
        .join(",")
}

fn sdist_build_env(platform: Platform) -> Vec<(String, String)> {
    if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        // python-build-standalone defaults sysconfig's compiler to clang,
        // which is absent on the target host; see LINUX_PORT.md stage 3.
        vec![
            ("CC".into(), "gcc".into()),
            ("CXX".into(), "g++".into()),
            ("LDSHARED".into(), "gcc -shared".into()),
        ]
    } else {
        Vec::new()
    }
}

pub fn derivation_fingerprint() -> String {
    format!("sdist-build/2;toolchain:{}", build_toolchain_fingerprint())
}

fn sdist_identity(
    platform: Platform,
    pkg: &LockedPackage,
    pin: &crate::python::PinnedPython,
) -> Identity {
    Identity {
        kind: "sdist-build".into(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "sdist-build/2".to_string()),
            ("sdist_sha256".to_string(), pkg.sha256.clone()),
            (
                "python".to_string(),
                format!("{}:{}", pin.version, pin.sha256),
            ),
            ("platform".to_string(), platform.triple().to_string()),
            ("toolchain".to_string(), build_toolchain_fingerprint()),
        ]),
    }
}

fn wrap_sandbox_build_error(pkg: &LockedPackage, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "sandboxed build of {}=={} failed: {error}\n\
             (network is denied during builds; sdists needing undeclared \
             build deps or network access are unsupported in v0)",
            pkg.name, pkg.version
        ),
    )
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
        let platform = Platform::Aarch64AppleDarwin;
        let pin = crate::python::lookup(platform, "3.12.14").unwrap();
        let identity = sdist_identity(platform, &pkg, pin);
        assert_eq!(
            identity.object_id(),
            "a26c6aa7246296eac77249f89a9faed77175eb16-docopt-0.6.2"
        );
    }

    #[test]
    fn build_sdist_preserves_unsupported_kind() {
        let pkg = LockedPackage {
            name: "example".into(),
            version: "1.0.0".into(),
            filename: "example-1.0.0.tar.gz".into(),
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
            })
            .collect(),
    }
}

/// Build (or fetch from store) the wheel for an sdist. Returns the path to
/// the built .whl inside its immutable store object.
pub fn build_sdist_wheel(
    store: &Store,
    platform: Platform,
    pkg: &LockedPackage,
    python_version: &str,
) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "sdist build", "stage 3")?;
    let pin = crate::python::lookup(platform, python_version)
        .ok_or_else(|| no_pin(&format!("cpython {python_version}"), platform, "stage 2"))?;
    let identity = sdist_identity(platform, pkg, pin);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return find_wheel(&store.object_path(&id));
    }

    // Hermetic build env through the ordinary kernel path (cache-shared
    // across all sdist builds for this interpreter).
    let build_env = project::realize_env(store, platform, &build_toolchain_plan(python_version))?;
    let sdist = download_verified(store, &pkg.url, &pkg.sha256)?;

    let work = store.stage()?; // writable build area
    let outdir = work.join("out");
    fs::create_dir_all(&outdir)?;
    // pip only treats arguments with archive-looking names as paths; the
    // cache stores by bare hash, so give the sdist its real filename.
    // COPY, never hard-link: a build writing through a hard link would
    // poison the verified artifact cache.
    if pkg.filename.contains('/') || pkg.filename.contains("..") || pkg.filename.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsafe sdist filename: {:?}", pkg.filename),
        ));
    }
    let sdist_named = work.join(&pkg.filename);
    fs::copy(&sdist, &sdist_named)?;
    // The copy inherits the cache's read-only mode; the build may not care,
    // but keep it writable-free either way.

    let py = build_env.join("bin/python");
    // Narrow reads to declared inputs only: the build env object and the
    // CPython object its bin/python resolves to. (mach-lookup and broad
    // process-exec remain allowed -- documented v0 sandbox limitation.)
    let cpython_obj = crate::python::ensure_python_for(store, pin, platform)?;
    let sb = Sandbox {
        read: vec![&build_env, &cpython_obj],
        write: vec![&work],
    };
    let env_path = format!("{}:/usr/bin:/bin", build_env.join("bin").display());
    let build_envs = sdist_build_env(platform);
    sb.run_in_on(
        platform,
        &[
            py.to_str().unwrap(),
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "-w",
            outdir.to_str().unwrap(),
            sdist_named.to_str().unwrap(),
        ],
        &env_path,
        &work,
        &work,
        &build_envs,
    )
    .map_err(|e| wrap_sandbox_build_error(pkg, e))?;

    // Exactly one wheel expected; stage it alone as the object's content.
    let wheels: Vec<_> = fs::read_dir(&outdir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "whl").unwrap_or(false))
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
    let _ = fs::remove_dir_all(&work);
    let (obj, _) = store.commit(&identity, &staged, &[])?;
    find_wheel(&obj)
}

fn find_wheel(dir: &std::path::Path) -> io::Result<PathBuf> {
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().map(|e| e == "whl").unwrap_or(false) {
            return Ok(p);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no wheel found in {}", dir.display()),
    ))
}

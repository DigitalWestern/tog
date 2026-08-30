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
pub fn derivation_fingerprint() -> String {
    format!(
        "sdist-build/2;toolchain:{}",
        BUILD_TOOLCHAIN.iter().map(|t| t.4).collect::<Vec<_>>().join(",")
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
            })
            .collect(),
    }
}

/// Build (or fetch from store) the wheel for an sdist. Returns the path to
/// the built .whl inside its immutable store object.
pub fn build_sdist_wheel(
    store: &Store,
    pkg: &LockedPackage,
    python_version: &str,
) -> io::Result<PathBuf> {
    let pin = crate::python::lookup(python_version).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("no pinned CPython {python_version}"))
    })?;
    let identity = Identity {
        kind: "sdist-build".into(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "sdist-build/2".to_string()),
            ("sdist_sha256".to_string(), pkg.sha256.clone()),
            ("python".to_string(), format!("{}:{}", pin.version, pin.sha256)),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
            (
                "toolchain".to_string(),
                BUILD_TOOLCHAIN
                    .iter()
                    .map(|t| t.4)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        return find_wheel(&store.object_path(&id));
    }

    // Hermetic build env through the ordinary kernel path (cache-shared
    // across all sdist builds for this interpreter).
    let build_env = project::realize_env(store, &build_toolchain_plan(python_version))?;
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
    let cpython_obj = crate::python::ensure_python(store, pin)?;
    let sb = Sandbox {
        read: vec![&build_env, &cpython_obj],
        write: vec![&work],
    };
    let env_path = format!("{}:/usr/bin:/bin", build_env.join("bin").display());
    sb.run(
        &[
            py.to_str().unwrap(),
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--no-index",            "-w",
            outdir.to_str().unwrap(),
            sdist_named.to_str().unwrap(),
        ],
        &env_path,
        &work,
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!(
                "sandboxed build of {}=={} failed: {e}\n\
                 (network is denied during builds; sdists needing undeclared \
                 build deps or network access are unsupported in v0)",
                pkg.name, pkg.version
            ),
        )
    })?;

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
    let obj = store.commit(&identity, &staged)?;
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

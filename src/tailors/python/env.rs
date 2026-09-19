//! Python environment realization and projection (python tailor): the
//! venv-shaped store object a plan realizes to, its input-addressed
//! identity, and the projection of that object into a project directory.
//! It lives in the tailor, not in `comforter`, so the comforter stays
//! ecosystem-neutral.

use crate::comforter::{
    move_reserved_backup, persist_root_for_refs_with_project_lock, replace_project_symlink,
    reserve_backup_real_dir_for_store, store_from_object_path, write_closure_with_project_lock,
    ClosureRefs, InputRecord,
};
use crate::kernel::fetch::download_verified_held;
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::types::{ArtifactKind, Identity, Plan};
use crate::tailors::python;
use crate::tailors::python::pyselect;
use crate::tailors::python::wheel;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Realize the environment object for `plan`. Downloads/validates all
/// artifacts, assembles the venv shape in a staging dir, commits atomically.
/// Cache hit if the identical env already exists.
pub fn realize_env(store: &Store, platform: Platform, plan: &Plan) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    realize_env_at_depth(store, platform, plan, 0)
}

/// Canonical package order and duplicate rejection shared by planning and
/// realization.
pub(super) fn canonical_packages<'a>(
    plan: &'a Plan,
) -> io::Result<Vec<&'a crate::kernel::types::LockedPackage>> {
    let mut packages: Vec<&crate::kernel::types::LockedPackage> = plan.packages.iter().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    for w in packages.windows(2) {
        if w[0].name == w[1].name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate package in plan: {}", w[0].name),
            ));
        }
    }
    Ok(packages)
}

/// Build the one canonical environment identity used by both planning and
/// realization. `cpython_id` is pure during planning and is the realized
/// interpreter object's id during execution; every other input is shared.
pub(super) fn environment_identity(
    store: &Store,
    platform: Platform,
    plan: &Plan,
    cpython_id: &str,
) -> io::Result<Identity> {
    let pin = python::lookup(platform, &plan.python_version)
        .ok_or_else(|| no_pin(&format!("cpython {}", plan.python_version), platform))?;
    let packages = canonical_packages(plan)?;
    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "python-env/2".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert("cpython".to_string(), cpython_id.to_string());
    let mut native_libs_id = None;
    for p in packages {
        let value = match p.kind {
            ArtifactKind::Wheel => format!("Wheel:{}", p.sha256),
            ArtifactKind::Sdist => {
                // A git dependency is packed into a deterministic sdist first,
                // so its identity is the ordinary sdist derivation over that
                // archive's hash (a pure function of the commit's tree).
                let owned;
                let p = if p.git.is_some() {
                    owned = crate::tailors::python::build::git_sdist_package(store, platform, p)?;
                    &owned
                } else {
                    p
                };
                let sdist = crate::tailors::python::build::plan_sdist_identity_input(
                    store,
                    platform,
                    p,
                    &pin.version,
                    Some(plan),
                )?;
                if native_libs_id.is_none() {
                    native_libs_id = sdist.native_libs_id;
                }
                sdist.input
            }
        };
        inputs.insert(format!("pkg:{}", p.name), value);
    }
    if let Some(native_libs_id) = native_libs_id {
        inputs.insert("native_libs".into(), native_libs_id);
    }
    Ok(Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: plan.python_version.clone(),
        inputs,
    })
}

/// Compute an environment object id without realizing its files. Build
/// planning uses this so an isolated sdist can commit its schema-3 identity
/// into the parent before the parent cache lookup.
pub(crate) fn planned_env_object_id(
    store: &Store,
    platform: Platform,
    plan: &Plan,
) -> io::Result<String> {
    let pin = python::lookup(platform, &plan.python_version)
        .ok_or_else(|| no_pin(&format!("cpython {}", plan.python_version), platform))?;
    let cpython_id = python::object_id_for(platform, &pin.version)?;
    Ok(environment_identity(store, platform, plan, &cpython_id)?.object_id())
}

/// Internal realization entry point used by sdist build environments. The
/// depth is carried through nested build-requirement sdists so a malicious or
/// pathological chain cannot recurse forever.
pub(crate) fn realize_env_at_depth(
    store: &Store,
    platform: Platform,
    plan: &Plan,
    sdist_depth: usize,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Python environment")?;
    let pin = python::lookup(platform, &plan.python_version)
        .ok_or_else(|| no_pin(&format!("cpython {}", plan.python_version), platform))?;
    let python_obj = python::ensure_python_for(store, pin, platform)?;

    // Identity planning and realization use exactly the same input builder.
    // In particular, native sdist requirements contribute the pure libset id;
    // the libset itself is realized only by a build that actually runs.
    let cpython_id = python_obj
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let identity = environment_identity(store, platform, plan, &cpython_id)?;
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    // Canonical package order + duplicate rejection: identity uses the same
    // helper, and this borrowed list drives deterministic installation.
    let packages = canonical_packages(plan)?;

    // Fetch everything first (all-or-nothing before assembly starts).
    let mut artifacts: Vec<(&crate::kernel::types::LockedPackage, PathBuf)> = Vec::new();
    // Keep verified cache leases alive until every wheel has been extracted.
    let mut _cache_leases = Vec::new();
    for &p in &packages {
        let wheel_file = match p.kind {
            ArtifactKind::Wheel => {
                let lease = download_verified_held(store, &p.url, &p.sha256)?;
                let path = lease.to_path_buf();
                drop(lease);
                path
            }
            // sdist -> wheel via sandboxed derivation (network denied).
            ArtifactKind::Sdist => {
                let owned;
                let source = if p.git.is_some() {
                    owned = crate::tailors::python::build::git_sdist_package(store, platform, p)?;
                    &owned
                } else {
                    p
                };
                crate::tailors::python::build::build_sdist_wheel_at_depth(
                    store,
                    platform,
                    source,
                    &pin.version,
                    Some(plan),
                    sdist_depth + 1,
                )?
            }
        };
        artifacts.push((p, wheel_file));
    }
    // Sdist realization may recursively fetch toolchains. Re-verify all
    // wheel inputs only after that work, then hold their leases through wheel
    // extraction and publication.
    for (p, path) in &mut artifacts {
        if p.kind == ArtifactKind::Wheel {
            let lease = download_verified_held(store, &p.url, &p.sha256)?;
            *path = lease.to_path_buf();
            _cache_leases.push(lease);
        }
    }

    let minor = pin.version.split('.').take(2).collect::<Vec<_>>().join(".");
    let staged = store.stage()?;
    let bin = staged.join("bin");
    let site = staged.join(format!("lib/python{minor}/site-packages"));
    fs::create_dir_all(&bin)?;
    fs::create_dir_all(&site)?;

    // Standard venv shape: symlinked interpreter + pyvenv.cfg. CPython finds
    // pyvenv.cfg next to the symlink, so store-side python resolves this env.
    let py_target = python_obj.join("bin/python3");
    symlink(&py_target, bin.join("python"))?;
    symlink("python", bin.join("python3"))?;
    symlink("python", bin.join(format!("python{minor}")))?;
    fs::write(
        staged.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\nversion = {}\n",
            python_obj.join("bin").display(),
            pin.version
        ),
    )?;

    // The env's python path — as it will exist after commit — for shebangs.
    let final_python = store.object_path(&id).join("bin/python");
    let mut installed = BTreeMap::new();
    for (_p, wheel_file) in &artifacts {
        wheel::install_wheel(
            wheel_file,
            &site,
            &bin,
            &minor,
            &final_python,
            &mut installed,
        )?;
    }

    let candidate = crate::kernel::policy::object_exceptions();
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(&python_obj)?)?;
    if let Some(native_id) = identity.inputs.get("native_libs") {
        deps.object_id(native_id)?;
    }
    for (package, wheel_file) in &artifacts {
        match package.kind {
            ArtifactKind::Wheel => {
                deps.cache_digest(crate::kernel::fetch::Digest::sha256(&package.sha256)?);
            }
            ArtifactKind::Sdist => {
                let object = wheel_file.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "sdist wheel path has no object parent: {}",
                            wheel_file.display()
                        ),
                    )
                })?;
                deps.object_id(&crate::kernel::store::object_id_from_path(object)?)?;
            }
        }
    }
    let (object, applied) = store.commit_with_deps(&identity, &staged, &candidate, &deps)?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// Project an env into a project directory: `.venv` symlink (atomic swap)
/// plus closure-envelope provenance (.tog/closures/python.json).
pub fn project_env(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_env_inner(project_dir, env_obj, plan, None, &[], attribution)
}

/// `project_env_with_selection` plus the input files recorded for status.
pub fn project_env_with_inputs(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
    inputs: &[InputRecord],
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_env_inner(
        project_dir,
        env_obj,
        plan,
        Some(selection),
        inputs,
        attribution,
    )
}

/// Project a Python env and retain the exact interpreter constraint that led
/// to the selected pin. This is separate from `project_env` to keep the
/// existing kernel-facing helper compatible with hand-built Plans.
pub fn project_env_with_selection(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_env_inner(
        project_dir,
        env_obj,
        plan,
        Some(selection),
        &[],
        attribution,
    )
}

pub(super) fn project_env_inner(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: Option<&pyselect::PythonSelection>,
    inputs: &[InputRecord],
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let venv = project_dir.join(".venv");
    let store = store_from_object_path(env_obj)
        .ok_or_else(|| io::Error::other("environment object is not in a Tog store"))?;
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let env_obj = env_obj.canonicalize()?;
    let project_lock = store.project_lock(project_dir)?;
    let native_reference = crate::tailors::python::nativelibs::env_reference(&env_obj)?;
    let backup = reserve_backup_real_dir_for_store(&venv, &store)?;
    let mut refs = ClosureRefs::new();
    refs.object_path(&store, &activity, &env_obj)?;
    if let Some(native_reference) = native_reference.as_ref() {
        let native_id = native_reference["id"].as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native library closure reference has no object id",
            )
        })?;
        refs.object_id(&store, &activity, native_id)?;
    }
    if let Some(backup) = backup.as_ref() {
        refs.backup(&store, &activity, backup)?;
    }
    // Durable protection precedes both the user-data move and the visible
    // .venv switch. A failed later step therefore over-retains safely.
    persist_root_for_refs_with_project_lock(project_dir, &store, &activity, &refs, &project_lock)?;
    if let Some(backup) = backup.as_ref() {
        move_reserved_backup(&venv, backup)?;
    }
    // replace_project_symlink makes and renames its own temporary link; an
    // extra one here would be left behind in the user's project on every
    // sync.
    replace_project_symlink(&venv, &env_obj, ".venv")?;

    let python = selection
        .map(|selection| {
            serde_json::json!({
                "version": selection.pin.version,
                "constraint": selection.constraint,
                "constraint_source": selection.constraint_source,
            })
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "version": plan.python_version,
                "constraint": serde_json::Value::Null,
                "constraint_source": serde_json::Value::Null,
            })
        });
    write_closure_with_project_lock(
        project_dir,
        "python",
        serde_json::json!({
            "env_object": env_obj,
            "native_libs": native_reference,
            "backup_path": backup,
            "plan": plan,
            "python": python,
            "inputs": inputs,
        }),
        &store,
        &activity,
        refs,
        &project_lock,
        attribution,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::types::LockedPackage;
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn test_store(label: &str) -> Store {
        let root = std::env::temp_dir().join(format!(
            "tog-project-identity-{label}-{}",
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

    fn local_sdist(store: &Store, name: &str, requires: &str) -> LockedPackage {
        let source = store.root.join(format!("{name}-source"));
        let root = source.join(format!("{name}-1.0"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            format!("[build-system]\nrequires = [{requires}]\nbuild-backend = \"setuptools.build_meta\"\n"),
        )
        .unwrap();
        let archive = store.root.join(format!("{name}-1.0.tar.gz"));
        let status = std::process::Command::new("/usr/bin/tar")
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
            git: None,
        }
    }

    fn local_native_sdist(store: &Store, name: &str) -> LockedPackage {
        let source = store.root.join(format!("{name}-native-source"));
        let root = source.join(format!("{name}-1.0"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            "[build-system]\nrequires = [\"setuptools>=40.8\"]\nbuild-backend = \"setuptools.build_meta\"\n",
        )
        .unwrap();
        fs::write(root.join("binding.gyp"), "{}").unwrap();
        let archive = store.root.join(format!("{name}-1.0.tar.gz"));
        let status = std::process::Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg(format!("{name}-1.0"))
            .status()
            .unwrap();
        assert!(status.success());
        let sha256 = hex::encode(sha2::Sha256::digest(fs::read(&archive).unwrap()));
        let _ = fs::remove_dir_all(source);
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

    fn cached_build_plan(store: &Store, requirement: &str, sha256: &str) -> String {
        let platform = Platform::host().unwrap();
        let requires = vec![requirement.to_string()];
        let key = crate::tailors::python::build_requires::lock_cache_key(
            platform, "3.12.14", &requires, None,
        );
        let lock = store.cache_path("build-lock", &key);
        let plan_path = store.cache_path("build-plan", &key);
        fs::create_dir_all(lock.parent().unwrap()).unwrap();
        fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
        fs::write(lock, "# cached test lock\n").unwrap();
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![LockedPackage {
                name: "setuptools".into(),
                version: "84.0.0".into(),
                filename: "setuptools.whl".into(),
                url: String::new(),
                sha256: sha256.into(),
                kind: ArtifactKind::Wheel,
                git: None,
            }],
        };
        fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        key
    }

    fn write_closure(dir: &Path, platform: Option<&str>) {
        fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        let mut v = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"ok": true}
        });
        if let Some(platform) = platform {
            v["platform"] = serde_json::Value::String(platform.to_string());
        }
        fs::write(dir.join(".tog/closures/python.json"), v.to_string()).unwrap();
    }

    fn closure_test_body(store: &Store) -> serde_json::Value {
        serde_json::json!({"store_object": store.object_path("closure-test")})
    }

    fn complete_object(store: &Store, name: &str) -> String {
        crate::kernel::objmeta::register_test_kinds();
        let identity = crate::kernel::types::Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let id = identity.object_id();
        let staged = store.stage().unwrap();
        fs::write(staged.join("payload"), name).unwrap();
        store
            .commit_with_deps(
                &identity,
                &staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();
        let object = store.object_path(&id);
        let mut perms = fs::metadata(&object).unwrap().permissions();
        perms.set_mode(perms.mode() & !0o222);
        fs::set_permissions(&object, perms).unwrap();
        id
    }

    #[test]
    fn fast_sdist_parent_input_keeps_the_legacy_identity() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("fast-golden");
        let fast = local_sdist(&store, "fast-golden", "\"setuptools>=40.8\"");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![fast.clone()],
        };
        let actual = planned_env_object_id(&store, Platform::host().unwrap(), &plan).unwrap();
        let expected = Identity {
            kind: "python-env".into(),
            name: "env".into(),
            version: "3.12.14".into(),
            inputs: BTreeMap::from([
                ("schema".into(), "python-env/2".into()),
                (
                    "store_root".into(),
                    store.root.to_string_lossy().into_owned(),
                ),
                (
                    "cpython".into(),
                    python::object_id_for(Platform::host().unwrap(), "3.12.14").unwrap(),
                ),
                (
                    "pkg:fast-golden".into(),
                    format!(
                        "Sdist:{}:{}",
                        fast.sha256,
                        crate::tailors::python::build::derivation_fingerprint()
                    ),
                ),
            ]),
        }
        .object_id();
        assert_eq!(actual, expected);
        let _ = fs::remove_dir_all(&store.root);
    }

    #[test]
    fn isolated_sdist_build_environment_changes_parent_identity() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("isolated-input");
        let isolated = local_sdist(&store, "isolated-input", "\"setuptools~=83.1\"");
        let fast = local_sdist(&store, "fast-input", "\"setuptools>=40.8\"");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![fast, isolated],
        };
        let key = cached_build_plan(&store, "setuptools~=83.1", &"a".repeat(64));
        let first = planned_env_object_id(&store, Platform::host().unwrap(), &plan).unwrap();
        cached_build_plan(&store, "setuptools~=83.1", &"b".repeat(64));
        let second = planned_env_object_id(&store, Platform::host().unwrap(), &plan).unwrap();
        assert_ne!(
            first, second,
            "schema-3 build-env input must affect parent id"
        );
        assert_eq!(
            key,
            crate::tailors::python::build_requires::lock_cache_key(
                Platform::host().unwrap(),
                "3.12.14",
                &["setuptools~=83.1".into()],
                None,
            )
        );
        let _ = fs::remove_dir_all(&store.root);
    }

    #[test]
    fn planned_and_realized_env_id_match_for_a_native_sdist() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("native-sdist-identity");
        let platform = Platform::host().unwrap();
        let native = local_native_sdist(&store, "native-sdist-identity");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![native],
        };
        let planned = planned_env_object_id(&store, platform, &plan).unwrap();
        let cpython_id = python::object_id_for(platform, &plan.python_version).unwrap();
        let realized = environment_identity(&store, platform, &plan, &cpython_id).unwrap();
        assert_eq!(planned, realized.object_id());
        if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            let native_id =
                crate::tailors::python::nativelibs::object_id_for(&store, platform).unwrap();
            assert_eq!(
                realized.inputs.get("native_libs").map(String::as_str),
                Some(native_id.as_str())
            );
        }
        let _ = fs::remove_dir_all(&store.root);
    }
}

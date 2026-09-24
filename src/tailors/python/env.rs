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
use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::download_verified_held;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
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
/// Realize the environment for a caller that holds no selection: the
/// shipped catalog release for the plan's interpreter. `x` outside a
/// project and tests use this; a project sync uses `realize_env_for`.
pub fn realize_env(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
) -> io::Result<PathBuf> {
    let shipped = python::shipped_selection(&plan.python_version)?;
    realize_env_for(store, activity, platform, plan, &shipped)
}

/// Realize the environment for `plan` with the toolchain the project's
/// selection names. Downloads and validates every artifact, assembles the
/// venv shape in a staging dir, commits atomically. Cache hit if the
/// identical env already exists.
pub fn realize_env_for(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    selected: &Selected,
) -> io::Result<PathBuf> {
    realize_env_with(store, activity, platform, plan, selected, None)
}

/// [`realize_env_for`], building any sdist with a Rust extension on `rust`:
/// the Rust the project's own toolchain lock names, when it has one. `None`
/// keeps the shipped Rust the sdist's toolchain file resolves to.
pub fn realize_env_with(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    selected: &Selected,
    rust: Option<&Selected>,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    realize_env_at_depth(store, activity, platform, plan, selected, rust, 0)
}

/// A plan and the toolchain realizing it must name one CPython. They are
/// produced together on every path; a disagreement is a programming error
/// caught here rather than an environment built against the wrong
/// interpreter.
pub(super) fn agreeing(plan: &Plan, selected: &Selected) -> io::Result<()> {
    if plan.python_version != selected.version("cpython")? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "python plan names cpython {} but the selected toolchain names {}",
                plan.python_version,
                selected.version("cpython")?
            ),
        ));
    }
    Ok(())
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

/// The two spellings of the `python-env/3` native decision. The producer
/// writes one of them on every commit, so a dropped `native_libs` key is a
/// contract violation rather than a different legitimate environment.
pub(super) const NATIVE_LIBS_MOUNTED: &str = "native-libs";
pub(super) const NATIVE_NONE: &str = "none";

/// The `python-env/3` digest over the whole package set: every `pkg:` entry,
/// key and value NUL-terminated so no pair can be re-spelled as another, in
/// the order a `BTreeMap` yields them. It is written unconditionally — the
/// empty environment gets the digest of no packages at all.
///
/// The two callers below take their entries from **different sources on
/// purpose**. The producer digests the plan's package list; the identity
/// contract in `objects.rs` digests the `pkg:` inputs the finished identity
/// actually carries. A producer that writes one fewer input than its plan
/// names makes the two disagree, which is the drift `python-env/3` exists to
/// catch. Digesting the input map on both sides would move the digest along
/// with the drift and catch nothing.
fn package_digest_of(entries: &BTreeMap<String, String>) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// The contract's side: over the `pkg:` inputs this identity carries.
pub(super) fn package_digest_of_inputs(inputs: &BTreeMap<String, String>) -> String {
    package_digest_of(
        &inputs
            .iter()
            .filter(|(key, _)| key.starts_with("pkg:"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// A package the plan names for which no entry was computed. Both traversals
/// of the plan below can hit this, and both report it the same way: it is a
/// producer bug, never a legitimately smaller environment.
fn missing_entry(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("plan names package {name} with no identity entry"),
    )
}

/// The producer's side: a traversal of the plan's own package list, separate
/// from the loop that writes the identity inputs.
fn package_digest_of_plan(
    packages: &[&crate::kernel::types::LockedPackage],
    values: &BTreeMap<String, String>,
) -> io::Result<String> {
    let mut entries = BTreeMap::new();
    for p in packages {
        let key = format!("pkg:{}", p.name);
        let value = values.get(&key).ok_or_else(|| missing_entry(&p.name))?;
        entries.insert(key, value.clone());
    }
    Ok(package_digest_of(&entries))
}

/// Build the one canonical environment identity used by both planning and
/// realization. `cpython_id` is pure during planning and is the realized
/// interpreter object's id during execution; every other input is shared.
pub(super) fn environment_identity(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    cpython_id: &str,
    selected: &Selected,
    rust: Option<&Selected>,
) -> io::Result<Identity> {
    environment_identity_inner(
        store, activity, platform, plan, cpython_id, selected, rust, None,
    )
}

/// The exact producer drift `python-env/3` exists to catch: the plan names
/// `skip_package`, the input loop never writes its `pkg:` entry, and the
/// package digest is still taken over the whole plan. Only tests build this.
#[cfg(test)]
pub(super) fn environment_identity_skipping_input(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    cpython_id: &str,
    selected: &Selected,
    skip_package: &str,
) -> io::Result<Identity> {
    environment_identity_inner(
        store,
        activity,
        platform,
        plan,
        cpython_id,
        selected,
        None,
        Some(skip_package),
    )
}

fn environment_identity_inner(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    cpython_id: &str,
    selected: &Selected,
    rust: Option<&Selected>,
    // The drift test seam, carried in release builds too: production always
    // passes `None`, and only `environment_identity_skipping_input` does not.
    skip_package: Option<&str>,
) -> io::Result<Identity> {
    agreeing(plan, selected)?;
    let packages = canonical_packages(plan)?;
    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "python-env/3".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert("cpython".to_string(), cpython_id.to_string());
    let mut native_libs_id = None;
    // The per-package entry. This is the expensive half — an sdist is
    // planned here — so it is computed once and kept beside the plan.
    let mut values = BTreeMap::new();
    for p in &packages {
        let value = match p.kind {
            ArtifactKind::Wheel => format!("Wheel:{}", p.sha256),
            ArtifactKind::Sdist => {
                // A git dependency is packed into a deterministic sdist first,
                // so its identity is the ordinary sdist derivation over that
                // archive's hash (a pure function of the commit's tree).
                let owned;
                let p = if p.git.is_some() {
                    owned = crate::tailors::python::build::git_sdist_package(
                        store, activity, platform, p,
                    )?;
                    &owned
                } else {
                    *p
                };
                let sdist = crate::tailors::python::build::plan_sdist_identity_input(
                    store,
                    activity,
                    platform,
                    p,
                    selected,
                    rust,
                    Some(plan),
                )?;
                if native_libs_id.is_none() {
                    native_libs_id = sdist.native_libs_id;
                }
                sdist.input
            }
        };
        values.insert(format!("pkg:{}", p.name), value);
    }
    // One identity input per planned package.
    for p in &packages {
        if skip_package == Some(p.name.as_str()) {
            continue;
        }
        let key = format!("pkg:{}", p.name);
        let value = values
            .get(&key)
            .ok_or_else(|| missing_entry(&p.name))?
            .clone();
        inputs.insert(key, value);
    }
    // The two unconditional inputs `python-env/3` adds. Under /2 a one-wheel
    // plan that lost its only `pkg:` key hashed to the legitimate empty
    // environment, and a native sdist that lost `native_libs` passed every
    // check, because every check keyed on the presence of the key it checked.
    //
    // The digest is taken from the plan, not from `inputs`: if the loop above
    // ever writes fewer inputs than the plan names, this value still covers
    // the whole plan and the contract's recomputation over the identity
    // disagrees with it.
    inputs.insert(
        "package_digest".to_string(),
        package_digest_of_plan(&packages, &values)?,
    );
    inputs.insert(
        "native".to_string(),
        match native_libs_id {
            Some(_) => NATIVE_LIBS_MOUNTED,
            None => NATIVE_NONE,
        }
        .to_string(),
    );
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
/// planning uses this so an isolated sdist can commit its isolated-build identity
/// into the parent before the parent cache lookup.
pub(crate) fn planned_env_object_id(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    selected: &Selected,
    rust: Option<&Selected>,
) -> io::Result<String> {
    let cpython_id = crate::tailors::python::cpython_object_id(selected, platform)?;
    Ok(
        environment_identity(store, activity, platform, plan, &cpython_id, selected, rust)?
            .object_id(),
    )
}

/// Internal realization entry point used by sdist build environments. The
/// depth is carried through nested build-requirement sdists so a malicious or
/// pathological chain cannot recurse forever.
pub(crate) fn realize_env_at_depth(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &Plan,
    selected: &Selected,
    rust: Option<&Selected>,
    sdist_depth: usize,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Python environment")?;
    agreeing(plan, selected)?;
    let python_obj = python::realize_runtime(store, activity, platform, selected)?;

    // Identity planning and realization use exactly the same input builder.
    // In particular, native sdist requirements contribute the pure libset id;
    // the libset itself is realized only by a build that actually runs.
    let cpython_id = python_obj
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let identity =
        environment_identity(store, activity, platform, plan, &cpython_id, selected, rust)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
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
                let lease = download_verified_held(store, activity, &p.url, &p.sha256)?;
                let path = lease.to_path_buf();
                drop(lease);
                path
            }
            // sdist -> wheel via sandboxed derivation (network denied).
            ArtifactKind::Sdist => {
                let owned;
                let source = if p.git.is_some() {
                    owned = crate::tailors::python::build::git_sdist_package(
                        store, activity, platform, p,
                    )?;
                    &owned
                } else {
                    p
                };
                crate::tailors::python::build::build_sdist_wheel_at_depth(
                    store,
                    activity,
                    platform,
                    source,
                    selected,
                    rust,
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
            let lease = download_verified_held(store, activity, &p.url, &p.sha256)?;
            *path = lease.to_path_buf();
            _cache_leases.push(lease);
        }
    }

    let minor = plan
        .python_version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    let staged = store.stage_with_activity(activity)?;
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
            plan.python_version
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
    let (object, applied) =
        store.commit_with_activity_and_deps(activity, &identity, &staged, &candidate, &deps)?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// The closure record `tog status`, `tog ls` and `tog gc` read. The
/// toolchain entries are present exactly when the caller held a selection:
/// which bundle this environment was built from, and the interpreter object
/// realized from it.
fn python_closure_body(
    env_obj: &Path,
    native_reference: &Option<serde_json::Value>,
    backup: &Option<PathBuf>,
    plan: &Plan,
    selection: Option<&pyselect::PythonSelection>,
    inputs: &[InputRecord],
    runtime_record: Option<serde_json::Value>,
) -> serde_json::Value {
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
    let mut body = serde_json::json!({
        "env_object": env_obj,
        "native_libs": native_reference,
        "backup_path": backup,
        "plan": plan,
        "python": python,
        "inputs": inputs,
    });
    if let Some(record) = runtime_record {
        for (key, value) in record.as_object().into_iter().flatten() {
            body[key] = value.clone();
        }
    }
    body
}

/// `project_env_with_selection` plus the input files recorded for status
/// and, on a project path, the toolchain this environment was built with:
/// the bundle it came from and the interpreter object it realized, which
/// the closure records so a later run resolves the same bytes.
pub fn project_env_with_inputs(
    activity: &StoreActivity,
    project: &ProjectRoot,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
    inputs: &[InputRecord],
    toolchain: Option<(&Selected, &Path)>,
    helpers: &serde_json::Value,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_env_inner(
        activity,
        project,
        env_obj,
        plan,
        Some(selection),
        inputs,
        toolchain,
        helpers,
        attribution,
    )
}

/// Project an env into a project directory (`.venv` symlink, atomic swap,
/// plus closure-envelope provenance in `.tog/closures/python.json`) and
/// retain the exact interpreter constraint that led to the selected pin.
/// `tog x` uses this: it has a selection but no recorded input files.
pub fn project_env_with_selection(
    activity: &StoreActivity,
    project: &ProjectRoot,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_env_inner(
        activity,
        project,
        env_obj,
        plan,
        Some(selection),
        &[],
        None,
        &serde_json::Value::Null,
        attribution,
    )
}

pub(super) fn project_env_inner(
    activity: &StoreActivity,
    project: &ProjectRoot,
    env_obj: &Path,
    plan: &Plan,
    selection: Option<&pyselect::PythonSelection>,
    inputs: &[InputRecord],
    toolchain: Option<(&Selected, &Path)>,
    // The helper decision (`tailors::helper_record`), stored beside the
    // toolchain record; `Null` writes none.
    helpers: &serde_json::Value,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    // `.venv` is moved aside, replaced and published through the held
    // project descriptor, never through the project's path.
    let venv = Path::new(".venv");
    let project_dir = project.path();
    let store = store_from_object_path(env_obj)
        .ok_or_else(|| io::Error::other("environment object is not in a Tog store"))?;
    let env_obj = env_obj.canonicalize()?;
    let project_lock = store.project_lock(project_dir)?;
    let native_reference = crate::kernel::provider::nativelibs::env_reference(&env_obj)?;
    let backup = reserve_backup_real_dir_for_store(project, venv, &store)?;
    let mut refs = ClosureRefs::new();
    refs.object_path(&store, activity, &env_obj)?;
    // The interpreter is referenced directly, not only through the
    // environment, so gc keeps the object a later run resolves.
    let runtime_record = match toolchain {
        Some((selected, runtime)) => {
            refs.object_path(&store, activity, runtime)?;
            let mut record = crate::comforter::toolchain::closure_record(selected, runtime);
            if !helpers.is_null() {
                record["toolchain"]["helpers"] = helpers.clone();
            }
            Some(record)
        }
        None => None,
    };
    if let Some(native_reference) = native_reference.as_ref() {
        let native_id = native_reference["id"].as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native library closure reference has no object id",
            )
        })?;
        refs.object_id(&store, activity, native_id)?;
    }
    if let Some(backup) = backup.as_ref() {
        refs.backup(&store, activity, backup)?;
    }
    // Durable protection precedes both the user-data move and the visible
    // .venv switch. A failed later step therefore over-retains safely.
    persist_root_for_refs_with_project_lock(project, &store, activity, &refs, &project_lock)?;
    if let Some(backup) = backup.as_ref() {
        move_reserved_backup(project, venv, backup)?;
    }
    // replace_project_symlink makes and renames its own temporary link; an
    // extra one here would be left behind in the user's project on every
    // sync.
    replace_project_symlink(project, venv, &env_obj, ".venv")?;

    let body = python_closure_body(
        &env_obj,
        &native_reference,
        &backup,
        plan,
        selection,
        inputs,
        runtime_record,
    );
    write_closure_with_project_lock(
        project,
        "python",
        body,
        &store,
        activity,
        refs,
        &project_lock,
        attribution,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What sync writes: the bundle it planned from and the interpreter
    /// object it realized, beside every key `ls`, `status` and `sbom`
    /// already read.
    #[test]
    fn the_closure_body_records_the_bundle_and_the_runtime_object() {
        let selected = selected_3_12();
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: Vec::new(),
        };
        let selection = pyselect::locked(
            Platform::host().unwrap(),
            "3.12.14",
            &pyselect::PythonInputs::default(),
        )
        .unwrap();
        let runtime = Path::new("/store/objects/cpython-3.12.14-abcdef");
        let body = python_closure_body(
            Path::new("/store/objects/env-1"),
            &None,
            &None,
            &plan,
            Some(&selection),
            &[],
            Some(crate::comforter::toolchain::closure_record(
                &selected, runtime,
            )),
        );
        assert_eq!(body["toolchain"]["ecosystem"], "python");
        assert_eq!(body["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(body["toolchain"]["versions"]["cpython"], "3.12.14");
        assert_eq!(body["runtime_object"]["id"], "cpython-3.12.14-abcdef");
        assert_eq!(body["runtime_object"]["path"], runtime.to_str().unwrap());
        // Every key the older readers depend on is still there.
        assert_eq!(body["python"]["version"], "3.12.14");
        assert_eq!(body["env_object"], "/store/objects/env-1");
        assert_eq!(body["plan"]["python_version"], "3.12.14");

        // A caller with no selection (`x` outside a project) writes the
        // body it always wrote, with no toolchain entries to resolve.
        let bare = python_closure_body(
            Path::new("/store/objects/env-1"),
            &None,
            &None,
            &plan,
            Some(&selection),
            &[],
            None,
        );
        assert!(bare.get("toolchain").is_none());
        assert!(bare.get("runtime_object").is_none());
    }

    /// The durable root/2 record `project_env_inner` publishes names exactly
    /// the environment object, the interpreter object, the native library
    /// object the environment was built against, and the backup of the
    /// user's real `.venv`: nothing inferred from the closure JSON, nothing
    /// missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        use std::os::unix::fs::PermissionsExt;
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let store = test_store("closure-refs");
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        for sub in ["roots", "backups"] {
            fs::create_dir_all(store.root.join(sub)).unwrap();
        }
        let env_id = format!("{}-env-0", "1".repeat(40));
        let runtime_id = format!("{}-cpython-3.12.14", "2".repeat(40));
        let native_id = format!("{}-native-libs-0", "3".repeat(40));
        for (id, inputs) in [
            (&env_id, serde_json::json!({ "native_libs": native_id })),
            (&runtime_id, serde_json::json!({})),
            (&native_id, serde_json::json!({})),
        ] {
            let object = store.object_path(id);
            fs::create_dir_all(&object).unwrap();
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": id,
                    "identity": {"kind": "test", "name": id, "version": "0", "inputs": inputs},
                }))
                .unwrap(),
            )
            .unwrap();
        }
        // A real .venv the user made: it is moved into a store backup.
        let project = std::env::temp_dir().join(format!(
            "tog-python-closure-refs-project-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&project);
        fs::create_dir_all(project.join(".venv/lib")).unwrap();
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: Vec::new(),
        };
        let selected = selected_3_12();
        let runtime = store.object_path(&runtime_id);
        project_env_inner(
            activity,
            &ProjectRoot::open(&project).unwrap(),
            &store.object_path(&env_id),
            &plan,
            None,
            &[],
            Some((&selected, runtime.as_path())),
            &serde_json::Value::Null,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let backups: Vec<PathBuf> = fs::read_dir(store.root.join("backups"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([env_id, runtime_id, native_id])
        );
        assert_eq!(
            record.projections,
            std::collections::BTreeSet::from([store
                .projection_ref(crate::kernel::store::ProjectionBase::Backups, &backups[0])
                .unwrap()])
        );

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
        let _ = crate::kernel::store::remove_tree(&store.root);
        let _ = fs::remove_dir_all(&project);
    }

    /// The shipped release the fixture plans name. Selection is the
    /// kernel's job; these tests are about what an identity hashes.
    fn selected_3_12() -> crate::kernel::toolchain::Selected {
        python::shipped_selection("3.12.14").expect("shipped CPython release")
    }
    use crate::kernel::types::LockedPackage;
    use sha2::Digest as _;

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

    /// `python-env/3` goldens, on both platforms, from fixed inputs: a
    /// fixed store root (a real identity input) and one wheel. The identity
    /// constructor is a pure function of its platform argument, so the
    /// Darwin value is computed here and the macOS gate only confirms it.
    /// The `/2` spelling of the same plan is a different object id, so the
    /// bump reissues every environment; and the drift `/2` could not see —
    /// a one-wheel plan losing its only `pkg:` key — no longer collides
    /// with the empty environment.
    #[test]
    fn environment_identity_goldens_and_dropped_sole_wheel() {
        crate::tailors::install_kinds();
        let store = Store {
            root: PathBuf::from("/fixture/tog-store"),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        let empty_plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: Vec::new(),
        };
        let wheel_plan = Plan {
            packages: vec![LockedPackage {
                name: "example".into(),
                version: "1.0.0".into(),
                filename: "example-1.0.0-py3-none-any.whl".into(),
                url: "https://files.pythonhosted.org/example.whl".into(),
                sha256: "a".repeat(64),
                kind: ArtifactKind::Wheel,
                git: None,
            }],
            ..empty_plan.clone()
        };
        for (platform, golden) in [
            (
                Platform::X86_64UnknownLinuxGnu,
                "306c7508efb42b2526003af9975593dc92cf1abc-env-3.12.14",
            ),
            (
                Platform::Aarch64AppleDarwin,
                "8c17d18f771550bb1f0178cb694ae02b1f565806-env-3.12.14",
            ),
        ] {
            let cpython = python::object_id_for(platform, "3.12.14").unwrap();
            let empty = environment_identity(
                &store,
                activity,
                platform,
                &empty_plan,
                &cpython,
                &selected_3_12(),
                None,
            )
            .unwrap();
            let wheel = environment_identity(
                &store,
                activity,
                platform,
                &wheel_plan,
                &cpython,
                &selected_3_12(),
                None,
            )
            .unwrap();
            assert_eq!(wheel.inputs["schema"], "python-env/3");
            assert_eq!(wheel.inputs["native"], NATIVE_NONE);
            assert_eq!(wheel.object_id(), golden, "{}", platform.triple());
            assert_eq!(
                crate::kernel::objmeta::check_identity_grammar(&wheel),
                Ok(())
            );
            assert_ne!(
                empty.inputs["package_digest"],
                wheel.inputs["package_digest"]
            );

            // The `/2` spelling of the same plan: a different object id,
            // which is the store-wide rebuild this bump accepts.
            let mut old = wheel.clone();
            old.inputs.insert("schema".into(), "python-env/2".into());
            old.inputs.remove("package_digest");
            old.inputs.remove("native");
            assert_ne!(old.object_id(), wheel.object_id());

            // The drift `/2` could not see.
            let mut dropped = wheel.clone();
            dropped.inputs.remove("pkg:example");
            let reason = crate::kernel::objmeta::check_identity_grammar(&dropped).unwrap_err();
            assert!(
                reason.contains("Python environment package digest"),
                "{reason}"
            );
            assert_ne!(dropped.object_id(), empty.object_id());
        }
    }

    /// The real shape of the drift, not a mutated finished identity: a
    /// producer whose input loop never writes one planned package. The
    /// package digest comes from the plan, so it still covers the package
    /// the identity is missing and the contract refuses the commit.
    ///
    /// Building the digest from the input map instead would move it along
    /// with the drift, and this identity would be the empty environment's,
    /// byte for byte — the `python-env/2` collision the bump exists to close.
    #[test]
    fn a_producer_that_skips_a_package_input_is_refused() {
        crate::tailors::install_kinds();
        let store = Store {
            root: PathBuf::from("/fixture/tog-store"),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        let empty_plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: Vec::new(),
        };
        let wheel = |name: &str| LockedPackage {
            name: name.into(),
            version: "1.0.0".into(),
            filename: format!("{name}-1.0.0-py3-none-any.whl"),
            url: format!("https://files.pythonhosted.org/{name}.whl"),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Wheel,
            git: None,
        };
        let one_wheel_plan = Plan {
            packages: vec![wheel("example")],
            ..empty_plan.clone()
        };
        let two_wheel_plan = Plan {
            packages: vec![wheel("example"), wheel("second-example")],
            ..empty_plan.clone()
        };
        for platform in Platform::ALL.iter().copied() {
            let cpython = python::object_id_for(platform, "3.12.14").unwrap();
            let empty = environment_identity(
                &store,
                activity,
                platform,
                &empty_plan,
                &cpython,
                &selected_3_12(),
                None,
            )
            .unwrap();
            let one = environment_identity(
                &store,
                activity,
                platform,
                &one_wheel_plan,
                &cpython,
                &selected_3_12(),
                None,
            )
            .unwrap();
            // The collision `python-env/2` had.
            assert_ne!(one.object_id(), empty.object_id(), "{}", platform.triple());

            for (plan, skipped) in [
                (&one_wheel_plan, "example"),
                (&two_wheel_plan, "second-example"),
            ] {
                let drifted = environment_identity_skipping_input(
                    &store,
                    activity,
                    platform,
                    plan,
                    &cpython,
                    &selected_3_12(),
                    skipped,
                )
                .unwrap();
                assert!(!drifted.inputs.contains_key(&format!("pkg:{skipped}")));
                let reason = crate::kernel::objmeta::check_identity_grammar(&drifted).unwrap_err();
                assert!(
                    reason.contains("Python environment package digest"),
                    "{}: {reason}",
                    platform.triple()
                );
                assert_ne!(drifted.object_id(), empty.object_id());
                assert_ne!(drifted.object_id(), one.object_id());
            }
        }
    }

    #[test]
    fn fast_sdist_parent_input_keeps_the_legacy_identity() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let store = test_store("fast-golden");
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let fast = local_sdist(&store, "fast-golden", "\"setuptools>=40.8\"");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![fast.clone()],
        };
        let actual = planned_env_object_id(
            &store,
            activity,
            Platform::host().unwrap(),
            &plan,
            &selected_3_12(),
            None,
        )
        .unwrap();
        let mut inputs = BTreeMap::from([
            ("schema".to_string(), "python-env/3".to_string()),
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
        ]);
        inputs.insert("package_digest".into(), package_digest_of_inputs(&inputs));
        inputs.insert("native".into(), NATIVE_NONE.into());
        let expected = Identity {
            kind: "python-env".into(),
            name: "env".into(),
            version: "3.12.14".into(),
            inputs,
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
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let isolated = local_sdist(&store, "isolated-input", "\"setuptools~=83.1\"");
        let fast = local_sdist(&store, "fast-input", "\"setuptools>=40.8\"");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![fast, isolated],
        };
        let key = cached_build_plan(&store, "setuptools~=83.1", &"a".repeat(64));
        let first = planned_env_object_id(
            &store,
            activity,
            Platform::host().unwrap(),
            &plan,
            &selected_3_12(),
            None,
        )
        .unwrap();
        cached_build_plan(&store, "setuptools~=83.1", &"b".repeat(64));
        let second = planned_env_object_id(
            &store,
            activity,
            Platform::host().unwrap(),
            &plan,
            &selected_3_12(),
            None,
        )
        .unwrap();
        assert_ne!(
            first, second,
            "isolated-build build_env input must affect parent id"
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
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let platform = Platform::host().unwrap();
        let native = local_native_sdist(&store, "native-sdist-identity");
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![native],
        };
        let planned =
            planned_env_object_id(&store, activity, platform, &plan, &selected_3_12(), None)
                .unwrap();
        let cpython_id = python::object_id_for(platform, &plan.python_version).unwrap();
        let realized = environment_identity(
            &store,
            activity,
            platform,
            &plan,
            &cpython_id,
            &selected_3_12(),
            None,
        )
        .unwrap();
        assert_eq!(planned, realized.object_id());
        if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            let native_id =
                crate::kernel::provider::nativelibs::object_id_for(&store, platform).unwrap();
            assert_eq!(
                realized.inputs.get("native_libs").map(String::as_str),
                Some(native_id.as_str())
            );
        }
        let _ = fs::remove_dir_all(&store.root);
    }
}

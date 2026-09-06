//! Environment (comforter) realization + projection.
//!
//! An environment is itself a store object (venv-shaped, immutable) whose
//! identity is the python object id plus every locked artifact hash. Two
//! projects with identical locks share one env object; different locks get
//! different objects and coexist. Projection into a project is one symlink.

use crate::fetch::download_verified;
use crate::platform::{no_pin, Platform};
use crate::store::Store;
use crate::types::{ArtifactKind, Identity, Plan};
use crate::{pyselect, python, wheel};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Common closure envelope (Sol review 4): every tailor's provenance lands
/// at .blanket/closures/<ecosystem>.json with a shared outer shape; the
/// `body` stays tailor-owned. Written atomically.
pub fn write_closure(
    project_dir: &Path,
    ecosystem: &str,
    mut body: serde_json::Value,
) -> io::Result<()> {
    let project_dir = project_dir.canonicalize()?;
    let dir = project_dir.join(".blanket/closures");
    fs::create_dir_all(&dir)?;
    // A symlinked closures dir would carry provenance writes outside the
    // project (same class as the cargo-home/bin escape).
    let dir = dir.canonicalize()?;
    if !dir.starts_with(&project_dir) {
        return Err(io::Error::other(format!(
            "{} escapes the project; refusing to write closures there",
            dir.display()
        )));
    }
    let pending = crate::policy::pending();
    if let Some(body) = body.as_object_mut() {
        body.insert("exceptions".into(), serde_json::to_value(&pending)?);
    }
    // Envelope-level platform (LINUX_PORT.md stage 6): a project synced on
    // a Mac and then on a Linux box carries two different closures over
    // time; readers must not assume the body's object ids are valid for
    // the current host. Additive field, schema unchanged.
    let platform = Platform::host()?.triple();
    // All tailor closure bodies carry at least one canonical object path. Use
    // it to register the exact store involved; this keeps unit tests that use
    // synthetic stores from accidentally creating ~/.blanket/store. The
    // fallback is for future tailor bodies that do not yet carry an object
    // path.
    let store = store_from_closure_body(&body).unwrap_or(Store::open()?);
    let envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": ecosystem,
        "platform": platform,
        "projected_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "body": body,
    });
    let dest = dir.join(format!("{ecosystem}.json"));
    let tmp = dir.join(format!(".{ecosystem}.json.tmp.{}", std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(&envelope)?)?;
    fs::rename(&tmp, &dest)?;
    store.register_root(&project_dir)?;
    crate::policy::clear();
    Ok(())
}

fn store_from_closure_body(body: &serde_json::Value) -> Option<Store> {
    fn find(value: &serde_json::Value) -> Option<Store> {
        match value {
            serde_json::Value::String(text) if Path::new(text).is_absolute() => {
                let path = Path::new(text);
                for ancestor in path.ancestors() {
                    if ancestor.file_name().and_then(|name| name.to_str()) == Some("objects") {
                        let root = ancestor.parent()?.to_path_buf();
                        if root.join("objects").is_dir() {
                            return Some(Store { root });
                        }
                    }
                }
                None
            }
            serde_json::Value::Array(values) => values.iter().find_map(find),
            serde_json::Value::Object(values) => values.values().find_map(find),
            _ => None,
        }
    }
    find(body)
}

/// Read a tailor's closure body back (for `blanket run` and friends).
pub fn read_closure(project_dir: &Path, ecosystem: &str) -> io::Result<serde_json::Value> {
    let path = project_dir.join(format!(".blanket/closures/{ecosystem}.json"));
    let text = fs::read_to_string(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("read {}: {e}; run `blanket sync` first", path.display()),
        )
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse {}: {e}; run `blanket sync` first", path.display()),
        )
    })?;
    if let Some(recorded) = v["platform"].as_str() {
        let host = Platform::host()?;
        if recorded != host.triple() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{}: closure was projected on {recorded}; this host is {}; run `blanket sync` here",
                    path.display(),
                    host.triple()
                ),
            ));
        }
    }
    // Envelopes without a platform field predate the Linux port (all darwin);
    // they are accepted and their object ids simply will not resolve on a
    // foreign store, which already demands a re-sync.
    if v["schema"] != "closure/1" || v["ecosystem"] != ecosystem {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: unknown closure schema/ecosystem; re-run `blanket sync`",
                path.display()
            ),
        ));
    }
    Ok(v["body"].clone())
}

/// Copy-on-write clone of a whole tree (cp -c uses APFS clonefile; plain
/// copy fallback), then restore user-write bits, which the clone inherits
/// as read-only from the store. Used for writable projections of immutable
/// objects (npm mutablePackages, elixir deps trees).
pub fn clone_tree(src: &Path, dest: &Path) -> io::Result<()> {
    clone_tree_for(src, dest, Platform::host()?)
}

pub(crate) fn clone_tree_for(src: &Path, dest: &Path, platform: Platform) -> io::Result<()> {
    use std::process::Command;
    let clone = if platform.is_macos() {
        Command::new("/bin/cp")
            .args(["-Rc"])
            .arg(src)
            .arg(dest)
            .status()?
    } else {
        Command::new("/bin/cp")
            .args(["-a", "--reflink=auto"])
            .arg(src)
            .arg(dest)
            .status()?
    };
    if !clone.success() {
        if dest.exists() {
            crate::store::remove_tree(dest)?;
        }
        let plain = Command::new("/bin/cp")
            .arg("-R")
            .arg(src)
            .arg(dest)
            .status()?;
        if !plain.success() {
            return Err(io::Error::other("cloning projected tree failed"));
        }
    }
    restore_write_bits(dest)
}

fn restore_write_bits(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    let mode = md.permissions().mode();
    if mode & 0o200 == 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200))?;
    }
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            restore_write_bits(&entry?.path())?;
        }
    }
    Ok(())
}

/// Resolve an object reference from a closure body, CONTAINED to the
/// active store: the recorded id must exist in the store and the recorded
/// path must be exactly the store's path for that id. A project-editable
/// closure must never inject arbitrary executable paths into `blanket run`
/// (Sol review 5, reproduced against the ruby closure).
pub fn closure_object(
    store: &crate::store::Store,
    closure: &serde_json::Value,
    key: &str,
    probe: &str,
) -> io::Result<PathBuf> {
    let bad = |msg: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure {key}: {msg}; run `blanket sync` first"),
        )
    };
    let id = closure[key]["id"]
        .as_str()
        .ok_or_else(|| bad("missing id"))?;
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(bad("malformed id"));
    }
    if !store.has(id) {
        return Err(bad("object not in the store"));
    }
    let path = store.object_path(id);
    if closure[key]["path"].as_str().map(Path::new) != Some(path.as_path()) {
        return Err(bad("recorded path disagrees with the store"));
    }
    if !probe.is_empty() && !path.join(probe).exists() {
        return Err(bad("object is missing its expected content"));
    }
    Ok(path)
}

/// Realize the environment object for `plan`. Downloads/validates all
/// artifacts, assembles the venv shape in a staging dir, commits atomically.
/// Cache hit if the identical env already exists.
pub fn realize_env(store: &Store, platform: Platform, plan: &Plan) -> io::Result<PathBuf> {
    realize_env_at_depth(store, platform, plan, 0)
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
        .ok_or_else(|| no_pin(&format!("cpython {}", plan.python_version), platform, "stage 2"))?;
    let mut packages: Vec<&crate::types::LockedPackage> = plan.packages.iter().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    for w in packages.windows(2) {
        if w[0].name == w[1].name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate package in plan: {}", w[0].name),
            ));
        }
    }

    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "python-env/2".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert("cpython".to_string(), python::object_id_for(platform, &pin.version)?);
    for p in packages {
        let value = match p.kind {
            ArtifactKind::Wheel => format!("Wheel:{}", p.sha256),
            ArtifactKind::Sdist => crate::build::sdist_identity_input(
                store,
                platform,
                p,
                &pin.version,
                Some(plan),
            )?,
        };
        inputs.insert(format!("pkg:{}", p.name), value);
    }
    Ok(Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: plan.python_version.clone(),
        inputs,
    }
    .object_id())
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
    crate::platform::require_host(platform, "Python environment", "stage 2")?;
    let pin = python::lookup(platform, &plan.python_version)
        .ok_or_else(|| no_pin(&format!("cpython {}", plan.python_version), platform, "stage 2"))?;
    let python_obj = python::ensure_python_for(store, pin, platform)?;

    // Canonical package order + duplicate rejection: identity must commit
    // to exactly one artifact per name, installed in a deterministic order.
    let mut packages: Vec<&crate::types::LockedPackage> = plan.packages.iter().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    for w in packages.windows(2) {
        if w[0].name == w[1].name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate package in plan: {}", w[0].name),
            ));
        }
    }

    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "python-env/2".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert(
        "cpython".to_string(),
        python_obj
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );
    for p in &packages {
        let value = match p.kind {
            ArtifactKind::Wheel => format!("Wheel:{}", p.sha256),
            ArtifactKind::Sdist => crate::build::sdist_identity_input(
                store,
                platform,
                p,
                &pin.version,
                Some(plan),
            )?,
        };
        inputs.insert(format!("pkg:{}", p.name), value);
    }
    let identity = Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: plan.python_version.clone(),
        inputs,
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    // Fetch everything first (all-or-nothing before assembly starts).
    let mut artifacts: Vec<(&crate::types::LockedPackage, PathBuf)> = Vec::new();
    for &p in &packages {
        let wheel_file = match p.kind {
            ArtifactKind::Wheel => download_verified(store, &p.url, &p.sha256)?,
            // sdist -> wheel via sandboxed derivation (network denied).
            ArtifactKind::Sdist => {
                crate::build::build_sdist_wheel_at_depth(
                    store,
                    platform,
                    p,
                    &pin.version,
                    Some(plan),
                    sdist_depth + 1,
                )?
            }
        };
        artifacts.push((p, wheel_file));
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

    let candidate = crate::policy::object_exceptions();
    let (object, applied) = store.commit(&identity, &staged, &candidate)?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// If `path` is a real directory (a pre-blanket install), move it out of the
/// project into `<blanket-home>/backups/` so no tool (tsc, vitest, eslint)
/// ever crawls it again. blanket-home is derived from the env object's store
/// (`<store>/objects/<id>` -> store parent), so tests with temp stores back
/// up into the temp dir, never the real one. Returns the backup location.
pub fn backup_real_dir(path: &Path, env_obj: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(md) if !md.file_type().is_symlink() && md.is_dir() => {}
        _ => return Ok(None),
    }
    let home = env_obj
        .parent() // objects/
        .and_then(|p| p.parent()) // store root
        .and_then(|p| p.parent()) // blanket home
        .ok_or_else(|| io::Error::other("cannot locate blanket home for backup"))?;
    let backups = home.join("backups");
    fs::create_dir_all(&backups)?;
    let project = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let dirname = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dir".into());
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dest = backups.join(format!("{project}-{dirname}-{secs}"));
    fs::rename(path, &dest).map_err(|e| {
        io::Error::new(e.kind(), format!(
            "could not move existing {} aside to {}: {e}",
            path.display(),
            dest.display()
        ))
    })?;
    eprintln!(
        "blanket: moved existing {} to {} (delete it once you're happy)",
        path.display(),
        dest.display()
    );
    Ok(Some(dest))
}

/// Project an env into a project directory: `.venv` symlink (atomic swap)
/// plus closure-envelope provenance (.blanket/closures/python.json).
pub fn project_env(project_dir: &Path, env_obj: &Path, plan: &Plan) -> io::Result<()> {
    project_env_inner(project_dir, env_obj, plan, None)
}

/// Project a Python env and retain the exact interpreter constraint that led
/// to the selected pin. This is separate from `project_env` to keep the
/// existing kernel-facing helper compatible with hand-built Plans.
pub fn project_env_with_selection(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: &pyselect::PythonSelection,
) -> io::Result<()> {
    project_env_inner(project_dir, env_obj, plan, Some(selection))
}

fn project_env_inner(
    project_dir: &Path,
    env_obj: &Path,
    plan: &Plan,
    selection: Option<&pyselect::PythonSelection>,
) -> io::Result<()> {
    let venv = project_dir.join(".venv");
    backup_real_dir(&venv, env_obj)?;
    let tmp = project_dir.join(format!(
        ".venv.blanket-swap.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    symlink(env_obj, &tmp)?;
    fs::rename(&tmp, &venv)?; // atomic replace, including over an old symlink

    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
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
    write_closure(
        project_dir,
        "python",
        serde_json::json!({
            "env_object": env_obj,
            "plan": plan,
            "python": python,
        }),
    )
}

#[cfg(test)]
mod closure_platform_tests {
    use super::*;
    use sha2::Digest as _;
    use crate::types::LockedPackage;

    fn test_store(label: &str) -> Store {
        let root = std::env::temp_dir().join(format!("blanket-project-identity-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        Store { root: root.canonicalize().unwrap() }
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
        }
    }

    fn cached_build_plan(store: &Store, requirement: &str, sha256: &str) -> String {
        let platform = Platform::host().unwrap();
        let requires = vec![requirement.to_string()];
        let key = crate::build_requires::lock_cache_key(platform, "3.12.14", &requires, None);
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
            }],
        };
        fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        key
    }

    fn write_closure(dir: &Path, platform: Option<&str>) {
        fs::create_dir_all(dir.join(".blanket/closures")).unwrap();
        let mut v = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"ok": true}
        });
        if let Some(platform) = platform {
            v["platform"] = serde_json::Value::String(platform.to_string());
        }
        fs::write(dir.join(".blanket/closures/python.json"), v.to_string()).unwrap();
    }

    #[test]
    fn foreign_platform_closure_is_refused_and_legacy_is_accepted() {
        let host = Platform::host().unwrap();
        let foreign = Platform::ALL
            .iter()
            .copied()
            .find(|p| *p != host)
            .unwrap();
        let dir = std::env::temp_dir().join(format!("blanket-closure-plat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        write_closure(&dir, Some(foreign.triple()));
        let err = read_closure(&dir, "python").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
        assert!(err.to_string().contains(foreign.triple()), "{err}");

        write_closure(&dir, Some(host.triple()));
        assert_eq!(read_closure(&dir, "python").unwrap()["ok"], true);

        write_closure(&dir, None); // pre-port envelope
        assert_eq!(read_closure(&dir, "python").unwrap()["ok"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fast_sdist_parent_input_keeps_the_legacy_identity() {
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
                ("store_root".into(), store.root.to_string_lossy().into_owned()),
                ("cpython".into(), python::object_id_for(Platform::host().unwrap(), "3.12.14").unwrap()),
                (
                    "pkg:fast-golden".into(),
                    format!("Sdist:{}:{}", fast.sha256, crate::build::derivation_fingerprint()),
                ),
            ]),
        }
        .object_id();
        assert_eq!(actual, expected);
        let _ = fs::remove_dir_all(&store.root);
    }

    #[test]
    fn isolated_sdist_build_environment_changes_parent_identity() {
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
        assert_ne!(first, second, "schema-3 build-env input must affect parent id");
        assert_eq!(key, crate::build_requires::lock_cache_key(
            Platform::host().unwrap(),
            "3.12.14",
            &["setuptools~=83.1".into()],
            None,
        ));
        let _ = fs::remove_dir_all(&store.root);
    }
}

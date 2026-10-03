//! From project inputs to a Python `Plan`: manifest discovery, interpreter
//! selection, `uv` locking of unpinned requirements, the PyPI planner, and
//! the project-local plan cache.

use crate::comforter;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::{DelegateSpec, DoorKind, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use crate::kernel::types;
use crate::kernel::ui;
use crate::tailors::python;
use crate::tailors::python::manifest;
use crate::tailors::python::pypi;
use crate::tailors::python::pyselect;
use std::io;
use std::path::{Path, PathBuf};

pub const PLANNER_SCHEMA: &str = "python-planner/3";
const PLAN_CACHE: &str = ".tog/plan.json";
const MANIFEST_REQUIREMENTS: &str = ".tog/manifest-requirements.txt";
const MANIFEST_CONSTRAINTS: &str = ".tog/manifest-constraints.txt";
const LOCK_STAMP: &str = ".tog/lock-source.hash";

pub fn planner_input_hash(
    platform: Platform,
    python_version: &str,
    text: &str,
    glibc: pypi::Glibc,
) -> String {
    use sha2::{Digest, Sha256};
    let glibc_input = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        format!("\0{}.{}", glibc.0, glibc.1)
    } else {
        String::new()
    };
    hex::encode(Sha256::digest(
        format!(
            "{PLANNER_SCHEMA}\x00{python_version}\x00{text}\x00{}{glibc_input}",
            platform.triple(),
        )
        .as_bytes(),
    ))
}

pub fn has_python_input(project: &ProjectRoot) -> io::Result<bool> {
    manifest::has_manifest(project)
}

/// The Python plan, the interpreter selection it was made with, and the
/// project files it was computed from (recorded in the closure for status).
pub type PythonPlan = (
    types::Plan,
    pyselect::PythonSelection,
    Vec<comforter::InputRecord>,
);

/// Candidate input files for the status record: the manifest that won, the
/// interpreter request, and every lock tog reads or writes, hashed through
/// the held project descriptor by `comforter::input_records`.
pub fn python_input_records(
    project: &ProjectRoot,
    manifest: &manifest::Manifest,
) -> io::Result<Vec<comforter::InputRecord>> {
    let dir = project.path();
    let mut candidates: Vec<PathBuf> = Vec::new();
    match &manifest.source_path {
        Some(path) => candidates.push(path.clone()),
        None => candidates.push(dir.join(&manifest.input)),
    }
    for extra in [
        ".python-version",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "requirements.lock.txt",
        "uv.lock",
        "poetry.lock",
        "pdm.lock",
    ] {
        candidates.push(dir.join(extra));
    }
    comforter::input_records(project, &candidates)
}

/// Plan from project inputs, returning the interpreter selection that was
/// used. The manifest layer may only learn the constraint after a sandboxed
/// `setup.py egg_info`, so the selection is made here and handed back to the
/// caller: planning, realization and the closure all use this one value.
///
/// Planning hits PyPI, so successful plans are cached in `.tog/plan.json`
/// keyed by a hash of the inputs; an unchanged lock replans offline.
///
/// The project is read, and `.tog` written, through the held descriptor;
/// its path only names files to uv and to the messages.
pub fn read_plan(
    project: &ProjectRoot,
    selected: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<PythonPlan> {
    let (dir, platform) = (project.path(), door.platform());
    // The interpreter is decided: it is the one this project's toolchain
    // selection names. Planning reads the manifest with it and checks it
    // against every declared constraint; nothing here reselects, so a
    // `setup.py` probe cannot move the version out from under the lock.
    let version = selected.version("cpython")?;
    let mut manifest = manifest::discover(platform, project, version)?;
    let mut selection = pyselect::locked(platform, version, &manifest.python)?;
    if manifest.requires_setup() {
        let dynamic_dependencies = manifest.dynamic_dependencies;
        if let Err(error) = manifest.prepare_setup(project, selected, door) {
            // Every ordinary failure in here is already `InvalidData`
            // (`unreadable` in the manifest layer hardcodes it, and it
            // wraps the sandboxed egg_info probe), so the kind cannot
            // tell a descriptor refusal from a probe that did not work.
            // Fall back on both: a symlinked `.tog` is still refused a
            // few lines below, at the first write through the project
            // descriptor.
            if !dynamic_dependencies {
                return Err(error);
            }
            let Some(mut fallback) = manifest::dynamic_requirements_fallback(project)? else {
                return Err(error);
            };
            // The probe's error carries the sandbox log's last lines after
            // a marker; those go out as progress lines first, so the
            // warning and its next line stay a pair.
            let text = error.to_string();
            let (reason, tail) = match text.split_once("last 20 lines:\n") {
                Some((reason, tail)) => (reason.trim_end_matches("; ").to_string(), Some(tail)),
                None => (text.clone(), None),
            };
            if let Some(tail) = tail {
                ui::note("setup.py probe output, last 20 lines:");
                for line in tail.lines() {
                    ui::note(&format!("  {line}"));
                }
            }
            // `next:`, not `fix:`: re-running the probe by hand shows why
            // it failed; it does not make it pass.
            ui::warning_next(
                &format!(
                    "setup.py metadata probe failed; using the requirements directory \
                     convention: {reason}"
                ),
                "tog run python setup.py egg_info",
            );
            fallback.python = manifest.python.clone();
            manifest = fallback;
        }
        // The probe may have added a `requires-python` the lock never
        // reads. It cannot change the interpreter, so it is checked
        // against the locked one instead: the probe loop this replaces
        // existed only to let selection chase its own metadata.
        selection = pyselect::locked(platform, version, &manifest.python)?;
    }
    if manifest.is_empty() && !manifest.provenance.contains("empty manifest") {
        manifest.provenance.push_str(" (empty manifest)");
    }
    ui::note(&format!("python inputs: {}", manifest.provenance));
    let input = manifest.input.clone();
    let source = manifest.requirements_text();
    let resolver_source = manifest.resolver_text();
    if !input.starts_with("requirements") {
        record_skippable_specs(&input, &source)?;
    }
    selection.emit_warnings();

    // A found manifest may intentionally declare no dependencies. Keep the
    // interpreter-only plan on the normal realization/projection path, but do
    // not ask uv to compile an empty setup.cfg or requirements file.
    let inputs = python_input_records(project, &manifest)?;
    if manifest.is_empty() {
        return Ok((
            types::Plan {
                ecosystem: "python".into(),
                python_version: version.into(),
                packages: Vec::new(),
            },
            selection,
            inputs,
        ));
    }

    if let Some(packages) = manifest.locked_packages {
        return Ok((
            types::Plan {
                ecosystem: "python".into(),
                python_version: version.into(),
                packages,
            },
            selection,
            inputs,
        ));
    }

    let generated_input = if (input.starts_with("requirements") || is_fully_pinned(&source))
        && resolver_source == source
    {
        None
    } else {
        // The compile input is named to uv by pathname, but tog writes it
        // through the held project descriptor so a symlinked `.tog` is
        // refused rather than followed.
        let path = dir.join(MANIFEST_REQUIREMENTS);
        let mut text = if manifest.has_constraints() {
            let constraints = dir.join(MANIFEST_CONSTRAINTS);
            project.write_file(
                Path::new(MANIFEST_CONSTRAINTS),
                manifest.constraints_text().as_bytes(),
            )?;
            format!(
                "{}-c {}\n",
                manifest.normalized_requirements_text(),
                constraints.display()
            )
        } else {
            resolver_source.clone()
        };
        if text.is_empty() {
            text.push('\n');
        }
        project.write_file(Path::new(MANIFEST_REQUIREMENTS), text.as_bytes())?;
        Some(path)
    };
    let compile_path = if generated_input.is_some() {
        generated_input.as_deref()
    } else {
        manifest.source_path.as_deref()
    };
    let text = if is_fully_pinned(&source) {
        match pypi::parse_requirements(&source) {
            Ok(_) => source,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
            Err(e) => {
                ui::note(&format!(
                    "requirements.txt is pinned but not directly consumable ({e}); \
                     re-locking for this platform with uv into requirements.lock.txt"
                ));
                let text = locked_requirements(
                    door,
                    project,
                    &input,
                    &resolver_source,
                    selected,
                    compile_path,
                )?;
                // Said once the lock exists, with its full path: an
                // automatic sync can run from a subdirectory of the project.
                let lock = dir.join("requirements.lock.txt");
                ui::warning(
                    &format!(
                        "{} holds the pins this platform can consume; commit it so every \
                         sync reads the same lock",
                        lock.display()
                    ),
                    &ui::shell_line(&["git", "add", &lock.display().to_string()]),
                );
                text
            }
        }
    } else {
        locked_requirements(
            door,
            project,
            &input,
            &resolver_source,
            selected,
            compile_path,
        )?
    };

    // These are project-local .tog caches, not store identities; one
    // re-plan after moving a project between platforms is acceptable.
    let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        pypi::host_glibc()?
    } else {
        pypi::Glibc(0, 0)
    };
    // The lock may have just been (re)written above: hash it now.
    let inputs = python_input_records(project, &manifest)?;
    let input_hash = planner_input_hash(platform, version, &text, glibc);
    // A symlinked or non-regular cache is a refusal; an unreadable regular
    // file is a miss that the write below replaces.
    let cached = match project.read_file(Path::new(PLAN_CACHE)) {
        Ok(cached) => cached,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
        Err(_) => None,
    };
    if let Some(cached) = cached {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash.as_str() {
                if let Ok(plan) = serde_json::from_value::<types::Plan>(v["plan"].clone()) {
                    return Ok((plan, selection, inputs));
                }
            }
        }
    }

    let plan = pypi::plan_python(platform, &text, version)?;
    project.write_file(
        Path::new(PLAN_CACHE),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "input_hash": input_hash,
            "plan": plan,
        }))?,
    )?;
    Ok((plan, selection, inputs))
}

pub fn record_skippable_specs(input: &str, source: &str) -> io::Result<()> {
    record_skippable_specs_with(input, source, policy::record)
}

pub fn record_skippable_specs_with<F>(_input: &str, source: &str, mut record: F) -> io::Result<()>
where
    F: FnMut(&str, &str, &str) -> io::Result<()>,
{
    let specs: Vec<String> = pypi::skippable_specs(source);
    for spec in specs {
        record(
            policy::REQUIREMENT_SKIPPED,
            &spec,
            "project-local or direct reference is not a locked registry package",
        )?;
    }
    for option in pypi::unattested_index_options(source) {
        record(
            policy::UNATTESTED_INDEX,
            &option,
            "requirements index/find-links options are recorded but never followed",
        )?;
    }
    Ok(())
}

/// Most non-comment logical lines (after backslash continuations) carry a
/// --hash= option. That is the shape `uv pip compile --generate-hashes`
/// emits and the only shape the planner accepts directly.
pub fn is_fully_pinned(text: &str) -> bool {
    let mut logical = String::new();
    let mut any = false;
    for raw in text.lines().chain(std::iter::once("")) {
        if let Some(stripped) = raw.strip_suffix('\\') {
            logical.push_str(stripped);
            continue;
        }
        logical.push_str(raw);
        let line = logical.trim();
        let line = match line.find(" #") {
            Some(i) => line[..i].trim(),
            None => line,
        };
        if !line.is_empty() && !line.starts_with('#') {
            any = true;
            let spec = line
                .split_whitespace()
                .filter(|token| !token.starts_with("--hash="))
                .collect::<Vec<_>>()
                .join(" ");
            if pypi::is_skippable_spec(&spec) {
                logical.clear();
                continue;
            }
            if !line.contains("--hash=") {
                return false;
            }
        }
        logical.clear();
    }
    any
}

/// Resolve ranged requirements to a hash-pinned lock via uv, cached in
/// requirements.lock.txt and regenerated when the source input changes.
/// uv runs in the project by path; the lock it writes is read back through
/// the held descriptor.
///
/// uv runs through a missing-lock door on `door`'s scope.
pub fn locked_requirements(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    input: &str,
    source: &str,
    selected: &Selected,
    compile_path: Option<&Path>,
) -> io::Result<String> {
    let dir = project.path();
    let pyver = selected.version("cpython")?;
    let lock_path = Path::new("requirements.lock.txt");
    let source_hash = if compile_path.is_some_and(|path| {
        !path
            .components()
            .any(|component| component.as_os_str() == ".tog")
    }) {
        let path = compile_path.expect("checked above");
        let tree_hash = manifest::requirements_tree_hash(project, path)?;
        lock_source_hash(pyver, &format!("{source}\0{tree_hash}"))
    } else {
        lock_source_hash(pyver, source)
    };
    // The stamp is tog's own state (strict no-follow read); the lock is a
    // project input. Anything unreadable is a miss, as before.
    if let (Ok(Some(stamp)), Ok(Some(lock))) = (
        project.read_file(Path::new(LOCK_STAMP)),
        project.read_input_string(lock_path),
    ) {
        if cached_lock_matches(&String::from_utf8_lossy(&stamp), &lock, &source_hash) {
            return Ok(lock);
        }
    }
    ui::note(&format!(
        "{input} is not hash-pinned; resolving with the store uv..."
    ));
    // Store-pinned uv, not host uv: a bare machine needs only tog.
    let uv = python::realize_uv(door.store(), door.lease(), door.platform(), selected)?.join("uv");
    let compile_input = compile_path.and_then(|path| path.to_str()).unwrap_or(input);
    let mut spec = DelegateSpec::new(&uv);
    spec.args(["pip", "compile", compile_input, "--generate-hashes"]);
    if !ui::verbose() {
        spec.arg("--quiet");
    }
    spec.args(["--python-version", pyver])
        // Manifest index directives and ambient pip/uv index variables are
        // never trusted. Resolution is explicitly public PyPI only.
        .args(["--index-url", "https://pypi.org/simple"])
        .args(["-o", "requirements.lock.txt"])
        .lock_root(dir)
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    spec.trace();
    let status = door
        .reopen(DoorKind::MissingLock)
        .run(spec)
        .map_err(|e| io::Error::new(e.kind(), format!("run store uv ({}): {e}", uv.display())))?
        .status;
    if !status.success() {
        return Err(io::Error::other("uv pip compile failed"));
    }
    // The stamp is the only file tog writes here, and it goes through the
    // held project descriptor, so a `.tog` swapped for a symlink is refused
    // rather than followed. `requirements.lock.txt` beside it is uv's own
    // write by pathname.
    project.write_file(Path::new(LOCK_STAMP), source_hash.as_bytes())?;
    project.read_input_string(lock_path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: uv wrote no lock", dir.join(lock_path).display()),
        )
    })
}

pub fn cached_lock_matches(stamp: &str, lock: &str, source_hash: &str) -> bool {
    !lock.is_empty() && stamp.trim() == source_hash
}

/// Stamp deciding whether `uv pip compile` must re-run. Deliberately NOT
/// platform-qualified: `.tog/lock-source.hash` is per-machine state and
/// the format is byte-identical to the pre-port one, so existing darwin
/// stamps stay valid after the Linux port (platform lives in
/// `planner_input_hash`, which keys the plan cache).
pub fn lock_source_hash(pyver: &str, source: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{pyver}\x00{source}").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::StoreActivity;
    use crate::kernel::store;
    use crate::kernel::supervise;

    /// A lease on `store` itself, for the case that runs a child against it.
    /// The other cases use a store that is absent or not a directory on
    /// purpose, so they borrow `testutil::detached_lease` instead.
    fn test_activity(store: &store::Store) -> StoreActivity {
        store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap()
    }

    /// The selection these tests plan with: the shipped release for the
    /// interpreter the fixtures expect. Choosing it is the kernel's job.
    fn selected() -> crate::kernel::toolchain::Selected {
        python::shipped_selection(pyselect::DEFAULT_VERSION).expect("shipped CPython release")
    }

    #[test]
    fn cache_key_builders_track_independent_inputs() {
        let source = "six==1.17.0\n";
        let darwin_plan = planner_input_hash(
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            source,
            pypi::Glibc(0, 0),
        );
        let linux_plan = planner_input_hash(
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            source,
            pypi::Glibc(2, 43),
        );
        let linux_changed_glibc = planner_input_hash(
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            source,
            pypi::Glibc(2, 42),
        );
        let changed_plan = planner_input_hash(
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            "six==1.17.0\n# changed",
            pypi::Glibc(0, 0),
        );
        assert_ne!(darwin_plan, changed_plan); // source only
        assert_ne!(darwin_plan, linux_plan); // platform only
        assert_ne!(linux_plan, linux_changed_glibc); // host glibc only
        assert_eq!(
            darwin_plan,
            planner_input_hash(
                Platform::Aarch64AppleDarwin,
                "3.12.14",
                source,
                pypi::Glibc(2, 43),
            )
        ); // neither
        assert_eq!(
            darwin_plan,
            "dc181496c6681389a89b3191dba44abdfe8efef8044e540777e7b62c91166411"
        );

        // The lock-source stamp is platform-free on purpose (see its doc):
        // this is main's exact format, so pre-port darwin stamps stay valid.
        let lock = lock_source_hash("3.12", source);
        let changed_lock = lock_source_hash("3.12", "six==1.17.0\n# changed");
        assert_ne!(lock, changed_lock); // source only
        assert_eq!(lock, lock_source_hash("3.12", source)); // same input
        assert!(cached_lock_matches(&lock, "six==1.17.0\n", &lock));
        assert!(!cached_lock_matches(&changed_lock, "six==1.17.0\n", &lock));
        assert!(!cached_lock_matches(&lock, "", &lock));
        {
            use sha2::{Digest, Sha256};
            assert_eq!(
                lock,
                hex::encode(Sha256::digest(format!("3.12\x00{source}").as_bytes()))
            );
        }
    }

    #[test]
    fn plan_cache_behind_a_symlinked_tog_is_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project = temp.0.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        // Hash-pinned, so planning never needs uv and the cache read is the
        // first store-free step that can refuse.
        std::fs::write(
            project.join("requirements.txt"),
            format!("six==1.17.0 --hash=sha256:{}\n", "a".repeat(64)),
        )
        .unwrap();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(outside.join(".tog")).unwrap();
        std::os::unix::fs::symlink(outside.join(".tog"), project.join(".tog")).unwrap();
        let store = store::Store {
            root: temp.0.join("absent-store"),
        };
        let root = ProjectRoot::open(&project).unwrap();
        let e = read_plan(
            &root,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not a real directory"), "{e}");
        assert!(!store.root.exists(), "a refused cache touched the store");
        assert!(
            std::fs::read_dir(outside.join(".tog"))
                .unwrap()
                .next()
                .is_none(),
            "wrote through the symlinked .tog"
        );
    }

    /// Plant the pinned uv as a script that writes the lock uv would have
    /// produced. `ensure_uv_for` returns a store object it already has, so
    /// `locked_requirements` reaches its stamp write with no network.
    fn store_with_stub_uv(root: &Path) -> store::Store {
        use std::os::unix::fs::PermissionsExt as _;
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = store::Store {
            root: root.canonicalize().unwrap(),
        };
        crate::tailors::install_kinds();
        let host = Platform::host().unwrap();
        let pin = python::uv_pins()
            .unwrap()
            .iter()
            .find(|pin| pin.platform == host)
            .unwrap();
        let staged = store.stage().unwrap();
        let uv = staged.join("uv");
        std::fs::write(
            &uv,
            "#!/bin/sh\necho 'six==1.17.0 --hash=sha256:aaaa' > requirements.lock.txt\n",
        )
        .unwrap();
        std::fs::set_permissions(&uv, std::fs::Permissions::from_mode(0o755)).unwrap();
        store
            .commit_with_deps(
                &python::uv_identity(pin),
                &staged,
                &[],
                &store::ObjectDeps::new(),
            )
            .unwrap();
        store
    }

    #[test]
    fn lock_stamp_behind_a_symlinked_tog_is_refused() {
        let _supervision = supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        // Unpinned, so planning has to re-lock and reach the stamp write.
        std::fs::write(project_dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project_dir.join(".tog")).unwrap();
        let store = store_with_stub_uv(&temp.0.join("store"));

        let project = ProjectRoot::open(&project_dir).unwrap();
        let error = read_plan(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &test_activity(&store),
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a real directory"), "{error}");
        // uv's own lock landed in the project; only tog's stamp was refused.
        assert!(project_dir.join("requirements.lock.txt").is_file());
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "wrote the lock stamp through the symlinked .tog"
        );
    }

    /// A `setup.py egg_info` probe that cannot run must not abort planning:
    /// a PEP 621 `dynamic = ["dependencies"]` project falls back to the
    /// requirements-directory convention. Everything `prepare_setup` can
    /// fail with is already `InvalidData` (`unreadable` in the manifest
    /// layer hardcodes it), so the fallback cannot be gated on the kind.
    #[test]
    fn a_probe_failure_falls_back_to_the_requirements_directory() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(project_dir.join("requirements")).unwrap();
        std::fs::write(
            project_dir.join("pyproject.toml"),
            "[project]\nname = \"p\"\nversion = \"0\"\ndynamic = [\"dependencies\"]\n",
        )
        .unwrap();
        std::fs::write(
            project_dir.join("setup.py"),
            "from setuptools import setup\nsetup()\n",
        )
        .unwrap();
        let pinned = format!("six==1.17.0 --hash=sha256:{}\n", "a".repeat(64));
        std::fs::write(project_dir.join("requirements/common.txt"), &pinned).unwrap();
        // A store root that is a regular file: the probe's first store
        // access fails offline and immediately, which is the cheapest
        // stand-in for "egg_info cannot run here".
        let store_root = temp.0.join("not-a-store");
        std::fs::write(&store_root, b"").unwrap();
        let store = store::Store { root: store_root };

        // Prime the plan cache under the key the fallback text produces, so
        // planning finishes offline. A cache hit is itself the assertion:
        // if the probe failure had aborted, or the fallback had read
        // anything but requirements/common.txt, this key would not match.
        let platform = Platform::host().unwrap();
        let version = pyselect::select_python(platform, &[]).unwrap().pin.version;
        let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            pypi::host_glibc().unwrap()
        } else {
            pypi::Glibc(0, 0)
        };
        let plan = types::Plan {
            ecosystem: "python".into(),
            python_version: version.into(),
            packages: Vec::new(),
        };
        let project = ProjectRoot::open(&project_dir).unwrap();
        project
            .write_file(
                Path::new(PLAN_CACHE),
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "input_hash": planner_input_hash(platform, version, &pinned, glibc),
                    "plan": plan,
                }))
                .unwrap(),
            )
            .unwrap();

        let (planned, selection, inputs) = read_plan(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                platform,
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap();
        assert_eq!(planned.python_version, version);
        assert_eq!(selection.pin.version, version);
        assert!(
            inputs
                .iter()
                .any(|record| record.path == "requirements/common.txt"),
            "planning did not read the requirements directory: {:?}",
            inputs.iter().map(|r| &r.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn manifest_snapshots_behind_a_symlinked_tog_are_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project_dir = temp.0.join("proj");
        std::fs::create_dir_all(&project_dir).unwrap();
        // A pyproject manifest needs a generated uv compile input, so the
        // manifest snapshot is written before uv or the store is reached.
        std::fs::write(
            project_dir.join("pyproject.toml"),
            "[project]\nname = \"p\"\nversion = \"0\"\ndependencies = [\"six\"]\n",
        )
        .unwrap();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, project_dir.join(".tog")).unwrap();
        let store = store::Store {
            root: temp.0.join("absent-store"),
        };

        let project = ProjectRoot::open(&project_dir).unwrap();
        let error = read_plan(
            &project,
            &selected(),
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &crate::kernel::testutil::detached_lease().1,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a real directory"), "{error}");
        assert!(!store.root.exists(), "a refused snapshot touched the store");
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "wrote a manifest snapshot through the symlinked .tog"
        );
    }

    #[test]
    fn plan_skipped_requirement_is_strict_or_recorded_once() {
        let _attribution_lock = policy::exception_guard();
        let attribution = policy::Attribution::open("python").unwrap();
        let source = ".\n";
        let strict = policy::Policy {
            strict: true,
            ..policy::Policy::default()
        };
        let error =
            record_skippable_specs_with("requirements.txt", source, |kind, subject, detail| {
                policy::record_with(&strict, kind, subject, detail)
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut recorded = Vec::new();
        record_skippable_specs_with("requirements.txt", source, |kind, subject, detail| {
            recorded.push((kind.to_string(), subject.to_string(), detail.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(pypi::parse_requirements(source).unwrap().is_empty());
        attribution.discard();
    }
}

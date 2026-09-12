//! From project inputs to a Python `Plan`: manifest discovery, interpreter
//! selection, `uv` locking of unpinned requirements, the PyPI planner, and
//! the project-local plan cache. Moved from `commands/shared.rs` (Stage 3).

use crate::comforter;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store;
use crate::kernel::supervise;
use crate::kernel::types;
use crate::kernel::ui;
use crate::tailors::python;
use crate::tailors::python::manifest;
use crate::tailors::python::pypi;
use crate::tailors::python::pyselect;
use std::io;
use std::path::{Path, PathBuf};

pub const PLANNER_SCHEMA: &str = "python-planner/3";

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

pub fn has_python_input(dir: &Path) -> io::Result<bool> {
    manifest::has_manifest(dir)
}

/// Plan from project inputs. Planning hits PyPI, so successful plans are
/// cached in .blanket/plan.json keyed by a hash of the inputs; an unchanged
/// lock replans offline and instantly.
/// Plan from project inputs, returning the interpreter selection that was
/// used. The manifest layer may only learn the constraint after a sandboxed
/// `setup.py egg_info`, so the selection is made here and handed back to the
/// caller: planning, realization and the closure all use this one value.
/// The Python plan, the interpreter selection it was made with, and the
/// project files it was computed from (recorded in the closure for status).
pub type PythonPlan = (
    types::Plan,
    pyselect::PythonSelection,
    Vec<comforter::InputRecord>,
);

/// Candidate input files for the status record: the manifest that won, the
/// interpreter request, and every lock blanket reads or writes.
pub fn python_input_records(
    dir: &Path,
    manifest: &manifest::Manifest,
) -> io::Result<Vec<comforter::InputRecord>> {
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
    comforter::input_records(dir, &candidates)
}

pub fn read_plan(platform: Platform, dir: &Path, store: &store::Store) -> io::Result<PythonPlan> {
    let mut manifest = manifest::discover(platform, dir)?;
    let mut selection = pyselect::select_python_with_inputs(platform, &manifest.python)?;
    if manifest.requires_setup() {
        let dynamic_dependencies = manifest.dynamic_dependencies;
        const MAX_SETUP_PROBES: usize = 3;
        let mut selection_history = vec![selection.pin.version.to_string()];
        let mut stabilized = false;
        for _ in 0..MAX_SETUP_PROBES {
            let probed_version = selection.pin.version;
            if let Err(error) = manifest.prepare_setup(platform, dir, store, probed_version) {
                if !dynamic_dependencies {
                    return Err(error);
                }
                let Some(mut fallback) = manifest::dynamic_requirements_fallback(dir)? else {
                    return Err(error);
                };
                eprintln!(
                    "blanket: setup.py metadata probe failed; using the requirements directory convention: {error}"
                );
                fallback.python = manifest.python.clone();
                manifest = fallback;
                selection = pyselect::select_python_with_inputs(platform, &manifest.python)?;
                stabilized = true;
                break;
            }

            let next = pyselect::select_python_with_inputs(platform, &manifest.python)?;
            if next.pin.version == probed_version {
                selection = next;
                stabilized = true;
                break;
            }
            selection = next;
            selection_history.push(selection.pin.version.to_string());
        }
        if !stabilized {
            return Err(io::Error::other(format!(
                "setup.py metadata probe and Python selection did not stabilize after {MAX_SETUP_PROBES} probes (oscillation: {})",
                selection_history.join(" -> "),
            )));
        }
    }
    if manifest.is_empty() && !manifest.provenance.contains("empty manifest") {
        manifest.provenance.push_str(" (empty manifest)");
    }
    eprintln!("blanket: python inputs: {}", manifest.provenance);
    let input = manifest.input.clone();
    let source = manifest.requirements_text();
    let resolver_source = manifest.resolver_text();
    if !input.starts_with("requirements") {
        record_skippable_specs(&input, &source)?;
    }
    selection.emit_warnings();
    let pin = selection.pin;

    // A found manifest may intentionally declare no dependencies. Keep the
    // interpreter-only plan on the normal realization/projection path, but do
    // not ask uv to compile an empty setup.cfg or requirements file.
    let inputs = python_input_records(dir, &manifest)?;
    if manifest.is_empty() {
        return Ok((
            types::Plan {
                ecosystem: "python".into(),
                python_version: pin.version.into(),
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
                python_version: pin.version.into(),
                packages,
            },
            selection,
            inputs,
        ));
    }

    let generated_input = if input.starts_with("requirements") && resolver_source == source {
        None
    } else if is_fully_pinned(&source) && resolver_source == source {
        None
    } else {
        let path = dir.join(".blanket/manifest-requirements.txt");
        std::fs::create_dir_all(dir.join(".blanket"))?;
        let mut text = if manifest.has_constraints() {
            let constraints = dir.join(".blanket/manifest-constraints.txt");
            std::fs::write(&constraints, manifest.constraints_text())?;
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
        std::fs::write(&path, text)?;
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
                eprintln!(
                    "blanket: requirements.txt is pinned but not directly \
                     consumable ({e}); re-locking for this platform with uv..."
                );
                locked_requirements(
                    platform,
                    dir,
                    store,
                    &input,
                    &resolver_source,
                    pin.version,
                    compile_path,
                )?
            }
        }
    } else {
        locked_requirements(
            platform,
            dir,
            store,
            &input,
            &resolver_source,
            pin.version,
            compile_path,
        )?
    };

    // These are project-local .blanket caches, not store identities; one
    // re-plan after moving a project between platforms is acceptable.
    let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        pypi::host_glibc()?
    } else {
        pypi::Glibc(0, 0)
    };
    // The lock may have just been (re)written above: hash it now.
    let inputs = python_input_records(dir, &manifest)?;
    let input_hash = planner_input_hash(platform, pin.version, &text, glibc);
    let cache_path = dir.join(".blanket/plan.json");
    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash.as_str() {
                if let Ok(plan) = serde_json::from_value::<types::Plan>(v["plan"].clone()) {
                    return Ok((plan, selection, inputs));
                }
            }
        }
    }

    let plan = pypi::plan_python(platform, &text, pin.version)?;
    std::fs::create_dir_all(dir.join(".blanket"))?;
    std::fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&serde_json::json!({
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

/// Every non-comment logical line (after backslash continuations) carries a
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
pub fn locked_requirements(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
    input: &str,
    source: &str,
    pyver: &str,
    compile_path: Option<&Path>,
) -> io::Result<String> {
    let lock_path = dir.join("requirements.lock.txt");
    let stamp_path = dir.join(".blanket/lock-source.hash");
    let source_hash = if compile_path.is_some_and(|path| {
        !path
            .components()
            .any(|component| component.as_os_str() == ".blanket")
    }) {
        let path = compile_path.expect("checked above");
        let tree_hash = manifest::requirements_tree_hash(path)?;
        lock_source_hash(pyver, &format!("{source}\0{tree_hash}"))
    } else {
        lock_source_hash(pyver, source)
    };
    if let (Ok(stamp), Ok(lock)) = (
        std::fs::read_to_string(&stamp_path),
        std::fs::read_to_string(&lock_path),
    ) {
        if cached_lock_matches(&stamp, &lock, &source_hash) {
            return Ok(lock);
        }
    }
    eprintln!("blanket: {input} is not hash-pinned; resolving with the store uv...");
    // Store-pinned uv, not host uv: a bare machine needs only blanket.
    let uv = python::ensure_uv_for(store, platform)?.join("uv");
    let compile_input = compile_path.and_then(|path| path.to_str()).unwrap_or(input);
    let mut command = std::process::Command::new(&uv);
    command.args(["pip", "compile", compile_input, "--generate-hashes"]);
    if !ui::verbose() {
        command.arg("--quiet");
    }
    command
        .args(["--python-version", pyver])
        // Manifest index directives and ambient pip/uv index variables are
        // never trusted. Resolution is explicitly public PyPI only.
        .args(["--index-url", "https://pypi.org/simple"])
        .args(["-o", "requirements.lock.txt"])
        .current_dir(dir)
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    ui::trace_command(&command);
    let status = supervise::status_owned(&mut command, store)
        .map_err(|e| io::Error::new(e.kind(), format!("run store uv ({}): {e}", uv.display())))?;
    if !status.success() {
        return Err(io::Error::other("uv pip compile failed"));
    }
    std::fs::create_dir_all(dir.join(".blanket"))?;
    std::fs::write(&stamp_path, &source_hash)?;
    std::fs::read_to_string(&lock_path)
}

pub fn cached_lock_matches(stamp: &str, lock: &str, source_hash: &str) -> bool {
    !lock.is_empty() && stamp.trim() == source_hash
}

/// Stamp deciding whether `uv pip compile` must re-run. Deliberately NOT
/// platform-qualified: `.blanket/lock-source.hash` is per-machine state and
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
    fn unconstrained_python_keeps_default_and_existing_cache_inputs() {
        let selection = pyselect::select_python(Platform::Aarch64AppleDarwin, &[]).unwrap();
        assert_eq!(selection.pin.version, "3.12.14");
        let source = "six==1.17.0\n";
        assert_eq!(
            planner_input_hash(
                Platform::Aarch64AppleDarwin,
                selection.pin.version,
                source,
                pypi::Glibc(0, 0),
            ),
            "dc181496c6681389a89b3191dba44abdfe8efef8044e540777e7b62c91166411"
        );
        assert_eq!(
            lock_source_hash(selection.pin.version, source),
            "2036e745694799536bfd9bee5ce7f4fbf3a1f621d96e8d54e632e4d0c2334c67"
        );
    }

    #[test]
    fn plan_skipped_requirement_is_strict_or_recorded_once() {
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
    }
}

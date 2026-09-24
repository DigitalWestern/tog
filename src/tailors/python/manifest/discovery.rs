//! Manifest discovery (python tailor): which files a project has, which
//! manifest shape wins, and the `[tool.tog]` configuration that steers it.

use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct TogPythonConfig {
    pub(super) requirements: Option<PathBuf>,
    pub(super) extras: BTreeSet<String>,
}

pub(super) fn config(project: &ProjectRoot) -> io::Result<TogPythonConfig> {
    let path = project.path().join("tog.toml");
    if !is_project_file(project, &path) {
        return Ok(TogPythonConfig::default());
    }
    let value = parse_toml(&path, &read_text(project, &path)?)?;
    let Some(python) = value.get("python").and_then(toml::Value::as_table) else {
        return Ok(TogPythonConfig::default());
    };
    let requirements = python
        .get("requirements")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from);
    let extras = python
        .get("extras")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_ascii_lowercase)
        .collect();
    Ok(TogPythonConfig {
        requirements,
        extras,
    })
}

pub(super) fn pyproject_sections(value: &toml::Value) -> (bool, bool, bool) {
    let project = value.get("project").and_then(toml::Value::as_table);
    // A PEP 621 project with no dependencies is still a real, empty Python
    // manifest. This covers metadata-only projects such as youtube-dl.
    let has_project = project.is_some();
    let poetry = value
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(toml::Value::as_table)
        .is_some();
    let groups = value.get("dependency-groups").is_some()
        || value
            .get("tool")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get("pdm"))
            .and_then(toml::Value::as_table)
            .is_some_and(|p| p.contains_key("dev-dependencies"));
    (has_project, poetry, groups)
}

pub(super) fn project_dependencies_are_dynamic(value: &toml::Value) -> bool {
    value
        .get("project")
        .and_then(toml::Value::as_table)
        .and_then(|project| project.get("dynamic"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .any(|name| name == "dependencies")
}

/// Read only enough metadata to decide whether Python is present. Parsing is
/// intentional: a found but broken manifest is reported as unreadable, not as
/// a misleading "nothing to sync here". The project is read through the
/// held descriptor.
pub fn has_manifest(project: &ProjectRoot) -> io::Result<bool> {
    let dir = project.path();
    let is_file = |name: &str| is_project_file(project, &dir.join(name));
    if is_file("requirements.lock.txt") || is_file("requirements.txt") {
        return Ok(true);
    }
    let pyproject = dir.join("pyproject.toml");
    if is_file("pyproject.toml") {
        let value = parse_toml(&pyproject, &read_text(project, &pyproject)?)?;
        let (project, poetry, groups) = pyproject_sections(&value);
        if project || poetry || groups {
            return Ok(true);
        }
    }
    if is_file("setup.cfg") || is_file("setup.py") {
        return Ok(true);
    }
    Ok(requirements_directory_candidate(project, &config(project)?)?.is_some())
}

/// Interpreter-input collection lives in `pyselect`. Keep the manifest
/// boundary's error class around it so preflight and planning report the same
/// diagnosis.
pub fn python_inputs(project: &ProjectRoot) -> io::Result<PythonInputs> {
    pyselect::collect_project_inputs(project)
        .map_err(|e| unreadable(&project.path().join("pyproject.toml"), e))
}

/// Discover the project's manifest. `python_version` is the interpreter the
/// project's toolchain selection names: marker evaluation (Poetry's
/// environment markers, a `uv.lock` entry's `python_version`) is a function
/// of the interpreter that will run, so discovery is handed the locked one
/// rather than choosing its own. The project is read through the held
/// descriptor.
pub fn discover(
    platform: Platform,
    project: &ProjectRoot,
    python_version: &str,
) -> io::Result<Manifest> {
    let dir = project.path();
    let is_file = |name: &str| is_project_file(project, &dir.join(name));
    let cfg = config(project)?;
    let collected_python = python_inputs(project)?;
    let dynamic_dependencies = if is_file("pyproject.toml") {
        let path = dir.join("pyproject.toml");
        project_dependencies_are_dynamic(&parse_toml(&path, &read_text(project, &path)?)?)
    } else {
        false
    };
    let mut manifest = if is_file("requirements.txt") {
        requirements_manifest(project, &dir.join("requirements.txt"), "requirements.txt")?
    } else if is_file("pyproject.toml") {
        let path = dir.join("pyproject.toml");
        let text = read_text(project, &path)?;
        let value = parse_toml(&path, &text)?;
        let (has_project, poetry, groups) = pyproject_sections(&value);
        // PEP 621 is the public metadata format and takes precedence when a
        // project also carries a legacy Poetry table.
        if has_project && project_dependencies_are_dynamic(&value) {
            // PEP 621's dynamic declaration is a promise that another build
            // input supplies the dependencies. An empty [project] table here
            // is not evidence of an empty environment. Let setup.py and the
            // requirements-directory convention provide that source.
            dynamic_dependencies_manifest(project, &cfg)?
        } else if has_project {
            project_manifest(project, &value, &text, &cfg)?
        } else if poetry {
            poetry_manifest(platform, project, &value, &text, &cfg, python_version)?
        } else if groups {
            project_manifest(project, &value, &text, &cfg)?
        } else {
            setup_or_requirements_manifest(project, &cfg)?
        }
    } else if is_file("setup.cfg")
        || is_file("setup.py")
        || requirements_directory_candidate(project, &cfg)?.is_some()
    {
        setup_or_requirements_manifest(project, &cfg)?
    } else if is_file("requirements.lock.txt") {
        // With no discoverable source, a lock is an explicitly supplied
        // requirements file. The generated-lock cache path is only reached
        // after a live source has been discovered above.
        let lock = dir.join("requirements.lock.txt");
        requirements_manifest(project, &lock, "requirements.lock.txt")?
    } else {
        setup_or_requirements_manifest(project, &cfg)?
    };

    manifest.python = collected_python;
    manifest.dynamic_dependencies = dynamic_dependencies;
    if let Some(packages) = manifest.uv_lock.clone() {
        let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            pypi::host_glibc()?
        } else {
            pypi::Glibc(0, 0)
        };
        manifest.locked_packages = uv_lock_manifest(
            &packages,
            &manifest.requirements,
            platform,
            python_version,
            glibc,
        )?;
    }
    if manifest.is_empty() && !manifest.requires_setup() {
        manifest.provenance.push_str(" (empty manifest)");
    }
    Ok(manifest)
}

pub(super) fn dynamic_dependencies_manifest(
    project: &ProjectRoot,
    cfg: &TogPythonConfig,
) -> io::Result<Manifest> {
    match setup_or_requirements_manifest(project, cfg) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(unreadable(
            &project.path().join("pyproject.toml"),
            "[project].dynamic includes dependencies but no setup.py or requirements directory was found",
        )),
        result => result,
    }
}

/// If a dynamic backend cannot run in the metadata sandbox, an adjacent
/// requirements tree is still a useful, explicit dependency source. This is
/// the recovery path used by projects such as vllm whose setup.py imports a
/// package that is itself not installed during egg_info.
pub fn dynamic_requirements_fallback(project: &ProjectRoot) -> io::Result<Option<Manifest>> {
    let dir = project.path();
    let cfg = config(project)?;
    let Some(path) = requirements_directory_candidate(project, &cfg)? else {
        return Ok(None);
    };
    let relative = path
        .strip_prefix(dir)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    requirements_manifest(project, &path, &relative).map(Some)
}

pub(super) fn setup_or_requirements_manifest(
    project: &ProjectRoot,
    cfg: &TogPythonConfig,
) -> io::Result<Manifest> {
    let dir = project.path();
    let setup_cfg_path = dir.join("setup.cfg");
    let setup_py_path = dir.join("setup.py");
    if is_project_file(project, &setup_cfg_path) {
        let text = read_text(project, &setup_cfg_path)?;
        let parsed = pyselect::parse_setup_cfg(&text);
        let mut requirements = parsed.install_requires.clone();
        for (extra, values) in &parsed.extras_require {
            if cfg.extras.contains(extra) {
                requirements.extend(values.iter().cloned());
            } else {
                for value in values {
                    crate::kernel::policy::record(
                        crate::kernel::policy::SKIPPED_OPTIONAL,
                        value,
                        &format!("setup.cfg extra `{extra}` was not requested"),
                    )?;
                }
            }
        }
        let setup_py_safe = if !is_project_file(project, &setup_py_path) {
            true
        } else {
            let setup_py = read_text(project, &setup_py_path)?;
            // A declarative install_requires list is authoritative. An empty
            // list is not: setup.py may provide the real dependencies, and a
            // call through an alias (for example `s(...)`) must be probed.
            setup_py_is_provably_trivial(&setup_py)
                || (parsed.install_requires_found && !parsed.install_requires.is_empty())
        };
        if setup_py_safe {
            return Ok(Manifest {
                input: "setup.cfg".into(),
                requirements,
                constraints: Vec::new(),
                python: PythonInputs::default(),
                provenance: "setup.cfg [options]".into(),
                source: text,
                source_path: Some(setup_cfg_path),
                locked_packages: None,
                uv_lock: None,
                has_index_options: false,
                has_skippable_specs: false,
                setup: false,
                setup_cfg: true,
                dynamic_dependencies: false,
            });
        }
    }
    if is_project_file(project, &setup_py_path) {
        return Ok(Manifest {
            input: "setup.py".into(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            python: PythonInputs::default(),
            provenance: "setup.py (sandboxed egg_info)".into(),
            source: String::new(),
            source_path: Some(setup_py_path),
            locked_packages: None,
            uv_lock: None,
            has_index_options: false,
            has_skippable_specs: false,
            setup: true,
            setup_cfg: false,
            dynamic_dependencies: false,
        });
    }
    let Some(path) = requirements_directory_candidate(project, cfg)? else {
        return Err(no_manifest());
    };
    let relative = path
        .strip_prefix(dir)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    requirements_manifest(project, &path, &relative)
}

pub(super) fn project_manifest(
    root: &ProjectRoot,
    value: &toml::Value,
    source: &str,
    cfg: &TogPythonConfig,
) -> io::Result<Manifest> {
    let dir = root.path();
    let mut requirements = Vec::new();
    let project = value
        .get("project")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    if let Some(dependencies) = project.get("dependencies") {
        let values = dependencies.as_array().ok_or_else(|| {
            unreadable(
                &dir.join("pyproject.toml"),
                "project.dependencies must be an array",
            )
        })?;
        for value in values {
            let value = value.as_str().ok_or_else(|| {
                unreadable(
                    &dir.join("pyproject.toml"),
                    "project.dependencies must contain strings",
                )
            })?;
            requirements.push(value.to_string());
        }
    }
    if let Some(optional_value) = project.get("optional-dependencies") {
        let optional = optional_value.as_table().ok_or_else(|| {
            unreadable(
                &dir.join("pyproject.toml"),
                "project.optional-dependencies must be a table",
            )
        })?;
        for (extra, values) in optional {
            let active = cfg.extras.contains(&extra.to_ascii_lowercase());
            let values = values.as_array().ok_or_else(|| {
                unreadable(
                    &dir.join("pyproject.toml"),
                    "optional-dependencies values must be arrays",
                )
            })?;
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    unreadable(
                        &dir.join("pyproject.toml"),
                        "optional dependency must be a string",
                    )
                })?;
                if active {
                    requirements.push(value.to_string());
                } else {
                    crate::kernel::policy::record(
                        crate::kernel::policy::SKIPPED_OPTIONAL,
                        value,
                        &format!("optional dependency group `{extra}` was not requested"),
                    )?;
                }
            }
        }
    }
    if value.get("dependency-groups").is_some() {
        crate::kernel::policy::record(
            crate::kernel::policy::SKIPPED_OPTIONAL,
            "[dependency-groups]",
            "PEP 735 dependency groups are excluded by default",
        )?;
    }
    if let Some(dev) = value
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("pdm"))
        .and_then(toml::Value::as_table)
        .and_then(|pdm| pdm.get("dev-dependencies"))
    {
        crate::kernel::policy::record(
            crate::kernel::policy::SKIPPED_OPTIONAL,
            "[tool.pdm.dev-dependencies]",
            &format!("development dependency group excluded by default ({dev})"),
        )?;
    }
    record_uv_sources(value)?;
    let uv_lock = if is_project_file(root, &dir.join("uv.lock")) {
        let path = dir.join("uv.lock");
        Some(parse_uv_lock(&read_text(root, &path)?)?)
    } else {
        None
    };
    let provenance = if uv_lock.is_some() {
        "pyproject.toml [project] (+ uv.lock)"
    } else {
        "pyproject.toml [project]"
    };
    let manifest = Manifest {
        input: "pyproject.toml".into(),
        requirements,
        constraints: Vec::new(),
        python: PythonInputs::default(),
        provenance: provenance.into(),
        source: String::new(),
        source_path: None,
        locked_packages: None,
        uv_lock,
        has_index_options: false,
        has_skippable_specs: false,
        setup: false,
        setup_cfg: false,
        dynamic_dependencies: false,
    };
    Ok(with_generated_source(manifest, source))
}

pub(super) fn with_generated_source(mut manifest: Manifest, _source: &str) -> Manifest {
    manifest.source = manifest.requirements_text();
    manifest
}

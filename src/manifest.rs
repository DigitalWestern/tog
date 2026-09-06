//! Python manifest discovery and normalization.
//!
//! A manifest is deliberately reduced to one boring intermediate form: PEP
//! 508-ish requirement lines, the Python inputs collected by `pyselect`, and
//! a short provenance string.  Lock importers may additionally provide the
//! exact artifact URL selected from their own file list; they still enter the
//! ordinary Python `Plan` and realization path.

use crate::build;
use crate::platform::Platform;
use crate::pypi;
use crate::pyselect::{self, ConstraintSource, PythonInputs};
use crate::sandbox::BuildSpec;
use crate::store::Store;
use crate::types::{ArtifactKind, LockedPackage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Manifest {
    pub input: String,
    pub requirements: Vec<String>,
    constraints: Vec<String>,
    pub python: PythonInputs,
    pub provenance: String,
    pub source: String,
    /// A real requirements file can be handed to uv so includes and
    /// constraints retain their pip semantics. Generated manifests use None.
    pub source_path: Option<PathBuf>,
    pub locked_packages: Option<Vec<LockedPackage>>,
    uv_lock: Option<Vec<UvPackage>>,
    has_index_options: bool,
    has_skippable_specs: bool,
    setup: bool,
    setup_cfg: bool,
    pub dynamic_dependencies: bool,
}

impl Manifest {
    pub fn requirements_text(&self) -> String {
        if self.input.starts_with("requirements") {
            return self.source.clone();
        }
        if self.requirements.is_empty() {
            self.source.clone()
        } else {
            self.requirements.join("\n") + "\n"
        }
    }

    /// Requirements-file text for the resolver. Index options are removed
    /// after being recorded as exceptions, and includes are flattened, so a
    /// private index named by a child file can never be followed by uv.
    pub fn resolver_text(&self) -> String {
        if self.input.starts_with("requirements")
            && self.has_index_options
        {
            return if self.requirements.is_empty() && self.constraints.is_empty() {
                String::new()
            } else {
                join_requirements(&self.requirements, &self.constraints)
            };
        }
        if self.input.starts_with("requirements")
            && (self.has_skippable_specs || !self.constraints.is_empty())
        {
            return if self.requirements.is_empty() && self.constraints.is_empty() {
                String::new()
            } else {
                join_requirements(&self.requirements, &self.constraints)
            };
        }
        self.requirements_text()
    }

    /// The normalized install requirements without constraint-only entries.
    /// The caller may write the latter to a separate `-c` file when includes
    /// or unattested options require flattening the manifest.
    pub fn normalized_requirements_text(&self) -> String {
        if self.requirements.is_empty() {
            String::new()
        } else {
            self.requirements.join("\n") + "\n"
        }
    }

    pub fn has_constraints(&self) -> bool {
        !self.constraints.is_empty()
    }

    pub fn constraints_text(&self) -> String {
        join_requirements(&[], &self.constraints)
    }

    pub fn is_empty(&self) -> bool {
        if matches!(self.input.as_str(), "setup.cfg" | "setup.py" | "pyproject.toml") {
            return self.requirements.is_empty();
        }
        self.requirements.is_empty()
            && pypi::logical_requirement_lines(&self.source)
                .iter()
                .all(|line| pypi::is_requirement_option(line) || line.trim().is_empty())
    }

    pub fn requires_setup(&self) -> bool {
        self.setup && !self.setup_cfg
    }

    /// Complete a setup.py manifest after the caller has selected the first
    /// compatible interpreter.  The metadata cache is content-addressed by
    /// the manifest tree, not by its current working directory.
    pub fn prepare_setup(
        &mut self,
        platform: Platform,
        dir: &Path,
        store: &Store,
        python_version: &str,
    ) -> io::Result<()> {
        if !self.setup || self.setup_cfg {
            return Ok(());
        }
        let tree_hash = setup_tree_hash(dir)?;
        let cache_path = dir.join(".blanket/egg-info.json");
        if let Ok(text) = fs::read_to_string(&cache_path) {
            if let Ok(cache) = serde_json::from_str::<SetupCache>(&text) {
                if setup_cache_matches(
                    &cache,
                    &tree_hash,
                    platform,
                    python_version,
                    &build::derivation_fingerprint(),
                ) {
                    self.requirements = cache.requirements;
                    self.source = self.requirements_text();
                    if let Some(value) = cache.requires_python {
                        self.python
                            .constraints
                            .push(ConstraintSource::new(value, "setup.py PKG-INFO"));
                    }
                    return Ok(());
                }
            }
        }

        let build_env = build::ensure_build_environment(store, platform, python_version)
            .map_err(|error| unreadable(&dir.join("setup.py"), error))?;
        let pin = crate::python::lookup(platform, python_version).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("no pinned CPython {python_version} for setup.py egg_info"),
            )
        })?;
        let cpython = crate::python::ensure_python_for(store, pin, platform)
            .map_err(|error| unreadable(&dir.join("setup.py"), error))?;
        let scratch = store.stage()?;
        let egg_base = scratch.join("egg-info");
        let log = scratch.join("egg-info.log");
        fs::create_dir_all(&egg_base)?;
        let py = build_env.join("bin/python");
        let quote = |path: &Path| shell_quote(&path.to_string_lossy());
        let command = format!(
            "exec {} setup.py egg_info --egg-base {} >{} 2>&1",
            quote(&py),
            quote(&egg_base),
            quote(&log)
        );
        let project_root = dir.canonicalize().map_err(|e| unreadable(dir, e))?;
        let spec = BuildSpec {
            argv: vec!["/bin/sh".into(), "-c".into(), command],
            cwd: project_root.clone(),
            env: vec![(
                "SETUPTOOLS_USE_DISTUTILS".into(),
                "local".into(),
            )],
            read: vec![project_root, build_env.clone(), cpython],
            write: vec![scratch.clone()],
            scratch: scratch.clone(),
            path: format!(
                "{}:/usr/bin:/bin",
                build_env.join("bin").display()
            ),
        };
        let result = crate::sandbox::run_build_spec(&spec);
        if let Err(error) = result {
            let tail = read_tail(&log, 20);
            let _ = fs::remove_dir_all(&scratch);
            return Err(unreadable(
                &dir.join("setup.py"),
                io::Error::other(format!(
                    "sandboxed egg_info failed: {error}; last 20 lines:\n{tail}"
                )),
            ));
        }

        let requirements = if let Some(requires_file) = find_named_file(&egg_base, "requires.txt") {
            let text = fs::read_to_string(&requires_file)
                .map_err(|error| unreadable(&requires_file, error))?;
            pypi::parse_requires_txt(&text)
                .map_err(|error| unreadable(&requires_file, error))?
        } else {
            Vec::new()
        };
        let pkg_info = find_named_file(&egg_base, "PKG-INFO");
        let requires_python = pkg_info
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| parse_requires_python_metadata(&text));
        let cache = SetupCache {
            tree_hash,
            requirements: requirements.clone(),
            requires_python: requires_python.clone(),
            python_version: python_version.to_string(),
            platform: platform.triple().to_string(),
            build_toolchain: build::derivation_fingerprint(),
        };
        fs::create_dir_all(dir.join(".blanket"))?;
        fs::write(&cache_path, serde_json::to_vec_pretty(&cache)?)?;
        let _ = fs::remove_dir_all(&scratch);
        self.requirements = requirements;
        self.source = self.requirements_text();
        if let Some(value) = requires_python {
            self.python
                .constraints
                .push(ConstraintSource::new(value, "setup.py PKG-INFO"));
        }
        Ok(())
    }
}

fn join_requirements(requirements: &[String], constraints: &[String]) -> String {
    requirements
        .iter()
        .chain(constraints.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct SetupCache {
    tree_hash: String,
    requirements: Vec<String>,
    requires_python: Option<String>,
    #[serde(default)]
    python_version: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    build_toolchain: String,
}

fn setup_cache_matches(
    cache: &SetupCache,
    tree_hash: &str,
    platform: Platform,
    python_version: &str,
    build_toolchain: &str,
) -> bool {
    cache.tree_hash == tree_hash
        && cache.python_version == python_version
        && cache.platform == platform.triple()
        && cache.build_toolchain == build_toolchain
}

#[derive(Debug, Clone, Default)]
struct BlanketPythonConfig {
    requirements: Option<PathBuf>,
    extras: BTreeSet<String>,
}

fn unreadable(path: &Path, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "unreadable_manifest: {}: {error}; this is a broken manifest or a blanket bug",
            path.display()
        ),
    )
}

fn read_text(path: &Path) -> io::Result<String> {
    fs::read_to_string(path).map_err(|e| unreadable(path, e))
}

fn parse_toml(path: &Path, text: &str) -> io::Result<toml::Value> {
    toml::from_str(text).map_err(|e| unreadable(path, e))
}

fn config(dir: &Path) -> io::Result<BlanketPythonConfig> {
    let path = dir.join("blanket.toml");
    if !path.is_file() {
        return Ok(BlanketPythonConfig::default());
    }
    let value = parse_toml(&path, &read_text(&path)?)?;
    let Some(python) = value.get("python").and_then(toml::Value::as_table) else {
        return Ok(BlanketPythonConfig::default());
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
    Ok(BlanketPythonConfig { requirements, extras })
}

fn pyproject_sections(value: &toml::Value) -> (bool, bool, bool) {
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

fn project_dependencies_are_dynamic(value: &toml::Value) -> bool {
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
/// intentional: a found but broken manifest is `unreadable_manifest`, not a
/// misleading `no_manifest`.
pub fn has_manifest(dir: &Path) -> io::Result<bool> {
    if dir.join("requirements.lock.txt").is_file() || dir.join("requirements.txt").is_file() {
        return Ok(true);
    }
    let pyproject = dir.join("pyproject.toml");
    if pyproject.is_file() {
        let value = parse_toml(&pyproject, &read_text(&pyproject)?)?;
        let (project, poetry, groups) = pyproject_sections(&value);
        if project || poetry || groups {
            return Ok(true);
        }
    }
    if dir.join("setup.cfg").is_file() || dir.join("setup.py").is_file() {
        return Ok(true);
    }
    Ok(requirements_directory_candidate(dir, &config(dir)?)?.is_some())
}

/// Item 8 owns interpreter-input collection. Keep the manifest boundary's
/// error class around it so preflight and planning report the same diagnosis.
pub fn python_inputs(dir: &Path) -> io::Result<PythonInputs> {
    pyselect::collect_project_inputs(dir)
        .map_err(|e| unreadable(&dir.join("pyproject.toml"), e))
}

pub fn discover(platform: Platform, dir: &Path) -> io::Result<Manifest> {
    let cfg = config(dir)?;
    let collected_python = python_inputs(dir)?;
    let discovery_selection =
        pyselect::select_python_with_inputs(platform, &collected_python)?;
    let dynamic_dependencies = if dir.join("pyproject.toml").is_file() {
        let path = dir.join("pyproject.toml");
        project_dependencies_are_dynamic(&parse_toml(&path, &read_text(&path)?)?)
    } else {
        false
    };
    let mut manifest = if dir.join("requirements.txt").is_file() {
        requirements_manifest(dir, &dir.join("requirements.txt"), "requirements.txt")?
    } else if dir.join("pyproject.toml").is_file() {
        let path = dir.join("pyproject.toml");
        let text = read_text(&path)?;
        let value = parse_toml(&path, &text)?;
        let (project, poetry, groups) = pyproject_sections(&value);
        // PEP 621 is the public metadata format and takes precedence when a
        // project also carries a legacy Poetry table.
        if project && project_dependencies_are_dynamic(&value) {
            // PEP 621's dynamic declaration is a promise that another build
            // input supplies the dependencies. An empty [project] table here
            // is not evidence of an empty environment. Let setup.py and the
            // requirements-directory convention provide that source.
            dynamic_dependencies_manifest(dir, &cfg)?
        } else if project {
            project_manifest(dir, &value, &text, &cfg)?
        } else if poetry {
            poetry_manifest(
                platform,
                dir,
                &value,
                &text,
                &cfg,
                discovery_selection.pin.version,
            )?
        } else if groups {
            project_manifest(dir, &value, &text, &cfg)?
        } else {
            setup_or_requirements_manifest(dir, &cfg)?
        }
    } else if dir.join("setup.cfg").is_file()
        || dir.join("setup.py").is_file()
        || requirements_directory_candidate(dir, &cfg)?.is_some()
    {
        setup_or_requirements_manifest(dir, &cfg)?
    } else if dir.join("requirements.lock.txt").is_file() {
        // With no discoverable source, a lock is an explicitly supplied
        // requirements file. The generated-lock cache path is only reached
        // after a live source has been discovered above.
        let lock = dir.join("requirements.lock.txt");
        requirements_manifest(dir, &lock, "requirements.lock.txt")?
    } else {
        setup_or_requirements_manifest(dir, &cfg)?
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
            discovery_selection.pin.version,
            glibc,
        )?;
    }
    if manifest.is_empty() && !manifest.requires_setup() {
        manifest.provenance.push_str(" (empty manifest)");
    }
    Ok(manifest)
}

fn dynamic_dependencies_manifest(
    dir: &Path,
    cfg: &BlanketPythonConfig,
) -> io::Result<Manifest> {
    match setup_or_requirements_manifest(dir, cfg) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(unreadable(
            &dir.join("pyproject.toml"),
            "[project].dynamic includes dependencies but no setup.py or requirements directory was found",
        )),
        result => result,
    }
}

/// If a dynamic backend cannot run in the metadata sandbox, an adjacent
/// requirements tree is still a useful, explicit dependency source. This is
/// the recovery path used by projects such as vllm whose setup.py imports a
/// package that is itself not installed during egg_info.
pub fn dynamic_requirements_fallback(dir: &Path) -> io::Result<Option<Manifest>> {
    let cfg = config(dir)?;
    let Some(path) = requirements_directory_candidate(dir, &cfg)? else {
        return Ok(None);
    };
    let relative = path
        .strip_prefix(dir)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    requirements_manifest(dir, &path, &relative).map(Some)
}

fn setup_or_requirements_manifest(dir: &Path, cfg: &BlanketPythonConfig) -> io::Result<Manifest> {
    let setup_cfg_path = dir.join("setup.cfg");
    let setup_py_path = dir.join("setup.py");
    if setup_cfg_path.is_file() {
        let text = read_text(&setup_cfg_path)?;
        let parsed = parse_setup_cfg(&text).map_err(|e| unreadable(&setup_cfg_path, e))?;
        let trivial = !setup_py_path.is_file()
            || is_trivial_setup_py(&read_text(&setup_py_path)?);
        if (parsed.install_requires_found && trivial) || (!setup_py_path.is_file() && trivial) {
            return Ok(Manifest {
                input: "setup.cfg".into(),
                requirements: parsed.requirements,
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
    if setup_py_path.is_file() {
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
    let Some(path) = requirements_directory_candidate(dir, cfg)? else {
        return Err(no_manifest());
    };
    let relative = path
        .strip_prefix(dir)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    requirements_manifest(dir, &path, &relative)
}

fn requirements_manifest(_dir: &Path, path: &Path, input: &str) -> io::Result<Manifest> {
    let source = read_text(path)?;
    validate_requirement_includes(path, &mut Vec::new(), &mut BTreeSet::new())?;
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    collect_requirement_lines(
        path,
        &mut Vec::new(),
        &mut BTreeSet::new(),
        &mut requirements,
        &mut constraints,
        false,
    )?;
    let mut filtered = Vec::new();
    let mut has_skippable_specs = false;
    for requirement in requirements {
        if pypi::is_skippable_spec(&requirement) {
            has_skippable_specs = true;
            crate::policy::record(
                crate::policy::REQUIREMENT_SKIPPED,
                &requirement,
                "project-local or direct reference is not a locked registry package",
            )?;
        } else {
            filtered.push(requirement);
        }
    }
    let requirements = filtered;
    let mut index_options = Vec::new();
    collect_index_options(path, &mut Vec::new(), &mut BTreeSet::new(), &mut index_options)?;
    let has_index_options = !index_options.is_empty();
    for option in index_options {
        crate::policy::record(
            crate::policy::UNATTESTED_INDEX,
            &option,
            "requirements index/find-links options are recorded but never followed",
        )?;
    }
    Ok(Manifest {
        input: input.into(),
        requirements,
        constraints,
        python: PythonInputs::default(),
        provenance: input.into(),
        source,
        source_path: Some(path.to_path_buf()),
        locked_packages: None,
        uv_lock: None,
        has_index_options,
        has_skippable_specs,
        setup: false,
        setup_cfg: false,
        dynamic_dependencies: false,
    })
}

fn project_manifest(
    dir: &Path,
    value: &toml::Value,
    source: &str,
    cfg: &BlanketPythonConfig,
) -> io::Result<Manifest> {
    let mut requirements = Vec::new();
    let project = value
        .get("project")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    if let Some(dependencies) = project.get("dependencies") {
        let values = dependencies.as_array().ok_or_else(|| {
            unreadable(&dir.join("pyproject.toml"), "project.dependencies must be an array")
        })?;
        for value in values {
            let value = value
                .as_str()
                .ok_or_else(|| unreadable(&dir.join("pyproject.toml"), "project.dependencies must contain strings"))?;
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
            let values = values
                .as_array()
                .ok_or_else(|| unreadable(&dir.join("pyproject.toml"), "optional-dependencies values must be arrays"))?;
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    unreadable(&dir.join("pyproject.toml"), "optional dependency must be a string")
                })?;
                if active {
                    requirements.push(value.to_string());
                } else {
                    crate::policy::record(
                        crate::policy::SKIPPED_OPTIONAL,
                        value,
                        &format!("optional dependency group `{extra}` was not requested"),
                    )?;
                }
            }
        }
    }
    if value.get("dependency-groups").is_some() {
        crate::policy::record(
            crate::policy::SKIPPED_OPTIONAL,
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
        crate::policy::record(
            crate::policy::SKIPPED_OPTIONAL,
            "[tool.pdm.dev-dependencies]",
            &format!("development dependency group excluded by default ({dev})"),
        )?;
    }
    record_uv_sources(value)?;
    let uv_lock = if dir.join("uv.lock").is_file() {
        let path = dir.join("uv.lock");
        Some(parse_uv_lock(&read_text(&path)?)?)
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

fn with_generated_source(mut manifest: Manifest, _source: &str) -> Manifest {
    manifest.source = manifest.requirements_text();
    manifest
}

fn poetry_manifest(
    platform: Platform,
    dir: &Path,
    value: &toml::Value,
    _source: &str,
    cfg: &BlanketPythonConfig,
    python_version: &str,
) -> io::Result<Manifest> {
    let poetry = value
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| unreadable(&dir.join("pyproject.toml"), "[tool.poetry] must be a table"))?;
    let empty_deps = toml::map::Map::new();
    let deps = match poetry.get("dependencies") {
        Some(value) => value.as_table().ok_or_else(|| {
            unreadable(&dir.join("pyproject.toml"), "Poetry dependencies must be a table")
        })?,
        None => &empty_deps,
    };
    let extras = poetry
        .get("extras")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    if let Some(sources) = poetry.get("source").and_then(toml::Value::as_array) {
        for source in sources {
            let Some(source) = source.as_table() else {
                return Err(unreadable(&dir.join("pyproject.toml"), "Poetry source must be a table"));
            };
            let url = source
                .get("url")
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            if !is_public_pypi_url(url) {
                let name = source
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("poetry source");
                crate::policy::record(
                    crate::policy::UNATTESTED_INDEX,
                    name,
                    "Poetry private source is not followed; the public PyPI index remains the only resolver",
                )?;
            }
        }
    }
    let requested = cfg.extras.clone();
    let mut requirements = Vec::new();
    for (name, value) in deps {
        if name.eq_ignore_ascii_case("python") {
            continue;
        }
        let tables: Vec<toml::Value> = match value {
            toml::Value::String(version) => vec![toml::Value::String(version.clone())],
            toml::Value::Table(_) => vec![value.clone()],
            toml::Value::Array(values) => values.clone(),
            _ => {
                return Err(unreadable(
                    &dir.join("pyproject.toml"),
                    format!("Poetry dependency `{name}` must be a string, table, or array"),
                ))
            }
        };
        for value in tables {
            let Some(req) = poetry_requirement(name, &value, &extras, &requested)
                .map_err(|error| unreadable(&dir.join("pyproject.toml"), error))?
            else {
                continue;
            };
            requirements.push(req);
        }
    }
    for (group, present) in [
        ("dev-dependencies", poetry.contains_key("dev-dependencies")),
        ("group.*.dependencies", poetry.contains_key("group")),
    ] {
        if !present {
            continue;
        }
        crate::policy::record(
            crate::policy::SKIPPED_OPTIONAL,
            group,
            "Poetry development dependency group is excluded by default",
        )?;
    }
    let lock_path = dir.join("poetry.lock");
    let (requirements, locked) = if lock_path.is_file() {
        let lock_text = read_text(&lock_path)?;
        let lock = parse_toml(&lock_path, &lock_text)?;
        check_poetry_content_hash(value, &lock)?;
        let locked = poetry_lock_requirements(platform, value, &lock, cfg, python_version)
            .map_err(|error| unreadable(&lock_path, error))?;
        // A present lock is authoritative, including an intentionally empty
        // main group. Never silently re-resolve from pyproject metadata.
        (locked, true)
    } else {
        (requirements, false)
    };
    let provenance = if lock_path.is_file() && locked {
        "pyproject.toml [tool.poetry] (+ poetry.lock)"
    } else {
        "pyproject.toml [tool.poetry]"
    };
    Ok(Manifest {
        input: "pyproject.toml".into(),
        source: requirements.join("\n") + if requirements.is_empty() { "" } else { "\n" },
        requirements,
        constraints: Vec::new(),
        python: PythonInputs::default(),
        provenance: provenance.into(),
        source_path: None,
        locked_packages: None,
        uv_lock: None,
        has_index_options: false,
        has_skippable_specs: false,
        setup: false,
        setup_cfg: false,
        dynamic_dependencies: false,
    })
}

fn poetry_requirement(
    name: &str,
    value: &toml::Value,
    extras: &toml::map::Map<String, toml::Value>,
    requested: &BTreeSet<String>,
) -> io::Result<Option<String>> {
    let (version, table) = match value {
        toml::Value::String(version) => (version.clone(), None),
        toml::Value::Table(table) => (
            table
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("*")
                .to_string(),
            Some(table),
        ),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Poetry dependency value is not usable")),
    };
    if let Some(table) = table {
        let optional = table
            .get("optional")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if optional {
            let active = extras.iter().any(|(extra, deps)| {
                requested.contains(&extra.to_ascii_lowercase())
                    && deps
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(toml::Value::as_str)
                        .any(|dep| dep.eq_ignore_ascii_case(name))
            });
            if !active {
                crate::policy::record(
                    crate::policy::SKIPPED_OPTIONAL,
                    name,
                    "Poetry optional dependency was not selected by a requested extra",
                )?;
                return Ok(None);
            }
        }
        for key in ["git", "path", "url"] {
            if table.contains_key(key) {
                crate::policy::record(
                    crate::policy::REQUIREMENT_SKIPPED,
                    name,
                    &format!("Poetry {key} dependency is not a locked registry package"),
                )?;
                return Ok(None);
            }
        }
        if table.contains_key("source") {
            crate::policy::record(
                crate::policy::UNATTESTED_INDEX,
                name,
                "Poetry private source is not followed; the public PyPI index remains the only resolver",
            )?;
        }
        let mut requirement_name = name.to_string();
        if let Some(values) = table.get("extras").and_then(toml::Value::as_array) {
            let values: Vec<_> = values.iter().filter_map(toml::Value::as_str).collect();
            if !values.is_empty() {
                requirement_name.push('[');
                requirement_name.push_str(&values.join(","));
                requirement_name.push(']');
            }
        }
        let marker = table
            .get("markers")
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        let python_marker = table
            .get("python")
            .and_then(toml::Value::as_str)
            .map(poetry_python_marker)
            .transpose()?
            .flatten();
        let mut output = format!(
            "{}{}",
            requirement_name,
            poetry_constraint_to_pep440(&version)?
        );
        let marker = match (marker, python_marker) {
            (Some(left), Some(right)) => Some(format!("({left}) and ({right})")),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        if let Some(marker) = marker {
            output.push_str("; ");
            output.push_str(&marker);
        }
        return Ok(Some(output));
    }
    Ok(Some(format!("{}{}", name, poetry_constraint_to_pep440(&version)?)))
}

/// Convert the useful Poetry version language to PEP 440 specifiers.
pub fn poetry_constraint_to_pep440(version: &str) -> io::Result<String> {
    let version = version.trim();
    if version.is_empty() || version == "*" {
        return Ok(String::new());
    }
    let alternatives: Vec<String> = version
        .split("||")
        .map(|alternative| {
            alternative
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(poetry_clause_to_pep440)
                .collect::<io::Result<Vec<_>>>()
                .map(|parts| parts.into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(","))
        })
        .collect::<io::Result<_>>()?;
    Ok(alternatives
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" || "))
}

fn poetry_clause_to_pep440(clause: &str) -> io::Result<String> {
    let clause = clause.trim();
    if clause == "*" {
        return Ok(String::new());
    }
    let (operator, rest) = [">=", "<=", "!=", "==", ">", "<", "^", "~", "="]
        .iter()
        .find_map(|op| clause.strip_prefix(op).map(|rest| (*op, rest.trim())))
        .unwrap_or(("==", clause));
    if rest.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Poetry version constraint `{clause}`"),
        ));
    }
    if rest.ends_with(".*") {
        return match operator {
            "=" | "==" | "!=" => Ok(format!("{operator}{rest}")),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("wildcards need equality in Poetry version constraint `{clause}`"),
            )),
        };
    }
    if operator == "^" || operator == "~" {
        let values: Vec<u64> = rest
            .split('.')
            .map(|part| part.parse::<u64>())
            .collect::<Result<_, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid Poetry version `{rest}`")))?;
        if values.is_empty() || values.len() > 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid Poetry version `{rest}`")));
        }
        let mut upper = values.clone();
        if operator == "~" {
            if upper.len() == 1 {
                upper[0] += 1;
            } else {
                upper[1] += 1;
            }
            for value in upper.iter_mut().skip(2) {
                *value = 0;
            }
        } else {
            let index = values
                .iter()
                .position(|value| *value != 0)
                .unwrap_or(values.len().saturating_sub(1));
            upper[index] += 1;
            for value in upper.iter_mut().skip(index + 1) {
                *value = 0;
            }
        }
        let upper = upper.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
        let lower = format!(">={rest}");
        return Ok(format!("{lower},<{upper}"));
    }
    Ok(match operator {
        "=" | "==" => format!("=={rest}"),
        other => format!("{other}{rest}"),
    })
}

fn poetry_python_marker(version: &str) -> io::Result<Option<String>> {
    let pep = poetry_constraint_to_pep440(version)?;
    if pep.is_empty() {
        return Ok(None);
    }
    let alternatives = pep
        .split(" || ")
        .map(|alternative| -> io::Result<String> {
            Ok(alternative
                .split(',')
                .map(|clause| {
                    let (op, value) = [">=", "<=", "!=", ">", "<", "=="]
                        .iter()
                        .find_map(|op| clause.strip_prefix(op).map(|value| (*op, value)))
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("unsupported Poetry python constraint `{version}`")))?;
                    Ok(format!("python_version {op} '{value}'"))
                })
                .collect::<io::Result<Vec<_>>>()?
                .join(" and "))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Some(if alternatives.len() == 1 {
        alternatives[0].clone()
    } else {
        alternatives
            .into_iter()
            .map(|value| format!("({value})"))
            .collect::<Vec<_>>()
            .join(" or ")
    }))
}

fn poetry_lock_requirements(
    platform: Platform,
    pyproject: &toml::Value,
    lock: &toml::Value,
    cfg: &BlanketPythonConfig,
    python_version: &str,
) -> io::Result<Vec<String>> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "poetry.lock has no [[package]] entries"))?;
    let deps = pyproject
        .get("tool").and_then(toml::Value::as_table)
        .and_then(|t| t.get("poetry")).and_then(toml::Value::as_table)
        .and_then(|t| t.get("dependencies")).and_then(toml::Value::as_table)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Poetry dependencies missing"))?;
    let extras = pyproject
        .get("tool").and_then(toml::Value::as_table)
        .and_then(|t| t.get("poetry")).and_then(toml::Value::as_table)
        .and_then(|t| t.get("extras")).and_then(toml::Value::as_table)
        .cloned().unwrap_or_default();
    let requested = &cfg.extras;
    let roots: BTreeSet<String> = deps
        .iter()
        .filter(|(name, value)| {
            if name.eq_ignore_ascii_case("python") { return false; }
            let optional = value.as_table().and_then(|t| t.get("optional")).and_then(toml::Value::as_bool).unwrap_or(false);
            !optional || extras.iter().any(|(extra, values)| requested.contains(&extra.to_ascii_lowercase()) && values.as_array().into_iter().flatten().filter_map(toml::Value::as_str).any(|v| v.eq_ignore_ascii_case(name)))
        })
        .map(|(name, _)| normalize_name(name))
        .collect();
    let mut by_name: BTreeMap<String, Vec<&toml::Value>> = BTreeMap::new();
    for package in packages {
        let table = package.as_table().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "poetry.lock package is not a table"))?;
        let name = table.get("name").and_then(toml::Value::as_str).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "poetry.lock package has no name"))?;
        by_name.entry(normalize_name(name)).or_default().push(package);
    }
    for root in &roots {
        if select_poetry_package(by_name.get(root), python_version, platform)?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("poetry.lock has no locked package for main dependency {root}"),
            ));
        }
    }
    let mut reachable = roots.clone();
    let mut queue: VecDeque<String> = roots.clone().into_iter().collect();
    while let Some(name) = queue.pop_front() {
        let Some(package) = select_poetry_package(by_name.get(&name), python_version, platform)?
            .and_then(toml::Value::as_table)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("poetry.lock has no package variant compatible with Python {python_version} for {name}"),
            ));
        };
        if let Some(dependencies) = package.get("dependencies").and_then(toml::Value::as_table) {
            for dependency in poetry_active_dependencies(dependencies, python_version, platform)? {
                if reachable.insert(dependency.clone()) { queue.push_back(dependency); }
            }
        }
    }
    let mut output = Vec::new();
    for name in reachable {
        let Some(package) = select_poetry_package(by_name.get(&name), python_version, platform)?
            .and_then(toml::Value::as_table)
        else {
            continue;
        };
        let optional = package.get("optional").and_then(toml::Value::as_bool).unwrap_or(false);
        if optional && !roots.contains(&name) { continue; }
        if package.get("category").and_then(toml::Value::as_str).is_some_and(|v| v != "main") { continue; }
        if package.get("groups").and_then(toml::Value::as_array).is_some_and(|groups| !groups.iter().filter_map(toml::Value::as_str).any(|group| group == "main")) { continue; }
        if let Some(source) = package.get("source").and_then(toml::Value::as_table) {
            let source_type = source.get("type").and_then(toml::Value::as_str).unwrap_or_default();
            if matches!(source_type, "directory" | "git" | "url") {
                crate::policy::record(
                    crate::policy::REQUIREMENT_SKIPPED,
                    &name,
                    &format!("Poetry lock package uses unsupported {source_type} source"),
                )?;
                continue;
            }
            let url = source.get("url").and_then(toml::Value::as_str).unwrap_or_default();
            if !is_public_pypi_url(url) && source.get("reference").and_then(toml::Value::as_str) != Some("pypi") {
                crate::policy::record(
                    crate::policy::UNATTESTED_INDEX,
                    &name,
                    "Poetry lock package has a non-default source",
                )?;
            }
        }
        let hashes = poetry_package_hashes(lock, package, &name)?;
        if hashes.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidData, format!("poetry.lock package {name} has no sha256 file hash"))); }
        let version = package.get("version").and_then(toml::Value::as_str).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("poetry.lock package {name} has no version")))?;
        output.push(format!("{name}=={version} {}", hashes.iter().map(|hash| format!("--hash=sha256:{hash}")).collect::<Vec<_>>().join(" ")));
    }
    output.sort();
    Ok(output)
}

fn select_poetry_package<'a>(
    variants: Option<&Vec<&'a toml::Value>>,
    python_version: &str,
    platform: Platform,
) -> io::Result<Option<&'a toml::Value>> {
    let Some(variants) = variants else {
        return Ok(None);
    };
    for package in variants {
        let Some(table) = package.as_table() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "poetry.lock package is not a table",
            ));
        };
        if poetry_package_matches(table, python_version, platform)? {
            // Poetry's forked package entries are expected to be disjoint.
            // Selecting the first matching entry preserves the lock's order
            // and, importantly, never lets a later incompatible fork shadow
            // an earlier compatible one.
            return Ok(Some(*package));
        }
    }
    Ok(None)
}

fn poetry_package_matches(
    package: &toml::map::Map<String, toml::Value>,
    python_version: &str,
    platform: Platform,
) -> io::Result<bool> {
    if let Some(versions) = package.get("python-versions").and_then(toml::Value::as_str) {
        let pep440 = poetry_constraint_to_pep440(versions)?;
        if !pyselect::matches_specifier(&pep440, python_version)? {
            return Ok(false);
        }
    }
    if let Some(markers) = package.get("markers").and_then(toml::Value::as_str) {
        if !marker_matches(markers, python_version, platform)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn poetry_dependency_variant_matches(
    value: &toml::Value,
    python_version: &str,
    platform: Platform,
) -> io::Result<bool> {
    let Some(table) = value.as_table() else {
        return Ok(true);
    };
    if let Some(markers) = table.get("markers").and_then(toml::Value::as_str) {
        if !marker_matches(markers, python_version, platform)? {
            return Ok(false);
        }
    }
    if let Some(python) = table.get("python").and_then(toml::Value::as_str) {
        let Some(marker) = poetry_python_marker(python)? else {
            return Ok(true);
        };
        if !marker_matches(&marker, python_version, platform)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn poetry_active_dependencies(
    dependencies: &toml::map::Map<String, toml::Value>,
    python_version: &str,
    platform: Platform,
) -> io::Result<Vec<String>> {
    let mut active = Vec::new();
    for (name, value) in dependencies {
        let enabled = match value {
            toml::Value::Array(values) => {
                let mut enabled = false;
                for value in values {
                    if poetry_dependency_variant_matches(value, python_version, platform)? {
                        enabled = true;
                        break;
                    }
                }
                enabled
            }
            value => poetry_dependency_variant_matches(value, python_version, platform)?,
        };
        if enabled {
            active.push(normalize_name(name.split('[').next().unwrap_or(name)));
        }
    }
    Ok(active)
}

/// Evaluate the small PEP 508 marker subset emitted by Poetry and uv lock
/// files. Lock variants must be filtered before graph traversal, so retaining
/// the marker text and handing it to an unconstrained resolver is not enough.
fn marker_matches(expression: &str, python_version: &str, platform: Platform) -> io::Result<bool> {
    let expression = strip_marker_parens(expression.trim());
    if expression.is_empty() {
        return Ok(true);
    }
    let alternatives = split_marker_keyword(expression, "or");
    if alternatives.len() > 1 {
        return alternatives
            .into_iter()
            .map(|part| marker_matches(part, python_version, platform))
            .collect::<io::Result<Vec<_>>>()
            .map(|values| values.into_iter().any(|value| value));
    }
    let conjunction = split_marker_keyword(expression, "and");
    if conjunction.len() > 1 {
        return conjunction
            .into_iter()
            .map(|part| marker_matches(part, python_version, platform))
            .collect::<io::Result<Vec<_>>>()
            .map(|values| values.into_iter().all(|value| value));
    }
    if let Some(rest) = expression.strip_prefix("not ") {
        return marker_matches(rest, python_version, platform).map(|value| !value);
    }

    let operators = [" not in ", " in ", ">=", "<=", "==", "!=", ">", "<"];
    let (left, operator, right) = operators
        .iter()
        .find_map(|operator| {
            expression.find(operator).map(|index| {
                (
                    expression[..index].trim(),
                    *operator,
                    expression[index + operator.len()..].trim(),
                )
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported environment marker `{expression}`"),
            )
        })?;
    let left_value = marker_value(left, python_version, platform).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported environment marker variable `{left}`"),
        )
    })?;
    let right_value = right
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| right.strip_prefix('\'').and_then(|value| value.strip_suffix('\'')))
        .unwrap_or(right);
    let numeric = matches!(left, "python_version" | "python_full_version");
    Ok(compare_marker(left_value.as_str(), right_value, operator, numeric))
}

fn marker_value(name: &str, python_version: &str, platform: Platform) -> Option<String> {
    let python_full_version = python_version.to_string();
    let python_version = python_version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    Some(match name {
        "python_version" => python_version,
        "python_full_version" => python_full_version,
        "sys_platform" => if matches!(platform, Platform::Aarch64AppleDarwin) { "darwin" } else { "linux" }.to_string(),
        "os_name" => "posix".to_string(),
        "platform_system" => {
            if matches!(platform, Platform::Aarch64AppleDarwin) { "Darwin" } else { "Linux" }
                .to_string()
        }
        "platform_machine" => {
            if matches!(platform, Platform::Aarch64AppleDarwin) { "arm64" } else { "x86_64" }
                .to_string()
        }
        "implementation_name" => "cpython".to_string(),
        "platform_python_implementation" => "CPython".to_string(),
        "extra" => String::new(),
        _ => return None,
    })
}

fn compare_marker(left: &str, right: &str, operator: &str, numeric: bool) -> bool {
    if numeric {
        let parse = |value: &str| {
            value
                .split('.')
                .map(|part| part.parse::<u64>().ok())
                .collect::<Option<Vec<_>>>()
        };
        if let (Some(mut left), Some(mut right)) = (parse(left), parse(right)) {
            let length = left.len().max(right.len());
            left.resize(length, 0);
            right.resize(length, 0);
            return compare_order(left.cmp(&right), operator);
        }
    }
    match operator {
        "==" => left == right,
        "!=" => left != right,
        ">=" => left >= right,
        "<=" => left <= right,
        ">" => left > right,
        "<" => left < right,
        " in " => right.split_whitespace().any(|value| value == left),
        " not in " => !right.split_whitespace().any(|value| value == left),
        _ => false,
    }
}

fn compare_order(order: std::cmp::Ordering, operator: &str) -> bool {
    match operator {
        "==" => order == std::cmp::Ordering::Equal,
        "!=" => order != std::cmp::Ordering::Equal,
        ">=" => order != std::cmp::Ordering::Less,
        "<=" => order != std::cmp::Ordering::Greater,
        ">" => order == std::cmp::Ordering::Greater,
        "<" => order == std::cmp::Ordering::Less,
        _ => false,
    }
}

fn strip_marker_parens(mut expression: &str) -> &str {
    loop {
        let bytes = expression.as_bytes();
        if bytes.first() != Some(&b'(') || bytes.last() != Some(&b')') {
            return expression;
        }
        let mut depth = 0;
        let mut quote = None;
        let mut closes_early = false;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if let Some(current) = quote {
                if byte == current && (index == 0 || bytes[index - 1] != b'\\') {
                    quote = None;
                }
                continue;
            }
            if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
            } else if byte == b'(' {
                depth += 1;
            } else if byte == b')' {
                depth -= 1;
                if depth == 0 && index != bytes.len() - 1 {
                    closes_early = true;
                    break;
                }
            }
        }
        if closes_early || depth != 0 {
            return expression;
        }
        expression = expression[1..expression.len() - 1].trim();
    }
}

fn split_marker_keyword<'a>(expression: &'a str, keyword: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let bytes = expression.as_bytes();
    for index in 0..bytes.len() {
        let byte = bytes[index];
        if let Some(current) = quote {
            if byte == current && (index == 0 || bytes[index - 1] != b'\\') {
                quote = None;
            }
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            continue;
        }
        match byte {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        let end = index + keyword.len();
        let boundary_before = index == 0 || bytes[index - 1].is_ascii_whitespace();
        let boundary_after = end >= bytes.len() || bytes[end].is_ascii_whitespace();
        if depth == 0
            && boundary_before
            && boundary_after
            && expression[index..].starts_with(keyword)
        {
            parts.push(expression[start..index].trim());
            start = end;
        }
    }
    if parts.is_empty() {
        vec![expression]
    } else {
        parts.push(expression[start..].trim());
        parts
    }
}

fn poetry_package_hashes(lock: &toml::Value, package: &toml::map::Map<String, toml::Value>, name: &str) -> io::Result<Vec<String>> {
    let mut hashes = Vec::new();
    if let Some(files) = package.get("files").and_then(toml::Value::as_array) {
        for file in files {
            if let Some(hash) = file
                .as_table()
                .and_then(|file| file.get("hash"))
                .and_then(toml::Value::as_str)
            {
                if let Some(hash) = hash.strip_prefix("sha256:") {
                    hashes.push(hash.to_ascii_lowercase());
                }
            }
        }
    }
    if hashes.is_empty() {
        let metadata_files = lock
            .get("metadata")
            .and_then(toml::Value::as_table)
            .and_then(|metadata| metadata.get("files"))
            .and_then(toml::Value::as_table)
            .and_then(|files| {
                files.iter().find_map(|(package_name, files)| {
                    (normalize_name(package_name) == name).then_some(files)
                })
            })
            .and_then(toml::Value::as_array);
        if let Some(files) = metadata_files {
            for file in files {
                let hash = file
                    .as_str()
                    .and_then(|value| value.strip_prefix("sha256:"))
                    .or_else(|| {
                        file.as_table()
                            .and_then(|file| file.get("hash"))
                            .and_then(toml::Value::as_str)
                            .and_then(|value| value.strip_prefix("sha256:"))
                    });
                if let Some(hash) = hash {
                    hashes.push(hash.to_ascii_lowercase());
                }
            }
        }
    }
    hashes.sort();
    hashes.dedup();
    Ok(hashes)
}

fn check_poetry_content_hash(project: &toml::Value, lock: &toml::Value) -> io::Result<()> {
    let Some(expected) = lock.get("metadata").and_then(toml::Value::as_table).and_then(|m| m.get("content-hash")).and_then(toml::Value::as_str) else { return Ok(()); };
    let project_content = project
        .get("project")
        .and_then(toml::Value::as_table);
    let group_content = project
        .get("dependency-groups")
        .and_then(toml::Value::as_table);
    let poetry = project
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();

    // This mirrors Poetry's Locker._get_content_hash: only dependency-bearing
    // PEP 621 fields, legacy Poetry fields, and PEP 735 groups participate.
    // Python's json.dumps uses a space after commas and colons by default;
    // retain that detail because it is part of the on-disk digest.
    let project_keys = ["requires-python", "dependencies", "optional-dependencies"];
    let mut relevant_project = BTreeMap::new();
    for key in project_keys {
        if let Some(value) = project_content.and_then(|table| table.get(key)) {
            relevant_project.insert(key, toml_json(value)?);
        }
    }
    let legacy_keys = ["dependencies", "source", "extras", "dev-dependencies"];
    let relevant_keys = [
        "dependencies",
        "source",
        "extras",
        "dev-dependencies",
        "group",
    ];
    let mut relevant_poetry = BTreeMap::new();
    for key in relevant_keys {
        if let Some(value) = poetry.get(key) {
            relevant_poetry.insert(key, toml_json(value)?);
        } else if legacy_keys.contains(&key)
            && relevant_project.is_empty()
            && group_content.map_or(true, toml::map::Map::is_empty)
        {
            relevant_poetry.insert(key, serde_json::Value::Null);
        }
    }
    let mut selected = BTreeMap::new();
    if !relevant_project.is_empty() {
        selected.insert("project", serde_json::to_value(relevant_project).map_err(|e| io::Error::other(e.to_string()))?);
    }
    if let Some(groups) = group_content.filter(|groups| !groups.is_empty()) {
        selected.insert("dependency-groups", toml_json_table(groups)?);
    }
    if !selected.is_empty() {
        selected.insert(
            "tool",
            serde_json::json!({"poetry": relevant_poetry}),
        );
    } else {
        selected.extend(relevant_poetry);
    }
    let compact = serde_json::to_string(&selected).map_err(|e| io::Error::other(e.to_string()))?;
    let json = python_json_spacing(&compact).into_bytes();
    let actual = hex::encode(Sha256::digest(json));
    if actual != expected {
        eprintln!("blanket: warning: poetry.lock content-hash disagrees with pyproject.toml; preferring the lock");
        crate::policy::record(crate::policy::LOCK_DISAGREEMENT, "poetry.lock", &format!("content-hash {expected} != computed {actual}; lock preferred"))?;
    }
    Ok(())
}

fn toml_json(value: &toml::Value) -> io::Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| io::Error::other(error.to_string()))
}

fn toml_json_table(
    table: &toml::map::Map<String, toml::Value>,
) -> io::Result<serde_json::Value> {
    toml_json(&toml::Value::Table(table.clone()))
}

fn python_json_spacing(compact: &str) -> String {
    let mut output = String::with_capacity(compact.len() + compact.len() / 8);
    let mut in_string = false;
    let mut escaped = false;
    for character in compact.chars() {
        if in_string {
            output.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else {
            if character == '"' {
                in_string = true;
            }
            output.push(character);
            if matches!(character, ',' | ':') {
                output.push(' ');
            }
        }
    }
    output
}

fn record_uv_sources(value: &toml::Value) -> io::Result<()> {
    let Some(sources) = value.get("tool").and_then(toml::Value::as_table).and_then(|t| t.get("uv")).and_then(toml::Value::as_table).and_then(|u| u.get("sources")).and_then(toml::Value::as_table) else { return Ok(()); };
    for (name, source) in sources {
        if let Some(table) = source.as_table() {
            for key in ["path", "git", "directory", "url"] {
                if table.contains_key(key) { crate::policy::record(crate::policy::REQUIREMENT_SKIPPED, name, &format!("uv source `{key}` is not a locked registry package"))?; }
            }
            if table.contains_key("index") { crate::policy::record(crate::policy::UNATTESTED_INDEX, name, "uv private index source is not followed")?; }
        }
    }
    Ok(())
}

fn is_public_pypi_url(url: &str) -> bool {
    url.is_empty()
        || url.contains("://pypi.org")
        || url.contains("://files.pythonhosted.org")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvFile { pub url: String, pub hash: String, pub filename: String, pub kind: ArtifactKind }

#[derive(Debug, Clone)]
pub struct UvPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub files: Vec<UvFile>,
    pub dependencies: Vec<String>,
    pub resolution_markers: Vec<String>,
    dependency_edges: Vec<UvDependency>,
}

#[derive(Debug, Clone)]
struct UvDependency {
    name: String,
    marker: Option<String>,
}

pub fn parse_uv_lock(text: &str) -> io::Result<Vec<UvPackage>> {
    let value: toml::Value = toml::from_str(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock: {e}")))?;
    let packages = value.get("package").and_then(toml::Value::as_array).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "uv.lock has no [[package]] entries"))?;
    packages.iter().map(|package| {
        let table = package.as_table().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "uv.lock package is not a table"))?;
        let name = table.get("name").and_then(toml::Value::as_str).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "uv.lock package has no name"))?;
        let source = table.get("source").map(|v| v.to_string()).unwrap_or_else(|| "registry".into());
        let version = table.get("version").and_then(toml::Value::as_str).unwrap_or_default();
        if version.is_empty() && !is_local_uv_source(&source) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name} has no version")));
        }
        let mut dependencies = Vec::new();
        let mut dependency_edges = Vec::new();
        if let Some(value) = table.get("dependencies") {
            for dependency in value
                .as_array()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name}.dependencies is not an array")))?
            {
                let (dependency_name, marker) = if let Some(dependency_name) = dependency.as_str() {
                    (dependency_name, None)
                } else if let Some(table) = dependency.as_table() {
                    let Some(dependency_name) = table.get("name").and_then(toml::Value::as_str) else {
                        continue;
                    };
                    let marker = table
                        .get("marker")
                        .or_else(|| table.get("markers"))
                        .and_then(toml::Value::as_str)
                        .map(str::to_string);
                    (dependency_name, marker)
                } else {
                    continue;
                };
                let dependency_name = normalize_name(dependency_name);
                dependencies.push(dependency_name.clone());
                dependency_edges.push(UvDependency { name: dependency_name, marker });
            }
        }
        let resolution_markers = table
            .get("resolution-markers")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(str::to_string)
            .collect();
        let mut files = Vec::new();
        if let Some(sdist) = table.get("sdist") {
            let sdist = sdist.as_table().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name}.sdist is not a table"))
            })?;
            files.push(uv_file(sdist, ArtifactKind::Sdist).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name}.sdist lacks a URL and sha256 hash"))
            })?);
        }
        if let Some(wheels) = table.get("wheels") {
            let wheels = wheels.as_array().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name}.wheels is not an array"))
            })?;
            for wheel in wheels {
                let wheel = wheel.as_table().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name} wheel is not a table"))
                })?;
                files.push(uv_file(wheel, ArtifactKind::Wheel).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock {name} wheel lacks a URL and sha256 hash"))
                })?);
            }
        }
        Ok(UvPackage {
            name: normalize_name(name),
            version: version.into(),
            source,
            files,
            dependencies,
            resolution_markers,
            dependency_edges,
        })
    }).collect()
}

fn uv_file(table: &toml::map::Map<String, toml::Value>, kind: ArtifactKind) -> Option<UvFile> {
    let url = table.get("url")?.as_str()?.to_string();
    let hash = table.get("hash")?.as_str()?.strip_prefix("sha256:")?.to_ascii_lowercase();
    let filename = url.rsplit('/').next()?.split(['?', '#']).next()?.to_string();
    Some(UvFile { url, hash, filename, kind })
}

fn uv_lock_manifest(
    packages: &[UvPackage],
    requirements: &[String],
    platform: Platform,
    python_version: &str,
    glibc: pypi::Glibc,
) -> io::Result<Option<Vec<LockedPackage>>> {
    let minor = python_version.split('.').take(2).collect::<Vec<_>>().join("");
    let tag = format!("cp{minor}");
    let mut by_name: BTreeMap<String, Vec<&UvPackage>> = BTreeMap::new();
    for package in packages {
        by_name.entry(package.name.clone()).or_default().push(package);
    }
    let has_project_root = packages.iter().any(|package| is_uv_project_root(&package.source));
    let mut roots: BTreeSet<String> = requirements.iter().filter_map(|r| requirement_name(r)).collect();
    if roots.is_empty() {
        // A uv lock normally carries an editable/virtual package for the
        // project itself. Its dependencies are the default (non-dev) roots;
        // development groups remain unreachable from this package graph.
        for package in packages.iter().filter(|package| is_uv_project_root(&package.source)) {
            let legacy_edges;
            let dependency_edges = if package.dependency_edges.is_empty() {
                legacy_edges = package
                    .dependencies
                    .iter()
                    .map(|name| UvDependency { name: name.clone(), marker: None })
                    .collect::<Vec<_>>();
                &legacy_edges
            } else {
                &package.dependency_edges
            };
            for dependency in dependency_edges {
                if dependency
                    .marker
                    .as_deref()
                    .map_or(Ok(true), |marker| marker_matches(marker, python_version, platform))?
                {
                    roots.insert(dependency.name.clone());
                }
            }
        }
    }
    let selected_names = if roots.is_empty() && !has_project_root {
        // Older/minimal uv locks may omit the project root. Preserve useful
        // behavior for those files by considering every registry package.
        packages.iter().map(|package| package.name.clone()).collect()
    } else {
        let mut reachable = roots;
        let mut queue: VecDeque<String> = reachable.iter().cloned().collect();
        while let Some(name) = queue.pop_front() {
            let Some(package) = select_uv_package(by_name.get(&name), python_version, platform)? else {
                continue;
            };
            let legacy_edges;
            let dependency_edges = if package.dependency_edges.is_empty() {
                legacy_edges = package
                    .dependencies
                    .iter()
                    .map(|name| UvDependency { name: name.clone(), marker: None })
                    .collect::<Vec<_>>();
                &legacy_edges
            } else {
                &package.dependency_edges
            };
            for dependency in dependency_edges {
                if dependency
                    .marker
                    .as_deref()
                    .map_or(Ok(true), |marker| marker_matches(marker, python_version, platform))?
                    && reachable.insert(dependency.name.clone())
                {
                    queue.push_back(dependency.name.clone());
                }
            }
        }
        reachable
    };
    let mut selected_packages = BTreeMap::new();
    for name in &selected_names {
        let Some(package) = select_uv_package(by_name.get(name), python_version, platform)? else {
            eprintln!(
                "blanket: uv.lock has no package variant compatible with the host for {name}; falling back to uv resolution"
            );
            return Ok(None);
        };
        selected_packages.insert(name.clone(), package);
    }
    let mut output = Vec::new();
    for package in selected_packages.into_values() {
        if is_local_uv_source(&package.source) {
            if !is_uv_project_root(&package.source) {
                crate::policy::record(
                    crate::policy::REQUIREMENT_SKIPPED,
                    &package.name,
                    "uv lock package is a local or VCS source, not a locked registry artifact",
                )?;
            }
            continue;
        }
        if package.source != "registry"
            && package.source.contains("registry")
            && !package.source.contains("pypi.org")
            && !package.source.contains("files.pythonhosted.org")
        {
            crate::policy::record(
                crate::policy::UNATTESTED_INDEX,
                &package.name,
                "uv lock package names a non-public registry source",
            )?;
        }
        let candidates: Vec<_> = package.files.iter().map(|f| pypi::FileCandidate { filename: f.filename.clone(), url: f.url.clone(), sha256: f.hash.clone() }).collect();
        let Some((file, _)) = pypi::select_file(&candidates, &tag, platform, glibc) else {
            eprintln!("blanket: uv.lock has no file compatible with the host for {}; falling back to uv resolution", package.name);
            return Ok(None);
        };
        let kind = package.files.iter().find(|f| f.url == file.url).map(|f| f.kind).unwrap_or(ArtifactKind::Wheel);
        output.push(LockedPackage { name: package.name.clone(), version: package.version.clone(), filename: file.filename.clone(), url: file.url.clone(), sha256: file.sha256.clone(), kind });
    }
    if output.is_empty() { return Ok(None); }
    output.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Some(output))
}

fn select_uv_package<'a>(
    variants: Option<&Vec<&'a UvPackage>>,
    python_version: &str,
    platform: Platform,
) -> io::Result<Option<&'a UvPackage>> {
    let Some(variants) = variants else {
        return Ok(None);
    };
    for package in variants {
        if package.resolution_markers.is_empty()
            || package
                .resolution_markers
                .iter()
                .map(|marker| marker_matches(marker, python_version, platform))
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .any(|matches| matches)
        {
            return Ok(Some(*package));
        }
    }
    Ok(None)
}

fn is_local_uv_source(source: &str) -> bool {
    source.contains("editable")
        || source.contains("virtual")
        || source.contains("directory")
        || source.contains("path")
        || source.contains("git")
        || source.contains("url")
        || source.contains("workspace")
}

fn is_uv_project_root(source: &str) -> bool {
    (source.contains("editable") || source.contains("virtual"))
        && (source.contains("\".\"") || source.contains("'.'"))
}

fn requirement_name(requirement: &str) -> Option<String> {
    let name = requirement
        .split_once(['<', '>', '=', '!', ';', '['])
        .map_or(requirement, |(name, _)| name)
        .trim();
    (!name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')))
    .then(|| normalize_name(name))
}

fn requirements_directory_candidate(
    dir: &Path,
    cfg: &BlanketPythonConfig,
) -> io::Result<Option<PathBuf>> {
    let requirements = dir.join("requirements");
    if !requirements.is_dir() { return Ok(None); }
    if let Some(explicit) = &cfg.requirements {
        let path = if explicit.is_absolute() { explicit.clone() } else { dir.join(explicit) };
        if path.is_file() { return Ok(Some(path)); }
        return Err(unreadable(
            &path,
            "blanket.toml [python].requirements points to a missing file",
        ));
    }
    for hardware in ["cpu.txt", "cuda.txt", "rocm.txt", "xpu.txt"] {
        let path = requirements.join(hardware);
        if path.is_file() { return Ok(Some(path)); }
    }
    for name in ["common.txt", "base.txt", "requirements.in"] {
        let path = requirements.join(name);
        if path.is_file() { return Ok(Some(path)); }
    }
    Ok(None)
}

fn validate_requirement_includes(path: &Path, stack: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    let path = path.canonicalize().map_err(|e| unreadable(path, e))?;
    if stack.contains(&path) { return Err(unreadable(&path, format!("requirements include cycle: {}", stack.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(" -> ")))); }
    if !seen.insert(path.clone()) { return Ok(()); }
    stack.push(path.clone());
    let text = read_text(&path)?;
    for line in pypi::logical_requirement_lines(&text) {
        if is_include_directive(&line) && include_target(&line).is_none() {
            return Err(unreadable(&path, "requirements include is missing its file argument"));
        }
        let target = include_target(&line).map(|(_, target)| target);
        if let Some(target) = target { let child = path.parent().unwrap_or(Path::new(".")).join(target.trim()); if !child.is_file() { return Err(unreadable(&child, "included requirements file is missing")); } validate_requirement_includes(&child, stack, seen)?; }
    }
    stack.pop();
    Ok(())
}

fn collect_requirement_lines(
    path: &Path,
    stack: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
    output: &mut Vec<String>,
    constraints: &mut Vec<String>,
    constraints_only: bool,
) -> io::Result<()> {
    let path = path.canonicalize().map_err(|e| unreadable(path, e))?;
    if stack.contains(&path) {
        return Err(unreadable(&path, "requirements include cycle"));
    }
    if !seen.insert(path.clone()) {
        return Ok(());
    }
    stack.push(path.clone());
    for line in pypi::logical_requirement_lines(&read_text(&path)?) {
        if is_include_directive(&line) && include_target(&line).is_none() {
            return Err(unreadable(&path, "requirements include is missing its file argument"));
        }
        let directive = line.split_whitespace().next().unwrap_or_default();
        let target = match directive {
            "-r" | "--requirement" | "-c" | "--constraint" => {
                line.split_whitespace().nth(1)
            }
            _ => include_target(&line).map(|(_, target)| target),
        };
        if let Some(target) = target {
            let is_constraint = matches!(
                directive,
                "-c" | "--constraint"
            ) || directive.starts_with("-c=") || directive.starts_with("--constraint=");
            let child = path.parent().unwrap_or(Path::new(".")).join(target);
            collect_requirement_lines(
                &child,
                stack,
                seen,
                output,
                constraints,
                constraints_only || is_constraint,
            )?;
        } else if !constraints_only && !pypi::is_requirement_option(&line) {
            output.push(line);
        } else if constraints_only && !pypi::is_requirement_option(&line) {
            constraints.push(line);
        }
    }
    stack.pop();
    Ok(())
}

fn include_target(line: &str) -> Option<(&str, &str)> {
    let first = line.split_whitespace().next()?;
    if matches!(first, "-r" | "--requirement" | "-c" | "--constraint") {
        return line
            .split_whitespace()
            .nth(1)
            .map(|target| (first, target));
    }
    for option in ["-r=", "--requirement=", "-c=", "--constraint="] {
        if let Some(target) = first.strip_prefix(option) {
            return Some((option, target));
        }
    }
    None
}

fn is_include_directive(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or_default();
    matches!(first, "-r" | "--requirement" | "-c" | "--constraint")
        || first.starts_with("-r=")
        || first.starts_with("--requirement=")
        || first.starts_with("-c=")
        || first.starts_with("--constraint=")
}

fn collect_index_options(
    path: &Path,
    stack: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
    output: &mut Vec<String>,
) -> io::Result<()> {
    let path = path.canonicalize().map_err(|e| unreadable(path, e))?;
    if stack.contains(&path) {
        return Err(unreadable(&path, "requirements include cycle"));
    }
    if !seen.insert(path.clone()) {
        return Ok(());
    }
    stack.push(path.clone());
    for line in pypi::logical_requirement_lines(&read_text(&path)?) {
        output.extend(pypi::unattested_index_options(&line));
        if let Some((_, target)) = include_target(&line) {
            let child = path.parent().unwrap_or(Path::new(".")).join(target.trim());
            collect_index_options(&child, stack, seen, output)?;
        }
    }
    stack.pop();
    Ok(())
}

#[derive(Debug, Clone)]
struct SetupCfg { requirements: Vec<String>, install_requires_found: bool }

fn parse_setup_cfg(text: &str) -> io::Result<SetupCfg> {
    let mut section = String::new();
    let mut requirements = Vec::new();
    let mut in_requires = false;
    let mut found = false;
    for raw in text.lines() {
        let line = strip_inline_comment(raw);
        let trim = line.trim();
        if trim.is_empty() { continue; }
        if trim.starts_with('[') && trim.ends_with(']') { section = trim[1..trim.len()-1].trim().to_ascii_lowercase(); in_requires = false; continue; }
        if line.chars().next().is_some_and(char::is_whitespace) {
            if section == "options" && in_requires { requirements.push(trim.to_string()); }
            continue;
        }
        if section != "options" { continue; }
        let Some((key, value)) = line.split_once(['=', ':']) else { continue; };
        in_requires = key.trim().eq_ignore_ascii_case("install_requires");
        if in_requires { found = true; if !value.trim().is_empty() { requirements.push(value.trim().to_string()); } }
    }
    Ok(SetupCfg { requirements, install_requires_found: found })
}

fn strip_inline_comment(line: &str) -> &str {
    line.char_indices().find(|(i, c)| *c == '#' && (*i == 0 || line.as_bytes()[*i - 1].is_ascii_whitespace())).map(|(i, _)| &line[..i]).unwrap_or(line)
}

fn is_trivial_setup_py(text: &str) -> bool {
    let mut code = String::new();
    for line in text.lines() {
        let line = strip_inline_comment(line).trim();
        if !line.is_empty() {
            code.push_str(line);
            code.push('\n');
        }
    }
    let Some(call_start) = code
        .find("setuptools.setup(")
        .or_else(|| code.find("setup("))
    else {
        return false;
    };
    let prefix = code[..call_start].trim();
    let import_only = prefix.lines().all(|line| {
        line.starts_with("from setuptools") || line.starts_with("import setuptools")
    });
    if !import_only || code[call_start..].matches("setup(").count() != 1 {
        return false;
    }
    let mut depth = 0i32;
    let mut end = None;
    for (offset, character) in code[call_start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(call_start + offset + character.len_utf8());
                    break;
                }
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    end.is_some_and(|end| code[end..].trim().is_empty())
}

fn parse_requires_python_metadata(text: &str) -> Option<String> {
    text.lines().find_map(|line| line.strip_prefix("Requires-Python:").map(str::trim).filter(|v| !v.is_empty()).map(str::to_string))
}

fn find_named_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut entries = fs::read_dir(root).ok()?.flatten().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries { let path = entry.path(); if path.is_dir() { if let Some(found) = find_named_file(&path, name) { return Some(found); } } else if path.file_name().and_then(|n| n.to_str()) == Some(name) { return Some(path); } }
    None
}

fn read_tail(path: &Path, count: usize) -> String {
    fs::read_to_string(path).unwrap_or_default().lines().rev().take(count).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
}

fn shell_quote(value: &str) -> String { format!("'{}'", value.replace('\'', "'\\''")) }

fn setup_tree_hash(dir: &Path) -> io::Result<String> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "requirements.lock.txt" {
            continue;
        }
        if matches!(name.as_str(), "setup.py" | "setup.cfg" | "pyproject.toml" | "MANIFEST.in") || name.contains("requirements") { paths.insert(entry.path()); }
    }
    let reqdir = dir.join("requirements");
    if reqdir.is_dir() { collect_tree(&reqdir, &mut paths)?; }
    let mut hasher = Sha256::new();
    for path in paths { if path.is_dir() { continue; } let relative = path.strip_prefix(dir).unwrap_or(&path); hasher.update(relative.to_string_lossy().as_bytes()); hasher.update([0]); hasher.update(fs::read(&path).map_err(|e| unreadable(&path, e))?); hasher.update([0]); }
    Ok(hex::encode(hasher.finalize()))
}

fn collect_tree(path: &Path, paths: &mut BTreeSet<PathBuf>) -> io::Result<()> { for entry in fs::read_dir(path)? { let entry = entry?; let child = entry.path(); if child.is_dir() { collect_tree(&child, paths)?; } else { paths.insert(child); } } Ok(()) }

fn normalize_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !separator {
                normalized.push('-');
            }
            separator = true;
        } else {
            normalized.push(character.to_ascii_lowercase());
            separator = false;
        }
    }
    normalized
}

fn no_manifest() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no_manifest: nothing found; looked for requirements.lock.txt, requirements.txt, pyproject.toml ([project] or [tool.poetry]), setup.cfg, setup.py, and requirements/{common.txt,base.txt,requirements.in,cpu.txt,cuda.txt,rocm.txt,xpu.txt}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_project(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blanket-manifest-{name}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn poetry_constraints_cover_the_supported_table() {
        let cases = [
            ("^0.4.1", ">=0.4.1,<0.5.0"), ("^1.2", ">=1.2,<2.0"),
            ("^0.0.3", ">=0.0.3,<0.0.4"), ("~1.2", ">=1.2,<1.3"),
            ("~1.2.3", ">=1.2.3,<1.3.0"), ("1.2.*", "==1.2.*"),
            ("*", ""), (">=1.0", ">=1.0"), ("<2", "<2"),
            (">1", ">1"), ("<=2", "<=2"), ("!=1.2", "!=1.2"), ("!=1.2.*", "!=1.2.*"),
            ("=1.2", "==1.2"), ("1.2", "==1.2"), ("^1.2.3", ">=1.2.3,<2.0.0"),
            ("^0.2.3", ">=0.2.3,<0.3.0"), ("^0.0.0", ">=0.0.0,<0.0.1"),
            ("~1", ">=1,<2"), ("~1.2.0", ">=1.2.0,<1.3.0"),
            (">=1.0,<2.0", ">=1.0,<2.0"), ("^1.0 || ^2.0", ">=1.0,<2.0 || >=2.0,<3.0"),
        ];
        assert!(cases.len() >= 15);
        for (input, expected) in cases { assert_eq!(poetry_constraint_to_pep440(input).unwrap(), expected, "{input}"); }
    }

    #[test]
    fn parses_uv_lock_file_hashes() {
        let packages = parse_uv_lock(r#"[[package]]
name = "six"
version = "1.17.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version >= '3.12'"]
dependencies = [{ name = "idna", marker = "python_version >= '3.12'" }]
sdist = { url = "https://files.pythonhosted.org/six.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
wheels = [{ url = "https://files.pythonhosted.org/six.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]
"#).unwrap();
        assert_eq!(packages[0].files.len(), 2);
        assert_eq!(packages[0].files[1].hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(packages[0].dependencies, ["idna"]);
        assert_eq!(packages[0].resolution_markers, ["python_full_version >= '3.12'"]);
        assert_eq!(packages[0].dependency_edges[0].marker.as_deref(), Some("python_version >= '3.12'"));
    }

    #[test]
    fn uv_lock_project_root_may_omit_a_version() {
        let packages = parse_uv_lock(r#"[[package]]
name = "demo"
source = { editable = "." }
dependencies = [{ name = "six" }]
"#).unwrap();
        assert_eq!(packages[0].version, "");
        assert_eq!(packages[0].dependencies, ["six"]);
    }

    #[test]
    fn uv_lock_empty_project_root_does_not_pull_in_dev_packages() {
        let packages = vec![
            UvPackage {
                name: "demo".into(), version: String::new(), source: "{ editable = \".\" }".into(),
                files: Vec::new(), dependencies: Vec::new(),
                resolution_markers: Vec::new(), dependency_edges: Vec::new(),
            },
            UvPackage {
                name: "pytest".into(), version: "8.0.0".into(), source: "registry".into(),
                files: vec![UvFile {
                    url: "https://files.example/pytest-8.0.0.tar.gz".into(), hash: "a".repeat(64),
                    filename: "pytest-8.0.0.tar.gz".into(), kind: ArtifactKind::Sdist,
                }], dependencies: Vec::new(), resolution_markers: Vec::new(), dependency_edges: Vec::new(),
            },
        ];
        assert!(uv_lock_manifest(
            &packages, &[], Platform::X86_64UnknownLinuxGnu, "3.12.14", pypi::Glibc(2, 43)
        ).unwrap().is_none());
    }

    #[test]
    fn uv_lock_selection_uses_the_selected_host_interpreter() {
        let packages = vec![UvPackage {
            name: "demo".into(),
            version: "1.0.0".into(),
            source: "{ registry = \"https://pypi.org/simple\" }".into(),
            files: vec![
                UvFile {
                    url: "https://files.example/demo-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl".into(),
                    hash: "a".repeat(64),
                    filename: "demo-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl".into(),
                    kind: ArtifactKind::Wheel,
                },
                UvFile {
                    url: "https://files.example/demo-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl".into(),
                    hash: "b".repeat(64),
                    filename: "demo-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl".into(),
                    kind: ArtifactKind::Wheel,
                },
            ],
            dependencies: Vec::new(),
            resolution_markers: Vec::new(), dependency_edges: Vec::new(),
        }];
        let selected = uv_lock_manifest(
            &packages,
            &["demo==1.0.0".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected[0].filename, packages[0].files[1].filename);
    }

    #[test]
    fn uv_lock_follows_selected_roots_not_unreachable_dev_packages() {
        let file = |name: &str| UvFile {
            url: format!("https://files.example/{name}-1.0.0.tar.gz"),
            hash: "a".repeat(64),
            filename: format!("{name}-1.0.0.tar.gz"),
            kind: ArtifactKind::Sdist,
        };
        let packages = vec![
            UvPackage {
                name: "six".into(), version: "1.0.0".into(), source: "registry".into(),
                files: vec![file("six")], dependencies: vec!["idna".into()],
                resolution_markers: Vec::new(), dependency_edges: Vec::new(),
            },
            UvPackage {
                name: "idna".into(), version: "3.0.0".into(), source: "registry".into(),
                files: vec![file("idna")], dependencies: Vec::new(),
                resolution_markers: Vec::new(), dependency_edges: Vec::new(),
            },
            UvPackage {
                name: "pytest".into(), version: "8.0.0".into(), source: "registry".into(),
                files: vec![file("pytest")], dependencies: Vec::new(),
                resolution_markers: Vec::new(), dependency_edges: Vec::new(),
            },
        ];
        let selected = uv_lock_manifest(
            &packages,
            &["six".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        ).unwrap().unwrap();
        assert_eq!(
            selected.iter().map(|package| package.name.as_str()).collect::<Vec<_>>(),
            ["idna", "six"]
        );
    }

    #[test]
    fn setup_cfg_multiline_and_comments() {
        let cfg = parse_setup_cfg("[options]\ninstall_requires =\n  six>=1 # comment\n  markupsafe\n").unwrap();
        assert_eq!(cfg.requirements, ["six>=1", "markupsafe"]);
    }

    #[test]
    fn poetry_table_dependency_preserves_extras_and_markers() {
        let value: toml::Value = toml::from_str(
            r#"version = "^1.2.3"
optional = true
markers = "sys_platform == 'linux'"
extras = ["security"]
"#,
        ).unwrap();
        let extras: toml::Value = toml::from_str("security = [\"demo\"]").unwrap();
        let requested = ["security".to_string()].into_iter().collect();
        assert_eq!(
            poetry_requirement("demo", &value, extras.as_table().unwrap(), &requested).unwrap(),
            Some("demo[security]>=1.2.3,<2.0.0; sys_platform == 'linux'".into())
        );
    }

    #[test]
    fn poetry_lock_keeps_reachable_main_hashes_only() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
six = "^1.0"

[tool.poetry.group.dev.dependencies]
pytest = "*"
"#,
        ).unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "six"
version = "1.17.0"
groups = ["main"]
dependencies = { idna = ">=3" }
files = [{ file = "six.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[[package]]
name = "idna"
version = "3.10"
groups = ["main"]
files = [{ file = "idna.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "pytest"
version = "8.0.0"
groups = ["dev"]
files = [{ file = "pytest.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        ).unwrap();
        let requirements = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &BlanketPythonConfig::default(),
            "3.12.14",
        ).unwrap();
        assert_eq!(requirements.len(), 2);
        assert!(requirements.iter().any(|line| line.starts_with("six==1.17.0") && line.contains("aaaaaaaa")));
        assert!(!requirements.iter().any(|line| line.starts_with("pytest==")));
    }

    #[test]
    fn constraints_remain_constraint_only_after_flattening() {
        let dir = temp_project("constraints");
        fs::write(dir.join("requirements.txt"), "-c constraints.txt\nsix>=1\n").unwrap();
        fs::write(dir.join("constraints.txt"), "six<2\n").unwrap();
        let manifest = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap();
        assert_eq!(manifest.normalized_requirements_text(), "six>=1\n");
        assert_eq!(manifest.constraints_text(), "six<2\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn setup_shim_detection_accepts_multiline_setup_call() {
        assert!(is_trivial_setup_py(
            "from setuptools import setup\nsetup(\n  name='demo',\n  version='1'\n)\n"
        ));
        assert!(!is_trivial_setup_py(
            "from setuptools import setup\nrequirements = read_requirements()\nsetup(install_requires=requirements)\n"
        ));
    }

    #[test]
    fn setup_metadata_cache_identity_includes_interpreter_platform_and_toolchain() {
        let cache = SetupCache {
            tree_hash: "tree".into(),
            requirements: Vec::new(),
            requires_python: None,
            python_version: "3.12.14".into(),
            platform: Platform::X86_64UnknownLinuxGnu.triple().into(),
            build_toolchain: build::derivation_fingerprint(),
        };
        let toolchain = build::derivation_fingerprint();
        assert!(setup_cache_matches(
            &cache,
            "tree",
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            &toolchain,
        ));
        assert!(!setup_cache_matches(
            &cache,
            "tree",
            Platform::X86_64UnknownLinuxGnu,
            "3.10.21",
            &toolchain,
        ));
        assert!(!setup_cache_matches(
            &cache,
            "tree",
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            &toolchain,
        ));
        assert!(!setup_cache_matches(&cache, "tree", Platform::X86_64UnknownLinuxGnu, "3.12.14", "changed"));
    }

    #[test]
    fn hardware_requirements_default_to_cpu_and_honor_override() {
        let dir = temp_project("hardware");
        fs::create_dir_all(dir.join("requirements")).unwrap();
        fs::write(dir.join("requirements/cpu.txt"), "six==1.0\n").unwrap();
        fs::write(dir.join("requirements/cuda.txt"), "numpy==1.0\n").unwrap();
        let default = requirements_directory_candidate(&dir, &BlanketPythonConfig::default())
            .unwrap()
            .unwrap();
        assert_eq!(default.file_name().unwrap(), "cpu.txt");
        let override_cfg = BlanketPythonConfig {
            requirements: Some("requirements/cuda.txt".into()),
            extras: BTreeSet::new(),
        };
        let selected = requirements_directory_candidate(&dir, &override_cfg)
            .unwrap()
            .unwrap();
        assert_eq!(selected.file_name().unwrap(), "cuda.txt");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn nested_index_options_are_removed_from_resolver_input() {
        let dir = temp_project("nested-index");
        fs::write(dir.join("requirements.txt"), "-r child.txt\n").unwrap();
        fs::write(
            dir.join("child.txt"),
            "--index-url https://private.invalid/simple\nsix>=1\n",
        )
        .unwrap();
        let manifest = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap();
        assert_eq!(manifest.requirements, ["six>=1"]);
        assert_eq!(manifest.resolver_text(), "six>=1\n");
        crate::policy::clear();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn discovery_order_prefers_requirements_then_project_then_poetry_then_setup_and_dir() {
        let cases = [
            ("requirements", "requirements.txt", "requirements.txt"),
            ("project", "pyproject.toml", "pyproject.toml [project]"),
            ("poetry", "pyproject.toml\npoetry.lock", "pyproject.toml [tool.poetry] (+ poetry.lock)"),
            ("setupcfg", "setup.cfg", "setup.cfg [options] (empty manifest)"),
            ("setuppy", "setup.py", "setup.py (sandboxed egg_info)"),
            ("reqdir", "requirements/common.txt", "requirements/common.txt"),
        ];
        for (name, files, expected) in cases {
            let dir = temp_project(name);
            for (index, file) in files.split('\n').enumerate() {
                let path = dir.join(file);
                if let Some(parent) = path.parent() { fs::create_dir_all(parent).unwrap(); }
                let text = match file {
                    "requirements.txt" | "requirements/common.txt" => "six>=1\n",
                    "pyproject.toml" if name == "project" => "[project]\ndependencies = [\"six\"]\n",
                    "pyproject.toml" => "[tool.poetry.dependencies]\nsix = \"^1.0\"\n",
                    "poetry.lock" => "[[package]]\nname=\"six\"\nversion=\"1.0\"\nfiles=[{file=\"six.whl\",hash=\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]\n[metadata]\ncontent-hash=\"\"\n",
                    "setup.cfg" => "[options]\n",
                    "setup.py" => "from setuptools import setup\nsetup()\n",
                    _ => "",
                };
                fs::write(path, text).unwrap();
                if index == 0 && name == "reqdir" { fs::remove_file(dir.join(file)).ok(); }
            }
            if name == "reqdir" {
                fs::create_dir_all(dir.join("requirements")).unwrap();
                fs::write(dir.join("requirements/common.txt"), "six>=1\n").unwrap();
            }
            let got = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap();
            assert_eq!(got.provenance, expected, "{name}");
            let _ = fs::remove_dir_all(dir);
            crate::policy::clear();
        }
    }

    #[test]
    fn generated_lock_does_not_shadow_the_live_project_source() {
        let dir = temp_project("lock-shadow");
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"demo\"\ndependencies = [\"idna==3.10\"]\n",
        )
        .unwrap();
        fs::write(dir.join("requirements.lock.txt"), "six==1.17.0\n").unwrap();
        fs::create_dir_all(dir.join(".blanket")).unwrap();
        fs::write(dir.join(".blanket/lock-source.hash"), "stale\n").unwrap();

        let manifest = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap();
        assert_eq!(manifest.provenance, "pyproject.toml [project]");
        assert_eq!(manifest.requirements, ["idna==3.10"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dynamic_project_dependencies_fall_through_to_requirements_directory() {
        let dir = temp_project("dynamic-reqdir");
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"vllm-shaped\"\ndynamic = [\"version\", \"dependencies\"]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("requirements")).unwrap();
        fs::write(dir.join("requirements/common.txt"), "six==1.17.0\n").unwrap();

        let manifest = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap();
        assert_eq!(manifest.input, "requirements/common.txt");
        assert_eq!(manifest.requirements, ["six==1.17.0"]);
        assert!(!manifest.provenance.contains("empty manifest"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dynamic_project_without_a_dependency_source_fails_loudly() {
        let dir = temp_project("dynamic-missing");
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"dynamic-demo\"\ndynamic = [\"dependencies\"]\n",
        )
        .unwrap();
        let error = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap_err();
        assert!(error.to_string().contains("dynamic"));
        assert!(!error.to_string().contains("empty manifest"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn poetry_lock_selects_python_conditioned_package_and_edge_variants() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
root = "*"
"#,
        )
        .unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "root"
version = "1.0.0"
python-versions = "*"
groups = ["main"]
dependencies = { dep = [
  { version = "*", markers = "python_version < '3.12'" },
  { version = "*", markers = "python_version >= '3.12'" },
] }
files = [{ file = "root.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[[package]]
name = "dep"
version = "1.0.0"
python-versions = "<3.12"
groups = ["main"]
files = [{ file = "dep-1.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "dep"
version = "2.0.0"
python-versions = ">=3.12"
groups = ["main"]
files = [{ file = "dep-2.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        )
        .unwrap();
        let cfg = BlanketPythonConfig::default();
        let old = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &cfg,
            "3.11.16",
        )
        .unwrap();
        let new = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &cfg,
            "3.12.14",
        )
        .unwrap();
        assert!(old.iter().any(|line| line.starts_with("dep==1.0.0")));
        assert!(!old.iter().any(|line| line.starts_with("dep==2.0.0")));
        assert!(new.iter().any(|line| line.starts_with("dep==2.0.0")));
        assert!(!new.iter().any(|line| line.starts_with("dep==1.0.0")));
    }

    #[test]
    fn uv_lock_selects_resolution_and_dependency_marker_variants() {
        let file = |name: &str, version: &str| UvFile {
            url: format!("https://files.example/{name}-{version}.tar.gz"),
            hash: "a".repeat(64),
            filename: format!("{name}-{version}.tar.gz"),
            kind: ArtifactKind::Sdist,
        };
        let packages = vec![
            UvPackage {
                name: "root".into(),
                version: "1.0.0".into(),
                source: "{ editable = \".\" }".into(),
                files: vec![file("root", "1.0.0")],
                dependencies: vec!["dep".into()],
                resolution_markers: Vec::new(),
                dependency_edges: vec![
                    UvDependency {
                        name: "dep".into(),
                        marker: Some("python_version < '3.12'".into()),
                    },
                    UvDependency {
                        name: "dep".into(),
                        marker: Some("python_version >= '3.12'".into()),
                    },
                ],
            },
            UvPackage {
                name: "dep".into(),
                version: "1.0.0".into(),
                source: "registry".into(),
                files: vec![file("dep", "1.0.0")],
                dependencies: Vec::new(),
                resolution_markers: vec!["python_full_version < '3.12'".into()],
                dependency_edges: Vec::new(),
            },
            UvPackage {
                name: "dep".into(),
                version: "2.0.0".into(),
                source: "registry".into(),
                files: vec![file("dep", "2.0.0")],
                dependencies: Vec::new(),
                resolution_markers: vec!["python_full_version >= '3.12'".into()],
                dependency_edges: Vec::new(),
            },
        ];
        let old = uv_lock_manifest(
            &packages,
            &[],
            Platform::X86_64UnknownLinuxGnu,
            "3.11.16",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        let new = uv_lock_manifest(
            &packages,
            &[],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert!(old.iter().any(|package| package.version == "1.0.0"));
        assert!(!old.iter().any(|package| package.name == "dep" && package.version == "2.0.0"));
        assert!(new.iter().any(|package| package.name == "dep" && package.version == "2.0.0"));
        assert!(!new.iter().any(|package| package.name == "dep" && package.version == "1.0.0"));
    }

    #[test]
    fn requirements_include_cycles_are_unreadable_manifests() {
        let dir = temp_project("cycle");
        fs::write(dir.join("requirements.txt"), "-r other.txt\n").unwrap();
        fs::write(dir.join("other.txt"), "-r requirements.txt\n").unwrap();
        let error = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap_err();
        assert!(error.to_string().contains("unreadable_manifest"));
        assert!(error.to_string().contains("cycle"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn no_manifest_error_names_the_search() {
        let dir = temp_project("none");
        let error = discover(Platform::X86_64UnknownLinuxGnu, &dir).unwrap_err();
        assert!(error.to_string().contains("no_manifest"));
        assert!(error.to_string().contains("setup.py"));
        let _ = fs::remove_dir_all(dir);
    }
}

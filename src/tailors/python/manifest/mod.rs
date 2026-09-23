//! Python manifest discovery and normalization.
//!
//! A manifest is deliberately reduced to one boring intermediate form: PEP
//! 508-ish requirement lines, the Python inputs collected by `pyselect`, and
//! a short provenance string.  Lock importers may additionally provide the
//! exact artifact URL selected from their own file list; they still enter the
//! ordinary Python `Plan` and realization path.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::types::{ArtifactKind, LockedPackage};
use crate::tailors::python::build;
use crate::tailors::python::pypi;
use crate::tailors::python::pyselect::{self, ConstraintSource, PythonInputs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

mod discovery;
mod markers;
mod poetry;
mod requirements;
mod setup;
mod uv;

pub use discovery::*;
use markers::*;
pub use poetry::*;
pub use requirements::*;
use setup::*;
pub use uv::*;

/// The setup.py metadata cache, project-relative. Both read and written
/// through the held project descriptor: a hit chooses the requirements the
/// plan is built from, so a tampered one is a refusal, not a miss.
const SETUP_CACHE: &str = ".tog/egg-info.json";

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
        if self.input.starts_with("requirements") && self.has_index_options {
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
        if matches!(
            self.input.as_str(),
            "setup.cfg" | "setup.py" | "pyproject.toml"
        ) {
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
        project: &ProjectRoot,
        store: &Store,
        selected: &crate::kernel::toolchain::Selected,
    ) -> io::Result<()> {
        let python_version = selected.version("cpython")?;
        if !self.setup || self.setup_cfg {
            return Ok(());
        }
        let tree_hash = setup_tree_hash(dir)?;
        // Read through the held descriptor, and treat a refusal as an error
        // rather than a miss. A cache hit decides the requirements this plan
        // is built from, and `setup_cache_matches` gates only on the tree
        // hash, platform, interpreter and toolchain fingerprint — all of
        // them computable by whoever planted a symlinked `.tog`. An
        // unreadable or malformed regular file is still a plain miss.
        let cached = match project.read_file(Path::new(SETUP_CACHE)) {
            Ok(cached) => cached,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
            Err(_) => None,
        };
        if let Some(bytes) = cached {
            if let Ok(cache) = serde_json::from_slice::<SetupCache>(&bytes) {
                if setup_cache_matches(
                    &cache,
                    &tree_hash,
                    platform,
                    python_version,
                    &build::derivation_fingerprint(),
                ) {
                    self.requirements = cache.requirements;
                    self.source = self.requirements_text();
                    replace_setup_requires_python(&mut self.python, cache.requires_python);
                    return Ok(());
                }
            }
        }

        let build_env = build::ensure_build_environment(store, platform, selected)
            .map_err(|error| unreadable(&dir.join("setup.py"), error))?;
        let cpython = crate::tailors::python::realize_runtime(store, platform, selected)
            .map_err(|error| unreadable(&dir.join("setup.py"), error))?;
        // One lease covers the scratch directory and the sandboxed probe.
        let activity = &store.activity(crate::kernel::activity::ActivityMode::Shared)?;
        let scratch = store.stage_with_activity(activity)?;
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
            env: vec![("SETUPTOOLS_USE_DISTUTILS".into(), "local".into())],
            read: vec![project_root, build_env.clone(), cpython],
            write: vec![scratch.clone()],
            scratch: scratch.clone(),
            path: format!("{}:/usr/bin:/bin", build_env.join("bin").display()),
        };
        let result =
            crate::kernel::sandbox::run_build_spec_on_with_activity(platform, &spec, activity);
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
            pypi::parse_requires_txt(&text).map_err(|error| unreadable(&requires_file, error))?
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
        // Through the held project descriptor: a symlinked `.tog` must not
        // carry this cache outside the project.
        project.write_file(Path::new(SETUP_CACHE), &serde_json::to_vec_pretty(&cache)?)?;
        let _ = fs::remove_dir_all(&scratch);
        self.requirements = requirements;
        self.source = self.requirements_text();
        replace_setup_requires_python(&mut self.python, requires_python);
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

fn unreadable(path: &Path, error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "cannot read {}: {error}; the manifest is broken, or this is a tog bug",
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

fn toml_json(value: &toml::Value) -> io::Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| io::Error::other(error.to_string()))
}

fn toml_json_table(table: &toml::map::Map<String, toml::Value>) -> io::Result<serde_json::Value> {
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

fn find_named_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut entries = fs::read_dir(root).ok()?.flatten().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_named_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
            return Some(path);
        }
    }
    None
}

fn read_tail(path: &Path, count: usize) -> String {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .rev()
        .take(count)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

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
    io::Error::new(io::ErrorKind::NotFound, "nothing to sync here: no Python manifest found; looked for requirements.lock.txt, requirements.txt, pyproject.toml ([project] or [tool.poetry]), setup.cfg, setup.py, and requirements/{common.txt,base.txt,requirements.in,cpu.txt,cuda.txt,rocm.txt,xpu.txt}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_project(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tog-manifest-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_setup_cache_behind_a_symlinked_tog_is_refused_not_honoured() {
        let root = temp_project("egg-info-symlink");
        let dir = root.join("project");
        let outside = root.join("outside");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(
            dir.join("setup.py"),
            "from setuptools import setup\nsetup()\n",
        )
        .unwrap();

        let platform = Platform::host().unwrap();
        let python_version = "3.12.14";
        // A cache that matches on every field prepare_setup gates on, all of
        // them computable by whoever plants the symlink. Only the descriptor
        // walk stands between it and the plan.
        let planted = SetupCache {
            tree_hash: setup_tree_hash(&dir).unwrap(),
            requirements: vec!["attacker-controlled==1.0".to_string()],
            requires_python: None,
            python_version: python_version.to_string(),
            platform: platform.triple().to_string(),
            build_toolchain: build::derivation_fingerprint(),
        };
        fs::write(
            outside.join("egg-info.json"),
            serde_json::to_vec_pretty(&planted).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, dir.join(".tog")).unwrap();

        let mut manifest = discover(platform, &dir, python_version).unwrap();
        assert!(manifest.requires_setup(), "fixture is not a setup.py tree");
        let project = ProjectRoot::open(&dir).unwrap();
        let store = Store {
            root: root.join("absent-store"),
        };
        let error = manifest
            .prepare_setup(
                platform,
                &dir,
                &project,
                &store,
                &crate::tailors::python::shipped_selection(python_version).unwrap(),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert!(
            !manifest
                .requirements
                .iter()
                .any(|entry| entry.contains("attacker-controlled")),
            "the planted cache reached the plan: {:?}",
            manifest.requirements
        );
        assert!(!store.root.exists(), "a refused cache touched the store");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn poetry_constraints_cover_the_supported_table() {
        let cases = [
            ("^0.4.1", ">=0.4.1,<0.5.0"),
            ("^1.2", ">=1.2,<2.0"),
            ("^0.0.3", ">=0.0.3,<0.0.4"),
            ("~1.2", ">=1.2,<1.3"),
            ("~1.2.3", ">=1.2.3,<1.3.0"),
            ("1.2.*", "==1.2.*"),
            ("*", ""),
            (">=1.0", ">=1.0"),
            ("<2", "<2"),
            (">1", ">1"),
            ("<=2", "<=2"),
            ("!=1.2", "!=1.2"),
            ("!=1.2.*", "!=1.2.*"),
            ("=1.2", "==1.2"),
            ("1.2", "==1.2"),
            ("^1.2.3", ">=1.2.3,<2.0.0"),
            ("^0.2.3", ">=0.2.3,<0.3.0"),
            ("^0.0.0", ">=0.0.0,<0.0.1"),
            ("~1", ">=1,<2"),
            ("~1.2.0", ">=1.2.0,<1.3.0"),
            (">=1.0,<2.0", ">=1.0,<2.0"),
            ("^1.0 || ^2.0", ">=1.0,<2.0 || >=2.0,<3.0"),
        ];
        assert!(cases.len() >= 15);
        for (input, expected) in cases {
            assert_eq!(
                poetry_constraint_to_pep440(input).unwrap(),
                expected,
                "{input}"
            );
        }
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
        assert_eq!(
            packages[0].files[1].hash,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(packages[0].dependencies, ["idna"]);
        assert_eq!(
            packages[0].resolution_markers,
            ["python_full_version >= '3.12'"]
        );
        assert_eq!(
            packages[0].dependency_edges[0].marker.as_deref(),
            Some("python_version >= '3.12'")
        );
    }

    #[test]
    fn uv_lock_project_root_may_omit_a_version() {
        let packages = parse_uv_lock(
            r#"[[package]]
name = "demo"
source = { editable = "." }
dependencies = [{ name = "six" }]
"#,
        )
        .unwrap();
        assert_eq!(packages[0].version, "");
        assert_eq!(packages[0].dependencies, ["six"]);
    }

    #[test]
    fn uv_lock_empty_project_root_does_not_pull_in_dev_packages() {
        let packages = vec![
            UvPackage {
                name: "demo".into(),
                version: String::new(),
                source: "{ editable = \".\" }".into(),
                files: Vec::new(),
                dependencies: Vec::new(),
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
            UvPackage {
                name: "pytest".into(),
                version: "8.0.0".into(),
                source: "registry".into(),
                files: vec![UvFile {
                    url: "https://files.example/pytest-8.0.0.tar.gz".into(),
                    hash: "a".repeat(64),
                    filename: "pytest-8.0.0.tar.gz".into(),
                    kind: ArtifactKind::Sdist,
                }],
                dependencies: Vec::new(),
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
        ];
        assert!(uv_lock_manifest(
            &packages,
            &[],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43)
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn uv_lock_selection_uses_the_selected_host_interpreter() {
        let packages = vec![UvPackage {
            name: "demo".into(),
            version: "1.0.0".into(),
            source: "{ registry = \"https://pypi.org/simple\" }".into(),
            files: vec![
                UvFile {
                    url: "https://files.example/demo-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl"
                        .into(),
                    hash: "a".repeat(64),
                    filename: "demo-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl".into(),
                    kind: ArtifactKind::Wheel,
                },
                UvFile {
                    url: "https://files.example/demo-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl"
                        .into(),
                    hash: "b".repeat(64),
                    filename: "demo-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl".into(),
                    kind: ArtifactKind::Wheel,
                },
            ],
            dependencies: Vec::new(),
            resolution_markers: Vec::new(),
            dependency_edges: Vec::new(),
            optional_dependencies: BTreeMap::new(),
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
                name: "six".into(),
                version: "1.0.0".into(),
                source: "registry".into(),
                files: vec![file("six")],
                dependencies: vec!["idna".into()],
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
            UvPackage {
                name: "idna".into(),
                version: "3.0.0".into(),
                source: "registry".into(),
                files: vec![file("idna")],
                dependencies: Vec::new(),
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
            UvPackage {
                name: "pytest".into(),
                version: "8.0.0".into(),
                source: "registry".into(),
                files: vec![file("pytest")],
                dependencies: Vec::new(),
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
        ];
        let selected = uv_lock_manifest(
            &packages,
            &["six".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["idna", "six"]
        );
    }

    #[test]
    fn uv_lock_without_a_project_root_takes_every_non_local_package() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let package = |name: &str, source: &str| UvPackage {
            name: name.into(),
            version: "1.0.0".into(),
            source: source.into(),
            files: vec![UvFile {
                url: format!("https://files.example/{name}-1.0.0.tar.gz"),
                hash: "a".repeat(64),
                filename: format!("{name}-1.0.0.tar.gz"),
                kind: ArtifactKind::Sdist,
            }],
            dependencies: Vec::new(),
            resolution_markers: Vec::new(),
            dependency_edges: Vec::new(),
            optional_dependencies: BTreeMap::new(),
        };
        // No editable/virtual root and no explicit requirements: the whole
        // lock is in scope, minus the local/VCS sources, which are recorded
        // as skipped requirements instead.
        let packages = vec![
            package("six", "registry"),
            package("vendored", "{ directory = \"vendor/local\" }"),
            package(
                "private",
                "{ registry = \"https://private.invalid/simple\" }",
            ),
        ];
        let selected = uv_lock_manifest(
            &packages,
            &[],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["private", "six"]
        );
        let _ = crate::kernel::policy::drain();
    }

    #[test]
    fn setup_cfg_multiline_and_comments() {
        let cfg = pyselect::parse_setup_cfg(
            "[options]\ninstall_requires =\n  six>=1 # comment\n  markupsafe\n",
        );
        assert_eq!(cfg.install_requires, ["six>=1", "markupsafe"]);
    }

    #[test]
    fn poetry_table_dependency_preserves_extras_and_markers() {
        let value: toml::Value = toml::from_str(
            r#"version = "^1.2.3"
optional = true
markers = "sys_platform == 'linux'"
extras = ["security"]
"#,
        )
        .unwrap();
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
        )
        .unwrap();
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
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert_eq!(requirements.len(), 2);
        assert!(requirements
            .iter()
            .any(|line| line.starts_with("six==1.17.0") && line.contains("aaaaaaaa")));
        assert!(!requirements.iter().any(|line| line.starts_with("pytest==")));
    }

    #[test]
    fn poetry_lock_filters_legacy_categories_and_unsupported_sources() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
six = "^1.0"
devtool = "*"
vendored = "*"
"#,
        )
        .unwrap();
        // Poetry 1.x labelled groups with `category` instead of `groups`, and
        // a directory/git/url source has no registry artifact to lock.
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "six"
version = "1.17.0"
category = "main"
files = [{ file = "six.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[[package]]
name = "devtool"
version = "2.0.0"
category = "dev"
files = [{ file = "devtool.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "vendored"
version = "0.1.0"
category = "main"
source = { type = "directory", url = "../vendored" }
files = [{ file = "vendored.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        )
        .unwrap();
        let requirements = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert_eq!(requirements.len(), 1);
        assert!(
            requirements[0].starts_with("six==1.17.0"),
            "{requirements:?}"
        );
        let _ = crate::kernel::policy::drain();
    }

    #[test]
    fn poetry_lock_package_without_a_hash_is_an_error() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
six = "^1.0"
"#,
        )
        .unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "six"
version = "1.17.0"
groups = ["main"]
files = []
"#,
        )
        .unwrap();
        let error = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "poetry.lock package six has no sha256 file hash"
        );
    }

    #[test]
    fn constraints_remain_constraint_only_after_flattening() {
        let dir = temp_project("constraints");
        fs::write(dir.join("requirements.txt"), "-c constraints.txt\nsix>=1\n").unwrap();
        fs::write(dir.join("constraints.txt"), "six<2\n").unwrap();
        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
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
        assert!(!setup_cache_matches(
            &cache,
            "tree",
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            "changed"
        ));
    }

    #[test]
    fn hardware_requirements_default_to_cpu_and_honor_override() {
        let dir = temp_project("hardware");
        fs::create_dir_all(dir.join("requirements")).unwrap();
        fs::write(dir.join("requirements/cpu.txt"), "six==1.0\n").unwrap();
        fs::write(dir.join("requirements/cuda.txt"), "numpy==1.0\n").unwrap();
        let default = requirements_directory_candidate(&dir, &TogPythonConfig::default())
            .unwrap()
            .unwrap();
        assert_eq!(default.file_name().unwrap(), "cpu.txt");
        let override_cfg = TogPythonConfig {
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
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let dir = temp_project("nested-index");
        fs::write(dir.join("requirements.txt"), "-r child.txt\n").unwrap();
        fs::write(
            dir.join("child.txt"),
            "--index-url https://private.invalid/simple\nsix>=1\n",
        )
        .unwrap();
        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.requirements, ["six>=1"]);
        assert_eq!(manifest.resolver_text(), "six>=1\n");
        let _ = crate::kernel::policy::drain();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn discovery_order_prefers_requirements_then_project_then_poetry_then_setup_and_dir() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let cases = [
            ("requirements", "requirements.txt", "requirements.txt"),
            ("project", "pyproject.toml", "pyproject.toml [project]"),
            (
                "poetry",
                "pyproject.toml\npoetry.lock",
                "pyproject.toml [tool.poetry] (+ poetry.lock)",
            ),
            (
                "setupcfg",
                "setup.cfg",
                "setup.cfg [options] (empty manifest)",
            ),
            ("setuppy", "setup.py", "setup.py (sandboxed egg_info)"),
            (
                "reqdir",
                "requirements/common.txt",
                "requirements/common.txt",
            ),
        ];
        for (name, files, expected) in cases {
            let dir = temp_project(name);
            for (index, file) in files.split('\n').enumerate() {
                let path = dir.join(file);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
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
                if index == 0 && name == "reqdir" {
                    fs::remove_file(dir.join(file)).ok();
                }
            }
            if name == "reqdir" {
                fs::create_dir_all(dir.join("requirements")).unwrap();
                fs::write(dir.join("requirements/common.txt"), "six>=1\n").unwrap();
            }
            let got = discover(
                Platform::X86_64UnknownLinuxGnu,
                &dir,
                crate::tailors::python::pyselect::DEFAULT_VERSION,
            )
            .unwrap();
            assert_eq!(got.provenance, expected, "{name}");
            let _ = fs::remove_dir_all(dir);
            let _ = crate::kernel::policy::drain();
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
        fs::create_dir_all(dir.join(".tog")).unwrap();
        fs::write(dir.join(".tog/lock-source.hash"), "stale\n").unwrap();

        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
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

        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
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
        let error = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap_err();
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
        let cfg = TogPythonConfig::default();
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
    fn poetry_lock_edge_version_constraint_wins_over_first_python_variant() {
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
groups = ["main"]
dependencies = { dep = ">=2" }
files = [{ file = "root.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[[package]]
name = "dep"
version = "1.0.0"
python-versions = "*"
groups = ["main"]
files = [{ file = "dep-1.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "dep"
version = "2.0.0.post1"
python-versions = "*"
groups = ["main"]
files = [{ file = "dep-2.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        )
        .unwrap();
        let output = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert!(output
            .iter()
            .any(|line| line.starts_with("dep==2.0.0.post1")));
        assert!(!output.iter().any(|line| line.starts_with("dep==1.0.0")));
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
                        version: None,
                        extras: BTreeSet::new(),
                    },
                    UvDependency {
                        name: "dep".into(),
                        marker: Some("python_version >= '3.12'".into()),
                        version: None,
                        extras: BTreeSet::new(),
                    },
                ],
                optional_dependencies: BTreeMap::new(),
            },
            UvPackage {
                name: "dep".into(),
                version: "1.0.0".into(),
                source: "registry".into(),
                files: vec![file("dep", "1.0.0")],
                dependencies: Vec::new(),
                resolution_markers: vec!["python_full_version < '3.12'".into()],
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
            UvPackage {
                name: "dep".into(),
                version: "2.0.0".into(),
                source: "registry".into(),
                files: vec![file("dep", "2.0.0")],
                dependencies: Vec::new(),
                resolution_markers: vec!["python_full_version >= '3.12'".into()],
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
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
        assert!(!old
            .iter()
            .any(|package| package.name == "dep" && package.version == "2.0.0"));
        assert!(new
            .iter()
            .any(|package| package.name == "dep" && package.version == "2.0.0"));
        assert!(!new
            .iter()
            .any(|package| package.name == "dep" && package.version == "1.0.0"));
    }

    #[test]
    fn uv_lock_rejects_root_constraint_that_locked_version_cannot_satisfy() {
        let package = UvPackage {
            name: "foo".into(),
            version: "1.0.0".into(),
            source: "registry".into(),
            files: vec![UvFile {
                url: "https://files.example/foo-1.0.0.tar.gz".into(),
                hash: "a".repeat(64),
                filename: "foo-1.0.0.tar.gz".into(),
                kind: ArtifactKind::Sdist,
            }],
            dependencies: Vec::new(),
            resolution_markers: Vec::new(),
            dependency_edges: Vec::new(),
            optional_dependencies: BTreeMap::new(),
        };
        let error = uv_lock_manifest(
            &[package],
            &["foo>=2".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap_err();
        assert!(error.to_string().contains("foo"));
        assert!(error.to_string().contains(">=2"));
    }

    #[test]
    fn uv_lock_root_extra_traverses_optional_dependency_table() {
        let file = |name: &str| UvFile {
            url: format!("https://files.example/{name}-1.0.0.tar.gz"),
            hash: "a".repeat(64),
            filename: format!("{name}-1.0.0.tar.gz"),
            kind: ArtifactKind::Sdist,
        };
        let packages = vec![
            UvPackage {
                name: "foo".into(),
                version: "1.0.0".into(),
                source: "registry".into(),
                files: vec![file("foo")],
                dependencies: Vec::new(),
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: [(
                    "feature".into(),
                    vec![UvDependency {
                        name: "bar".into(),
                        marker: None,
                        version: None,
                        extras: BTreeSet::new(),
                    }],
                )]
                .into_iter()
                .collect(),
            },
            UvPackage {
                name: "bar".into(),
                version: "1.0.0".into(),
                source: "registry".into(),
                files: vec![file("bar")],
                dependencies: Vec::new(),
                resolution_markers: Vec::new(),
                dependency_edges: Vec::new(),
                optional_dependencies: BTreeMap::new(),
            },
        ];
        let selected = uv_lock_manifest(
            &packages,
            &["foo[feature]".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["bar", "foo"]
        );
    }

    #[test]
    fn uv_serialized_extra_field_activates_a_package_extra() {
        let lock = r#"[[package]]
name = "demo"
source = { editable = "." }
dependencies = [{ name = "foo", extra = ["feature"] }]

[[package]]
name = "foo"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
optional-dependencies = { feature = [{ name = "bar" }] }
sdist = { url = "https://files.example/foo-1.0.0.tar.gz", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }

[[package]]
name = "bar"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/bar-1.0.0.tar.gz", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
"#;
        let packages = parse_uv_lock(lock).unwrap();
        assert_eq!(
            packages[0].dependency_edges[0].extras,
            ["feature".to_string()].into_iter().collect()
        );
        let selected = uv_lock_manifest(
            &packages,
            &[],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            ["bar", "foo"]
        );
    }

    #[test]
    fn poetry_serialized_extra_requirements_activate_nested_extras_to_fixpoint() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
pbs-installer = { version = "*", extras = ["all"] }
"#,
        )
        .unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "pbs-installer"
version = "1.0.0"
groups = ["main"]
files = [{ file = "pbs-installer.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[package.extras]
all = ["pbs-installer[download,install]"]
download = ["download-dep"]
install = ["install-dep"]

[[package]]
name = "download-dep"
version = "1.0.0"
groups = ["main"]
files = [{ file = "download-dep.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "install-dep"
version = "1.0.0"
groups = ["main"]
files = [{ file = "install-dep.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        )
        .unwrap();
        let output = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert!(output.iter().any(|line| line.starts_with("download-dep==")));
        assert!(output.iter().any(|line| line.starts_with("install-dep==")));
    }

    #[test]
    fn poetry_lock_extra_edges_preserve_their_constraints() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
foo = { version = "*", extras = ["feature"] }
"#,
        )
        .unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "foo"
version = "1.0.0"
groups = ["main"]
files = [{ file = "foo.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[package.extras]
feature = ["bar (>=2,<3)"]

[[package]]
name = "bar"
version = "1.0.0"
groups = ["main"]
files = [{ file = "bar-1.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "bar"
version = "2.0.0"
groups = ["main"]
files = [{ file = "bar-2.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        )
        .unwrap();
        let output = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert!(output.iter().any(|line| line.starts_with("foo==1.0.0")));
        assert!(output.iter().any(|line| line.starts_with("bar==2.0.0")));
        assert!(!output.iter().any(|line| line.starts_with("bar==1.0.0")));
    }

    #[test]
    fn poetry_serialized_extra_markers_are_filtered_before_graph_traversal() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
foo = { version = "*", extras = ["feature"] }
"#,
        )
        .unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "foo"
version = "1.0.0"
groups = ["main"]
files = [{ file = "foo.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[package.extras]
feature = [
  'linux-dep (>=1) ; sys_platform == "linux"',
  'colorama (>=0.4) ; sys_platform == "win32"',
]

[[package]]
name = "linux-dep"
version = "1.0.0"
groups = ["main"]
files = [{ file = "linux-dep.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "colorama"
version = "0.4.6"
groups = ["main"]
files = [{ file = "colorama.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]
"#,
        )
        .unwrap();
        let output = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert!(output.iter().any(|line| line.starts_with("linux-dep==")));
        assert!(!output.iter().any(|line| line.starts_with("colorama==")));
    }

    #[test]
    fn poetry_variant_reselection_retracts_discarded_dependencies() {
        let project: toml::Value = toml::from_str(
            r#"[tool.poetry.dependencies]
a = "*"
z = "*"
"#,
        )
        .unwrap();
        let lock: toml::Value = toml::from_str(
            r#"[[package]]
name = "a"
version = "1.0.0"
groups = ["main"]
dependencies = { old = "*" }
files = [{ file = "a-1.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]

[[package]]
name = "a"
version = "2.0.0"
groups = ["main"]
files = [{ file = "a-2.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]

[[package]]
name = "z"
version = "1.0.0"
groups = ["main"]
dependencies = { a = ">=2" }
files = [{ file = "z.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }]

[[package]]
name = "old"
version = "1.0.0"
groups = ["main"]
files = [{ file = "old.whl", hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" }]
"#,
        )
        .unwrap();
        let output = poetry_lock_requirements(
            Platform::X86_64UnknownLinuxGnu,
            &project,
            &lock,
            &TogPythonConfig::default(),
            "3.12.14",
        )
        .unwrap();
        assert!(output.iter().any(|line| line.starts_with("a==2.0.0")));
        assert!(output.iter().any(|line| line.starts_with("z==1.0.0")));
        assert!(!output.iter().any(|line| line.starts_with("old==")));
    }

    #[test]
    fn uv_lock_skips_inactive_root_markers() {
        let package = UvPackage {
            name: "windows-only".into(),
            version: "1.0.0".into(),
            source: "registry".into(),
            files: vec![UvFile {
                url: "https://files.example/windows-only-1.0.0.tar.gz".into(),
                hash: "a".repeat(64),
                filename: "windows-only-1.0.0.tar.gz".into(),
                kind: ArtifactKind::Sdist,
            }],
            dependencies: Vec::new(),
            resolution_markers: Vec::new(),
            dependency_edges: Vec::new(),
            optional_dependencies: BTreeMap::new(),
        };
        let selected = uv_lock_manifest(
            &[package],
            &["windows-only; sys_platform == 'win32'".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn marker_membership_uses_pep508_string_semantics() {
        assert!(marker_matches(
            "python_version in '3.12'",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(!marker_matches(
            "python_version in '3.12'",
            "3.11.16",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(marker_matches(
            "sys_platform in 'linux,darwin'",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(!marker_matches(
            "sys_platform not in 'linux,darwin'",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        let cases = [
            ("python_version == '3.12.*'", true),
            ("python_version != '3.12.*'", false),
            ("python_full_version >= '3.12.0'", true),
            ("python_full_version < '3.12.14'", false),
        ];
        for (marker, expected) in cases {
            assert_eq!(
                marker_matches(marker, "3.12.14", Platform::X86_64UnknownLinuxGnu).unwrap(),
                expected,
                "{marker}"
            );
        }
    }

    #[test]
    fn poetry_python_markers_keep_patch_precision_and_marker_grammar() {
        assert_eq!(
            poetry_python_marker(">=3.12.1").unwrap().as_deref(),
            Some("python_full_version >= '3.12.1'"),
        );
        assert!(marker_matches(
            "python_full_version >= '3.12.1'",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(!marker_matches(
            "python_full_version >= '3.12.1'",
            "3.12.0",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(marker_matches(
            "python_version ~= '3.12'",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(marker_matches(
            "'3.12' == python_version",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
        assert!(marker_matches(
            "'3.11' < python_version",
            "3.12.14",
            Platform::X86_64UnknownLinuxGnu,
        )
        .unwrap());
    }

    #[test]
    fn requirements_tree_hash_changes_when_an_included_file_changes() {
        let dir = temp_project("requirements-tree-hash");
        fs::create_dir_all(dir.join("requirements")).unwrap();
        let top = dir.join("requirements/cpu.txt");
        let child = dir.join("requirements/common.txt");
        fs::write(&top, "-r common.txt\n").unwrap();
        fs::write(&child, "six==1.0\n").unwrap();
        let old = requirements_tree_hash(&top).unwrap();
        fs::write(&child, "six==2.0\n").unwrap();
        let new = requirements_tree_hash(&top).unwrap();
        assert_ne!(old, new);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_requirement_includes_are_discovered_and_hashed() {
        let dir = temp_project("compact-includes");
        fs::create_dir_all(dir.join("requirements")).unwrap();
        let top = dir.join("requirements/cpu.txt");
        fs::write(
            &top,
            "-rcommon.txt\n-c../constraints.txt\n--requirement=extra.txt\n",
        )
        .unwrap();
        fs::write(dir.join("requirements/common.txt"), "six\n").unwrap();
        fs::write(dir.join("requirements/extra.txt"), "idna\n").unwrap();
        fs::write(dir.join("constraints.txt"), "six<2\n").unwrap();
        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.normalized_requirements_text(), "six\nidna\n");
        assert_eq!(manifest.constraints_text(), "six<2\n");
        let old = requirements_tree_hash(&top).unwrap();
        fs::write(dir.join("constraints.txt"), "six<3\n").unwrap();
        assert_ne!(old, requirements_tree_hash(&top).unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_constraint_then_requirement_include_uses_both_contexts() {
        let dir = temp_project("include-context");
        fs::write(dir.join("requirements.txt"), "-c deps.txt\n-r deps.txt\n").unwrap();
        fs::write(dir.join("deps.txt"), "six\n").unwrap();
        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.normalized_requirements_text(), "six\n");
        assert_eq!(manifest.constraints_text(), "six\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn uv_locked_postrelease_satisfies_a_normal_package_constraint() {
        let package = UvPackage {
            name: "foo".into(),
            version: "1.0.0.post1".into(),
            source: "registry".into(),
            files: vec![UvFile {
                url: "https://files.example/foo-1.0.0.post1.tar.gz".into(),
                hash: "a".repeat(64),
                filename: "foo-1.0.0.post1.tar.gz".into(),
                kind: ArtifactKind::Sdist,
            }],
            dependencies: Vec::new(),
            resolution_markers: Vec::new(),
            dependency_edges: Vec::new(),
            optional_dependencies: BTreeMap::new(),
        };
        let selected = uv_lock_manifest(
            &[package],
            &["foo>=1; python_version == '3.12.*'".into()],
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            pypi::Glibc(2, 43),
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected[0].version, "1.0.0.post1");
    }

    #[test]
    fn setup_hash_covers_imported_sources_but_excludes_generated_outputs() {
        let dir = temp_project("setup-tree-hash");
        fs::write(dir.join("setup.py"), "from deps import requirements\n").unwrap();
        fs::write(dir.join("deps.py"), "requirements = ['six']\n").unwrap();
        fs::write(dir.join("requirements.lock.txt"), "stale\n").unwrap();
        fs::create_dir_all(dir.join(".tog")).unwrap();
        fs::write(dir.join(".tog/egg-info.json"), "cache\n").unwrap();
        let old = setup_tree_hash(&dir).unwrap();
        fs::write(dir.join("deps.py"), "requirements = ['idna']\n").unwrap();
        let changed = setup_tree_hash(&dir).unwrap();
        assert_ne!(old, changed);
        fs::write(dir.join("requirements.lock.txt"), "different\n").unwrap();
        fs::write(dir.join(".tog/egg-info.json"), "different\n").unwrap();
        assert_eq!(changed, setup_tree_hash(&dir).unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn setup_cfg_empty_requires_probe_when_setup_py_declares_install_requires() {
        let dir = temp_project("setupcfg-probe");
        fs::write(dir.join("setup.cfg"), "[options]\ninstall_requires =\n").unwrap();
        fs::write(
            dir.join("setup.py"),
            "from setuptools import setup as s\ns(install_requires=['six'])\n",
        )
        .unwrap();
        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.input, "setup.py");
        assert!(manifest.requires_setup());
        assert!(!is_trivial_setup_py(
            "from setuptools import setup as s\ns(install_requires=['six'])\n"
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn indented_setup_cfg_install_requires_is_a_manifest_dependency() {
        let dir = temp_project("setupcfg-indented-manifest");
        fs::write(
            dir.join("setup.cfg"),
            "[options]\n  install_requires =\n    six\n",
        )
        .unwrap();
        let manifest = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap();
        assert_eq!(manifest.input, "setup.cfg");
        assert_eq!(manifest.requirements, ["six"]);
        assert!(!manifest.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn requirements_include_cycles_are_unreadable_manifests() {
        let dir = temp_project("cycle");
        fs::write(dir.join("requirements.txt"), "-r other.txt\n").unwrap();
        fs::write(dir.join("other.txt"), "-r requirements.txt\n").unwrap();
        let error = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot read"));
        assert!(error.to_string().contains("the manifest is broken"));
        assert!(error.to_string().contains("cycle"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn no_manifest_error_names_the_search() {
        let dir = temp_project("none");
        let error = discover(
            Platform::X86_64UnknownLinuxGnu,
            &dir,
            crate::tailors::python::pyselect::DEFAULT_VERSION,
        )
        .unwrap_err();
        // The classifier prefix is gone: this is the text a user reads.
        assert!(!error.to_string().contains("no_manifest"));
        assert!(error.to_string().contains("nothing to sync here"));
        assert!(error.to_string().contains("setup.py"));
        let _ = fs::remove_dir_all(dir);
    }
}

//! CPython constraint parsing and selection.
//!
//! Version parsing and matching lives in `pep440`; this module only collects
//! interpreter inputs and chooses one of blanket's pinned CPython builds. It
//! is pure once project files have been collected: selection never consults
//! the host Python or a package index.

use crate::platform::Platform;
use crate::python::{PinnedPython, PYTHONS};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

const DEFAULT_VERSION: &str = "3.12.14";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintSource {
    pub text: String,
    pub source: String,
}

impl ConstraintSource {
    pub fn new(text: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            source: source.into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PythonInputs {
    pub explicit: Option<ExplicitPython>,
    pub constraints: Vec<ConstraintSource>,
}

/// The dependency-bearing subset of setuptools' setup.cfg metadata.
///
/// This is intentionally parsed here, next to the interpreter constraint
/// extractor, so manifest discovery and Python selection share ConfigParser's
/// continuation rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupCfgMetadata {
    pub install_requires: Vec<String>,
    pub install_requires_found: bool,
    pub python_requires: Option<String>,
    pub extras_require: BTreeMap<String, Vec<String>>,
    pub packages_find: Option<SetupCfgPackagesFind>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupCfgPackagesFind {
    pub where_: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitPython {
    pub raw: String,
    pub source: String,
    version: crate::pep440::Version,
}

#[derive(Debug)]
pub struct PythonSelection {
    pub pin: &'static PinnedPython,
    pub constraint: Option<String>,
    pub constraint_source: Option<String>,
    pub warnings: Vec<String>,
    pub explicit_request: Option<String>,
}

impl PythonSelection {
    pub fn is_default(&self) -> bool {
        self.pin.version == DEFAULT_VERSION
    }

    /// Human-readable diagnostics are emitted by the caller so preflight and
    /// planning can share one selection without printing twice.
    pub fn selection_message(&self) -> String {
        if let Some(raw) = &self.explicit_request {
            format!(
                "blanket: python {} selected (.python-version \"{}\" from .python-version)",
                self.pin.version, raw
            )
        } else {
            format!(
                "blanket: python {} selected (requires-python \"{}\" from {})",
                self.pin.version,
                self.constraint.as_deref().unwrap_or("*"),
                self.constraint_source
                    .as_deref()
                    .unwrap_or("project metadata")
            )
        }
    }

    pub fn emit_warnings(&self) {
        for warning in &self.warnings {
            eprintln!("{warning}");
        }
        if !self.is_default() {
            eprintln!("{}", self.selection_message());
        }
    }
}

/// Pure PEP 440/Poetry matching helper for a pinned X.Y.Z candidate.
pub fn matches_specifier(specifier: &str, version: &str) -> io::Result<bool> {
    crate::pep440::matches_specifier(specifier, version)
}

/// Select a pinned CPython from already-collected declared constraints. With
/// no constraints this deliberately returns the historical 3.12.14 pin.
pub fn select_python(
    platform: Platform,
    constraints: &[ConstraintSource],
) -> io::Result<PythonSelection> {
    select_python_with_inputs(
        platform,
        &PythonInputs {
            explicit: None,
            constraints: constraints.to_vec(),
        },
    )
}

pub fn select_python_with_inputs(
    platform: Platform,
    inputs: &PythonInputs,
) -> io::Result<PythonSelection> {
    let pins: Vec<_> = PYTHONS
        .iter()
        .filter(|pin| pin.platform == platform)
        .collect();
    let parsed = inputs
        .constraints
        .iter()
        .map(|constraint| {
            crate::pep440::SpecifierSet::parse(&constraint.text, &constraint.source)
                .map(|set| (constraint, set))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let constraint_text = if inputs.constraints.is_empty() {
        None
    } else {
        Some(
            inputs
                .constraints
                .iter()
                .map(|constraint| constraint.text.as_str())
                .collect::<Vec<_>>()
                .join(" && "),
        )
    };
    let constraint_source = if inputs.constraints.is_empty() {
        None
    } else {
        Some(
            inputs
                .constraints
                .iter()
                .map(|constraint| constraint.source.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )
    };
    let mut warnings = Vec::new();
    let (pin, explicit_request) = if let Some(explicit) = &inputs.explicit {
        let matching = pins.iter().copied().find(|pin| {
            let version = pinned_version(pin.version).expect("pinned CPython version");
            version.major() == explicit.version.major()
                && version.minor() == explicit.version.minor()
        });
        let Some(pin) = matching else {
            return Err(no_satisfying_pin(
                platform,
                &format!(".python-version \"{}\"", explicit.raw),
                &explicit.source,
                &pins,
            ));
        };
        if explicit.version.release_len() == 3 && pin.version != explicit.raw {
            warnings.push(format!(
                "blanket: .python-version requests CPython {}; using pinned patch {}",
                explicit.raw, pin.version
            ));
        }
        let violated: Vec<_> = parsed
            .iter()
            .filter(|(_, specifier)| {
                !specifier.matches(&pinned_version(pin.version).expect("pinned version"))
            })
            .map(|(constraint, _)| constraint)
            .collect();
        if !violated.is_empty() {
            let declared = violated
                .iter()
                .map(|constraint| format!("\"{}\" from {}", constraint.text, constraint.source))
                .collect::<Vec<_>>()
                .join(", ");
            warnings.push(format!(
                "blanket: .python-version \"{}\" violates declared Python constraint {}; honoring explicit request",
                explicit.raw, declared
            ));
        }
        (pin, Some(explicit.raw.clone()))
    } else {
        let satisfies = |pin: &&PinnedPython| {
            let version = pinned_version(pin.version).expect("pinned CPython version");
            parsed
                .iter()
                .all(|(_, specifier)| specifier.matches(&version))
        };
        let default = pins
            .iter()
            .copied()
            .find(|pin| pin.version == DEFAULT_VERSION)
            .ok_or_else(|| no_satisfying_pin(platform, "the default CPython", "pins", &pins))?;
        let pin = if parsed.is_empty() || satisfies(&&default) {
            default
        } else {
            pins.iter()
                .copied()
                .filter(|pin| satisfies(&pin))
                .max_by(|left, right| {
                    pinned_version(left.version)
                        .expect("pinned version")
                        .cmp(&pinned_version(right.version).expect("pinned version"))
                })
                .ok_or_else(|| {
                    no_satisfying_pin(
                        platform,
                        constraint_text.as_deref().unwrap_or("*"),
                        constraint_source.as_deref().unwrap_or("project metadata"),
                        &pins,
                    )
                })?
        };
        (pin, None)
    };

    Ok(PythonSelection {
        pin,
        constraint: inputs
            .explicit
            .as_ref()
            .map(|explicit| explicit.raw.clone())
            .or(constraint_text),
        constraint_source: inputs
            .explicit
            .as_ref()
            .map(|explicit| explicit.source.clone())
            .or(constraint_source),
        warnings,
        explicit_request,
    })
}

/// Reconstruct the selection recorded in a plan when a later metadata phase
/// (for example sandboxed setup.py `PKG-INFO`) added a constraint that is not
/// visible to the lightweight preflight collector.
pub fn select_python_for_version(
    platform: Platform,
    inputs: &PythonInputs,
    version: &str,
) -> io::Result<PythonSelection> {
    let current = select_python_with_inputs(platform, inputs)?;
    if current.pin.version == version {
        return Ok(current);
    }
    let mut forced = inputs.clone();
    let minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
    forced
        .constraints
        .push(ConstraintSource::new(format!("=={minor}.*"), "locked plan"));
    select_python_with_inputs(platform, &forced)
}

fn no_satisfying_pin(
    platform: Platform,
    constraint: &str,
    source: &str,
    pins: &[&PinnedPython],
) -> io::Error {
    let versions = pins
        .iter()
        .map(|pin| pin.version)
        .collect::<Vec<_>>()
        .join(", ");
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "no pinned CPython satisfies {constraint} from {source} on {} (pinned: {versions}; LINUX_PORT.md stage 2)",
            platform.triple()
        ),
    )
}

fn pinned_version(text: &str) -> Option<crate::pep440::Version> {
    let version = crate::pep440::Version::parse(text).ok()?;
    (version.release_len() == 3 && !version.has_epoch() && !version.is_prerelease())
        .then_some(version)
}

/// Parse the first usable line of a `.python-version` file. Unsupported
/// environments are rejected loudly instead of being mistaken for CPython.
pub fn parse_python_version_file(text: &str, source: &str) -> io::Result<ExplicitPython> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{source}: .python-version has no CPython version"),
            )
        })?;
    let lower = line.to_ascii_lowercase();
    if lower.contains("pypy")
        || lower.contains("miniconda")
        || lower == "system"
        || lower.contains("-dev")
        || lower.ends_with('t')
        || lower.contains("free-thread")
        || lower.contains("freethread")
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{source}: unsupported Python interpreter request `{line}`"),
        ));
    }
    let numeric = line
        .strip_prefix("python")
        .or_else(|| line.strip_prefix("Python"))
        .or_else(|| line.strip_prefix("cpython-"))
        .or_else(|| line.strip_prefix("cpython@"))
        .or_else(|| line.strip_prefix("CPython-"))
        .or_else(|| line.strip_prefix("CPython@"))
        .unwrap_or(line);
    let pieces: Vec<_> = numeric.split('.').collect();
    if !(2..=3).contains(&pieces.len())
        || pieces
            .iter()
            .any(|piece| piece.is_empty() || !piece.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{source}: invalid .python-version request `{line}`"),
        ));
    }
    Ok(ExplicitPython {
        raw: line.to_string(),
        source: source.to_string(),
        version: crate::pep440::Version::parse(numeric).map_err(|why| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{source}: invalid .python-version request `{line}`: {why}"),
            )
        })?,
    })
}

/// Collect all interpreter constraints that already exist in a project.
/// Dependency parsing remains the responsibility of item 10; this function
/// only reads metadata needed to choose the CPython pin.
pub fn collect_project_inputs(dir: &Path) -> io::Result<PythonInputs> {
    let mut inputs = PythonInputs::default();
    let version_path = dir.join(".python-version");
    if version_path.is_file() {
        let text = std::fs::read_to_string(&version_path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", version_path.display())))?;
        inputs.explicit = Some(parse_python_version_file(&text, ".python-version")?);
    }

    let pyproject_path = dir.join("pyproject.toml");
    if pyproject_path.is_file() {
        let text = std::fs::read_to_string(&pyproject_path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", pyproject_path.display())))?;
        let value: toml::Value = toml::from_str(&text).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", pyproject_path.display()),
            )
        })?;
        if let Some(requires) = value
            .get("project")
            .and_then(toml::Value::as_table)
            .and_then(|project| project.get("requires-python"))
        {
            let text = requires.as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: requires-python must be a string",
                        pyproject_path.display()
                    ),
                )
            })?;
            inputs
                .constraints
                .push(ConstraintSource::new(text, "pyproject.toml"));
        }
        if let Some(python) = value
            .get("tool")
            .and_then(toml::Value::as_table)
            .and_then(|tool| tool.get("poetry"))
            .and_then(toml::Value::as_table)
            .and_then(|poetry| poetry.get("dependencies"))
            .and_then(toml::Value::as_table)
            .and_then(|dependencies| dependencies.get("python"))
        {
            let text = match python {
                toml::Value::String(text) => text.clone(),
                toml::Value::Table(table) => table
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{}: [tool.poetry.dependencies].python table needs a string version",
                                pyproject_path.display()
                            ),
                        )
                    })?
                    .to_string(),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: [tool.poetry.dependencies].python must be a string or table",
                            pyproject_path.display()
                        ),
                    ))
                }
            };
            inputs
                .constraints
                .push(ConstraintSource::new(text, "pyproject.toml"));
        }
    }

    let setup_cfg = dir.join("setup.cfg");
    if setup_cfg.is_file() {
        let text = std::fs::read_to_string(&setup_cfg)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", setup_cfg.display())))?;
        if let Some(value) = parse_setup_cfg(&text).python_requires {
            inputs
                .constraints
                .push(ConstraintSource::new(value, "setup.cfg"));
        }
    }

    let setup_py = dir.join("setup.py");
    if setup_py.is_file() {
        let text = std::fs::read_to_string(&setup_py)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", setup_py.display())))?;
        // Interim item-8 scan; item 10's sandboxed egg_info dump replaces
        // this because setup.py may compute python_requires dynamically.
        if let Some(value) = extract_setup_py_python_requires(&text) {
            inputs
                .constraints
                .push(ConstraintSource::new(value, "setup.py"));
        }
    }
    Ok(inputs)
}

/// Parse the setup.cfg sections used by manifest discovery.
///
/// ConfigParser treats a physical line as a continuation only when it is
/// indented more deeply than the option key. In particular, an indented key
/// is still a key, not a continuation of the previous option.
pub fn parse_setup_cfg(text: &str) -> SetupCfgMetadata {
    let mut section = String::new();
    let mut current_key: Option<String> = None;
    let mut current_values = Vec::new();
    let mut option_indent: Option<usize> = None;
    let mut metadata = SetupCfgMetadata::default();

    let finish =
        |section: &str, key: Option<String>, values: &[String], metadata: &mut SetupCfgMetadata| {
            let Some(key) = key else {
                return;
            };
            if section.eq_ignore_ascii_case("options") {
                match key.as_str() {
                    "install_requires" => {
                        metadata.install_requires_found = true;
                        metadata.install_requires.extend(
                            values
                                .iter()
                                .map(String::as_str)
                                .filter(|value| !value.trim().is_empty())
                                .map(str::to_string),
                        );
                    }
                    "python_requires" => {
                        let value = values
                            .iter()
                            .map(String::as_str)
                            .filter(|value| !value.trim().is_empty())
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !value.is_empty() {
                            metadata.python_requires = Some(value);
                        }
                    }
                    _ => {}
                }
            } else if section.eq_ignore_ascii_case("options.extras_require") {
                for value in values.iter().filter(|value| !value.trim().is_empty()) {
                    metadata
                        .extras_require
                        .entry(key.clone())
                        .or_default()
                        .push(value.trim().to_string());
                }
            } else if section.eq_ignore_ascii_case("options.packages.find") {
                let packages = metadata.packages_find.get_or_insert_with(Default::default);
                for value in values.iter().filter(|value| !value.trim().is_empty()) {
                    let values = value
                        .split_whitespace()
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    match key.as_str() {
                        "where" => packages.where_.extend(values),
                        "include" => packages.include.extend(values),
                        "exclude" => packages.exclude.extend(values),
                        _ => {}
                    }
                }
            }
        };

    for raw in text.lines() {
        // ConfigParser ignores full-line comments before it applies the
        // continuation indentation rule. An unindented `; comment` therefore
        // cannot terminate a multi-line install_requires value.
        let raw_trimmed = raw.trim_start();
        if raw_trimmed.starts_with('#') || raw_trimmed.starts_with(';') {
            continue;
        }
        let line = strip_setup_cfg_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if option_indent.is_some_and(|active| indent > active) {
            current_values.push(trimmed.to_string());
            continue;
        }

        finish(&section, current_key.take(), &current_values, &mut metadata);
        current_values.clear();
        option_indent = None;

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            continue;
        }

        option_indent = Some(indent);
        let Some(separator) = trimmed.find(['=', ':']) else {
            continue;
        };
        current_key = Some(trimmed[..separator].trim().to_ascii_lowercase());
        let value = trimmed[separator + 1..].trim();
        if !value.is_empty() {
            current_values.push(value.to_string());
        }
    }
    finish(&section, current_key, &current_values, &mut metadata);
    metadata
}

fn strip_setup_cfg_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(index, character)| {
            *character == '#' && (*index == 0 || line.as_bytes()[*index - 1].is_ascii_whitespace())
        })
        .map(|(index, _)| &line[..index])
        .unwrap_or(line)
}

pub fn extract_setup_cfg_python_requires(text: &str) -> Option<String> {
    parse_setup_cfg(text).python_requires
}

pub fn extract_setup_py_python_requires(text: &str) -> Option<String> {
    let key = "python_requires";
    let mut search_from = 0;
    while let Some(found) = text[search_from..].find(key) {
        let start = search_from + found + key.len();
        let mut pos = start;
        while text
            .as_bytes()
            .get(pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            pos += 1;
        }
        if text.as_bytes().get(pos) != Some(&b'=') {
            search_from = start;
            continue;
        }
        pos += 1;
        while text
            .as_bytes()
            .get(pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            pos += 1;
        }
        let Some(&quote) = text.as_bytes().get(pos) else {
            return None;
        };
        if quote != b'\'' && quote != b'"' {
            search_from = pos;
            continue;
        }
        pos += 1;
        let value_start = pos;
        while let Some(&byte) = text.as_bytes().get(pos) {
            if byte == quote {
                return Some(text[value_start..pos].to_string());
            }
            pos += 1;
        }
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(text: &str) -> ConstraintSource {
        ConstraintSource::new(text, "test")
    }

    fn selected(text: &str) -> io::Result<String> {
        Ok(select_python(Platform::X86_64UnknownLinuxGnu, &[c(text)])?
            .pin
            .version
            .to_string())
    }

    #[test]
    fn specifier_selection_table_covers_pep440_and_poetry() {
        let cases = [
            ("*", "3.12.14"),
            ("3.11", "3.11.16"),
            ("3.11.*", "3.11.16"),
            ("==3.11.*", "3.11.16"),
            ("!=3.9.*", "3.12.14"),
            (">=3.10,<3.13", "3.12.14"),
            (">=3.9 <3.12", "3.11.16"),
            ("<3.12", "3.11.16"),
            ("<4", "3.12.14"),
            (">=3.13", "3.14.7"),
            ("==3.10.*", "3.10.21"),
            (">3.11", "3.12.14"),
            (">3.12", "3.12.14"),
            ("==3.12", "error"),
            (">=3.8.0", "3.12.14"),
            ("~=3.10", "3.12.14"),
            ("~=3.10.2", "3.10.21"),
            ("^3.9", "3.12.14"),
            ("^3.9.2", "3.12.14"),
            ("~3.9", "error"),
            ("~3.9.1", "error"),
            (">=3.10, !=3.11.*", "3.12.14"),
            ("<3.11 || >=3.14", "3.14.7"),
            ("==3.10.0", "error"),
            ("<=3.10.21", "3.10.21"),
            (">=3.14.0", "3.14.7"),
            ("!=3.14.*", "3.12.14"),
            (">=3.12.14", "3.12.14"),
            (">3.14", "3.14.7"),
            ("^0.4.1", "error"),
            ("~3.12", "3.12.14"),
            ("===3.11.16", "3.11.16"),
        ];
        assert!(cases.len() >= 30);
        for (specifier, expected) in cases {
            let actual = selected(specifier);
            if expected == "error" {
                assert!(
                    actual.is_err(),
                    "{specifier} unexpectedly selected {actual:?}"
                );
            } else {
                assert_eq!(actual.unwrap(), expected, "{specifier}");
            }
        }
    }

    #[test]
    fn exact_equality_is_not_a_prefix_but_bare_python_is() {
        assert!(!matches_specifier("==3.12", "3.12.14").unwrap());
        assert!(matches_specifier("3.12", "3.12.14").unwrap());
        assert!(matches_specifier("==3.12.*", "3.12.14").unwrap());
        assert!(!matches_specifier("!=3.12.*", "3.12.14").unwrap());
    }

    #[test]
    fn no_constraints_keep_the_historical_default() {
        let selection = select_python(Platform::X86_64UnknownLinuxGnu, &[]).unwrap();
        assert_eq!(selection.pin.version, DEFAULT_VERSION);
        assert!(selection.warnings.is_empty());
    }

    #[test]
    fn python_version_formats_and_unsupported_interpreters() {
        for text in [
            "3.11",
            "3.11.4",
            "python3.11",
            "cpython-3.11",
            "cpython@3.11",
        ] {
            assert_eq!(
                parse_python_version_file(text, ".python-version")
                    .unwrap()
                    .version
                    .major(),
                3
            );
        }
        for text in [
            "3.11-dev",
            "3.11t",
            "3.11-free-threaded",
            "pypy3.11",
            "miniconda3",
            "system",
        ] {
            assert_eq!(
                parse_python_version_file(text, ".python-version")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
        }
        let parsed =
            parse_python_version_file("# comment\n\n3.11\n3.10", ".python-version").unwrap();
        assert_eq!(parsed.raw, "3.11");
    }

    #[test]
    fn explicit_version_precedes_declared_constraints_and_warns() {
        let inputs = PythonInputs {
            explicit: Some(parse_python_version_file("3.10", ".python-version").unwrap()),
            constraints: vec![c(">=3.12")],
        };
        let selection =
            select_python_with_inputs(Platform::X86_64UnknownLinuxGnu, &inputs).unwrap();
        assert_eq!(selection.pin.version, "3.10.21");
        assert!(selection
            .warnings
            .iter()
            .any(|warning| warning.contains("3.10")));
        assert!(selection
            .warnings
            .iter()
            .any(|warning| warning.contains(">=3.12")));
    }

    #[test]
    fn unpinned_patch_request_uses_the_pinned_patch_and_warns() {
        let inputs = PythonInputs {
            explicit: Some(parse_python_version_file("3.11.4", ".python-version").unwrap()),
            constraints: Vec::new(),
        };
        let selection =
            select_python_with_inputs(Platform::X86_64UnknownLinuxGnu, &inputs).unwrap();
        assert_eq!(selection.pin.version, "3.11.16");
        assert!(selection
            .warnings
            .iter()
            .any(|warning| { warning.contains("3.11.4") && warning.contains("3.11.16") }));
    }

    #[test]
    fn arbitrary_equality_is_literal_and_empty_set_is_unconstrained() {
        assert!(matches_specifier("===3.12.14", "3.12.14").unwrap());
        assert!(!matches_specifier("===3.11.*", "3.11.16").unwrap());
        assert!(!matches_specifier("===3.12.014", "3.12.14").unwrap());
        assert!(!matches_specifier("===3.12", "3.12.14").unwrap());
        assert!(matches_specifier("", "3.12.14").unwrap());
        assert!(matches_specifier("   ", "3.10.21").unwrap());
        assert_eq!(
            select_python(
                Platform::X86_64UnknownLinuxGnu,
                &[ConstraintSource::new("", "pyproject.toml")]
            )
            .unwrap()
            .pin
            .version,
            "3.12.14"
        );
    }

    #[test]
    fn setup_cfg_indented_option_keys_are_options_not_continuations() {
        let cfg = "[options]\n  python_requires = <3.12\n  zip_safe = False\n";
        assert_eq!(
            extract_setup_cfg_python_requires(cfg).as_deref(),
            Some("<3.12")
        );
        let cfg = "[options]\n  install_requires =\n    six\n  python_requires =\n    >=3.9,\n    <3.12\n[options.extras_require]\n  x = y\n";
        assert_eq!(
            extract_setup_cfg_python_requires(cfg).as_deref(),
            Some(">=3.9, <3.12")
        );
        let cfg = "[options]\npython_requires = >=3.8\n[metadata]\n  python_requires = <3.0\n";
        assert_eq!(
            extract_setup_cfg_python_requires(cfg).as_deref(),
            Some(">=3.8")
        );
    }

    #[test]
    fn setup_cfg_and_setup_py_extractors_handle_requested_shapes() {
        let cfg = "[metadata]\nname=x\n[options]\npython_requires: >=3.9,\n  <3.12\n";
        assert_eq!(
            extract_setup_cfg_python_requires(cfg).as_deref(),
            Some(">=3.9, <3.12")
        );
        assert_eq!(
            extract_setup_py_python_requires("setup(python_requires = \"<3.12\")"),
            Some("<3.12".into())
        );
    }

    #[test]
    fn setup_cfg_metadata_parser_returns_dependency_sections() {
        let cfg = "[options]\n  install_requires =\n    six\n  python_requires = >=3.9,\n    <3.13\n[options.extras_require]\n  test =\n    pytest\n[options.packages.find]\n  where = src\n  include = demo*\n";
        let metadata = parse_setup_cfg(cfg);
        assert_eq!(metadata.install_requires, ["six"]);
        assert_eq!(metadata.python_requires.as_deref(), Some(">=3.9, <3.13"));
        assert_eq!(metadata.extras_require["test"], ["pytest"]);
        let packages = metadata.packages_find.unwrap();
        assert_eq!(packages.where_, ["src"]);
        assert_eq!(packages.include, ["demo*"]);
    }

    #[test]
    fn setup_cfg_full_line_comments_do_not_end_install_requires() {
        let cfg = "[options]\ninstall_requires =\n  six\n; an unindented comment\n  idna\n# another comment\n  packaging\n";
        let metadata = parse_setup_cfg(cfg);
        assert_eq!(metadata.install_requires, ["six", "idna", "packaging"]);
    }

    #[test]
    fn poetry_python_table_comes_from_interpreter_constraints() {
        let temp = std::env::temp_dir().join(format!("blanket-pyselect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::write(
            temp.join("pyproject.toml"),
            "[tool.poetry.dependencies]\npython = { version = \"^3.9\", python = \">=3.9\" }\n",
        )
        .unwrap();
        let inputs = collect_project_inputs(&temp).unwrap();
        assert_eq!(inputs.constraints.len(), 1);
        assert_eq!(inputs.constraints[0].text, "^3.9");
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn invalid_specifier_names_source_and_text() {
        let error = select_python(
            Platform::X86_64UnknownLinuxGnu,
            &[ConstraintSource::new(">=3.9, nonsense", "setup.py")],
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("setup.py"));
        assert!(error.to_string().contains(">=3.9, nonsense"));
    }
}

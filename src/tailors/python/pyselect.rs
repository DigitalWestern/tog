//! CPython constraint parsing and selection.
//!
//! Version parsing and matching lives in `pep440`; this module only collects
//! interpreter inputs and chooses one of tog's pinned CPython builds. It
//! is pure once project files have been collected: selection never consults
//! the host Python or a package index.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::provider::cpython::default_version;
use crate::kernel::toolchain::input::{python_version_line, PythonVersionRefusal};
use crate::tailors::python::{pythons, PinnedPython};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

#[cfg(test)]
pub(crate) use crate::kernel::provider::cpython::DEFAULT_VERSION;

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

pub use crate::kernel::setuptools::{extract_setup_py_python_requires, parse_setup_cfg};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitPython {
    pub raw: String,
    pub source: String,
    version: crate::kernel::pep440::Version,
}

#[derive(Clone, Debug)]
pub struct PythonSelection {
    /// The pinned build this project runs.
    pub pin: &'static PinnedPython,
    pub constraint: Option<String>,
    pub constraint_source: Option<String>,
    /// Advisories this selection carries: (message, the command that
    /// resolves it), printed as one warning and its fix line each.
    pub warnings: Vec<(String, String)>,
    pub explicit_request: Option<String>,
}

impl PythonSelection {
    pub fn is_default(&self) -> bool {
        default_version().is_ok_and(|default| self.pin.version == default)
    }

    /// Human-readable diagnostics are emitted by the caller so preflight and
    /// planning can share one selection without printing twice.
    pub fn selection_message(&self) -> String {
        if let Some(raw) = &self.explicit_request {
            format!(
                "python {} selected (.python-version \"{}\" from .python-version)",
                self.pin.version, raw
            )
        } else {
            format!(
                "python {} selected (requires-python \"{}\" from {})",
                self.pin.version,
                self.constraint.as_deref().unwrap_or("*"),
                self.constraint_source
                    .as_deref()
                    .unwrap_or("project metadata")
            )
        }
    }

    pub fn emit_warnings(&self) {
        for (message, fix) in &self.warnings {
            crate::kernel::ui::warning(message, fix);
        }
        if !self.is_default() {
            crate::kernel::ui::note(&self.selection_message());
        }
    }
}

/// Pure PEP 440/Poetry matching helper for a pinned X.Y.Z candidate.
pub fn matches_specifier(specifier: &str, version: &str) -> io::Result<bool> {
    crate::kernel::pep440::matches_specifier(specifier, version)
}

#[cfg(test)]
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

/// The joined constraint text and its sources, for the closure record and
/// the selection message. `None` when the project declares none.
fn declared(inputs: &PythonInputs) -> (Option<String>, Option<String>) {
    if inputs.constraints.is_empty() {
        return (None, None);
    }
    let join = |pick: fn(&ConstraintSource) -> &str, sep: &str| {
        Some(
            inputs
                .constraints
                .iter()
                .map(pick)
                .collect::<Vec<_>>()
                .join(sep),
        )
    };
    (
        join(|constraint| constraint.text.as_str(), " && "),
        join(|constraint| constraint.source.as_str(), ", "),
    )
}

/// The selection for the interpreter the project's toolchain selection
/// names, checked against every constraint the project declares.
///
/// This chooses nothing: `version` comes from `tog-toolchain.toml` (or the
/// selection a first sync is about to publish), which already honored
/// `.python-version` and `requires-python`. What is left here are the
/// sources the lock deliberately does not read — a `setup.cfg`
/// `python_requires`, a constraint only `setup.py` metadata states — so a
/// disagreement is a warning naming the next command, never a reselection.
/// A version this tog has no build for is refused rather than approximated.
pub fn locked(
    platform: Platform,
    version: &str,
    inputs: &PythonInputs,
) -> io::Result<PythonSelection> {
    let pin = crate::tailors::python::lookup(platform, version).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "tog-toolchain.toml selects cpython {version}, which this tog has no build for on {}; \
                 upgrade tog or run `tog update --toolchain python`",
                platform.triple()
            ),
        )
    })?;
    let selected = pinned_version(pin.version).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pinned CPython {} is not a release version", pin.version),
        )
    })?;
    let (constraint_text, constraint_source) = declared(inputs);
    let mut warnings = Vec::new();
    let violated: Vec<String> = inputs
        .constraints
        .iter()
        .map(|constraint| {
            crate::kernel::pep440::SpecifierSet::parse(&constraint.text, &constraint.source)
                .map(|set| (constraint, set))
        })
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|(_, specifier)| !specifier.matches(&selected))
        .map(|(constraint, _)| format!("\"{}\" from {}", constraint.text, constraint.source))
        .collect();
    if !violated.is_empty() {
        warnings.push((
            format!(
                "cpython {} from tog-toolchain.toml does not satisfy {}; honoring the lock \
                 (change the declaration first)",
                pin.version,
                violated.join(", ")
            ),
            "tog update --toolchain python".to_string(),
        ));
    }
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
        explicit_request: inputs
            .explicit
            .as_ref()
            .map(|explicit| explicit.raw.clone()),
    })
}

/// The project's interpreter request, read and parsed without choosing a
/// pin: `.python-version` and every stated constraint must be well-formed
/// on any host. Selection against this host's pins is
/// `select_python_with_inputs`.
pub fn check_project_inputs(project: &ProjectRoot) -> io::Result<()> {
    let inputs = collect_project_inputs(project)?;
    for constraint in &inputs.constraints {
        crate::kernel::pep440::SpecifierSet::parse(&constraint.text, &constraint.source)?;
    }
    Ok(())
}

pub fn select_python_with_inputs(
    platform: Platform,
    inputs: &PythonInputs,
) -> io::Result<PythonSelection> {
    let default_version = default_version()?;
    let pins: Vec<_> = pythons()?
        .iter()
        .filter(|pin| pin.platform == platform)
        .collect();
    let parsed = inputs
        .constraints
        .iter()
        .map(|constraint| {
            crate::kernel::pep440::SpecifierSet::parse(&constraint.text, &constraint.source)
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
        let matching = select_explicit_pin(&pins, &explicit.version, default_version);
        let Some(pin) = matching else {
            if explicit.version.release_len() == 3 {
                return Err(no_exact_satisfying_pin(platform, explicit, &pins));
            } else {
                return Err(no_satisfying_pin(
                    platform,
                    &format!(".python-version \"{}\"", explicit.raw),
                    &explicit.source,
                    &pins,
                ));
            }
        };
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
            warnings.push((
                format!(
                    ".python-version \"{}\" violates declared Python constraint {}; honoring \
                     .python-version (change one of them first)",
                    explicit.raw, declared
                ),
                "tog update --toolchain python".to_string(),
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
            .find(|pin| pin.version == default_version)
            .ok_or_else(|| no_satisfying_pin(platform, "the default CPython", "pins", &pins))?;
        let pin = if parsed.is_empty() || satisfies(&default) {
            default
        } else {
            pins.iter()
                .copied()
                .filter(|pin| satisfies(pin))
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

/// Choose an explicit request from an already platform-filtered pin slice.
/// Three-part requests match one pinned build; two-part requests choose the
/// shipped default when it is on that minor (as the catalog's selection
/// does, so newer patches never move it) and the numerically newest patch
/// otherwise. The caller validates the request's textual spelling before
/// constructing its `Version`.
fn select_explicit_pin<'a>(
    pins: &[&'a PinnedPython],
    requested: &crate::kernel::pep440::Version,
    default_version: &str,
) -> Option<&'a PinnedPython> {
    match requested.release_len() {
        3 => pins.iter().copied().find(|pin| {
            pinned_version(pin.version)
                .expect("pinned CPython version")
                .cmp(requested)
                .is_eq()
        }),
        2 => {
            let on_minor = |pin: &&&PinnedPython| {
                let version = pinned_version(pin.version).expect("pinned CPython version");
                version.major() == requested.major() && version.minor() == requested.minor()
            };
            if let Some(default) = pins
                .iter()
                .filter(on_minor)
                .find(|pin| pin.version == default_version)
            {
                return Some(default);
            }
            pins.iter()
                .copied()
                .filter(|pin| on_minor(&pin))
                .max_by(|left, right| {
                    pinned_version(left.version)
                        .expect("pinned CPython version")
                        .cmp(&pinned_version(right.version).expect("pinned CPython version"))
                })
        }
        _ => None,
    }
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

/// The pinned CPython builds, one entry per line, oldest first: `3.12.0 to
/// 3.12.14` for a line with several patches. The catalog holds every
/// verifiable patch of each maintained line, so the full list would bury
/// the answer.
fn pinned_lines(pins: &[&PinnedPython]) -> String {
    let mut lines: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for pin in pins {
        if let Some(version) = pinned_version(pin.version) {
            lines
                .entry((version.major(), version.minor()))
                .or_default()
                .push((version, pin.version));
        }
    }
    lines
        .into_values()
        .map(|mut patches| {
            patches.sort();
            let first = patches.first().map(|(_, text)| *text).unwrap_or_default();
            let last = patches.last().map(|(_, text)| *text).unwrap_or_default();
            if first == last {
                first.to_string()
            } else {
                format!("{first} to {last}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn no_satisfying_pin(
    platform: Platform,
    constraint: &str,
    source: &str,
    pins: &[&PinnedPython],
) -> io::Error {
    let versions = pinned_lines(pins);
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "no pinned CPython satisfies {constraint} from {source} on {} (pinned: {versions})",
            platform.triple()
        ),
    )
}

fn no_exact_satisfying_pin(
    platform: Platform,
    explicit: &ExplicitPython,
    pins: &[&PinnedPython],
) -> io::Error {
    let versions = pinned_lines(pins);
    let minor = format!("{}.{}", explicit.version.major(), explicit.version.minor());
    let mut same_line: Vec<_> = pins
        .iter()
        .filter_map(|pin| pinned_version(pin.version).map(|pinned| (pinned, pin.version)))
        .filter(|(pinned, _)| {
            pinned.major() == explicit.version.major() && pinned.minor() == explicit.version.minor()
        })
        .collect();
    same_line.sort();
    let next_step = if same_line.is_empty() {
        format!("request one of: {versions}")
    } else {
        let patches = same_line
            .iter()
            .map(|(_, text)| *text)
            .collect::<Vec<_>>()
            .join(", ");
        format!("pin {minor} to accept the pinned patch, or request one of: {patches}")
    };
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "{}: exact CPython request `{}` is not pinned for {} (pinned versions available: {versions}); next step: {next_step}",
            explicit.source,
            explicit.raw,
            platform.triple(),
        ),
    )
}

fn pinned_version(text: &str) -> Option<crate::kernel::pep440::Version> {
    let version = crate::kernel::pep440::Version::parse(text).ok()?;
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
    let version = python_version_line(line).map_err(|refusal| match refusal {
        PythonVersionRefusal::Unsupported => io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{source}: unsupported Python interpreter request `{line}`"),
        ),
        PythonVersionRefusal::Invalid(why) => io::Error::new(
            io::ErrorKind::InvalidData,
            match why {
                Some(why) => format!("{source}: invalid .python-version request `{line}`: {why}"),
                None => format!("{source}: invalid .python-version request `{line}`"),
            },
        ),
    })?;
    Ok(ExplicitPython {
        raw: line.to_string(),
        source: source.to_string(),
        version,
    })
}

/// Collect all interpreter constraints that already exist in a project.
/// Dependency parsing happens in the manifest modules; this function only
/// reads metadata needed to choose the CPython pin. The project is read
/// through the held descriptor.
pub fn collect_project_inputs(project: &ProjectRoot) -> io::Result<PythonInputs> {
    let dir = project.path();
    let mut inputs = PythonInputs::default();
    if let Some(text) = read_project_input(project, ".python-version")? {
        inputs.explicit = Some(parse_python_version_file(&text, ".python-version")?);
    }

    let pyproject_path = dir.join("pyproject.toml");
    if let Some(text) = read_project_input(project, "pyproject.toml")? {
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

    if let Some(text) = read_project_input(project, "setup.cfg")? {
        if let Some(value) = parse_setup_cfg(&text).python_requires {
            inputs
                .constraints
                .push(ConstraintSource::new(value, "setup.cfg"));
        }
    }

    if let Some(text) = read_project_input(project, "setup.py")? {
        // A static text scan. setup.py may compute python_requires
        // dynamically, which this cannot see; a sandboxed egg_info dump
        // would.
        if let Some(value) = extract_setup_py_python_requires(&text) {
            inputs
                .constraints
                .push(ConstraintSource::new(value, "setup.py"));
        }
    }
    Ok(inputs)
}

/// The text of a project input when it is a regular file (`None` when it is
/// absent or is not a file, as `is_file` skipped it), read through the held
/// descriptor. Errors name the file as the pathname read did.
fn read_project_input(project: &ProjectRoot, name: &str) -> io::Result<Option<String>> {
    if !project.is_input_file(Path::new(name)) {
        return Ok(None);
    }
    let path = project.path().join(name);
    let bytes = project
        .read_input(Path::new(name))
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    String::from_utf8(bytes).map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: stream did not contain valid UTF-8", path.display()),
        )
    })
}

#[cfg(test)]
pub fn extract_setup_cfg_python_requires(text: &str) -> Option<String> {
    parse_setup_cfg(text).python_requires
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

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
            ("==3.12", "3.12.0"),
            (">=3.8.0", "3.12.14"),
            ("~=3.10", "3.12.14"),
            ("~=3.10.2", "3.10.21"),
            ("^3.9", "3.12.14"),
            ("^3.9.2", "3.12.14"),
            ("~3.9", "error: no pinned CPython satisfies"),
            ("~3.9.1", "error: no pinned CPython satisfies"),
            (">=3.10, !=3.11.*", "3.12.14"),
            ("<3.11 || >=3.14", "3.14.7"),
            ("==3.10.0", "error: no pinned CPython satisfies"),
            ("<=3.10.21", "3.10.21"),
            (">=3.14.0", "3.14.7"),
            ("!=3.14.*", "3.12.14"),
            (">=3.12.14", "3.12.14"),
            (">3.14", "3.14.7"),
            ("^0.4.1", "error: no pinned CPython satisfies"),
            ("~3.12", "3.12.14"),
            ("===3.11.16", "3.11.16"),
        ];
        assert!(cases.len() >= 30);
        for (specifier, expected) in cases {
            let actual = selected(specifier);
            if let Some(needle) = expected.strip_prefix("error: ") {
                let error = actual
                    .expect_err(&format!("{specifier} selected a version"))
                    .to_string();
                assert!(
                    error.contains(&format!("{needle} {specifier} from")),
                    "{specifier}: {error}"
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
            "3.11.4-dev",
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
    fn python_version_requires_canonical_release_components() {
        for text in ["03.11", "3.11.016"] {
            let error = parse_python_version_file(text, ".python-version").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{text}");
        }
    }

    /// The toolchain lock and interpreter selection read `.python-version`
    /// through one parser, so a line one accepts the other never refuses
    /// (#479): `tog update --toolchain` must not lock what the sync refuses.
    #[test]
    fn python_version_lock_and_selection_agree() {
        use crate::kernel::toolchain::input::{read_python_version, InputRow};
        for line in [
            "3.12",
            "3.12.4",
            "python3.12",
            "Python3.12",
            "CPYTHON-3.12",
            "cpython@3.12.4",
            "3.12.*",
            ">=3.11",
            ">3.11",
            "<=3.13",
            "^3.9",
            "~=3.11.2",
            "3.11 || 3.12",
            "3.12 3.13",
            "3.12rc1",
            "3.12.4+abc",
            "03.12",
            "3",
            "*",
            "system",
            "pypy3.10",
            "graalpy-24",
            "3.13t",
            "3.13-dev",
            "python",
        ] {
            let selected = parse_python_version_file(line, ".python-version");
            let row = InputRow {
                path: ".python-version".into(),
                field: "version".to_string(),
                value: read_python_version(line.as_bytes()),
                absent: false,
                sha256: Some("a".repeat(64)),
            };
            let locked = crate::kernel::toolchain::resolve::request_for("python", &[row]);
            assert_eq!(selected.is_ok(), locked.is_ok(), "{line}");
        }
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
            .any(|(message, _)| message.contains("3.10")));
        assert!(selection
            .warnings
            .iter()
            .any(|(message, _)| message.contains(">=3.12")));
        assert!(selection
            .warnings
            .iter()
            .all(|(_, fix)| fix == "tog update --toolchain python"));
    }

    #[test]
    fn unpinned_patch_request_fails_closed() {
        // 3.11.2 is a real CPython release no python-build-standalone
        // release publishes a verifiable build of.
        for request in ["3.11.2", "python3.11.2", "cpython@3.11.2"] {
            let inputs = PythonInputs {
                explicit: Some(parse_python_version_file(request, ".python-version").unwrap()),
                constraints: Vec::new(),
            };
            let error =
                select_python_with_inputs(Platform::X86_64UnknownLinuxGnu, &inputs).unwrap_err();
            let message = error.to_string();
            assert!(message.contains(request), "{message}");
            assert!(message.contains(".python-version"), "{message}");
            for pinned in ["3.12.14", "3.13.15", "3.10.21", "3.11.16", "3.14.7"] {
                assert!(message.contains(pinned), "{message}");
            }
            assert!(
                message.contains("pin 3.11 to accept the pinned patch"),
                "{message}"
            );
            assert!(message.contains("request one of:"), "{message}");
        }
    }

    #[test]
    fn exact_pinned_request_selects_without_warning_in_supported_spellings() {
        for request in [
            "3.11.16",
            "python3.11.16",
            "Python3.11.16",
            "cpython-3.11.16",
            "cpython@3.11.16",
            "CPython-3.11.16",
            "CPython@3.11.16",
        ] {
            let inputs = PythonInputs {
                explicit: Some(parse_python_version_file(request, ".python-version").unwrap()),
                constraints: Vec::new(),
            };
            let selection =
                select_python_with_inputs(Platform::X86_64UnknownLinuxGnu, &inputs).unwrap();
            assert_eq!(selection.pin.version, "3.11.16", "{request}");
            assert!(selection.warnings.is_empty(), "{request}");
        }
    }

    #[test]
    fn explicit_request_pin_choice_is_newest_for_minor_and_exact_for_patch() {
        let newer = PinnedPython {
            platform: Platform::X86_64UnknownLinuxGnu,
            version: "3.11.16",
            sha256: "16",
        };
        let older = PinnedPython {
            platform: Platform::X86_64UnknownLinuxGnu,
            version: "3.11.9",
            sha256: "9",
        };
        let minor = crate::kernel::pep440::Version::parse("3.11").unwrap();
        for pins in [[&older, &newer], [&newer, &older]] {
            assert_eq!(
                select_explicit_pin(&pins, &minor, "3.12.14")
                    .unwrap()
                    .version,
                "3.11.16"
            );
            // The default wins its own minor over a newer patch.
            assert_eq!(
                select_explicit_pin(&pins, &minor, "3.11.9")
                    .unwrap()
                    .version,
                "3.11.9"
            );
        }

        let pins = [&older, &newer];
        let exact = crate::kernel::pep440::Version::parse("3.11.9").unwrap();
        assert_eq!(
            select_explicit_pin(&pins, &exact, "3.11.16")
                .unwrap()
                .version,
            "3.11.9"
        );

        let unavailable = crate::kernel::pep440::Version::parse("3.11.4").unwrap();
        assert!(select_explicit_pin(&pins, &unavailable, "3.11.16").is_none());
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
        let scratch = TempDir::named("pyselect");
        let temp = scratch.0.clone();
        std::fs::write(
            temp.join("pyproject.toml"),
            "[tool.poetry.dependencies]\npython = { version = \"^3.9\", python = \">=3.9\" }\n",
        )
        .unwrap();
        let inputs = collect_project_inputs(&ProjectRoot::open(&temp).unwrap()).unwrap();
        assert_eq!(inputs.constraints.len(), 1);
        assert_eq!(inputs.constraints[0].text, "^3.9");
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

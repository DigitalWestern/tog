//! Poetry projects (python tailor): `pyproject.toml` dependency tables,
//! `poetry.lock` resolution, and the content-hash check.

use super::*;

pub(super) fn poetry_manifest(
    platform: Platform,
    dir: &Path,
    value: &toml::Value,
    _source: &str,
    cfg: &TogPythonConfig,
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
            unreadable(
                &dir.join("pyproject.toml"),
                "Poetry dependencies must be a table",
            )
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
                return Err(unreadable(
                    &dir.join("pyproject.toml"),
                    "Poetry source must be a table",
                ));
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
                crate::kernel::policy::record(
                    crate::kernel::policy::UNATTESTED_INDEX,
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
        crate::kernel::policy::record(
            crate::kernel::policy::SKIPPED_OPTIONAL,
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

pub(super) fn poetry_requirement(
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
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Poetry dependency value is not usable",
            ))
        }
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
                crate::kernel::policy::record(
                    crate::kernel::policy::SKIPPED_OPTIONAL,
                    name,
                    "Poetry optional dependency was not selected by a requested extra",
                )?;
                return Ok(None);
            }
        }
        for key in ["git", "path", "url"] {
            if table.contains_key(key) {
                crate::kernel::policy::record(
                    crate::kernel::policy::REQUIREMENT_SKIPPED,
                    name,
                    &format!("Poetry {key} dependency is not a locked registry package"),
                )?;
                return Ok(None);
            }
        }
        if table.contains_key("source") {
            crate::kernel::policy::record(
                crate::kernel::policy::UNATTESTED_INDEX,
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
    Ok(Some(format!(
        "{}{}",
        name,
        poetry_constraint_to_pep440(&version)?
    )))
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
                .map(|parts| {
                    parts
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join(",")
                })
        })
        .collect::<io::Result<_>>()?;
    Ok(alternatives
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" || "))
}

pub(super) fn poetry_clause_to_pep440(clause: &str) -> io::Result<String> {
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
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Poetry version `{rest}`"),
                )
            })?;
        if values.is_empty() || values.len() > 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Poetry version `{rest}`"),
            ));
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
        let upper = upper
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".");
        let lower = format!(">={rest}");
        return Ok(format!("{lower},<{upper}"));
    }
    Ok(match operator {
        "=" | "==" => format!("=={rest}"),
        other => format!("{other}{rest}"),
    })
}

pub(super) fn poetry_python_marker(version: &str) -> io::Result<Option<String>> {
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
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("unsupported Poetry python constraint `{version}`"),
                            )
                        })?;
                    let variable = if crate::tailors::python::pep440::Version::parse(value)
                        .ok()
                        .is_some_and(|value| value.release_len() >= 3)
                    {
                        "python_full_version"
                    } else {
                        "python_version"
                    };
                    Ok(format!("{variable} {op} '{value}'"))
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

pub(super) fn poetry_lock_requirements(
    platform: Platform,
    pyproject: &toml::Value,
    lock: &toml::Value,
    cfg: &TogPythonConfig,
    python_version: &str,
) -> io::Result<Vec<String>> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "poetry.lock has no [[package]] entries",
            )
        })?;
    let deps = poetry_section(pyproject, "dependencies")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Poetry dependencies missing"))?;
    let extras = poetry_section(pyproject, "extras")
        .cloned()
        .unwrap_or_default();
    let requested = &cfg.extras;
    let roots = poetry_root_dependencies(deps, &extras, requested, python_version, platform)?;
    let by_name = index_poetry_packages(packages)?;
    // A package variant can change after a later root contributes a
    // constraint. Rebuild the graph from the roots until the selected
    // variants stop changing; this retracts descendants of discarded
    // variants instead of leaving them in `reachable` forever.
    let mut previous_selected = BTreeMap::<String, toml::Value>::new();
    let mut final_reachable = BTreeSet::new();
    let max_iterations = packages.len().saturating_mul(4).max(8);
    let mut stabilized = false;
    for _ in 0..max_iterations {
        let (selected, reachable) = resolve_poetry_round(
            &roots,
            &by_name,
            &previous_selected,
            python_version,
            platform,
        )?;
        final_reachable = reachable;
        if selected == previous_selected {
            stabilized = true;
            previous_selected = selected;
            break;
        }
        previous_selected = selected;
    }
    if !stabilized {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "poetry.lock package graph did not stabilize",
        ));
    }
    let mut output = Vec::new();
    for name in final_reachable {
        let Some(package) = previous_selected.get(&name).and_then(toml::Value::as_table) else {
            continue;
        };
        if !poetry_package_is_main(package) {
            continue;
        }
        if record_poetry_source_exceptions(&name, package)? {
            continue;
        }
        output.push(poetry_requirement_line(lock, package, &name)?);
    }
    output.sort();
    Ok(output)
}

/// The `[tool.poetry.<key>]` table, if the pyproject declares one.
fn poetry_section<'a>(
    pyproject: &'a toml::Value,
    key: &str,
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    pyproject
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get(key))
        .and_then(toml::Value::as_table)
}

/// Group the lock's `[[package]]` entries by normalized name; a name may
/// have several variants, each conditioned on the Python version.
fn index_poetry_packages(
    packages: &[toml::Value],
) -> io::Result<BTreeMap<String, Vec<&toml::Value>>> {
    let mut by_name: BTreeMap<String, Vec<&toml::Value>> = BTreeMap::new();
    for package in packages {
        let table = package.as_table().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "poetry.lock package is not a table",
            )
        })?;
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "poetry.lock package has no name",
                )
            })?;
        by_name
            .entry(normalize_name(name))
            .or_default()
            .push(package);
    }
    Ok(by_name)
}

/// One pass of the fixpoint: walk the graph from the roots, preferring the
/// variant the previous pass chose, and return what this pass selected
/// along with the set of names it reached.
#[allow(clippy::type_complexity)]
fn resolve_poetry_round(
    roots: &[PoetryDependency],
    by_name: &BTreeMap<String, Vec<&toml::Value>>,
    previous_selected: &BTreeMap<String, toml::Value>,
    python_version: &str,
    platform: Platform,
) -> io::Result<(BTreeMap<String, toml::Value>, BTreeSet<String>)> {
    let mut incoming: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut requested_extras: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::new();
    for root in roots {
        add_poetry_edge(
            &mut incoming,
            &mut requested_extras,
            &mut reachable,
            &mut queue,
            root.clone(),
        );
    }
    let mut selected = BTreeMap::<String, toml::Value>::new();
    while let Some(name) = queue.pop_front() {
        let constraints = incoming.get(&name).map(Vec::as_slice).unwrap_or(&[]);
        let Some(package) = select_poetry_package(
            by_name.get(&name),
            python_version,
            platform,
            Some(constraints),
            previous_selected.get(&name),
        )?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "poetry.lock has no package variant for {name} satisfying {} on Python {python_version}",
                    format_poetry_constraints(constraints),
                ),
            ));
        };
        selected.insert(name.clone(), package.clone());
        let package = package.as_table().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "poetry.lock package is not a table",
            )
        })?;
        let mut dependencies = package
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .map(|dependencies| {
                poetry_active_dependencies(
                    dependencies,
                    python_version,
                    platform,
                    requested_extras.get(&name),
                )
            })
            .transpose()?
            .unwrap_or_default();
        dependencies.extend(poetry_lock_extra_dependencies(
            package,
            requested_extras.get(&name),
            python_version,
            platform,
        )?);
        for dependency in dependencies {
            add_poetry_edge(
                &mut incoming,
                &mut requested_extras,
                &mut reachable,
                &mut queue,
                dependency,
            );
        }
    }
    Ok((selected, reachable))
}

/// Whether a locked package belongs to the main group. Poetry 2.x lists
/// `groups`; 1.x carried a single `category` instead.
fn poetry_package_is_main(package: &toml::map::Map<String, toml::Value>) -> bool {
    if package
        .get("category")
        .and_then(toml::Value::as_str)
        .is_some_and(|v| v != "main")
    {
        return false;
    }
    !package
        .get("groups")
        .and_then(toml::Value::as_array)
        .is_some_and(|groups| {
            !groups
                .iter()
                .filter_map(toml::Value::as_str)
                .any(|group| group == "main")
        })
}

/// Record what this package's source costs us in attestation. Returns true
/// when the source has no locked registry artifact and must be skipped.
fn record_poetry_source_exceptions(
    name: &str,
    package: &toml::map::Map<String, toml::Value>,
) -> io::Result<bool> {
    let Some(source) = package.get("source").and_then(toml::Value::as_table) else {
        return Ok(false);
    };
    let source_type = source
        .get("type")
        .and_then(toml::Value::as_str)
        .unwrap_or_default();
    if matches!(source_type, "directory" | "git" | "url") {
        crate::kernel::policy::record(
            crate::kernel::policy::REQUIREMENT_SKIPPED,
            name,
            &format!("Poetry lock package uses unsupported {source_type} source"),
        )?;
        return Ok(true);
    }
    let url = source
        .get("url")
        .and_then(toml::Value::as_str)
        .unwrap_or_default();
    if !is_public_pypi_url(url)
        && source.get("reference").and_then(toml::Value::as_str) != Some("pypi")
    {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_INDEX,
            name,
            "Poetry lock package has a non-default source",
        )?;
    }
    Ok(false)
}

/// The pinned requirement line for one locked package, hashes and all.
fn poetry_requirement_line(
    lock: &toml::Value,
    package: &toml::map::Map<String, toml::Value>,
    name: &str,
) -> io::Result<String> {
    let hashes = poetry_package_hashes(lock, package, name)?;
    if hashes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("poetry.lock package {name} has no sha256 file hash"),
        ));
    }
    let version = package
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("poetry.lock package {name} has no version"),
            )
        })?;
    Ok(format!(
        "{name}=={version} {}",
        hashes
            .iter()
            .map(|hash| format!("--hash=sha256:{hash}"))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}

pub(super) fn select_poetry_package<'a>(
    variants: Option<&Vec<&'a toml::Value>>,
    python_version: &str,
    platform: Platform,
    constraints: Option<&[String]>,
    preferred: Option<&toml::Value>,
) -> io::Result<Option<&'a toml::Value>> {
    let Some(variants) = variants else {
        return Ok(None);
    };
    let candidate_versions = variants
        .iter()
        .filter_map(|package| package.as_table()?.get("version")?.as_str())
        .collect::<Vec<_>>();
    if let Some(preferred) = preferred {
        for package in variants {
            if *package == preferred
                && poetry_package_matches(
                    package.as_table().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "poetry.lock package is not a table",
                        )
                    })?,
                    python_version,
                    platform,
                    constraints.unwrap_or(&[]),
                    &candidate_versions,
                )?
            {
                return Ok(Some(*package));
            }
        }
    }
    for package in variants {
        let Some(table) = package.as_table() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "poetry.lock package is not a table",
            ));
        };
        if poetry_package_matches(
            table,
            python_version,
            platform,
            constraints.unwrap_or(&[]),
            &candidate_versions,
        )? {
            // Poetry's forked package entries are expected to be disjoint.
            // Selecting the first matching entry preserves the lock's order
            // and, importantly, never lets a later incompatible fork shadow
            // an earlier compatible one.
            return Ok(Some(*package));
        }
    }
    Ok(None)
}

pub(super) fn poetry_package_matches(
    package: &toml::map::Map<String, toml::Value>,
    python_version: &str,
    platform: Platform,
    constraints: &[String],
    candidate_versions: &[&str],
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
    if !constraints.is_empty() {
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "poetry.lock package has no version",
                )
            })?;
        let specifiers = constraints
            .iter()
            .map(|constraint| poetry_constraint_to_pep440(constraint))
            .collect::<io::Result<Vec<_>>>()?;
        let specifiers = specifiers
            .iter()
            .filter(|specifier| !specifier.is_empty())
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !specifiers.is_empty()
            && !crate::tailors::python::pep440::matches_specifiers_with_candidates(
                &specifiers,
                version,
                candidate_versions,
            )?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PoetryDependency {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) extras: BTreeSet<String>,
    pub(super) marker: Option<String>,
}

pub(super) fn poetry_lock_extra_dependencies(
    package: &toml::map::Map<String, toml::Value>,
    requested_extras: Option<&BTreeSet<String>>,
    python_version: &str,
    platform: Platform,
) -> io::Result<Vec<PoetryDependency>> {
    let Some(requested_extras) = requested_extras else {
        return Ok(Vec::new());
    };
    let Some(extras) = package.get("extras").and_then(toml::Value::as_table) else {
        return Ok(Vec::new());
    };
    let mut active = Vec::new();
    for (extra, values) in extras {
        if !requested_extras.contains(&extra.to_ascii_lowercase()) {
            continue;
        }
        let values = values.as_array().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Poetry lock extra `{extra}` must contain an array"),
            )
        })?;
        for value in values {
            let value = value.as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Poetry lock extra `{extra}` must contain strings"),
                )
            })?;
            let dependency = parse_poetry_lock_extra_dependency(value)?;
            if dependency.marker.as_deref().map_or(Ok(true), |marker| {
                marker_matches(marker, python_version, platform)
            })? {
                active.push(dependency);
            }
        }
    }
    Ok(active)
}

pub(super) fn parse_poetry_lock_extra_dependency(value: &str) -> io::Result<PoetryDependency> {
    let value = value.trim();
    let (requirement, marker) = value
        .split_once(';')
        .map_or((value, None), |(requirement, marker)| {
            (requirement.trim(), Some(marker.trim().to_string()))
        });
    if requirement.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed Poetry lock extra dependency `{value}`"),
        ));
    }
    let (name, version) = if let Some(open) = requirement.find(" (") {
        if !requirement.ends_with(')') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed Poetry lock extra dependency `{value}`"),
            ));
        }
        (
            &requirement[..open],
            &requirement[open + 2..requirement.len() - 1],
        )
    } else {
        (requirement, "*")
    };
    if name.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed Poetry lock extra dependency `{value}`"),
        ));
    }
    let (name, extras) = parse_dependency_extras(name)?;
    Ok(PoetryDependency {
        name: dependency_name(name),
        version: version.trim().to_string(),
        extras,
        marker,
    })
}

pub(super) fn parse_dependency_extras(value: &str) -> io::Result<(&str, BTreeSet<String>)> {
    let value = value.trim();
    let Some(open) = value.find('[') else {
        return Ok((value, BTreeSet::new()));
    };
    let Some(relative_close) = value[open + 1..].find(']') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed dependency extras `{value}`"),
        ));
    };
    let close = open + 1 + relative_close;
    if !value[close + 1..].trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed dependency extras `{value}`"),
        ));
    }
    let extras = value[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|extra| !extra.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    Ok((value[..open].trim(), extras))
}

pub(super) fn poetry_root_dependencies(
    dependencies: &toml::map::Map<String, toml::Value>,
    extras: &toml::map::Map<String, toml::Value>,
    requested: &BTreeSet<String>,
    python_version: &str,
    platform: Platform,
) -> io::Result<Vec<PoetryDependency>> {
    let mut output = Vec::new();
    for (name, value) in dependencies {
        if name.eq_ignore_ascii_case("python") {
            continue;
        }
        let optional = value
            .as_table()
            .and_then(|table| table.get("optional"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let selected_by_extra = extras.iter().any(|(extra, values)| {
            requested.contains(&extra.to_ascii_lowercase())
                && values
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(toml::Value::as_str)
                    .any(|value| dependency_name(value) == normalize_name(name))
        });
        if optional && !selected_by_extra {
            continue;
        }
        let values = match value {
            toml::Value::Array(values) => values.iter().collect::<Vec<_>>(),
            value => vec![value],
        };
        for value in values {
            if poetry_dependency_variant_matches(value, python_version, platform, None)? {
                output.push(poetry_dependency(name, value)?);
            }
        }
    }
    Ok(output)
}

pub(super) fn poetry_dependency(name: &str, value: &toml::Value) -> io::Result<PoetryDependency> {
    let (version, extras) = match value {
        toml::Value::String(version) => (version.clone(), BTreeSet::new()),
        toml::Value::Table(table) => {
            let extras = table
                .get("extras")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect();
            (
                table
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("*")
                    .to_string(),
                extras,
            )
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Poetry dependency is not a string or table",
            ))
        }
    };
    Ok(PoetryDependency {
        name: dependency_name(name),
        version,
        extras,
        marker: None,
    })
}

pub(super) fn add_poetry_edge(
    incoming: &mut BTreeMap<String, Vec<String>>,
    requested_extras: &mut BTreeMap<String, BTreeSet<String>>,
    reachable: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    dependency: PoetryDependency,
) {
    let name = dependency.name;
    let version = dependency.version.trim().to_string();
    let changed = if !version.is_empty() && version != "*" {
        let constraints = incoming.entry(name.clone()).or_default();
        if constraints.contains(&version) {
            false
        } else {
            constraints.push(version);
            true
        }
    } else {
        incoming.entry(name.clone()).or_default();
        false
    };
    let extras_changed = {
        let extras = requested_extras.entry(name.clone()).or_default();
        let before = extras.len();
        extras.extend(dependency.extras);
        extras.len() != before
    };
    if reachable.insert(name.clone()) || changed || extras_changed {
        queue.push_back(name.clone());
    }
}

pub(super) fn format_poetry_constraints(constraints: &[String]) -> String {
    if constraints.is_empty() {
        "any version".into()
    } else {
        constraints.join(" and ")
    }
}

pub(super) fn dependency_name(value: &str) -> String {
    normalize_name(value.split('[').next().unwrap_or(value).trim())
}

pub(super) fn poetry_dependency_variant_matches(
    value: &toml::Value,
    python_version: &str,
    platform: Platform,
    requested_extras: Option<&BTreeSet<String>>,
) -> io::Result<bool> {
    let Some(table) = value.as_table() else {
        return Ok(true);
    };
    if let Some(markers) = table.get("markers").and_then(toml::Value::as_str) {
        let matches = match requested_extras {
            Some(extras) if !extras.is_empty() => extras
                .iter()
                .map(|extra| {
                    marker_matches_for_extra(markers, python_version, platform, Some(extra))
                })
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .any(|matches| matches),
            _ => marker_matches(markers, python_version, platform)?,
        };
        if !matches {
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

pub(super) fn poetry_active_dependencies(
    dependencies: &toml::map::Map<String, toml::Value>,
    python_version: &str,
    platform: Platform,
    requested_extras: Option<&BTreeSet<String>>,
) -> io::Result<Vec<PoetryDependency>> {
    let mut active = Vec::new();
    for (name, value) in dependencies {
        let enabled = match value {
            toml::Value::Array(values) => {
                for value in values {
                    if poetry_dependency_variant_matches(
                        value,
                        python_version,
                        platform,
                        requested_extras,
                    )? {
                        active.push(poetry_dependency(name, value)?);
                    }
                }
                continue;
            }
            value => poetry_dependency_variant_matches(
                value,
                python_version,
                platform,
                requested_extras,
            )?,
        };
        if enabled {
            active.push(poetry_dependency(name, value)?);
        }
    }
    Ok(active)
}

pub(super) fn poetry_package_hashes(
    lock: &toml::Value,
    package: &toml::map::Map<String, toml::Value>,
    name: &str,
) -> io::Result<Vec<String>> {
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

pub(super) fn check_poetry_content_hash(
    project: &toml::Value,
    lock: &toml::Value,
) -> io::Result<()> {
    let Some(expected) = lock
        .get("metadata")
        .and_then(toml::Value::as_table)
        .and_then(|m| m.get("content-hash"))
        .and_then(toml::Value::as_str)
    else {
        return Ok(());
    };
    let project_content = project.get("project").and_then(toml::Value::as_table);
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
        selected.insert(
            "project",
            serde_json::to_value(relevant_project).map_err(|e| io::Error::other(e.to_string()))?,
        );
    }
    if let Some(groups) = group_content.filter(|groups| !groups.is_empty()) {
        selected.insert("dependency-groups", toml_json_table(groups)?);
    }
    if !selected.is_empty() {
        selected.insert("tool", serde_json::json!({"poetry": relevant_poetry}));
    } else {
        selected.extend(relevant_poetry);
    }
    let compact = serde_json::to_string(&selected).map_err(|e| io::Error::other(e.to_string()))?;
    let json = python_json_spacing(&compact).into_bytes();
    let actual = hex::encode(Sha256::digest(json));
    if actual != expected {
        crate::kernel::ui::warning(
            "poetry.lock content-hash disagrees with pyproject.toml; preferring the lock",
        );
        crate::kernel::policy::record(
            crate::kernel::policy::LOCK_DISAGREEMENT,
            "poetry.lock",
            &format!("content-hash {expected} != computed {actual}; lock preferred"),
        )?;
    }
    Ok(())
}

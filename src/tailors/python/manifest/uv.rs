//! uv projects (python tailor): `uv.lock` parsing and resolution into a
//! manifest, plus the `[tool.uv.sources]` recording.

use super::*;

pub(super) fn record_uv_sources(value: &toml::Value) -> io::Result<()> {
    let Some(sources) = value
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("uv"))
        .and_then(toml::Value::as_table)
        .and_then(|u| u.get("sources"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(());
    };
    for (name, source) in sources {
        if let Some(table) = source.as_table() {
            for key in ["path", "git", "directory", "url"] {
                if table.contains_key(key) {
                    crate::kernel::policy::record(
                        crate::kernel::policy::REQUIREMENT_SKIPPED,
                        name,
                        &format!("uv source `{key}` is not a locked registry package"),
                    )?;
                }
            }
            if table.contains_key("index") {
                crate::kernel::policy::record(
                    crate::kernel::policy::UNATTESTED_INDEX,
                    name,
                    "uv private index source is not followed",
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn is_public_pypi_url(url: &str) -> bool {
    url.is_empty() || url.contains("://pypi.org") || url.contains("://files.pythonhosted.org")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvFile {
    pub url: String,
    pub hash: String,
    pub filename: String,
    pub kind: ArtifactKind,
}

#[derive(Debug, Clone)]
pub struct UvPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub files: Vec<UvFile>,
    pub dependencies: Vec<String>,
    pub resolution_markers: Vec<String>,
    pub(super) dependency_edges: Vec<UvDependency>,
    pub(super) optional_dependencies: BTreeMap<String, Vec<UvDependency>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UvDependency {
    pub(super) name: String,
    pub(super) marker: Option<String>,
    pub(super) version: Option<String>,
    pub(super) extras: BTreeSet<String>,
}

pub fn parse_uv_lock(text: &str) -> io::Result<Vec<UvPackage>> {
    let value: toml::Value = toml::from_str(text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("uv.lock: {e}")))?;
    let packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "uv.lock has no [[package]] entries",
            )
        })?;
    packages
        .iter()
        .map(|package| {
            let table = package.as_table().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "uv.lock package is not a table")
            })?;
            let name = table
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "uv.lock package has no name")
                })?;
            let source = table
                .get("source")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "registry".into());
            let version = table
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            if version.is_empty() && !is_local_uv_source(&source) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("uv.lock {name} has no version"),
                ));
            }
            let mut dependencies = Vec::new();
            let mut dependency_edges = Vec::new();
            if let Some(value) = table.get("dependencies") {
                for dependency in value.as_array().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("uv.lock {name}.dependencies is not an array"),
                    )
                })? {
                    let Some(edge) = parse_uv_dependency(dependency) else {
                        continue;
                    };
                    dependencies.push(edge.name.clone());
                    dependency_edges.push(edge);
                }
            }
            let optional_dependencies = table
                .get("optional-dependencies")
                .and_then(toml::Value::as_table)
                .map(|groups| {
                    groups
                        .iter()
                        .map(|(extra, values)| {
                            let edges = values
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(parse_uv_dependency)
                                .collect::<Vec<_>>();
                            (extra.to_ascii_lowercase(), edges)
                        })
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default();
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
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("uv.lock {name}.sdist is not a table"),
                    )
                })?;
                files.push(uv_file(sdist, ArtifactKind::Sdist).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("uv.lock {name}.sdist lacks a URL and sha256 hash"),
                    )
                })?);
            }
            if let Some(wheels) = table.get("wheels") {
                let wheels = wheels.as_array().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("uv.lock {name}.wheels is not an array"),
                    )
                })?;
                for wheel in wheels {
                    let wheel = wheel.as_table().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("uv.lock {name} wheel is not a table"),
                        )
                    })?;
                    files.push(uv_file(wheel, ArtifactKind::Wheel).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("uv.lock {name} wheel lacks a URL and sha256 hash"),
                        )
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
                optional_dependencies,
            })
        })
        .collect()
}

pub(super) fn parse_uv_dependency(value: &toml::Value) -> Option<UvDependency> {
    if let Some(name) = value.as_str() {
        return parse_uv_requirement(name).ok();
    }
    let table = value.as_table()?;
    let name = table.get("name")?.as_str()?;
    let extras = table
        // uv's lock serializer calls this field `extra` (singular), even
        // though it contains the set of extras requested on the edge.
        .get("extra")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_ascii_lowercase)
        .collect();
    Some(UvDependency {
        name: normalize_name(name),
        marker: table
            .get("marker")
            .or_else(|| table.get("markers"))
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        version: table
            .get("version")
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        extras,
    })
}

pub(super) fn uv_file(
    table: &toml::map::Map<String, toml::Value>,
    kind: ArtifactKind,
) -> Option<UvFile> {
    let url = table.get("url")?.as_str()?.to_string();
    let hash = table
        .get("hash")?
        .as_str()?
        .strip_prefix("sha256:")?
        .to_ascii_lowercase();
    // The downloader would refuse a malformed digest too, but the lock is
    // the place to say so: a hash that cannot match anything is no hash.
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let filename = url
        .rsplit('/')
        .next()?
        .split(['?', '#'])
        .next()?
        .to_string();
    Some(UvFile {
        url,
        hash,
        filename,
        kind,
    })
}

pub(super) fn uv_lock_manifest(
    packages: &[UvPackage],
    requirements: &[String],
    platform: Platform,
    python_version: &str,
    glibc: pypi::Glibc,
) -> io::Result<Option<Vec<LockedPackage>>> {
    let minor = python_version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join("");
    let tag = format!("cp{minor}");
    let mut by_name: BTreeMap<String, Vec<&UvPackage>> = BTreeMap::new();
    for package in packages {
        by_name
            .entry(package.name.clone())
            .or_default()
            .push(package);
    }
    let has_project_root = packages
        .iter()
        .any(|package| is_uv_project_root(&package.source));
    let explicit_requirements = !requirements.is_empty();
    let mut frontier = UvFrontier::default();
    for requirement in requirements {
        let edge = parse_uv_requirement(requirement)?;
        frontier.push_if_applicable(edge, python_version, platform)?;
    }
    if !explicit_requirements {
        // A uv lock normally carries an editable/virtual package for the
        // project itself. Its dependencies are the default (non-dev) roots;
        // development groups remain unreachable from this package graph.
        seed_project_roots(&mut frontier, packages, python_version, platform)?;
    }
    let selected_names =
        if frontier.reachable.is_empty() && !explicit_requirements && !has_project_root {
            // Older/minimal uv locks may omit the project root. Preserve useful
            // behavior for those files by considering every registry package.
            packages
                .iter()
                .map(|package| package.name.clone())
                .collect()
        } else {
            walk_uv_graph(&mut frontier, &by_name, python_version, platform)?;
            std::mem::take(&mut frontier.reachable)
        };
    let mut selected_packages = BTreeMap::new();
    for name in &selected_names {
        let Some(package) = resolve_uv_package(
            name,
            &by_name,
            python_version,
            platform,
            frontier.constraints(name),
        )?
        else {
            return Ok(None);
        };
        selected_packages.insert(name.clone(), package);
    }
    let mut output = Vec::new();
    for package in selected_packages.into_values() {
        if record_uv_source_exceptions(package)? {
            continue;
        }
        let Some(locked) = locked_from_uv_package(package, &tag, platform, glibc) else {
            return Ok(None);
        };
        output.push(locked);
    }
    if output.is_empty() {
        return if explicit_requirements {
            Ok(Some(output))
        } else {
            Ok(None)
        };
    }
    output.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Some(output))
}

/// The breadth-first frontier of the uv package graph: which packages are
/// reachable, the version constraints their incoming edges carry, and the
/// extras that were requested of them.
#[derive(Default)]
struct UvFrontier {
    incoming: BTreeMap<String, Vec<String>>,
    requested_extras: BTreeMap<String, BTreeSet<String>>,
    reachable: BTreeSet<String>,
    queue: VecDeque<String>,
}

impl UvFrontier {
    /// Enqueue `edge` unless its marker rules this host out.
    fn push_if_applicable(
        &mut self,
        edge: UvDependency,
        python_version: &str,
        platform: Platform,
    ) -> io::Result<()> {
        if edge.marker.as_deref().map_or(Ok(true), |marker| {
            marker_matches(marker, python_version, platform)
        })? {
            add_uv_edge(
                &mut self.incoming,
                &mut self.requested_extras,
                &mut self.reachable,
                &mut self.queue,
                edge,
            );
        }
        Ok(())
    }

    fn constraints(&self, name: &str) -> &[String] {
        self.incoming.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// A package's dependency edges, synthesised from the legacy `dependencies`
/// name list when the richer edge table is absent.
fn uv_dependency_edges(package: &UvPackage) -> Vec<UvDependency> {
    if !package.dependency_edges.is_empty() {
        return package.dependency_edges.clone();
    }
    package
        .dependencies
        .iter()
        .map(|name| UvDependency {
            name: name.clone(),
            marker: None,
            version: None,
            extras: BTreeSet::new(),
        })
        .collect()
}

/// Seed the frontier from the lock's editable/virtual project packages.
fn seed_project_roots(
    frontier: &mut UvFrontier,
    packages: &[UvPackage],
    python_version: &str,
    platform: Platform,
) -> io::Result<()> {
    for package in packages
        .iter()
        .filter(|package| is_uv_project_root(&package.source))
    {
        for dependency in uv_dependency_edges(package) {
            frontier.push_if_applicable(dependency, python_version, platform)?;
        }
    }
    Ok(())
}

/// Drain the queue, following each selected package's edges (plus the edges
/// of any extra that was requested of it) until the graph closes.
fn walk_uv_graph(
    frontier: &mut UvFrontier,
    by_name: &BTreeMap<String, Vec<&UvPackage>>,
    python_version: &str,
    platform: Platform,
) -> io::Result<()> {
    while let Some(name) = frontier.queue.pop_front() {
        let Some(package) = resolve_uv_package(
            &name,
            by_name,
            python_version,
            platform,
            frontier.constraints(&name),
        )?
        else {
            continue;
        };
        let mut edges = uv_dependency_edges(package);
        if let Some(extras) = frontier.requested_extras.get(&name) {
            for extra in extras {
                if let Some(optional) = package.optional_dependencies.get(extra) {
                    edges.extend(optional.iter().cloned());
                }
            }
        }
        for dependency in edges {
            frontier.push_if_applicable(dependency, python_version, platform)?;
        }
    }
    Ok(())
}

/// Pick the variant of `name` this host can use. `Ok(None)` means the lock
/// is unusable here and the caller should fall back to uv's own resolver;
/// an unsatisfiable constraint is an error instead, since that is the lock
/// contradicting itself rather than a host mismatch.
fn resolve_uv_package<'a>(
    name: &str,
    by_name: &BTreeMap<String, Vec<&'a UvPackage>>,
    python_version: &str,
    platform: Platform,
    constraints: &[String],
) -> io::Result<Option<&'a UvPackage>> {
    if let Some(package) =
        select_uv_package(by_name.get(name), python_version, platform, constraints)?
    {
        return Ok(Some(package));
    }
    if !constraints.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "uv.lock package {name} cannot satisfy incoming constraints: {}",
                constraints.join(" and "),
            ),
        ));
    }
    crate::kernel::ui::warning(
        &format!(
            "uv.lock has no package variant compatible with the host for {name}; \
             falling back to uv resolution"
        ),
        &format!("tog update {name}"),
    );
    Ok(None)
}

/// Record what this package's source costs us in attestation. Returns true
/// when the package carries no locked registry artifact and must be skipped.
fn record_uv_source_exceptions(package: &UvPackage) -> io::Result<bool> {
    if is_local_uv_source(&package.source) {
        if !is_uv_project_root(&package.source) {
            crate::kernel::policy::record(
                crate::kernel::policy::REQUIREMENT_SKIPPED,
                &package.name,
                "uv lock package is a local or VCS source, not a locked registry artifact",
            )?;
        }
        return Ok(true);
    }
    if package.source != "registry"
        && package.source.contains("registry")
        && !package.source.contains("pypi.org")
        && !package.source.contains("files.pythonhosted.org")
    {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_INDEX,
            &package.name,
            "uv lock package names a non-public registry source",
        )?;
    }
    Ok(false)
}

/// Choose the host-compatible file for `package`. `None` means the lock has
/// nothing this host can install.
fn locked_from_uv_package(
    package: &UvPackage,
    tag: &str,
    platform: Platform,
    glibc: pypi::Glibc,
) -> Option<LockedPackage> {
    let candidates: Vec<_> = package
        .files
        .iter()
        .map(|f| pypi::FileCandidate {
            filename: f.filename.clone(),
            url: f.url.clone(),
            sha256: f.hash.clone(),
        })
        .collect();
    let Some((file, _)) = pypi::select_file(&candidates, tag, platform, glibc) else {
        crate::kernel::ui::warning(
            &format!(
                "uv.lock has no file compatible with the host for {}; falling back to uv \
                 resolution",
                package.name
            ),
            &format!("tog update {}", package.name),
        );
        return None;
    };
    let kind = package
        .files
        .iter()
        .find(|f| f.url == file.url)
        .map(|f| f.kind)
        .unwrap_or(ArtifactKind::Wheel);
    Some(LockedPackage {
        name: package.name.clone(),
        version: package.version.clone(),
        filename: file.filename.clone(),
        url: file.url.clone(),
        sha256: file.sha256.clone(),
        kind,
        git: None,
    })
}

pub(super) fn select_uv_package<'a>(
    variants: Option<&Vec<&'a UvPackage>>,
    python_version: &str,
    platform: Platform,
    constraints: &[String],
) -> io::Result<Option<&'a UvPackage>> {
    let Some(variants) = variants else {
        return Ok(None);
    };
    for package in variants {
        let version_matches = if constraints.is_empty() {
            true
        } else {
            let specifiers = constraints.iter().map(String::as_str).collect::<Vec<_>>();
            let candidates = variants
                .iter()
                .map(|variant| variant.version.as_str())
                .collect::<Vec<_>>();
            crate::tailors::python::pep440::matches_specifiers_with_candidates(
                &specifiers,
                &package.version,
                &candidates,
            )?
        };
        if version_matches
            && (package.resolution_markers.is_empty()
                || package
                    .resolution_markers
                    .iter()
                    .map(|marker| marker_matches(marker, python_version, platform))
                    .collect::<io::Result<Vec<_>>>()?
                    .into_iter()
                    .any(|matches| matches))
        {
            return Ok(Some(*package));
        }
    }
    Ok(None)
}

pub(super) fn is_local_uv_source(source: &str) -> bool {
    source.contains("editable")
        || source.contains("virtual")
        || source.contains("directory")
        || source.contains("path")
        || source.contains("git")
        || source.contains("url")
        || source.contains("workspace")
}

pub(super) fn is_uv_project_root(source: &str) -> bool {
    (source.contains("editable") || source.contains("virtual"))
        && (source.contains("\".\"") || source.contains("'.'"))
}

pub(super) fn parse_uv_requirement(requirement: &str) -> io::Result<UvDependency> {
    let (body, marker) = requirement
        .split_once(';')
        .map_or((requirement, None), |(body, marker)| {
            (body, Some(marker.trim().to_string()))
        });
    let body = body.trim();
    let name_end = body
        .find(['[', '<', '>', '=', '!', '~', ' ', '\t'])
        .unwrap_or(body.len());
    let raw_name = body[..name_end].trim();
    if raw_name.is_empty()
        || !raw_name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid uv requirement `{requirement}`"),
        ));
    }
    let mut rest = body[name_end..].trim();
    let mut extras = BTreeSet::new();
    if let Some(after_open) = rest.strip_prefix('[') {
        let Some(close) = after_open.find(']') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid uv requirement `{requirement}`"),
            ));
        };
        for extra in after_open[..close].split(',') {
            let extra = extra.trim();
            if !extra.is_empty() {
                extras.insert(extra.to_ascii_lowercase());
            }
        }
        rest = after_open[close + 1..].trim();
    }
    Ok(UvDependency {
        name: normalize_name(raw_name),
        marker,
        version: (!rest.is_empty()).then(|| rest.to_string()),
        extras,
    })
}

pub(super) fn add_uv_edge(
    incoming: &mut BTreeMap<String, Vec<String>>,
    requested_extras: &mut BTreeMap<String, BTreeSet<String>>,
    reachable: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    dependency: UvDependency,
) {
    let name = dependency.name;
    let version_changed = if let Some(version) = dependency.version.filter(|v| v != "*") {
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
    if reachable.insert(name.clone()) || version_changed || extras_changed {
        queue.push_back(name);
    }
}

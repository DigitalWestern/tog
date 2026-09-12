//! requirements.txt projects (python tailor): include resolution, the
//! requirements tree hash, and index-option collection.

use super::*;

pub(super) fn requirements_manifest(_dir: &Path, path: &Path, input: &str) -> io::Result<Manifest> {
    let source = read_text(path)?;
    validate_requirement_includes(path, false, &mut Vec::new(), &mut BTreeSet::new())?;
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
            crate::kernel::policy::record(
                crate::kernel::policy::REQUIREMENT_SKIPPED,
                &requirement,
                "project-local or direct reference is not a locked registry package",
            )?;
        } else {
            filtered.push(requirement);
        }
    }
    let requirements = filtered;
    let mut index_options = Vec::new();
    collect_index_options(
        path,
        &mut Vec::new(),
        &mut BTreeSet::new(),
        &mut index_options,
    )?;
    let has_index_options = !index_options.is_empty();
    for option in index_options {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_INDEX,
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

pub(super) fn requirements_directory_candidate(
    dir: &Path,
    cfg: &BlanketPythonConfig,
) -> io::Result<Option<PathBuf>> {
    let requirements = dir.join("requirements");
    if !requirements.is_dir() {
        return Ok(None);
    }
    if let Some(explicit) = &cfg.requirements {
        let path = if explicit.is_absolute() {
            explicit.clone()
        } else {
            dir.join(explicit)
        };
        if path.is_file() {
            return Ok(Some(path));
        }
        return Err(unreadable(
            &path,
            "blanket.toml [python].requirements points to a missing file",
        ));
    }
    for hardware in ["cpu.txt", "cuda.txt", "rocm.txt", "xpu.txt"] {
        let path = requirements.join(hardware);
        if path.is_file() {
            return Ok(Some(path));
        }
    }
    for name in ["common.txt", "base.txt", "requirements.in"] {
        let path = requirements.join(name);
        if path.is_file() {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

pub(super) fn validate_requirement_includes(
    path: &Path,
    constraints_only: bool,
    stack: &mut Vec<(PathBuf, bool)>,
    seen: &mut BTreeSet<(PathBuf, bool)>,
) -> io::Result<()> {
    let path = path.canonicalize().map_err(|e| unreadable(path, e))?;
    let key = (path.clone(), constraints_only);
    if stack.contains(&key) {
        return Err(unreadable(
            &path,
            format!(
                "requirements include cycle: {}",
                stack
                    .iter()
                    .map(|(p, _)| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
        ));
    }
    if !seen.insert(key.clone()) {
        return Ok(());
    }
    stack.push(key);
    let text = read_text(&path)?;
    for line in pypi::logical_requirement_lines(&text) {
        if let Some(include) = parse_include_directive(&line) {
            let target = include.target.ok_or_else(|| {
                unreadable(&path, "requirements include is missing its file argument")
            })?;
            let child = path.parent().unwrap_or(Path::new(".")).join(target.trim());
            if !child.is_file() {
                return Err(unreadable(&child, "included requirements file is missing"));
            }
            validate_requirement_includes(
                &child,
                constraints_only || include.constraint,
                stack,
                seen,
            )?;
        }
    }
    stack.pop();
    Ok(())
}

/// Hash a requirements file together with every file reached through its
/// `-r`/`-c` include closure.  uv follows those includes itself when the
/// source is handed to it, so the cache key must cover the same files rather
/// than only the bytes of the top-level file.
pub fn requirements_tree_hash(path: &Path) -> io::Result<String> {
    let top = path.canonicalize().map_err(|e| unreadable(path, e))?;
    let root = top.parent().unwrap_or(Path::new("."));
    let mut visited = BTreeSet::new();
    let mut files = BTreeSet::new();
    collect_requirement_files(&top, false, &mut Vec::new(), &mut visited, &mut files)?;
    let mut hasher = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(&file).map_err(|e| unreadable(&file, e))?);
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn collect_requirement_files(
    path: &Path,
    constraints_only: bool,
    stack: &mut Vec<(PathBuf, bool)>,
    visited: &mut BTreeSet<(PathBuf, bool)>,
    files: &mut BTreeSet<PathBuf>,
) -> io::Result<()> {
    let path = path.canonicalize().map_err(|e| unreadable(path, e))?;
    let key = (path.clone(), constraints_only);
    if stack.contains(&key) {
        return Err(unreadable(&path, "requirements include cycle"));
    }
    if !visited.insert(key.clone()) {
        return Ok(());
    }
    files.insert(path.clone());
    stack.push(key);
    for line in pypi::logical_requirement_lines(&read_text(&path)?) {
        if let Some(include) = parse_include_directive(&line) {
            let Some(target) = include.target else {
                continue;
            };
            let child = path.parent().unwrap_or(Path::new(".")).join(target.trim());
            collect_requirement_files(
                &child,
                constraints_only || include.constraint,
                stack,
                visited,
                files,
            )?;
        }
    }
    stack.pop();
    Ok(())
}

pub(super) fn collect_requirement_lines(
    path: &Path,
    stack: &mut Vec<(PathBuf, bool)>,
    seen: &mut BTreeSet<(PathBuf, bool)>,
    output: &mut Vec<String>,
    constraints: &mut Vec<String>,
    constraints_only: bool,
) -> io::Result<()> {
    let path = path.canonicalize().map_err(|e| unreadable(path, e))?;
    let key = (path.clone(), constraints_only);
    if stack.contains(&key) {
        return Err(unreadable(&path, "requirements include cycle"));
    }
    if !seen.insert(key.clone()) {
        return Ok(());
    }
    stack.push(key);
    for line in pypi::logical_requirement_lines(&read_text(&path)?) {
        if let Some(include) = parse_include_directive(&line) {
            let target = include.target.ok_or_else(|| {
                unreadable(&path, "requirements include is missing its file argument")
            })?;
            let is_constraint = include.constraint;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IncludeDirective {
    pub(super) target: Option<String>,
    pub(super) constraint: bool,
}

/// Parse every pip include spelling in one place. This parser is shared by
/// discovery, flattening, index-option traversal, and the transitive hash.
pub(super) fn parse_include_directive(line: &str) -> Option<IncludeDirective> {
    let first = line.split_whitespace().next()?;
    let exact = match first {
        "-r" | "--requirement" => Some(false),
        "-c" | "--constraint" => Some(true),
        _ => None,
    };
    if let Some(constraint) = exact {
        return Some(IncludeDirective {
            target: line.split_whitespace().nth(1).map(str::to_string),
            constraint,
        });
    }
    for (option, constraint) in [
        ("--requirement=", false),
        ("--constraint=", true),
        ("-r=", false),
        ("-c=", true),
    ] {
        if let Some(target) = first.strip_prefix(option) {
            return Some(IncludeDirective {
                target: (!target.is_empty()).then(|| target.to_string()),
                constraint,
            });
        }
    }
    if let Some(target) = first.strip_prefix("-r").filter(|target| !target.is_empty()) {
        return Some(IncludeDirective {
            target: Some(target.to_string()),
            constraint: false,
        });
    }
    if let Some(target) = first.strip_prefix("-c").filter(|target| !target.is_empty()) {
        return Some(IncludeDirective {
            target: Some(target.to_string()),
            constraint: true,
        });
    }
    None
}

pub(super) fn collect_index_options(
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
        if let Some(include) = parse_include_directive(&line) {
            let Some(target) = include.target else {
                continue;
            };
            let child = path.parent().unwrap_or(Path::new(".")).join(target.trim());
            collect_index_options(&child, stack, seen, output)?;
        }
    }
    stack.pop();
    Ok(())
}

pub(super) fn strip_inline_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(i, c)| *c == '#' && (*i == 0 || line.as_bytes()[*i - 1].is_ascii_whitespace()))
        .map(|(i, _)| &line[..i])
        .unwrap_or(line)
}

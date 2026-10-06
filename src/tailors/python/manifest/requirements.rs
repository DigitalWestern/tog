//! requirements.txt projects (python tailor): include resolution, the
//! requirements tree hash, and index-option collection.

use super::*;

/// The requirements file and every include are read through the held
/// project descriptor (`read_project_file`).
pub(super) fn requirements_manifest(
    project: &ProjectRoot,
    path: &Path,
    input: &str,
) -> io::Result<Manifest> {
    let source = read_text(project, path)?;
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    let mut index_options = Vec::new();
    // The mode a file was first reached in. A file reached both as
    // requirements and as constraints lists its index options once.
    let mut first_mode = BTreeMap::new();
    walk_includes(project, path, &mut |step| {
        match step {
            IncludeStep::File {
                file,
                constraints_only,
            } => {
                first_mode
                    .entry(file.to_path_buf())
                    .or_insert(constraints_only);
            }
            IncludeStep::Line {
                file,
                line,
                constraints_only,
            } => {
                if first_mode.get(file) == Some(&constraints_only) {
                    index_options.extend(pypi::unattested_index_options(line));
                }
                if !pypi::is_requirement_option(line) {
                    let list = if constraints_only {
                        &mut constraints
                    } else {
                        &mut requirements
                    };
                    list.push(line.to_string());
                }
            }
        }
        Ok(())
    })?;
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
    project: &ProjectRoot,
    cfg: &TogPythonConfig,
) -> io::Result<Option<PathBuf>> {
    let dir = project.path();
    let requirements = dir.join("requirements");
    if !is_project_dir(project, &requirements) {
        return Ok(None);
    }
    if let Some(explicit) = &cfg.requirements {
        let path = if explicit.is_absolute() {
            explicit.clone()
        } else {
            dir.join(explicit)
        };
        if is_project_file(project, &path) {
            return Ok(Some(path));
        }
        return Err(unreadable(
            &path,
            "tog.toml [python].requirements points to a missing file",
        ));
    }
    for hardware in ["cpu.txt", "cuda.txt", "rocm.txt", "xpu.txt"] {
        let path = requirements.join(hardware);
        if is_project_file(project, &path) {
            return Ok(Some(path));
        }
    }
    for name in ["common.txt", "base.txt", "requirements.in"] {
        let path = requirements.join(name);
        if is_project_file(project, &path) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// One step of [`walk_includes`].
pub(super) enum IncludeStep<'a> {
    /// A file entered for the first time under this `constraints_only`.
    File {
        file: &'a Path,
        constraints_only: bool,
    },
    /// One logical line of `file` that is not an include directive.
    Line {
        file: &'a Path,
        line: &'a str,
        constraints_only: bool,
    },
}

/// Walk a requirements file and its `-r`/`-c` include closure depth first,
/// in file order, calling `visit` for each file and each non-include line.
/// The one place the include rules live: an include without its file
/// argument, a missing included file and a cycle are all errors. A file is
/// visited once per `constraints_only` value, because the same file
/// reached through `-c` contributes constraints, not requirements.
pub(super) fn walk_includes(
    project: &ProjectRoot,
    path: &Path,
    visit: &mut dyn FnMut(IncludeStep<'_>) -> io::Result<()>,
) -> io::Result<()> {
    walk_from(
        project,
        path,
        false,
        &mut Vec::new(),
        &mut BTreeSet::new(),
        visit,
    )
}

fn walk_from(
    project: &ProjectRoot,
    path: &Path,
    constraints_only: bool,
    stack: &mut Vec<(PathBuf, bool)>,
    seen: &mut BTreeSet<(PathBuf, bool)>,
    visit: &mut dyn FnMut(IncludeStep<'_>) -> io::Result<()>,
) -> io::Result<()> {
    let path = canonical_project_path(project, path).map_err(|e| unreadable(path, e))?;
    let key = (path.clone(), constraints_only);
    if stack.contains(&key) {
        return Err(unreadable(
            &path,
            format!(
                "requirements include cycle: {}",
                stack
                    .iter()
                    .map(|(p, _)| p.display().to_string())
                    .chain([path.display().to_string()])
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
        ));
    }
    if !seen.insert(key.clone()) {
        return Ok(());
    }
    visit(IncludeStep::File {
        file: &path,
        constraints_only,
    })?;
    stack.push(key);
    for line in pypi::logical_requirement_lines(&read_text(project, &path)?) {
        let Some(include) = parse_include_directive(&line) else {
            visit(IncludeStep::Line {
                file: &path,
                line: &line,
                constraints_only,
            })?;
            continue;
        };
        let target = include.target.ok_or_else(|| {
            unreadable(&path, "requirements include is missing its file argument")
        })?;
        let child = path.parent().unwrap_or(Path::new(".")).join(target.trim());
        if !is_project_file(project, &child) {
            return Err(unreadable(&child, "included requirements file is missing"));
        }
        walk_from(
            project,
            &child,
            constraints_only || include.constraint,
            stack,
            seen,
            visit,
        )?;
    }
    stack.pop();
    Ok(())
}

/// Hash a requirements file together with every file reached through its
/// `-r`/`-c` include closure.  uv follows those includes itself when the
/// source is handed to it, so the cache key must cover the same files rather
/// than only the bytes of the top-level file. Each file is read through the
/// held project descriptor.
pub fn requirements_tree_hash(project: &ProjectRoot, path: &Path) -> io::Result<String> {
    let top = canonical_project_path(project, path).map_err(|e| unreadable(path, e))?;
    let root = top.parent().unwrap_or(Path::new("."));
    let mut files = BTreeSet::new();
    walk_includes(project, &top, &mut |step| {
        if let IncludeStep::File { file, .. } = step {
            files.insert(file.to_path_buf());
        }
        Ok(())
    })?;
    let mut hasher = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(read_project_file(project, &file).map_err(|e| unreadable(&file, e))?);
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
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

pub(super) fn strip_inline_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(i, c)| *c == '#' && (*i == 0 || line.as_bytes()[*i - 1].is_ascii_whitespace()))
        .map(|(i, _)| &line[..i])
        .unwrap_or(line)
}

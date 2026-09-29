//! `tog add` / `remove` / `update` for Python (`Tailor::edit_manifest`).
//!
//! uv edits a `[project]` pyproject and its uv.lock; a pip-compile pair or a
//! plain requirements file is edited here as text and re-locked with the
//! store uv. Poetry, PDM, setup.py and a `requirements/` directory are not
//! pinned tools, so those refuse with the exact edit to make.

use super::pypi;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::{DelegateSpec, ResolutionDoor};
use crate::kernel::ui;
use crate::tailors::edit::{
    other, registry_latest, run_inherited, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
};
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "py",
    name: "PyPI",
};

/// `Tailor::registry_exists`: `Some(latest version)` when PyPI knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let url = format!("https://pypi.org/pypi/{name}/json");
    registry_latest(REGISTRY, name, &url, |v| {
        v["info"]["version"].as_str().map(str::to_string)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyShape {
    /// `pyproject.toml` with `[project]` and no foreign lock: uv edits it.
    Uv,
    Poetry,
    Pdm,
    /// `requirements.in` compiled into `requirements.txt` (pip-tools / uv
    /// convention): tog edits the .in and recompiles.
    PipCompile,
    /// A plain requirements file tog re-locks into requirements.lock.txt.
    Requirements(PathBuf),
    Setup,
    RequirementsDir,
}

pub fn python_shape(project: &Path) -> io::Result<PyShape> {
    let has = |name: &str| project.join(name).is_file();
    if has("requirements.in") && has("requirements.txt") {
        return Ok(PyShape::PipCompile);
    }
    if has("requirements.txt") {
        return Ok(PyShape::Requirements(project.join("requirements.txt")));
    }
    if has("pyproject.toml") {
        let text = fs::read_to_string(project.join("pyproject.toml"))?;
        let value: toml::Table = text
            .parse()
            .map_err(|error| other(format!("pyproject.toml: {error}")))?;
        let tool = value.get("tool").and_then(toml::Value::as_table);
        if has("poetry.lock") || tool.is_some_and(|tool| tool.contains_key("poetry")) {
            return Ok(PyShape::Poetry);
        }
        if has("pdm.lock") {
            return Ok(PyShape::Pdm);
        }
        if value.get("project").is_some() {
            return Ok(PyShape::Uv);
        }
    }
    if has("setup.cfg") || has("setup.py") {
        return Ok(PyShape::Setup);
    }
    if project.join("requirements").is_dir() {
        return Ok(PyShape::RequirementsDir);
    }
    Err(other("no Python manifest here"))
}

fn python_line(texts: &[String]) -> String {
    texts
        .iter()
        .map(|text| format!("\"{text}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `Tailor::edit_manifest` for Python.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    Ok(EditOutcome {
        files: edit_files(edit, door)?,
        sync_root: edit.project.to_path_buf(),
    })
}

fn edit_files(edit: &ManifestEdit<'_>, door: &mut ResolutionDoor<'_>) -> io::Result<Vec<String>> {
    let (project, verb, dev) = (edit.project, edit.verb, edit.dev);
    let texts = &edit.texts();
    let names = &edit.names();
    let shape = python_shape(project)?;
    match shape {
        PyShape::Poetry => Err(other(match verb {
            EditVerb::Add => format!(
                "this is a Poetry project and Poetry is not a pinned tool: add {} under [tool.poetry.dependencies] in pyproject.toml (or run 'poetry add {}'), then 'tog'",
                python_line(texts),
                texts.join(" ")
            ),
            EditVerb::Remove => format!(
                "this is a Poetry project: remove {} from [tool.poetry.dependencies] in pyproject.toml (or run 'poetry remove {}'), then 'tog'",
                names.join(", "),
                names.join(" ")
            ),
            EditVerb::Update => "this is a Poetry project: run 'poetry update' (or 'poetry lock'), then 'tog'".to_string(),
        })),
        PyShape::Pdm => Err(other(format!(
            "this is a PDM project (pdm.lock) and PDM is not a pinned tool: run 'pdm {} {}', then 'tog'",
            match verb {
                EditVerb::Add => "add",
                EditVerb::Remove => "remove",
                EditVerb::Update => "update",
            },
            texts.join(" ")
        ))),
        PyShape::Setup => Err(other(match verb {
            EditVerb::Add => format!(
                "dependencies live in install_requires here: add {} to setup.cfg [options] install_requires (or setup.py), then 'tog'",
                python_line(texts)
            ),
            EditVerb::Remove => format!(
                "dependencies live in install_requires here: remove {} from setup.cfg / setup.py, then 'tog'",
                names.join(", ")
            ),
            EditVerb::Update => "install_requires projects re-lock on every sync (there is no separate lock to update); loosen the constraint in setup.cfg / setup.py, then 'tog'".to_string(),
        })),
        PyShape::RequirementsDir => Err(other(format!(
            "dependencies live under requirements/ here: edit the file that applies (requirements/common.txt, base.txt, ...) to {} {}, then 'tog'",
            match verb {
                EditVerb::Add => "add",
                EditVerb::Remove => "remove",
                EditVerb::Update => "update",
            },
            texts.join(" ")
        ))),
        PyShape::Uv => python_uv(edit, door),
        PyShape::PipCompile => {
            if dev {
                return Err(other("--dev has no meaning for a requirements file"));
            }
            let input = project.join("requirements.in");
            let output = project.join("requirements.txt");
            match verb {
                EditVerb::Add => edit_requirements(&input, texts, &[])?,
                EditVerb::Remove => edit_requirements(&input, &[], names)?,
                EditVerb::Update => {}
            }
            let upgrade = upgrade_flags(verb, names);
            uv_compile(edit, door, &input, &output, &upgrade)?;
            Ok(vec![
                "requirements.in".to_string(),
                "requirements.txt".to_string(),
            ])
        }
        PyShape::Requirements(path) => {
            if dev {
                return Err(other("--dev has no meaning for a requirements file"));
            }
            let file = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            match verb {
                EditVerb::Add => edit_requirements(&path, texts, &[])?,
                EditVerb::Remove => edit_requirements(&path, &[], names)?,
                EditVerb::Update => {}
            }
            let lock = project.join("requirements.lock.txt");
            let mut files = vec![file];
            if verb == EditVerb::Update && lock.is_file() {
                uv_compile(edit, door, &path, &lock, &upgrade_flags(verb, names))?;
                files.push("requirements.lock.txt".to_string());
            } else {
                // The ordinary sync re-locks when the source hash changes; a
                // stale stamp from an unchanged source (update with no lock
                // yet) is cleared so sync resolves afresh. Through the held
                // project descriptor, so a symlinked `.tog` cannot redirect
                // the unlink outside the project.
                ProjectRoot::open(project)?.remove_file(Path::new(".tog/lock-source.hash"))?;
                if verb == EditVerb::Update {
                    files.push("(re-locks on sync)".to_string());
                }
            }
            Ok(files)
        }
    }
}

fn upgrade_flags(verb: EditVerb, names: &[String]) -> Vec<String> {
    if verb != EditVerb::Update {
        return Vec::new();
    }
    if names.is_empty() {
        return vec!["--upgrade".to_string()];
    }
    names
        .iter()
        .flat_map(|name| ["--upgrade-package".to_string(), name.clone()])
        .collect()
}

/// A requirement line's normalized name (`None` for comments, options,
/// blank lines).
pub fn requirement_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
        return None;
    }
    let end = line
        .find(|c: char| " [<>=!~;#@\\".contains(c))
        .unwrap_or(line.len());
    let name = &line[..end];
    if name.is_empty() {
        None
    } else {
        Some(pypi::normalize_name(name))
    }
}

/// Add specs (replacing an existing logical record for the same name) and
/// remove names; everything else in the file is preserved byte for byte.
/// Written atomically.
pub fn edit_requirements(path: &Path, add: &[String], remove: &[String]) -> io::Result<()> {
    let text = fs::read_to_string(path)?;

    for value in add.iter().chain(remove) {
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(other(format!(
                "dependency requirement '{value}' must not contain CR, LF, or NUL"
            )));
        }
    }

    #[derive(Debug)]
    struct Record {
        raw: String,
        name: Option<String>,
    }

    fn physical_lines(text: &str) -> Vec<&str> {
        if text.is_empty() {
            return Vec::new();
        }
        text.split_inclusive('\n').collect()
    }

    fn continued(line: &str) -> bool {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        line.trim_end_matches([' ', '\t']).ends_with('\\')
    }

    // A requirement and its indented `--hash` continuations are one logical
    // record.  Editing whole records, not physical lines, is what keeps a
    // remove from leaving orphaned hash constraints behind.
    let physical = physical_lines(&text);
    let mut records = Vec::new();
    let mut index = 0;
    while index < physical.len() {
        let start = index;
        while index + 1 < physical.len() && continued(physical[index]) {
            index += 1;
        }
        index += 1;
        let raw = physical[start..index].concat();
        let name = requirement_name(physical[start]);
        records.push(Record { raw, name });
    }
    let existing_names: Vec<String> = records
        .iter()
        .filter_map(|record| record.name.clone())
        .collect();

    let remove_names: Vec<String> = remove
        .iter()
        .map(|name| pypi::normalize_name(name))
        .collect();
    for (name, wanted) in remove.iter().zip(&remove_names) {
        let matches: Vec<usize> = records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| (record.name.as_deref() == Some(wanted)).then_some(index))
            .collect();
        if matches.is_empty() {
            return Err(other(format!(
                "'{name}' is not declared in {}",
                path.display()
            )));
        }
        if matches.len() > 1 {
            return Err(other(format!(
                "'{name}' is declared {} times in {}; refusing an ambiguous edit",
                matches.len(),
                path.display()
            )));
        }
    }

    let mut additions = Vec::new();
    let mut add_names = Vec::new();
    for spec in add {
        let wanted = requirement_name(spec).ok_or_else(|| {
            other(format!(
                "'{spec}' is not a requirement (name first, e.g. 'requests>=2')"
            ))
        })?;
        if add_names.contains(&wanted) {
            return Err(other(format!(
                "'{spec}' duplicates another requirement in the same edit"
            )));
        }
        let matches = records
            .iter()
            .filter(|record| record.name.as_deref() == Some(&wanted))
            .count();
        if matches > 1 {
            return Err(other(format!(
                "'{spec}' matches {} declarations in {}; refusing an ambiguous edit",
                matches,
                path.display()
            )));
        }
        add_names.push(wanted.clone());
        additions.push((wanted, spec));
    }

    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(text.len());
    for record in records {
        if record
            .name
            .as_ref()
            .is_some_and(|name| remove_names.contains(name))
        {
            continue;
        }
        if let Some((_, spec)) = additions
            .iter()
            .find(|(wanted, _)| record.name.as_ref() == Some(wanted))
        {
            if requirement_has_marker(&record.raw) != requirement_has_marker(spec) {
                return Err(other(format!(
                    "'{spec}' would change the environment marker on an existing declaration in {}; specify the marker explicitly",
                    path.display()
                )));
            }
            // Keep the original logical record's final line ending, so a
            // no-trailing-newline file stays that way and CRLF files stay
            // CRLF.  Replacing the whole record also removes all old hashes.
            let ending = if record.raw.ends_with("\r\n") {
                "\r\n"
            } else if record.raw.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            out.push_str(spec);
            out.push_str(ending);
        } else {
            out.push_str(&record.raw);
        }
    }

    let unmatched: Vec<&String> = additions
        .iter()
        .filter_map(|(wanted, spec)| (!existing_names.contains(wanted)).then_some(*spec))
        .collect();
    if !unmatched.is_empty() {
        if !out.is_empty() && !out.ends_with(['\n', '\r']) {
            out.push_str(newline);
        }
        for (index, spec) in unmatched.iter().enumerate() {
            out.push_str(spec);
            if text.ends_with(['\n', '\r']) || index + 1 < unmatched.len() {
                out.push_str(newline);
            }
        }
    }

    write_atomic_requirements(path, &out)
}

fn requirement_has_marker(value: &str) -> bool {
    value
        .split_once('#')
        .map_or(value, |(before_comment, _)| before_comment)
        .contains(';')
}

fn write_atomic_requirements(path: &Path, contents: &str) -> io::Result<()> {
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "requirements".into());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    let mut temp = None;
    for _ in 0..100 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.tog-edit-{stamp}-{}-{counter}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temp, mut file) =
        temp.ok_or_else(|| other("could not create a unique requirements temp file"))?;
    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(
            &temp,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        ) {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
    }
    if let Err(error) = file.write_all(contents.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

/// The store uv, run in the project on the project's interpreter, with
/// the user's index settings removed.
fn uv_spec(
    edit: &ManifestEdit<'_>,
    door: &ResolutionDoor<'_>,
) -> io::Result<(DelegateSpec, String)> {
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    let toolchain = edit.host.toolchain(edit.project, "python")?;
    let version = toolchain.version("cpython")?.to_string();
    let uv = super::realize_uv(store, activity, platform, &toolchain)?.join("uv");
    let interpreter = super::realize_runtime(store, activity, platform, &toolchain)?;
    let mut spec = DelegateSpec::new(uv);
    spec.lock_root(edit.project)
        .env("UV_PYTHON", interpreter.join("bin/python3"))
        .env("UV_PYTHON_DOWNLOADS", "never")
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    Ok((spec, version))
}

fn uv_compile(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
    input: &Path,
    output: &Path,
    extra: &[String],
) -> io::Result<()> {
    let (mut spec, version) = uv_spec(edit, door)?;
    spec.args(["pip", "compile"])
        .arg(input)
        .arg("--generate-hashes");
    if !ui::verbose() {
        spec.arg("--quiet");
    }
    spec.args(["--python-version", &version])
        .args(["--index-url", "https://pypi.org/simple"])
        .arg("-o")
        .arg(output)
        .args(extra);
    run_inherited(door, spec, "store uv pip compile")
}

fn python_uv(edit: &ManifestEdit<'_>, door: &mut ResolutionDoor<'_>) -> io::Result<Vec<String>> {
    let texts = &edit.texts();
    let (mut spec, _) = uv_spec(edit, door)?;
    match edit.verb {
        EditVerb::Add => {
            spec.args(["add", "--no-sync"]);
            if edit.dev {
                spec.arg("--dev");
            }
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
        EditVerb::Remove => {
            spec.args(["remove", "--no-sync"]);
            if edit.dev {
                spec.arg("--dev");
            }
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
        EditVerb::Update => {
            spec.arg("lock");
            if texts.is_empty() {
                spec.arg("--upgrade");
            }
            for name in texts {
                spec.args(["--upgrade-package", name]);
            }
        }
    }
    run_inherited(door, spec, "store uv")?;
    Ok(vec!["pyproject.toml".to_string(), "uv.lock".to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn requirement_names_and_edits() {
        assert_eq!(
            requirement_name("Requests>=2 ; python_version<'3'"),
            Some("requests".into())
        );
        assert_eq!(
            requirement_name("zope.Interface[x]==5"),
            Some("zope-interface".into())
        );
        assert_eq!(requirement_name("# comment"), None);
        assert_eq!(requirement_name("-r other.txt"), None);
        assert_eq!(requirement_name("--hash=sha256:abc"), None);
        assert_eq!(requirement_name(""), None);

        let scratch = TempDir::named("deps");
        let temp = scratch.0.clone();
        let file = temp.join("requirements.txt");
        fs::write(&file, "# pinned\nsix==1.16.0\n-r extra.txt\n").unwrap();
        edit_requirements(&file, &["requests>=2".into(), "six==1.17.0".into()], &[]).unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "# pinned\nsix==1.17.0\n-r extra.txt\nrequests>=2\n"
        );
        edit_requirements(&file, &[], &["SIX".into()]).unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "# pinned\n-r extra.txt\nrequests>=2\n"
        );
        let error = edit_requirements(&file, &[], &["six".into()]).unwrap_err();
        assert!(error.to_string().contains("'six' is not declared"));
        let error = edit_requirements(&file, &["-e .".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("not a requirement"));
    }

    #[test]
    fn requirement_edits_are_logical_lossless_and_ambiguous_edits_fail() {
        let scratch = TempDir::named("deps-logical");
        let temp = scratch.0.clone();
        let file = temp.join("requirements.txt");
        fs::write(
            &file,
            "# pinned\r\nfoo==1.0 \\\r\n    --hash=sha256:abc\r\nbar==2.0",
        )
        .unwrap();
        edit_requirements(&file, &[], &["foo".into()]).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "# pinned\r\nbar==2.0");

        fs::write(
            &file,
            "foo==1; python_version<'3'\nfoo==2; python_version>='3'\n",
        )
        .unwrap();
        let error = edit_requirements(&file, &["foo==3".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("ambiguous"), "{error}");
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "foo==1; python_version<'3'\nfoo==2; python_version>='3'\n"
        );

        fs::write(&file, "foo==1; python_version<'3'\n").unwrap();
        let error = edit_requirements(&file, &["foo==3".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("environment marker"), "{error}");
        edit_requirements(&file, &["foo==3; python_version<'3'".into()], &[]).unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "foo==3; python_version<'3'\n"
        );

        let error = edit_requirements(&file, &["foo\nbar".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("CR, LF, or NUL"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn requirement_edit_does_not_follow_predictable_temp_symlink() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let scratch = TempDir::named("deps-atomic");
        let temp = scratch.0.clone();
        let file = temp.join("requirements.txt");
        let target = temp.join("outside");
        let old_temp = file.with_extension(format!("tog-edit.{}", std::process::id()));
        fs::write(&file, "six\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&target, "must remain\n").unwrap();
        symlink(&target, &old_temp).unwrap();

        edit_requirements(&file, &["requests".into()], &[]).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "must remain\n");
        assert_eq!(fs::read_to_string(&file).unwrap(), "six\nrequests\n");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn python_shapes_follow_the_sync_order() {
        let scratch = TempDir::named("shape");
        let temp = scratch.0.clone();
        assert!(python_shape(&temp).is_err());
        fs::write(temp.join("setup.py"), "").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Setup);
        fs::write(temp.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Uv);
        fs::write(temp.join("pyproject.toml"), "[tool.poetry]\nname='x'\n").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Poetry);
        fs::write(temp.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        fs::write(temp.join("pdm.lock"), "").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Pdm);
        // requirements.txt wins over pyproject, as in sync.
        fs::write(temp.join("requirements.txt"), "six\n").unwrap();
        assert_eq!(
            python_shape(&temp).unwrap(),
            PyShape::Requirements(temp.join("requirements.txt"))
        );
        fs::write(temp.join("requirements.in"), "six\n").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::PipCompile);
    }

    #[test]
    fn upgrade_flags_shape() {
        assert!(upgrade_flags(EditVerb::Add, &["x".into()]).is_empty());
        assert_eq!(upgrade_flags(EditVerb::Update, &[]), vec!["--upgrade"]);
        assert_eq!(
            upgrade_flags(EditVerb::Update, &["a".into(), "b".into()]),
            vec!["--upgrade-package", "a", "--upgrade-package", "b"]
        );
    }
}

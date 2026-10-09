//! Python's resolution files, uv workspaces, and `tog attest` (python
//! tailor): what a uv door writes and reads in a project, and the lock
//! check a signed record attests.

use super::door::{self, Builds, Index, Uv, UvRun, UvTarget};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::resolve::record::{self, RecordSlot};
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The files a uv door writes at a lock root: the project manifest and
/// uv's lock, and the pip-compile pair and the lock tog compiles from a
/// requirements file.
const OUTPUTS: [&str; 5] = [
    "pyproject.toml",
    "uv.lock",
    "requirements.in",
    "requirements.txt",
    "requirements.lock.txt",
];

/// Project files uv reads when it resolves and never writes: the setuptools
/// metadata a project without `[project]` declares its dependencies in.
const INPUTS: [&str; 3] = ["setup.cfg", "setup.py", "tog.toml"];

/// The requirements files whose `-r`/`-c` includes a door's uv reads.
const REQUIREMENTS: [&str; 2] = ["requirements.in", "requirements.txt"];

/// The deepest workspace member a members glob is expanded to, and the
/// most ancestors searched for a workspace root.
const MAX_DEPTH: usize = 24;

/// `Tailor::resolution_outputs` for Python: [`OUTPUTS`] and the
/// `pyproject.toml` of every uv workspace member, which `uv lock` reads and
/// an edit made in a member writes.
pub(crate) fn resolution_outputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut outputs: Vec<PathBuf> = OUTPUTS.iter().map(PathBuf::from).collect();
    for member in workspace_members(root)? {
        outputs.push(member.join("pyproject.toml"));
    }
    Ok(outputs)
}

/// `Tailor::resolution_inputs` for Python: [`INPUTS`] and every file a
/// requirements file includes inside the project.
pub(crate) fn resolution_inputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut inputs: Vec<PathBuf> = INPUTS.iter().map(PathBuf::from).collect();
    for file in includes(root)?.inside {
        if !inputs.contains(&file) {
            inputs.push(file);
        }
    }
    Ok(inputs)
}

/// The closure's `resolution_basis`: every resolution file of `root` that
/// exists, by digest. The sync takes it right after planning, from the
/// files the plan was built from.
pub(crate) fn resolution_basis(root: &ProjectRoot) -> io::Result<crate::comforter::join::Digests> {
    let mut listed = resolution_outputs(root)?;
    listed.extend(resolution_inputs(root)?);
    record::file_digests(root, &listed)
}

/// The files the top-level requirements files include, split by whether
/// they lie in the project.
struct Includes {
    /// Project-relative, the top-level files and [`OUTPUTS`] left out.
    inside: Vec<PathBuf>,
    outside: Vec<PathBuf>,
}

fn includes(root: &ProjectRoot) -> io::Result<Includes> {
    let mut found = Includes {
        inside: Vec::new(),
        outside: Vec::new(),
    };
    let mut sources: Vec<PathBuf> = REQUIREMENTS
        .iter()
        .filter(|top| root.is_input_file(Path::new(top)))
        .map(|top| root.path().join(top))
        .collect();
    if let Some(source) = super::manifest::resolution_requirements_source(root)? {
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    for top in sources {
        for file in super::manifest::include_closure(root, &top)? {
            match super::manifest::held_relative(root, &file) {
                Some(relative) => {
                    let listed = OUTPUTS.iter().any(|output| relative == Path::new(output));
                    if !listed && !found.inside.contains(&relative) {
                        found.inside.push(relative);
                    }
                }
                None => {
                    if !found.outside.contains(&file) {
                        found.outside.push(file);
                    }
                }
            }
        }
    }
    Ok(found)
}

/// Whether a requirements file includes a file outside the project. uv
/// then compiles the flattened text tog read, and the door publishes its
/// lock with no record: a record names files inside the project only.
pub(crate) fn has_external_includes(root: &ProjectRoot) -> io::Result<bool> {
    Ok(!includes(root)?.outside.is_empty())
}

/// The `[tool.uv.workspace]` table of a `pyproject.toml`'s text: its
/// `members` and `exclude` globs. `None` when the file declares no
/// workspace.
fn workspace_globs(text: &str) -> io::Result<Option<(Vec<String>, Vec<String>)>> {
    let table: toml::Table = text.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pyproject.toml: {error}"),
        )
    })?;
    let Some(workspace) = table
        .get("tool")
        .and_then(|tool| tool.get("uv"))
        .and_then(|uv| uv.get("workspace"))
    else {
        return Ok(None);
    };
    let list = |key: &str| -> io::Result<Vec<String>> {
        match workspace.get(key) {
            None => Ok(Vec::new()),
            Some(value) => value
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "pyproject.toml: [tool.uv.workspace] {key} is not a list of \
                             strings, so the workspace's members cannot be named in a \
                             resolution record"
                        ),
                    )
                }),
        }
    };
    Ok(Some((list("members")?, list("exclude")?)))
}

/// The uv workspace members of `root` (its `pyproject.toml`'s
/// `[tool.uv.workspace]`), each a directory relative to the root holding a
/// `pyproject.toml`, the root itself left out. A member glob naming a path
/// that is not plain and inside the project is an error: a member left out
/// would leave a record attesting a manifest it never covered.
pub(crate) fn workspace_members(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let Some(text) = root.read_input_string(Path::new("pyproject.toml"))? else {
        return Ok(Vec::new());
    };
    let Some((members, exclude)) = workspace_globs(&text)? else {
        return Ok(Vec::new());
    };
    let excluded = exclude
        .iter()
        .map(|pattern| compile(pattern.trim_start_matches("./").trim_end_matches('/')))
        .collect::<io::Result<Vec<_>>>()?;
    let mut found: Vec<PathBuf> = Vec::new();
    for pattern in &members {
        for dir in expand(root, pattern)? {
            let path = PathBuf::from(&dir);
            if !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "pyproject.toml names the uv workspace member {pattern:?}, which is not \
                         a plain path inside the project; a resolution record names files \
                         inside the project only"
                    ),
                ));
            }
            if excluded
                .iter()
                .any(|glob| glob.matches_with(&dir, glob_options()))
            {
                continue;
            }
            if root.is_input_file(&path.join("pyproject.toml")) && !found.contains(&path) {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

fn glob_options() -> glob::MatchOptions {
    glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    }
}

fn compile(pattern: &str) -> io::Result<glob::Pattern> {
    glob::Pattern::new(pattern).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pyproject.toml: the uv workspace pattern {pattern:?} is not a glob: {error}"),
        )
    })
}

/// The directories under the project a members entry names: the literal
/// path, or every directory a glob matches. The walk follows no symlink
/// and skips environments and tog's own state.
fn expand(root: &ProjectRoot, pattern: &str) -> io::Result<Vec<String>> {
    let trimmed = pattern.trim_start_matches("./").trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return Ok(Vec::new());
    }
    if !trimmed.contains(['*', '?', '[']) {
        return Ok(vec![trimmed.to_string()]);
    }
    let compiled = compile(trimmed)?;
    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(PathBuf::new(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let listed = root.read_input_dir(if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &dir
        })?;
        let Some(entries) = listed else {
            continue;
        };
        for name in entries {
            if [".venv", ".git", ".tog", "node_modules", "__pycache__"]
                .iter()
                .any(|skip| name == *skip)
            {
                continue;
            }
            let path = dir.join(&name);
            if !matches!(root.entry(&path), Ok(Entry::Directory)) {
                continue;
            }
            let relative = path.to_string_lossy().into_owned();
            if compiled.matches_with(&relative, glob_options()) {
                found.push(relative);
            }
            if depth + 1 < MAX_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Where a uv edit made in `project` writes its lock: the root of the uv
/// workspace that lists `project` as a member, or `project` itself. uv
/// takes the nearest ancestor declaring a workspace; a project it does not
/// list is its own root.
pub(crate) fn lock_root(project: &Path) -> io::Result<PathBuf> {
    for ancestor in project.ancestors().skip(1).take(MAX_DEPTH) {
        let manifest = ancestor.join("pyproject.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(Some(_)) = workspace_globs(&text) else {
            continue;
        };
        let held = ProjectRoot::open(ancestor)?;
        let Ok(relative) = project.strip_prefix(ancestor) else {
            return Ok(project.to_path_buf());
        };
        if workspace_members(&held)?
            .iter()
            .any(|member| member == relative)
        {
            return Ok(ancestor.to_path_buf());
        }
        return Ok(project.to_path_buf());
    }
    Ok(project.to_path_buf())
}

/// `tog attest` for Python. A `uv.lock` project runs `uv lock --locked`; a
/// project tog compiles a requirements lock for reruns that same `uv pip
/// compile` and requires the lock byte-unchanged. Each goes through
/// `door`'s transaction with the record's producer, and publishes nothing:
/// `tog attest` publishes every record only once every check passed.
pub(crate) fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    toolchain: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    let err = |text: String| io::Error::other(text);
    let dir = project.path();
    let (args, index, lock) = if project.is_input_file(Path::new("uv.lock")) {
        let args: Vec<OsString> = vec!["lock".into(), "--locked".into()];
        (args, Index::Project, "uv.lock")
    } else if project.is_input_file(Path::new("requirements.lock.txt")) {
        refuse_foreign_header(project, "requirements.lock.txt")?;
        // The input planning compiles the lock from: a requirements file,
        // or the text tog generates from a pyproject or setup.cfg.
        let input = super::inputs::lock_compile_input(project, toolchain, door)?;
        (
            compile_args(
                &input,
                "requirements.lock.txt",
                toolchain.version("cpython")?,
            ),
            Index::PipCompile,
            "requirements.lock.txt",
        )
    } else if project.is_input_file(Path::new("requirements.in"))
        && project.is_input_file(Path::new("requirements.txt"))
    {
        refuse_foreign_header(project, "requirements.txt")?;
        (
            compile_args(
                "requirements.in",
                "requirements.txt",
                toolchain.version("cpython")?,
            ),
            Index::PipCompile,
            "requirements.txt",
        )
    } else if project.is_input_file(Path::new("pyproject.toml"))
        || project.is_input_file(Path::new("requirements.txt"))
        || project.is_input_file(Path::new("setup.cfg"))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{} has no lock a tool resolved (no uv.lock, requirements.lock.txt, or \
                 requirements.in with its compiled requirements.txt), so there is no lock check \
                 to attest; run `tog` to write one, commit it, then attest",
                dir.display()
            ),
        ));
    } else {
        return Err(err(format!(
            "{} has no Python lock to attest",
            dir.display()
        )));
    };
    if has_external_includes(project)? {
        return Err(err(format!(
            "a requirements file in {} includes a file outside the project, which no resolution \
             record can name; move it into the project, then attest",
            dir.display()
        )));
    }
    let uv = Uv::for_door(door, toolchain)?;
    let refs: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
    let mut spec = crate::tailors::record_spec(&super::tailor::Python, project, uv.tool(), &refs)?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = RecordSlot::default();
    let report = door::run_uv(
        door,
        UvRun {
            uv: &uv,
            lock_root: dir,
            cwd: None,
            args,
            index,
            outputs: resolution_outputs(project)?,
            target: UvTarget::Project {
                record: Some(spec),
                slot: slot.clone(),
            },
            builds: Builds::Probe,
            capture: true,
            policy: None,
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "{lock} in {} is not what the lock check accepts, so it is not attested; run `tog` \
             to bring it up to date and commit the result\n{}",
            dir.display(),
            crate::kernel::resolve::confine::scrub_signing_key(
                String::from_utf8_lossy(&report.stderr).trim()
            )
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("the Python lock check published no record".into()))
}

/// Refuse to check a compiled lock whose header is not tog's: rerunning
/// the compile would rewrite that header, so the check could never pass.
fn refuse_foreign_header(project: &ProjectRoot, output: &str) -> io::Result<()> {
    let text = project
        .read_input_string(Path::new(output))?
        .unwrap_or_default();
    if compiled_by_tog(&text) {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{output} in {} was not compiled by tog (its header names another command), so \
         rerunning the compile would rewrite it and the check cannot pass; delete it, run \
         `tog` to compile it again, commit the result, then attest",
        project.path().display()
    )))
}

/// The `uv pip compile` arguments that write `output` from `input`, the
/// same for the missing-lock door, an edit, and attest, so a rerun writes
/// the same bytes: hashes, the locked interpreter's version, tog's header
/// line, and quiet (the probe captures, and a failure shows uv's words).
pub(crate) fn compile_args(input: &str, output: &str, python_version: &str) -> Vec<OsString> {
    [
        "pip",
        "compile",
        input,
        "--generate-hashes",
        "--quiet",
        "--python-version",
        python_version,
        "--custom-compile-command",
        door::COMPILE_COMMAND,
        "-o",
        output,
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// Whether a compiled lock's header names tog's compile command (the one
/// [`compile_args`] gives uv). uv writes the command after its
/// "autogenerated" line, indented, on a line of its own.
pub(crate) fn compiled_by_tog(lock: &str) -> bool {
    lock.lines()
        .take(4)
        .any(|line| line.trim_start_matches('#').trim() == door::COMPILE_COMMAND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    const WORKSPACE: &str = "[project]\nname = \"root\"\nversion = \"0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\", \"tools/cli\"]\nexclude = [\"packages/skip\"]\n";

    fn workspace(temp: &Path) -> PathBuf {
        let root = temp.join("ws");
        write(&root, "pyproject.toml", WORKSPACE);
        write(
            &root,
            "packages/a/pyproject.toml",
            "[project]\nname = \"a\"\n",
        );
        write(
            &root,
            "packages/b/pyproject.toml",
            "[project]\nname = \"b\"\n",
        );
        write(
            &root,
            "packages/skip/pyproject.toml",
            "[project]\nname = \"skip\"\n",
        );
        write(&root, "packages/empty/README", "no manifest\n");
        write(
            &root,
            "tools/cli/pyproject.toml",
            "[project]\nname = \"cli\"\n",
        );
        root.canonicalize().unwrap()
    }

    #[test]
    fn workspace_members_expand_globs_and_honor_exclude() {
        let temp = TempDir::named("py-ws-members");
        let root = workspace(&temp.0);
        let held = ProjectRoot::open(&root).unwrap();
        assert_eq!(
            workspace_members(&held).unwrap(),
            [
                PathBuf::from("packages/a"),
                PathBuf::from("packages/b"),
                PathBuf::from("tools/cli")
            ]
        );
        let outputs = resolution_outputs(&held).unwrap();
        assert!(outputs.contains(&PathBuf::from("packages/a/pyproject.toml")));
        assert!(!outputs.contains(&PathBuf::from("packages/skip/pyproject.toml")));
        assert!(outputs.contains(&PathBuf::from("uv.lock")));
    }

    #[test]
    fn a_member_outside_the_project_is_refused() {
        let temp = TempDir::named("py-ws-escape");
        let root = temp.0.join("ws");
        write(
            &root,
            "pyproject.toml",
            "[tool.uv.workspace]\nmembers = [\"../elsewhere\"]\n",
        );
        let held = ProjectRoot::open(&root).unwrap();
        let error = workspace_members(&held).unwrap_err();
        assert!(error.to_string().contains("not a plain path"), "{error}");
    }

    #[test]
    fn a_listed_member_locks_at_the_workspace_root() {
        let temp = TempDir::named("py-ws-root");
        let root = workspace(&temp.0);
        assert_eq!(lock_root(&root.join("packages/a")).unwrap(), root);
        assert_eq!(lock_root(&root.join("tools/cli")).unwrap(), root);
        // Excluded, and not a member at all: each its own root.
        let skip = root.join("packages/skip");
        assert_eq!(lock_root(&skip).unwrap(), skip);
        let empty = root.join("packages/empty");
        assert_eq!(lock_root(&empty).unwrap(), empty);
        assert_eq!(lock_root(&root).unwrap(), root);
    }

    #[test]
    fn includes_inside_the_project_are_inputs_and_outside_ones_are_flagged() {
        let temp = TempDir::named("py-includes");
        let root = temp.0.join("proj");
        write(
            &root,
            "requirements.in",
            "-r base.in\n-c constraints/pins.txt\nsix\n",
        );
        write(&root, "base.in", "idna\n");
        write(&root, "constraints/pins.txt", "idna<4\n");
        let held = ProjectRoot::open(&root).unwrap();
        let inputs = resolution_inputs(&held).unwrap();
        assert!(inputs.contains(&PathBuf::from("base.in")), "{inputs:?}");
        assert!(inputs.contains(&PathBuf::from("constraints/pins.txt")));
        assert!(inputs.contains(&PathBuf::from("setup.cfg")));
        assert!(!inputs.contains(&PathBuf::from("requirements.in")));
        assert!(!has_external_includes(&held).unwrap());

        write(&temp.0, "shared.txt", "attrs\n");
        write(&root, "requirements.txt", "-r ../shared.txt\n");
        let held = ProjectRoot::open(&root).unwrap();
        assert!(has_external_includes(&held).unwrap());
    }

    #[test]
    fn requirements_directory_and_configured_sources_are_covered() {
        let temp = TempDir::named("py-directory-inputs");
        let root = temp.0.join("proj");
        write(&root, "requirements/cpu.txt", "-r common.txt\n");
        write(&root, "requirements/common.txt", "six\n");
        let held = ProjectRoot::open(&root).unwrap();
        let inputs = resolution_inputs(&held).unwrap();
        assert!(inputs.contains(&PathBuf::from("requirements/cpu.txt")));
        assert!(inputs.contains(&PathBuf::from("requirements/common.txt")));
        assert!(inputs.contains(&PathBuf::from("tog.toml")));
        assert!(!has_external_includes(&held).unwrap());

        write(&root, "tog.toml", "[python]\nrequirements = 'custom.in'\n");
        write(&root, "custom.in", "-c pins.txt\nsix\n");
        write(&root, "pins.txt", "six<2\n");
        let inputs = resolution_inputs(&held).unwrap();
        assert!(inputs.contains(&PathBuf::from("custom.in")));
        assert!(inputs.contains(&PathBuf::from("pins.txt")));
        write(&temp.0, "external.in", "six\n");
        write(
            &root,
            "tog.toml",
            "[python]\nrequirements = '../external.in'\n",
        );
        assert!(has_external_includes(&held).unwrap());
    }

    /// The header uv writes for `--custom-compile-command tog`, and one a
    /// direct run wrote.
    #[test]
    fn a_lock_compiled_by_tog_is_recognized_by_its_header() {
        let ours = "# This file was autogenerated by uv via the following command:\n#    tog\nsix==1.16.0 \\\n";
        assert!(compiled_by_tog(ours));
        let theirs = "# This file was autogenerated by uv via the following command:\n#    uv pip compile requirements.in -o requirements.txt\nsix==1.16.0\n";
        assert!(!compiled_by_tog(theirs));
        let args = compile_args("requirements.in", "requirements.txt", "3.12.8");
        assert!(args.iter().any(|arg| arg == "--custom-compile-command"));
        assert_eq!(args.last().unwrap(), "requirements.txt");
    }
}

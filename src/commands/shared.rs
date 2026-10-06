//! Helpers two or more commands share: project-directory resolution and
//! exit-code plumbing. Ecosystem-specific input loaders stay in their
//! respective tailors.

use crate::comforter::{self, toolchain::EcosystemInput};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::toolchain::{lock, runtime, Selected};
use crate::tailors::RegistryTool;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) use crate::kernel::context::project_dir;
pub(crate) use crate::tailors::{
    CachedTool, DepSpec, EditVerb, ManifestEdit, PackageRegistry, Tailor,
};

/// The ecosystems `tog add` can choose, in registry order, each with the
/// public registry it names (`Tailor::package_registry`).
pub(crate) fn edit_tailors() -> Vec<(&'static dyn Tailor, PackageRegistry)> {
    crate::tailors::registry()
        .iter()
        .filter_map(|tailor| {
            tailor
                .package_registry()
                .map(|registry| (*tailor, registry))
        })
        .collect()
}

/// The project a command run at some directory belongs to
/// ([`project_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectLocation {
    pub root: PathBuf,
    /// tog has marked `root` as a project: it holds a projection
    /// (`.tog/closures`) or a toolchain lock entry. An unmarked root only
    /// has manifests.
    pub marked: bool,
    /// The ecosystems whose inputs are at `root` (`inspect::detected`).
    pub detected: Vec<&'static str>,
}

/// Which project am I in? The one answer every command uses: `run`,
/// `sync`, `tog <script>`, `fmt`, `add`, `x` and toolchain selection.
///
/// 1. The nearest ancestor tog has marked: a projection (`.tog/closures`)
///    or a toolchain lock entry, a dangling symlink included, so a lock
///    that cannot be read refuses instead of being skipped. A marked root
///    wins over a nearer manifest, so a nested `package.json` under a
///    synced root (a docs site) keeps belonging to that root, and an outer
///    checkout never decides an inner project's runtime. A bare `.tog`
///    (a journal left by a first sync that failed) is not a mark: it would
///    claim every unsynced project below it. `$HOME/.tog` is tog's own
///    home, not a project.
///    A marked root that holds no project input of its own (a stray lock
///    above the real project) does not hide a manifest nearer to `cwd`:
///    rule 2 is tried first, and the marked root is the answer only when
///    rule 2 finds nothing.
/// 2. Otherwise the nearest ancestor with any project input, so `tog run`
///    from `src/` of a never-synced project finds the project.
/// 3. Otherwise none.
pub(crate) fn project_for(cwd: &Path) -> io::Result<Option<ProjectLocation>> {
    // `cwd` comes from `getcwd`, which resolves symlinks, so a `$HOME`
    // that is itself a symlink is resolved before the two are compared.
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.canonicalize().unwrap_or(home));
    project_for_in(cwd, home.as_deref())
}

fn project_for_in(cwd: &Path, home: Option<&Path>) -> io::Result<Option<ProjectLocation>> {
    let marked = cwd.ancestors().find(|dir| {
        dir.join(lock::LOCK_PATH).symlink_metadata().is_ok()
            || (dir.join(".tog/closures").is_dir() && home != Some(*dir))
    });
    if let Some(root) = marked {
        let detected = crate::commands::inspect::detected(root)?;
        if !detected.is_empty() {
            return Ok(Some(ProjectLocation {
                root: root.to_path_buf(),
                marked: true,
                detected,
            }));
        }
        return Ok(Some(match nearest_manifest(cwd)? {
            Some(nearer) => nearer,
            None => ProjectLocation {
                root: root.to_path_buf(),
                marked: true,
                detected,
            },
        }));
    }
    nearest_manifest(cwd)
}

/// The nearest ancestor of `cwd` with any project input, marked or not.
/// `add`, `remove` and `update` edit this one: in a synced Cargo, npm or
/// uv workspace only the workspace root is marked, and the manifest to
/// edit is the member's, which the tailor finds from the member directory.
pub(crate) fn nearest_manifest(cwd: &Path) -> io::Result<Option<ProjectLocation>> {
    for dir in cwd.ancestors() {
        let detected = crate::commands::inspect::detected(dir)?;
        if !detected.is_empty() {
            return Ok(Some(ProjectLocation {
                root: dir.to_path_buf(),
                marked: false,
                detected,
            }));
        }
    }
    Ok(None)
}

/// The directory a command at `cwd` works in: its project's root, or `cwd`
/// itself outside any project.
pub(crate) fn project_root(cwd: &Path) -> io::Result<PathBuf> {
    Ok(project_for(cwd)?.map_or_else(|| cwd.to_path_buf(), |location| location.root))
}

/// The steps of the project script `name` at `root`, before any sync:
/// the first tailor's `Tailor::project_script`, `None` when no ecosystem
/// has such a script. `tog <script>` and `tog fmt` ask this to decide
/// whether a word is a script; `tog run` reads the projected script once
/// synced (`Tailor::projected_script`).
pub(crate) fn package_script(
    root: &Path,
    name: &str,
    args: &[String],
) -> io::Result<Option<Vec<(String, String)>>> {
    for tailor in crate::tailors::registry() {
        if let Some(steps) = tailor.project_script(root, name, args)? {
            return Ok(Some(steps));
        }
    }
    Ok(None)
}

/// What a projection under `dir` contributes to a child environment: the
/// PATH prefixes every tailor wants ahead of the inherited PATH, with the
/// variables it sets and removes applied to `command`. `cwd` is where the
/// user ran from and `cmd` the command line, which some ecosystems refuse.
///
/// `tog run` spawns that command and `tog env` prints it. Both go through
/// here so neither can drift from what a projection really is.
pub(crate) fn projected_env(
    ctx: &crate::kernel::context::Context,
    dir: &Path,
    cwd: &Path,
    cmd: &[String],
    command: &mut std::process::Command,
) -> io::Result<Vec<String>> {
    // Held once: every closure and projection the environment is built
    // from is read through this descriptor.
    let project = crate::kernel::fsroot::ProjectRoot::open(dir)?;
    let mut prefix = Vec::new();
    for tailor in crate::tailors::registry() {
        prefix.extend(tailor.run_env(ctx, &project, cwd, cmd, command)?);
    }
    Ok(prefix)
}

/// What toolchain resolution needs to know about each detected ecosystem:
/// its shipped catalog, its local-toolchain reader, and the helper
/// releases its lock section pins.
pub(crate) fn ecosystem_inputs(present: &[&dyn Tailor]) -> io::Result<Vec<EcosystemInput>> {
    let mut out = Vec::new();
    for tailor in present {
        out.push(EcosystemInput {
            lock_ecosystem: tailor.lock_ecosystem().to_string(),
            catalog: tailor.toolchain_catalog()?,
            external: tailor.external_toolchain(),
            helper_pins: tailor.helper_pins()?,
            declared_helpers: tailor.helpers().iter().map(|h| h.to_string()).collect(),
        });
    }
    Ok(out)
}

/// The toolchain a command that realizes a runtime outside `sync` uses
/// (`x`, and the delegated `add`/`remove`/`update` edits): the committed
/// lock of the nearest project at or above `cwd` when there is one, the
/// catalog's selection for that project's sources or the shipped default
/// otherwise. Nothing here
/// chooses a version of its own or writes a lock, and a stale lock refuses
/// exactly as a sync would.
pub(crate) fn selected_toolchain(
    platform: Platform,
    cwd: &Path,
    ecosystem: &str,
) -> io::Result<Selected> {
    let tailor = crate::tailors::by_id(ecosystem).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported ecosystem '{ecosystem}'"),
        )
    })?;
    // The project's committed lock when it has one, and the catalog's
    // selection for its sources otherwise. A lock that cannot be read
    // refuses here: it must not fall through to the shipped default.
    if let Some(location) = project_for(cwd)? {
        let root = ProjectRoot::open(&location.root)?;
        // A registry tool of an ecosystem this project does not have (a
        // Python tool in a Cargo project) is not the project's to pin: when
        // the committed lock has no section for it, it runs on the shipped
        // runtime. An ecosystem the project has keeps the lock's refusals,
        // and with no lock the project's own sources decide, as below.
        let lock_ecosystem = tailor.lock_ecosystem();
        // Detected again through this root, so the ecosystems and the lock
        // are those of one directory: a project put at the path since
        // `project_for` looked cannot borrow the earlier answer.
        let has_ecosystem = crate::tailors::detected_in(&root)?
            .iter()
            .any(|found| found.lock_ecosystem() == lock_ecosystem);
        if !has_ecosystem && lock_names(&root, lock_ecosystem)? == Some(false) {
            return runtime::shipped(&tailor.toolchain_catalog()?);
        }
        let resolved = comforter::toolchain::resolve(
            &root,
            platform,
            ecosystem_inputs(&[tailor])?,
            comforter::toolchain::Mode::ReadOnly,
            false,
        )?;
        return resolved.get(tailor.lock_ecosystem()).cloned();
    }
    runtime::shipped(&tailor.toolchain_catalog()?)
}

/// Whether the project's committed toolchain lock has a section for
/// `ecosystem`, or `None` when there is no lock. A lock that cannot be
/// read refuses.
fn lock_names(root: &ProjectRoot, ecosystem: &str) -> io::Result<Option<bool>> {
    lock::ToolchainLock::read_bytes_via(root)?
        .map(|bytes| {
            Ok(lock::ToolchainLock::parse(&bytes)?
                .ecosystem(ecosystem)
                .is_some())
        })
        .transpose()
}

/// The helper toolchains (`Tailor::helpers`) `ecosystem` builds with at
/// `cwd`, outside `sync`, decided by the rule sync uses
/// (`tailors::helper_selections`): a helper ecosystem the nearest project
/// has is that project's selection, read as [`selected_toolchain`] reads
/// it; any other gets the tailor's default. Only `names` are decided.
pub(crate) fn selected_helpers(
    platform: Platform,
    cwd: &Path,
    ecosystem: &str,
    names: &[&str],
) -> io::Result<std::collections::BTreeMap<String, Selected>> {
    let tailor = crate::tailors::by_id(ecosystem).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported ecosystem '{ecosystem}'"),
        )
    })?;
    // The project `selected_toolchain` reads.
    let location = project_for(cwd)?;
    let project = location.as_ref().map(|location| location.root.as_path());
    let present = match project {
        Some(dir) => crate::tailors::detected(dir)?,
        None => Vec::new(),
    };
    let mut selections = std::collections::BTreeMap::new();
    for helper in names {
        if let (Some(dir), Some(owner)) = (
            project,
            present
                .iter()
                .find(|tailor| tailor.lock_ecosystem() == *helper),
        ) {
            selections.insert(
                (*helper).to_string(),
                selected_toolchain(platform, dir, owner.id())?,
            );
        }
    }
    let mut helpers = crate::tailors::helper_selections(tailor, &selections)?;
    helpers.retain(|helper, _| names.contains(&helper.as_str()));
    Ok(helpers)
}

/// The tool `tog x` installs and launches for `ecosystem`
/// (`Tailor::registry_tool`). An ecosystem with no registry tool answers
/// `tog x does not support <id>`.
pub(crate) fn registry_tool(ecosystem: &str) -> io::Result<&'static dyn RegistryTool> {
    crate::tailors::by_id(ecosystem)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported ecosystem '{ecosystem}'"),
            )
        })?
        .registry_tool()
}

/// Every ecosystem `tog x` can run a tool from, as (tailor id, tool), in
/// registry order.
pub(crate) fn registry_tools() -> Vec<(&'static str, &'static dyn RegistryTool)> {
    crate::tailors::registry()
        .iter()
        .filter_map(|tailor| Some((tailor.id(), tailor.registry_tool().ok()?)))
        .collect()
}

pub(crate) fn child_status_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

pub(crate) fn no_inputs() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "nothing to sync here: no manifest found (looked for {}; see 'tog help inputs')",
            input_files()
        ),
    )
}

/// Every file any tailor detects a project by ([`Tailor::input_files`]),
/// in registry order: the one list the "no project" messages print.
pub(crate) fn input_files() -> String {
    crate::tailors::registry()
        .iter()
        .map(|tailor| tailor.input_files())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What an edit or a lock check borrows from its command: toolchain
/// selection outside a sync, and the `tog x` cache a pinned package
/// manager lives in.
pub(crate) struct CommandHost {
    pub platform: Platform,
}

impl crate::tailors::EditHost for CommandHost {
    fn toolchain(&self, dir: &Path, ecosystem: &str) -> io::Result<Selected> {
        selected_toolchain(self.platform, dir, ecosystem)
    }

    fn cached_tool(
        &self,
        ecosystem: &str,
        project: &Path,
        package: &str,
        version: &str,
        door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<CachedTool> {
        crate::commands::x::realize_cached_tool(project, ecosystem, package, version, door)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// A CPython version the shipped catalog has that is not the default,
    /// so a source naming it is visibly honored.
    fn a_non_default_python() -> String {
        let catalog = crate::tailors::by_id("python")
            .unwrap()
            .toolchain_catalog()
            .unwrap();
        let default = runtime::shipped(&catalog)
            .unwrap()
            .version("cpython")
            .unwrap()
            .to_string();
        catalog
            .bundles()
            .iter()
            .filter(|bundle| Platform::ALL.iter().all(|p| bundle.complete_for(*p)))
            .filter_map(|bundle| bundle.component("cpython").map(|c| c.version.clone()))
            .find(|version| *version != default)
            .expect("the shipped catalog needs a second CPython")
    }

    /// A registry tool of an ecosystem the project does not have runs on
    /// that ecosystem's shipped runtime, even beside a lock with no section
    /// for it. A project that has the ecosystem still refuses a lock
    /// missing its section, and a section the lock does pin is used.
    #[test]
    fn a_tool_outside_the_project_ecosystems_runs_on_the_shipped_runtime() {
        let platform = Platform::host().unwrap();
        let t = TempDir::new();
        let lock_for = |dir: &Path, ecosystems: &[&str]| {
            let root = ProjectRoot::open(dir).unwrap();
            let tailors: Vec<_> = ecosystems
                .iter()
                .map(|id| crate::tailors::by_id(id).unwrap())
                .collect();
            comforter::toolchain::resolve(
                &root,
                platform,
                ecosystem_inputs(&tailors).unwrap(),
                comforter::toolchain::Mode::Update { only: None },
                false,
            )
            .unwrap()
            .pending
            .unwrap()
            .publish_via(&root)
            .unwrap();
        };

        // A Cargo-only project with its Rust lock: Python and Node tools.
        let cargo = t.0.join("cargo");
        std::fs::create_dir_all(cargo.join("src")).unwrap();
        std::fs::write(
            cargo.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(cargo.join("src/main.rs"), "fn main() {}\n").unwrap();
        lock_for(&cargo, &["cargo"]);
        for ecosystem in ["python", "node"] {
            let selected = selected_toolchain(platform, &cargo, ecosystem).unwrap();
            assert_eq!(
                selected.source,
                crate::kernel::toolchain::Source::Shipped,
                "{ecosystem}"
            );
        }

        // A Python project whose lock holds only another section refuses.
        let python = t.0.join("python");
        std::fs::create_dir_all(&python).unwrap();
        std::fs::write(
            python.join("pyproject.toml"),
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            python.join("Cargo.toml"),
            std::fs::read(cargo.join("Cargo.toml")).unwrap(),
        )
        .unwrap();
        std::fs::create_dir_all(python.join("src")).unwrap();
        std::fs::write(python.join("src/main.rs"), "fn main() {}\n").unwrap();
        lock_for(&python, &["cargo"]);
        let error = selected_toolchain(platform, &python, "python").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("has no [toolchain.python] section"),
            "{error}"
        );

        // Mixed and locked for both: the lock decides.
        lock_for(&python, &["cargo", "python"]);
        let selected = selected_toolchain(platform, &python, "python").unwrap();
        assert_eq!(selected.source, crate::kernel::toolchain::Source::Lock);
    }

    #[test]
    fn selected_toolchain_reads_the_project_not_the_shipped_default() {
        let platform = Platform::host().unwrap();
        let t = TempDir::new();
        let other = a_non_default_python();

        // No project at all: the shipped default, whatever a stray
        // version file above says.
        let bare = t.0.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::write(t.0.join(".python-version"), format!("{other}\n")).unwrap();
        let shipped = selected_toolchain(platform, &bare, "python").unwrap();
        assert_eq!(shipped.source, crate::kernel::toolchain::Source::Shipped);
        assert_ne!(shipped.version("cpython").unwrap(), other);

        // A projection with no lock resolves the project's own sources,
        // exactly as the sync that creates its lock would.
        let project = t.0.join("project");
        std::fs::create_dir_all(project.join(".tog/closures")).unwrap();
        std::fs::write(project.join(".python-version"), format!("{other}\n")).unwrap();
        let selected = selected_toolchain(platform, &project.join("src"), "python").unwrap();
        assert_eq!(selected.version("cpython").unwrap(), other);
        assert_eq!(selected.source, crate::kernel::toolchain::Source::Shipped);

        // A committed lock decides, even with no `.tog` beside it, and a
        // lock its inputs have moved away from refuses as a sync would.
        let locked = t.0.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join(".python-version"), format!("{other}\n")).unwrap();
        let root = ProjectRoot::open(&locked).unwrap();
        let python = crate::tailors::by_id("python").unwrap();
        let created = comforter::toolchain::resolve(
            &root,
            platform,
            ecosystem_inputs(&[python]).unwrap(),
            comforter::toolchain::Mode::Writable,
            false,
        )
        .unwrap();
        created.pending.unwrap().publish_via(&root).unwrap();
        let honored = selected_toolchain(platform, &locked.join("src"), "python").unwrap();
        assert_eq!(honored.source, crate::kernel::toolchain::Source::Lock);
        assert_eq!(honored.version("cpython").unwrap(), other);
        let default = shipped.version("cpython").unwrap();
        std::fs::write(locked.join(".python-version"), format!("{default}\n")).unwrap();
        let error = selected_toolchain(platform, &locked, "python").unwrap_err();
        assert!(error.to_string().contains("is stale for python"), "{error}");
        assert!(!locked.join(".tog").exists());

        // A lock entry that is not a regular file refuses; it never falls
        // through to the default.
        let broken = t.0.join("broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::os::unix::fs::symlink("nowhere", broken.join(lock::LOCK_PATH)).unwrap();
        let error = selected_toolchain(platform, &broken, "python").unwrap_err();
        assert!(error.to_string().contains("tog-toolchain.toml"), "{error}");
        let dir_lock = t.0.join("dir-lock");
        std::fs::create_dir_all(dir_lock.join(lock::LOCK_PATH)).unwrap();
        let error = selected_toolchain(platform, &dir_lock, "python").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("tog-toolchain.toml is not a regular file"),
            "{error}"
        );
    }

    #[test]
    fn project_for_prefers_a_marked_root_then_the_nearest_manifest() {
        let t = TempDir::new();
        // Only answers inside the temporary directory count: with
        // `TMPDIR` under `$HOME`, the walk without a home goes on up to
        // the developer's own `~/.tog`.
        let none = |dir: &Path| {
            project_for_in(dir, None)
                .unwrap()
                .filter(|location| location.root.starts_with(&t.0))
        };
        // A synced root keeps a plain node_modules and a nested manifest
        // below it (a docs site).
        let root = t.0.join("proj");
        std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();
        let docs = root.join("docs");
        std::fs::create_dir_all(docs.join("node_modules")).unwrap();
        std::fs::write(docs.join("package.json"), "{}").unwrap();
        assert_eq!(none(&docs).unwrap().root, root);
        assert!(none(&root).unwrap().marked);
        // A lock entry marks a project too, a dangling symlink included.
        let locked = t.0.join("locked");
        std::fs::create_dir_all(locked.join("src")).unwrap();
        std::os::unix::fs::symlink("missing", locked.join(lock::LOCK_PATH)).unwrap();
        assert_eq!(none(&locked.join("src")).unwrap().root, locked);
        // Unmarked: the nearest manifest above.
        let fresh = t.0.join("fresh");
        std::fs::create_dir_all(fresh.join("src/deep")).unwrap();
        std::fs::write(fresh.join("package.json"), "{}").unwrap();
        let location = none(&fresh.join("src/deep")).unwrap();
        assert_eq!(location.root, fresh);
        assert!(!location.marked);
        assert_eq!(location.detected, ["node"]);
        // A bare `.tog` above an unsynced project does not claim it.
        let stray = t.0.join("code");
        std::fs::create_dir_all(stray.join(".tog/journal")).unwrap();
        std::fs::create_dir_all(stray.join("app")).unwrap();
        std::fs::write(stray.join("app/go.mod"), "module app\n").unwrap();
        assert_eq!(none(&stray.join("app")).unwrap().root, stray.join("app"));
        // A marked directory with no project input of its own does not
        // hide the manifest nearer the user. With nothing nearer, it is
        // still the answer.
        let lone = t.0.join("lone");
        let app = lone.join("app");
        std::fs::create_dir_all(app.join("src")).unwrap();
        std::fs::write(lone.join(lock::LOCK_PATH), "").unwrap();
        let location = none(&app.join("src")).unwrap();
        assert_eq!(location.root, lone);
        assert!(location.marked);
        std::fs::write(app.join("package.json"), "{}").unwrap();
        let location = none(&app.join("src")).unwrap();
        assert_eq!(location.root, app);
        assert_eq!(location.detected, ["node"]);
        // An edit goes to the nearest manifest, under a marked root too:
        // a workspace member, not the workspace root.
        assert_eq!(nearest_manifest(&docs).unwrap().unwrap().root, docs);
        // Nothing at all.
        let outside = t.0.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert_eq!(none(&outside), None);
    }

    #[test]
    fn the_tog_home_is_not_a_project() {
        let t = TempDir::new();
        let home = t.0.join("home");
        // tog's home holds `x` environments and the store, never a
        // projection, but its shape must not matter either way.
        std::fs::create_dir_all(home.join(".tog/closures")).unwrap();
        let work = home.join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        assert_eq!(
            project_for_in(&work.join("src"), Some(&home))
                .unwrap()
                .filter(|location| location.root.starts_with(&t.0)),
            None
        );
        // Without the home rule the walk would stop at `~`.
        assert_eq!(
            project_for_in(&work.join("src"), None)
                .unwrap()
                .unwrap()
                .root,
            home
        );
        std::fs::write(work.join("package.json"), "{}").unwrap();
        assert_eq!(
            project_for_in(&work.join("src"), Some(&home))
                .unwrap()
                .unwrap()
                .root,
            work
        );
    }

    /// The "no manifest found" list and `tog help inputs` name the same
    /// files: every file a tailor detects by is in the help topic.
    #[test]
    fn every_detected_input_file_is_in_the_help() {
        let help = crate::cli::inputs();
        for tailor in crate::tailors::registry() {
            for item in tailor.input_files().split(", ") {
                let name = item.split([' ', '{']).next().unwrap();
                // `pyproject.toml ([project], [tool.poetry], ...)`: the
                // tables qualify the file before them.
                if name.starts_with('[') {
                    continue;
                }
                assert!(
                    help.contains(name),
                    "{}: {name} is not in 'tog help inputs'",
                    tailor.id()
                );
            }
        }
        let error = no_inputs().to_string();
        assert!(error.contains("package.json, package-lock.json"), "{error}");
        assert!(error.contains("setup.cfg"), "{error}");
        assert!(error.contains("see 'tog help inputs'"), "{error}");
    }

    #[test]
    fn package_script_reads_the_root_package_json() {
        let t = TempDir::new();
        assert_eq!(package_script(&t.0, "test", &[]).unwrap(), None);
        std::fs::write(
            t.0.join("package.json"),
            r#"{"scripts":{"test":"node t.js"}}"#,
        )
        .unwrap();
        assert!(package_script(&t.0, "test", &[]).unwrap().is_some());
        assert_eq!(package_script(&t.0, "lint", &[]).unwrap(), None);
    }
}

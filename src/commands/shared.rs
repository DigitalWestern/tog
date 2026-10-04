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
    CachedTool, DepSpec, EditHost, EditVerb, ManifestEdit, PackageRegistry, Tailor,
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
    /// tog has marked `root` as a project: it holds a `.tog` directory or
    /// a toolchain lock entry. An unmarked root only has manifests.
    pub marked: bool,
    /// The ecosystems whose inputs are at `root` (`inspect::detected`).
    pub detected: Vec<&'static str>,
}

/// Which project am I in? The one answer every command uses: `run`,
/// `sync`, `tog <script>`, `fmt`, `add`, `x` and toolchain selection.
///
/// 1. The nearest ancestor tog has marked: a `.tog` directory (closures,
///    the journal, the resolution record) or a toolchain lock entry, a
///    dangling symlink included, so a lock that cannot be read refuses
///    instead of being skipped. A marked root wins over a nearer manifest,
///    so a nested `package.json` under a synced root (a docs site) keeps
///    belonging to that root, and an outer checkout never decides an inner
///    project's runtime. `$HOME/.tog` is tog's own home, not a project.
/// 2. Otherwise the nearest ancestor with any project input, so `tog run`
///    from `src/` of a never-synced project finds the project.
/// 3. Otherwise none.
pub(crate) fn project_for(cwd: &Path) -> io::Result<Option<ProjectLocation>> {
    project_for_in(cwd, std::env::var_os("HOME").map(PathBuf::from).as_deref())
}

fn project_for_in(cwd: &Path, home: Option<&Path>) -> io::Result<Option<ProjectLocation>> {
    let marked = cwd.ancestors().find(|dir| {
        dir.join(lock::LOCK_PATH).symlink_metadata().is_ok()
            || (dir.join(".tog").is_dir() && home != Some(*dir))
    });
    if let Some(root) = marked {
        return Ok(Some(ProjectLocation {
            root: root.to_path_buf(),
            marked: true,
            detected: crate::commands::inspect::detected(root)?,
        }));
    }
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

/// The steps of the `package.json` script `name` at `root`, before any
/// sync: `None` when there is no `package.json` or no such script. `tog
/// <script>` and `tog fmt` ask this to decide whether a word is a script;
/// `tog run` reads the projected `package.json` once synced.
pub(crate) fn package_script(
    root: &Path,
    name: &str,
    args: &[String],
) -> io::Result<Option<Vec<(String, String)>>> {
    let package_json = root.join("package.json");
    if !package_json.is_file() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&package_json)?;
    crate::tailors::node::script_commands_from_package(&json, name, args)
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
        "nothing to sync here: no manifest found (looked for requirements.lock.txt, requirements.txt, pyproject.toml ([project], [tool.poetry], [dependency-groups]), setup.cfg, setup.py, requirements/{common.txt,base.txt,requirements.in,cpu.txt,cuda.txt,rocm.txt,xpu.txt}, package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.toml, go.mod, Gemfile, mix.exs, and .csproj/packages.lock.json)",
    )
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

        // A `.tog` boundary with no lock resolves the project's own
        // sources, exactly as the sync that creates its lock would.
        let project = t.0.join("project");
        std::fs::create_dir_all(project.join(".tog")).unwrap();
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
        let none = |dir: &Path| project_for_in(dir, None).unwrap();
        // A synced root keeps a plain node_modules and a nested manifest
        // below it (a docs site).
        let root = t.0.join("proj");
        std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
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
        // Nothing at all.
        let outside = t.0.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert_eq!(none(&outside), None);
        assert_eq!(project_root(&outside).unwrap(), outside);
    }

    #[test]
    fn the_tog_home_is_not_a_project() {
        let t = TempDir::new();
        let home = t.0.join("home");
        std::fs::create_dir_all(home.join(".tog/store")).unwrap();
        let work = home.join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        assert_eq!(
            project_for_in(&work.join("src"), Some(&home)).unwrap(),
            None
        );
        std::fs::write(work.join("package.json"), "{}").unwrap();
        assert_eq!(
            project_for_in(&work.join("src"), Some(&home))
                .unwrap()
                .unwrap()
                .root,
            work
        );
        // Without the home rule the walk would stop at `~`.
        assert_eq!(
            project_for_in(&work.join("src"), None)
                .unwrap()
                .unwrap()
                .root,
            home
        );
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

//! Helpers two or more commands share: project-directory resolution and
//! exit-code plumbing. Ecosystem-specific input loaders stay in their
//! respective tailors.

use crate::comforter::{self, toolchain::EcosystemInput};
use crate::commands::inspect;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::toolchain::{lock, runtime, Selected};
use crate::tailors::{RegistryTool, Tailor};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) use crate::kernel::context::project_dir;

/// Nearest ancestor that is a tog projection: every tailor writes
/// `.tog/closures/<eco>.json`, so that directory is the proof. A plain
/// `node_modules` or `.venv` in a subdirectory (a docs site, a vendored
/// tool) is NOT a projection and must not stop the walk-up.
pub(crate) fn projected_root(cwd: &Path) -> PathBuf {
    cwd.ancestors()
        .find(|d| d.join(".tog/closures").is_dir())
        .unwrap_or(cwd)
        .to_path_buf()
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
    let mut prefix = Vec::new();
    for tailor in crate::tailors::registry() {
        prefix.extend(tailor.run_env(ctx, dir, cwd, cmd, command)?);
    }
    Ok(prefix)
}

/// What toolchain resolution needs to know about each detected ecosystem:
/// its shipped catalog, and what a closure written before the lock existed
/// proves (`comforter::toolchain::legacy_evidence`).
pub(crate) fn ecosystem_inputs(
    dir: &Path,
    present: &[&dyn Tailor],
) -> io::Result<Vec<EcosystemInput>> {
    let closures = inspect::closures(dir)?;
    let mut out = Vec::new();
    for tailor in present {
        let legacy = closures
            .iter()
            .find(|closure| closure.ecosystem == tailor.id())
            .and_then(|closure| comforter::toolchain::legacy_evidence(*tailor, &closure.envelope));
        out.push(EcosystemInput {
            lock_ecosystem: tailor.lock_ecosystem().to_string(),
            catalog: tailor.toolchain_catalog()?,
            legacy,
        });
    }
    Ok(out)
}

/// The toolchain a command that realizes a runtime outside `sync` uses
/// (`x`, and the delegated `add`/`remove`/`update` edits): the committed
/// lock of the nearest project at or above `cwd` when there is one, seeded
/// from a pre-lock closure or the shipped catalog otherwise. Nothing here
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
    for dir in cwd.ancestors() {
        // Any entry under the lock's name decides where to look, a dangling
        // symlink or a directory included: reading through the held root
        // descriptor is what refuses those, and a lock that cannot be read
        // must not fall through to the shipped default. A `.tog` directory
        // is an explicit project boundary too, so an outer checkout's lock
        // never decides an inner project's runtime; resolving there honors
        // the project's own sources and a pre-lock closure.
        let lock_entry = dir.join(lock::LOCK_PATH).symlink_metadata().is_ok();
        if lock_entry || dir.join(".tog").is_dir() {
            let root = ProjectRoot::open(dir)?;
            let resolved = comforter::toolchain::resolve(
                &root,
                platform,
                ecosystem_inputs(dir, &[tailor])?,
                comforter::toolchain::Mode::ReadOnly,
                false,
            )?;
            return resolved.get(tailor.lock_ecosystem()).cloned();
        }
    }
    runtime::shipped(&tailor.toolchain_catalog()?)
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

        // A lock entry that is not a regular file refuses; it never falls
        // through to the default.
        let broken = t.0.join("broken");
        std::fs::create_dir_all(&broken).unwrap();
        std::os::unix::fs::symlink("nowhere", broken.join(lock::LOCK_PATH)).unwrap();
        let error = selected_toolchain(platform, &broken, "python").unwrap_err();
        assert!(error.to_string().contains("tog-toolchain.toml"), "{error}");
        let dir_lock = t.0.join("dir-lock");
        std::fs::create_dir_all(dir_lock.join(lock::LOCK_PATH)).unwrap();
        assert!(selected_toolchain(platform, &dir_lock, "python").is_err());
    }

    #[test]
    fn projected_root_skips_plain_node_modules() {
        let t = TempDir::new();
        let root = t.0.join("proj");
        std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
        let sub = root.join("docs");
        std::fs::create_dir_all(sub.join("node_modules")).unwrap();
        assert_eq!(projected_root(&sub), root);
        assert_eq!(projected_root(&root), root);
        let outside = t.0.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert_eq!(projected_root(&outside), outside);
    }
}

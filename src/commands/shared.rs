//! Helpers two or more commands share: project-directory resolution and
//! exit-code plumbing. Ecosystem-specific input loaders stay in their
//! respective tailors.

use crate::comforter::{self, toolchain::EcosystemInput};
use crate::commands::inspect;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::toolchain::{lock, runtime, Selected};
use crate::tailors::Tailor;
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

/// What toolchain resolution needs to know about each detected ecosystem:
/// its shipped catalog, and what a closure written before the lock existed
/// proves. A closure that already records a `toolchain` body key was
/// written by a lock-aware sync and needs no seeding; one for a foreign
/// platform still yields evidence, carrying its own platform, because the
/// seed refuses on that platform rather than guessing from the host.
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
            .filter(|closure| closure.body.get("toolchain").is_none())
            .map(|closure| {
                let platform = closure.platform.as_deref().and_then(Platform::from_triple);
                tailor.legacy_toolchain_evidence(tailor.id(), platform, &closure.body)
            });
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
        if dir.join(lock::LOCK_PATH).is_file() {
            // Reading through the held root descriptor is what refuses a
            // symlinked lock; the test above only decides where to look.
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
        // A `.tog` directory is an explicit project boundary, so an outer
        // checkout's lock never decides an inner project's runtime.
        if dir.join(".tog").is_dir() {
            break;
        }
    }
    runtime::shipped(&tailor.toolchain_catalog()?)
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

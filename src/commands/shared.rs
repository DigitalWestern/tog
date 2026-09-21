//! Helpers two or more commands share: project-directory resolution and
//! exit-code plumbing. Ecosystem-specific input loaders stay in their
//! respective tailors.

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

//! Conservative input coverage for executable project manifests. The
//! resolver sees only the listed project files and its private scratch.

use super::snapshot::PathGlob;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use std::io;
use std::path::{Path, PathBuf};

/// List every regular file the project snapshot permits, except outputs.
/// A symlink cannot be represented by the receipt's regular-file digests.
/// Refuse it rather than attest a partial executable-manifest input set.
pub(crate) fn project_files(
    project: &ProjectRoot,
    excludes: &[&str],
    outputs: &[&str],
) -> io::Result<Vec<PathBuf>> {
    let excludes = excludes
        .iter()
        .map(|pattern| PathGlob::new(pattern))
        .collect::<io::Result<Vec<_>>>()?;
    let mut files = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let dir = if relative.as_os_str().is_empty() {
            project.try_clone()?
        } else {
            project.subdir(&relative)?.ok_or_else(|| {
                io::Error::other(format!(
                    "{} vanished while listing resolution inputs",
                    relative.display()
                ))
            })?
        };
        for name in dir.read_dir(Path::new("."))?.unwrap_or_default() {
            let path = relative.join(&name);
            if excludes.iter().any(|pattern| pattern.matches(&path))
                || outputs.iter().any(|output| path == Path::new(output))
            {
                continue;
            }
            match dir.entry(Path::new(&name))? {
                Entry::Regular => files.push(path),
                Entry::Directory => pending.push(path),
                Entry::Symlink => {
                    return Err(io::Error::other(format!(
                        "{} is a symlink in executable-manifest resolution inputs; \
                         use regular files inside the project so the receipt covers them",
                        path.display()
                    )));
                }
                _ => {}
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn coverage_includes_nested_code_and_data_but_not_hidden_resolver_state() {
        let temp = TempDir::new();
        for directory in ["apps/web", "config/nested", ".tog", ".git", "deps"] {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        for file in [
            "mix.exs",
            "mix.lock",
            "apps/web/mix.exs",
            "config/nested/data.json",
            ".tog/closure.json",
            ".git/config",
            "deps/dep.exs",
        ] {
            fs::write(temp.0.join(file), "input").unwrap();
        }
        let held = ProjectRoot::open(&temp.0).unwrap();
        let files =
            project_files(&held, &[".tog", ".git", "deps"], &["mix.exs", "mix.lock"]).unwrap();
        assert_eq!(
            files,
            vec![
                PathBuf::from("apps/web/mix.exs"),
                PathBuf::from("config/nested/data.json")
            ]
        );
        symlink("apps", temp.0.join("linked-apps")).unwrap();
        assert!(project_files(&held, &[".tog", ".git", "deps"], &[]).is_err());
    }
}

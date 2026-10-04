//! Is a projection still current? The `State` a tailor's `closure_state`
//! answers with, and the input/lock/object checks the answers are built
//! from. Ecosystem-neutral; the per-ecosystem rules live in each tailor.

use crate::kernel::fsroot::ProjectRoot;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Synced,
    NotSynced,
    /// Input files that differ from what the last sync consumed.
    Changed(Vec<String>),
    ProjectionMissing(String),
    ForeignPlatform(String),
    /// Synced, but this closure predates input recording.
    Unchecked(String),
}

pub fn string(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

/// Compare recorded `inputs` (python, node) with the files in the held
/// project.
fn changed_inputs(project: &ProjectRoot, inputs: &[Value]) -> io::Result<Vec<String>> {
    let mut changed = Vec::new();
    for input in inputs {
        let path = string(&input["path"]);
        let recorded = string(&input["sha256"]);
        if path.is_empty() {
            continue;
        }
        match input_sha256(project, Path::new(&path))? {
            None => changed.push(format!("{path} (removed)")),
            Some(current) if current != recorded => changed.push(path),
            Some(_) => {}
        }
    }
    Ok(changed)
}

/// The sha256 of a project input, read through the held descriptor;
/// `None` when it is absent or not a regular file.
fn input_sha256(project: &ProjectRoot, relative: &Path) -> io::Result<Option<String>> {
    // External Python requirements are recorded as absolute paths. These
    // intentionally remain external inputs, matching the record writer.
    if relative.is_absolute() {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(relative)
        {
            Ok(file) => file,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(None)
            }
            Err(error) => {
                // Some nonregular entries (Unix sockets) cannot be opened.
                // A successful read still requires the opened FD's metadata.
                // Match the previous is_file preflight for paths that
                // cannot be classified as regular (including symlink loops).
                if !fs::metadata(relative).is_ok_and(|meta| meta.is_file()) {
                    return Ok(None);
                }
                return Err(error);
            }
        };
        if !file.metadata()?.is_file() {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        return Ok(Some(hex::encode(Sha256::digest(bytes))));
    }
    if !project.is_input_file(relative) {
        return Ok(None);
    }
    Ok(project
        .read_input(relative)?
        .map(|bytes| hex::encode(Sha256::digest(bytes))))
}

/// Compare a single recorded lock hash with the file in the held project.
fn changed_lock(project: &ProjectRoot, lock: &str, recorded: &str) -> io::Result<Vec<String>> {
    let found = input_sha256(project, Path::new(lock))?;
    // `go.sum` may be legitimately absent; the go tailor records the hash
    // of the empty string, so match it.
    let current = found
        .clone()
        .unwrap_or_else(|| hex::encode(Sha256::digest(b"")));
    Ok(if recorded.is_empty() || current == recorded {
        Vec::new()
    } else if found.is_some() {
        vec![lock.to_string()]
    } else {
        vec![format!("{lock} (removed)")]
    })
}

pub fn symlink_target(path: &Path) -> Option<PathBuf> {
    fs::read_link(path).ok()
}

pub fn canonical_symlink_target(path: &Path) -> Option<PathBuf> {
    let target = symlink_target(path)?;
    let target = if target.is_absolute() {
        target
    } else {
        path.parent()?.join(target)
    };
    target.canonicalize().ok()
}

/// The first of `fields` whose recorded object directory is gone, labelled
/// for the user. `None` means every recorded path is still a directory, so
/// the name says what the return value means: `Some` is the defect.
fn missing_object_path(body: &Value, fields: &[&str]) -> Option<String> {
    for field in fields {
        let Some(path) = body[*field]["path"].as_str() else {
            continue;
        };
        if !Path::new(path).is_dir() {
            return Some(format!("{field} object"));
        }
    }
    None
}

pub fn object_liveness_state(body: &Value, fields: &[&str]) -> Option<State> {
    missing_object_path(body, fields).map(State::ProjectionMissing)
}

pub fn recorded_inputs_state(project: &ProjectRoot, body: &Value) -> io::Result<State> {
    match body["inputs"].as_array() {
        Some(inputs) if !inputs.is_empty() => {
            let changed = changed_inputs(project, inputs)?;
            Ok(if changed.is_empty() {
                State::Synced
            } else {
                State::Changed(changed)
            })
        }
        _ => Ok(State::Unchecked(
            "inputs were not recorded by this sync; run 'tog' once to enable checks".into(),
        )),
    }
}

pub fn lock_state(project: &ProjectRoot, lock: &str, recorded: &str) -> io::Result<State> {
    if recorded.is_empty() {
        return Ok(State::Unchecked(format!("{lock} hash not recorded")));
    }
    let changed = changed_lock(project, lock, recorded)?;
    Ok(if changed.is_empty() {
        State::Synced
    } else {
        State::Changed(changed)
    })
}

/// The state most tailors report: a recorded object gone from the store is
/// a missing projection, checked first so a lock that cannot be read never
/// hides it; otherwise the lock file against the hash in `hash_field`.
pub fn standard_state(
    project: &ProjectRoot,
    body: &Value,
    objects: &[&str],
    lock: &str,
    hash_field: &str,
) -> io::Result<State> {
    match object_liveness_state(body, objects) {
        Some(state) => Ok(state),
        None => lock_state(project, lock, &string(&body[hash_field])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn external_absolute_requirements_track_unchanged_changed_and_removed_bytes() {
        let temp = crate::kernel::testutil::TempDir::new();
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        let external = temp.0.join("requirements.txt");
        fs::write(&external, "six==1.17.0\n").unwrap();
        let body = json!({"inputs": [{"path": external,
            "sha256": sha256_file(&external).unwrap()}]});
        let project = ProjectRoot::open(&dir).unwrap();
        assert_eq!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Synced
        );
        fs::write(&external, "six==1.16.0\n").unwrap();
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
        fs::remove_file(&external).unwrap();
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
    }

    #[test]
    fn absolute_requirements_replaced_by_a_directory_or_fifo_are_changed() {
        use std::os::unix::ffi::OsStrExt;
        let temp = crate::kernel::testutil::TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let external = temp.0.join("external");
        let body = json!({"inputs": [{"path": external, "sha256": "old"}]});
        fs::create_dir(&external).unwrap();
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
        fs::remove_dir(&external).unwrap();
        let path = std::ffi::CString::new(external.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated name remains valid for the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
    }

    #[test]
    fn absolute_requirements_with_a_file_parent_are_changed() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        fs::write(temp.0.join("parent"), "not a directory").unwrap();
        let body =
            json!({"inputs": [{"path": temp.0.join("parent/requirements.txt"), "sha256": "old"}]});
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn absolute_requirements_replaced_by_a_unix_socket_are_changed() {
        use std::os::fd::AsRawFd;
        let temp = crate::kernel::testutil::TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let directory = fs::File::open(&temp.0).unwrap();
        // Keep the socket pathname short even with a long TMPDIR.
        let alias = format!("/proc/self/fd/{}/socket", directory.as_raw_fd());
        let _listener = std::os::unix::net::UnixListener::bind(alias).unwrap();
        let body = json!({"inputs": [{"path": temp.0.join("socket"), "sha256": "old"}]});
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
    }

    #[test]
    fn absolute_requirements_replaced_by_a_symlink_loop_are_changed() {
        let temp = crate::kernel::testutil::TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let external = temp.0.join("external");
        std::os::unix::fs::symlink("external", &external).unwrap();
        let body = json!({"inputs": [{"path": external, "sha256": "old"}]});
        assert!(matches!(
            recorded_inputs_state(&project, &body).unwrap(),
            State::Changed(_)
        ));
    }

    /// The helper reports the missing path, not the present one: a `Some`
    /// is always a defect, and `object_liveness_state` turns exactly that
    /// into `ProjectionMissing`.
    #[test]
    fn missing_object_path_names_the_absent_object() {
        let present = std::env::temp_dir();
        let absent = present.join("tog-status-no-such-object");
        let body = json!({
            "env_object": {"path": present.display().to_string()},
            "cache_object": {"path": absent.display().to_string()},
        });
        let fields = ["env_object", "cache_object"];

        assert_eq!(
            missing_object_path(&body, &fields),
            Some("cache_object object".to_string())
        );
        assert_eq!(missing_object_path(&body, &["env_object"]), None);
        assert_eq!(
            object_liveness_state(&body, &fields),
            Some(State::ProjectionMissing("cache_object object".into()))
        );
        assert_eq!(object_liveness_state(&body, &["env_object"]), None);
        // A field the closure never recorded is not a missing object.
        assert_eq!(missing_object_path(&body, &["absent_field"]), None);
    }
}

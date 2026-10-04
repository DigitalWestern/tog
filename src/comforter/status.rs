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

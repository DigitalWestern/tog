//! Is a projection still current? The `State` a tailor's `closure_state`
//! answers with, and the input/lock/object checks the answers are built
//! from. Ecosystem-neutral; the per-ecosystem rules live in each tailor.

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

/// Compare recorded `inputs` (python, node) with the files on disk.
fn changed_inputs(dir: &Path, inputs: &[Value]) -> io::Result<Vec<String>> {
    let mut changed = Vec::new();
    for input in inputs {
        let path = string(&input["path"]);
        let recorded = string(&input["sha256"]);
        if path.is_empty() {
            continue;
        }
        let file = dir.join(&path);
        if !file.is_file() {
            changed.push(format!("{path} (removed)"));
        } else if sha256_file(&file)? != recorded {
            changed.push(path);
        }
    }
    Ok(changed)
}

/// Compare a single recorded lock hash with the file on disk.
fn changed_lock(dir: &Path, lock: &str, recorded: &str) -> io::Result<Vec<String>> {
    let file = dir.join(lock);
    let current = if file.is_file() {
        sha256_file(&file)?
    } else {
        // `go.sum` may be legitimately absent; the go tailor records the
        // hash of the empty string, so match it.
        hex::encode(Sha256::digest(b""))
    };
    Ok(if recorded.is_empty() {
        Vec::new()
    } else if current == recorded {
        Vec::new()
    } else if file.is_file() {
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

fn object_path_exists(body: &Value, fields: &[&str]) -> Option<String> {
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
    object_path_exists(body, fields).map(State::ProjectionMissing)
}

pub fn recorded_inputs_state(dir: &Path, body: &Value) -> io::Result<State> {
    match body["inputs"].as_array() {
        Some(inputs) if !inputs.is_empty() => {
            let changed = changed_inputs(dir, inputs)?;
            Ok(if changed.is_empty() {
                State::Synced
            } else {
                State::Changed(changed)
            })
        }
        _ => Ok(State::Unchecked(
            "inputs were not recorded by this sync; run 'tog sync' once to enable checks"
                .into(),
        )),
    }
}

pub fn lock_state(dir: &Path, lock: &str, recorded: &str) -> io::Result<State> {
    if recorded.is_empty() {
        return Ok(State::Unchecked(format!("{lock} hash not recorded")));
    }
    let changed = changed_lock(dir, lock, recorded)?;
    Ok(if changed.is_empty() {
        State::Synced
    } else {
        State::Changed(changed)
    })
}

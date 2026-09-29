//! Base data types shared by every layer (kernel layer): object identity,
//! locked packages, and plans.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A git dependency pinned to a commit. Realized by `kernel::gitsrc`; lives
/// here so `types` does not depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSource {
    /// Normalized: no `git+` prefix or fragment. HTTP credentials are removed
    /// from the authority, while SSH usernames and repository paths are kept.
    pub url: String,
    /// Full 40-character commit hash.
    pub commit: String,
    /// Package subdirectory inside the repository, if the dependency names one.
    pub subdirectory: Option<String>,
}

/// Identity of a store object: hashed canonically to produce the object id.
/// Input-addressed (like Nix): the id commits to what the object was made FROM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub kind: String, // "cpython" | "wheel-env" | "sdist-build" | ...
    pub name: String,
    pub version: String,
    /// Sorted map of every input that determines the output (artifact hashes,
    /// dependency object ids, build flags). BTreeMap => canonical ordering.
    pub inputs: BTreeMap<String, String>,
}

impl Identity {
    /// Object id: first 40 hex chars (160 bits) of sha256 over canonical
    /// JSON, plus a human-readable suffix. Stable across machines.
    pub fn object_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let canon = serde_json::to_vec(self).expect("identity serializes");
        let h = hex::encode(Sha256::digest(&canon));
        format!(
            "{}-{}-{}",
            &h[..40],
            sanitize(&self.name),
            sanitize(&self.version)
        )
    }
}

/// The readable label in an object id. The hash already makes the id
/// unique, so the label may lose detail: a `.` right after another `.`
/// becomes `-`, because `is_object_id` (rightly) refuses any `..`, and an
/// id it refuses could be published but never dropped.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let keep = c.is_ascii_alphanumeric() || c == '_' || (c == '.' && !out.ends_with('.'));
        out.push(if keep { c } else { '-' });
    }
    out
}

/// One fully-locked dependency chosen by a planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub filename: String,
    pub url: String,
    pub sha256: String,
    pub kind: ArtifactKind,
    /// A git dependency pinned to a commit. The checkout is
    /// packed into a deterministic sdist before building, so everything
    /// downstream — build-system inspection, isolated build envs, identity —
    /// is the ordinary sdist path. Absent for registry packages, so plans
    /// written before this field stay readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    Wheel,
    Sdist,
}

/// The typed locked plan an adapter hands the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub ecosystem: String, // "python"
    pub python_version: String,
    pub packages: Vec<LockedPackage>,
}

#[cfg(test)]
mod object_id_tests {
    use super::*;

    fn id(name: &str, version: &str) -> String {
        Identity {
            kind: "wheel-env".into(),
            name: name.into(),
            version: version.into(),
            inputs: BTreeMap::new(),
        }
        .object_id()
    }

    /// Every id tog publishes must pass `is_object_id`, or `tog gc
    /// --drop-object` refuses it and the store's sweep wedges on it.
    #[test]
    fn names_and_versions_with_dot_runs_still_give_droppable_ids() {
        for (name, version, label) in [
            ("a..b", "1.0", "a.-b-1.0"),
            ("x", "1...0", "x-1.-.0"),
            ("..", "..", ".--.-"),
            ("my pkg/../x", "1.0", "my-pkg-.--x-1.0"),
            ("numpy", "2.1.0", "numpy-2.1.0"),
        ] {
            let id = id(name, version);
            assert_eq!(&id[41..], label, "{name} {version}");
            assert!(crate::kernel::store::is_object_id(&id), "{id}");
        }
    }

    #[test]
    fn the_label_does_not_decide_uniqueness() {
        assert_ne!(id("a..b", "1"), id("a.-b", "1"));
    }
}

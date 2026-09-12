//! Base data types shared by every layer (kernel layer): object identity,
//! locked packages, and plans.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
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
    /// A git dependency pinned to a commit (NEXT.md item 4). The checkout is
    /// packed into a deterministic sdist before building, so everything
    /// downstream — build-system inspection, isolated build envs, identity —
    /// is the ordinary sdist path. Absent for registry packages, so plans
    /// written before this field stay readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<crate::kernel::gitsrc::GitSource>,
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

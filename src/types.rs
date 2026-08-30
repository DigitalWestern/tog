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
    /// Object id: first 16 hex chars of sha256 over canonical JSON, plus a
    /// human-readable suffix. Stable across machines.
    pub fn object_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let canon = serde_json::to_vec(self).expect("identity serializes");
        let h = hex::encode(Sha256::digest(&canon));
        format!("{}-{}-{}", &h[..16], sanitize(&self.name), sanitize(&self.version))
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' { c } else { '-' })
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

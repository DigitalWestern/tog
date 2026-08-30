//! Python planner: parse a hash-pinned requirements.txt and lock each
//! requirement to one exact PyPI artifact (wheel preferred, sdist fallback).
//!
//! IMPLEMENTATION CONTRACT (see plan_python below) — being implemented.

use crate::types::{ArtifactKind, LockedPackage, Plan};
use std::io;

/// Parse `requirements.txt` content in pip/uv `--generate-hashes` format:
///
///   name==1.2.3 \
///       --hash=sha256:abc... \
///       --hash=sha256:def...
///
/// Rules:
/// - Only exact `==` pins are accepted; anything else is a hard error.
/// - Lines may continue with a trailing backslash; comments (#) and blank
///   lines are skipped; environment markers after ';' are rejected (v0).
/// - Extras like `name[extra]==...` are rejected (v0) with a clear error.
/// - Returns (normalized_name, version, set_of_sha256_hex) triples.
///   Normalized name: PEP 503 (lowercase, runs of -_. collapse to '-').
pub fn parse_requirements(text: &str) -> io::Result<Vec<Requirement>> {
    let _ = text;
    todo!("luna: implement")
}

#[derive(Debug, Clone)]
pub struct Requirement {
    pub name: String, // PEP 503 normalized
    pub version: String,
    pub sha256s: Vec<String>, // lowercase hex, no "sha256:" prefix
}

/// Lock every requirement against PyPI's JSON API
/// (GET https://pypi.org/pypi/<name>/<version>/json).
///
/// Selection, per requirement, from response["urls"]:
/// 1. Filter to files whose digests.sha256 is in the requirement's hash set.
///    Empty after filtering => hard error (supply-chain mismatch).
/// 2. Among survivors pick, in order of preference:
///    a. wheel with a platform tag matching macOS arm64 (macosx_*_arm64 or
///       macosx_*_universal2) and an interpreter tag compatible with
///       `python_tag` (e.g. "cp312"): exact cpXYZ, or abi3 with cpABC <= ours.
///    b. pure wheel: py3-none-any (or py2.py3-none-any).
///    c. sdist (.tar.gz / .zip) => ArtifactKind::Sdist.
///    Multi-platform-tag wheels (tags joined with '.') count if ANY tag matches.
/// 3. Anything else (e.g. only a linux wheel) => hard error naming the files seen.
///
/// `python_tag` is like "cp312". Wheel filename format:
///   {dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl
pub fn lock_requirements(
    reqs: &[Requirement],
    python_version: &str,
    python_tag: &str,
) -> io::Result<Vec<LockedPackage>> {
    let _ = (reqs, python_version, python_tag);
    todo!("luna: implement")
}

/// End-to-end planner: text -> Plan.
pub fn plan_python(requirements_text: &str, python_version: &str) -> io::Result<Plan> {
    let reqs = parse_requirements(requirements_text)?;
    let minor = python_version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join("");
    let tag = format!("cp{minor}");
    let packages = lock_requirements(&reqs, python_version, &tag)?;
    Ok(Plan {
        ecosystem: "python".into(),
        python_version: python_version.into(),
        packages,
    })
}

// keep ArtifactKind referenced so stubs compile standalone
#[allow(dead_code)]
fn _kinds() -> ArtifactKind {
    ArtifactKind::Wheel
}

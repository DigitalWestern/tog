//! The PyPI tailor: parses a hash-pinned requirements.txt and locks each
//! requirement to one exact PyPI artifact (wheel preferred, sdist
//! fallback), cutting the pattern (Plan) the kernel realizes.

use crate::types::{ArtifactKind, LockedPackage, Plan};
use std::io;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[derive(Debug, Clone)]
pub struct Requirement {
    pub name: String, // PEP 503 normalized
    pub version: String,
    pub sha256s: Vec<String>, // lowercase hex, no "sha256:" prefix
}

/// PEP 503 name normalization: lowercase; runs of [-_.] collapse to '-'.
fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// Strip a comment: '#' at line start or preceded by whitespace.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

/// Parse pip/uv `--generate-hashes` format. Only exact `==` pins with at
/// least one sha256 hash are accepted; see doc for rejection rules.
pub fn parse_requirements(text: &str) -> io::Result<Vec<Requirement>> {
    // Fold physical lines into logical lines (trailing backslash joins).
    let mut logical: Vec<String> = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = strip_comment(raw);
        let trimmed = line.trim_end();
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
        } else {
            current.push_str(trimmed);
            if !current.trim().is_empty() {
                logical.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if !current.trim().is_empty() {
        logical.push(current);
    }

    let mut reqs = Vec::new();
    for line in logical {
        let mut spec = String::new();
        let mut hashes: Vec<String> = Vec::new();
        for tok in line.split_whitespace() {
            if tok == "-e" || tok == "--editable" {
                return Err(err("editable requirements are not supported"));
            }
            if let Some(h) = tok.strip_prefix("--hash=") {
                let Some(hex) = h.strip_prefix("sha256:") else {
                    return Err(err(format!("only sha256 hashes are supported, got: {tok}")));
                };
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(err(format!("malformed sha256 hash: {hex}")));
                }
                hashes.push(hex.to_ascii_lowercase());
            } else if tok.starts_with('-') {
                return Err(err(format!("unsupported option in requirements: {tok}")));
            } else {
                spec.push_str(tok);
            }
        }
        if spec.is_empty() {
            continue;
        }
        if spec.contains(';') {
            return Err(err(format!(
                "environment markers are not supported (v0): {spec}"
            )));
        }
        if spec.contains('[') {
            return Err(err(format!("extras are not supported (v0): {spec}")));
        }
        let Some((name, version)) = spec.split_once("==") else {
            return Err(err(format!(
                "only exact '==' pins are supported: {spec}"
            )));
        };
        if version.contains('=') || version.contains('<') || version.contains('>')
            || name.contains('<') || name.contains('>') || name.contains('~')
            || name.contains('!') || version.contains('*')
        {
            return Err(err(format!("only exact '==' pins are supported: {spec}")));
        }
        if name.is_empty() || version.is_empty() {
            return Err(err(format!("malformed requirement: {spec}")));
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            || !name.as_bytes()[0].is_ascii_alphanumeric()
        {
            return Err(err(format!("invalid project name: {name}")));
        }
        if hashes.is_empty() {
            return Err(err(format!(
                "{spec}: blanket requires hash-pinned requirements; \
                 generate with: uv pip compile --generate-hashes"
            )));
        }
        reqs.push(Requirement {
            name: normalize_name(name),
            version: version.to_string(),
            sha256s: hashes,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in &reqs {
        if !seen.insert(&r.name) {
            return Err(err(format!("duplicate requirement: {}", r.name)));
        }
    }
    Ok(reqs)
}

/// One downloadable file for a (name, version), from the PyPI JSON API.
#[derive(Debug, Clone)]
pub struct FileCandidate {
    pub filename: String,
    pub url: String,
    pub sha256: String,
}

/// Wheel-or-sdist choice for macOS arm64 given python tag like "cp312".
/// Returns (band, tiebreak); lower wins. None = incompatible.
/// Bands: 0 native exact, 1 native abi3, 2 universal2 exact,
/// 3 universal2 abi3, 4 pure, 6 sdist. abi3 tiebreak prefers the
/// highest compatible cp tag.
fn score(filename: &str, python_tag: &str) -> Option<(u32, u32)> {
    let ours: u32 = python_tag.strip_prefix("cp")?.parse().ok()?;
    if filename.ends_with(".tar.gz") || filename.ends_with(".zip") {
        return Some((6, 0));
    }
    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() < 5 {
        return None;
    }
    let (py, abi, plat) = (
        parts[parts.len() - 3],
        parts[parts.len() - 2],
        parts[parts.len() - 1],
    );
    let pys: Vec<&str> = py.split('.').collect();
    let plats: Vec<&str> = plat.split('.').collect();

    let arm64 = plats
        .iter()
        .any(|p| p.starts_with("macosx_") && p.ends_with("_arm64"));
    let universal2 = plats
        .iter()
        .any(|p| p.starts_with("macosx_") && p.ends_with("_universal2"));
    let anyplat = plats.iter().any(|p| *p == "any");

    let abis: Vec<&str> = abi.split('.').collect();
    // Exact requires a matching ABI too: cpNNN wheels must carry our cpNNN
    // abi (or abi3/none); a cp312-cp311-* wheel is NOT usable on 3.12.
    let abi_ok = abis
        .iter()
        .any(|a| *a == python_tag || *a == "abi3" || *a == "none");
    let exact = pys.iter().any(|t| *t == python_tag) && abi_ok;
    // abi3: any cpNNN <= ours counts; prefer the highest such NNN.
    let abi3_best = if abis.iter().any(|a| *a == "abi3") {
        pys.iter()
            .filter_map(|t| t.strip_prefix("cp")?.parse::<u32>().ok())
            .filter(|n| *n <= ours)
            .max()
    } else {
        None
    };
    // Pure wheels must be abi-none. Interpreter tag may be py3, a generic
    // pyNNN <= ours, or our exact cpNNN (e.g. cp312-none-any).
    let none_abi = abis.iter().any(|a| *a == "none");
    let py_ok = pys.iter().any(|t| {
        *t == "py3"
            || *t == python_tag
            || t.strip_prefix("py")
                .and_then(|n| n.parse::<u32>().ok())
                .map(|n| n == 3 || n <= ours)
                .unwrap_or(false)
    });
    let pure = py_ok && none_abi;

    if arm64 && exact {
        return Some((0, 0));
    }
    if arm64 {
        if let Some(n) = abi3_best {
            return Some((1, ours - n));
        }
    }
    if universal2 && exact {
        return Some((2, 0));
    }
    if universal2 {
        if let Some(n) = abi3_best {
            return Some((3, ours - n));
        }
    }
    if anyplat && pure {
        return Some((4, 0));
    }
    None
}

/// Pick the best compatible file, preferring lowest score.
pub fn select_file<'a>(
    files: &'a [FileCandidate],
    python_tag: &str,
) -> Option<(&'a FileCandidate, ArtifactKind)> {
    files
        .iter()
        .filter_map(|f| score(&f.filename, python_tag).map(|s| (s, f)))
        .min_by_key(|(s, f)| (*s, f.filename.clone()))
        .map(|(s, f)| {
            let kind = if s.0 >= 6 {
                ArtifactKind::Sdist
            } else {
                ArtifactKind::Wheel
            };
            (f, kind)
        })
}

fn fetch_candidates(name: &str, version: &str) -> io::Result<Vec<FileCandidate>> {
    let url = format!("https://pypi.org/pypi/{name}/{version}/json");
    let body = ureq::get(&url)
        .call()
        .map_err(|e| err(format!("PyPI lookup failed for {name}=={version}: {e}")))?
        .into_string()
        .map_err(|e| err(format!("PyPI response for {name}: {e}")))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| err(format!("PyPI JSON for {name}: {e}")))?;
    let urls = v["urls"]
        .as_array()
        .ok_or_else(|| err(format!("PyPI JSON for {name} has no urls array")))?;
    Ok(urls
        .iter()
        .filter_map(|u| {
            Some(FileCandidate {
                filename: u["filename"].as_str()?.to_string(),
                url: u["url"].as_str()?.to_string(),
                sha256: u["digests"]["sha256"].as_str()?.to_ascii_lowercase(),
            })
        })
        .collect())
}

/// Lock every requirement against PyPI, honoring the hash pins.
pub fn lock_requirements(reqs: &[Requirement], python_tag: &str) -> io::Result<Vec<LockedPackage>> {
    let mut out = Vec::new();
    for r in reqs {
        let all = fetch_candidates(&r.name, &r.version)?;
        let matching: Vec<FileCandidate> = all
            .iter()
            .filter(|f| r.sha256s.contains(&f.sha256))
            .cloned()
            .collect();
        if matching.is_empty() {
            return Err(err(format!(
                "{}=={}: none of PyPI's files match the pinned hashes \
                 (supply-chain mismatch or stale lock). PyPI has: {}",
                r.name,
                r.version,
                all.iter()
                    .map(|f| f.filename.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let Some((chosen, kind)) = select_file(&matching, python_tag) else {
            return Err(err(format!(
                "{}=={}: no file compatible with {python_tag} on macOS arm64 \
                 among hash-matched files: {}",
                r.name,
                r.version,
                matching
                    .iter()
                    .map(|f| f.filename.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        out.push(LockedPackage {
            name: r.name.clone(),
            version: r.version.clone(),
            filename: chosen.filename.clone(),
            url: chosen.url.clone(),
            sha256: chosen.sha256.clone(),
            kind,
        });
    }
    Ok(out)
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
    let packages = lock_requirements(&reqs, &tag)?;
    Ok(Plan {
        ecosystem: "python".into(),
        python_version: python_version.into(),
        packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiline_with_hashes() {
        let text = "\
# lockfile header\n\
markupsafe==2.1.5 \\\n\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001 \\\n\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000002\n\
six==1.17.0 \\\n\
    --hash=sha256:00000000000000000000000000000000000000000000000000000000000000AA\n";
        let reqs = parse_requirements(text).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].name, "markupsafe");
        assert_eq!(reqs[0].version, "2.1.5");
        assert_eq!(reqs[0].sha256s.len(), 2);
        // hex lowercased
        assert!(reqs[1].sha256s[0].ends_with("aa"));
    }

    #[test]
    fn normalizes_names() {
        let text = "Flask_SQLAlchemy.Extra==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001\n";
        let reqs = parse_requirements(text).unwrap();
        assert_eq!(reqs[0].name, "flask-sqlalchemy-extra");
    }

    #[test]
    fn comment_only_when_preceded_by_whitespace() {
        // '#' inside a token is not a comment -- but such names then fail
        // the project-name grammar, which is the correct outcome.
        let text = "a#b==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001\n";
        assert!(parse_requirements(text).is_err());
        let text2 = "six==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001 # trailing\n";
        assert_eq!(parse_requirements(text2).unwrap()[0].version, "1.0");
    }

    #[test]
    fn rejects_duplicates_and_bad_abi_wheels() {
        let dup = "six==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001\n\
Six==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000002\n";
        assert!(parse_requirements(dup).is_err());
        // cp312 python tag with cp311 abi: unusable, must be rejected.
        let files = vec![fc("pkg-1.0-cp312-cp311-macosx_11_0_arm64.whl")];
        assert!(select_file(&files, "cp312").is_none());
        // py3 with non-none abi is not a pure wheel.
        let files2 = vec![fc("pkg-1.0-py3-cp39-any.whl")];
        assert!(select_file(&files2, "cp312").is_none());
    }

    #[test]
    fn rejections() {
        for bad in [
            "six>=1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "six==1.0",                    // no hash
            "six[extra]==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "six==1.0; python_version<'3' --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "-e ./local",
            "six==1.0 --hash=md5:abc",
            "-r other.txt",
        ] {
            assert!(parse_requirements(bad).is_err(), "should reject: {bad}");
        }
    }

    fn fc(filename: &str) -> FileCandidate {
        FileCandidate {
            filename: filename.into(),
            url: format!("https://x/{filename}"),
            sha256: "0".repeat(64),
        }
    }

    #[test]
    fn selection_prefers_native_then_abi3_then_universal2_then_pure_then_sdist() {
        let files = vec![
            fc("pkg-1.0.tar.gz"),
            fc("pkg-1.0-py3-none-any.whl"),
            fc("pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-cp312-cp312-macosx_10_9_universal2.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
        ];
        let (best, kind) = select_file(&files, "cp312").unwrap();
        assert_eq!(best.filename, "pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl");
        assert_eq!(kind, ArtifactKind::Wheel);

        // Without the exact native wheel, abi3 arm64 wins.
        let files2: Vec<_> = files
            .iter()
            .filter(|f| !f.filename.contains("cp312-cp312-macosx_11_0_arm64"))
            .cloned()
            .collect();
        let (best2, _) = select_file(&files2, "cp312").unwrap();
        assert_eq!(best2.filename, "pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl");

        // abi3 prefers highest compatible cp tag.
        let files3 = vec![
            fc("pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-cp311-abi3-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-cp313-abi3-macosx_11_0_arm64.whl"), // newer than ours: skip
        ];
        let (best3, _) = select_file(&files3, "cp312").unwrap();
        assert_eq!(best3.filename, "pkg-1.0-cp311-abi3-macosx_11_0_arm64.whl");

        // Only linux wheel: incompatible.
        let files4 = vec![fc("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl")];
        assert!(select_file(&files4, "cp312").is_none());

        // universal2 beats pure; pure beats sdist.
        let files5 = vec![
            fc("pkg-1.0.tar.gz"),
            fc("pkg-1.0-py3-none-any.whl"),
            fc("pkg-1.0-cp312-cp312-macosx_10_9_universal2.whl"),
        ];
        let (best5, _) = select_file(&files5, "cp312").unwrap();
        assert!(best5.filename.contains("universal2"));

        let files6 = vec![fc("pkg-1.0.tar.gz"), fc("pkg-1.0-py2.py3-none-any.whl")];
        let (best6, kind6) = select_file(&files6, "cp312").unwrap();
        assert!(best6.filename.ends_with(".whl"));
        assert_eq!(kind6, ArtifactKind::Wheel);

        let files7 = vec![fc("pkg-1.0.tar.gz")];
        let (_, kind7) = select_file(&files7, "cp312").unwrap();
        assert_eq!(kind7, ArtifactKind::Sdist);
    }

    #[test]
    fn multi_tag_wheels_match_any_tag() {
        let files = vec![fc(
            "pkg-1.0-cp310.cp311.cp312-abi3-macosx_10_9_universal2.macosx_11_0_arm64.whl",
        )];
        let (best, _) = select_file(&files, "cp312").unwrap();
        assert!(best.filename.contains("abi3"));
    }
}

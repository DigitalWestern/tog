//! The PyPI tailor: parses a hash-pinned requirements.txt and locks each
//! requirement to one exact PyPI artifact (wheel preferred, sdist
//! fallback), cutting the pattern (Plan) the kernel realizes.

use crate::platform::Platform;
use crate::store::Store;
use crate::types::{ArtifactKind, LockedPackage, Plan};
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::ffi::CStr;
use std::fs;
use std::io;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::raw::c_char;
use std::process::Command;
use std::sync::OnceLock;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
extern "C" {
    fn gnu_get_libc_version() -> *const c_char;
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Glibc(pub u32, pub u32);

fn parse_glibc_version(text: &str) -> Option<Glibc> {
    let text = text.trim();
    let version = text.strip_prefix("glibc ").unwrap_or(text);
    // "2.43", "2.43.9000" (rawhide/branched builds), "glibc 2.43". Only the
    // first two components matter for manylinux compatibility.
    let mut parts = version.split('.');
    let digits = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    let major = digits(parts.next()?)?;
    let minor = digits(parts.next()?)?;
    Some(Glibc(major, minor))
}

fn detect_host_glibc() -> Result<Glibc, String> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // The symbol is only declared on glibc targets; if it is unusable,
        // continue to the portable getconf fallback below.
        let version = unsafe { gnu_get_libc_version() };
        if !version.is_null() {
            if let Ok(version) = unsafe { CStr::from_ptr(version) }.to_str() {
                if let Some(glibc) = parse_glibc_version(version) {
                    return Ok(glibc);
                }
            }
        }
    }

    let output = Command::new("/usr/bin/getconf")
        .arg("GNU_LIBC_VERSION")
        .output()
        .map_err(|error| format!("could not run /usr/bin/getconf GNU_LIBC_VERSION: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "/usr/bin/getconf GNU_LIBC_VERSION failed with {status}",
            status = output.status
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "/usr/bin/getconf returned non-UTF-8 output".to_string())?;
    parse_glibc_version(&text)
        .ok_or_else(|| format!("could not parse glibc version from getconf output: {text:?}"))
}

pub fn host_glibc() -> io::Result<Glibc> {
    static HOST: OnceLock<Result<Glibc, String>> = OnceLock::new();
    match HOST.get_or_init(detect_host_glibc) {
        Ok(glibc) => Ok(*glibc),
        Err(message) => Err(io::Error::other(format!(
            "could not determine host glibc version: {message}"
        ))),
    }
}

#[derive(Debug, Clone)]
pub struct Requirement {
    pub name: String, // PEP 503 normalized
    pub version: String,
    pub sha256s: Vec<String>, // lowercase hex, no "sha256:" prefix
    /// A `name @ git+URL@<commit>` requirement (NEXT.md item 4). The commit is
    /// the verification, so such a line carries no `--hash`.
    pub git: Option<crate::gitsrc::GitSource>,
}

/// Parse `name @ git+URL@<40-hex commit>`, optionally with
/// `#subdirectory=path`. Anything less pinned is not a requirement blanket can
/// lock, and the caller reports it.
pub fn parse_git_requirement(spec: &str) -> Option<Requirement> {
    let (name, reference) = spec.split_once('@')?;
    let name = name.trim();
    let reference = reference.trim();
    if name.is_empty() || !reference.starts_with("git+") {
        return None;
    }
    let (reference, subdirectory) = match reference.split_once('#') {
        Some((before, fragment)) => (
            before,
            fragment
                .split('&')
                .find_map(|part| part.strip_prefix("subdirectory="))
                .map(str::to_string),
        ),
        None => (reference, None),
    };
    let (url, commit) = reference.rsplit_once('@')?;
    if !crate::gitsrc::is_full_commit(commit) {
        return None;
    }
    let name = normalize_name(name);
    // The name becomes a path component and an archive member, so it must be
    // a plain component — normalize_name alone still admits '/' and ','.
    if !crate::gitsrc::is_safe_component(&name) {
        return None;
    }
    Some(Requirement {
        name,
        // A git requirement has no release version; the commit names it.
        version: format!("0+git.{}", &commit[..12]),
        sha256s: Vec::new(),
        git: Some(crate::gitsrc::GitSource {
            url: crate::gitsrc::normalize_url(url),
            commit: commit.to_ascii_lowercase(),
            subdirectory,
        }),
    })
}

/// PEP 503 name normalization: lowercase; runs of [-_.] collapse to '-'.
pub fn normalize_name(name: &str) -> String {
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

fn logical_lines(text: &str) -> Vec<String> {
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
    logical
}

/// Expose pip's logical-line handling to manifest discovery. Comments are
/// removed only when `#` is at the start or follows whitespace, so URLs and
/// hashes remain intact.
pub fn logical_requirement_lines(text: &str) -> Vec<String> {
    logical_lines(text)
}

/// Whether a logical line is one of the include/index directives that the
/// manifest layer handles before resolution.
pub fn is_requirement_option(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or_default();
    matches!(
        first,
        "-r" | "--requirement"
            | "-c"
            | "--constraint"
            | "--index-url"
            | "--extra-index-url"
            | "--find-links"
            | "--trusted-host"
    ) || first.starts_with("--index-url=")
        || first.starts_with("--extra-index-url=")
        || first.starts_with("--find-links=")
        || first.starts_with("--trusted-host=")
        || first.starts_with("-r=")
        || first.starts_with("--requirement=")
        || first.starts_with("-c=")
        || first.starts_with("--constraint=")
}

/// Index configuration is deliberately data-only: blanket reports it as an
/// unattested input and never follows the configured index during locking.
pub fn unattested_index_options(text: &str) -> Vec<String> {
    logical_lines(text)
        .into_iter()
        .filter(|line| {
            let first = line.split_whitespace().next().unwrap_or_default();
            matches!(
                first,
                "--index-url" | "--extra-index-url" | "--find-links" | "--trusted-host"
            ) || first.starts_with("--index-url=")
                || first.starts_with("--extra-index-url=")
                || first.starts_with("--find-links=")
                || first.starts_with("--trusted-host=")
        })
        .collect()
}

/// Parse setuptools' generated `requires.txt`. Unnamed lines are install
/// requirements; extra sections are intentionally skipped, while a section
/// such as `[:python_version < '3.9']` contributes that marker.
pub fn parse_requires_txt(text: &str) -> io::Result<Vec<String>> {
    enum Section {
        Extra,
        Marker(String),
    }
    let mut section: Option<Section> = None;
    let mut output = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = &line[1..line.len() - 1];
            section = if let Some(marker) = name.strip_prefix(':') {
                Some(Section::Marker(marker.trim().to_string()))
            } else {
                Some(Section::Extra)
            };
            continue;
        }
        match &section {
            Some(Section::Marker(marker)) => output.push(format!("{line}; {marker}")),
            Some(Section::Extra) => {}
            None => output.push(line.to_string()),
        }
    }
    Ok(output)
}

/// Return project-local/direct specs without recording policy exceptions.
pub fn skippable_specs(text: &str) -> Vec<String> {
    logical_lines(text)
        .into_iter()
        .map(|line| {
            line.split_whitespace()
                .filter(|token| !token.starts_with("--hash="))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|spec| is_skippable_spec(spec))
        .collect()
}

/// Whether a requirement is project-local or a direct reference that blanket
/// cannot turn into a verified registry package.
pub fn is_skippable_spec(spec: &str) -> bool {
    let spec = spec.trim();
    let is_local = |p: &str| {
        p == "."
            || p.starts_with("./")
            || p.starts_with("../")
            || p.starts_with('/')
            || p.starts_with("file:")
    };
    let is_url = |r: &str| {
        r.starts_with("https://")
            || r.starts_with("http://")
            || r.starts_with("git+")
            || r.starts_with("file:")
    };
    if is_local(spec) || is_url(spec) {
        return true;
    }
    for flag in ["-e ", "--editable ", "-e=", "--editable="] {
        if let Some(target) = spec.strip_prefix(flag) {
            return is_local(target.trim()) || is_url(target.trim());
        }
    }
    spec.split_once('@')
        .map(|(name, reference)| !name.trim().is_empty() && is_url(reference.trim()))
        .unwrap_or(false)
}

/// Parse pip/uv `--generate-hashes` format. Only exact `==` pins with at
/// least one sha256 hash are accepted; see doc for rejection rules.
pub fn parse_requirements(text: &str) -> io::Result<Vec<Requirement>> {
    let mut reqs = Vec::new();
    for line in logical_lines(text) {
        if is_requirement_option(&line) {
            // Includes and index directives are validated/recorded by the
            // manifest layer. They are not package requirements themselves.
            continue;
        }
        let mut spec = String::new();
        let mut hashes: Vec<String> = Vec::new();
        for tok in line.split_whitespace() {
            if let Some(h) = tok.strip_prefix("--hash=") {
                let Some(hex) = h.strip_prefix("sha256:") else {
                    return Err(err(format!("only sha256 hashes are supported, got: {tok}")));
                };
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(err(format!("malformed sha256 hash: {hex}")));
                }
                hashes.push(hex.to_ascii_lowercase());
            } else {
                if !spec.is_empty() {
                    spec.push(' ');
                }
                spec.push_str(tok);
            }
        }
        if spec.is_empty() {
            continue;
        }
        if let Some(requirement) = parse_git_requirement(&spec) {
            reqs.push(requirement);
            continue;
        }
        if is_skippable_spec(&spec) {
            continue;
        }
        for tok in spec.split_whitespace() {
            if tok == "-e" || tok == "--editable" {
                return Err(err("editable requirements are not supported"));
            }
            if tok.starts_with('-') {
                return Err(err(format!("unsupported option in requirements: {tok}")));
            }
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
            return Err(err(format!("only exact '==' pins are supported: {spec}")));
        };
        if version.contains('=')
            || version.contains('<')
            || version.contains('>')
            || name.contains('<')
            || name.contains('>')
            || name.contains('~')
            || name.contains('!')
            || version.contains('*')
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
            git: None,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Score {
    family_rank: u32,
    abi_rank: u32,
    abi3_floor: u32,
    glibc_floor: (u32, u32),
}

type ScoreOrder = (
    u32,
    u32,
    std::cmp::Reverse<u32>,
    std::cmp::Reverse<(u32, u32)>,
);

fn score_order(score: Score) -> ScoreOrder {
    (
        score.family_rank,
        score.abi_rank,
        std::cmp::Reverse(score.abi3_floor),
        std::cmp::Reverse(score.glibc_floor),
    )
}

fn parse_cp_tag(tag: &str) -> Option<u32> {
    let digits = tag.strip_prefix("cp")?;
    if digits.len() < 2 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn parse_python_tag(tag: &str) -> Option<(u32, u32)> {
    let digits = tag.strip_prefix("cp")?;
    if digits.len() < 2 || !digits.starts_with('3') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ours = digits.parse().ok()?;
    let minor = digits[1..].parse().ok()?;
    Some((ours, minor))
}

fn manylinux_floor(tag: &str) -> Option<(u32, u32)> {
    match tag {
        "manylinux1_x86_64" => return Some((2, 5)),
        "manylinux2010_x86_64" => return Some((2, 12)),
        "manylinux2014_x86_64" => return Some((2, 17)),
        _ => {}
    }
    let rest = tag.strip_prefix("manylinux_")?;
    let parts: Vec<_> = rest.split('_').collect();
    if parts.len() != 4 || parts[2] != "x86" || parts[3] != "64" {
        return None;
    }
    let digits = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    Some((digits(parts[0])?, digits(parts[1])?))
}

fn platform_score(tag: &str, platform: Platform, glibc: Glibc) -> Option<(u32, (u32, u32))> {
    match platform {
        Platform::Aarch64AppleDarwin => {
            if tag.starts_with("macosx_") && tag.ends_with("_arm64") {
                Some((0, (0, 0)))
            } else if tag.starts_with("macosx_") && tag.ends_with("_universal2") {
                Some((1, (0, 0)))
            } else if tag == "any" {
                Some((2, (0, 0)))
            } else {
                None
            }
        }
        Platform::X86_64UnknownLinuxGnu => {
            if let Some(floor) = manylinux_floor(tag) {
                (floor <= (glibc.0, glibc.1)).then_some((0, floor))
            } else if tag == "linux_x86_64" {
                Some((1, (0, 0)))
            } else if tag == "any" {
                Some((2, (0, 0)))
            } else {
                None
            }
        }
    }
}

fn pure_python_tag(tag: &str, python_tag: &str, python_minor: u32) -> bool {
    if tag == "py3" || tag == python_tag {
        return true;
    }
    let Some(minor) = tag.strip_prefix("py3") else {
        return false;
    };
    !minor.is_empty()
        && minor.len() <= 2
        && minor.bytes().all(|byte| byte.is_ascii_digit())
        && minor
            .parse::<u32>()
            .is_ok_and(|minor| minor <= python_minor)
}

/// Score a wheel or source archive for an explicit host platform.
///
/// The filename's compressed py/abi/platform tags are expanded as a
/// Cartesian product. The best compatible tuple is retained, then the
/// caller adds the filename as the final deterministic tiebreaker.
fn score(filename: &str, python_tag: &str, platform: Platform, glibc: Glibc) -> Option<Score> {
    let (ours, python_minor) = parse_python_tag(python_tag)?;
    if let Some(stem) = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".zip"))
    {
        if stem.rsplit_once('-').is_some() {
            return Some(Score {
                family_rank: 3,
                abi_rank: 0,
                abi3_floor: 0,
                glibc_floor: (0, 0),
            });
        }
        return None;
    }

    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    if !matches!(parts.len(), 5 | 6) || parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    let py = parts[parts.len() - 3];
    let abi = parts[parts.len() - 2];
    let plat = parts[parts.len() - 1];
    let mut best = None;
    for py_tag in py.split('.') {
        for abi_tag in abi.split('.') {
            let abi_score = if abi_tag == python_tag && py_tag == python_tag {
                Some((0, 0))
            } else if abi_tag == "abi3" {
                // Stable ABI: cp3Y with 3.2 <= 3.Y <= our 3.N. Compare as
                // (major, minor) so cp40+ (Python 4) never counts as a floor.
                parse_cp_tag(py_tag)
                    .filter(|floor| {
                        let (major, minor) = (floor / 10, floor % 10);
                        let floor_is_3x = *floor >= 32 && *floor < 40 && major == 3;
                        let floor_is_3xx = *floor >= 310 && *floor / 100 == 3;
                        (floor_is_3x && minor >= 2 && *floor <= ours)
                            || (floor_is_3xx && *floor <= ours)
                    })
                    .map(|floor| (1, floor))
            } else if abi_tag == "none" && pure_python_tag(py_tag, python_tag, python_minor) {
                Some((2, 0))
            } else {
                None
            };
            let Some((abi_rank, abi3_floor)) = abi_score else {
                continue;
            };
            for platform_tag in plat.split('.') {
                // A platform-independent wheel cannot carry a compiled ABI:
                // pip never pairs `any` with cpNNN/abi3, and the pre-port
                // macOS selector rejected it too.
                if platform_tag == "any" && abi_rank != 2 {
                    continue;
                }
                let Some((family_rank, glibc_floor)) =
                    platform_score(platform_tag, platform, glibc)
                else {
                    continue;
                };
                let candidate = Score {
                    family_rank,
                    abi_rank,
                    abi3_floor,
                    glibc_floor,
                };
                if best
                    .map(|current| score_order(candidate) < score_order(current))
                    .unwrap_or(true)
                {
                    best = Some(candidate);
                }
            }
        }
    }
    best
}

/// Pick the best compatible file, preferring the specified ordering key.
pub fn select_file<'a>(
    files: &'a [FileCandidate],
    python_tag: &str,
    platform: Platform,
    glibc: Glibc,
) -> Option<(&'a FileCandidate, ArtifactKind)> {
    files
        .iter()
        .filter_map(|f| score(&f.filename, python_tag, platform, glibc).map(|s| (s, f)))
        .min_by_key(|(s, f)| {
            let order = score_order(*s);
            (order.0, order.1, order.2, order.3, f.filename.clone())
        })
        .map(|(s, f)| {
            let kind = if s.family_rank == 3 {
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
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| err(format!("PyPI JSON for {name}: {e}")))?;
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
pub fn lock_requirements(
    platform: Platform,
    glibc: Glibc,
    reqs: &[Requirement],
    python_tag: &str,
) -> io::Result<Vec<LockedPackage>> {
    let mut out = Vec::new();
    for r in reqs {
        // A git requirement is already fully determined by its commit: there
        // is no index lookup and no wheel to select. The checkout is packed
        // into an sdist at realization (build::git_sdist_package).
        if let Some(source) = &r.git {
            out.push(LockedPackage {
                name: r.name.clone(),
                version: r.version.clone(),
                filename: format!("{}-{}.tar.gz", r.name, r.version),
                url: format!("git+{}@{}", source.url, source.commit),
                sha256: String::new(),
                kind: ArtifactKind::Sdist,
                git: Some(source.clone()),
            });
            continue;
        }
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
        let Some((chosen, kind)) = select_file(&matching, python_tag, platform, glibc) else {
            let host = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
                format!("{} (glibc {}.{})", platform.triple(), glibc.0, glibc.1)
            } else {
                platform.triple().to_string()
            };
            return Err(err(format!(
                "{}=={}: no file compatible with {python_tag} on {host} \
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
            git: None,
        });
    }
    Ok(out)
}

/// End-to-end planner: text -> Plan.
pub fn plan_python(
    platform: Platform,
    requirements_text: &str,
    python_version: &str,
) -> io::Result<Plan> {
    let reqs = parse_requirements(requirements_text)?;
    let minor = python_version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join("");
    let tag = format!("cp{minor}");
    let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        host_glibc()?
    } else {
        Glibc(0, 0)
    };
    let packages = lock_requirements(platform, glibc, &reqs, &tag)?;
    Ok(Plan {
        ecosystem: "python".into(),
        python_version: python_version.into(),
        packages,
    })
}

/// Resolve a small, temporary requirements text with the store-pinned uv.
/// Callers own the resulting lock's cache key and persistence; this helper is
/// deliberately just the reusable uv invocation shared by project and sdist
/// planning.
pub(crate) fn lock_requirement_text_with_uv(
    store: &Store,
    platform: Platform,
    requirements_text: &str,
    python_version: &str,
    constraints: Option<&str>,
) -> io::Result<String> {
    let uv = crate::python::ensure_uv_for(store, platform)?.join("uv");
    let scratch = store.stage()?;
    let input = scratch.join("requirements.in");
    let output = scratch.join("requirements.lock.txt");
    let constraints_path = scratch.join("constraints.txt");
    let result = (|| {
        fs::write(&input, requirements_text)?;
        if let Some(constraints) = constraints {
            fs::write(&constraints_path, format!("{constraints}\n"))?;
        }
        let mut command = Command::new(&uv);
        command.args([
            "pip",
            "compile",
            "--generate-hashes",
            "--python-version",
            python_version,
            // Build requirements are metadata inputs, not permission to run
            // arbitrary backends. Build-only sdists fail loudly instead.
            "--no-build",
        ]);
        if constraints.is_some() {
            command.args([
                "-c",
                constraints_path.to_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "constraints path is not UTF-8")
                })?,
            ]);
        }
        let uv_output = command
            .arg(&input)
            .args(["-o"])
            .arg(&output)
            .output()
            .map_err(|e| {
                io::Error::new(e.kind(), format!("run store uv ({}): {e}", uv.display()))
            })?;
        if !uv_output.status.success() {
            let names = requirements_text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(|line| {
                    line.split(|ch: char| {
                        matches!(ch, '<' | '>' | '=' | '!' | '~' | '[' | ';' | ' ' | '\t')
                    })
                    .next()
                    .unwrap_or(line)
                })
                .collect::<Vec<_>>()
                .join(", ");
            let diagnostics = String::from_utf8_lossy(&uv_output.stderr)
                .trim()
                .to_string();
            return Err(io::Error::other(format!(
                "uv pip compile failed for build requirements ({names}); sdist-only build dependencies are unsupported during resolve-time metadata builds: {diagnostics}"
            )));
        }
        fs::read_to_string(&output)
    })();
    let _ = crate::store::remove_tree(&scratch);
    result
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
    fn requires_txt_sections_keep_markers_and_drop_extras() {
        let text = "base>=1\n[dev]\npytest\n[:python_version < '3.12']\nolddep==1\n";
        assert_eq!(
            parse_requires_txt(text).unwrap(),
            ["base>=1", "olddep==1; python_version < '3.12'"]
        );
    }

    #[test]
    fn requirements_options_and_inline_comments_are_data_only() {
        let text = "--index-url https://private.invalid/simple\nsix==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001 # note\n";
        assert_eq!(parse_requirements(text).unwrap().len(), 1);
        assert_eq!(
            unattested_index_options(text),
            vec!["--index-url https://private.invalid/simple"]
        );
    }

    #[test]
    fn rejects_duplicates_and_bad_abi_wheels() {
        let dup = "six==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001\n\
Six==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000002\n";
        assert!(parse_requirements(dup).is_err());
        // cp312 python tag with cp311 abi: unusable, must be rejected.
        let files = vec![fc("pkg-1.0-cp312-cp311-macosx_11_0_arm64.whl")];
        assert!(darwin_select(&files, "cp312").is_none());
        // py3 with non-none abi is not a pure wheel.
        let files2 = vec![fc("pkg-1.0-py3-cp39-any.whl")];
        assert!(darwin_select(&files2, "cp312").is_none());
    }

    #[test]
    fn rejections() {
        for bad in [
            "six>=1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "six==1.0",                    // no hash
            "six[extra]==1.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "six==1.0; python_version<'3' --hash=sha256:0000000000000000000000000000000000000000000000000000000000000001",
            "-e sixpkg",                  // editable that is neither local nor a URL
            "six==1.0 --hash=md5:abc",
        ] {
            assert!(parse_requirements(bad).is_err(), "should reject: {bad}");
        }
        assert!(
            parse_requirements("-r other.txt\n--index-url https://private.invalid/simple\n")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn identifies_project_and_direct_requirements() {
        for spec in [
            ".",
            "-e ./local",
            "-e ../local",
            "--editable ./local",
            "-e .",
            "./local",
            "/abs/path/pkg",
            "file:./wheel.whl",
            "pkg @ file:///path/pkg.whl",
            "https://example.test/pkg.whl",
            "gradio@https://example.test/gradio.whl",
            "pkg @ git+https://example.test/pkg.git@deadbeef",
        ] {
            assert!(is_skippable_spec(spec), "should skip: {spec}");
        }
        for spec in ["gradio@not-a-url", "six==1.0", "-r other.txt", "six"] {
            assert!(!is_skippable_spec(spec), "should not skip: {spec}");
        }
    }

    fn fc(filename: &str) -> FileCandidate {
        FileCandidate {
            filename: filename.into(),
            url: format!("https://x/{filename}"),
            sha256: "0".repeat(64),
        }
    }

    fn darwin_select<'a>(
        files: &'a [FileCandidate],
        python_tag: &str,
    ) -> Option<(&'a FileCandidate, ArtifactKind)> {
        select_file(files, python_tag, Platform::Aarch64AppleDarwin, Glibc(0, 0))
    }

    fn linux_select<'a>(
        files: &'a [FileCandidate],
        python_tag: &str,
        glibc: Glibc,
    ) -> Option<(&'a FileCandidate, ArtifactKind)> {
        select_file(files, python_tag, Platform::X86_64UnknownLinuxGnu, glibc)
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
        let (best, kind) = darwin_select(&files, "cp312").unwrap();
        assert_eq!(best.filename, "pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl");
        assert_eq!(kind, ArtifactKind::Wheel);

        // Without the exact native wheel, abi3 arm64 wins.
        let files2: Vec<_> = files
            .iter()
            .filter(|f| !f.filename.contains("cp312-cp312-macosx_11_0_arm64"))
            .cloned()
            .collect();
        let (best2, _) = darwin_select(&files2, "cp312").unwrap();
        assert_eq!(best2.filename, "pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl");

        // abi3 prefers highest compatible cp tag.
        let files3 = vec![
            fc("pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-cp311-abi3-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-cp313-abi3-macosx_11_0_arm64.whl"), // newer than ours: skip
        ];
        let (best3, _) = darwin_select(&files3, "cp312").unwrap();
        assert_eq!(best3.filename, "pkg-1.0-cp311-abi3-macosx_11_0_arm64.whl");

        // Only linux wheel: incompatible.
        let files4 = vec![fc("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl")];
        assert!(darwin_select(&files4, "cp312").is_none());

        // universal2 beats pure; pure beats sdist.
        let files5 = vec![
            fc("pkg-1.0.tar.gz"),
            fc("pkg-1.0-py3-none-any.whl"),
            fc("pkg-1.0-cp312-cp312-macosx_10_9_universal2.whl"),
        ];
        let (best5, _) = darwin_select(&files5, "cp312").unwrap();
        assert!(best5.filename.contains("universal2"));

        // Pure wheel with a platform tag (comfy-angle, patchright: hit-rate
        // run 2026-09-02) — compatible, beats the pure any-platform wheel.
        let files_plat = vec![
            fc("pkg-1.0-py3-none-any.whl"),
            fc("pkg-1.0-py3-none-macosx_11_0_arm64.whl"),
            fc("pkg-1.0-py3-none-manylinux_2_28_aarch64.whl"),
            fc("pkg-1.0-py3-none-win_amd64.whl"),
        ];
        let (best_plat, _) = darwin_select(&files_plat, "cp312").unwrap();
        assert_eq!(best_plat.filename, "pkg-1.0-py3-none-macosx_11_0_arm64.whl");
        let files_plat2 = vec![fc("pkg-1.0-py3-none-macosx_10_13_x86_64.whl")];
        assert!(darwin_select(&files_plat2, "cp312").is_none());

        let files6 = vec![fc("pkg-1.0.tar.gz"), fc("pkg-1.0-py2.py3-none-any.whl")];
        let (best6, kind6) = darwin_select(&files6, "cp312").unwrap();
        assert!(best6.filename.ends_with(".whl"));
        assert_eq!(kind6, ArtifactKind::Wheel);

        let files7 = vec![fc("pkg-1.0.tar.gz")];
        let (_, kind7) = darwin_select(&files7, "cp312").unwrap();
        assert_eq!(kind7, ArtifactKind::Sdist);
    }

    #[test]
    fn multi_tag_wheels_match_any_tag() {
        let files = vec![fc(
            "pkg-1.0-cp310.cp311.cp312-abi3-macosx_10_9_universal2.macosx_11_0_arm64.whl",
        )];
        let (best, _) = darwin_select(&files, "cp312").unwrap();
        assert!(best.filename.contains("abi3"));
    }

    #[test]
    fn linux_selection_prefers_manylinux_floor_then_linux_then_any_then_sdist() {
        let files = vec![
            fc("pkg-1.0.tar.gz"),
            fc("pkg-1.0-py3-none-any.whl"),
            fc("pkg-1.0-cp312-cp312-linux_x86_64.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux_2_5_x86_64.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
        ];
        let (best, _) = linux_select(&files, "cp312", Glibc(2, 43)).unwrap();
        assert!(best.filename.contains("manylinux_2_17"));

        let files = vec![
            fc("pkg-1.0.tar.gz"),
            fc("pkg-1.0-py3-none-any.whl"),
            fc("pkg-1.0-cp312-cp312-linux_x86_64.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux_2_5_x86_64.whl"),
        ];
        let (best, _) = linux_select(&files, "cp312", Glibc(2, 43)).unwrap();
        assert!(best.filename.contains("manylinux_2_5"));

        let files = vec![fc("pkg-1.0.tar.gz"), fc("pkg-1.0-py3-none-any.whl")];
        let (best, _) = linux_select(&files, "cp312", Glibc(2, 43)).unwrap();
        assert!(best.filename.ends_with("any.whl"));
    }

    #[test]
    fn linux_glibc_floor_must_fit_and_equal_is_accepted() {
        let files = vec![
            fc("pkg-1.0-cp312-cp312-manylinux2014_x86_64.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux2010_x86_64.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"),
        ];
        let (best, _) = linux_select(&files, "cp312", Glibc(2, 12)).unwrap();
        assert!(best.filename.contains("manylinux2010"));

        let equal = vec![fc("pkg-1.0-cp312-cp312-manylinux_2_12_x86_64.whl")];
        assert!(linux_select(&equal, "cp312", Glibc(2, 12)).is_some());
    }

    #[test]
    fn cross_platform_and_foreign_architecture_wheels_are_rejected() {
        for filename in [
            "pkg-1.0-cp312-cp312-musllinux_1_2_x86_64.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_17_aarch64.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_17_i686.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_17_ppc64le.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_17_s390x.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_17_armv7l.whl",
            "pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl",
        ] {
            assert!(
                linux_select(&[fc(filename)], "cp312", Glibc(2, 43)).is_none(),
                "should reject {filename}"
            );
        }
        assert!(darwin_select(
            &[fc("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl")],
            "cp312"
        )
        .is_none());
    }

    #[test]
    fn compressed_tags_are_expanded() {
        let manylinux = vec![fc(
            "pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        )];
        assert!(linux_select(&manylinux, "cp312", Glibc(2, 43)).is_some());

        let pure = vec![fc("pkg-1.0-py2.py3-none-any.whl")];
        assert!(linux_select(&pure, "cp312", Glibc(2, 43)).is_some());
    }

    #[test]
    fn abi3_is_below_exact_and_prefers_highest_compatible_floor() {
        let files = vec![
            fc("pkg-1.0-cp38-abi3-manylinux_2_17_x86_64.whl"),
            fc("pkg-1.0-cp311-abi3-manylinux_2_17_x86_64.whl"),
            fc("pkg-1.0-cp312-abi3-manylinux_2_17_x86_64.whl"),
            fc("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
        ];
        let (best, _) = linux_select(&files, "cp312", Glibc(2, 43)).unwrap();
        assert!(best.filename.contains("cp312-cp312"));

        let abi3_only = vec![
            fc("pkg-1.0-cp38-abi3-manylinux_2_17_x86_64.whl"),
            fc("pkg-1.0-cp311-abi3-manylinux_2_17_x86_64.whl"),
            fc("pkg-1.0-cp312-abi3-manylinux_2_17_x86_64.whl"),
            fc("pkg-1.0-cp313-abi3-manylinux_2_17_x86_64.whl"),
        ];
        let (best, _) = linux_select(&abi3_only, "cp312", Glibc(2, 43)).unwrap();
        assert!(best.filename.contains("cp312-abi3"));

        let too_new = vec![fc("pkg-1.0-cp313-abi3-manylinux_2_17_x86_64.whl")];
        assert!(linux_select(&too_new, "cp312", Glibc(2, 43)).is_none());
    }

    #[test]
    fn pure_wheel_python_tags_are_version_checked() {
        for tag in ["py2", "py27", "py4", "cp27", "py313"] {
            let files = vec![fc(&format!("pkg-1.0-{tag}-none-any.whl"))];
            assert!(
                linux_select(&files, "cp312", Glibc(2, 43)).is_none(),
                "should reject {tag}"
            );
        }
        for tag in ["py3", "py311", "py312", "cp312"] {
            let files = vec![fc(&format!("pkg-1.0-{tag}-none-any.whl"))];
            assert!(
                linux_select(&files, "cp312", Glibc(2, 43)).is_some(),
                "should accept {tag}"
            );
        }
    }

    #[test]
    fn abi_mismatch_and_malformed_wheels_are_rejected() {
        let mismatch = vec![fc("pkg-1.0-cp312-cp311-manylinux_2_17_x86_64.whl")];
        assert!(linux_select(&mismatch, "cp312", Glibc(2, 43)).is_none());

        for filename in [
            "pkg-1.0-cp312-cp312.whl",
            "pkg-1.0-cp312-cp312-manylinux_bad_x86_64.whl",
            "pkg-1.0-cp312-cp312-manylinux_2_999999999999999999999_x86_64.whl",
            "pkg-1.0-cp312-cp312-manylinux_999999999999999999999_17_x86_64.whl",
        ] {
            assert!(
                linux_select(&[fc(filename)], "cp312", Glibc(2, 43)).is_none(),
                "should reject malformed {filename}"
            );
        }
    }

    #[test]
    fn selection_ties_break_by_filename() {
        let files = vec![
            fc("b-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
            fc("a-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
        ];
        let (best, _) = linux_select(&files, "cp312", Glibc(2, 43)).unwrap();
        assert_eq!(best.filename, "a-1.0-cp312-cp312-manylinux_2_17_x86_64.whl");
    }

    #[test]
    fn any_platform_requires_none_abi() {
        for platform in Platform::ALL {
            for f in ["pkg-1.0-cp312-cp312-any.whl", "pkg-1.0-cp39-abi3-any.whl"] {
                assert!(
                    score(f, "cp312", *platform, Glibc(2, 43)).is_none(),
                    "{f} must be rejected on {platform:?}"
                );
            }
            assert!(score("pkg-1.0-py3-none-any.whl", "cp312", *platform, Glibc(2, 43)).is_some());
        }
    }

    #[test]
    fn glibc_version_parsing() {
        assert_eq!(parse_glibc_version("2.43"), Some(Glibc(2, 43)));
        assert_eq!(parse_glibc_version("glibc 2.43\n"), Some(Glibc(2, 43)));
        assert_eq!(parse_glibc_version("2.43.9000"), Some(Glibc(2, 43)));
        assert_eq!(parse_glibc_version("x"), None);
        assert_eq!(parse_glibc_version("2"), None);
        assert_eq!(parse_glibc_version("+2.43"), None);
        assert_eq!(parse_glibc_version("2.99999999999999999999"), None);
    }

    #[test]
    fn manylinux_floor_rejects_signs_and_python4_abi3_floors_are_not_floors() {
        let linux = Platform::X86_64UnknownLinuxGnu;
        assert!(score(
            "pkg-1.0-cp312-cp312-manylinux_+2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 43)
        )
        .is_none());
        assert!(score(
            "pkg-1.0-cp40-abi3-manylinux_2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 43)
        )
        .is_none());
        assert!(score(
            "pkg-1.0-cp38-abi3-manylinux_2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 43)
        )
        .is_some());
        assert!(score(
            "pkg-1.0-cp310-abi3-manylinux_2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 43)
        )
        .is_some());
    }

    #[test]
    fn linux_platform_none_wheel_beats_any_and_compressed_second_alternative_counts() {
        let linux = Platform::X86_64UnknownLinuxGnu;
        let plat = score(
            "pkg-1.0-py3-none-manylinux_2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 43),
        )
        .unwrap();
        let any = score("pkg-1.0-py3-none-any.whl", "cp312", linux, Glibc(2, 43)).unwrap();
        assert!(score_order(plat) < score_order(any));
        // only the second alternative fits glibc 2.17
        assert!(score(
            "pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.manylinux_2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 17)
        )
        .is_some());
        assert!(score(
            "pkg-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 17)
        )
        .is_none());
        // cp313 target
        assert!(score(
            "pkg-1.0-cp313-cp313-manylinux_2_17_x86_64.whl",
            "cp313",
            linux,
            Glibc(2, 43)
        )
        .is_some());
        assert!(score(
            "pkg-1.0-cp313-cp313-manylinux_2_17_x86_64.whl",
            "cp312",
            linux,
            Glibc(2, 43)
        )
        .is_none());
    }

    #[test]
    fn darwin_abi3_ranks_above_platform_none_like_pip() {
        // Deliberate change from the pre-port selector, which ranked
        // py3-none-macosx_*_arm64 ahead of abi3. pip's supported-tag order
        // puts every abi3 variant before py3-none-<plat>; we follow pip.
        let mac = Platform::Aarch64AppleDarwin;
        let abi3 = score(
            "pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl",
            "cp312",
            mac,
            Glibc(0, 0),
        )
        .unwrap();
        let none = score(
            "pkg-1.0-py3-none-macosx_11_0_arm64.whl",
            "cp312",
            mac,
            Glibc(0, 0),
        )
        .unwrap();
        let exact = score(
            "pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl",
            "cp312",
            mac,
            Glibc(0, 0),
        )
        .unwrap();
        assert!(score_order(exact) < score_order(abi3));
        assert!(score_order(abi3) < score_order(none));
    }
}

#[cfg(test)]
mod git_requirement_tests {
    use super::*;

    #[test]
    fn pinned_git_requirements_parse_and_unpinned_ones_do_not() {
        let commit = "a".repeat(40);
        let req = parse_git_requirement(&format!(
            "six @ git+https://github.com/benjaminp/six@{commit}"
        ))
        .expect("a pinned git requirement");
        assert_eq!(req.name, "six");
        assert_eq!(req.version, format!("0+git.{}", &commit[..12]));
        assert!(req.sha256s.is_empty(), "the commit is the verification");
        let source = req.git.expect("a git source");
        assert_eq!(source.url, "https://github.com/benjaminp/six");
        assert_eq!(source.commit, commit);
        assert_eq!(source.subdirectory, None);

        let with_subdir = parse_git_requirement(&format!(
            "pkg @ git+https://example.invalid/repo@{commit}#subdirectory=python/pkg"
        ))
        .expect("subdirectory form");
        assert_eq!(
            with_subdir.git.unwrap().subdirectory.as_deref(),
            Some("python/pkg")
        );

        // Unpinned or non-git forms are not git requirements.
        assert!(parse_git_requirement("six @ git+https://github.com/benjaminp/six@main").is_none());
        assert!(parse_git_requirement("six @ https://example.invalid/six.tar.gz").is_none());
        assert!(parse_git_requirement("six==1.17.0").is_none());
    }

    #[test]
    fn a_git_line_survives_requirements_parsing() {
        let commit = "b".repeat(40);
        let text = format!(
            "six==1.17.0 --hash=sha256:{}\npkg @ git+https://example.invalid/repo@{commit}\n",
            "c".repeat(64)
        );
        let reqs = parse_requirements(&text).expect("parse");
        assert_eq!(reqs.len(), 2);
        let git = reqs
            .iter()
            .find(|r| r.name == "pkg")
            .expect("the git requirement");
        assert_eq!(git.git.as_ref().unwrap().commit, commit);
        // The registry requirement is untouched.
        let six = reqs.iter().find(|r| r.name == "six").expect("six");
        assert!(six.git.is_none());
        assert_eq!(six.version, "1.17.0");
    }
}

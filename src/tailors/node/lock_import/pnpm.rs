//! pnpm-lock.yaml import (node tailor): importers, snapshots, catalogs,
//! patches, and the graph they resolve to.

use super::*;

/// Every importer `pnpm-lock.yaml` enumerates, as paths relative to the lock
/// root (`.` is the root itself).
///
/// This is the authoritative membership list for a pnpm workspace: pnpm
/// produced it with its own glob engine, so consulting it settles membership
/// exactly rather than reimplementing that engine's syntax.
pub fn pnpm_lock_importers(lock_yaml: &str) -> io::Result<Vec<String>> {
    let parsed = parse_yaml(lock_yaml)?;
    let root = yaml_map(&parsed, "pnpm-lock.yaml")?;
    Ok(importer_map(root)?.into_keys().collect())
}

pub(super) fn trim_peer_suffix(value: &str) -> &str {
    let parenthesis = value.find('(');
    // pnpm v9 also encodes peer context as `_peer@version`. An underscore
    // before the package/version separator is an ordinary npm package-name
    // character (for example `evp_bytestokey@1.0.3`) and is not a suffix.
    let underscore = {
        let delimiter = if value.starts_with('@') {
            value[1..].find('@').map(|index| index + 1)
        } else {
            value.find('@')
        };
        delimiter
            .and_then(|index| {
                value[index + 1..]
                    .find('_')
                    .map(|offset| index + 1 + offset)
            })
            .or_else(|| delimiter.is_none().then(|| value.find('_')).flatten())
    };
    [parenthesis, underscore]
        .into_iter()
        .flatten()
        .min()
        .map(|index| &value[..index])
        .unwrap_or(value)
}

pub(super) fn split_identity(value: &str) -> Option<(String, String)> {
    let value = trim_peer_suffix(value.trim().trim_start_matches('/'));
    let at = if value.starts_with('@') {
        value[1..].find('@')? + 1
    } else {
        value.find('@')?
    };
    if at == 0 || at + 1 >= value.len() {
        return None;
    }
    Some((value[..at].to_string(), value[at + 1..].to_string()))
}

pub(super) fn normalize_pnpm_identity(key: &str) -> Option<(String, String)> {
    if let Some(identity) = split_identity(key) {
        return Some(identity);
    }
    let value = key.trim().trim_start_matches('/');
    let slash = value.rfind('/')?;
    if slash == 0 || slash + 1 >= value.len() {
        return None;
    }
    Some((value[..slash].to_string(), value[slash + 1..].to_string()))
}

/// Normalize the spelling of a pnpm snapshot key once, while retaining its
/// peer suffix. Package metadata is keyed by the base identity below; the
/// graph is keyed by this full identity. pnpm v6 used `/name/version` and
/// `/name@version`, while newer lockfiles generally use `name@version`.
pub(super) fn normalize_pnpm_snapshot_key(key: &str) -> Option<String> {
    let raw = key.trim().trim_start_matches('/');
    if raw.is_empty() {
        return None;
    }
    let (name, version) = if let Some((name, _version)) = split_identity(raw) {
        // split_identity deliberately strips peer suffixes, so recover the
        // exact version from the separator in the original spelling.
        let name_end = if raw.starts_with('@') {
            raw[1..].find('@').map(|index| index + 1)?
        } else {
            raw.find('@')?
        };
        (name, raw[name_end + 1..].to_string())
    } else {
        let slash = raw.rfind('/')?;
        if slash == 0 || slash + 1 >= raw.len() {
            return None;
        }
        (raw[..slash].to_string(), raw[slash + 1..].to_string())
    };
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(format!("{name}@{version}"))
}

pub(super) fn identity_key_for_snapshot(key: &str) -> String {
    normalize_pnpm_identity(key)
        .map(|(name, version)| identity_key(&name, &version))
        .unwrap_or_else(|| key.to_string())
}

pub(super) fn patch_path(project_dir: &Path, raw: &str) -> io::Result<PathBuf> {
    let path = Path::new(raw);
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.starts_with('~')
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(err(format!(
            "pnpm patch path {raw:?} must be a project-relative file"
        )));
    }
    let root = project_dir.canonicalize()?;
    let path = project_dir.join(path).canonicalize()?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(err(format!(
            "pnpm patch path {raw:?} is outside the project or is not a file"
        )));
    }
    Ok(path)
}

pub(super) fn verify_patch_hash(
    package: &str,
    path: &Path,
    declared: &str,
) -> io::Result<Option<String>> {
    let bytes = fs::read(path)?;
    let matched = check_patch_hash(declared, &bytes).map_err(|actual| {
        err(format!(
            "pnpm patch {package} hash mismatch for {} (expected {declared}, got {actual})",
            path.display()
        ))
    })?;
    Ok(match matched {
        PatchMatch::Raw => None,
        PatchMatch::Normalized => Some(hex::encode(Sha256::digest(&bytes))),
    })
}

/// Length of pnpm 9's base32 patch hash. md5 is 16 bytes and RFC 4648 base32
/// spends one character per 5 bits, so 128 bits fill 25 characters plus one
/// holding the trailing 3 bits: 26 characters once the 6 `=` are stripped.
const PNPM_BASE32_HASH_LEN: usize = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatchMatch {
    Raw,
    Normalized,
}

/// Check a lockfile-declared `patchedDependencies` hash against patch bytes.
/// On success, the result reports whether the declaration matched the raw bytes
/// or the pnpm-normalized text. The md5/base32 form always reports
/// `PatchMatch::Normalized`. The error carries the computed hash in the same
/// encoding the lockfile used (base32 for the md5 form, hex for the sha256
/// forms), so a caller can print a comparable expected/actual pair; for the
/// `sha256-<hex>` spelling the prefix is preserved so the pair reads the same.
///
/// pnpm changed both the algorithm and the encoding between major versions and
/// blanket accepts every form still found in lockfiles:
///
/// * pnpm 9 (`lockfileVersion: '9.0'`) writes `createBase32HashFromFile`:
///   md5 of the file, RFC 4648 base32, padding stripped, lowercased —
///   <https://github.com/pnpm/pnpm/blob/v9.15.0/packages/crypto.base32-hash/src/index.ts>
///   `base32.stringify(crypto.hash('md5', str, 'buffer')).replace(/(=+)$/, '').toLowerCase()`,
///   called as `hash: await createBase32HashFromFile(patchFilePath)` from
///   <https://github.com/pnpm/pnpm/blob/v9.15.0/lockfile/settings-checker/src/calcPatchHashes.ts>.
/// * pnpm 10 and 11 write `createHexHashFromFile` from that same call site:
///   the full 64-character sha256 hex digest —
///   <https://github.com/pnpm/pnpm/blob/v10.15.0/crypto/hash/src/index.ts>
///   (`createHexHash` is `crypto.hash('sha256', input, 'hex')`).
/// * bare `<64 hex>` is pnpm 10/11's `createHexHashFromFile` result.
/// * `sha256-<64 hex>` is accepted for the explicit `{path, hash}` shape that
///   hand-written and generated lockfiles use.
///
/// For both pnpm-native forms, pnpm reads the file as UTF-8, replacing invalid
/// sequences with U+FFFD, then replaces CRLF with LF
/// (`readNormalizedFile`: `content.split('\r\n').join('\n')`). The md5 form
/// accepts only that normalized/lossy digest. SHA-256 forms accept either that
/// digest or the raw-byte digest, preserving compatibility with lockfiles
/// produced by the earlier blanket implementation. A normalized match must
/// bind the raw bytes separately for environment identity because distinct
/// invalid UTF-8 byte sequences can normalize to the same text. A raw match
/// keeps the historical identity unchanged.
///
/// Everything else fails closed: a wrong length, a wrong alphabet, and
/// uppercase or still-padded base32 all compare unequal to the computed digest.
pub(crate) fn check_patch_hash(declared: &str, bytes: &[u8]) -> Result<PatchMatch, String> {
    let normalized = pnpm_normalized(bytes);
    if declared.len() == PNPM_BASE32_HASH_LEN {
        let actual = base32_lower(&md5(&normalized));
        return if declared == actual {
            Ok(PatchMatch::Normalized)
        } else {
            Err(actual)
        };
    }
    let normalized_sha256 = hex::encode(Sha256::digest(&normalized));
    let expected = declared.strip_prefix("sha256-").unwrap_or(declared);
    let raw_sha256 = hex::encode(Sha256::digest(bytes));
    if expected.len() == 64
        && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        && expected.eq_ignore_ascii_case(&raw_sha256)
    {
        Ok(PatchMatch::Raw)
    } else if expected.len() == 64
        && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        && expected.eq_ignore_ascii_case(&normalized_sha256)
    {
        Ok(PatchMatch::Normalized)
    } else if declared.starts_with("sha256-") {
        Err(format!("sha256-{normalized_sha256}"))
    } else {
        Err(normalized_sha256)
    }
}

/// Decode as UTF-8 with U+FFFD replacement, then collapse every CRLF to LF,
/// matching pnpm's `readNormalizedFile`. A lone CR is left alone.
fn pnpm_normalized(bytes: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(bytes)
        .split("\r\n")
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

/// RFC 4648 base32 with the lowercase alphabet and no padding, the shape
/// pnpm's `createBase32Hash` produces.
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// RFC 1321 md5. Needed only to read pnpm 9's patch hashes, which is not worth
/// a dependency; this is never used to attest anything blanket itself writes.
fn md5(input: &[u8]) -> [u8; 16] {
    /// Per-round left-rotation amounts (RFC 1321 section 3.4).
    const SHIFTS: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    /// `SINES[i] = floor(2^32 * abs(sin(i + 1)))` (RFC 1321 table T).
    const SINES: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut message = Vec::with_capacity(input.len() + 72);
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_le_bytes());
    for block in message.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (word, raw) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(raw.try_into().expect("4 bytes"));
        }
        let [mut a, mut b, mut c, mut d] = state;
        for round in 0..64 {
            let (mixed, index) = match round / 16 {
                0 => ((b & c) | (!b & d), round),
                1 => ((d & b) | (!d & c), (5 * round + 1) % 16),
                2 => (b ^ c ^ d, (3 * round + 5) % 16),
                _ => (c ^ (b | !d), (7 * round) % 16),
            };
            let rotated = mixed
                .wrapping_add(a)
                .wrapping_add(SINES[round])
                .wrapping_add(words[index])
                .rotate_left(SHIFTS[round]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0u8; 16];
    for (slot, word) in digest.chunks_exact_mut(4).zip(state) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

pub(super) fn pnpm_patches(
    root: &BTreeMap<String, YamlValue>,
    project_dir: &Path,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<Vec<(String, NpmPatch)>> {
    let Some(value) = root.get("patchedDependencies") else {
        return Ok(Vec::new());
    };
    let patches = yaml_map(value, "pnpm patchedDependencies")?;
    let mut result = Vec::new();
    for (package, value) in patches {
        // pnpm 9 writes the hash in the lockfile and uses the conventional
        // patches/<package>@<version>.patch path. Also accept the explicit
        // {path, hash} shape used by older/generated lockfile variants.
        let (raw_path, hash) = if let Some(hash) = yaml_str(Some(value)) {
            let escaped = format!("patches/{}.patch", package.replace('/', "__"));
            let conventional = format!("patches/{package}.patch");
            let raw_path = if project_dir.join(&escaped).is_file() {
                escaped
            } else {
                conventional
            };
            (raw_path, hash)
        } else {
            let entry = yaml_map(value, &format!("pnpm patch {package}"))?;
            let raw_path = yaml_str(entry.get("path"))
                .ok_or_else(|| err(format!("pnpm patch {package} has no string path")))?;
            let hash = yaml_str(entry.get("hash"))
                .ok_or_else(|| err(format!("pnpm patch {package} has no string patch hash")))?;
            (raw_path.to_string(), hash)
        };
        let path = patch_path(project_dir, &raw_path)?;
        let content_sha256 = verify_patch_hash(package, &path, hash)?;
        let identity = normalize_pnpm_snapshot_key(package).ok_or_else(|| {
            err(format!(
                "pnpm patch {package} has no package@version identity"
            ))
        })?;
        if hash.len() == PNPM_BASE32_HASH_LEN {
            let detail = "pnpm 9 md5 patch hash accepted and verified, but is cryptographically weak; the environment id binds the patch by sha256";
            if let Err(policy_error) =
                record(crate::kernel::policy::WEAK_INTEGRITY, &identity, detail)
            {
                return Err(err(format!(
                    "pnpm patch {identity} uses weak md5 hash ({policy_error})"
                )));
            }
        }
        result.push((
            identity,
            NpmPatch {
                path: path.to_string_lossy().into_owned(),
                hash: hash.to_string(),
                content_sha256,
            },
        ));
    }
    Ok(result)
}

pub(super) fn attach_pnpm_patches(
    nodes: &mut BTreeMap<String, Node>,
    patches: &[(String, NpmPatch)],
) -> io::Result<()> {
    let mut applied = BTreeSet::new();
    for node in nodes.values_mut() {
        let Some((identity, patch)) = patches.iter().find(|(identity, _)| {
            identity_key_for_snapshot(identity) == identity_key_for_snapshot(&node.key)
        }) else {
            continue;
        };
        node.patch = Some(patch.clone());
        applied.insert(identity);
    }
    if applied.len() != patches.len() {
        let missing = patches
            .iter()
            .filter(|(identity, _)| !applied.contains(identity))
            .map(|(identity, _)| identity)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(err(format!(
            "pnpm patchedDependencies has no matching locked package: {missing}"
        )));
    }
    Ok(())
}

pub(super) fn source_error(
    name: &str,
    resolution: Option<&BTreeMap<String, YamlValue>>,
) -> Option<String> {
    // A commit hash is a fingerprint: pinned git sources are realized.
    if pinned_git_source(resolution).is_some() {
        return None;
    }
    let resolution = resolution?;
    let kind = yaml_str(resolution.get("type")).unwrap_or_default();
    let repo = yaml_str(resolution.get("repo"));
    if kind == "git" || repo.is_some() {
        let repo = repo.unwrap_or("(unknown repository)");
        let commit = yaml_str(resolution.get("commit")).unwrap_or("unspecified commit");
        // Same persisted wording as `git_dependency_detail`; do not reword.
        return Some(
            crate::tailors::node::git_dependency_detail(name, &format!("git+{repo}#{commit}"))
                .unwrap_or_else(|| {
                    format!(
                        "npm_git_dep: {name}: repo {repo}, commit {commit}; \
                     git sources are deferred to NEXT.md item 4"
                    )
                }),
        );
    }
    let tarball = yaml_str(resolution.get("tarball")).unwrap_or_default();
    let has_integrity = yaml_str(resolution.get("integrity")).is_some();
    if !has_integrity {
        if let Some(detail) = crate::tailors::node::git_dependency_detail(name, tarball) {
            return Some(detail);
        }
    }
    if tarball.starts_with("file:") || tarball.starts_with("link:") {
        return Some(format!("local dependency {tarball}"));
    }
    None
}

pub(super) fn dep_version_key(
    name: &str,
    version: &str,
    snapshots: &BTreeMap<String, Node>,
) -> Option<String> {
    let version = version.trim();
    let direct = normalize_pnpm_snapshot_key(&format!("{name}@{version}"))
        .unwrap_or_else(|| format!("{name}@{version}"));
    if snapshots.contains_key(&direct) {
        return Some(direct);
    }
    let identity = identity_key(name, version);
    let candidates: Vec<String> = snapshots
        .keys()
        .filter(|key| identity_key_for_snapshot(key) == identity)
        .cloned()
        .collect();
    // A version-only edge is unambiguous only when the lockfile has one
    // snapshot for that package identity. If peer variants exist, choosing
    // one lexicographically is a wrong graph; pnpm normally writes the peer
    // suffix into the edge and the exact lookup above handles it.
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

pub(super) fn workspace_target(
    project_dir: &Path,
    importer: &str,
    raw: &str,
) -> io::Result<String> {
    // pnpm v6 collapses a workspace package's `file:../..` importer
    // reference to the synthetic `file:` package. That entry denotes the
    // project root, not an empty/unsafe path.
    if raw.is_empty() {
        return Ok(".".into());
    }
    if raw.starts_with('/') || raw.starts_with('~') {
        return Err(err(format!(
            "workspace link target {raw:?} is outside the project"
        )));
    }
    let mut relative = Vec::<String>::new();
    if importer != "." {
        for component in Path::new(importer).components() {
            if let Component::Normal(value) = component {
                relative.push(value.to_string_lossy().into_owned());
            }
        }
    }
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(value) => relative.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                if relative.pop().is_none() {
                    return Err(err(format!(
                        "workspace link target {raw:?} is outside the project"
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(err(format!(
                    "workspace link target {raw:?} is outside the project"
                )))
            }
        }
    }
    let target = if relative.is_empty() {
        ".".to_string()
    } else {
        relative.join("/")
    };
    let root = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    let target_path = root.join(&target);
    if target_path.exists() {
        let canonical = target_path.canonicalize()?;
        if !canonical.starts_with(&root) {
            return Err(err(format!(
                "workspace link target {raw:?} is outside the project"
            )));
        }
    }
    Ok(target)
}

pub(super) fn target_for_ref(
    name: &str,
    reference: &str,
    importer: &str,
    snapshots: &BTreeMap<String, Node>,
    project_dir: &Path,
) -> Target {
    let reference = reference.trim();
    let local_reference = reference
        .find("file:")
        .map(|index| &reference[index..])
        .or_else(|| reference.find("link:").map(|index| &reference[index..]))
        .or_else(|| reference.strip_prefix("link:").map(|_| reference));
    if let Some(local_reference) = local_reference {
        let raw = local_reference
            .split_once(':')
            .map(|(_, value)| value)
            .unwrap_or("");
        // pnpm v9 writes `file:` versions as project-relative paths even
        // when the importer is nested, while `link:` versions remain
        // importer-relative. Prefer the existing project-root target for the
        // former and retain the importer-relative fallback for older locks.
        let target = if local_reference.starts_with("file:") {
            workspace_target(project_dir, ".", raw)
                .ok()
                .filter(|target| project_dir.join(target).exists())
                .map(Ok)
                .unwrap_or_else(|| workspace_target(project_dir, importer, raw))
        } else {
            workspace_target(project_dir, importer, raw)
        };
        return match target {
            Ok(target) => Target::Link(target),
            Err(error) => Target::External(format!(
                "{error} (reference {reference:?}, importer {importer:?})"
            )),
        };
    }
    if reference.starts_with("workspace:") || reference.starts_with("catalog:") {
        return Target::External(format!("unresolved {reference} dependency for {name}"));
    }
    // pnpm represents npm aliases as logical-name: real-name@version. The
    // physical package is keyed by the real name, while placement still uses
    // the logical dependency name.
    if let Some(snapshot_key) = normalize_pnpm_snapshot_key(reference) {
        if snapshots.contains_key(&snapshot_key) {
            return Target::Node(snapshot_key);
        }
    }
    if let Some((real_name, real_version)) = split_identity(reference) {
        return match dep_version_key(&real_name, &real_version, snapshots) {
            Some(key) => Target::Node(key),
            None => Target::External(format!("missing snapshot for {name}@{reference}")),
        };
    }
    match dep_version_key(name, reference, snapshots) {
        Some(key) => Target::Node(key),
        None => Target::External(format!("missing snapshot for {name}@{reference}")),
    }
}

pub(super) fn importer_dependencies(
    importer: &BTreeMap<String, YamlValue>,
    importer_name: &str,
    snapshots: &BTreeMap<String, Node>,
    project_dir: &Path,
    catalogs: &BTreeMap<String, BTreeMap<String, String>>,
    local_snapshots: &BTreeMap<String, Vec<Dependency>>,
    local_link_deps: &mut BTreeMap<String, Vec<Dependency>>,
) -> io::Result<Vec<Dependency>> {
    let mut deps = BTreeMap::<String, Dependency>::new();
    for (field, optional) in [
        ("dependencies", false),
        ("devDependencies", false),
        ("optionalDependencies", true),
    ] {
        let Some(value) = importer.get(field) else {
            continue;
        };
        let map = yaml_map(value, &format!("importer {importer_name} {field}"))?;
        for (name, value) in map {
            let item = yaml_map(value, &format!("importer {importer_name} {field} {name}"))?;
            let specifier = yaml_str(item.get("specifier")).unwrap_or_default();
            if let Some(catalog) = specifier.strip_prefix("catalog:") {
                let catalog_name = if catalog.is_empty() {
                    "default"
                } else {
                    catalog
                };
                if catalogs
                    .get(catalog_name)
                    .and_then(|catalog| catalog.get(name))
                    .is_none()
                {
                    return Err(err(format!(
                        "importer {importer_name} dependency {name}: catalog:{catalog} is not defined"
                    )));
                }
            }
            let version = yaml_str(item.get("version")).ok_or_else(|| {
                err(format!(
                    "importer {importer_name} dependency {name}: missing version"
                ))
            })?;
            let target = target_for_ref(name, version, importer_name, snapshots, project_dir);
            if let Target::Link(target_path) = &target {
                if let Some(dependencies) = local_snapshots.get(
                    &normalize_pnpm_snapshot_key(&format!("{name}@{version}")).unwrap_or_default(),
                ) {
                    local_link_deps
                        .entry(target_path.clone())
                        .or_insert_with(|| dependencies.clone());
                }
            }
            deps.insert(
                name.clone(),
                Dependency {
                    name: name.clone(),
                    target,
                    optional,
                },
            );
        }
    }
    Ok(deps.into_values().collect())
}

pub(super) fn pnpm_catalogs(
    root: &BTreeMap<String, YamlValue>,
) -> io::Result<BTreeMap<String, BTreeMap<String, String>>> {
    let mut catalogs = BTreeMap::new();
    let Some(value) = root.get("catalogs") else {
        return Ok(catalogs);
    };
    let map = yaml_map(value, "catalogs")?;
    for (name, value) in map {
        let entries = yaml_map(value, &format!("catalog {name}"))?;
        let mut catalog = BTreeMap::new();
        for (package, value) in entries {
            let selected = yaml_str(Some(value))
                .or_else(|| {
                    yaml_map(value, "")
                        .ok()
                        .and_then(|map| yaml_str(map.get("version")))
                })
                .unwrap_or_default()
                .to_string();
            catalog.insert(package.clone(), selected);
        }
        catalogs.insert(name.clone(), catalog);
    }
    Ok(catalogs)
}

pub(super) fn snapshot_dependencies(
    snapshot: &BTreeMap<String, YamlValue>,
    snapshot_key: &str,
    lookup: &BTreeMap<String, Node>,
    project_dir: &Path,
) -> io::Result<Vec<Dependency>> {
    let mut deps = BTreeMap::<String, Dependency>::new();
    for (field, optional) in [("dependencies", false), ("optionalDependencies", true)] {
        if let Some(value) = snapshot.get(field) {
            let map = yaml_map(value, &format!("snapshot {snapshot_key} {field}"))?;
            for (name, value) in map {
                let reference = yaml_str(Some(value)).unwrap_or_default();
                deps.insert(
                    name.clone(),
                    Dependency {
                        name: name.clone(),
                        target: target_for_ref(name, reference, ".", lookup, project_dir),
                        optional,
                    },
                );
            }
        }
    }
    Ok(deps.into_values().collect())
}

pub(super) fn is_local_snapshot(snapshot_key: &str) -> bool {
    normalize_pnpm_identity(snapshot_key)
        .map(|(_, version)| version.starts_with("file:") || version.starts_with("link:"))
        .unwrap_or(false)
}

pub(super) fn local_snapshot_target(
    snapshot_key: &str,
    project_dir: &Path,
) -> io::Result<Option<String>> {
    let Some((_, version)) = normalize_pnpm_identity(snapshot_key) else {
        return Ok(None);
    };
    let Some(raw) = version
        .strip_prefix("file:")
        .or_else(|| version.strip_prefix("link:"))
    else {
        return Ok(None);
    };
    workspace_target(project_dir, ".", raw).map(Some)
}

pub(super) fn pnpm_nodes(
    packages: &BTreeMap<String, YamlValue>,
    snapshots_value: Option<&YamlValue>,
    project_dir: &Path,
) -> io::Result<(BTreeMap<String, Node>, BTreeMap<String, Vec<Dependency>>)> {
    // Keep one metadata record per canonical package key. These records are
    // tarball facts only; they are never graph nodes until a snapshot selects
    // them. This prevents a v6 `/a@1` package entry from shadowing the real
    // dependency-bearing snapshot with an empty placeholder.
    let mut package_nodes = BTreeMap::<String, Node>::new();
    for (raw_key, value) in packages {
        let entry = yaml_map(value, &format!("packages {raw_key}"))?;
        let resolution = entry.get("resolution").and_then(|value| match value {
            YamlValue::Map(map) => Some(map),
            _ => None,
        });
        if yaml_str(resolution.and_then(|map| map.get("type"))) == Some("directory") {
            // pnpm 6 represents workspace source roots as a synthetic
            // packages entry such as 'file:'; importer edges become NpmLink.
            continue;
        }
        let Some(snapshot_key) = normalize_pnpm_snapshot_key(raw_key) else {
            return Err(err(format!(
                "packages entry {raw_key:?} has no name@version identity"
            )));
        };
        let Some((name, version)) = normalize_pnpm_identity(&snapshot_key) else {
            return Err(err(format!(
                "packages entry {raw_key:?} has no name@version identity"
            )));
        };
        let integrity = resolution
            .and_then(|resolution| yaml_str(resolution.get("integrity")))
            .unwrap_or_default()
            .to_string();
        let external = source_error(&name, resolution);
        // A pinned git source is recorded as a git+ URL so the package builder
        // (which parses it back) realizes the commit.
        let url = match pinned_git_source(resolution) {
            Some(source) => format!("git+{}#{}", source.url, source.commit),
            None => package_url(&name, &version, resolution).unwrap_or_default(),
        };
        if package_nodes
            .insert(
                snapshot_key.clone(),
                Node {
                    key: snapshot_key,
                    name,
                    version,
                    url,
                    integrity,
                    optional: yaml_bool(entry.get("optional")),
                    os: yaml_list(entry.get("os")),
                    cpu: yaml_list(entry.get("cpu")),
                    libc: yaml_list(entry.get("libc")),
                    external,
                    patch: None,
                    deps: Vec::new(),
                },
            )
            .is_some()
        {
            return Err(err(format!(
                "duplicate normalized pnpm package key {raw_key:?}"
            )));
        }
    }

    let mut snapshots = BTreeMap::<String, BTreeMap<String, YamlValue>>::new();
    if let Some(value) = snapshots_value {
        for (raw_key, value) in yaml_map(value, "snapshots")? {
            let snapshot_key = normalize_pnpm_snapshot_key(raw_key).ok_or_else(|| {
                err(format!(
                    "snapshots entry {raw_key:?} has no name@version identity"
                ))
            })?;
            if snapshots
                .insert(
                    snapshot_key,
                    yaml_map(value, &format!("snapshots {raw_key}"))?.clone(),
                )
                .is_some()
            {
                return Err(err(format!(
                    "duplicate normalized pnpm snapshot key {raw_key:?}"
                )));
            }
        }
    } else {
        // pnpm 6 stores dependency edges on the package entries. Normalize
        // those keys into the same full snapshot namespace before lookup.
        for (raw_key, value) in packages {
            let Some(snapshot_key) = normalize_pnpm_snapshot_key(raw_key) else {
                continue;
            };
            if package_nodes.contains_key(&snapshot_key) {
                snapshots.insert(
                    snapshot_key,
                    yaml_map(value, &format!("packages {raw_key}"))?.clone(),
                );
            }
        }
    }

    let snapshot_metadata: BTreeMap<String, Node> = snapshots
        .keys()
        .filter_map(|snapshot_key| {
            let base = identity_key_for_snapshot(snapshot_key);
            package_nodes
                .get(snapshot_key)
                .or_else(|| {
                    package_nodes
                        .values()
                        .find(|node| identity_key(&node.name, &node.version) == base)
                })
                .map(|node| {
                    let mut node = node.clone();
                    node.key = snapshot_key.clone();
                    (snapshot_key.clone(), node)
                })
        })
        .collect();

    if snapshots.is_empty() {
        // Some v9 lockfiles legitimately carry an empty snapshots map for a
        // graph with no package-to-package edges. The package entries are
        // then the complete set of real nodes, not metadata placeholders.
        return Ok((package_nodes, BTreeMap::new()));
    }

    let local_snapshots = snapshots
        .iter()
        .filter(|(snapshot_key, _)| is_local_snapshot(snapshot_key))
        .map(|(snapshot_key, snapshot)| {
            Ok((
                snapshot_key.clone(),
                snapshot_dependencies(snapshot, snapshot_key, &snapshot_metadata, project_dir)?,
            ))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    let mut nodes = BTreeMap::new();
    for (snapshot_key, snapshot) in snapshots {
        let Some(mut node) = snapshot_metadata.get(&snapshot_key).cloned() else {
            if is_local_snapshot(&snapshot_key) {
                // Local file/link snapshots are workspace source projections,
                // not fetchable package nodes. Empty local snapshots are
                // represented by their importer Target::Link edges; their
                // dependency edges are retained in local_snapshots below.
                continue;
            }
            // A snapshot without package metadata cannot be fetched faithfully.
            return Err(err(format!(
                "pnpm snapshot {snapshot_key} has no matching packages metadata"
            )));
        };
        node.deps =
            snapshot_dependencies(&snapshot, &snapshot_key, &snapshot_metadata, project_dir)?;
        nodes.insert(snapshot_key, node);
    }
    Ok((nodes, local_snapshots))
}

pub(super) fn importer_map(
    root: &BTreeMap<String, YamlValue>,
) -> io::Result<BTreeMap<String, BTreeMap<String, YamlValue>>> {
    let Some(value) = root.get("importers") else {
        return Ok(BTreeMap::new());
    };
    let map = yaml_map(value, "importers")?;
    map.iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                yaml_map(value, &format!("importer {key}"))?.clone(),
            ))
        })
        .collect()
}

pub(super) fn pnpm_legacy_root(root: &BTreeMap<String, YamlValue>) -> BTreeMap<String, YamlValue> {
    let mut importer = BTreeMap::new();
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(value) = root.get(field) {
            importer.insert(field.to_string(), value.clone());
        }
    }
    importer
}

/// Parse pnpm lockfile versions 9 and the compatible importer shape of v6.
pub fn plan_pnpm(platform: Platform, lock_yaml: &str, project_dir: &Path) -> io::Result<NpmPlan> {
    let mut record = |kind: &str, subject: &str, detail: &str| {
        crate::kernel::policy::record(kind, subject, detail)
    };
    plan_pnpm_with_recorder(platform, lock_yaml, project_dir, &mut record)
}

fn plan_pnpm_with_recorder(
    platform: Platform,
    lock_yaml: &str,
    project_dir: &Path,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<NpmPlan> {
    // pnpm can append a second document when a lock is merged from a
    // package-manager-generated prelude. The last document is the effective
    // lock graph.
    let lock_yaml = lock_yaml.rsplit("\n---").next().unwrap_or(lock_yaml);
    let parsed = parse_yaml(lock_yaml)?;
    let root = yaml_map(&parsed, "pnpm lockfile")?;
    let version = yaml_str(root.get("lockfileVersion")).unwrap_or_default();
    let version = version.trim_end_matches(".0");
    if version != "9" && version != "6" {
        return Err(err(format!(
            "unsupported pnpm lockfileVersion {:?} (blanket supports 9.0 and 6.0)",
            yaml_str(root.get("lockfileVersion")).unwrap_or_default()
        )));
    }
    // A project with no dependencies has no `packages` map at all: pnpm writes
    // only `importers: { .: {} }`. That is an empty graph, not a broken lock.
    let empty_packages = BTreeMap::new();
    let packages = match root.get("packages") {
        Some(value) => yaml_map(value, "packages")?,
        None => &empty_packages,
    };
    let snapshots = root.get("snapshots");
    let patches = pnpm_patches(root, project_dir, record)?;
    let (mut nodes, local_snapshots) = pnpm_nodes(packages, snapshots, project_dir)?;
    attach_pnpm_patches(&mut nodes, &patches)?;
    let catalogs = pnpm_catalogs(root)?;
    let importers = importer_map(root)?;
    let root_importer = importers
        .get(".")
        .cloned()
        .unwrap_or_else(|| pnpm_legacy_root(root));
    let mut local_link_deps = BTreeMap::new();
    for (snapshot_key, dependencies) in &local_snapshots {
        if let Some(target) = local_snapshot_target(snapshot_key, project_dir)? {
            local_link_deps
                .entry(target)
                .or_insert_with(|| dependencies.clone());
        }
    }
    let mut roots = importer_dependencies(
        &root_importer,
        ".",
        &nodes,
        project_dir,
        &catalogs,
        &local_snapshots,
        &mut local_link_deps,
    )?
    .into_iter()
    .map(|dependency| RootDependency {
        dependency,
        workspace: None,
    })
    .collect::<Vec<_>>();
    let mut workspace_roots = Vec::new();
    let workspace_paths = importers
        .keys()
        .filter(|name| name.as_str() != ".")
        .cloned()
        .collect::<BTreeSet<_>>();
    for (importer_name, importer) in importers {
        if importer_name == "." {
            continue;
        }
        for dependency in importer_dependencies(
            &importer,
            &importer_name,
            &nodes,
            project_dir,
            &catalogs,
            &local_snapshots,
            &mut local_link_deps,
        )? {
            workspace_roots.push(RootDependency {
                dependency,
                workspace: Some(importer_name.clone()),
            });
        }
    }
    roots.sort_by(|a, b| a.dependency.name.cmp(&b.dependency.name));
    workspace_roots.sort_by(|a, b| {
        a.workspace
            .cmp(&b.workspace)
            .then_with(|| a.dependency.name.cmp(&b.dependency.name))
    });
    build_plan(
        platform,
        Graph {
            nodes,
            roots,
            workspace_roots,
            workspace_paths,
            local_link_deps,
        },
        "pnpm-lock.yaml",
    )
}

#[cfg(test)]
pub(super) fn plan_pnpm_with_policy(
    platform: Platform,
    lock_yaml: &str,
    project_dir: &Path,
    policy: &crate::kernel::policy::Policy,
) -> io::Result<NpmPlan> {
    let mut record = |kind: &str, subject: &str, detail: &str| {
        crate::kernel::policy::record_with(policy, kind, subject, detail)
    };
    plan_pnpm_with_recorder(platform, lock_yaml, project_dir, &mut record)
}

#[cfg(test)]
mod patch_hash_tests {
    use super::*;

    const PATCH: &[u8] = b"diff --git a/index.js b/index.js\n";
    /// pnpm 9's `createBase32HashFromFile` of `PATCH`.
    const PATCH_BASE32: &str = "kpncbvlbnwqxywzzahw2g7pnwq";
    /// pnpm 10's `createHexHashFromFile` of `PATCH`.
    const PATCH_HEX: &str = "2692094a267de7e28825147fd6cb2ebde098a4e68c25dfa3976ac806f4a1a784";

    #[test]
    fn md5_matches_the_rfc_1321_test_suite() {
        for (input, expected) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "1234567890123456789012345678901234567890\
                 1234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(
                hex::encode(md5(input.as_bytes())),
                expected,
                "md5({input:?})"
            );
        }
    }

    #[test]
    fn base32_lower_matches_the_rfc_4648_test_vectors_without_padding() {
        for (input, expected) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(
                base32_lower(input.as_bytes()),
                expected,
                "base32({input:?})"
            );
        }
    }

    /// The exact sample from the hit-rate run
    /// (`tests/fixtures/hitrate-linux-2026-09-11.csv`): `paperclipai/paperclip`
    /// at commit ad0ad43 declares `fymctidcjqjhi4cj72qtivlxry` for
    /// `patches/@agentclientprotocol__claude-agent-acp@0.70.0.patch`. That file
    /// has sha256 `823c105c…d6c` — the value blanket used to print as "got" —
    /// and md5 `2e1829a0624c12747049fea13455778e`, which base32-encodes to the
    /// declared string. It confirms md5, not a truncated sha256, is the input.
    #[test]
    fn the_real_pnpm_9_lockfile_sample_is_base32_of_md5() {
        let digest = hex::decode("2e1829a0624c12747049fea13455778e").unwrap();
        let encoded = base32_lower(&digest);
        assert_eq!(encoded, "fymctidcjqjhi4cj72qtivlxry");
        assert_eq!(encoded.len(), PNPM_BASE32_HASH_LEN);
    }

    #[test]
    fn check_patch_hash_accepts_every_encoding_pnpm_writes() {
        assert_eq!(
            check_patch_hash(PATCH_BASE32, PATCH),
            Ok(PatchMatch::Normalized)
        );
        assert_eq!(check_patch_hash(PATCH_HEX, PATCH), Ok(PatchMatch::Raw));
        assert_eq!(
            check_patch_hash(&format!("sha256-{PATCH_HEX}"), PATCH),
            Ok(PatchMatch::Raw)
        );
        assert_eq!(
            check_patch_hash(&PATCH_HEX.to_ascii_uppercase(), PATCH),
            Ok(PatchMatch::Raw)
        );
    }

    #[test]
    fn check_patch_hash_fails_closed_on_anything_else() {
        for declared in [
            // Right shape, wrong file.
            "uncj4ibb6pblo7yg3phh2pzyhy",
            // The base32 alphabet is lowercase and unpadded in pnpm lockfiles.
            &PATCH_BASE32.to_ascii_uppercase(),
            &format!("{PATCH_BASE32}======"),
            // 26 characters, but outside the a-z2-7 alphabet.
            "kpncbvlbnwqxywzzahw2g7pnw!",
            // Wrong length, wrong alphabet, empty, and a bare algorithm tag.
            &PATCH_HEX[..63],
            &format!("{PATCH_HEX}0"),
            "",
            "sha256-",
            &format!("sha512-{PATCH_HEX}"),
            &"z".repeat(64),
        ] {
            assert!(
                check_patch_hash(declared, PATCH).is_err(),
                "accepted {declared}"
            );
        }
    }

    /// The mismatch error reports the computed hash in the declaration's own
    /// encoding, so the pair in the message is comparable.
    #[test]
    fn the_computed_hash_is_reported_in_the_declared_encoding() {
        assert_eq!(
            check_patch_hash("uncj4ibb6pblo7yg3phh2pzyhy", PATCH),
            Err(PATCH_BASE32.to_string())
        );
        assert_eq!(
            check_patch_hash(&"0".repeat(64), PATCH),
            Err(PATCH_HEX.to_string())
        );
        assert_eq!(
            check_patch_hash(&format!("sha256-{}", "0".repeat(64)), PATCH),
            Err(format!("sha256-{PATCH_HEX}"))
        );
    }

    /// pnpm hashes the file after `content.split('\r\n').join('\n')`, so a
    /// CRLF patch carries the hash of its LF form under both encodings.
    #[test]
    fn crlf_is_normalized_to_lf_before_hashing() {
        let crlf = b"first line\r\nsecond line\r\n";
        assert_eq!(
            check_patch_hash("ovs2ag6tl4y3vavlkxexrqnxku", crlf),
            Ok(PatchMatch::Normalized)
        );
        assert_eq!(
            check_patch_hash(
                "c2097f55f01fc297fc7f4acf21438123e06e4d409a818524428534e850642f4f",
                crlf
            ),
            Ok(PatchMatch::Normalized)
        );
        assert_eq!(
            check_patch_hash(
                "sha256-a6ad0f6d0647ff79b6c9fbce44e1f9955b395b563f661705a691949bf6e0a75e",
                crlf
            ),
            Ok(PatchMatch::Raw)
        );
        assert_eq!(
            check_patch_hash(&"0".repeat(64), crlf),
            Err("c2097f55f01fc297fc7f4acf21438123e06e4d409a818524428534e850642f4f".into())
        );
        // A lone CR is not a line ending and is left in place.
        assert_eq!(pnpm_normalized(b"a\rb\r\nc\r"), b"a\rb\nc\r");
    }

    #[test]
    fn invalid_utf8_is_replaced_before_hashing() {
        let bytes = b"\xff\n";
        assert_eq!(
            check_patch_hash("yaionrthuo5kctp4vgwr3hgkw4", bytes),
            Ok(PatchMatch::Normalized)
        );
        assert_eq!(
            check_patch_hash(
                "8d75cfafa290dea108e554948eae67ba5c418cad73059f9452ff6fc652d5c869",
                bytes
            ),
            Ok(PatchMatch::Normalized)
        );
    }

    #[test]
    fn normalized_sha256_matches_bind_raw_content_and_raw_matches_do_not() {
        let root = std::env::temp_dir().join(format!(
            "blanket-pnpm-patch-hash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let normalized_path = root.join("normalized.patch");
        let raw_path = root.join("raw.patch");
        let normalized_bytes = b"first line\r\n";
        let normalized_digest = hex::encode(Sha256::digest(b"first line\n"));
        fs::write(&normalized_path, normalized_bytes).unwrap();
        fs::write(&raw_path, PATCH).unwrap();

        assert_eq!(
            verify_patch_hash("normalized", &normalized_path, &normalized_digest).unwrap(),
            Some(hex::encode(Sha256::digest(normalized_bytes)))
        );
        assert_eq!(
            verify_patch_hash("raw", &raw_path, PATCH_HEX).unwrap(),
            None
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn distinct_raw_files_that_normalize_identically_get_distinct_bindings() {
        let root = std::env::temp_dir().join(format!(
            "blanket-pnpm-patch-content-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let first = b"+\xff\n";
        let second = b"+\xfe\n";
        assert_eq!(pnpm_normalized(first), pnpm_normalized(second));
        let declared = hex::encode(Sha256::digest(pnpm_normalized(first)));
        let first_path = root.join("first.patch");
        let second_path = root.join("second.patch");
        fs::write(&first_path, first).unwrap();
        fs::write(&second_path, second).unwrap();

        let first_content = verify_patch_hash("first", &first_path, &declared)
            .unwrap()
            .unwrap();
        let second_content = verify_patch_hash("second", &second_path, &declared)
            .unwrap()
            .unwrap();
        assert_ne!(first_content, second_content);
        let _ = fs::remove_dir_all(root);
    }
}

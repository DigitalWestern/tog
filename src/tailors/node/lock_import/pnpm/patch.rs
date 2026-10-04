//! A pnpm `patchedDependencies` file (node tailor): where it may live in
//! the project, and the hash pnpm records for it, checked byte for byte
//! against what the lockfile says.

use super::*;

pub(crate) fn patch_path(project: &ProjectRoot, raw: &str) -> io::Result<PathBuf> {
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
    // The canonical path is what the plan records (realization re-reads and
    // re-verifies it). Containment is checked on that pathname; whether it
    // is a file is asked of the held descriptor.
    let path = project
        .path()
        .join(path)
        .canonicalize()
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => err(format!("pnpm patch path {raw:?} does not exist")),
            _ => error,
        })?;
    if !project
        .relative(&path)
        .is_some_and(|relative| project.is_input_file(relative))
    {
        return Err(err(format!(
            "pnpm patch path {raw:?} is outside the project or is not a file"
        )));
    }
    Ok(path)
}

/// The bytes of a patch `patch_path` accepted, read through the held
/// project descriptor rather than by its recorded pathname.
pub(crate) fn read_patch(project: &ProjectRoot, path: &Path) -> io::Result<Vec<u8>> {
    let relative = project.relative(path).ok_or_else(|| {
        err(format!(
            "pnpm patch {} is outside the project",
            path.display()
        ))
    })?;
    project.read_input(relative)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", path.display()),
        )
    })
}

pub(crate) fn verify_patch_hash(
    package: &str,
    path: &Path,
    bytes: &[u8],
    declared: &str,
) -> io::Result<Option<String>> {
    let matched = check_patch_hash(declared, bytes).map_err(|actual| {
        err(format!(
            "pnpm patch {package} hash mismatch for {} (expected {declared}, got {actual})",
            path.display()
        ))
    })?;
    Ok(match matched {
        PatchMatch::Raw => None,
        PatchMatch::Normalized => Some(hex::encode(Sha256::digest(bytes))),
    })
}

/// Length of pnpm 9's base32 patch hash. md5 is 16 bytes and RFC 4648 base32
/// spends one character per 5 bits, so 128 bits fill 25 characters plus one
/// holding the trailing 3 bits: 26 characters once the 6 `=` are stripped.
pub(crate) const PNPM_BASE32_HASH_LEN: usize = 26;

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
/// tog accepts every form still found in lockfiles:
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
/// produced by the earlier tog implementation. A normalized match must
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
pub(super) fn pnpm_normalized(bytes: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(bytes)
        .split("\r\n")
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

/// RFC 4648 base32 with the lowercase alphabet and no padding, the shape
/// pnpm's `createBase32Hash` produces.
pub(super) fn base32_lower(bytes: &[u8]) -> String {
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
/// a dependency; this is never used to attest anything tog itself writes.
pub(super) fn md5(input: &[u8]) -> [u8; 16] {
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
    for block in message.as_chunks::<64>().0 {
        let mut words = [0u32; 16];
        for (word, raw) in words.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*raw);
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
    for (slot, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

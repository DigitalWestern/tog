//! Keeping the signing key's secret out of what tog prints and relays: a
//! parser's error quotes the line it failed on, and a project file can be
//! the key under another name (a symlink, a hard link, an include). The
//! secret is matched as any run of [`MIN_SECRET_RUN`] or more of its
//! characters, across a line break and its gutter, in whole texts
//! ([`scrub_signing_key`]) and in streams cut at any point ([`Scrubber`]).

use super::confine::signing_key_paths;
use std::fs;
use std::path::PathBuf;

/// `text` with the signing key's secret replaced, wherever it appears: a
/// last layer for a child's output tog relays and for everything tog prints
/// (a parser's error quotes the line it failed on, and a project file can
/// be the key under another name). See [`redact`] for what is matched.
pub fn scrub_signing_key(text: &str) -> String {
    let secrets = signing_key_secrets();
    if secrets.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mask = redaction_mask(bytes, secrets);
    // The secret is ASCII, so a redacted run never splits a character.
    String::from_utf8(redact(bytes, &mask)).unwrap_or_else(|_| text.to_string())
}

/// The shortest run of a secret's characters that is redacted. The secret
/// is 64 hex digits; 10 of them in a row turn up by chance about once in
/// 10^12 positions, so ordinary hashes in tog's output are left alone.
pub(crate) const MIN_SECRET_RUN: usize = 10;

/// The text replacing each redacted run.
pub(crate) const REDACTED: &[u8] = b"[signing key redacted]";

/// The secrets of the signing-key files ([`signing_key_paths`]), read once
/// per process: the part after the last `:` of each line (the hex seed of
/// `ed25519:<seed>`), or the whole line when it has none, if at least 16
/// bytes long. A file that cannot be read adds nothing.
pub fn signing_key_secrets() -> &'static [Vec<u8>] {
    static SECRETS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    SECRETS.get_or_init(|| key_secrets(&signing_key_paths()))
}

pub(crate) fn key_secrets(keys: &[PathBuf]) -> Vec<Vec<u8>> {
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    for path in keys {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines().map(str::trim) {
            let secret = line.rsplit(':').next().unwrap_or(line);
            if secret.len() >= 16 && !secrets.iter().any(|s| s == secret.as_bytes()) {
                secrets.push(secret.as_bytes().to_vec());
            }
        }
    }
    secrets
}

/// How many gutter bytes (spaces, tabs, `|`, more line breaks) after a
/// line break are skipped when matching a secret across lines. A longer
/// gap ends a match, so what a streaming [`Scrubber`] must hold back stays
/// bounded.
pub(crate) const GUTTER_MAX: usize = 16;

/// The text as matched: line breaks and up to [`GUTTER_MAX`] gutter bytes
/// after them left out, each byte with its index in `text`. A longer gutter
/// becomes a break (`None`), which no secret byte matches.
fn match_view(text: &[u8]) -> Vec<Option<(u8, usize)>> {
    let mut view = Vec::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if matches!(text[index], b'\n' | b'\r') {
            let start = index;
            index += 1;
            while index < text.len() && matches!(text[index], b' ' | b'\t' | b'|' | b'\n' | b'\r') {
                index += 1;
            }
            if index - start > GUTTER_MAX + 1 {
                view.push(None);
            }
            continue;
        }
        view.push(Some((text[index], index)));
        index += 1;
    }
    view
}

/// For each secret, where each byte value occurs in it: a match is only
/// tried from those offsets.
fn secret_offsets(secrets: &[Vec<u8>]) -> Vec<Vec<Vec<usize>>> {
    secrets
        .iter()
        .map(|secret| {
            let mut offsets = vec![Vec::new(); 256];
            for (offset, byte) in secret.iter().enumerate() {
                offsets[*byte as usize].push(offset);
            }
            offsets
        })
        .collect()
}

/// Which bytes of `text` belong to a secret: every run of at least
/// [`MIN_SECRET_RUN`] bytes that is a piece of one. Line breaks do not
/// hide it: a newline or carriage return and up to [`GUTTER_MAX`] spaces,
/// tabs and `|` after it (a parse error's gutter) are skipped when
/// matching, so a secret split across two lines is found whole, and both
/// of its parts are marked whatever their length.
pub fn redaction_mask(text: &[u8], secrets: &[Vec<u8>]) -> Vec<bool> {
    let mut mask = vec![false; text.len()];
    if secrets.is_empty() {
        return mask;
    }
    let view = match_view(text);
    let offsets = secret_offsets(secrets);
    for start in 0..view.len() {
        let Some((first, _)) = view[start] else {
            continue;
        };
        let mut longest = 0;
        for (secret, offsets) in secrets.iter().zip(&offsets) {
            for &offset in &offsets[first as usize] {
                let mut length = 0;
                while start + length < view.len()
                    && offset + length < secret.len()
                    && view[start + length].map(|(byte, _)| byte) == Some(secret[offset + length])
                {
                    length += 1;
                }
                longest = longest.max(length);
            }
        }
        if longest >= MIN_SECRET_RUN {
            for (_, original) in view[start..start + longest].iter().flatten() {
                mask[*original] = true;
            }
        }
    }
    mask
}

/// How many bytes at the end of `text` could still be the start (or the
/// middle) of a secret match that bytes yet to come complete: the longest
/// tail whose matched form is a piece of a secret, with the line breaks and
/// gutter after it. Zero when the text ends in a break or in nothing a
/// secret holds.
fn open_tail(text: &[u8], secrets: &[Vec<u8>], offsets: &[Vec<Vec<usize>>]) -> usize {
    let view = match_view(text);
    let Some(Some((last, _))) = view.last().copied() else {
        return 0;
    };
    let mut longest = 0;
    for (secret, offsets) in secrets.iter().zip(offsets) {
        for &end in &offsets[last as usize] {
            let mut length = 0;
            while length <= end
                && length < view.len()
                && view[view.len() - 1 - length].map(|(byte, _)| byte) == Some(secret[end - length])
            {
                length += 1;
            }
            longest = longest.max(length);
        }
    }
    if longest == 0 {
        return 0;
    }
    match view[view.len() - longest] {
        Some((_, original)) => text.len() - original,
        None => 0,
    }
}

/// One output stream's scrubber: bytes in, the same bytes out with every
/// secret replaced ([`redaction_mask`]), however the stream was cut into
/// reads. It holds back only the tail that could still be part of a match
/// ([`open_tail`], at most a secret's length with its gutters), never on a
/// timer or a pause, and keeps the bytes it has passed on as context, so a
/// match that started in them is still found. Order is kept.
pub struct Scrubber {
    secrets: Vec<Vec<u8>>,
    offsets: Vec<Vec<Vec<usize>>>,
    /// The last bytes passed on, for matching only.
    context: Vec<u8>,
    /// Bytes not yet passed on.
    pending: Vec<u8>,
    context_max: usize,
}

impl Scrubber {
    pub fn new(secrets: Vec<Vec<u8>>) -> Scrubber {
        let longest = secrets.iter().map(Vec::len).max().unwrap_or(0);
        Scrubber {
            offsets: secret_offsets(&secrets),
            secrets,
            context: Vec::new(),
            pending: Vec::new(),
            context_max: longest * (GUTTER_MAX + 2),
        }
    }

    /// Take `bytes`; return what can be passed on now.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return bytes.to_vec();
        }
        self.pending.extend_from_slice(bytes);
        let mut joined = self.context.clone();
        joined.extend_from_slice(&self.pending);
        let hold = open_tail(&joined, &self.secrets, &self.offsets).min(self.pending.len());
        self.release(&joined, self.pending.len() - hold)
    }

    /// The stream ended: everything left.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let mut joined = self.context.clone();
        joined.extend_from_slice(&self.pending);
        self.release(&joined, self.pending.len())
    }

    /// Pass on the first `count` pending bytes, redacted with the match
    /// found over context and pending together.
    fn release(&mut self, joined: &[u8], count: usize) -> Vec<u8> {
        if count == 0 {
            return Vec::new();
        }
        let mask = redaction_mask(joined, &self.secrets);
        let start = self.context.len();
        let out = redact(&self.pending[..count], &mask[start..start + count]);
        self.context.extend(self.pending.drain(..count));
        if self.context.len() > self.context_max {
            let excess = self.context.len() - self.context_max;
            self.context.drain(..excess);
        }
        out
    }
}

/// `text` with each run of masked bytes replaced by [`REDACTED`].
pub fn redact(text: &[u8], mask: &[bool]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if mask[index] {
            out.extend_from_slice(REDACTED);
            while index < text.len() && mask[index] {
                index += 1;
            }
        } else {
            out.push(text[index]);
            index += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn scrub_with(text: &str, secrets: &[Vec<u8>]) -> String {
        String::from_utf8(redact(
            text.as_bytes(),
            &redaction_mask(text.as_bytes(), secrets),
        ))
        .unwrap()
    }

    #[test]
    fn a_relayed_message_never_carries_the_key() {
        const SEED: &str = "0123456789abcdef0123456789abcdef";
        let temp = TempDir::named("confine-scrub");
        let key = temp.0.join("signing.key");
        fs::write(&key, format!("ed25519:{SEED}\n")).unwrap();
        let secrets = key_secrets(&[key.clone(), temp.0.join("missing")]);
        assert_eq!(secrets, vec![SEED.as_bytes().to_vec()]);
        let text = format!("error: invalid TOML\n  |\n1 | ed25519:{SEED}\n  |");
        let scrubbed = scrub_with(&text, &secrets);
        assert!(!scrubbed.contains("0123456789"), "{scrubbed}");
        assert!(
            scrubbed.contains("ed25519:[signing key redacted]\n"),
            "{scrubbed}"
        );
        // A piece of it, quoted alone.
        let scrubbed = scrub_with("value \"6789abcdef0123\" end", &secrets);
        assert_eq!(scrubbed, "value \"[signing key redacted]\" end");
        // Split across two lines, behind a gutter, with a short tail: both
        // parts go.
        let split = format!("1 | {}\n  | {}\nnext", &SEED[..27], &SEED[27..]);
        let scrubbed = scrub_with(&split, &secrets);
        assert_eq!(
            scrubbed,
            "1 | [signing key redacted]\n  | [signing key redacted]\nnext"
        );
        // A short coincidence and the public prefix are left alone.
        let plain = "ed25519:PUBLIC sha 01234567 abcdef";
        assert_eq!(scrub_with(plain, &secrets), plain);
        assert_eq!(scrub_with("plain", &[]), "plain");
    }

    /// The streaming scrubber gives the same answer however the stream is
    /// cut, holds back no more than a secret's length (with gutters), and
    /// passes ordinary output through unchanged.
    #[test]
    fn the_scrubber_does_not_depend_on_how_the_stream_is_cut() {
        const SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let secrets = vec![SEED.as_bytes().to_vec()];
        let stream = |pieces: &[&[u8]]| {
            let mut scrubber = Scrubber::new(secrets.clone());
            let mut out = Vec::new();
            for piece in pieces {
                out.extend(scrubber.push(piece));
                assert!(scrubber.pending.len() <= SEED.len() * (GUTTER_MAX + 2));
            }
            out.extend(scrubber.finish());
            String::from_utf8(out).unwrap()
        };
        let text = format!(
            "plain 0123 line\n1 | ed25519:{}\n  | {}\nafter {}\n",
            &SEED[..20],
            &SEED[20..],
            &SEED[5..17]
        );
        let whole = stream(&[text.as_bytes()]);
        let bytes: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
        assert_eq!(stream(&bytes), whole);
        let threes: Vec<&[u8]> = text.as_bytes().chunks(3).collect();
        assert_eq!(stream(&threes), whole);
        for start in 0..=SEED.len() - MIN_SECRET_RUN {
            assert!(
                !whole.contains(&SEED[start..start + MIN_SECRET_RUN]),
                "{whole}"
            );
        }
        assert!(whole.starts_with("plain 0123 line\n1 | ed25519:[signing key redacted]"));
        assert!(whole.ends_with("after [signing key redacted]\n"), "{whole}");
        // Ordinary output, hex included, is unchanged.
        let plain = "Compiling foo v0.1.0\nsha256 0123abcd\n  |  \n".repeat(50);
        let pieces: Vec<&[u8]> = plain.as_bytes().chunks(7).collect();
        assert_eq!(stream(&pieces), plain);
        // A long gutter ends a match: the scrubber's hold stays bounded.
        let spaced = format!("{}\n{}{}", &SEED[..6], " ".repeat(64), &SEED[6..12]);
        assert_eq!(stream(&[spaced.as_bytes()]), spaced);
    }
}

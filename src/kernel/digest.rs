//! Content digests (kernel layer): the validated `Digest` value that
//! artifact verification, cache addressing, and object metadata share.

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

/// Content digest for artifact verification and cache addressing.
/// Fields are private: a Digest can only hold validated lowercase hex of
/// the exact right length, so it can never smuggle path components into
/// cache paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest {
    pub(crate) algo: Algo,
    hex: String,
}

impl Digest {
    fn validated(algo: Algo, hex: &str) -> io::Result<Digest> {
        let want = match algo {
            Algo::Sha1 => 40,
            Algo::Sha256 => 64,
            Algo::Sha512 => 128,
        };
        let hex = hex.to_ascii_lowercase();
        if hex.len() != want || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed {} hex digest: {hex}", algo_name(algo)),
            ));
        }
        Ok(Digest { algo, hex })
    }
    pub fn sha256(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha256, hex)
    }
    pub fn sha1(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha1, hex)
    }
    pub fn sha512(hex: &str) -> io::Result<Digest> {
        Digest::validated(Algo::Sha512, hex)
    }
    pub fn algo(&self) -> &'static str {
        algo_name(self.algo)
    }
    pub fn hex(&self) -> &str {
        &self.hex
    }
    /// Parse an npm SRI string like "sha512-<base64>", "sha256-<base64>", or
    /// the legacy "sha1-<base64>" form.
    pub fn from_sri(sri: &str) -> io::Result<Digest> {
        let (algo, b64) = sri.split_once('-').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed integrity: {sri}"),
            )
        })?;
        let bytes = base64_decode(b64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad base64 in integrity: {sri}"),
            )
        })?;
        let hex = hex::encode(bytes);
        match algo {
            "sha1" => Digest::sha1(&hex),
            "sha256" => Digest::sha256(&hex),
            "sha512" => Digest::sha512(&hex),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported integrity algorithm: {other}"),
            )),
        }
    }
}

pub(super) fn algo_name(a: Algo) -> &'static str {
    match a {
        Algo::Sha1 => "sha1",
        Algo::Sha256 => "sha256",
        Algo::Sha512 => "sha512",
    }
}

/// Minimal RFC 4648 standard-alphabet base64 encoder (with padding).
/// The single encoder the crate uses: store paths, SRI values, and test
/// auth headers all encode through here so the alphabet cannot drift.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let acc = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(acc >> 18) as usize & 63] as char);
        out.push(ALPHABET[(acc >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(acc >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[acc as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Minimal RFC 4648 base64 (standard alphabet, optional padding).
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let n = chunk.len();
        if n >= 2 {
            out.push((acc >> 16) as u8);
        }
        if n >= 3 {
            out.push((acc >> 8) as u8);
        }
        if n == 4 {
            out.push(acc as u8);
        }
        if n == 1 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sri_roundtrip() {
        // echo -n hello | shasum -a 512 -> base64 of raw digest
        let d = Digest::from_sri(
            "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==",
        )
        .unwrap();
        assert_eq!(d.algo(), "sha512");
        assert!(d.hex().starts_with("9b71d224bd62f378"));
        assert!(Digest::from_sri("md5-abc").is_err());
        assert!(Digest::from_sri("nodash").is_err());
    }
}

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
        let bytes = crate::kernel::base64::decode(b64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad base64 in integrity: {sri}"),
            )
        })?;
        let hex = hex::encode(bytes);
        match algo_named(algo) {
            Some(algo) => Digest::validated(algo, &hex),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported integrity algorithm: {algo}"),
            )),
        }
    }

    /// A digest from an algorithm name and its hex, as object records and
    /// cache paths spell them.
    pub fn from_parts(algo: &str, hex: &str) -> io::Result<Digest> {
        match algo_named(algo) {
            Some(algo) => Digest::validated(algo, hex),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported digest algorithm {algo}"),
            )),
        }
    }
}

/// The strongest entry tog supports in an SRI list such as
/// `"sha512-... sha1-..."` (npm, pnpm and yarn all write lists), or `None`
/// when no entry names sha512, sha256 or sha1.
pub fn strongest_sri(list: &str) -> Option<&str> {
    list.split_whitespace()
        .filter_map(|entry| Some((algo_named(entry.split_once('-')?.0)?, entry)))
        .max_by_key(|(algo, _)| *algo)
        .map(|(_, entry)| entry)
}

fn algo_named(name: &str) -> Option<Algo> {
    match name {
        "sha1" => Some(Algo::Sha1),
        "sha256" => Some(Algo::Sha256),
        "sha512" => Some(Algo::Sha512),
        _ => None,
    }
}

pub(super) fn algo_name(a: Algo) -> &'static str {
    match a {
        Algo::Sha1 => "sha1",
        Algo::Sha256 => "sha256",
        Algo::Sha512 => "sha512",
    }
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

    #[test]
    fn the_strongest_supported_sri_in_a_list_wins() {
        assert_eq!(strongest_sri("sha1-a sha512-b sha256-c"), Some("sha512-b"));
        assert_eq!(strongest_sri("  sha256-c\tsha1-a "), Some("sha256-c"));
        assert_eq!(strongest_sri("sha384-x sha1-a"), Some("sha1-a"));
        assert_eq!(strongest_sri("sha384-x md5-y"), None);
        assert_eq!(strongest_sri(""), None);
    }

    #[test]
    fn from_parts_names_the_algorithm_it_does_not_know() {
        let hex = "a".repeat(64);
        assert_eq!(Digest::from_parts("sha256", &hex).unwrap().hex(), hex);
        let error = Digest::from_parts("md5", &hex).unwrap_err();
        assert_eq!(error.to_string(), "unsupported digest algorithm md5");
        assert!(Digest::from_parts("sha1", &hex).is_err());
    }
}

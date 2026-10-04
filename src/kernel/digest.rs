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

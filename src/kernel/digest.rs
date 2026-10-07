//! Content digests (kernel layer): the validated `Digest` value that
//! artifact verification, cache addressing, and object metadata share.

use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use std::io::{self, Read};

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

/// The lowercase hex digest of everything `reader` yields, read in 64 KiB
/// chunks. The one content hasher: a caller holding a descriptor hashes
/// that descriptor, and `kernel::fetch::hash_file` opens a path for the
/// rest.
pub(crate) fn hash_reader(reader: &mut impl Read, algo: Algo) -> io::Result<String> {
    let mut buf = vec![0u8; 65536];
    let mut h256 = Sha256::new();
    let mut h512 = Sha512::new();
    let mut h1 = Sha1::new();
    loop {
        // A read cut short by a signal read nothing: try it again.
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        match algo {
            Algo::Sha1 => h1.update(&buf[..n]),
            Algo::Sha256 => h256.update(&buf[..n]),
            Algo::Sha512 => h512.update(&buf[..n]),
        }
    }
    Ok(match algo {
        Algo::Sha1 => hex::encode(h1.finalize()),
        Algo::Sha256 => hex::encode(h256.finalize()),
        Algo::Sha512 => hex::encode(h512.finalize()),
    })
}

/// Every entry of the strongest algorithm tog supports in an SRI list such
/// as `"sha512-... sha1-..."` (npm, pnpm and yarn all write lists), as one
/// canonical list: sorted, without duplicates, space-separated. A list may
/// carry several hashes of that algorithm, and the bytes are allowed when
/// they match any one of them (the W3C SRI rule, and npm's ssri), so the
/// order a lock wrote them in means nothing and two orders give the same
/// list. `None` when no entry names sha512, sha256 or sha1.
pub fn strongest_sri(list: &str) -> Option<String> {
    let entries: Vec<(Algo, &str)> = list
        .split_whitespace()
        .filter_map(|entry| Some((algo_named(entry.split_once('-')?.0)?, entry)))
        .collect();
    let strongest = entries.iter().map(|(algo, _)| *algo).max()?;
    let mut chosen: Vec<&str> = entries
        .into_iter()
        .filter(|(algo, _)| *algo == strongest)
        .map(|(_, entry)| entry)
        .collect();
    chosen.sort_unstable();
    chosen.dedup();
    Some(chosen.join(" "))
}

/// The digests an SRI list allows: every entry of its strongest algorithm
/// (see [`strongest_sri`]), parsed, sorted and without duplicates. Never a
/// weaker one: bytes that match only a weaker entry are refused. A
/// malformed entry of the strongest algorithm is an error, not skipped: a
/// lock that names a hash tog cannot read was not written by the tool it
/// claims. A list with no supported entry is the error `from_sri` gives
/// for it.
pub fn sri_candidates(list: &str) -> io::Result<Vec<Digest>> {
    let Some(strongest) = strongest_sri(list) else {
        return Digest::from_sri(list.trim()).map(|digest| vec![digest]);
    };
    let mut digests = strongest
        .split(' ')
        .map(Digest::from_sri)
        .collect::<io::Result<Vec<_>>>()?;
    digests.sort();
    digests.dedup();
    Ok(digests)
}

/// Candidates as identities and records spell them: `algo:hex`, joined by
/// `|` when there are several. One candidate reads exactly as a single
/// digest always has, so a lock with one hash keeps its identity.
pub fn describe_candidates(candidates: &[Digest]) -> String {
    candidates
        .iter()
        .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
        .collect::<Vec<_>>()
        .join("|")
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
    fn hash_reader_matches_known_digests_for_empty_and_multi_buffer_input() {
        let empty: &[u8] = b"";
        assert_eq!(
            hash_reader(&mut &*empty, Algo::Sha1).unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hash_reader(&mut &*empty, Algo::Sha256).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(hash_reader(&mut &*empty, Algo::Sha512)
            .unwrap()
            .starts_with("cf83e1357eefb8bd"));
        // Three and a bit 64 KiB reads: the chunks must add up to one digest.
        let big = vec![b'a'; 3 * 65536 + 17];
        let whole = {
            use sha2::Digest as _;
            hex::encode(Sha256::digest(&big))
        };
        assert_eq!(
            hash_reader(&mut big.as_slice(), Algo::Sha256).unwrap(),
            whole
        );
    }

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
        assert_eq!(
            strongest_sri("sha1-a sha512-b sha256-c").as_deref(),
            Some("sha512-b")
        );
        assert_eq!(
            strongest_sri("  sha256-c\tsha1-a ").as_deref(),
            Some("sha256-c")
        );
        assert_eq!(strongest_sri("sha384-x sha1-a").as_deref(), Some("sha1-a"));
        // Every strongest entry is kept, in one order whatever the lock's.
        assert_eq!(
            strongest_sri("sha512-y sha1-a sha512-x sha512-y").as_deref(),
            Some("sha512-x sha512-y")
        );
        assert_eq!(
            strongest_sri("sha512-x sha512-y"),
            strongest_sri("sha512-y sha512-x")
        );
        assert_eq!(strongest_sri("sha384-x md5-y"), None);
        assert_eq!(strongest_sri(""), None);
    }

    #[test]
    fn sri_candidates_keep_every_strongest_hash_and_refuse_bad_ones() {
        let sri = |bytes: &[u8]| {
            let mut hasher = Sha512::new();
            hasher.update(bytes);
            format!(
                "sha512-{}",
                crate::kernel::base64::encode(&hasher.finalize())
            )
        };
        let (a, b) = (sri(b"a"), sri(b"b"));
        let weak = "sha1-qvTGHdzF6KLavt4PO0gs2a6pQ00=";
        let forward = sri_candidates(&format!("{a} {weak} {b}")).unwrap();
        let backward = sri_candidates(&format!("{b} {a}")).unwrap();
        assert_eq!(forward.len(), 2);
        assert!(forward.iter().all(|digest| digest.algo() == "sha512"));
        assert_eq!(forward, backward);
        assert_eq!(
            describe_candidates(&forward),
            describe_candidates(&backward)
        );
        assert_eq!(describe_candidates(&forward[..1]).matches('|').count(), 0);
        // A malformed strongest entry fails the list; a weaker entry is
        // never what is left to verify against.
        assert!(sri_candidates(&format!("{a} sha512-!!!")).is_err());
        assert!(sri_candidates("sha384-x md5-y").is_err());
        assert_eq!(sri_candidates(weak).unwrap()[0].algo(), "sha1");
    }

    /// A read a signal interrupts is retried, not the end of the hash.
    #[test]
    fn hash_reader_retries_an_interrupted_read() {
        struct Flaky(bool, &'static [u8]);
        impl Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.1.read(buf)
            }
        }
        assert_eq!(
            hash_reader(&mut Flaky(true, b""), Algo::Sha1).unwrap(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
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

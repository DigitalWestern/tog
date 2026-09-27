//! Closure signing (kernel layer): Ed25519 key files, the canonical bytes a
//! signature covers, sign and verify, and the trusted-key set the policy
//! chain accumulates for `tog audit`.
//!
//! A signature proves that a closure envelope was written by a sync holding
//! a particular private key. It covers the envelope parsed as a JSON value
//! with the top-level `signature` field removed, serialized compact with keys
//! in byte order at every depth (`serde_json::Map` is a BTreeMap here).
//! Whitespace and key order in the file do not affect verification; any
//! change to the parsed value does, including inside `body.exceptions[]`.
//!
//! Key file: one line, `ed25519:<64 hex>` (the 32-byte seed), mode 0600.
//! Policy syntax for a public key: `ed25519:<64 hex>`. The envelope field
//! carries the bare 64-hex public key under `signature.key`.

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// The one algorithm: both the key prefix in policy and key files, and the
/// `alg` value in the envelope.
pub const ALGORITHM: &str = "ed25519";
const KEY_PREFIX: &str = "ed25519:";
/// The largest key file the loader reads. A real key file is 73 bytes.
const MAX_KEY_FILE_BYTES: u64 = 1024;

/// A 32-byte Ed25519 public key. Ordered and hashable so a set of keys can
/// be compared and deduplicated on the decoded bytes, not on the spelling.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Parse the policy syntax `ed25519:<64 hex>`. Hex is accepted in either
    /// case; `Display` renders it lowercase. The `ed25519:` prefix itself is
    /// exact (lowercase): it names the algorithm, not a value. The input is
    /// quoted in the error because it comes from a policy file a pull
    /// request can edit.
    pub fn parse(text: &str) -> Result<Self, String> {
        let Some(hex_part) = text.strip_prefix(KEY_PREFIX) else {
            return Err(format!(
                "{text:?} is not a public key: expected 'ed25519:<64 hex characters>'"
            ));
        };
        Self::from_hex(hex_part).ok_or_else(|| {
            format!("{text:?} is not a public key: expected 64 hex characters after 'ed25519:'")
        })
    }

    /// Decode the bare 64-hex form the envelope carries.
    pub fn from_hex(hex_part: &str) -> Option<Self> {
        if hex_part.len() != 64 {
            return None;
        }
        let bytes = hex::decode(hex_part).ok()?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase 64-hex, without the prefix: the envelope's `signature.key`.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for PublicKey {
    /// The policy syntax: `ed25519:<64 lowercase hex>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{KEY_PREFIX}{}", self.hex())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Serializes as the prefixed policy syntax (`ed25519:<hex>`), the form
/// policy files and reports use. The envelope's `signature.key` is the bare
/// hex from `PublicKey::hex`; `SigningKey::sign` writes it, and a key built
/// with `serde_json::to_value` would never verify.
impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// A set of public keys, compared on decoded bytes.
pub type KeySet = BTreeSet<PublicKey>;

/// Keep only the keys `declared` also names. Used when a lower policy scope
/// (project or `--policy`) narrows the machine scope's trusted set: it can
/// drop keys, never add them.
pub fn intersect(effective: &mut KeySet, declared: &KeySet) {
    effective.retain(|key| declared.contains(key));
}

/// A loaded private key. The seed never leaves this process: it is neither
/// printed nor serialized.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    public: PublicKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({})", self.public)
    }
}

impl SigningKey {
    fn from_seed(seed: &[u8; 32]) -> io::Result<Self> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        let mut public = [0u8; 32];
        public.copy_from_slice(pair.public_key().as_ref());
        Ok(Self {
            pair,
            public: PublicKey(public),
        })
    }

    /// Load a key file. The file is opened once and every check runs on
    /// that handle: it must be a regular file, not accessible by group or
    /// other, and hold exactly one `ed25519:<64 hex>` line. Any failure is
    /// an error; a key that is configured never silently becomes "no key".
    pub fn load(path: &Path) -> io::Result<Self> {
        let refuse = |detail: String| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("signing key {}: {detail}", path.display()),
            )
        };
        if path.as_os_str().is_empty() {
            return Err(refuse("the configured path is empty".into()));
        }
        // Non-blocking open: a FIFO at the path must fail the regular-file
        // check below, not block the command until a writer appears.
        // O_NONBLOCK has no effect on a regular file.
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK);
        let file = options.open(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("signing key {}: {error}", path.display()),
            )
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| refuse(format!("cannot stat it: {error}")))?;
        if !metadata.is_file() {
            return Err(refuse("not a regular file".into()));
        }
        #[cfg(unix)]
        {
            let mode = metadata.mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(refuse(format!(
                    "mode {mode:04o} is accessible by group or other; run 'chmod 600' on it"
                )));
            }
        }
        if metadata.len() > MAX_KEY_FILE_BYTES {
            return Err(refuse(format!(
                "{} bytes is too large for a key file",
                metadata.len()
            )));
        }
        // The size check above is a fast path; the read itself is bounded
        // too, so a file whose reported size lies cannot be read whole.
        let mut text = String::new();
        (&file)
            .take(MAX_KEY_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|error| refuse(format!("cannot read it as UTF-8 text: {error}")))?;
        if text.len() as u64 > MAX_KEY_FILE_BYTES {
            return Err(refuse("longer than 1024 bytes; not a key file".into()));
        }
        let seed = parse_seed(&text).map_err(refuse)?;
        Self::from_seed(&seed)
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Sign `envelope` in place: compute its canonical bytes and set the
    /// top-level `signature` field. An existing `signature` is replaced;
    /// it is never part of what is signed.
    pub fn sign(&self, envelope: &mut Value) -> io::Result<()> {
        let bytes = canonical_bytes(envelope)?;
        let signature = self.pair.sign(&bytes);
        envelope
            .as_object_mut()
            .expect("canonical_bytes accepted an object")
            .insert(
                "signature".into(),
                json!({
                    "alg": ALGORITHM,
                    "key": self.public.hex(),
                    "sig": hex::encode(signature.as_ref()),
                }),
            );
        Ok(())
    }
}

/// The one accepted key-file grammar: `ed25519:<64 hex>` plus an optional
/// trailing newline. Anything else, including a second line, is malformed.
fn parse_seed(text: &str) -> Result<[u8; 32], String> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err("the file is empty; expected one line 'ed25519:<64 hex>'".into());
    }
    if line.contains('\n') {
        return Err("expected exactly one line 'ed25519:<64 hex>'".into());
    }
    let Some(hex_part) = line.strip_prefix(KEY_PREFIX) else {
        return Err("expected one line 'ed25519:<64 hex>'".into());
    };
    if hex_part.len() != 64 {
        return Err(format!(
            "expected 64 hex characters after 'ed25519:', found {}",
            hex_part.len()
        ));
    }
    let bytes = hex::decode(hex_part).map_err(|_| "expected 64 hex characters after 'ed25519:'")?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

/// Create a new key file at `path` and return its public key. The file is
/// created exclusively with mode 0600 from the first open: an existing
/// file or symlink at `path` is refused, never truncated. The seed is
/// written once and never printed.
pub fn generate(path: &Path) -> io::Result<PublicKey> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "keygen: the key path is empty",
        ));
    }
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| io::Error::other("keygen: the system random source failed"))?;
    let key = SigningKey::from_seed(&seed)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("keygen: create {}: {error}", path.display()),
        )
    })?;
    let result = (|| {
        file.write_all(format!("{KEY_PREFIX}{}\n", hex::encode(seed)).as_bytes())?;
        file.sync_all()
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(key.public_key())
}

/// The bytes a signature covers: the envelope with its top-level
/// `signature` removed, serialized compact. Keys are in byte order at every
/// depth, so the writer's value and the verifier's reparse of the
/// pretty-printed file produce identical bytes. Numbers are preserved by
/// serde_json's `float_roundtrip` feature; a float that is reparsed from
/// its shortest representation gives the same bytes again.
pub fn canonical_bytes(envelope: &Value) -> io::Result<Vec<u8>> {
    let Value::Object(map) = envelope else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "closure envelope is not a JSON object",
        ));
    };
    let mut map = map.clone();
    map.remove("signature");
    serde_json::to_vec(&Value::Object(map)).map_err(io::Error::from)
}

/// What verification found in one envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// No `signature` field at all.
    Unsigned,
    /// A `signature` field is present and does not verify: tampered
    /// record, malformed field, unknown algorithm. `key` is the public key
    /// the field named when it could be decoded, so a report can show it.
    Bad {
        key: Option<PublicKey>,
        reason: String,
    },
    /// The signature verifies under the named key. Whether that key is
    /// trusted is a separate, policy question.
    Valid(PublicKey),
}

/// Verify `envelope` against its own `signature` field. This says nothing
/// about trust: a valid signature under any key is `Valid`. A non-object
/// envelope has no signature and is `Unsigned`; shape validation is the
/// caller's job after authentication.
pub fn verify(envelope: &Value) -> Verification {
    let Some(field) = envelope.get("signature") else {
        return Verification::Unsigned;
    };
    let bad = |key: Option<PublicKey>, reason: &str| Verification::Bad {
        key,
        reason: reason.to_string(),
    };
    let Some(signature) = field.as_object() else {
        return bad(None, "the signature field is not an object");
    };
    let key = signature
        .get("key")
        .and_then(Value::as_str)
        .and_then(PublicKey::from_hex);
    if let Some(unexpected) = signature
        .keys()
        .find(|name| !matches!(name.as_str(), "alg" | "key" | "sig"))
    {
        return bad(key, &format!("unexpected signature field {unexpected:?}"));
    }
    match signature.get("alg").and_then(Value::as_str) {
        Some(ALGORITHM) => {}
        Some(other) => return bad(key, &format!("unsupported signature algorithm {other:?}")),
        None => return bad(key, "the signature names no algorithm"),
    }
    let Some(key) = key else {
        return bad(None, "the signature's public key is malformed");
    };
    let signature_bytes = signature
        .get("sig")
        .and_then(Value::as_str)
        .filter(|hex_part| hex_part.len() == 128)
        .and_then(|hex_part| hex::decode(hex_part).ok());
    let Some(signature_bytes) = signature_bytes else {
        return bad(Some(key), "the signature value is malformed");
    };
    let bytes = match canonical_bytes(envelope) {
        Ok(bytes) => bytes,
        Err(error) => return bad(Some(key), &error.to_string()),
    };
    match UnparsedPublicKey::new(&ED25519, key.as_bytes()).verify(&bytes, &signature_bytes) {
        Ok(()) => Verification::Valid(key),
        Err(_) => bad(Some(key), "record does not match its signature"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn fixed_key() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32]).unwrap()
    }

    /// The signature the all-sevens seed produces over
    /// `{"body":{"n":1},"schema":"closure/1"}`: pins key derivation and the
    /// canonical bytes together, so a change to either moves it.
    const FIXED_SIGNATURE: &str = "ec462ca39c39f1a303c2d766857487ba5b5768184685881bd6365d5c96e92a2b9f52d93ae97a92b4c925cf934508f945482f7e4aa46711fbec0d82bd8d48b802";
    /// The public key of the all-sevens seed, as ring derives it. Pins the
    /// derivation so a `ring` upgrade cannot silently move every key.
    const FIXED_SEED_PUBLIC_KEY: &str =
        "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    fn envelope() -> Value {
        json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": "x86_64-unknown-linux-gnu",
            "projected_at": 1_700_000_000u64,
            "body": {
                "inputs": [{"path": "requirements.txt", "sha256": "ab"}],
                "exceptions": [{"kind": "skipped_optional", "subject": "dev", "detail": ""}],
                "ratio": 2.291712365432881e-9,
            },
        })
    }

    #[test]
    fn keygen_load_sign_verify_round_trip() {
        let temp = TempDir::named("roundtrip");
        let path = temp.0.join("key");
        let public = generate(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("ed25519:"), "{text}");
        assert_eq!(text.len(), "ed25519:".len() + 64 + 1);
        assert!(text.ends_with('\n'));
        assert!(
            !text.contains(&public.hex()),
            "the seed file must not hold the public key"
        );
        let key = SigningKey::load(&path).unwrap();
        assert_eq!(key.public_key(), public);
        let mut value = envelope();
        key.sign(&mut value).unwrap();
        assert_eq!(value["signature"]["alg"], "ed25519");
        assert_eq!(value["signature"]["key"], public.hex());
        assert_eq!(value["signature"]["sig"].as_str().unwrap().len(), 128);
        assert_eq!(verify(&value), Verification::Valid(public));
        // Signing again replaces the field and still verifies.
        key.sign(&mut value).unwrap();
        assert_eq!(verify(&value), Verification::Valid(public));
    }

    #[test]
    fn signatures_are_deterministic() {
        let key = fixed_key();
        let mut a = envelope();
        let mut b = envelope();
        key.sign(&mut a).unwrap();
        key.sign(&mut b).unwrap();
        assert_eq!(a["signature"], b["signature"]);
    }

    #[test]
    fn a_signature_survives_pretty_print_and_reparse() {
        let key = fixed_key();
        let mut value = envelope();
        key.sign(&mut value).unwrap();
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        assert!(pretty.contains("2.291712365432881e-9"), "{pretty}");
        let reparsed: Value = serde_json::from_str(&pretty).unwrap();
        assert_eq!(
            canonical_bytes(&reparsed).unwrap(),
            canonical_bytes(&value).unwrap()
        );
        assert_eq!(verify(&reparsed), Verification::Valid(key.public_key()));
        // Key order and whitespace in the file are irrelevant.
        let shuffled = format!(
            "{{ \"signature\": {}, \"body\": {}, \"projected_at\": 1700000000, \"platform\": \"x86_64-unknown-linux-gnu\", \"ecosystem\": \"python\", \"schema\": \"closure/1\" }}",
            value["signature"], value["body"]
        );
        let shuffled: Value = serde_json::from_str(&shuffled).unwrap();
        assert_eq!(verify(&shuffled), Verification::Valid(key.public_key()));
    }

    #[test]
    fn canonical_byte_vectors_are_pinned() {
        // These vectors pin the serializer: nested keys in byte order at
        // every depth, escaping, integer boundaries, and finite floats
        // reparsed from their shortest form. A dependency upgrade that
        // changes any of them changes what every existing signature
        // covers, so it must be treated as a format change.
        let cases: &[(&str, &str)] = &[
            (
                r#"{"z": 1, "a": {"y": [3, {"b": 2, "a": 1}], "b": true}, "signature": {"x": 1}}"#,
                r#"{"a":{"b":true,"y":[3,{"a":1,"b":2}]},"z":1}"#,
            ),
            (
                r#"{"s": "quote\" backslash\\ slash/ tab\t nul\u0000 unit\u001f snow\u2603 emoji\ud83d\ude00 del\u007f"}"#,
                "{\"s\":\"quote\\\" backslash\\\\ slash/ tab\\t nul\\u0000 unit\\u001f snow\u{2603} emoji\u{1F600} del\u{7f}\"}",
            ),
            (
                r#"{"max_u64": 18446744073709551615, "min_i64": -9223372036854775808, "zero": 0, "neg": -1}"#,
                r#"{"max_u64":18446744073709551615,"min_i64":-9223372036854775808,"neg":-1,"zero":0}"#,
            ),
            (
                r#"{"a": 2.291712365432881e-9, "b": -0.0, "c": 5e-324, "d": 1.7976931348623157e308, "e": 0.1, "f": 1.0, "g": 1e21, "h": 123456789012345680000}"#,
                r#"{"a":2.291712365432881e-9,"b":-0.0,"c":5e-324,"d":1.7976931348623157e+308,"e":0.1,"f":1.0,"g":1e+21,"h":1.2345678901234568e+20}"#,
            ),
            (r#"{"empty": {}, "list": [], "null": null, "signature": null}"#, r#"{"empty":{},"list":[],"null":null}"#),
        ];
        for (input, expected) in cases {
            let value: Value = serde_json::from_str(input).unwrap();
            let bytes = canonical_bytes(&value).unwrap();
            assert_eq!(
                std::str::from_utf8(&bytes).unwrap(),
                *expected,
                "input {input}"
            );
            // The canonical form is a fixed point: reparsing it and
            // canonicalizing again gives the same bytes.
            let again: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(canonical_bytes(&again).unwrap(), bytes, "input {input}");
        }
    }

    #[test]
    fn a_fixed_seed_gives_a_fixed_signature() {
        // Pins the key derivation and the canonical bytes together: a
        // change to either moves this signature.
        let key = fixed_key();
        assert_eq!(key.public_key().to_string(), FIXED_SEED_PUBLIC_KEY);
        let mut value: Value =
            serde_json::from_str(r#"{"schema":"closure/1","body":{"n":1}}"#).unwrap();
        key.sign(&mut value).unwrap();
        assert_eq!(value["signature"]["sig"], FIXED_SIGNATURE);
        // The same value in another key order signs to the same bytes.
        let mut again: Value =
            serde_json::from_str(r#"{"body":{"n":1},"schema":"closure/1"}"#).unwrap();
        key.sign(&mut again).unwrap();
        assert_eq!(again["signature"]["sig"], FIXED_SIGNATURE);
    }

    #[test]
    fn tampering_anywhere_in_the_value_is_a_bad_signature() {
        let key = fixed_key();
        let mut signed = envelope();
        key.sign(&mut signed).unwrap();
        let public = key.public_key();
        let bad = |value: &Value| match verify(value) {
            Verification::Bad { key, reason } => (key, reason),
            other => panic!("expected a bad signature, got {other:?}"),
        };
        let mut edited = signed.clone();
        edited["body"]["exceptions"] = json!([]);
        assert_eq!(
            bad(&edited),
            (
                Some(public),
                "record does not match its signature".to_string()
            )
        );
        let mut edited = signed.clone();
        edited["platform"] = json!("aarch64-apple-darwin");
        assert_eq!(bad(&edited).0, Some(public));
        let mut edited = signed.clone();
        edited["unknown_envelope_field"] = json!(1);
        assert_eq!(bad(&edited).0, Some(public));
        let mut edited = signed.clone();
        edited["body"]["ratio"] = json!(2.2917123654328812e-9);
        assert_eq!(bad(&edited).0, Some(public));
        let mut edited = signed.clone();
        edited.as_object_mut().unwrap().remove("schema");
        assert_eq!(bad(&edited).0, Some(public));
    }

    #[test]
    fn malformed_signature_fields_are_bad_not_unsigned() {
        let key = fixed_key();
        let mut signed = envelope();
        key.sign(&mut signed).unwrap();
        let public = key.public_key();
        let bad = |value: &Value| match verify(value) {
            Verification::Bad { key, reason } => (key, reason),
            other => panic!("expected a bad signature, got {other:?}"),
        };
        let mut edited = signed.clone();
        edited["signature"] = Value::Null;
        assert_eq!(bad(&edited).0, None);
        let mut edited = signed.clone();
        edited["signature"] = json!("ed25519");
        assert_eq!(bad(&edited).0, None);
        let mut edited = signed.clone();
        edited["signature"]["alg"] = json!("rsa");
        let (found, reason) = bad(&edited);
        assert_eq!(found, Some(public));
        assert!(reason.contains("rsa"), "{reason}");
        let mut edited = signed.clone();
        edited["signature"].as_object_mut().unwrap().remove("alg");
        assert_eq!(bad(&edited).0, Some(public));
        let mut edited = signed.clone();
        edited["signature"]["key"] = json!("ab");
        assert_eq!(bad(&edited).0, None);
        let mut edited = signed.clone();
        edited["signature"]["key"] = json!(format!("ed25519:{}", public.hex()));
        assert_eq!(
            bad(&edited).0,
            None,
            "the envelope carries the bare hex form"
        );
        let mut edited = signed.clone();
        edited["signature"]["sig"] = json!("00");
        assert_eq!(bad(&edited).0, Some(public));
        let mut edited = signed.clone();
        let mut wrong = edited["signature"]["sig"].as_str().unwrap().to_string();
        wrong.replace_range(0..2, if wrong.starts_with("00") { "11" } else { "00" });
        edited["signature"]["sig"] = json!(wrong);
        assert_eq!(bad(&edited).0, Some(public));
        let mut edited = signed.clone();
        edited["signature"]["extra"] = json!(1);
        assert_eq!(bad(&edited).0, Some(public));
        // Another key's signature over the same bytes: valid under that key.
        let other = SigningKey::from_seed(&[9u8; 32]).unwrap();
        let mut resigned = signed.clone();
        other.sign(&mut resigned).unwrap();
        assert_eq!(verify(&resigned), Verification::Valid(other.public_key()));
        // Swapping in the other key without re-signing is bad under it.
        let mut edited = signed.clone();
        edited["signature"]["key"] = json!(other.public_key().hex());
        assert_eq!(bad(&edited).0, Some(other.public_key()));
    }

    #[test]
    fn unsigned_and_non_object_envelopes() {
        assert_eq!(verify(&envelope()), Verification::Unsigned);
        assert_eq!(verify(&json!([1, 2])), Verification::Unsigned);
        assert_eq!(verify(&Value::Null), Verification::Unsigned);
        assert!(canonical_bytes(&json!([1])).is_err());
        let key = fixed_key();
        let mut signed = envelope();
        key.sign(&mut signed).unwrap();
        signed.as_object_mut().unwrap().remove("signature");
        assert_eq!(verify(&signed), Verification::Unsigned);
    }

    #[test]
    fn duplicate_keys_are_interpreted_last_wins_everywhere() {
        let key = fixed_key();
        let mut signed: Value =
            serde_json::from_str(r#"{"schema":"closure/1","body":{"a":2}}"#).unwrap();
        key.sign(&mut signed).unwrap();
        let signature = signed["signature"].to_string();
        // A duplicate whose last value matches the signed value verifies:
        // the parsed value is the same value.
        let text =
            format!(r#"{{"schema":"closure/1","body":{{"a":1,"a":2}},"signature":{signature}}}"#);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(verify(&value), Verification::Valid(key.public_key()));
        // A duplicate whose last value differs changes the effective value.
        let text =
            format!(r#"{{"schema":"closure/1","body":{{"a":2,"a":1}},"signature":{signature}}}"#);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert!(matches!(verify(&value), Verification::Bad { .. }));
        // The same inside the signature object: the last `sig` wins.
        let text = format!(
            r#"{{"schema":"closure/1","body":{{"a":2}},"signature":{{"sig":"00","alg":"ed25519","key":"{}","sig":{}}}}}"#,
            key.public_key().hex(),
            signed["signature"]["sig"]
        );
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(verify(&value), Verification::Valid(key.public_key()));
    }

    #[test]
    fn public_key_syntax_normalizes_hex_case_and_refuses_the_rest() {
        let key = fixed_key().public_key();
        let upper = format!("ed25519:{}", key.hex().to_uppercase());
        assert_eq!(PublicKey::parse(&upper).unwrap(), key);
        assert_eq!(
            PublicKey::parse(&upper).unwrap().to_string(),
            key.to_string()
        );
        assert_eq!(key.to_string(), format!("ed25519:{}", key.hex()));
        assert_eq!(key.to_string().len(), "ed25519:".len() + 64);
        for bad in [
            "",
            "ed25519:",
            &key.hex(),
            &format!("ed25519:{}0", key.hex()),
            &format!("ed25519:{}", &key.hex()[..63]),
            &format!("ed25519:{}", key.hex().replace(['0', '1'], "g")),
            &format!("rsa:{}", key.hex()),
            &format!("ED25519:{}", key.hex()),
            &format!(" ed25519:{}", key.hex()),
        ] {
            assert!(PublicKey::parse(bad).is_err(), "{bad:?} parsed");
        }
        assert!(PublicKey::from_hex(&format!("ed25519:{}", key.hex())).is_none());
        // serde: a string in, the lowercase policy syntax out.
        let parsed: PublicKey = serde_json::from_value(json!(upper)).unwrap();
        assert_eq!(parsed, key);
        assert_eq!(serde_json::to_value(key).unwrap(), json!(key.to_string()));
        assert!(serde_json::from_value::<PublicKey>(json!("nope")).is_err());
        assert!(serde_json::from_value::<PublicKey>(json!(1)).is_err());
        // A set compares decoded bytes: the two spellings are one key.
        let set: KeySet = [PublicKey::parse(&upper).unwrap(), key]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn intersect_keeps_only_keys_both_name() {
        let a = SigningKey::from_seed(&[1u8; 32]).unwrap().public_key();
        let b = SigningKey::from_seed(&[2u8; 32]).unwrap().public_key();
        let c = SigningKey::from_seed(&[3u8; 32]).unwrap().public_key();
        let mut effective: KeySet = [a, b].into_iter().collect();
        intersect(&mut effective, &[b, c].into_iter().collect());
        assert_eq!(effective, [b].into_iter().collect());
        intersect(&mut effective, &KeySet::new());
        assert!(effective.is_empty());
        let mut effective: KeySet = [a].into_iter().collect();
        intersect(&mut effective, &[a, b, c].into_iter().collect());
        assert_eq!(effective, [a].into_iter().collect(), "narrowing never adds");
    }

    #[test]
    fn key_file_loading_refuses_what_it_must() {
        let temp = TempDir::named("keyfile");
        let seed = hex::encode([5u8; 32]);
        let good = temp.0.join("good");
        fs::write(&good, format!("ed25519:{seed}\n")).unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(SigningKey::load(&good).is_ok());
        // No trailing newline and CRLF are both one line.
        let bare = temp.0.join("bare");
        fs::write(&bare, format!("ed25519:{seed}")).unwrap();
        fs::set_permissions(&bare, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(SigningKey::load(&bare).is_ok());
        let crlf = temp.0.join("crlf");
        fs::write(&crlf, format!("ed25519:{seed}\r\n")).unwrap();
        fs::set_permissions(&crlf, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(SigningKey::load(&crlf).is_ok());

        let error = |path: &Path| SigningKey::load(path).unwrap_err().to_string();
        assert!(
            error(Path::new("")).contains("empty"),
            "{}",
            error(Path::new(""))
        );
        let missing = temp.0.join("missing");
        assert_eq!(
            SigningKey::load(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(
            error(&temp.0).contains("not a regular file"),
            "{}",
            error(&temp.0)
        );
        for mode in [0o640, 0o604, 0o644, 0o660, 0o601, 0o606] {
            let loose = temp.0.join(format!("loose-{mode:o}"));
            fs::write(&loose, format!("ed25519:{seed}\n")).unwrap();
            fs::set_permissions(&loose, fs::Permissions::from_mode(mode)).unwrap();
            let message = error(&loose);
            assert!(
                message.contains("group or other") && message.contains("chmod 600"),
                "{mode:o}: {message}"
            );
        }
        for (name, content, expected) in [
            ("empty", String::new(), "empty"),
            ("newline-only", "\n".to_string(), "empty"),
            (
                "two-lines",
                format!("ed25519:{seed}\nsecond\n"),
                "exactly one line",
            ),
            ("no-prefix", format!("{seed}\n"), "expected one line"),
            ("wrong-prefix", format!("rsa:{seed}\n"), "expected one line"),
            ("short", format!("ed25519:{}\n", &seed[..62]), "found 62"),
            ("long", format!("ed25519:{seed}00\n"), "found 66"),
            (
                "not-hex",
                format!("ed25519:{}zz\n", &seed[..62]),
                "64 hex characters",
            ),
            (
                "pem",
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_string(),
                "exactly one line",
            ),
            (
                "seed-with-comment",
                format!("ed25519:{seed} # comment\n"),
                "found 74",
            ),
        ] {
            let path = temp.0.join(name);
            fs::write(&path, content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let message = error(&path);
            assert!(
                message.starts_with("signing key") && message.contains(expected),
                "{name}: {message}"
            );
        }
        // A FIFO is refused, not waited on.
        let fifo = temp.0.join("fifo");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(
            error(&fifo).contains("not a regular file"),
            "{}",
            error(&fifo)
        );
        // A file whose reported size lies (procfs says 0) passes the size
        // check, so the length of what was read is what refuses it. This
        // pins that check; the `.take()` bounding the read is not visible
        // here, since an unbounded read of a finite file ends in the same
        // refusal, only after reading more.
        let environ = Path::new("/proc/self/environ");
        if environ.exists() {
            assert_eq!(fs::metadata(environ).unwrap().len(), 0);
            let message = SigningKey::load(environ).unwrap_err().to_string();
            if fs::read(environ).unwrap().len() > 1024 {
                assert!(
                    message.ends_with(": longer than 1024 bytes; not a key file"),
                    "{message}"
                );
            } else {
                assert!(message.starts_with("signing key"), "{message}");
            }
        }
        let huge = temp.0.join("huge");
        fs::write(&huge, vec![b'a'; 4096]).unwrap();
        fs::set_permissions(&huge, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(error(&huge).contains("too large"), "{}", error(&huge));
        let binary = temp.0.join("binary");
        fs::write(&binary, [0xffu8, 0xfe, 0x00]).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(error(&binary).contains("UTF-8"), "{}", error(&binary));
    }

    #[test]
    fn keygen_never_overwrites_a_file_or_follows_a_symlink() {
        let temp = TempDir::named("keygen");
        let existing = temp.0.join("existing");
        fs::write(&existing, "keep me\n").unwrap();
        let error = generate(&existing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert_eq!(fs::read_to_string(&existing).unwrap(), "keep me\n");
        let target = temp.0.join("target");
        fs::write(&target, "also keep\n").unwrap();
        let link = temp.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(generate(&link).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "also keep\n");
        let dangling = temp.0.join("dangling");
        std::os::unix::fs::symlink(temp.0.join("nowhere"), &dangling).unwrap();
        assert!(generate(&dangling).is_err());
        assert!(!temp.0.join("nowhere").exists());
        assert!(generate(&temp.0.join("no-such-dir/key")).is_err());
        assert!(generate(Path::new("")).is_err());
        // Two generated keys differ.
        let a = generate(&temp.0.join("a")).unwrap();
        let b = generate(&temp.0.join("b")).unwrap();
        assert_ne!(a, b);
    }
}

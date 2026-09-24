//! Where the Rust channel-manifest pins come from. `tools/rust_channel_pin.py`
//! verifies each manifest's detached signature against the Rust release key
//! checked in at `tools/keys/rust-release-signing-key.asc` before it prints
//! the sha256 that `CHANNEL_MANIFESTS` pins. These tests hold that key to the
//! published fingerprint, and the tool to refusing bytes Rust did not sign.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha1::{Digest, Sha1};

/// The primary key of "Rust Language (Tag and Release Signing Key)
/// <rust-key@rust-lang.org>".
const RUST_KEY_FINGERPRINT: &str = "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn base64(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {c}"),
        }
    };
    let symbols: Vec<u8> = text
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    let mut out = Vec::new();
    for chunk in symbols.chunks(4) {
        let mut word = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            word |= value(*c) << (18 - 6 * i);
        }
        let bytes = word.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    out
}

/// The v4 fingerprint of the first packet of an armored OpenPGP key: the
/// SHA-1 of 0x99, the two-byte body length, and the public-key packet body
/// (RFC 4880, 12.2).
fn primary_fingerprint(armored: &str) -> String {
    let body: String = armored
        .lines()
        .skip_while(|line| !line.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        .skip(1)
        .skip_while(|line| !line.trim().is_empty())
        .skip(1)
        .take_while(|line| !line.starts_with('=') && !line.starts_with("-----END"))
        .collect();
    let packets = base64(&body);
    let header = packets[0];
    assert!(header & 0x80 != 0, "not an OpenPGP packet");
    let (tag, length, start) = if header & 0x40 == 0 {
        let tag = (header >> 2) & 0x0f;
        match header & 0x03 {
            0 => (tag, packets[1] as usize, 2),
            1 => (
                tag,
                u16::from_be_bytes([packets[1], packets[2]]) as usize,
                3,
            ),
            2 => (
                tag,
                u32::from_be_bytes([packets[1], packets[2], packets[3], packets[4]]) as usize,
                5,
            ),
            _ => panic!("indeterminate packet length"),
        }
    } else {
        let tag = header & 0x3f;
        match packets[1] {
            octet @ 0..=191 => (tag, octet as usize, 2),
            octet @ 192..=223 => (
                tag,
                ((octet as usize - 192) << 8) + packets[2] as usize + 192,
                3,
            ),
            255 => (
                tag,
                u32::from_be_bytes([packets[2], packets[3], packets[4], packets[5]]) as usize,
                6,
            ),
            _ => panic!("partial packet length"),
        }
    };
    assert_eq!(tag, 6, "the first packet is not a public key");
    let key = &packets[start..start + length];
    assert_eq!(key[0], 4, "not a version 4 key");
    let mut sha1 = Sha1::new();
    sha1.update([0x99]);
    sha1.update((length as u16).to_be_bytes());
    sha1.update(key);
    hex::encode_upper(sha1.finalize())
}

#[test]
fn the_checked_in_key_is_the_rust_release_key() {
    let armored =
        std::fs::read_to_string(repo().join("tools/keys/rust-release-signing-key.asc")).unwrap();
    assert_eq!(primary_fingerprint(&armored), RUST_KEY_FINGERPRINT);
    // The tool checks signatures against the same fingerprint.
    let tool = std::fs::read_to_string(repo().join("tools/rust_channel_pin.py")).unwrap();
    assert!(
        tool.contains(&format!("FINGERPRINT = \"{RUST_KEY_FINGERPRINT}\"")),
        "tools/rust_channel_pin.py checks another fingerprint"
    );
}

fn pin_tool(args: &[&str]) -> std::process::Output {
    Command::new("python3")
        .arg(repo().join("tools/rust_channel_pin.py"))
        .args(args)
        .output()
        .expect("python3")
}

/// Offline, with the checked-in signature of the 1.96.1 manifest: the
/// trimmed test fixture is not the bytes Rust signed, so the tool refuses to
/// pin it. Needs `gpg` and `gpgv`.
#[test]
#[ignore]
fn the_pin_tool_refuses_a_manifest_rust_did_not_sign() {
    let signature = repo().join("tools/keys/channel-rust-1.96.1.toml.asc");
    let fixture = repo().join("src/kernel/provider/rust_channel_fixture.toml");
    let output = pin_tool(&[
        "1.96.1",
        "--manifest",
        path(&fixture),
        "--signature",
        path(&signature),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("does not verify"), "{stderr}");
}

/// Network: every row of `CHANNEL_MANIFESTS` is the sha256 of a manifest
/// whose signature verifies against the checked-in Rust key.
#[test]
#[ignore]
fn every_pinned_channel_manifest_is_signed_by_rust() {
    let output = pin_tool(&["--check"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!(
            "Rust {}: ",
            tog::kernel::provider::rust::RUST_VERSION
        )),
        "{stdout}"
    );
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

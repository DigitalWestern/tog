#!/usr/bin/env python3
"""Pin a Rust channel manifest: verify its signature, print its sha256.

tog provisions Rust components and cross targets from the official channel
manifest `channel-rust-<version>.toml`, pinned by sha256 in
`src/kernel/provider/rust.rs` (`CHANNEL_MANIFESTS`). At runtime tog checks
only that sha256. This tool is where the sha256 comes from: it downloads the
manifest and its detached signature, verifies the signature with `gpgv`
against the Rust release signing key checked in at
`tools/keys/rust-release-signing-key.asc`, and only then prints the pin.

    python3 tools/rust_channel_pin.py 1.96.1      # verify, print the Rust row
    python3 tools/rust_channel_pin.py --check     # re-verify every pinned row
    python3 tools/rust_channel_pin.py 1.96.1 --manifest FILE --signature FILE
                                                  # verify local files, offline

Needs `gpg` (to read the armored key) and `gpgv`. Exits non-zero, naming the
reason, when a signature does not verify, is not from the Rust key, or a
pinned sha256 is not the signed manifest's.
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
KEY = os.path.join(REPO, "tools", "keys", "rust-release-signing-key.asc")
PINS = os.path.join(REPO, "src", "kernel", "provider", "rust.rs")
DIST = "https://static.rust-lang.org/dist"
# "Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>",
# as published at https://static.rust-lang.org/rust-key.gpg.ascii.
FINGERPRINT = "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"


def fail(message):
    print(f"rust_channel_pin: {message}", file=sys.stderr)
    sys.exit(1)


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def verify(version, manifest, signature, scratch):
    """Verify `signature` over `manifest` with the checked-in key only."""
    keyring = os.path.join(scratch, "rust.gpg")
    home = os.path.join(scratch, "gnupg")
    os.makedirs(home, mode=0o700, exist_ok=True)
    with open(KEY, "rb") as armored, open(keyring, "wb") as out:
        subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--dearmor"],
            stdin=armored,
            stdout=out,
            check=True,
        )
    paths = {}
    for name, data in (("manifest", manifest), ("signature", signature)):
        paths[name] = os.path.join(scratch, f"channel-rust-{version}.{name}")
        with open(paths[name], "wb") as out:
            out.write(data)
    result = subprocess.run(
        [
            "gpgv",
            "--homedir",
            home,
            "--status-fd",
            "1",
            "--keyring",
            keyring,
            paths["signature"],
            paths["manifest"],
        ],
        capture_output=True,
        text=True,
    )
    # VALIDSIG <signing-key fpr> ... <primary-key fpr>: the last field is the
    # primary key the signature chains to.
    valid = [
        line.split()
        for line in result.stdout.splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    if result.returncode != 0 or not valid:
        fail(
            f"channel-rust-{version}.toml: the signature does not verify against the Rust "
            f"release key\n{result.stderr.strip()}"
        )
    if valid[0][-1] != FINGERPRINT:
        fail(f"channel-rust-{version}.toml is signed by {valid[0][-1]}, not the Rust key {FINGERPRINT}")
    manifest_version = re.search(rb'^manifest-version = "([^"]+)"', manifest, re.M)
    if not manifest_version or manifest_version.group(1) != b"2":
        fail(f"channel-rust-{version}.toml is not a version 2 manifest")
    return hashlib.sha256(manifest).hexdigest()


def pinned():
    """Every (version, sha256) row of CHANNEL_MANIFESTS."""
    with open(PINS, encoding="utf-8") as source:
        text = source.read()
    table = re.search(r"pub const CHANNEL_MANIFESTS[^=]*=\s*&\[(.*?)\];", text, re.S)
    if not table:
        fail(f"no CHANNEL_MANIFESTS table in {PINS}")
    rows = re.findall(r'version:\s*"([^"]+)",\s*sha256:\s*"([0-9a-f]{64})"', table.group(1))
    if not rows:
        fail(f"CHANNEL_MANIFESTS in {PINS} has no rows")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", nargs="?")
    parser.add_argument("--check", action="store_true", help="re-verify every pinned row")
    parser.add_argument("--manifest", help="a local manifest instead of downloading it")
    parser.add_argument("--signature", help="a local detached signature for --manifest")
    args = parser.parse_args()
    if bool(args.manifest) != bool(args.signature):
        fail("--manifest and --signature go together")
    if args.check == bool(args.version):
        fail("give a version, or --check")
    scratch_root = os.environ.get("TMPDIR") or None
    with tempfile.TemporaryDirectory(prefix="rust-channel-pin-", dir=scratch_root) as scratch:
        if args.check:
            for version, sha256 in pinned():
                url = f"{DIST}/channel-rust-{version}.toml"
                digest = verify(version, fetch(url), fetch(url + ".asc"), scratch)
                if digest != sha256:
                    fail(f"Rust {version}: pinned {sha256}, but the signed manifest is {digest}")
                print(f"Rust {version}: {digest} is the signed manifest")
            return
        if args.manifest:
            with open(args.manifest, "rb") as m, open(args.signature, "rb") as s:
                manifest, signature = m.read(), s.read()
        else:
            url = f"{DIST}/channel-rust-{args.version}.toml"
            manifest, signature = fetch(url), fetch(url + ".asc")
        digest = verify(args.version, manifest, signature, scratch)
        print(
            "ChannelManifestPin {\n"
            f'    version: "{args.version}",\n'
            f'    sha256: "{digest}",\n'
            "},"
        )


if __name__ == "__main__":
    main()

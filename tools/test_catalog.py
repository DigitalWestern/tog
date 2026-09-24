#!/usr/bin/env python3
"""Offline tests for tools/catalog.py: `python3 tools/test_catalog.py`.

The network is replaced by a table of URL -> body, shaped like the upstream
answers the generator reads. The Hex and rebar3 CSV rows are recorded
verbatim from builds.hex.pm/installs (2026-09-23); the archives are
stand-ins whose digests the fake listings publish, so every verification
path runs for real.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import catalog  # noqa: E402

DARWIN, LINUX = catalog.DARWIN, catalog.LINUX

# Recorded from https://builds.hex.pm/installs/hex.csv and rebar.csv.
HEX_CSV = """\
2.5.0,729168e52d990a4f30ae5a8643d9bdf1a51f6d7734a6e18241b0f04114f34e599a062302254557d78b415b308db77219a242f3d124339076da9aa5d385b78569,1.20.0,29
2.5.1,b97d99a4d137bfa7fbd2c70e141f345e911d45ad541c2e8f8cd500edb0d8d682eb52463a3ccd85cfc18e141b847d4f6a03534e2a0dbd798014c1ed641572cc8f,1.19.0,28
2.5.1,690f12f6933088bb32f1d7125485fb13426318c03cfeabcbd3cce55824cddf2a701104b09b7f4cd7092fe7f76d5b669e391a072428ec4526879b36f62820ae5d,1.20.0,28
2.5.1,6629f4b4bb2e040326151ebb853aad065e342c65ad3a0f2a2674dcf7164eb4328d6c929513d7230309ad75042024e72bef0e0a51ebff373b4173d2746b1772b7,1.20.0,29
"""
REBAR_CSV = """\
3.24.0,158473850233093e6a1417e9779919cb6768402ea967db510d926bc5e74361377e9176014e827c622098e0dbf96b505677addc4bd4817ce2b9b4f4bc8121768b,1.18.3,27
3.25.1,992fd755b7926fae455e5e07d9d195f4d3e7f181609eed1b9cabfe548624df10d148cd4b59bda40bebb185d3d68f9a9fd68a70b294101c8ad9cf0fadcc683d24,1.18.4,28
"""


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def sha512(body):
    return hashlib.sha512(body).hexdigest()


class FakeNetwork:
    """`catalog.http_get`, answered from a table; records every request."""

    def __init__(self):
        self.bodies = {}
        self.requests = []

    def __call__(self, url):
        self.requests.append(url)
        body = self.bodies.get(url)
        if body is None:
            return None
        return body if isinstance(body, bytes) else body.encode()

    def json(self, url, value):
        self.bodies[url] = json.dumps(value)


class Base(unittest.TestCase):
    def setUp(self):
        self.net = FakeNetwork()
        self.scratch = tempfile.TemporaryDirectory()
        self.saved = (catalog.http_get, catalog.CACHE, catalog.run_linux_bottle, catalog.REPO)
        catalog.http_get = self.net
        catalog.CACHE = os.path.join(self.scratch.name, "cache")
        # Running a stand-in bottle's bin/ruby is not the point here.
        catalog.run_linux_bottle = lambda *args: False

    def tearDown(self):
        catalog.http_get, catalog.CACHE, catalog.run_linux_bottle, catalog.REPO = self.saved
        self.scratch.cleanup()


class Http(Base):
    def test_listings_and_checksum_files_are_fetched_fresh_every_time(self):
        url = "https://go.dev/dl/?mode=json"
        self.net.bodies[url] = "[1]"
        self.assertEqual(catalog.fetch_json(url), [1])
        self.net.bodies[url] = "[1, 2]"
        self.assertEqual(catalog.fetch_json(url), [1, 2])
        self.assertEqual(self.net.requests.count(url), 2)

    def test_a_404_is_not_remembered(self):
        url = "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/x.tar.gz.sha512"
        self.assertIsNone(catalog.fetch_text(url, missing_ok=True))
        with self.assertRaises(catalog.Failure):
            catalog.fetch_text(url)
        self.net.bodies[url] = "abc  x.tar.gz\n"
        self.assertEqual(catalog.fetch_text(url, missing_ok=True), "abc  x.tar.gz\n")

    def test_only_archives_are_cached_and_are_rehashed_on_every_use(self):
        url = "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz"
        self.net.bodies[url] = b"archive"
        self.assertEqual(catalog.download_digest(url, "sha256"), sha256(b"archive"))
        self.assertEqual(catalog.download_digest(url, "sha512"), sha512(b"archive"))
        self.assertEqual(self.net.requests.count(url), 1)
        with open(catalog.archive_path(url), "wb") as f:
            f.write(b"tampered")
        self.assertEqual(catalog.download_digest(url, "sha256"), sha256(b"tampered"))


class MixRule(unittest.TestCase):
    def test_the_newest_install_whose_elixir_and_otp_are_not_newer(self):
        self.assertEqual(catalog.mix_pick(HEX_CSV, "1.20.4", "29")[:1], ("2.5.1",))
        self.assertEqual(catalog.mix_pick(HEX_CSV, "1.20.4", "29")[2:], ("1.20.0", "29"))
        self.assertEqual(catalog.mix_pick(HEX_CSV, "1.19.5", "28")[2:], ("1.19.0", "28"))
        # rebar3 has no OTP 29 build: Mix takes the OTP 28 one.
        self.assertEqual(catalog.mix_pick(REBAR_CSV, "1.20.4", "29")[0], "3.25.1")
        self.assertIsNone(catalog.mix_pick(HEX_CSV, "1.18.0", "29"))


def written(eco, root, releases):
    """`releases` rendered into a catalog file under `root`, read back."""
    catalog.REPO = root
    path = os.path.join(root, catalog.FILES[eco])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(catalog.render(eco, releases[0]["key"], releases))
    return catalog.read_document(eco)["release"]


def github_releases(net, repo, releases):
    net.json(f"https://api.github.com/repos/{repo}/releases?per_page=100&page=1", releases)


def asset(name, body):
    return {"name": name, "digest": f"sha256:{sha256(body)}"}


class Elixir(Base):
    OTP, ELIXIR = "29.0.5", "1.20.4"

    def setUp(self):
        super().setUp()
        net = self.net
        darwin = b"otp darwin"
        linux = b"otp linux"
        self.zip = b"elixir zip"
        ltag = f"otp-{self.OTP}-{LINUX}-fedora44"
        lname = f"OTP-{self.OTP}-{LINUX}-fedora44.tar.gz"
        github_releases(net, catalog.ERLEF, [{
            "tag_name": f"OTP-{self.OTP}", "prerelease": False,
            "assets": [asset("otp-aarch64-apple-darwin.tar.gz", darwin)],
        }])
        github_releases(net, catalog.TOG_TOOLCHAINS, [{
            "tag_name": ltag, "prerelease": False, "assets": [asset(lname, linux)],
        }])
        net.bodies[f"https://github.com/{catalog.TOG_TOOLCHAINS}/releases/download/{ltag}/{lname}.sha256"] = (
            f"{sha256(linux)}  {lname}\n")
        github_releases(net, catalog.ELIXIR, [{
            "tag_name": f"v{self.ELIXIR}", "prerelease": False, "draft": False,
            "assets": [asset("elixir-otp-29.zip", self.zip)],
        }])
        zip_url = f"https://github.com/{catalog.ELIXIR}/releases/download/v{self.ELIXIR}/elixir-otp-29.zip"
        net.bodies[zip_url] = self.zip
        net.bodies[zip_url + ".sha256sum"] = f"{sha256(self.zip)}  elixir-otp-29.zip\n"
        self.hex_csv = []
        self.rebar_csv = []
        self.install("hex", "2.5.1", "1.20.0", "29")
        self.install("rebar3", "3.25.1", "1.18.4", "28")

    def install(self, tool, version, elixir_dir, otp):
        suffix = ".ez" if tool == "hex" else ""
        body = f"{tool} {version} {elixir_dir} {otp}".encode()
        self.net.bodies[f"https://builds.hex.pm/installs/{elixir_dir}/{tool}-{version}-otp-{otp}{suffix}"] = body
        rows = self.hex_csv if tool == "hex" else self.rebar_csv
        rows.append(f"{version},{sha512(body)},{elixir_dir},{otp}")
        self.net.bodies["https://builds.hex.pm/installs/hex.csv"] = "\n".join(self.hex_csv) + "\n"
        self.net.bodies["https://builds.hex.pm/installs/rebar.csv"] = "\n".join(self.rebar_csv) + "\n"

    def generate(self, existing):
        report = catalog.Report("elixir")
        return catalog.generate_elixir(existing, report), report

    def shipped(self):
        """The pair as a later run reads it: rendered, written, parsed back
        (the file orders artifact rows by component, not as generated)."""
        out, report = self.generate([])
        self.assertEqual(report.added, [f"beam-otp{self.OTP}-elixir{self.ELIXIR}"])
        return written("elixir", self.scratch.name, list(out.values()))

    def test_a_shipped_pair_is_verified_against_the_tools_it_records(self):
        existing = self.shipped()
        out, report = self.generate(existing)
        self.assertEqual(list(out.values()), existing)
        self.assertEqual((report.added, report.republished), ([], []))

    def test_a_newer_hex_is_a_new_revision_and_the_shipped_pair_is_kept(self):
        existing = self.shipped()
        self.install("hex", "2.6.0", "1.20.0", "29")
        out, report = self.generate(existing)
        key = f"beam-otp{self.OTP}-elixir{self.ELIXIR}"
        self.assertEqual(out[key], existing[0])
        revision = out[f"{key}-r2"]
        self.assertEqual(revision["revision"], 2)
        self.assertIn({"name": "hex", "version": "2.6.0"}, revision["components"])
        self.assertEqual(report.added, [f"{key}-r2"])
        self.assertEqual([k for k, _ in report.republished], [f"{key}-r2"])
        # And the next run keeps both, adding nothing.
        again, report = self.generate(list(out.values()))
        self.assertEqual(again, out)
        self.assertEqual(report.added, [])
        # A third Hex is revision 3.
        self.install("hex", "2.7.0", "1.20.0", "29")
        third, report = self.generate(list(again.values()))
        self.assertEqual(third[f"{key}-r3"]["revision"], 3)

    def test_a_recorded_install_upstream_withdrew_is_an_error(self):
        existing = self.shipped()
        self.hex_csv.clear()
        self.install("hex", "2.6.0", "1.20.0", "29")
        with self.assertRaisesRegex(catalog.Failure, "no longer lists"):
            self.generate(existing)

    def test_a_shipped_row_whose_bytes_changed_is_an_error(self):
        existing = self.shipped()
        zip_url = f"https://github.com/{catalog.ELIXIR}/releases/download/v{self.ELIXIR}/elixir-otp-29.zip"
        os.remove(catalog.archive_path(zip_url))
        self.net.bodies[zip_url] = b"re-published"
        with self.assertRaises(catalog.Failure):
            self.generate(existing)


def bottle(tag):
    """A stand-in portable-ruby bottle with the recipe's layout."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        for name in ("bin/ruby", "bin/gem", "bin/bundle", "lib/libruby-static.a",
                     "include/ruby-3.4.0/ruby.h"):
            info = tarfile.TarInfo(f"portable-ruby/{tag}/{name}")
            info.size = len(tag)
            tar.addfile(info, io.BytesIO(tag.encode()))
    return data.getvalue()


class Ruby(Base):
    def setUp(self):
        super().setUp()
        self.net.bodies[
            "https://raw.githubusercontent.com/ruby/www.ruby-lang.org/master/_data/branches.yml"
        ] = "- name: 3.4\n  status: normal maintenance\n\n- name: 4.0\n  status: normal maintenance\n"
        self.releases = []

    def publish(self, tag):
        assets = []
        for platform in catalog.PLATFORMS:
            name = f"portable-ruby-{tag}.{catalog.BOTTLE_TAGS[platform]}.bottle.tar.gz"
            body = bottle(tag)
            self.net.bodies[f"https://github.com/{catalog.PORTABLE}/releases/download/{tag}/{name}"] = body
            assets.append(asset(name, body))
        self.releases.append({"tag_name": tag, "draft": False, "prerelease": False, "assets": assets})
        github_releases(self.net, catalog.PORTABLE, self.releases)

    def generate(self, existing):
        report = catalog.Report("ruby")
        return catalog.generate_ruby(existing, report), report

    def test_a_homebrew_rebuild_is_a_new_revision_beside_the_shipped_bottle(self):
        self.publish("3.4.6")
        first, _ = self.generate([])
        self.assertEqual(list(first), ["ruby-3.4.6"])
        self.assertIsNone(first["ruby-3.4.6"]["revision"])
        self.publish("3.4.6_1")
        out, report = self.generate(list(first.values()))
        self.assertEqual(out["ruby-3.4.6"], first["ruby-3.4.6"])
        rebuild = out["ruby-3.4.6_1"]
        self.assertEqual(rebuild["revision"], 2)
        self.assertEqual(rebuild["components"], [{"name": "ruby", "version": "3.4.6"}])
        self.assertEqual({a["build"] for a in rebuild["artifacts"]}, {"3.4.6_1"})
        self.assertEqual([k for k, _ in report.republished], ["ruby-3.4.6_1"])
        # A second rebuild takes Homebrew's number when it is higher.
        self.publish("3.4.6_3")
        again, _ = self.generate(list(out.values()))
        self.assertEqual(again["ruby-3.4.6_3"]["revision"], 3)

    def test_a_new_version_enters_with_its_newest_rebuild(self):
        self.publish("3.4.7")
        self.publish("3.4.7_1")
        out, report = self.generate([])
        self.assertEqual(list(out), ["ruby-3.4.7"])
        self.assertEqual(out["ruby-3.4.7"]["artifacts"][0]["build"], "3.4.7_1")
        self.assertEqual(report.republished, [])

    def test_check_reports_a_rebuild_as_drift_and_writes_nothing(self):
        catalog.REPO = self.scratch.name
        path = os.path.join(self.scratch.name, catalog.FILES["ruby"])
        os.makedirs(os.path.dirname(path))
        self.publish("3.4.6")
        first, _ = self.generate([])
        text = catalog.render("ruby", "ruby-3.4.6", list(first.values()))
        with open(path, "w") as f:
            f.write(text)
        args = type("Args", (), {"check": True, "set_default": None})()
        self.assertTrue(catalog.run("ruby", args))
        self.publish("3.4.6_1")
        self.assertFalse(catalog.run("ruby", args))
        with open(path) as f:
            self.assertEqual(f.read(), text)
        # Written, the rebuild renders after the shipped release of its
        # version, and the default does not move.
        args.check = False
        self.assertTrue(catalog.run("ruby", args))
        with open(path) as f:
            written = f.read()
        self.assertIn('default = "ruby-3.4.6"', written)
        self.assertLess(written.index('key = "ruby-3.4.6"'), written.index('key = "ruby-3.4.6_1"'))
        self.assertIn("revision = 2\n", written)


class Rust(Base):
    """The Rust reader against a fake static.rust-lang.org. The manifests
    are signed for real, by a throwaway key standing in for the Rust release
    key, so gpgv runs on every path."""

    DIST = "https://static.rust-lang.org/dist"

    @classmethod
    def setUpClass(cls):
        cls.gnupg = tempfile.TemporaryDirectory()
        home = cls.gnupg.name
        os.chmod(home, 0o700)
        cls.gpg = ["gpg", "--homedir", home, "--batch", "--quiet", "--pinentry-mode", "loopback",
                   "--passphrase", ""]
        subprocess.run(cls.gpg + ["--quick-gen-key", "Test Rust Key <rust@example.invalid>",
                                  "ed25519", "sign", "never"], check=True, capture_output=True)
        listing = subprocess.run(cls.gpg + ["--with-colons", "--list-keys"], check=True,
                                 capture_output=True, text=True).stdout
        cls.fingerprint = next(line.split(":")[9] for line in listing.splitlines()
                               if line.startswith("fpr:"))
        cls.key = os.path.join(home, "test-key.asc")
        with open(cls.key, "wb") as f:
            f.write(subprocess.run(cls.gpg + ["--armor", "--export"], check=True,
                                   capture_output=True).stdout)

    @classmethod
    def tearDownClass(cls):
        cls.gnupg.cleanup()

    def setUp(self):
        super().setUp()
        self.rust_saved = (catalog.RUST_KEY, catalog.RUST_FINGERPRINT, catalog.RUST_OLDEST)
        catalog.RUST_KEY = self.key
        catalog.RUST_FINGERPRINT = self.fingerprint
        catalog.RUST_OLDEST = (1, 70, 0)

    def tearDown(self):
        catalog.RUST_KEY, catalog.RUST_FINGERPRINT, catalog.RUST_OLDEST = self.rust_saved
        super().tearDown()

    def sign(self, body):
        path = os.path.join(self.scratch.name, "to-sign")
        with open(path, "wb") as f:
            f.write(body)
        return subprocess.run(self.gpg + ["--armor", "--detach-sign", "--output", "-", path],
                              check=True, capture_output=True).stdout

    @staticmethod
    def archive_sha(name):
        return sha256(name.encode())

    def manifest(self, version, missing=()):
        lines = ['manifest-version = "2"', 'date = "2026-01-01"']
        for package, name in (("rustc", "rustc"), ("rust-std", "rust-std"), ("cargo", "cargo"),
                              ("rustfmt-preview", "rustfmt")):
            lines += [f"[pkg.{package}]", f'version = "{version} (0123abc 2026-01-01)"']
            for platform in (DARWIN, LINUX):
                if (name, platform) in missing:
                    continue
                archive = f"{name}-{version}-{platform}.tar.xz"
                lines += [f"[pkg.{package}.target.{platform}]", "available = true",
                          f'xz_url = "{self.DIST}/2026-01-01/{archive}"',
                          f'xz_hash = "{self.archive_sha(archive)}"']
        lines += ["[renames.rustfmt]", 'to = "rustfmt-preview"']
        return ("\n".join(lines) + "\n").encode()

    def publish(self, version, missing=(), signed=None, stable=False):
        body = self.manifest(version, missing)
        url = f"{self.DIST}/channel-rust-{version}.toml"
        self.net.bodies[url] = body
        self.net.bodies[url + ".asc"] = self.sign(signed if signed is not None else body)
        self.net.bodies[url + ".sha256"] = f"{sha256(body)}  channel-rust-{version}.toml\n"
        for name in ("rustc", "rust-std", "cargo", "rustfmt"):
            for platform in (DARWIN, LINUX):
                archive = f"{name}-{version}-{platform}.tar.xz"
                self.net.bodies[f"{self.DIST}/{archive}.sha256"] = f"{self.archive_sha(archive)}  {archive}\n"
        if stable:
            self.net.bodies[f"{self.DIST}/channel-rust-stable.toml"] = body
        return body

    def generate(self, existing):
        report = catalog.Report("cargo")
        return catalog.generate_cargo(existing, report), report

    def test_every_stable_release_from_the_oldest_is_signed_verified_and_pinned(self):
        self.publish("1.70.0")
        self.publish("1.71.0")
        body = self.publish("1.71.1", stable=True)
        out, report = self.generate([])
        self.assertEqual(sorted(out), ["rust-1.70.0", "rust-1.71.0", "rust-1.71.1"])
        rel = out["rust-1.71.1"]
        self.assertEqual([c["name"] for c in rel["components"]],
                         ["rustc", "rust-std", "cargo", "rustfmt", "channel-manifest"])
        self.assertEqual(len(rel["artifacts"]), 10)
        rows = {(a["platform"], a["component"]): a for a in rel["artifacts"]}
        rustc = rows[(LINUX, "rustc")]
        # The undated URL, the digest the signed manifest names.
        self.assertEqual(rustc["url"], f"{self.DIST}/rustc-1.71.1-{LINUX}.tar.xz")
        self.assertEqual(rustc["digest"], "sha256:" + self.archive_sha(f"rustc-1.71.1-{LINUX}.tar.xz"))
        self.assertEqual(rows[(DARWIN, "rustfmt")]["recipe"], "rustfmt/1")
        manifest = rows[(DARWIN, "channel-manifest")]
        self.assertEqual(manifest["url"], f"{self.DIST}/channel-rust-1.71.1.toml")
        self.assertEqual(manifest["digest"], "sha256:" + sha256(body))
        self.assertEqual(manifest["recipe"], "rust-channel-manifest/1")
        self.assertEqual(report.skipped, [])
        # The render is the canonical document, newest first.
        text = catalog.render("cargo", "rust-1.71.1", list(out.values()))
        self.assertIn('default = "rust-1.71.1"', text)
        self.assertLess(text.index('key = "rust-1.71.1"'), text.index('key = "rust-1.70.0"'))

    def test_a_manifest_the_signature_does_not_cover_is_refused(self):
        self.publish("1.70.0", signed=b"other bytes\n", stable=True)
        with self.assertRaisesRegex(catalog.Failure, "does not verify"):
            self.generate([])

    def test_a_signature_by_a_key_other_than_rusts_is_refused(self):
        self.publish("1.70.0", stable=True)
        catalog.RUST_FINGERPRINT = "0" * 40
        with self.assertRaisesRegex(catalog.Failure, "not the Rust release key"):
            self.generate([])

    def test_a_release_missing_an_archive_is_skipped_with_the_reason(self):
        self.publish("1.70.0", missing={("rustfmt", DARWIN)})
        self.publish("1.71.0", stable=True)
        out, report = self.generate([])
        self.assertEqual(list(out), ["rust-1.71.0"])
        self.assertEqual(len(report.skipped), 1)
        self.assertIn(f"rustfmt-preview .tar.xz for {DARWIN}", report.skipped[0][1])

    def test_a_published_sha256_that_disagrees_is_an_error(self):
        self.publish("1.70.0", stable=True)
        self.net.bodies[f"{self.DIST}/cargo-1.70.0-{LINUX}.tar.xz.sha256"] = "0" * 64 + "  x\n"
        with self.assertRaisesRegex(catalog.Failure, r"\.sha256"):
            self.generate([])

    def test_a_shipped_row_upstream_no_longer_signs_is_an_error(self):
        self.publish("1.70.0", stable=True)
        first, _ = self.generate([])
        shipped = json.loads(json.dumps(first["rust-1.70.0"]))
        shipped["artifacts"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(catalog.Failure, "no longer matches upstream"):
            self.generate([shipped])

    def test_the_real_key_refuses_the_trimmed_fixture_under_the_real_signature(self):
        """The checked-in Rust key and 1.96.1 signature: the trimmed test
        fixture is not the bytes Rust signed."""
        catalog.RUST_KEY, catalog.RUST_FINGERPRINT = self.rust_saved[0], self.rust_saved[1]
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo, "tools/keys/channel-rust-1.96.1.toml.asc"), "rb") as f:
            signature = f.read()
        with open(os.path.join(repo, "src/kernel/provider/rust_channel_fixture.toml"), "rb") as f:
            fixture = f.read()
        with self.assertRaisesRegex(catalog.Failure, "does not verify"):
            catalog.rust_verify("1.96.1", fixture, signature, catalog.rust_keyring())


if __name__ == "__main__":
    unittest.main()

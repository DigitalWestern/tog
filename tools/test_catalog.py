#!/usr/bin/env python3
"""Offline tests for tools/catalog.py: `python3 tools/test_catalog.py`.

The network is replaced by a table of URL -> body, shaped like the upstream
answers the generator reads. The Hex and rebar3 CSV rows are recorded
verbatim from builds.hex.pm/installs (2026-09-23); the archives are
stand-ins whose digests the fake listings publish, so every verification
path runs for real.
"""
import contextlib
import datetime
import hashlib
import io
import json
import lzma
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
        self.saved = (catalog.http_get, catalog.CACHE, catalog.run_linux_bottle, catalog.REPO,
                      catalog.SCRATCH, catalog.TODAY)
        catalog.http_get = self.net
        catalog.CACHE = os.path.join(self.scratch.name, "cache")
        # Keyrings, signatures and manifests land in the test's own scratch
        # directory, which is removed afterwards, not in a fresh /tmp one.
        catalog.SCRATCH = os.path.join(self.scratch.name, "work")
        os.makedirs(catalog.SCRATCH)
        # Running a stand-in bottle's bin/ruby is not the point here.
        catalog.run_linux_bottle = lambda *args: False

    def tearDown(self):
        (catalog.http_get, catalog.CACHE, catalog.run_linux_bottle, catalog.REPO,
         catalog.SCRATCH, catalog.TODAY) = self.saved
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


def run_quietly(eco, check):
    """`catalog.run` on the catalog under `catalog.REPO`: (ok, what it printed)."""
    args = type("Args", (), {"check": check, "set_default": None})()
    with contextlib.redirect_stdout(io.StringIO()) as out:
        ok = catalog.run(eco, args)
    return ok, out.getvalue()


def read(path):
    with open(path) as f:
        return f.read()


def assert_every_field_is_checked(test, eco, existing, generate):
    """A shipped row whose digest still matches but whose URL, recipe,
    provider or build differs from upstream's is refused like a changed
    digest: the whole row is compared, not just its checksum."""
    rel = existing[0]
    primary = catalog.PRIMARY[eco][0]
    i = max(n for n, a in enumerate(rel["artifacts"]) if a["component"] == primary)
    for field, value in (("url", rel["artifacts"][i]["url"] + ".moved"), ("recipe", "other/1"),
                         ("provider", "elsewhere.invalid"), ("build", "0")):
        with test.subTest(field=field):
            changed = dict(rel, artifacts=[dict(a) for a in rel["artifacts"]])
            changed["artifacts"][i][field] = value
            with test.assertRaises(catalog.Failure) as cm:
                generate([changed] + existing[1:])
            lines = str(cm.exception).splitlines()
            test.assertEqual(lines[0], f"{eco}: {rel['key']}: the checked-in row no longer matches upstream")
            test.assertIn(repr(value), lines[1])


def gpg_home(cls):
    """A throwaway GnuPG home and the gpg command that uses it. Removal is
    registered as a class cleanup before any key is made, so it runs even if
    setUpClass fails; it stops the home's gpg-agent and removes its socket
    directory first, so no agent or socket outlives the tests."""
    home = tempfile.TemporaryDirectory()

    def cleanup():
        for args in (["--kill", "gpg-agent"], ["--remove-socketdir"]):
            try:
                subprocess.run(["gpgconf", "--homedir", home.name] + args, capture_output=True)
            except OSError:
                pass
        home.cleanup()

    cls.addClassCleanup(cleanup)
    os.chmod(home.name, 0o700)
    gpg = ["gpg", "--homedir", home.name, "--batch", "--quiet", "--pinentry-mode", "loopback",
           "--passphrase", ""]
    return home.name, gpg


def gen_key(gpg, uid):
    """A new ed25519 signing key in `gpg`'s home: its fingerprint."""
    subprocess.run(gpg + ["--quick-gen-key", uid, "ed25519", "sign", "never"],
                   check=True, capture_output=True)
    listing = subprocess.run(gpg + ["--with-colons", "--list-keys", uid], check=True,
                             capture_output=True, text=True).stdout
    return next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))


class ChecksumLines(unittest.TestCase):
    """The exact `sha256sum` output format, nothing looser."""

    D = "ab" * 32

    def test_text_and_binary_modes_keep_the_name_verbatim(self):
        text = f"{self.D}  node.tar.gz\r\n{self.D.upper()} *bin.zip\n{self.D}  name with  spaces \n"
        self.assertEqual(
            catalog.checksum_lines("src", text),
            [(self.D, "node.tar.gz"), (self.D.upper(), "bin.zip"), (self.D, "name with  spaces ")],
        )

    def test_other_shapes_are_refused(self):
        for line in [
            f"{self.D} one-space.tar.gz",
            f"{self.D}\ttab.tar.gz",
            f" {self.D}  leading.tar.gz",
            f"{self.D}  ",
            f"{self.D[:-1]}  short.tar.gz",
            f"{self.D}0  long.tar.gz",
            "",
        ]:
            with self.subTest(line=line), self.assertRaises(catalog.Failure) as cm:
                catalog.checksum_lines("src", f"{self.D}  ok.tar.gz\n{line}\n")
            self.assertEqual(str(cm.exception), f"src: malformed checksum line {line!r}")


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
        home, cls.gpg = gpg_home(cls)
        cls.fingerprint = gen_key(cls.gpg, "Test Rust Key <rust@example.invalid>")
        cls.key = os.path.join(home, "test-key.asc")
        with open(cls.key, "wb") as f:
            f.write(subprocess.run(cls.gpg + ["--armor", "--export"], check=True,
                                   capture_output=True).stdout)

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

    def test_the_real_manifest_verifies_under_the_real_key_and_yields_the_shipped_rows(self):
        """The checked-in Rust key, and the real 1.96.1 channel manifest and
        its detached signature (tools/keys/, the manifest xz-compressed):
        gpgv accepts them, and the reader turns them into exactly the
        rust-1.96.1 release rust.catalog.toml ships."""
        catalog.RUST_KEY, catalog.RUST_FINGERPRINT = self.rust_saved[0], self.rust_saved[1]
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        keys = os.path.join(repo, "tools/keys")
        with lzma.open(os.path.join(keys, "channel-rust-1.96.1.toml.xz")) as f:
            manifest = f.read()
        with open(os.path.join(keys, "channel-rust-1.96.1.toml.asc"), "rb") as f:
            signature = f.read()
        catalog.rust_verify("1.96.1", manifest, signature, catalog.rust_keyring())
        url = f"{self.DIST}/channel-rust-1.96.1.toml"
        self.net.bodies[url] = manifest
        self.net.bodies[url + ".asc"] = signature
        rel, why = catalog.rust_release("1.96.1", catalog.rust_keyring())
        self.assertIsNone(why)
        catalog.REPO = repo
        shipped = next(r for r in catalog.read_document("cargo")["release"]
                       if r["key"] == "rust-1.96.1")
        self.assertEqual(rel["components"], shipped["components"])
        key = lambda a: (a["platform"], a["component"])
        self.assertEqual(sorted(rel["artifacts"], key=key), sorted(shipped["artifacts"], key=key))
        manifest_row = next(a for a in rel["artifacts"] if a["component"] == "channel-manifest")
        self.assertEqual(manifest_row["digest"], "sha256:" + sha256(manifest))

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


class Go(Base):
    """go.dev's release JSON, cross-checked with dl.google.com's .sha256."""

    ALL = "https://go.dev/dl/?mode=json&include=all"
    SUPPORTED = "https://go.dev/dl/?mode=json"

    def setUp(self):
        super().setUp()
        self.all = []
        self.supported = []

    @staticmethod
    def archive(version, platform):
        return f"go{version}.{'darwin-arm64' if platform == DARWIN else 'linux-amd64'}.tar.gz"

    def publish(self, version, platforms=(DARWIN, LINUX), stable=True, supported=True):
        files = [{"filename": f"go{version}.src.tar.gz", "os": "", "arch": "", "kind": "source",
                  "sha256": sha256(b"src")},
                 {"filename": f"go{version}.darwin-arm64.pkg", "os": "darwin", "arch": "arm64",
                  "kind": "installer", "sha256": sha256(b"pkg")}]
        for platform in platforms:
            name = self.archive(version, platform)
            os_, arch = ("darwin", "arm64") if platform == DARWIN else ("linux", "amd64")
            files.append({"filename": name, "os": os_, "arch": arch, "kind": "archive",
                          "sha256": sha256(name.encode())})
            self.net.bodies[f"https://dl.google.com/go/{name}.sha256"] = sha256(name.encode())
        entry = {"version": f"go{version}", "stable": stable, "files": files}
        self.all.insert(0, entry)
        if supported:
            self.supported.insert(0, entry)
        self.net.json(self.ALL, self.all)
        self.net.json(self.SUPPORTED, self.supported)

    def generate(self, existing):
        report = catalog.Report("go")
        return catalog.generate_go(existing, report), report

    def shipped(self, *versions):
        out, _ = self.generate([])
        return written("go", self.scratch.name, [out[f"go-{v}"] for v in versions])

    def expected(self, version):
        return {
            "key": f"go-{version}", "revision": None,
            "components": [{"name": "go", "version": version}],
            "artifacts": [
                {"platform": platform, "component": "go", "provider": "go.dev", "build": version,
                 "recipe": "go-toolchain/1", "url": f"https://go.dev/dl/{self.archive(version, platform)}",
                 "digest": "sha256:" + sha256(self.archive(version, platform).encode())}
                for platform in (DARWIN, LINUX)
            ],
        }

    def test_supported_stable_releases_enter_with_go_devs_digests(self):
        self.publish("1.25.9", supported=False)
        self.publish("1.26.3")
        self.publish("1.27rc1", stable=False)
        self.publish("1.26.4", stable=False)  # go.dev's own flag, even on a x.y.z version
        out, report = self.generate([])
        self.assertEqual(out, {"go-1.26.3": self.expected("1.26.3")})
        self.assertEqual((report.added, report.skipped), (["go-1.26.3"], []))
        self.assertEqual(out["go-1.26.3"]["artifacts"][1]["url"],
                         "https://go.dev/dl/go1.26.3.linux-amd64.tar.gz")

    def test_shipped_releases_are_kept_and_a_new_patch_enters_beside_them(self):
        self.publish("1.25.9")
        self.publish("1.26.3")
        existing = self.shipped("1.26.3", "1.25.9")
        # The 1.25 line leaves go.dev's supported list; its shipped row stays.
        self.supported[:] = [r for r in self.supported if r["version"] != "go1.25.9"]
        self.publish("1.26.4")
        out, report = self.generate(existing)
        self.assertEqual(out["go-1.26.3"], existing[0])
        self.assertEqual(out["go-1.25.9"], existing[1])
        self.assertEqual(out["go-1.26.4"], self.expected("1.26.4"))
        self.assertEqual(report.added, ["go-1.26.4"])
        again, report = self.generate(list(out.values()))
        self.assertEqual((again, report.added), (out, []))

    def test_a_release_without_both_archives_is_skipped_with_the_reason(self):
        self.publish("1.26.3", platforms=(LINUX,))
        out, report = self.generate([])
        self.assertEqual(out, {})
        self.assertEqual(report.skipped, [("go-1.26.3", f"go.dev publishes no archive for {DARWIN}")])

    def test_a_shipped_release_go_dev_withdrew_is_an_error(self):
        self.publish("1.26.3")
        existing = self.shipped("1.26.3")
        self.all[0]["files"] = [f for f in self.all[0]["files"] if f["os"] != "darwin"]
        self.net.json(self.ALL, self.all)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), "go: go-1.26.3: go.dev no longer lists both archives")
        self.all.clear()
        self.publish("1.26.4")
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), "go: go-1.26.3: go.dev no longer lists both archives")

    def test_a_shipped_row_whose_digest_changed_upstream_is_an_error(self):
        self.publish("1.26.3")
        existing = self.shipped("1.26.3")
        self.all[0]["files"][-1]["sha256"] = "e" * 64
        self.net.json(self.ALL, self.all)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        lines = str(cm.exception).splitlines()
        self.assertEqual(lines[0], "go: go-1.26.3: the checked-in row no longer matches upstream")
        self.assertIn("sha256:" + "e" * 64, lines[2])

    def test_a_shipped_row_differing_in_any_field_but_its_digest_is_an_error(self):
        self.publish("1.26.3")
        assert_every_field_is_checked(self, "go", self.shipped("1.26.3"), self.generate)

    def test_a_stable_release_whose_version_is_not_x_y_z_is_not_admitted(self):
        # go.dev flags it stable and its line is supported: only the
        # version-format guard keeps it out.
        self.publish("1.26.3")
        self.publish("1.26.4rc1", supported=False)
        self.publish("1.26.4.1", supported=False)
        out, report = self.generate([])
        self.assertEqual(out, {"go-1.26.3": self.expected("1.26.3")})
        self.assertEqual((report.added, report.skipped), (["go-1.26.3"], []))

    def test_a_dl_google_sha256_that_disagrees_is_an_error(self):
        self.publish("1.26.3")
        name = "go1.26.3.linux-amd64.tar.gz"
        self.net.bodies[f"https://dl.google.com/go/{name}.sha256"] = "0" * 64
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception),
                         f"go {name} .sha256: sha256:{'0' * 64} != sha256:{sha256(name.encode())}")

    def test_a_shipped_row_whose_dl_google_sha256_disagrees_is_an_error(self):
        self.publish("1.26.3")
        existing = self.shipped("1.26.3")
        name = "go1.26.3.darwin-arm64.tar.gz"
        self.net.bodies[f"https://dl.google.com/go/{name}.sha256"] = "0" * 64
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception),
                         f"go {name} .sha256: sha256:{'0' * 64} != sha256:{sha256(name.encode())}")

    def test_a_missing_dl_google_sha256_is_an_error(self):
        self.publish("1.26.3")
        url = "https://dl.google.com/go/go1.26.3.linux-amd64.tar.gz.sha256"
        del self.net.bodies[url]
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception), f"{url}: 404")

    def test_check_reports_a_new_release_as_drift_and_writes_nothing(self):
        self.publish("1.26.3")
        self.shipped("1.26.3")
        path = os.path.join(self.scratch.name, catalog.FILES["go"])
        text = read(path)
        self.assertEqual(run_quietly("go", check=True)[0], True)
        self.publish("1.26.4")
        ok, out = run_quietly("go", check=True)
        self.assertFalse(ok)
        self.assertIn("go: src/tailors/go/catalog.toml differs from what upstream publishes today "
                      "(1 new, 0 of them new revisions)", out)
        self.assertEqual(read(path), text)
        self.assertTrue(run_quietly("go", check=False)[0])
        now = read(path)
        self.assertIn('default = "go-1.26.3"', now)
        self.assertIn('key = "go-1.26.4"', now)
        self.assertIn(text[text.index('\n[[release]]'):], now)


class Node(Base):
    """nodejs.org's index and SHASUMS256.txt, whose detached signature is
    made for real by a throwaway key standing in for the Node release keys
    (served as the keyring), so gpgv runs on every path."""

    INDEX = "https://nodejs.org/dist/index.json"
    SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
    KEYRING = "https://raw.githubusercontent.com/nodejs/release-keys/main/gpg/pubring.kbx"

    @classmethod
    def setUpClass(cls):
        _, cls.gpg = gpg_home(cls)
        cls.release_key = gen_key(cls.gpg, "Test Node Releaser <node@example.invalid>")
        cls.stranger = gen_key(cls.gpg, "Someone Else <stranger@example.invalid>")
        cls.keyring = subprocess.run(cls.gpg + ["--export", cls.release_key], check=True,
                                     capture_output=True).stdout

    def setUp(self):
        super().setUp()
        # gpgv runs without --homedir: keep it out of the user's ~/.gnupg.
        self.home = os.environ.get("GNUPGHOME")
        os.environ["GNUPGHOME"] = os.path.join(self.scratch.name, "gnupg")
        os.makedirs(os.environ["GNUPGHOME"], mode=0o700)
        catalog.TODAY = datetime.date(2026, 6, 1)
        self.net.bodies[self.KEYRING] = self.keyring
        self.releasers_saved = catalog.NODE_RELEASERS
        catalog.NODE_RELEASERS = os.path.join(self.scratch.name, "node-releasers.txt")
        with open(catalog.NODE_RELEASERS, "w") as f:
            f.write(f"# the test releaser\n{self.release_key}  # Test Node Releaser\n")
        self.net.json(self.SCHEDULE, {
            "v20": {"start": "2023-04-18", "end": "2026-04-30"},
            "v22": {"start": "2024-04-24", "end": "2027-04-30"},
            "v24": {"start": "2025-05-06", "end": "2028-04-30"},
            "v26": {"start": "2026-10-20", "end": "2029-04-30"},
        })
        self.index = []

    def tearDown(self):
        catalog.NODE_RELEASERS = self.releasers_saved
        if self.home is None:
            os.environ.pop("GNUPGHOME", None)
        else:
            os.environ["GNUPGHOME"] = self.home
        super().tearDown()

    def sign(self, body, key=None):
        path = os.path.join(self.scratch.name, "to-sign")
        with open(path, "wb") as f:
            f.write(body)
        return subprocess.run(self.gpg + ["--local-user", key or self.release_key, "--detach-sign",
                                          "--output", "-", path], check=True, capture_output=True).stdout

    @staticmethod
    def tarball(version, platform):
        return f"node-v{version}-{'darwin-arm64' if platform == DARWIN else 'linux-x64'}.tar.gz"

    def shasums(self, version, platforms=(DARWIN, LINUX), digest=None):
        lines = [f"{sha256(b'src')}  node-v{version}.tar.gz",
                 f"{sha256(b'exe')}  win-x64/node.exe"]
        for platform in platforms:
            name = self.tarball(version, platform)
            lines.append(f"{digest or sha256(name.encode())}  {name}")
        return ("\n".join(lines) + "\n").encode()

    def publish(self, version, platforms=(DARWIN, LINUX), listed=True):
        base = f"https://nodejs.org/dist/v{version}/"
        body = self.shasums(version, platforms)
        self.net.bodies[base + "SHASUMS256.txt"] = body
        self.net.bodies[base + "SHASUMS256.txt.sig"] = self.sign(body)
        if listed:
            self.index.insert(0, {"version": f"v{version}"})
            self.net.json(self.INDEX, self.index)

    def generate(self, existing):
        report = catalog.Report("node")
        return catalog.generate_node(existing, report), report

    def shipped(self, *versions):
        out, _ = self.generate([])
        return written("node", self.scratch.name, [out[f"node-{v}"] for v in versions])

    def expected(self, version):
        return {
            "key": f"node-{version}", "revision": None,
            "components": [{"name": "node", "version": version}],
            "artifacts": [
                {"platform": platform, "component": "node", "provider": "nodejs.org", "build": version,
                 "recipe": "nodejs/legacy",
                 "url": f"https://nodejs.org/dist/v{version}/{self.tarball(version, platform)}",
                 "digest": "sha256:" + sha256(self.tarball(version, platform).encode())}
                for platform in (DARWIN, LINUX)
            ],
        }

    def test_releases_of_lines_the_schedule_supports_enter_with_signed_digests(self):
        self.publish("20.19.5")   # line ended
        self.publish("22.20.0")
        self.publish("24.9.0")
        self.publish("26.0.0")    # line not started
        out, report = self.generate([])
        self.assertEqual(out, {"node-24.9.0": self.expected("24.9.0"),
                               "node-22.20.0": self.expected("22.20.0")})
        self.assertEqual((report.added, report.skipped), (["node-24.9.0", "node-22.20.0"], []))
        self.assertEqual(out["node-24.9.0"]["artifacts"][1]["url"],
                         "https://nodejs.org/dist/v24.9.0/node-v24.9.0-linux-x64.tar.gz")

    def test_shipped_releases_are_kept_even_after_their_line_ends(self):
        self.publish("24.9.0")
        existing = self.shipped("24.9.0")
        catalog.TODAY = datetime.date(2028, 6, 1)
        self.publish("24.10.0")
        out, report = self.generate(existing)
        self.assertEqual(list(out.values()), existing)
        self.assertEqual(report.added, [])

    def test_a_new_release_enters_beside_the_shipped_one(self):
        self.publish("24.9.0")
        existing = self.shipped("24.9.0")
        self.publish("24.10.0")
        out, report = self.generate(existing)
        self.assertEqual(out["node-24.9.0"], existing[0])
        self.assertEqual(out["node-24.10.0"], self.expected("24.10.0"))
        self.assertEqual(report.added, ["node-24.10.0"])

    def test_shasums_the_signature_does_not_cover_are_refused(self):
        self.publish("24.9.0")
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"] = self.sign(b"other bytes\n")
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertTrue(str(cm.exception).startswith(
            "node 24.9.0: SHASUMS256.txt signature does not verify:\n"), str(cm.exception))

    def test_shasums_signed_by_a_key_outside_the_keyring_are_refused(self):
        self.publish("24.9.0")
        body = self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt"]
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"] = self.sign(body, self.stranger)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertTrue(str(cm.exception).startswith(
            "node 24.9.0: SHASUMS256.txt signature does not verify:\n"), str(cm.exception))

    def test_a_stranger_who_replaces_both_keyring_and_shasums_is_refused(self):
        self.publish("24.9.0")
        self.net.bodies[self.KEYRING] = subprocess.run(
            self.gpg + ["--export", self.stranger], check=True, capture_output=True).stdout
        body = self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt"]
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"] = self.sign(body, self.stranger)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception),
                         f"node 24.9.0: SHASUMS256.txt is signed by {self.stranger}, which is not a "
                         f"releaser pinned in {os.path.relpath(catalog.NODE_RELEASERS, catalog.REPO)}")

    def test_the_pinned_releasers_file_must_name_fingerprints(self):
        for body in ("# nothing pinned\n", "abc  # not a fingerprint\n"):
            with self.subTest(body=body):
                with open(catalog.NODE_RELEASERS, "w") as f:
                    f.write(body)
                with self.assertRaises(catalog.Failure) as cm:
                    catalog.node_fingerprints()
                self.assertIn("malformed or no fingerprints", str(cm.exception))

    def test_the_checked_in_releasers_are_the_node_readme_keys(self):
        catalog.NODE_RELEASERS = self.releasers_saved
        pins = catalog.node_fingerprints()
        self.assertEqual(len(pins), 29)
        # Two current releasers, as the nodejs/node README lists them.
        self.assertLessEqual({"C0D6248439F1D5604AAFFB4021D900FFDB233756",
                              "DD8F2338BAE7501E3DD5AC78C273792F7D83545D"}, pins)

    def test_a_shipped_release_whose_shasums_no_longer_verify_is_an_error(self):
        self.publish("24.9.0")
        existing = self.shipped("24.9.0")
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"] = self.sign(b"x", self.stranger)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertTrue(str(cm.exception).startswith(
            "node 24.9.0: SHASUMS256.txt signature does not verify:\n"), str(cm.exception))

    def test_a_missing_signature_is_an_error(self):
        self.publish("24.9.0")
        url = "https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"
        del self.net.bodies[url]
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception), f"{url}: 404")

    def test_a_shipped_row_whose_digest_changed_upstream_is_an_error(self):
        self.publish("24.9.0")
        existing = self.shipped("24.9.0")
        # Re-published and properly signed: still not the shipped bytes.
        body = self.shasums("24.9.0", digest="e" * 64)
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt"] = body
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"] = self.sign(body)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        lines = str(cm.exception).splitlines()
        self.assertEqual(lines[0], "node: node-24.9.0: the checked-in row no longer matches upstream")
        self.assertIn("sha256:" + "e" * 64, lines[2])

    def test_a_shipped_row_differing_in_any_field_but_its_digest_is_an_error(self):
        self.publish("24.9.0")
        assert_every_field_is_checked(self, "node", self.shipped("24.9.0"), self.generate)

    def test_a_malformed_shasums_line_is_an_error(self):
        self.publish("24.9.0")
        body = self.shasums("24.9.0") + b"not-a-digest  node-v24.9.0-extra.tar.gz\n"
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt"] = body
        self.net.bodies["https://nodejs.org/dist/v24.9.0/SHASUMS256.txt.sig"] = self.sign(body)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception), "node 24.9.0: SHASUMS256.txt: malformed checksum line "
                                            "'not-a-digest  node-v24.9.0-extra.tar.gz'")

    def test_a_shipped_row_upstream_withdrew_is_an_error(self):
        self.publish("24.9.0")
        existing = self.shipped("24.9.0")
        self.publish("24.9.0", platforms=(LINUX,), listed=False)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        lines = str(cm.exception).splitlines()
        self.assertEqual(lines[0], "node: node-24.9.0: the checked-in row no longer matches upstream")
        self.assertEqual(lines[2], "  upstream:   None")

    def test_a_release_missing_a_tarball_is_skipped_with_the_reason(self):
        self.publish("24.9.0", platforms=(LINUX,))
        out, report = self.generate([])
        self.assertEqual(out, {})
        self.assertEqual(report.skipped, [("node-24.9.0", f"nodejs.org publishes no {DARWIN} tarball")])

    def test_check_reports_a_new_release_as_drift_and_writes_nothing(self):
        self.publish("24.9.0")
        self.shipped("24.9.0")
        path = os.path.join(self.scratch.name, catalog.FILES["node"])
        text = read(path)
        self.assertTrue(run_quietly("node", check=True)[0])
        self.publish("24.10.0")
        ok, out = run_quietly("node", check=True)
        self.assertFalse(ok)
        self.assertIn("node: src/tailors/node/catalog.toml differs from what upstream publishes today "
                      "(1 new, 0 of them new revisions)", out)
        self.assertEqual(read(path), text)


class Python(Base):
    """python-build-standalone's per-release SHA256SUMS, cross-checked with
    GitHub's asset digests; uv rides along from the default release."""

    UV = "0.12.7"
    UV_RELEASE = f"https://api.github.com/repos/astral-sh/uv/releases/tags/{UV}"

    def setUp(self):
        super().setUp()
        self.net.json("https://peps.python.org/api/release-cycle.json", {
            "3.13": {"status": "bugfix"}, "3.12": {"status": "security"},
            "3.9": {"status": "end-of-life"},
        })
        self.sums = {}      # tag -> {asset name: digest}
        self.tags = ["20260101", "20210101"]  # no SHA256SUMS: skipped, named
        for platform in (DARWIN, LINUX):
            url = f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{platform}.tar.gz"
            self.net.bodies[url + ".sha256"] = f"{sha256(url.encode())}  uv-{platform}.tar.gz\n"
        self.net.json(self.UV_RELEASE, {"assets": [
            {"name": f"uv-{platform}.tar.gz", "digest": "sha256:" + sha256(
                f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{platform}.tar.gz".encode())}
            for platform in (DARWIN, LINUX)] + [{"name": "uv-installer.sh", "digest": None}]})
        self.sync()

    def sync(self):
        self.net.json(f"https://api.github.com/repos/{catalog.PBS}/tags?per_page=100&page=1",
                      [{"name": t} for t in self.tags + ["latest"]])
        for tag, sums in self.sums.items():
            # Alternate sha256sum's text (`  name`) and binary (` *name`) modes.
            lines = [f"{digest} {'*' if i % 2 else ' '}{name}" for i, (name, digest) in enumerate(sums.items())]
            self.net.bodies[catalog.pbs_url(tag, "SHA256SUMS")] = "\n".join(lines) + "\n"
            self.net.json(f"https://api.github.com/repos/{catalog.PBS}/releases/tags/{tag}",
                          {"assets": [{"name": n, "digest": f"sha256:{d}"} for n, d in sums.items()]
                           + [{"name": "SHA256SUMS", "digest": None}]})

    def publish(self, tag, versions, platforms=(DARWIN, LINUX)):
        if tag not in self.tags:
            self.tags.insert(0, tag)
        sums = self.sums.setdefault(tag, {})
        for version in versions:
            for platform in platforms:
                name = catalog.pbs_asset(version, tag, platform)
                sums[name] = sha256(name.encode())
            sums[f"cpython-{version}+{tag}-{LINUX}-debug-full.tar.zst"] = sha256(b"debug")
        self.sync()

    def github_digest(self, tag, name, digest):
        """PBS `tag`'s GitHub release, with `name`'s recorded digest set to
        `digest` (None: GitHub recorded none), or the asset gone (`...`)."""
        url = f"https://api.github.com/repos/{catalog.PBS}/releases/tags/{tag}"
        release = json.loads(self.net.bodies[url])
        release["assets"] = [dict(a, digest=digest) if a["name"] == name else a
                             for a in release["assets"] if not (a["name"] == name and digest is ...)]
        self.net.json(url, release)

    def uv_rows(self):
        return [{"platform": platform, "component": "uv", "provider": "uv", "build": self.UV,
                 "recipe": "uv/legacy",
                 "url": f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{platform}.tar.gz",
                 "digest": "sha256:" + sha256(
                     f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{platform}.tar.gz".encode())}
                for platform in (DARWIN, LINUX)]

    def expected(self, version, tag):
        return {
            "key": f"cpython-{version}", "revision": None,
            "components": [{"name": "cpython", "version": version}, {"name": "uv", "version": self.UV}],
            "artifacts": [
                {"platform": platform, "component": "cpython", "provider": "python-build-standalone",
                 "build": tag, "recipe": "cpython/legacy",
                 "url": catalog.pbs_url(tag, catalog.pbs_asset(version, tag, platform)),
                 "digest": "sha256:" + sha256(catalog.pbs_asset(version, tag, platform).encode())}
                for platform in (DARWIN, LINUX)
            ] + self.uv_rows(),
        }

    def shipped(self):
        """cpython-3.12.1 from PBS 20260801, the default, as checked in."""
        self.publish("20260801", ["3.12.1"])
        return written("python", self.scratch.name, [self.expected("3.12.1", "20260801")])

    def generate(self, existing, default="cpython-3.12.1"):
        report = catalog.Report("python")
        return catalog.generate_python(existing, report, default), report

    def test_new_versions_take_the_newest_pbs_release_and_shipped_rows_keep_theirs(self):
        existing = self.shipped()
        self.publish("20260801", ["3.13.0"])
        self.publish("20260910", ["3.12.1", "3.12.2", "3.13.0", "3.13.1", "3.9.25"])
        out, report = self.generate(existing)
        self.assertEqual(out, {
            "cpython-3.12.1": existing[0],
            "cpython-3.12.2": self.expected("3.12.2", "20260910"),
            "cpython-3.13.0": self.expected("3.13.0", "20260910"),
            "cpython-3.13.1": self.expected("3.13.1", "20260910"),
        })
        self.assertEqual(out["cpython-3.12.1"]["artifacts"][0]["build"], "20260801")
        self.assertEqual(
            out["cpython-3.13.1"]["artifacts"][1]["url"],
            "https://github.com/astral-sh/python-build-standalone/releases/download/20260910/"
            "cpython-3.13.1%2B20260910-x86_64-unknown-linux-gnu-install_only.tar.gz")
        self.assertEqual(report.added, ["cpython-3.12.2", "cpython-3.13.0", "cpython-3.13.1"])
        self.assertEqual(report.skipped, [
            ("PBS releases 20260101, 1 releases before 20220227",
             "no SHA256SUMS published, so nothing to verify a row against"),
            ("cpython-3.12.0", "no PBS release with a SHA256SUMS publishes it for both platforms"),
        ])
        again, report = self.generate(list(out.values()))
        self.assertEqual((again, report.added), (out, []))

    def test_a_version_no_pbs_release_builds_for_both_platforms_is_skipped(self):
        existing = self.shipped()
        self.publish("20260910", ["3.13.0"], platforms=(LINUX,))
        self.publish("20260801", ["3.13.0"], platforms=(DARWIN,))
        out, report = self.generate(existing)
        self.assertEqual(list(out), ["cpython-3.12.1"])
        self.assertIn(("cpython-3.13.0", "no PBS release publishes install_only builds for both platforms"),
                      report.skipped)
        self.assertEqual([what for what, _ in report.skipped].count("cpython-3.13.0"), 1)

    def test_the_default_must_be_checked_in(self):
        existing = self.shipped()
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing, default="cpython-3.13.0")
        self.assertEqual(str(cm.exception),
                         "python: default cpython-3.13.0 is not checked in; the uv pin is read from it")

    def test_a_shipped_row_its_sha256sums_no_longer_lists_is_an_error(self):
        existing = self.shipped()
        del self.sums["20260801"][catalog.pbs_asset("3.12.1", "20260801", DARWIN)]
        self.sync()
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        message = "python: cpython-3.12.1: PBS 20260801 SHA256SUMS no longer lists both builds"
        self.assertEqual(str(cm.exception), message)
        # Nor when the whole SHA256SUMS is gone.
        del self.net.bodies[catalog.pbs_url("20260801", "SHA256SUMS")]
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), message)

    def test_a_shipped_row_whose_digest_changed_upstream_is_an_error(self):
        existing = self.shipped()
        self.sums["20260801"][catalog.pbs_asset("3.12.1", "20260801", LINUX)] = "e" * 64
        self.sync()
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        lines = str(cm.exception).splitlines()
        self.assertEqual(lines[0], "python: cpython-3.12.1: the checked-in row no longer matches upstream")
        self.assertIn("sha256:" + "e" * 64, lines[2])

    def test_a_github_digest_that_disagrees_is_an_error(self):
        existing = self.shipped()
        self.publish("20260910", ["3.13.0"])
        name = catalog.pbs_asset("3.13.0", "20260910", LINUX)
        self.github_digest("20260910", name, "sha256:" + "0" * 64)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception),
                         f"python {name} GitHub digest: sha256:{'0' * 64} != sha256:{sha256(name.encode())}")

    def test_a_shipped_rows_github_digest_that_disagrees_is_an_error(self):
        existing = self.shipped()
        name = catalog.pbs_asset("3.12.1", "20260801", DARWIN)
        self.github_digest("20260801", name, "sha256:" + "0" * 64)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception),
                         f"python {name} GitHub digest: sha256:{'0' * 64} != sha256:{sha256(name.encode())}")

    def test_a_uv_sha256_that_disagrees_is_an_error(self):
        existing = self.shipped()
        for platform in (DARWIN, LINUX):
            with self.subTest(platform=platform):
                url = f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{platform}.tar.gz"
                good = self.net.bodies[url + ".sha256"]
                self.net.bodies[url + ".sha256"] = "0" * 64 + f"  uv-{platform}.tar.gz\n"
                try:
                    with self.assertRaises(catalog.Failure) as cm:
                        self.generate(existing)
                finally:
                    self.net.bodies[url + ".sha256"] = good
                self.assertEqual(str(cm.exception), f"uv uv-{platform}.tar.gz .sha256: "
                                                    f"sha256:{'0' * 64} != sha256:{sha256(url.encode())}")

    def uv_asset(self, platform, **change):
        """The uv release's asset for `platform` changed by `change`, or
        removed when `change` is empty."""
        release = json.loads(self.net.bodies[self.UV_RELEASE])
        name = f"uv-{platform}.tar.gz"
        release["assets"] = [dict(a, **change) if a["name"] == name else a
                             for a in release["assets"] if change or a["name"] != name]
        self.net.json(self.UV_RELEASE, release)

    def test_a_uv_github_digest_that_disagrees_is_an_error(self):
        existing = self.shipped()
        url = f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{LINUX}.tar.gz"
        self.uv_asset(LINUX, digest="sha256:" + "0" * 64)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), f"uv uv-{LINUX}.tar.gz GitHub digest: "
                                            f"sha256:{'0' * 64} != sha256:{sha256(url.encode())}")

    def test_a_uv_asset_github_does_not_list_is_an_error_and_one_without_a_digest_is_not(self):
        existing = self.shipped()
        self.uv_asset(DARWIN, digest=None)
        out, _ = self.generate(existing)
        self.assertEqual(list(out), ["cpython-3.12.1"])
        self.uv_asset(DARWIN)
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), f"uv {self.UV} release has no asset uv-{DARWIN}.tar.gz")

    def test_a_uv_sha256_file_that_is_not_one_line_naming_the_asset_is_an_error(self):
        existing = self.shipped()
        url = f"https://github.com/astral-sh/uv/releases/download/{self.UV}/uv-{LINUX}.tar.gz"
        good = self.net.bodies[url + ".sha256"]
        digest = sha256(url.encode())
        source = f"uv {self.UV} uv-{LINUX}.tar.gz.sha256"
        for body, message in (
            ("", f"{source}: expected exactly one line naming uv-{LINUX}.tar.gz, got []"),
            (f"{digest}  uv-other.tar.gz\n",
             f"{source}: expected exactly one line naming uv-{LINUX}.tar.gz, "
             f"got [('{digest}', 'uv-other.tar.gz')]"),
            (good + good, f"{source}: expected exactly one line naming uv-{LINUX}.tar.gz, "
                          f"got [('{digest}', 'uv-{LINUX}.tar.gz'), ('{digest}', 'uv-{LINUX}.tar.gz')]"),
            (digest + "\n", f"{source}: malformed checksum line {digest!r}"),
        ):
            with self.subTest(body=body):
                self.net.bodies[url + ".sha256"] = body
                with self.assertRaises(catalog.Failure) as cm:
                    self.generate(existing)
                self.assertEqual(str(cm.exception), message)
        # Binary mode and an upper-case digest are the same file.
        self.net.bodies[url + ".sha256"] = f"{digest.upper()} *uv-{LINUX}.tar.gz\n"
        out, _ = self.generate(existing)
        self.assertEqual(list(out), ["cpython-3.12.1"])

    def test_a_shipped_row_differing_in_any_field_but_its_digest_is_an_error(self):
        assert_every_field_is_checked(self, "python", self.shipped(), self.generate)

    def test_a_cpython_asset_missing_from_its_github_release_is_an_error(self):
        existing = self.shipped()
        self.publish("20260910", ["3.13.0"])
        # A shipped row's release, and a new row's.
        for tag, version, platform in (("20260801", "3.12.1", DARWIN), ("20260910", "3.13.0", LINUX)):
            with self.subTest(tag=tag, platform=platform):
                self.sync()
                name = catalog.pbs_asset(version, tag, platform)
                self.github_digest(tag, name, ...)
                with self.assertRaises(catalog.Failure) as cm:
                    self.generate(existing)
                self.assertEqual(str(cm.exception), f"python: PBS {tag} release has no asset {name}")

    def test_a_cpython_asset_github_recorded_no_digest_for_rests_on_sha256sums(self):
        existing = self.shipped()
        self.publish("20260910", ["3.13.0"])
        self.github_digest("20260801", catalog.pbs_asset("3.12.1", "20260801", LINUX), None)
        self.github_digest("20260910", catalog.pbs_asset("3.13.0", "20260910", DARWIN), None)
        out, report = self.generate(existing)
        self.assertEqual(out, {"cpython-3.12.1": existing[0],
                               "cpython-3.13.0": self.expected("3.13.0", "20260910")})
        self.assertEqual(report.added, ["cpython-3.13.0"])
        # The digest the row carries is still the one SHA256SUMS lists.
        self.sums["20260910"][catalog.pbs_asset("3.13.0", "20260910", DARWIN)] = "e" * 64
        self.sync()
        self.github_digest("20260910", catalog.pbs_asset("3.13.0", "20260910", DARWIN), None)
        out, _ = self.generate(existing)
        self.assertEqual(out["cpython-3.13.0"]["artifacts"][0]["digest"], "sha256:" + "e" * 64)

    def test_a_malformed_sha256sums_line_is_an_error(self):
        existing = self.shipped()
        url = catalog.pbs_url("20260801", "SHA256SUMS")
        self.net.bodies[url] += "0123  cpython-3.12.1+20260801-extra.tar.gz extra\n"
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), "python: PBS 20260801 SHA256SUMS: malformed checksum line "
                                            "'0123  cpython-3.12.1+20260801-extra.tar.gz extra'")

    def test_check_reports_a_new_version_as_drift_and_writes_nothing(self):
        self.shipped()
        path = os.path.join(self.scratch.name, catalog.FILES["python"])
        text = read(path)
        self.assertTrue(run_quietly("python", check=True)[0])
        self.publish("20260910", ["3.12.2"])
        ok, out = run_quietly("python", check=True)
        self.assertFalse(ok)
        self.assertIn("python: src/kernel/provider/cpython.catalog.toml differs from what upstream "
                      "publishes today (1 new, 0 of them new revisions)", out)
        self.assertEqual(read(path), text)


class Dotnet(Base):
    """Microsoft's release metadata (sha512), cross-checked with the
    .sha512 file beside each archive."""

    META = "https://builds.dotnet.microsoft.com/dotnet/release-metadata"

    def setUp(self):
        super().setUp()
        self.channels = {"10.0": "active", "9.0": "maintenance", "8.0": "eol", "11.0": "preview"}
        self.releases = {channel: [] for channel in self.channels}
        self.net.json(f"{self.META}/releases-index.json", {"releases-index": [
            {"channel-version": c, "support-phase": phase, "releases.json": f"{self.META}/{c}/releases.json"}
            for c, phase in self.channels.items()
        ]})
        self.sync()

    def sync(self):
        for channel, releases in self.releases.items():
            self.net.json(f"{self.META}/{channel}/releases.json", {"releases": releases})

    @staticmethod
    def url(version, platform):
        slug = "osx-arm64" if platform == DARWIN else "linux-x64"
        return f"https://builds.dotnet.microsoft.com/dotnet/Sdk/{version}/dotnet-sdk-{version}-{slug}.tar.gz"

    def sdk(self, version, platforms=(DARWIN, LINUX), sidecar=True):
        files = [{"name": "dotnet-sdk-win-x64.zip", "url": "https://example.invalid/sdk.zip", "hash": "AB"}]
        for platform in platforms:
            url = self.url(version, platform)
            name = "dotnet-sdk-osx-arm64.tar.gz" if platform == DARWIN else "dotnet-sdk-linux-x64.tar.gz"
            files.append({"name": name, "url": url, "hash": sha512(url.encode()).upper()})
            if sidecar:
                self.net.bodies[url + ".sha512"] = sha512(url.encode()) + "\n"
        return {"version": version, "files": files}

    def publish(self, channel, *versions, old_style=False, **kw):
        sdks = [self.sdk(v, **kw) for v in versions]
        entry = {"sdk": sdks[0]} if old_style else {"sdk": sdks[0], "sdks": sdks}
        self.releases[channel].insert(0, entry)
        self.sync()

    def generate(self, existing):
        report = catalog.Report("dotnet")
        return catalog.generate_dotnet(existing, report), report

    def expected(self, version):
        return {
            "key": f"dotnet-sdk-{version}", "revision": None,
            "components": [{"name": "dotnet-sdk", "version": version}],
            "artifacts": [
                {"platform": platform, "component": "dotnet-sdk", "provider": "builds.dotnet.microsoft.com",
                 "build": version, "recipe": "dotnet-sdk/1", "url": self.url(version, platform),
                 "digest": "sha512:" + sha512(self.url(version, platform).encode())}
                for platform in (DARWIN, LINUX)
            ],
        }

    def shipped(self, *versions):
        return written("dotnet", self.scratch.name, [self.expected(v) for v in versions])

    def test_supported_channels_enter_and_previews_and_eol_channels_do_not(self):
        self.publish("10.0", "10.0.100", "10.0.100-rc.2.25502.107")
        self.publish("9.0", "9.0.300", old_style=True)
        self.publish("8.0", "8.0.400")
        self.publish("11.0", "11.0.100-preview.1.26101.1")
        out, report = self.generate([])
        self.assertEqual(out, {"dotnet-sdk-9.0.300": self.expected("9.0.300"),
                               "dotnet-sdk-10.0.100": self.expected("10.0.100")})
        self.assertEqual((report.added, report.skipped, report.notes),
                         (["dotnet-sdk-9.0.300", "dotnet-sdk-10.0.100"], [], []))
        self.assertNotIn(f"{self.META}/8.0/releases.json", self.net.requests)

    def test_shipped_rows_are_kept_even_in_an_eol_channel(self):
        self.publish("8.0", "8.0.400")
        self.publish("10.0", "10.0.100")
        existing = self.shipped("8.0.400")
        # Read now that a shipped row may live there, but nothing new enters.
        self.publish("8.0", "8.0.401")
        out, report = self.generate(existing)
        self.assertEqual(out, {"dotnet-sdk-8.0.400": existing[0],
                               "dotnet-sdk-10.0.100": self.expected("10.0.100")})
        self.assertEqual(report.added, ["dotnet-sdk-10.0.100"])

    def test_a_shipped_release_no_longer_in_the_metadata_is_an_error(self):
        self.publish("10.0", "10.0.100")
        existing = self.shipped("9.0.300")
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception), "dotnet: dotnet-sdk-9.0.300: no longer in the release metadata")

    def test_a_shipped_row_whose_hash_changed_upstream_is_an_error(self):
        self.publish("10.0", "10.0.100")
        existing = self.shipped("10.0.100")
        self.releases["10.0"][0]["sdks"][0]["files"][-1]["hash"] = "E" * 128
        self.sync()
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        lines = str(cm.exception).splitlines()
        self.assertEqual(lines[0], "dotnet: dotnet-sdk-10.0.100: the checked-in row no longer matches upstream")
        self.assertIn("sha512:" + "e" * 128, lines[2])

    def test_a_shipped_row_differing_in_any_field_but_its_digest_is_an_error(self):
        self.publish("10.0", "10.0.100")
        assert_every_field_is_checked(self, "dotnet", self.shipped("10.0.100"), self.generate)

    def test_a_shipped_row_upstream_withdrew_is_an_error(self):
        self.publish("10.0", "10.0.100", platforms=(LINUX,))
        existing = self.shipped("10.0.100")
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        lines = str(cm.exception).splitlines()
        self.assertEqual(lines[0], "dotnet: dotnet-sdk-10.0.100: the checked-in row no longer matches upstream")
        self.assertEqual(lines[2], "  upstream:   None")

    def test_an_archive_off_the_shipped_endpoint_is_refused(self):
        self.publish("10.0", "10.0.100")
        self.releases["10.0"][0]["sdks"][0]["files"][1]["url"] = "https://evil.example/dotnet-sdk.tar.gz"
        self.sync()
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception),
                         "dotnet 10.0.100: https://evil.example/dotnet-sdk.tar.gz is not on the shipped endpoint")

    def test_a_sha512_beside_the_archive_that_disagrees_is_an_error(self):
        self.publish("10.0", "10.0.100")
        url = self.url("10.0.100", LINUX)
        self.net.bodies[url + ".sha512"] = "0" * 128
        with self.assertRaises(catalog.Failure) as cm:
            self.generate([])
        self.assertEqual(str(cm.exception),
                         f"dotnet {url} .sha512: sha512:{'0' * 128} != sha512:{sha512(url.encode())}")

    def test_a_shipped_rows_sha512_that_disagrees_is_an_error(self):
        self.publish("10.0", "10.0.100")
        existing = self.shipped("10.0.100")
        url = self.url("10.0.100", DARWIN)
        self.net.bodies[url + ".sha512"] = "0" * 128
        with self.assertRaises(catalog.Failure) as cm:
            self.generate(existing)
        self.assertEqual(str(cm.exception),
                         f"dotnet {url} .sha512: sha512:{'0' * 128} != sha512:{sha512(url.encode())}")

    def test_rows_without_a_sha512_beside_them_are_noted(self):
        self.publish("10.0", "10.0.100")
        self.publish("9.0", "9.0.300", sidecar=False)
        out, report = self.generate([])
        self.assertEqual(sorted(out), ["dotnet-sdk-10.0.100", "dotnet-sdk-9.0.300"])
        self.assertEqual(report.notes, ["2 of 4 rows have no .sha512 beside the archive; "
                                        "the release metadata is their only published checksum"])

    def test_a_release_missing_an_archive_is_skipped_with_the_reason(self):
        self.publish("10.0", "10.0.101", platforms=(LINUX,))
        out, report = self.generate([])
        self.assertEqual(out, {})
        self.assertEqual(report.skipped, [("dotnet-sdk-10.0.101", f"no {DARWIN} archive in the release metadata")])

    def test_check_reports_a_new_release_as_drift_and_writes_nothing(self):
        self.publish("10.0", "10.0.100")
        self.shipped("10.0.100")
        path = os.path.join(self.scratch.name, catalog.FILES["dotnet"])
        text = read(path)
        self.assertTrue(run_quietly("dotnet", check=True)[0])
        self.publish("10.0", "10.0.101")
        ok, out = run_quietly("dotnet", check=True)
        self.assertFalse(ok)
        self.assertIn("dotnet: src/tailors/dotnet/catalog.toml differs from what upstream publishes today "
                      "(1 new, 0 of them new revisions)", out)
        self.assertEqual(read(path), text)


if __name__ == "__main__":
    unittest.main()

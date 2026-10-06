#!/usr/bin/env python3
"""Generate and verify tog's shipped toolchain catalogs.

Each ecosystem's shipped releases live in a checked-in TOML file that the
binary embeds (`src/kernel/toolchain/document.rs` reads it). This script is
the only thing that writes those files. For each ecosystem it:

1. reads the file that is checked in now (its releases and its `default`);
2. fetches the publisher's release list and checksum source, and verifies
   every row, existing and new, against it (and against a second upstream
   source where the publisher has one: a detached signature, a per-file
   checksum, GitHub's own asset digest, or the downloaded bytes);
3. keeps every existing release byte-for-byte (rows are append-only: a
   row that no longer verifies is a hard error, never a silent rewrite);
4. appends the releases of the currently supported upstream lines that
   publish both supported platforms (aarch64-apple-darwin and
   x86_64-unknown-linux-gnu), and reports every release it skipped and why;
5. writes the file in the canonical spelling `Document::render` produces.

The default never moves unless `--set-default <release key>` says so.

A release upstream re-publishes (a Homebrew portable-ruby rebuild, a newer
Hex or rebar3 for a BEAM pair) never replaces the shipped row: it is a new
release with its own key and a higher `revision`, and `--check` reports it.

Usage, from the repository root:

    python3 tools/catalog.py                 # every ecosystem
    python3 tools/catalog.py go node         # just these
    python3 tools/catalog.py --check go      # verify, write nothing, exit 1 on drift
    python3 tools/catalog.py --set-default go-1.27.1 go

Needs network access, `gpgv` (Node's SHASUMS256.txt and Rust's channel
manifest signatures) and `tar`.
GitHub API calls use $GH_TOKEN / $GITHUB_TOKEN, or `gh auth token`, when
available. Release listings and checksum files are fetched fresh on every
run; only archives, which a versioned URL names immutably, are cached under
$TMPDIR/tog-catalog-cache (a cached archive is re-hashed on every use).
Standard library only. Offline tests: `python3 tools/test_catalog.py`.
"""
import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DARWIN = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-gnu"
PLATFORMS = (DARWIN, LINUX)
TODAY = datetime.date.today()

FILES = {
    "python": "src/kernel/provider/cpython.catalog.toml",
    "node": "src/tailors/node/catalog.toml",
    "go": "src/tailors/go/catalog.toml",
    "ruby": "src/tailors/ruby/catalog.toml",
    "elixir": "src/tailors/elixir/catalog.toml",
    "dotnet": "src/tailors/dotnet/catalog.toml",
    "cargo": "src/kernel/provider/rust.catalog.toml",
}
PRIMARY = {
    "python": ["cpython"],
    "node": ["node"],
    "go": ["go"],
    "ruby": ["ruby"],
    "elixir": ["otp", "elixir"],
    "dotnet": ["dotnet-sdk"],
    "cargo": ["rustc"],
}


class Failure(Exception):
    """A row that does not verify, or an upstream that cannot be read."""


# --------------------------------------------------------------------------
# HTTP. Listings, indexes and checksum files change upstream (a new release,
# a re-published asset), so they are always fetched fresh: a cached answer
# would hide a release or let `--check` pass on yesterday's data. Only an
# archive's bytes are cached, because its URL names one immutable upload,
# and every use hashes the cached bytes again. Nothing is cached for a 404.

CACHE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "tog-catalog-cache")
_token = None


def github_token():
    global _token
    if _token is None:
        _token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
        if not _token:
            try:
                _token = subprocess.run(
                    ["gh", "auth", "token"], capture_output=True, text=True, check=True
                ).stdout.strip()
            except (OSError, subprocess.CalledProcessError):
                _token = ""
    return _token


def http_get(url):
    """One GET: the body, or None for a 404. The single network seam (the
    offline tests replace it)."""
    headers = {"User-Agent": "tog-catalog-generator"}
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        if github_token():
            headers["Authorization"] = f"Bearer {github_token()}"
    last = None
    for _ in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
    raise Failure(f"{url}: {last}")


def fetch(url, missing_ok=False):
    """A fresh GET of `url`; None when `missing_ok` and the answer is 404."""
    body = http_get(url)
    if body is None:
        if missing_ok:
            return None
        raise Failure(f"{url}: 404")
    return body


def fetch_json(url):
    return json.loads(fetch(url))


def fetch_text(url, missing_ok=False):
    body = fetch(url, missing_ok=missing_ok)
    return None if body is None else body.decode()


def archive_path(url):
    """The archive at `url`, downloaded once into the cache."""
    path = os.path.join(CACHE, hashlib.sha256(url.encode()).hexdigest())
    if not os.path.exists(path):
        body = fetch(url)
        os.makedirs(CACHE, exist_ok=True)
        with open(path + ".part", "wb") as f:
            f.write(body)
        os.replace(path + ".part", path)
    return path


def download_digest(url, algo):
    """The hex digest under `algo` of the archive at `url`."""
    h = hashlib.new(algo)
    with open(archive_path(url), "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parallel(fn, items, workers=12):
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        return list(pool.map(fn, items))


def github_release(repo, tag):
    return fetch_json(f"https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}")


def github_releases(repo):
    out, page = [], 1
    while True:
        batch = fetch_json(f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}")
        out.extend(batch)
        if len(batch) < 100:
            return out
        page += 1


def github_tags(repo):
    out, page = [], 1
    while True:
        batch = fetch_json(f"https://api.github.com/repos/{repo}/tags?per_page=100&page={page}")
        out.extend(t["name"] for t in batch)
        if len(batch) < 100:
            return out
        page += 1


def asset_digests(release):
    """GitHub's own sha256 of each release asset, where it records one."""
    return {a["name"]: a.get("digest") for a in release.get("assets", [])}


def check_github_digest(report, what, recorded, digest, vouched_by):
    """Compare `digest` with GitHub's own digest of the asset. GitHub
    records none for assets uploaded before it began to, and then the run
    says which source alone vouches for the row instead of passing over
    the missing check in silence. `vouched_by` None: upstream publishes no
    checksum of its own, so the row rests on its TLS download alone."""
    if recorded is None and vouched_by is None:
        report.note(f"{what}: GitHub records no digest and upstream publishes none, "
                    "so the row is trusted on its TLS download alone")
    elif recorded is None:
        report.note(f"{what}: GitHub records no digest, so {vouched_by} is its only check")
    else:
        expect_equal(f"{what} GitHub digest", recorded, digest)


def version_key(text):
    return tuple(int(p) for p in text.split("."))


# --------------------------------------------------------------------------
# The document: rows, releases, and the canonical spelling.


def row(platform, component, provider, build, recipe, url, digest):
    return {
        "platform": platform,
        "component": component,
        "provider": provider,
        "build": build,
        "recipe": recipe,
        "url": url,
        "digest": digest,
    }


def release(key, components, artifacts, revision=None):
    return {"key": key, "revision": revision, "components": components, "artifacts": artifacts}


def component(name, version, embedded_in=None):
    c = {"name": name, "version": version}
    if embedded_in:
        c["embedded_in"] = embedded_in
    return c


def read_document(eco):
    path = os.path.join(REPO, FILES[eco])
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    for r in doc.get("release", []):
        r.setdefault("revision", None)
    return doc


def quote(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def primary_versions(eco, rel):
    versions = {c["name"]: c["version"] for c in rel["components"]}
    return tuple(version_key(versions[name]) for name in PRIMARY[eco])


def render(eco, default, releases):
    """The bytes `Document::render` writes: keep the two in step."""
    out = [
        f"# The shipped {eco} toolchain catalog. Generated and verified by\n",
        f"# `python3 tools/catalog.py {eco}`: regenerate it, do not edit it by hand.\n",
        "# Rows are append-only; `default` is what a project with no pin gets.\n",
        "schema = 1\n",
        f"ecosystem = {quote(eco)}\n",
        "primary = [" + ", ".join(quote(p) for p in PRIMARY[eco]) + "]\n",
        f"default = {quote(default)}\n",
    ]
    ordered = sorted(releases, key=lambda r: primary_versions(eco, r), reverse=True)
    for rel in ordered:
        out.append("\n[[release]]\n")
        out.append(f"key = {quote(rel['key'])}\n")
        if rel.get("revision") is not None:
            out.append(f"revision = {rel['revision']}\n")
        out.append("components = [\n")
        names = []
        for c in rel["components"]:
            names.append(c["name"])
            line = f"  {{ name = {quote(c['name'])}, version = {quote(c['version'])}"
            if c.get("embedded_in"):
                line += f", embedded_in = {quote(c['embedded_in'])}"
            out.append(line + " },\n")
        out.append("]\nartifacts = [\n")
        rows = sorted(rel["artifacts"], key=lambda a: (names.index(a["component"]), a["platform"]))
        for a in rows:
            out.append(
                "  { "
                + ", ".join(
                    f"{field} = {quote(a[field])}"
                    for field in ("platform", "component", "provider", "build", "recipe", "url", "digest")
                )
                + " },\n"
            )
        out.append("]\n")
    return "".join(out)


class Report:
    def __init__(self, eco):
        self.eco = eco
        self.kept = 0
        self.added = []
        self.skipped = []
        self.verified_rows = 0
        self.notes = []
        self.republished = []

    def republish(self, key, why):
        """A new revision of a release already shipped: upstream moved."""
        self.added.append(key)
        self.republished.append((key, why))

    def skip(self, what, why):
        self.skipped.append((what, why))

    def note(self, text):
        self.notes.append(text)

    def print(self):
        print(f"{self.eco}: {self.kept} kept, {len(self.added)} added, "
              f"{self.verified_rows} rows verified, {len(self.skipped)} skipped")
        for key in self.added:
            print(f"  + {key}")
        for what, why in self.skipped:
            print(f"  - skipped {what}: {why}")
        for key, why in self.republished:
            print(f"  ! {key} is a new revision: {why}")
        for text in self.notes:
            print(f"  note: {text}")


def next_revision(releases):
    """The revision after every shipped release of one upstream version; a
    release written without one counts as revision 1."""
    return max((r.get("revision") or 1) for r in releases) + 1


def normalized(rel):
    rel = dict(rel)
    rel["artifacts"] = sorted(rel["artifacts"], key=lambda a: (a["component"], a["platform"]))
    return rel


def check_row(eco, key, existing, fresh):
    """An existing release must be exactly what upstream publishes today."""
    if fresh is None or normalized(existing) != normalized(fresh):
        raise Failure(
            f"{eco}: {key}: the checked-in row no longer matches upstream\n"
            f"  checked in: {existing}\n  upstream:   {fresh}"
        )


def expect_equal(what, a, b):
    if a != b:
        raise Failure(f"{what}: {a} != {b}")


def checksum_lines(source, text):
    """A `sha256sum` checksum file as (digest, name) pairs: `<hex>  <name>`
    (text mode) or `<hex> *<name>` (binary mode), the name kept verbatim.
    Any other line is an error naming `source` and the line."""
    pairs = []
    for line in text.splitlines():
        m = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
        if m is None:
            raise Failure(f"{source}: malformed checksum line {line!r}")
        pairs.append(m.groups())
    return pairs


# --------------------------------------------------------------------------
# Go: go.dev's release JSON (sha256), cross-checked with dl.google.com's
# per-file .sha256. Supported lines are the ones go.dev lists without
# include=all.


def go_rows(report):
    everything = fetch_json("https://go.dev/dl/?mode=json&include=all")
    supported = fetch_json("https://go.dev/dl/?mode=json")
    lines = {".".join(r["version"][2:].split(".")[:2]) for r in supported}
    by_version = {}
    for r in everything:
        if not r.get("stable"):
            continue
        version = r["version"][2:]
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            continue
        files = {}
        for f in r["files"]:
            if f["kind"] != "archive":
                continue
            if (f["os"], f["arch"]) == ("darwin", "arm64"):
                files[DARWIN] = f
            elif (f["os"], f["arch"]) == ("linux", "amd64"):
                files[LINUX] = f
        by_version[version] = files
    return lines, by_version


def go_release(version, files):
    rows = []
    for platform in PLATFORMS:
        f = files[platform]
        rows.append(row(platform, "go", "go.dev", version, "go-toolchain/1",
                        f"https://go.dev/dl/{f['filename']}", f"sha256:{f['sha256']}"))
    return release(f"go-{version}", [component("go", version)], rows)


def go_cross_check(rel):
    for a in rel["artifacts"]:
        name = a["url"].rsplit("/", 1)[1]
        text = fetch_text(f"https://dl.google.com/go/{name}.sha256").split()[0]
        expect_equal(f"go {name} .sha256", "sha256:" + text, a["digest"])


def generate_go(existing, report):
    lines, by_version = go_rows(report)
    out = {}
    for rel in existing:
        version = rel["components"][0]["version"]
        files = by_version.get(version, {})
        if len(files) != 2:
            raise Failure(f"go: {rel['key']}: go.dev no longer lists both archives")
        check_row("go", rel["key"], rel, go_release(version, files))
        out[rel["key"]] = rel
    for version, files in by_version.items():
        key = f"go-{version}"
        if key in out or ".".join(version.split(".")[:2]) not in lines:
            continue
        missing = [p for p in PLATFORMS if p not in files]
        if missing:
            report.skip(key, f"go.dev publishes no archive for {', '.join(missing)}")
            continue
        out[key] = go_release(version, files)
        report.added.append(key)
    parallel(go_cross_check, list(out.values()))
    return out


# --------------------------------------------------------------------------
# Node: nodejs.org's index, and each release's SHASUMS256.txt, whose
# detached signature is checked against the nodejs/release-keys keyring and
# must chain to a releaser pinned in tools/keys/node-releasers.txt.
# Supported lines are the ones the nodejs/Release schedule has started and
# not yet ended.


SCRATCH = None


def scratch_file(name, body):
    """`body` written under this run's scratch directory."""
    global SCRATCH
    if SCRATCH is None:
        SCRATCH = tempfile.mkdtemp(prefix="tog-catalog-")
    path = os.path.join(SCRATCH, name)
    with open(path, "wb") as f:
        f.write(body)
    return path


# The keyring comes from GitHub, so it only supplies key material: a
# signature counts only when it chains to a primary key pinned in
# tools/keys/node-releasers.txt, so whoever could replace both the keyring
# and SHASUMS256.txt still cannot pass.
NODE_RELEASERS = os.path.join(REPO, "tools", "keys", "node-releasers.txt")


def node_fingerprints():
    """The pinned releasers' primary-key fingerprints."""
    with open(NODE_RELEASERS) as f:
        lines = [line.split("#", 1)[0].strip() for line in f]
    pins = {line for line in lines if line}
    bad = sorted(p for p in pins if not re.fullmatch(r"[0-9A-F]{40}", p))
    if bad or not pins:
        raise Failure(f"{NODE_RELEASERS}: malformed or no fingerprints: {bad}")
    return pins


def node_keyring():
    body = fetch("https://raw.githubusercontent.com/nodejs/release-keys/main/gpg/pubring.kbx")
    return scratch_file("node-release-keys.kbx", body)


def node_shasums(version, keyring, pins):
    base = f"https://nodejs.org/dist/v{version}/"
    text = fetch(base + "SHASUMS256.txt")
    sig = fetch(base + "SHASUMS256.txt.sig")
    text_path = scratch_file(f"node-{version}-SHASUMS256.txt", text)
    sig_path = scratch_file(f"node-{version}-SHASUMS256.txt.sig", sig)
    result = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", keyring, sig_path, text_path],
                            capture_output=True, text=True)
    # VALIDSIG <signing-key fpr> ... <primary-key fpr>: the last field is the
    # primary key the signature chains to, which a subkey signature names too.
    valid = [line.split() for line in result.stdout.splitlines()
             if line.startswith("[GNUPG:] VALIDSIG ")]
    if result.returncode != 0 or not valid:
        raise Failure(f"node {version}: SHASUMS256.txt signature does not verify:\n{result.stderr}")
    # gpgv exits 0 only when every signature verifies, so any one of them
    # chaining to a pinned releaser is enough.
    signers = [line[-1] for line in valid]
    if not any(signer in pins for signer in signers):
        raise Failure(f"node {version}: SHASUMS256.txt is signed by {', '.join(signers)}, "
                      f"which is not a releaser pinned in {os.path.relpath(NODE_RELEASERS, REPO)}")
    return {name: digest for digest, name in checksum_lines(f"node {version}: SHASUMS256.txt", text.decode())}


def node_release(version, sums):
    rows = []
    for platform, slug in ((DARWIN, "darwin-arm64"), (LINUX, "linux-x64")):
        name = f"node-v{version}-{slug}.tar.gz"
        if name not in sums:
            return None, platform
        rows.append(row(platform, "node", "nodejs.org", version, "nodejs/legacy",
                        f"https://nodejs.org/dist/v{version}/{name}", f"sha256:{sums[name]}"))
    return release(f"node-{version}", [component("node", version)], rows), None


def generate_node(existing, report):
    index = fetch_json("https://nodejs.org/dist/index.json")
    schedule = fetch_json("https://raw.githubusercontent.com/nodejs/Release/main/schedule.json")
    lines = {
        line[1:]
        for line, span in schedule.items()
        if datetime.date.fromisoformat(span["start"]) <= TODAY < datetime.date.fromisoformat(span["end"])
    }
    wanted = [r["version"][1:] for r in index if r["version"][1:].split(".")[0] in lines]
    keyring, pins = node_keyring(), node_fingerprints()
    versions = sorted({rel["components"][0]["version"] for rel in existing} | set(wanted), key=version_key)
    sums = dict(zip(versions, parallel(lambda v: node_shasums(v, keyring, pins), versions)))
    out = {}
    for rel in existing:
        version = rel["components"][0]["version"]
        fresh, _ = node_release(version, sums[version])
        check_row("node", rel["key"], rel, fresh)
        out[rel["key"]] = rel
    for version in wanted:
        key = f"node-{version}"
        if key in out:
            continue
        fresh, missing = node_release(version, sums[version])
        if fresh is None:
            report.skip(key, f"nodejs.org publishes no {missing} tarball")
            continue
        out[key] = fresh
        report.added.append(key)
    return out


# --------------------------------------------------------------------------
# Python: python-build-standalone's per-release SHA256SUMS, cross-checked
# with GitHub's asset digests. Supported minors are the CPython lines whose
# status is bugfix or security. A new version takes the newest PBS release
# that publishes its install_only build for both platforms; an existing row
# keeps the PBS release it was minted from. Every bundle carries the uv
# the default release carries.

PBS = "astral-sh/python-build-standalone"


def pbs_asset(version, tag, platform):
    return f"cpython-{version}+{tag}-{platform}-install_only.tar.gz"


def pbs_url(tag, name):
    return f"https://github.com/{PBS}/releases/download/{tag}/{urllib.parse.quote(name, safe='')}"


def pbs_sums(tag):
    text = fetch_text(pbs_url(tag, "SHA256SUMS"), missing_ok=True)
    if text is None:
        return None
    return {name: digest for digest, name in checksum_lines(f"python: PBS {tag} SHA256SUMS", text)}


def generate_python(existing, report, default_key):
    cycle = fetch_json("https://peps.python.org/api/release-cycle.json")
    minors = {line for line, info in cycle.items() if info["status"] in ("bugfix", "security")}
    tags = sorted((t for t in github_tags(PBS) if re.fullmatch(r"\d{8}", t)), reverse=True)
    sums = dict(zip(tags, parallel(pbs_sums, tags)))
    no_sums = [t for t in tags if sums[t] is None]
    if no_sums:
        early = [t for t in no_sums if t < "20220227"]
        named = [t for t in no_sums if t >= "20220227"]
        what = ", ".join(named + ([f"{len(early)} releases before 20220227"] if early else []))
        report.skip(f"PBS releases {what}", "no SHA256SUMS published, so nothing to verify a row against")
    default = next((r for r in existing if r["key"] == default_key), None)
    if default is None:
        raise Failure(f"python: default {default_key} is not checked in; the uv pin is read from it")
    uv = [a for a in default["artifacts"] if a["component"] == "uv"]
    uv_component = next(c for c in default["components"] if c["name"] == "uv")

    def cpython_rows(version, tag):
        rows = []
        for platform in PLATFORMS:
            name = pbs_asset(version, tag, platform)
            digest = (sums.get(tag) or {}).get(name)
            if digest is None:
                return None
            rows.append(row(platform, "cpython", "python-build-standalone", tag, "cpython/legacy",
                            pbs_url(tag, name), f"sha256:{digest}"))
        return rows

    def bundle(version, tag):
        rows = cpython_rows(version, tag)
        if rows is None:
            return None
        return release(f"cpython-{version}", [component("cpython", version), dict(uv_component)],
                       rows + [dict(a) for a in uv])

    out = {}
    for rel in existing:
        version = next(c["version"] for c in rel["components"] if c["name"] == "cpython")
        tag = next(a["build"] for a in rel["artifacts"] if a["component"] == "cpython")
        fresh = bundle(version, tag)
        if fresh is None:
            raise Failure(f"python: {rel['key']}: PBS {tag} SHA256SUMS no longer lists both builds")
        # uv rows are compared as the default carries them.
        check_row("python", rel["key"], rel, fresh)
        out[rel["key"]] = rel
    seen = {}
    pattern = re.compile(r"cpython-(\d+\.\d+\.\d+)\+(\d{8})-(.+)-install_only\.tar\.gz")
    for tag in tags:
        for name in sums[tag] or {}:
            m = pattern.fullmatch(name)
            if m and m.group(3) in PLATFORMS:
                seen.setdefault(m.group(1), set()).add(tag)
    for version in sorted(seen, key=version_key):
        key = f"cpython-{version}"
        if key in out or ".".join(version.split(".")[:2]) not in minors:
            continue
        for tag in sorted(seen[version], reverse=True):
            fresh = bundle(version, tag)
            if fresh is not None:
                out[key] = fresh
                report.added.append(key)
                break
        else:
            report.skip(key, "no PBS release publishes install_only builds for both platforms")
    # CPython patches PBS never built (or built only before it published
    # SHA256SUMS): named, so a gap in the catalog is never silent.
    for minor in sorted(minors, key=version_key):
        patches = [version_key(v)[2] for v in seen if v.startswith(minor + ".")]
        for patch in range(0, max(patches, default=-1) + 1):
            key = f"cpython-{minor}.{patch}"
            if key not in out and not any(what == key for what, _ in report.skipped):
                report.skip(key, "no PBS release with a SHA256SUMS publishes it for both platforms")

    # Second source: GitHub's own digest for every CPython asset we ship.
    used_tags = sorted({a["build"] for r in out.values() for a in r["artifacts"] if a["component"] == "cpython"})
    digests = dict(zip(used_tags, parallel(lambda t: asset_digests(github_release(PBS, t)), used_tags)))
    for rel in out.values():
        for a in rel["artifacts"]:
            if a["component"] != "cpython":
                continue
            name = urllib.parse.unquote(a["url"].rsplit("/", 1)[1])
            if name not in digests[a["build"]]:
                raise Failure(f"python: PBS {a['build']} release has no asset {name}")
            # Every cpython row's digest is the one SHA256SUMS lists (above).
            check_github_digest(report, f"python {name}", digests[a["build"]][name], a["digest"],
                                "its SHA256SUMS")
    # uv: its own published .sha256, and GitHub's digest.
    uv_digests = {}
    for a in uv:
        name = a["url"].rsplit("/", 1)[1]
        tag = a["build"]
        source = f"uv {tag} {name}.sha256"
        lines = checksum_lines(source, fetch_text(a["url"] + ".sha256"))
        if [listed for _, listed in lines] != [name]:
            raise Failure(f"{source}: expected exactly one line naming {name}, got {lines!r}")
        expect_equal(f"uv {name} .sha256", "sha256:" + lines[0][0].lower(), a["digest"])
        if tag not in uv_digests:
            uv_digests[tag] = asset_digests(github_release("astral-sh/uv", tag))
        if name not in uv_digests[tag]:
            raise Failure(f"uv {tag} release has no asset {name}")
        check_github_digest(report, f"uv {name}", uv_digests[tag][name], a["digest"], "its .sha256")
    return out


# --------------------------------------------------------------------------
# Ruby: Homebrew's portable-ruby bottles (the artifact the Ruby tailor
# realizes). Each bottle is downloaded, hashed, compared with GitHub's
# digest, and its layout checked against the `ruby-toolchain/1` recipe.
# Supported lines are ruby-lang's branches still in normal or security
# maintenance. A version enters with Homebrew's newest rebuild of it
# (`3.3.4_1`); a later rebuild of a shipped version is a new release,
# `ruby-3.3.4_2` with `revision = 2`, beside the old one.

PORTABLE = "Homebrew/homebrew-portable-ruby"
BOTTLE_TAGS = {DARWIN: "arm64_big_sur", LINUX: "x86_64_linux"}


def ruby_lines():
    text = fetch_text("https://raw.githubusercontent.com/ruby/www.ruby-lang.org/master/_data/branches.yml")
    lines = set()
    for block in re.split(r"^- ", text, flags=re.M)[1:]:
        name = re.search(r"name:\s*['\"]?([\d.]+)", block)
        status = re.search(r"status:\s*(.+)", block)
        if name and status and status.group(1).strip() in ("normal maintenance", "security maintenance"):
            lines.add(name.group(1))
    return lines


def check_bottle_layout(path, tag):
    """The `ruby-toolchain/1` recipe: one `portable-ruby/<tag>/` root that
    `--strip-components 2` removes, no link leaving it, and the entries the
    tailor's layout check requires."""
    root = f"portable-ruby/{tag}"
    names = []
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            name = os.path.normpath(member.name)
            if name != root and not name.startswith(root + "/"):
                raise Failure(f"ruby {tag}: bottle entry {member.name} is outside {root}/")
            if member.issym():
                target = os.path.normpath(os.path.join(os.path.dirname(name), member.linkname))
                if member.linkname.startswith("/") or not target.startswith(root + "/"):
                    raise Failure(f"ruby {tag}: symlink {member.name} -> {member.linkname} leaves the bottle")
            if member.islnk() and not os.path.normpath(member.linkname).startswith(root + "/"):
                raise Failure(f"ruby {tag}: hard link {member.name} -> {member.linkname} leaves the bottle")
            names.append(name[len(root) + 1:])
    checks = {
        "bin/ruby": lambda n: n == "bin/ruby",
        "bin/gem": lambda n: n == "bin/gem",
        "a Bundler launcher": lambda n: n.startswith("bin/bundle"),
        "libruby": lambda n: n.startswith("lib/") and n.rsplit("/", 1)[-1].startswith("libruby"),
        "ruby.h": lambda n: n.startswith("include/") and n.endswith("/ruby.h"),
    }
    for what, test in checks.items():
        if not any(test(n) for n in names):
            raise Failure(f"ruby {tag}: bottle lacks {what}")
    # The recipe realizes the bottle unrepaired, which is only sound when
    # the extensions that need host libraries are compiled into bin/ruby.
    for name in names:
        if re.search(r"/(openssl|psych|zlib|fiddle)\.(so|bundle)$", name):
            raise Failure(f"ruby {tag}: {name} is a dynamic extension; the recipe expects static ones")


def run_linux_bottle(path, tag, version):
    """On a Linux x86_64 host, run the bottle the way the tailor lays it
    out: extracted with two components stripped, from a directory it was
    not built in, loading the extensions that would need host libraries."""
    if (os.uname().sysname, os.uname().machine) != ("Linux", "x86_64"):
        return False
    import tempfile
    with tempfile.TemporaryDirectory(prefix="tog-catalog-ruby-") as scratch:
        subprocess.run(["tar", "-xzf", path, "-C", scratch, "--strip-components", "2"], check=True)
        result = subprocess.run(
            [os.path.join(scratch, "bin/ruby"), "-ropenssl", "-rpsych", "-rzlib", "-e", "print RUBY_VERSION"],
            capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
        )
        if result.returncode != 0 or result.stdout != version:
            raise Failure(f"ruby {tag}: the relocated Linux bottle does not run: {result.stderr.strip()}")
    return True


def ruby_release(report, tag, release_json, key=None, revision=None):
    version = tag.split("_")[0]
    digests = asset_digests(release_json)
    rows = []
    for platform in PLATFORMS:
        name = f"portable-ruby-{tag}.{BOTTLE_TAGS[platform]}.bottle.tar.gz"
        if name not in digests:
            return None, platform
        url = f"https://github.com/{PORTABLE}/releases/download/{tag}/{name}"
        digest = "sha256:" + download_digest(url, "sha256")
        check_github_digest(report, f"ruby {name}", digests[name], digest, None)
        check_bottle_layout(archive_path(url), tag)
        if platform == LINUX:
            run_linux_bottle(archive_path(url), tag, version)
        rows.append(row(platform, "ruby", "homebrew-portable-ruby", tag, "ruby-toolchain/1", url, digest))
    return release(key or f"ruby-{version}", [component("ruby", version)], rows, revision), None


def generate_ruby(existing, report):
    lines = ruby_lines()
    releases = {r["tag_name"]: r for r in github_releases(PORTABLE) if not r["draft"]}
    out = {}
    for rel in existing:
        tag = rel["artifacts"][0]["build"]
        if tag not in releases:
            raise Failure(f"ruby: {rel['key']}: portable-ruby no longer publishes {tag}")
        fresh, _ = ruby_release(report, tag, releases[tag], rel["key"], rel.get("revision"))
        check_row("ruby", rel["key"], rel, fresh)
        out[rel["key"]] = rel
    newest = {}
    for tag, r in releases.items():
        m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:_(\d+))?", tag)
        if not m:
            continue
        version, revision = m.group(1), int(m.group(2) or 0)
        if ".".join(version.split(".")[:2]) not in lines:
            continue
        if r["prerelease"]:
            if f"ruby-{version}" not in out:
                report.skip(f"portable-ruby {tag}", "marked prerelease by Homebrew")
            continue
        if version not in newest or revision > newest[version][0]:
            newest[version] = (revision, tag)
    for version, (rebuild, tag) in sorted(newest.items(), key=lambda kv: version_key(kv[0])):
        shipped = [r for r in out.values() if r["components"][0]["version"] == version]
        if any(r["artifacts"][0]["build"] == tag for r in shipped):
            continue
        if shipped:
            # Homebrew rebuilt a version this catalog ships: the old bottle
            # stays (locks name it), the rebuild is a revision beside it.
            key, revision = f"ruby-{tag}", max(rebuild, next_revision(shipped))
        else:
            key, revision = f"ruby-{version}", None
        fresh, missing = ruby_release(report, tag, releases[tag], key, revision)
        if fresh is None:
            report.skip(key, f"portable-ruby {tag} has no {missing} bottle")
            continue
        out[key] = fresh
        if shipped:
            report.republish(key, f"Homebrew rebuilt ruby {version} as {tag}")
        else:
            report.added.append(key)
    report.skip("ruby-lang lines without a portable-ruby build",
                ", ".join(sorted(l for l in lines if not any(v.startswith(l + ".") for v in newest))) or "none")
    return out


# --------------------------------------------------------------------------
# Elixir: the BEAM pair. OTP is a per-platform build (erlef/otp_builds on
# Darwin, DigitalWestern/tog-toolchains on Linux), so an OTP version enters
# only when both exist. Elixir is the platform-neutral `elixir-otp-<major>`
# zip; Hex and rebar3 follow Mix's own rule over builds.hex.pm's install
# CSVs (the newest row whose Elixir and OTP are not newer than the pair).
# Elixir zips, Hex and rebar3 are small and downloaded to hash. Mix's rule
# only chooses the tools of a new pair: a shipped pair is verified against
# the Hex and rebar3 it records, and when builds.hex.pm later publishes a
# newer eligible one, that is a new revision of the pair
# (`beam-otp29.0.5-elixir1.20.4-r2`, `revision = 2`), never an edit.

ERLEF = "erlef/otp_builds"
TOG_TOOLCHAINS = "DigitalWestern/tog-toolchains"
ELIXIR = "elixir-lang/elixir"


def elixir_version_key(text):
    return version_key(text)


def mix_pick(csv_text, elixir, otp_major):
    """Mix.Local.find_latest_eligible_version: the last CSV row whose Elixir
    directory is not newer than `elixir` and whose OTP is not newer."""
    rows = [line.split(",") for line in csv_text.strip().splitlines()]
    for fields in reversed(rows):
        if len(fields) < 4:
            continue
        artifact, digest, elixir_dir, otp = fields[:4]
        if elixir_version_key(elixir_dir) <= elixir_version_key(elixir) and int(otp) <= int(otp_major):
            return artifact, digest, elixir_dir, otp
    return None


def generate_elixir(existing, report):
    darwin = {}
    for r in github_releases(ERLEF):
        m = re.fullmatch(r"OTP-(\d+(?:\.\d+)+)", r["tag_name"])
        if m and not r["prerelease"]:
            d = asset_digests(r).get("otp-aarch64-apple-darwin.tar.gz")
            if d:
                darwin[m.group(1)] = (r["tag_name"], d)
    linux = {}
    for r in github_releases(TOG_TOOLCHAINS):
        m = re.fullmatch(r"otp-(\d+(?:\.\d+)+)-x86_64-unknown-linux-gnu-(\w+)", r["tag_name"])
        if not m:
            continue
        name = f"OTP-{m.group(1)}-x86_64-unknown-linux-gnu-{m.group(2)}.tar.gz"
        digests = asset_digests(r)
        if name not in digests:
            continue
        side = fetch_text(f"https://github.com/{TOG_TOOLCHAINS}/releases/download/{r['tag_name']}/{name}.sha256").split()[0]
        digest = "sha256:" + side
        check_github_digest(report, f"tog-toolchains {name}", digests[name], digest, "its .sha256")
        linux[m.group(1)] = (r["tag_name"], name, digest)
    otps = sorted(set(darwin) & set(linux), key=version_key)
    majors_supported = sorted({int(v.split(".")[0]) for v in darwin}, reverse=True)[:3]
    no_linux = [v for v in darwin if v not in linux and int(v.split(".")[0]) in majors_supported]
    if no_linux:
        report.skip(f"{len(no_linux)} OTP releases ({', '.join(sorted(no_linux, key=version_key)[-4:])}, ...)",
                    "no Linux build in tog-toolchains (DESIGNS WP3 PR 8 rebuilds OTP)")
    hex_csv = fetch_text("https://builds.hex.pm/installs/hex.csv")
    rebar_csv = fetch_text("https://builds.hex.pm/installs/rebar.csv")
    elixirs = {}
    for r in github_releases(ELIXIR):
        m = re.fullmatch(r"v(\d+\.\d+\.\d+)", r["tag_name"])
        if m and not r["prerelease"] and not r["draft"]:
            elixirs[m.group(1)] = r

    def zip_row(elixir, major):
        r = elixirs[elixir]
        name = f"elixir-otp-{major}.zip"
        digests = asset_digests(r)
        if name not in digests:
            return None
        url = f"https://github.com/{ELIXIR}/releases/download/v{elixir}/{name}"
        published = fetch_text(url + ".sha256sum").split()[0]
        digest = "sha256:" + download_digest(url, "sha256")
        expect_equal(f"elixir {elixir} {name} .sha256sum", "sha256:" + published, digest)
        check_github_digest(report, f"elixir {elixir} {name}", digests[name], digest, "its .sha256sum")
        return url, digest

    def installs_row(csv_text, tool, picked):
        """The row for one builds.hex.pm install `(version, sha512, elixir
        dir, otp)`, its bytes checked against the CSV's sha512."""
        version, sha512, elixir_dir, otp = picked
        suffix = ".ez" if tool == "hex" else ""
        url = f"https://builds.hex.pm/installs/{elixir_dir}/{tool}-{version}-otp-{otp}{suffix}"
        expect_equal(f"{tool} {url} sha512", sha512, download_digest(url, "sha512"))
        return version, f"{tool}-{version}-otp-{otp}", url, f"sha512:{sha512}"

    def recorded_pick(csv_text, tool, rel):
        """The install a shipped pair records, as the CSV lists it today."""
        url = next(a["url"] for a in rel["artifacts"] if a["component"] == tool)
        m = re.fullmatch(rf"https://builds\.hex\.pm/installs/([^/]+)/{tool}-(.+)-otp-(\d+)(?:\.ez)?", url)
        if m is None:
            raise Failure(f"elixir: {rel['key']}: {url} is not a builds.hex.pm install")
        elixir_dir, version, otp = m.groups()
        for fields in (line.split(",") for line in csv_text.strip().splitlines()):
            if len(fields) >= 4 and (fields[0], fields[2], fields[3]) == (version, elixir_dir, otp):
                return tuple(fields[:4])
        raise Failure(f"elixir: {rel['key']}: builds.hex.pm no longer lists {url}")

    def bundle(otp, elixir, hex_pick=None, rebar_pick=None, key=None, revision=None):
        """The pair's release; Hex and rebar3 are Mix's choice unless given."""
        major = otp.split(".")[0]
        z = zip_row(elixir, major)
        hex_pick = hex_pick or mix_pick(hex_csv, elixir, major)
        rebar_pick = rebar_pick or mix_pick(rebar_csv, elixir, major)
        if z is None or hex_pick is None or rebar_pick is None:
            return None
        hexr = installs_row(hex_csv, "hex", hex_pick)
        rebar = installs_row(rebar_csv, "rebar3", rebar_pick)
        dtag, ddigest = darwin[otp]
        ltag, lname, ldigest = linux[otp]
        rows = [
            row(DARWIN, "otp", "erlef-otp-builds", dtag, "beam-toolchain/1",
                f"https://github.com/{ERLEF}/releases/download/{dtag}/otp-aarch64-apple-darwin.tar.gz", ddigest),
            row(LINUX, "otp", "tog-toolchains", ltag, "otp-install-cross-minimal/1",
                f"https://github.com/{TOG_TOOLCHAINS}/releases/download/{ltag}/{lname}", ldigest),
        ]
        for platform in PLATFORMS:
            rows.append(row(platform, "elixir", "elixir-lang", f"v{elixir}-otp-{major}", "beam-toolchain/1", z[0], z[1]))
            rows.append(row(platform, "hex", "builds.hex.pm", hexr[1], "beam-toolchain/1", hexr[2], hexr[3]))
            rows.append(row(platform, "rebar3", "builds.hex.pm", rebar[1], "beam-toolchain/1", rebar[2], rebar[3]))
        return release(
            key or f"beam-otp{otp}-elixir{elixir}",
            [component("otp", otp), component("elixir", elixir), component("hex", hexr[0]),
             component("rebar3", rebar[0])],
            rows,
            revision,
        )

    def pair(rel):
        versions = {c["name"]: c["version"] for c in rel["components"]}
        return versions["otp"], versions["elixir"]

    def tools(rel):
        return sorted({(a["component"], a["url"]) for a in rel["artifacts"] if a["component"] in ("hex", "rebar3")})

    out = {}
    for rel in existing:
        otp, elixir = pair(rel)
        if otp not in darwin or otp not in linux or elixir not in elixirs:
            raise Failure(f"elixir: {rel['key']}: an upstream no longer publishes OTP {otp} or Elixir {elixir}")
        fresh = bundle(otp, elixir, recorded_pick(hex_csv, "hex", rel), recorded_pick(rebar_csv, "rebar3", rel),
                       rel["key"], rel.get("revision"))
        check_row("elixir", rel["key"], rel, fresh)
        out[rel["key"]] = rel
    for otp in otps:
        major = otp.split(".")[0]
        for elixir in sorted(elixirs, key=version_key):
            key = f"beam-otp{otp}-elixir{elixir}"
            if f"elixir-otp-{major}.zip" not in asset_digests(elixirs[elixir]):
                continue
            shipped = [r for r in out.values() if pair(r) == (otp, elixir)]
            if shipped:
                fresh = bundle(otp, elixir)
                if fresh is None or any(tools(r) == tools(fresh) for r in shipped):
                    continue
                revision = next_revision(shipped)
                key = f"{key}-r{revision}"
                out[key] = bundle(otp, elixir, key=key, revision=revision)
                report.republish(key, "builds.hex.pm publishes a newer Hex or rebar3 Mix would install")
                continue
            fresh = bundle(otp, elixir)
            if fresh is None:
                report.skip(key, "no Hex or rebar3 build Mix would install for this pair")
                continue
            out[key] = fresh
            report.added.append(key)
    return out


# --------------------------------------------------------------------------
# .NET: Microsoft's release metadata (sha512), cross-checked with the
# `.sha512` file served beside each archive. Supported channels are the
# ones whose support phase is active or maintenance; previews are never
# admitted.


def dotnet_release(sdk):
    files = {f["name"]: f for f in sdk["files"]}
    rows = []
    version = sdk["version"]
    for platform, name in ((DARWIN, "dotnet-sdk-osx-arm64.tar.gz"), (LINUX, "dotnet-sdk-linux-x64.tar.gz")):
        f = files.get(name)
        if f is None:
            return None, platform
        url = f["url"]
        if not url.startswith("https://builds.dotnet.microsoft.com/dotnet/"):
            raise Failure(f"dotnet {version}: {url} is not on the shipped endpoint")
        rows.append(row(platform, "dotnet-sdk", "builds.dotnet.microsoft.com", version, "dotnet-sdk/1",
                        url, f"sha512:{f['hash'].lower()}"))
    return release(f"dotnet-sdk-{version}", [component("dotnet-sdk", version)], rows), None


def dotnet_cross_check(rel):
    """Rows with a `.sha512` beside the archive; older SDKs have none, and
    the release metadata is then their only published checksum."""
    checked = 0
    for a in rel["artifacts"]:
        text = fetch_text(a["url"] + ".sha512", missing_ok=True)
        if text is None:
            continue
        expect_equal(f"dotnet {a['url']} .sha512", "sha512:" + text.split()[0].lower(), a["digest"])
        checked += 1
    return checked


def generate_dotnet(existing, report):
    index = fetch_json("https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json")
    sdks = {}
    for channel in index["releases-index"]:
        supported = channel["support-phase"] in ("active", "maintenance")
        meta = fetch_json(channel["releases.json"]) if supported or existing else None
        if meta is None:
            continue
        for r in meta["releases"]:
            for sdk in r.get("sdks") or [r["sdk"]]:
                if re.fullmatch(r"\d+\.\d+\.\d+", sdk["version"]):
                    sdks.setdefault(sdk["version"], (sdk, supported))
    out = {}
    for rel in existing:
        version = rel["components"][0]["version"]
        if version not in sdks:
            raise Failure(f"dotnet: {rel['key']}: no longer in the release metadata")
        fresh, _ = dotnet_release(sdks[version][0])
        check_row("dotnet", rel["key"], rel, fresh)
        out[rel["key"]] = rel
    for version, (sdk, supported) in sorted(sdks.items(), key=lambda kv: version_key(kv[0])):
        key = f"dotnet-sdk-{version}"
        if key in out or not supported:
            continue
        fresh, missing = dotnet_release(sdk)
        if fresh is None:
            report.skip(key, f"no {missing} archive in the release metadata")
            continue
        out[key] = fresh
        report.added.append(key)
    checked = sum(parallel(dotnet_cross_check, list(out.values()), workers=16))
    total = sum(len(r["artifacts"]) for r in out.values())
    if checked < total:
        report.note(f"{total - checked} of {total} rows have no .sha512 beside the archive; "
                    "the release metadata is their only published checksum")
    return out


# --------------------------------------------------------------------------
# Rust: each stable release's channel manifest (channel-rust-<version>.toml),
# whose detached signature is checked with gpgv against the Rust release key
# checked in at tools/keys/rust-release-signing-key.asc. The manifest names
# every archive by sha256; a release's rows are its rustc, rust-std, cargo
# and rustfmt archives on each platform, plus the manifest itself (tog
# provisions optional components and cross targets from it, pinned by that
# row). Each archive row is cross-checked against the .sha256 file beside
# it on static.rust-lang.org. Supported releases are every stable release
# from RUST_OLDEST through the current stable channel.

RUST_DIST = "https://static.rust-lang.org/dist"
RUST_KEY = os.path.join(REPO, "tools", "keys", "rust-release-signing-key.asc")
# "Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>", as
# published at https://static.rust-lang.org/rust-key.gpg.ascii.
RUST_FINGERPRINT = "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
RUST_OLDEST = (1, 70, 0)
# (catalog component, manifest package, recipe). A package the manifest
# renames is looked up under its new name.
RUST_COMPONENTS = (
    ("rustc", "rustc", "rust-toolchain/1"),
    ("rust-std", "rust-std", "rust-toolchain/1"),
    ("cargo", "cargo", "rust-toolchain/1"),
    ("rustfmt", "rustfmt", "rustfmt/1"),
)
RUST_MANIFEST = "channel-manifest"
RUST_MANIFEST_RECIPE = "rust-channel-manifest/1"


def dearmor(text):
    """The binary packets of an ASCII-armored OpenPGP block, which is the
    keyring format gpgv reads."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("-----BEGIN PGP"))
    body = []
    in_headers = True
    for line in lines[start + 1:]:
        if in_headers:
            if not line.strip():
                in_headers = False
            continue
        if line.startswith("=") or line.startswith("-----END"):
            break
        body.append(line.strip())
    return base64.b64decode("".join(body))


def rust_keyring():
    with open(RUST_KEY) as f:
        return scratch_file("rust-release-key.gpg", dearmor(f.read()))


def rust_verify(version, manifest, signature, keyring):
    """The manifest's signature must verify, and chain to the Rust key."""
    manifest_path = scratch_file(f"channel-rust-{version}.toml", manifest)
    signature_path = scratch_file(f"channel-rust-{version}.toml.asc", signature)
    home = os.path.join(os.path.dirname(keyring), "gnupg-home")
    os.makedirs(home, mode=0o700, exist_ok=True)
    result = subprocess.run(
        ["gpgv", "--homedir", home, "--status-fd", "1", "--keyring", keyring,
         signature_path, manifest_path],
        capture_output=True, text=True,
    )
    # VALIDSIG <signing-key fpr> ... <primary-key fpr>: the last field is the
    # primary key the signature chains to.
    valid = [line.split() for line in result.stdout.splitlines()
             if line.startswith("[GNUPG:] VALIDSIG ")]
    if result.returncode != 0 or not valid:
        raise Failure(f"rust {version}: channel-rust-{version}.toml signature does not verify "
                      f"against the Rust release key:\n{result.stderr.strip()}")
    signers = [line[-1] for line in valid]
    if RUST_FINGERPRINT not in signers:
        raise Failure(f"rust {version}: channel-rust-{version}.toml is signed by {', '.join(signers)}, "
                      f"not the Rust release key {RUST_FINGERPRINT}")


def rust_stable_versions():
    """Every stable release from RUST_OLDEST through the current stable."""
    stable = tomllib.loads(fetch_text(f"{RUST_DIST}/channel-rust-stable.toml"))
    current = version_key(stable["pkg"]["rustc"]["version"].split()[0])

    def patches(minor):
        out, patch = [], 0
        while True:
            version = f"{current[0]}.{minor}.{patch}"
            if fetch(f"{RUST_DIST}/channel-rust-{version}.toml.sha256", missing_ok=True) is None:
                return out
            out.append(version)
            patch += 1

    minors = range(RUST_OLDEST[1], current[1] + 1)
    versions = [v for vs in parallel(patches, list(minors)) for v in vs]
    versions = [v for v in versions if RUST_OLDEST <= version_key(v) <= current]
    if f"{current[0]}.{current[1]}.{current[2]}" not in versions:
        raise Failure(f"rust: the stable channel is {current}, but its versioned manifest is missing")
    return versions


def rust_release(version, keyring):
    """The release for `version`, or (None, why) when a platform lacks one
    of its archives."""
    url = f"{RUST_DIST}/channel-rust-{version}.toml"
    manifest = fetch(url)
    rust_verify(version, manifest, fetch(url + ".asc"), keyring)
    doc = tomllib.loads(manifest.decode())
    if doc.get("manifest-version") != "2":
        raise Failure(f"rust {version}: manifest-version {doc.get('manifest-version')} is not 2")
    expect_equal(f"rust {version}: manifest rustc version",
                 doc["pkg"]["rustc"]["version"].split()[0], version)
    renames = {name: to["to"] for name, to in doc.get("renames", {}).items()}
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    rows = []
    for platform in PLATFORMS:
        for name, package, recipe in RUST_COMPONENTS:
            package = renames.get(package, package)
            target = doc["pkg"].get(package, {}).get("target", {}).get(platform)
            if not target or not target.get("available") or not target.get("xz_url"):
                return None, f"the manifest publishes no {package} .tar.xz for {platform}"
            archive = target["xz_url"].rsplit("/", 1)[1]
            if archive != f"{name}-{version}-{platform}.tar.xz":
                raise Failure(f"rust {version}: {package} for {platform} is {archive}")
            # The undated URL: the same bytes (the cross-check proves it),
            # under the name every release has kept.
            rows.append(row(platform, name, "static.rust-lang.org", version, recipe,
                            f"{RUST_DIST}/{archive}", f"sha256:{target['xz_hash']}"))
        rows.append(row(platform, RUST_MANIFEST, "static.rust-lang.org", version,
                        RUST_MANIFEST_RECIPE, url, manifest_digest))
    components = [component(name, version) for name, _, _ in RUST_COMPONENTS]
    components.append(component(RUST_MANIFEST, version))
    return release(f"rust-{version}", components, rows), None


def rust_cross_check(rel):
    for a in rel["artifacts"]:
        text = fetch_text(a["url"] + ".sha256")
        expect_equal(f"rust {a['url']} .sha256", "sha256:" + text.split()[0], a["digest"])


def generate_cargo(existing, report):
    versions = rust_stable_versions()
    keyring = rust_keyring()
    known = {rel["components"][0]["version"] for rel in existing}
    wanted = sorted(known | set(versions), key=version_key)
    built = dict(zip(wanted, parallel(lambda v: rust_release(v, keyring), wanted, workers=8)))
    out = {}
    for rel in existing:
        version = rel["components"][0]["version"]
        fresh, _ = built[version]
        check_row("cargo", rel["key"], rel, fresh)
        out[rel["key"]] = rel
    for version in versions:
        key = f"rust-{version}"
        if key in out:
            continue
        fresh, why = built[version]
        if fresh is None:
            report.skip(key, why)
            continue
        out[key] = fresh
        report.added.append(key)
    parallel(rust_cross_check, list(out.values()), workers=16)
    return out


# --------------------------------------------------------------------------


def run(eco, args):
    report = Report(eco)
    doc = read_document(eco)
    existing = doc["release"] if doc else []
    default = args.set_default or (doc and doc["default"])
    if not default:
        raise Failure(f"{eco}: no checked-in catalog; pass --set-default <release key>")
    if eco == "python":
        out = generate_python(existing, report, doc["default"] if doc else default)
    else:
        out = globals()[f"generate_{eco}"](existing, report)
    report.kept = len(existing)
    report.verified_rows = sum(len(r["artifacts"]) for r in out.values())
    if default not in out:
        raise Failure(f"{eco}: default {default} is not a release of the catalog")
    text = render(eco, default, list(out.values()))
    path = os.path.join(REPO, FILES[eco])
    current = None
    if os.path.exists(path):
        with open(path) as f:
            current = f.read()
    report.print()
    if args.check:
        if current != text:
            print(f"{eco}: {FILES[eco]} differs from what upstream publishes today "
                  f"({len(report.added)} new, {len(report.republished)} of them new revisions)")
            return False
        return True
    if current != text:
        with open(path, "w") as f:
            f.write(text)
        print(f"{eco}: wrote {FILES[eco]}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("ecosystems", nargs="*", metavar="ECOSYSTEM",
                        help=f"any of: {', '.join(FILES)} (default: all)")
    parser.add_argument("--check", action="store_true",
                        help="verify and compare with the checked-in file; write nothing")
    parser.add_argument("--set-default", metavar="RELEASE",
                        help="make RELEASE the default (one ecosystem only)")
    args = parser.parse_args()
    ecosystems = args.ecosystems or list(FILES)
    unknown = [eco for eco in ecosystems if eco not in FILES]
    if unknown:
        parser.error(f"unknown ecosystem {', '.join(unknown)}; choose from {', '.join(FILES)}")
    if args.set_default and len(ecosystems) != 1:
        parser.error("--set-default names one ecosystem's release")
    ok = True
    for eco in ecosystems:
        try:
            ok = run(eco, args) and ok
        except Failure as failure:
            print(f"error: {failure}", file=sys.stderr)
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Write tests/fixtures/proxy/registry/cargo-git/: a one-commit crate served
as git smart HTTP (protocol v2) at https://github.com/tog-fixtures/leaf.

The repository is built here with a fixed author and date, so its commit id
never changes, and each answer comes from this machine's `git upload-pack`,
not from GitHub: the fixture needs no network and no account. The commit id
and the `ls-refs` answer are the same on every run; the `fetch` answer is a
pack whose bytes depend on the git build that wrote it (its compression and
delta choices), so regenerating with another git rewrites that file and its
sha256 in the index. Protocol v2 sends `ls-refs` and `fetch` to
the same URL, so the two POST rows carry `request_has`, the command the
fixture upstream matches in the request body to pick one.

Usage: python3 tools/git_fixture.py [--out tests/fixtures/proxy/registry/cargo-git]
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

URL = "https://github.com/tog-fixtures/leaf"
FILES = {
    "Cargo.toml": '[package]\nname = "leaf"\nversion = "0.1.0"\nedition = "2021"\n',
    "src/lib.rs": "pub fn leaf() -> u8 {\n    1\n}\n",
}
IDENTITY = {
    "GIT_AUTHOR_NAME": "tog fixtures",
    "GIT_AUTHOR_EMAIL": "fixtures@tog.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_NAME": "tog fixtures",
    "GIT_COMMITTER_EMAIL": "fixtures@tog.invalid",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


def pkt(line):
    data = line.encode()
    return b"%04x" % (len(data) + 4) + data


def git(repo, *args, stdin=None, env=None):
    full = {"PATH": "/usr/bin:/bin", "HOME": repo, "GIT_CONFIG_NOSYSTEM": "1", **IDENTITY, **(env or {})}
    return subprocess.run(["git", "-C", repo, *args], input=stdin, env=full,
                           check=True, capture_output=True).stdout


def build(repo):
    git(repo, "init", "-q", "-b", "main")
    for name, text in FILES.items():
        path = os.path.join(repo, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as file:
            file.write(text)
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "leaf 0.1.0")
    return git(repo, "rev-parse", "HEAD").decode().strip()


def upload_pack(repo, request=None):
    args = ["upload-pack", "--stateless-rpc"]
    if request is None:
        args.append("--http-backend-info-refs")
    return git(repo, *args, ".", stdin=request or b"", env={"GIT_PROTOCOL": "version=2"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="tests/fixtures/proxy/registry/cargo-git")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as repo:
        commit = build(repo)
        advertisement = pkt("# service=git-upload-pack\n") + b"0000" + upload_pack(repo)
        ls_refs = upload_pack(repo, pkt("command=ls-refs\n") + b"0001" + pkt("peel\n")
                              + pkt("symrefs\n") + pkt("unborn\n") + pkt("ref-prefix HEAD\n") + b"0000")
        fetch = upload_pack(repo, pkt("command=fetch\n") + b"0001" + pkt("thin-pack\n")
                            + pkt("no-progress\n") + pkt("ofs-delta\n") + pkt(f"want {commit}\n")
                            + pkt("done\n") + b"0000")
    host_path = URL.removeprefix("https://")
    rows = [
        ("GET", f"{URL}/info/refs?service=git-upload-pack", f"{host_path}/info/refs@service%3Dgit-upload-pack.body",
         "application/x-git-upload-pack-advertisement", None, advertisement),
        ("POST", f"{URL}/git-upload-pack", f"{host_path}/git-upload-pack@ls-refs.body",
         "application/x-git-upload-pack-result", "command=ls-refs", ls_refs),
        ("POST", f"{URL}/git-upload-pack", f"{host_path}/git-upload-pack@fetch.body",
         "application/x-git-upload-pack-result", "command=fetch", fetch),
    ]
    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    index = []
    for method, url, file, content_type, request_has, body in rows:
        path = os.path.join(args.out, file)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(body)
        row = {"method": method, "url": url, "status": 200, "headers": {"Content-Type": content_type},
               "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "file": file,
               "census_label": "cargo-git-generated", "commit": commit}
        if request_has:
            row["request_has"] = request_has
        index.append(row)
    with open(os.path.join(args.out, "index.json"), "w") as out:
        json.dump(index, out, indent=1)
        out.write("\n")
    print(commit)


if __name__ == "__main__":
    main()

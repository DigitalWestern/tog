#!/usr/bin/env python3
"""Reproduce Package A observations using only newly created disposable stores.

Usage: python3 adversarial.py /absolute/path/to/blanket
The assertions describe the reviewed revision's observed behavior, including
unsafe behavior; this is evidence, not a passing safety acceptance suite.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

BIN = Path(sys.argv[1]).resolve()
RESULTS = []


class Fixture:
    def __init__(self, label):
        self.base = Path(tempfile.mkdtemp(prefix="a-review-" + label + "-"))
        self.store = self.base / "store"
        self.env = dict(os.environ, BLANKET_STORE=str(self.store), HOME=str(self.base))
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"]:
            (self.store / sub).mkdir(parents=True, exist_ok=True)
        (self.store / "roots/.initialized").write_text("1\n")
        self.obj = self.store / "objects" / ("1" * 40 + "-protected-1")
        self.obj.mkdir()
        (self.obj / "payload").write_text("live data\n")
        (self.store / "meta" / (self.obj.name + ".json")).write_text(json.dumps({
            "identity": {"kind": "test", "name": "protected", "version": "1", "inputs": {}},
            "refs": [],
        }))
        os.utime(self.obj, (time.time() - 40 * 86400,) * 2)

    def project(self, name="project", live=True):
        p = self.base / name
        c = p / ".blanket/closures"
        c.mkdir(parents=True, exist_ok=True)
        if live:
            (c / "python.json").write_text(json.dumps({
                "schema": "closure/1", "ecosystem": "python",
                "body": {"env_object": str(self.obj)},
            }))
        return p

    def record(self, p, key=None):
        key = key or hashlib.sha1(os.fsencode(p.resolve())).hexdigest()
        (self.store / "roots" / key).write_bytes(os.fsencode(p) + b"\n")
        return key

    def run(self, *args):
        r = subprocess.run([str(BIN), *map(os.fspath, args)], cwd=getattr(self, "cwd", self.base),
                           env=self.env, capture_output=True, text=True)
        return {"args": list(map(os.fspath, args)), "exit": r.returncode,
                "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}

    def log(self, name, **data):
        result = {"case": name, "fixture": str(self.base), **data}
        RESULTS.append(result)
        print(json.dumps(result, ensure_ascii=True), flush=True)


def registry_omissions():
    for mode in ["symlink", "dangling-symlink", "empty-record"]:
        f = Fixture(mode)
        p = f.project()
        key = f.record(p)
        record = f.store / "roots" / key
        control = f.run("gc", "--keep-days=0")
        assert control["exit"] == 0 and f.obj.exists(), control
        record.unlink()
        if mode == "empty-record":
            record.write_text("")
        else:
            target = f.base / "saved-record"
            if mode == "symlink":
                target.write_text(str(p) + "\n")
            record.symlink_to(target)
        listing = f.run("store", "roots")
        result = f.run("gc", "--project", "--keep-days=0")
        assert listing["exit"] == 0 and key not in listing["stdout"], listing
        assert result["exit"] == 0 and not f.obj.exists(), result
        f.log(mode, control=control, listing=listing, sweep=result,
              live_object_deleted=not f.obj.exists(), record_survives=os.path.lexists(record))


def key_case():
    f = Fixture("case")
    lower = "abcdef0123456789abcdef0123456789abcdef01"
    upper = lower.upper()
    f.record(f.project("lower"), lower)
    f.record(f.project("upper"), upper)
    listing = f.run("store", "roots")
    result = f.run("gc", "--forget", upper)
    assert upper in listing["stdout"] and lower in listing["stdout"], listing
    assert result["exit"] == 0, result
    assert (f.store / "roots" / upper).exists()
    assert not (f.store / "roots" / lower).exists()
    f.log("case-fold-forgets-other-record", listing=listing, forget=result,
          requested_record_survives=True, other_record_deleted=True)


def dry_register_and_preflight():
    f = Fixture("dry-register")
    p = f.project("old")
    key = f.record(p)
    shutil.rmtree(p)
    new = f.project("new")
    new_key = hashlib.sha1(os.fsencode(new.resolve())).hexdigest()
    before = sorted(x.name for x in (f.store / "roots").iterdir())
    result = f.run("gc", "--dry-run", "--forget", key, "--register", new)
    after = sorted(x.name for x in (f.store / "roots").iterdir())
    assert result["exit"] == 0 and key in after and new_key in after and new_key not in before
    f.log("dry-forget-register-writes", invocation=result, before=before, after=after)

    for mode in ["same-root", "duplicate", "unknown", "alias"]:
        f = Fixture("preflight-" + mode)
        p = f.project()
        key = f.record(p)
        other = f.project("other")
        before = {x.name: x.read_bytes() for x in (f.store / "roots").iterdir()}
        if mode == "same-root":
            args = ["--register", p, "--forget", key]
        elif mode == "alias":
            alias = f.base / "alias"
            alias.symlink_to(p, target_is_directory=True)
            args = ["--forget", key, "--register", alias]
        elif mode == "duplicate":
            args = ["--register", other, "--forget", key, key]
        else:
            args = ["--register", other, "--forget", key, "f" * 40]
        result = f.run("gc", *args)
        after = {x.name: x.read_bytes() for x in (f.store / "roots").iterdir()}
        assert result["exit"] != 0 and before == after, result
        f.log("preflight-" + mode, invocation=result, registry_unchanged=True)


def unrelated_invalid_record():
    f = Fixture("invalid-record")
    key = f.record(f.project())
    bad = "e" * 40
    (f.store / "roots" / bad).write_bytes(b"\xff\n")
    results = [f.run("gc", "--forget", k) for k in [key, bad]]
    assert all(r["exit"] != 0 for r in results), results
    assert (f.store / "roots" / key).exists() and (f.store / "roots" / bad).exists()
    f.log("unrelated-invalid-record-blocks-all-forgetting", invocations=results)


def path_identity():
    f = Fixture("trailing-space")
    p = f.project("project ")
    f.project("project", live=False)
    result = f.run("gc", "--register", p, "--keep-days=0")
    assert result["exit"] == 0 and not f.obj.exists(), result
    f.log("trailing-space-selects-other-project", invocation=result,
          listing=f.run("store", "roots"), original_closure_survives=(p / ".blanket/closures/python.json").exists(),
          live_object_deleted=True)

    f = Fixture("non-utf8")
    raw = os.fsencode(f.base) + b"/project-\xff"
    replacement = f.project("project-\ufffd", live=False)
    os.makedirs(raw + b"/.blanket/closures")
    with open(raw + b"/.blanket/closures/python.json", "w") as stream:
        json.dump({"body": {"env_object": str(f.obj)}}, stream)
    # Keep argv UTF-8: env::args itself panics on a raw-byte CLI path.
    f.cwd = raw
    result = f.run("gc", "--register", ".", "--keep-days=0")
    assert result["exit"] == 0 and not f.obj.exists(), result
    expected_key = hashlib.sha1(os.fsencode(replacement)).hexdigest()
    assert (f.store / "roots" / expected_key).exists()
    f.log("lossy-path-identity", invocation=result, colliding_key=expected_key, live_object_deleted=True)


def blocking_paths_and_entrypoints():
    for mode in ["missing", "dangling", "loop", "missing-closures", "not-directory"]:
        f = Fixture(mode)
        p = f.project()
        key = f.record(p)
        if mode == "missing-closures":
            shutil.rmtree(p / ".blanket/closures")
        else:
            shutil.rmtree(p)
            if mode == "dangling":
                p.symlink_to(f.base / "absent")
            elif mode == "loop":
                p.symlink_to(p)
            elif mode == "not-directory":
                p.write_text("not a directory")
        invocations = []
        for args in [[], ["--dry-run"], ["--project"], ["--project", "--dry-run"]]:
            result = f.run("gc", "--keep-days=0", *args)
            assert result["exit"] != 0 and "refusing to sweep" in result["stderr"], result
            assert f.obj.exists() and (f.store / "roots" / key).exists()
            invocations.append(result)
        f.log("blocks-" + mode, invocations=invocations, object_and_record_survive=True)

    f = Fixture("uninitialized")
    (f.store / "roots/.initialized").unlink()
    result = f.run("gc", "--project", "--collect-legacy", "--keep-days=0")
    assert result["exit"] != 0 and f.obj.exists(), result
    f.log("pre-registry-block", invocation=result, object_survives=True)


def early_return_and_key_boundary():
    f = Fixture("early-return")
    key = f.record(f.project())
    stage = f.store / "tmp/stage-old"
    stage.mkdir()
    os.utime(stage, (time.time() - 40 * 86400,) * 2)
    result = f.run("gc", "--forget", key, "--project", "--collect-legacy", "--keep-days=0")
    assert result["exit"] == 0 and f.obj.exists() and stage.exists(), result
    following = f.run("gc", "--project", "--collect-legacy", "--keep-days=0")
    assert following["exit"] == 0 and not f.obj.exists() and not stage.exists(), following
    f.log("real-forget-early-return", invocation=result, later_gc=following)
    for key in ["../outside", "--project", "a" * 40 + "/../outside", "$(touch SENTINEL)", "a" * 39]:
        result = f.run("gc", "--forget=" + key)
        assert result["exit"] != 0 and not (f.base / "SENTINEL").exists(), result
    f.log("argument-boundary", malformed_keys_refused=5, sentinel_absent=True)


def mount_child():
    for backing_closures in [False, True]:
        f = Fixture("unmount")
        p = f.base / "mountpoint"
        p.mkdir()
        if backing_closures:
            (p / ".blanket/closures").mkdir(parents=True)
        subprocess.run(["mount", "-t", "tmpfs", "tmpfs", str(p)], check=True)
        try:
            f.project("mountpoint")
            key = f.record(p)
            control = f.run("gc", "--keep-days=0")
            assert control["exit"] == 0 and f.obj.exists(), control
        finally:
            subprocess.run(["umount", str(p)], check=True)
        result = f.run("gc", "--project", "--keep-days=0")
        if backing_closures:
            assert result["exit"] == 0 and not f.obj.exists(), result
        else:
            assert result["exit"] != 0 and f.obj.exists(), result
        f.log("unmounted-with-backing-closures" if backing_closures else "unmounted-bare",
              control=control, sweep=result, live_object_deleted=not f.obj.exists(),
              record_survives=(f.store / "roots" / key).exists())


if __name__ == "__main__":
    if "--mount-child" in sys.argv:
        mount_child()
    else:
        registry_omissions()
        key_case()
        dry_register_and_preflight()
        unrelated_invalid_record()
        path_identity()
        blocking_paths_and_entrypoints()
        early_return_and_key_boundary()
        # Mount operations happen only in a new user/mount namespace.
        r = subprocess.run(["unshare", "-Urnm", sys.executable, str(Path(__file__).resolve()),
                            str(BIN), "--mount-child"], capture_output=True, text=True)
        print(r.stdout, end="")
        if r.returncode:
            print(json.dumps({"case": "mount-test-unavailable-or-failed", "exit": r.returncode,
                              "stderr": r.stderr}), flush=True)
            sys.exit(r.returncode)

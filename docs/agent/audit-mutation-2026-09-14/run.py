#!/usr/bin/env python3
"""Hand-rolled mutation check for src/commands/audit.rs.

Runs a clean baseline first, then applies one mutant at a time, runs the
audit test set, records the exit code and the first failing test, restores
the pristine copy and verifies the restore byte-for-byte before moving on.

Run from anywhere: `python3 docs/agent/audit-mutation-2026-09-14/run.py [M09 ...]`.
With no ids it runs every mutant in mutants.py. Logs go to a fresh temp dir
(printed at the end); honour TMPDIR so they land on a real disk.

Exit status: 0 only if the baseline was green and every requested mutant was
killed by a test failure. A red baseline, a compile error or other non-test
failure under a mutant, an unknown id, a non-unique snippet, a survivor, or a
restore mismatch all exit 1, so a wrong run cannot read as a clean one.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mutants import MUTANTS

# docs/agent/audit-mutation-2026-09-14/run.py -> repo root is three levels up.
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TARGET = f"{REPO}/src/commands/audit.rs"
# Scratch outside the tree: the pristine copy and one cargo log per mutant.
LOGDIR = tempfile.mkdtemp(prefix="audit-mutation-")
PRISTINE = f"{LOGDIR}/audit.rs.pristine"
CMD = ["cargo", "test", "--lib", "--test", "cli", "audit"]


def cargo(log):
    with open(log, "w") as fh:
        code = subprocess.call(CMD, cwd=REPO, stdout=fh, stderr=subprocess.STDOUT)
    with open(log) as fh:
        text = fh.read()
    fails = re.findall(r"^failures:\n((?:    \S+\n)+)", text, re.M)
    names = [n.strip() for b in fails for n in b.strip().split("\n")]
    non_test = code != 0 and not names
    return code, names, non_test


def restore_and_check(original):
    shutil.copyfile(PRISTINE, TARGET)
    with open(TARGET) as fh:
        restored = fh.read()
    if restored != original:
        print(f"RESTORE MISMATCH: {TARGET} differs from the pristine copy; stop")
        sys.exit(1)


def run(ids):
    known = {m[0] for m in MUTANTS}
    unknown = sorted(ids - known)
    if unknown:
        print(f"unknown mutant id(s): {', '.join(unknown)}")
        sys.exit(1)
    shutil.copyfile(TARGET, PRISTINE)
    with open(PRISTINE) as fh:
        original = fh.read()

    code, names, non_test = cargo(f"{LOGDIR}/baseline.log")
    if code != 0:
        why = "non-test failure (compile error?)" if non_test else f"failing tests: {names}"
        print(f"baseline is red (exit={code}, {why}); see {LOGDIR}/baseline.log")
        sys.exit(1)
    print(f"baseline exit=0 green", flush=True)

    results = []
    try:
        for mid, desc, old, new in MUTANTS:
            if ids and mid not in ids:
                continue
            count = original.count(old)
            if count != 1:
                print(f"{mid} snippet appears {count} times, must be exactly 1")
                results.append((mid, desc, "SNIPPET-ERROR", ""))
                continue
            with open(TARGET, "w") as fh:
                fh.write(original.replace(old, new, 1))
            code, names, non_test = cargo(f"{LOGDIR}/{mid}.log")
            restore_and_check(original)
            if non_test:
                with open(f"{LOGDIR}/{mid}.log") as fh:
                    text = fh.read()
                kind = "COMPILE-ERROR" if ("error[" in text or "could not compile" in text) else "NON-TEST-FAILURE"
                results.append((mid, desc, kind, ""))
                print(f"{mid} exit={code} {kind:8} {desc}", flush=True)
                continue
            first = ""
            if names:
                first = f"{names[0]} (+{len(names)-1} more)" if len(names) > 1 else names[0]
            status = "killed" if code != 0 else "SURVIVED"
            results.append((mid, desc, status, first))
            print(f"{mid} exit={code} {status:8} {first:60} {desc}", flush=True)
    finally:
        restore_and_check(original)
    bad = [r for r in results if r[2] != "killed"]
    print(f"\n{len(results)} mutants, {len(results)-len(bad)} killed, {len(bad)} not killed (logs: {LOGDIR})")
    for r in bad:
        print(f"  {r[2]} {r[0]} {r[1]}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    run(set(sys.argv[1:]))

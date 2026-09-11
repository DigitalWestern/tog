#!/usr/bin/env python3
"""Compare sealed A and mutant binaries, all against disposable stores.

Usage: python3 mutation_evidence.py /directory/containing/blanket-a-and-mutants
"""
from pathlib import Path
import shutil
import sys
import adversarial as a

S = Path(sys.argv[1]).resolve()

f = a.Fixture("M1-delete")
p = f.project()
key = f.record(p)
shutil.rmtree(p)
a.BIN = S / "blanket-a"
baseline = f.run("gc", "--project", "--keep-days=0")
assert baseline["exit"] != 0 and f.obj.exists() and (f.store / "roots" / key).exists()
a.BIN = S / "blanket-M1"
mutant = f.run("gc", "--project", "--keep-days=0")
assert mutant["exit"] == 0 and not f.obj.exists() and not (f.store / "roots" / key).exists()
f.log("M1-actual-deletion", baseline=baseline, mutant=mutant,
      mutant_deleted_object_and_record=True)

f = a.Fixture("M3-other-root")
live_key = f.record(f.project("live"))
missing = f.project("forgotten", live=False)
key = f.record(missing)
shutil.rmtree(missing)
a.BIN = S / "blanket-a"
baseline = f.run("gc", "--dry-run", "--forget", key, "--keep-days=0")
assert baseline["exit"] == 0 and "would remove object" not in baseline["stdout"], baseline
a.BIN = S / "blanket-M3"
mutant = f.run("gc", "--dry-run", "--forget", key, "--keep-days=0")
assert mutant["exit"] == 0 and "would remove object" in mutant["stdout"], mutant
assert f.obj.exists() and (f.store / "roots" / live_key).exists()
f.log("M3-other-root-ignored", baseline=baseline, mutant=mutant,
      other_live_root_ignored=True, dry_run_did_not_delete=True)

f = a.Fixture("M4-same-root")
p = f.project()
key = f.record(p)
a.BIN = S / "blanket-a"
baseline = f.run("gc", "--register", p, "--forget", key)
assert baseline["exit"] != 0 and (f.store / "roots" / key).exists()
a.BIN = S / "blanket-M4"
mutant = f.run("gc", "--register", p, "--forget", key)
assert mutant["exit"] == 0 and not (f.store / "roots" / key).exists()
f.log("M4-preflight-record-loss", baseline=baseline, mutant=mutant,
      mutant_deleted_record=True)

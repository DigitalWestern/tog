#!/usr/bin/env python3
"""Run mutations only inside this review's disposable isolated worktree."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

S = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
W = S / "isolated"
assert W.name == "isolated" and (W / ".git").is_file()
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=W, text=True).strip() == "9b11e05eb4422040f39a547fb0f14f82ff1aa1d4"
subprocess.run(["git", "diff", "HEAD", "--exit-code"], cwd=W, check=True, stdout=subprocess.DEVNULL)
ORIGINAL = {p: (W / p).read_text() for p in ["src/gc.rs", "src/main.rs", "src/store.rs"]}
ENV = dict(os.environ, TMPDIR=(S / "a-tmp-path").read_text().strip(),
           BLANKET_SANDBOX_TESTS="required")
ENV["BLANKET_STORE"] = ENV["TMPDIR"] + "/mutation-default-store"
SUMMARY = []


def command(name, args):
    with (S / (name + ".log")).open("w") as log:
        r = subprocess.run(["cargo", *args, "--offline", "--target-dir", str(S / "target-a")],
                           cwd=W, env=ENV, stdout=log, stderr=subprocess.STDOUT)
    SUMMARY.append({"command": name, "exit": r.returncode})
    print(json.dumps(SUMMARY[-1]), flush=True)
    return r.returncode


def test(name, args):
    # Cargo flags must precede the test runner's `--`.
    with (S / (name + ".log")).open("w") as log:
        r = subprocess.run(["cargo", "test", "--offline", "--target-dir", str(S / "target-a"), *args],
                           cwd=W, env=ENV, stdout=log, stderr=subprocess.STDOUT)
    SUMMARY.append({"command": name, "exit": r.returncode})
    print(json.dumps(SUMMARY[-1]), flush=True)
    return r.returncode


def reset():
    for p, text in ORIGINAL.items():
        (W / p).write_text(text)


def mutate(name, p, text):
    reset()
    assert text != ORIGINAL[p]
    (W / p).write_text(text)
    patch = subprocess.check_output(["git", "diff", "--", p], cwd=W)
    (S / (name + ".patch")).write_bytes(patch)


try:
    if not (S / "blanket-a").exists():
        assert command("baseline-build", ["build"]) == 0
        shutil.copy2(S / "target-a/debug/blanket", S / "blanket-a")
    g = ORIGINAL["src/gc.rs"]
    a = g.index("        // A root whose project cannot be resolved")
    b = g.index("        let project = root\n", a)
    old = '''        let closures = root.path.join(".blanket/closures");
        if !root.path.is_dir() || !closures.is_dir() {
            if !options.dry_run {
                store.remove_root_entry(root)?;
            }
            continue;
        }
'''
    mutate("M1-stale-root-drop", "src/gc.rs", g[:a] + old + g[b:])
    assert test("M1-gc-tests", ["--lib", "gc::tests"]) == 101
    assert command("M1-build", ["build"]) == 0
    shutil.copy2(S / "target-a/debug/blanket", S / "blanket-M1")

    needle = '''        if options.forgotten.iter().any(|key| key == &root.key) {
            continue;
        }
'''
    assert g.count(needle) == 1
    mutate("M2-remove-forgotten-filter", "src/gc.rs", g.replace(needle, ""))
    assert test("M2-gc-tests", ["--lib", "gc::tests"]) == 101

    mutate("M3-ignore-all-roots", "src/gc.rs",
           g.replace("options.forgotten.iter().any(|key| key == &root.key)", "!options.forgotten.is_empty()"))
    assert test("M3-full-suite", []) == 0
    assert test("M3-A-integration", ["--test", "gc", "gc_keeps_deleted_node_project_until_forgotten", "--", "--ignored"]) == 0
    shutil.copy2(S / "target-a/debug/blanket", S / "blanket-M3")

    m = ORIGINAL["src/main.rs"]
    a = m.index("    // Registering and forgetting the same root")
    b = m.index("    for project in &args.register {\n        let entry = store.register_root(project)?;", a)
    mutate("M4-remove-preflight", "src/main.rs", m[:a] + m[b:])
    assert test("M4-full-suite", []) == 0
    assert test("M4-A-integration", ["--test", "gc", "gc_keeps_deleted_node_project_until_forgotten", "--", "--ignored"]) == 0
    shutil.copy2(S / "target-a/debug/blanket", S / "blanket-M4")

    needle = '''    if !options.dry_run && !args.forget.is_empty() {
        return Ok(());
    }
'''
    assert m.count(needle) == 1
    mutate("M5-remove-early-return", "src/main.rs", m.replace(needle, ""))
    assert test("M5-A-integration", ["--test", "gc", "gc_keeps_deleted_node_project_until_forgotten", "--", "--ignored"]) == 101

    s = ORIGINAL["src/store.rs"]
    mutate("M6-remove-key-validation", "src/store.rs", s.replace("        Self::validate_root_key(key)?;\n", ""))
    assert test("M6-forget-tests", ["--lib", "gc::tests::forget_rejects_unknown_and_malformed_keys"]) == 101
finally:
    reset()
    (S / "mutation-summary.json").write_text(json.dumps(SUMMARY, indent=2) + "\n")
    subprocess.run(["git", "diff", "HEAD", "--exit-code"], cwd=W, check=True)

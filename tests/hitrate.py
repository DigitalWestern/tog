#!/usr/bin/env python3
"""Hit-rate measurement (NEXT.md item 1): does `blanket sync` work, zero
config, on a random popular real project?

    python3 tests/hitrate.py [--n 30] [--out hitrate.csv] [--timeout 600]

Picks the top-starred non-archived GitHub repos per ecosystem that carry a
manifest (python: requirements.txt/pyproject.toml/setup.py; npm:
package.json), shallow-clones each into a scratch dir, runs the release
binary's `sync` with a throwaway BLANKET_STORE, and records outcome +
failure class. Everything but the toolchain objects is pruned from the
store between repos so the run fits in a few GB of disk.
"""
import argparse, csv, json, os, re, shutil, signal, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLANKET = os.path.join(ROOT, "target/release/blanket")
TOOLCHAIN = ("-cpython-", "-nodejs-", "-uv-")
SKIP_NAMES = re.compile(
    r"awesome|interview|cheat|roadmap|tutorial|book|course|system-design|"
    r"public-apis|free-|handbook|guide|curriculum|challenge|30-|100-|"
    r"algorithm|learn|examples|docs$|javascript-questions|clean-code",
    re.I,
)

# (class, regex over the combined stderr tail); first match wins.
CLASSES = [
    ("no_inputs", r"nothing to sync here"),
    ("py_editable", r"editable requirements"),
    ("py_markers", r"environment markers are not supported"),
    ("py_extras", r"extras are not supported"),
    ("py_req_option", r"unsupported option in requirements"),
    ("py_uv_resolve_failed", r"uv pip compile failed"),
    ("py_sdist_build_failed", r"sdist|build backend|setup\.py"),
    ("py_no_wheel", r"no compatible|no wheel|no artifact"),
    ("npm_ws_nested", r"nested inside workspace"),
    ("npm_git_or_file_dep", r"resolved.*(git|file|must be https)|'resolved' URL|non-https"),
    ("npm_lockfile_v1", r"unsupported lockfileVersion"),
    ("npm_resolve_failed", r"npm install --package-lock-only failed"),
    ("npm_lock_stale", r"lock.*(stale|out of date|does not match)|freshness"),
    ("npm_platform", r"does not support darwin/arm64"),
    ("npm_script_failed", r"script.*(failed|exit)|postinstall|preinstall|node-gyp"),
    ("npm_bad_lock_path", r"malformed lockfile package path|unsafe link"),
    ("npm_too_big", r"expands past 1 GiB"),
    ("fetch_failed", r"fetch .*: |sha256 mismatch|hash mismatch"),
]


def gh_json(path, **params):
    args = ["gh", "api", "-X", "GET", path]
    for k, v in params.items():
        args += ["-f", f"{k}={v}"]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def has_file(full, names):
    for n in names:
        r = subprocess.run(
            ["gh", "api", f"repos/{full}/contents/{n}"], capture_output=True, text=True
        )
        if r.returncode == 0:
            return True
    return False


def pick(lang, n, manifests):
    """Top-starred repos with a manifest at the root, skipping list-repos."""
    langs = {"python": ["python"], "npm": ["typescript", "javascript"]}[lang]
    seen, out = set(), []
    for l in langs:
        for page in (1, 2):
            items = gh_json(
                "search/repositories",
                q=f"language:{l} archived:false stars:>5000",
                sort="stars", order="desc", per_page="50", page=str(page),
            )["items"]
            for it in items:
                full = it["full_name"]
                if full in seen or SKIP_NAMES.search(full) or it["size"] > 300_000:
                    continue
                seen.add(full)
                out.append((it["stargazers_count"], full))
    out.sort(reverse=True)
    chosen = []
    for stars, full in out:
        if len(chosen) >= n:
            break
        if has_file(full, manifests):
            chosen.append((full, stars))
            print(f"  pick {lang}: {full} ({stars}★)", file=sys.stderr)
    return chosen


def free_gb(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize / 1e9


def rm_rf(path):
    if os.path.lexists(path):
        subprocess.run(["chmod", "-R", "u+w", path], capture_output=True)
        shutil.rmtree(path, ignore_errors=True)


def prune_store(store):
    """Keep only toolchain objects (+ their meta); drop envs, cache, forests."""
    objs = os.path.join(store, "objects")
    keep = set()
    if os.path.isdir(objs):
        for name in os.listdir(objs):
            if any(t in name for t in TOOLCHAIN):
                keep.add(name)
            else:
                rm_rf(os.path.join(objs, name))
    meta = os.path.join(store, "meta")
    if os.path.isdir(meta):
        for name in os.listdir(meta):
            if name[:-5] not in keep:
                os.remove(os.path.join(meta, name))
    for d in ("cache", "forests", "backups", "tmp", "planner"):
        rm_rf(os.path.join(store, d))


def run_timed(args, cwd, env, timeout):
    """Run in its own process group so a timeout kills the whole tree."""
    t0 = time.time()
    p = subprocess.Popen(
        args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, start_new_session=True,
    )
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out, time.time() - t0
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return "timeout", out, time.time() - t0


def classify(rc, out):
    if rc == 0:
        return "ok"
    if rc == "timeout":
        return "timeout"
    for name, rx in CLASSES:
        if re.search(rx, out, re.I):
            return name
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out", default="hitrate.csv")
    ap.add_argument("--work", default=os.environ.get("HITRATE_WORK", "/tmp/blanket-hitrate"))
    ap.add_argument("--only", choices=["python", "npm"])
    ap.add_argument("--repos", help="file of '<lang> <owner/name>' lines (skips GitHub search)")
    a = ap.parse_args()

    if not os.path.exists(BLANKET):
        sys.exit(f"build first: cargo build --release ({BLANKET} missing)")
    os.makedirs(a.work, exist_ok=True)
    store = os.path.join(a.work, "store")
    env = dict(os.environ, BLANKET_STORE=store, GIT_TERMINAL_PROMPT="0")

    manifests = {
        "python": ["requirements.txt", "pyproject.toml", "setup.py"],
        "npm": ["package.json"],
    }
    targets = []
    if a.repos:
        for line in open(a.repos):
            if line.strip() and not line.startswith("#"):
                lang, full = line.split()
                targets.append((lang, full, 0))
    else:
        for lang in ("python", "npm"):
            if a.only and lang != a.only:
                continue
            targets += [(lang, full, stars) for full, stars in pick(lang, a.n, manifests[lang])]

    done = set()
    if os.path.exists(a.out):
        with open(a.out) as f:
            done = {r["repo"] for r in csv.DictReader(f)}
    new = not done
    fout = open(a.out, "a", newline="")
    w = csv.writer(fout)
    if new:
        w.writerow(["lang", "repo", "stars", "status", "class", "seconds", "inputs", "error"])

    for lang, full, stars in targets:
        if full in done:
            continue
        if free_gb(a.work) < 3:
            print(f"ABORT: <3GB free on disk before {full}", file=sys.stderr)
            break
        clone = os.path.join(a.work, "repo")
        rm_rf(clone)
        print(f"== {lang} {full}", file=sys.stderr)
        rc, out, secs = run_timed(
            ["git", "clone", "--depth", "1", "--quiet", f"https://github.com/{full}.git", clone],
            a.work, env, 300,
        )
        if rc != 0:
            w.writerow([lang, full, stars, "fail", "clone_failed", f"{secs:.0f}", "", out.strip()[-300:]])
            fout.flush()
            continue
        inputs = ",".join(
            n for n in ["requirements.txt", "pyproject.toml", "setup.py", "package.json",
                        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"]
            if os.path.exists(os.path.join(clone, n))
        )
        rc, out, secs = run_timed([BLANKET, "sync"], clone, env, a.timeout)
        cls = classify(rc, out)
        err = ""
        if cls != "ok":
            lines = [l for l in out.strip().splitlines() if l.strip()]
            errl = [l for l in lines if "error" in l.lower()]
            err = (errl[-1] if errl else (lines[-1] if lines else ""))[:400]
        status = "ok" if cls == "ok" else "fail"
        print(f"   -> {status} {cls} {secs:.0f}s {err}", file=sys.stderr)
        w.writerow([lang, full, stars, status, cls, f"{secs:.0f}", inputs, err])
        fout.flush()
        rm_rf(clone)
        prune_store(store)

    fout.close()
    # Summary
    rows = list(csv.DictReader(open(a.out)))
    for lang in ("python", "npm"):
        rs = [r for r in rows if r["lang"] == lang]
        if not rs:
            continue
        ok = sum(r["status"] == "ok" for r in rs)
        print(f"\n{lang}: {ok}/{len(rs)} ok ({100 * ok // len(rs)}%)")
        counts = {}
        for r in rs:
            counts[r["class"]] = counts.get(r["class"], 0) + 1
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {v:3d}  {k}")


if __name__ == "__main__":
    main()

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
import argparse, csv, glob, json, os, re, shutil, signal, stat, subprocess, sys, time

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
    ("platform_unsupported", r"LINUX_PORT\.md"),
    ("no_inputs", r"nothing to sync here"),
    ("py_editable", r"editable requirements"),
    ("py_markers", r"environment markers are not supported"),
    ("py_extras", r"extras are not supported"),
    ("py_req_option", r"unsupported option in requirements"),
    ("py_uv_resolve_failed", r"uv pip compile failed"),
    ("py_sdist_build_failed", r"sdist|build backend|setup\.py|sandbox-exec|bwrap|xcrun|clang|gcc|cc1plus|glibc"),
    ("py_no_wheel", r"no compatible|no wheel|no artifact|manylinux|x86_64-unknown-linux-gnu"),
    ("npm_ws_nested", r"nested inside workspace"),
    ("npm_git_or_file_dep", r"resolved.*(git|file|must be https)|'resolved' URL|non-https"),
    ("npm_lockfile_v1", r"unsupported lockfileVersion"),
    ("npm_resolve_failed", r"npm install --package-lock-only failed"),
    ("npm_lock_stale", r"lock.*(stale|out of date|does not match)|freshness"),
    ("npm_platform", r"does not support (darwin/arm64|linux/(x64|amd64))|macosx|arm64|manylinux|x86_64-unknown-linux-gnu"),
    ("npm_script_failed", r"script.*(failed|exit)|postinstall|preinstall|node-gyp|sandbox-exec|bwrap|xcrun|clang|gcc|cc1plus|glibc"),
    ("npm_bad_lock_path", r"malformed lockfile package path|unsafe link"),
    ("npm_too_big", r"expands past 1 GiB"),
    ("fetch_failed", r"fetch .*: |sha256 mismatch|hash mismatch"),
]

CSV_COLUMNS = [
    "lang", "repo", "stars", "status", "class", "seconds", "inputs", "error",
    "exceptions", "exception_kinds", "platform", "blanket_commit",
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
    if not os.path.lexists(path):
        return
    if not os.path.isdir(path) or os.path.islink(path):
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return

    # Store objects are read-only trees (files AND directories); a
    # per-file onerror chmod is not enough because unlink needs write
    # permission on the parent directory. Make the whole tree writable
    # first, without following symlinks.
    for root, dirs, files in os.walk(path, topdown=True):
        for name in dirs + files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                try:
                    os.chmod(full, stat.S_IRWXU)
                except FileNotFoundError:
                    pass
    try:
        os.chmod(path, stat.S_IRWXU)
    except FileNotFoundError:
        return

    def remove_readonly(func, name, _exc):
        try:
            os.chmod(name, stat.S_IRWXU)
            func(name)
        except FileNotFoundError:
            pass

    shutil.rmtree(path, onerror=remove_readonly)


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
                rm_rf(os.path.join(meta, name))
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


def read_repos(path):
    targets = []
    with open(path, newline="") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 3 or fields[0] not in ("python", "npm"):
                raise ValueError(
                    f"{path}:{lineno}: expected ecosystem<TAB>owner/name<TAB>commit"
                )
            lang, full, commit = fields
            if not re.fullmatch(r"[^/\s]+/[^/\s]+", full):
                raise ValueError(f"{path}:{lineno}: invalid repository {full!r}")
            if not commit:
                raise ValueError(f"{path}:{lineno}: empty commit")
            targets.append((lang, full, 0, commit))
    return targets


def uname_platform():
    result = subprocess.run(["uname", "-sm"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def platform_from_text(text):
    if re.search(r"x86_64-unknown-linux-gnu", text, re.I):
        return "x86_64-unknown-linux-gnu"
    if re.search(r"aarch64-apple-darwin", text, re.I):
        return "aarch64-apple-darwin"
    if re.search(r"(?:linux/(?:x64|amd64)|linux-x64|manylinux)", text, re.I):
        return "linux-x64"
    if re.search(r"(?:darwin/arm64|darwin-arm64|macosx.*arm64)", text, re.I):
        return "darwin-arm64"
    return ""


def platform_from_closures(project):
    values = []
    for path in glob.glob(os.path.join(project, ".blanket", "closure*.json")):
        values.append(path)
    values += glob.glob(os.path.join(project, ".blanket", "closures", "*.json"))
    for path in values:
        try:
            with open(path) as f:
                value = json.load(f)
        except (OSError, ValueError):
            continue

        def find_platform(node):
            if isinstance(node, dict):
                if isinstance(node.get("platform"), str) and node["platform"]:
                    return node["platform"]
                for child in node.values():
                    found = find_platform(child)
                    if found:
                        return found
            elif isinstance(node, list):
                for child in node:
                    found = find_platform(child)
                    if found:
                        return found
            return ""

        found = find_platform(value)
        if found:
            return found
    return ""


def exceptions_from_closures(project):
    paths = set(glob.glob(os.path.join(project, ".blanket", "closure*.json")))
    paths.update(glob.glob(os.path.join(project, ".blanket", "closures", "*.json")))
    kinds = []
    for path in sorted(paths):
        try:
            with open(path) as f:
                value = json.load(f)
        except (OSError, ValueError):
            continue
        records = value.get("body", {}).get("exceptions", [])
        if not isinstance(records, list):
            records = value.get("exceptions", [])
        if not isinstance(records, list):
            continue
        kinds += [record["kind"] for record in records
                  if isinstance(record, dict) and isinstance(record.get("kind"), str)]
    return len(kinds), ",".join(kinds)


def blanket_commit():
    result = subprocess.run(
        ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def sync_repo(full, commit, clone, work, env):
    url = f"https://github.com/{full}.git"
    if commit == "HEAD":
        return run_timed(
            ["git", "clone", "--depth", "1", "--quiet", url, clone],
            work, env, 300,
        )
    t0 = time.time()
    commands = [
        (["git", "init", "--quiet", clone], work),
        (["git", "-C", clone, "remote", "add", "origin", url], work),
        (["git", "-C", clone, "fetch", "--depth", "1", "origin", commit], work),
        (["git", "-C", clone, "checkout", "--quiet", "FETCH_HEAD"], work),
    ]
    output = []
    for command, cwd in commands:
        rc, out, _ = run_timed(command, cwd, env, 300)
        output.append(out)
        if rc != 0:
            return rc, "".join(output), time.time() - t0
    return 0, "".join(output), time.time() - t0


def retain_failure(clone, work, lang, full):
    if not os.path.lexists(clone):
        return
    failures = os.path.join(work, "failures")
    os.makedirs(failures, exist_ok=True)
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{lang}-{full}")
    target = os.path.join(failures, label)
    suffix = 2
    while os.path.lexists(target):
        target = os.path.join(failures, f"{label}-{suffix}")
        suffix += 1
    shutil.move(clone, target)


def read_rows(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        lines = [line for line in f if line.strip() and not line.startswith("#")]
    return list(csv.DictReader(lines)) if lines else []


def dry_run(targets, work):
    print(f"work: {work}")
    for lang, full, _stars, commit in targets:
        clone = os.path.join(work, "repo")
        if commit == "HEAD":
            git = f"git clone --depth 1 https://github.com/{full}.git {clone}"
        else:
            git = (
                f"git init {clone}; git -C {clone} remote add origin "
                f"https://github.com/{full}.git; git -C {clone} fetch --depth 1 "
                f"origin {commit}; git -C {clone} checkout FETCH_HEAD"
            )
        print(f"{lang}\t{full}\t{commit}")
        print(f"  {git}")
        print(f"  BLANKET_STORE={os.path.join(work, 'store')} {BLANKET} sync")


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
    ap.add_argument("--repos", help="tab-separated '<ecosystem>\t<owner/name>\t<commit>' file")
    ap.add_argument("--dry-run", action="store_true", help="print planned commands without touching disk or network")
    ap.add_argument("--keep", action="store_true", help="retain failed clones under WORK/failures")
    a = ap.parse_args()

    manifests = {
        "python": ["requirements.txt", "pyproject.toml", "setup.py"],
        "npm": ["package.json"],
    }
    targets = []
    if a.repos:
        try:
            targets = read_repos(a.repos)
        except (OSError, ValueError) as e:
            ap.error(str(e))
    else:
        if a.dry_run:
            ap.error("--dry-run requires --repos so it does not perform GitHub searches")
        for lang in ("python", "npm"):
            if a.only and lang != a.only:
                continue
            targets += [(lang, full, stars, "HEAD") for full, stars in pick(lang, a.n, manifests[lang])]

    if a.only:
        targets = [target for target in targets if target[0] == a.only]
    # --n is per ecosystem, matching the GitHub-search behavior. The lock
    # file remains the complete 60-repo population when --n is omitted/default.
    limited = []
    for lang in ("python", "npm"):
        limited += [target for target in targets if target[0] == lang][:a.n]
    targets = limited

    if a.dry_run:
        dry_run(targets, a.work)
        return

    if not os.path.exists(BLANKET):
        sys.exit(f"build first: cargo build --release ({BLANKET} missing)")
    os.makedirs(a.work, exist_ok=True)
    store = os.path.join(a.work, "store")
    env = dict(os.environ, BLANKET_STORE=store, GIT_TERMINAL_PROMPT="0")
    run_platform = uname_platform()
    tool_commit = blanket_commit()

    done = set()
    rows = read_rows(a.out)
    if rows:
        old_columns = set(rows[0])
        if old_columns != set(CSV_COLUMNS):
            sys.exit(f"existing output {a.out} has an old header; choose a new --out path")
        done = {r["repo"] for r in rows}
    new = not os.path.exists(a.out) or os.path.getsize(a.out) == 0
    fout = open(a.out, "a", newline="")
    w = csv.writer(fout)
    if new:
        fout.write(f"# platform={run_platform} blanket_commit={tool_commit}\n")
        w.writerow(CSV_COLUMNS)

    for lang, full, stars, commit in targets:
        if full in done:
            continue
        if free_gb(a.work) < 3:
            print(f"ABORT: <3GB free on disk before {full}", file=sys.stderr)
            break
        clone = os.path.join(a.work, "repo")
        rm_rf(clone)
        print(f"== {lang} {full}", file=sys.stderr)
        failed = True
        try:
            rc, out, secs = sync_repo(full, commit, clone, a.work, env)
            if rc != 0:
                cls, status = "clone_failed", "fail"
                inputs = ""
                exceptions, exception_kinds = 0, ""
                err = out.strip()[-300:]
            else:
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
                exceptions, exception_kinds = (
                    exceptions_from_closures(clone) if rc == 0 else (0, "")
                )
                failed = status != "ok"
            platform = platform_from_closures(clone) or platform_from_text(out) or run_platform
            print(f"   -> {status} {cls} {secs:.0f}s {err}", file=sys.stderr)
            w.writerow([
                lang, full, stars, status, cls, f"{secs:.0f}", inputs, err,
                exceptions, exception_kinds, platform, tool_commit,
            ])
            fout.flush()
        finally:
            if failed and a.keep:
                retain_failure(clone, a.work, lang, full)
            else:
                rm_rf(clone)
            prune_store(store)

    fout.close()
    # Summary
    rows = read_rows(a.out)
    print(f"\nplatform: {run_platform}")
    print(f"blanket_commit: {tool_commit}")
    for lang in ("python", "npm"):
        rs = [r for r in rows if r["lang"] == lang]
        if not rs:
            continue
        ok = sum(r["status"] == "ok" and int(r.get("exceptions", 0) or 0) == 0 for r in rs)
        ok_with_exceptions = sum(
            r["status"] == "ok" and int(r.get("exceptions", 0) or 0) > 0 for r in rs
        )
        print(f"\n{lang}: {ok + ok_with_exceptions}/{len(rs)} syncs ok ({100 * (ok + ok_with_exceptions) // len(rs)}%)")
        print(f"  ok: {ok}")
        print(f"  ok_with_exceptions: {ok_with_exceptions}")
        counts = {}
        for r in rs:
            for kind in filter(None, r.get("exception_kinds", "").split(",")):
                counts[kind] = counts.get(kind, 0) + 1
        if counts:
            print("  exception kinds:")
        for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"    {v:3d}  {k}")
        counts = {}
        for r in rs:
            counts[r["class"]] = counts.get(r["class"], 0) + 1
        print("  failure classes:")
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"    {v:3d}  {k}")
    usage = shutil.disk_usage(a.work)
    print(
        f"\ndisk: {usage.used / 1e9:.2f} GB used, "
        f"{usage.free / 1e9:.2f} GB free ({usage.total / 1e9:.2f} GB total)"
    )


if __name__ == "__main__":
    main()

#!/bin/bash
# Blanket acceptance tests (Sol's checklist, MVP subset).
# Runs the real binary against real PyPI with a throwaway store.
set -euo pipefail

BLANKET="$(cd "$(dirname "$0")/.." && pwd)/target/debug/blanket"
FIXTURES="$(cd "$(dirname "$0")/fixtures" && pwd)"
WORK="$(mktemp -d /tmp/blanket-accept.XXXXXX)"
export BLANKET_STORE="$WORK/store"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

cp -R "$FIXTURES/proj-a" "$WORK/a"
cp -R "$FIXTURES/proj-b" "$WORK/b"

echo "== 1. sync + run (proj-a: markupsafe 3.0.2 + six)"
(cd "$WORK/a" && "$BLANKET" sync)
V=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe, six; print(markupsafe.__version__)')
[ "$V" = "3.0.2" ] && ok "imports work, correct version ($V)" || bad "got '$V'"

echo "== 2. conflicting versions coexist (proj-b: markupsafe 2.1.5)"
(cd "$WORK/b" && "$BLANKET" sync)
VB=$(cd "$WORK/b" && "$BLANKET" run python -c 'import markupsafe; print(markupsafe.__version__)')
VA=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe; print(markupsafe.__version__)')
[ "$VB" = "2.1.5" ] && [ "$VA" = "3.0.2" ] && ok "a=$VA b=$VB simultaneously" || bad "a=$VA b=$VB"

echo "== 3. second sync of identical lock is a cache hit (same object, no re-download)"
cp -R "$FIXTURES/proj-a" "$WORK/a2"
ENV_A=$(readlink "$WORK/a/.venv")
T0=$(date +%s)
(cd "$WORK/a2" && "$BLANKET" sync)
T1=$(date +%s)
ENV_A2=$(readlink "$WORK/a2/.venv")
[ "$ENV_A" = "$ENV_A2" ] && ok "identical env object reused: $(basename "$ENV_A")" || bad "objects differ"
[ $((T1-T0)) -le 5 ] && ok "resync fast (${T1}s-${T0}s)" || bad "resync slow: $((T1-T0))s"

echo "== 4. offline reconstruction: delete projection, resync with network denied"
rm -f "$WORK/a/.venv"
if (cd "$WORK/a" && sandbox-exec -p '(version 1)(allow default)(deny network*)' "$BLANKET" sync); then
  V=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe; print(markupsafe.__version__)')
  [ "$V" = "3.0.2" ] && ok "reconstructed offline" || bad "offline env broken: $V"
else
  bad "offline resync failed (network dependency in resync path)"
fi

echo "== 5. lock change swaps env atomically; python toolchain object unchanged"
PYOBJ_BEFORE=$(ls "$BLANKET_STORE/objects" | grep cpython)
cp "$WORK/b/requirements.txt" "$WORK/a/requirements.txt"
(cd "$WORK/a" && "$BLANKET" sync)
V=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe; print(markupsafe.__version__)')
[ "$V" = "2.1.5" ] && ok "env switched to new lock" || bad "got $V"
PYOBJ_AFTER=$(ls "$BLANKET_STORE/objects" | grep cpython)
[ "$PYOBJ_BEFORE" = "$PYOBJ_AFTER" ] && ok "cpython object untouched by lock change" || bad "cpython object churned"

echo "== 6. rollback: restoring old lock is an instant cache hit"
cp "$FIXTURES/proj-a/requirements.txt" "$WORK/a/requirements.txt"
T0=$(date +%s)
(cd "$WORK/a" && "$BLANKET" sync)
T1=$(date +%s)
V=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe; print(markupsafe.__version__)')
[ "$V" = "3.0.2" ] && [ $((T1-T0)) -le 5 ] && ok "rolled back in $((T1-T0))s" || bad "v=$V t=$((T1-T0))s"

echo "== 7. store objects are immutable"
OBJ="$BLANKET_STORE/objects/$(basename "$ENV_A")"
if touch "$OBJ/tamper" 2>/dev/null; then bad "store object writable"; rm -f "$OBJ/tamper"; else ok "write into store object refused"; fi

echo "== 8. sdist builds in a network-denied sandbox (docopt, sdist-only on PyPI)"
cp -R "$FIXTURES/proj-c" "$WORK/c"
if (cd "$WORK/c" && "$BLANKET" sync); then
  OUT=$(cd "$WORK/c" && "$BLANKET" run python -c 'import docopt; print(docopt.__version__)')
  [ "$OUT" = "0.6.2" ] && ok "sdist built + importable ($OUT)" || bad "docopt import: $OUT"
else
  bad "sdist sync failed"
fi

echo "== 9. a build that attempts network access fails (evil sdist fixture)"
if (cd "$(dirname "$0")/.." && cargo test --quiet --test sandbox_deny -- --ignored) ; then
  ok "network egress during build was denied"
else
  bad "evil build did not fail as required"
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]

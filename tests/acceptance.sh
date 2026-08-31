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

echo "== 4a. offline reprojection: delete only .venv, resync with network denied"
rm -f "$WORK/a/.venv"
if (cd "$WORK/a" && sandbox-exec -p '(version 1)(allow default)(deny network*)' "$BLANKET" sync); then
  V=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe; print(markupsafe.__version__)')
  [ "$V" = "3.0.2" ] && ok "reprojected offline" || bad "offline env broken: $V"
else
  bad "offline reprojection failed"
fi

echo "== 4b. offline RECONSTRUCTION: delete env objects, rebuild from artifact cache"
rm -f "$WORK/a/.venv"
chmod -R u+w "$BLANKET_STORE/objects"
for o in "$BLANKET_STORE/objects"/*env*; do rm -rf "$o"; done
rm -f "$BLANKET_STORE"/meta/*env*.json
if (cd "$WORK/a" && sandbox-exec -p '(version 1)(allow default)(deny network*)' "$BLANKET" sync); then
  V=$(cd "$WORK/a" && "$BLANKET" run python -c 'import markupsafe, six; print(markupsafe.__version__)')
  [ "$V" = "3.0.2" ] && ok "env object rebuilt offline from verified artifact cache" || bad "rebuilt env broken: $V"
else
  bad "offline reconstruction failed (resync needed network)"
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

echo "== 9b. npm install scripts: sandboxed, network access fails closed"
if (cd "$(dirname "$0")/.." && cargo test --quiet --test npm_scripts -- --ignored) ; then
  ok "install scripts run hermetically; network egress denied"
else
  bad "npm script sandbox tests failed"
fi

echo "== 10. npm: lockfile -> immutable node_modules, store-provisioned node"
cp -R "$FIXTURES/proj-npm" "$WORK/n"
(cd "$WORK/n" && "$BLANKET" sync)
OUT=$(cd "$WORK/n" && "$BLANKET" run node index.js)
[ "$OUT" = "is-odd(3): true" ] && ok "npm deps resolve + run ($OUT)" || bad "got '$OUT'"
NV=$(cd "$WORK/n" && "$BLANKET" run node -e 'console.log(process.version)')
[ "$NV" = "v24.20.0" ] && ok "node came from the store ($NV)" || bad "node version: $NV"
# Forest contract: the node_modules TOP LEVEL is writable scratch space
# (vite/.prisma caches), while package CONTENTS stay immutable in the store.
if touch "$WORK/n/node_modules/.scratch" 2>/dev/null; then ok "node_modules top level writable (forest)"; else bad "forest top level not writable"; fi
if touch "$WORK/n/node_modules/is-odd/tamper" 2>/dev/null; then bad "package contents writable"; else ok "package contents immutable"; fi

echo "== 10b. declared mutable packages: clone projection, writable, unattested"
cp -R "$FIXTURES/proj-npm" "$WORK/nm"
(cd "$WORK/nm" && node -e "const p=require('./package.json'); p.blanket={mutablePackages:['is-odd']}; require('fs').writeFileSync('package.json', JSON.stringify(p))" 2>/dev/null \
  || python3 -c "import json;p=json.load(open('$WORK/nm/package.json'));p['blanket']={'mutablePackages':['is-odd']};json.dump(p,open('$WORK/nm/package.json','w'))")
(cd "$WORK/nm" && "$BLANKET" sync)
if touch "$WORK/nm/node_modules/is-odd/scratch" 2>/dev/null; then ok "declared mutable package is writable"; else bad "mutable package not writable"; fi
grep -q '"mutable_state": "unattested"' "$WORK/nm/.blanket/node-closure.json" && ok "closure records unattested mutable state" || bad "closure missing mutable_state"

echo "== 10c. cargo: vendor projection + sandboxed build + offline rebuild"
cp -R "$FIXTURES/cargo-hello" "$WORK/cargo"
(cd "$WORK/cargo" && "$BLANKET" sync)
(cd "$WORK/cargo" && "$BLANKET" build)
OUT=$(cd "$WORK/cargo" && "$BLANKET" run target/debug/cargo-hello)
[ "$OUT" = "hello 128" ] && ok "cargo build + run ($OUT)" || bad "cargo output: $OUT"
# blanket build itself runs cargo inside the network-denied sandbox (an
# outer sandbox-exec cannot nest); a clean-target rebuild proves the store
# serves everything.
rm -rf "$WORK/cargo/target"
if (cd "$WORK/cargo" && "$BLANKET" build); then
  ok "cargo rebuild from store (sandboxed, network-denied)"
else
  bad "cargo rebuild failed"
fi

echo "== 11. polyglot project: python + node from one sync, one kernel"
cp -R "$FIXTURES/proj-poly" "$WORK/p"
(cd "$WORK/p" && "$BLANKET" sync)
PY=$(cd "$WORK/p" && "$BLANKET" run python -c 'import six; print(six.__version__)')
JS=$(cd "$WORK/p" && "$BLANKET" run node index.js)
[ "$PY" = "1.17.0" ] && [ "$JS" = "is-odd(3): true" ] && ok "both ecosystems projected (py six=$PY, $JS)" || bad "py=$PY js=$JS"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]

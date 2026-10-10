#!/bin/bash
# Tog acceptance tests (Sol's checklist, MVP subset).
# Runs the real binary against real PyPI with a throwaway store.
set -euo pipefail

TOG="$(cd "$(dirname "$0")/.." && pwd)/target/debug/tog"
FIXTURES="$(cd "$(dirname "$0")/fixtures" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tog-accept.XXXXXX")"
export TOG_STORE="$WORK/store"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
# A throwaway home, so the developer's or runner's ~/.tog is never read or
# written.
export HOME="$WORK/home"
mkdir -p "$HOME"
# audit trusts only signed closures: every sync here signs with a throwaway
# key, and the machine policy (TOG_POLICY) trusts it.
"$TOG" keygen "$WORK/signing.key" > "$WORK/policy.toml"
export TOG_SIGNING_KEY="$WORK/signing.key"
export TOG_POLICY="$WORK/policy.toml"

pass=0; fail=0

# Network-denied wrapper for the offline checks: Seatbelt on macOS, a user +
# network namespace on Linux (unshare -rn).
deny_net() {
  case "$(uname -s)" in
    Darwin) sandbox-exec -p '(version 1)(allow default)(deny network*)' "$@" ;;
    Linux)  unshare -rn "$@" ;;
    *) echo "deny_net: unsupported OS" >&2; return 1 ;;
  esac
}
ok()   { pass=$((pass+1)); echo "  ok: $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL: $1"; }

cp -R "$FIXTURES/proj-a" "$WORK/a"
cp -R "$FIXTURES/proj-b" "$WORK/b"

echo "== 1. sync + run (proj-a: markupsafe 3.0.2 + six)"
(cd "$WORK/a" && "$TOG" sync)
V=$(cd "$WORK/a" && "$TOG" run python -c 'import markupsafe, six; print(markupsafe.__version__)')
[ "$V" = "3.0.2" ] && ok "imports work, correct version ($V)" || bad "got '$V'"

echo "== 2. conflicting versions coexist (proj-b: markupsafe 2.1.5)"
(cd "$WORK/b" && "$TOG" sync)
VB=$(cd "$WORK/b" && "$TOG" run python -c 'import markupsafe; print(markupsafe.__version__)')
VA=$(cd "$WORK/a" && "$TOG" run python -c 'import markupsafe; print(markupsafe.__version__)')
[ "$VB" = "2.1.5" ] && [ "$VA" = "3.0.2" ] && ok "a=$VA b=$VB simultaneously" || bad "a=$VA b=$VB"

echo "== 3. second sync of identical lock is a cache hit (same object, no re-download)"
cp -R "$FIXTURES/proj-a" "$WORK/a2"
ENV_A=$(readlink "$WORK/a/.venv")
T0=$(date +%s)
(cd "$WORK/a2" && "$TOG" sync)
T1=$(date +%s)
ENV_A2=$(readlink "$WORK/a2/.venv")
[ "$ENV_A" = "$ENV_A2" ] && ok "identical env object reused: $(basename "$ENV_A")" || bad "objects differ"
[ $((T1-T0)) -le 5 ] && ok "resync fast (${T1}s-${T0}s)" || bad "resync slow: $((T1-T0))s"

echo "== 4a. offline reprojection: delete only .venv, resync with network denied"
rm -f "$WORK/a/.venv"
if (cd "$WORK/a" && deny_net "$TOG" sync); then
  V=$(cd "$WORK/a" && "$TOG" run python -c 'import markupsafe; print(markupsafe.__version__)')
  [ "$V" = "3.0.2" ] && ok "reprojected offline" || bad "offline env broken: $V"
else
  bad "offline reprojection failed"
fi

echo "== 4b. offline RECONSTRUCTION: delete env objects, rebuild from artifact cache"
rm -f "$WORK/a/.venv"
chmod -R u+w "$TOG_STORE/objects"
for o in "$TOG_STORE/objects"/*env*; do rm -rf "$o"; done
rm -f "$TOG_STORE"/meta/*env*.json
if (cd "$WORK/a" && deny_net "$TOG" sync); then
  V=$(cd "$WORK/a" && "$TOG" run python -c 'import markupsafe, six; print(markupsafe.__version__)')
  [ "$V" = "3.0.2" ] && ok "env object rebuilt offline from verified artifact cache" || bad "rebuilt env broken: $V"
else
  bad "offline reconstruction failed (resync needed network)"
fi

echo "== 5. lock change swaps env atomically; python toolchain object unchanged"
PYOBJ_BEFORE=$(ls "$TOG_STORE/objects" | grep cpython)
cp "$WORK/b/requirements.txt" "$WORK/a/requirements.txt"
(cd "$WORK/a" && "$TOG" sync)
V=$(cd "$WORK/a" && "$TOG" run python -c 'import markupsafe; print(markupsafe.__version__)')
[ "$V" = "2.1.5" ] && ok "env switched to new lock" || bad "got $V"
PYOBJ_AFTER=$(ls "$TOG_STORE/objects" | grep cpython)
[ "$PYOBJ_BEFORE" = "$PYOBJ_AFTER" ] && ok "cpython object untouched by lock change" || bad "cpython object churned"

echo "== 6. rollback: restoring old lock is an instant cache hit"
cp "$FIXTURES/proj-a/requirements.txt" "$WORK/a/requirements.txt"
T0=$(date +%s)
(cd "$WORK/a" && "$TOG" sync)
T1=$(date +%s)
V=$(cd "$WORK/a" && "$TOG" run python -c 'import markupsafe; print(markupsafe.__version__)')
[ "$V" = "3.0.2" ] && [ $((T1-T0)) -le 5 ] && ok "rolled back in $((T1-T0))s" || bad "v=$V t=$((T1-T0))s"

echo "== 7. store objects are immutable"
OBJ="$TOG_STORE/objects/$(basename "$ENV_A")"
if touch "$OBJ/tamper" 2>/dev/null; then bad "store object writable"; rm -f "$OBJ/tamper"; else ok "write into store object refused"; fi

echo "== 8. sdist builds in a network-denied sandbox (docopt, sdist-only on PyPI)"
cp -R "$FIXTURES/proj-c" "$WORK/c"
if (cd "$WORK/c" && "$TOG" sync); then
  OUT=$(cd "$WORK/c" && "$TOG" run python -c 'import docopt; print(docopt.__version__)')
  [ "$OUT" = "0.6.2" ] && ok "sdist built + importable ($OUT)" || bad "docopt import: $OUT"
else
  bad "sdist sync failed"
fi

echo "== 10. npm: lockfile -> immutable node_modules, store-provisioned node"
cp -R "$FIXTURES/proj-npm" "$WORK/n"
(cd "$WORK/n" && "$TOG" sync)
OUT=$(cd "$WORK/n" && "$TOG" run node index.js)
[ "$OUT" = "is-odd(3): true" ] && ok "npm deps resolve + run ($OUT)" || bad "got '$OUT'"
NV=$(cd "$WORK/n" && "$TOG" run node -e 'console.log(process.version)')
[ "$NV" = "v24.20.0" ] && ok "node came from the store ($NV)" || bad "node version: $NV"
# Forest contract: the node_modules TOP LEVEL is writable scratch space
# (vite/.prisma caches), while package CONTENTS stay immutable in the store.
if touch "$WORK/n/node_modules/.scratch" 2>/dev/null; then ok "node_modules top level writable (forest)"; else bad "forest top level not writable"; fi
if touch "$WORK/n/node_modules/is-odd/tamper" 2>/dev/null; then bad "package contents writable"; else ok "package contents immutable"; fi

echo "== 10b. declared mutable packages: clone projection, writable, unattested"
cp -R "$FIXTURES/proj-npm" "$WORK/nm"
(cd "$WORK/nm" && node -e "const p=require('./package.json'); p.tog={mutablePackages:['is-odd']}; require('fs').writeFileSync('package.json', JSON.stringify(p))" 2>/dev/null \
  || python3 -c "import json;p=json.load(open('$WORK/nm/package.json'));p['tog']={'mutablePackages':['is-odd']};json.dump(p,open('$WORK/nm/package.json','w'))")
(cd "$WORK/nm" && "$TOG" sync)
if touch "$WORK/nm/node_modules/is-odd/scratch" 2>/dev/null; then ok "declared mutable package is writable"; else bad "mutable package not writable"; fi
grep -q '"mutable_state": "unattested"' "$WORK/nm/.tog/closures/node.json" && ok "closure records unattested mutable state" || bad "closure missing mutable_state"

echo "== 10c. cargo: vendor projection + sandboxed build + offline rebuild"
cp -R "$FIXTURES/cargo-hello" "$WORK/cargo"
(cd "$WORK/cargo" && "$TOG" sync)
(cd "$WORK/cargo" && "$TOG" build)
OUT=$(cd "$WORK/cargo" && "$TOG" run target/debug/cargo-hello)
[ "$OUT" = "hello 128" ] && ok "cargo build + run ($OUT)" || bad "cargo output: $OUT"
# tog build itself runs cargo inside the network-denied sandbox (an
# outer sandbox-exec cannot nest); a clean-target rebuild proves the store
# serves everything.
rm -rf "$WORK/cargo/target"
if (cd "$WORK/cargo" && "$TOG" build); then
  ok "cargo rebuild from store (sandboxed, network-denied)"
else
  bad "cargo rebuild failed"
fi

echo "== 10d. cargo: hostile project config + build.rs network probe"
# Hostile .cargo/config.toml (evil source dir + fake rustc) arrives AFTER a
# legit lock: forced --config + RUSTC must neutralize both.
mkdir -p "$WORK/cargo/.cargo"
printf '#!/bin/sh\necho FAKE RUSTC >&2\nexit 1\n' > "$WORK/cargo/fake-rustc"
chmod +x "$WORK/cargo/fake-rustc"
cat > "$WORK/cargo/.cargo/config.toml" <<HOSTILE
[source.crates-io]
replace-with = "evil"
[source.evil]
directory = "$WORK/cargo/nonexistent"
[build]
rustc = "$WORK/cargo/fake-rustc"
HOSTILE
rm -rf "$WORK/cargo/target"
if (cd "$WORK/cargo" && "$TOG" build) && [ "$(cd "$WORK/cargo" && "$TOG" run target/debug/cargo-hello)" = "hello 128" ]; then
  ok "hostile source/rustc config neutralized"
else
  bad "hostile config was honored"
fi
if (cd "$WORK/cargo" && "$TOG" build --config 'net.offline=false' 2>"$WORK/config-takeover.err"); then
  bad "--config takeover accepted"
elif grep -q -- '--config is managed by tog' "$WORK/config-takeover.err"; then
  ok "--config takeover rejected"
else
  bad "--config takeover failed for another reason: $(cat "$WORK/config-takeover.err")"
fi
rm -rf "$WORK/cargo/.cargo" "$WORK/cargo/fake-rustc"
# build.rs that PANICS if the network is reachable: build success = denial.
mkdir -p "$WORK/netdeny/src"
printf '[package]\nname = "netdeny"\nversion = "0.1.0"\nedition = "2021"\n' > "$WORK/netdeny/Cargo.toml"
printf 'version = 4\n\n[[package]]\nname = "netdeny"\nversion = "0.1.0"\n' > "$WORK/netdeny/Cargo.lock"
printf 'fn main() {}\n' > "$WORK/netdeny/src/main.rs"
cat > "$WORK/netdeny/build.rs" <<'NETDENY'
use std::net::TcpStream;
use std::time::Duration;
fn main() {
    let addr = "1.1.1.1:80".parse().unwrap();
    if TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok() {
        panic!("network reachable inside the build sandbox!");
    }
}
NETDENY
# Positive control first: the probe's target must be reachable from this
# machine, or a build that "denies" the network proves nothing.
if (exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null; then
  ok "build.rs network probe target is reachable outside the sandbox"
  if (cd "$WORK/netdeny" && "$TOG" sync && "$TOG" build); then
    ok "build.rs network probe confirms denial"
  else
    bad "netdeny build failed (or network was reachable)"
  fi
else
  bad "build.rs network probe target 1.1.1.1:80 is unreachable from this machine; the denial check cannot run"
fi

echo "== 10e. go: modcache projection + sandboxed build + offline rebuild"
cp -R "$FIXTURES/go-hello" "$WORK/go"
(cd "$WORK/go" && "$TOG" sync)
(cd "$WORK/go" && "$TOG" build)
# rsc.io/quote's Hello() picks its greeting from LC_ALL/LC_MESSAGES/LANG; an unset or
# C/POSIX locale lands on the "pirate" entry ("Ahoy, world!"). Pin the locale so the
# check does not depend on the calling shell (seen from a macOS agent shell, 2026-09-05).
OUT=$(cd "$WORK/go" && LC_ALL=en_US.UTF-8 ./hello)
[ "$OUT" = "Hello, world." ] && ok "go build + run ($OUT)" || bad "go output: $OUT"
rm -f "$WORK/go/hello"
if (cd "$WORK/go" && "$TOG" build go); then
  ok "go rebuild from store (sandboxed, network-denied)"
else
  bad "go rebuild failed"
fi

echo "== 10f. ruby: gems projection + sandboxed native-ext install"
cp -R "$FIXTURES/ruby-hello" "$WORK/rb"
mkdir -p "$WORK/rb/.bundle"
printf -- "---\nBUNDLE_PATH: \"/nonexistent\"\n" > "$WORK/rb/.bundle/config"  # must be neutralized
(cd "$WORK/rb" && "$TOG" sync)
OUT=$(cd "$WORK/rb" && "$TOG" run ruby -e 'require "racc/parser"; require "rake"; puts "ok"')
[ "$OUT" = "ok" ] && ok "ruby native-ext gems load ($OUT)" || bad "ruby output: $OUT"
WHICH=$(cd "$WORK/rb" && "$TOG" run sh -c 'command -v rake')
case "$WHICH" in */objects/*) ok "rake resolves in the store";; *) bad "rake resolved at: $WHICH";; esac
OUT=$(cd "$WORK/rb" && "$TOG" run sh -c "$WHICH --version")
case "$OUT" in *13.*) ok "store binstub executes ($OUT)";; *) bad "store binstub: $OUT";; esac

echo "== 10g. elixir: hex deps + sandboxed mix compile (rebar3 dep)"
# The Linux OTP needs glibc 2.43; a host below that (ubuntu-22.04 in
# .github/workflows/heavy.yml) sets TOG_ACCEPT_SKIP_ELIXIR=1 and skips it.
if [ "${TOG_ACCEPT_SKIP_ELIXIR:-}" = 1 ]; then
  echo "  skip: elixir (TOG_ACCEPT_SKIP_ELIXIR=1; the Linux OTP needs glibc 2.43)"
else
cp -R "$FIXTURES/elixir-hello" "$WORK/ex"
(cd "$WORK/ex" && "$TOG" sync)
(cd "$WORK/ex" && "$TOG" build)
OUT=$(cd "$WORK/ex" && "$TOG" run mix run -e 'IO.puts(ExReal.hello())')
case "$OUT" in *'{"beam":"ok"}'*) ok "elixir build + run ($OUT)";; *) bad "elixir output: $OUT";; esac
fi

echo "== 10h. dotnet: locked nuget packages + sandboxed two-phase build"
cp -R "$FIXTURES/dotnet-hello" "$WORK/dn"
(cd "$WORK/dn" && "$TOG" sync)
(cd "$WORK/dn" && "$TOG" build)
DLL=$(command ls "$WORK/dn"/bin/tog-*/proj.dll | head -1)
OUT=$(cd "$WORK/dn" && "$TOG" run dotnet "$DLL")
case "$OUT" in *'{"dotnet":"ok"}'*) ok "dotnet build + run ($OUT)";; *) bad "dotnet output: $OUT";; esac
if (cd "$WORK/dn" && "$TOG" run dotnet build 2>/dev/null); then
  bad "dotnet build verb accepted at run"
else
  ok "build-capable dotnet verbs are sandbox-only"
fi

echo "== 11. polyglot project: python + node from one sync, one kernel"
cp -R "$FIXTURES/proj-poly" "$WORK/p"
# The Python fixture has no resolver provenance. Make it a
# pip-compile pair and resolve through tog before requiring an attested
# closure at the company-policy gate. Hashes alone are not a receipt.
cp "$WORK/p/requirements.txt" "$WORK/p/requirements.in"
(cd "$WORK/p" && "$TOG" update --no-sync py:six)
(cd "$WORK/p" && "$TOG" sync)
# The update compiles requirements.txt from requirements.in through the
# door with a signed record. The fixture's
# package-lock.json is shipped, so no sync resolved it and the first sync
# records unrecorded-resolution, which the company policy audited in 13
# denies. attest gives the lock a signed resolution record
# (npm's own lock check in the verification door, the lock left byte for
# byte; it needs the toolchain lock the first sync wrote), as a repository
# that adopts tog would, and the next sync carries no exception.
LOCK_BEFORE=$(cksum < "$WORK/p/package-lock.json")
if (cd "$WORK/p" && "$TOG" attest node); then
  [ "$(cksum < "$WORK/p/package-lock.json")" = "$LOCK_BEFORE" ] && [ -f "$WORK/p/.tog/resolution/node.json" ] \
    && ok "attest node signed a record for the fixture lock and left the lock as it was" \
    || bad "attest node changed the lock or wrote no record"
else
  bad "attest node failed"
fi
(cd "$WORK/p" && "$TOG" sync)
PY=$(cd "$WORK/p" && "$TOG" run python -c 'import six; print(six.__version__)')
JS=$(cd "$WORK/p" && "$TOG" run node index.js)
[ "$PY" = "1.17.0" ] && [ "$JS" = "is-odd(3): true" ] && ok "both ecosystems projected (py six=$PY, $JS)" || bad "py=$PY js=$JS"

echo "== 12. sbom: CycloneDX export covers every synced closure"
SBOM=$(cd "$WORK/p" && "$TOG" sbom)
case "$SBOM" in
  *'"bomFormat": "CycloneDX"'*) ok "sbom emits CycloneDX";;
  *) bad "sbom output missing bomFormat";;
esac
echo "$SBOM" | grep -q 'pkg:pypi/six@' && echo "$SBOM" | grep -q 'pkg:npm/is-odd@' \
  && ok "sbom lists both ecosystems' packages" || bad "sbom missing expected purls"

echo "== 13. audit: offline admission gate over the polyglot closures"
POLICY="$(cd "$(dirname "$0")/.." && pwd)/docs/human/policy-company.toml"
mkdir -p "$WORK/nostore"
chmod 555 "$WORK/nostore"
export TOG_STORE="$WORK/nostore/store"
# An absent path under an unwritable dir proves audit never opened or wrote the store.
AUDIT_JSON=$(cd "$WORK/p" && deny_net "$TOG" audit --json --policy "$POLICY") && STATUS=0 || STATUS=$?
CLEAN_JSON_CHECK=$(printf '%s\n' "$AUDIT_JSON" | python3 -c '
import json, sys
report = json.load(sys.stdin)
closures = report["closures"]
ecosystems = {closure["ecosystem"] for closure in closures}
if len(closures) != 2 or ecosystems != {"python", "node"}:
    raise SystemExit(f"unexpected ecosystems: {ecosystems}")
if report["passed"] is not True or any(
    closure["freshness"] != "current" or closure["passed"] is not True
    for closure in closures
):
    raise SystemExit("clean closure is not current and passed")
print("clean report has current, passing python and node closures")
' 2>&1) && CLEAN_JSON_STATUS=0 || CLEAN_JSON_STATUS=$?
if [ "$STATUS" -eq 0 ] && [ "$CLEAN_JSON_STATUS" -eq 0 ]; then
  ok "clean polyglot closures pass the company policy, network denied"
else
  bad "clean --json: exit $STATUS, check=$CLEAN_JSON_CHECK, output: $AUDIT_JSON"
fi

# Plant one exception the company policy denies, in the node closure only.
NODE_CLOSURE="$WORK/p/.tog/closures/node.json"
mv "$NODE_CLOSURE" "$WORK/node.json.orig"
cp "$WORK/node.json.orig" "$NODE_CLOSURE"
python3 - "$NODE_CLOSURE" "$TOG_SIGNING_KEY" <<'PLANT'
import json, os, subprocess, sys, tempfile
path, key_file = sys.argv[1], sys.argv[2]
doc = json.load(open(path))
doc["body"]["exceptions"].append({
    "kind": "install-script-failed",
    "subject": "acceptance-plant",
    "detail": "planted by tests/acceptance.sh step 13",
})
# Re-sign it with the throwaway key, as kernel::signing does: ed25519 over
# the envelope minus its signature, compact JSON with sorted keys. Without
# this, audit reports a bad signature and never looks at the exception.
seed = bytes.fromhex(open(key_file).read().strip().removeprefix("ed25519:"))
unsigned = {name: value for name, value in doc.items() if name != "signature"}
message = json.dumps(unsigned, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
with tempfile.TemporaryDirectory() as scratch:
    der = os.path.join(scratch, "key.der")
    with open(der, "wb") as handle:  # the seed as a PKCS#8 Ed25519 key
        handle.write(bytes.fromhex("302e020100300506032b657004220420") + seed)
    signed = os.path.join(scratch, "message")
    with open(signed, "wb") as handle:
        handle.write(message.encode())
    doc["signature"]["sig"] = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", der, "-in", signed],
        check=True, capture_output=True,
    ).stdout.hex()
with open(path, "w") as handle:
    json.dump(doc, handle, indent=2)
PLANT
AUDIT=$(cd "$WORK/p" && deny_net "$TOG" audit --policy "$POLICY") && STATUS=0 || STATUS=$?
if [ "$STATUS" -eq 1 ] && printf '%s\n' "$AUDIT" | grep -q 'install-script-failed' \
   && printf '%s\n' "$AUDIT" | grep -q 'acceptance-plant'; then
  ok "planted denied exception fails the gate (exit 1, names the kind and subject)"
else
  bad "planted exception: exit $STATUS, output: $AUDIT"
fi
AUDIT_JSON=$(cd "$WORK/p" && deny_net "$TOG" audit --json --policy "$POLICY") && STATUS=0 || STATUS=$?
PLANTED_JSON_CHECK=$(printf '%s\n' "$AUDIT_JSON" | python3 -c '
import json, sys
report = json.load(sys.stdin)
node = [closure for closure in report["closures"] if closure["ecosystem"] == "node"]
if len(node) != 1:
    raise SystemExit("node verdict missing or duplicated")
node = node[0]
if report["passed"] is not False or node["passed"] is not False:
    raise SystemExit("planted report unexpectedly passed")
if node["freshness"] != "current":
    raise SystemExit("node freshness: " + str(node["freshness"]))
if not any(
    exception["kind"] == "install-script-failed"
    and exception["subject"] == "acceptance-plant"
    for exception in node["denied"]
):
    raise SystemExit("planted denial missing from node verdict")
print("node verdict is current with the planted denied exception")
' 2>&1) && PLANTED_JSON_STATUS=0 || PLANTED_JSON_STATUS=$?
if [ "$STATUS" -eq 1 ] && [ "$PLANTED_JSON_STATUS" -eq 0 ]; then
  ok "--json report parses with a current node denial (exit 1, passed=false)"
else
  bad "--json: exit $STATUS, check=$PLANTED_JSON_CHECK, output: $AUDIT_JSON"
fi
rm "$NODE_CLOSURE"
mv "$WORK/node.json.orig" "$NODE_CLOSURE"

if [ ! -e "$TOG_STORE" ]; then
  ok "audit did not create a store under the unwritable directory"
else
  bad "audit created store path under unwritable directory: $TOG_STORE"
fi
export TOG_STORE="$WORK/store"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]

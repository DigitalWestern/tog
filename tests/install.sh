#!/bin/bash
# End-to-end test of install.sh with no network: package the locally built
# binary the way release.yml does, serve it from a local HTTP server, and run
# the installer into throwaway HOMEs. Run after `cargo build --release`:
#
#   bash tests/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BLANKET_BIN:-$ROOT/target/release/blanket}"
[ -x "$BIN" ] || BIN="$ROOT/target/debug/blanket"
[ -x "$BIN" ] || { echo "no blanket binary: run cargo build first" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/blanket-install-test.XXXXXX")"
SERVER=""
trap '[ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null; rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  ok: $1"; }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
count_marks() { grep -c '# >>> blanket >>>' "$1" 2>/dev/null || true; }

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) triple=x86_64-unknown-linux-gnu ;;
    Darwin/arm64) triple=aarch64-apple-darwin ;;
    *) echo "unsupported test host" >&2; exit 1 ;;
esac

# --- a release directory laid out exactly like the GitHub Release assets ----
asset="blanket-$triple.tar.gz"
mkdir -p "$WORK/release" "$WORK/stage"
cp "$BIN" "$WORK/stage/blanket"
tar -C "$WORK/stage" -czf "$WORK/release/$asset" blanket
( cd "$WORK/release" && { sha256sum "$asset" 2>/dev/null || shasum -a 256 "$asset"; } > "$asset.sha256" )

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$WORK/release" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$port/$asset.sha256" >/dev/null 2>&1 && break
    sleep 0.1
done
export BLANKET_DOWNLOAD_BASE="http://127.0.0.1:$port"
BASE_PATH="/usr/bin:/bin"
run_installer() { # HOME SHELL PATH [args...]
    local home="$1" shell="$2" path="$3"; shift 3
    mkdir -p "$home"
    env -i HOME="$home" SHELL="$shell" PATH="$path" TERM=dumb \
        BLANKET_DOWNLOAD_BASE="$BLANKET_DOWNLOAD_BASE" \
        sh "$ROOT/install.sh" "$@"
}

echo "== 1. zsh user, install dir not on PATH"
H="$WORK/h1"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "binary installed and runs"         "$H/.local/bin/blanket" --version
check "env file exists"                   test -f "$H/.blanket/env"
check "sourcing env puts blanket on PATH" sh -c ". '$H/.blanket/env' && command -v blanket | grep -q '$H/.local/bin/blanket'"
check "sourcing env twice does not grow PATH" sh -c ". '$H/.blanket/env'; . '$H/.blanket/env'; [ \"\$(echo \"\$PATH\" | tr : '\n' | grep -c '$H/.local/bin')\" = 1 ]"
check ".zshrc created with one block"     test "$(count_marks "$H/.zshrc")" = 1
check ".zshrc sources env"                grep -Fq '. "$HOME/.blanket/env"' "$H/.zshrc"
check ".zshrc adds fpath"                 grep -Fq 'fpath=("$HOME/.blanket/completions" $fpath)' "$H/.zshrc"
check "zsh completion is an fpath file"   sh -c "head -1 '$H/.blanket/completions/_blanket' | grep -q '^#compdef blanket'"
check "bash completion installed"         test -s "$H/.local/share/bash-completion/completions/blanket"
check "no .bashrc invented for a zsh user" test ! -e "$H/.bashrc"
check "final hint names the env file"     grep -Fq 'source "$HOME/.blanket/env"' <<<"$out"
if command -v zsh >/dev/null 2>&1; then
    check "zsh loads .zshrc and completes without error" \
        env -i HOME="$H" TERM=dumb zsh -ic 'autoload -Uz compinit && compinit -u -D && source ~/.zshrc && command -v blanket && whence -w _blanket | grep -q function'
fi
run_installer "$H" /bin/zsh "$BASE_PATH" >/dev/null 2>&1 || bad "second run exited non-zero"
check "second run is idempotent (one block)" test "$(count_marks "$H/.zshrc")" = 1

echo "== 2. bash user, install dir already on PATH"
H="$WORK/h2"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "binary installed"                  "$H/.local/bin/blanket" --version
check "no startup file touched"           sh -c "! ls '$H'/.bashrc '$H'/.profile '$H'/.bash_profile '$H'/.zshrc 2>/dev/null | grep -q ."
check "reports already on PATH"           grep -q 'already on PATH' <<<"$out"

echo "== 3. bash user, existing .bashrc and .profile, dir off PATH"
H="$WORK/h3"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; echo '# mine' > "$H/.profile"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check ".bashrc got one block"             test "$(count_marks "$H/.bashrc")" = 1
check ".profile got one block"            test "$(count_marks "$H/.profile")" = 1
check "user content preserved"            grep -q '^# mine' "$H/.bashrc"
check "bash -l sees blanket via .profile" env -i HOME="$H" PATH="$BASE_PATH" bash -lc 'command -v blanket'
check "bash -i sees blanket via .bashrc"  env -i HOME="$H" PATH="$BASE_PATH" TERM=dumb bash -ic 'command -v blanket'

echo "== 4. --no-modify-path and --dir"
H="$WORK/h4"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" --no-modify-path "--dir=$H/bin" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "installed into --dir"              "$H/bin/blanket" --version
check "no .zshrc written"                 test ! -e "$H/.zshrc"
check "prints the export line"            grep -Fq "export PATH=\"$H/bin:\$PATH\"" <<<"$out"

echo "== 5. tampered checksum is refused"
H="$WORK/h5"
cp "$WORK/release/$asset.sha256" "$WORK/good.sha256"
printf '%064d  %s\n' 0 "$asset" > "$WORK/release/$asset.sha256"
if run_installer "$H" /bin/zsh "$BASE_PATH" >/dev/null 2>&1; then bad "installer accepted a bad checksum"; else ok "installer refused a bad checksum"; fi
check "nothing installed after refusal"   test ! -e "$H/.local/bin/blanket"
cp "$WORK/good.sha256" "$WORK/release/$asset.sha256"

echo "== 6. --no-completions"
H="$WORK/h6"
run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" --no-completions >/dev/null 2>&1 || bad "installer exited non-zero"
check "no completion files"               test ! -e "$H/.blanket/completions/_blanket" -a ! -e "$H/.local/share/bash-completion/completions/blanket"

echo
echo "install.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

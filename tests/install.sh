#!/bin/bash
# End-to-end test of install.sh with no network: package the locally built
# binary the way release.yml does, serve it from a local HTTP server, and run
# the installer into throwaway HOMEs. Run after `cargo build --release`:
#
#   bash tests/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${TOG_BIN:-$ROOT/target/release/tog}"
[ -x "$BIN" ] || BIN="$ROOT/target/debug/tog"
[ -x "$BIN" ] || { echo "no tog binary: run cargo build first" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/tog-install-test.XXXXXX")"
SERVER=""
trap '[ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null; rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  ok: $1"; }
bad() { fail=$((fail+1)); echo "  FAIL: $1"; }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
count_marks() { grep -c '# >>> tog >>>' "$1" 2>/dev/null || true; }

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) triple=x86_64-unknown-linux-gnu ;;
    Darwin/arm64) triple=aarch64-apple-darwin ;;
    *) echo "unsupported test host" >&2; exit 1 ;;
esac

# --- a release directory laid out exactly like the GitHub Release assets ----
asset="tog-$triple.tar.gz"
mkdir -p "$WORK/release" "$WORK/stage"
cp "$BIN" "$WORK/stage/tog"
tar -C "$WORK/stage" -czf "$WORK/release/$asset" tog
( cd "$WORK/release" && { sha256sum "$asset" 2>/dev/null || shasum -a 256 "$asset"; } > "$asset.sha256" )

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$WORK/release" >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:$port/$asset.sha256" >/dev/null 2>&1 && break
    sleep 0.1
done
export TOG_DOWNLOAD_BASE="http://127.0.0.1:$port"
BASE_PATH="/usr/bin:/bin"
run_installer() { # HOME SHELL PATH [args...]
    local home="$1" shell="$2" path="$3"; shift 3
    mkdir -p "$home"
    env -i HOME="$home" SHELL="$shell" PATH="$path" TERM=dumb \
        TOG_DOWNLOAD_BASE="$TOG_DOWNLOAD_BASE" \
        sh "$ROOT/install.sh" "$@"
}

echo "== 1. zsh user, install dir not on PATH"
H="$WORK/h1"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "binary installed and runs"         "$H/.local/bin/tog" --version
check "env file exists"                   test -f "$H/.tog/env"
check "sourcing env puts tog on PATH" sh -c ". '$H/.tog/env' && command -v tog | grep -q '$H/.local/bin/tog'"
check "sourcing env twice does not grow PATH" sh -c ". '$H/.tog/env'; . '$H/.tog/env'; [ \"\$(echo \"\$PATH\" | tr : '\n' | grep -c '$H/.local/bin')\" = 1 ]"
check ".zshrc created with one block"     test "$(count_marks "$H/.zshrc")" = 1
check ".zshrc sources env"                grep -Fq '. "$HOME/.tog/env"' "$H/.zshrc"
check ".zshrc adds fpath"                 grep -Fq 'fpath=("$HOME/.tog/completions" $fpath)' "$H/.zshrc"
check "zsh completion is an fpath file"   sh -c "head -1 '$H/.tog/completions/_tog' | grep -q '^#compdef tog'"
check "bash completion installed"         test -s "$H/.local/share/bash-completion/completions/tog"
check "no .bashrc invented for a zsh user" test ! -e "$H/.bashrc"
check "final hint names the env file"     grep -Fq 'source "$HOME/.tog/env"' <<<"$out"
if command -v zsh >/dev/null 2>&1; then
    check "zsh loads .zshrc and completes without error" \
        env -i HOME="$H" TERM=dumb zsh -ic 'autoload -Uz compinit && compinit -u -D && source ~/.zshrc && command -v tog && whence -w _tog | grep -q function'
fi
run_installer "$H" /bin/zsh "$BASE_PATH" >/dev/null 2>&1 || bad "second run exited non-zero"
check "second run is idempotent (one block)" test "$(count_marks "$H/.zshrc")" = 1

echo "== 2. bash user, install dir already on PATH"
H="$WORK/h2"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "binary installed"                  "$H/.local/bin/tog" --version
check "no startup file touched"           sh -c "! ls '$H'/.bashrc '$H'/.profile '$H'/.bash_profile '$H'/.zshrc 2>/dev/null | grep -q ."
check "reports already on PATH"           grep -q 'already on PATH' <<<"$out"

echo "== 3. bash user, existing .bashrc and .profile, dir off PATH"
H="$WORK/h3"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; echo '# mine' > "$H/.profile"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check ".bashrc got one block"             test "$(count_marks "$H/.bashrc")" = 1
check ".profile got one block"            test "$(count_marks "$H/.profile")" = 1
check "user content preserved"            grep -q '^# mine' "$H/.bashrc"
check "bash -l sees tog via .profile" env -i HOME="$H" PATH="$BASE_PATH" bash -lc 'command -v tog'
check "bash -i sees tog via .bashrc"  env -i HOME="$H" PATH="$BASE_PATH" TERM=dumb bash -ic 'command -v tog'

echo "== 4. --no-modify-path and --dir"
H="$WORK/h4"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" --no-modify-path "--dir=$H/bin" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "installed into --dir"              "$H/bin/tog" --version
check "no .zshrc written"                 test ! -e "$H/.zshrc"
check "prints the export line"            grep -Fq "export PATH=\"$H/bin:\$PATH\"" <<<"$out"

echo "== 5. tampered checksum is refused"
H="$WORK/h5"
cp "$WORK/release/$asset.sha256" "$WORK/good.sha256"
printf '%064d  %s\n' 0 "$asset" > "$WORK/release/$asset.sha256"
if run_installer "$H" /bin/zsh "$BASE_PATH" >/dev/null 2>&1; then bad "installer accepted a bad checksum"; else ok "installer refused a bad checksum"; fi
check "nothing installed after refusal"   test ! -e "$H/.local/bin/tog"
cp "$WORK/good.sha256" "$WORK/release/$asset.sha256"

echo "== 6. --no-completions"
H="$WORK/h6"
run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" --no-completions >/dev/null 2>&1 || bad "installer exited non-zero"
check "no completion files"               test ! -e "$H/.tog/completions/_tog" -a ! -e "$H/.local/share/bash-completion/completions/tog"

echo "== 7. the store is named and sized before the PATH hint"
H="$WORK/h7"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "names the store path"              grep -Fq "store: $H/.tog/store" <<<"$out"
check "says what will fill it"            grep -Eq 'created by the first sync|so far' <<<"$out"
check "names the uninstall command"       grep -Fq 'install.sh --uninstall' <<<"$out"
check "a written completion is never empty" sh -c "[ -s '$H/.tog/completions/_tog' ] && [ -s '$H/.local/share/bash-completion/completions/tog' ]"

echo "== 8. replacing an existing tog reports old -> new"
H="$WORK/h8"
mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "tog 0.0.1-old"\n' > "$H/.local/bin/tog"
chmod 755 "$H/.local/bin/tog"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "names both versions"               grep -Fq 'upgraded tog 0.0.1-old -> ' <<<"$out"
out="$(run_installer "$H" /bin/bash "$H/.local/bin:$BASE_PATH" 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
check "a same-version rerun says so"      grep -Fq '(same version)' <<<"$out"

echo "== 9. --uninstall removes what it installed and keeps the store"
H="$WORK/h9"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; echo '# mine' > "$H/.profile"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
mkdir -p "$H/.tog/store/objects"; echo keep > "$H/.tog/store/objects/an-object"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "binary removed"                    test ! -e "$H/.local/bin/tog"
check "env file removed"                  test ! -e "$H/.tog/env"
check "zsh completion removed"            test ! -e "$H/.tog/completions/_tog"
check "bash completion removed"           test ! -e "$H/.local/share/bash-completion/completions/tog"
check ".bashrc block removed"             test "$(count_marks "$H/.bashrc")" = 0
check ".bashrc user content preserved"    grep -q '^# mine' "$H/.bashrc"
check ".profile block removed"            test "$(count_marks "$H/.profile")" = 0
check ".profile user content preserved"   grep -q '^# mine' "$H/.profile"
check "store kept"                        test -f "$H/.tog/store/objects/an-object"
check "names the store it kept"           grep -Fq "$H/.tog/store" <<<"$out"
check "prints how to remove the store"    grep -Fq "rm -rf '$H/.tog/store'" <<<"$out"
check "a second uninstall is harmless" run_installer "$H" /bin/bash "$BASE_PATH" --uninstall

echo "== 10. --uninstall with nothing installed"
H="$WORK/h10"; mkdir -p "$H"
out="$(run_installer "$H" /bin/zsh "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "says there is no binary"           grep -Fq 'no tog binary at' <<<"$out"
if grep -Fq downloading <<<"$out"; then bad "--uninstall downloaded something"; else ok "--uninstall never downloads"; fi

echo "== 11. --uninstall refuses a startup file whose markers do not pair"
H="$WORK/h12"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
# Somebody edited the block out by hand and left the opening marker behind.
grep -v '^# <<< tog <<<$' "$H/.bashrc" > "$H/.bashrc.tmp" && mv "$H/.bashrc.tmp" "$H/.bashrc"
echo '# after the unclosed block' >> "$H/.bashrc"
before="$(cat "$H/.bashrc")"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "refuses the unbalanced file"       grep -Fq 'refusing to edit it' <<<"$out"
check "leaves the unbalanced file byte-identical" test "$before" = "$(cat "$H/.bashrc")"
check "content after the marker survives" grep -Fq '# after the unclosed block' "$H/.bashrc"
check "no backup written for a refusal"   test ! -e "$H/.bashrc.tog.bak"
check "the binary still went"             test ! -e "$H/.local/bin/tog"

echo "== 12. a balanced strip keeps a backup and the file's mode"
H="$WORK/h13"; mkdir -p "$H"; echo '# mine' > "$H/.bashrc"; chmod 600 "$H/.bashrc"
run_installer "$H" /bin/bash "$BASE_PATH" >/dev/null 2>&1 || bad "installer exited non-zero"
mode_before="$(ls -l "$H/.bashrc" | cut -c1-10)"
run_installer "$H" /bin/bash "$BASE_PATH" --uninstall >/dev/null 2>&1 || bad "--uninstall exited non-zero"
check "backup kept"                       grep -Fq '# >>> tog >>>' "$H/.bashrc.tog.bak"
check "block gone from the live file"     test "$(count_marks "$H/.bashrc")" = 0
check "mode preserved across the rewrite" test "$mode_before" = "$(ls -l "$H/.bashrc" | cut -c1-10)"

echo "== 13. --uninstall does not delete something that is not tog"
H="$WORK/h14"; mkdir -p "$H/.local/bin"
printf '#!/bin/sh\necho "someone-elses-tool 2.0"\n' > "$H/.local/bin/tog"
chmod 755 "$H/.local/bin/tog"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "imposter left in place"            test -x "$H/.local/bin/tog"
check "says why it left it"               grep -Fq 'does not identify itself as tog' <<<"$out"
# A symlink out of the install directory is a package manager's, not ours.
H="$WORK/h15"; mkdir -p "$H/.local/bin" "$H/opt"
cp "$BIN" "$H/opt/tog"
ln -s "$H/opt/tog" "$H/.local/bin/tog"
out="$(run_installer "$H" /bin/bash "$BASE_PATH" --uninstall 2>&1)" || { echo "$out"; bad "--uninstall exited non-zero"; }
check "outside symlink left in place"     test -L "$H/.local/bin/tog"
check "says it is a symlink elsewhere"    grep -Fq 'outside' <<<"$out"

echo "== 14. empty --dir and missing HOME are usage errors, not surprises"
if run_installer "$WORK/h16" /bin/bash "$BASE_PATH" --dir= >/dev/null 2>&1; then
    bad "--dir= was accepted"
else ok "--dir= is refused"; fi
if env -i PATH="$BASE_PATH" TERM=dumb TOG_DOWNLOAD_BASE="$TOG_DOWNLOAD_BASE" \
    sh "$ROOT/install.sh" >/dev/null 2>&1; then
    bad "installer ran with no HOME"
else ok "no HOME is refused"; fi
out="$(env -i PATH="$BASE_PATH" TERM=dumb sh "$ROOT/install.sh" 2>&1 || true)"
check "the no-HOME message names HOME"    grep -Fq 'HOME is not set' <<<"$out"

echo "== 15. TOG_NO_MODIFY_PATH only turns PATH editing off when it means it"
for value in 0 1; do
    H="$WORK/h11-$value"; mkdir -p "$H"
    env -i HOME="$H" SHELL=/bin/bash PATH="$BASE_PATH" TERM=dumb \
        TOG_NO_MODIFY_PATH="$value" TOG_DOWNLOAD_BASE="$TOG_DOWNLOAD_BASE" \
        sh "$ROOT/install.sh" >/dev/null 2>&1 || bad "installer exited non-zero"
    if [ "$value" = 0 ]; then
        check "TOG_NO_MODIFY_PATH=0 still edits .bashrc" test "$(count_marks "$H/.bashrc")" = 1
    else
        check "TOG_NO_MODIFY_PATH=1 edits nothing"       test ! -e "$H/.bashrc"
    fi
done

echo
echo "install.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

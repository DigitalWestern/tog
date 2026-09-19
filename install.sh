#!/bin/sh
# tog installer: download the release binary for this machine, put it on
# PATH, and wire shell completions. POSIX sh on purpose; it must run under
# dash, bash, zsh, and macOS /bin/sh.
#
#   curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh
#
# Options (as arguments, or environment variables):
#   --version=<v>       release tag to install (TOG_VERSION; default: latest)
#   --dir=<path>        where the binary goes (TOG_INSTALL_DIR; default ~/.local/bin)
#   --no-modify-path    never edit shell startup files (TOG_NO_MODIFY_PATH=1)
#   --no-completions    skip shell completions
#   --help
#
# What it changes on disk, and nothing else:
#   <dir>/tog                          the binary
#   ~/.tog/env                         POSIX snippet that prepends <dir> to PATH
#   ~/.tog/completions/_tog        zsh completion (autoloaded via fpath)
#   ~/.local/share/bash-completion/completions/tog
#   ~/.config/fish/completions/tog.fish
#   ~/.config/fish/conf.d/tog.fish     fish PATH hook
#   one marked block appended to ~/.profile, ~/.bashrc, ~/.bash_profile,
#   and ~/.zshrc when they exist (or the one your $SHELL reads), only when
#   <dir> is not already on PATH.
#
# A script cannot change the PATH of the shell that piped it in. The last
# line it prints is the one command that finishes the job for the current
# terminal; every new terminal picks it up on its own.

set -eu

REPO="DigitalWestern/tog"
VERSION="${TOG_VERSION:-latest}"
INSTALL_DIR="${TOG_INSTALL_DIR:-$HOME/.local/bin}"
MODIFY_PATH="${TOG_NO_MODIFY_PATH:+0}"
MODIFY_PATH="${MODIFY_PATH:-1}"
COMPLETIONS=1
TOG_HOME="$HOME/.tog"
MARK_BEGIN="# >>> tog >>>"
MARK_END="# <<< tog <<<"

say()  { printf 'tog-install: %s\n' "$*" >&2; }
fail() { printf 'tog-install: error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [--version=<tag>] [--dir=<path>] [--no-modify-path] [--no-completions]

  --version=<tag>    release to install (default: latest; also TOG_VERSION)
  --dir=<path>       where the binary goes (default ~/.local/bin; also TOG_INSTALL_DIR)
  --no-modify-path   never edit shell startup files (also TOG_NO_MODIFY_PATH=1)
  --no-completions   skip bash/zsh/fish completions
EOF
}

for arg in "$@"; do
    case "$arg" in
        --version=*) VERSION="${arg#--version=}" ;;
        --dir=*) INSTALL_DIR="${arg#--dir=}" ;;
        --no-modify-path) MODIFY_PATH=0 ;;
        --no-completions) COMPLETIONS=0 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown option '$arg' (try --help)" ;;
    esac
done

# --- platform ---------------------------------------------------------------
# Same two rows as src/kernel/platform.rs; anything else must build from source.
os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
    Linux/x86_64) triple="x86_64-unknown-linux-gnu" ;;
    Darwin/arm64) triple="aarch64-apple-darwin" ;;
    *)
        fail "no prebuilt binary for $os/$arch (tog ships for Linux x86_64 and macOS arm64).
  Build from source instead:  cargo install --git https://github.com/$REPO --locked"
        ;;
esac
if [ "$triple" = "x86_64-unknown-linux-gnu" ] && [ ! -e /lib64/ld-linux-x86-64.so.2 ]; then
    fail "this Linux has no glibc loader at /lib64/ld-linux-x86-64.so.2 (musl or Alpine?); tog pins glibc toolchains"
fi

# --- download ---------------------------------------------------------------
asset="tog-$triple.tar.gz"
case "$VERSION" in
    latest) base="https://github.com/$REPO/releases/latest/download" ;;
    v*)     base="https://github.com/$REPO/releases/download/$VERSION" ;;
    *)      base="https://github.com/$REPO/releases/download/v$VERSION" ;;
esac
# Test hook: serve the two asset files from anywhere (tests/install.sh uses it).
base="${TOG_DOWNLOAD_BASE:-$base}"

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
else
    fail "need curl or wget to download $base/$asset"
fi

if command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    fail "need sha256sum or shasum to verify the download"
fi

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t tog-install)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $base/$asset"
fetch "$base/$asset" "$tmp/$asset" \
    || fail "download failed. Is there a release at https://github.com/$REPO/releases ?"
fetch "$base/$asset.sha256" "$tmp/$asset.sha256" \
    || fail "checksum file missing next to the release asset; refusing to install an unverified binary"

expected="$(cut -d' ' -f1 "$tmp/$asset.sha256" | tr -d '\r\n')"
actual="$(digest "$tmp/$asset")"
[ -n "$expected" ] || fail "empty checksum file"
[ "$expected" = "$actual" ] || fail "sha256 mismatch for $asset
  expected $expected
  got      $actual"

tar -xzf "$tmp/$asset" -C "$tmp" || fail "cannot extract $asset"
[ -f "$tmp/tog" ] || fail "archive did not contain a 'tog' binary"

# --- install ----------------------------------------------------------------
mkdir -p "$INSTALL_DIR" || fail "cannot create $INSTALL_DIR"
# Copy to a sibling and rename so a running `tog` never sees a half-written file.
cp "$tmp/tog" "$INSTALL_DIR/.tog.tmp.$$" || fail "cannot write to $INSTALL_DIR"
chmod 755 "$INSTALL_DIR/.tog.tmp.$$"
mv -f "$INSTALL_DIR/.tog.tmp.$$" "$INSTALL_DIR/tog"
installed="$("$INSTALL_DIR/tog" --version 2>/dev/null || true)"
[ -n "$installed" ] || fail "$INSTALL_DIR/tog does not run on this machine"
say "installed $installed to $INSTALL_DIR/tog"

# --- PATH -------------------------------------------------------------------
on_path=0
case ":$PATH:" in
    *":$INSTALL_DIR:"*) on_path=1 ;;
esac

mkdir -p "$TOG_HOME"
# ~/.tog/env is POSIX sh: it is read by sh, bash, and zsh alike. Idempotent
# so sourcing it twice does not grow PATH.
cat >"$TOG_HOME/env" <<EOF
# tog: put the tog binary on PATH. Written by install.sh; safe to source repeatedly.
case ":\${PATH}:" in
    *":$INSTALL_DIR:"*) ;;
    *) export PATH="$INSTALL_DIR:\$PATH" ;;
esac
EOF

# Append one marked block to a startup file, once.
append_block() {
    file="$1"
    body="$2"
    if [ -f "$file" ] && grep -Fq "$MARK_BEGIN" "$file" 2>/dev/null; then
        return 0
    fi
    [ -f "$file" ] || [ "$3" = "create" ] || return 0
    printf '\n%s\n%s\n%s\n' "$MARK_BEGIN" "$body" "$MARK_END" >>"$file" \
        || { say "could not write $file (skipped)"; return 0; }
    say "added PATH setup to $file"
}

posix_line=". \"\$HOME/.tog/env\""
zsh_block="$posix_line
fpath=(\"\$HOME/.tog/completions\" \$fpath)
if (( \$+functions[compdef] )); then autoload -Uz _tog && compdef _tog tog; fi"

shell_name="$(basename "${SHELL:-sh}")"
zdotdir="${ZDOTDIR:-$HOME}"

if [ "$MODIFY_PATH" = 1 ] && [ "$on_path" = 0 ]; then
    # The file the user's login shell reads is created if missing; the others
    # are only touched when they already exist.
    case "$shell_name" in
        zsh)  append_block "$zdotdir/.zshrc" "$zsh_block" create ;;
        bash) if [ "$os" = Darwin ]; then
                  append_block "$HOME/.bash_profile" "$posix_line" create
              else
                  append_block "$HOME/.bashrc" "$posix_line" create
              fi ;;
        fish) : ;;
        *)    append_block "$HOME/.profile" "$posix_line" create ;;
    esac
    append_block "$HOME/.profile" "$posix_line" existing
    append_block "$HOME/.bashrc" "$posix_line" existing
    append_block "$HOME/.bash_profile" "$posix_line" existing
    append_block "$zdotdir/.zshrc" "$zsh_block" existing
    # fish does not read POSIX files; conf.d snippets are auto-sourced.
    if command -v fish >/dev/null 2>&1 || [ "$shell_name" = fish ]; then
        fish_confd="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d"
        mkdir -p "$fish_confd" 2>/dev/null && cat >"$fish_confd/tog.fish" <<EOF
# tog: put the tog binary on PATH. Written by install.sh.
if not contains -- "$INSTALL_DIR" \$PATH
    set -gx PATH "$INSTALL_DIR" \$PATH
end
EOF
        say "added PATH setup to $fish_confd/tog.fish"
    fi
elif [ "$MODIFY_PATH" = 1 ] && [ "$shell_name" = zsh ] && [ "$COMPLETIONS" = 1 ]; then
    # Already on PATH, but zsh still needs the fpath entry for completions.
    append_block "$zdotdir/.zshrc" "$zsh_block" existing
fi

# --- completions ------------------------------------------------------------
if [ "$COMPLETIONS" = 1 ]; then
    bin="$INSTALL_DIR/tog"
    mkdir -p "$TOG_HOME/completions"
    "$bin" completions zsh >"$TOG_HOME/completions/_tog" 2>/dev/null || true
    bash_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
    if mkdir -p "$bash_dir" 2>/dev/null; then
        "$bin" completions bash >"$bash_dir/tog" 2>/dev/null || true
    fi
    if command -v fish >/dev/null 2>&1 || [ "$shell_name" = fish ]; then
        fish_dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
        if mkdir -p "$fish_dir" 2>/dev/null; then
            "$bin" completions fish >"$fish_dir/tog.fish" 2>/dev/null || true
        fi
    fi
    say "shell completions installed (bash, zsh, fish)"
fi

# --- done -------------------------------------------------------------------
if [ "$on_path" = 1 ]; then
    say "done. '$INSTALL_DIR' is already on PATH: try 'tog --version'"
elif [ "$MODIFY_PATH" = 0 ]; then
    say "done. '$INSTALL_DIR' is not on PATH and --no-modify-path was given; add it yourself:"
    printf '\n    export PATH="%s:$PATH"\n\n' "$INSTALL_DIR" >&2
else
    say "done. New terminals already have tog. For this one, run:"
    if [ "$shell_name" = fish ]; then
        printf '\n    set -gx PATH "%s" $PATH\n\n' "$INSTALL_DIR" >&2
    else
        printf '\n    source "$HOME/.tog/env"\n\n' >&2
    fi
fi

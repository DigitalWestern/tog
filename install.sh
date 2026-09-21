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
#   --uninstall         remove everything this script installed (not the store)
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
# What it never touches: the store (~/.tog/store, or TOG_STORE), ~/.tog/x,
# and ~/.tog/forests. Those hold downloaded toolchains and realized
# environments, they can be several GiB, and --uninstall leaves them alone
# and says so.
#
# A script cannot change the PATH of the shell that piped it in. The last
# line it prints is the one command that finishes the job for the current
# terminal; every new terminal picks it up on its own.

set -eu

REPO="DigitalWestern/tog"
VERSION="${TOG_VERSION:-latest}"
INSTALL_DIR="${TOG_INSTALL_DIR:-$HOME/.local/bin}"
# Only a real value turns PATH editing off: TOG_NO_MODIFY_PATH=0 used to
# disable it, which is the opposite of what it reads like.
MODIFY_PATH=1
case "${TOG_NO_MODIFY_PATH:-}" in
    '' | 0 | false | no) ;;
    *) MODIFY_PATH=0 ;;
esac
COMPLETIONS=1
UNINSTALL=0
TOG_HOME="$HOME/.tog"
STORE="${TOG_STORE:-$TOG_HOME/store}"
MARK_BEGIN="# >>> tog >>>"
MARK_END="# <<< tog <<<"
shell_name="$(basename "${SHELL:-sh}")"
zdotdir="${ZDOTDIR:-$HOME}"

say()  { printf 'tog-install: %s\n' "$*" >&2; }
fail() { printf 'tog-install: error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [--version=<tag>] [--dir=<path>] [--no-modify-path] [--no-completions]
       install.sh --uninstall [--dir=<path>]

  --version=<tag>    release to install (default: latest; also TOG_VERSION)
  --dir=<path>       where the binary goes (default ~/.local/bin; also TOG_INSTALL_DIR)
  --no-modify-path   never edit shell startup files (also TOG_NO_MODIFY_PATH=1)
  --no-completions   skip bash/zsh/fish completions
  --uninstall        remove the binary, the env file, the completions, and the
                     PATH blocks this script wrote; the store is left alone
EOF
}

for arg in "$@"; do
    case "$arg" in
        --version=*) VERSION="${arg#--version=}" ;;
        --dir=*) INSTALL_DIR="${arg#--dir=}" ;;
        --no-modify-path) MODIFY_PATH=0 ;;
        --no-completions) COMPLETIONS=0 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown option '$arg' (try --help)" ;;
    esac
done

# --- uninstall --------------------------------------------------------------
# Removes exactly what the header says this script writes, and nothing else.
# The store is data, not an installation: it is named, sized, and left behind.
# Never fatal: a file that will not go is reported, and the rest still runs.
drop_file() {
    [ -e "$1" ] || [ -L "$1" ] || return 0
    if rm -f "$1"; then
        say "removed $1"
    else
        say "could not remove $1"
    fi
    return 0
}

# Delete the marked block in place, keeping the file's mode and owner.
strip_block() {
    file="$1"
    [ -f "$file" ] || return 0
    grep -Fq "$MARK_BEGIN" "$file" 2>/dev/null || return 0
    scratch="$file.tog-uninstall.$$"
    awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
        $0 == begin { skip = 1; next }
        $0 == end   { skip = 0; next }
        skip { next }
        { print }
    ' "$file" >"$scratch" 2>/dev/null \
        || { say "could not rewrite $file (left as it is)"; rm -f "$scratch"; return 0; }
    if cat "$scratch" >"$file" 2>/dev/null; then
        say "removed the tog block from $file"
    else
        say "could not rewrite $file (left as it is)"
    fi
    rm -f "$scratch"
}

uninstall() {
    if [ -f "$INSTALL_DIR/tog" ]; then
        gone="$("$INSTALL_DIR/tog" --version 2>/dev/null || echo tog)"
        if rm -f "$INSTALL_DIR/tog"; then
            say "removed $gone from $INSTALL_DIR/tog"
        else
            say "could not remove $INSTALL_DIR/tog"
        fi
    else
        say "no tog binary at $INSTALL_DIR/tog (use --dir=<path> if it is elsewhere)"
    fi
    drop_file "$TOG_HOME/env"
    drop_file "$TOG_HOME/completions/_tog"
    rmdir "$TOG_HOME/completions" 2>/dev/null || true
    drop_file "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/tog"
    drop_file "${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/tog.fish"
    drop_file "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/tog.fish"
    strip_block "$HOME/.profile"
    strip_block "$HOME/.bashrc"
    strip_block "$HOME/.bash_profile"
    strip_block "$zdotdir/.zshrc"

    say "not removed, because it is your data and not the installation:"
    if [ -d "$STORE" ]; then
        size="$(du -sh "$STORE" 2>/dev/null | cut -f1)"
        say "  $STORE (${size:-size unknown}) - toolchains, packages, environments"
    else
        say "  $STORE (does not exist) - toolchains, packages, environments"
    fi
    for extra in "$TOG_HOME/x" "$TOG_HOME/forests"; do
        if [ -d "$extra" ]; then say "  $extra"; fi
    done
    say "to reclaim that space:  rm -rf '$STORE'"
    say "projects keep their own .venv, node_modules and .tog/ until you delete them"
    say "done. The current terminal may still have tog cached; run 'hash -r'"
}

if [ "$UNINSTALL" = 1 ]; then
    uninstall
    exit 0
fi

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
# What is being replaced, if anything: read it before the file is overwritten.
previous=""
if [ -x "$INSTALL_DIR/tog" ]; then
    previous="$("$INSTALL_DIR/tog" --version 2>/dev/null || true)"
fi
mkdir -p "$INSTALL_DIR" || fail "cannot create $INSTALL_DIR"
# Copy to a sibling and rename so a running `tog` never sees a half-written file.
cp "$tmp/tog" "$INSTALL_DIR/.tog.tmp.$$" || fail "cannot write to $INSTALL_DIR"
chmod 755 "$INSTALL_DIR/.tog.tmp.$$"
mv -f "$INSTALL_DIR/.tog.tmp.$$" "$INSTALL_DIR/tog"
installed="$("$INSTALL_DIR/tog" --version 2>/dev/null || true)"
[ -n "$installed" ] || fail "$INSTALL_DIR/tog does not run on this machine"
if [ -z "$previous" ]; then
    say "installed $installed to $INSTALL_DIR/tog"
elif [ "$previous" = "$installed" ]; then
    say "reinstalled $installed to $INSTALL_DIR/tog (same version)"
else
    say "upgraded $previous -> $installed in $INSTALL_DIR"
fi
shadow="$(command -v tog 2>/dev/null || true)"
if [ -n "$shadow" ] && [ "$shadow" != "$INSTALL_DIR/tog" ]; then
    say "note: '$shadow' comes first on this PATH and will keep winning"
fi

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
# Generate to a scratch file and only keep it when it has content: a failed
# `tog completions` used to leave a zero-byte file that the shell sources
# happily and that breaks completion with no error anywhere.
write_completion() { # <shell> <destination>
    scratch="$2.tog-install.$$"
    if "$bin" completions "$1" >"$scratch" 2>/dev/null && [ -s "$scratch" ]; then
        mv -f "$scratch" "$2"
        return 0
    fi
    rm -f "$scratch"
    say "could not generate the $1 completion (skipped)"
    return 1
}

if [ "$COMPLETIONS" = 1 ]; then
    bin="$INSTALL_DIR/tog"
    wired=""
    if mkdir -p "$TOG_HOME/completions" 2>/dev/null \
        && write_completion zsh "$TOG_HOME/completions/_tog"; then
        wired="zsh"
    fi
    bash_dir="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions"
    if mkdir -p "$bash_dir" 2>/dev/null && write_completion bash "$bash_dir/tog"; then
        wired="${wired:+$wired, }bash"
    fi
    if command -v fish >/dev/null 2>&1 || [ "$shell_name" = fish ]; then
        fish_dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions"
        if mkdir -p "$fish_dir" 2>/dev/null \
            && write_completion fish "$fish_dir/tog.fish"; then
            wired="${wired:+$wired, }fish"
        fi
    fi
    if [ -n "$wired" ]; then
        say "shell completions installed ($wired)"
    else
        say "no shell completions installed"
    fi
fi

# --- done -------------------------------------------------------------------
# Where the disk goes. The only size hint tog gave before this line was a
# low-free-space warning, which arrives long after the decision matters.
say "store: $STORE (every toolchain, package and environment; projects share it)"
if [ -d "$STORE" ]; then
    size="$(du -sh "$STORE" 2>/dev/null | cut -f1)"
    say "  ${size:-size unknown} so far; 'tog doctor' reports it, 'tog gc' reclaims it"
else
    say "  created by the first sync; budget ~700 MiB for a Python plus a Node project"
fi
say "to undo all of this later: sh install.sh --uninstall (it keeps the store)"

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

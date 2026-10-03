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

# Every path below hangs off HOME, and `set -u` would report it as a bare
# "unbound variable" with no hint about what to do.
if [ -z "${HOME:-}" ]; then
    printf 'tog-install: error: %s\n' \
        "HOME is not set; run this as a real user, or pass --dir=<path> with HOME=<path> set" >&2
    exit 1
fi

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

# $1 single-quoted for a shell, with embedded apostrophes escaped, so a path
# printed as a command to run is safe to paste whatever is in it. Done with
# parameter expansion rather than sed: the sed program for this has to carry
# backslashes through the shell's quoting and then through sed's replacement
# rules, and getting that wrong is silent -- a path with two apostrophes came
# out as a valid command for the wrong directory.
shquote() {
    _sq_rest="$1"
    _sq_out=""
    _sq_q="'"
    while :; do
        case "$_sq_rest" in
            *"$_sq_q"*) ;;
            *) break ;;
        esac
        _sq_out=$_sq_out${_sq_rest%%"$_sq_q"*}$_sq_q\\$_sq_q$_sq_q
        _sq_rest=${_sq_rest#*"$_sq_q"}
    done
    printf '%s%s%s' "$_sq_q" "$_sq_out$_sq_rest" "$_sq_q"
}

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
        --dir=*)
            INSTALL_DIR="${arg#--dir=}"
            [ -n "$INSTALL_DIR" ] || fail "--dir= needs a path (e.g. --dir=\$HOME/bin)"
            ;;
        --no-modify-path) MODIFY_PATH=0 ;;
        --no-completions) COMPLETIONS=0 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown option '$arg' (try --help)" ;;
    esac
done
# TOG_INSTALL_DIR= (set but empty) reaches here the same way --dir= does.
[ -n "$INSTALL_DIR" ] || fail "install directory is empty; set TOG_INSTALL_DIR or pass --dir=<path>"

# --- paths and probes -------------------------------------------------------
# The real path of $1: follow the leaf's symlink chain (bounded, so a loop
# cannot hang the script), then resolve the directory with `cd -P` so a
# symlinked parent collapses too. Lexical comparison is not enough:
# `bin/tog -> ../elsewhere/tog` is inside the directory only on paper.
resolve_path() {
    _rs_path="$1"
    _rs_hops=0
    while [ -L "$_rs_path" ] && [ "$_rs_hops" -lt 40 ]; do
        _rs_target="$(readlink "$_rs_path")" || return 1
        case "$_rs_target" in
            /*) _rs_path="$_rs_target" ;;
            *) _rs_path="$(dirname "$_rs_path")/$_rs_target" ;;
        esac
        _rs_hops=$((_rs_hops + 1))
    done
    [ "$_rs_hops" -lt 40 ] || return 1
    _rs_dir="$(cd -P "$(dirname "$_rs_path")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s' "$_rs_dir" "$(basename "$_rs_path")"
}

# `<path> --version`, bounded. Whatever sits at that path is an unknown
# program: it may block on a tty, a socket, or a lock. `timeout` is not in
# POSIX and stock macOS does not ship it, so where it is missing the probe
# runs unbounded -- which is what every version of this script did before.
# Empty output, or a non-zero exit, is reported as no version at all.
probe_version() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 5 "$1" --version 2>/dev/null || true
    else
        "$1" --version 2>/dev/null || true
    fi
}

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

# Is there exactly one well-formed tog block in $1? Whole-line comparison,
# so a marker quoted inside a longer line is not a marker; and the state
# machine catches what counting cannot: an end before its begin, a begin
# inside an open block, or a block still open at EOF.
#   0 = one or more well-formed blocks   1 = no marker at all   2 = malformed
scan_markers() {
    awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
        $0 == begin { if (open) { bad = 1; exit } open = 1; seen = 1; next }
        $0 == end   { if (!open) { bad = 1; exit } open = 0; next }
        END { if (bad || open) exit 2; if (!seen) exit 1; exit 0 }
    ' "$1" 2>/dev/null
}

# Delete the marked block. A startup file is somebody's shell, so: refuse on
# anything that is not a clean begin/end pair, edit the file the path really
# resolves to rather than a symlink standing in for it, keep a .tog.bak, and
# swap the rewrite in by rename so an interrupted uninstall leaves no
# half-file.
strip_block() {
    file="$1"
    [ -f "$file" ] || return 0

    # A dotfile is often a symlink into a dotfiles repo (stow, chezmoi). Edit
    # the file it points at: renaming over the link would replace the link
    # with a regular file and leave the real rc untouched.
    target="$(resolve_path "$file")" \
        || { say "could not resolve $file (left as it is)"; return 0; }
    [ -f "$target" ] || return 0

    status=0
    scan_markers "$target" || status=$?
    [ "$status" = 1 ] && return 0
    if [ "$status" != 0 ]; then
        say "$target has a malformed tog block (an end marker before its begin, a nested begin, or no end at all); refusing to edit it. Remove the block by hand."
        return 0
    fi

    backup="$target.tog.bak"
    if [ -L "$backup" ]; then
        say "$backup is a symlink; refusing to write a backup through it. Remove it and run --uninstall again."
        return 0
    fi
    # mktemp reserves an unpredictable name next to the file; cp then
    # recreates it so the scratch carries the rc file's mode and the rename
    # cannot change the file's bits.
    scratch="$(mktemp "$target.tog-uninstall.XXXXXX" 2>/dev/null)" \
        || { say "could not create a scratch file next to $target (left as it is)"; return 0; }
    rm -f "$scratch"
    cp "$target" "$backup" 2>/dev/null \
        || { say "could not back up $target (left as it is)"; return 0; }
    cp "$target" "$scratch" 2>/dev/null \
        || { say "could not rewrite $target (left as it is)"; return 0; }
    if awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
        $0 == begin { skip = 1; next }
        $0 == end   { skip = 0; next }
        skip { next }
        { print }
    ' "$target" >"$scratch" 2>/dev/null && mv -f "$scratch" "$target"; then
        say "removed the tog block from $target (previous copy: $backup)"
    else
        say "could not rewrite $target (left as it is)"
        rm -f "$scratch"
    fi
}

# Is <path> a file this script would have installed? Two questions, both
# answered before anything is deleted: does it really live in the install
# directory -- resolved, not spelled, so `bin/tog -> ../elsewhere/tog` is
# refused -- and does running it say "tog "?
removable() {
    [ -f "$1" ] || return 1
    real="$(resolve_path "$1")" \
        || { say "could not resolve $1; leaving it alone"; return 1; }
    real_dir="$(cd -P "$INSTALL_DIR" 2>/dev/null && pwd -P)" \
        || { say "could not resolve $INSTALL_DIR; leaving $1 alone"; return 1; }
    if [ "${real%/*}" != "$real_dir" ]; then
        say "$1 resolves to $real, outside $real_dir; leaving it alone"
        return 1
    fi
    version="$(probe_version "$1")"
    case "$version" in
        "tog "*) return 0 ;;
        *)
            say "$1 does not identify itself as tog; leaving it alone"
            return 1
            ;;
    esac
}

uninstall() {
    if [ ! -e "$INSTALL_DIR/tog" ] && [ ! -L "$INSTALL_DIR/tog" ]; then
        say "no tog binary at $INSTALL_DIR/tog (use --dir=<path> if it is elsewhere)"
    elif [ -L "$INSTALL_DIR/tog" ] && [ ! -e "$INSTALL_DIR/tog" ]; then
        # Dangling: nothing to ask for a version, and nothing to be sure of.
        say "$INSTALL_DIR/tog is a symlink to $(readlink "$INSTALL_DIR/tog"), which does not exist; leaving it alone"
    elif removable "$INSTALL_DIR/tog"; then
        gone="$version"
        if rm -f "$INSTALL_DIR/tog"; then
            say "removed $gone from $INSTALL_DIR/tog"
        else
            say "could not remove $INSTALL_DIR/tog"
        fi
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
    say "to reclaim that space:  rm -rf $(shquote "$STORE")"
    say "projects keep their own .venv, node_modules and .tog/ until you delete them"
    say "done. The current terminal may still have tog cached; run 'hash -r'"
}

if [ "$UNINSTALL" = 1 ]; then
    uninstall
    exit 0
fi

# --- platform ---------------------------------------------------------------
# Same two rows as src/kernel/platform.rs; anything else must build from source.
# release.yml builds Linux x86_64 only until the macOS gate (#66); the Darwin
# row stays so a release that carries the asset again needs no script change.
os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
    Linux/x86_64) triple="x86_64-unknown-linux-gnu" ;;
    Darwin/arm64) triple="aarch64-apple-darwin" ;;
    *)
        fail "no prebuilt binary for $os/$arch (releases are built for Linux x86_64).
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
    || fail "download failed. Is there a release at https://github.com/$REPO/releases with $asset?
  Releases are built for Linux x86_64 only for now (macOS waits on #66).
  Build from source instead:  cargo install --git https://github.com/$REPO --locked"
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
    previous="$(probe_version "$INSTALL_DIR/tog")"
    # Only a tog version belongs in an "upgraded X -> Y" line.
    case "$previous" in
        "tog "*) ;;
        *) previous="" ;;
    esac
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

# tog

One binary that owns the outer loop every language ecosystem shares:
provision a pinned toolchain, realize a locked dependency graph into an
immutable content-addressed store, project an environment, run your code.

Nix's model, without Nix's interface. Seven ecosystems: Python, npm,
Cargo, Go, Ruby, Elixir, .NET. Your `.venv` and `node_modules` become
read-only-backed environments you can rebuild offline, share, and roll
back atomically.

| Read | For |
|---|---|
| [STATUS.md](STATUS.md) | where the project is, what is next |
| [docs/human/ARCHITECTURE.md](docs/human/ARCHITECTURE.md) | how it works |
| [docs/human/CLI.md](docs/human/CLI.md) | the command surface (spec) |
| [docs/human/LIMITATIONS.md](docs/human/LIMITATIONS.md) | what it honestly cannot do |
| [FOLLOW-UPS.md](FOLLOW-UPS.md) | the to-do list and open decisions |
| [docs/agent/DESIGNS.md](docs/agent/DESIGNS.md) | designed but unbuilt work (for agents) |
| [docs/human/ADDING-A-TAILOR.md](docs/human/ADDING-A-TAILOR.md) | adding an ecosystem |

## Host prerequisites

Tog downloads every language toolchain itself, but native builds
compile against the host C toolchain, and the Linux build sandbox uses
bubblewrap. On Fedora:

```sh
sudo dnf install bubblewrap gcc gcc-c++ make binutils glibc-devel \
  pkgconf-pkg-config patch zlib-ng-compat-devel libxcrypt-devel
```

## Install

One line on Linux x86_64 or macOS arm64. It downloads the release binary
for your machine, checks its sha256, puts it in `~/.local/bin`, adds that
directory to PATH if it is not already there, and installs bash, zsh, and
fish completions:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh
```

Every new terminal has `tog` from then on. A script cannot change the
PATH of the terminal that ran it, so it ends by printing the one command
that finishes the job there (`source ~/.tog/env`). Options:
`--dir=<path>`, `--version=<tag>`, `--no-modify-path`, `--no-completions`;
the header of [install.sh](install.sh) lists every file it touches.

From source, with a Rust toolchain (`cargo install` puts the binary in
`~/.cargo/bin`, which rustup already added to PATH):

```sh
cargo install --git https://github.com/DigitalWestern/tog --locked
# or, inside a checkout:
cargo install --path . --locked
tog completions zsh > ~/.zfunc/_tog   # bash | zsh | fish; optional
```

Do not `cargo install tog` from crates.io: that name belongs to an
unrelated crate. Releases are built by
[.github/workflows/release.yml](.github/workflows/release.yml) on a `v*` tag.

## Use

```sh
cd your-project     # an EXISTING project works as-is:
tog             # realize + project -> ./.venv and/or ./node_modules
tog run python app.py       # run inside the projected env(s)
tog add requests            # add a dependency with the ecosystem's own tool
tog x ruff check .          # run a tool without adding it (like uvx / npx)
tog build                   # sandboxed Cargo build (network denied)
tog gc --dry-run            # preview unreferenced store/cache cleanup
tog doctor                  # host prerequisites, sandbox, store, free space
tog --version
```

Full command reference: [docs/human/CLI.md](docs/human/CLI.md), or
`tog help <command>`. Exit status: 0 success, 1 command failed, 2
usage error; `run` passes the program's status through.

Policy is permissive by default; `.tog/policy.toml` can tighten it
(`deny = ["install-script-failed", "git-dependency"]`), or
`tog sync --strict` denies every exception.

You never install Python or Node yourself: `tog sync` materializes
pinned, verified toolchains into the store and wires `.venv` /
`node_modules` to them. A project with both lockfiles gets both
ecosystems from one sync. Resolution belongs to the ecosystem's own
pinned tool; realization, verification, and provenance belong to
tog.

## Store properties (proven by `tests/acceptance.sh` against real PyPI)

- conflicting dependency versions coexist across projects
- identical locks share one immutable environment object (instant resync)
- environments rebuild offline from the verified artifact cache alone
- lock switches and rollbacks are atomic symlink swaps
- store objects are read-only; nothing mutates an environment in place
- sdists and npm install scripts build hermetically (network denied)

## Test

```sh
cargo test                                # unit and offline tests; CI runs this and cargo fmt --check
cargo test -- --ignored --test-threads=1  # heavy: network, real registries, one store per run under TMPDIR
bash tests/acceptance.sh                  # the full end-to-end checklist
```

On Linux the sandbox is bubblewrap (`dnf install bubblewrap`); set
`TOG_SANDBOX_TESTS=required` to fail instead of skip when it is missing,
and point `TMPDIR` at a real disk, because a small tmpfs fills. A test that
sets `TOG_STORE` uses a temp dir and holds `store::STORE_ENV_LOCK`; a
test that realizes through a child holds `supervise::SUPERVISION_TEST_LOCK`.
`tests/architecture.rs` enforces the layering rules, the store lock, and
that comments describe code rather than cite plans.

## Working across machines

Nothing platform-specific is committed: `.venv`, `node_modules`,
`.tog/` are ignored. Each host keeps its own store; toolchain and
environment object ids include the platform triple, so a shared store
never reuses a Mac object on Linux — only the artifact cache is common,
because artifacts are content-addressed. After switching machines, run
`tog sync` once; it is a cache hit if that host has seen the lock.

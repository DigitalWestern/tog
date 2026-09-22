# tog

One binary that owns the outer loop every language ecosystem shares:
provision a pinned toolchain, realize a locked dependency graph into an
immutable content-addressed store, project an environment, run your code.

Nix's model, without Nix's interface. Seven ecosystems: Python, npm,
Cargo, Go, Ruby, Elixir, .NET. Your `.venv` and `node_modules` become
read-only-backed environments you can rebuild offline, share, and roll
back atomically.

New here? [docs/human/GETTING-STARTED.md](docs/human/GETTING-STARTED.md)
walks from install to a working Python and npm project, with the real
output of every command.

## Six words tog prints at you

| word | what it means |
|---|---|
| **store** | `~/.tog/store`: read-only, content-addressed objects — toolchains, packages, whole environments — shared by every project on the machine |
| **realize** | turn a locked dependency graph into those objects, verifying every download by hash |
| **project** (verb) | point this project's `.venv` or `node_modules` at one realized object, by swapping a single symlink |
| **closure** | `.tog/closures/<ecosystem>.json`: the record a sync leaves behind — which inputs, which objects, which exceptions. `tog audit` judges it |
| **exception** | something a sync had to allow that it cannot fully vouch for: a failed install script, a git dependency, a SHA-1 lock entry. Recorded, never hidden |
| **permissive** | the default policy: record exceptions and carry on. `--strict`, `TOG_STRICT=1`, or a `deny` list refuses them instead |

The bedding words (tailor, pattern, comforter, closet) are internal and the
CLI never prints them; they are defined in
[ARCHITECTURE.md](docs/human/ARCHITECTURE.md#vocabulary).

| Read | For |
|---|---|
| [docs/human/GETTING-STARTED.md](docs/human/GETTING-STARTED.md) | install to first working project |
| [STATUS.md](STATUS.md) | where the project is, what is next |
| [docs/human/ARCHITECTURE.md](docs/human/ARCHITECTURE.md) | how it works |
| [docs/human/CLI.md](docs/human/CLI.md) | the command surface (spec) |
| [docs/human/EDITORS.md](docs/human/EDITORS.md) | VS Code and PyCharm setup |
| [docs/human/LIMITATIONS.md](docs/human/LIMITATIONS.md) | what it honestly cannot do |
| [FOLLOW-UPS.md](FOLLOW-UPS.md) | the to-do list and open decisions |
| [docs/agent/DESIGNS.md](docs/agent/DESIGNS.md) | designed but unbuilt work (for agents) |
| [docs/human/ADDING-A-TAILOR.md](docs/human/ADDING-A-TAILOR.md) | adding an ecosystem |

## Host prerequisites

Tog downloads every language toolchain itself, but native builds
compile against the host C toolchain, and the Linux build sandbox uses
bubblewrap.

```sh
# Ubuntu / Debian
sudo apt install bubblewrap build-essential pkg-config patch \
  zlib1g-dev libxcrypt-dev

# Fedora
sudo dnf install bubblewrap gcc gcc-c++ make binutils glibc-devel \
  pkgconf-pkg-config patch zlib-ng-compat-devel libxcrypt-devel

# Arch
sudo pacman -S bubblewrap base-devel pkgconf patch zlib libxcrypt

# macOS: the command-line tools; the sandbox is the system's own
xcode-select --install
```

`tog doctor` prints the command for the host it runs on. Ubuntu 22.04's
bubblewrap cannot run tog's sandbox (issue #87); Ubuntu 24.04 and
Debian 13 work.

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
that finishes the job there (`source ~/.tog/env`). It also prints where the
store is and roughly how big it gets, and names the version it replaced when
one was already there. Options: `--dir=<path>`, `--version=<tag>`,
`--no-modify-path`, `--no-completions`; the header of
[install.sh](install.sh) lists every file it touches.

To undo it, run the same script with `--uninstall`:

```sh
curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh -s -- --uninstall
```

That removes the binary, `~/.tog/env`, the completions, and the PATH blocks
it added. It does not remove the store: it prints its path and size and the
`rm -rf` that would, because the store is downloaded data, not the program.

To update later, ask the binary itself:

```sh
tog update --self
```

It reads the newest release from GitHub, stops when this build already is
that version, and otherwise downloads the binary for your machine, checks
the sha256 the release publishes, and renames it over the running one. It
refuses, naming the directory, when that directory is not writable. `tog
doctor` says when a newer release exists (one request; "not checked" when
offline), and `tog --version` prints the commit and its date, so a stale
binary can be told from a current one. Nothing checks in the background.

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
tog             # set up ./.venv and/or ./node_modules from the lockfiles, then show the help
tog run python app.py       # run one command inside the environment(s)
tog dev                     # a package.json script, without the 'run'
tog test --watch            # same; every later argument is the script's
eval "$(tog env)"           # or put the environment in this whole shell
tog add requests            # add a dependency with the ecosystem's own tool
tog x ruff check .          # run a tool without adding it (like uvx / npx)
tog build                   # sandboxed Cargo build (network denied)
tog status                  # is the projection still current with the lock?
tog update --toolchain      # re-select the runtimes and rewrite tog-toolchain.toml
tog gc --dry-run            # preview unreferenced store/cache cleanup
tog doctor                  # host prerequisites, sandbox, store, free space, newer release?
tog update --self           # replace this binary with the newest release
tog --version               # tog 0.1.0 (7688cfd 2026-09-21): crate version, commit, date
```

`tog <script>` is the short form of `tog run <script>` for any package.json
script whose name is not a tog command; a built-in always wins, so `tog
build` is the sandboxed build and never a script called build. Use `tog run
build` for that one. Arguments go to the script unchanged, so there is no
npm-style `--` separator to remember: `tog test --watch`, not
`tog test -- --watch`.

`tog env` prints the environment as shell exports instead of running one
command in it. For a whole directory rather than a whole shell, hand it to
direnv: `echo 'eval "$(tog env)"' > .envrc && direnv allow`. Editors need
the same thing plus one interpreter path —
[docs/human/EDITORS.md](docs/human/EDITORS.md) has both, and says which of
their package-install buttons will not work against a read-only projection.

Full command reference: [docs/human/CLI.md](docs/human/CLI.md), or
`tog help <command>`, which opens with worked examples of that command.
Exit status: 0 success, 1 command failed, 2 usage error; `run` passes the
program's status through.

Policy is permissive by default; `.tog/policy.toml` can tighten it
(`deny = ["install-script-failed", "git-dependency"]`), or
`tog --strict` denies every exception.

You never install Python or Node yourself: a bare `tog` materializes
pinned, verified toolchains into the store and wires `.venv` /
`node_modules` to them. Your first sync writes `tog-toolchain.toml` next to
your manifests, naming the exact runtime per ecosystem; commit it, and
everyone who syncs the repo afterwards gets that runtime. `tog
--frozen` checks the file instead of writing one, and `tog update
--toolchain` is the only thing that moves a locked runtime. A project with both lockfiles gets both
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

## What `.tog/` holds, and what to commit

A sync writes a `.tog/` directory next to your lockfiles. Two things in it
are records that a reviewer and CI need, and the rest is a machine-local
cache. `tog audit`, the CI admission gate, reads only the first two, so a
repository that ignores all of `.tog/` can never make `tog audit` pass.

| path | commit? | what it is |
|---|---|---|
| `tog-toolchain.toml` | **yes** (it is outside `.tog/`) | the exact toolchain per ecosystem, written by your first sync. Everyone who syncs this repo gets that runtime; `tog update --toolchain` is the only thing that moves it |
| `.tog/closures/*.json` | **yes** | one record per ecosystem: inputs, object ids, exceptions, signature. `tog audit`, `tog ls`, `tog sbom` and `tog status` read it |
| `.tog/policy.toml` | **yes**, if you use one | the project's deny list, merged with the machine policy. See [docs/human/policy-company.toml](docs/human/policy-company.toml) |
| `.tog/plan.json`, `.tog/go-plan.json` | no | plan cache, keyed by input hash |
| `.tog/manifest-*.txt`, `.tog/lock-source.hash`, `.tog/egg-info.json` | no | Python manifest snapshots and stamps |
| `.tog/cargo-home/` | no | the Cargo config and shim a sandboxed build runs with |

The matching `.gitignore` stanza — ignore the cache, keep the records. The
`**/` is not decoration: a monorepo gets one `.tog/` per subproject, and a
root-anchored `.tog/*` would miss every one of them.

```gitignore
.venv
node_modules/
**/.tog/*
!**/.tog/closures/
!**/.tog/policy.toml
```

Three things to know before you adopt this.

- A committed closure is a *record*, not a certificate. `tog ls` and
  `tog sbom` read one with no store and no projection, and a closure diff is
  how a reviewer sees that a pull request added a `git-dependency`. But
  `tog status` and `tog audit` also check the local `.venv` /
  `node_modules`, so on a fresh checkout they exit 1 until something syncs.
  A CI gate therefore syncs first and audits what that sync wrote.
- A closure is one file per ecosystem, not one per platform, and it records
  the platform it was synced on, so a mixed Mac and Linux team overwrites
  one record with the other; the loser reads `elsewhere` in `tog status`.
- Every sync rewrites the record's `projected_at`, so a local sync
  dirties the committed file even when nothing about the environment
  changed.

The last two point the same way: let one protected job on one platform write
the closures that get committed. The CI recipe is in
[docs/human/CLI.md](docs/human/CLI.md#gating-a-pull-request-with-sync-and-audit).

## Working across machines

Nothing platform-specific is committed: `.venv`, `node_modules` and the
cached half of `.tog/` are ignored; the closures and the project policy are
committed. Each host keeps its own store; toolchain and environment object
ids include the platform triple, so a shared store never reuses a Mac object
on Linux — only the artifact cache is common, because artifacts are
content-addressed. After switching machines, run `tog` once; it is a
cache hit if that host has seen the lock.

## License

MIT. See [LICENSE](LICENSE).

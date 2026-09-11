# blanket

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
| [FOLLOW-UPS.md](FOLLOW-UPS.md) | what is owed and flagged |
| [docs/agent/](docs/agent/) | review ledgers, evidence, design history (for agents) |

## Host prerequisites

Blanket downloads every language toolchain itself, but native builds
compile against the host C toolchain, and the Linux build sandbox uses
bubblewrap. On Fedora:

```sh
sudo dnf install bubblewrap gcc gcc-c++ make binutils glibc-devel \
  pkgconf-pkg-config patch zlib-ng-compat-devel libxcrypt-devel
```

## Use

```sh
cargo build --release

cd your-project     # an EXISTING project works as-is:
blanket             # realize + project -> ./.venv and/or ./node_modules
blanket run python app.py       # run inside the projected env(s)
blanket add requests            # add a dependency with the ecosystem's own tool
blanket x ruff check .          # run a tool without adding it (like uvx / npx)
blanket build                   # sandboxed Cargo build (network denied)
blanket gc --dry-run            # preview unreferenced store/cache cleanup
blanket doctor                  # host prerequisites, sandbox, store, free space
blanket --version
```

Full command reference: [docs/human/CLI.md](docs/human/CLI.md), or
`blanket help <command>`. Exit status: 0 success, 1 command failed, 2
usage error; `run` passes the program's status through.

Policy is permissive by default; `.blanket/policy.toml` can tighten it
(`deny = ["install-script-failed", "git-dependency"]`), or
`blanket sync --strict` denies every exception.

You never install Python or Node yourself: `blanket sync` materializes
pinned, verified toolchains into the store and wires `.venv` /
`node_modules` to them. A project with both lockfiles gets both
ecosystems from one sync. Resolution belongs to the ecosystem's own
pinned tool; realization, verification, and provenance belong to
blanket.

## Store properties (proven by `tests/acceptance.sh` against real PyPI)

- conflicting dependency versions coexist across projects
- identical locks share one immutable environment object (instant resync)
- environments rebuild offline from the verified artifact cache alone
- lock switches and rollbacks are atomic symlink swaps
- store objects are read-only; nothing mutates an environment in place
- sdists and npm install scripts build hermetically (network denied)

## Test

```sh
cargo test               # unit tests (no network)
bash tests/acceptance.sh # end-to-end (network, real PyPI, throwaway store)
```

## Working across machines

Nothing platform-specific is committed: `.venv`, `node_modules`,
`.blanket/` are ignored. Each host keeps its own store; toolchain and
environment object ids include the platform triple, so a shared store
never reuses a Mac object on Linux — only the artifact cache is common,
because artifacts are content-addressed. After switching machines, run
`blanket sync` once; it is a cache hit if that host has seen the lock.

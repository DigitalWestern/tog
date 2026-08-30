# blanket

One binary that owns the outer loop every language ecosystem shares:
provision a toolchain, realize a locked dependency graph into an immutable
content-addressed store, project an environment, run your code.

Nix's model, without Nix's interface. See [ARCHITECTURE.md](ARCHITECTURE.md)
and [blanket-notes.md](blanket-notes.md) for the design history.

The vocabulary: each language gets a **tailor** (adapter) that cuts its
ecosystem's packages into a **pattern** (locked plan), which blanket
realizes into a **comforter** (an immutable, shareable environment) kept
in the **closet** (the store). Your `.venv` and `node_modules` are
comforters.

**Status: MVP — Python + Node ecosystems, macOS arm64.**

## Use

```sh
cargo build --release

cd your-project
# blanket consumes hash-pinned lockfiles (no solver of its own yet):
uv pip compile --generate-hashes requirements.in -o requirements.txt  # python
npm install --package-lock-only                                      # node
echo "3.12" > .python-version   # optional; 3.12 is the default

blanket sync                    # realize + project -> ./.venv and/or ./node_modules
blanket run python app.py       # run inside the projected env(s)
blanket run node index.js
blanket plan                    # show the locked plan(s) (JSON)
blanket store path              # where the store lives
```

You never install Python or Node: `blanket sync` materializes pinned,
verified toolchains (python-build-standalone CPython; nodejs.org Node)
into the store and wires `.venv` / `node_modules` to them. A project with
both lockfiles gets both ecosystems from one sync — one kernel, two
adapters.

Properties the store gives you (see `tests/acceptance.sh`, which proves
each one against real PyPI):

- conflicting dependency versions coexist across projects
- identical locks share one immutable environment object (instant resync)
- environments rebuild offline from the verified artifact cache alone
- lock switches and rollbacks are atomic symlink swaps
- store objects are read-only; nothing can mutate an environment in place
- sdists build hermetically (sandbox-exec, network denied) and a build
  that attempts network access fails
- npm lockfiles realize to immutable node_modules trees; polyglot
  projects sync both ecosystems in one command

## Test

```sh
cargo test               # unit tests (no network)
bash tests/acceptance.sh # end-to-end (network, real PyPI, throwaway store)
```

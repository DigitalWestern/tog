# blanket

One binary that owns the outer loop every language ecosystem shares:
provision a toolchain, realize a locked dependency graph into an immutable
content-addressed store, project an environment, run your code.

Nix's model, without Nix's interface. See [ARCHITECTURE.md](ARCHITECTURE.md)
and [blanket-notes.md](blanket-notes.md) for the design history.

**Status: MVP — Python ecosystem, macOS arm64.**

## Use

```sh
cargo build --release

cd your-python-project
# blanket consumes hash-pinned lockfiles (no solver of its own yet):
uv pip compile --generate-hashes requirements.in -o requirements.txt
echo "3.12" > .python-version   # optional; 3.12 is the default

blanket sync                    # realize + project -> ./.venv
blanket run python app.py       # run inside the projected env
blanket plan                    # show the locked plan (JSON)
blanket store path              # where the store lives
```

You never install Python: `blanket sync` materializes a pinned, verified
CPython (astral-sh/python-build-standalone) into the store and wires
`.venv` to it.

Properties the store gives you (see `tests/acceptance.sh`, which proves
each one against real PyPI):

- conflicting dependency versions coexist across projects
- identical locks share one immutable environment object (instant resync)
- everything reconstructs offline from the artifact cache
- lock switches and rollbacks are atomic symlink swaps
- store objects are read-only; nothing can mutate an environment in place

## Test

```sh
cargo test               # unit tests (no network)
bash tests/acceptance.sh # end-to-end (network, real PyPI, throwaway store)
```

# blanket

One binary that owns the outer loop every language ecosystem shares:
provision a toolchain, realize a locked dependency graph into an immutable
content-addressed store, project an environment, run your code.

Nix's model, without Nix's interface. See [ARCHITECTURE.md](ARCHITECTURE.md)
for how it works, [ROADMAP.md](ROADMAP.md) for where it's pointed
(enterprise supply-chain security + the four pillars), and
[blanket-notes.md](blanket-notes.md) for the design history.

The vocabulary: each language gets a **tailor** (adapter) that cuts its
ecosystem's packages into a **pattern** (locked plan), which blanket
realizes into a **comforter** (an immutable, shareable environment) kept
in the **closet** (the store). Your `.venv` and `node_modules` are
comforters.

**Status: all seven ecosystems pass the acceptance checklist on both platforms: Linux x86_64 (Fedora 44) and macOS arm64 (macOS 26.6.2), both on 2026-09-05 at commit dbf7ac4.** Every darwin pin and store identity is byte-identical to the pre-port tree; the Mac runs after the merge found two fixture/latent bugs, both fixed (LINUX_PORT.md changelog). Python + Node are proven on real projects; the others on the fixtures in `tests/`.
Proven on: Next.js 15 (build + vitest), vite apps (build AND dev server),
prisma (generate/query), native addons compiled hermetically
(better-sqlite3 from source, sharp via declared artifacts), npm
workspaces, FastAPI + pandas/lxml stacks.

## Linux host prerequisites

Blanket downloads every language toolchain itself, but native builds
compile against the host C toolchain (like Xcode CLT on macOS) and the
build sandbox uses bubblewrap. On Fedora:

```sh
sudo dnf install bubblewrap gcc gcc-c++ make binutils glibc-devel \
  pkgconf-pkg-config patch zlib-ng-compat-devel libxcrypt-devel
```

Unprivileged user namespaces must be enabled (`/proc/sys/user/max_user_namespaces` > 0;
Fedora's default). SELinux enforcing is fine.

## Use

```sh
cargo build --release

cd your-project     # an EXISTING project works as-is:
blanket sync        # realize + project -> ./.venv and/or ./node_modules
blanket run python app.py       # run inside the projected env(s)
blanket run vite dev
blanket plan                    # show the locked plan(s) (JSON)
blanket build                   # sandboxed Cargo build (network denied)
blanket store path              # where the store lives
blanket sync --fresh            # rebuild the projection (drops caches)
```

Policy is permissive by default; `.blanket/policy.toml` can tighten it:

```toml
# .blanket/policy.toml
strict = false
deny = [
  "install-script-failed",
  "git-dependency",
]
```

Use `blanket sync --strict` or `BLANKET_STRICT=1` to deny every exception.

`blanket run dev` / `blanket run test` runs the `package.json` script inside the projected env; the script wins over a same-named PATH executable.

`sync` meets projects where they are: it discovers `requirements.txt`,
Poetry/PDM/uv/hatch `pyproject.toml` metadata, `setup.cfg`, computed
`setup.py` metadata, and conventional `requirements/` files in that order.
Ranged inputs are locked via the store uv (`requirements.lock.txt`,
hash-pinned, auto-refreshed); Poetry and uv lockfiles are imported when their
host-compatible hashes are available. Optional/dev groups are excluded by
default. A found manifest with no dependencies succeeds as an interpreter-only
empty environment, while a directory with no Python manifest reports
`no_manifest` and a broken found file reports `unreadable_manifest`. A
`setup.py egg_info` probe runs read-only in the network-denied build sandbox
and is cached by the manifest tree hash. A
`package.json` without `package-lock.json` (bun/yarn projects) gets one
via npm; an existing real `node_modules`/`.venv` is moved aside to
`~/.blanket/backups/`. Resolution belongs to the ecosystem's tools —
realization, verification, and provenance belong to blanket.

Python uses the explicit `.python-version` request when present; otherwise
it intersects `requires-python`/`python_requires` metadata and selects the
default CPython 3.12.14 when compatible, or the newest compatible pinned
CPython 3.10.21, 3.11.16, 3.12.14, 3.13.15, or 3.14.7.

npm install scripts run inside a network-denied sandbox with pinned
toolchains (store node headers + pinned CPython for node-gyp). Two escape
hatches, both explicit in `package.json`:

```jsonc
"blanket": {
  // packages that must write into their own directory at runtime (prisma):
  "mutablePackages": ["@prisma/engines"],
  // install-time downloads, declared as verified inputs (old sharp):
  "artifacts": [{ "url": "https://...", "sha256": "<hex>",
                  "path": ".npm/_libvips/libvips-8.14.5-darwin-arm64v8.tar.br" }]
}
```

You never install Python or Node: `blanket sync` materializes pinned,
verified toolchains (python-build-standalone CPython; nodejs.org Node)
into the store and wires `.venv` / `node_modules` to them. A project with
both lockfiles gets both ecosystems from one sync — one kernel, two
adapters.

Cargo projects use the pinned store Rust toolchain and a vendor directory
source. `blanket build` runs Cargo in the network-denied sandbox; `blanket run
cargo ...` uses the projected offline wrapper without sandboxing. `cargo
install` through that wrapper writes unmanaged binaries into the projected
Cargo home and is not recorded in `cargo-closure.json`.

Properties the store gives you (see `tests/acceptance.sh`, which proves
each one against real PyPI):

- conflicting dependency versions coexist across projects
- identical locks share one immutable environment object (instant resync)
- environments rebuild offline from the verified artifact cache alone
- lock switches and rollbacks are atomic symlink swaps
- store objects are read-only; nothing can mutate an environment in place
- sdists AND npm install scripts build hermetically (sandbox-exec,
  network denied); a script that cannot complete is retained with an
  `install-script-failed` exception (strict mode refuses it)
- node_modules projects as a writable forest over immutable store
  packages: tool caches (vite) work, package contents can't be mutated
- polyglot projects sync both ecosystems in one command

## Test

```sh
cargo test               # unit tests (no network)
bash tests/acceptance.sh # end-to-end (network, real PyPI, throwaway store)
```

## Working across machines

A project can be synced on a Mac and on a Linux box in turn. Nothing
platform-specific is committed: `.venv`, `node_modules`, `.blanket/` are
ignored. Each host keeps its own store; toolchain and environment object
ids include the platform triple, so a store shared between platforms (or
rsynced) never reuses a Mac object on Linux — only the artifact cache
(`cache/sha256/`) is common, because artifacts are content-addressed.
`.blanket/closures/<eco>.json` records the `platform` it was projected on.
After switching machines, run `blanket sync` once; it is a cache hit if
that host has seen the lock before.

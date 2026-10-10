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
| [docs/human/PRODUCT.md](docs/human/PRODUCT.md) | what tog is as a product: the deliverables, who each is for, what is open and what is not |
| [CONTRIBUTING.md](CONTRIBUTING.md) | the license and the sign-off rule |
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

`tog doctor` prints the command for the host it runs on. Ubuntu 23.10
and later restrict unprivileged user namespaces through AppArmor, which
bubblewrap needs; when bubblewrap is refused a namespace and that switch
is on, `tog doctor` names it.

## Install

Releases are built by
[.github/workflows/release.yml](.github/workflows/release.yml) on a `v*`
tag, for Linux x86_64 only (macOS arm64 waits on #66). On Linux x86_64
this is one line. It downloads the release binary for your machine, checks
its sha256, puts it in `~/.local/bin`, adds that directory to PATH if it is
not already there, and installs bash, zsh, and fish completions:

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

To update an installed release later, ask the binary itself:

```sh
tog update --self
```

It reads the newest release from GitHub, stops when this build already is
that version, and otherwise downloads the binary for your machine, checks
the sha256 the release publishes, and renames it over the running one. It
refuses, naming the directory, when that directory is not writable. `tog
doctor` says when a newer release exists (one request; "not checked" when
offline, or while no release can be read; an `ok` row naming this machine
when that release has no build for it), and `tog --version` prints the
commit and its date, so a stale binary can be told from a current one.
Nothing checks in the background. Both ask GitHub without logging in.
Releases are built for Linux x86_64 only for now.

### From source

On any other machine, or to run the current `main`: you need a Rust
toolchain from [rustup](https://rustup.rs); `cargo install` puts the binary
in `~/.cargo/bin`, which rustup already added to PATH:

```sh
git clone https://github.com/DigitalWestern/tog
cd tog
cargo install --path . --locked
tog completions zsh > ~/.zfunc/_tog   # bash | zsh | fish; optional
```

`cargo install --git https://github.com/DigitalWestern/tog --locked` does
the same without keeping a checkout. Do not `cargo install tog` from
crates.io: that name belongs to an unrelated crate. To update a source
install, pull and run `cargo install --path . --locked` again.

## Use

```sh
cd your-project     # an EXISTING project works as-is:
tog             # set up ./.venv and/or ./node_modules from the lockfiles, then show what to run next
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

`tog <file>` is the same short form for a source file: `tog app.py` runs
`python app.py` in the project's environment, `tog main.go` runs `go run
main.go`. The extension picks the runtime (`.py`, `.js`, `.mjs`, `.cjs`,
`.ts`, `.mts`, `.cts`, `.rb`, `.exs`, `.go`), the project has to have that
ecosystem, and a `.rs` or `.cs` file points at `tog build` instead.

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
bash tests/install.sh                     # the installer, offline; CI runs this after cargo build
cargo test -- --ignored --test-threads=2  # heavy: network, real registries, scratch stores under TMPDIR
bash tests/acceptance.sh                  # the full end-to-end checklist
```

CI (`.github/workflows/ci.yml`) runs the first two on every PR. The last
two download toolchains and packages, so they run weekly instead, in
`.github/workflows/heavy.yml`; start it by hand from the Actions tab. It
also runs on a PR that changes tar extraction or downloads
(`src/kernel/archive.rs`, `src/kernel/fetch.rs`), the toolchain
providers or a catalog, `Cargo.lock`, or the heavy suite itself, and on
any PR with the `heavy` label (the list is in heavy.yml's `gate` job).
The label comes off after the first green run
(`.github/workflows/heavy-unlabel.yml`); add it again to rerun. CI skips a
change to only `FOLLOW-UPS.md` or `STATUS.md`.

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
| `.tog/resolution/*.json` | **yes** | one signed resolution record per lock: which tog door produced the lock and manifest, in which isolation, and the ledger of every fetch. `tog attest` writes them; a sync's join checks them |
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
!**/.tog/resolution/
!**/.tog/policy.toml
```

Only receipts live in `.tog/resolution/`. The journals a door keeps while
it runs are in `.tog/journal/`, which stays ignored.

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

## Signing locks: who attests

A lock is trusted when a signed resolution record says a tog door produced
it: the ecosystem's own tool ran confined (bubblewrap, or rootless podman
where bubblewrap cannot run), reached its registry only through tog's
proxy, and every fetch went into a ledger. The company policy
([docs/human/policy-company.toml](docs/human/policy-company.toml)) denies a
lock without one (`unrecorded-resolution`). `tog attest` is how a
repository's existing locks get records: it runs each ecosystem's own lock
check confined and signs the result only when the lock comes out
byte-unchanged. Some existing locks need migration first. A hand-pinned
Python requirements file has no resolver provenance and must be recompiled
through Tog before attestation. See [the attest migration rules](docs/human/CLI.md).

Two setups. Both are verified the same way, against the `[signing]` keys
in the machine policy.

**On CI, the default.** Keep the signing key in an operator-controlled
workflow and binary. `tog attest` may evaluate project code, but only
inside confined resolution tools. The keyless gate verifies the signed
records against machine trust and the same candidate files.

The worked example below is a manual candidate-verification workflow.
Run it from the protected default branch, with the full candidate commit
SHA. Configure `tog-attest` as a protected environment that permits only
that branch, requires operator approval of the candidate and does not
allow approval bypass. Store `TOG_ATTEST_KEY` in that environment, not as
a repository-wide secret. Set the operator-owned repository variables
`TOG_ATTEST_PUBKEY`, `TOG_INSTALL_REF` (a reviewed full commit SHA from the
Tog repository) and `TOG_VERSION` (a reviewed release tag with these
commands). All three jobs check out the identical candidate and install
the same release. None executes a workflow or installer from the candidate.

Branch protection alone does not make a pull request's workflow trusted.
Do not put the signing secret in a candidate-controlled `pull_request`
workflow or run candidate scripts through `pull_request_target`. See
[GitHub's workflow security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
and [environment protections](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

```yaml
name: Tog candidate verification
on:
  workflow_dispatch:
    inputs:
      candidate_sha:
        description: Reviewed candidate commit (full 40-character SHA)
        required: true
        type: string
permissions:
  contents: read

env:
  TOG_CANDIDATE_SHA: ${{ inputs.candidate_sha }}
  TOG_INSTALL_REF: ${{ vars.TOG_INSTALL_REF }}
  TOG_VERSION: ${{ vars.TOG_VERSION }}

jobs:
  attest:
    if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-22.04
    environment: tog-attest
    steps:
      - name: Validate the candidate identity
        run: '[[ "$TOG_CANDIDATE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]'
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: ${{ env.TOG_CANDIDATE_SHA }}
          path: candidate
          persist-credentials: false
      - name: Install the reviewed Tog release and isolation backend
        run: |
          [[ "$TOG_INSTALL_REF" =~ ^[0-9a-fA-F]{40}$ ]]
          test -n "$TOG_VERSION"
          sudo apt-get update
          sudo apt-get install -y bubblewrap
          curl -fsSL "https://raw.githubusercontent.com/DigitalWestern/tog/$TOG_INSTALL_REF/install.sh" \
            | sh -s -- --version="$TOG_VERSION" --dir="$RUNNER_TEMP/tog-bin" --no-modify-path --no-completions
          echo "$RUNNER_TEMP/tog-bin" >> "$GITHUB_PATH"
      - name: Attest only through confined resolution tools
        id: attest
        working-directory: candidate
        run: |
          umask 077
          attest_key_file=$(mktemp "$RUNNER_TEMP/tog-key.XXXXXX")
          trap 'rm -f "$attest_key_file"' EXIT
          record_dir=$(mktemp -d "$RUNNER_TEMP/tog-records.XXXXXX")
          printf '%s' "$TOG_ATTEST_KEY" > "$attest_key_file"
          unset TOG_ATTEST_KEY
          TOG_SIGNING_KEY="$attest_key_file" tog attest --record-out "$record_dir"
          printf 'records=%s\n' "$record_dir" >> "$GITHUB_OUTPUT"
        env:
          TOG_ATTEST_KEY: ${{ secrets.TOG_ATTEST_KEY }}
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: resolution-records
          path: ${{ steps.attest.outputs.records }}
          if-no-files-found: error

  gate:
    needs: attest
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: ${{ env.TOG_CANDIDATE_SHA }}
          path: candidate
          persist-credentials: false
      - name: Install the reviewed Tog release and isolation backend
        run: |
          [[ "$TOG_INSTALL_REF" =~ ^[0-9a-fA-F]{40}$ ]]
          test -n "$TOG_VERSION"
          sudo apt-get update
          sudo apt-get install -y bubblewrap
          curl -fsSL "https://raw.githubusercontent.com/DigitalWestern/tog/$TOG_INSTALL_REF/install.sh" \
            | sh -s -- --version="$TOG_VERSION" --dir="$RUNNER_TEMP/tog-bin" --no-modify-path --no-completions
          echo "$RUNNER_TEMP/tog-bin" >> "$GITHUB_PATH"
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4
        with:
          name: resolution-records
          path: ${{ runner.temp }}/resolution-records
      - name: Verify resolution receipts and enforce policy
        working-directory: candidate
        run: |
          printf '[signing]\ntrusted = ["%s"]\n' "$TOG_ATTEST_PUBKEY" > "$RUNNER_TEMP/policy.toml"
          export TOG_POLICY="$RUNNER_TEMP/policy.toml"
          tog --strict sync --frozen --resolution-record "$RUNNER_TEMP/resolution-records"
        env:
          TOG_ATTEST_PUBKEY: ${{ vars.TOG_ATTEST_PUBKEY }}

  test:
    needs: gate
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: ${{ env.TOG_CANDIDATE_SHA }}
          path: candidate
          persist-credentials: false
      - name: Install the reviewed Tog release and isolation backend
        run: |
          [[ "$TOG_INSTALL_REF" =~ ^[0-9a-fA-F]{40}$ ]]
          test -n "$TOG_VERSION"
          sudo apt-get update
          sudo apt-get install -y bubblewrap
          curl -fsSL "https://raw.githubusercontent.com/DigitalWestern/tog/$TOG_INSTALL_REF/install.sh" \
            | sh -s -- --version="$TOG_VERSION" --dir="$RUNNER_TEMP/tog-bin" --no-modify-path --no-completions
          echo "$RUNNER_TEMP/tog-bin" >> "$GITHUB_PATH"
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4
        with:
          name: resolution-records
          path: ${{ runner.temp }}/resolution-records
      - name: Verify again, then run the project's tests without the key
        working-directory: candidate
        run: |
          printf '[signing]\ntrusted = ["%s"]\n' "$TOG_ATTEST_PUBKEY" > "$RUNNER_TEMP/policy.toml"
          export TOG_POLICY="$RUNNER_TEMP/policy.toml"
          tog --strict sync --frozen --resolution-record "$RUNNER_TEMP/resolution-records"
          tog run npm test
        env:
          TOG_ATTEST_PUBKEY: ${{ vars.TOG_ATTEST_PUBKEY }}
```

Replace `tog run npm test` with the project's actual test command. `tog run`
executes on the host, so this last job must be disposable and hold no key or
other secrets. The attestation artifact stays outside the checkout in every
job. That prevents candidate symlinks from controlling host-side upload and
keeps added receipt files out of executable-manifest input coverage. The key
is removed even on failure, before artifact upload.

This gate verifies resolution signatures during a fresh policy-enforced
sync. Its keyless sync writes unsigned closure records, so `tog audit`
under the trusted-key policy would refuse those closures. Signed resolution
receipts do not sign closures. A signed-closure gate needs a separate trusted
closure-producing setup.

`--strict` rejects every exception, including `resolution-build` and
`stale-resolution`, which the company template deliberately permits. A team
that permits those kinds should use its operator-owned machine deny policy
with the trusted keys instead of `--strict`. Project policy can narrow
machine trust and denials. It cannot supply the gate's trust roots.

This manual workflow's Actions check belongs to its default-branch run,
not automatically to the candidate pull request. Automatic required checks
need a separately reviewed result-publishing flow that binds its verdict to
that exact candidate SHA. A skipped signing job is not a passed gate. Fork
pull requests do not receive repository secrets in ordinary `pull_request`
workflows. Maintainers can verify a fork commit with the trusted workflow
after choosing and approving that exact commit.

The alternative is a bot commit from the same trusted signing setup:
`tog attest` without `--record-out` writes `.tog/resolution/`, which the bot
commits to the candidate branch. The keyless gate then uses
`tog --strict sync --frozen` with no record flag. This still needs immutable
candidate selection and a protected key-holding workflow.

**Per developer.** Each developer makes a key (`tog keygen <path>`), sets
`TOG_SIGNING_KEY=<path>`, and the team lists every public key in the
machine policy's `[signing] trusted` set on the gate. Then `tog add`,
`tog update` and a missing-lock sync sign their own records as they
write the lock, and the developer commits `.tog/resolution/` with it. A
laptop that runs project code holds a key this way, which is why CI
signing is the default.

## Working across machines

Nothing platform-specific is committed: `.venv`, `node_modules` and the
cached half of `.tog/` are ignored; the closures and the project policy are
committed. Each host keeps its own store; toolchain and environment object
ids include the platform triple, so a shared store never reuses a Mac object
on Linux — only the artifact cache is common, because artifacts are
content-addressed. After switching machines, run `tog` once; it is a
cache hit if that host has seen the lock.

## License

Apache-2.0. See [LICENSE](LICENSE). Contributions are accepted under
the Developer Certificate of Origin, one `Signed-off-by` line per commit;
[CONTRIBUTING.md](CONTRIBUTING.md) has the rule and the one command.

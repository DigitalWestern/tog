# Blanket CLI — the plan for levels one and two

*Written 2026-09-06. Status: levels one and two are implemented on branch
`cli/levels-1-2` (PR #20) and not yet merged to main; this document is the
spec they were built against, kept as written so the two can be compared.
Unreviewed — see REVIEW.md entry 1. Level three (blanket standing in for
pip/npm/cargo in the shell, shims, activation) is deliberately out of scope
here and gets its own document when we come back to it.*

The thesis, one line: **blanket wins by being the easiest tool in the room,
and the CLI is where easy is decided.** Every verb below is judged by one
question: does a developer who has never read ARCHITECTURE.md get what they
wanted on the first try, and when they don't, does the message tell them the
next command to type?

## The target help screen (this is the spec)

```
blanket 0.1.0 — one command for every package manager

USAGE:
  blanket [<options>] <command> [<args>...]
  blanket                      in a project: the same as 'blanket sync'
  blanket <script> [<args>...] run a package.json script (like 'npm run')

EVERYDAY:
  sync       realize and project the environment(s) from the project's inputs
  add        add a dependency, re-lock, sync
  remove     remove a dependency, re-lock, sync
  update     update dependencies within the manifest's constraints, sync
  run        run a command or script inside the environment(s)
  x          run a tool without adding it to the project (like npx / uvx)
  build      sandboxed, network-denied build (cargo | go | elixir | dotnet)
  fmt        format a Rust project with the pinned rustfmt

INSPECT:
  status     is the projection current with the manifest and the lock?
  ls         list what is installed, per ecosystem
  plan       print the locked plan(s) as JSON
  sbom       CycloneDX 1.5 SBOM of the synced closures
  doctor     check host prerequisites, the sandbox, and the store

MAINTAIN:
  gc         collect unreferenced store objects and cached artifacts
  store      'store path', 'store roots'
  completions print a shell completion script (bash | zsh | fish)
  help       show help for a command
  version    print the version

OPTIONS:
  -C, --directory <dir>  run as if blanket had been started in <dir>
  -q, --quiet            only errors and results on stdout
  -v, --verbose          show every subprocess and decision
      --no-color         plain output (also: NO_COLOR, or a non-tty stderr)
  -h, --help             print help ('blanket help <command>' for one command)
  -V, --version          print the version

PROJECT INPUTS ...        (the existing block; `.python-version` accepts a
                           minor request or an exact pinned patch)
ENVIRONMENT ...           (BLANKET_STORE, BLANKET_STRICT, BLANKET_POLICY)

Exit status: 0 success, 1 failure, 2 usage error; 'run', 'x' and 'fmt' pass
the program's exit status through.
```

The kernel's vocabulary (plan, store, closure, sbom) is demoted to INSPECT
and MAINTAIN. Tailor, comforter, closet never appear in argv or in help; they
live in the docs.

For Python, `.python-version` uses canonical uv-style request shapes:
`X.Y` selects the newest pinned patch for that minor, while `X.Y.Z` selects
only that exact pinned build. Release components must be decimal with no
leading zeroes; an unavailable exact patch fails with the available pinned
versions and the instruction to request `X.Y` when the pinned patch is
acceptable.

---

## Level one: one grammar

### What is wrong today

- `blanket sync --fersh` silently syncs without `--fresh`; `blanket sync now`
  silently ignores `now`. Every flag-taking command uses `any()` or a
  positional peek. "Never loosen anything silent" is a project rule and the
  CLI breaks it on line one.
- No `--help`, `-h`, `help <cmd>`, or `--version`. Everything unknown prints
  the whole usage blob to stderr and exits 2, including a typo.
- Exit codes disagree: a bad `gc` flag exits 1, a bad top-level word exits 2.
- `sbom` only understands `--output` as its first word; no `-o`, no
  `--output=`.
- `store` with no subcommand prints the full usage instead of the two words
  it accepts.
- Help, parsing, and 1,400 lines of orchestration all live in `main.rs`.

### The rules

1. **Every argument is validated.** Unknown option or stray positional →
   `blanket: error: sync: unknown option '--fersh'; did you mean '--fresh'?`
   then `Run 'blanket help sync' for usage.` and exit 2. Suggestions come
   from edit distance ≤ len/3 or a prefix relation, never for one-letter
   words, so they are rarely wrong and never noisy.
2. **Help everywhere, on stdout, exit 0.** `blanket help`, `blanket help
   <cmd>`, `blanket <cmd> -h|--help`, `blanket -h|--help`. `blanket` with no
   arguments outside a project prints usage to stderr and exits 2 (unchanged;
   level two changes what it does *inside* a project).
3. **Version.** `blanket version`, `-V`, `--version` → `blanket 0.1.0`.
4. **Pass-through is sacred.** `run` and `build` hand every argument after
   the program/ecosystem to the tool unchanged. Only a *leading* `-h`/`--help`
   is blanket's; `--` forces pass-through. `blanket build --release` and
   `blanket run dotnet --version` keep working exactly as they do now.
5. **`-C <dir>`** before the command, like make and git. Nothing else changes.
6. **One exit-status contract**: 0, 1, 2 as above; `run` passes the child's
   status through (signals → 128+n, already the case for scripts).
7. **One parser module**, `src/cli.rs`, pure and unit-tested: argv in,
   `Command` enum out, or a `UsageError` that knows which command's help is
   relevant. `main.rs` becomes a dispatcher. The command table is *data*
   (name, summary, usage line, options with descriptions), so help text,
   suggestions, and completions are generated from one source and cannot
   disagree.

### Output conventions (apply to every verb, old and new)

- **stdout is for results, stderr is for narration.** `plan`, `sbom`, `ls
  --json`, `store path` write parseable output to stdout and nothing else.
  Progress ("resolving with the store uv...", "synced: .venv -> ...") stays on
  stderr with the `blanket:` prefix it already has.
- **Errors have three parts**: what failed, why, what to type next. Today's
  best messages already do this (`no environment projected here; run
  'blanket sync' first`); the rule is that every new message must, and the
  worst existing ones get rewritten as they are touched. The `no_manifest`
  error is the first candidate: it lists nineteen filenames in one line.
- **`--quiet`** suppresses narration; **`--verbose`** prints every
  subprocess command line and every decision (which manifest won, which
  Python was selected and why, which lock source was used). Verbose is the
  bug-report mode and should make "what did blanket do" answerable without
  reading the code.
- **Color** only when stderr is a tty and neither `NO_COLOR` nor
  `--no-color` is set; only for the `error:`/`warning:` words and the
  `synced:` lines. Never in stdout.
- **`--json`** on `plan` (already JSON), `ls`, `status`, `doctor`. Stable
  keys; documented in the command's help.

### Completions

`blanket completions bash|zsh|fish` prints a script generated from the
command table: commands, per-command options, `help <cmd>`, `store path|
roots`, `build <ecosystem>`. Script names from package.json complete under
`run` when a package.json is present (cheap: read the file at completion
time). This is the cheapest "easy to use" feature there is once the table is
data.

### Status

Level one is implemented (branch `cli/levels-1-2`, 2026-09-06): rules 1–7,
`-q`/`-v`/`--no-color`, `tests/cli.rs` against the binary, docs. Verbose
traces the subprocesses `main.rs` starts; the tailors' own subprocesses are
a follow-up. Completions shipped with level two.

### Acceptance

- `cargo test` passes; new `tests/cli.rs` runs the binary offline: no args,
  `--help`, `help sync`, `--version`, `snyc`, `sync --fersh`, `gc --keep-days
  x`, `store`, `plan` in an empty directory (exit 1, `no_manifest`), `-C`.
- Every argv shape in `tests/*.rs` and `tests/acceptance.sh` is unchanged.
- `bash tests/acceptance.sh` on Linux; the Mac run is a cache-hit re-run.

---

## Level two: verbs that match how people work

Principle for every verb that touches a manifest or a lock: **resolution
belongs to the ecosystem's tool, realization belongs to blanket** (the
doctrine already used for missing lockfiles). Blanket never invents a
resolver or a manifest editor where the pinned tool has one. Where the
pinned tool has none, blanket **refuses with the exact line to add and the
file to add it to**, then the user runs `blanket` and the ordinary sync path
takes over. Refusing-with-instructions is a feature here, not a gap: it is
still one tool that tells you what to do.

Every delegated edit runs **unsandboxed with network, using only store
tools** (the store uv, the store node's npm, the store cargo, ...). This is
the same trust boundary as today's lock generation and is listed as such in
LIMITATIONS.md. Nothing in level two adds a host-tool dependency.

### 2.1 Bare `blanket` and `blanket install`

- Inside a project (any manifest found from the current directory): bare
  `blanket` means `blanket sync`. This is the single largest usability win
  available and costs ten lines.
- Outside a project: usage to stderr, exit 2, with a first line that says
  `blanket: no project here (looked for requirements.txt, package.json,
  Cargo.toml, ...); run 'blanket --help'`. The nineteen-filename list moves
  into `blanket help sync`.
- `install` and `i` are accepted aliases for `sync`. Help lists `sync`
  only, with "(alias: install)". People type what pip and npm taught them;
  the alias costs nothing and the canonical name stays one word.

### 2.2 `blanket <script>`

`blanket dev`, `blanket test`, `blanket build:web`. Resolution order for an
unknown first word:

1. A built-in verb always wins (`blanket build` is the sandboxed build,
   never a script named build; `blanket run build` reaches the script).
2. Otherwise, if the nearest projected root has a package.json with that
   script, run it exactly as `blanket run <script>` would.
3. Otherwise: `unknown command 'dev'` with the usual suggestion, plus
   `(no package.json script named 'dev' here)` when a package.json exists.

`blanket run <script>` stays the unambiguous spelling and is what docs use
in examples. A `blanket.toml` `[tasks]` table for cross-language scripts is
the natural extension but is **not** in this plan; it is the task-runner
question PLAN.md defers until a real polyglot need appears (WP1's
`blanket fmt` contract is the shape a named tool command takes).

### 2.3 `blanket fmt`

`blanket fmt [--check] [--eco <ecosystem>] [--] [<args>...]` discovers the
Cargo workspace with the pinned Cargo tool, reads metadata without resolving
dependencies, and fetches and runs the matching pinned rustfmt when needed.
It can format a project before its first sync, does not create `Cargo.lock` or
a vendor object, and passes the tool's exit status through. `--check` is
blanket's flag; after it and `--eco` (or after `--`), arguments go to
`cargo-fmt` unchanged. Rust is the only implementation; a polyglot directory
needs `--eco rust`. Both `--eco <ecosystem>` and `--eco=<ecosystem>` are
accepted and validated the same way: an empty value, or one that starts with
`-` (`--eco --check`, `--eco=--check`), is a usage error (exit 2), never an
ecosystem name.

The run writes `.blanket/closures/rustfmt.json`, a toolchain-only closure:
`blanket ls` shows it as a `rustfmt` row, `blanket sbom` inventories the two
store objects it pins (`rust` and `rustfmt`), `blanket gc` keeps them live,
and `blanket status` ignores it (it has no dependency-sync state to compare).

If the nearest projected root's `package.json` has a script named `fmt`, that
script takes precedence and runs exactly as `blanket run fmt` would; `--check`
and any pass-through arguments go to the script, `--eco` never does. Use
`blanket run fmt` to address the script explicitly, and `blanket fmt --eco
rust` to bypass it: an explicit `--eco` selects the ecosystem, so it always
formats that ecosystem and never delegates to a script.

### 2.4 `blanket add`, `blanket remove`, `blanket update`

```
blanket add <spec>...    [--dev] [--no-sync]
blanket remove <name>... [--dev] [--no-sync]
blanket update [<name>...] [--no-sync]
```

Flow, identical for the three: pick the ecosystem → delegate the manifest
and lock edit to the store tool → run the ordinary sync → print what changed
(`added requests 2.32.5 (requirements.txt, requirements.lock.txt)`).
`--no-sync` stops after the lock edit, for people who want to review the
diff first. `remove --dev` selects development dependencies for uv and Cargo,
matching `add --dev`. All dependency arguments are validated before delegation.

**Planned (WP2 design, not implemented in level two):** `blanket sync
--frozen` reads and validates `blanket-toolchain.toml` without creating or
updating it, including its contained regular-file inputs and complete artifact
rows for both supported platforms. --frozen never modifies project inputs,
blanket-toolchain.toml, or the catalog cache; it may realize store objects and
write the projection after validation succeeds; validation failure exits before
any write. Frozen validation evaluates nothing at all: every ecosystem's
reader is declarative-only, so where only an unsandboxed evaluator could
answer, it refuses instead of falling back. setup.py-computed metadata and
mix.exs compatibility are therefore not frozen sources, and a Ruby version
comes from .ruby-version or .tool-versions, never from evaluating the Gemfile.
The sandboxed probe below belongs to the ordinary planning path, where it runs
with network denied, the project read-only, and scratch-only writes; its setup
`BuildSpec` uses
`argv = ["/bin/sh", "-c", "exec <build-env>/bin/python setup.py egg_info
--egg-base <scratch>/egg-info ><scratch>/egg-info.log 2>&1"]`, with the
project root as cwd and the build environment, CPython, and scratch as roots
(`src/manifest.rs:162-178`); it does not run `/bin/sh setup.py`. The write
boundary's regression is
`tests/toolchain_lock.rs::frozen_validation_failure_precedes_all_writes`: the
failing case leaves inputs, the lock, the catalog cache, the store, and the
projection unchanged, while its valid case permits realization and projection.
`blanket update --toolchain [<ecosystem>]` is the only command that upgrades
those exact runtime selections; it may be run for one ecosystem or all present
ecosystems and then invokes ordinary sync. It is separate from dependency
update and does not edit the ecosystem's dependency lockfile.

**Choosing the ecosystem (decided 2026-09-06: infer from evidence, then
ask; no required syntax).** Blanket never picks an ecosystem on a coin flip,
but it also never makes a person learn a prefix. The ladder, cheapest first,
stopping at the first rung that answers:

1. *The name's shape.* `@scope/name` is npm; `github.com/...` (a slash and a
   dotted host) is Go; `Foo.Bar` PascalCase with dots is NuGet. Structural
   facts, not heuristics.
2. *Where you are standing.* The nearest manifest walking up from the
   current directory. In a repo with `web/package.json` and a root
   `pyproject.toml`, `blanket add react` from `web/` is npm. Only a
   directory holding several manifests itself reaches rung 3.
3. *Ask the registries.* One existence check per candidate registry (the
   same network `add` needs anyway). A name known to exactly one registry
   is resolved by fact.
4. *Ask the human.* Known to several registries and stderr is a terminal:
   `requests exists on PyPI (2.32.5) and npm (0.3.0). Which? [1/2]`. The
   versions make a squat obvious; a name that exists in two places is the
   case where slowing down is right.
5. *Non-interactive fallback.* No terminal and still ambiguous: error
   listing the candidates and the explicit spelling `npm:react` /
   `py:requests` / `cargo:` / `go:` / `gem:` / `hex:` / `nuget:`. The prefix
   exists for scripts and CI; help mentions it once. A human at a keyboard
   never needs it.

**Delegation table.** "Refuse" always means: print the exact line and file,
exit 1, no writes.

| ecosystem | project shape | add | remove | update |
|---|---|---|---|---|
| Python | `requirements.txt` (blanket's own lock flow) | blanket adds or replaces a logical requirements record, then the existing uv `pip compile` re-lock runs | blanket deletes the full record, including hash continuations (exact-name match; ambiguous declarations and names available only through `-r` includes are refused) | delete the lock stamp and re-lock with `--upgrade` / `--upgrade-package <name>` |
| Python | `pyproject.toml` with `[project]`, no foreign lock | store uv: `uv add --no-sync`, `uv remove --no-sync`, `uv lock --upgrade[-package]`; uv edits pyproject.toml format-preservingly and writes uv.lock, which item 10 already imports | same | same |
| Python | `poetry.lock` / `pdm.lock` present, or `[tool.poetry]` | refuse (poetry/pdm are not pinned; uv would create a second lock) | refuse | refuse |
| Python | `setup.py` / `setup.cfg` only | refuse with the `install_requires` line | refuse | n/a |
| Node | `package-lock.json` or no lock | store npm: `npm install --package-lock-only --ignore-scripts [--save-dev] <spec>`, `npm uninstall --package-lock-only`, `npm update --package-lock-only [<name>]` | same | same |
| Node | `pnpm-lock.yaml` | store pnpm at the exact version in root `package.json` `packageManager` (for example `pnpm@9.12.3`, optionally with a Corepack `+sha224.`/`+sha256.`/`+sha512.` hash, which is verified; any other algorithm is refused by name), then `pnpm add --lockfile-only --ignore-scripts`, `pnpm remove --lockfile-only`, or `pnpm update --lockfile-only --ignore-scripts`, each with `--config.enable-modules-dir=false` and `--config.modules-dir`/`--config.virtual-store-dir` pointed into a per-run store stage so the project's `node_modules` is neither read nor written; lifecycle scripts are off for all three (`--lockfile-only` forces pnpm's `ignoreScripts`; pnpm's `remove` parser rejects the flag, so `npm_config_ignore_scripts` in the delegate's environment carries it there); only a positively matched pnpm workspace root is inherited, and workspace-root edits add `-w` | same | same |
| Node | Yarn classic v1 `yarn.lock` | refuse: run `yarn add …`, then `blanket` (Yarn classic has no lockfile-only edit mode; a workspace-faithful scratch edit is future work) | refuse: run `yarn remove …`, then `blanket` | refuse: run `yarn update`, then `blanket` |
| Node | Yarn Berry (`.yarnrc.yml` or Yarn 2+) | refuse: Berry cache checksums are not npm tarball integrity values; convert with `npm install --package-lock-only` or `pnpm install --lockfile-only`, then `blanket` | same | same |
| Cargo | any | store cargo: `cargo add`, `cargo remove`, `cargo update [-p <name>]` with network, exactly as `generate-lockfile` runs today | same | same |
| Go | any | store go: `go get <mod>[@ver]`, `go get <mod>@none`, `go get -u [<mod>]`; later sync owns tidy resolution | same | same |
| Ruby | any | store bundler: `bundle add <gem>`, `bundle remove <gem>`, `bundle update [<gem>]` with `BUNDLE_IGNORE_CONFIG` enforced and `BUNDLE_FROZEN=false` for edits; realization remains frozen | same | same |
| Elixir | any | refuse with the `{:name, "~> x.y"}` line for mix.exs (there is no `mix add`) | refuse | store mix: `mix deps.update [<name>]` |
| .NET | any | refuse with `dotnet add package <name>` + `dotnet restore --force-evaluate` (restore evaluates MSBuild on the host, which blanket never does outside the sandbox — the mandatory-lock rule) | refuse | refuse |

Every row that delegates also has the delegate's stdout/stderr shown under
`--verbose` and summarized otherwise.

**Writes to user files.** `add` is the first time blanket modifies something
the user owns. Rules: write atomically (temp file + rename, the store's
existing helper); never reformat a file blanket did not fully generate (the
requirements.txt append preserves everything above it, uv and npm preserve
formatting themselves); print every file touched; `--no-sync` for review.

If one request would edit more than one project root (for example, a Python
file in a pnpm member and the pnpm workspace root), blanket refuses before
delegation and names both roots; run the two adds separately.

A pnpm workspace member is identified from `pnpm-lock.yaml`'s `importers`
list, which pnpm itself produced with its own glob engine; blanket has no
glob matcher, so no pattern can be misread and none can be silently treated
as a non-match. `pnpm-workspace.yaml` is never consulted, because since pnpm
10 it is also the project-level settings file of a repository that has no
workspace at all. A project the lock does not list, under a root the lock
shows really is a workspace, is refused by name rather than handed to npm:
put a `.blanket` directory in the project to declare it its own root.

### 2.5 `blanket x <tool>[@version] [<args>...]`

Run a tool from a registry without touching the project, cached forever:

```
blanket x ruff check .          # PyPI, if the project is Python or --py
blanket x npm:prettier --write . 
blanket x py:cowsay@6.1 hello
blanket x --from httpie http GET example.org   # bin name ≠ package name
```

Mechanism, reusing the kernel unchanged: a synthetic single-requirement
plan (uv `pip compile` of one spec, or a temp package.json + `npm install
--package-lock-only`) → the existing `realize_env` / `realize_node_env` →
run `<bin>` from the object's `bin/` (or `.bin/`) with the ecosystem
variables `run` would set. The object is input-addressed on the resolved
lock, so the second `blanket x ruff` is a store hit and starts in
milliseconds; `gc` treats these objects like any other, rooted by a small
`~/.blanket/x/` registry with a keep-days window.

Ecosystem choice: prefix, or `--py`/`--npm`; unprefixed → the ecosystems
present in the current project, tried in order Python, Node; unprefixed
outside any project → usage error naming the prefixes. No cross-registry
lookups to guess. Python and Node only in v0; cargo (`cargo install`-style)
and go (`go run pkg@ver`) are the obvious next two and fit the same shape.

`blanket x --clean` removes every registered environment under
`~/.blanket/x/`, and unregisters each root. `blanket x --clean <tool>[@version]`
selects that tool (all versions when the version is omitted); `--py`, `--npm`,
and `--from <package>` keep their normal meanings. Cleanup accepts no
arguments after the tool. It prints one line per removed environment and a
summary that the immutable store objects remain until the next `blanket gc`;
when a removed environment was a node tool the summary also names `blanket gc
--project`, the only pass that reclaims the
`~/.blanket/forests/<project-key>/<projection-id>` node_modules forest the
environment used. `nothing to clean` is printed only when no candidate
matched at all: a root that was considered and skipped (in use, or a legacy
root whose package could not be recovered) is reported as
`removed 0 environment(s), skipped 1`. Exit status is 0 whenever cleanup
completed, whether or not anything was removed.
A running tool holds a shared lock in the permanent
`~/.blanket/x/.locks/<root-name>.lock`, made inheritable immediately before
exec, so cleanup
reports it as in use and leaves it for a later retry. A successful removal
unlinks that lock file while still holding it, so `.locks` never collects one
stale file per environment ever created; the next runner recreates it. The
request and
ownership state (`realizing` or `ready`) are recorded in `x.json` beside the
closure before realization begins. For older roots without `x.json`, cleanup
matches the exact package recovered from the generated `requirements.in` or
`package.json`; if it cannot recover the package it skips that root with a
removal hint. A cleanup without a tool still removes every safe x root,
including partial realizations. Cleanup and `blanket x` accept exactly the
same layouts: both resolve `$HOME` and `~/.blanket` once (either may be a
symlink — moving the cache to another volume is supported, and an environment
created that way can also be removed), both refuse a relative `HOME`, and both
refuse a symlinked or non-directory `~/.blanket/x`. Cleanup never treats
`.locks` as an environment.

### 2.6 `blanket status`

Per ecosystem found here: `synced`, `lock changed since sync`, `manifest
changed since lock`, or `not synced`, computed from the closure's recorded
lock hash, the current lock, and the manifest tree hash the planner already
computes. Exit 0 only when everything is `synced`, so CI can use it as a
"did you commit the lock" gate. For Go, status also compares the exact
version selected from `go.mod` with the closure's recorded toolchain version.
Older Go closures without that recorded version are shown as
`synced-unchecked` until the next sync; missing projections and changed lock
hashes remain reported first.
`--json` is available for tooling.

### 2.7 `blanket ls [<ecosystem>] [--json]`

Name, version, and (with `--verbose`) artifact and store object id for every
package in each synced closure. Straight from `.blanket/closures/*.json`;
no store access. This is the "what is on this machine" query the enterprise
pitch promises, made typeable. The optional filter word is one of the seven
ecosystems plus `rustfmt`, the toolchain-only closure `blanket fmt` writes:
every row `ls` can print is a word `ls` accepts.

### 2.8 `blanket doctor`

The first-five-minutes command: platform (and whether it is supported),
store path and whether it is writable and on which filesystem, sandbox
availability (`bwrap` and user namespaces on Linux, `sandbox-exec` on macOS)
with the install hint from README, host C toolchain presence for native
builds, free disk under the store, pinned toolchains already realized. Each
line is `ok`, `warn`, or `fail` with the fix. Exit 1 on any `fail`.

### Status of level two (2026-09-06)

Implemented on branch `cli/levels-1-2`: phase B (bare `blanket` → sync,
`install` / `i`, `blanket <script>`, `status`, `ls`, `doctor`,
`completions`), phase C (`add` / `remove` / `update` with the evidence
ladder and the delegation table; `src/deps.rs`) and phase D (`x` for PyPI
and npm; `src/xrun.rs`). Python and Node closures carry an additive
`inputs` field (root manifest and lock file hashes) that `status` compares.
Offline paths are covered by `tests/cli.rs`. The supported dependency-edit
shapes have real add/update/remove round trips in `tests/deps_e2e.rs`,
including uv development dependencies and pnpm workspace selection. Yarn
classic remains a refusal because it has no lockfile-only edit mode and a
workspace-faithful scratch edit is future work. Astra review findings and
final Linux gate results are in REVIEW-2026-09-06.md. The macOS arm64 run
remains outstanding.

### 2.9 Deferred within level two

- **`blanket why <pkg>`**: the closure records packages, not edges
  (`LockedPackage` and `NpmPackage` carry no dependency list). `why` needs
  the planner to persist edges into the closure envelope; that is a kernel
  change with an identity-schema question, so it waits for a session of its
  own. Worth doing: it is the question `sbom` consumers ask first.
- **`blanket init`** (new project scaffolding) — different product surface.
- **`blanket.toml` tasks** — see 2.2.

---

## Phasing

| phase | contents | size | depends on |
|---|---|---|---|
| A | level one: finish the draft (`tests/cli.rs`, `-q`/`-v`/`--no-color`, docs) | S | — |
| B | bare `blanket`, `install` alias, `blanket <script>`, `status`, `ls`, `doctor`, `completions` | M | A |
| C | `add` / `remove` / `update` for the green rows; refuse-with-instructions for the rest | L | A |
| D | `x` for Python and Node | M | A |
| later | `why` (needs closure edges), `x` for cargo/go, level three | | |

B before C on purpose: B is all reading and dispatch, no writes to user
files, and it delivers most of the "easy" feel. C is where the design
decisions with consequences live (writing manifests), so it goes after the
grammar and the read-only verbs have settled. D is independent of C and can
run in parallel.

Review shape, same as the overnight items: Codex implements, Astra reviews,
`cargo test` offline for the grammar and dispatch, ignored e2e per ecosystem
row for `add`/`remove`/`x` against the fixtures in `tests/fixtures/`
(proj-a for requirements.txt, proj-pdm for pyproject, proj-npm, cargo-hello,
go-hello, ruby-hello), and one acceptance.sh section per new verb.

## Decisions to confirm

1. **Bare `blanket` = sync** inside a project. (Recommended yes.)
2. **`install` as an alias** for sync, or one name only. (Recommended alias.)
3. ~~Prefix syntax for ambiguity~~ **Decided: the evidence ladder** (name
   shape → nearest manifest → registry existence → prompt), with the prefix
   only as the non-interactive escape hatch. See 2.3.
4. **`add` refuses for Yarn classic/Poetry/PDM/.NET/Elixir in v0** rather
   than growing new edit paths. pnpm uses its exact root `packageManager`
   version and lockfile-only mode; each refusal names the exact command, and
   a future implementation can turn a row green without changing the CLI.
5. **`x` v0 is Python and Node only.**

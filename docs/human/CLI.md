# Tog CLI

*Written 2026-09-10. Replaces the 2026-09-06 plan at the repo root: what it
promised is shipped, so this file describes only what exists. The help screen
below is the spec, generated from the command table in `src/cli/spec.rs`; if this
file and the binary differ, fix this file.*

```
tog 0.1.0 — one command for every package manager

USAGE:
  tog                        set up this project, then show this help
  tog <command> [<args>...]  run a command ('tog help <command>' explains it)
  tog <script> [<args>...]   run a package.json script (like 'npm run')

START HERE:
  tog                   set up the project from its lockfiles
  tog run <command>     run something inside that environment
  tog add <package>     add a dependency, re-lock, sync
  tog doctor            check this machine when something looks wrong

EVERYDAY:
  add          add a dependency, re-lock, sync
  remove       remove a dependency, re-lock, sync
  update       update dependencies, --toolchain, or --self (tog itself)
  run          run a command or package.json script in the environment(s)
  env          print the environment as shell exports (for eval or direnv)
  x            run a tool without adding it as a dependency (like npx / uvx)
  build        sandboxed, network-denied build (cargo | go | elixir | dotnet)
  fmt          format the Rust workspace with the pinned rustfmt

INSPECT:
  doctor       check host prerequisites, the sandbox, and the store
  status       is the environment current with the manifest and the lock?
  ls           list what is installed, per ecosystem
  audit        would the synced environments pass a policy? (CI gate)
  plan         print the locked plan(s) as JSON
  sbom         CycloneDX 1.5 SBOM of the synced environments

MAINTAIN:
  gc           collect unreferenced store objects and cached artifacts
  store        'store path', 'store roots'
  keygen       create a closure-signing key and print its public key
  completions  print a shell completion script (bash | zsh | fish)
  help         show help for a command
  version      print the version

SETUP OPTIONS (the bare 'tog' only; 'tog help setup' explains them):
  --fresh     rebuild .venv / node_modules from scratch

OPTIONS (before or after the command; after 'run', 'build' or a script name
everything belongs to the program, and 'fmt' and 'x' take them only ahead of
the tool's own arguments):
  -C, --directory <dir>  run as if tog had been started in <dir>
  -q, --quiet            errors and results only
  -v, --verbose          every decision and subprocess command line
      --no-color         plain output (also: NO_COLOR, or a non-tty stderr)
      --frozen           CI: the implicit sync checks the locks are current
                         without writing them
      --strict           the implicit sync refuses every policy exception
                         (same as TOG_STRICT=1)
  -h, --help             this help ('tog help <command>' for one command)
  -V, --version          print the version

ENVIRONMENT:
  TOG_STORE           store root (default ~/.tog/store)
  TOG_STRICT=1        refuse every policy exception, like 'tog --strict'
  TOG_POLICY          policy file used instead of ~/.tog/policy.toml
  TOG_SIGNING_KEY     key file; every command that writes a closure signs it
  NO_COLOR            plain output, like --no-color

Exit status: 0 success, 1 failure, 2 usage error; 'run', 'x' and 'fmt' pass
the program's status through. Which files tog reads per ecosystem:
'tog help inputs'. Full reference: docs/human/CLI.md.
```

## Conventions

- **stdout is results, stderr is narration.** `plan`, `sbom`, `env`,
  `store path`, and the `--json` forms write parseable output to stdout and
  nothing else (`env` is evaled by a shell, so a stray word there is a
  syntax error in someone's session). Narration stays on stderr with a
  `tog:` prefix, and the prefix says which kind it is: progress is
  `tog: <what is happening>`, an advisory you may want to act on (a
  fallback, a directory moved aside, unsigned closures under a policy that
  checks signatures) is
  `tog: warning: <what happened>`, and every warning is followed by
  `tog:     fix: <command>`, the one command that resolves it, ready to
  paste; a line with nothing for you to do is progress, not a warning. A
  failure is `tog: error: <what failed>`. `--quiet` silences the first two
  and never the third. `gc` narrates, so every line it prints — registered,
  forgot, would free, freed, cleanup skipped — is stderr and `--quiet`
  silences all of it.
- **`--json` is a promise about both streams.** With `--json`, stdout
  carries the JSON document and nothing else, narration stays on stderr,
  and a failure is one JSON object on stderr: `{"error":"<message>"}`.
  That holds for every failure the command itself reports, whatever its
  exit status: `audit --json` still exits 2 for a misconfigured gate (an
  unreadable `--policy` file, no trusted set at machine scope), so CI can
  tell an operator mistake from a denied build, and still writes the JSON
  object rather than prose. Only an argv error is exempt — it is prose at
  exit 2, because argv was wrong before the command that promised JSON
  ever started. `status`, `ls`, `audit`, `doctor` and `plan` take
  `--json`; `plan` prints JSON either way.
- **Errors have three parts**: what failed, why, what to type next. Unknown
  options get an edit-distance or prefix suggestion
  (`unknown option '--fersh'; did you mean '--fresh'?`) and exit 2.
- **`--quiet`** suppresses narration; **`--verbose`** prints every decision
  and every subprocess command line — the bug-report mode. An error is never
  narration: `--quiet` redirects stderr but keeps a private copy of it, and
  errors *and panics* go there, so a crash is never silent.
- **Downloads report progress** on a tty stderr — the artifact's name, the
  bytes so far, and the total when the server declares a `Content-Length` —
  redrawn in place about ten times a second and erased when the download
  ends. A redirected stderr (a pipe, a log, CI) and `--quiet` get nothing.
- **Network failures say what happened**: offline, DNS, proxy, https-only,
  or the server's status, with the URL named once. Not ureq's words.
- **Color** only on a tty stderr, only for `error:`/`warning:` and
  `fix:`/`synced:` words (`fix:` is green, like `synced:`); `--no-color` or
  `NO_COLOR` turns it off, and stdout never gets it.
- **Global options work before or after the command.** `-C <dir>`, `-q`,
  `-v`, `--no-color`, `--frozen` and `--strict` mean the same thing in
  either position (`tog ls -v` and `tog -v ls` are the same command),
  except where the rest of the line belongs to something else: `run`,
  `build` and a script name pass every argument after them to the program
  (`tog dev --strict` gives the script `--strict`), `fmt` and `x` accept
  them only ahead of the tool's own arguments, and the value slot of a
  command's own option is never searched (`tog gc --register -v` registers
  a directory called `-v`; the command table says which options take a
  value). What reaches that slot is then the option's own business — see
  the next rule.
- **Pass-through is sacred.** `run`, `build`, `x`, and `fmt` hand every
  argument after the command to the tool unchanged, and `--` forces
  pass-through (`tog build --release` works). What tog keeps for itself is
  a *leading* `-h`/`--help` in all four, plus, for `fmt` and `x` only, the
  global options while they still precede the tool's first non-option word:
  `tog x -q ruff -q` runs ruff quietly with `-q` of its own. Use `--` when
  a tool argument is spelled like one of those (`tog fmt -- -v`).
- **An option's single value follows one rule.** An option that takes one
  value refuses an empty one, and refuses a separate word that starts with
  `-`: `tog sbom -o --json` is a mistyped flag, not a request to write a
  file named `--json`, and `tog -C ""` is a usage error rather than a
  directory change that fails later. A value that really does start with a
  dash is given inline, after an `=`:

      tog sbom --output=-report.json
      tog --directory=-work plan

  A lone `-` is a separate word starting with `-` like any other, so it is
  refused too; `tog sbom --output=-` names a file called `-`. Nothing needs
  it: `sbom` already writes to stdout when `--output` is left off.

  The rule stops at the option's own grammar, so a value tog will not use
  as a path is refused in both forms: `--eco` and `--from` name an
  ecosystem and a package, `--forget` and `--drop-object` a key and an
  object id, `--keep-days` a number, and none of those can start with a
  dash. A list option (`--register <dir>...`) is the exception in the
  other direction: it holds every word up to the next long option, so a
  directory really called `-v` is registered rather than refused.

## Completions

`tog completions bash|zsh|fish` prints a script generated from the same
command table as the help: commands, per-command options, `store path|roots`,
`build <ecosystem>`. package.json script names complete under `run` and as
the first word when a package.json is present.

## Everyday verbs

**The bare `tog`** is the setup step, and there is no verb for it: like
`cargo build`, every command that needs the environment brings it current on
the way in. Inside a project a bare `tog` discovers every ecosystem present
in the current directory, realizes each locked plan into the store, projects
it (`.venv`, `node_modules`, `.tog/...`), and then prints what `tog help`
prints; outside a project it prints that help and exits 0. A manifest with
no dependencies syncs an interpreter-only environment. The help only follows
a sync that succeeded, so a failure stays the last thing on screen.

It takes three flags, and with any of them the help is not printed and a
directory with no project is a failure (exit 1) rather than orientation, so
a CI job pointed at the wrong directory goes red: `tog --frozen` validates
the locks without writing them (below), `tog --fresh` drops project-local
caches and rebuilds, and `tog --strict` refuses every policy exception.
Inside a project `tog -q` is a sync with no narration and no help. `--fresh`
stays on the bare form: rebuilding before every command is never what
someone means, so `tog --fresh status` is a usage error. `--frozen` and
`--strict` are global options, accepted before the verb and after it where
any global option is: `run`, `build` and a script name hand everything after
them to the program, so there the flags go first (`tog --frozen dev`), and
`fmt` and `x` take them only ahead of the tool's own arguments. They govern
the implicit sync of `run`, `env`, `build`, `tog <script>` and a
package.json `fmt` script. `tog help setup` is the
bare form's screen and `tog help inputs` the files it reads per ecosystem.

`run`, `env`, `build` and `tog <script>` sync on their own when the project
is not synced or its inputs changed (see **run**), so a bare `tog` is only
needed for a sync with nothing to run after it. `sync`, `install` and `i`
still work as hidden aliases of the bare form, flags included, so a pip or
npm reflex and existing CI keep working; they are not listed, completed, or
suggested. They take no package name: `tog install requests` is a usage
error that names `tog add requests`.

The first writable sync of a project with no toolchain lock selects a
runtime per ecosystem, writes `tog-toolchain.toml` at the project root, and
says so; commit it. Every later sync honors that file and reselects nothing,
so a catalog or binary upgrade alone cannot move a locked runtime. A
declarative toolchain source that disagrees with what the lock recorded —
`.python-version`, `requires-python`, `.node-version`, `engines.node`,
`rust-toolchain.toml`, `go.mod`, `.ruby-version`, `.tool-versions`,
`global.json` — stops the sync with both values and names
`tog update --toolchain`. So does a lock with no section for an ecosystem
the project just gained: that is stale, not absent. Comparison is by the
re-derived value, never by the file's digest alone, so a `tog add` that
rewrites a multi-purpose manifest leaves the lock fresh.

`--frozen` validates the committed lock instead of creating one and refuses
a missing or stale one.

--frozen never modifies project inputs, tog-toolchain.toml, or the catalog
cache; it may realize store objects and write the projection after validation
succeeds; validation failure exits before any write.

Validation reads declarative files only and evaluates no
project code, which is why a Gemfile's `ruby` directive and `setup.py`
metadata are not toolchain sources: a project whose only statement of its
version is computed fails `--frozen` closed, naming the declarative file to
add. `--frozen` also skips missing-lock generation, so a project with no
dependency lock is refused by the ecosystem that needs one rather than
having one written for it.

Policy exceptions are recorded in `.tog/closures/*.json`
and summarized as a count with where to read them; `--strict`,
`TOG_STRICT=1`, or a `.tog/policy.toml` deny list refuses them instead —
note that `--strict` fails the sync, so it is a setting to sync *under*, not
a way to clear exceptions already recorded. Closures are written unsigned
unless `TOG_SIGNING_KEY` is set; sync says so once per store, and on every
sync only where the policy chain declares a `[signing]` table.

**add / remove / update** edit the manifest and lock with the ecosystem's own
pinned tool (uv, npm, pnpm, cargo, go, bundler, mix), then sync. `--no-sync`
stops after the edit so the diff can be reviewed; `--dev` (`-D`) selects
development dependencies (`remove --dev` only for uv and Cargo). Refusals —
Poetry, PDM, Yarn classic and Berry, setup.py, Elixir `mix add`, .NET —
print the exact line and file to run yourself, exit 1, no writes. Every
dependency argument is validated before delegation, and a request that would
edit more than one project root (a pnpm member plus its workspace root) is
refused with both roots named. Ecosystem choice, cheapest rung first:

1. an explicit prefix (`py:`, `npm:`, `cargo:`, `go:`, `gem:`, `hex:`,
   `nuget:`) or the name's shape: `@scope/name` is npm, `github.com/...` is
   Go, dotted PascalCase is NuGet;
2. the nearest manifest walking up from here;
3. registry existence checks when one directory holds several manifests — a
   name known to exactly one registry wins, known to several asks at the
   terminal;
4. non-interactive: the error lists the candidates and the prefixes. Tog
   never guesses from the bare name.

Constraints pass through to the tool: `react@18`, `rails@~> 7.1`.

**update --self** updates tog itself and touches no project, store, or key.
It reads GitHub's latest release (one request), stops with "nothing to do"
when this build already is that version or newer, and otherwise downloads
`tog-<triple>.tar.gz` and its `.sha256` from the release, verifies the
digest, extracts the binary to a sibling of the running one, runs its
`--version`, and renames it over the running binary, which keeps working
because it holds its open file. The writability probe runs before anything
is downloaded: when the binary's directory cannot be written, the refusal
names the directory and the installer. The downloaded binary must report the
release's version, so a mislabeled asset is refused too. It takes no other
argument. A release is compared by version only, because a release does not
name the commit it was built from: a local build of the same crate version
is "at the latest release's version" and stays. The asset names and the
checksum rule are `install.sh`'s, so the two read a release the same way. `TOG_RELEASE_MANIFEST` names another
manifest URL (the tests use `file://`); nothing checks in the background.

**update --toolchain** `[<ecosystem>]` is the other update, and the two never
mix. It re-reads the declarative toolchain sources, selects the newest
compatible release for every ecosystem the project has — as discovery finds
them, which is how a newly added ecosystem gains its section — or only the
named one (`python`, `node`, `rust` or `cargo`, `go`, `ruby`, `elixir`, `dotnet`),
rewrites `tog-toolchain.toml` atomically, and then syncs. It takes no
package name, never touches a dependency lock, and is the only thing that
moves a locked runtime. `--no-sync` stops after the lock is written, so the
diff can be reviewed before anything is realized.

**fmt** runs the pinned rustfmt for a Rust workspace, discovered with the
store Cargo and `--no-deps`, so a project that has never been synced needs
no Cargo.lock or vendor object; `--check` passes rustfmt's status through.
The run writes a toolchain-only `rustfmt` closure that `ls`/`sbom`/`gc` see,
`audit` compares with the pin, and `status` ignores. A package.json script named `fmt` wins and runs as
`tog run fmt`; an explicit `--eco rust` bypasses the script.

**run** executes a command with the PATH and ecosystem variables of the
nearest projected root (the closest ancestor with `.tog/closures/`). A
package.json script of the same name wins over an executable on PATH and
runs with the npm lifecycle environment; the exit code passes through.
`tog <script>` is the short form for any first word that is not a
built-in command, and a built-in always wins (`tog build` is the
sandboxed build, never a script named build; `tog run build` reaches the
script). Arguments after the script name go to the script unchanged, so
there is no npm-style `--` separator: `tog test --watch` passes `--watch`,
and `tog test -- --watch` passes a literal `--` as well. Completion offers
the package.json script names as first words whenever a package.json is
present, which is where most people find the shorthand.

The environment is the one the project's inputs describe. Before the
command runs, `run` makes the same check `status` prints, offline: when
nothing is synced yet, a manifest or lock changed since the last sync, the
projection is gone, or the closure was synced on another platform, the
project is synced first, with one `tog: syncing first: <ecosystem>
<state>` line on stderr saying why, and then the command runs. It is the
same sync a bare `tog` runs, so a sync that would refuse (a stale toolchain
lock, a denied exception) refuses here in its own words before anything
runs. One sync per command, never a second look: a state a sync does not
clear costs a sync per command, not a loop. From a subdirectory of a
never-synced project the nearest ancestor with a manifest is the project;
once synced, the nearest `.tog/closures/` decides, as before. A directory
with no manifest above it has nothing to sync and exits 1 saying so.

A projection is a symlink into an immutable store object, so the commands
that would *mutate* one are refused with the verb that replaces them, before
the projection is even looked up:

- `pip install|uninstall|wheel` and `easy_install` — and the same through
  `python -m pip` — name `tog add` / `tog remove`.
- `activate`, and `source .../activate`: there is no activate script.
  `tog run <command>` *is* the activation, per command rather than per
  shell.
- `npm`/`pnpm`/`yarn`/`bun` with an installing subcommand (`install`, `ci`,
  `add`, `remove`, `update`, `link`, `dedupe`, …), plus bare `yarn` and bare
  `bun`, which install. `install` and `ci` are answered with the bare `tog`,
  which sets `node_modules` up from the lockfile (`tog --fresh` rebuilds
  it); the verbs that change the
  lockfile are answered with `tog add` / `tog remove` / `tog update`.

Reading an environment is not changing it, so `pip list`, `pip freeze`,
`pip show`, `pip check`, `pip download` and `npm ls` run normally, as does
everything else: `npm run build`, `npm test`, `python -m pytest`. A
`node_modules` that a tool already replaced is reported by `tog status` as a
real directory written over the projection, and the next sync moves it
aside — saying where it went — and re-projects.

**env** prints that same environment on stdout as lines a shell can eval:
one `export PATH=...` with the projected prefixes ahead of `"$PATH"`, then
one line per ecosystem variable (`VIRTUAL_ENV`, `PYTHONDONTWRITEBYTECODE`,
`CARGO_HOME`, the Go and Ruby variables, …). A variable the projection
*removes* — `RUSTUP_TOOLCHAIN`, for one — is printed as `unset NAME`. Every
value is single-quoted whether it needs it or not, so a path with a space
or a quote in it survives; the inherited PATH is referenced rather than
expanded, so the output never freezes one shell's PATH into another's.
Nothing else reaches stdout.

`--shell bash|zsh|fish` picks the syntax. bash and zsh are identical POSIX
sh; fish gets `set -gx PATH <dir>... $PATH` and `set -e NAME`. The default
is the basename of `$SHELL` when that is one of the three and bash
otherwise, so a shell tog does not speak gets the form most likely to work
rather than a refusal; an unrecognized `--shell` value is a usage error with
a suggestion, exactly like `completions`. Like `run`, it syncs first when
the project is not synced or its inputs changed; that narration is stderr,
so stdout still carries the environment or nothing at all. Outside a
project nothing is printed and it exits 1 saying there is no manifest.

```sh
eval "$(tog env)"        # this shell, until it exits
echo 'eval "$(tog env)"' > .envrc && direnv allow   # this directory
```

The trade-off is worth stating, because it is the one tog otherwise avoids:
`tog run <command>` scopes the environment to one child process, while an
evaled `tog env` is *ambient* — every later command in that shell sees it,
including ones tog knows nothing about, and it outlives a `cd` out of the
project. direnv is what puts the scope back, loading the environment on
entering the directory and unloading it on leaving. That is also why this is
a verb you type rather than an `activate` script tog writes into the
projection ([LIMITATIONS.md](LIMITATIONS.md)). A package.json script named
`env` is reached with `tog run env`; a built-in always wins. Editors see a
projection through this verb and through the `.venv` interpreter path:
[EDITORS.md](EDITORS.md).

**x** resolves a tool from PyPI or npm, realizes it as an ordinary store
environment (a store hit from the second run on), and executes it. Registry:
a `py:`/`npm:` prefix on the tool, `--py` (`--python`) or `--npm`
(`--node`), or the current project's ecosystem (Python first, then Node);
outside a project the prefix is required. `--from` names the package when the executable is called
something else (`tog x --from httpie http`). Sharp edges of `x --clean`:

- It removes cached environments under `~/.tog/x/`, or only the selected
  tool's (all versions when `@version` is omitted); store objects stay until
  the next `tog gc` — for a node tool the summary names
  `tog gc --project`, the only pass that reclaims the forest.
- It takes flags and an optional tool, never free arguments; exit status is
  0 whenever cleanup completed, and `nothing to clean` prints only when no
  candidate matched — a root skipped as in use is reported.
- A running tool is left in place, reported as in use; retry after it exits.
- An environment is keyed on the runtime it runs on as well as the tool, so
  a project with a toolchain lock gets the tool on the locked runtime and an
  `update --toolchain` gives the next run a fresh environment. Environments
  made by an older tog have a different name and are never reused; they stay
  until `tog x --clean`.

**build** runs the ecosystem's build tool in the network-denied sandbox with
the pinned toolchain and realized dependency objects; the ecosystem is
inferred only when exactly one build-capable project (Cargo.toml, go.mod,
mix.exs, `*.csproj`) is found from here upward — name it when several are.
Like `run`, it syncs first when the ecosystem it builds is not synced or its
inputs changed, so it never builds against a lock the manifest has moved
past; that sync may write a lock (and `tog-toolchain.toml`), as `cargo build`
updates `Cargo.lock`. Only the built ecosystem decides: a stale Python or Node
environment elsewhere in the repository does not start a sync in front of a
Cargo build, and when the built ecosystem is stale the sync that runs
prepares and realizes the built one only, so an unrelated environment
whose install fails (offline, a broken install script) does not stop the
build. Host support and the toolchain lock are still checked for the whole
project first, so an unrelated ecosystem this host cannot run, or one whose
lock section is stale, still refuses before the build. The build
itself never writes one. CI that must not write a lock runs `tog --frozen`
before it, and the check then finds nothing to do — or goes one step in a
single command, `tog --frozen build`, whose implicit sync runs frozen.

## Inspect verbs

**status** compares each closure's recorded inputs against the files on disk
and checks the projection is in place, naming the changed file otherwise.
One row per detected ecosystem, then a summary line (`2 of 3 synced; 1
unchecked.`) and, when something is not synced, a line explaining each word
that needs it. The states: `synced`, `changed` (with the files),
`not synced`, `missing` (the projection is gone), `elsewhere` (the closure
was written on another platform and says nothing about this host),
and `unchecked` — a closure this binary could not compare, because the
record predates the input recording the comparison needs. The toolchain lock
is part of the comparison and reports under `changed`, naming
`tog-toolchain.toml`: a missing lock (run `tog` to create it), a
source that disagrees with a recorded row or a lock with no section for
this ecosystem (both name `tog update --toolchain <ecosystem>`), or a
projection built from a bundle the lock no longer names (run `tog`).
A verdict that a sync would refuse is reported ahead of the closure's
own changed files, so the row names the verb that moves it; a closure that
recorded no toolchain at all is `unchecked` until one sync records it.
`unchecked` is not a
pass: it is reported under its own word, `--json` reports `"state":
"unchecked"` with `"synced": false`, and the command exits 1, like every
other not-synced state. Offline, read-only, exit 0 only when every detected
ecosystem is `synced`, so CI can use it as a "did you commit the lock" gate.

**audit** is the CI admission gate: it reads the closure records every sync
committed to `.tog/closures/*.json`, authenticates each one, and judges the
exceptions it records against the policy chain (`TOG_POLICY` or
`~/.tog/policy.toml`, every ancestor's `.tog/policy.toml`,
`TOG_STRICT`) merged with `--policy <file>`. Merging only tightens: a
project or `--policy` file can add denials and drop trusted keys, never the
reverse; a `--policy` file that is missing or malformed is a usage error
(exit 2), never ignored, so CI can tell an operator mistake from a denied
build.

What a pass proves: every closure file carries a valid signature from a key
the machine policy trusts, every ecosystem detected in the directory has its
primary closure, each record is current for the inputs on disk, and no
recorded exception is denied or unknown. It does not prove the signer's
sync was honest or safe to run (see [LIMITATIONS.md](LIMITATIONS.md)).

**What has to be in the repository for this to work.** `audit` reads
`.tog/closures/*.json`, and the policy chain includes `.tog/policy.toml` at
every ancestor. Both are records of a decision, so both are committed; the
rest of `.tog/` (`plan.json`, `go-plan.json`, the Python manifest snapshots
and stamps, `cargo-home/`) is a machine-local cache and is ignored. A
repository that ignores all of `.tog/` has nothing for `ls`, `sbom` or
`status` to read, and no closure diff for a reviewer to look at. The
`.gitignore` stanza and the full table are in
[the README](../../README.md#what-tog-holds-and-what-to-commit).

Be clear about what committing them does and does not buy. `ls` and `sbom`
read a committed closure with no store and no projection, and a closure diff
is how a reviewer sees that a pull request added a `git-dependency` or a
`weak-integrity` exception. But `status` and `audit` both check the *local*
projection, so on a fresh checkout with no `.venv` or `node_modules` they
report `missing` / `stale` and exit 1. Neither is a records-only verifier:
a gate has to sync first, in the checkout it is judging.

A closure is one file per ecosystem, not one per platform, and it records
the platform it was synced on. Two people on different platforms therefore
overwrite each other's record, and the one the gate did not run on is
`stale` ("synced on <platform>, not this host"). A sync also rewrites
`projected_at` every time, so a local sync dirties the committed file even
when the environment is unchanged. Have one protected job, on one platform,
write the closures that are committed.

Signing: `tog keygen <path>` writes an Ed25519 key file (mode 0600,
never overwriting an existing file or symlink) and prints the `[signing]`
table that trusts it; the private seed is never printed. With
`TOG_SIGNING_KEY=<path>` set, every command that writes a closure
(`sync`, `fmt`, `build`, `add`, `remove`, `update`) signs it. The key is
loaded once, before the store is opened or a manifest is edited; a configured key (including an empty path) that is
missing, malformed, not a regular file, or readable by group or other fails
the command, never silently downgrades to unsigned. Unset, the record is
written unsigned and the sync summary says so. Trust is the machine
policy's `[signing]` table, `trusted = ["ed25519:<64 hex>", ...]`, in
`TOG_POLICY` or `~/.tog/policy.toml`; a project `.tog/policy.toml`
or the `--policy` file can only intersect with it, so a pull request that
edits the record and the project policy can only remove trust. With no
`[signing]` table at machine scope the gate is not configured: exit 2 with
the fix in the message, before any record is judged. An explicit
`trusted = []` is a decision: every signed record is `untrusted`. Rotation:
add the new public key to the machine policy, re-sync under the new private
key, then remove the old key; removal is revocation, and the records it
signed become `untrusted` with the re-sync fix in the message. Expected
deployment: a protected CI job holds the key, runs a trusted binary against
an approved checkout, and commits the closures; a fork's pull request gets a
sync-only job with no key and no `audit` (see "Gating a pull request with
sync and audit"). A job that runs untrusted project code must
not hold a signing key: `sync` can execute project code during planning and
`fmt` can delegate a package script, and mode 0600 does not stop same-user
code from reading the key. Keep it outside the checkout, the store, and any
sandbox read root, and discard checkout-supplied plan caches before a
signing sync. The signature is an additive envelope field
(`signature: {alg, key, sig}`) over the canonical bytes of the whole record:
`schema`, `ecosystem`, `platform`, `projected_at`, and all of `body`
including `body.exceptions[]`. Whitespace and key order in the file do not
matter; any change to the parsed value does. `run`, `x`, `ls`, `sbom`, and
`status` keep accepting unsigned records: verification is the gate's job.

Per closure it prints the ecosystem, the record (sha256 of the closure file
bytes), and the first of these that applies: `bad-signature` (a signature
is present and does not verify: tampered, malformed, or an unknown
algorithm; find out who changed it, then regenerate under a trusted key),
`untrusted` (verifies under a key the effective set does not contain; the
line names the key and the scopes that exclude it), `outdated` (no
signature, or a record from before inputs, platform, or the exception
record were written; run `tog` once under a trusted key, then
commit), `stale` (the same inputs-changed / projection-missing /
other-platform checks `status` makes, made per closure file from that
file's own record), `denied` (each denied exception's kind, subject, and
detail), `unknown` (an exception kind this binary cannot judge), or `clean`
(permitted exceptions counted by kind). A `bad-signature`, `untrusted`, or
unsigned record is not evaluated further: freshness is not computed and no
exception is judged, and the line says `(not evaluated)` rather than
claiming anything about its contents. A detected ecosystem with no
`.tog/closures/<ecosystem>.json` is listed as `missing` and fails the
report; the optional `rustfmt` record is not a substitute for `cargo.json`.
Only `clean` with nothing missing passes. The `rustfmt` closure
`tog fmt` writes projects nothing, so its inputs are the rustfmt object
it ran, the directory the toolchain file was looked up from, and the
components that file asked for that tog does not provide. It is `stale`
when any of those, or the Rust object and version beside them, is not what
this binary would record for the same run now (including a toolchain with
no pinned rustfmt), and `outdated` when it predates recording inputs;
either way the fix is `tog fmt`. A closure file whose `ecosystem` field
disagrees with its name, or whose envelope is malformed (not `closure/1`,
no ecosystem string, a non-object body), is refused with exit 1, not
judged. No rebuild, no store access, no network, no sandbox: it works on a
machine without bubblewrap.

`--json` writes the report to stdout. `project` and each closure's `path`
are lossy UTF-8 strings. On Unix, a non-UTF-8 project path also has a
sibling `project_bytes` field, and a non-UTF-8 closure path has a sibling
`path_bytes` field, each containing the lowercase hex of the raw path bytes.
Each closure has `verdict` (the word above), `signature` (`state` one of
`trusted`, `unsigned`, `untrusted`, `bad`; `key` present when a public key
could be decoded; `detail` the reason, or the excluding scopes), `freshness`
(`current`, `stale`, `outdated`, or `not-evaluated`), `freshness_detail`,
and `denied`, `unknown`, `permitted`, which are `null` for a record that was
not evaluated. `missing` lists the detected ecosystems without a primary
closure. `policy.trusted` is the effective trusted set. Under
`policy.sources` it lists the policies that were merged into the one it
judged against, in merge order. Each source has `origin`, `strict`, `deny`,
and `trusted` (`null` when the file has no `[signing]` table, `[]` when it
explicitly trusts nobody); file-backed sources also have `path` as a lossy
UTF-8 string. A non-UTF-8 path also has `path_bytes` as the lowercase hex
of its raw bytes; that field is present only for non-UTF-8 paths. `origin`
is `machine` (`TOG_POLICY`, or `~/.tog/policy.toml`), `project` (an
ancestor's `.tog/policy.toml`), `flag` (the `--policy <file>` file, and
nothing else for audit), or `env` (`TOG_STRICT=1`). The supplied
`--policy` file is listed after the ordinary chain. The `path` field is
omitted for strictness-only sources, and `deny` is always an array,
including when it is empty. A file source is listed when it exists and is
merged even if it denies nothing. In the text report, each file-backed
source is one `policy: <origin> "<path>" [denies a, b] [(strict)] [trusts
<keys> | trusts nobody]` result line on stdout. Paths are always
Rust-Debug-quoted, so spaces and policy-like words in a filename cannot
change the grammar. Strictness-only sources omit the path. Policy lines
come first, then verdict lines, then `missing` lines, and `--quiet` leaves
them in place. Exit 0 when every closure is clean and none is missing, 1
otherwise, 2 when the gate is misconfigured. A company deny list to start
from ships as [policy-company.toml](policy-company.toml); every kind it
names is checked against the binary's kind list by a unit test. Exception
kind names use one separator, the hyphen (`weak-integrity`,
`skipped-optional`, `artifact-not-provisioned`); the older underscore
spellings are still read from policy files and from closures written by
earlier versions, and are judged and printed as the hyphenated name.

A refusal names the knob that refused and the edit that lifts it, not just
the kind: `policy denies weak-integrity: left-pad: sha1 integrity;
'weak-integrity' is in the deny list in /etc/tog/policy.toml; remove that
line to allow it`, or, when strictness is the cause, the flag
(`--strict ...; rerun without --strict`), the variable (`unset
TOG_STRICT`), or the file that set `strict = true`.

**ls** reads `.tog/closures/*.json` (no store access): name, version, and
toolchain per package, `-v` adds artifact and store object (and works in
either position); the filter word is one of
`python`, `node`, `cargo`, `go`, `ruby`, `elixir`, `dotnet`, `rustfmt`.
**plan** prints what a sync would realize, one JSON document per ecosystem.
**sbom** emits CycloneDX 1.5 to stdout or `-o <file>`. **doctor** checks
this build against the newest release (the first row, `warn` with `run 'tog
update --self'` when one is newer, `ok` with `not checked` when the manifest
is unreachable: offline is not unhealthy), then platform, store, sandbox,
host C toolchain, and realized toolchains, each line `ok`/`warn`/`fail`
(lowercase, in text and in JSON) with the fix; exit 1 on any fail.

**--version** prints `tog <crate version> (<short commit> <commit date>)`,
stamped at build time from the checkout (`tog 0.1.0 (7688cfd 2026-09-21)`);
outside a checkout the parenthesis says `unknown build`. Two binaries of the
same crate version built from different commits print different lines, which
is what makes "is this binary stale?" answerable and what a bug report
should quote.

### Gating a pull request with sync and audit

`audit` judges the closure in the checkout it is run in, against the
projection in that checkout, so the job has to sync before it audits. That
also makes the gate stronger than a file check: the sync itself fails on a
denied exception, so the policy is enforced while the environment is built
rather than inspected afterwards.

```yaml
name: tog
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install tog
        run: |
          curl -fsSL https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh \
            | sh -s -- --no-modify-path --no-completions
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      # The machine policy: the deny list, and the public keys audit trusts.
      # Nothing secret — a public key is a public key — but audit exits 2
      # without a [signing] table, so the gate is never silently unconfigured.
      - name: Machine policy
        run: |
          mkdir -p ~/.tog
          cp ci/tog-policy.toml ~/.tog/policy.toml

      # Build the environment under that policy. A denied exception fails
      # here, before anything is judged. The key signs the closure this sync
      # writes; see the caveat below for which jobs may hold one.
      - name: Sync
        env:
          TOG_SIGNING_KEY: ${{ runner.temp }}/tog.key
        run: |
          # printf, not a herestring: no bash dependency, and no newline
          # appended to the key. umask before the write, so the file is
          # never briefly world-readable.
          (umask 077; printf '%s' '${{ secrets.TOG_SIGNING_KEY }}' > "$TOG_SIGNING_KEY")
          tog --frozen
          rm -f "$TOG_SIGNING_KEY"

      # Every closure signed by a trusted key, current for the inputs on
      # disk, no denied or unknown exception. Exit 1 is a denied build,
      # exit 2 an operator mistake (missing or malformed policy).
      - run: tog audit

      - run: tog sbom -o sbom.json
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: sbom.json }
```

**Which jobs may hold the key.** A sync executes project code while
planning, and mode 0600 does not stop same-user code from reading a key, so
the job above is only safe on a ref you control — a protected branch, or a
`pull_request_target`-style job you have deliberately reviewed. For pull
requests from forks, drop the key and the `audit` step and run the sync
alone:

```yaml
      - run: tog --frozen --strict    # or: tog --frozen, under ci/tog-policy.toml
      - run: tog sbom -o sbom.json
```

That still refuses every exception the policy denies, which is the part that
matters for an untrusted branch; it just does not produce a signed record.
The closures a reviewer reads in the diff come from the protected job, or
from a developer running a signing sync locally.

On a runner without unprivileged user namespaces the build sandbox is
unavailable, so a project that needs `tog build` or sdist compilation needs
a runner that has them; `sync` of a wheel-only or lock-only project does
not.


## Maintain verbs

**gc** follows every registered project closure and removes unreferenced
store objects, stale artifacts (retention `--keep-days <n>`), and stale
staging; objects touched in the last ten minutes are always kept so a
concurrent sync cannot lose one. Sharp edges:

- `--forget <key>...` removes protection records by the exact keys printed
  by `tog store roots` (`<40-hex key>  <path>`, one line each), matched
  as typed including case. It removes only the record, so its objects become
  collectible; it clears even an unusable record without reading any other,
  so a damaged record never blocks recovering from it.
- `--dry-run` prints the same plan a sweep would execute — `would remove …`,
  `blocked: …` with the recovery action, `skipped: …` — and writes nothing;
  it refuses alongside `--register`, which would have to write a record.
- Any object whose recorded evidence cannot be certified stops the sweep
  rather than being guessed at — `--collect-legacy` never overrides that —
  as does an unavailable legacy pathname-only record; restore it or forget
  its key.
- `--migrate-metadata` upgrades provable legacy object metadata to
  `object-meta/2` and stops without sweeping (`N upgraded, M unresolved`);
  it is incompatible with the registry and collection options. It never
  deletes anything: its job is to list every record that stops the sweep,
  including the ones nothing can read, each with the command that clears it.
  The same migration also runs automatically before the first
  resource-consuming job. When it is deferred because records are
  unresolved, the warning is printed once per store and again whenever the
  list of records changes, since it would otherwise precede every command
  until someone acted on it; `tog gc --migrate-metadata` repeats it on
  demand. A deferral because another Tog job owns the store is transient
  and still prints every time.
- `--drop-object <id>...` removes an object and its record outright, for the
  records the sweep cannot use: unusable, still legacy after migration, or
  missing their object (and an object missing its record). Everything in the
  store is content-addressed, so the next sync that needs the object rebuilds
  it at the same id. It refuses an object whose record is readable and
  certified — that is the sweep's decision, reached by forgetting the roots
  that protect it — and it refuses to leave a readable record naming an
  object it removed, naming the whole set that has to go together instead.
  It takes `--dry-run` and nothing else.
- `--project` also collects old unused project forests and backups; legacy
  sibling-home forests are never swept and are reported as skipped.

**keygen** `<path>` creates a closure-signing key (see **audit** above) and
prints the `[signing]` table to paste into the machine policy.
**store** prints the store root (`store path`) or every registered project
root (`store roots`). **version** prints `tog 0.1.0`.

## Open questions

- `tog why <pkg>`: closures record packages, not dependency edges.
- `x` for cargo and go; a `tog.toml` `[tasks]` table for cross-language
  scripts — both wait for a real need.

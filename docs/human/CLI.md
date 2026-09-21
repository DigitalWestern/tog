# Tog CLI

*Written 2026-09-10. Replaces the 2026-09-06 plan at the repo root: what it
promised is shipped, so this file describes only what exists. The help screen
below is the spec, generated from the command table in `src/cli/spec.rs`; if this
file and the binary differ, fix this file.*

```
tog 0.1.0 — one command for every package manager

USAGE:
  tog [<options>] <command> [<args>...]
  tog                      in a project: the same as 'tog sync'
  tog <script> [<args>...] run a package.json script (like 'npm run')

EVERYDAY:
  sync         realize and project the environment(s); aliases: install, i
  add          add a dependency, re-lock, sync
  remove       remove a dependency, re-lock, sync
  update       update dependencies within the manifest's constraints, sync
  run          run a command or package.json script inside the projected env(s)
  x            run a tool without adding it to the project (like npx / uvx)
  build        sandboxed, network-denied build (cargo | go | elixir | dotnet)
  fmt          format the Rust project with the pinned rustfmt

INSPECT:
  doctor       check host prerequisites, the sandbox, and the store
  status       is the projection current with the manifest and the lock?
  ls           list what is installed, per ecosystem
  audit        would the synced closures pass a policy? (CI admission gate)
  plan         print the locked plan(s) as JSON
  sbom         CycloneDX 1.5 SBOM of the synced closures

MAINTAIN:
  gc           collect unreferenced store objects and cached artifacts
  store        'store path', 'store roots'
  keygen       create a closure-signing key and print its public key
  completions  print a shell completion script (bash | zsh | fish)
  help         show help for a command
  version      print the version

OPTIONS:
  -C, --directory <dir>  run as if tog had been started in <dir>
  -q, --quiet            no narration: only errors and results on stdout
  -v, --verbose          show every decision and subprocess command line
      --no-color         plain output (also: NO_COLOR, or a non-tty stderr)
  -h, --help             print help ('tog help <command>' for one command)
  -V, --version          print the version
  Any of these may be given before or after the command, except
  where the rest of the line belongs to a program ('run', 'build')
  or a tool ('fmt', 'x').

ENVIRONMENT:
  TOG_STORE           store root (default ~/.tog/store)
  TOG_STRICT=1        refuse every policy exception, like --strict
  TOG_POLICY          policy file used instead of ~/.tog/policy.toml
  TOG_SIGNING_KEY     key file; every command that writes a closure signs it
  NO_COLOR            plain output, like --no-color

Exit status: 0 success, 1 failure, 2 usage error; 'run', 'x' and 'fmt'
pass the program's status through.

PROJECT INPUTS: every ecosystem whose manifest is found here is synced —
requirements.txt/pyproject.toml/setup.py, package-lock.json/pnpm-lock.yaml/
yarn.lock, Cargo.toml, go.mod, Gemfile, mix.exs, *.csproj. The full table,
with what each one locks, is in 'tog help sync'.
```

## Conventions

- **stdout is results, stderr is narration.** `plan`, `sbom`, `store path`,
  and the `--json` forms write parseable output to stdout and nothing else;
  progress keeps the `tog:` prefix on stderr. `gc` narrates, so every line
  it prints — registered, forgot, would free, freed, cleanup skipped — is
  stderr and `--quiet` silences all of it.
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
  (`sync: unknown option '--fersh'; did you mean '--fresh'?`) and exit 2.
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
- **Color** only on a tty stderr, only for `error:`/`warning:` and `synced:`
  words; `--no-color` or `NO_COLOR` turns it off, and stdout never gets it.
- **Global options work before or after the command.** `-C <dir>`, `-q`,
  `-v` and `--no-color` mean the same thing in either position (`tog ls -v`
  and `tog -v ls` are the same command), except where the rest of the line
  belongs to something else: `run` and `build` pass every argument after
  the verb to the program, `fmt` and `x` accept them only ahead of the
  tool's own arguments, and the value slot of a command's own option is
  never searched (`tog gc --register -v` registers a directory called
  `-v`; the command table says which options take a value). What reaches
  that slot is then the option's own business — see the next rule.
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

**sync** (aliases: `install`, `i`; a bare `tog` inside a project means
`sync`) discovers every ecosystem present in the current directory, realizes
each locked plan into the store, and projects it (`.venv`, `node_modules`,
`.tog/...`); a manifest with no dependencies syncs an interpreter-only
environment, and `--fresh` drops project-local caches and rebuilds. It takes
no package name: `tog install requests` is a usage error that names
`tog add requests`. Policy exceptions are recorded in `.tog/closures/*.json`
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
present, which is where most people find the shorthand. There is no
`tog env` and no direnv integration: everything still runs through a tog
process (issue #108).

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
  `bun`, which install. `install` and `ci` are answered with `tog sync`,
  which rebuilds `node_modules` from the lockfile; the verbs that change the
  lockfile are answered with `tog add` / `tog remove` / `tog update`.

Reading an environment is not changing it, so `pip list`, `pip freeze`,
`pip show`, `pip check`, `pip download` and `npm ls` run normally, as does
everything else: `npm run build`, `npm test`, `python -m pytest`. A
`node_modules` that a tool already replaced is reported by `tog status` as a
real directory written over the projection, and the next `tog sync` moves it
aside — saying where it went — and re-projects.

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

**build** runs the ecosystem's build tool in the network-denied sandbox with
the pinned toolchain and realized dependency objects; the ecosystem is
inferred only when exactly one build-capable project (Cargo.toml, go.mod,
mix.exs, `*.csproj`) is found from here upward — name it when several are.

## Inspect verbs

**status** compares each closure's recorded inputs against the files on disk
and checks the projection is in place, naming the changed file otherwise.
One row per detected ecosystem, then a summary line (`2 of 3 synced; 1
unchecked.`) and, when something is not synced, a line explaining each word
that needs it. The states: `synced`, `changed` (with the files),
`not synced`, `missing` (the projection is gone), `elsewhere` (the closure
was written on another platform and says nothing about this host), and
`unchecked` — a closure this binary could not compare, because the record
predates the input recording the comparison needs. `unchecked` is not a
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
repository that ignores all of `.tog/` can never make `audit` pass, because
the gate has nothing to read. The `.gitignore` stanza and the full table
are in [the README](../../README.md#what-tog-holds-and-what-to-commit).

A closure is one file per ecosystem, not one per platform, and it records
the platform it was synced on. Two people on different platforms therefore
overwrite each other's record, and the one the gate did not run on is
`stale` ("synced on <platform>, not this host"). A sync also rewrites
`projected_at` every time, so a local sync dirties the committed file even
when the environment is unchanged. Have one protected job, on one platform,
write the closures that CI judges.

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
an approved checkout, and commits the closures; pull-request jobs run
`audit` with public keys only. A job that runs untrusted project code must
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
record were written; run `tog sync` once under a trusted key, then
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
**plan** prints what `sync` would realize, one JSON document per ecosystem.
**sbom** emits CycloneDX 1.5 to stdout or `-o <file>`. **doctor** checks
platform, store, sandbox, host C toolchain, and realized toolchains, each
line `ok`/`warn`/`fail` (lowercase, in text and in JSON) with the fix;
exit 1 on any fail.

### Gating a pull request on the closures

The job below is the expected shape: a checkout, a tog, `tog status` to
prove the committed closures still match the committed locks, and `tog
audit` with public keys only. No signing key goes anywhere near a job that
runs project code. Tog has no GitHub Action of its own yet, so the job
installs the binary the same way a developer does.

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

      # Your repository's copy of the trusted public keys. Nothing secret:
      # a public key is a public key, and audit refuses to run at all
      # without a [signing] table at machine scope.
      - name: Machine policy
        run: |
          mkdir -p ~/.tog
          cp ci/tog-policy.toml ~/.tog/policy.toml

      # Did the author commit a closure that matches the lock they committed?
      # Offline, read-only, exit 1 on anything not synced.
      - run: tog status

      # Is every closure signed by a trusted key, current, and free of
      # denied exceptions? Exit 1 is a denied build, exit 2 is an operator
      # mistake (missing or malformed policy).
      - run: tog audit --policy ci/tog-deny.toml
```

The sync that writes those closures belongs in a separate, protected job
that holds `TOG_SIGNING_KEY` and commits the result; see the deployment
paragraph above for why it must not be this one. On a runner without
unprivileged user namespaces the sandbox is unavailable, so keep `sync` and
`build` out of the pull-request job and let it read records only.

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
- `sync --frozen` (validate `tog-toolchain.toml` without touching it)
  and `update --toolchain` are designed but not implemented.
- `x` for cargo and go; a `tog.toml` `[tasks]` table for cross-language
  scripts — both wait for a real need.

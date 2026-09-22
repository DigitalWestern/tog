//! The command table: every command's usage, options, and help text.

use super::{Group, Spec, VERSION};

const HELP_OPTION: (&str, &str) = ("-h, --help", "print this help");
const JSON_OPTION: (&str, &str) = ("--json", "machine-readable output on stdout");

/// What `tog ls` accepts as a filter word. `ls` lists closures, not
/// ecosystems: besides the seven ecosystems it prints a row for the
/// toolchain-only `rustfmt` closure `tog fmt` writes, and every name
/// `ls` can print must be a name it accepts. This is the `ls` vocabulary
/// only; it never selects an ecosystem for sync, add, or build.
pub const LS_WORDS: &[&str] = &[
    "python", "node", "cargo", "go", "ruby", "elixir", "dotnet", "rustfmt",
];
pub const BUILD_WORDS: &[&str] = &["cargo", "go", "elixir", "dotnet"];
pub const SHELL_WORDS: &[&str] = &["bash", "zsh", "fish"];

/// What `tog update --toolchain` accepts as an ecosystem. These are the
/// `[toolchain.<name>]` section keys of `tog-toolchain.toml`, which is why
/// Rust appears under its own name rather than `cargo`; `cargo` is accepted
/// as a spelling of it, because every other verb calls that ecosystem
/// `cargo`.
pub const TOOLCHAIN_WORDS: &[&str] = &["python", "node", "rust", "go", "ruby", "elixir", "dotnet"];

/// The accepted spelling that is not a section key, offered for
/// suggestions but not listed as one of the names.
pub const TOOLCHAIN_ALIAS: &str = "cargo";

/// The `[toolchain.<name>]` section key an accepted word names.
pub fn toolchain_section(word: &str) -> Option<&'static str> {
    match word {
        "cargo" | "rust" => Some("rust"),
        "python" => Some("python"),
        "node" => Some("node"),
        "go" => Some("go"),
        "ruby" => Some("ruby"),
        "elixir" => Some("elixir"),
        "dotnet" => Some("dotnet"),
        _ => None,
    }
}
pub const SYNC_ALIASES: &[&str] = &["install", "i"];

pub const COMMANDS: &[Spec] = &[
    Spec {
        name: "sync",
        group: Group::Everyday,
        summary: "set up the environment(s) from the locks; aliases: install, i",
        usage: "tog sync [--fresh] [--strict] [--frozen]   (aliases: install, i)",
        description: "\
Discovers every ecosystem present in the current directory, realizes each
locked plan into the immutable store, and projects it into the project
(.venv, node_modules, .tog/...). A bare 'tog' inside a project does the
same and then prints this help; outside a project it prints the help and
exits 0. 'tog run', 'tog env' and 'tog <script>' sync on their own
whenever the project is not synced or its inputs changed, so typing
'sync' is for a sync with options, a sync with nothing to run after it,
or a sync with no help after it. A found manifest with no dependencies
syncs an interpreter-only environment. It takes no package name: adding a
dependency is 'tog add <package>'.

PROJECT INPUTS (any combination; each ecosystem found here is synced):
  python   requirements.txt, pyproject.toml, setup.cfg/setup.py,
           requirements/*; ranged inputs are locked into a hash-pinned
           requirements.lock.txt, and a Poetry/uv lockfile is imported
           when compatible. .python-version selects the interpreter: X.Y
           takes the newest pinned patch, X.Y.Z must be an exact pinned
           build, and with neither the newest pinned build is taken once
           and then recorded in tog-toolchain.toml.
  node     package-lock.json (v2/v3), pnpm-lock.yaml (v9, v6 importer
           shape also accepted), yarn.lock (Yarn classic v1)
  cargo    Cargo.toml, Cargo.lock; a missing lock is written by the
           store Cargo
  go       go.mod, go.sum; the closure is computed by the store Go
  ruby     Gemfile, Gemfile.lock; a missing lock is resolved by store
           bundler
  elixir   mix.exs, mix.lock; a missing lock is resolved by store mix
  dotnet   *.csproj with packages.lock.json (the lock is mandatory)

TOOLCHAIN: the first writable sync writes tog-toolchain.toml at the project
root, naming the exact runtime per ecosystem; commit it. Later syncs honor
it and never reselect. A source file that disagrees with the lock
(.python-version, .node-version, go.mod, rust-toolchain.toml, .ruby-version,
.tool-versions, global.json) stops the sync and names
'tog update --toolchain', which is the only way to move a locked runtime.

--frozen never modifies project inputs, tog-toolchain.toml, or the catalog
cache; it may realize store objects and write the projection after validation
succeeds; validation failure exits before any write.

Policy exceptions (unattested inputs, failed install scripts, ...) are
recorded in .tog/closures/*.json and summarized at the end; --strict, a
TOG_STRICT=1 environment, or a .tog/policy.toml deny list refuses
them instead.",
        examples: &[
            ("tog", "sync this project; the bare form also prints this help"),
            ("tog sync --frozen", "CI: check the locks are current without writing them"),
            ("tog sync --fresh", "rebuild .venv / node_modules from scratch"),
        ],
        options: &[
            ("--fresh", "rebuild the projection, dropping project-local caches"),
            ("--strict", "refuse every policy exception (same as TOG_STRICT=1)"),
            (
                "--frozen",
                "validate tog-toolchain.toml and the dependency locks without writing either; fail if missing or stale",
            ),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "add",
        group: Group::Everyday,
        summary: "add a dependency, re-lock, sync",
        usage: "tog add <package>... [--dev] [--no-sync]",
        description: "\
Adds each package to the project's manifest with the ecosystem's own pinned
tool (uv, the store npm, pinned pnpm, cargo, go, bundler), re-locks, and
syncs. Where no pinned tool can make the edit (Poetry, PDM, Yarn classic,
setup.py, Elixir, .NET) tog refuses and prints the exact line and file
instead.

Which ecosystem: an explicit prefix (py:requests, npm:react, cargo:serde,
go:github.com/x/y, gem:rails, hex:jason, nuget:Foo.Bar) or the name's shape
(@scope/name, github.com/..., Foo.Bar) decides it; otherwise the nearest
manifest walking up from here; if that directory holds several, the
registries are asked and a name known to exactly one wins; if several know
it you are asked at the terminal. Tog never guesses from the bare name.
Constraints pass through to the tool: 'requests>=2', 'react@18',
'serde@1', 'rails@~> 7.1'.",
        examples: &[
            ("tog add requests", "add a dependency, re-lock, and sync"),
            ("tog add react@18 --dev", "a development dependency, at a version"),
            ("tog add py:requests", "name the ecosystem when several manifests are here"),
        ],
        options: &[
            ("-D, --dev", "a development dependency (uv --dev, npm --save-dev, cargo --dev, bundler group development)"),
            ("--no-sync", "stop after the manifest and lock edit; review, then run 'tog'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "remove",
        group: Group::Everyday,
        summary: "remove a dependency, re-lock, sync",
        usage: "tog remove <package>... [--dev] [--no-sync]",
        description: "\
The inverse of add, through the same pinned tools with the same ecosystem
choice. For a plain requirements file tog deletes the line itself.",
        examples: &[
            ("tog remove requests", "drop it from the manifest, re-lock, and sync"),
            ("tog remove react --dev", "from the development dependencies"),
        ],
        options: &[
            ("-D, --dev", "remove from development dependencies (uv --dev, cargo --dev)"),
            ("--no-sync", "stop after the manifest and lock edit; review, then run 'tog'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "update",
        group: Group::Everyday,
        summary: "update dependencies, --toolchain, or --self (tog itself)",
        usage: "tog update [<package>...] [--no-sync]\n  tog update --toolchain [<ecosystem>] [--no-sync]\n  tog update --self",
        description: "\
Re-locks everything (or only the named packages) to the newest versions the
manifest allows: uv lock --upgrade, npm update, cargo update, go get -u,
bundle update, mix deps.update, and pnpm update --lockfile-only. Poetry, PDM,
Yarn classic, and .NET projects are told which command to run with their own
tool.

--toolchain is the other update, and the two never mix: it re-reads the
project's declarative toolchain sources, selects the newest compatible
release for every ecosystem the project has, or only <ecosystem> — python,
node, rust (spelled cargo too), go, ruby, elixir, dotnet — rewrites
tog-toolchain.toml, and syncs. It takes no package name and leaves every
dependency lock alone. It is also how an ecosystem the project just gained
gets its section, and the next step every stale-lock refusal names.
--no-sync stops after the lock is written, so the diff can be reviewed
before anything is realized.

--self updates tog itself and touches no project: it asks GitHub for the
newest release, stops when this build is already that version, and
otherwise downloads the binary for this machine, checks the sha256 the
release publishes, and renames it over the running binary. It refuses,
naming the directory, when that directory is not writable. 'tog doctor'
says when a newer release exists; nothing checks in the background.",
        examples: &[
            ("tog update", "re-lock every dependency"),
            ("tog update --toolchain python", "move the pinned Python, then sync"),
            ("tog update --self", "replace this binary with the newest release"),
        ],
        options: &[
            ("--no-sync", "stop after the lock edit; review, then run 'tog'"),
            (
                "--toolchain [<ecosystem>]",
                "re-select the toolchain from the project's version files and rewrite tog-toolchain.toml, then sync",
            ),
            (
                "--self",
                "replace this tog binary with the newest GitHub release",
            ),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "run",
        group: Group::Everyday,
        summary: "run a command or package.json script in the environment(s)",
        usage: "tog run [--] <command> [<args>...]",
        description: "\
Executes <command> with PATH and the ecosystem variables of the nearest
projected root (the closest ancestor with .tog/closures/). When the
project has a package.json and <command> names one of its scripts, the
script runs (pre/name/post, npm environment, exit code passed through) and
wins over a same-named executable on PATH; 'tog <script>' is the short
form when the script name is not a tog command. Everything after
<command> is passed through unchanged.

The environment is the one the project's inputs describe: when nothing is
synced yet, or 'tog status' would say a manifest or lock changed, the
project is synced first (one line on stderr says why) and then the command
runs. A sync that would refuse refuses here too, in its own words. A
directory with no manifest has nothing to sync and exits 1 saying so.",
        examples: &[
            ("tog run python app.py", "run a program in the project's environment"),
            ("tog run pytest -q", "every argument after the command is passed through"),
            ("tog dev", "a package.json script, without the word 'run'"),
        ],
        options: &[HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "env",
        group: Group::Everyday,
        summary: "print the environment as shell exports (for eval or direnv)",
        usage: "tog env [--shell <bash|zsh|fish>]",
        description: "\
Prints, on stdout, the same PATH and ecosystem variables 'tog run' would
give a child: one line per variable, in the syntax --shell names. Nothing
but those lines goes to stdout, so the output is safe to eval.

'tog run <command>' scopes that environment to one command. 'env' makes it
ambient instead: every later command in the shell that evals it sees the
environment, including commands tog knows nothing about. direnv is what
scopes an ambient environment back to a directory, loading it on entry and
unloading it on exit.

  eval \"$(tog env)\"        # this shell, until it exits
  echo 'eval \"$(tog env)\"' > .envrc && direnv allow
                           # direnv: scoped to this directory

--shell defaults to the basename of $SHELL when that is bash, zsh, or fish,
and to bash otherwise; bash and zsh get identical POSIX sh syntax. A
variable the environment removes is printed as 'unset NAME' ('set -e NAME'
for fish), and $PATH is kept at the end of the new PATH rather than
expanded, so the same line can be evaled twice.

Like 'run', it syncs first when the project is not synced or its inputs
changed; that narration goes to stderr, so stdout still carries only the
environment. A directory with no manifest prints nothing and exits 1
saying so. A package.json script named 'env' is reached with
'tog run env': a built-in always wins.",
        examples: &[
            ("eval \"$(tog env)\"", "this shell, until it exits"),
            ("echo 'eval \"$(tog env)\"' > .envrc && direnv allow", "direnv, per directory"),
        ],
        options: &[
            (
                "--shell <bash|zsh|fish>",
                "which syntax to print; default: the basename of $SHELL when it is one of these, else bash",
            ),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "x",
        group: Group::Everyday,
        summary: "run a tool without adding it as a dependency (like npx / uvx)",
        usage: "tog x [--py | --npm] [--from <package>] <tool>[@<version>] [<args>...]\n  tog x --clean [--py | --npm] [--from <package>] [<tool>[@<version>]]",
        description: "\
Resolves the package with the store uv or npm, realizes it as an ordinary
store environment (a store hit from the second run on), and executes the
tool with every argument passed through. Which registry: 'py:' or 'npm:'
on the tool, --py / --npm, or the current project's ecosystem (Python
first, then Node); outside a project the prefix is required. --from names
the package when the executable is called something else
('tog x --from httpie http'). Environments live under ~/.tog/x/
and are gc roots like any project. `--clean` removes every cached x
environment, or only the selected tool's environments; store objects stay
until the next `tog gc`. A running tool is left in place and reported as
in use; retry after it exits.",
        examples: &[
            ("tog x ruff check .", "run a tool that is not a dependency"),
            ("tog x --npm prettier --write .", "say which registry when it is ambiguous"),
            ("tog x --from httpie http example.com", "when the tool and the package differ"),
        ],
        options: &[
            ("--clean", "remove cached x environments instead of running a tool"),
            ("--py, --python", "resolve from PyPI"),
            ("--npm, --node", "resolve from npm"),
            ("--from <package>", "the package that provides <tool>"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "build",
        group: Group::Everyday,
        summary: "sandboxed, network-denied build (cargo | go | elixir | dotnet)",
        usage: "tog build [<ecosystem>] [--] [<tool args>...]",
        description: "\
Runs the ecosystem's build tool inside the network-denied sandbox with the
pinned toolchain and the realized dependency objects. The ecosystem is
inferred when exactly one build-capable project (Cargo.toml, go.mod,
mix.exs, *.csproj) is found from here upward; name it when several are.
Every argument after the ecosystem is handed to the tool unchanged, so
'tog build --release' works; use '--' if the first tool argument is
'-h' or '--help'.",
        examples: &[
            ("tog build", "network-denied build with the pinned toolchain"),
            ("tog build --release", "arguments after the verb go to the build tool"),
        ],
        options: &[HELP_OPTION],
        words: BUILD_WORDS,
    },
    Spec {
        name: "fmt",
        group: Group::Everyday,
        summary: "format the Rust workspace with the pinned rustfmt",
        usage: "tog fmt [--check] [--eco <ecosystem>] [--] [<args>...]",
        description: "\
Runs the pinned rustfmt/cargo-fmt for a Rust workspace. The workspace is
discovered with the store Cargo tool and Cargo metadata is read with
--no-deps, so a project that has never been synced needs no Cargo.lock,
dependency resolution, or vendor object. --check returns rustfmt's status.
A package.json script named fmt takes precedence and is run as
'tog run fmt'. In a polyglot directory use --eco rust: an explicit --eco
selects the ecosystem, so it formats Rust instead of running that script.
Other ecosystems are not implemented yet.",
        examples: &[
            ("tog fmt", "format the Rust workspace with the pinned rustfmt"),
            ("tog fmt --check", "CI: fail when something is unformatted"),
        ],
        options: &[
            ("--check", "check formatting without editing files"),
            ("--eco <ecosystem>", "select the ecosystem (Rust: rust)"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "doctor",
        group: Group::Inspect,
        summary: "check host prerequisites, the sandbox, and the store",
        usage: "tog doctor [--json]",
        description: "\
The first-five-minutes command. Checks this build against the newest
GitHub release (one request; 'not checked' when offline), the platform,
the store (path, writable, free space), the build sandbox (bubblewrap and
user namespaces on Linux, sandbox-exec on macOS), the host C toolchain
native builds need, the toolchains already realized, and the project in
the current directory. Each line is ok, warn, or fail with the fix; exit
status 1 on any fail.",
        examples: &[
            ("tog doctor", "check this machine, the sandbox, and the store"),
            ("tog doctor --json", "the same rows as one JSON document"),
        ],
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "status",
        group: Group::Inspect,
        summary: "is the environment current with the manifest and the lock?",
        usage: "tog status [--json]",
        description: "\
For every ecosystem found here: 'synced' when the last sync's inputs are
byte-identical to the files on disk and the projection is in place;
otherwise which file changed, that the projection is missing, or that the
closure was synced on another platform. Offline and read-only. Exit status
0 only when everything is synced, so CI can use it as a 'did you commit the
lock' gate.",
        examples: &[
            ("tog status", "is the environment current with the lock?"),
            ("tog status --json", "machine-readable, for a CI step"),
        ],
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "ls",
        group: Group::Inspect,
        summary: "list what is installed, per ecosystem",
        usage: "tog ls [<ecosystem>] [--json]",
        description: "\
Name and version of every package in each synced closure, with the
toolchain each runs on; -v adds the artifact and store object. Read from
.tog/closures/*.json, no store access. Ecosystems: python, node,
cargo, go, ruby, elixir, dotnet; plus rustfmt, the toolchain-only closure
'tog fmt' writes.",
        examples: &[
            ("tog ls", "every package in every synced ecosystem"),
            ("tog ls python", "one ecosystem only"),
        ],
        options: &[
            ("-v, --verbose", "add each package's artifact and store object"),
            JSON_OPTION,
            HELP_OPTION,
        ],
        words: LS_WORDS,
    },
    Spec {
        name: "audit",
        group: Group::Inspect,
        summary: "would the synced environments pass a policy? (CI gate)",
        usage: "tog audit [--policy <file>] [--json]",
        description: "\
Reads the closure records every sync committed to .tog/closures/*.json,
verifies each record's signature against the [signing] trusted keys in the
machine policy (TOG_POLICY or ~/.tog/policy.toml; a project
.tog/policy.toml or --policy <file> can only drop keys, never add one),
and judges the exceptions it records against the policy chain merged with
--policy <file>. Merging only tightens: the file can add denials but never
loosen what the machine or project policy says. Per closure, the first that
applies: bad-signature (tampered or malformed; find out who changed it),
untrusted (signed by a key the trusted set does not contain), outdated
(unsigned, or predates input, platform, or exception recording; run
'tog sync' once under a trusted key, then commit), stale (its inputs
changed since the sync, the same check 'tog status' makes), denied
(each denied exception's kind, subject, and detail, plus a count of
permitted ones by kind), unknown (a kind this binary cannot judge), or
clean. A record that is not trusted is not evaluated further. A detected
ecosystem with no closure is missing. The rustfmt closure 'tog fmt'
writes is stale when this binary would record that run differently now;
rerun 'tog fmt'. Only clean passes. Offline, read-only, no store
access, no sandbox needed. Exit status 0 when every closure is clean and
none is missing, 1 otherwise, 2 when no trusted key is configured.
'tog keygen' creates a signing key; set TOG_SIGNING_KEY where sync
runs. A company deny list to start from ships as docs/human/policy-company.toml.",
        examples: &[
            ("tog audit", "the CI gate for a pipeline"),
            ("tog audit --policy docs/human/policy-company.toml", "add a company deny list"),
        ],
        options: &[
            ("--policy <file>", "also deny what this policy file denies"),
            JSON_OPTION,
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "plan",
        group: Group::Inspect,
        summary: "print the locked plan(s) as JSON",
        usage: "tog plan [--json]",
        description: "\
Prints one JSON document per ecosystem found here, exactly what 'tog
sync' would realize. Planning may resolve missing lockfiles with the store's
own uv/npm/cargo and cache the result under .tog/.
The output is JSON either way; --json adds nothing but the promise every
--json command makes: stdout is JSON and a failure is a JSON object on
stderr.",
        examples: &[
            ("tog plan", "the locked plan for every ecosystem, as JSON"),
            ("tog plan | jq .", "read it with jq"),
        ],
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "sbom",
        group: Group::Inspect,
        summary: "CycloneDX 1.5 SBOM of the synced environments",
        usage: "tog sbom [--output <file>]",
        description: "\
Emits a CycloneDX 1.5 document covering every ecosystem closure recorded by
the last sync: pinned hashes, purls, and toolchain store ids. Writes to
stdout unless --output is given.",
        examples: &[
            ("tog sbom", "a CycloneDX document on stdout"),
            ("tog sbom -o sbom.json", "write it to a file instead"),
        ],
        options: &[
            ("-o, --output <file>", "write the document to <file> instead of stdout"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "gc",
        group: Group::Maintain,
        summary: "collect unreferenced store objects and cached artifacts",
        usage: "tog gc [--dry-run] [--keep-days <n>] [--project] [--collect-legacy]\n  \
                tog gc --migrate-metadata [--dry-run]\n  \
                tog gc --drop-object <id>... [--dry-run]\n  \
                tog gc --register <dir>... [--forget <key>...]",
        description: "\
Follows every registered project closure, removes store objects nothing
references, drops cached artifacts older than the retention window, and
cleans stale staging directories. Objects touched in the last ten minutes
are always kept so a concurrent sync cannot lose one. Ordinary gc never
deletes inside project projections; --project collects old unused forests
and backups. A record that says for itself what it needs keeps protecting
it even when the project directory is gone; an older pathname-only record
that has become unavailable stops the sweep instead of losing its record,
so make it available again or forget it with --forget. Cleanup is skipped
while another Tog job is using this store, and any object whose
recorded evidence cannot be certified stops the sweep rather than being
guessed at; --migrate-metadata lists every record that stops it and
--drop-object removes the ones that cannot be repaired. Usable on a copied
store from any host.",
        examples: &[
            ("tog gc --dry-run", "what would be collected, without collecting it"),
            ("tog gc", "collect unreferenced store objects"),
            ("tog gc --project", "also collect old project forests and backups"),
        ],
        options: &[
            (
                "--dry-run",
                "report what would be removed without removing it or writing any record",
            ),
            ("--keep-days <n>", "retain cached artifacts used within <n> days"),
            ("--project", "also collect old unused project forests and backups"),
            (
                "--collect-legacy",
                "also collect objects written before the roots registry existed; \
                 never a licence to delete through evidence that is missing",
            ),
            (
                "--migrate-metadata",
                "upgrade provable legacy object metadata without collecting",
            ),
            (
                "--drop-object <id>...",
                "drop an object whose metadata is unusable, legacy, or missing, together \
                 with its record; the next sync rebuilds it",
            ),
            (
                "--register <dir>...",
                "register project roots before collecting (pre-registry projects)",
            ),
            (
                "--forget <key>...",
                "forget project roots by their exact key (`store roots` prints keys); \
                 removes only the protection record, so their objects become collectible",
            ),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "store",
        group: Group::Maintain,
        summary: "'store path', 'store roots'",
        usage: "tog store <path | roots>",
        // Not a `\`-continued literal: that escape eats the leading spaces
        // of the next line, and this description is a two-row table.
        description: "  path    print the store root (~/.tog/store unless TOG_STORE is set)
  roots   list every registered project root as '<key>  <path>'",
        examples: &[
            ("tog store path", "where the store lives"),
            ("tog store roots", "every project the store protects"),
        ],
        options: &[HELP_OPTION],
        words: &["path", "roots"],
    },
    Spec {
        name: "keygen",
        group: Group::Maintain,
        summary: "create a closure-signing key and print its public key",
        usage: "tog keygen <path>",
        description: "\
Writes a new Ed25519 signing key to <path> (created exclusively, mode 0600;
an existing file or symlink is refused, never overwritten) and prints the
public key on stdout as the [signing] policy table to paste into the
machine policy. Set TOG_SIGNING_KEY=<path> where 'tog sync' and
'tog fmt' run so every closure they write is signed; 'tog audit'
accepts only records signed by a key the machine policy trusts. Keep the
key outside the checkout, the store, and any sandbox read root; a job that
runs untrusted project code must not hold one.",
        examples: &[
            ("tog keygen ~/.tog/signing.key", "then set TOG_SIGNING_KEY to it where sync runs"),
            ("tog keygen ci.key", "the public key it prints goes in the policy"),
        ],
        options: &[HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "completions",
        group: Group::Maintain,
        summary: "print a shell completion script (bash | zsh | fish)",
        usage: "tog completions <bash | zsh | fish>",
        description: "\
Generated from the same command table as this help, so it cannot drift.
Install:
  bash   tog completions bash > ~/.local/share/bash-completion/completions/tog
  zsh    tog completions zsh  > \"${fpath[1]}/_tog\"   (then: compinit)
  fish   tog completions fish > ~/.config/fish/completions/tog.fish
Package.json script names complete after 'tog run' and as the first
word when a package.json is in the current directory.",
        examples: &[
            ("eval \"$(tog completions bash)\"", "this shell, right now"),
            ("tog completions zsh > \"${fpath[1]}/_tog\"", "then: compinit"),
        ],
        options: &[HELP_OPTION],
        words: SHELL_WORDS,
    },
];

/// The four lines a newcomer needs before the command table means anything:
/// set up, run, add, and the one command that explains a broken machine.
/// Hand-written rather than generated, because the order is the lesson.
const START_HERE: &str = "\
START HERE:
  tog                   set up the project from its lockfiles
  tog run <command>     run something inside that environment
  tog add <package>     add a dependency, re-lock, sync
  tog doctor            check this machine when something looks wrong
";

const ENVIRONMENT: &str = "\
ENVIRONMENT:
  TOG_STORE           store root (default ~/.tog/store)
  TOG_STRICT=1        refuse every policy exception, like 'sync --strict'
  TOG_POLICY          policy file used instead of ~/.tog/policy.toml
  TOG_SIGNING_KEY     key file; every command that writes a closure signs it
  NO_COLOR            plain output, like --no-color
";

pub fn spec(name: &str) -> Option<&'static Spec> {
    let name = canonical_name(name);
    COMMANDS.iter().find(|spec| spec.name == name)
}

/// `install` and `i` are `sync`.
pub fn canonical_name(name: &str) -> &str {
    if SYNC_ALIASES.contains(&name) {
        "sync"
    } else {
        name
    }
}

/// The global options, with the heading carrying the rule about where they
/// may appear: a note under the block was read as a footnote and missed.
const GLOBAL_OPTIONS: &str = "\
OPTIONS (before or after the command; after 'run' or 'build' everything
belongs to the program, and 'fmt' and 'x' take them only ahead of the tool's
own arguments):
  -C, --directory <dir>  run as if tog had been started in <dir>
  -q, --quiet            errors and results only
  -v, --verbose          every decision and subprocess command line
      --no-color         plain output (also: NO_COLOR, or a non-tty stderr)
  -h, --help             this help ('tog help <command>' for one command)
  -V, --version          print the version
";

/// Top-level help: what the three shapes of argv mean, the four commands to
/// start with, the command list by group, the global options, and the
/// environment. The lockfile table is reference material and lives in
/// `tog help sync`, which names every file per ecosystem.
pub fn usage() -> String {
    let mut text = format!(
        "tog {VERSION} — one command for every package manager\n\n\
         USAGE:\n  \
         tog                        sync this project, then show this help\n  \
         tog <command> [<args>...]  run a command ('tog help <command>' explains it)\n  \
         tog <script> [<args>...]   run a package.json script (like 'npm run')\n\n"
    );
    text.push_str(START_HERE);
    let width = COMMANDS
        .iter()
        .map(|spec| spec.name.len())
        .max()
        .unwrap_or(0)
        .max("version".len());
    for (group, title) in [
        (Group::Everyday, "EVERYDAY"),
        (Group::Inspect, "INSPECT"),
        (Group::Maintain, "MAINTAIN"),
    ] {
        text.push_str(&format!("\n{title}:\n"));
        for spec in COMMANDS.iter().filter(|spec| spec.group == group) {
            text.push_str(&format!("  {:width$}  {}\n", spec.name, spec.summary));
        }
        if group == Group::Maintain {
            text.push_str(&format!(
                "  {:width$}  show help for a command\n  {:width$}  print the version\n",
                "help", "version"
            ));
        }
    }
    text.push('\n');
    text.push_str(GLOBAL_OPTIONS);
    text.push('\n');
    text.push_str(ENVIRONMENT);
    text.push_str(
        "\nExit status: 0 success, 1 failure, 2 usage error; 'run', 'x' and 'fmt' pass\n\
         the program's status through. Which files tog reads per ecosystem:\n\
         'tog help sync'. Full reference: docs/human/CLI.md.\n",
    );
    text
}

/// Every line of every help screen fits this many columns: the narrowest
/// terminal worth supporting, and the width `every_help_line_fits_eighty_columns`
/// holds the whole command table to.
pub const HELP_WIDTH: usize = 80;

/// One `  <flag>  <description>` line, wrapped into the description column.
/// A word longer than the column is left whole: a flag spelling or a path
/// must never be broken across lines.
fn option_line(flag: &str, width: usize, description: &str) -> String {
    let indent = 2 + width + 2;
    let mut out = String::new();
    let mut line = format!("  {flag:width$}  ");
    let mut filled = false;
    for word in description.split_whitespace() {
        if filled && line.chars().count() + word.chars().count() > HELP_WIDTH {
            out.push_str(line.trim_end());
            out.push('\n');
            line = " ".repeat(indent);
        }
        line.push_str(word);
        line.push(' ');
        filled = true;
    }
    out.push_str(line.trim_end());
    out.push('\n');
    out
}

/// Where a global option may appear for this command. `run` and `build`
/// hand everything after the verb to the program; `fmt` and `x` own the
/// options that precede the tool's own arguments.
fn global_option_note(name: &str) -> &'static str {
    match name {
        "run" | "build" => {
            "Global options (-C, -q, -v, --no-color) go before the command: every\n\
             argument after it belongs to the program.\n"
        }
        "fmt" | "x" => {
            "Global options (-C, -q, -v, --no-color) go before the command or\n\
             ahead of the tool's own arguments.\n"
        }
        _ => "Global options (-C, -q, -v, --no-color) work before or after the\ncommand.\n",
    }
}

/// Help for one command: what it is, how it is spelled, what it looks like
/// in use, its options, and only then the prose. EXAMPLES comes before
/// OPTIONS because a working line teaches the shape faster than a flag
/// list, and DETAILS gives the prose a heading to skip past.
pub fn help(spec: &Spec) -> String {
    let mut text = format!(
        "tog {} — {}\n\nUSAGE:\n  {}\n\nEXAMPLES:\n",
        spec.name, spec.summary, spec.usage
    );
    let width = spec
        .examples
        .iter()
        .map(|(command, _)| command.chars().count())
        .max()
        .unwrap_or(0);
    for (command, gloss) in spec.examples {
        text.push_str(&option_line(command, width, gloss));
    }
    text.push_str("\nOPTIONS:\n");
    let width = spec
        .options
        .iter()
        .map(|(flag, _)| flag.len())
        .max()
        .unwrap_or(0);
    for (flag, description) in spec.options {
        text.push_str(&option_line(flag, width, description));
    }
    text.push_str("\nDETAILS:\n");
    text.push_str(spec.description);
    text.push_str("\n\n");
    text.push_str(global_option_note(spec.name));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_lists_every_command_with_its_help() {
        let text = usage();
        for title in [
            "START HERE:",
            "EVERYDAY:",
            "INSPECT:",
            "MAINTAIN:",
            "OPTIONS (",
            "ENVIRONMENT:",
        ] {
            assert!(text.contains(title), "usage lacks {title}");
        }
        for spec in COMMANDS {
            assert!(
                text.contains(&format!("  {}", spec.name)),
                "usage lacks {}",
                spec.name
            );
            let help = help(spec);
            assert!(help.starts_with(&format!("tog {} — ", spec.name)));
            assert!(help.contains(spec.usage));
            // Option descriptions are wrapped into their column, so the
            // comparison is on words, not on the line breaks between them.
            let flat = words(&help);
            for (flag, description) in spec.options {
                assert!(
                    help.contains(flag) && flat.contains(&words(description)),
                    "{flag}"
                );
            }
        }
        assert!(text.contains("TOG_STORE"));
        // The lockfile table moved to 'tog help sync'; the top level says so.
        assert!(text.contains("'tog help sync'"));
        assert!(text.contains("tog <script> [<args>...]"));
        assert!(text.contains("Exit status: 0 success, 1 failure, 2 usage error"));
    }

    fn words(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Every command shows what it looks like in use, and every example is
    /// a line that can be typed: it invokes tog, either as the first word
    /// or inside a shell substitution (`eval "$(tog env)"`). An example
    /// that is not a tog command line teaches the wrong thing.
    #[test]
    fn every_command_shows_an_example_that_runs_tog() {
        for spec in COMMANDS {
            assert!(
                !spec.examples.is_empty(),
                "tog {}: no EXAMPLES block",
                spec.name
            );
            let help = help(spec);
            assert!(help.contains("EXAMPLES:"), "tog {}", spec.name);
            assert!(help.contains("DETAILS:"), "tog {}", spec.name);
            for (command, gloss) in spec.examples {
                assert!(
                    *command == "tog" || command.starts_with("tog ") || command.contains("tog "),
                    "tog {}: '{command}' does not run tog",
                    spec.name
                );
                assert!(
                    !gloss.is_empty(),
                    "tog {}: '{command}' has no gloss",
                    spec.name
                );
                assert!(help.contains(command), "tog {}: '{command}'", spec.name);
            }
        }
    }

    /// Help is read in a terminal, so every line of it fits one. This holds
    /// `tog --help` and every `tog help <command>` to `HELP_WIDTH`.
    #[test]
    fn every_help_line_fits_eighty_columns() {
        let screens = std::iter::once(("tog --help".to_string(), usage())).chain(
            COMMANDS
                .iter()
                .map(|spec| (format!("tog help {}", spec.name), help(spec))),
        );
        let mut over = Vec::new();
        for (screen, text) in screens {
            for line in text.lines() {
                let columns = line.chars().count();
                if columns > HELP_WIDTH {
                    over.push(format!("{screen}: {columns} columns: {line}"));
                }
            }
        }
        assert!(
            over.is_empty(),
            "help lines over 80 columns:\n{}",
            over.join("\n")
        );
    }

    /// The extra spellings the parser accepts but the option table used to
    /// hide are on the help screen, and no USAGE line omits the primary long
    /// spelling of an option its own OPTIONS block lists (#100). The second
    /// half checks one spelling per option on purpose: `tog x` lists
    /// `--python` and `--node` in OPTIONS but keeps its usage line to
    /// `[--py | --npm]` to stay inside eighty columns.
    #[test]
    fn help_lists_the_extra_spellings_and_usage_matches_options() {
        for (command, spellings) in [
            ("add", &["-D", "--dev"][..]),
            ("remove", &["-D", "--dev"]),
            ("x", &["--py", "--python", "--npm", "--node"]),
        ] {
            let text = help(spec(command).expect(command));
            for spelling in spellings {
                assert!(
                    text.contains(spelling),
                    "tog help {command} hides '{spelling}'"
                );
            }
        }
        // `remove --dev` is real, so the usage line has to show it.
        assert!(spec("remove").unwrap().usage.contains("[--dev]"));
        for command in COMMANDS {
            let usage = command.usage;
            for (flag, _) in command.options {
                let long = super::super::parse::option_spellings(flag)
                    .find(|spelling| spelling.starts_with("--"));
                let Some(long) = long else { continue };
                // `-h` is never spelled in a usage line, and a command that
                // re-lists a global flag (`ls -v`) documents it in OPTIONS
                // only, because the global block already covers where it goes.
                if long == "--help" || super::super::parse::GLOBAL_FLAGS.contains(&long) {
                    continue;
                }
                assert!(
                    usage.contains(long),
                    "tog {} usage omits {long}: {usage}",
                    command.name
                );
            }
        }
    }

    /// The command list is the first screen a newcomer reads, so no summary
    /// line explains tog with tog's own words. The internal vocabulary
    /// stays in the long descriptions, where there is room to define it; a
    /// summary says install, set up, link, or environment instead. No
    /// allow-list: every summary passes as written, so a new command's
    /// has to as well.
    #[test]
    fn no_summary_explains_tog_in_togs_own_vocabulary() {
        const JARGON: &[&str] = &["realiz", "project"];
        for spec in COMMANDS {
            let summary = spec.summary.to_ascii_lowercase();
            for word in JARGON {
                assert!(
                    !summary.contains(word),
                    "tog {}: the summary says '{word}': {}",
                    spec.name,
                    spec.summary
                );
            }
        }
    }

    /// The everyday verbs come first in their group, and the aliases are
    /// on the screen that lists the commands.
    #[test]
    fn the_command_list_leads_with_the_everyday_verbs() {
        let text = usage();
        let position = |needle: &str| text.find(needle).expect(needle);
        assert!(position("  sync") < position("  fmt"));
        assert!(position("  doctor") < position("  audit"));
        assert!(position("EVERYDAY:") < position("INSPECT:"));
        // The four commands to start with come before the full table, and
        // the reference material (options, environment) after it.
        assert!(position("START HERE:") < position("EVERYDAY:"));
        assert!(position("EVERYDAY:") < position("OPTIONS ("));
        assert!(position("OPTIONS (") < position("ENVIRONMENT:"));
        for alias in SYNC_ALIASES {
            assert!(text.contains(*alias), "the command list hides '{alias}'");
        }
    }
}

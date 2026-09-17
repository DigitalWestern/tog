//! The command table: every command's usage, options, and help text.

use super::{Group, Spec, VERSION};

const HELP_OPTION: (&str, &str) = ("-h, --help", "print this help");
const JSON_OPTION: (&str, &str) = ("--json", "machine-readable output on stdout");

/// What `blanket ls` accepts as a filter word. `ls` lists closures, not
/// ecosystems: besides the seven ecosystems it prints a row for the
/// toolchain-only `rustfmt` closure `blanket fmt` writes, and every name
/// `ls` can print must be a name it accepts. This is the `ls` vocabulary
/// only; it never selects an ecosystem for sync, add, or build.
pub const LS_WORDS: &[&str] = &[
    "python", "node", "cargo", "go", "ruby", "elixir", "dotnet", "rustfmt",
];
pub const BUILD_WORDS: &[&str] = &["cargo", "go", "elixir", "dotnet"];
pub const SHELL_WORDS: &[&str] = &["bash", "zsh", "fish"];
pub const SYNC_ALIASES: &[&str] = &["install", "i"];

pub const COMMANDS: &[Spec] = &[
    Spec {
        name: "sync",
        group: Group::Everyday,
        summary: "realize and project the environment(s) from the project's inputs",
        usage: "blanket sync [--fresh] [--strict]        (alias: install, i)",
        description: "\
Discovers every ecosystem present in the current directory (see PROJECT
INPUTS in 'blanket --help'), realizes each locked plan into the immutable
store, and projects it into the project (.venv, node_modules, .blanket/...).
A bare 'blanket' inside a project does the same. A found manifest with no
dependencies syncs an interpreter-only environment.
Policy exceptions (unattested inputs, failed install scripts, ...) are
recorded in .blanket/closures/*.json and summarized at the end; --strict, a
BLANKET_STRICT=1 environment, or a .blanket/policy.toml deny list refuses
them instead.",
        options: &[
            ("--fresh", "rebuild the projection, dropping project-local caches"),
            ("--strict", "refuse every policy exception (same as BLANKET_STRICT=1)"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "fmt",
        group: Group::Everyday,
        summary: "format the Rust project with the pinned rustfmt",
        usage: "blanket fmt [--check] [--eco <ecosystem>] [--] [<args>...]",
        description: "\
Runs the pinned rustfmt/cargo-fmt for a Rust workspace. The workspace is
discovered with the store Cargo tool and Cargo metadata is read with
--no-deps, so a project that has never been synced needs no Cargo.lock,
dependency resolution, or vendor object. --check returns rustfmt's status.
A package.json script named fmt takes precedence and is run as
'blanket run fmt'. In a polyglot directory use --eco rust: an explicit --eco
selects the ecosystem, so it formats Rust instead of running that script.
Other ecosystems are not implemented yet.",
        options: &[
            ("--check", "check formatting without editing files"),
            ("--eco <ecosystem>", "select the ecosystem (Rust: rust)"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "add",
        group: Group::Everyday,
        summary: "add a dependency, re-lock, sync",
        usage: "blanket add <package>... [--dev] [--no-sync]",
        description: "\
Adds each package to the project's manifest with the ecosystem's own pinned
tool (uv, the store npm, pinned pnpm, cargo, go, bundler), re-locks, and
syncs. Where no pinned tool can make the edit (Poetry, PDM, Yarn classic,
setup.py, Elixir, .NET) blanket refuses and prints the exact line and file
instead.

Which ecosystem: an explicit prefix (py:requests, npm:react, cargo:serde,
go:github.com/x/y, gem:rails, hex:jason, nuget:Foo.Bar) or the name's shape
(@scope/name, github.com/..., Foo.Bar) decides it; otherwise the nearest
manifest walking up from here; if that directory holds several, the
registries are asked and a name known to exactly one wins; if several know
it you are asked at the terminal. Blanket never guesses from the bare name.
Constraints pass through to the tool: 'requests>=2', 'react@18',
'serde@1', 'rails@~> 7.1'.",
        options: &[
            ("--dev", "a development dependency (uv --dev, npm --save-dev, cargo --dev, bundler group development)"),
            ("--no-sync", "stop after the manifest and lock edit; review, then run 'blanket'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "remove",
        group: Group::Everyday,
        summary: "remove a dependency, re-lock, sync",
        usage: "blanket remove <package>... [--no-sync]",
        description: "\
The inverse of add, through the same pinned tools with the same ecosystem
choice. For a plain requirements file blanket deletes the line itself.",
        options: &[
            ("--dev", "remove from development dependencies (uv --dev, cargo --dev)"),
            ("--no-sync", "stop after the manifest and lock edit; review, then run 'blanket'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "update",
        group: Group::Everyday,
        summary: "update dependencies within the manifest's constraints, sync",
        usage: "blanket update [<package>...] [--no-sync]",
        description: "\
Re-locks everything (or only the named packages) to the newest versions the
manifest allows: uv lock --upgrade, npm update, cargo update, go get -u,
bundle update, mix deps.update, and pnpm update --lockfile-only. Poetry, PDM,
Yarn classic, and .NET projects are told which command to run with their own
tool.",
        options: &[
            ("--no-sync", "stop after the lock edit; review, then run 'blanket'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "run",
        group: Group::Everyday,
        summary: "run a command or package.json script inside the projected env(s)",
        usage: "blanket run [--] <command> [<args>...]",
        description: "\
Executes <command> with PATH and the ecosystem variables of the nearest
projected root (the closest ancestor with .blanket/closures/). When the
project has a package.json and <command> names one of its scripts, the
script runs (pre/name/post, npm environment, exit code passed through) and
wins over a same-named executable on PATH; 'blanket <script>' is the short
form when the script name is not a blanket command. Everything after
<command> is passed through unchanged.",
        options: &[HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "x",
        group: Group::Everyday,
        summary: "run a tool without adding it to the project (like npx / uvx)",
        usage: "blanket x [--py | --npm] [--from <package>] <tool>[@<version>] [<args>...]\n  blanket x --clean [--py | --npm] [--from <package>] [<tool>[@<version>]]",
        description: "\
Resolves the package with the store uv or npm, realizes it as an ordinary
store environment (a store hit from the second run on), and executes the
tool with every argument passed through. Which registry: 'py:' or 'npm:'
on the tool, --py / --npm, or the current project's ecosystem (Python
first, then Node); outside a project the prefix is required. --from names
the package when the executable is called something else
('blanket x --from httpie http'). Environments live under ~/.blanket/x/
and are gc roots like any project. `--clean` removes every cached x
environment, or only the selected tool's environments; store objects stay
until the next `blanket gc`. A running tool is left in place and reported as
in use; retry after it exits.",
        options: &[
            ("--clean", "remove cached x environments instead of running a tool"),
            ("--py", "resolve from PyPI"),
            ("--npm", "resolve from npm"),
            ("--from <package>", "the package that provides <tool>"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "build",
        group: Group::Everyday,
        summary: "sandboxed, network-denied build (cargo | go | elixir | dotnet)",
        usage: "blanket build [<ecosystem>] [--] [<tool args>...]",
        description: "\
Runs the ecosystem's build tool inside the network-denied sandbox with the
pinned toolchain and the realized dependency objects. The ecosystem is
inferred when exactly one build-capable project (Cargo.toml, go.mod,
mix.exs, *.csproj) is found from here upward; name it when several are.
Every argument after the ecosystem is handed to the tool unchanged, so
'blanket build --release' works; use '--' if the first tool argument is
'-h' or '--help'.",
        options: &[HELP_OPTION],
        words: BUILD_WORDS,
    },
    Spec {
        name: "status",
        group: Group::Inspect,
        summary: "is the projection current with the manifest and the lock?",
        usage: "blanket status [--json]",
        description: "\
For every ecosystem found here: 'synced' when the last sync's inputs are
byte-identical to the files on disk and the projection is in place;
otherwise which file changed, that the projection is missing, or that the
closure was synced on another platform. Offline and read-only. Exit status
0 only when everything is synced, so CI can use it as a 'did you commit the
lock' gate.",
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "audit",
        group: Group::Inspect,
        summary: "would the synced closures pass a policy? (CI admission gate)",
        usage: "blanket audit [--policy <file>] [--json]",
        description: "\
Reads the exceptions every sync recorded in .blanket/closures/*.json and
judges them against the policy chain (BLANKET_POLICY or
~/.blanket/policy.toml, every ancestor's .blanket/policy.toml, BLANKET_STRICT)
unioned with --policy <file>. Union only tightens: the file can add denials
but never loosen what the machine or project policy says. Per closure:
clean, denied (each denied exception's kind, subject, and detail, plus a
count of permitted ones by kind), stale (its inputs changed since the sync,
the same check 'blanket status' makes), or unchecked (the closure predates
input or exception recording). The rustfmt closure 'blanket fmt' writes
is stale when this binary would record that run differently now (another
rustfmt pin, or other toolchain components); rerun 'blanket fmt'. Only clean
passes: an audit of a stale or unchecked record proves nothing. Offline, read-only, no store access, no
sandbox needed. Exit status 0 when every closure is clean, 1 otherwise.
A company deny list to start from ships as docs/human/policy-company.toml.",
        options: &[
            ("--policy <file>", "also deny what this policy file denies"),
            JSON_OPTION,
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "ls",
        group: Group::Inspect,
        summary: "list what is installed, per ecosystem",
        usage: "blanket ls [<ecosystem>] [--json]",
        description: "\
Name and version of every package in each synced closure, with the
toolchain each runs on; -v adds the artifact and store object. Read from
.blanket/closures/*.json, no store access. Ecosystems: python, node,
cargo, go, ruby, elixir, dotnet; plus rustfmt, the toolchain-only closure
'blanket fmt' writes.",
        options: &[JSON_OPTION, HELP_OPTION],
        words: LS_WORDS,
    },
    Spec {
        name: "plan",
        group: Group::Inspect,
        summary: "print the locked plan(s) as JSON",
        usage: "blanket plan",
        description: "\
Prints one JSON document per ecosystem found here, exactly what 'blanket
sync' would realize. Planning may resolve missing lockfiles with the store's
own uv/npm/cargo and cache the result under .blanket/.",
        options: &[HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "sbom",
        group: Group::Inspect,
        summary: "CycloneDX 1.5 SBOM of the synced closures",
        usage: "blanket sbom [--output <file>]",
        description: "\
Emits a CycloneDX 1.5 document covering every ecosystem closure recorded by
the last sync: pinned hashes, purls, and toolchain store ids. Writes to
stdout unless --output is given.",
        options: &[
            ("-o, --output <file>", "write the document to <file> instead of stdout"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "doctor",
        group: Group::Inspect,
        summary: "check host prerequisites, the sandbox, and the store",
        usage: "blanket doctor [--json]",
        description: "\
The first-five-minutes command. Checks the platform, the store (path,
writable, free space), the build sandbox (bubblewrap and user namespaces on
Linux, sandbox-exec on macOS), the host C toolchain native builds need, the
toolchains already realized, and the project in the current directory. Each
line is ok, warn, or fail with the fix; exit status 1 on any fail.",
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "gc",
        group: Group::Maintain,
        summary: "collect unreferenced store objects and cached artifacts",
        usage: "blanket gc [--dry-run] [--keep-days <n>] [--project] [--collect-legacy] [--migrate-metadata] [--register <dir>...] [--forget <key>...]",
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
while another Blanket job is using this store, and any object whose
recorded evidence cannot be certified stops the sweep rather than being
guessed at. Usable on a copied store from any host.",
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
        usage: "blanket store <path | roots>",
        description: "\
  path    print the store root (~/.blanket/store unless BLANKET_STORE is set)
  roots   list every registered project root as '<key>  <path>'",
        options: &[HELP_OPTION],
        words: &["path", "roots"],
    },
    Spec {
        name: "completions",
        group: Group::Maintain,
        summary: "print a shell completion script (bash | zsh | fish)",
        usage: "blanket completions <bash | zsh | fish>",
        description: "\
Generated from the same command table as this help, so it cannot drift.
Install:
  bash   blanket completions bash > ~/.local/share/bash-completion/completions/blanket
  zsh    blanket completions zsh  > \"${fpath[1]}/_blanket\"   (then: compinit)
  fish   blanket completions fish > ~/.config/fish/completions/blanket.fish
Package.json script names complete after 'blanket run' and as the first
word when a package.json is in the current directory.",
        options: &[HELP_OPTION],
        words: SHELL_WORDS,
    },
];

const PROJECT_INPUTS: &str = "\
PROJECT INPUTS (any combination; each found ecosystem is synced):
  requirements.txt, pyproject.toml, setup.cfg/setup.py, or requirements/*
                          Python deps; ranged inputs are locked via the store
                          uv into requirements.lock.txt (hash-pinned), while
                          Poetry/uv lockfiles are imported when compatible
  .python-version         optional; X.Y selects the newest pinned patch and
                          X.Y.Z must be an exact pinned build; otherwise
                          selected from project constraints (default: CPython 3.12.14)
  package-lock.json       npm lockfile v2/v3
  pnpm-lock.yaml          pnpm lockfile v9 (v6 importer shape also accepted)
  yarn.lock               Yarn classic v1 lockfile
  Cargo.toml/Cargo.lock   Rust deps; a missing Cargo.lock is generated by
                          the store Cargo
  go.mod/go.sum           Go deps; closure computed by the store Go toolchain
  Gemfile/Gemfile.lock    Ruby gems; a missing lock is resolved by store bundler
  mix.exs/mix.lock        Elixir hex deps; a missing lock is resolved by store mix
  *.csproj + packages.lock.json
                          .NET NuGet deps (the lock is mandatory)
";

const ENVIRONMENT: &str = "\
ENVIRONMENT:
  BLANKET_STORE           store root (default ~/.blanket/store)
  BLANKET_STRICT=1        refuse every policy exception, like --strict
  BLANKET_POLICY          policy file used instead of ~/.blanket/policy.toml
  NO_COLOR                plain output, like --no-color
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

const GLOBAL_OPTIONS: &str = "\
OPTIONS:
  -C, --directory <dir>  run as if blanket had been started in <dir>
  -q, --quiet            no narration: only errors and results on stdout
  -v, --verbose          show every decision and subprocess command line
      --no-color         plain output (also: NO_COLOR, or a non-tty stderr)
  -h, --help             print help ('blanket help <command>' for one command)
  -V, --version          print the version
";

/// Top-level help: the command list by group, global options, inputs.
pub fn usage() -> String {
    let mut text = format!(
        "blanket {VERSION} — one command for every package manager\n\n\
         USAGE:\n  \
         blanket [<options>] <command> [<args>...]\n  \
         blanket                      in a project: the same as 'blanket sync'\n  \
         blanket <script> [<args>...] run a package.json script (like 'npm run')\n"
    );
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
    text.push_str(PROJECT_INPUTS);
    text.push('\n');
    text.push_str(ENVIRONMENT);
    text.push_str(
        "\nExit status: 0 success, 1 failure, 2 usage error; 'run', 'x' and 'fmt'\n\
         pass the program's status through.\n",
    );
    text
}

/// Help for one command.
pub fn help(spec: &Spec) -> String {
    let mut text = format!(
        "blanket {} — {}\n\nUSAGE:\n  {}\n\nOPTIONS:\n",
        spec.name, spec.summary, spec.usage
    );
    let width = spec
        .options
        .iter()
        .map(|(flag, _)| flag.len())
        .max()
        .unwrap_or(0);
    for (flag, description) in spec.options {
        text.push_str(&format!("  {flag:width$}  {description}\n"));
    }
    text.push('\n');
    text.push_str(spec.description);
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_lists_every_command_with_its_help() {
        let text = usage();
        for title in [
            "EVERYDAY:",
            "INSPECT:",
            "MAINTAIN:",
            "OPTIONS:",
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
            assert!(help.starts_with(&format!("blanket {} — ", spec.name)));
            assert!(help.contains(spec.usage));
            for (flag, description) in spec.options {
                assert!(help.contains(flag) && help.contains(description), "{flag}");
            }
        }
        assert!(text.contains("BLANKET_STORE"));
        assert!(text.contains("requirements.txt"));
        assert!(text.contains("blanket <script> [<args>...]"));
        assert!(text.contains("Exit status: 0 success, 1 failure, 2 usage error"));
    }
}

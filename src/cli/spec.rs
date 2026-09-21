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
pub const SYNC_ALIASES: &[&str] = &["install", "i"];

pub const COMMANDS: &[Spec] = &[
    Spec {
        name: "sync",
        group: Group::Everyday,
        summary: "realize and project the environment(s); aliases: install, i",
        usage: "tog sync [--fresh] [--strict]        (aliases: install, i)",
        description: "\
Discovers every ecosystem present in the current directory, realizes each
locked plan into the immutable store, and projects it into the project
(.venv, node_modules, .tog/...). A bare 'tog' inside a project does the
same. A found manifest with no dependencies syncs an interpreter-only
environment. It takes no package name: adding a dependency is
'tog add <package>'.

PROJECT INPUTS (any combination; each ecosystem found here is synced):
  python   requirements.txt, pyproject.toml, setup.cfg/setup.py,
           requirements/*; ranged inputs are locked into a hash-pinned
           requirements.lock.txt, and a Poetry/uv lockfile is imported
           when compatible. .python-version selects the interpreter: X.Y
           takes the newest pinned patch, X.Y.Z must be an exact pinned
           build (default: CPython 3.12.14).
  node     package-lock.json (v2/v3), pnpm-lock.yaml (v9, v6 importer
           shape also accepted), yarn.lock (Yarn classic v1)
  cargo    Cargo.toml, Cargo.lock; a missing lock is written by the
           store Cargo
  go       go.mod, go.sum; the closure is computed by the store Go
  ruby     Gemfile, Gemfile.lock; a missing lock is resolved by store
           bundler
  elixir   mix.exs, mix.lock; a missing lock is resolved by store mix
  dotnet   *.csproj with packages.lock.json (the lock is mandatory)

Policy exceptions (unattested inputs, failed install scripts, ...) are
recorded in .tog/closures/*.json and summarized at the end; --strict, a
TOG_STRICT=1 environment, or a .tog/policy.toml deny list refuses
them instead.",
        options: &[
            ("--fresh", "rebuild the projection, dropping project-local caches"),
            ("--strict", "refuse every policy exception (same as TOG_STRICT=1)"),
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
        options: &[
            ("--dev", "a development dependency (uv --dev, npm --save-dev, cargo --dev, bundler group development)"),
            ("--no-sync", "stop after the manifest and lock edit; review, then run 'tog'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "remove",
        group: Group::Everyday,
        summary: "remove a dependency, re-lock, sync",
        usage: "tog remove <package>... [--no-sync]",
        description: "\
The inverse of add, through the same pinned tools with the same ecosystem
choice. For a plain requirements file tog deletes the line itself.",
        options: &[
            ("--dev", "remove from development dependencies (uv --dev, cargo --dev)"),
            ("--no-sync", "stop after the manifest and lock edit; review, then run 'tog'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "update",
        group: Group::Everyday,
        summary: "update dependencies within the manifest's constraints, sync",
        usage: "tog update [<package>...] [--no-sync]",
        description: "\
Re-locks everything (or only the named packages) to the newest versions the
manifest allows: uv lock --upgrade, npm update, cargo update, go get -u,
bundle update, mix deps.update, and pnpm update --lockfile-only. Poetry, PDM,
Yarn classic, and .NET projects are told which command to run with their own
tool.",
        options: &[
            ("--no-sync", "stop after the lock edit; review, then run 'tog'"),
            HELP_OPTION,
        ],
        words: &[],
    },
    Spec {
        name: "run",
        group: Group::Everyday,
        summary: "run a command or package.json script inside the projected env(s)",
        usage: "tog run [--] <command> [<args>...]",
        description: "\
Executes <command> with PATH and the ecosystem variables of the nearest
projected root (the closest ancestor with .tog/closures/). When the
project has a package.json and <command> names one of its scripts, the
script runs (pre/name/post, npm environment, exit code passed through) and
wins over a same-named executable on PATH; 'tog <script>' is the short
form when the script name is not a tog command. Everything after
<command> is passed through unchanged.",
        options: &[HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "x",
        group: Group::Everyday,
        summary: "run a tool without adding it to the project (like npx / uvx)",
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
        usage: "tog build [<ecosystem>] [--] [<tool args>...]",
        description: "\
Runs the ecosystem's build tool inside the network-denied sandbox with the
pinned toolchain and the realized dependency objects. The ecosystem is
inferred when exactly one build-capable project (Cargo.toml, go.mod,
mix.exs, *.csproj) is found from here upward; name it when several are.
Every argument after the ecosystem is handed to the tool unchanged, so
'tog build --release' works; use '--' if the first tool argument is
'-h' or '--help'.",
        options: &[HELP_OPTION],
        words: BUILD_WORDS,
    },
    Spec {
        name: "fmt",
        group: Group::Everyday,
        summary: "format the Rust project with the pinned rustfmt",
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
The first-five-minutes command. Checks the platform, the store (path,
writable, free space), the build sandbox (bubblewrap and user namespaces on
Linux, sandbox-exec on macOS), the host C toolchain native builds need, the
toolchains already realized, and the project in the current directory. Each
line is ok, warn, or fail with the fix; exit status 1 on any fail.",
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "status",
        group: Group::Inspect,
        summary: "is the projection current with the manifest and the lock?",
        usage: "tog status [--json]",
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
        summary: "would the synced closures pass a policy? (CI admission gate)",
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
        options: &[JSON_OPTION, HELP_OPTION],
        words: &[],
    },
    Spec {
        name: "sbom",
        group: Group::Inspect,
        summary: "CycloneDX 1.5 SBOM of the synced closures",
        usage: "tog sbom [--output <file>]",
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
        description: "\
  path    print the store root (~/.tog/store unless TOG_STORE is set)
  roots   list every registered project root as '<key>  <path>'",
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
        options: &[HELP_OPTION],
        words: SHELL_WORDS,
    },
];

const PROJECT_INPUTS: &str = "\
PROJECT INPUTS: every ecosystem whose manifest is found here is synced —
requirements.txt/pyproject.toml/setup.py, package-lock.json/pnpm-lock.yaml/
yarn.lock, Cargo.toml, go.mod, Gemfile, mix.exs, *.csproj. The full table,
with what each one locks, is in 'tog help sync'.
";

const ENVIRONMENT: &str = "\
ENVIRONMENT:
  TOG_STORE           store root (default ~/.tog/store)
  TOG_STRICT=1        refuse every policy exception, like --strict
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

const GLOBAL_OPTIONS: &str = "\
OPTIONS:
  -C, --directory <dir>  run as if tog had been started in <dir>
  -q, --quiet            no narration: only errors and results on stdout
  -v, --verbose          show every decision and subprocess command line
      --no-color         plain output (also: NO_COLOR, or a non-tty stderr)
  -h, --help             print help ('tog help <command>' for one command)
  -V, --version          print the version
";

/// Top-level help: the command list by group, global options, inputs.
pub fn usage() -> String {
    let mut text = format!(
        "tog {VERSION} — one command for every package manager\n\n\
         USAGE:\n  \
         tog [<options>] <command> [<args>...]\n  \
         tog                      in a project: the same as 'tog sync'\n  \
         tog <script> [<args>...] run a package.json script (like 'npm run')\n"
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
    text.push_str(
        "  Any of these may be given before or after the command, except\n  \
         where the rest of the line belongs to a program ('run', 'build')\n  \
         or a tool ('fmt', 'x').\n",
    );
    text.push('\n');
    text.push_str(ENVIRONMENT);
    text.push_str(
        "\nExit status: 0 success, 1 failure, 2 usage error; 'run', 'x' and 'fmt'\n\
         pass the program's status through.\n\n",
    );
    text.push_str(PROJECT_INPUTS);
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

/// Help for one command.
pub fn help(spec: &Spec) -> String {
    let mut text = format!(
        "tog {} — {}\n\nUSAGE:\n  {}\n\nOPTIONS:\n",
        spec.name, spec.summary, spec.usage
    );
    let width = spec
        .options
        .iter()
        .map(|(flag, _)| flag.len())
        .max()
        .unwrap_or(0);
    for (flag, description) in spec.options {
        text.push_str(&option_line(flag, width, description));
    }
    text.push('\n');
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
        assert!(text.contains("requirements.txt"));
        assert!(text.contains("tog <script> [<args>...]"));
        assert!(text.contains("Exit status: 0 success, 1 failure, 2 usage error"));
    }

    fn words(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
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

    /// The everyday verbs come first in their group, and the aliases are
    /// on the screen that lists the commands.
    #[test]
    fn the_command_list_leads_with_the_everyday_verbs() {
        let text = usage();
        let position = |needle: &str| text.find(needle).expect(needle);
        assert!(position("  sync") < position("  fmt"));
        assert!(position("  doctor") < position("  audit"));
        assert!(position("EVERYDAY:") < position("INSPECT:"));
        // The lockfile table is reference material, not the first thing to
        // read; the verbs and the options come before it.
        assert!(position("OPTIONS:") < position("PROJECT INPUTS"));
        assert!(position("ENVIRONMENT:") < position("PROJECT INPUTS"));
        for alias in SYNC_ALIASES {
            assert!(text.contains(*alias), "the command list hides '{alias}'");
        }
    }
}

//! The command surface: one grammar for every `blanket` invocation.
//!
//! This module is pure — it never touches the store, the filesystem, or the
//! host platform — so every shape of argv is unit-testable and `main` is a
//! thin dispatcher. Rules the grammar enforces, none of them silently:
//!
//! - every option is validated: an unknown flag or stray positional is a
//!   usage error (exit 2) with a "did you mean" suggestion when one is close;
//! - `blanket help [<command>]`, `--help`/`-h`, `--version`/`-V` work at the
//!   top level and `-h`/`--help` inside every command;
//! - `run` and `build` pass their arguments through to the program untouched
//!   (only a leading `-h`/`--help` is blanket's; `--` forces pass-through);
//! - `-C <dir>` runs the command as if started in `<dir>`; `-q`, `-v` and
//!   `--no-color` set the output conventions (see `ui`);
//! - a bare `blanket` and an unknown first word are *not* decided here: the
//!   dispatcher turns them into `sync` inside a project and into a
//!   package.json script run when one matches (CLI.md 2.1, 2.2).
//!
//! Exit status contract: 0 success, 1 the command failed, 2 usage error.

use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Sync {
        fresh: bool,
        strict: bool,
    },
    Fmt {
        check: bool,
        ecosystem: Option<String>,
        args: Vec<String>,
    },
    Plan,
    /// Everything after `build` (ecosystem name and tool arguments); the
    /// ecosystem is inferred by the dispatcher from the project layout.
    Build {
        args: Vec<String>,
    },
    /// The program (or package.json script) and its arguments.
    Run {
        command: Vec<String>,
    },
    Sbom {
        output: Option<PathBuf>,
    },
    Add {
        specs: Vec<String>,
        dev: bool,
        no_sync: bool,
    },
    Remove {
        names: Vec<String>,
        dev: bool,
        no_sync: bool,
    },
    Update {
        names: Vec<String>,
        no_sync: bool,
    },
    /// `x [--py|--npm] [--from <package>] <tool>[@<version>] [<args>...]`.
    X {
        ecosystem: Option<String>,
        from: Option<String>,
        tool: String,
        args: Vec<String>,
    },
    /// Remove cached x environments. With no tool, removes every x
    /// environment; otherwise the tool's environments only.
    XClean {
        ecosystem: Option<String>,
        from: Option<String>,
        tool: Option<String>,
    },
    Status {
        json: bool,
    },
    Ls {
        ecosystem: Option<String>,
        json: bool,
    },
    Doctor {
        json: bool,
    },
    Gc(GcArgs),
    StorePath,
    StoreRoots,
    Completions {
        shell: Shell,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GcArgs {
    pub dry_run: bool,
    pub keep_days: Option<u64>,
    pub project: bool,
    pub collect_legacy: bool,
    pub register: Vec<PathBuf>,
}

/// Options accepted before the command; they apply to every command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options {
    /// `-C <dir>`: change into this directory before running the command.
    pub directory: Option<PathBuf>,
    /// `-q`: no narration; only errors and the command's stdout result.
    pub quiet: bool,
    /// `-v`: every decision and every subprocess command line.
    pub verbose: bool,
    /// `--no-color`: never emit ANSI color (NO_COLOR and a non-tty stderr
    /// have the same effect).
    pub no_color: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub options: Options,
    pub command: Command,
}

/// What `main` does with argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Run(Invocation),
    /// Print to stdout and exit 0 (help, version).
    Print(String),
    /// `blanket` with no command: `sync` inside a project, usage outside.
    Implicit(Options),
    /// A first word that is not a command: a package.json script if one
    /// matches, otherwise the usage error in `message`.
    Script {
        options: Options,
        name: String,
        args: Vec<String>,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError {
    pub message: String,
    /// The command whose help is relevant (`None` → top-level usage).
    pub command: Option<&'static str>,
}

impl UsageError {
    fn new(message: impl Into<String>, command: Option<&'static str>) -> Self {
        UsageError {
            message: message.into(),
            command,
        }
    }

    /// The text `main` writes to stderr before exiting with `EXIT_USAGE`.
    pub fn render(&self) -> String {
        render_usage_error(&self.message, self.command)
    }
}

pub fn render_usage_error(message: &str, command: Option<&str>) -> String {
    let hint = match command {
        Some(name) => format!("Run 'blanket help {name}' for usage."),
        None => "Run 'blanket --help' for usage.".to_string(),
    };
    format!("blanket: error: {message}\n{hint}\n")
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.render().trim_end())
    }
}

impl std::error::Error for UsageError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Everyday,
    Inspect,
    Maintain,
}

/// Static description of one command: drives parsing suggestions, the help
/// text, and shell completions, so none of them can disagree.
pub struct Spec {
    pub name: &'static str,
    pub group: Group,
    pub summary: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
    /// `(flag spelling, description)`; each comma-separated spelling's
    /// first token (before a space or `=`) is what suggestions match.
    pub options: &'static [(&'static str, &'static str)],
    /// Fixed positional words, for completion (`store path|roots`).
    pub words: &'static [&'static str],
}

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
tool (uv, the store npm, cargo, go, bundler), re-locks, and syncs. Where no
pinned tool can make the edit (Poetry, PDM, pnpm, yarn, setup.py, Elixir,
.NET) blanket refuses and prints the exact line and file instead.

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
bundle update, mix deps.update. Poetry, PDM, pnpm, yarn and .NET projects
are told which command to run with their own tool.",
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
        usage: "blanket gc [--dry-run] [--keep-days <n>] [--project] [--collect-legacy] [--register <dir>...]",
        description: "\
Follows every registered project closure, removes store objects nothing
references, drops cached artifacts older than the retention window, and
cleans stale staging directories. Objects touched in the last ten minutes
are always kept so a concurrent sync cannot lose one. Ordinary gc never
deletes inside project projections; --project collects old unused forests
and backups. Usable on a copied store from any host.",
        options: &[
            ("--dry-run", "report what would be removed without removing it"),
            ("--keep-days <n>", "retain cached artifacts used within <n> days"),
            ("--project", "also collect old unused project forests and backups"),
            (
                "--collect-legacy",
                "also collect objects written before the roots registry existed",
            ),
            (
                "--register <dir>...",
                "register project roots before collecting (pre-registry projects)",
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
  roots   list the project directories registered with this store",
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

const VERSION_WORDS: [&str; 3] = ["-V", "--version", "version"];
const HELP_WORDS: [&str; 3] = ["-h", "--help", "help"];

fn version_text() -> String {
    format!("blanket {VERSION}\n")
}

pub fn parse(args: &[String]) -> Result<Parsed, UsageError> {
    let mut options = Options::default();
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if HELP_WORDS.contains(&arg) {
            return help_topic(args.get(index + 1).map(String::as_str)).map(Parsed::Print);
        }
        if VERSION_WORDS.contains(&arg) {
            return Ok(Parsed::Print(version_text()));
        }
        match arg {
            "-C" | "--directory" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new(format!("{arg} needs a directory"), None))?;
                options.directory = Some(PathBuf::from(value));
                index += 2;
            }
            _ if arg.starts_with("--directory=") => {
                options.directory = Some(non_empty(
                    &arg["--directory=".len()..],
                    "--directory",
                    None,
                )?);
                index += 1;
            }
            _ if arg.starts_with("-C") => {
                options.directory = Some(PathBuf::from(&arg[2..]));
                index += 1;
            }
            "-q" | "--quiet" => {
                options.quiet = true;
                index += 1;
            }
            "-v" | "--verbose" => {
                options.verbose = true;
                index += 1;
            }
            "--no-color" => {
                options.no_color = true;
                index += 1;
            }
            _ if arg.starts_with('-') => {
                let known = [
                    "--directory",
                    "--quiet",
                    "--verbose",
                    "--no-color",
                    "--help",
                    "--version",
                ];
                return Err(UsageError::new(
                    with_suggestion(
                        format!("unknown option '{arg}'"),
                        flag_name(arg),
                        known.iter().copied(),
                    ),
                    None,
                ));
            }
            _ => break,
        }
    }
    let Some(word) = args.get(index).map(String::as_str) else {
        return Ok(Parsed::Implicit(options));
    };
    let rest = &args[index + 1..];
    let name = canonical_name(word);
    let command = match name {
        "sync" => parse_sync(rest)?,
        "fmt" => parse_fmt(rest)?,
        "plan" => parse_plan(rest)?,
        "build" => parse_passthrough(rest, "build")?,
        "run" => parse_passthrough(rest, "run")?,
        "sbom" => parse_sbom(rest)?,
        "add" | "remove" | "update" => parse_deps(rest, name)?,
        "x" => parse_x(rest)?,
        "status" => parse_json_only(rest, "status")?.map(|json| Command::Status { json }),
        "ls" => parse_ls(rest)?,
        "doctor" => parse_json_only(rest, "doctor")?.map(|json| Command::Doctor { json }),
        "gc" => parse_gc(rest)?,
        "store" => parse_store(rest)?,
        "completions" => parse_completions(rest)?,
        other => {
            return Ok(Parsed::Script {
                options,
                name: other.to_string(),
                args: rest.to_vec(),
                message: with_suggestion(
                    format!("unknown command '{other}'"),
                    other,
                    COMMANDS
                        .iter()
                        .map(|spec| spec.name)
                        .chain(["help", "version"]),
                ),
            });
        }
    };
    let command = match command {
        Some(command) => command,
        None => return Ok(Parsed::Print(help(spec(name).expect("known command")))),
    };
    Ok(Parsed::Run(Invocation { options, command }))
}

fn help_topic(topic: Option<&str>) -> Result<String, UsageError> {
    match topic {
        None => Ok(usage()),
        Some(name) if HELP_WORDS.contains(&name) => Ok(usage()),
        Some(name) if VERSION_WORDS.contains(&name) => Ok(version_text()),
        Some(name) => spec(name).map(help).ok_or_else(|| {
            UsageError::new(
                with_suggestion(
                    format!("no help for '{name}': not a blanket command"),
                    name,
                    COMMANDS.iter().map(|spec| spec.name),
                ),
                None,
            )
        }),
    }
}

/// `Ok(None)` means the command's help was requested.
fn parse_sync(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut fresh = false;
    let mut strict = false;
    for arg in args {
        match arg.as_str() {
            "--fresh" => fresh = true,
            "--strict" => strict = true,
            "-h" | "--help" => return Ok(None),
            other => return Err(reject("sync", other)),
        }
    }
    Ok(Some(Command::Sync { fresh, strict }))
}

fn parse_fmt(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut check = false;
    let mut ecosystem = None;
    let mut passthrough = false;
    let mut tool_args = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if index == 0 && matches!(arg.as_str(), "-h" | "--help") {
            return Ok(None);
        }
        if passthrough {
            tool_args.push(arg.clone());
            index += 1;
            continue;
        }
        match arg.as_str() {
            "--" => passthrough = true,
            "--check" => check = true,
            "--eco" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new("fmt: --eco needs an ecosystem", Some("fmt")))?;
                if value.is_empty() || value.starts_with('-') {
                    return Err(UsageError::new(
                        "fmt: --eco needs an ecosystem",
                        Some("fmt"),
                    ));
                }
                ecosystem = Some(value.clone());
                index += 1;
            }
            value if value.starts_with("--eco=") => {
                // Same rule as the separate-word form: a mistyped flag
                // (`--eco=--check`) is a usage error, not an ecosystem name.
                let value = &value["--eco=".len()..];
                if value.is_empty() || value.starts_with('-') {
                    return Err(UsageError::new(
                        "fmt: --eco needs an ecosystem",
                        Some("fmt"),
                    ));
                }
                ecosystem = Some(value.to_string());
            }
            value
                if value.starts_with("--")
                    && suggest(value, ["--check", "--eco"].into_iter()).is_some() =>
            {
                return Err(reject("fmt", value));
            }
            value => {
                passthrough = true;
                tool_args.push(value.to_string());
            }
        }
        index += 1;
    }
    Ok(Some(Command::Fmt {
        check,
        ecosystem,
        args: tool_args,
    }))
}

fn parse_plan(args: &[String]) -> Result<Option<Command>, UsageError> {
    match args.first().map(String::as_str) {
        None => Ok(Some(Command::Plan)),
        Some("-h" | "--help") => Ok(None),
        Some(other) => Err(reject("plan", other)),
    }
}

/// Commands whose only option is `--json`. `Ok(Some(json))`.
fn parse_json_only(args: &[String], name: &'static str) -> Result<Option<bool>, UsageError> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Ok(None),
            other => return Err(reject(name, other)),
        }
    }
    Ok(Some(json))
}

fn parse_ls(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut json = false;
    let mut ecosystem = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Ok(None),
            other if other.starts_with('-') => return Err(reject("ls", other)),
            other => {
                if ecosystem.is_some() {
                    return Err(UsageError::new(
                        format!("ls: unexpected argument '{other}' (one ecosystem at most)"),
                        Some("ls"),
                    ));
                }
                if !LS_WORDS.contains(&other) {
                    return Err(UsageError::new(
                        with_suggestion(
                            format!(
                                "ls: unknown ecosystem '{other}' (one of: {})",
                                LS_WORDS.join(", ")
                            ),
                            other,
                            LS_WORDS.iter().copied(),
                        ),
                        Some("ls"),
                    ));
                }
                ecosystem = Some(other.to_string());
            }
        }
    }
    Ok(Some(Command::Ls { ecosystem, json }))
}

/// `run` and `build` own only a leading help flag; `--` forces pass-through
/// of a program argument that happens to be `-h`.
fn parse_passthrough(args: &[String], name: &'static str) -> Result<Option<Command>, UsageError> {
    let args = match args.first().map(String::as_str) {
        Some("-h" | "--help") => return Ok(None),
        Some("--") => &args[1..],
        _ => args,
    };
    if name == "run" && args.is_empty() {
        return Err(UsageError::new("run: no command given", Some("run")));
    }
    let args = args.to_vec();
    Ok(Some(match name {
        "run" => Command::Run { command: args },
        _ => Command::Build { args },
    }))
}

fn parse_deps(args: &[String], name: &str) -> Result<Option<Command>, UsageError> {
    let name: &'static str = match name {
        "add" => "add",
        "remove" => "remove",
        _ => "update",
    };
    let mut dev = false;
    let mut no_sync = false;
    let mut positional = Vec::new();
    let mut passthrough = false;
    for arg in args {
        if passthrough {
            validate_dependency_arg(name, arg)?;
            positional.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "--" => passthrough = true,
            "-h" | "--help" => return Ok(None),
            "--no-sync" => no_sync = true,
            "--dev" | "-D" if matches!(name, "add" | "remove") => dev = true,
            other if other.starts_with('-') && other.len() > 1 => return Err(reject(name, other)),
            other => {
                validate_dependency_arg(name, other)?;
                positional.push(other.to_string());
            }
        }
    }
    match name {
        "add" if positional.is_empty() => Err(UsageError::new(
            "add: no package given (e.g. 'blanket add requests', 'blanket add npm:react@18')",
            Some("add"),
        )),
        "add" => Ok(Some(Command::Add {
            specs: positional,
            dev,
            no_sync,
        })),
        "remove" if positional.is_empty() => {
            Err(UsageError::new("remove: no package given", Some("remove")))
        }
        "remove" => Ok(Some(Command::Remove {
            names: positional,
            dev,
            no_sync,
        })),
        _ => Ok(Some(Command::Update {
            names: positional,
            no_sync,
        })),
    }
}

fn validate_dependency_arg(name: &'static str, arg: &str) -> Result<(), UsageError> {
    // Keep malformed argv at the grammar boundary. In particular, a newline
    // in a requirements spec must never reach a text append or a delegated
    // package-manager command, and an option-looking package must not become
    // an option to that tool after `--`.
    if arg.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(UsageError::new(
            format!("{name}: dependency spec contains CR, LF, or NUL"),
            Some(name),
        ));
    }
    crate::deps::validate_spec(arg)
        .map_err(|error| UsageError::new(format!("{name}: {error}"), Some(name)))
}

fn parse_x(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut ecosystem = None;
    let mut from = None;
    let mut clean = false;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "--clean" => clean = true,
            "--py" | "--python" => ecosystem = Some("python".to_string()),
            "--npm" | "--node" => ecosystem = Some("node".to_string()),
            "--from" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new("--from needs a package name", Some("x")))?;
                validate_x_package(value)?;
                from = Some(value.clone());
                index += 1;
            }
            _ if arg.starts_with("--from=") => {
                let value = non_empty(&arg["--from=".len()..], "--from", Some("x"))?
                    .to_string_lossy()
                    .into_owned();
                validate_x_package(&value)?;
                from = Some(value);
            }
            "--" => {
                index += 1;
                break;
            }
            _ if arg.starts_with('-') && arg.len() > 1 => return Err(reject("x", arg)),
            _ => break,
        }
        index += 1;
    }
    let Some(tool) = args.get(index) else {
        if clean {
            if from.is_some() {
                return Err(UsageError::new(
                    "x: --clean --from requires a tool name",
                    Some("x"),
                ));
            }
            return Ok(Some(Command::XClean {
                ecosystem,
                from,
                tool: None,
            }));
        }
        return Err(UsageError::new(
            "x: no tool given (e.g. 'blanket x ruff check .', 'blanket x npm:prettier --write .')",
            Some("x"),
        ));
    };
    let mut tool = tool.clone();
    if let Some(rest) = tool.strip_prefix("py:") {
        ecosystem = Some("python".to_string());
        tool = rest.to_string();
    } else if let Some(rest) = tool.strip_prefix("npm:") {
        ecosystem = Some("node".to_string());
        tool = rest.to_string();
    }
    if clean && args.get(index + 1).is_some() {
        return Err(UsageError::new(
            format!("x --clean: unexpected argument '{}'", args[index + 1]),
            Some("x"),
        ));
    }
    if tool.is_empty() {
        return Err(UsageError::new("x: empty tool name", Some("x")));
    }
    if from.is_some() {
        let (bin, _) = split_x_version(&tool);
        validate_x_bin(bin)?;
    } else {
        // Without --from the tool is also the package name, so npm scoped
        // names such as @scope/cli legitimately contain one slash.
        validate_x_text("tool", &tool, true)?;
    }
    validate_x_version_pair(from.as_deref(), &tool)?;
    if clean {
        return Ok(Some(Command::XClean {
            ecosystem,
            from,
            tool: Some(tool),
        }));
    }
    Ok(Some(Command::X {
        ecosystem,
        from,
        tool,
        args: args[index + 1..].to_vec(),
    }))
}

fn split_x_version(value: &str) -> (&str, Option<&str>) {
    match value.rfind('@') {
        Some(0) | None => (value, None),
        Some(index) => (&value[..index], Some(&value[index + 1..])),
    }
}

fn validate_x_version_pair(from: Option<&str>, tool: &str) -> Result<(), UsageError> {
    let (_, tool_version) = split_x_version(tool);
    let from_version = from.and_then(|value| split_x_version(value).1);
    for version in [from_version, tool_version].into_iter().flatten() {
        if version.is_empty()
            || version
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            || version.chars().any(char::is_whitespace)
            || version.starts_with('-')
        {
            return Err(UsageError::new("x: invalid version", Some("x")));
        }
    }
    if let (Some(from), Some(tool)) = (from_version, tool_version) {
        if from != tool {
            return Err(UsageError::new(
                "x: --from package version conflicts with the tool version; specify only one or use the same version",
                Some("x"),
            ));
        }
    }
    Ok(())
}

fn validate_x_text(label: &str, value: &str, allow_slash: bool) -> Result<(), UsageError> {
    if value.is_empty()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || value.chars().any(char::is_whitespace)
        || value.starts_with('-')
        || (!allow_slash && (value.contains('/') || value.contains('\\')))
    {
        return Err(UsageError::new(
            format!("x: invalid {label} '{value}'"),
            Some("x"),
        ));
    }
    Ok(())
}

fn validate_x_package(value: &str) -> Result<(), UsageError> {
    // A scoped npm package contains one slash, but a filesystem path must
    // never be accepted as a package name. Version text is checked by xrun
    // after splitting package@version; these checks keep argv errors at exit 2.
    validate_x_text("package", value, true)?;
    if value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains("/../")
        || value.ends_with("/..")
        || value.contains('\\')
    {
        return Err(UsageError::new(
            format!("x: invalid package '{value}'"),
            Some("x"),
        ));
    }
    Ok(())
}

fn validate_x_bin(value: &str) -> Result<(), UsageError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ".-_".contains(ch))
    {
        return Err(UsageError::new(
            "x: --from requires a single safe executable name",
            Some("x"),
        ));
    }
    Ok(())
}

fn parse_sbom(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut output = None;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "-o" | "--output" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    UsageError::new(format!("{arg} needs a file path"), Some("sbom"))
                })?;
                output = Some(PathBuf::from(value));
                index += 1;
            }
            _ if arg.starts_with("--output=") => {
                output = Some(non_empty(
                    &arg["--output=".len()..],
                    "--output",
                    Some("sbom"),
                )?);
            }
            other => return Err(reject("sbom", other)),
        }
        index += 1;
    }
    Ok(Some(Command::Sbom { output }))
}

fn parse_gc(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut gc = GcArgs::default();
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "--dry-run" => gc.dry_run = true,
            "--project" => gc.project = true,
            "--collect-legacy" => gc.collect_legacy = true,
            "--register" => {
                index += 1;
                let first = index;
                while index < args.len() && !args[index].starts_with("--") {
                    gc.register.push(PathBuf::from(&args[index]));
                    index += 1;
                }
                if first == index {
                    return Err(UsageError::new(
                        "--register needs at least one project directory",
                        Some("gc"),
                    ));
                }
                continue;
            }
            _ if arg.starts_with("--register=") => {
                gc.register.push(non_empty(
                    &arg["--register=".len()..],
                    "--register",
                    Some("gc"),
                )?);
            }
            "--keep-days" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new("--keep-days needs <n>", Some("gc")))?;
                gc.keep_days = Some(parse_days(value)?);
                index += 1;
            }
            _ if arg.starts_with("--keep-days=") => {
                gc.keep_days = Some(parse_days(&arg["--keep-days=".len()..])?);
            }
            other => return Err(reject("gc", other)),
        }
        index += 1;
    }
    Ok(Some(Command::Gc(gc)))
}

fn parse_days(value: &str) -> Result<u64, UsageError> {
    value.parse().map_err(|_| {
        UsageError::new(
            format!("--keep-days expects a whole number of days, got '{value}'"),
            Some("gc"),
        )
    })
}

fn parse_store(args: &[String]) -> Result<Option<Command>, UsageError> {
    let command = match args.first().map(String::as_str) {
        Some("path") => Command::StorePath,
        Some("roots") => Command::StoreRoots,
        Some("-h" | "--help") => return Ok(None),
        None => {
            return Err(UsageError::new(
                "store needs a subcommand: 'store path' or 'store roots'",
                Some("store"),
            ))
        }
        Some(other) => {
            return Err(UsageError::new(
                with_suggestion(
                    format!("unknown store subcommand '{other}'"),
                    other,
                    ["path", "roots"].into_iter(),
                ),
                Some("store"),
            ))
        }
    };
    if let Some(extra) = args.get(1) {
        return Err(UsageError::new(
            format!("store {}: unexpected argument '{extra}'", args[0]),
            Some("store"),
        ));
    }
    Ok(Some(command))
}

fn parse_completions(args: &[String]) -> Result<Option<Command>, UsageError> {
    let shell = match args.first().map(String::as_str) {
        Some("bash") => Shell::Bash,
        Some("zsh") => Shell::Zsh,
        Some("fish") => Shell::Fish,
        Some("-h" | "--help") => return Ok(None),
        None => {
            return Err(UsageError::new(
                "completions needs a shell: bash, zsh, or fish",
                Some("completions"),
            ))
        }
        Some(other) => {
            return Err(UsageError::new(
                with_suggestion(
                    format!("unsupported shell '{other}' (bash, zsh, or fish)"),
                    other,
                    SHELL_WORDS.iter().copied(),
                ),
                Some("completions"),
            ))
        }
    };
    if let Some(extra) = args.get(1) {
        return Err(UsageError::new(
            format!("completions: unexpected argument '{extra}'"),
            Some("completions"),
        ));
    }
    Ok(Some(Command::Completions { shell }))
}

fn non_empty(
    value: &str,
    flag: &str,
    command: Option<&'static str>,
) -> Result<PathBuf, UsageError> {
    if value.is_empty() {
        return Err(UsageError::new(format!("{flag}= needs a value"), command));
    }
    Ok(PathBuf::from(value))
}

/// Unknown option or stray positional for a command with a fixed option set.
fn reject(name: &'static str, arg: &str) -> UsageError {
    let spec = spec(name).expect("known command");
    let message = if arg.starts_with('-') {
        with_suggestion(
            format!("{name}: unknown option '{arg}'"),
            flag_name(arg),
            spec.options
                .iter()
                .flat_map(|(flag, _)| option_spellings(flag)),
        )
    } else {
        format!("{name}: unexpected argument '{arg}'")
    };
    UsageError::new(message, Some(name))
}

/// `"-o, --output <file>"` → `["-o", "--output"]`.
pub fn option_spellings(flag: &'static str) -> impl Iterator<Item = &'static str> {
    flag.split(", ")
        .map(|part| part.split([' ', '=']).next().unwrap_or(part))
}

/// The flag without an inline `=value`.
fn flag_name(arg: &str) -> &str {
    arg.split('=').next().unwrap_or(arg)
}

fn with_suggestion<'a>(
    message: String,
    word: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> String {
    match suggest(word, candidates) {
        Some(near) => format!("{message}; did you mean '{near}'?"),
        None => message,
    }
}

/// The closest candidate when it is close enough to be a typo: the same
/// word up to case or an `=value` suffix, a prefix relation (two characters
/// or more), or, for words of four characters or more, an edit distance of
/// at most one third of the word where an adjacent transposition counts as
/// one edit. Short words never get distance-based guesses: `-q` must not
/// become "did you mean -h".
pub fn suggest<'a>(word: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let word = word.to_ascii_lowercase();
    let budget = if word.len() >= 4 {
        (word.len() / 3).max(1)
    } else {
        0
    };
    let mut best: Option<(usize, &str)> = None;
    for candidate in candidates {
        let lower = candidate.to_ascii_lowercase();
        let distance = if lower == word {
            0
        } else if word.len() >= 2 && (lower.starts_with(&word) || word.starts_with(&lower)) {
            0
        } else {
            edit_distance(&word, &lower)
        };
        if distance <= budget && best.map_or(true, |(d, _)| distance < d) {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// Optimal string alignment distance: Levenshtein plus adjacent
/// transposition as a single edit (`snyc` → `sync` is one).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let width = b.len() + 1;
    let mut d = vec![0usize; (a.len() + 1) * width];
    for i in 0..=a.len() {
        d[i * width] = i;
    }
    for j in 0..=b.len() {
        d[j] = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[(i - 1) * width + j] + 1)
                .min(d[i * width + j - 1] + 1)
                .min(d[(i - 1) * width + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[(i - 2) * width + j - 2] + 1);
            }
            d[i * width + j] = best;
        }
    }
    d[a.len() * width + b.len()]
}

// ---------------------------------------------------------------------------
// Shell completions, generated from the command table.

/// Every option spelling a command accepts, `--help` included.
fn command_flags(spec: &Spec) -> Vec<&'static str> {
    spec.options
        .iter()
        .flat_map(|(flag, _)| option_spellings(flag))
        .collect()
}

fn all_command_words() -> Vec<&'static str> {
    COMMANDS
        .iter()
        .map(|spec| spec.name)
        .chain(SYNC_ALIASES.iter().copied())
        .chain(["help", "version"])
        .collect()
}

const GLOBAL_FLAGS: &[&str] = &[
    "-C",
    "--directory",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "--no-color",
    "-h",
    "--help",
    "-V",
    "--version",
];

/// The one-liner every shell uses to read script names out of package.json.
/// Deliberately a sed/grep pipeline: completion must not need jq or node.
const SCRIPTS_PIPELINE: &str = r#"sed -n '/"scripts"[[:space:]]*:/,/}/p' package.json | grep -oE '^[[:space:]]*"[^"]+"[[:space:]]*:' | tr -d ' \t":'"#;

pub fn completions(shell: Shell) -> String {
    match shell {
        Shell::Bash => bash_completions(),
        Shell::Zsh => zsh_completions(),
        Shell::Fish => fish_completions(),
    }
}

fn bash_completions() -> String {
    let mut out = String::from(
        "# bash completion for blanket — generated by 'blanket completions bash'\n\
         _blanket_scripts() {\n    [[ -f package.json ]] || return 0\n    ",
    );
    out.push_str(SCRIPTS_PIPELINE);
    out.push_str(
        "\n}\n\n_blanket() {\n    local cur cmd=\"\" i\n    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n    \
         for ((i = 1; i < COMP_CWORD; i++)); do\n        case \"${COMP_WORDS[i]}\" in\n            \
         -C|--directory) ((i++)) ;;\n            -*) ;;\n            *) cmd=\"${COMP_WORDS[i]}\"; break ;;\n        \
         esac\n    done\n    if [[ -z \"$cmd\" ]]; then\n        if [[ \"$cur\" == -* ]]; then\n            ",
    );
    out.push_str(&format!(
        "COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n",
        GLOBAL_FLAGS.join(" ")
    ));
    out.push_str(&format!(
        "        else\n            COMPREPLY=( $(compgen -W \"{} $(_blanket_scripts)\" -- \"$cur\") )\n        fi\n        return\n    fi\n    case \"$cmd\" in\n",
        all_command_words().join(" ")
    ));
    for spec in COMMANDS {
        let mut words: Vec<&str> = spec.words.to_vec();
        words.extend(command_flags(spec));
        let pattern = if spec.name == "sync" {
            "sync|install|i".to_string()
        } else {
            spec.name.to_string()
        };
        match spec.name {
            "run" => out.push_str(
                "        run)\n            if [[ $i -eq $((COMP_CWORD - 1)) ]]; then\n                \
                 COMPREPLY=( $(compgen -W \"$(_blanket_scripts)\" -c -- \"$cur\") )\n            else\n                \
                 COMPREPLY=( $(compgen -f -- \"$cur\") )\n            fi ;;\n",
            ),
            "build" => out.push_str(&format!(
                "        build)\n            if [[ $i -eq $((COMP_CWORD - 1)) ]]; then\n                \
                 COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") )\n            else\n                \
                 COMPREPLY=( $(compgen -f -- \"$cur\") )\n            fi ;;\n",
                words.join(" ")
            )),
            _ => out.push_str(&format!(
                "        {pattern}) COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ) ;;\n",
                words.join(" ")
            )),
        }
    }
    out.push_str(&format!(
        "        help) COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ) ;;\n        *) COMPREPLY=() ;;\n    esac\n}}\n\ncomplete -F _blanket blanket\n",
        COMMANDS.iter().map(|spec| spec.name).collect::<Vec<_>>().join(" ")
    ));
    out
}

fn zsh_quote(text: &str) -> String {
    text.replace('\'', "'\\''")
        .replace(':', "\\:")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn zsh_completions() -> String {
    let mut out = String::from(
        "#compdef blanket\n# zsh completion for blanket — generated by 'blanket completions zsh'\n\n\
         _blanket_scripts() {\n    [[ -f package.json ]] || return 1\n    local -a scripts\n    scripts=(${(f)\"$(",
    );
    out.push_str(SCRIPTS_PIPELINE);
    out.push_str(")\"})\n    (( ${#scripts} )) && _describe -t scripts 'package.json script' scripts\n}\n\n_blanket() {\n    local -a commands\n    commands=(\n");
    for spec in COMMANDS {
        out.push_str(&format!(
            "        '{}:{}'\n",
            spec.name,
            zsh_quote(spec.summary)
        ));
    }
    out.push_str("        'install:alias for sync'\n        'help:show help for a command'\n        'version:print the version'\n    )\n    local curcontext=\"$curcontext\" state line\n    _arguments -C \\\n        '(-C --directory)'{-C,--directory}'[run as if started in <dir>]:directory:_files -/' \\\n        '(-q --quiet)'{-q,--quiet}'[no narration]' \\\n        '(-v --verbose)'{-v,--verbose}'[show every decision and subprocess]' \\\n        '--no-color[plain output]' \\\n        '(-h --help)'{-h,--help}'[print help]' \\\n        '(-V --version)'{-V,--version}'[print the version]' \\\n        '1: :->command' \\\n        '*:: :->args'\n    case $state in\n        command)\n            _describe -t commands 'blanket command' commands\n            _blanket_scripts\n            ;;\n        args)\n            case $words[1] in\n");
    for spec in COMMANDS {
        let pattern = if spec.name == "sync" {
            "sync|install|i".to_string()
        } else {
            spec.name.to_string()
        };
        if spec.name == "run" {
            out.push_str("                run)\n                    if (( CURRENT == 2 )); then\n                        _blanket_scripts\n                        _command_names -e\n                    else\n                        _files\n                    fi\n                    ;;\n");
            continue;
        }
        let mut specs: Vec<String> = spec
            .options
            .iter()
            .flat_map(|(flag, description)| {
                option_spellings(flag)
                    .map(move |spelling| format!("'{spelling}[{}]'", zsh_quote(description)))
            })
            .collect();
        if !spec.words.is_empty() {
            specs.push(format!("'1:word:({})'", spec.words.join(" ")));
        }
        if spec.name == "build" || spec.name == "gc" {
            specs.push("'*:file:_files'".to_string());
        }
        out.push_str(&format!(
            "                {pattern})\n                    _arguments {}\n                    ;;\n",
            specs.join(" ")
        ));
    }
    out.push_str(&format!(
        "                help)\n                    _values 'command' {}\n                    ;;\n                *)\n                    _files\n                    ;;\n            esac\n            ;;\n    esac\n}}\n\n_blanket \"$@\"\n",
        COMMANDS.iter().map(|spec| spec.name).collect::<Vec<_>>().join(" ")
    ));
    out
}

fn fish_quote(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\'', "\\'")
}

fn fish_completions() -> String {
    let mut out = String::from(
        "# fish completion for blanket — generated by 'blanket completions fish'\n\
         function __blanket_scripts\n    test -f package.json; or return\n    ",
    );
    out.push_str(SCRIPTS_PIPELINE);
    out.push_str("\nend\n\ncomplete -c blanket -f\n");
    let globals: &[(&str, &str, &str, bool)] = &[
        ("C", "directory", "run as if started in <dir>", true),
        ("q", "quiet", "no narration", false),
        ("v", "verbose", "show every decision and subprocess", false),
        ("", "no-color", "plain output", false),
        ("h", "help", "print help", false),
        ("V", "version", "print the version", false),
    ];
    for (short, long, description, takes_value) in globals {
        let mut line = String::from("complete -c blanket -n '__fish_use_subcommand'");
        if !short.is_empty() {
            line.push_str(&format!(" -s {short}"));
        }
        line.push_str(&format!(" -l {long}"));
        if *takes_value {
            line.push_str(" -r -a '(__fish_complete_directories)'");
        }
        line.push_str(&format!(" -d '{}'\n", fish_quote(description)));
        out.push_str(&line);
    }
    for spec in COMMANDS {
        out.push_str(&format!(
            "complete -c blanket -n '__fish_use_subcommand' -a {} -d '{}'\n",
            spec.name,
            fish_quote(spec.summary)
        ));
    }
    out.push_str("complete -c blanket -n '__fish_use_subcommand' -a install -d 'alias for sync'\n");
    out.push_str(
        "complete -c blanket -n '__fish_use_subcommand' -a help -d 'show help for a command'\n",
    );
    out.push_str(
        "complete -c blanket -n '__fish_use_subcommand' -a version -d 'print the version'\n",
    );
    out.push_str("complete -c blanket -n '__fish_use_subcommand' -a '(__blanket_scripts)' -d 'package.json script'\n");
    for spec in COMMANDS {
        let seen = if spec.name == "sync" {
            "sync install i".to_string()
        } else {
            spec.name.to_string()
        };
        for (flag, description) in spec.options {
            for spelling in option_spellings(flag) {
                let (kind, name) = if let Some(long) = spelling.strip_prefix("--") {
                    ("-l", long)
                } else {
                    ("-s", &spelling[1..])
                };
                let value = if flag.contains('<') { " -r" } else { "" };
                out.push_str(&format!(
                    "complete -c blanket -n '__fish_seen_subcommand_from {seen}' {kind} {name}{value} -d '{}'\n",
                    fish_quote(description)
                ));
            }
        }
        if !spec.words.is_empty() {
            out.push_str(&format!(
                "complete -c blanket -n '__fish_seen_subcommand_from {seen}' -a '{}'\n",
                spec.words.join(" ")
            ));
        }
        if spec.name == "run" {
            out.push_str("complete -c blanket -n '__fish_seen_subcommand_from run' -a '(__blanket_scripts)' -d 'package.json script'\n");
            out.push_str("complete -c blanket -n '__fish_seen_subcommand_from run' -a '(__fish_complete_command)'\n");
        }
        if spec.name == "build" || spec.name == "gc" {
            out.push_str(&format!(
                "complete -c blanket -n '__fish_seen_subcommand_from {seen}' -F\n"
            ));
        }
    }
    out.push_str(&format!(
        "complete -c blanket -n '__fish_seen_subcommand_from help' -a '{}'\n",
        COMMANDS
            .iter()
            .map(|spec| spec.name)
            .collect::<Vec<_>>()
            .join(" ")
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    fn run(words: &[&str]) -> Invocation {
        match parse(&argv(words)).unwrap() {
            Parsed::Run(invocation) => invocation,
            other => panic!("expected a command, got {other:?}"),
        }
    }

    fn command(words: &[&str]) -> Command {
        run(words).command
    }

    fn printed(words: &[&str]) -> String {
        match parse(&argv(words)).unwrap() {
            Parsed::Print(text) => text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    fn message(words: &[&str]) -> String {
        match parse(&argv(words)) {
            Err(error) => error.message,
            Ok(Parsed::Script { message, .. }) => message,
            Ok(other) => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn no_command_is_implicit_and_keeps_the_options() {
        assert_eq!(parse(&[]), Ok(Parsed::Implicit(Options::default())));
        assert_eq!(
            parse(&argv(&["-C", "/tmp", "-q"])),
            Ok(Parsed::Implicit(Options {
                directory: Some(PathBuf::from("/tmp")),
                quiet: true,
                ..Options::default()
            }))
        );
    }

    #[test]
    fn unknown_first_word_is_a_script_candidate() {
        assert_eq!(
            parse(&argv(&["-v", "dev", "--port", "3000"])),
            Ok(Parsed::Script {
                options: Options {
                    verbose: true,
                    ..Options::default()
                },
                name: "dev".into(),
                args: argv(&["--port", "3000"]),
                message: "unknown command 'dev'".into(),
            })
        );
        assert_eq!(
            message(&["snyc"]),
            "unknown command 'snyc'; did you mean 'sync'?"
        );
        assert_eq!(
            message(&["sy"]),
            "unknown command 'sy'; did you mean 'sync'?"
        );
        assert_eq!(
            message(&["gcc"]),
            "unknown command 'gcc'; did you mean 'gc'?"
        );
        assert_eq!(message(&["deploy"]), "unknown command 'deploy'");
        assert_eq!(
            render_usage_error("unknown command 'deploy'", None),
            "blanket: error: unknown command 'deploy'\nRun 'blanket --help' for usage.\n"
        );
        assert_eq!(message(&["--fresh", "sync"]), "unknown option '--fresh'");
        assert_eq!(
            message(&["--dir", "x", "sync"]),
            "unknown option '--dir'; did you mean '--directory'?"
        );
    }

    #[test]
    fn help_and_version_at_every_level() {
        for words in [&["--help"][..], &["-h"], &["help"], &["help", "help"]] {
            assert_eq!(printed(words), usage(), "{words:?}");
        }
        for words in [
            &["--version"][..],
            &["-V"],
            &["version"],
            &["help", "version"],
        ] {
            assert_eq!(printed(words), format!("blanket {VERSION}\n"), "{words:?}");
        }
        for spec in COMMANDS {
            assert_eq!(
                printed(&["help", spec.name]),
                help(spec),
                "help {}",
                spec.name
            );
            assert_eq!(
                printed(&[spec.name, "--help"]),
                help(spec),
                "{} --help",
                spec.name
            );
            assert_eq!(printed(&[spec.name, "-h"]), help(spec), "{} -h", spec.name);
        }
        assert_eq!(printed(&["help", "install"]), help(spec("sync").unwrap()));
        assert_eq!(printed(&["i", "--help"]), help(spec("sync").unwrap()));
        assert_eq!(
            printed(&["gc", "--dry-run", "--help"]),
            help(spec("gc").unwrap())
        );
        assert_eq!(printed(&["-C", "/tmp", "--help"]), usage());
        assert!(message(&["help", "snyc"]).contains("did you mean 'sync'?"));
    }

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

    #[test]
    fn sync_flags_and_aliases() {
        let plain = Command::Sync {
            fresh: false,
            strict: false,
        };
        assert_eq!(command(&["sync"]), plain);
        assert_eq!(command(&["install"]), plain);
        assert_eq!(command(&["i"]), plain);
        assert_eq!(
            command(&["install", "--strict", "--fresh"]),
            Command::Sync {
                fresh: true,
                strict: true
            }
        );
        assert_eq!(
            message(&["sync", "--fersh"]),
            "sync: unknown option '--fersh'; did you mean '--fresh'?"
        );
        assert_eq!(
            message(&["i", "--strict=1"]),
            "sync: unknown option '--strict=1'; did you mean '--strict'?"
        );
        assert_eq!(message(&["sync", "now"]), "sync: unexpected argument 'now'");
        assert_eq!(
            parse(&argv(&["sync", "now"])).unwrap_err().render(),
            "blanket: error: sync: unexpected argument 'now'\nRun 'blanket help sync' for usage.\n"
        );
    }

    #[test]
    fn fmt_grammar_separates_blanket_flags_from_tool_args() {
        assert_eq!(
            command(&["fmt"]),
            Command::Fmt {
                check: false,
                ecosystem: None,
                args: vec![],
            }
        );
        assert_eq!(
            command(&["fmt", "--check", "--eco", "rust", "--edition", "2024"]),
            Command::Fmt {
                check: true,
                ecosystem: Some("rust".into()),
                args: argv(&["--edition", "2024"]),
            }
        );
        assert_eq!(
            command(&["fmt", "--", "--help"]),
            Command::Fmt {
                check: false,
                ecosystem: None,
                args: argv(&["--help"]),
            }
        );
        assert_eq!(
            message(&["fmt", "--chekc"]),
            "fmt: unknown option '--chekc'; did you mean '--check'?"
        );
        assert_eq!(
            command(&["fmt", "--eco=rust"]),
            Command::Fmt {
                check: false,
                ecosystem: Some("rust".into()),
                args: vec![],
            }
        );
        assert_eq!(message(&["fmt", "--eco"]), "fmt: --eco needs an ecosystem");
        // Both spellings reject a value that is really a mistyped flag.
        for args in [
            &["fmt", "--eco", "--check"][..],
            &["fmt", "--eco=--check"],
            &["fmt", "--eco="],
        ] {
            assert_eq!(message(args), "fmt: --eco needs an ecosystem", "{args:?}");
        }
    }

    #[test]
    fn plan_takes_nothing() {
        assert_eq!(command(&["plan"]), Command::Plan);
        assert_eq!(
            message(&["plan", "--json"]),
            "plan: unknown option '--json'"
        );
        assert_eq!(message(&["plan", "x"]), "plan: unexpected argument 'x'");
    }

    #[test]
    fn inspect_commands() {
        assert_eq!(command(&["status"]), Command::Status { json: false });
        assert_eq!(
            command(&["status", "--json"]),
            Command::Status { json: true }
        );
        assert_eq!(message(&["status", "-j"]), "status: unknown option '-j'");
        assert_eq!(
            command(&["doctor", "--json"]),
            Command::Doctor { json: true }
        );
        assert_eq!(
            command(&["ls"]),
            Command::Ls {
                ecosystem: None,
                json: false
            }
        );
        assert_eq!(
            command(&["ls", "node", "--json"]),
            Command::Ls {
                ecosystem: Some("node".into()),
                json: true
            }
        );
        // The row `blanket fmt` makes `ls` print is a word `ls` accepts.
        assert_eq!(
            command(&["ls", "rustfmt"]),
            Command::Ls {
                ecosystem: Some("rustfmt".into()),
                json: false
            }
        );
        assert_eq!(
            message(&["ls", "npm"]),
            "ls: unknown ecosystem 'npm' (one of: python, node, cargo, go, ruby, elixir, dotnet, rustfmt)"
        );
        assert_eq!(
            message(&["ls", "pyhton"]),
            "ls: unknown ecosystem 'pyhton' (one of: python, node, cargo, go, ruby, elixir, dotnet, rustfmt); did you mean 'python'?"
        );
        assert_eq!(
            message(&["ls", "node", "python"]),
            "ls: unexpected argument 'python' (one ecosystem at most)"
        );
    }

    #[test]
    fn dependency_verbs() {
        assert_eq!(
            command(&["add", "requests>=2", "npm:react@18", "--dev", "--no-sync"]),
            Command::Add {
                specs: argv(&["requests>=2", "npm:react@18"]),
                dev: true,
                no_sync: true,
            }
        );
        assert!(message(&["add", "-D", "--", "-weird"])
            .contains("dependency spec '-weird' looks like a tool option"));
        assert!(message(&["add"]).starts_with("add: no package given"));
        assert_eq!(
            message(&["add", "--dve", "x"]),
            "add: unknown option '--dve'; did you mean '--dev'?"
        );
        assert_eq!(
            message(&["remove", "--dve", "x"]),
            "remove: unknown option '--dve'; did you mean '--dev'?"
        );
        assert_eq!(
            command(&["remove", "six", "--no-sync"]),
            Command::Remove {
                names: argv(&["six"]),
                dev: false,
                no_sync: true,
            }
        );
        assert_eq!(
            command(&["remove", "--dev", "six"]),
            Command::Remove {
                names: argv(&["six"]),
                dev: true,
                no_sync: false,
            }
        );
        assert_eq!(message(&["remove"]), "remove: no package given");
        assert_eq!(
            command(&["update"]),
            Command::Update {
                names: vec![],
                no_sync: false,
            }
        );
        assert_eq!(
            command(&["update", "serde", "tokio"]),
            Command::Update {
                names: argv(&["serde", "tokio"]),
                no_sync: false,
            }
        );
        for name in ["add", "remove", "update", "x"] {
            assert_eq!(printed(&[name, "--help"]), help(spec(name).unwrap()));
        }
    }

    #[test]
    fn x_owns_only_its_leading_flags() {
        assert_eq!(
            command(&["x", "ruff", "check", "--fix", "."]),
            Command::X {
                ecosystem: None,
                from: None,
                tool: "ruff".into(),
                args: argv(&["check", "--fix", "."]),
            }
        );
        assert_eq!(
            command(&["x", "--npm", "--from", "@angular/cli", "ng@18", "--version"]),
            Command::X {
                ecosystem: Some("node".into()),
                from: Some("@angular/cli".into()),
                tool: "ng@18".into(),
                args: argv(&["--version"]),
            }
        );
        assert_eq!(
            command(&["x", "py:cowsay@6.1", "hi"]),
            Command::X {
                ecosystem: Some("python".into()),
                from: None,
                tool: "cowsay@6.1".into(),
                args: argv(&["hi"]),
            }
        );
        assert!(message(&["x", "--", "--weird-tool"]).contains("x: invalid tool"));
        assert!(message(&["x"]).starts_with("x: no tool given"));
        assert_eq!(message(&["x", "--from"]), "--from needs a package name");
        assert_eq!(
            message(&["x", "--pyy", "ruff"]),
            "x: unknown option '--pyy'; did you mean '--py'?"
        );
        assert_eq!(
            command(&["x", "--clean"]),
            Command::XClean {
                ecosystem: None,
                from: None,
                tool: None,
            }
        );
        assert_eq!(
            command(&["x", "--clean", "--py", "ruff@0.6.1"]),
            Command::XClean {
                ecosystem: Some("python".into()),
                from: None,
                tool: Some("ruff@0.6.1".into()),
            }
        );
        assert_eq!(
            message(&["x", "--clean", "ruff", "extra"]),
            "x --clean: unexpected argument 'extra'"
        );
    }

    #[test]
    fn run_and_build_pass_arguments_through() {
        assert_eq!(
            command(&["run", "python", "-c", "print(1)", "--help"]),
            Command::Run {
                command: argv(&["python", "-c", "print(1)", "--help"])
            }
        );
        assert_eq!(
            command(&["run", "--", "-h"]),
            Command::Run {
                command: argv(&["-h"])
            }
        );
        assert_eq!(message(&["run"]), "run: no command given");
        assert_eq!(message(&["run", "--"]), "run: no command given");
        assert_eq!(command(&["build"]), Command::Build { args: vec![] });
        assert_eq!(command(&["build", "--"]), Command::Build { args: vec![] });
        assert_eq!(
            command(&["build", "cargo", "--release", "-h"]),
            Command::Build {
                args: argv(&["cargo", "--release", "-h"])
            }
        );
        assert_eq!(
            command(&["build", "--", "--help"]),
            Command::Build {
                args: argv(&["--help"])
            }
        );
        assert_eq!(
            command(&["build", "--release"]),
            Command::Build {
                args: argv(&["--release"])
            }
        );
    }

    #[test]
    fn sbom_output_spellings() {
        assert_eq!(command(&["sbom"]), Command::Sbom { output: None });
        for words in [
            &["sbom", "--output", "bom.json"][..],
            &["sbom", "-o", "bom.json"],
            &["sbom", "--output=bom.json"],
        ] {
            assert_eq!(
                command(words),
                Command::Sbom {
                    output: Some(PathBuf::from("bom.json"))
                },
                "{words:?}"
            );
        }
        assert_eq!(message(&["sbom", "--output"]), "--output needs a file path");
        assert_eq!(message(&["sbom", "--output="]), "--output= needs a value");
        assert_eq!(
            message(&["sbom", "--out", "x"]),
            "sbom: unknown option '--out'; did you mean '--output'?"
        );
        assert_eq!(
            message(&["sbom", "bom.json"]),
            "sbom: unexpected argument 'bom.json'"
        );
    }

    #[test]
    fn gc_options_keep_their_shapes() {
        assert_eq!(command(&["gc"]), Command::Gc(GcArgs::default()));
        assert_eq!(
            command(&[
                "gc",
                "--dry-run",
                "--keep-days",
                "0",
                "--register",
                "/a",
                "/b",
                "--project",
                "--register=/c",
                "--collect-legacy",
                "--keep-days=7",
            ]),
            Command::Gc(GcArgs {
                dry_run: true,
                keep_days: Some(7),
                project: true,
                collect_legacy: true,
                register: vec!["/a".into(), "/b".into(), "/c".into()],
            })
        );
        assert_eq!(
            message(&["gc", "--register"]),
            "--register needs at least one project directory"
        );
        assert_eq!(
            message(&["gc", "--register", "--dry-run"]),
            "--register needs at least one project directory"
        );
        assert_eq!(message(&["gc", "--register="]), "--register= needs a value");
        assert_eq!(message(&["gc", "--keep-days"]), "--keep-days needs <n>");
        assert_eq!(
            message(&["gc", "--keep-days", "soon"]),
            "--keep-days expects a whole number of days, got 'soon'"
        );
        assert_eq!(
            message(&["gc", "--keep-days=-1"]),
            "--keep-days expects a whole number of days, got '-1'"
        );
        assert_eq!(
            message(&["gc", "--dryrun"]),
            "gc: unknown option '--dryrun'; did you mean '--dry-run'?"
        );
        assert_eq!(message(&["gc", "now"]), "gc: unexpected argument 'now'");
    }

    #[test]
    fn store_and_completions_words() {
        assert_eq!(command(&["store", "path"]), Command::StorePath);
        assert_eq!(command(&["store", "roots"]), Command::StoreRoots);
        assert_eq!(
            message(&["store"]),
            "store needs a subcommand: 'store path' or 'store roots'"
        );
        assert_eq!(
            message(&["store", "root"]),
            "unknown store subcommand 'root'; did you mean 'roots'?"
        );
        assert_eq!(
            message(&["store", "path", "x"]),
            "store path: unexpected argument 'x'"
        );
        assert_eq!(
            command(&["completions", "zsh"]),
            Command::Completions { shell: Shell::Zsh }
        );
        assert_eq!(
            message(&["completions"]),
            "completions needs a shell: bash, zsh, or fish"
        );
        assert_eq!(
            message(&["completions", "powershell"]),
            "unsupported shell 'powershell' (bash, zsh, or fish)"
        );
        assert_eq!(
            message(&["completions", "bas"]),
            "unsupported shell 'bas' (bash, zsh, or fish); did you mean 'bash'?"
        );
    }

    #[test]
    fn directory_option_spellings() {
        for words in [
            &["-C", "/work", "plan"][..],
            &["-C/work", "plan"],
            &["--directory", "/work", "plan"],
            &["--directory=/work", "plan"],
        ] {
            assert_eq!(
                run(words),
                Invocation {
                    options: Options {
                        directory: Some(PathBuf::from("/work")),
                        ..Options::default()
                    },
                    command: Command::Plan
                },
                "{words:?}"
            );
        }
        assert_eq!(run(&["plan"]).options, Options::default());
        assert_eq!(message(&["-C"]), "-C needs a directory");
        assert_eq!(message(&["--directory="]), "--directory= needs a value");
        assert_eq!(
            command(&["run", "make", "-C", "sub"]),
            Command::Run {
                command: argv(&["make", "-C", "sub"])
            }
        );
    }

    #[test]
    fn output_options_are_global_and_validated() {
        assert_eq!(
            run(&["-q", "-v", "--no-color", "-C", "/w", "plan"]).options,
            Options {
                directory: Some(PathBuf::from("/w")),
                quiet: true,
                verbose: true,
                no_color: true,
            }
        );
        assert!(run(&["--quiet", "--verbose", "plan"]).options.quiet);
        assert_eq!(
            message(&["--quite", "plan"]),
            "unknown option '--quite'; did you mean '--quiet'?"
        );
        assert_eq!(printed(&["-V"]), format!("blanket {VERSION}\n"));
        assert!(run(&["-v", "plan"]).options.verbose);
        assert_eq!(message(&["sync", "-q"]), "sync: unknown option '-q'");
        assert_eq!(
            command(&["run", "pytest", "-q"]),
            Command::Run {
                command: argv(&["pytest", "-q"])
            }
        );
    }

    #[test]
    fn suggestions_are_conservative() {
        let commands = || COMMANDS.iter().map(|spec| spec.name);
        assert_eq!(suggest("sync", commands()), Some("sync"));
        assert_eq!(suggest("SYNC", commands()), Some("sync"));
        assert_eq!(suggest("s", commands()), None);
        assert_eq!(suggest("gcx", commands()), Some("gc"));
        assert_eq!(suggest("gxc", commands()), None);
        assert_eq!(suggest("-q", ["-h", "-v"].into_iter()), None);
        assert_eq!(suggest("stor", commands()), Some("store"));
        assert_eq!(suggest("bulid", commands()), Some("build"));
        assert_eq!(suggest("snyc", commands()), Some("sync"));
        assert_eq!(suggest("deploy", commands()), None);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("snyc", "sync"), 1);
        assert_eq!(edit_distance("ab", "ba"), 1);
    }

    #[test]
    fn completions_cover_every_command_and_option() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let script = completions(shell);
            for spec in COMMANDS {
                assert!(script.contains(spec.name), "{shell:?} lacks {}", spec.name);
                for flag in command_flags(spec) {
                    // fish spells `--json` as `-l json` and `-o` as `-s o`.
                    let spelled = match (shell, flag.strip_prefix("--")) {
                        (Shell::Fish, Some(long)) => format!("-l {long}"),
                        (Shell::Fish, None) => format!("-s {}", &flag[1..]),
                        _ => flag.to_string(),
                    };
                    assert!(
                        script.contains(&spelled),
                        "{shell:?} lacks {} {spelled}",
                        spec.name
                    );
                }
                for word in spec.words {
                    assert!(
                        script.contains(word),
                        "{shell:?} lacks {} {word}",
                        spec.name
                    );
                }
            }
            assert!(script.contains("install"), "{shell:?} lacks the sync alias");
            assert!(
                script.contains("package.json"),
                "{shell:?} lacks script completion"
            );
        }
        assert!(completions(Shell::Bash).ends_with("complete -F _blanket blanket\n"));
        assert!(completions(Shell::Zsh).starts_with("#compdef blanket\n"));
        assert!(completions(Shell::Fish).contains("complete -c blanket -f\n"));
        assert_eq!(zsh_quote("a:b [c]"), "a\\:b \\[c\\]");
        assert_eq!(fish_quote("it's"), "it\\'s");
    }
}

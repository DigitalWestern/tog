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
//!   `--no-color` set the output conventions (see `ui`).
//!
//! Exit status contract: 0 success, 1 the command failed, 2 usage error.

use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Sync { fresh: bool, strict: bool },
    Plan,
    /// Everything after `build` (ecosystem name and tool arguments); the
    /// ecosystem is inferred by the dispatcher from the project layout.
    Build { args: Vec<String> },
    /// The program (or package.json script) and its arguments.
    Run { command: Vec<String> },
    Sbom { output: Option<PathBuf> },
    Gc(GcArgs),
    StorePath,
    StoreRoots,
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

/// What `main` does with argv: run a command, or print text and exit 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Run(Invocation),
    Print(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// `blanket` with nothing after it: the full usage goes to stderr.
    NoCommand,
    Invalid {
        message: String,
        /// The command whose help is relevant (`None` → top-level usage).
        command: Option<&'static str>,
    },
}

impl UsageError {
    fn invalid(message: impl Into<String>, command: Option<&'static str>) -> Self {
        UsageError::Invalid {
            message: message.into(),
            command,
        }
    }

    /// The text `main` writes to stderr before exiting with `EXIT_USAGE`.
    pub fn render(&self) -> String {
        match self {
            UsageError::NoCommand => usage(),
            UsageError::Invalid { message, command } => {
                let hint = match command {
                    Some(name) => format!("Run 'blanket help {name}' for usage."),
                    None => "Run 'blanket --help' for usage.".to_string(),
                };
                format!("blanket: error: {message}\n{hint}\n")
            }
        }
    }
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.render().trim_end())
    }
}

impl std::error::Error for UsageError {}

/// Static description of one command: drives both parsing suggestions and
/// the help text, so the two can never disagree.
pub struct Spec {
    pub name: &'static str,
    pub summary: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
    /// `(flag spelling, description)`; the spelling's first token (before a
    /// space or `=`) is what suggestions match against.
    pub options: &'static [(&'static str, &'static str)],
}

const HELP_OPTION: (&str, &str) = ("-h, --help", "print this help");

pub const COMMANDS: &[Spec] = &[
    Spec {
        name: "sync",
        summary: "realize and project the environment(s) from the project's inputs",
        usage: "blanket sync [--fresh] [--strict]",
        description: "\
Discovers every ecosystem present in the current directory (see PROJECT
INPUTS in 'blanket --help'), realizes each locked plan into the immutable
store, and projects it into the project (.venv, node_modules, .blanket/...).
A found manifest with no dependencies syncs an interpreter-only environment.
Policy exceptions (unattested inputs, failed install scripts, ...) are
recorded in .blanket/closures/*.json and summarized at the end; --strict, a
BLANKET_STRICT=1 environment, or a .blanket/policy.toml deny list refuses
them instead.",
        options: &[
            ("--fresh", "rebuild the projection, dropping project-local caches"),
            ("--strict", "refuse every policy exception (same as BLANKET_STRICT=1)"),
            HELP_OPTION,
        ],
    },
    Spec {
        name: "plan",
        summary: "print the locked plan(s) as JSON",
        usage: "blanket plan",
        description: "\
Prints one JSON document per ecosystem found here, exactly what 'blanket
sync' would realize. Planning may resolve missing lockfiles with the store's
own uv/npm/cargo and cache the result under .blanket/.",
        options: &[HELP_OPTION],
    },
    Spec {
        name: "build",
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
    },
    Spec {
        name: "run",
        summary: "run a command or package.json script inside the projected env(s)",
        usage: "blanket run [--] <command> [<args>...]",
        description: "\
Executes <command> with PATH and the ecosystem variables of the nearest
projected root (the closest ancestor with .blanket/closures/). When the
project has a package.json and <command> names one of its scripts, the
script runs (pre/name/post, npm environment, exit code passed through) and
wins over a same-named executable on PATH. Everything after <command> is
passed through unchanged.",
        options: &[HELP_OPTION],
    },
    Spec {
        name: "sbom",
        summary: "CycloneDX 1.5 SBOM from the synced closures",
        usage: "blanket sbom [--output <file>]",
        description: "\
Emits a CycloneDX 1.5 document covering every ecosystem closure recorded by
the last sync: pinned hashes, purls, and toolchain store ids. Writes to
stdout unless --output is given.",
        options: &[
            ("-o, --output <file>", "write the document to <file> instead of stdout"),
            HELP_OPTION,
        ],
    },
    Spec {
        name: "gc",
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
    },
    Spec {
        name: "store",
        summary: "inspect the store: 'store path', 'store roots'",
        usage: "blanket store <path | roots>",
        description: "\
  path    print the store root (~/.blanket/store unless BLANKET_STORE is set)
  roots   list the project directories registered with this store",
        options: &[HELP_OPTION],
    },
];

const PROJECT_INPUTS: &str = "\
PROJECT INPUTS (any combination; each found ecosystem is synced):
  requirements.txt, pyproject.toml, setup.cfg/setup.py, or requirements/*
                          Python deps; ranged inputs are locked via the store
                          uv into requirements.lock.txt (hash-pinned), while
                          Poetry/uv lockfiles are imported when compatible
  .python-version         optional; otherwise selected from project
                          constraints (default: CPython 3.12.14)
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
";

pub fn spec(name: &str) -> Option<&'static Spec> {
    COMMANDS.iter().find(|spec| spec.name == name)
}

/// Top-level help: the command list, global options, project inputs.
pub fn usage() -> String {
    let mut text = format!(
        "blanket {VERSION} — universal realization & environment kernel\n\n\
         USAGE:\n  blanket [-C <dir>] <command> [<args>...]\n\nCOMMANDS:\n"
    );
    let width = COMMANDS
        .iter()
        .map(|spec| spec.name.len())
        .max()
        .unwrap_or(0)
        .max("version".len());
    for spec in COMMANDS {
        text.push_str(&format!("  {:width$}  {}\n", spec.name, spec.summary));
    }
    text.push_str(&format!(
        "  {:width$}  show help for a command\n  {:width$}  print the version\n",
        "help", "version"
    ));
    text.push_str(
        "\nOPTIONS:\n  \
         -C, --directory <dir>  run as if blanket had been started in <dir>\n  \
         -q, --quiet            no narration: only errors and results on stdout\n  \
         -v, --verbose          show every decision and subprocess command line\n      \
         --no-color             plain output (also: NO_COLOR, or a non-tty stderr)\n  \
         -h, --help             print help ('blanket help <command>' for one command)\n  \
         -V, --version          print the version\n\n",
    );
    text.push_str(PROJECT_INPUTS);
    text.push('\n');
    text.push_str(ENVIRONMENT);
    text.push_str("\nExit status: 0 success, 1 failure, 2 usage error.\n");
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
                let value = args.get(index + 1).ok_or_else(|| {
                    UsageError::invalid(format!("{arg} needs a directory"), None)
                })?;
                options.directory = Some(PathBuf::from(value));
                index += 2;
            }
            _ if arg.starts_with("--directory=") => {
                options.directory =
                    Some(non_empty(&arg["--directory=".len()..], "--directory", None)?);
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
                return Err(UsageError::invalid(
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
    let Some(name) = args.get(index).map(String::as_str) else {
        return Err(UsageError::NoCommand);
    };
    let rest = &args[index + 1..];
    let command = match name {
        "sync" => parse_sync(rest)?,
        "plan" => parse_plan(rest)?,
        "build" => parse_passthrough(rest, "build")?,
        "run" => parse_passthrough(rest, "run")?,
        "sbom" => parse_sbom(rest)?,
        "gc" => parse_gc(rest)?,
        "store" => parse_store(rest)?,
        other => {
            return Err(UsageError::invalid(
                with_suggestion(
                    format!("unknown command '{other}'"),
                    other,
                    COMMANDS
                        .iter()
                        .map(|spec| spec.name)
                        .chain(["help", "version"]),
                ),
                None,
            ))
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
            UsageError::invalid(
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

fn parse_plan(args: &[String]) -> Result<Option<Command>, UsageError> {
    match args.first().map(String::as_str) {
        None => Ok(Some(Command::Plan)),
        Some("-h" | "--help") => Ok(None),
        Some(other) => Err(reject("plan", other)),
    }
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
        return Err(UsageError::invalid("run: no command given", Some("run")));
    }
    let args = args.to_vec();
    Ok(Some(match name {
        "run" => Command::Run { command: args },
        _ => Command::Build { args },
    }))
}

fn parse_sbom(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut output = None;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "-o" | "--output" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    UsageError::invalid(format!("{arg} needs a file path"), Some("sbom"))
                })?;
                output = Some(PathBuf::from(value));
                index += 1;
            }
            _ if arg.starts_with("--output=") => {
                output = Some(non_empty(&arg["--output=".len()..], "--output", Some("sbom"))?);
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
                    return Err(UsageError::invalid(
                        "--register needs at least one project directory",
                        Some("gc"),
                    ));
                }
                continue;
            }
            _ if arg.starts_with("--register=") => {
                gc.register
                    .push(non_empty(&arg["--register=".len()..], "--register", Some("gc"))?);
            }
            "--keep-days" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::invalid("--keep-days needs <n>", Some("gc")))?;
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
        UsageError::invalid(
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
            return Err(UsageError::invalid(
                "store needs a subcommand: 'store path' or 'store roots'",
                Some("store"),
            ))
        }
        Some(other) => {
            return Err(UsageError::invalid(
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
        return Err(UsageError::invalid(
            format!("store {}: unexpected argument '{extra}'", args[0]),
            Some("store"),
        ));
    }
    Ok(Some(command))
}

fn non_empty(
    value: &str,
    flag: &str,
    command: Option<&'static str>,
) -> Result<PathBuf, UsageError> {
    if value.is_empty() {
        return Err(UsageError::invalid(format!("{flag}= needs a value"), command));
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
            spec.options.iter().flat_map(|(flag, _)| option_spellings(flag)),
        )
    } else {
        format!("{name}: unexpected argument '{arg}'")
    };
    UsageError::invalid(message, Some(name))
}

/// `"-o, --output <file>"` → `["-o", "--output"]`.
fn option_spellings(flag: &'static str) -> impl Iterator<Item = &'static str> {
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
    let budget = if word.len() >= 4 { (word.len() / 3).max(1) } else { 0 };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    fn run(words: &[&str]) -> Invocation {
        match parse(&argv(words)).unwrap() {
            Parsed::Run(invocation) => invocation,
            Parsed::Print(text) => panic!("expected a command, got text:\n{text}"),
        }
    }

    fn command(words: &[&str]) -> Command {
        run(words).command
    }

    fn printed(words: &[&str]) -> String {
        match parse(&argv(words)).unwrap() {
            Parsed::Print(text) => text,
            Parsed::Run(invocation) => panic!("expected text, got {invocation:?}"),
        }
    }

    fn error(words: &[&str]) -> UsageError {
        parse(&argv(words)).unwrap_err()
    }

    fn message(words: &[&str]) -> String {
        match error(words) {
            UsageError::Invalid { message, .. } => message,
            UsageError::NoCommand => panic!("expected an invalid-usage error"),
        }
    }

    #[test]
    fn no_arguments_is_a_usage_error_that_prints_usage() {
        assert_eq!(error(&[]), UsageError::NoCommand);
        assert_eq!(UsageError::NoCommand.render(), usage());
        // -C alone never counts as a command.
        assert_eq!(error(&["-C", "/tmp"]), UsageError::NoCommand);
    }

    #[test]
    fn help_and_version_at_every_level() {
        for words in [&["--help"][..], &["-h"], &["help"], &["help", "help"]] {
            assert_eq!(printed(words), usage(), "{words:?}");
        }
        for words in [&["--version"][..], &["-V"], &["version"], &["help", "version"]] {
            assert_eq!(printed(words), format!("blanket {VERSION}\n"), "{words:?}");
        }
        for spec in COMMANDS {
            assert_eq!(printed(&["help", spec.name]), help(spec), "help {}", spec.name);
            assert_eq!(printed(&[spec.name, "--help"]), help(spec), "{} --help", spec.name);
            assert_eq!(printed(&[spec.name, "-h"]), help(spec), "{} -h", spec.name);
        }
        // Help flags mixed into a flag-taking command still win.
        assert_eq!(printed(&["gc", "--dry-run", "--help"]), help(spec("gc").unwrap()));
        // Global options before the command are honored around help.
        assert_eq!(printed(&["-C", "/tmp", "--help"]), usage());
        assert!(message(&["help", "snyc"]).contains("did you mean 'sync'?"));
    }

    #[test]
    fn usage_lists_every_command_with_its_help() {
        let text = usage();
        for spec in COMMANDS {
            assert!(text.contains(&format!("  {}", spec.name)), "usage lacks {}", spec.name);
            let help = help(spec);
            assert!(help.starts_with(&format!("blanket {} — ", spec.name)));
            assert!(help.contains(spec.usage));
            for (flag, description) in spec.options {
                assert!(help.contains(flag) && help.contains(description), "{flag}");
            }
        }
        assert!(text.contains("BLANKET_STORE"));
        assert!(text.contains("requirements.txt"));
        assert!(text.contains("Exit status: 0 success, 1 failure, 2 usage error."));
    }

    #[test]
    fn sync_flags_are_validated() {
        assert_eq!(
            command(&["sync"]),
            Command::Sync {
                fresh: false,
                strict: false
            }
        );
        assert_eq!(
            command(&["sync", "--strict", "--fresh"]),
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
            message(&["sync", "--strict=1"]),
            "sync: unknown option '--strict=1'; did you mean '--strict'?"
        );
        assert_eq!(message(&["sync", "now"]), "sync: unexpected argument 'now'");
        assert_eq!(
            error(&["sync", "now"]).render(),
            "blanket: error: sync: unexpected argument 'now'\nRun 'blanket help sync' for usage.\n"
        );
    }

    #[test]
    fn plan_takes_nothing() {
        assert_eq!(command(&["plan"]), Command::Plan);
        assert_eq!(message(&["plan", "--json"]), "plan: unknown option '--json'");
        assert_eq!(message(&["plan", "x"]), "plan: unexpected argument 'x'");
    }

    #[test]
    fn run_and_build_pass_arguments_through() {
        assert_eq!(
            command(&["run", "python", "-c", "print(1)", "--help"]),
            Command::Run {
                command: argv(&["python", "-c", "print(1)", "--help"])
            }
        );
        assert_eq!(command(&["run", "--", "-h"]), Command::Run { command: argv(&["-h"]) });
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
        // `blanket build --release` must keep working: only a LEADING help
        // flag belongs to blanket.
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
        assert_eq!(message(&["sbom", "bom.json"]), "sbom: unexpected argument 'bom.json'");
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
    fn store_subcommands() {
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
    }

    #[test]
    fn unknown_commands_get_suggestions() {
        assert_eq!(
            message(&["snyc"]),
            "unknown command 'snyc'; did you mean 'sync'?"
        );
        assert_eq!(message(&["sy"]), "unknown command 'sy'; did you mean 'sync'?");
        assert_eq!(message(&["gcc"]), "unknown command 'gcc'; did you mean 'gc'?");
        assert_eq!(message(&["install"]), "unknown command 'install'");
        assert_eq!(
            error(&["install"]).render(),
            "blanket: error: unknown command 'install'\nRun 'blanket --help' for usage.\n"
        );
        assert_eq!(
            message(&["--fresh", "sync"]),
            "unknown option '--fresh'"
        );
        assert_eq!(
            message(&["--dir", "x", "sync"]),
            "unknown option '--dir'; did you mean '--directory'?"
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
        // After the command, -C belongs to the command (run passes it on).
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
        assert_eq!(run(&["--quiet", "--verbose", "plan"]).options.quiet, true);
        assert_eq!(
            message(&["--quite", "plan"]),
            "unknown option '--quite'; did you mean '--quiet'?"
        );
        // -v is verbose, -V is version: both exist, neither is a typo of the other.
        assert_eq!(printed(&["-V"]), format!("blanket {VERSION}\n"));
        assert!(run(&["-v", "plan"]).options.verbose);
        // After the command they belong to the command.
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
        // An exact match is a suggestion too: it is how `--strict=1` learns
        // that `--strict` takes no value.
        assert_eq!(suggest("sync", commands()), Some("sync"));
        assert_eq!(suggest("SYNC", commands()), Some("sync"));
        assert_eq!(suggest("s", commands()), None); // one letter is not a typo
        assert_eq!(suggest("gcx", commands()), Some("gc")); // prefix relation
        assert_eq!(suggest("gxc", commands()), None); // short words: no edit guesses
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
}

//! The command surface: one grammar for every `blanket` invocation.
//!
//! This module is pure — it never touches the store, the filesystem, or the
//! host platform — so every shape of argv is unit-testable and `main` is a
//! thin dispatcher. Rules the grammar enforces, none of them silently:
//!
//! - every option is validated: an unknown flag or stray positional is a
//!   usage error (exit 2) with a "did you mean" suggestion when one is close;
//! - `blanket help [<command>]`, `--help`/`-h`, `--version`/`-V` work at the
//!   top level and `-h`/`--help` inside every command, first argument only
//!   where the rest is passed through (`fmt`, `run`, `build`);
//! - `run` and `build` pass their arguments through to the program untouched
//!   (only a leading `-h`/`--help` is blanket's; `--` forces pass-through);
//! - `-C <dir>` runs the command as if started in `<dir>`; `-q`, `-v` and
//!   `--no-color` set the output conventions (see `ui`);
//! - a bare `blanket` and an unknown first word are *not* decided here: the
//!   dispatcher turns them into `sync` inside a project and into a
//!   package.json script run when one matches.
//!
//! Exit status contract: 0 success, 1 the command failed, 2 usage error.

mod completions;
mod parse;
mod spec;

pub use self::completions::completions;
pub use self::parse::{option_spellings, parse, suggest};
pub use self::spec::{
    canonical_name, help, spec, usage, BUILD_WORDS, COMMANDS, LS_WORDS, SHELL_WORDS, SYNC_ALIASES,
};

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
    /// `audit [--policy <file>] [--json]`: judge the recorded closures
    /// against the policy chain unioned with `policy`.
    Audit {
        policy: Option<PathBuf>,
        json: bool,
    },
    Ls {
        ecosystem: Option<String>,
        json: bool,
    },
    Doctor {
        json: bool,
    },
    /// `keygen <path>`: write a new closure-signing key file and print its
    /// public key in policy syntax.
    Keygen {
        path: PathBuf,
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
    pub migrate_metadata: bool,
    pub register: Vec<PathBuf>,
    pub forget: Vec<String>,
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

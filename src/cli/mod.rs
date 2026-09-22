//! The command surface: one grammar for every `tog` invocation.
//!
//! This module is pure — it never touches the store, the filesystem, or the
//! host platform — so every shape of argv is unit-testable and `main` is a
//! thin dispatcher. Rules the grammar enforces, none of them silently:
//!
//! - every option is validated: an unknown flag or stray positional is a
//!   usage error (exit 2) with a "did you mean" suggestion when one is close;
//! - `tog help [<command>]`, `--help`/`-h`, `--version`/`-V` work at the
//!   top level and `-h`/`--help` inside every command, first argument only
//!   where the rest is passed through (`fmt`, `run`, `build`);
//! - `run` and `build` pass their arguments through to the program untouched
//!   (only a leading `-h`/`--help` is tog's; `--` forces pass-through);
//! - `-C <dir>` runs the command as if started in `<dir>`; `-q`, `-v` and
//!   `--no-color` set the output conventions (see `ui`). A global option is
//!   accepted before or after the verb, except where the rest of argv
//!   belongs to a program (`run`, `build`) or to a tool (`fmt`, `x`, after
//!   its own options);
//! - a bare `tog` and an unknown first word are *not* decided here: the
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
        /// Validate the committed `tog-toolchain.toml` instead of creating
        /// one, and refuse a missing or stale lock before anything is
        /// written.
        frozen: bool,
    },
    Fmt {
        check: bool,
        ecosystem: Option<String>,
        args: Vec<String>,
    },
    Plan {
        json: bool,
    },
    /// Everything after `build` (ecosystem name and tool arguments); the
    /// ecosystem is inferred by the dispatcher from the project layout.
    Build {
        args: Vec<String>,
    },
    /// The program (or package.json script) and its arguments.
    Run {
        command: Vec<String>,
    },
    /// `env [--shell <shell>]`: the environment `run` would give a child,
    /// printed as shell assignments. `None` leaves the choice to the
    /// command, which reads `$SHELL`: the grammar stays pure.
    Env {
        shell: Option<Shell>,
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
    /// `update [<package>...]` re-locks dependencies; `update --toolchain
    /// [<ecosystem>]` re-selects the toolchain instead. The two never mix:
    /// `toolchain` is `Some` exactly when `names` is empty and the
    /// dependency locks are left alone.
    Update {
        names: Vec<String>,
        no_sync: bool,
        toolchain: Option<ToolchainUpdate>,
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

impl Command {
    /// Did this invocation ask for machine-readable output? Under `--json`
    /// stdout carries nothing but the JSON document and a failure is a JSON
    /// object on stderr, so a script never has to parse prose.
    pub fn json_output(&self) -> bool {
        matches!(
            self,
            Command::Status { json: true }
                | Command::Audit { json: true, .. }
                | Command::Ls { json: true, .. }
                | Command::Doctor { json: true }
                | Command::Plan { json: true }
        )
    }
}

/// Which toolchains `update --toolchain` re-selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainUpdate {
    /// The `[toolchain.<name>]` section key when one was named; `None`
    /// updates every ecosystem discovery finds in the project, which is how
    /// a newly added ecosystem gains its section.
    pub ecosystem: Option<String>,
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
    /// Store object ids to remove outright, with their records. The recovery
    /// path for a record the sweep cannot read; see `kernel::gc::drop`.
    pub drop_objects: Vec<String>,
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
    /// `tog` with no command: `sync` inside a project, usage outside.
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
        Some(name) => format!("Run 'tog help {name}' for usage."),
        None => "Run 'tog --help' for usage.".to_string(),
    };
    format!("tog: error: {message}\n{hint}\n")
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

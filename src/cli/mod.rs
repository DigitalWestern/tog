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
//! - `--frozen` and `--strict` (`SyncFlags`) govern a sync, so a verb that
//!   never syncs refuses them instead of accepting and ignoring them;
//! - a bare `tog` and an unknown first word are *not* decided here: the
//!   dispatcher turns a bare `tog` into `sync` inside a project (and prints
//!   `usage()` after a sync that succeeded, so the first word a newcomer
//!   types also shows them the rest), into the help outside one, and an
//!   unknown first word into a package.json script run when one matches.
//!   A bare `tog` with `--frozen`, `--fresh` or `--strict` is decided here:
//!   it is `sync` with those flags, and no help follows it. `sync`,
//!   `install` and `i` still parse as that command but are never listed,
//!   completed, or suggested (`Group::Bare`).
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
/// The short commit id and the commit date the binary was built from,
/// stamped by `build.rs`; `unknown` outside a git checkout.
pub const BUILD_COMMIT: &str = env!("TOG_BUILD_COMMIT");
pub const BUILD_DATE: &str = env!("TOG_BUILD_DATE");

/// What `tog --version` prints, without the newline: `tog 0.1.0 (7688cfd
/// 2026-09-21)`. The crate version alone cannot say whether a binary is
/// stale, because every local build of the same crate version prints the
/// same number; the commit and its date can. `install.sh` prints this
/// whole line when it replaces a binary; `update --self` and `doctor`
/// compare the crate version only, because a release does not name the
/// commit it was built from.
pub fn version_line() -> String {
    match (BUILD_COMMIT, BUILD_DATE) {
        ("unknown", "unknown") => format!("tog {VERSION} (unknown build)"),
        (commit, date) => format!("tog {VERSION} ({commit} {date})"),
    }
}
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// The bare `tog` (and its hidden names `sync`, `install`, `i`).
    /// `--frozen` and `--strict` travel beside it in `SyncFlags`.
    Sync {
        fresh: bool,
    },
    /// `fmt` syncs when it is a package.json script delegated to `run`, so
    /// it takes `SyncFlags` ahead of the tool's own arguments.
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
    /// `SyncFlags` typed before the verb govern the implicit sync, never
    /// the build itself.
    Build {
        args: Vec<String>,
    },
    /// The program (or package.json script) and its arguments. `SyncFlags`
    /// typed before the verb govern the implicit sync, never the program.
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
    /// `--strict` governs the sync that follows the edit. `--frozen` is
    /// refused with `add`, `remove` and `update`, which exist to write the
    /// lock that `--frozen` only checks.
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
    /// `update --self`: replace this binary with the newest GitHub release.
    /// Its own variant rather than a third mode of `Update`: it needs no
    /// project, no store, and no signing key, and the dispatcher must be
    /// able to tell that apart without reading three fields.
    SelfUpdate,
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
    /// `--frozen` and `--strict`. Accepted before the verb, and after it
    /// except for the pass-through verbs `run` and `build`, which hand
    /// everything after the verb to the program. A verb that never syncs
    /// refuses them.
    pub sync: SyncFlags,
}

/// `--frozen` and `--strict`: the two flags that govern a sync wherever one
/// happens (the bare `tog`, the implicit sync of `run`, `env`, `build`,
/// `fmt` and a script, the sync after `add`/`remove`/`update`, `plan`'s
/// lock generation, and the policy `x` judges under). Read once by the
/// parser from either side of the verb and handed to the dispatcher, which
/// passes `--frozen` to the verbs and records `--strict` for every policy
/// load in the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncFlags {
    /// `--frozen`: validate the committed `tog-toolchain.toml` instead of
    /// creating one, never generate a dependency lock, and refuse a missing
    /// or stale lock before anything is written.
    pub frozen: bool,
    /// `--strict`: refuse every policy exception (same as `TOG_STRICT=1`).
    pub strict: bool,
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
    /// The hidden `__resolution-relay`: the first process inside the
    /// resolution door's sandbox. tog starts it; nobody types it, so it is
    /// never listed, completed, or suggested, and it takes no global option.
    Relay(RelayInvocation),
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

/// `__resolution-relay [--exec-log-fd <n>] [--env-fd <n>] <socket> <address> -- <tool>...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayInvocation {
    pub socket: String,
    pub listen: String,
    pub exec_log_fd: Option<i32>,
    pub env_fd: Option<i32>,
    pub argv: Vec<String>,
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
        // The bare form's hidden name is not what its help is called.
        Some("sync") => "Run 'tog help setup' for usage.".to_string(),
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
    /// The bare `tog`. Its flags and help live under the hidden name
    /// `sync` (aliases `install`, `i`), which still parses so a pip or npm
    /// reflex and existing CI keep working, but is never listed,
    /// completed, or suggested.
    Bare,
}

/// Static description of one command: drives parsing suggestions, the help
/// text, and shell completions, so none of them can disagree.
pub struct Spec {
    pub name: &'static str,
    pub group: Group,
    pub summary: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
    /// `(command line, one-line gloss)`, printed under EXAMPLES before the
    /// options. Every command has at least one, and each one is a line that
    /// works as written: the examples are the part of a help screen a
    /// newcomer reads first.
    pub examples: &'static [(&'static str, &'static str)],
    /// `(flag spelling, description)`; each comma-separated spelling's
    /// first token (before a space or `=`) is what suggestions match.
    pub options: &'static [(&'static str, &'static str)],
    /// Fixed positional words, for completion (`store path|roots`).
    pub words: &'static [&'static str],
}

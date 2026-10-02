//! The runtime tripwire behind `kernel::supervise`'s `local_*` functions.
//!
//! A host-local helper is a child that needs no network: `tar`, `cp`,
//! `patch`, an offline extraction. A dependency tool is not one of those
//! unless its whole invocation says so in a form listed below: the exact
//! argv shape of the one reviewed call site, the tog-owned helper script it
//! runs (checked by content), and the environment the child will really
//! see (the command's explicit edits over tog's own environment), with
//! every variable that could turn the network or an interpreter option back
//! on pinned or absent. Every other start of a resolver program is refused,
//! so a new call site that should have gone through the door fails the
//! first time it runs instead of reaching the network.
//!
//! A program counts as a resolver by the name it is started under
//! (case-insensitively, since macOS file systems are) and by the file that
//! name resolves to, so a symlink or a `PATH` entry under another name does
//! not hide one. A copy or a hard link under another name does: the check
//! reads names, not file contents. It catches a call site written the wrong
//! way by mistake; it is not a sandbox against code that means to hide a
//! resolver.
//!
//! `RESOLVERS` names programs, not wrappers. `sh -c`, `env`, `bwrap` and
//! `sandbox-exec` pass by design (a `tog run` script is `sh -c`), so a
//! resolver started through one is not seen.

use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// The file names of every dependency tool tog runs, and of the programs
/// that can fetch or install one. `git` is here because a resolver can
/// reach it (npm and cargo git dependencies); tog's own verified git
/// fetches go through `kernel::gitsrc`, not a `local_*` call. `rustup`,
/// `uvx`, `corepack`, `node`, `yarn`, `rebar3`, `pip`, `pip3`, `bundler`
/// and `iex` can each download or run project code, and no host-local
/// helper runs any of them, so they are refused outright.
pub const RESOLVERS: &[&str] = &[
    "uv", "uvx", "pip", "pip3", "npm", "npx", "pnpm", "yarn", "corepack", "node", "cargo",
    "rustup", "go", "bundle", "bundler", "gem", "ruby", "mix", "elixir", "iex", "erl", "rebar3",
    "dotnet", "git",
];

/// The expression the Elixir tailor's staged-OTP probe evaluates: load
/// crypto and ssl and print the release and root. It lives here, in the
/// reviewed table, so the one `erl` form a host-local helper may run is
/// exactly this text and nothing a later edit slips in beside it.
pub const OTP_RUNTIME_PROBE: &str = "ok = crypto:start(), \
             32 = byte_size(crypto:hash(sha256, <<\"tog\">>)), \
             {ok, _} = application:ensure_all_started(ssl), \
             true = is_list(ssl:versions()), \
             io:format(\"~s~n~s~n\", [erlang:system_info(otp_release), code:root_dir()]), \
             halt(0).";

/// The sha256 of the Ruby tailor's helper script, the only script the
/// `ruby ... spec` form may run. The tailor's test pins it to the text it
/// writes, so editing the helper means reviewing this table again.
pub const RUBY_HELPER_SHA256: &str =
    "4743cea01d2cbac47bd61f579904cf4e6bbcf82bc5452b8bbb039e939c33f6e3";

/// The sha256 of the Elixir tailor's helper script, the only script the
/// `elixir ... hexmark` form may run. Pinned by the tailor's test, as for
/// Ruby.
pub const ELIXIR_HELPER_SHA256: &str =
    "aab9cac87d2f2ae4dc292d033ee35910d687dfdd897073d0f601509db9aef40f";

/// The Elixir tailor's environment scrub, which it uses for every BEAM run:
/// every variable with one of these prefixes (compared case-insensitively)
/// or names is removed, then the forced ones are set. They live here so the
/// `hexmark` form checks exactly what the tailor removes.
pub const ELIXIR_ENV_REMOVE_PREFIXES: &[&str] = &["MIX_", "HEX_", "REBAR_", "ERL_", "ELIXIR_"];
pub const ELIXIR_ENV_REMOVE: &[&str] =
    &["ERTS_BIN", "RUN_ERL_PIPE", "RUN_ERL_LOG", "ERLC_USE_SERVER"];

/// Every variable the Elixir tailor forces after the scrub (its test holds
/// it to the tailor's list), and the ones among them that name a path.
pub const ELIXIR_FORCED: &[&str] = &[
    "MIX_DEPS_PATH",
    "MIX_ARCHIVES",
    "MIX_REBAR3",
    "MIX_HOME",
    "HEX_HOME",
    "HEX_OFFLINE",
    "MIX_TARGET",
];
/// The Ruby tailor's environment scrub and forced variables, shared the
/// same way for the `spec` form.
pub const RUBY_ENV_REMOVE_PREFIXES: &[&str] = &["BUNDLE_", "BUNDLER_"];
pub const RUBY_ENV_REMOVE: &[&str] = &[
    "RUBYOPT",
    "RUBYLIB",
    "RUBYGEMS_GEMDEPS",
    "GEM_SPEC_CACHE",
    "GEM_HOME",
    "GEM_PATH",
];
pub const RUBY_FORCED: &[&str] = &[
    "GEM_HOME",
    "GEM_PATH",
    "BUNDLE_IGNORE_CONFIG",
    "BUNDLE_GEMFILE",
    "BUNDLE_FROZEN",
    "BUNDLE_DISABLE_SHARED_GEMS",
    "BUNDLE_AUTO_INSTALL",
    "BUNDLE_DISABLE_VERSION_CHECK",
    "GEMRC",
];

const ELIXIR_FORCED_PATHS: &[&str] = &[
    "MIX_DEPS_PATH",
    "MIX_ARCHIVES",
    "MIX_REBAR3",
    "MIX_HOME",
    "HEX_HOME",
];

/// What a form sees of one invocation: the arguments after the program,
/// its working directory, its explicit environment edits (`None` is a
/// removed variable), the file it would execute and the store it runs for
/// (both canonical, `None` when they do not resolve).
struct Invocation<'a> {
    args: Vec<&'a OsStr>,
    cwd: Option<&'a Path>,
    env: Vec<(&'a OsStr, Option<&'a OsStr>)>,
    program: Option<PathBuf>,
    /// Whether the command names its program by an absolute path. A bare
    /// name is resolved here through tog's `PATH`, which an `env_clear`ed
    /// child does not use, so no form admits one.
    absolute: bool,
    store: Option<PathBuf>,
}

impl Invocation<'_> {
    /// The command's own edit of `key`: `Some(None)` when it removes the
    /// variable, `None` when it leaves the inherited value alone.
    fn edit(&self, key: &str) -> Option<Option<&OsStr>> {
        self.env
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    }

    /// Whether the command itself sets `key` to exactly `value`, whatever
    /// tog's own environment holds.
    fn set_to(&self, key: &str, value: &str) -> bool {
        self.edit(key) == Some(Some(OsStr::new(value)))
    }

    /// Whether the command itself removes `key`.
    fn removed(&self, key: &str) -> bool {
        self.edit(key) == Some(None)
    }

    /// Whether `path` names something inside the store: absolute, with no
    /// `..`, and under the store root once the part of it that exists is
    /// resolved (so a symlink out of the store does not count). The part
    /// that does not exist yet is a directory the child will create.
    fn under_store(&self, path: &Path) -> bool {
        let Some(store) = self.store.as_deref() else {
            return false;
        };
        if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
            return false;
        }
        let mut existing = path;
        let mut tail = Vec::new();
        loop {
            if let Ok(real) = existing.canonicalize() {
                let full = tail.iter().rev().fold(real, |full, part| full.join(part));
                return full.starts_with(store) && full != store;
            }
            match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    tail.push(name);
                    existing = parent;
                }
                _ => return false,
            }
        }
    }

    /// Whether the command itself sets `key` to one path inside the store
    /// (not a `:`-separated list that could append another).
    fn set_under_store(&self, key: &str) -> bool {
        matches!(self.edit(key), Some(Some(value))
            if !value.to_string_lossy().contains(':') && self.under_store(Path::new(value)))
    }

    /// Whether the program is a realized store object, named by absolute
    /// path: never a tool found on the host (a version-manager shim, a
    /// rustup proxy), and never a staged file under `<store>/tmp`, where
    /// unpacked packages and in-flight downloads also land.
    fn program_in_store(&self) -> bool {
        self.program_under_store(&["objects"])
    }

    /// Whether the program is a store file under one of the top-level
    /// store directories `tops`, named by absolute path.
    fn program_under_store(&self, tops: &[&str]) -> bool {
        let (Some(program), Some(store)) = (self.program.as_deref(), self.store.as_deref()) else {
            return false;
        };
        self.absolute
            && self.under_store(program)
            && program.strip_prefix(store).is_ok_and(|inside| {
                matches!(inside.components().next(), Some(Component::Normal(top)) if tops.iter().any(|allowed| top == *allowed))
            })
    }

    /// The value the child sees for `key`: the command's own edit, or else
    /// tog's environment, which the child inherits. `Command::env_clear`
    /// is not visible here, so a form that needs a variable gone requires
    /// it removed explicitly; a cleared command is judged as if it
    /// inherited, which can only refuse more.
    fn effective(&self, key: &str) -> Option<OsString> {
        match self.env.iter().find(|(name, _)| *name == key) {
            Some((_, value)) => value.map(OsStr::to_os_string),
            None => std::env::var_os(key),
        }
    }

    /// Whether the child sees no variable of a scrubbed family (a name
    /// with one of `prefixes`, compared case-insensitively, or one of
    /// `names`) except the `forced` ones the command itself sets: each
    /// inherited one is edited by the command, and every one it sets is
    /// forced.
    fn family_clean(&self, prefixes: &[&str], names: &[&str], forced: &[&str]) -> bool {
        let in_family = |name: &OsStr| {
            let name = name.to_string_lossy();
            names.contains(&name.as_ref())
                || prefixes.iter().any(|prefix| {
                    name.get(..prefix.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                })
        };
        let sets_only_forced = self.env.iter().all(|(name, value)| {
            !in_family(name) || value.is_none() || forced.iter().any(|key| *name == *key)
        });
        let inherits_none = std::env::vars_os().all(|(name, _)| {
            !in_family(&name) || self.env.iter().any(|(edited, _)| *edited == name)
        });
        sets_only_forced && inherits_none
    }

    /// Whether the command itself edits every variable tog has, so the
    /// child inherits nothing.
    fn fully_cleared(&self) -> bool {
        std::env::vars_os().all(|(name, _)| self.env.iter().any(|(edited, _)| *edited == name))
    }

    /// Whether every variable the command itself sets is one of `allowed`.
    fn sets_only(&self, allowed: &[&str]) -> bool {
        self.env
            .iter()
            .all(|(name, value)| value.is_none() || allowed.iter().any(|key| *name == *key))
    }

    /// Whether the command itself sets `PATH`, every entry is in the store
    /// or is `/usr/bin` or `/bin`, and every store entry comes before the
    /// system ones: no version-manager shim or user directory can answer
    /// for a program the child starts by name, and no host program can
    /// shadow a store one.
    fn path_confined(&self) -> bool {
        let Some(Some(path)) = self.edit("PATH") else {
            return false;
        };
        let mut system_seen = false;
        std::env::split_paths(path).all(|dir| {
            if dir == Path::new("/usr/bin") || dir == Path::new("/bin") {
                system_seen = true;
                true
            } else {
                !system_seen && self.under_store(&dir)
            }
        })
    }

    /// Argument `index` as text, when it is valid UTF-8.
    fn arg(&self, index: usize) -> Option<&str> {
        self.args.get(index).and_then(|arg| arg.to_str())
    }

    /// Whether no argument from `from` on could be read as an option.
    fn no_options_from(&self, from: usize) -> bool {
        self.args
            .iter()
            .skip(from)
            .all(|arg| !arg.to_string_lossy().starts_with('-'))
    }

    /// Whether argument `index` is an absolute path to a regular file named
    /// `name` inside the store whose content has sha256 `expected`: the
    /// tog-owned helper, in a directory only tog writes.
    fn is_helper(&self, index: usize, name: &str, expected: &str) -> bool {
        let Some(path) = self.args.get(index).map(Path::new) else {
            return false;
        };
        if !path.is_absolute()
            || path.file_name() != Some(OsStr::new(name))
            || !self.under_store(path)
        {
            return false;
        }
        match std::fs::read(path) {
            Ok(bytes) => hex::encode(Sha256::digest(&bytes)) == expected,
            Err(_) => false,
        }
    }
}

/// One reviewed offline form: a resolver program, and the invocation under
/// which it reaches no network and runs nothing but tog's own code.
struct OfflineForm {
    program: &'static str,
    matches: fn(&Invocation) -> bool,
}

/// Go variables that must be pinned for an extraction to stay offline: no
/// proxy, no checksum database, no toolchain switch, no config file, no
/// workspace, no version-control fetch, no auth helper.
const GO_OFFLINE_PINNED: &[(&str, &str)] = &[
    ("GOPROXY", "off"),
    ("GOSUMDB", "off"),
    ("GOTOOLCHAIN", "local"),
    ("GOENV", "off"),
    ("GOWORK", "off"),
    ("GOVCS", "*:off"),
    ("GOAUTH", "off"),
];

/// Go variables that must be removed: each can route a module around
/// `GOPROXY=off` (`GONOPROXY`, `GOPRIVATE`), relax verification
/// (`GONOSUMDB`, `GOINSECURE`), add flags (`GOFLAGS`), or run a program
/// (`GOCACHEPROG`).
const GO_OFFLINE_UNSET: &[&str] = &[
    "GOFLAGS",
    "GONOPROXY",
    "GOPRIVATE",
    "GONOSUMDB",
    "GOINSECURE",
    "GOCACHEPROG",
];

/// What each form's command may set itself, beyond what it removes. A
/// form admits no other variable, so a caller cannot add `LD_PRELOAD`,
/// `LD_LIBRARY_PATH`, or a tool setting outside the checked families.
const GO_OFFLINE_SETS: &[&str] = &[
    "GOAUTH",
    "GOENV",
    "GOMODCACHE",
    "GOPROXY",
    "GOROOT",
    "GOSUMDB",
    "GOTOOLCHAIN",
    "GOVCS",
    "GOWORK",
    "HOME",
];
const ELIXIR_HEXMARK_SETS: &[&str] = &[
    "HEX_HOME",
    "HEX_OFFLINE",
    "HOME",
    "MIX_ARCHIVES",
    "MIX_DEPS_PATH",
    "MIX_HOME",
    "MIX_REBAR3",
    "MIX_TARGET",
    "PATH",
    "TMPDIR",
];
const RUBY_SPEC_SETS: &[&str] = &[
    "BUNDLE_AUTO_INSTALL",
    "BUNDLE_DISABLE_SHARED_GEMS",
    "BUNDLE_DISABLE_VERSION_CHECK",
    "BUNDLE_FROZEN",
    "BUNDLE_GEMFILE",
    "BUNDLE_IGNORE_CONFIG",
    "GEMRC",
    "GEM_HOME",
    "GEM_PATH",
    "HOME",
    "PATH",
];

/// The Cargo tailor's workspace lookup, argument for argument.
const CARGO_LOCATE_PROJECT: &[&str] = &[
    "locate-project",
    "--workspace",
    "--message-format",
    "plain",
    "--offline",
];

/// `cargo locate-project` as the Cargo tailor builds it: the store Cargo
/// with rustup's toolchain selection removed.
fn cargo_locate_project(run: &Invocation) -> bool {
    run.args.len() == CARGO_LOCATE_PROJECT.len()
        && CARGO_LOCATE_PROJECT
            .iter()
            .enumerate()
            .all(|(index, expected)| run.arg(index) == Some(*expected))
        && run.program_in_store()
        && run.sets_only(&[])
        && run.removed("RUSTUP_HOME")
        && run.removed("RUSTUP_TOOLCHAIN")
}

/// `go mod download` of module versions as the Go tailor builds it. Every
/// variable is the command's own edit, never tog's inherited one: pinned
/// ones set, the rest removed rather than emptied (Go reads an empty value
/// as unset and falls back to `$GOROOT/go.env`), and `GOROOT` the store
/// toolchain the program belongs to, so that fallback is the store's file.
/// `HOME` in the store and `XDG_CONFIG_HOME` removed keep the user's Go
/// configuration (telemetry upload among it) out.
fn go_mod_download(run: &Invocation) -> bool {
    let goroot_is_the_programs = || {
        let Some(Some(goroot)) = run.edit("GOROOT") else {
            return false;
        };
        let toolchain = run
            .program
            .as_deref()
            .and_then(Path::parent)
            .and_then(Path::parent);
        toolchain.is_some() && Path::new(goroot).canonicalize().ok().as_deref() == toolchain
    };
    run.arg(0) == Some("mod")
        && run.arg(1) == Some("download")
        && run.args.len() > 2
        && run.no_options_from(2)
        && run
            .args
            .iter()
            .skip(2)
            .all(|arg| arg.to_string_lossy().contains('@'))
        && run.program_in_store()
        && run.sets_only(GO_OFFLINE_SETS)
        && goroot_is_the_programs()
        && GO_OFFLINE_PINNED
            .iter()
            .all(|(key, value)| run.set_to(key, value))
        && GO_OFFLINE_UNSET.iter().all(|key| run.removed(key))
        && run.set_under_store("GOMODCACHE")
        && run.set_under_store("HOME")
        && run.removed("XDG_CONFIG_HOME")
}

/// The Elixir helper's `hexmark` mode as the Elixir tailor builds it: the
/// store `elixir` running the pinned helper over a dependency in the store.
/// The scrubbed family carries only the forced variables (no `ERL_*`,
/// `ELIXIR_*` or `ERTS_BIN` to add code or pick another `erl`), with
/// `HEX_OFFLINE=1`; `PATH` holds only the store and `/usr/bin`, `/bin`
/// (the `elixir` script starts `erl` by name); and `HOME` in the store with
/// `XDG_CONFIG_HOME` removed keeps a user `.erlang` from running.
fn elixir_hexmark(run: &Invocation) -> bool {
    run.args.len() == 8
        && run.is_helper(0, "helper.exs", ELIXIR_HELPER_SHA256)
        && run.arg(1) == Some("hexmark")
        && run.no_options_from(1)
        && run.under_store(Path::new(run.args[2]))
        && run.program_in_store()
        && run.sets_only(ELIXIR_HEXMARK_SETS)
        && run.family_clean(ELIXIR_ENV_REMOVE_PREFIXES, ELIXIR_ENV_REMOVE, ELIXIR_FORCED)
        && run.set_to("HEX_OFFLINE", "1")
        && run.set_to("MIX_TARGET", "host")
        && ELIXIR_FORCED_PATHS
            .iter()
            .all(|key| run.set_under_store(key))
        && run.path_confined()
        && run.set_under_store("HOME")
        && run.set_under_store("TMPDIR")
        && run.removed("XDG_CONFIG_HOME")
}

/// The staged-OTP probe as the Elixir tailor builds it: the staged `erl`
/// evaluating exactly the reviewed expression, in an environment the
/// command empties itself and then gives only `PATH` (store and `/usr/bin`,
/// `/bin`), `HOME` and `TMPDIR` in the store, and `LANG=C`. No `ERL_*`
/// variable can add an `-eval`, and no `XDG_CONFIG_HOME` or user `HOME`
/// can supply a `.erlang` boot file.
fn otp_probe(run: &Invocation) -> bool {
    run.args.len() == 3
        && run.arg(0) == Some("-noshell")
        && run.arg(1) == Some("-eval")
        && run.arg(2) == Some(OTP_RUNTIME_PROBE)
        // The one form that runs a staged program: the OTP release being
        // checked before it becomes an object.
        && run.program_under_store(&["tmp"])
        && run.fully_cleared()
        && run.sets_only(&["PATH", "HOME", "TMPDIR", "LANG"])
        && run.path_confined()
        && run.set_under_store("HOME")
        && run.set_under_store("TMPDIR")
        && run.set_to("LANG", "C")
}

/// The Ruby helper's `spec` mode as the Ruby tailor builds it: the store
/// `ruby` running the pinned helper over a `.gem` in the store. The
/// scrubbed family carries only the forced variables (no `RUBYOPT`,
/// `RUBYLIB` or `RUBYGEMS_GEMDEPS`), every one of them set; `GEM_HOME` and
/// `GEM_PATH` are in the store, so RubyGems activates no gem from
/// elsewhere at startup; `GEMRC=/dev/null` and `HOME` in the store keep a
/// user `.gemrc` out; and the store Ruby comes first on `PATH`.
fn ruby_spec(run: &Invocation) -> bool {
    let ruby_first_on_path = || {
        let Some(Some(path)) = run.edit("PATH") else {
            return false;
        };
        let first = std::env::split_paths(path).next();
        let bin = run.program.as_deref().and_then(Path::parent);
        bin.is_some() && first.and_then(|dir| dir.canonicalize().ok()).as_deref() == bin
    };
    run.args.len() == 3
        && run.is_helper(0, "helper.rb", RUBY_HELPER_SHA256)
        && run.arg(1) == Some("spec")
        && run.no_options_from(1)
        && run.under_store(Path::new(run.args[2]))
        && run.program_in_store()
        && run.sets_only(RUBY_SPEC_SETS)
        && run.family_clean(RUBY_ENV_REMOVE_PREFIXES, RUBY_ENV_REMOVE, RUBY_FORCED)
        && run.set_to("BUNDLE_IGNORE_CONFIG", "1")
        && run.set_to("BUNDLE_AUTO_INSTALL", "false")
        && run.set_to("BUNDLE_DISABLE_SHARED_GEMS", "true")
        && run.set_to("BUNDLE_DISABLE_VERSION_CHECK", "true")
        && (run.set_to("BUNDLE_FROZEN", "true") || run.set_to("BUNDLE_FROZEN", "false"))
        && RUBY_FORCED
            .iter()
            .all(|key| matches!(run.edit(key), Some(Some(_))))
        && run.set_under_store("GEM_HOME")
        && run.set_under_store("GEM_PATH")
        && run.set_to("GEMRC", "/dev/null")
        && run.set_under_store("HOME")
        && ruby_first_on_path()
}

const OFFLINE_FORMS: &[OfflineForm] = &[
    // The Cargo tailor's workspace lookup: the store Cargo (a rustup proxy
    // could install a toolchain the project names), forbidden the network.
    OfflineForm {
        program: "cargo",
        matches: cargo_locate_project,
    },
    // The Go tailor's module extraction: `go mod download path@version...`
    // by the store Go from a module cache tog staged, with the complete
    // offline environment.
    OfflineForm {
        program: "go",
        matches: go_mod_download,
    },
    // The Elixir helper's `hexmark` mode: writes a verified dependency's
    // .hex marker.
    OfflineForm {
        program: "elixir",
        matches: elixir_hexmark,
    },
    // The staged-OTP probe: loads crypto and ssl and prints two lines.
    OfflineForm {
        program: "erl",
        matches: otp_probe,
    },
    // The Ruby helper's `spec` mode: reads the gemspec of a .gem tog
    // already verified.
    OfflineForm {
        program: "ruby",
        matches: ruby_spec,
    },
];

/// The resolver names `name` matches, compared case-insensitively.
fn resolver_named(name: &OsStr) -> Option<&'static str> {
    let name = name.to_string_lossy();
    RESOLVERS
        .iter()
        .copied()
        .find(|resolver| resolver.eq_ignore_ascii_case(&name))
}

/// The file `command` would execute, resolved the way `execvp` does: a
/// program with a `/` is a path (relative to the command's directory), and
/// a bare name is looked up on the child's `PATH`, skipping entries that
/// are not executable files. `None` when nothing resolves.
fn resolved_program(command: &Command, run: &Invocation) -> Option<PathBuf> {
    let program = Path::new(command.get_program());
    let base = run
        .cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())?;
    if program.components().count() > 1 || program.is_absolute() {
        return base.join(program).canonicalize().ok();
    }
    let path = run.effective("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| base.join(dir).join(program))
        .find(|candidate| is_executable_file(candidate))
        .and_then(|found| found.canonicalize().ok())
}

/// Whether `path` is a regular file with an execute bit, the files
/// `execvp` would run from a `PATH` search.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// The refusal for `command`, run for the store at `store_root`, when it
/// starts a resolver outside every offline form; `None` when a host-local
/// helper may run it.
pub(crate) fn refusal(command: &Command, store_root: &Path) -> Option<io::Error> {
    let mut run = Invocation {
        args: command.get_args().collect(),
        cwd: command.get_current_dir(),
        env: command.get_envs().collect(),
        program: None,
        absolute: Path::new(command.get_program()).is_absolute(),
        store: store_root.canonicalize().ok(),
    };
    run.program = resolved_program(command, &run);
    let supplied = Path::new(command.get_program())
        .file_name()
        .unwrap_or_else(|| command.get_program());
    let mut names: Vec<&'static str> = Vec::new();
    names.extend(resolver_named(supplied));
    if let Some(resolved) = run.program.as_deref() {
        if let Some(name) = resolved.file_name().and_then(resolver_named) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    // Every resolver name the program answers to must be one of its own
    // offline forms: a `go` that is really `git` has no form.
    if names.iter().all(|name| {
        OFFLINE_FORMS
            .iter()
            .any(|form| form.program == *name && (form.matches)(&run))
    }) {
        return None;
    }
    Some(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is a dependency tool and must start through kernel::resolve's door, not as a host-local helper ({})",
            names.join("/"),
            crate::kernel::ui::shell_line(
                &std::iter::once(command.get_program())
                    .chain(run.args.iter().copied())
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            )
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::{store_program, TempDir};

    /// A scratch store holding a program at each path a test starts, so a
    /// form's store pin is met and only the property under test differs.
    struct Fixture(TempDir);

    impl Fixture {
        fn new(label: &str) -> Self {
            Self(TempDir::named(label))
        }

        /// `relative` inside the store, created as an executable script.
        fn program(&self, relative: &str) -> String {
            let path = store_program(&self.0 .0, relative);
            path.to_str().unwrap().to_string()
        }

        /// `relative` inside the store, not created.
        fn path(&self, relative: &str) -> String {
            self.0 .0.join(relative).to_str().unwrap().to_string()
        }

        fn refusal(&self, command: &Command) -> Option<io::Error> {
            refusal(command, &self.0 .0)
        }

        fn admits(&self, command: &Command) {
            if let Some(error) = self.refusal(command) {
                panic!("refused {command:?}: {error}");
            }
        }

        fn refused(&self, command: &Command) {
            let error = self.refusal(command).unwrap_or_else(|| {
                panic!(
                    "admitted {:?} {:?} {:?}",
                    command.get_program(),
                    command.get_args().collect::<Vec<_>>(),
                    command.get_envs().collect::<Vec<_>>()
                )
            });
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("kernel::resolve"), "{error}");
        }

        /// The Cargo tailor's workspace lookup, as it builds it.
        fn cargo_lookup(&self, program: &str) -> Command {
            let mut command = command(program, CARGO_LOCATE_PROJECT, &[]);
            command
                .env_remove("RUSTUP_HOME")
                .env_remove("RUSTUP_TOOLCHAIN");
            command
        }
    }

    fn command(program: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(program);
        command.args(args);
        for (key, value) in env {
            command.env(key, value);
        }
        command
    }

    /// The argv (and the environment each form reads) of every census row:
    /// every place tog runs a tool that resolves with the network or
    /// evaluates project code. Each goes through the door, and none of them
    /// may start through a `local_*` helper.
    #[test]
    fn every_resolver_invocation_goes_through_the_door() {
        let go_online = [
            ("GOPROXY", "https://proxy.golang.org"),
            ("GOSUMDB", "sum.golang.org"),
        ];
        let census: &[(&str, &[&str], &[(&str, &str)])] = &[
            // Python: requirements lock, build requirements, add/remove/update,
            // requirements.in edits, `tog x`.
            (
                "/s/uv/uv",
                &["pip", "compile", "requirements.in", "--generate-hashes"],
                &[],
            ),
            (
                "/s/uv/uv",
                &["pip", "compile", "--generate-hashes", "--no-build"],
                &[],
            ),
            ("/s/uv/uv", &["add", "--no-sync", "--", "requests"], &[]),
            ("/s/uv/uv", &["remove", "--no-sync", "--", "requests"], &[]),
            ("/s/uv/uv", &["lock", "--upgrade"], &[]),
            // An sdist's Rust extension with no Cargo.lock of its own.
            (
                "/s/rust/bin/cargo",
                &["generate-lockfile", "--manifest-path", "/stage/Cargo.toml"],
                &[],
            ),
            // Node: missing lock, add/remove/update, pinned pnpm, `tog x`.
            (
                "/s/node/bin/npm",
                &["install", "--package-lock-only", "--ignore-scripts"],
                &[],
            ),
            (
                "/s/node/bin/npm",
                &["uninstall", "--package-lock-only", "--ignore-scripts"],
                &[],
            ),
            (
                "/s/node/bin/npm",
                &["update", "--package-lock-only", "--ignore-scripts"],
                &[],
            ),
            (
                "/x/node_modules/.bin/pnpm",
                &["add", "--lockfile-only", "--ignore-scripts"],
                &[],
            ),
            // Cargo: missing lock and add/remove/update.
            ("/s/rust/bin/cargo", &["generate-lockfile"], &[]),
            (
                "/s/rust/bin/cargo",
                &["add", "--", "serde"],
                &[("CARGO_NET_OFFLINE", "false")],
            ),
            ("/s/rust/bin/cargo", &["remove", "--", "serde"], &[]),
            ("/s/rust/bin/cargo", &["update", "-p", "serde"], &[]),
            // Go: the tidy gate, tidy, the closure download, `go get`.
            ("/s/go/bin/go", &["mod", "tidy", "-diff"], &go_online),
            ("/s/go/bin/go", &["mod", "tidy"], &go_online),
            (
                "/s/go/bin/go",
                &["mod", "download", "-json", "all"],
                &go_online,
            ),
            ("/s/go/bin/go", &["get", "example.com/m@v1.0.0"], &go_online),
            // Ruby: `bundle lock`, both helper gates, add/remove/update.
            ("/s/ruby/bin/bundle", &["lock"], &[]),
            (
                "/s/ruby/bin/ruby",
                &["/stage/helper.rb", "check", "/p/Gemfile", "/p/Gemfile.lock"],
                &[],
            ),
            (
                "/s/ruby/bin/ruby",
                &["/stage/helper.rb", "plan", "/p/Gemfile.lock"],
                &[],
            ),
            (
                "/s/ruby/bin/bundle",
                &["add", "rails"],
                &[("BUNDLE_FROZEN", "false")],
            ),
            ("/s/ruby/bin/bundle", &["remove", "rails"], &[]),
            ("/s/ruby/bin/bundle", &["update", "--all"], &[]),
            // Elixir: missing lock, the check gate, the lock parser, update.
            ("/s/beam/elixir/bin/mix", &["deps.get"], &[]),
            (
                "/s/beam/elixir/bin/mix",
                &["deps.get", "--check-locked"],
                &[],
            ),
            (
                "/s/beam/elixir/bin/elixir",
                &["/stage/helper.exs", "lock", "/stage/mix.lock"],
                &[("HEX_OFFLINE", "1")],
            ),
            ("/s/beam/elixir/bin/mix", &["deps.update", "--all"], &[]),
            // .NET: missing lock.
            (
                "/s/sdk/dotnet",
                &[
                    "restore",
                    "--use-lock-file",
                    "--configfile",
                    "/stage/nuget.config",
                ],
                &[],
            ),
        ];
        // Each row is started from a real file in the store, so none is
        // refused only for running a host tool.
        let fixture = Fixture::new("tripwire-census");
        for (program, args, env) in census {
            let program = fixture.program(
                &program
                    .replacen("/s/", "objects/", 1)
                    .replacen("/x/", "tmp/", 1),
            );
            assert!(
                fixture.refusal(&command(&program, args, env)).is_some(),
                "census tool could start as a host-local helper: {program} {args:?} {env:?}"
            );
        }
    }

    /// The complete offline environment the Go extraction sets, for the
    /// store Go at `program`: every pinned variable set, every other one
    /// removed, the Go root and the module cache in the store.
    fn go_offline_at(fixture: &Fixture, program: &str, args: &[&str]) -> Command {
        let mut command = command(program, args, GO_OFFLINE_PINNED);
        for key in GO_OFFLINE_UNSET {
            command.env_remove(key);
        }
        let goroot = Path::new(program).parent().unwrap().parent().unwrap();
        command
            .env("GOROOT", goroot)
            .env("GOMODCACHE", fixture.path("tmp/stage-modcache"))
            .env("HOME", fixture.path("tmp/stage-cwd"))
            .env_remove("XDG_CONFIG_HOME");
        command
    }

    fn go_offline(fixture: &Fixture, args: &[&str]) -> Command {
        go_offline_at(fixture, &fixture.program("objects/go/bin/go"), args)
    }

    /// Each offline form lets its own helper through and nothing near it:
    /// the same program with the network allowed, or another mode. The
    /// Ruby and Elixir forms, which need the tailors' own helper scripts,
    /// are admitted by those tailors' tests over the real call sites.
    #[test]
    fn offline_forms_admit_only_their_own_argv() {
        let fixture = Fixture::new("tripwire-forms");
        let cargo = fixture.program("objects/rust/bin/cargo");
        fixture.admits(&fixture.cargo_lookup(&cargo));
        fixture.admits(&go_offline(&fixture, &["mod", "download", "a@v1", "b@v2"]));
        fixture.admits(&command("/usr/bin/tar", &["-xf", "a.tar"], &[]));
        fixture.admits(&command("/bin/cp", &["-a", "a", "b"], &[]));
        let go = fixture.program("objects/go/bin/go");
        let erl = fixture.program("tmp/stage/otp/bin/erl");
        let ruby = fixture.program("objects/ruby/bin/ruby");
        for command in [
            command(&cargo, &["locate-project", "--workspace"], &[]),
            command(&go, &["mod", "download", "a@v1"], &[]),
            command(&erl, &["-noshell", "-eval", "halt(0)."], &[]),
            command(&ruby, &["-e", "spec"], &[]),
            command("git", &["fetch"], &[]),
            command("npx", &["cowsay"], &[]),
        ] {
            fixture.refused(&command);
        }
        // Tools that fetch or install a resolver, refused by name wherever
        // they live.
        for name in [
            "rustup", "uvx", "corepack", "node", "yarn", "rebar3", "pip", "pip3", "bundler", "iex",
        ] {
            let program = fixture.program(&format!("objects/tools/bin/{name}"));
            fixture.refused(&command(&program, &["--version"], &[]));
            fixture.refused(&command(name, &["--version"], &[]));
        }
        for form in OFFLINE_FORMS {
            assert!(RESOLVERS.contains(&form.program), "{}", form.program);
        }
    }

    /// The workspace lookup runs only as the tailor builds it: the store
    /// Cargo, the exact argv, and rustup's toolchain selection removed. A
    /// host `cargo` is a rustup proxy that can install whatever toolchain
    /// the project names.
    #[test]
    fn cargo_form_requires_the_store_cargo_as_built() {
        let fixture = Fixture::new("tripwire-cargo");
        let cargo = fixture.program("objects/rust/bin/cargo");
        fixture.admits(&fixture.cargo_lookup(&cargo));
        let outside = Fixture::new("tripwire-cargo-host");
        let host = outside.program("bin/cargo");
        fixture.refused(&fixture.cargo_lookup(&host));
        fixture.refused(&fixture.cargo_lookup("/nonexistent/tog-test/bin/cargo"));
        let mut on_path = fixture.cargo_lookup("cargo");
        on_path.env("PATH", Path::new(&host).parent().unwrap());
        fixture.refused(&on_path);
        for key in ["RUSTUP_HOME", "RUSTUP_TOOLCHAIN"] {
            let mut inherited = command(&cargo, CARGO_LOCATE_PROJECT, &[]);
            let other = if key == "RUSTUP_HOME" {
                "RUSTUP_TOOLCHAIN"
            } else {
                "RUSTUP_HOME"
            };
            inherited.env_remove(other);
            fixture.refused(&inherited);
            let mut pinned = fixture.cargo_lookup(&cargo);
            pinned.env(key, "nightly");
            fixture.refused(&pinned);
        }
        for args in [
            &["locate-project", "--workspace", "--offline"][..],
            &[
                "locate-project",
                "--workspace",
                "--message-format",
                "plain",
                "--offline",
                "-Zunstable-options",
            ],
            &[
                "locate-project",
                "--offline",
                "--message-format",
                "plain",
                "--workspace",
            ],
        ] {
            let mut command = command(&cargo, args, &[]);
            command
                .env_remove("RUSTUP_HOME")
                .env_remove("RUSTUP_TOOLCHAIN");
            fixture.refused(&command);
        }
    }

    /// `GOPROXY=off` alone is not offline: go admits only `mod download` of
    /// module versions, and only with every other variable that can fetch,
    /// add flags or run a program pinned or gone.
    #[test]
    fn go_offline_form_requires_the_invocation_and_the_whole_environment() {
        let fixture = Fixture::new("tripwire-go");
        let go = fixture.program("objects/go/bin/go");
        fixture.admits(&go_offline(&fixture, &["mod", "download", "a@v1"]));
        fixture.refused(&go_offline(&fixture, &["run", "/tmp/arbitrary.go"]));
        fixture.refused(&go_offline(&fixture, &["mod", "download"]));
        fixture.refused(&go_offline(&fixture, &["mod", "download", "-x", "a@v1"]));
        fixture.refused(&go_offline(&fixture, &["mod", "download", "all"]));
        for (key, value) in [
            ("GONOPROXY", "*"),
            ("GOPRIVATE", "*"),
            ("GOFLAGS", "-modfile=/tmp/x"),
            ("GOCACHEPROG", "/tmp/run-me"),
            ("GOENV", "/tmp/go.env"),
            ("GOTOOLCHAIN", "auto"),
            ("GOVCS", "*:all"),
            ("GOPROXY", "https://proxy.golang.org"),
        ] {
            let mut command = go_offline(&fixture, &["mod", "download", "a@v1"]);
            command.env(key, value);
            fixture.refused(&command);
        }
        for key in [
            "GOVCS",
            "GOAUTH",
            "GOTOOLCHAIN",
            "GOROOT",
            "GOMODCACHE",
            "HOME",
        ] {
            let mut command = go_offline(&fixture, &["mod", "download", "a@v1"]);
            command.env_remove(key);
            fixture.refused(&command);
        }
        // Emptied is not removed: Go falls back to `$GOROOT/go.env`.
        for key in GO_OFFLINE_UNSET {
            let mut command = go_offline(&fixture, &["mod", "download", "a@v1"]);
            command.env(key, "");
            fixture.refused(&command);
        }
        // The Go root, the module cache and the home outside the store, or
        // a Go root that is another toolchain than the program's.
        let other = fixture.program("objects/go2/bin/go");
        let other_root = Path::new(&other).parent().unwrap().parent().unwrap();
        for (key, value) in [
            ("GOROOT", Path::new("/usr/lib/go")),
            ("GOROOT", other_root),
            ("GOMODCACHE", Path::new("/tmp/modcache")),
            ("HOME", Path::new("/tmp")),
            ("XDG_CONFIG_HOME", Path::new("/tmp")),
        ] {
            let mut command = go_offline(&fixture, &["mod", "download", "a@v1"]);
            command.env(key, value);
            fixture.refused(&command);
        }
        // A host `go` (a version-manager shim, say) with the whole
        // environment is still refused.
        let outside = Fixture::new("tripwire-go-host");
        fixture.refused(&go_offline_at(
            &fixture,
            &outside.program("go/bin/go"),
            &["mod", "download", "a@v1"],
        ));
        let only_proxy_off = command(
            &go,
            &["mod", "download", "a@v1"],
            &[("GOPROXY", "off"), ("GOSUMDB", "off")],
        );
        fixture.refused(&only_proxy_off);
    }

    /// The Ruby and Elixir forms run the tailors' helper and nothing else:
    /// an interpreter option in argv, a script that is not the helper, or
    /// an option variable in the environment is refused.
    #[test]
    fn helper_forms_are_bound_to_the_trusted_helper() {
        let fixture = Fixture::new("tripwire-helpers");
        let rb = fixture.path("tmp/stage/helper.rb");
        let exs = fixture.path("tmp/stage/helper.exs");
        std::fs::create_dir_all(fixture.path("tmp/stage")).unwrap();
        std::fs::write(&rb, "puts 'not the helper'\n").unwrap();
        std::fs::write(&exs, "IO.puts(\"not the helper\")\n").unwrap();
        let ruby = fixture.program("objects/ruby/bin/ruby");
        let elixir = fixture.program("objects/beam/elixir/bin/elixir");
        let gem = fixture.path("cache/x.gem");
        fixture.refused(&command(&ruby, &["-eputs('x')", "spec", &gem], &[]));
        fixture.refused(&command(&ruby, &[&rb, "spec", &gem], &[]));
        fixture.refused(&command(&ruby, &["-I/tmp", "spec", &gem], &[]));
        let hexmark = |script: &str| {
            command(
                &elixir,
                &[script, "hexmark", "/d", "x", "1", "i", "o", "mix"],
                &[("HEX_OFFLINE", "1")],
            )
        };
        fixture.refused(&hexmark("/tmp/arbitrary.exs"));
        fixture.refused(&hexmark(&exs));
        fixture.refused(&hexmark("--eval"));
    }

    /// A form admits its program only as the realized store object, named
    /// by absolute path: not a bare name tog's own `PATH` happens to
    /// resolve to it (an `env_clear`ed child searches libc's default path
    /// instead), and not a file staged under `<store>/tmp`, where unpacked
    /// packages land. Only the OTP probe runs a staged program.
    #[test]
    fn forms_admit_only_an_absolute_realized_program() {
        let fixture = Fixture::new("tripwire-program");
        let cargo = fixture.program("objects/rust/bin/cargo");
        fixture.admits(&fixture.cargo_lookup(&cargo));
        let staged = fixture.program("tmp/unpacked/bin/cargo");
        fixture.refused(&fixture.cargo_lookup(&staged));
        let bin = Path::new(&cargo).parent().unwrap();
        let mut bare = fixture.cargo_lookup("cargo");
        bare.env("PATH", bin);
        fixture.refused(&bare);
        let go = fixture.program("tmp/unpacked/go/bin/go");
        fixture.refused(&go_offline_at(&fixture, &go, &["mod", "download", "m@v1"]));
    }

    /// A form admits only the variables its call site sets: an added
    /// loader preload, library path, or unrelated tool setting is refused.
    #[test]
    fn forms_refuse_a_variable_their_call_site_does_not_set() {
        let fixture = Fixture::new("tripwire-extra-env");
        let cargo = fixture.program("objects/rust/bin/cargo");
        let go_args = ["mod", "download", "example.com/m@v1.0.0"];
        fixture.admits(&go_offline(&fixture, &go_args));
        for (key, value) in [
            ("LD_PRELOAD", "/tmp/x.so"),
            ("LD_LIBRARY_PATH", "/tmp"),
            ("CARGO_HOME", "/tmp"),
        ] {
            let mut lookup = fixture.cargo_lookup(&cargo);
            lookup.env(key, value);
            fixture.refused(&lookup);
            let mut download = go_offline(&fixture, &go_args);
            download.env(key, value);
            fixture.refused(&download);
        }
    }

    /// A confined `PATH` lists the store first: a host `/usr/bin` ahead of
    /// the store would let a host program shadow the store one the child
    /// starts by name.
    #[test]
    fn a_confined_path_puts_the_store_first() {
        let fixture = Fixture::new("tripwire-path-order");
        let store_bin = fixture.path("objects/beam/bin");
        let confined = |path: &str| {
            Invocation {
                args: Vec::new(),
                cwd: None,
                env: vec![(OsStr::new("PATH"), Some(OsStr::new(path)))],
                program: None,
                absolute: true,
                store: fixture.0 .0.canonicalize().ok(),
            }
            .path_confined()
        };
        std::fs::create_dir_all(&store_bin).unwrap();
        assert!(confined(&format!("{store_bin}:/usr/bin:/bin")));
        assert!(!confined(&format!("/usr/bin:{store_bin}")));
        assert!(!confined(&format!("{store_bin}:/opt/shims")));
    }

    /// The helper must be a file in the store, not a copy with the right
    /// content in a directory another user could swap it in.
    #[test]
    fn a_helper_outside_the_store_is_refused() {
        let fixture = Fixture::new("tripwire-helper-place");
        let outside = TempDir::named("tripwire-helper-outside");
        let script = outside.0.join("helper.rb");
        std::fs::write(&script, b"anything").unwrap();
        let run = Invocation {
            args: vec![script.as_os_str()],
            cwd: None,
            env: Vec::new(),
            program: None,
            absolute: true,
            store: fixture.0 .0.canonicalize().ok(),
        };
        let digest = hex::encode(Sha256::digest(b"anything"));
        assert!(!run.is_helper(0, "helper.rb", &digest));
        let inside = fixture.path("tmp/stage/helper.rb");
        std::fs::create_dir_all(fixture.path("tmp/stage")).unwrap();
        std::fs::write(&inside, b"anything").unwrap();
        let run = Invocation {
            args: vec![OsStr::new(&inside)],
            ..run
        };
        assert!(run.is_helper(0, "helper.rb", &digest));
    }

    /// The probe's argv alone is not enough: an `ERL_*` variable can carry
    /// an `-eval` of its own, so each must be absent from what the child
    /// sees.
    #[test]
    fn erl_probe_requires_the_erlang_option_variables_gone() {
        let fixture = Fixture::new("tripwire-erl");
        let erl = fixture.program("tmp/stage/otp/bin/erl");
        let home = fixture.path("tmp/stage");
        let probe = ["-noshell", "-eval", OTP_RUNTIME_PROBE];
        let clean = || {
            let mut command = command(&erl, &probe, &[]);
            for (key, _) in std::env::vars_os() {
                command.env_remove(key);
            }
            command
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &home)
                .env("TMPDIR", &home)
                .env("LANG", "C");
            command
        };
        fixture.admits(&clean());
        for key in ["ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS"] {
            let mut command = clean();
            command.env(key, "-eval 'os:cmd(\"curl example.com\")'");
            fixture.refused(&command);
        }
        // A user `.erlang` through `HOME` or `XDG_CONFIG_HOME`, and an
        // `erl` found through a user directory on `PATH`.
        for (key, value) in [
            ("HOME", "/home/someone"),
            ("XDG_CONFIG_HOME", "/home/someone/.config"),
            ("PATH", "/home/someone/.asdf/shims:/usr/bin:/bin"),
            ("PATH", ":/usr/bin"),
        ] {
            let mut command = clean();
            command.env(key, value);
            fixture.refused(&command);
        }
        // One inherited variable left in place: the probe must inherit
        // nothing.
        let kept = std::env::vars_os().map(|(key, _)| key).find(|key| {
            !["PATH", "HOME", "TMPDIR", "LANG"]
                .iter()
                .any(|set| key == set)
        });
        if let Some(kept) = kept {
            let mut command = command(&erl, &probe, &[]);
            for (key, _) in std::env::vars_os().filter(|(key, _)| *key != kept) {
                command.env_remove(key);
            }
            command
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &home)
                .env("TMPDIR", &home)
                .env("LANG", "C");
            fixture.refused(&command);
        }
        // The same probe from an `erl` outside the store.
        let outside = Fixture::new("tripwire-erl-host");
        let mut host = clean();
        let mut moved = Command::new(outside.program("otp/bin/erl"));
        moved.args(host.get_args());
        for (key, value) in host.get_envs() {
            match value {
                Some(value) => moved.env(key, value),
                None => moved.env_remove(key),
            };
        }
        host = moved;
        fixture.refused(&host);
    }

    /// A resolver is recognized by the name it is started under, in any
    /// case, and by the file that name resolves to: a symlink or a `PATH`
    /// entry under another name does not hide it, and a resolver named
    /// like another resolver gets only the forms both names allow.
    #[cfg(unix)]
    #[test]
    fn aliases_and_case_do_not_hide_a_resolver() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new("tripwire-alias");
        let git = fixture.program("objects/tools/bin/git");
        let bin = Path::new(&git).parent().unwrap().to_path_buf();
        symlink(&git, bin.join("fetcher")).unwrap();
        symlink(&git, bin.join("go")).unwrap();
        let fetcher = bin.join("fetcher");
        fixture.refused(&command(fetcher.to_str().unwrap(), &["fetch"], &[]));
        fixture.refused(&command("GIT", &["fetch"], &[]));
        fixture.refused(&command("/usr/bin/Git", &["fetch"], &[]));
        fixture.refused(&command(
            "fetcher",
            &["fetch"],
            &[("PATH", bin.to_str().unwrap())],
        ));
        let mut relative = command("bin/fetcher", &["fetch"], &[]);
        relative.current_dir(bin.parent().unwrap());
        fixture.refused(&relative);
        // `go` that is really `git`: the go form does not cover git.
        let disguised = go_offline_at(
            &fixture,
            bin.join("go").to_str().unwrap(),
            &["mod", "download", "a@v1"],
        );
        fixture.refused(&disguised);
        // A helper that resolves to no resolver still runs.
        fixture.admits(&command("/bin/cp", &["-a", "a", "b"], &[]));
    }

    /// A `PATH` search skips what `execvp` skips: a non-executable file
    /// earlier on `PATH` does not stand in for the resolver after it.
    #[cfg(unix)]
    #[test]
    fn path_lookup_skips_files_that_are_not_executable() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new("tripwire-exec-bit");
        let git = fixture.program("objects/tools/bin/git");
        let plain = fixture.path("tmp/plain");
        let linked = fixture.path("tmp/linked");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(Path::new(&plain).join("fetcher"), "not a program\n").unwrap();
        symlink(&git, Path::new(&linked).join("fetcher")).unwrap();
        let path = format!("{plain}:{linked}");
        fixture.refused(&command("fetcher", &["fetch"], &[("PATH", &path)]));
    }

    /// A known limit: a copy or a hard link of a resolver under another
    /// name is a different file name with no link to follow, so the
    /// tripwire does not see it. It catches a call site written the wrong
    /// way by mistake, not code that means to hide a resolver.
    #[cfg(unix)]
    #[test]
    fn a_copy_or_hard_link_under_another_name_is_not_seen() {
        let fixture = Fixture::new("tripwire-copy");
        let git = fixture.program("objects/tools/bin/git");
        let bin = Path::new(&git).parent().unwrap();
        std::fs::copy(&git, bin.join("copied")).unwrap();
        std::fs::hard_link(&git, bin.join("linked")).unwrap();
        for name in ["copied", "linked"] {
            let program = bin.join(name);
            assert!(
                fixture
                    .refusal(&command(program.to_str().unwrap(), &["fetch"], &[]))
                    .is_none(),
                "{name}: if this is refused, the limit is gone; update the module doc"
            );
        }
    }
}

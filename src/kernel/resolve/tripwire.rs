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
//! name resolves to, so a symlink or copy under another name does not hide
//! one.

use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The file names of every dependency tool tog runs. `git` is here because
/// a resolver can reach it (npm and cargo git dependencies); tog's own
/// verified git fetches go through `kernel::gitsrc`, not a `local_*` call.
pub const RESOLVERS: &[&str] = &[
    "uv", "npm", "npx", "pnpm", "cargo", "go", "bundle", "gem", "ruby", "mix", "elixir", "erl",
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

/// What a form sees of one invocation: the arguments after the program,
/// its working directory, and its explicit environment edits (`None` is a
/// removed variable).
struct Invocation<'a> {
    args: Vec<&'a OsStr>,
    cwd: Option<&'a Path>,
    env: Vec<(&'a OsStr, Option<&'a OsStr>)>,
}

impl Invocation<'_> {
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

    /// Whether the child sees `key` set to exactly `value`.
    fn is(&self, key: &str, value: &str) -> bool {
        self.effective(key).as_deref() == Some(OsStr::new(value))
    }

    /// Whether the child sees `key` unset or empty.
    fn unset(&self, key: &str) -> bool {
        self.effective(key).is_none_or(|value| value.is_empty())
    }

    /// Whether the child sees no variable whose name starts with `prefix`
    /// (compared case-insensitively).
    fn none_with_prefix(&self, prefix: &str) -> bool {
        let matches = |name: &OsStr| {
            name.to_string_lossy()
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        };
        let explicit = self
            .env
            .iter()
            .any(|(name, value)| matches(name) && value.is_some());
        let inherited = std::env::vars_os()
            .any(|(name, _)| matches(&name) && !self.env.iter().any(|(edited, _)| *edited == name));
        !explicit && !inherited
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
    /// `name` whose content has sha256 `expected`: the tog-owned helper,
    /// whatever directory it was staged in.
    fn is_helper(&self, index: usize, name: &str, expected: &str) -> bool {
        let Some(path) = self.args.get(index).map(Path::new) else {
            return false;
        };
        if !path.is_absolute() || path.file_name() != Some(OsStr::new(name)) {
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

/// Go variables that must be unset or empty: each can route a module around
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

const OFFLINE_FORMS: &[OfflineForm] = &[
    // `cargo locate-project --offline` reads the workspace layout and is
    // forbidden the network.
    OfflineForm {
        program: "cargo",
        matches: |run| {
            run.arg(0) == Some("locate-project") && run.args.contains(&OsStr::new("--offline"))
        },
    },
    // The Go tailor's module extraction: `go mod download path@version...`
    // from a module cache tog staged, with the complete offline
    // environment.
    OfflineForm {
        program: "go",
        matches: |run| {
            run.arg(0) == Some("mod")
                && run.arg(1) == Some("download")
                && run.args.len() > 2
                && run.no_options_from(2)
                && run
                    .args
                    .iter()
                    .skip(2)
                    .all(|arg| arg.to_string_lossy().contains('@'))
                && GO_OFFLINE_PINNED
                    .iter()
                    .all(|(key, value)| run.is(key, value))
                && GO_OFFLINE_UNSET.iter().all(|key| run.unset(key))
        },
    },
    // The Elixir helper's `hexmark` mode: writes a verified dependency's
    // .hex marker, with HEX_OFFLINE=1 and no Erlang or Elixir option
    // variables for the VM to pick up.
    OfflineForm {
        program: "elixir",
        matches: |run| {
            run.args.len() == 8
                && run.is_helper(0, "helper.exs", ELIXIR_HELPER_SHA256)
                && run.arg(1) == Some("hexmark")
                && run.no_options_from(1)
                && run.is("HEX_OFFLINE", "1")
                && run.none_with_prefix("ERL_")
                && run.none_with_prefix("ELIXIR_")
        },
    },
    // The staged-OTP probe: loads crypto and ssl and prints two lines, with
    // no `ERL_*` variable (`ERL_AFLAGS`, `ERL_FLAGS`, `ERL_ZFLAGS`,
    // `ERL_LIBS`) able to add code or an `-eval` of its own.
    OfflineForm {
        program: "erl",
        matches: |run| {
            run.args.len() == 3
                && run.arg(0) == Some("-noshell")
                && run.arg(1) == Some("-eval")
                && run.arg(2) == Some(OTP_RUNTIME_PROBE)
                && run.none_with_prefix("ERL_")
                && run.none_with_prefix("ELIXIR_")
        },
    },
    // The Ruby helper's `spec` mode: reads the gemspec of a .gem tog
    // already verified, with no interpreter option variables.
    OfflineForm {
        program: "ruby",
        matches: |run| {
            run.args.len() == 3
                && run.is_helper(0, "helper.rb", RUBY_HELPER_SHA256)
                && run.arg(1) == Some("spec")
                && run.no_options_from(1)
                && Path::new(run.args[2]).is_absolute()
                && ["RUBYOPT", "RUBYLIB", "RUBYGEMS_GEMDEPS"]
                    .iter()
                    .all(|key| run.unset(key))
        },
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
/// a bare name is looked up on the child's `PATH`. `None` when nothing
/// resolves.
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
        .find(|candidate| candidate.is_file())
        .and_then(|found| found.canonicalize().ok())
}

/// The refusal for `command`, when it starts a resolver outside every
/// offline form; `None` when a host-local helper may run it.
pub(crate) fn refusal(command: &Command) -> Option<io::Error> {
    let run = Invocation {
        args: command.get_args().collect(),
        cwd: command.get_current_dir(),
        env: command.get_envs().collect(),
    };
    let supplied = Path::new(command.get_program())
        .file_name()
        .unwrap_or_else(|| command.get_program());
    let mut names: Vec<&'static str> = Vec::new();
    names.extend(resolver_named(supplied));
    if let Some(resolved) = resolved_program(command, &run) {
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
        for (program, args, env) in census {
            assert!(
                refusal(&command(program, args, env)).is_some(),
                "census tool could start as a host-local helper: {program} {args:?} {env:?}"
            );
        }
    }

    /// The complete offline environment the Go extraction sets: every
    /// pinned variable set and every other one removed.
    fn go_offline(args: &[&str]) -> Command {
        go_offline_at("/s/go/bin/go", args)
    }

    fn go_offline_at(program: &str, args: &[&str]) -> Command {
        let mut command = command(program, args, GO_OFFLINE_PINNED);
        for key in GO_OFFLINE_UNSET {
            command.env_remove(key);
        }
        command
    }

    fn refused(command: &Command) {
        let error = refusal(command).unwrap_or_else(|| {
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

    /// Each offline form lets its own helper through and nothing near it:
    /// the same program with the network allowed, or another mode. The
    /// Ruby and Elixir forms, which need the tailors' own helper scripts,
    /// are admitted by those tailors' tests over the real call sites.
    #[test]
    fn offline_forms_admit_only_their_own_argv() {
        let admitted = [
            command(
                "/s/rust/bin/cargo",
                &[
                    "locate-project",
                    "--workspace",
                    "--message-format",
                    "plain",
                    "--offline",
                ],
                &[],
            ),
            go_offline(&["mod", "download", "a@v1", "b@v2"]),
            command("/usr/bin/tar", &["-xf", "a.tar"], &[]),
            command("/bin/cp", &["-a", "a", "b"], &[]),
        ];
        for command in &admitted {
            assert!(refusal(command).is_none(), "{command:?}");
        }
        for command in [
            command("/s/rust/bin/cargo", &["locate-project", "--workspace"], &[]),
            command("/s/go/bin/go", &["mod", "download", "a@v1"], &[]),
            command("/s/otp/bin/erl", &["-noshell", "-eval", "halt(0)."], &[]),
            command("/s/ruby/bin/ruby", &["-e", "spec"], &[]),
            command("git", &["fetch"], &[]),
            command("npx", &["cowsay"], &[]),
        ] {
            refused(&command);
        }
        for form in OFFLINE_FORMS {
            assert!(RESOLVERS.contains(&form.program), "{}", form.program);
        }
    }

    /// `GOPROXY=off` alone is not offline: go admits only `mod download` of
    /// module versions, and only with every other variable that can fetch,
    /// add flags or run a program pinned or gone.
    #[test]
    fn go_offline_form_requires_the_invocation_and_the_whole_environment() {
        refused(&go_offline(&["run", "/tmp/arbitrary.go"]));
        refused(&go_offline(&["mod", "download"]));
        refused(&go_offline(&["mod", "download", "-x", "a@v1"]));
        refused(&go_offline(&["mod", "download", "all"]));
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
            let mut command = go_offline(&["mod", "download", "a@v1"]);
            command.env(key, value);
            refused(&command);
        }
        for key in ["GOVCS", "GOAUTH", "GOTOOLCHAIN"] {
            let mut command = go_offline(&["mod", "download", "a@v1"]);
            command.env_remove(key);
            refused(&command);
        }
        let only_proxy_off = command(
            "/s/go/bin/go",
            &["mod", "download", "a@v1"],
            &[("GOPROXY", "off"), ("GOSUMDB", "off")],
        );
        refused(&only_proxy_off);
    }

    /// The Ruby and Elixir forms run the tailors' helper and nothing else:
    /// an interpreter option in argv, a script that is not the helper, or
    /// an option variable in the environment is refused.
    #[test]
    fn helper_forms_are_bound_to_the_trusted_helper() {
        let scratch = crate::kernel::testutil::TempDir::named("tripwire-helpers");
        let impostor_rb = scratch.0.join("helper.rb");
        let impostor_exs = scratch.0.join("helper.exs");
        std::fs::write(&impostor_rb, "puts 'not the helper'\n").unwrap();
        std::fs::write(&impostor_exs, "IO.puts(\"not the helper\")\n").unwrap();
        let rb = impostor_rb.to_str().unwrap();
        let exs = impostor_exs.to_str().unwrap();
        refused(&command(
            "/s/ruby/bin/ruby",
            &["-eputs('x')", "spec", "unused"],
            &[],
        ));
        refused(&command(
            "/s/ruby/bin/ruby",
            &[rb, "spec", "/cache/x.gem"],
            &[],
        ));
        refused(&command(
            "/s/ruby/bin/ruby",
            &["-I/tmp", "spec", "/cache/x.gem"],
            &[],
        ));
        refused(&command(
            "/s/beam/elixir/bin/elixir",
            &[
                "/tmp/arbitrary.exs",
                "hexmark",
                "/d",
                "x",
                "1",
                "i",
                "o",
                "mix",
            ],
            &[("HEX_OFFLINE", "1")],
        ));
        refused(&command(
            "/s/beam/elixir/bin/elixir",
            &[exs, "hexmark", "/d", "x", "1", "i", "o", "mix"],
            &[("HEX_OFFLINE", "1")],
        ));
        refused(&command(
            "/s/beam/elixir/bin/elixir",
            &["--eval", "hexmark", "/d", "x", "1", "i", "o", "mix"],
            &[("HEX_OFFLINE", "1")],
        ));
    }

    /// The probe's argv alone is not enough: an `ERL_*` variable can carry
    /// an `-eval` of its own, so each must be absent from what the child
    /// sees.
    #[test]
    fn erl_probe_requires_the_erlang_option_variables_gone() {
        let probe = ["-noshell", "-eval", OTP_RUNTIME_PROBE];
        let mut clean = command("/s/otp/bin/erl", &probe, &[]);
        for (key, _) in std::env::vars_os() {
            clean.env_remove(key);
        }
        assert!(refusal(&clean).is_none(), "{clean:?}");
        for key in ["ERL_AFLAGS", "ERL_FLAGS", "ERL_ZFLAGS", "ERL_LIBS"] {
            let mut command = command("/s/otp/bin/erl", &probe, &[]);
            for (key, _) in std::env::vars_os() {
                command.env_remove(key);
            }
            command.env(key, "-eval 'os:cmd(\"curl example.com\")'");
            refused(&command);
        }
    }

    /// A resolver is recognized by the name it is started under, in any
    /// case, and by the file that name resolves to: a symlink or a `PATH`
    /// entry under another name does not hide it, and a resolver named
    /// like another resolver gets only the forms both names allow.
    #[cfg(unix)]
    #[test]
    fn aliases_and_case_do_not_hide_a_resolver() {
        use std::os::unix::fs::symlink;
        let scratch = crate::kernel::testutil::TempDir::named("tripwire-alias");
        let bin = scratch.0.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let git = bin.join("git");
        std::fs::write(&git, "#!/bin/sh\n").unwrap();
        symlink(&git, bin.join("fetcher")).unwrap();
        symlink(&git, bin.join("go")).unwrap();
        let fetcher = bin.join("fetcher");
        refused(&command(fetcher.to_str().unwrap(), &["fetch"], &[]));
        refused(&command("GIT", &["fetch"], &[]));
        refused(&command("/usr/bin/Git", &["fetch"], &[]));
        refused(&command(
            "fetcher",
            &["fetch"],
            &[("PATH", bin.to_str().unwrap())],
        ));
        let mut relative = command("bin/fetcher", &["fetch"], &[]);
        relative.current_dir(&scratch.0);
        refused(&relative);
        // `go` that is really `git`: the go form does not cover git.
        let disguised = go_offline_at(
            bin.join("go").to_str().unwrap(),
            &["mod", "download", "a@v1"],
        );
        refused(&disguised);
        // A helper that resolves to no resolver still runs.
        assert!(refusal(&command("/bin/cp", &["-a", "a", "b"], &[])).is_none());
    }
}

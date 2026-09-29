//! The runtime tripwire behind `kernel::supervise`'s `local_*` functions.
//!
//! A host-local helper is a child that needs no network: `tar`, `cp`,
//! `patch`, an offline extraction. A dependency tool is not one of those
//! unless its argv (and, where the tool reads it, its environment) says so
//! in a form listed below. Every other start of a resolver program is
//! refused, so a new call site that should have gone through the door
//! fails the first time it runs instead of reaching the network.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
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

/// One reviewed offline form: a resolver program, and the argv and
/// environment under which it reaches no network. `matches` reads the
/// arguments after the program and the command's explicit environment
/// edits (`None` is a removed variable).
struct OfflineForm {
    program: &'static str,
    matches: fn(&[&OsStr], &[(&OsStr, Option<&OsStr>)]) -> bool,
}

/// Whether the command sets `key` to exactly `value`.
fn sets(env: &[(&OsStr, Option<&OsStr>)], key: &str, value: &str) -> bool {
    env.iter()
        .any(|(name, set)| *name == key && *set == Some(OsStr::new(value)))
}

const OFFLINE_FORMS: &[OfflineForm] = &[
    // `cargo locate-project --offline` reads the workspace layout and is
    // forbidden the network.
    OfflineForm {
        program: "cargo",
        matches: |args, _env| {
            args.first() == Some(&OsStr::new("locate-project"))
                && args.contains(&OsStr::new("--offline"))
        },
    },
    // With GOPROXY=off go downloads no module: it extracts from the module
    // cache tog staged.
    OfflineForm {
        program: "go",
        matches: |_args, env| sets(env, "GOPROXY", "off"),
    },
    // The helper's `hexmark` mode writes a verified dependency's .hex
    // marker, with HEX_OFFLINE=1.
    OfflineForm {
        program: "elixir",
        matches: |args, env| {
            args.len() >= 2 && args[1] == "hexmark" && sets(env, "HEX_OFFLINE", "1")
        },
    },
    // The staged-OTP probe: loads crypto and ssl and prints two lines.
    OfflineForm {
        program: "erl",
        matches: |args, _env| {
            args.len() == 3
                && args[0] == "-noshell"
                && args[1] == "-eval"
                && args[2] == OTP_RUNTIME_PROBE
        },
    },
    // The helper's `spec` mode reads the gemspec of a .gem tog already
    // verified.
    OfflineForm {
        program: "ruby",
        matches: |args, _env| args.len() == 3 && args[1] == "spec",
    },
];

/// The refusal for `command`, when it starts a resolver outside every
/// offline form; `None` when a host-local helper may run it.
pub(crate) fn refusal(command: &Command) -> Option<io::Error> {
    let program = Path::new(command.get_program())
        .file_name()
        .unwrap_or_else(|| command.get_program());
    let name = program.to_str()?;
    if !RESOLVERS.contains(&name) {
        return None;
    }
    let args: Vec<&OsStr> = command.get_args().collect();
    let env: Vec<(&OsStr, Option<&OsStr>)> = command.get_envs().collect();
    if OFFLINE_FORMS
        .iter()
        .any(|form| form.program == name && (form.matches)(&args, &env))
    {
        return None;
    }
    Some(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} is a dependency tool and must start through kernel::resolve's door, not as a host-local helper ({})",
            name,
            crate::kernel::ui::shell_line(
                &std::iter::once(command.get_program())
                    .chain(args.iter().copied())
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

    /// Each offline form lets its own helper through and nothing near it:
    /// the same program with the network allowed, or another mode.
    #[test]
    fn offline_forms_admit_only_their_own_argv() {
        let admitted: &[(&str, &[&str], &[(&str, &str)])] = &[
            (
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
            (
                "/s/go/bin/go",
                &["mod", "download", "a@v1"],
                &[("GOPROXY", "off"), ("GOSUMDB", "off")],
            ),
            (
                "/s/beam/elixir/bin/elixir",
                &["/stage/h.exs", "hexmark", "/stage/dep", "x", "1.0.0"],
                &[("HEX_OFFLINE", "1")],
            ),
            (
                "/s/otp/bin/erl",
                &["-noshell", "-eval", OTP_RUNTIME_PROBE],
                &[],
            ),
            (
                "/s/ruby/bin/ruby",
                &["/stage/helper.rb", "spec", "/cache/x.gem"],
                &[],
            ),
            ("/usr/bin/tar", &["-xf", "a.tar"], &[]),
            ("/bin/cp", &["-a", "a", "b"], &[]),
        ];
        for (program, args, env) in admitted {
            assert!(
                refusal(&command(program, args, env)).is_none(),
                "{program} {args:?}"
            );
        }
        let refused: &[(&str, &[&str], &[(&str, &str)])] = &[
            ("/s/rust/bin/cargo", &["locate-project", "--workspace"], &[]),
            ("/s/go/bin/go", &["mod", "download", "a@v1"], &[]),
            (
                "/s/beam/elixir/bin/elixir",
                &["/stage/h.exs", "hexmark", "/stage/dep"],
                &[],
            ),
            ("/s/otp/bin/erl", &["-noshell", "-eval", "halt(0)."], &[]),
            ("/s/ruby/bin/ruby", &["-e", "spec"], &[]),
            ("git", &["fetch"], &[]),
            ("npx", &["cowsay"], &[]),
        ];
        for (program, args, env) in refused {
            let error = refusal(&command(program, args, env))
                .unwrap_or_else(|| panic!("admitted {program} {args:?}"));
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("kernel::resolve"), "{error}");
        }
        for form in OFFLINE_FORMS {
            assert!(RESOLVERS.contains(&form.program), "{}", form.program);
        }
    }
}

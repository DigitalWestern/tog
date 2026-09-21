//! The command surface, exercised through the real binary and offline: no
//! store objects are realized, no network is touched. Every case here is a
//! contract from CLI.md (exit status 0/1/2, help on stdout, errors on stderr
//! with a next step, pass-through for `run`).

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-cli-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        // Mark the fixture as a project boundary. This temp directory can
        // itself live below a developer checkout with package manifests;
        // ancestor discovery must not make these fixtures non-hermetic.
        std::fs::create_dir_all(path.join(".tog")).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary in `cwd` with a throwaway store and home, so nothing here
/// can read the developer's policy or touch a real store.
fn tog(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    tog_env(cwd, home, args, &[])
}

fn tog_env(cwd: &Path, home: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tog"));
    command
        .args(args)
        .current_dir(cwd)
        .env("TOG_STORE", home.join("store"))
        .env("HOME", home)
        .env_remove("TOG_POLICY")
        .env_remove("TOG_STRICT")
        .env_remove("TOG_SIGNING_KEY")
        .env("NO_COLOR", "1");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("spawn tog")
}

/// The signing key under `home`, generated on first use and trusted by
/// `home`'s machine policy (`~/.tog/policy.toml`, created with an empty
/// deny list or appended to). Every closure fixture is signed with it.
fn signing_key(home: &Path) -> tog::kernel::signing::SigningKey {
    let path = home.join("signing.key");
    if !path.exists() {
        let public = tog::kernel::signing::generate(&path).unwrap();
        let policy = home.join(".tog/policy.toml");
        std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
        let mut text = std::fs::read_to_string(&policy).unwrap_or_else(|_| "deny = []\n".into());
        text.push_str(&format!("\n[signing]\ntrusted = [\"{public}\"]\n"));
        std::fs::write(&policy, text).unwrap();
    }
    tog::kernel::signing::SigningKey::load(&path).unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn no_arguments_prints_usage_and_exits_2() {
    let home = TempDir::new("noargs");
    let out = tog(&home.0, &home.0, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert!(stderr.contains("USAGE:"), "{stderr}");
    assert!(stderr.contains("  sync"), "{stderr}");
}

#[test]
fn help_goes_to_stdout_and_exits_0() {
    let home = TempDir::new("help");
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stderr.is_empty(), "{args:?}: {}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("EVERYDAY:"), "{args:?}: {stdout}");
        assert!(stdout.contains("TOG_STORE"), "{args:?}: {stdout}");
    }
    for args in [&["help", "sync"][..], &["sync", "--help"], &["sync", "-h"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let stdout = text(&out.stdout);
        assert!(stdout.starts_with("tog sync — "), "{args:?}: {stdout}");
        assert!(stdout.contains("--fresh"), "{args:?}: {stdout}");
    }
    let out = tog(&home.0, &home.0, &["help", "snyc"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("did you mean 'sync'?"));
}

#[test]
fn version() {
    let home = TempDir::new("version");
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert_eq!(
            text(&out.stdout),
            format!("tog {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn usage_errors_exit_2_with_a_next_step() {
    let home = TempDir::new("usage");
    let cases: &[(&[&str], &str, &str)] = &[
        (&["snyc"], "unknown command 'snyc'; did you mean 'sync'?", "tog --help"),
        (&["sync", "--fersh"], "sync: unknown option '--fersh'; did you mean '--fresh'?", "tog help sync"),
        (&["sync", "now"], "sync: unexpected argument 'now'; sync realizes what the project already declares — to add a dependency run 'tog add now'", "tog help sync"),
        (&["plan", "--json"], "plan: unknown option '--json'", "tog help plan"),
        (&["gc", "--keep-days", "soon"], "--keep-days expects a whole number of days, got 'soon'", "tog help gc"),
        (&["gc", "--dryrun"], "gc: unknown option '--dryrun'; did you mean '--dry-run'?", "tog help gc"),
        (&["sbom", "--output"], "--output needs a file path", "tog help sbom"),
        (&["store"], "store needs a subcommand: 'store path' or 'store roots'", "tog help store"),
        (&["store", "root"], "unknown store subcommand 'root'; did you mean 'roots'?", "tog help store"),
        (&["run"], "run: no command given", "tog help run"),
        (&["--dir", "x", "plan"], "unknown option '--dir'; did you mean '--directory'?", "tog --help"),
        (&["-C"], "-C needs a directory", "tog --help"),
        (&["add", "--", "--index-url"], "add: dependency spec '--index-url' looks like a tool option; package options are not allowed", "tog help add"),
        (&["add", "requests\n--index-url evil"], "add: dependency spec contains CR, LF, or NUL", "tog help add"),
        (&["x", "--from", "six", "/absolute/executable"], "x: --from requires a single safe executable name", "tog help x"),
    ];
    for (args, message, hint) in cases {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?} wrote to stdout");
        let stderr = text(&out.stderr);
        assert_eq!(
            stderr,
            format!("tog: error: {message}\nRun '{hint}' for usage.\n"),
            "{args:?}"
        );
    }
}

#[test]
fn fmt_is_named_and_typos_are_usage_errors() {
    let home = TempDir::new("fmt-cli");
    let out = tog(&home.0, &home.0, &["fmtt"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("unknown command 'fmtt'; did you mean 'fmt'?"));

    let out = tog(&home.0, &home.0, &["fmt", "--chekc"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("fmt: unknown option '--chekc'"));
    assert!(text(&out.stderr).contains("did you mean '--check'?"));

    // A value that is really a mistyped flag is a usage error in BOTH
    // spellings; `--eco=--check` must not be taken for an ecosystem name.
    for args in [
        &["fmt", "--eco", "--check"][..],
        &["fmt", "--eco=--check"],
        &["fmt", "--eco="],
    ] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            text(&out.stderr).contains("fmt: --eco needs an ecosystem"),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
}

/// `tog ls` prints a `rustfmt` row for the closure `tog fmt` writes,
/// so `tog ls rustfmt` must be a legal filter rather than a usage error.
#[test]
fn ls_accepts_every_ecosystem_name_it_can_print() {
    let home = TempDir::new("ls-words-home");
    let project = TempDir::new("ls-words-project");
    std::fs::create_dir_all(project.0.join(".tog/closures")).unwrap();
    std::fs::write(
        project.0.join(".tog/closures/rustfmt.json"),
        r#"{"schema":"closure/1","ecosystem":"rustfmt","projected_at":0,
            "body":{"rust_version":"1.96.1",
                    "rust_object":{"path":"/store/objects/r","id":"r"},
                    "rustfmt_object":{"path":"/store/objects/f","id":"f"}}}"#,
    )
    .unwrap();

    let out = tog(&project.0, &home.0, &["ls", "rustfmt"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).contains("rustfmt 1.96.1"),
        "{}",
        text(&out.stdout)
    );

    // The help text names the same set the parser accepts.
    let help = tog(&project.0, &home.0, &["ls", "-h"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        text(&help.stdout).contains("rustfmt"),
        "{}",
        text(&help.stdout)
    );

    let out = tog(&project.0, &home.0, &["ls", "npm"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("unknown ecosystem 'npm'"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn fmt_reports_ecosystem_and_project_errors_offline() {
    let home = TempDir::new("fmt-errors");
    let empty = TempDir::new("fmt-empty");
    let out = tog(&empty.0, &home.0, &["fmt"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no Rust project"));

    let out = tog(&empty.0, &home.0, &["fmt", "--eco", "python"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("fmt for python is not implemented yet"));
}

#[test]
fn fmt_script_precedence_does_not_try_rustfmt_without_a_projection() {
    let home = TempDir::new("fmt-script-home");
    let project = TempDir::new("fmt-script-project");
    std::fs::write(
        project.0.join("package.json"),
        r#"{"name":"p","scripts":{"fmt":"sh -c 'echo script-fmt; exit 7'"}}"#,
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["fmt"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("command 'fmt'"), "{stderr}");
    assert!(
        !stderr.contains("script-fmt"),
        "script unexpectedly ran: {stderr}"
    );
    assert!(!home.0.join("store/objects").is_dir());
    assert!(!project.0.join(".tog/closures/rustfmt.json").exists());
}

/// `--eco` is tog's own selector: in a polyglot root whose package.json
/// has a `fmt` script, `--eco rust` must reach the Rust path instead of
/// running the script with a meaningless trailing `--eco rust`. The fixture
/// pins an unrealizable toolchain so the Rust path fails offline, before any
/// download, with a diagnostic that could only come from that path.
#[test]
fn fmt_eco_selects_the_ecosystem_and_never_delegates_to_the_script() {
    let home = TempDir::new("fmt-eco-home");
    let project = TempDir::new("fmt-eco-project");
    std::fs::write(
        project.0.join("package.json"),
        r#"{"name":"p","scripts":{"fmt":"sh -c 'echo script-fmt \"$@\" > script-ran.txt; exit 7' sh"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.0.join("Cargo.toml"),
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        project.0.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.70.0\"\n",
    )
    .unwrap();

    let out = tog(&project.0, &home.0, &["fmt", "--eco", "rust"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("unsupported Rust toolchain \"1.70.0\""),
        "--eco rust did not reach the Rust path: {stderr}"
    );
    assert!(
        !stderr.contains("command 'fmt'") && !stderr.contains("script-fmt"),
        "--eco rust delegated to the package.json script: {stderr}"
    );
    assert!(!project.0.join("script-ran.txt").exists());

    // A non-Rust ecosystem is still refused here, not handed to the script.
    let out = tog(&project.0, &home.0, &["fmt", "--eco", "python"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("fmt for python is not implemented yet"),
        "{stderr}"
    );
    assert!(!project.0.join("script-ran.txt").exists());

    // Without --eco the script still wins (it needs a projection, so it stops
    // at `tog run fmt`'s diagnostic rather than reaching rustfmt).
    let out = tog(&project.0, &home.0, &["fmt", "--check"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("command 'fmt'"),
        "script no longer wins: {stderr}"
    );
    assert!(!stderr.contains("unsupported Rust toolchain"), "{stderr}");
    // Opening the store creates its directories; nothing was realized in it.
    let objects = home.0.join("store/objects");
    assert!(
        !objects.is_dir() || std::fs::read_dir(&objects).unwrap().next().is_none(),
        "an object was realized offline"
    );
}

#[test]
fn failures_exit_1_and_survive_quiet() {
    let home = TempDir::new("fail");
    let project = TempDir::new("empty");
    // An empty directory has no manifest: a real failure, not a usage error.
    let out = tog(&project.0, &home.0, &["plan"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("tog: error: no_manifest"), "{stderr}");

    // --quiet silences narration but never the error.
    let out = tog(&project.0, &home.0, &["--quiet", "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("tog: error: no_manifest"));
    let out = tog(&project.0, &home.0, &["-q", "--no-color", "-v", "plan"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn directory_option_changes_where_the_command_runs() {
    let home = TempDir::new("chdir");
    let project = TempDir::new("chdir-project");
    // Run from `home`, point at the empty project: the empty project's
    // failure proves the command ran there.
    let out = tog(
        &home.0,
        &home.0,
        &["-C", project.0.to_str().unwrap(), "plan"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no_manifest"));
    let out = tog(
        &home.0,
        &home.0,
        &["--directory", project.0.to_str().unwrap(), "-v", "plan"],
    );
    assert!(text(&out.stderr).contains("[verbose] working directory:"));

    let missing = project.0.join("missing");
    let out = tog(&home.0, &home.0, &["-C", missing.to_str().unwrap(), "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("tog: error: cannot change directory to"));
}

#[test]
fn run_passes_arguments_through_and_needs_a_projection() {
    let home = TempDir::new("run");
    let project = TempDir::new("run-project");
    // Flags after the program are the program's: tog does not parse
    // them, so the only error is the missing projection.
    let out = tog(&project.0, &home.0, &["run", "python", "--help"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("no environment projected here"), "{stderr}");
    assert!(stderr.contains("tog sync"), "{stderr}");
    // `--` reaches the same place with a program literally named `-h`.
    let out = tog(&project.0, &home.0, &["run", "--", "-h"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no environment projected here"));
}

#[test]
fn store_path_honors_the_store_variable() {
    let home = TempDir::new("store");
    let out = tog(&home.0, &home.0, &["store", "path"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let printed = PathBuf::from(text(&out.stdout).trim());
    assert_eq!(printed, home.0.join("store").canonicalize().unwrap());
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

// --- bare `tog`, aliases, the script shortcut, inspect verbs ---

#[test]
fn bare_tog_outside_a_project_prints_usage() {
    let home = TempDir::new("bare");
    let out = tog(&home.0, &home.0, &[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("tog: no project in "), "{stderr}");
    assert!(stderr.contains("USAGE:"), "{stderr}");
}

#[test]
fn install_alias_reaches_sync() {
    let home = TempDir::new("alias");
    let project = TempDir::new("alias-project");
    for args in [&["install"][..], &["i"], &["sync"]] {
        let out = tog(&project.0, &home.0, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(text(&out.stderr).contains("no_manifest"), "{args:?}");
    }
}

/// `tog install <pkg>` is what a pip or npm user types first, and
/// `install` is an alias for `sync`, which takes no package. Every
/// spelling must name `tog add` rather than reject the word.
#[test]
fn installing_a_package_by_name_points_at_add() {
    let home = TempDir::new("install-pkg");
    let project = TempDir::new("install-pkg-project");
    for verb in ["install", "i", "sync"] {
        let out = tog(&project.0, &home.0, &[verb, "requests"]);
        assert_eq!(out.status.code(), Some(2), "{verb}");
        let stderr = text(&out.stderr);
        assert!(stderr.contains("tog add requests"), "{verb}: {stderr}");
        assert!(
            stderr.contains("Run 'tog help sync' for usage."),
            "{stderr}"
        );
    }
    // The help the error sends them to names the verb too.
    let help = text(&tog(&project.0, &home.0, &["help", "sync"]).stdout);
    assert!(help.contains("tog add <package>"), "{help}");
}

/// A projected environment is immutable, so the habits that mutate one are
/// refused with the tog verb that replaces them — before the projection is
/// even looked for, because the explanation is the same everywhere.
#[test]
fn pip_activate_and_npm_install_are_refused_with_the_tog_verb() {
    let home = TempDir::new("immutable");
    let project = TempDir::new("immutable-project");
    let cases: &[(&[&str], &str)] = &[
        (&["run", "pip", "install", "flask"], "tog add <package>"),
        (&["run", "activate"], "no activate script"),
        (
            &["run", "source", ".venv/bin/activate"],
            "no activate script",
        ),
        (&["run", "npm", "install", "is-odd"], "tog add <package>"),
        (&["run", "yarn", "add", "is-odd"], "node_modules"),
    ];
    for (args, expected) in cases {
        let out = tog(&project.0, &home.0, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stderr = text(&out.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("No such file or directory"),
            "{args:?} leaked a raw os error: {stderr}"
        );
    }
    // Running a command is untouched; only the mutating verbs are refused.
    let out = tog(&project.0, &home.0, &["run", "npm", "run", "build"]);
    assert!(
        text(&out.stderr).contains("no environment projected here"),
        "{}",
        text(&out.stderr)
    );
}

/// `--quiet` points fd 2 at /dev/null. A panic must still reach the user,
/// or the process exits 101 having printed nothing at all.
#[test]
fn a_panic_is_printed_even_under_quiet() {
    let home = TempDir::new("panic-quiet");
    // No HOME and no TOG_STORE: the store's home lookup panics. The only
    // deterministic panic the CLI can be driven into from outside.
    let mut command = Command::new(env!("CARGO_BIN_EXE_tog"));
    let out = command
        .args(["--quiet", "store", "path"])
        .current_dir(&home.0)
        .env_remove("HOME")
        .env_remove("TOG_STORE")
        .env_remove("TOG_POLICY")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn tog");
    assert_eq!(out.status.code(), Some(101));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("internal error"),
        "quiet swallowed: {stderr:?}"
    );
    assert!(stderr.contains("HOME"), "{stderr}");
    assert!(stderr.contains("bug in tog"), "{stderr}");
}

#[test]
fn unknown_first_word_runs_a_package_json_script_or_errors() {
    let home = TempDir::new("script");
    let project = TempDir::new("script-project");
    std::fs::write(
        project.0.join("package.json"),
        r#"{"name": "p", "scripts": {"dev": "echo hi", "build": "echo built"}}"#,
    )
    .unwrap();
    // A script name resolves to `run`: the only failure is the missing
    // projection, which is a runtime error (1), not a usage error (2).
    let out = tog(&project.0, &home.0, &["dev", "--port", "3000"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no environment projected here"));
    // A built-in verb always wins over a same-named script.
    let out = tog(&project.0, &home.0, &["build"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("tog build requires"),
        "{}",
        text(&out.stderr)
    );
    // Not a script, not a verb: usage error naming the package.json.
    let out = tog(&project.0, &home.0, &["deploy"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "tog: error: unknown command 'deploy' (no package.json script named 'deploy' here)\nRun 'tog --help' for usage.\n"
    );
    // Without a package.json the message stays plain.
    let out = tog(&home.0, &home.0, &["deploy"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "tog: error: unknown command 'deploy'\nRun 'tog --help' for usage.\n"
    );
}

#[test]
fn inspect_verbs_offline() {
    let home = TempDir::new("inspect");
    let project = TempDir::new("inspect-project");

    let out = tog(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no project in"));
    let out = tog(&project.0, &home.0, &["ls"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("nothing synced here; run 'tog sync' first"));

    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let out = tog(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("python  not synced  run 'tog sync'"),
        "{}",
        text(&out.stdout)
    );
    let out = tog(&project.0, &home.0, &["status", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["synced"], false);
    assert_eq!(value["ecosystems"][0]["state"], "not-synced");

    let out = tog(&project.0, &home.0, &["doctor"]);
    let stdout = text(&out.stdout);
    for name in ["platform", "store", "sandbox", "c-toolchain", "project"] {
        assert!(stdout.contains(&format!("  {name}")), "{stdout}");
    }
    assert!(stdout.contains("python found; not synced yet"), "{stdout}");
    let out = tog(&project.0, &home.0, &["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["checks"].is_array());

    let out = tog(&project.0, &home.0, &["completions", "bash"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("complete -F _tog tog"));
    let out = tog(&project.0, &home.0, &["completions", "powershell"]);
    assert_eq!(out.status.code(), Some(2));
}

// --- the offline paths of add/remove/x ---

#[test]
fn dependency_verbs_offline_paths() {
    let home = TempDir::new("deps");
    // This suite may run below a checkout that has its own manifests; use
    // the filesystem root for the intentional no-project case so the
    // ancestor walk cannot discover that unrelated checkout.
    let out = tog(Path::new("/"), &home.0, &["add", "requests"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("no project from"),
        "{}",
        text(&out.stderr)
    );

    // A plain requirements file: tog edits it itself; with --no-sync
    // nothing else runs, so this is fully offline.
    let project = TempDir::new("deps-req");
    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let out = tog(
        &project.0,
        &home.0,
        &["add", "--no-sync", "requests>=2", "six==1.16.0"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(project.0.join("requirements.txt")).unwrap(),
        "six==1.16.0\nrequests>=2\n"
    );
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("requirements.txt: added requests, six"),
        "{stderr}"
    );
    assert!(stderr.contains("--no-sync"), "{stderr}");
    let out = tog(&project.0, &home.0, &["remove", "--no-sync", "idna"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("'idna' is not declared"));
    let out = tog(&project.0, &home.0, &["remove", "--no-sync", "Requests"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(project.0.join("requirements.txt")).unwrap(),
        "six==1.16.0\n"
    );
    // --dev has no meaning here.
    let out = tog(
        &project.0,
        &home.0,
        &["add", "--dev", "--no-sync", "pytest"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("--dev has no meaning"));

    // Refuse-with-instructions rows and missing tool declarations never touch
    // the network or the store.
    let setup = TempDir::new("deps-setup");
    std::fs::write(
        setup.0.join("setup.py"),
        "from setuptools import setup\nsetup()\n",
    )
    .unwrap();
    let out = tog(&setup.0, &home.0, &["add", "requests"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("install_requires"),
        "{}",
        text(&out.stderr)
    );
    let pnpm = TempDir::new("deps-pnpm");
    std::fs::write(pnpm.0.join("package.json"), "{}").unwrap();
    std::fs::write(pnpm.0.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    let out = tog(&pnpm.0, &home.0, &["add", "-D", "react", "left-pad"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains(
            "pnpm-lock.yaml is lockfile format 9.0; set packageManager to the exact pnpm version your team runs, e.g. from `pnpm --version`"
        ),
        "{}",
        text(&out.stderr)
    );
    let poetry = TempDir::new("deps-poetry");
    std::fs::write(poetry.0.join("pyproject.toml"), "[tool.poetry]\nname='p'\n").unwrap();
    let out = tog(&poetry.0, &home.0, &["update"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("poetry update"),
        "{}",
        text(&out.stderr)
    );
    let dotnet = TempDir::new("deps-dotnet");
    std::fs::write(dotnet.0.join("app.csproj"), "<Project/>").unwrap();
    let out = tog(&dotnet.0, &home.0, &["add", "Newtonsoft.Json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("dotnet add package Newtonsoft.Json"),
        "{}",
        text(&out.stderr)
    );
    // A shape that contradicts the project is caught before any tool runs.
    let out = tog(&project.0, &home.0, &["add", "@types/node"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("no node manifest"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn x_needs_a_registry_outside_a_project() {
    let home = TempDir::new("x");
    let out = tog(&home.0, &home.0, &["x", "ruff", "--version"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("tog x py:ruff"), "{stderr}");
    let out = tog(&home.0, &home.0, &["x"]);
    assert_eq!(out.status.code(), Some(2));
}

/// A pre-object-meta/2 record is upgraded by the automatic maintenance any
/// writable command runs at dispatch — not only by explicit
/// `gc --migrate-metadata`. Removing the automatic maintenance calls from
/// main must fail this test, because the record would stay legacy and the
/// next sweep would refuse it.
#[test]
fn command_dispatch_runs_automatic_metadata_maintenance() {
    let home = TempDir::new("x-maintenance");
    let store_root = home.0.join("store");
    let identity = tog::kernel::types::Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: "3.11.9".into(),
        inputs: [
            ("artifact_sha256".to_string(), "1".repeat(64)),
            (
                "platform".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
            ),
        ]
        .into_iter()
        .collect(),
    };
    let id = identity.object_id();
    let object = store_root.join("objects").join(&id);
    std::fs::create_dir_all(&object).unwrap();
    std::fs::write(object.join("payload"), "cpython").unwrap();
    let mut perms = std::fs::metadata(&object).unwrap().permissions();
    perms.set_mode(perms.mode() & !0o222);
    std::fs::set_permissions(&object, perms).unwrap();
    std::fs::create_dir_all(store_root.join("meta")).unwrap();
    let meta_path = store_root.join("meta").join(format!("{id}.json"));
    std::fs::write(
        &meta_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "id": id,
            "identity": identity,
            "created": 1,
            "exceptions": [],
            "refs": [],
        }))
        .unwrap(),
    )
    .unwrap();

    // An ordinary writable command in the maintenance set: it fails offline
    // (no x registry), but its dispatch already ran maintenance over the
    // store.
    let out = tog(&home.0, &home.0, &["x", "ruff", "--version"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));

    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    assert_eq!(
        record["evidence"], "adapted:cpython@1",
        "an ordinary writable command did not run automatic metadata maintenance: {}",
        record
    );
    assert!(record["schema"] == "object-meta/2", "{record}");
}

/// Issue #101. A record whose identity no longer hashes to the id it is
/// filed under cannot be read, so the fail-closed sweep refuses — and used
/// to reprint that refusal on every single command with no way out. The
/// warning is now news rather than noise, and `--drop-object` is the exit.
#[test]
fn an_unreadable_record_warns_once_and_is_cleared_by_drop_object() {
    let home = TempDir::new("wedged-record");
    let store_root = home.0.join("store");

    // A project root, so the sweep has an initialized registry to work from.
    std::fs::create_dir_all(&store_root).unwrap();
    let canonical_store = store_root.canonicalize().unwrap();
    let project = home.0.join("project");
    std::fs::create_dir_all(project.join(".tog/closures")).unwrap();
    let env_object = publish_certified_object(&canonical_store, "wedged-fixture-env");
    std::fs::write(
        project.join(".tog/closures/python.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"env_object": env_object.display().to_string()},
        }))
        .unwrap(),
    )
    .unwrap();
    let out = tog(
        &home.0,
        &home.0,
        &["gc", "--register", project.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    let identity = tog::kernel::types::Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: "3.11.9".into(),
        inputs: [
            ("artifact_sha256".to_string(), "1".repeat(64)),
            (
                "platform".to_string(),
                "x86_64-unknown-linux-gnu".to_string(),
            ),
        ]
        .into_iter()
        .collect(),
    };
    // The real-world shape: the identity was rewritten in place, so the id
    // the record is filed under is the hash of text that no longer exists.
    let real = identity.object_id();
    let id = format!(
        "{}{}",
        if real.starts_with('0') { '1' } else { '0' },
        &real[1..]
    );
    let object = canonical_store.join("objects").join(&id);
    std::fs::create_dir_all(&object).unwrap();
    std::fs::write(object.join("payload"), "cpython").unwrap();
    let meta_path = canonical_store.join("meta").join(format!("{id}.json"));
    std::fs::write(
        &meta_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "id": id,
            "identity": identity,
            "created": 1,
            "exceptions": [],
            "refs": [],
        }))
        .unwrap(),
    )
    .unwrap();

    // `x` fails offline, but its dispatch runs maintenance over the store.
    let first = tog(&home.0, &home.0, &["x", "ruff", "--version"]);
    let first = text(&first.stderr);
    assert!(
        first.contains("metadata maintenance deferred")
            && first.contains(&format!("--drop-object {id}")),
        "the deferral was not announced: {first}"
    );
    let second = tog(&home.0, &home.0, &["x", "ruff", "--version"]);
    let second = text(&second.stderr);
    assert!(
        !second.contains("metadata maintenance deferred"),
        "the same deferral was repeated: {second}"
    );

    // The command every refusal names must print the list, not refuse on it.
    let out = tog(&home.0, &home.0, &["gc", "--migrate-metadata"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let listed = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(
        listed.contains(&format!("--drop-object {id}")),
        "the recovery command is not named: {listed}"
    );

    let out = tog(&home.0, &home.0, &["gc", "--drop-object", &id]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!object.exists(), "{}", text(&out.stdout));
    assert!(!meta_path.exists(), "{}", text(&out.stdout));

    let out = tog(&home.0, &home.0, &["gc", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn x_clean_is_offline_and_strict_about_trailing_arguments() {
    let home = TempDir::new("x-clean");
    let out = tog(&home.0, &home.0, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("nothing to clean"));

    let out = tog(&home.0, &home.0, &["x", "--clean", "ruff", "extra"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "tog: error: x --clean: unexpected argument 'extra'\nRun 'tog help x' for usage.\n"
    );

    for shell in ["bash", "zsh", "fish"] {
        let out = tog(&home.0, &home.0, &["completions", shell]);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        let completion = text(&out.stdout);
        assert!(
            completion.contains(if shell == "fish" {
                "-l clean"
            } else {
                "--clean"
            }),
            "{shell}"
        );
    }
}

#[test]
fn x_clean_follows_a_symlinked_home_chain_the_way_the_runner_does() {
    // "Move the cache off the root disk": `~/.tog` is a symlink to
    // another volume. `tog x` follows it when it creates, locks and
    // registers a root, so cleanup has to reach exactly the same
    // environment — otherwise the roots it made could never be removed.
    let volume = TempDir::new("x-clean-volume-tog");
    let linked_tog_home = TempDir::new("x-clean-linked-tog");
    let root = volume.0.join(".tog/x/py-victim");
    std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
    std::fs::remove_dir_all(linked_tog_home.0.join(".tog")).unwrap();
    std::os::unix::fs::symlink(volume.0.join(".tog"), linked_tog_home.0.join(".tog")).unwrap();
    let out = tog(&linked_tog_home.0, &linked_tog_home.0, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("removed x environment"), "{stdout}");
    assert!(
        !root.exists(),
        "a root under a symlinked ~/.tog was left behind"
    );

    // The same for a symlinked $HOME itself.
    let real_home = TempDir::new("x-clean-real-home");
    let links = TempDir::new("x-clean-home-links");
    let root = real_home.0.join(".tog/x/py-victim");
    std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
    let home_link = links.0.join("home");
    std::os::unix::fs::symlink(&real_home.0, &home_link).unwrap();
    let out = tog(&home_link, &home_link, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("removed x environment"), "{stdout}");
    assert!(
        !root.exists(),
        "a root under a symlinked $HOME was left behind"
    );
}

#[test]
fn x_clean_refuses_a_symlinked_x_directory_or_a_relative_home() {
    // The final `x` component is where both `tog x` and `x --clean`
    // stop following, so neither can be pointed outside the home chain.
    let outside_x = TempDir::new("x-clean-outside-x");
    let symlinked_x_home = TempDir::new("x-clean-symlinked-x");
    let x_victim = outside_x.0.join("x/py-victim/.tog/closures");
    std::fs::create_dir_all(&x_victim).unwrap();
    std::os::unix::fs::symlink(outside_x.0.join("x"), symlinked_x_home.0.join(".tog/x")).unwrap();
    let out = tog(&symlinked_x_home.0, &symlinked_x_home.0, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("symlink") && stderr.contains("refusing"),
        "{stderr}"
    );
    assert!(x_victim.is_dir(), "symlink target was removed");

    let relative_home = TempDir::new("x-clean-relative-home");
    let relative_victim = relative_home
        .0
        .join("relative-home/.tog/x/py-victim/.tog/closures");
    std::fs::create_dir_all(&relative_victim).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tog"))
        .current_dir(&relative_home.0)
        .env("TOG_STORE", relative_home.0.join("store"))
        .env("HOME", "relative-home")
        .env_remove("TOG_POLICY")
        .env_remove("TOG_STRICT")
        .env("NO_COLOR", "1")
        .args(["x", "--clean"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("HOME must be an absolute directory"),
        "{stderr}"
    );
    assert!(relative_victim.is_dir(), "relative HOME target was removed");
}

/// A projection that claims store objects whose store cannot be recovered is
/// never removed, however empty the caller's own store happens to be. The
/// caller's `TOG_STORE` is not evidence about someone else's projection.
#[test]
fn x_clean_keeps_a_projection_whose_originating_store_is_unrecoverable() {
    let home = TempDir::new("x-clean-foreign-home");
    let project = TempDir::new("x-clean-foreign-project");
    let victim = home.0.join(".tog/x/py-foreign");
    std::fs::create_dir_all(victim.join(".tog/closures")).unwrap();
    // A closure naming an object in a store this invocation knows nothing
    // about — the shape a projection has after the machine's real store was
    // moved, or when TOG_STORE points somewhere new.
    std::fs::write(
        victim.join(".tog/closures/python.json"),
        r#"{"schema":"closure/1","ecosystem":"python","body":{"env_object":"/somewhere/else/store/objects/0000000000000000000000000000000000000000-python.env-9"}}"#,
    )
    .unwrap();

    let out = tog(&project.0, &home.0, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        victim.is_dir(),
        "a projection with an unrecoverable originating store was deleted: {stdout}"
    );
    assert!(
        stdout.contains("originating store could not be recovered"),
        "the skip was not narrated: {stdout}"
    );
}

/// Legacy roots (no `x.json`) must obey the ecosystem filter, and a
/// successful removal must leave nothing behind in `.locks`. Nothing here
/// needs the network or a realized object, so it belongs in the offline
/// suite: `HOME` and `TOG_STORE` are per-child temp directories.
#[test]
fn x_clean_py_leaves_legacy_npm_root() {
    let home = TempDir::new("x-clean-legacy-home");
    let project = TempDir::new("x-clean-legacy-project");

    let npm_root = home.0.join(".tog/x/npm-legacy");
    std::fs::create_dir_all(npm_root.join(".tog/closures")).unwrap();
    std::fs::write(
        npm_root.join("package.json"),
        r#"{"dependencies":{"prettier":"1.0.0"}}"#,
    )
    .unwrap();
    let py_root = home.0.join(".tog/x/py-legacy");
    std::fs::create_dir_all(py_root.join(".tog/closures")).unwrap();
    std::fs::write(py_root.join("requirements.in"), "ruff\n").unwrap();

    let out = tog(&project.0, &home.0, &["x", "--clean", "--py"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!py_root.exists(), "legacy Python root was not removed");
    assert!(
        npm_root.exists(),
        "legacy npm root was removed by --py cleanup"
    );
    let stdout = text(&out.stdout);
    assert!(
        !stdout.contains("gc --project"),
        "a python-only cleanup mentioned the node forests: {stdout}"
    );
    // The per-root lock is unlinked while it is still held, so `.locks`
    // cannot collect one stale file per environment ever created.
    assert!(
        !home.0.join(".tog/x/.locks/py-legacy.lock").exists(),
        "cleanup left the per-root lock file behind"
    );

    let out = tog(&project.0, &home.0, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!npm_root.exists(), "legacy npm root cleanup did not work");
    let stdout = text(&out.stdout);
    // A removed node root also orphans its ~/.tog/forests projection,
    // which plain `tog gc` never sweeps.
    assert!(stdout.contains("tog gc --project"), "{stdout}");
    assert!(
        !home.0.join(".tog/x/.locks/npm-legacy.lock").exists(),
        "cleanup left the per-root lock file behind"
    );
}

#[test]
fn x_clean_that_skips_every_candidate_does_not_claim_nothing_to_clean() {
    let home = TempDir::new("x-clean-unrecoverable");
    let root = home.0.join(".tog/x/mystery");
    std::fs::create_dir_all(root.join(".tog/closures")).unwrap();

    let out = tog(&home.0, &home.0, &["x", "--clean", "ruff"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("skipped x environment"), "{stdout}");
    assert!(
        !stdout.contains("nothing to clean"),
        "a run that skipped a candidate reported nothing to clean: {stdout}"
    );
    assert!(
        stdout.contains("removed 0 environment(s), skipped 1"),
        "{stdout}"
    );
    assert!(root.is_dir(), "an unrecoverable root was removed");
}

/// Build a cached, `ready` python `x` root for `home` whose store object
/// carries one recorded `file-collision` exception, and return the root.
fn cached_x_root_with_exception(home: &Path) -> PathBuf {
    // Every closure tog writes holds a path built from the store's own
    // canonicalized root, so the fixture has to canonicalize too: on macOS the
    // temp dir sits under /var, a symlink to /private/var, and an
    // uncanonicalized path here compares unequal to `store.object_path`.
    std::fs::create_dir_all(home.join("store/objects/test-env/bin")).unwrap();
    let store = home.join("store").canonicalize().unwrap();
    let object = store.join("objects/test-env");
    let executable = object.join("bin/ruff");
    std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::create_dir_all(store.join("meta")).unwrap();
    let exception = serde_json::json!({
        "kind": "file-collision",
        "subject": "ruff",
        "detail": "cached test exception"
    });
    std::fs::write(
        store.join("meta/test-env.json"),
        serde_json::json!({"id": "test-env", "exceptions": [exception.clone()]}).to_string(),
    )
    .unwrap();

    let key = hex::encode(Sha256::digest(
        format!(
            "x/2\0{}\0python\0fake\0\0{}",
            store.display(),
            tog::kernel::platform::Platform::host().unwrap().triple()
        )
        .as_bytes(),
    ));
    let root = home.join(".tog/x").join(format!("py-fake-{}", &key[..16]));
    std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
    std::os::unix::fs::symlink(&object, root.join(".venv")).unwrap();
    let body = serde_json::json!({
        "env_object": object,
        "exceptions": [exception]
    });
    std::fs::write(
        root.join(".tog/closures/python.json"),
        serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": tog::kernel::platform::Platform::host().unwrap().triple(),
            "body": body
        })
        .to_string(),
    )
    .unwrap();
    root
}

#[test]
fn cached_x_rechecks_object_exceptions_under_project_policy() {
    let home = TempDir::new("x-policy-home");
    let project = TempDir::new("x-policy-project");
    std::fs::write(
        project.0.join(".tog/policy.toml"),
        "deny = [\"file-collision\"]\n",
    )
    .unwrap();
    cached_x_root_with_exception(&home.0);

    let out = tog(
        &project.0,
        &home.0,
        &["x", "--py", "--from", "fake", "ruff"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("cached object test-env carries exception"),
        "{}",
        text(&out.stderr)
    );
}

/// A cache hit validates the projection once. When the validation ran twice
/// every persisted exception was narrated twice and queued twice, so one
/// exception read as two.
#[test]
fn cached_x_narrates_each_object_exception_once() {
    let home = TempDir::new("x-once-home");
    let project = TempDir::new("x-once-project");
    cached_x_root_with_exception(&home.0);

    let out = tog(
        &project.0,
        &home.0,
        &["x", "--py", "--from", "fake", "ruff"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert_eq!(
        stderr
            .matches("exception file-collision: ruff: cached test exception")
            .count(),
        1,
        "{stderr}"
    );
}

/// The refusal is user-facing behaviour, not just a value the selector
/// returns: `add` must stop before realizing anything and name both remedies.
#[test]
fn add_under_a_pnpm_workspace_that_does_not_list_the_project_refuses_offline() {
    let home = TempDir::new("pnpm-unlisted");
    let workspace = home.0.join("ws");
    let project = workspace.join("packages/added-since-install");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        workspace.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/listed: {}\n",
    )
    .unwrap();
    std::fs::write(
        workspace.join("pnpm-workspace.yaml"),
        "packages:\n  - packages/*\n",
    )
    .unwrap();
    std::fs::write(project.join("package.json"), "{\"name\":\"demo\"}\n").unwrap();

    let out = tog(&project, &home.0, &["add", "--no-sync", "is-number@7.0.0"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("does not list it as an importer"),
        "{stderr}"
    );
    assert!(stderr.contains("pnpm install"), "{stderr}");
    assert!(stderr.contains(".tog directory"), "{stderr}");
    assert!(
        !project.join("package-lock.json").exists(),
        "the refusal must not leave a stray npm lockfile behind"
    );
}

// ---------------------------------------------------------------------------
// `x --clean` may unregister a root only after successful cleanup.
//
// Both cases run offline through the real binary with a per-child HOME and
// TOG_STORE, so they belong in the ordinary suite rather than behind
// `--ignored`.
// ---------------------------------------------------------------------------

/// Build an x environment that the store has a durable root record for.
/// Returns `(x root, root key)`.
fn registered_x_environment(home: &Path, store_root: &Path) -> (PathBuf, String) {
    // Same reason as `cached_x_root_with_exception`: tog records object
    // paths under the store's canonicalized root, so the fixture must too
    // (on macOS the temp dir is under /var, a symlink to /private/var).
    std::fs::create_dir_all(store_root).unwrap();
    let store_root = store_root.canonicalize().unwrap();
    let store_root = store_root.as_path();
    let root = home.join(".tog/x/py-ruff-test");
    std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
    std::fs::write(root.join("requirements.in"), "ruff\n").unwrap();
    let object = publish_certified_object(store_root, "x-env");
    std::fs::write(
        root.join(".tog/closures/python.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"env_object": object.display().to_string()},
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join(".tog/x.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "x-request/2",
            "ecosystem": "python",
            "package": "ruff",
            "version": serde_json::Value::Null,
            "state": "ready",
            "store_root": store_root.display().to_string(),
        }))
        .unwrap(),
    )
    .unwrap();
    let canonical = root.canonicalize().unwrap();
    let key = hex::encode(sha1_of(canonical.to_string_lossy().as_bytes()));
    (root, key)
}

/// Publish a complete, fully certified store object by hand. Registration
/// requires the closure to name one, and these cases must not depend on a
/// realized toolchain or the network.
fn publish_certified_object(store_root: &Path, name: &str) -> PathBuf {
    let identity = tog::kernel::types::Identity {
        kind: "test".into(),
        name: name.into(),
        version: "1".into(),
        inputs: Default::default(),
    };
    let id = identity.object_id();
    let object = store_root.join("objects").join(&id);
    std::fs::create_dir_all(&object).unwrap();
    std::fs::write(object.join("payload"), name).unwrap();
    // An object is complete only when its directory is read-only and its
    // record is present, in that order.
    let mut perms = std::fs::metadata(&object).unwrap().permissions();
    perms.set_mode(perms.mode() & !0o222);
    std::fs::set_permissions(&object, perms).unwrap();
    std::fs::create_dir_all(store_root.join("meta")).unwrap();
    std::fs::write(
        store_root.join("meta").join(format!("{id}.json")),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "object-meta/2",
            "id": id,
            "identity": identity,
            "created": 1,
            "exceptions": [],
            "dependencies": [],
            "cache_digests": [],
            "evidence": "explicit",
        }))
        .unwrap(),
    )
    .unwrap();
    object
}

fn sha1_of(bytes: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    sha1::Sha1::digest(bytes).into()
}

fn registered_root_keys(home: &Path, cwd: &Path) -> Vec<String> {
    let out = tog(cwd, home, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    text(&out.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect()
}

/// A tool still running in the environment holds its per-root lock. Cleanup
/// must skip that candidate and leave its root record protecting the objects.
#[test]
fn busy_x_cleanup_retains_the_root_record() {
    let home = TempDir::new("x-clean-busy-home");
    let store_root = home.0.join("store");
    let (root, key) = registered_x_environment(&home.0, &store_root);

    let out = tog(
        &home.0,
        &home.0,
        &["gc", "--register", root.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        registered_root_keys(&home.0, &home.0).contains(&key),
        "the fixture was not registered"
    );

    // Hold the per-root lock the way a running tool does. `x --clean` takes
    // it non-blocking and exclusive, so this makes the candidate busy.
    let locks = home.0.join(".tog/x/.locks");
    std::fs::create_dir_all(&locks).unwrap();
    let lock_path = locks.join("py-ruff-test.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    use std::os::unix::io::AsRawFd;
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH) },
        0,
        "could not take the runner's shared lock"
    );

    let out = tog(&home.0, &home.0, &["x", "--clean"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        stdout.contains("in use by a running tool"),
        "a busy candidate was not narrated: {stdout}"
    );
    assert!(root.is_dir(), "a busy environment was removed: {stdout}");
    assert!(
        registered_root_keys(&home.0, &home.0).contains(&key),
        "busy cleanup gave up the root record: {stdout}"
    );
    drop(lock);
}

/// Cleanup that cannot complete must not unregister anything either. Here the
/// recorded originating store is not a real store, so the candidate's origin
/// can never be revalidated and the run fails before any removal.
#[test]
fn failed_x_cleanup_retains_the_root_record() {
    let home = TempDir::new("x-clean-failed-home");
    let store_root = home.0.join("store");
    let (root, key) = registered_x_environment(&home.0, &store_root);

    let out = tog(
        &home.0,
        &home.0,
        &["gc", "--register", root.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // Point the marker at a directory that exists but is not a store.
    let impostor = home.0.join("not-a-store");
    std::fs::create_dir_all(&impostor).unwrap();
    // `objects` is a regular file, so the recorded origin is structurally
    // not a store and can never be revalidated.
    std::fs::write(impostor.join("objects"), b"not a directory").unwrap();
    std::fs::write(
        root.join(".tog/x.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "x-request/2",
            "ecosystem": "python",
            "package": "ruff",
            "version": serde_json::Value::Null,
            "state": "ready",
            "store_root": impostor.display().to_string(),
        }))
        .unwrap(),
    )
    .unwrap();

    let out = tog(&home.0, &home.0, &["x", "--clean"]);
    let stderr = text(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a cleanup that could not validate its origin reported success: {}",
        text(&out.stdout)
    );
    assert!(stderr.contains("not a real store"), "{stderr}");
    assert!(root.is_dir(), "a failed cleanup removed the environment");
    assert!(
        registered_root_keys(&home.0, &home.0).contains(&key),
        "failed cleanup gave up the root record"
    );
}

/// Cleanup must recover the originating store from either spelling —
/// the explicit `x.json` marker, or a legacy environment's closure records —
/// and act on that store's registry, never on the caller's `TOG_STORE`.
#[test]
fn x_cleanup_revalidates_explicit_or_legacy_origin() {
    for spelling in ["explicit", "legacy"] {
        let home = TempDir::new(&format!("x-clean-origin-{spelling}"));
        let store_root = home.0.join("store");
        let (root, key) = registered_x_environment(&home.0, &store_root);
        if spelling == "legacy" {
            // A pre-`x-request/2` environment: the origin is only derivable
            // from the store object its closure names.
            std::fs::remove_file(root.join(".tog/x.json")).unwrap();
        }

        let out = tog(
            &home.0,
            &home.0,
            &["gc", "--register", root.to_str().unwrap()],
        );
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(registered_root_keys(&home.0, &home.0).contains(&key));

        let out = tog(&home.0, &home.0, &["x", "--clean"]);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(
            !root.exists(),
            "{spelling} origin was not resolved, so nothing was cleaned: {stdout}"
        );
        assert!(
            !registered_root_keys(&home.0, &home.0).contains(&key),
            "{spelling}: successful cleanup left the root record behind: {stdout}"
        );
    }
}

// --- CLI.md: `tog audit`, the CI admission gate over recorded exceptions ---

/// A python closure with recorded inputs, a projection, and one recorded
/// exception of `kind`, so `status` reports it synced and `audit` has
/// something to judge. Returns the closure path.
fn synced_python_closure_with_exception(home: &Path, project: &Path, kind: &str) -> PathBuf {
    std::fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let env = project.join("env-object");
    std::fs::create_dir_all(env.join("bin")).unwrap();
    std::os::unix::fs::symlink(&env, project.join(".venv")).unwrap();
    let requirements = hex::encode(Sha256::digest(
        std::fs::read(project.join("requirements.txt")).unwrap(),
    ));
    let platform = tog::kernel::platform::Platform::host().unwrap();
    let closures = project.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    let path = closures.join("python.json");
    let mut envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": "python",
        "platform": platform.triple(),
        "projected_at": 1,
        "body": {
            "env_object": env,
            "python": {"version": "3.12.14"},
            "plan": {"packages": []},
            "inputs": [{"path": "requirements.txt", "sha256": requirements}],
            "exceptions": [{
                "kind": kind,
                "subject": "left-pad",
                "detail": "git+https://example.invalid/left-pad",
            }],
        },
    });
    signing_key(home).sign(&mut envelope).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
    path
}

/// `policy::load` unions silently, so the merged deny set alone cannot say
/// which file asked for a denial. The JSON report carries the contributing
/// policies under `policy.sources`, in merge order, so a CI log shows
/// whether a denial came from the machine, the repository, or `--policy`.
#[test]
fn audit_json_attributes_each_policy_to_its_source_file() {
    // tog() sets HOME to this temp directory and explicitly removes both
    // TOG_POLICY and TOG_STRICT from the child.
    let home = TempDir::new("audit-sources-home");
    let project = TempDir::new("audit-sources-project");
    synced_python_closure_with_exception(&home.0, &project.0, "git-dependency");
    // The machine policy `signing_key` wrote: an empty deny list plus the
    // trusted key.
    let machine_policy = home.0.join(".tog/policy.toml");
    let project_policy = project.0.join(".tog/policy.toml");
    std::fs::write(&project_policy, "deny = [\"weak-integrity\"]\n").unwrap();
    let flag = project.0.join("company.toml");
    std::fs::write(&flag, "strict = false\ndeny = [\"git-dependency\"]\n").unwrap();

    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--json", "--policy", flag.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    // The child reports its own resolved cwd, which is not always the
    // string this test built (macOS resolves /var to /private/var), so
    // derive project-policy paths from the canonical project root.
    let project_root = std::fs::canonicalize(&project.0).unwrap();
    let parse_policy = |path: &Path| {
        tog::kernel::policy::parse_file(path, &std::fs::read_to_string(path).unwrap()).unwrap()
    };
    let source_json = |origin: &str, path: &Path| {
        let policy = parse_policy(path);
        serde_json::json!({
            "origin": origin,
            "path": path.to_string_lossy(),
            "strict": policy.strict,
            "deny": policy.deny,
            "trusted": policy.signing.map(|signing| signing.trusted),
        })
    };
    let mut expected = vec![source_json("machine", &machine_policy)];
    for ancestor in project_root.ancestors() {
        let path = ancestor.join(".tog/policy.toml");
        if path.exists() {
            expected.push(source_json("project", &path));
        }
    }
    expected.push(source_json("flag", &flag));

    // The pre-existing shape is untouched: sources are additive. Compute the
    // merged assertions from the same complete expected source array, so an
    // ambient ancestor policy is tested rather than ignored.
    let expected_strict = expected.iter().any(|source| source["strict"] == true);
    let expected_deny: BTreeSet<String> = expected
        .iter()
        .flat_map(|source| source["deny"].as_array().unwrap())
        .map(|kind| kind.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(value["passed"], false);
    assert!(
        value["project"]
            .as_str()
            .unwrap()
            .contains(project.0.file_name().unwrap().to_str().unwrap(),),
        "{value}"
    );
    assert_eq!(value["policy"]["strict"], expected_strict);
    let actual_deny: BTreeSet<String> =
        serde_json::from_value(value["policy"]["deny"].clone()).unwrap();
    assert_eq!(actual_deny, expected_deny);
    assert_eq!(value["closures"][0]["ecosystem"], "python");
    assert_eq!(value["closures"][0]["freshness"], "current");
    assert_eq!(value["closures"][0]["denied"][0]["kind"], "git-dependency");

    let sources = value["policy"]["sources"].as_array().unwrap();
    assert_eq!(sources, &expected);

    // The text report says the same thing, one line per source.
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", flag.to_str().unwrap()],
    );
    let stdout = text(&out.stdout);
    let dir_name = project.0.file_name().unwrap().to_str().unwrap();
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("policy: ") && line.contains(dir_name))
        .collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert!(lines[0].starts_with("policy: project "), "{stdout}");
    assert!(
        lines[0].ends_with(".tog/policy.toml\" denies weak-integrity"),
        "{stdout}"
    );
    assert!(lines[1].starts_with("policy: flag "), "{stdout}");
    assert!(
        lines[1].ends_with("company.toml\" denies git-dependency"),
        "{stdout}"
    );
    // These are results on stdout, so --quiet keeps them alongside the verdict.
    let out = tog(
        &project.0,
        &home.0,
        &["--quiet", "audit", "--policy", flag.to_str().unwrap()],
    );
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains(&format!(
            "policy: machine {:?}",
            machine_policy.to_string_lossy()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("policy: project "), "{stdout}");
    assert!(stdout.contains("policy: flag "), "{stdout}");
    assert!(
        stdout.contains("python  denied        closure "),
        "{stdout}"
    );
}

/// Write the `rustfmt` closure `tog fmt` would write for `project` with
/// this binary's pins, after `edit` changes its body.
fn write_rustfmt_closure(
    home: &Path,
    project: &Path,
    edit: impl FnOnce(&mut serde_json::Value),
) -> PathBuf {
    let platform = tog::kernel::platform::Platform::host().unwrap();
    let mut body = tog::tailors::cargo::rustfmt::pinned_record(platform, project, "").unwrap();
    body["exceptions"] = serde_json::json!([]);
    edit(&mut body);
    let closures = project.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    let path = closures.join("rustfmt.json");
    let mut envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": "rustfmt",
        "platform": platform.triple(),
        "projected_at": 1,
        "body": body,
    });
    signing_key(home).sign(&mut envelope).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
    path
}

/// The `rustfmt` record passes audit only when it names the rustfmt this
/// binary pins for the project; one made by another rustfmt is stale, and
/// one from before the record carried inputs is outdated.
#[test]
fn audit_compares_the_rustfmt_record_to_its_pin() {
    let home = TempDir::new("audit-rustfmt-home");
    let project = TempDir::new("audit-rustfmt-project");
    std::fs::write(project.0.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
    // A toolchain file naming rustfmt makes `sync` record an exception; the
    // read-only audit must resolve the same pin without recording one.
    std::fs::write(
        project.0.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"stable\"\ncomponents = [\"rustfmt\"]\n",
    )
    .unwrap();

    // The rustfmt record itself is clean; the report still fails because
    // the Cargo project it belongs to has no cargo.json (never synced), and
    // the optional rustfmt record is no substitute for it.
    write_rustfmt_closure(&home.0, &project.0, |_| {});
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(
        text(&out.stdout).contains("rustfmt  clean")
            && text(&out.stdout).contains("cargo    missing"),
        "{}",
        text(&out.stdout)
    );
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "clean");
    assert_eq!(value["closures"][0]["passed"], true);
    assert_eq!(value["closures"][0]["signature"]["state"], "trusted");
    assert_eq!(value["missing"], serde_json::json!(["cargo"]));
    assert_eq!(value["passed"], false);

    let older = format!("{}-rustfmt-1.95.0", "0".repeat(40));
    write_rustfmt_closure(&home.0, &project.0, |body| {
        body["inputs"]["rustfmt_object"] = serde_json::json!(older);
        body["rustfmt_object"]["id"] = serde_json::json!(older);
    });
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stdout).contains("rustfmt  stale")
            && text(&out.stdout).contains(&older)
            && text(&out.stdout).contains("run 'tog fmt'"),
        "{}",
        text(&out.stdout)
    );

    write_rustfmt_closure(&home.0, &project.0, |body| {
        body.as_object_mut().unwrap().remove("inputs");
    });
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["passed"], false);
    assert_eq!(value["closures"][0]["freshness"], "outdated");
    assert!(
        value["closures"][0]["freshness_detail"]
            .as_str()
            .unwrap()
            .contains("tog fmt"),
        "{value}"
    );
}

// APFS rejects non-UTF-8 filenames with EILSEQ. The filesystem case runs
// on Linux; audit's rendering unit tests cover these bytes on both hosts.
#[cfg(target_os = "linux")]
#[test]
fn audit_json_handles_non_utf8_project_and_closure_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let home = TempDir::new("audit-non-utf8-home");
    let parent = TempDir::new("audit-non-utf8-parent");
    let project = parent.0.join(OsString::from_vec(vec![
        b'p', b'r', b'o', b'j', b'e', b'c', b't', b'-', 0xff,
    ]));
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
    let closure = write_rustfmt_closure(&home.0, &project, |_| {});

    let out = tog(&project, &home.0, &["audit", "--json"]);
    // Exit 1: the Cargo project has no cargo.json (see the pin test above).
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["passed"], true);
    assert_eq!(value["missing"], serde_json::json!(["cargo"]));
    assert_eq!(value["project"], project.to_string_lossy().as_ref());
    assert_eq!(
        value["project_bytes"],
        hex::encode(project.as_os_str().as_bytes())
    );
    assert_eq!(
        value["closures"][0]["path"],
        closure.to_string_lossy().as_ref()
    );
    assert_eq!(
        value["closures"][0]["path_bytes"],
        hex::encode(closure.as_os_str().as_bytes())
    );
}

#[test]
fn audit_is_an_offline_admission_gate_over_recorded_exceptions() {
    let home = TempDir::new("audit-home");
    let project = TempDir::new("audit-project");

    // No trusted set in the machine policy: the gate is not configured,
    // which is an operator mistake (exit 2), before any record is read.
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no trusted signing keys configured")
            && text(&out.stderr).contains("[signing]"),
        "{}",
        text(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    // A project policy cannot configure it either.
    let key = signing_key(&home.0);
    let machine_policy = home.0.join(".tog/policy.toml");
    let trusting = std::fs::read_to_string(&machine_policy).unwrap();
    std::fs::write(&machine_policy, "deny = []\n").unwrap();
    std::fs::write(project.0.join(".tog/policy.toml"), &trusting).unwrap();
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    std::fs::remove_file(project.0.join(".tog/policy.toml")).unwrap();
    std::fs::write(&machine_policy, &trusting).unwrap();

    // Nothing synced: a failure with a next step, exit 1.
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("nothing synced"),
        "{}",
        text(&out.stderr)
    );

    // Usage errors exit 2.
    let out = tog(&project.0, &home.0, &["audit", "--policy"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("--policy needs a file path"),
        "{}",
        text(&out.stderr)
    );
    let out = tog(&project.0, &home.0, &["audit", "--strict"]);
    assert_eq!(out.status.code(), Some(2));
    let out = tog(&project.0, &home.0, &["help", "audit"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        text(&out.stdout).contains("policy-company.toml"),
        "{}",
        text(&out.stdout)
    );

    let closure = synced_python_closure_with_exception(&home.0, &project.0, "git-dependency");
    // No deny list anywhere: the recorded exception is permitted and counted.
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("python  clean         closure "),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "policy: machine {:?} trusts {}",
            machine_policy.to_string_lossy(),
            key.public_key()
        )),
        "{stdout}"
    );
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["signature"]["state"], "trusted");
    assert_eq!(
        value["closures"][0]["signature"]["key"],
        key.public_key().to_string()
    );
    assert_eq!(value["closures"][0]["verdict"], "clean");
    assert_eq!(
        value["policy"]["trusted"],
        serde_json::json!([key.public_key().to_string()])
    );
    assert_eq!(value["missing"], serde_json::json!([]));

    // A hand edit of the committed record: bad-signature, exit 1, no
    // exception judged; a stripped signature: outdated; another key:
    // untrusted, and a project policy naming that key does not help.
    let signed = std::fs::read_to_string(&closure).unwrap();
    let mut edited: serde_json::Value = serde_json::from_str(&signed).unwrap();
    edited["body"]["exceptions"] = serde_json::json!([]);
    std::fs::write(&closure, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "bad-signature");
    assert_eq!(value["closures"][0]["signature"]["state"], "bad");
    assert_eq!(value["closures"][0]["freshness"], "not-evaluated");
    assert_eq!(value["closures"][0]["denied"], serde_json::Value::Null);
    let out = tog(&project.0, &home.0, &["audit"]);
    assert!(
        text(&out.stdout).contains("python  bad-signature closure ")
            && text(&out.stdout).contains("(not evaluated)"),
        "{}",
        text(&out.stdout)
    );
    let mut stripped: serde_json::Value = serde_json::from_str(&signed).unwrap();
    stripped.as_object_mut().unwrap().remove("signature");
    std::fs::write(&closure, serde_json::to_vec_pretty(&stripped).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("python  outdated      closure ")
            && text(&out.stdout).contains("once under a trusted key, then commit"),
        "{}",
        text(&out.stdout)
    );
    let other_home = TempDir::new("audit-other-home");
    let other = signing_key(&other_home.0);
    let mut resigned: serde_json::Value = serde_json::from_str(&signed).unwrap();
    other.sign(&mut resigned).unwrap();
    std::fs::write(&closure, serde_json::to_vec_pretty(&resigned).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("python  untrusted     closure ")
            && text(&out.stdout).contains(&other.public_key().to_string()),
        "{}",
        text(&out.stdout)
    );
    std::fs::write(
        project.0.join(".tog/policy.toml"),
        format!(
            "[signing]\ntrusted = [\"{}\", \"{}\"]\n",
            key.public_key(),
            other.public_key()
        ),
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "untrusted");
    assert_eq!(
        value["policy"]["trusted"],
        serde_json::json!([key.public_key().to_string()])
    );
    // And a project policy that drops the machine key makes the genuine
    // record untrusted, naming the scope.
    std::fs::write(&closure, &signed).unwrap();
    std::fs::write(
        project.0.join(".tog/policy.toml"),
        format!("[signing]\ntrusted = [\"{}\"]\n", other.public_key()),
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("untrusted")
            && text(&out.stdout).contains("excluded by project"),
        "{}",
        text(&out.stdout)
    );
    std::fs::remove_file(project.0.join(".tog/policy.toml")).unwrap();
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    assert!(stdout.contains("permitted: git-dependency 1"), "{stdout}");
    // The audit never created a store.
    assert!(!home.0.join("store").exists());

    // --policy denies it: exit 1, the exception named with subject and detail.
    let company = home.0.join("company.toml");
    std::fs::write(&company, "deny = [\"git-dependency\"]\n").unwrap();
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", company.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("python  denied        closure "),
        "{stdout}"
    );
    assert!(
        stdout.contains("git-dependency  left-pad  git+https://example.invalid/left-pad"),
        "{stdout}"
    );
    let out = tog(
        &project.0,
        &home.0,
        &[
            "audit",
            "--json",
            &format!("--policy={}", company.display()),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["passed"], false);
    assert_eq!(value["policy"]["deny"][0], "git-dependency");
    assert_eq!(value["closures"][0]["freshness"], "current");
    assert_eq!(value["closures"][0]["denied"][0]["subject"], "left-pad");
    assert_eq!(
        value["closures"][0]["record_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    // The shipped template denies git dependencies too.
    let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/human/policy-company.toml");
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", template.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));

    // The project policy denies it; a permissive --policy file cannot loosen.
    std::fs::write(
        project.0.join(".tog/policy.toml"),
        "deny = [\"git-dependency\"]\n",
    )
    .unwrap();
    let permissive = home.0.join("permissive.toml");
    std::fs::write(&permissive, "deny = []\n").unwrap();
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", permissive.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("denied"),
        "{}",
        text(&out.stdout)
    );
    std::fs::remove_file(project.0.join(".tog/policy.toml")).unwrap();

    // A missing or malformed --policy file is an operator mistake, exit 2,
    // so CI can tell it from a denied build; the gate never runs under a
    // policy the caller did not get.
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", "/nonexistent/p.toml"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("nonexistent"),
        "{}",
        text(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let typo = home.0.join("typo.toml");
    std::fs::write(&typo, "deny = [\"git-dependecy\"]\n").unwrap();
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", typo.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("unknown deny kind"),
        "{}",
        text(&out.stderr)
    );
    let out = tog(&project.0, &home.0, &["audit", "--policy", "--json"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("--policy needs a file path"),
        "{}",
        text(&out.stderr)
    );

    // An exception kind this binary does not know is never permitted, under
    // any policy, and cannot be named in one either.
    let unknown = TempDir::new("audit-unknown");
    synced_python_closure_with_exception(&home.0, &unknown.0, "kind-from-a-newer-tog");
    let out = tog(&unknown.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("python  unknown       closure "),
        "{stdout}"
    );
    assert!(
        stdout.contains("unknown  kind-from-a-newer-tog  left-pad"),
        "{stdout}"
    );
    let out = tog(&unknown.0, &home.0, &["audit", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["passed"], false);
    assert_eq!(
        value["closures"][0]["unknown"][0]["kind"],
        "kind-from-a-newer-tog"
    );
    assert!(value["closures"][0]["denied"]
        .as_array()
        .unwrap()
        .is_empty());

    // A closure named for one ecosystem but claiming another is refused.
    let mismatch = TempDir::new("audit-mismatch");
    let path = synced_python_closure_with_exception(&home.0, &mismatch.0, "git-dependency");
    let body = std::fs::read_to_string(&path).unwrap().replacen(
        "\"ecosystem\": \"python\"",
        "\"ecosystem\": \"rustfmt\"",
        1,
    );
    assert!(body.contains("\"ecosystem\": \"rustfmt\""), "{body}");
    std::fs::write(&path, body).unwrap();
    let out = tog(&mismatch.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains(r#"claims ecosystem "rustfmt" but is named "python""#),
        "{}",
        text(&out.stderr)
    );

    // A stale closure never audits clean, even under no policy at all.
    std::fs::write(project.0.join("requirements.txt"), "six==1.16.0\n").unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["passed"], false);
    assert_eq!(value["closures"][0]["freshness"], "stale");
    assert!(value["closures"][0]["freshness_detail"]
        .as_str()
        .unwrap()
        .contains("requirements.txt"));
    let out = tog(&project.0, &home.0, &["audit"]);
    assert!(
        text(&out.stdout).contains("python  stale         closure "),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn keygen_writes_a_private_key_and_prints_the_policy_table() {
    let home = TempDir::new("keygen");
    let path = home.0.join("ci.key");
    let out = tog(&home.0, &home.0, &["keygen", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with("[signing]\ntrusted = [\"ed25519:"),
        "{stdout}"
    );
    let policy = tog::kernel::policy::parse_file(&path, &stdout).unwrap();
    let key = tog::kernel::signing::SigningKey::load(&path).unwrap();
    assert_eq!(
        policy.signing.unwrap().trusted,
        [key.public_key()].into_iter().collect()
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let seed = std::fs::read_to_string(&path).unwrap();
    assert!(!stdout.contains(seed.trim()) && !text(&out.stderr).contains(seed.trim()));
    assert!(
        text(&out.stderr).contains("TOG_SIGNING_KEY"),
        "{}",
        text(&out.stderr)
    );
    // Never overwrites.
    let out = tog(&home.0, &home.0, &["keygen", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("exists"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), seed);
    // Usage errors exit 2.
    for args in [
        &["keygen"][..],
        &["keygen", "a", "b"],
        &["keygen", "--json"],
        &["keygen", ""],
        &["keygen", "--", "a", "b"],
    ] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(!home.0.join("a").exists(), "{args:?} created a file");
    }
    // `--` lets a path that starts with a dash through.
    let dashed = home.0.join("-dashed.key");
    let out = tog(
        &home.0,
        &home.0,
        &["keygen", "--", dashed.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(dashed.is_file());
    let out = tog(&home.0, &home.0, &["help", "keygen"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("TOG_SIGNING_KEY"));
    // The key signs a record the audit trusts once the table is installed.
    let project = TempDir::new("keygen-project");
    std::fs::create_dir_all(home.0.join(".tog")).unwrap();
    std::fs::write(home.0.join(".tog/policy.toml"), &stdout).unwrap();
    std::fs::write(project.0.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
    let platform = tog::kernel::platform::Platform::host().unwrap();
    let mut body = tog::tailors::cargo::rustfmt::pinned_record(platform, &project.0, "").unwrap();
    body["exceptions"] = serde_json::json!([]);
    let mut envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": "rustfmt",
        "platform": platform.triple(),
        "projected_at": 1,
        "body": body,
    });
    key.sign(&mut envelope).unwrap();
    let closures = project.0.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    std::fs::write(
        closures.join("rustfmt.json"),
        serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .unwrap();
    // cargo.json is required for the detected Cargo project: the optional
    // rustfmt record alone is `missing` for cargo.
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "clean");
    assert_eq!(value["missing"], serde_json::json!(["cargo"]));
    let out = tog(&project.0, &home.0, &["audit"]);
    assert!(
        text(&out.stdout).contains("cargo    missing       no closure for the cargo inputs"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn a_bad_signing_key_fails_every_closure_writer_before_the_store_is_touched() {
    let home = TempDir::new("badkey-home");
    let project = TempDir::new("badkey-project");
    std::fs::write(project.0.join("requirements.txt"), "").unwrap();
    std::fs::write(project.0.join("Cargo.toml"), "[package]\nname = \"p\"\n").unwrap();
    let loose = home.0.join("loose.key");
    tog::kernel::signing::generate(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let malformed = home.0.join("malformed.key");
    std::fs::write(&malformed, "not a key\n").unwrap();
    std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o600)).unwrap();
    for (label, key) in [
        ("missing", "/nonexistent/signing.key"),
        ("empty", ""),
        ("loose", loose.to_str().unwrap()),
        ("malformed", malformed.to_str().unwrap()),
        ("directory", home.0.to_str().unwrap()),
    ] {
        for args in [
            &["sync"][..],
            &["fmt", "--eco", "rust", "--check"],
            &["build"],
            &["add", "py:six", "--no-sync"],
        ] {
            let out = tog_env(&project.0, &home.0, args, &[("TOG_SIGNING_KEY", key)]);
            assert_eq!(
                out.status.code(),
                Some(1),
                "{label} {args:?}: {}",
                text(&out.stderr)
            );
            let stderr = text(&out.stderr);
            assert!(
                stderr.contains("TOG_SIGNING_KEY") && stderr.contains("signing key"),
                "{label} {args:?}: {stderr}"
            );
            assert!(
                !home.0.join("store").exists(),
                "{label} {args:?}: store was opened"
            );
            assert!(
                !project.0.join(".tog/closures").exists(),
                "{label} {args:?}: a closure was written"
            );
            assert_eq!(
                std::fs::read_to_string(project.0.join("requirements.txt")).unwrap(),
                "",
                "{label} {args:?}: the manifest was edited"
            );
        }
    }
}

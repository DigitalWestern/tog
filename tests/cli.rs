//! The command surface, exercised through the real binary and offline: no
//! store objects are realized, no network is touched. Every case here is a
//! contract from CLI.md (exit status 0/1/2, help on stdout, errors on stderr
//! with a next step, pass-through for `run`).

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

mod common;

use common::{command, fresh_store, text, tog, tog_at, tog_env, tog_offline, TempDir};

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

/// With a setup flag the bare `tog` is a sync, so a directory with no
/// project fails and says so, rather than printing the help (a CI job
/// pointed at the wrong directory must go red) or naming a missing
/// tog-toolchain.toml.
#[test]
fn setup_flags_outside_a_project_fail_naming_the_missing_manifest() {
    let home = TempDir::boundary("cli-flags-noproject");
    for flag in ["--frozen", "--strict", "--fresh"] {
        let out = tog(&home.0, &home.0, &[flag]);
        assert_eq!(out.status.code(), Some(1), "{flag}");
        assert!(out.stdout.is_empty(), "{flag}: {}", text(&out.stdout));
        let stderr = text(&out.stderr);
        assert!(
            stderr.contains("nothing to sync here: no manifest found"),
            "{flag}: {stderr}"
        );
        assert!(!stderr.contains("tog-toolchain.toml"), "{flag}: {stderr}");
    }
}

/// A bare `tog` where there is nothing to sync is a request for
/// orientation, not a mistake: the help goes to stdout, the one line that
/// says why goes to stderr, and the status is 0.
#[test]
fn no_arguments_outside_a_project_prints_the_help_and_exits_0() {
    let home = TempDir::boundary("cli-noargs");
    let out = tog(&home.0, &home.0, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("USAGE:"), "{stdout}");
    assert!(stdout.contains("START HERE:"), "{stdout}");
    assert!(stdout.contains("  run"), "{stdout}");
    assert!(stdout.contains("SETUP OPTIONS"), "{stdout}");
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("tog: no project in "), "{stderr}");
    assert!(
        stderr.contains("nothing to sync, so here is the help"),
        "{stderr}"
    );
}

/// `-q` silences narration, not the answer. There is nothing else for this
/// invocation to print, so the help still goes to stdout; only the line on
/// stderr that explains it is dropped.
#[test]
fn quiet_outside_a_project_keeps_the_help_and_drops_the_note() {
    let home = TempDir::boundary("cli-noargs-quiet");
    let out = tog(&home.0, &home.0, &["-q"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("START HERE:"),
        "{}",
        text(&out.stdout)
    );
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
}

/// The footer follows a sync that worked. A sync that failed has already
/// said why, and nothing is printed under the error.
#[test]
fn a_bare_tog_whose_sync_fails_prints_no_footer() {
    let home = TempDir::boundary("cli-bare-fail-home");
    let project = TempDir::boundary("cli-bare-fail-project");
    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    // An unreadable signing key refuses before the store is opened: the
    // cheapest offline sync failure the suite has.
    let out = tog_env(
        &project.0,
        &home.0,
        &[],
        &[("TOG_SIGNING_KEY", "/nonexistent/signing.key")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("TOG_SIGNING_KEY"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn help_goes_to_stdout_and_exits_0() {
    let home = TempDir::boundary("cli-help");
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stderr.is_empty(), "{args:?}: {}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("START HERE:"), "{args:?}: {stdout}");
        assert!(stdout.contains("EVERYDAY:"), "{args:?}: {stdout}");
        assert!(stdout.contains("TOG_STORE"), "{args:?}: {stdout}");
    }
    // The bare form's screen, under its topic and under the hidden name a
    // pip or npm reflex reaches for.
    for args in [
        &["help", "setup"][..],
        &["help", "sync"],
        &["sync", "--help"],
        &["i", "-h"],
    ] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let stdout = text(&out.stdout);
        assert!(stdout.starts_with("tog — "), "{args:?}: {stdout}");
        // Every command screen leads with what it looks like in use and
        // keeps the prose behind a heading a reader can skip to.
        assert!(stdout.contains("EXAMPLES:"), "{args:?}: {stdout}");
        assert!(stdout.contains("DETAILS:"), "{args:?}: {stdout}");
        assert!(stdout.contains("--fresh"), "{args:?}: {stdout}");
        assert!(stdout.contains("--frozen"), "{args:?}: {stdout}");
        assert!(
            stdout.contains("tog [--frozen] [--fresh] [--strict]"),
            "{args:?}: {stdout}"
        );
        // `tog install <pkg>` is refused with a pointer to this screen,
        // which must name the verb that does take a package.
        assert!(stdout.contains("tog add <package>"), "{args:?}: {stdout}");
    }
    let inputs = text(&tog(&home.0, &home.0, &["help", "inputs"]).stdout);
    assert!(inputs.starts_with("tog inputs — "), "{inputs}");
    assert!(inputs.contains("package-lock.json"), "{inputs}");
    // `update` is two verbs and the help screen is the specification of the
    // surface, so both grammars are printed.
    let update = text(&tog(&home.0, &home.0, &["help", "update"]).stdout);
    assert!(
        update.contains("tog update [<package>...] [--no-sync]"),
        "{update}"
    );
    assert!(
        update.contains("tog update --toolchain [<ecosystem>] [--no-sync]"),
        "{update}"
    );
    assert!(update.contains("--toolchain [<ecosystem>]"), "{update}");
    let out = tog(&home.0, &home.0, &["help", "inptus"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("did you mean 'inputs'?"));
}

#[test]
fn version() {
    let home = TempDir::boundary("cli-version");
    let expected = format!("{}\n", tog::cli::version_line());
    // The crate version, then the build in parentheses: a short commit id
    // and its date from the checkout this binary was built in, or the one
    // word `unknown build` outside a checkout. Either way the line starts
    // with `tog <version>`, which is what install.sh matches on.
    assert!(
        expected.starts_with(&format!("tog {} (", env!("CARGO_PKG_VERSION"))),
        "{expected}"
    );
    let build = expected
        .trim_end()
        .rsplit_once('(')
        .map(|(_, build)| build.trim_end_matches(')'))
        .unwrap();
    if build != "unknown build" {
        let (commit, date) = build.split_once(' ').unwrap_or_else(|| panic!("{build}"));
        assert!(
            commit.len() >= 7 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "{build}"
        );
        assert!(
            date.len() == 10 && date.as_bytes()[4] == b'-' && date.as_bytes()[7] == b'-',
            "{build}"
        );
    }
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert_eq!(text(&out.stdout), expected);
    }
}

#[test]
fn usage_errors_exit_2_with_a_next_step() {
    let home = TempDir::boundary("cli-usage");
    let cases: &[(&[&str], &str, &str)] = &[
        (&["snyc"], "unknown command 'snyc'", "tog --help"),
        (&["--fersh"], "unknown option '--fersh'; did you mean '--fresh'?", "tog --help"),
        (&["--fresh", "status"], "--fresh belongs to the bare 'tog'; run 'tog --fresh' on its own", "tog --help"),
        (&["sync", "--fersh"], "unknown option '--fersh'; did you mean '--fresh'?", "tog help setup"),
        (&["sync", "now"], "unexpected argument 'now'; 'tog' sets up what the project already declares — to add a dependency run 'tog add now'", "tog help setup"),
        (&["plan", "--jsno"], "plan: unknown option '--jsno'; did you mean '--json'?", "tog help plan"),
        (&["gc", "--keep-days", "soon"], "--keep-days expects a whole number of days, got 'soon'", "tog help gc"),
        (&["gc", "--dryrun"], "gc: unknown option '--dryrun'; did you mean '--dry-run'?", "tog help gc"),
        (&["sbom", "--output"], "--output needs a file path", "tog help sbom"),
        (&["store"], "store needs a subcommand: 'store path' or 'store roots'", "tog help store"),
        (&["store", "root"], "unknown store subcommand 'root'; did you mean 'roots'?", "tog help store"),
        (&["run"], "run: no command given", "tog help run"),
        (&["--dir", "x", "plan"], "unknown option '--dir'; did you mean '--directory'?", "tog --help"),
        (&["-C"], "-C needs a directory", "tog --help"),
        (&["sbom", "-o", "--json"], "-o needs a file path", "tog help sbom"),
        (&["sbom", "-o", ""], "-o needs a file path", "tog help sbom"),
        (&["-C", "", "plan"], "-C needs a directory", "tog --help"),
        (&["-C", "-q", "plan"], "-C needs a directory", "tog --help"),
        (&["add", "--", "--index-url"], "add: dependency spec '--index-url' looks like a tool option; package options are not allowed", "tog help add"),
        (&["add", "requests\n--index-url evil"], "add: dependency spec contains CR, LF, or NUL", "tog help add"),
        (&["x", "--from", "six", "/absolute/executable"], "x: --from requires a single safe executable name", "tog help x"),
        (&["sync", "--frzoen"], "unknown option '--frzoen'; did you mean '--frozen'?", "tog help setup"),
        (&["update", "--toolchain", "serde"], "update --toolchain takes an ecosystem name, not a package; 'serde' is not one of python, node, rust, go, ruby, elixir, dotnet", "tog help update"),
        (&["update", "--toolchain", "pyhton"], "update --toolchain takes an ecosystem name, not a package; 'pyhton' is not one of python, node, rust, go, ruby, elixir, dotnet; did you mean 'python'?", "tog help update"),
        (&["add", "--toolchain"], "add: unknown option '--toolchain'", "tog help add"),
        (&["--frozen", "add", "x"], "--frozen checks the lock without writing it, and 'add' exists to write it; run 'tog add' without --frozen", "tog help add"),
        (&["remove", "x", "--frozen"], "--frozen checks the lock without writing it, and 'remove' exists to write it; run 'tog remove' without --frozen", "tog help remove"),
        (&["--frozen", "update"], "--frozen checks the lock without writing it, and 'update' exists to write it; run 'tog update' without --frozen", "tog help update"),
        (&["--frozen", "status"], "--frozen governs a sync, and 'status' never syncs; run 'tog status' without --frozen", "tog help status"),
        (&["sbom", "--strict"], "--strict governs a sync, and 'sbom' never syncs; run 'tog sbom' without --strict", "tog help sbom"),
        (&["--frozen", "x", "black"], "--frozen checks a project's lock, and 'x' resolves its tool from a registry with no lock to check; run 'tog x' without --frozen", "tog help x"),
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

/// `plan` generates a missing dependency lock the way a sync does, and
/// `--frozen` promises never to modify project inputs, so a frozen plan of
/// a project with no lock is refused by the tailor, naming the file, and
/// leaves the project as it found it. (Without `--frozen` the plan would
/// fetch Node to generate the lock, so only the frozen side runs offline.)
#[test]
fn frozen_plan_never_generates_a_lock() {
    let project = TempDir::boundary("cli-frozen-plan");
    std::fs::write(
        project.0.join("package.json"),
        r#"{"name":"hello","version":"1.0.0"}"#,
    )
    .unwrap();
    let out = tog(&project.0, &project.0, &["--frozen", "plan"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("package-lock.json is missing and --frozen never creates it"),
        "{stderr}"
    );
    assert!(
        !project.0.join("package-lock.json").exists(),
        "--frozen plan generated a lock"
    );
}

/// `--strict` holds for every verb that reaches a sync, whichever policy
/// load runs first. `fmt` loads the policy before it hands a package.json
/// `fmt` script to `run`, and `run`'s sync must still see the flag: a
/// strict sync never creates a toolchain lock, so both spellings refuse
/// before anything is written or downloaded.
#[test]
fn strict_fmt_script_never_creates_the_toolchain_lock() {
    let home = TempDir::boundary("cli-strict-fmt");
    std::fs::write(
        home.0.join("package.json"),
        r#"{"name":"hello","version":"1.0.0","scripts":{"fmt":"node -e 0"}}"#,
    )
    .unwrap();
    for args in [
        &["--strict", "fmt"][..],
        &["--strict", "run", "node", "-e", "0"],
    ] {
        let out = tog(&home.0, &home.0, args);
        let stderr = text(&out.stderr);
        assert!(!out.status.success(), "{args:?} succeeded: {stderr}");
        assert!(
            stderr.contains("tog-toolchain.toml is missing and strict policy never creates it"),
            "{args:?}: {stderr}"
        );
        assert!(
            !home.0.join("tog-toolchain.toml").exists(),
            "{args:?} wrote the toolchain lock"
        );
    }
}

#[test]
fn fmt_is_named_and_typos_are_usage_errors() {
    let home = TempDir::boundary("cli-fmt-cli");
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

/// `tog ls` accepts exactly the ecosystem names it can print. `tog fmt`
/// writes no closure, so a `rustfmt.json` an older tog left is not listed
/// and `rustfmt` is not a filter word.
#[test]
fn ls_accepts_every_ecosystem_name_it_can_print() {
    let home = TempDir::boundary("cli-ls-words-home");
    let project = TempDir::boundary("cli-ls-words-project");
    std::fs::create_dir_all(project.0.join(".tog/closures")).unwrap();
    std::fs::write(
        project.0.join(".tog/closures/rustfmt.json"),
        r#"{"schema":"closure/1","ecosystem":"rustfmt","projected_at":0,
            "body":{"rust_version":"1.96.1",
                    "rust_object":{"path":"/store/objects/r","id":"r"},
                    "rustfmt_object":{"path":"/store/objects/f","id":"f"}}}"#,
    )
    .unwrap();
    std::fs::write(
        project.0.join(".tog/closures/python.json"),
        r#"{"schema":"closure/1","ecosystem":"python","projected_at":0,
            "body":{"python":{"version":"3.12.14"},
                    "plan":{"packages":[{"name":"six","version":"1.17.0",
                                         "filename":"six-1.17.0-py2.py3-none-any.whl"}]}}}"#,
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["ls"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let everything = text(&out.stdout);
    assert!(
        everything.contains("six  1.17.0") && !everything.contains("rustfmt"),
        "{everything}"
    );
    let out = tog(&project.0, &home.0, &["ls", "python"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("six  1.17.0"));

    // The help text names the same set the parser accepts.
    let help = tog(&project.0, &home.0, &["ls", "-h"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        !text(&help.stdout).contains("rustfmt"),
        "{}",
        text(&help.stdout)
    );

    for word in ["npm", "rustfmt"] {
        let out = tog(&project.0, &home.0, &["ls", word]);
        assert_eq!(out.status.code(), Some(2));
        assert!(
            text(&out.stderr).contains(&format!("unknown ecosystem '{word}'")),
            "{}",
            text(&out.stderr)
        );
    }
}

/// A global option is the same option wherever it is typed. `tog ls -v` in
/// particular was a usage error that pointed at help documenting `-v`.
#[test]
fn global_options_work_after_the_command() {
    let home = TempDir::boundary("cli-globals-home");
    let project = TempDir::boundary("cli-globals-project");
    std::fs::create_dir_all(project.0.join(".tog/closures")).unwrap();
    std::fs::write(
        project.0.join(".tog/closures/python.json"),
        r#"{"schema":"closure/1","ecosystem":"python","projected_at":0,
            "body":{"python":{"version":"3.12.14"},
                    "plan":{"packages":[{"name":"six","version":"1.17.0",
                                         "filename":"six-1.17.0-py2.py3-none-any.whl"}]}}}"#,
    )
    .unwrap();

    // -v after the verb is the same -v: it adds the artifact column that
    // `tog help ls` promises, and the plain form still omits it.
    let out = tog(&project.0, &home.0, &["ls", "-v"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let verbose = text(&out.stdout);
    assert!(
        verbose.contains("six  1.17.0  six-1.17.0-py2.py3-none-any.whl"),
        "{verbose}"
    );
    let plain = text(&tog(&project.0, &home.0, &["ls"]).stdout);
    assert!(
        plain.contains("six  1.17.0") && !plain.contains(".whl"),
        "{plain}"
    );
    assert_eq!(
        verbose,
        text(&tog(&project.0, &home.0, &["-v", "ls"]).stdout)
    );

    // The help for ls documents -v, and now the parser accepts it.
    let help = tog(&project.0, &home.0, &["help", "ls"]);
    assert!(
        text(&help.stdout).contains("-v, --verbose"),
        "{}",
        text(&help.stdout)
    );

    // Every screen fits a standard terminal.
    for args in [&["--help"][..], &["help", "gc"], &["help", "x"]] {
        let out = tog(&project.0, &home.0, args);
        for line in text(&out.stdout).lines() {
            assert!(line.chars().count() <= 80, "{args:?}: {line}");
        }
    }

    // -q after the command silences narration the same way it does before,
    // and leaves the one thing quiet must never hide: the error.
    let empty = TempDir::boundary("cli-globals-empty");
    let out = tog(&empty.0, &home.0, &["status", "-q"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("tog: error: no project in"), "{stderr}");
    // Pass-through is untouched: `run` hands -v to the program.
    let out = tog(&empty.0, &home.0, &["run", "-v"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        !text(&out.stderr).contains("unknown option"),
        "{}",
        text(&out.stderr)
    );
}

/// `--json` is a promise about both streams: the document on stdout, and a
/// failure as one JSON object on stderr.
#[test]
fn json_commands_report_failure_as_json_on_stderr() {
    let home = TempDir::boundary("cli-json-errors-home");
    let project = TempDir::boundary("cli-json-errors-project");
    for args in [&["status", "--json"][..], &["ls", "--json"]] {
        let out = tog(&project.0, &home.0, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: {}", text(&out.stdout));
        let value: serde_json::Value =
            serde_json::from_slice(&out.stderr).unwrap_or_else(|error| {
                panic!(
                    "{args:?}: stderr is not JSON ({error}): {}",
                    text(&out.stderr)
                )
            });
        assert!(
            value["error"].as_str().is_some_and(|text| !text.is_empty()),
            "{args:?}: {value}"
        );
    }
    // Without --json the same failure is the prose error it always was.
    let out = tog(&project.0, &home.0, &["status"]);
    assert!(
        text(&out.stderr).starts_with("tog: error: "),
        "{}",
        text(&out.stderr)
    );

    // `plan` prints JSON, so it accepts --json instead of refusing it.
    let out = tog(&project.0, &home.0, &["plan", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert!(value["error"].as_str().is_some(), "{value}");

    // `audit --signed` reports a misconfigured gate itself, and keeps exit
    // 2 so CI can tell an operator mistake from a denied build; under
    // --json that report is a JSON object like any other failure.
    std::fs::create_dir_all(project.0.join(".tog/closures")).unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--signed", "--json"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let value: serde_json::Value = serde_json::from_slice(&out.stderr)
        .unwrap_or_else(|error| panic!("stderr is not JSON ({error}): {}", text(&out.stderr)));
    assert!(
        value["error"]
            .as_str()
            .is_some_and(|text| text.starts_with("audit: ")),
        "{value}"
    );
    // The same failure without --json is still the prose usage error.
    let out = tog(&project.0, &home.0, &["audit", "--signed"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).starts_with("tog: error: audit: "),
        "{}",
        text(&out.stderr)
    );
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--json", "--policy", "absent.toml"],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stderr).is_ok());

    // A failure `main` reports for a --json command is JSON too.
    let out = tog(
        &project.0,
        &home.0,
        &["doctor", "--json", "-C", "absent-dir"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let value: serde_json::Value = serde_json::from_slice(&out.stderr)
        .unwrap_or_else(|error| panic!("stderr is not JSON ({error}): {}", text(&out.stderr)));
    assert!(
        value["error"]
            .as_str()
            .is_some_and(|text| text.contains("cannot change directory")),
        "{value}"
    );
}

/// `gc` narrates; CLI.md reserves stdout for documents, so its lines go to
/// stderr where `--quiet` can silence them.
#[test]
fn gc_narrates_on_stderr_and_quiet_silences_it() {
    let home = TempDir::boundary("cli-gc-stream-home");
    let store_root = home.0.join("store");
    fresh_store(&store_root);
    let canonical_store = store_root.canonicalize().unwrap();
    let project = home.0.join("project");
    std::fs::create_dir_all(project.join(".tog/closures")).unwrap();
    let env_object = publish_certified_object(&canonical_store, "gc-stream-env");
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
    let registered = tog(
        &home.0,
        &home.0,
        &["gc", "--register", project.to_str().unwrap()],
    );
    assert_eq!(
        registered.status.code(),
        Some(0),
        "{}",
        text(&registered.stderr)
    );
    assert!(
        registered.stdout.is_empty(),
        "gc wrote to stdout: {}",
        text(&registered.stdout)
    );
    assert!(
        text(&registered.stderr).contains("registered root"),
        "{}",
        text(&registered.stderr)
    );

    let out = tog(&home.0, &home.0, &["gc", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        out.stdout.is_empty(),
        "gc wrote to stdout: {}",
        text(&out.stdout)
    );
    assert!(
        text(&out.stderr).contains("gc would free"),
        "{}",
        text(&out.stderr)
    );

    let quiet = tog(&home.0, &home.0, &["gc", "--dry-run", "-q"]);
    assert_eq!(quiet.status.code(), Some(0));
    assert!(quiet.stdout.is_empty());
    assert!(quiet.stderr.is_empty(), "{}", text(&quiet.stderr));
}

#[test]
fn fmt_reports_ecosystem_and_project_errors_offline() {
    let home = TempDir::boundary("cli-fmt-errors");
    let empty = TempDir::boundary("cli-fmt-empty");
    let out = tog(&empty.0, &home.0, &["fmt"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no Rust project"));

    let out = tog(&empty.0, &home.0, &["fmt", "--eco", "python"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("fmt: --eco python: tog fmt formats rust"));
    assert!(!home.0.join("store").exists());
}

/// `--eco` is tog's own selector: in a polyglot root whose package.json
/// has a `fmt` script, `--eco rust` must reach the Rust path instead of
/// running the script with a meaningless trailing `--eco rust`. The fixture
/// pins a channel no catalog release carries, so the Rust path fails
/// offline, before any download, on a diagnostic that names the channel and
/// could only come from that path.
#[test]
fn fmt_eco_selects_the_ecosystem_and_never_delegates_to_the_script() {
    let home = TempDir::boundary("cli-fmt-eco-home");
    let project = TempDir::boundary("cli-fmt-eco-project");
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
        "[toolchain]\nchannel = \"1.69.0\"\n",
    )
    .unwrap();

    let out = tog(&project.0, &home.0, &["fmt", "--eco", "rust"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("rust toolchain") && stderr.contains("1.69.0"),
        "--eco rust did not reach the Rust path: {stderr}"
    );
    assert!(
        !stderr.contains("command 'fmt'") && !stderr.contains("script-fmt"),
        "--eco rust delegated to the package.json script: {stderr}"
    );
    assert!(!project.0.join("script-ran.txt").exists());

    // A non-Rust ecosystem is still refused here, not handed to the script.
    let out = tog(&project.0, &home.0, &["fmt", "--eco", "python"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("fmt: --eco python: tog fmt formats rust"),
        "{stderr}"
    );
    assert!(!project.0.join("script-ran.txt").exists());

    // Without --eco the script still wins. It runs through `tog run`, which
    // syncs the never-synced project first; only that path says so, and the
    // pinned channel stops that sync offline, at selection, as it did the
    // Rust path above.
    let out = tog(&project.0, &home.0, &["fmt", "--check"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("syncing first: ") && stderr.contains("node not synced"),
        "script no longer wins: {stderr}"
    );
    assert!(!stderr.contains("script-fmt"), "{stderr}");
    assert!(!project.0.join("script-ran.txt").exists());
    assert!(!project.0.join(".tog/closures/rustfmt.json").exists());
    // Opening the store creates its directories; nothing was realized in it.
    let objects = home.0.join("store/objects");
    assert!(
        !objects.is_dir() || std::fs::read_dir(&objects).unwrap().next().is_none(),
        "an object was realized offline"
    );
}

#[test]
fn failures_exit_1_and_survive_quiet() {
    let home = TempDir::boundary("cli-fail");
    let project = TempDir::boundary("cli-empty");
    // An empty directory has no manifest: a real failure, not a usage error.
    let out = tog(&project.0, &home.0, &["plan"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.starts_with("tog: error: nothing to sync here"),
        "{stderr}"
    );
    // The machine prefix never reaches the user (#100).
    assert!(!stderr.contains("no_manifest"), "{stderr}");

    // --quiet silences narration but never the error.
    let out = tog(&project.0, &home.0, &["--quiet", "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("tog: error: nothing to sync here"));
    let out = tog(&project.0, &home.0, &["-q", "--no-color", "-v", "plan"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn directory_option_changes_where_the_command_runs() {
    let home = TempDir::boundary("cli-chdir");
    let project = TempDir::boundary("cli-chdir-project");
    // Only the project has a manifest. From `home` there is no project;
    // pointed at the project, status reports its python manifest, which
    // only a command that ran there can see.
    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let here = tog(&home.0, &home.0, &["status"]);
    assert_eq!(here.status.code(), Some(1));
    assert!(
        text(&here.stderr).contains("no project in"),
        "{}",
        text(&here.stderr)
    );
    assert!(
        !text(&here.stdout).contains("python"),
        "{}",
        text(&here.stdout)
    );
    for option in ["-C", "--directory"] {
        let out = tog(
            &home.0,
            &home.0,
            &[option, project.0.to_str().unwrap(), "-v", "status"],
        );
        assert!(
            text(&out.stdout).contains("python  not synced"),
            "{option}: stdout:\n{}\nstderr:\n{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        assert!(
            text(&out.stderr).contains(&format!(
                "[verbose] working directory: {}",
                project.0.display()
            )),
            "{option}: {}",
            text(&out.stderr)
        );
    }

    let missing = project.0.join("missing");
    let out = tog(&home.0, &home.0, &["-C", missing.to_str().unwrap(), "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("tog: error: cannot change directory to"));
}

#[test]
fn run_passes_arguments_through_and_needs_a_project() {
    let home = TempDir::boundary("cli-run");
    let project = TempDir::boundary("cli-run-project");
    // Flags after the program are the program's: tog does not parse
    // them, so the only error is the missing project. With no manifest
    // there is nothing to sync, and the message says what it looked for
    // rather than sending the user to a `tog` that would say the same.
    let out = tog(&project.0, &home.0, &["run", "python", "--help"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("no environment projected here"), "{stderr}");
    assert!(stderr.contains("no manifest to sync one from"), "{stderr}");
    assert!(stderr.contains("(see 'tog help inputs')"), "{stderr}");
    assert!(!stderr.contains("syncing first"), "{stderr}");
    // `--` reaches the same place with a program literally named `-h`.
    let out = tog(&project.0, &home.0, &["run", "--", "-h"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no environment projected here"));
}

/// A project that has a manifest but no projection is synced before the
/// command runs, and the sync's own refusal is the command's failure.
/// Offline: the manifest pins a CPython no catalog has, so the sync stops
/// at selection, before the store is written or anything is fetched.
#[test]
fn run_and_env_sync_a_project_before_reading_it() {
    let home = TempDir::boundary("cli-autosync");
    let project = TempDir::boundary("cli-autosync-project");
    std::fs::write(
        project.0.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = \"==0.0.1\"\n",
    )
    .unwrap();
    // From a subdirectory too: the manifest above is the project.
    let nested = project.0.join("src");
    std::fs::create_dir_all(&nested).unwrap();
    for cwd in [&project.0, &nested] {
        for args in [&["run", "python", "--version"][..], &["env"]] {
            let out = tog(cwd, &home.0, args);
            assert_eq!(out.status.code(), Some(1), "{args:?} in {}", cwd.display());
            let stderr = text(&out.stderr);
            assert!(
                stderr.contains("tog: syncing first: python not synced"),
                "{args:?} in {}: {stderr}",
                cwd.display()
            );
            assert!(stderr.contains("no pinned CPython"), "{args:?}: {stderr}");
            // The old advice would send them to the command that just ran.
            assert!(!stderr.contains("run `tog` first"), "{args:?}: {stderr}");
            assert!(out.stdout.is_empty(), "{args:?}: {}", text(&out.stdout));
        }
    }
}

/// The first build in a project with no toolchain lock creates the lock
/// for every ecosystem (#180), so a Python pin no catalog carries stops
/// `tog build cargo` too. The error says why, and what clears it.
/// Offline: selection fails before the store is written or anything is
/// fetched.
#[test]
fn a_first_scoped_build_explains_why_another_ecosystem_stops_it() {
    let home = TempDir::boundary("cli-first-build-home");
    let project = TempDir::boundary("cli-first-build-project");
    std::fs::write(
        project.0.join("Cargo.toml"),
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        project.0.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = \"==0.0.1\"\n",
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["build", "cargo"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("creating tog-toolchain.toml selects a toolchain for every ecosystem")
            && stderr.contains("fix the python toolchain error above"),
        "{stderr}"
    );
    assert!(!project.0.join("tog-toolchain.toml").exists());
}

/// `tog env` prints the environment `tog run` would give a child, so the
/// shell that evals it sees exactly what a tog-run command sees. Offline:
/// the `.venv` symlink and a closure record are the whole projection the
/// Python tailor reads, the same fixture `status` is tested against.
#[test]
fn env_prints_the_run_environment_as_shell_lines() {
    let home = TempDir::boundary("cli-env-home");
    let project = TempDir::boundary("cli-env-project");

    // Outside a project there is nothing to print, and stdout stays
    // empty: a shell evaling this must not get half an environment.
    let out = tog(&project.0, &home.0, &["env"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("no environment projected here"), "{stderr}");
    assert!(stderr.contains("no manifest to sync one from"), "{stderr}");

    let object = project.0.join("env-object");
    std::fs::create_dir_all(object.join("bin")).unwrap();
    std::os::unix::fs::symlink(&object, project.0.join(".venv")).unwrap();
    let platform = tog::kernel::platform::Platform::host().unwrap();
    let closures = project.0.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    std::fs::write(
        closures.join("python.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": platform.triple(),
            "projected_at": 1,
            "body": {
                "env_object": object,
                "python": {"version": "3.12.14"},
                "plan": {"packages": []},
            },
        }))
        .unwrap(),
    )
    .unwrap();
    // The command reads the cwd the kernel resolves, not the fixture path.
    let venv = project.0.canonicalize().unwrap().join(".venv");

    let out = tog(&project.0, &home.0, &["env"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("export PATH='"), "{stdout}");
    assert!(
        stdout.contains(&format!("{}/bin", venv.display())),
        "{stdout}"
    );
    // The inherited PATH is referenced, not frozen into the line.
    assert!(stdout.contains(":\"$PATH\"\n"), "{stdout}");
    assert!(
        stdout.contains(&format!("export VIRTUAL_ENV='{}'\n", venv.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains("export PYTHONDONTWRITEBYTECODE='1'\n"),
        "{stdout}"
    );
    // Every line is a shell statement: no narration reaches stdout.
    for line in stdout.lines() {
        assert!(
            line.starts_with("export ") || line.starts_with("unset "),
            "not a shell line: {line}"
        );
    }

    // `--shell` decides, whatever $SHELL says.
    let out = tog_env(
        &project.0,
        &home.0,
        &["env", "--shell", "fish"],
        &[("SHELL", "/bin/bash")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.starts_with("set -gx PATH '"), "{stdout}");
    assert!(stdout.contains(" $PATH\n"), "{stdout}");
    assert!(
        stdout.contains(&format!("set -gx VIRTUAL_ENV '{}'\n", venv.display())),
        "{stdout}"
    );

    // With no `--shell`, $SHELL chooses, and a shell tog does not speak
    // gets POSIX exports rather than a refusal.
    for (shell, first_word) in [("/usr/bin/fish", "set"), ("/bin/nu", "export")] {
        let out = tog_env(&project.0, &home.0, &["env"], &[("SHELL", shell)]);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        let stdout = text(&out.stdout);
        assert!(stdout.starts_with(first_word), "{shell}: {stdout}");
    }
}

#[test]
fn store_path_honors_the_store_variable() {
    let home = TempDir::boundary("cli-store");
    let out = tog(&home.0, &home.0, &["store", "path"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let printed = PathBuf::from(text(&out.stdout).trim());
    assert_eq!(printed, home.0.join("store"));
    // A relative store is read from the directory `-C` names, and the
    // answer says so: an absolute path, not the variable as typed.
    std::fs::create_dir(home.0.join("project")).unwrap();
    let out = tog_env(
        &home.0,
        &home.0,
        &["-C", "project", "store", "path"],
        &[("TOG_STORE", "relative-store")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let printed = PathBuf::from(text(&out.stdout).trim());
    assert_eq!(printed, home.0.join("project/relative-store"));
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    // Once the store exists, its canonical root.
    let out = tog(&home.0, &home.0, &["store", "path"]);
    let printed = PathBuf::from(text(&out.stdout).trim());
    assert_eq!(printed, home.0.join("store").canonicalize().unwrap());
}

// --- bare `tog`, aliases, the script shortcut, inspect verbs ---

/// A projected environment is immutable, so the habits that mutate one are
/// refused with the tog verb that replaces them — before the projection is
/// even looked for, because the explanation is the same everywhere.
#[test]
fn pip_activate_and_npm_install_are_refused_with_the_tog_verb() {
    let home = TempDir::boundary("cli-immutable");
    let project = TempDir::boundary("cli-immutable-project");
    let cases: &[(&[&str], &str)] = &[
        (&["run", "pip", "install", "flask"], "tog add <package>"),
        (
            &["run", "pip", "uninstall", "flask"],
            "tog remove <package>",
        ),
        // The same pip by another road.
        (
            &["run", "python", "-m", "pip", "install", "flask"],
            "tog add <package>",
        ),
        // A value-taking option puts a bare word before the subcommand.
        (
            &[
                "run",
                "pip",
                "--index-url",
                "https://m/simple",
                "install",
                "flask",
            ],
            "tog add <package>",
        ),
        (&["run", "activate"], "no activate script"),
        (
            &["run", "source", ".venv/bin/activate"],
            "no activate script",
        ),
        // install/ci install the lockfile, so `tog` replaces them.
        (
            &["run", "npm", "install", "is-odd"],
            "'tog' sets node_modules up from the lockfile",
        ),
        (
            &["run", "npm", "ci"],
            "'tog' sets node_modules up from the lockfile",
        ),
        (&["run", "yarn", "add", "is-odd"], "node_modules"),
        // A global option's value before the subcommand does not hide it.
        (
            &["run", "npm", "--prefix", ".", "install", "is-odd"],
            "'npm install' would replace the node_modules projection",
        ),
        // Bare yarn installs.
        (&["run", "yarn"], "node_modules"),
        // An install another command runs, and an npm abbreviation.
        (
            &["run", "npx", "npm", "install"],
            "'npm install' would replace the node_modules projection",
        ),
        (
            &["run", "npm", "dedu"],
            "'npm dedupe' would replace the node_modules projection",
        ),
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
    // Running or reading the environment is untouched; only the verbs that
    // would change it are refused.
    for args in [
        &["run", "npm", "run", "build"][..],
        &["run", "npm", "ls"],
        &["run", "pip", "list"],
        &["run", "pip", "--version"],
        &["run", "python", "-m", "pip", "list"],
        // `-m` after the script belongs to the script, not to python.
        &["run", "python", "script.py", "-m", "pip", "install", "x"],
    ] {
        let stderr = text(&tog(&project.0, &home.0, args).stderr);
        assert!(
            stderr.contains("no environment projected here"),
            "{args:?} was refused instead of run: {stderr}"
        );
    }
}

/// `--quiet` points fd 2 at /dev/null. A panic must still reach the user,
/// or the process exits 101 having printed nothing at all.
#[test]
fn a_panic_is_printed_even_under_quiet() {
    let home = TempDir::boundary("cli-panic-quiet");
    // No HOME and no TOG_STORE: the store's home lookup panics. The only
    // deterministic panic the CLI can be driven into from outside.
    let out = command(&home.0, &home.0, &home.0.join("store"))
        .args(["--quiet", "store", "path"])
        .env_remove("HOME")
        .env_remove("TOG_STORE")
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
    let home = TempDir::boundary("cli-script");
    let project = TempDir::boundary("cli-script-project");
    std::fs::write(
        project.0.join("package.json"),
        r#"{"name": "p", "scripts": {"dev": "echo hi", "build": "echo built"}}"#,
    )
    .unwrap();
    // A never-synced project is synced before the script runs. The
    // second manifest pins a CPython no catalog has, so that sync refuses
    // offline, before anything is fetched; the point here is only that
    // `run` was reached and syncs, a runtime error (1), not a usage error (2).
    std::fs::write(
        project.0.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = \"==0.0.1\"\n",
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["dev", "--port", "3000"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("syncing first: "), "{stderr}");
    assert!(stderr.contains("node not synced"), "{stderr}");
    assert!(stderr.contains("no pinned CPython"), "{stderr}");
    // From a subdirectory of the never-synced project, `tog dev` finds the
    // script `tog run dev` would (#251), instead of "unknown command".
    let src = project.0.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let out = tog(&src, &home.0, &["dev", "--port", "3000"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("syncing first: "), "{stderr}");
    assert!(stderr.contains("no pinned CPython"), "{stderr}");
    // A bare `tog` and `tog sync` from there sync the project above too:
    // the pinned CPython stops them at the project's own selection.
    for args in [&[][..], &["sync"]] {
        let out = tog(&src, &home.0, args);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains("no pinned CPython"), "{args:?}: {stderr}");
    }
    // A built-in verb always wins over a same-named script. `build` syncs
    // only for the ecosystem it builds, so the stale node and python
    // environments here start no sync in front of its own refusal.
    let out = tog(&project.0, &home.0, &["build"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("tog build requires"), "{stderr}");
    assert!(!stderr.contains("syncing first"), "{stderr}");
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
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

/// `tog build cargo` host-preflights only the ecosystem it builds (#159),
/// but every detected ecosystem's toolchain inputs are still checked: a
/// malformed Python request refuses the Cargo build rather than being
/// read as no request and locked as if absent.
#[test]
fn build_refuses_an_unrelated_ecosystems_malformed_toolchain_input() {
    let home = TempDir::boundary("cli-build-inputs");
    let project = TempDir::boundary("cli-build-inputs-project");
    std::fs::write(
        project.0.join("Cargo.toml"),
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        project.0.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = 3\n",
    )
    .unwrap();

    for args in [&[][..], &["build", "cargo"]] {
        let out = tog(&project.0, &home.0, args);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{args:?}: {}",
            text(&out.stderr)
        );
        let stderr = text(&out.stderr);
        assert!(
            stderr.contains("requires-python must be a string"),
            "{args:?}: {stderr}"
        );
        assert!(!project.0.join("tog-toolchain.toml").exists(), "{args:?}");
        assert!(
            !project.0.join(".tog/closures").exists(),
            "{args:?}: a closure was written"
        );
    }
}

/// Lock resolution stays whole under the build's narrowed sync (#159): with
/// both sections committed and only Python's toolchain input changed, a
/// Cargo build that needs a sync refuses on the stale Python section and
/// leaves the committed lock byte for byte as it was.
#[test]
fn build_refuses_an_unrelated_stale_lock_section_and_keeps_the_lock() {
    let home = TempDir::boundary("cli-build-stale");
    let project = TempDir::boundary("cli-build-stale-project");
    std::fs::write(
        project.0.join("Cargo.toml"),
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        project.0.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::write(project.0.join(".python-version"), "3.12\n").unwrap();
    let out = tog(&project.0, &home.0, &["update", "--toolchain", "--no-sync"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lock = std::fs::read(project.0.join("tog-toolchain.toml")).unwrap();
    let committed = String::from_utf8_lossy(&lock);
    assert!(committed.contains("[toolchain.python]"), "{committed}");
    assert!(committed.contains("[toolchain.rust]"), "{committed}");

    std::fs::write(project.0.join(".python-version"), "3.13\n").unwrap();
    let out = tog(&project.0, &home.0, &["build", "cargo"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("syncing first: cargo"), "{stderr}");
    assert!(
        stderr.contains("tog-toolchain.toml is stale for python"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(project.0.join("tog-toolchain.toml")).unwrap(),
        lock
    );
}

#[test]
fn inspect_verbs_offline() {
    let home = TempDir::boundary("cli-inspect");
    let project = TempDir::boundary("cli-inspect-project");

    let out = tog(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no project in"));
    let out = tog(&project.0, &home.0, &["ls"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("nothing synced here; run 'tog' first"));

    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let out = tog(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("python  not synced  run 'tog'"),
        "{}",
        text(&out.stdout)
    );
    let out = tog(&project.0, &home.0, &["status", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["synced"], false);
    assert_eq!(value["ecosystems"][0]["state"], "not-synced");

    let out = tog(&project.0, &home.0, &["doctor"]);
    let stdout = text(&out.stdout);
    for name in [
        "version",
        "platform",
        "store",
        "sandbox",
        "c-toolchain",
        "project",
    ] {
        assert!(stdout.contains(&format!("  {name}")), "{stdout}");
    }
    // The build is the first row, and an unreachable release manifest is
    // reported, not failed: offline is not unhealthy.
    let first = stdout.lines().next().unwrap();
    assert!(
        first.starts_with("ok    version   ")
            && first.contains(&tog::cli::version_line())
            && first.contains("newer release not checked ("),
        "{first}"
    );
    assert!(stdout.contains("python found; not synced yet"), "{stdout}");
    let out = tog(&project.0, &home.0, &["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["checks"].is_array());
    assert_eq!(value["checks"][0]["name"], "version");
    assert_eq!(value["checks"][0]["level"], "ok");

    let out = tog(&project.0, &home.0, &["completions", "bash"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("complete -F _tog tog"));
    let out = tog(&project.0, &home.0, &["completions", "powershell"]);
    assert_eq!(out.status.code(), Some(2));
}

/// `status`, `sbom`, `ls` and `store path` read the project, never the
/// store (#183, #252): they
/// create no store where there was none, so they work with a store that
/// cannot be written, and take no lease a GC sweep could make them wait on.
#[test]
fn read_only_reports_never_create_the_store() {
    let home = TempDir::boundary("cli-readonly-home");
    let project = TempDir::boundary("cli-readonly-project");
    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let out = tog(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("not synced"),
        "{}",
        text(&out.stdout)
    );
    let out = tog(&project.0, &home.0, &["sbom"]);
    assert!(
        text(&out.stderr).contains("no closures found"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        !home.0.join("store").exists(),
        "a read-only report created the store"
    );

    // A closure committed from the other OS: `sbom` and `ls` describe what
    // it records (#252), still without a store.
    let host = tog::kernel::platform::Platform::host().unwrap();
    let foreign = tog::kernel::platform::Platform::ALL
        .iter()
        .find(|platform| platform.is_macos() != host.is_macos())
        .unwrap();
    std::fs::create_dir_all(project.0.join(".tog/closures")).unwrap();
    std::fs::write(
        project.0.join(".tog/closures/python.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": foreign.triple(),
            "projected_at": 1,
            "body": {
                "env_object": "/store/objects/abc",
                "plan": {
                    "python_version": "3.12.14",
                    "packages": [
                        {"name": "six", "version": "1.17.0", "sha256": "aa".repeat(32)},
                    ],
                },
            },
        }))
        .unwrap(),
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["sbom"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("pkg:pypi/six@1.17.0"),
        "{}",
        text(&out.stdout)
    );
    let out = tog(&project.0, &home.0, &["ls"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("six"), "{}", text(&out.stdout));
    // `store path` answers where the store would be without making it.
    let out = tog(&project.0, &home.0, &["store", "path"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout).trim(),
        home.0.join("store").display().to_string()
    );
    assert!(
        !home.0.join("store").exists(),
        "sbom, ls or store path created the store"
    );
}

#[test]
fn successful_reports_ignore_store_permissions_and_the_gc_lease() {
    use tog::kernel::activity::ActivityMode;
    use tog::kernel::store::Store;

    let home = TempDir::boundary("cli-readonly-success-home");
    let project = TempDir::boundary("cli-readonly-success-project");
    synced_python_closure_with_exception(&home.0, &project.0, "git-dependency");
    let store = Store::open_at(&home.0.join("store")).unwrap();
    drop(store.activity(ActivityMode::Exclusive).unwrap());
    let lock = store.root.join("activity.lock");
    let before = common::snapshot(&store.root);

    let check_reports = || {
        for args in [["status", "--json"].as_slice(), ["sbom"].as_slice()] {
            let mut child = command(&project.0, &home.0, &store.root)
                .args(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("{args:?} waited for the GC lease");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
            let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            if args[0] == "status" {
                assert_eq!(value["synced"], true);
            } else {
                assert_eq!(value["bomFormat"], "CycloneDX");
            }
        }
        assert_eq!(common::snapshot(&store.root), before);
    };

    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::set_permissions(&store.root, std::fs::Permissions::from_mode(0o555)).unwrap();
    check_reports();
    std::fs::set_permissions(&store.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();

    let _gc = store.activity(ActivityMode::Exclusive).unwrap();
    check_reports();
}

/// A closure whose inputs were never recorded cannot be compared with the
/// files on disk, so `status` must not report it synced or exit 0: a CI
/// gate that trusts that word would admit any closure old enough.
#[test]
fn status_never_calls_an_unchecked_closure_synced() {
    let home = TempDir::boundary("cli-unchecked-home");
    let project = TempDir::boundary("cli-unchecked-project");
    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let env = project.0.join("env-object");
    std::fs::create_dir_all(env.join("bin")).unwrap();
    std::os::unix::fs::symlink(&env, project.0.join(".venv")).unwrap();
    let platform = tog::kernel::platform::Platform::host().unwrap();
    let closures = project.0.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    std::fs::write(
        closures.join("python.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": platform.triple(),
            "projected_at": 1,
            // No "inputs": the record predates input recording.
            "body": {
                "env_object": env,
                "python": {"version": "3.12.14"},
                "plan": {"packages": []},
            },
        }))
        .unwrap(),
    )
    .unwrap();

    let out = tog(&project.0, &home.0, &["status"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("python  unchecked"), "{stdout}");
    assert!(stdout.contains("0 of 1 synced; 1 unchecked."), "{stdout}");
    assert!(stdout.contains("Exit status is 0 only when"), "{stdout}");

    let out = tog(&project.0, &home.0, &["status", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["synced"], false);
    assert_eq!(value["ecosystems"][0]["state"], "unchecked");
}

// --- the offline paths of add/remove/x ---

#[test]
fn dependency_verbs_offline_paths() {
    let home = TempDir::boundary("cli-deps");
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
    let project = TempDir::boundary("cli-deps-req");
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
    let setup = TempDir::boundary("cli-deps-setup");
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
    let pnpm = TempDir::boundary("cli-deps-pnpm");
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
    let poetry = TempDir::boundary("cli-deps-poetry");
    std::fs::write(poetry.0.join("pyproject.toml"), "[tool.poetry]\nname='p'\n").unwrap();
    let out = tog(&poetry.0, &home.0, &["update"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("poetry update"),
        "{}",
        text(&out.stderr)
    );
    let dotnet = TempDir::boundary("cli-deps-dotnet");
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
    let home = TempDir::boundary("cli-x");
    let out = tog(&home.0, &home.0, &["x", "ruff", "--version"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("tog x py:ruff"), "{stderr}");
    let out = tog(&home.0, &home.0, &["x"]);
    assert_eq!(out.status.code(), Some(2));
}

/// Issue #101. A record whose identity no longer hashes to the id it is
/// filed under cannot be read, so the fail-closed sweep refuses. The refusal
/// names the record and `--drop-object`, which is the exit.
#[test]
fn an_unreadable_record_stops_the_sweep_and_is_cleared_by_drop_object() {
    let home = TempDir::boundary("cli-wedged-record");
    let store_root = home.0.join("store");

    // A project root, so the sweep has an initialized registry to work from.
    fresh_store(&store_root);
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

    // A command that does not sweep is not held up by the record: `x`
    // fails offline for its own reason and says nothing about it.
    let other = tog(&home.0, &home.0, &["x", "ruff", "--version"]);
    assert!(
        !text(&other.stderr).contains(&id),
        "{}",
        text(&other.stderr)
    );

    // The sweep refuses, deletes nothing, and names the way out.
    for args in [&["gc"][..], &["gc", "--dry-run"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
        let stderr = text(&out.stderr);
        assert!(stderr.contains("refusing to sweep"), "{stderr}");
        assert!(
            stderr.contains(&format!("--drop-object {id}")),
            "the recovery command is not named: {stderr}"
        );
        assert!(object.is_dir(), "{stderr}");
    }

    let out = tog(&home.0, &home.0, &["gc", "--drop-object", &id]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!object.exists(), "{}", text(&out.stdout));
    assert!(!meta_path.exists(), "{}", text(&out.stdout));

    let out = tog(&home.0, &home.0, &["gc", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

/// A store as a tog from before the format marker left it: namespaces, an
/// object with the record shape of that time, a pathname-only root, a
/// download, a staging leftover and a backup, and no marker. Returns the
/// canonical store root and the object's path.
fn pre_epoch_store(home: &Path) -> (PathBuf, PathBuf) {
    let store = home.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp/stage-old", "roots"] {
        std::fs::create_dir_all(store.join(sub)).unwrap();
    }
    std::fs::create_dir_all(store.join("backups/venv-old")).unwrap();
    let store = store.canonicalize().unwrap();
    let object = publish_certified_object(&store, "pre-epoch-env");
    let id = object.file_name().unwrap().to_str().unwrap().to_string();
    let record = store.join("meta").join(format!("{id}.json"));
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
    let fields = value.as_object_mut().unwrap();
    for key in ["schema", "dependencies", "cache_digests", "evidence"] {
        fields.remove(key);
    }
    fields.insert("refs".into(), serde_json::json!([]));
    std::fs::write(&record, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    std::fs::write(
        store.join("roots").join("a".repeat(40)),
        format!("{}\n", home.join("project").display()),
    )
    .unwrap();
    std::fs::write(store.join("cache/sha256").join("c".repeat(64)), b"download").unwrap();
    std::fs::write(store.join("backups/venv-old/kept"), b"mine").unwrap();
    (store, object)
}

/// The first command that opens a store creates it with the format marker.
#[test]
fn a_new_store_is_created_with_the_format_marker() {
    let home = TempDir::boundary("cli-format-new");
    let store = home.0.join("store");
    assert!(!store.exists());
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).is_empty(), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(store.join("format")).unwrap(),
        "tog-store 1\n"
    );
    assert!(store.join("objects").is_dir());
    // And it opens again, marker unchanged.
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(store.join("format")).unwrap(),
        "tog-store 1\n"
    );
}

/// A store with no marker is refused by every command that would read it,
/// with the fix on its own line, and is left exactly as it was. `store path` and
/// `doctor` still answer, and help and version never open a store.
#[test]
fn a_store_from_before_the_marker_is_refused_and_the_fix_is_named() {
    let home = TempDir::boundary("cli-format-pre-epoch");
    let (store, object) = pre_epoch_store(&home.0);

    for args in [
        &["gc"][..],
        &["gc", "--dry-run"],
        &["gc", "--keep-days", "0"],
        &["gc", "--forget", &"a".repeat(40)],
        &["store", "roots"],
        &["plan"],
        // The fix line is part of the failure: `--quiet` keeps it.
        &["-q", "store", "roots"],
        &["x", "ruff", "--version"],
    ] {
        let out = tog(&home.0, &home.0, args);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("has no format marker"),
            "{args:?}: {stderr}"
        );
        // The command is the fix line, not a phrase inside the sentence.
        assert!(
            stderr.ends_with("tog:     fix: tog gc --reset\n"),
            "{args:?}: {stderr}"
        );
        assert_eq!(
            stderr.matches("gc --reset").count(),
            1,
            "{args:?}: {stderr}"
        );
        assert!(
            stderr.contains("move the directory aside"),
            "{args:?}: {stderr}"
        );
        assert!(
            object.join("payload").is_file(),
            "{args:?} removed an object"
        );
        assert!(!store.join("format").exists(), "{args:?} wrote a marker");
        assert!(
            store.join("roots").join("a".repeat(40)).is_file(),
            "{args:?} removed a root"
        );
    }

    let out = tog(&home.0, &home.0, &["store", "path"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim_end(), store.to_str().unwrap());
    let stderr = text(&out.stderr);
    assert!(
        stderr.starts_with("tog: warning: the store at "),
        "{stderr}"
    );
    assert!(
        stderr.contains("tog:     fix: tog gc --reset\n"),
        "{stderr}"
    );

    let out = tog(&home.0, &home.0, &["doctor"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let row = stdout
        .lines()
        .find(|line| line.contains(" store "))
        .unwrap_or_else(|| panic!("no store row: {stdout}"));
    assert!(row.starts_with("fail"), "{row}");
    assert!(row.contains("has no format marker"), "{row}");
    assert!(row.contains("run 'tog gc --reset'"), "{row}");

    // A command asked for JSON fails in JSON, the fix a key of its own.
    let out = tog(&home.0, &home.0, &["plan", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    let failure: serde_json::Value = serde_json::from_slice(&out.stderr)
        .unwrap_or_else(|error| panic!("{error}: {}", text(&out.stderr)));
    assert_eq!(failure["fix"], "tog gc --reset");
    let error = failure["error"].as_str().unwrap();
    assert!(error.contains("has no format marker"), "{error}");
    assert!(!error.contains("--reset"), "{error}");

    for args in [&["--help"][..], &["version"], &["gc", "--help"]] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(text(&out.stderr).is_empty(), "{args:?}");
    }
    assert!(!store.join("format").exists());
}

/// A marker this tog does not know is refused too, and never rewritten: a
/// higher number says a newer tog wrote the store, anything else says the
/// marker is damaged.
#[test]
fn an_unknown_or_newer_format_marker_is_refused() {
    let home = TempDir::boundary("cli-format-unknown");
    let store = home.0.join("store");
    fresh_store(&store);
    let store = store.canonicalize().unwrap();
    let object = publish_certified_object(&store, "newer-env");

    for (marker, expected, fix) in [
        ("tog-store 2\n", "a newer tog wrote it", "tog update --self"),
        (
            "tog-store one\n",
            "a format marker this tog does not know",
            "tog gc --reset",
        ),
        (
            "",
            "a format marker this tog does not know",
            "tog gc --reset",
        ),
        (
            "tog-store 1\nextra\n",
            "a format marker this tog does not know",
            "tog gc --reset",
        ),
    ] {
        std::fs::write(store.join("format"), marker).unwrap();
        for args in [&["gc", "--dry-run"][..], &["store", "roots"]] {
            let out = tog(&home.0, &home.0, args);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "{marker:?} {args:?}: {stderr}");
            assert!(stderr.contains(expected), "{marker:?} {args:?}: {stderr}");
            assert!(
                stderr.ends_with(&format!("tog:     fix: {fix}\n")),
                "{marker:?} {args:?}: {stderr}"
            );
        }
        let out = tog(&home.0, &home.0, &["store", "path"]);
        assert_eq!(out.status.code(), Some(0), "{marker:?}");
        assert!(
            text(&out.stderr).contains(&format!("tog:     fix: {fix}\n")),
            "{marker:?}: {}",
            text(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(store.join("format")).unwrap(),
            marker,
            "the marker was rewritten"
        );
        assert!(object.join("payload").is_file(), "{marker:?}");
    }
}

/// A marker that exists and cannot be read is refused like an unknown one,
/// and takes no recovery verb with it: `store path` still prints the path
/// with the warning, `doctor` reports a failing store row and `gc --reset`
/// still empties the store.
#[test]
fn an_unreadable_format_marker_leaves_every_way_out_working() {
    let home = TempDir::boundary("cli-format-unreadable");
    let store = home.0.join("store");
    fresh_store(&store);
    let store = store.canonicalize().unwrap();
    let object = publish_certified_object(&store, "unreadable-env");
    let marker = store.join("format");
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&marker).is_ok() {
        // Root reads a file of any mode: there is nothing to refuse.
        return;
    }

    for args in [&["gc", "--dry-run"][..], &["store", "roots"]] {
        let out = tog(&home.0, &home.0, args);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("a format marker this tog cannot read"),
            "{args:?}: {stderr}"
        );
        assert!(
            stderr.ends_with("tog:     fix: tog gc --reset\n"),
            "{args:?}: {stderr}"
        );
        assert!(object.join("payload").is_file(), "{args:?}");
    }

    let out = tog(&home.0, &home.0, &["store", "path"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(text(&out.stdout).trim_end(), store.to_str().unwrap());
    assert!(
        stderr.starts_with("tog: warning: the store at "),
        "{stderr}"
    );
    assert!(stderr.contains("cannot read"), "{stderr}");
    assert!(
        stderr.contains("tog:     fix: tog gc --reset\n"),
        "{stderr}"
    );

    let out = tog(&home.0, &home.0, &["doctor"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let row = stdout
        .lines()
        .find(|line| line.contains(" store "))
        .unwrap_or_else(|| panic!("no store row: {stdout}"));
    assert!(row.starts_with("fail"), "{row}");
    assert!(row.contains("cannot read"), "{row}");
    assert!(row.contains("run 'tog gc --reset'"), "{row}");

    let out = tog(&home.0, &home.0, &["gc", "--reset", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("would remove"));
    assert!(object.join("payload").is_file());

    let out = tog(&home.0, &home.0, &["gc", "--reset"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!object.exists(), "reset kept an object");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "tog-store 1\n");
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

/// `gc --reset --dry-run` on a store tog refuses: it lists what a reset
/// would remove and changes nothing, so the store is still refused after.
#[test]
fn gc_reset_dry_run_lists_what_it_would_remove_and_writes_nothing() {
    let home = TempDir::boundary("cli-reset-dry-run");
    let (store, object) = pre_epoch_store(&home.0);

    let out = tog(&home.0, &home.0, &["gc", "--reset", "--dry-run"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    for name in ["objects", "meta", "roots"] {
        assert!(
            stderr.contains(&format!("tog: would remove {}", store.join(name).display())),
            "{name}: {stderr}"
        );
    }
    assert!(stderr.contains("would remove 1 staging entry"), "{stderr}");
    assert!(
        !stderr.contains(&store.join("cache").display().to_string()),
        "{stderr}"
    );
    assert!(
        !stderr.contains(&store.join("backups").display().to_string()),
        "{stderr}"
    );
    assert!(stderr.contains("would free"), "{stderr}");

    assert!(
        object.join("payload").is_file(),
        "a dry run removed an object"
    );
    assert!(store.join("tmp/stage-old").is_dir());
    assert!(store.join("roots").join("a".repeat(40)).is_file());
    assert!(!store.join("format").exists(), "a dry run wrote the marker");
    let out = tog(&home.0, &home.0, &["gc", "--dry-run"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("has no format marker"));
}

/// `gc --reset` takes no other option: a reset that also swept, registered
/// or forgot would be two commands' worth of deletion under one name.
#[test]
fn gc_reset_refuses_every_other_gc_option() {
    let home = TempDir::boundary("cli-reset-alone");
    let (store, object) = pre_epoch_store(&home.0);
    for args in [
        &["gc", "--reset", "--keep-days", "0"][..],
        &["gc", "--reset", "--project"],
        &["gc", "--reset", "--register", "."],
        &["gc", "--reset", "--forget", &"a".repeat(40)],
        &[
            "gc",
            "--reset",
            "--drop-object",
            &format!("{}-x-1", "a".repeat(40)),
        ],
    ] {
        let out = tog(&home.0, &home.0, args);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("--reset cannot be combined with other gc options"),
            "{args:?}: {stderr}"
        );
        assert!(object.join("payload").is_file(), "{args:?}");
        assert!(!store.join("format").exists(), "{args:?}");
    }
}

/// The way out, end to end: `gc --reset` empties a store tog refused, keeps
/// the downloads and the backups, and leaves a store that works: it opens,
/// takes a new object and a root, sweeps, and `doctor` passes its row.
#[test]
fn gc_reset_empties_a_refused_store_and_normal_use_resumes() {
    let home = TempDir::boundary("cli-reset");
    let (store, object) = pre_epoch_store(&home.0);
    let download = store.join("cache/sha256").join("c".repeat(64));

    let out = tog(&home.0, &home.0, &["gc", "--reset"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!("tog: removed {}", store.join("objects").display())),
        "{stderr}"
    );
    assert!(stderr.contains("kept the download cache"), "{stderr}");
    assert!(stderr.contains("run 'tog' in each project"), "{stderr}");

    assert_eq!(
        std::fs::read_to_string(store.join("format")).unwrap(),
        "tog-store 1\n"
    );
    assert!(!object.exists(), "the reset kept an object");
    for name in ["objects", "meta", "roots"] {
        assert_eq!(
            std::fs::read_dir(store.join(name)).unwrap().count(),
            0,
            "{name} is not empty"
        );
    }
    assert!(!store.join("tmp/stage-old").exists());
    assert_eq!(std::fs::read(&download).unwrap(), b"download");
    assert_eq!(
        std::fs::read(store.join("backups/venv-old/kept")).unwrap(),
        b"mine"
    );

    // Normal use. The store opens with nothing to say.
    let out = tog(&home.0, &home.0, &["store", "path"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stderr).is_empty(), "{}", text(&out.stderr));
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));

    // A project publishes an object and registers its root, as a sync does.
    let project = home.0.join("project");
    std::fs::create_dir_all(project.join(".tog/closures")).unwrap();
    let env_object = publish_certified_object(&store, "after-reset-env");
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
        &[
            "gc",
            "--register",
            project.to_str().unwrap(),
            "--keep-days",
            "0",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        env_object.join("payload").is_file(),
        "the sweep took a rooted object"
    );
    // The kept download is an ordinary unreferenced artifact again: the
    // sweep ages it out like any other, it is not pinned by the reset.
    let out = tog(&home.0, &home.0, &["gc", "--dry-run"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(registered_root_keys(&home.0, &home.0).len(), 1);

    let out = tog(&home.0, &home.0, &["doctor"]);
    let stdout = text(&out.stdout);
    let row = stdout
        .lines()
        .find(|line| line.contains(" store "))
        .unwrap_or_else(|| panic!("no store row: {stdout}"));
    assert!(row.starts_with("ok"), "{row}");

    // A second reset on a healthy store is the same operation.
    let out = tog(&home.0, &home.0, &["gc", "--reset"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!env_object.exists());
    assert_eq!(std::fs::read(&download).ok().is_some(), download.exists());
    assert_eq!(
        std::fs::read_to_string(store.join("format")).unwrap(),
        "tog-store 1\n"
    );
}

#[test]
fn x_clean_is_offline_and_strict_about_trailing_arguments() {
    let home = TempDir::boundary("cli-x-clean");
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
    let volume = TempDir::boundary("cli-x-clean-volume-tog");
    let linked_tog_home = TempDir::boundary("cli-x-clean-linked-tog");
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
    let real_home = TempDir::boundary("cli-x-clean-real-home");
    let links = TempDir::boundary("cli-x-clean-home-links");
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
    let outside_x = TempDir::boundary("cli-x-clean-outside-x");
    let symlinked_x_home = TempDir::boundary("cli-x-clean-symlinked-x");
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

    let relative_home = TempDir::boundary("cli-x-clean-relative-home");
    let relative_victim = relative_home
        .0
        .join("relative-home/.tog/x/py-victim/.tog/closures");
    std::fs::create_dir_all(&relative_victim).unwrap();
    let out = command(
        &relative_home.0,
        &relative_home.0,
        &relative_home.0.join("store"),
    )
    .env("HOME", "relative-home")
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

/// A root with no request record (`.tog/x.json`), as a tog before x/4 left
/// one, is a cache nothing reuses. A filtered clean cannot tell what it was
/// made for and leaves it alone without a word. The bare clean removes it
/// under the store its closure's objects live in, and skips one whose
/// store cannot be recovered rather than orphan that store's registration.
#[test]
fn x_clean_removes_a_root_without_a_request_record_only_when_unfiltered() {
    let home = TempDir::boundary("cli-x-clean-unrecorded-home");
    let project = TempDir::boundary("cli-x-clean-unrecorded-project");
    fresh_store(&home.0.join("store"));
    let store = home.0.join("store").canonicalize().unwrap();
    let object = publish_certified_object(&store, "unrecorded-env");
    let npm_root = home.0.join(".tog/x/npm-prettier-0123456789abcdef");
    std::fs::create_dir_all(npm_root.join(".tog/closures")).unwrap();
    std::fs::write(
        npm_root.join("package.json"),
        r#"{"dependencies":{"prettier":"1.0.0"}}"#,
    )
    .unwrap();
    let py_root = home.0.join(".tog/x/py-ruff-0123456789abcdef");
    std::fs::create_dir_all(py_root.join(".tog/closures")).unwrap();
    std::fs::write(py_root.join("requirements.in"), "ruff\n").unwrap();
    std::fs::write(
        py_root.join(".tog/closures/python.json"),
        serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"env_object": object.display().to_string()},
        })
        .to_string(),
    )
    .unwrap();
    let foreign = home.0.join(".tog/x/py-black-0123456789abcdef");
    std::fs::create_dir_all(foreign.join(".tog/closures")).unwrap();
    std::fs::write(
        foreign.join(".tog/closures/python.json"),
        r#"{"schema":"closure/1","ecosystem":"python","body":{"env_object":"/somewhere/else/store/objects/0000000000000000000000000000000000000000-python.env-9"}}"#,
    )
    .unwrap();

    for filter in [&["--py"][..], &["ruff"], &["--npm", "prettier"]] {
        let mut args = vec!["x", "--clean"];
        args.extend_from_slice(filter);
        let out = tog(&project.0, &home.0, &args);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert_eq!(stdout, "tog: x clean: nothing to clean\n", "{filter:?}");
        assert!(
            py_root.is_dir() && npm_root.is_dir() && foreign.is_dir(),
            "{filter:?}"
        );
    }

    let out = tog(&project.0, &home.0, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(!py_root.exists(), "{stdout}");
    assert!(!npm_root.exists(), "{stdout}");
    assert!(
        foreign.is_dir(),
        "a root with no recoverable owner was removed"
    );
    assert!(
        stdout.contains("its owning store could not be recovered"),
        "{stdout}"
    );
    assert!(
        stdout.contains("x clean removed 2 environment(s), skipped 1"),
        "{stdout}"
    );
    // The generated name still says which one was a node environment, and
    // a removed node root orphans its ~/.tog/forests projection.
    assert!(stdout.contains("tog gc --project"), "{stdout}");
    // The per-root lock is unlinked while it is still held, so `.locks`
    // cannot collect one stale file per environment ever created.
    for name in ["py-ruff-0123456789abcdef", "npm-prettier-0123456789abcdef"] {
        assert!(
            !home.0.join(format!(".tog/x/.locks/{name}.lock")).exists(),
            "cleanup left the per-root lock file behind"
        );
    }
}

/// A record-less root that store A registered, cleaned by a caller whose
/// `TOG_STORE` is B: cleanup recovers A from the closure, removes the root
/// under A's lease and drops A's record, so A's next `tog gc` really
/// reclaims the objects the root kept alive.
#[test]
fn x_clean_unregisters_a_record_less_root_from_its_own_store() {
    let home = TempDir::boundary("cli-x-clean-two-stores");
    let store_a = home.0.join("store");
    let store_b = home.0.join("store-b");
    let (root, key) = registered_x_environment(&home.0, &store_a);
    std::fs::remove_file(root.join(".tog/x.json")).unwrap();
    let out = tog(
        &home.0,
        &home.0,
        &["gc", "--register", root.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(registered_root_keys(&home.0, &home.0).contains(&key));
    let object = std::fs::read_dir(store_a.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .unwrap();
    // Old enough that only a root keeps it (gc's active window is ten
    // minutes), and no age-based retention: the record alone decides.
    std::fs::File::open(&object)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(11 * 60))
        .unwrap();
    let gc = ["gc", "--keep-days", "0"];
    // While registered, A's gc keeps the object.
    let out = tog(&home.0, &home.0, &gc);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(object.is_dir(), "gc collected an object a root keeps");

    std::fs::create_dir_all(&store_b).unwrap();
    let out = tog_at(&home.0, &home.0, &store_b, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(!root.exists(), "{stdout}");
    assert!(
        stdout.contains("tog: removed x environment") && !stdout.contains("no matching registry"),
        "{stdout}"
    );
    assert!(
        !registered_root_keys(&home.0, &home.0).contains(&key),
        "store A still registers the removed root: {stdout}"
    );

    let out = tog(&home.0, &home.0, &gc);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        !object.exists(),
        "store A kept the removed root's object: {}",
        text(&out.stdout)
    );
}

/// Build a cached, `ready` python `x` root for `home` whose store object
/// carries one recorded `file-collision` exception, and return the root.
fn cached_x_root_with_exception(home: &Path) -> PathBuf {
    // Every closure tog writes holds a path built from the store's own
    // canonicalized root, so the fixture has to canonicalize too: on macOS the
    // temp dir sits under /var, a symlink to /private/var, and an
    // uncanonicalized path here compares unequal to `store.object_path`.
    fresh_store(&home.join("store"));
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

    // Exactly the directory `tog x` will look in. The key covers the store
    // root, the request, and the runtime the environment runs on, so a
    // fixture built at any other name is a miss rather than the cache hit
    // these tests are about.
    let root = home.join(".tog/x").join(
        tog::commands::x_environment_name(
            &store,
            tog::kernel::platform::Platform::host().unwrap(),
            home,
            "python",
            "fake",
            None,
        )
        .unwrap(),
    );
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
    // A run that finished: only a root recorded `ready` is a cache hit.
    std::fs::write(
        root.join(".tog/x.json"),
        serde_json::json!({
            "schema": "x-request/2",
            "ecosystem": "python",
            "package": "fake",
            "version": serde_json::Value::Null,
            "state": "ready",
            "store_root": store.display().to_string(),
        })
        .to_string(),
    )
    .unwrap();
    root
}

#[test]
fn cached_x_rechecks_object_exceptions_under_project_policy() {
    let home = TempDir::boundary("cli-x-policy-home");
    let project = TempDir::boundary("cli-x-policy-project");
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

/// The same complete projection without its request record (a root a tog
/// before x/4 left) is not a cache hit: `tog x` starts a fresh realization
/// in that directory instead of running the executable it finds there. The
/// network is cut, so the realization fails and the cached tool never runs.
#[test]
fn cached_x_without_a_request_record_is_rebuilt_not_run() {
    let home = TempDir::boundary("cli-x-unrecorded-home");
    let project = TempDir::boundary("cli-x-unrecorded-project");
    let root = cached_x_root_with_exception(&home.0);
    std::fs::remove_file(root.join(".tog/x.json")).unwrap();

    let out = tog_offline(
        &project.0,
        &home.0,
        &["x", "--py", "--from", "fake", "ruff"],
    );
    assert_ne!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        !text(&out.stderr).contains("cached test exception"),
        "the record-less root was validated as a cache hit: {}",
        text(&out.stderr)
    );
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".tog/x.json")).unwrap()).unwrap();
    assert_eq!(record["state"], "realizing", "{record}");
}

/// A cache hit validates the projection once. When the validation ran twice
/// every persisted exception was narrated twice and queued twice, so one
/// exception read as two.
#[test]
fn cached_x_narrates_each_object_exception_once() {
    let home = TempDir::boundary("cli-x-once-home");
    let project = TempDir::boundary("cli-x-once-project");
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
    let home = TempDir::boundary("cli-pnpm-unlisted");
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
    fresh_store(store_root);
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
    let home = TempDir::boundary("cli-x-clean-busy-home");
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
    let home = TempDir::boundary("cli-x-clean-failed-home");
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

/// `x --clean` finds an environment's store from the environment's own
/// records: its request record, or with none, the object paths in its
/// closure. A store found either way that this tog does not read (no
/// format marker, or one it does not know) is not acted on: the environment
/// is skipped, and it and the store's record of it stay.
#[test]
fn x_clean_skips_an_environment_whose_store_this_tog_does_not_read() {
    for (case, with_request_record, marker) in [
        ("record-unmarked", true, None),
        ("record-unknown", true, Some("tog-store one\n")),
        ("closure-unmarked", false, None),
        ("closure-unknown", false, Some("tog-store one\n")),
    ] {
        let home = TempDir::boundary(&format!("cli-x-clean-refused-{case}"));
        let store_a = home.0.join("store");
        let store_b = home.0.join("store-b");
        let (root, key) = registered_x_environment(&home.0, &store_a);
        let out = tog(
            &home.0,
            &home.0,
            &["gc", "--register", root.to_str().unwrap()],
        );
        assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out.stderr));
        let record = store_a.join("roots").join(&key);
        assert!(record.is_file(), "{case}: the fixture was not registered");
        if !with_request_record {
            std::fs::remove_file(root.join(".tog/x.json")).unwrap();
        }
        match marker {
            Some(line) => std::fs::write(store_a.join("format"), line).unwrap(),
            None => std::fs::remove_file(store_a.join("format")).unwrap(),
        }
        let untouched = |when: &str, out: &std::process::Output| {
            assert!(
                root.join(".tog/closures/python.json").is_file(),
                "{case} {when}: the environment was removed: {}",
                text(&out.stdout)
            );
            assert!(
                record.is_file(),
                "{case} {when}: the root record was dropped"
            );
            assert_eq!(
                std::fs::read(store_a.join("format")).ok(),
                marker.map(|line| line.as_bytes().to_vec()),
                "{case} {when}: the marker changed"
            );
        };

        // From another store: the refused one is the environment's, so the
        // environment is skipped and the run is not a failure.
        let out = tog_at(&home.0, &home.0, &store_b, &["x", "--clean"]);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out.stderr));
        assert!(
            stdout.contains("its originating store is not one this tog reads"),
            "{case}: {stdout}"
        );
        // The fix is for the environment's store, not the selected one: a
        // bare `tog gc --reset` here would empty store B.
        let store_a = store_a.canonicalize().unwrap();
        assert!(
            stdout.contains(&format!(
                "; fix: TOG_STORE={} tog gc --reset)",
                store_a.display()
            )),
            "{case}: {stdout}"
        );
        assert!(stdout.contains("skipped 1"), "{case}: {stdout}");
        untouched("from another store", &out);

        // From the refused store itself: the same, and there the bare
        // command is the right one.
        let out = tog(&home.0, &home.0, &["x", "--clean"]);
        assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out.stderr));
        assert!(
            text(&out.stdout).contains("; fix: tog gc --reset)"),
            "{case}: {}",
            text(&out.stdout)
        );
        untouched("from its own store, unfiltered", &out);
        let out = tog(&home.0, &home.0, &["x", "--clean", "ruff"]);
        assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out.stderr));
        untouched("from its own store", &out);
        assert!(
            !text(&out.stdout).contains("removed x environment"),
            "{case}: {}",
            text(&out.stdout)
        );
    }
}

/// The fix `x --clean` prints for an environment whose store is refused is
/// a command for that store. Pasted as printed, in a shell where
/// `TOG_STORE` selects another, healthy store, it empties the refused one
/// and leaves the selected one alone. The refused store's path has a space
/// and an apostrophe in it, so the command only works if it is quoted.
#[test]
fn the_fix_x_clean_prints_resets_the_refused_store_and_no_other() {
    let home = TempDir::boundary("cli-x-clean-fix");
    let store_a = home.0.join("it's a store");
    let store_b = home.0.join("store-b");
    let (root, _) = registered_x_environment(&home.0, &store_a);
    let store_a = store_a.canonicalize().unwrap();
    let out = tog_at(
        &home.0,
        &home.0,
        &store_a,
        &["gc", "--register", root.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let object_a = std::fs::read_dir(store_a.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .unwrap();
    std::fs::remove_file(store_a.join("format")).unwrap();

    // Store B: healthy, selected, and holding an object and a root of its
    // own, which a reset aimed at it would remove.
    fresh_store(&store_b);
    let store_b = store_b.canonicalize().unwrap();
    let object_b = publish_certified_object(&store_b, "kept-env");
    let out = tog_at(&home.0, &home.0, &store_b, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    std::fs::write(store_b.join("roots/note"), b"mine").unwrap();

    let out = tog_at(&home.0, &home.0, &store_b, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let fix = stdout
        .lines()
        .find_map(|line| line.split_once("; fix: "))
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("no fix: {stdout}"));
    assert_eq!(
        fix,
        format!(
            "TOG_STORE='{}' tog gc --reset",
            store_a.to_str().unwrap().replace('\'', "'\\''")
        )
    );

    // Paste it: `tog` on PATH, TOG_STORE still naming store B.
    let out = paste_fix(fix, &home.0, &home.0, &store_b);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // Store A was emptied and is a store again.
    assert!(!object_a.exists(), "the fix did not reset store A");
    assert_eq!(
        std::fs::read_to_string(store_a.join("format")).unwrap(),
        "tog-store 1\n"
    );
    let out = tog_at(&home.0, &home.0, &store_a, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    // Store B is as it was.
    assert!(
        object_b.join("payload").is_file(),
        "the fix emptied store B"
    );
    assert_eq!(std::fs::read(store_b.join("roots/note")).unwrap(), b"mine");
    assert_eq!(
        std::fs::read_to_string(store_b.join("format")).unwrap(),
        "tog-store 1\n"
    );

    // And the environment can now be cleaned.
    let out = tog_at(&home.0, &home.0, &store_b, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!root.exists(), "{}", text(&out.stdout));
}

/// Run a fix line as it would be pasted: by `/bin/sh` in `cwd`, with `tog`
/// on PATH and `TOG_STORE` exported as `selected`, the way the shell that
/// printed it had it.
fn paste_fix(fix: &str, cwd: &Path, home: &Path, selected: &Path) -> std::process::Output {
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    if !bin.join("tog").exists() {
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_tog"), bin.join("tog")).unwrap();
    }
    common::command_for(Path::new("/bin/sh"), cwd, home, selected)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .arg("-c")
        .arg(fix)
        .output()
        .unwrap()
}

/// A relative `TOG_STORE` names a different store from every directory.
/// `tog -C project` resolves it under `project`, and the shell that pastes
/// the fix resolves it where the shell is. So the fix for the store under
/// `project` names that store, absolute, and pasting it leaves the store
/// beside the shell alone.
#[test]
fn the_fix_for_a_relatively_selected_store_resets_that_store_from_anywhere() {
    let home = TempDir::boundary("cli-format-relative");
    let work = home.0.join("work");
    std::fs::create_dir_all(work.join("project")).unwrap();
    let work = work.canonicalize().unwrap();
    // `work/store`: healthy, and what `TOG_STORE=store` means in `work`.
    fresh_store(&work.join("store"));
    let kept = publish_certified_object(&work.join("store"), "kept-env");
    // `work/project/store`: written before the marker existed.
    let refused = work.join("project/store");
    std::fs::create_dir_all(refused.join("objects")).unwrap();
    std::fs::create_dir_all(refused.join("meta")).unwrap();
    let old = publish_certified_object(&refused, "old-env");
    assert!(!refused.join("format").exists());

    let relative = Path::new("store");
    let out = tog_at(
        &work,
        &home.0,
        relative,
        &["-C", "project", "store", "roots"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("has no format marker"), "{stderr}");
    let fix = stderr
        .lines()
        .find_map(|line| line.strip_prefix("tog:     fix: "))
        .unwrap_or_else(|| panic!("no fix line: {stderr}"));
    assert_eq!(
        fix,
        format!("TOG_STORE={} tog gc --reset", refused.display())
    );
    // The same from inside the project, with no `-C`: still relative, so
    // still spelled out.
    let out = tog_at(
        &work.join("project"),
        &home.0,
        relative,
        &["store", "roots"],
    );
    assert!(
        text(&out.stderr).contains(&format!("tog:     fix: {fix}\n")),
        "{}",
        text(&out.stderr)
    );
    // `store path` and `doctor` print the same command.
    let out = tog_at(
        &work,
        &home.0,
        relative,
        &["-C", "project", "store", "path"],
    );
    assert!(
        text(&out.stderr).contains(&format!("tog:     fix: {fix}\n")),
        "{}",
        text(&out.stderr)
    );
    let out = tog_at(&work, &home.0, relative, &["-C", "project", "doctor"]);
    assert!(
        text(&out.stdout).contains(&format!("; run '{fix}'")),
        "{}",
        text(&out.stdout)
    );

    // Pasted in the shell at `work`, where `store` is the healthy store.
    let out = paste_fix(fix, &work, &home.0, relative);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!old.exists(), "the fix did not reset the refused store");
    assert_eq!(
        std::fs::read_to_string(refused.join("format")).unwrap(),
        "tog-store 1\n"
    );
    assert!(
        kept.join("payload").is_file(),
        "the fix emptied the store beside the shell"
    );

    // An absolute selection of the refused store is the one case with a
    // bare fix: it means the same store wherever it is pasted.
    std::fs::remove_file(refused.join("format")).unwrap();
    let out = tog_at(
        &work,
        &home.0,
        &refused,
        &["-C", "project", "store", "roots"],
    );
    assert!(
        text(&out.stderr).ends_with("tog:     fix: tog gc --reset\n"),
        "{}",
        text(&out.stderr)
    );
}

/// A store path that is not UTF-8 cannot be written in a `String`, and the
/// nearest text (U+FFFD for each bad byte) is another path. The fix spells
/// the path's own bytes, so pasting it resets the refused store and not a
/// store that happens to sit at the look-alike path.
#[test]
fn the_fix_for_a_store_whose_path_is_not_utf8_resets_that_store() {
    use std::os::unix::ffi::OsStrExt as _;
    let home = TempDir::boundary("cli-format-bytes");
    let base = home.0.canonicalize().unwrap();
    // Store A at `st<ff>`: refused. Store R at `st<U+FFFD>`: healthy, and
    // where a lossy spelling of A would point. Store B: selected.
    let store_a = base.join(std::ffi::OsStr::from_bytes(b"st\xff"));
    if std::fs::create_dir(&store_a).is_err() {
        // A filesystem that takes only UTF-8 names (APFS) has no such store.
        return;
    }
    assert_eq!(
        store_a.to_string_lossy(),
        base.join("st\u{fffd}").to_string_lossy()
    );
    let store_r = base.join("st\u{fffd}");
    let store_b = base.join("store-b");
    for sub in ["objects", "meta"] {
        std::fs::create_dir_all(store_a.join(sub)).unwrap();
    }
    let object_a = publish_certified_object(&store_a, "old-env");
    fresh_store(&store_r);
    let object_r = publish_certified_object(&store_r, "look-alike-env");
    fresh_store(&store_b);
    let object_b = publish_certified_object(&store_b, "selected-env");

    // An x environment recorded against store A, through a symlink whose
    // own name is text: a request record is JSON and holds only text.
    let link = base.join("link-to-a");
    std::os::unix::fs::symlink(&store_a, &link).unwrap();
    let root = home.0.join(".tog/x/py-ruff-test");
    std::fs::create_dir_all(root.join(".tog/closures")).unwrap();
    std::fs::write(
        root.join(".tog/x.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "x-request/2",
            "ecosystem": "python",
            "package": "ruff",
            "version": serde_json::Value::Null,
            "state": "ready",
            "store_root": link.to_str().unwrap(),
        }))
        .unwrap(),
    )
    .unwrap();

    let out = tog_at(&home.0, &home.0, &store_b, &["x", "--clean"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let fix = stdout
        .lines()
        .find_map(|line| line.split_once("; fix: "))
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("no fix: {stdout}"));
    assert!(
        fix.starts_with("TOG_STORE=\"$(printf '/") && fix.ends_with("/st\\377')\" tog gc --reset"),
        "{fix}"
    );
    assert!(!fix.contains('\u{fffd}'), "{fix}");

    let out = paste_fix(fix, &home.0, &home.0, &store_b);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!object_a.exists(), "the fix did not reset store A");
    assert_eq!(
        std::fs::read_to_string(store_a.join("format")).unwrap(),
        "tog-store 1\n"
    );
    assert!(
        object_r.join("payload").is_file(),
        "the fix emptied the store at the look-alike path"
    );
    assert!(
        object_b.join("payload").is_file(),
        "the fix emptied the selected store"
    );

    // Selected directly and absolutely, the bare command is right, and it
    // is the only spelling that needs no path at all.
    std::fs::remove_file(store_a.join("format")).unwrap();
    let out = tog_at(&home.0, &home.0, &store_a, &["store", "roots"]);
    assert!(
        text(&out.stderr).ends_with("tog:     fix: tog gc --reset\n"),
        "{}",
        text(&out.stderr)
    );
}

/// `tog doctor` does not wait behind a job that holds the store
/// exclusively (a sweep, a reset). It says the store is in use, as a
/// warning, and still reports everything that needs no store.
#[test]
fn doctor_reports_a_busy_store_and_runs_its_other_checks() {
    use std::os::unix::io::AsRawFd;
    let home = TempDir::boundary("cli-doctor-busy");
    let store = home.0.join("store");
    fresh_store(&store);
    let out = tog(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let free = tog(&home.0, &home.0, &["doctor"]);
    let free_rows = text(&free.stdout);

    // What a sweep holds: the exclusive flock on `activity.lock`.
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(store.join("activity.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
    // Let go after a while whatever happens, so a doctor that waits fails
    // this test (by the row it then prints) and does not hang it.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _ = released.recv_timeout(std::time::Duration::from_secs(60));
        drop(held);
    });

    let out = tog(&home.0, &home.0, &["doctor"]);
    let stdout = text(&out.stdout);
    let json = tog(&home.0, &home.0, &["doctor", "--json"]);
    release.send(()).unwrap();
    holder.join().unwrap();

    let row = |rows: &str, name: &str| {
        rows.lines()
            .find(|line| line.split_whitespace().nth(1) == Some(name))
            .map(str::to_string)
    };
    let store_row = row(&stdout, "store").unwrap_or_else(|| panic!("no store row: {stdout}"));
    assert!(store_row.starts_with("warn"), "{store_row}");
    assert!(
        store_row.contains("a Tog job is using the store at"),
        "{store_row}"
    );
    // The rows that read the store are left out, and every other row is
    // what it was when the store was free.
    for name in ["disk", "toolchains"] {
        assert!(row(&free_rows, name).is_some(), "{name}: {free_rows}");
        assert!(row(&stdout, name).is_none(), "{name}: {stdout}");
    }
    for name in ["platform", "policy", "project"] {
        assert_eq!(row(&stdout, name), row(&free_rows, name), "{name}");
        assert!(row(&stdout, name).is_some(), "{name}: {stdout}");
    }
    // A busy store is not a failure: the exit status is what it was.
    assert_eq!(out.status.code(), free.status.code(), "{stdout}");

    // The same row under `--json`.
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let busy = json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "store")
        .unwrap_or_else(|| panic!("no store check: {json}"));
    assert_eq!(busy["level"], "warn", "{busy}");
    assert!(
        busy["detail"]
            .as_str()
            .unwrap()
            .contains("a Tog job is using the store at"),
        "{busy}"
    );
}

/// A tog that finds another tog creating or emptying the store says what it
/// is waiting for before it waits, and goes on when the store is released.
#[test]
fn a_tog_waiting_for_the_store_root_says_so() {
    use std::io::BufRead as _;
    use std::os::unix::io::AsRawFd;
    let home = TempDir::boundary("cli-root-wait");
    let store = home.0.join("store");
    fresh_store(&store);
    // What a reset holds while it works: an exclusive flock on the root.
    let held = std::fs::File::open(&store).unwrap();
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
    // Released when the test says so, or after a while on its own, so a
    // tog that waits without a word fails the test and does not hang it.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _ = released.recv_timeout(std::time::Duration::from_secs(60));
        drop(held);
    });

    let mut child = command(&home.0, &home.0, &store)
        .args(["store", "roots"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    assert_eq!(
        line,
        format!(
            "tog: waiting for another tog that is creating or emptying the store at {}\n",
            store.canonicalize().unwrap().display()
        )
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "tog did not wait for the held store"
    );
    release.send(()).unwrap();
    holder.join().unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

/// Cleanup recovers the originating store from the `x.json` request record
/// and acts on that store's registry.
#[test]
fn x_cleanup_revalidates_the_recorded_origin() {
    let home = TempDir::boundary("cli-x-clean-origin-explicit");
    let store_root = home.0.join("store");
    let (root, key) = registered_x_environment(&home.0, &store_root);

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
        "the origin was not resolved, so nothing was cleaned: {stdout}"
    );
    assert!(
        !registered_root_keys(&home.0, &home.0).contains(&key),
        "successful cleanup left the root record behind: {stdout}"
    );
}

/// `tog gc` learns about x environments only as registered roots, like any
/// project. One with no request record, or whose closure no longer parses,
/// neither stops nor fails a sweep: gc never reads `.tog/x.json`.
#[test]
fn gc_sweeps_past_an_x_root_without_a_request_record() {
    let home = TempDir::boundary("cli-x-gc-unrecorded");
    let store_root = home.0.join("store");
    let (root, key) = registered_x_environment(&home.0, &store_root);
    std::fs::remove_file(root.join(".tog/x.json")).unwrap();
    let out = tog(
        &home.0,
        &home.0,
        &["gc", "--register", root.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(registered_root_keys(&home.0, &home.0).contains(&key));

    let out = tog(&home.0, &home.0, &["gc"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    std::fs::write(root.join(".tog/closures/python.json"), "{").unwrap();
    let out = tog(&home.0, &home.0, &["gc"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(root.is_dir(), "gc removed an x environment directory");

    // A record-less root the bare clean removed under another store leaves
    // that store's record pointing at nothing: gc still sweeps.
    std::fs::remove_dir_all(&root).unwrap();
    let out = tog(&home.0, &home.0, &["gc"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

// --- CLI.md: `tog audit`, the CI admission gate over recorded exceptions ---

/// Publish the `tog-toolchain.toml` section a writable sync of `project`
/// would write for `ecosystem` (a tailor id), through the same selection
/// and writer the binary uses, and return the bundle id a closure synced
/// against it records.
fn commit_toolchain_lock(project: &Path, ecosystem: &str) -> String {
    use tog::kernel::toolchain::lock::{ToolchainLock, LOCK_PATH};
    let tailor = tog::tailors::by_id(ecosystem).unwrap();
    let lock_ecosystem = tailor.lock_ecosystem();
    let root = tog::kernel::fsroot::ProjectRoot::open(project).unwrap();
    let rows = tog::kernel::toolchain::input::discover(&root, lock_ecosystem).unwrap();
    let catalog = tailor.toolchain_catalog().unwrap();
    let bundle = tog::kernel::toolchain::select_for(&catalog, lock_ecosystem, &rows).unwrap();
    let mut lock = ToolchainLock::read_via(&root)
        .unwrap()
        .unwrap_or_else(|| ToolchainLock::new(env!("CARGO_PKG_VERSION")));
    lock.set_ecosystem(lock_ecosystem, bundle, &rows).unwrap();
    std::fs::write(project.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
    bundle.bundle_id()
}

/// A python closure with recorded inputs, a projection, the matching
/// toolchain lock, and one recorded exception of `kind`, so `status`
/// reports it synced and `audit` has something to judge. Returns the
/// closure path.
fn synced_python_closure_with_exception(home: &Path, project: &Path, kind: &str) -> PathBuf {
    std::fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let env = project.join("env-object");
    std::fs::create_dir_all(env.join("bin")).unwrap();
    std::os::unix::fs::symlink(&env, project.join(".venv")).unwrap();
    let requirements = hex::encode(Sha256::digest(
        std::fs::read(project.join("requirements.txt")).unwrap(),
    ));
    let bundle_id = commit_toolchain_lock(project, "python");
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
            "plan": {"python_version": "3.12.14", "packages": []},
            "inputs": [{"path": "requirements.txt", "sha256": requirements}],
            "toolchain": {"bundle_id": bundle_id},
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

/// The solo setup: no `[signing]` table anywhere. `audit` judges the
/// records on their contents, says on stdout and in the JSON that it did
/// not check signatures, and still catches a denial and a tampered
/// signature; `--signed` is the form that refuses to run this way.
#[test]
fn audit_without_trusted_keys_judges_records_and_says_so() {
    let home = TempDir::boundary("cli-audit-unsigned-home");
    let project = TempDir::boundary("cli-audit-unsigned-project");
    let key_home = TempDir::boundary("cli-audit-unsigned-key");
    // The fixture signs with a key whose policy table lands under
    // `key_home`, so `home` has no [signing] table at all.
    let closure = synced_python_closure_with_exception(&key_home.0, &project.0, "git-dependency");
    let key = signing_key(&key_home.0);
    assert!(!home.0.join(".tog/policy.toml").exists());

    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("signatures: not checked"), "{stdout}");
    assert!(stdout.contains("tog keygen"), "{stdout}");
    assert!(
        stdout.contains("python  clean         closure "),
        "{stdout}"
    );
    assert!(stdout.contains("permitted: git-dependency 1"), "{stdout}");
    assert!(!stdout.contains("trusted key"), "{stdout}");
    assert!(
        text(&out.stderr).contains("signatures=not-checked"),
        "{}",
        text(&out.stderr)
    );
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["passed"], true);
    assert_eq!(value["signatures_checked"], false);
    assert_eq!(value["policy"]["trusted"], serde_json::Value::Null);
    assert_eq!(value["closures"][0]["verdict"], "clean");
    assert_eq!(value["closures"][0]["signature"]["state"], "not-checked");
    assert_eq!(
        value["closures"][0]["signature"]["key"],
        key.public_key().to_string()
    );
    assert_eq!(value["closures"][0]["permitted"]["git-dependency"], 1);

    // The policy is still judged: a deny list fails the report.
    let deny = project.0.join("deny.toml");
    std::fs::write(&deny, "deny = [\"git-dependency\"]\n").unwrap();
    let out = tog(
        &project.0,
        &home.0,
        &["audit", "--policy", deny.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("python  denied        closure "),
        "{stdout}"
    );
    assert!(
        stdout.contains("denied   git-dependency  left-pad"),
        "{stdout}"
    );

    // An unsigned record is judged the same way: no key to miss.
    let signed = std::fs::read_to_string(&closure).unwrap();
    let mut stripped: serde_json::Value = serde_json::from_str(&signed).unwrap();
    stripped.as_object_mut().unwrap().remove("signature");
    std::fs::write(&closure, serde_json::to_vec_pretty(&stripped).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "clean");
    assert_eq!(value["closures"][0]["signature"]["state"], "not-checked");
    assert_eq!(
        value["closures"][0]["signature"]["key"],
        serde_json::Value::Null
    );

    // A signature that is present and does not verify is still tamper
    // evidence, whoever signed: bad-signature, not evaluated, exit 1.
    let mut edited: serde_json::Value = serde_json::from_str(&signed).unwrap();
    edited["body"]["exceptions"] = serde_json::json!([]);
    std::fs::write(&closure, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "bad-signature");
    assert_eq!(value["closures"][0]["freshness"], "not-evaluated");
    let out = tog(&project.0, &home.0, &["audit"]);
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("regenerate with 'tog' and commit"),
        "{stdout}"
    );
    assert!(!stdout.contains("trusted key"), "{stdout}");

    // The CI form refuses to run this way, under --json too, and before
    // any record is read: a closure that is not even JSON gets the
    // configuration error, not a parse error. The plain form never
    // created a store.
    std::fs::write(&closure, b"{ not json").unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--signed", "--json"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("no trusted signing keys configured"),
        "{error}"
    );
    let out = tog(&project.0, &home.0, &["audit", "--signed"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no trusted signing keys configured")
            && !text(&out.stderr).contains("json"),
        "{}",
        text(&out.stderr)
    );
    assert!(!home.0.join("store").exists());
}

/// `status` shows what a sync allowed and could not vouch for, under the
/// row it belongs to, with no policy and no key: the read-only place to
/// see an exception before deciding whether to judge it.
#[test]
fn status_lists_the_exceptions_a_sync_recorded() {
    let home = TempDir::boundary("cli-status-exceptions-home");
    let project = TempDir::boundary("cli-status-exceptions-project");
    synced_python_closure_with_exception(&home.0, &project.0, "git-dependency");

    let out = tog(&project.0, &home.0, &["status"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("python  synced"), "{stdout}");
    // The whole line, newline included: an escaped control character in
    // the subject must not swallow the line break after it.
    assert!(
        stdout.contains("python  synced      (cpython 3.12.14; 0 packages)\n          exception   git-dependency  left-pad\n"),
        "{stdout}"
    );
    assert!(stdout.contains("1 of 1 synced."), "{stdout}");
    assert!(
        stdout.contains("1 policy exception(s) recorded") && stdout.contains("'tog audit'"),
        "{stdout}"
    );

    let out = tog(&project.0, &home.0, &["status", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["synced"], true);
    assert_eq!(
        value["ecosystems"][0]["exceptions"],
        serde_json::json!([{
            "kind": "git-dependency",
            "subject": "left-pad",
            "detail": "git+https://example.invalid/left-pad",
        }])
    );

    // A subject that carries control characters (a record is data from a
    // sync, and a resolution record is data from a tool) is escaped on
    // the text line, so it cannot forge a row or recolor the terminal,
    // and the row after it still starts on its own line. JSON carries the
    // subject as it was recorded.
    let closure = project.0.join(".tog/closures/python.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&closure).unwrap()).unwrap();
    record["body"]["exceptions"][0]["subject"] =
        serde_json::json!("left-pad\npython  synced\r\u{1b}[31m");
    std::fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["status"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains("          exception   git-dependency  left-pad\\npython  synced\\r\\u{1b}[31m\n\n1 of 1 synced.\n"),
        "{stdout}"
    );
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("python  synced"))
            .count(),
        1,
        "{stdout}"
    );
    let out = tog(&project.0, &home.0, &["status", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value["ecosystems"][0]["exceptions"][0]["subject"],
        "left-pad\npython  synced\r\u{1b}[31m"
    );

    // A joined resolution record's exceptions are listed even when the
    // closure has no top-level list of its own.
    record["body"].as_object_mut().unwrap().remove("exceptions");
    record["body"]["resolution"] = serde_json::json!({
        "exceptions": [{"kind": "unrecorded-resolution", "subject": "uv.lock", "detail": "no door"}]
    });
    std::fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["status", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value["ecosystems"][0]["exceptions"][0]["kind"],
        "unrecorded-resolution"
    );

    // An exception list that cannot be read is this row's finding, not the
    // whole report's: the row was synced on every other check, so it is
    // `unchecked` with the reason, and the ecosystem beside it still
    // reports. A row that already names a fix keeps it.
    record["body"].as_object_mut().unwrap().remove("resolution");
    record["body"]["exceptions"] = serde_json::json!("nope");
    std::fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    std::fs::write(project.0.join("package.json"), "{}\n").unwrap();
    let out = tog(&project.0, &home.0, &["status"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains("python  unchecked   ") && stdout.contains("malformed exception record"),
        "{stdout}"
    );
    assert!(stdout.contains("node    not synced"), "{stdout}");
    assert!(
        stdout.contains("0 of 2 synced; 1 unchecked, 1 not-synced."),
        "{stdout}"
    );
    // The unchecked row carries the reason itself: no second line for it.
    assert!(!stdout.contains("exception   unreadable"), "{stdout}");
    // Under a state that keeps its own fix, the read error is still
    // reported, beside the state: an empty list is not "none recorded".
    std::fs::remove_file(project.0.join(".venv")).unwrap();
    let out = tog(&project.0, &home.0, &["status"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("python  missing     "), "{stdout}");
    assert!(
        stdout.contains("          exception   unreadable  ")
            && stdout.contains("malformed exception record"),
        "{stdout}"
    );
    let out = tog(&project.0, &home.0, &["status", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["ecosystems"][0]["state"], "projection-missing");
    assert_eq!(value["ecosystems"][0]["exceptions"], serde_json::json!([]));
    assert!(
        value["ecosystems"][0]["exceptions_error"]
            .as_str()
            .unwrap()
            .contains("malformed exception record"),
        "{value}"
    );
    assert_eq!(
        value["ecosystems"][1]["exceptions_error"],
        serde_json::Value::Null
    );
}

/// `policy::load` unions silently, so the merged deny set alone cannot say
/// which file asked for a denial. The JSON report carries the contributing
/// policies under `policy.sources`, in merge order, so a CI log shows
/// whether a denial came from the machine, the repository, or `--policy`.
#[test]
fn audit_json_attributes_each_policy_to_its_source_file() {
    // tog() sets HOME to this temp directory and drops every TOG_*
    // variable, TOG_POLICY and TOG_STRICT included, from the child.
    let home = TempDir::boundary("cli-audit-sources-home");
    let project = TempDir::boundary("cli-audit-sources-project");
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

/// A gate that passes must not be running a toolchain the committed lock
/// no longer names: `audit` reads the same lock answer `status` gives, and
/// a missing lock, a stale lock row, or a closure built from another bundle
/// is stale, never clean.
#[test]
fn audit_is_stale_when_the_toolchain_lock_does_not_describe_the_closure() {
    let home = TempDir::boundary("cli-audit-lock-home");
    let project = TempDir::boundary("cli-audit-lock-project");
    let closure = synced_python_closure_with_exception(&home.0, &project.0, "git-dependency");
    let lock_path = project.0.join("tog-toolchain.toml");
    let audit = || {
        let out = tog(&project.0, &home.0, &["audit", "--json"]);
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        (out.status.code(), value["closures"][0].clone())
    };
    let (code, verdict) = audit();
    assert_eq!(code, Some(0), "{verdict}");
    assert_eq!(verdict["freshness"], "current");

    // No lock: the same line `status` prints, and the audit fails on it.
    let lock = std::fs::read(&lock_path).unwrap();
    std::fs::remove_file(&lock_path).unwrap();
    let (code, verdict) = audit();
    assert_eq!(code, Some(1));
    assert_eq!(verdict["verdict"], "stale");
    assert_eq!(verdict["freshness"], "stale");
    let status = tog(&project.0, &home.0, &["status", "--json"]);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        verdict["freshness_detail"],
        status["ecosystems"][0]["detail"][0]
    );
    assert_eq!(
        verdict["freshness_detail"],
        "tog-toolchain.toml (missing; run 'tog' to create it)"
    );
    let out = tog(&project.0, &home.0, &["audit"]);
    assert!(
        text(&out.stdout)
            .contains(": tog-toolchain.toml (missing; run 'tog' to create it), then audit again"),
        "{}",
        text(&out.stdout)
    );
    std::fs::write(&lock_path, &lock).unwrap();

    // A toolchain source moved after the lock was written: stale, naming
    // the verb that moves a locked runtime.
    std::fs::write(project.0.join(".python-version"), "3.13.15\n").unwrap();
    let (code, verdict) = audit();
    assert_eq!(code, Some(1));
    assert_eq!(verdict["freshness"], "stale");
    let detail = verdict["freshness_detail"].as_str().unwrap();
    assert!(detail.starts_with("tog-toolchain.toml stale: "), "{detail}");
    assert!(
        detail.ends_with("run 'tog update --toolchain python'"),
        "{detail}"
    );
    std::fs::remove_file(project.0.join(".python-version")).unwrap();
    let (code, _) = audit();
    assert_eq!(code, Some(0));

    // A signed record built from a different bundle than the lock names.
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&closure).unwrap()).unwrap();
    record["body"]["toolchain"]["bundle_id"] =
        serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    signing_key(&home.0).sign(&mut record).unwrap();
    std::fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let (code, verdict) = audit();
    assert_eq!(code, Some(1));
    assert_eq!(verdict["signature"]["state"], "trusted");
    assert_eq!(verdict["freshness"], "stale");
    assert_eq!(
        verdict["freshness_detail"],
        "tog-toolchain.toml (toolchain changed since the last sync; run 'tog')"
    );
}

/// An older `tog fmt` left `.tog/closures/rustfmt.json` beside the
/// project's closures. Nothing reads it any more: `audit`, `status`, and
/// `ls` answer as they would without it, rather than reporting an orphaned
/// or unknown record (`sbom` skips it too; its unit test covers that).
#[test]
fn a_leftover_rustfmt_record_is_ignored_by_every_reader() {
    let home = TempDir::boundary("cli-leftover-fmt-home");
    let project = TempDir::boundary("cli-leftover-fmt-project");
    synced_python_closure_with_exception(&home.0, &project.0, "git-dependency");
    let platform = tog::kernel::platform::Platform::host().unwrap();
    let mut envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": "rustfmt",
        "platform": platform.triple(),
        "projected_at": 1,
        "body": {
            "rust_version": "1.96.1",
            "rust_object": {"path": "/store/objects/r", "id": "r"},
            "rustfmt_object": {"path": "/store/objects/f", "id": "f"},
            "exceptions": [],
        },
    });
    signing_key(&home.0).sign(&mut envelope).unwrap();
    std::fs::write(
        project.0.join(".tog/closures/rustfmt.json"),
        serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .unwrap();

    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["closures"][0]["ecosystem"], "python");
    assert_eq!(value["missing"], serde_json::json!([]));
    assert_eq!(value["passed"], true);

    for args in [&["status"][..], &["ls"]] {
        let out = tog(&project.0, &home.0, args);
        assert!(
            !text(&out.stdout).contains("rustfmt") && !text(&out.stderr).contains("rustfmt"),
            "{args:?}\nstdout:\n{}\nstderr:\n{}",
            text(&out.stdout),
            text(&out.stderr)
        );
    }
    let out = tog(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
}

// APFS rejects non-UTF-8 filenames with EILSEQ. The filesystem case runs
// on Linux; audit's rendering unit tests cover these bytes on both hosts.
#[cfg(target_os = "linux")]
#[test]
fn audit_json_handles_non_utf8_project_and_closure_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let home = TempDir::boundary("cli-audit-non-utf8-home");
    let parent = TempDir::boundary("cli-audit-non-utf8-parent");
    let project = parent.0.join(OsString::from_vec(vec![
        b'p', b'r', b'o', b'j', b'e', b'c', b't', b'-', 0xff,
    ]));
    std::fs::create_dir_all(&project).unwrap();
    // A signed python record whose inputs were never recorded: the gate
    // reads and reports it (not current, so exit 1), which is all the path
    // rendering below needs.
    std::fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let closures = project.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    let closure = closures.join("python.json");
    let mut envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": "python",
        "platform": tog::kernel::platform::Platform::host().unwrap().triple(),
        "projected_at": 1,
        "body": {"plan": {"packages": []}, "exceptions": []},
    });
    signing_key(&home.0).sign(&mut envelope).unwrap();
    std::fs::write(&closure, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let out = tog(&project, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["ecosystem"], "python");
    assert_eq!(value["missing"], serde_json::json!([]));
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
    let home = TempDir::boundary("cli-audit-home");
    let project = TempDir::boundary("cli-audit-project");

    // No trusted set in the machine policy: a plain audit runs anyway
    // (nothing is synced yet, so it says so); the CI form, --signed, is
    // the one that refuses an unconfigured gate (exit 2) before any
    // record is read.
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("nothing synced"),
        "{}",
        text(&out.stderr)
    );
    let out = tog(&project.0, &home.0, &["audit", "--signed"]);
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
    let out = tog(&project.0, &home.0, &["audit", "--signed"]);
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
    // `audit` never syncs, so `--strict` is refused rather than accepted
    // and ignored; a real typo stays a usage error too.
    let out = tog(&project.0, &home.0, &["audit", "--strict"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("'audit' never syncs"),
        "{}",
        text(&out.stderr)
    );
    let out = tog(&project.0, &home.0, &["audit", "--stric"]);
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
    let other_home = TempDir::boundary("cli-audit-other-home");
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
    // With the project policy gone, the genuine record is clean again and
    // its exception is permitted and counted.
    let out = tog(&project.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("python  clean         closure "),
        "{stdout}"
    );
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
    let unknown = TempDir::boundary("cli-audit-unknown");
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
    let mismatch = TempDir::boundary("cli-audit-mismatch");
    let path = synced_python_closure_with_exception(&home.0, &mismatch.0, "git-dependency");
    let body = std::fs::read_to_string(&path).unwrap().replacen(
        "\"ecosystem\": \"python\"",
        "\"ecosystem\": \"node\"",
        1,
    );
    assert!(body.contains("\"ecosystem\": \"node\""), "{body}");
    std::fs::write(&path, body).unwrap();
    let out = tog(&mismatch.0, &home.0, &["audit"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains(r#"claims ecosystem "node" but is named "python""#),
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
    let home = TempDir::boundary("cli-keygen");
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
    let project = TempDir::boundary("cli-keygen-project");
    std::fs::create_dir_all(home.0.join(".tog")).unwrap();
    std::fs::write(home.0.join(".tog/policy.toml"), &stdout).unwrap();
    // The record is written under a scratch home (its own key and policy)
    // and re-signed with the key keygen made.
    let scratch = TempDir::boundary("cli-keygen-scratch");
    let closure = synced_python_closure_with_exception(&scratch.0, &project.0, "git-dependency");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&closure).unwrap()).unwrap();
    envelope.as_object_mut().unwrap().remove("signature");
    key.sign(&mut envelope).unwrap();
    std::fs::write(&closure, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
    let out = tog(&project.0, &home.0, &["audit", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["closures"][0]["verdict"], "clean");
    assert_eq!(value["closures"][0]["signature"]["state"], "trusted");
    assert_eq!(value["missing"], serde_json::json!([]));
}

#[test]
fn a_bad_signing_key_fails_every_closure_writer_before_the_store_is_touched() {
    let home = TempDir::boundary("cli-badkey-home");
    let project = TempDir::boundary("cli-badkey-project");
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
            &["build"],
            &["run", "true"],
            &["env"],
            &["add", "py:six", "--no-sync"],
            &["attest"],
            &["x", "py:ruff", "--version"],
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

/// A real signing key in `home` and the secret part of its file.
fn cargo_signing_key(home: &Path) -> (PathBuf, String) {
    let key = home.join("keys/signing.key");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    tog::kernel::signing::generate(&key).unwrap();
    let contents = std::fs::read_to_string(&key).unwrap();
    let seed = contents.trim().rsplit(':').next().unwrap().to_string();
    assert!(seed.len() >= 32, "{contents}");
    (key, seed)
}

const CARGO_KEY_COMMANDS: [&[&str]; 4] = [
    &["sync"],
    &["attest", "cargo"],
    &["add", "--no-sync", "cargo:itoa"],
    &["fmt"],
];

/// Each command a Cargo project's files reach, run without network with
/// `key` as the signing key: it fails, and no byte of the key reaches
/// stdout or stderr. Returns each command's stderr.
fn cargo_key_runs(project: &Path, home: &Path, key: &Path, seed: &str) -> Vec<String> {
    CARGO_KEY_COMMANDS
        .iter()
        .map(|args| {
            let out = common::offline_command(project, home, &home.join("store"))
                .args(*args)
                .env("TOG_SIGNING_KEY", key)
                .env("CARGO_HOME", home.join(".cargo"))
                .output()
                .expect("spawn tog without network");
            let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
            assert!(!out.status.success(), "{args:?}: {stderr}");
            assert!(
                !stdout.contains(seed) && !stderr.contains(seed),
                "{args:?}: the key reached the output\n{stdout}\n{stderr}"
            );
            stderr
        })
        .collect()
}

fn plain_cargo_project(project: &Path) {
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
}

/// A cloned Cargo project whose `Cargo.toml` is a hard link to the signing
/// key (the same inode, no symlink to see): tog's own reads refuse it
/// before anything is realized, and no
/// byte of the key reaches stdout or stderr. No cargo runs on the host to
/// quote it.
#[test]
fn a_cargo_manifest_hard_linked_to_the_signing_key_never_echoes_it() {
    let home = TempDir::boundary("cli-cargo-key-link");
    let project = TempDir::boundary("cli-cargo-key-link-project");
    let (key, seed) = cargo_signing_key(&home.0);
    std::fs::hard_link(&key, project.0.join("Cargo.toml")).unwrap();
    for (args, stderr) in CARGO_KEY_COMMANDS
        .iter()
        .zip(cargo_key_runs(&project.0, &home.0, &key, &seed))
    {
        // Refused by name, or (attest lists the workspace's outputs first)
        // by the position tog's own parser stopped at.
        let named = stderr.contains("is the signing key")
            || stderr.contains("Cargo.toml is not valid TOML at line 1");
        assert!(named, "{args:?}: {stderr}");
    }
    // Refused before anything was realized: no store object exists.
    let objects = home.0.join("store/objects");
    let realized = std::fs::read_dir(&objects).map_or(0, |entries| entries.count());
    assert_eq!(realized, 0, "{} holds objects", objects.display());
}

/// The other files a Cargo project's commands parse before anything is
/// downloaded (the toolchain files and the project policy), each a hard
/// link to the signing key: each command reaches the parser that fails on
/// it (its error quotes the line, so the redaction marker shows), and no
/// byte of the key reaches stdout or stderr. `attest` never reads
/// `rust-toolchain` (it runs frozen on `tog-toolchain.toml`), so that pair
/// is refused for the missing lock instead.
#[test]
fn project_files_hard_linked_to_the_signing_key_never_echo_it() {
    const REDACTED: &str = "[signing key redacted]";
    for file in [
        "rust-toolchain.toml",
        "rust-toolchain",
        "tog-toolchain.toml",
        ".tog/policy.toml",
    ] {
        let home = TempDir::boundary("cli-key-files");
        let project = TempDir::boundary("cli-key-files-project");
        let (key, seed) = cargo_signing_key(&home.0);
        plain_cargo_project(&project.0);
        let path = project.0.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::hard_link(&key, &path).unwrap();
        let runs = cargo_key_runs(&project.0, &home.0, &key, &seed);
        for (args, stderr) in CARGO_KEY_COMMANDS.iter().zip(runs) {
            let expected = match (file, args[0]) {
                ("rust-toolchain", "attest") => "tog-toolchain.toml is missing",
                _ => REDACTED,
            };
            assert!(
                stderr.contains(expected),
                "{file} {args:?}: expected {expected:?}\n{stderr}"
            );
        }
    }
}

/// `tog attest` refuses offline, before any tool or store, what it cannot
/// sign: an ecosystem with no lock a resolution door produces, or a project
/// with none at all.
#[test]
fn attest_refuses_an_ecosystem_without_a_resolution_door() {
    let home = TempDir::boundary("cli-attest-unsupported");
    let project = TempDir::boundary("cli-attest-unsupported-project");
    std::fs::write(
        project.0.join("Gemfile"),
        "source \"https://rubygems.org\"\n",
    )
    .unwrap();
    let out = tog(&project.0, &home.0, &["attest", "ruby"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("tog attest does not support ruby"),
        "{stderr}"
    );
    let out = tog(&project.0, &home.0, &["attest"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("nothing to attest"),
        "{}",
        text(&out.stderr)
    );
    let out = tog(&project.0, &home.0, &["attest", "node"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("no node project"),
        "{}",
        text(&out.stderr)
    );
    assert!(!home.0.join("store").exists());
    assert!(!project.0.join(".tog/closures").exists());
    assert!(!project.0.join(".tog/resolution").exists());
}

#[test]
fn attest_and_resolution_record_usage_errors_exit_2() {
    let home = TempDir::boundary("cli-attest-usage");
    for args in [
        &["attest", "--frozen"][..],
        &[
            "attest",
            "--ledger-import",
            "l.json",
            "--record-out",
            "r.json",
        ],
        &["attest", "golang"],
        &["status", "--resolution-record", "r.json"],
        &["--resolution-record", "r.json", "status"],
    ] {
        let out = tog(&home.0, &home.0, args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    // An unsigned artifact would never attest, so `--record-out` refuses
    // without a key before it looks at the project.
    let out = tog(&home.0, &home.0, &["attest", "--record-out", "r.json"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("TOG_SIGNING_KEY is not set"),
        "{}",
        text(&out.stderr)
    );
    assert!(!home.0.join("r.json").exists());
    let out = tog(&home.0, &home.0, &["help", "attest"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    for needle in ["--record-out", "--ledger-export", "--ledger-import"] {
        assert!(stdout.contains(needle), "{needle}: {stdout}");
    }
}

/// A supplied record that cannot be read fails the sync before anything
/// is resolved, and names the path.
#[test]
fn unreadable_resolution_record_fails_the_sync() {
    let home = TempDir::boundary("cli-record-missing");
    let project = TempDir::boundary("cli-record-missing-project");
    std::fs::write(
        project.0.join("go.mod"),
        "module example.com/p\n\ngo 1.22\n",
    )
    .unwrap();
    let out = tog(
        &project.0,
        &home.0,
        &["--resolution-record", "/nonexistent/go.json"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("/nonexistent/go.json"),
        "{}",
        text(&out.stderr)
    );
    assert!(!home.0.join("store").exists());
    assert!(!project.0.join(".tog/closures").exists());
    assert!(!project.0.join(".tog/resolution").exists());
}

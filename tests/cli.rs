//! The command surface, exercised through the real binary and offline: no
//! store objects are realized, no network is touched. Every case here is a
//! contract from CLI.md (exit status 0/1/2, help on stdout, errors on stderr
//! with a next step, pass-through for `run`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::fs::PermissionsExt;

use sha2::{Digest, Sha256};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-cli-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        // Mark the fixture as a project boundary. The review test directory
        // can itself live below a developer checkout with package manifests;
        // ancestor discovery must not make those fixtures non-hermetic.
        std::fs::create_dir_all(path.join(".blanket")).unwrap();
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
fn blanket(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_blanket"))
        .args(args)
        .current_dir(cwd)
        .env("BLANKET_STORE", home.join("store"))
        .env("HOME", home)
        .env_remove("BLANKET_POLICY")
        .env_remove("BLANKET_STRICT")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn blanket")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn no_arguments_prints_usage_and_exits_2() {
    let home = TempDir::new("noargs");
    let out = blanket(&home.0, &home.0, &[]);
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
        let out = blanket(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stderr.is_empty(), "{args:?}: {}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("EVERYDAY:"), "{args:?}: {stdout}");
        assert!(stdout.contains("BLANKET_STORE"), "{args:?}: {stdout}");
    }
    for args in [&["help", "sync"][..], &["sync", "--help"], &["sync", "-h"]] {
        let out = blanket(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let stdout = text(&out.stdout);
        assert!(stdout.starts_with("blanket sync — "), "{args:?}: {stdout}");
        assert!(stdout.contains("--fresh"), "{args:?}: {stdout}");
    }
    let out = blanket(&home.0, &home.0, &["help", "snyc"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("did you mean 'sync'?"));
}

#[test]
fn version() {
    let home = TempDir::new("version");
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let out = blanket(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert_eq!(
            text(&out.stdout),
            format!("blanket {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn usage_errors_exit_2_with_a_next_step() {
    let home = TempDir::new("usage");
    let cases: &[(&[&str], &str, &str)] = &[
        (&["snyc"], "unknown command 'snyc'; did you mean 'sync'?", "blanket --help"),
        (&["sync", "--fersh"], "sync: unknown option '--fersh'; did you mean '--fresh'?", "blanket help sync"),
        (&["sync", "now"], "sync: unexpected argument 'now'", "blanket help sync"),
        (&["plan", "--json"], "plan: unknown option '--json'", "blanket help plan"),
        (&["gc", "--keep-days", "soon"], "--keep-days expects a whole number of days, got 'soon'", "blanket help gc"),
        (&["gc", "--dryrun"], "gc: unknown option '--dryrun'; did you mean '--dry-run'?", "blanket help gc"),
        (&["sbom", "--output"], "--output needs a file path", "blanket help sbom"),
        (&["store"], "store needs a subcommand: 'store path' or 'store roots'", "blanket help store"),
        (&["store", "root"], "unknown store subcommand 'root'; did you mean 'roots'?", "blanket help store"),
        (&["run"], "run: no command given", "blanket help run"),
        (&["--dir", "x", "plan"], "unknown option '--dir'; did you mean '--directory'?", "blanket --help"),
        (&["-C"], "-C needs a directory", "blanket --help"),
        (&["add", "--", "--index-url"], "add: dependency spec '--index-url' looks like a tool option; package options are not allowed", "blanket help add"),
        (&["add", "requests\n--index-url evil"], "add: dependency spec contains CR, LF, or NUL", "blanket help add"),
        (&["x", "--from", "six", "/absolute/executable"], "x: --from requires a single safe executable name", "blanket help x"),
    ];
    for (args, message, hint) in cases {
        let out = blanket(&home.0, &home.0, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?} wrote to stdout");
        let stderr = text(&out.stderr);
        assert_eq!(
            stderr,
            format!("blanket: error: {message}\nRun '{hint}' for usage.\n"),
            "{args:?}"
        );
    }
}

#[test]
fn failures_exit_1_and_survive_quiet() {
    let home = TempDir::new("fail");
    let project = TempDir::new("empty");
    // An empty directory has no manifest: a real failure, not a usage error.
    let out = blanket(&project.0, &home.0, &["plan"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("blanket: error: no_manifest"), "{stderr}");

    // --quiet silences narration but never the error.
    let out = blanket(&project.0, &home.0, &["--quiet", "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("blanket: error: no_manifest"));
    let out = blanket(&project.0, &home.0, &["-q", "--no-color", "-v", "plan"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn directory_option_changes_where_the_command_runs() {
    let home = TempDir::new("chdir");
    let project = TempDir::new("chdir-project");
    // Run from `home`, point at the empty project: the empty project's
    // failure proves the command ran there.
    let out = blanket(&home.0, &home.0, &["-C", project.0.to_str().unwrap(), "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no_manifest"));
    let out = blanket(
        &home.0,
        &home.0,
        &["--directory", project.0.to_str().unwrap(), "-v", "plan"],
    );
    assert!(text(&out.stderr).contains("[verbose] working directory:"));

    let missing = project.0.join("missing");
    let out = blanket(&home.0, &home.0, &["-C", missing.to_str().unwrap(), "plan"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("blanket: error: cannot change directory to"));
}

#[test]
fn run_passes_arguments_through_and_needs_a_projection() {
    let home = TempDir::new("run");
    let project = TempDir::new("run-project");
    // Flags after the program are the program's: blanket does not parse
    // them, so the only error is the missing projection.
    let out = blanket(&project.0, &home.0, &["run", "python", "--help"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("no environment projected here"), "{stderr}");
    assert!(stderr.contains("blanket sync"), "{stderr}");
    // `--` reaches the same place with a program literally named `-h`.
    let out = blanket(&project.0, &home.0, &["run", "--", "-h"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no environment projected here"));
}

#[test]
fn store_path_honors_the_store_variable() {
    let home = TempDir::new("store");
    let out = blanket(&home.0, &home.0, &["store", "path"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let printed = PathBuf::from(text(&out.stdout).trim());
    assert_eq!(printed, home.0.join("store").canonicalize().unwrap());
    let out = blanket(&home.0, &home.0, &["store", "roots"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

// --- CLI.md level two: bare `blanket`, aliases, script shortcut, inspect ---

#[test]
fn bare_blanket_outside_a_project_prints_usage() {
    let home = TempDir::new("bare");
    let out = blanket(&home.0, &home.0, &[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("blanket: no project in "), "{stderr}");
    assert!(stderr.contains("USAGE:"), "{stderr}");
}

#[test]
fn install_alias_reaches_sync() {
    let home = TempDir::new("alias");
    let project = TempDir::new("alias-project");
    for args in [&["install"][..], &["i"], &["sync"]] {
        let out = blanket(&project.0, &home.0, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(text(&out.stderr).contains("no_manifest"), "{args:?}");
    }
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
    let out = blanket(&project.0, &home.0, &["dev", "--port", "3000"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("no environment projected here"));
    // A built-in verb always wins over a same-named script.
    let out = blanket(&project.0, &home.0, &["build"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("blanket build requires"), "{}", text(&out.stderr));
    // Not a script, not a verb: usage error naming the package.json.
    let out = blanket(&project.0, &home.0, &["deploy"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "blanket: error: unknown command 'deploy' (no package.json script named 'deploy' here)\nRun 'blanket --help' for usage.\n"
    );
    // Without a package.json the message stays plain.
    let out = blanket(&home.0, &home.0, &["deploy"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        text(&out.stderr),
        "blanket: error: unknown command 'deploy'\nRun 'blanket --help' for usage.\n"
    );
}

#[test]
fn inspect_verbs_offline() {
    let home = TempDir::new("inspect");
    let project = TempDir::new("inspect-project");

    let out = blanket(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no project in"));
    let out = blanket(&project.0, &home.0, &["ls"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("nothing synced here; run 'blanket sync' first"));

    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let out = blanket(&project.0, &home.0, &["status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).contains("python  not synced  run 'blanket sync'"), "{}", text(&out.stdout));
    let out = blanket(&project.0, &home.0, &["status", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["synced"], false);
    assert_eq!(value["ecosystems"][0]["state"], "not-synced");

    let out = blanket(&project.0, &home.0, &["doctor"]);
    let stdout = text(&out.stdout);
    for name in ["platform", "store", "sandbox", "c-toolchain", "project"] {
        assert!(stdout.contains(&format!("  {name}")), "{stdout}");
    }
    assert!(stdout.contains("python found; not synced yet"), "{stdout}");
    let out = blanket(&project.0, &home.0, &["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["checks"].is_array());

    let out = blanket(&project.0, &home.0, &["completions", "bash"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("complete -F _blanket blanket"));
    let out = blanket(&project.0, &home.0, &["completions", "powershell"]);
    assert_eq!(out.status.code(), Some(2));
}

// --- CLI.md level two, phases C and D: the offline paths of add/remove/x ---

#[test]
fn dependency_verbs_offline_paths() {
    let home = TempDir::new("deps");
    // The review suite may run below a checkout that has its own manifests;
    // use the filesystem root for the intentional no-project case so the
    // ancestor walk cannot discover that unrelated checkout.
    let out = blanket(Path::new("/"), &home.0, &["add", "requests"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no project from"), "{}", text(&out.stderr));

    // A plain requirements file: blanket edits it itself; with --no-sync
    // nothing else runs, so this is fully offline.
    let project = TempDir::new("deps-req");
    std::fs::write(project.0.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let out = blanket(&project.0, &home.0, &["add", "--no-sync", "requests>=2", "six==1.16.0"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(project.0.join("requirements.txt")).unwrap(),
        "six==1.16.0\nrequests>=2\n"
    );
    let stderr = text(&out.stderr);
    assert!(stderr.contains("requirements.txt: added requests, six"), "{stderr}");
    assert!(stderr.contains("--no-sync"), "{stderr}");
    let out = blanket(&project.0, &home.0, &["remove", "--no-sync", "idna"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("'idna' is not declared"));
    let out = blanket(&project.0, &home.0, &["remove", "--no-sync", "Requests"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(project.0.join("requirements.txt")).unwrap(),
        "six==1.16.0\n"
    );
    // --dev has no meaning here.
    let out = blanket(&project.0, &home.0, &["add", "--dev", "--no-sync", "pytest"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("--dev has no meaning"));

    // Refuse-with-instructions rows never touch the network or the store.
    let setup = TempDir::new("deps-setup");
    std::fs::write(setup.0.join("setup.py"), "from setuptools import setup\nsetup()\n").unwrap();
    let out = blanket(&setup.0, &home.0, &["add", "requests"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("install_requires"), "{}", text(&out.stderr));
    let pnpm = TempDir::new("deps-pnpm");
    std::fs::write(pnpm.0.join("package.json"), "{}").unwrap();
    std::fs::write(pnpm.0.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    let out = blanket(&pnpm.0, &home.0, &["add", "-D", "react", "left-pad"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("run 'pnpm add -D react left-pad'"), "{}", text(&out.stderr));
    let poetry = TempDir::new("deps-poetry");
    std::fs::write(poetry.0.join("pyproject.toml"), "[tool.poetry]\nname='p'\n").unwrap();
    let out = blanket(&poetry.0, &home.0, &["update"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("poetry update"), "{}", text(&out.stderr));
    let dotnet = TempDir::new("deps-dotnet");
    std::fs::write(dotnet.0.join("app.csproj"), "<Project/>").unwrap();
    let out = blanket(&dotnet.0, &home.0, &["add", "Newtonsoft.Json"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("dotnet add package Newtonsoft.Json"), "{}", text(&out.stderr));
    // A shape that contradicts the project is caught before any tool runs.
    let out = blanket(&project.0, &home.0, &["add", "@types/node"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no node manifest"), "{}", text(&out.stderr));
}

#[test]
fn x_needs_a_registry_outside_a_project() {
    let home = TempDir::new("x");
    let out = blanket(&home.0, &home.0, &["x", "ruff", "--version"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("blanket x py:ruff"), "{stderr}");
    let out = blanket(&home.0, &home.0, &["x"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn cached_x_rechecks_object_exceptions_under_project_policy() {
    let home = TempDir::new("x-policy-home");
    let project = TempDir::new("x-policy-project");
    std::fs::write(
        project.0.join(".blanket/policy.toml"),
        "deny = [\"file-collision\"]\n",
    )
    .unwrap();

    let store = home.0.join("store");
    let object = store.join("objects/test-env");
    std::fs::create_dir_all(object.join("bin")).unwrap();
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
            store.canonicalize().unwrap().display(),
            blanket::platform::Platform::host().unwrap().triple()
        )
            .as_bytes(),
    ));
    let root = home
        .0
        .join(".blanket/x")
        .join(format!("py-fake-{}", &key[..16]));
    std::fs::create_dir_all(root.join(".blanket/closures")).unwrap();
    std::os::unix::fs::symlink(&object, root.join(".venv")).unwrap();
    let body = serde_json::json!({
        "env_object": object,
        "exceptions": [exception]
    });
    std::fs::write(
        root.join(".blanket/closures/python.json"),
        serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "platform": blanket::platform::Platform::host().unwrap().triple(),
            "body": body
        })
        .to_string(),
    )
    .unwrap();

    let out = blanket(&project.0, &home.0, &["x", "--py", "--from", "fake", "ruff"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("cached object test-env carries exception"));
}

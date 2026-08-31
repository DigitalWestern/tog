//! End-to-end Ruby tailor test. Heavy: downloads the pinned portable Ruby
//! and the gem closure (racc compiles a C extension in the sandbox).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-ruby-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn blanket(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(project)
        .env("BLANKET_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

fn assert_ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
#[ignore]
fn ruby_sync_native_ext_and_run() {
    let temp = TempDir::new();
    let project = temp.0.join("ruby-hello");
    std::fs::create_dir_all(&project).unwrap();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ruby-hello");
    for f in ["Gemfile", "Gemfile.lock"] {
        std::fs::copy(fixtures.join(f), project.join(f)).unwrap();
    }
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    // Hostile .bundle/config must be neutralized (BUNDLE_IGNORE_CONFIG).
    std::fs::create_dir_all(project.join(".bundle")).unwrap();
    std::fs::write(
        project.join(".bundle/config"),
        "---\nBUNDLE_PATH: \"/nonexistent\"\nBUNDLE_GEMFILE: \"/nonexistent/Gemfile\"\n",
    )
    .unwrap();

    assert_ok(blanket(&binary, &project, &store, &["sync"]), "sync");
    // racc's C extension compiled in the sandbox; requiring it proves the
    // .bundle stayed loadable and the projected env works.
    let out = assert_ok(
        blanket(
            &binary,
            &project,
            &store,
            &["run", "ruby", "-e", "require \"racc/parser\"; require \"rake\"; puts \"ok \" + Rake::VERSION"],
        ),
        "run",
    );
    assert!(out.trim().starts_with("ok 13."), "{out}");
    // Gem binstub through the projected bin dir, ruby-first PATH.
    let version = assert_ok(
        blanket(&binary, &project, &store, &["run", "rake", "--version"]),
        "rake binstub",
    );
    assert!(version.contains("13."), "{version}");
}

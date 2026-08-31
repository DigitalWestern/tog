//! End-to-end .NET tailor test. Heavy: downloads the pinned SDK (~230MB)
//! and the NuGet closure.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-dotnet-e2e-{}-{}",
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
fn dotnet_sync_sandboxed_build_and_run() {
    let temp = TempDir::new();
    let project = temp.0.join("dotnet-hello");
    std::fs::create_dir_all(&project).unwrap();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dotnet-hello");
    for f in ["proj.csproj", "packages.lock.json", "Program.cs"] {
        std::fs::copy(fixtures.join(f), project.join(f)).unwrap();
    }
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    assert_ok(blanket(&binary, &project, &store, &["sync"]), "sync");
    assert_ok(blanket(&binary, &project, &store, &["build"]), "build");
    let dll = std::fs::read_dir(project.join("bin"))
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("blanket-"))
        .map(|e| e.path().join("proj.dll"))
        .expect("staged bin dir");
    assert!(dll.is_file());
    let out = assert_ok(
        blanket(&binary, &project, &store, &["run", "dotnet", dll.to_str().unwrap()]),
        "run built app",
    );
    assert!(out.contains("{\"dotnet\":\"ok\"}"), "{out}");
    // Build-capable verbs are sandbox-only.
    let refused = blanket(&binary, &project, &store, &["run", "dotnet", "build"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("blanket build dotnet"),
        "build verb must be refused at run"
    );
}

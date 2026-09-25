//! End-to-end .NET tailor test. Heavy: downloads the pinned SDK (~230MB)
//! and the NuGet closure.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

mod common;

use common::{assert_frozen_never_writes_the_lock, assert_ok, fixture, tog, tog_at, TempDir};

fn copy_dotnet_hello(project: &Path) {
    std::fs::create_dir_all(project).unwrap();
    let fixtures = fixture("dotnet-hello");
    for f in ["proj.csproj", "packages.lock.json", "Program.cs"] {
        std::fs::copy(fixtures.join(f), project.join(f)).unwrap();
    }
}

fn published_dll(project: &Path) -> PathBuf {
    std::fs::read_dir(project.join("bin"))
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("tog-"))
        .map(|e| e.path().join("proj.dll"))
        .expect("staged bin dir")
}

fn sdk_object(store: &Path) -> PathBuf {
    std::fs::read_dir(store.join("objects"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|path| path.join("dotnet").is_file() && path.join("sdk/9.0.317").is_dir())
        .expect("committed .NET SDK object")
}

fn assert_realization_does_not_evaluate_user_project(temp: &TempDir) {
    let project = temp.0.join("dotnet-tripwire");
    copy_dotnet_hello(&project);
    let csproj = project.join("proj.csproj");
    let mut text = std::fs::read_to_string(&csproj).unwrap();
    text = text.replace(
        "</Project>",
        "<Target Name=\"Tripwire\" BeforeTargets=\"Restore\"><WriteLinesToFile File=\"tripwire.txt\" Lines=\"executed\" Overwrite=\"true\" /></Target></Project>",
    );
    std::fs::write(csproj, text).unwrap();
    let store = temp.0.join("tripwire-store");
    assert_ok(
        tog_at(&project, &temp.0, &store, &["sync"]),
        "tripwire sync",
    );
    assert!(
        !project.join("tripwire.txt").exists(),
        "realization evaluated the user's project"
    );
}

#[test]
#[ignore]
fn dotnet_sync_sandboxed_build_and_run() {
    let temp = TempDir::new("dotnet-e2e");
    let project = temp.0.join("dotnet-hello");
    copy_dotnet_hello(&project);
    let store = temp.0.join("store");

    assert_ok(tog(&project, &temp.0, &["sync"]), "sync");
    let version = assert_ok(
        tog(&project, &temp.0, &["run", "dotnet", "--version"]),
        "dotnet --version",
    );
    assert!(
        version.lines().any(|line| line.trim() == "9.0.317"),
        "{version}"
    );
    if cfg!(target_os = "linux") {
        let info = assert_ok(
            tog(&project, &temp.0, &["run", "dotnet", "--info"]),
            "dotnet --info",
        );
        // `dotnet --info` pads with variable whitespace; compare fields.
        let field = |name: &str| {
            info.lines()
                .filter_map(|line| line.trim().strip_prefix(name))
                .map(|rest| rest.trim().to_string())
                .next()
        };
        assert_eq!(field("OS Platform:").as_deref(), Some("Linux"), "{info}");
        assert_eq!(field("RID:").as_deref(), Some("linux-x64"), "{info}");
        let base_path = sdk_object(&store).join("sdk/9.0.317");
        assert!(
            info.contains(&base_path.display().to_string()),
            "SDK base path is not under the committed store object: {base_path:?}\n{info}"
        );
    }
    assert_ok(tog(&project, &temp.0, &["build"]), "build");
    let dll = published_dll(&project);
    assert!(dll.is_file());
    let out = assert_ok(
        tog(&project, &temp.0, &["run", "dotnet", dll.to_str().unwrap()]),
        "run built app",
    );
    assert!(out.contains("{\"dotnet\":\"ok\"}"), "{out}");

    std::fs::remove_dir_all(dll.parent().unwrap()).unwrap();
    assert_ok(
        tog(&project, &temp.0, &["build"]),
        "build after published output deletion",
    );
    let rebuilt = published_dll(&project);
    let out = assert_ok(
        tog(
            &project,
            &temp.0,
            &["run", "dotnet", rebuilt.to_str().unwrap()],
        ),
        "run rebuilt app",
    );
    assert!(out.contains("{\"dotnet\":\"ok\"}"), "{out}");

    // Build-capable verbs are sandbox-only.
    let refused = tog(&project, &temp.0, &["run", "dotnet", "build"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("tog build dotnet"),
        "build verb must be refused at run"
    );

    assert_realization_does_not_evaluate_user_project(&temp);

    // Without its lock the project is refused under --frozen and left
    // alone; a plan regenerates the lock with the store SDK.
    assert_frozen_never_writes_the_lock(&project, &temp.0, "packages.lock.json");
}

#[test]
#[ignore]
fn dotnet_realization_does_not_evaluate_user_project() {
    let temp = TempDir::new("dotnet-e2e");
    assert_realization_does_not_evaluate_user_project(&temp);
}

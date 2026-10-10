//! End-to-end .NET tailor test. Heavy: downloads the pinned SDK (~230MB)
//! and the NuGet closure.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};

mod common;

use common::{
    assert_frozen_never_writes_the_lock, assert_ok, assert_private_run_home, fixture, temp_entries,
    tog, tog_at, TempDir,
};

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
    // Two tripwires. The property fires on evaluation itself: MSBuild
    // expands every property in a PropertyGroup before any target runs,
    // and `ReadAllText` of a file that does not exist fails that
    // evaluation (MSB4184), so a sync that so much as evaluates the
    // project fails. The target fires on any build of it: an initial
    // target runs before whatever target was asked for, restore included.
    text = text.replace(
        "<Project Sdk=\"Microsoft.NET.Sdk\">",
        "<Project Sdk=\"Microsoft.NET.Sdk\" InitialTargets=\"Tripwire\">",
    );
    text = text.replace(
        "</Project>",
        "<PropertyGroup><TripwireEvaluated>$([System.IO.File]::ReadAllText('$(MSBuildProjectDirectory)/tripwire-must-not-exist.txt'))</TripwireEvaluated></PropertyGroup>\
         <Target Name=\"Tripwire\" BeforeTargets=\"Restore\"><WriteLinesToFile File=\"tripwire.txt\" Lines=\"executed\" Overwrite=\"true\" /></Target></Project>",
    );
    assert!(text.contains("InitialTargets"), "{text}");
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

/// Exercise the CLI's signed receipt and strict resolution join using the
/// SDK already realized by the build test. Added project data must invalidate
/// evidence and preserve the last signed environment on refusal.
fn assert_signed_dotnet_resolution(temp: &TempDir) {
    let project = temp.0.join("dotnet-resolution");
    copy_dotnet_hello(&project);
    std::fs::remove_file(project.join("packages.lock.json")).unwrap();
    let key = temp.0.join("resolution.key");
    let trust = assert_ok(
        tog(&temp.0, &temp.0, &["keygen", key.to_str().unwrap()]),
        "resolution keygen",
    );
    std::fs::create_dir_all(temp.0.join(".tog")).unwrap();
    std::fs::write(
        temp.0.join(".tog/policy.toml"),
        format!("deny = [\"unrecorded-resolution\"]\n{trust}"),
    )
    .unwrap();
    let env = [("TOG_SIGNING_KEY", &key)];
    assert_ok(
        common::tog_env(&project, &temp.0, &["sync"], &env),
        "signed missing-lock restore",
    );
    let receipt_path = project.join(".tog/resolution/dotnet.json");
    let read = |path: &Path| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    };
    let public = tog::kernel::signing::SigningKey::load(&key)
        .unwrap()
        .public_key();
    let receipt = read(&receipt_path);
    assert_eq!(
        tog::kernel::signing::verify(&receipt),
        tog::kernel::signing::Verification::Valid(public)
    );
    let lock_before = std::fs::read(project.join("packages.lock.json")).unwrap();
    let project_before = std::fs::read(project.join("proj.csproj")).unwrap();
    assert_ok(
        common::tog_env(&project, &temp.0, &["attest", "dotnet"], &env),
        "signed .NET attest",
    );
    let receipt = read(&receipt_path);
    assert_eq!(
        tog::kernel::signing::verify(&receipt),
        tog::kernel::signing::Verification::Valid(public)
    );
    assert_eq!(
        std::fs::read(project.join("packages.lock.json")).unwrap(),
        lock_before
    );
    assert_eq!(
        std::fs::read(project.join("proj.csproj")).unwrap(),
        project_before
    );
    assert_ok(
        common::tog_env(&project, &temp.0, &["sync"], &env),
        "trusted .NET receipt join",
    );
    let closure_path = project.join(".tog/closures/dotnet.json");
    let closure_before = std::fs::read(&closure_path).unwrap();
    assert_eq!(read(&closure_path)["body"]["resolution"], receipt);
    std::fs::write(project.join("added-input.txt"), "new MSBuild-visible data").unwrap();
    let refused = common::tog_env(&project, &temp.0, &["sync"], &env);
    assert!(!refused.status.success());
    assert!(
        common::text(&refused.stderr).contains("policy denies unrecorded-resolution"),
        "{}",
        common::text(&refused.stderr)
    );
    assert_eq!(std::fs::read(closure_path).unwrap(), closure_before);
}

#[test]
#[ignore]
fn dotnet_sync_sandboxed_build_and_run() {
    let temp = TempDir::new("dotnet-e2e");
    let project = temp.0.join("dotnet-hello");
    copy_dotnet_hello(&project);
    let store = temp.0.join("store");
    let temp_before = temp_entries("tog-dn-run-");

    assert_ok(tog(&project, &temp.0, &["sync"]), "sync");
    let run_home = assert_private_run_home(&project, &temp.0, &store, "dotnet", "tog-dn-run-");
    let version = assert_ok(
        tog(&project, &temp.0, &["run", "dotnet", "--version"]),
        "dotnet --version",
    );
    // The run home carries the NuGet migration sentinel the sync path
    // writes, so a run never takes NuGet's machine-global migration mutex.
    let scratch = run_home.parent().unwrap();
    assert!(
        scratch.join("xdg-data/NuGet/Migrations/1").is_file(),
        "no NuGet migration sentinel under {}",
        scratch.display()
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
    let left: Vec<_> = temp_entries("tog-dn-run-")
        .difference(&temp_before)
        .cloned()
        .collect();
    assert!(left.is_empty(), "runs left {left:?} under the temp root");

    assert_signed_dotnet_resolution(&temp);
}

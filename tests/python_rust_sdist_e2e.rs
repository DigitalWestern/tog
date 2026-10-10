//! Real regression for an older Rust-backed Python source release.
#![allow(clippy::disallowed_methods)]

mod common;
use common::{assert_ok, command, TempDir};

#[test]
#[ignore]
fn tokenizers_legacy_rust_lints_do_not_prevent_its_source_build() {
    let temp = TempDir::new("tokenizers-lint-cap");
    // The project and home are separate directories: uv runs confined, and
    // the door refuses a project that contains the signing key under home.
    let project = &temp.0.join("project");
    let home = &temp.0.join("home");
    std::fs::create_dir_all(project).unwrap();
    std::fs::create_dir_all(home).unwrap();
    // Never reuse a successful wheel or environment from an earlier run.
    let store = temp.0.join("store");
    std::fs::write(project.join("requirements.txt"), "tokenizers==0.13.3\n").unwrap();
    // This release has no CPython 3.12 wheel, so sync exercises the source
    // build whose own crate trips invalid_reference_casting on modern Rust.
    std::fs::write(project.join(".python-version"), "3.12.14\n").unwrap();
    assert_ok(
        command(project, home, &store).arg("sync").output().unwrap(),
        "tokenizers source build",
    );
    let output = command(project, home, &store)
        .args([
            "run",
            "python",
            "-c",
            "import tokenizers; print(tokenizers.__version__)",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0.13.3");
    assert_ok(output, "import built tokenizers");
}

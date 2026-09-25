//! End-to-end wheel `.data` scheme coverage. Heavy: resolves greenlet and
//! realizes CPython plus the selected manylinux/macosx wheel, so it is ignored.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;

mod common;

use common::{assert_ok, copy_tree, fixture, tog_at, warm_store, TempDir};

#[test]
#[ignore]
fn greenlet_headers_are_installed_and_importable() {
    let temp = TempDir::new("wheel-data");
    let project = temp.0.join("proj-greenlet");
    copy_tree(&fixture("proj-greenlet"), &project);
    let store = warm_store(&temp);

    assert_ok(tog_at(&project, &temp.0, &store, &["sync"]), "sync alias");

    let closure: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join(".tog/closures/python.json")).unwrap())
            .unwrap();
    let env = PathBuf::from(closure["body"]["env_object"].as_str().unwrap());
    assert!(
        env.is_dir(),
        "environment object is missing: {}",
        env.display()
    );
    assert!(
        env.join("include/site/python3.12/greenlet/greenlet.h")
            .is_file(),
        "greenlet header was not installed under {}",
        env.display()
    );

    let output = assert_ok(
        tog_at(
            &project,
            &temp.0,
            &store,
            [
                "run",
                "python",
                "-c",
                "import greenlet; print(greenlet.__version__)",
            ]
            .as_slice(),
        ),
        "tog run python",
    );
    assert_eq!(output.trim(), "3.5.5");
}

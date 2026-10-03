//! Positive control for the sandboxed builder: a well-behaved sdist (docopt,
//! sdist-only on PyPI) must build into a wheel inside the network-denied
//! sandbox. Heavy; run: cargo test --test sdist_build -- --ignored
//! The store is a scratch one unless TOG_STORE names another, never the
//! developer's own.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use tog::kernel::platform::Platform;
use tog::kernel::types::*;
use tog::tailors::python;
use tog::tailors::python::build;

mod common;

use common::TempDir;

#[test]
#[ignore]
fn docopt_sdist_builds_in_sandbox() {
    let temp = TempDir::new("sdist-build");
    let store = common::open_store(&temp);
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let mut attribution = tog::kernel::policy::Attribution::open("python").unwrap();
    let pkg = LockedPackage {
        name: "docopt".into(),
        version: "0.6.2".into(),
        filename: "docopt-0.6.2.tar.gz".into(),
        url: "https://files.pythonhosted.org/packages/a2/55/8f8cab2afd404cf578136ef2cc5dfb50baa1761b68c9da1fb1e4eed343c9/docopt-0.6.2.tar.gz".into(),
        sha256: "49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491".into(),
        kind: ArtifactKind::Sdist,
        git: None,
    };
    let wheel = build::build_sdist_wheel(
        &mut tog::kernel::resolve::ResolutionDoor::open(
            &store,
            activity,
            Platform::host().unwrap(),
            tog::kernel::resolve::DoorKind::Planner,
            &mut attribution,
        )
        .unwrap(),
        &pkg,
        &python::shipped_selection("3.12.14").unwrap(),
    )
    .expect("sdist build");
    assert!(wheel
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("docopt-0.6.2-"));
    assert!(wheel.exists());
}

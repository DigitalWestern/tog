//! Positive control for the sandboxed builder: a well-behaved sdist (docopt,
//! sdist-only on PyPI) must build into a wheel inside the network-denied
//! sandbox. Heavy; run: cargo test --test sdist_build -- --ignored

use blanket::kernel::platform::Platform;
use blanket::kernel::store::Store;
use blanket::kernel::types::*;
use blanket::tailors::python::build;

#[test]
#[ignore]
fn docopt_sdist_builds_in_sandbox() {
    let store = Store::open().expect("store");
    let pkg = LockedPackage {
        name: "docopt".into(),
        version: "0.6.2".into(),
        filename: "docopt-0.6.2.tar.gz".into(),
        url: "https://files.pythonhosted.org/packages/a2/55/8f8cab2afd404cf578136ef2cc5dfb50baa1761b68c9da1fb1e4eed343c9/docopt-0.6.2.tar.gz".into(),
        sha256: "49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491".into(),
        kind: ArtifactKind::Sdist,
        git: None,
    };
    let wheel = build::build_sdist_wheel(&store, Platform::host().unwrap(), &pkg, "3.12.14")
        .expect("sdist build");
    assert!(wheel
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("docopt-0.6.2-"));
    assert!(wheel.exists());
}

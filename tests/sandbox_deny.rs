//! Acceptance: a build that attempts undeclared network access MUST fail.
//!
//! Heavy (realizes CPython + build toolchain on first run), so #[ignore]d;
//! tests/acceptance.sh runs it with a shared BLANKET_STORE:
//!     cargo test --test sandbox_deny -- --ignored

use blanket::{build, platform::Platform, store::Store, types::*};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[test]
#[ignore]
fn network_access_during_build_fails() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/evil-0.1.tar.gz");
    let bytes = std::fs::read(&fixture).expect("fixture exists");
    let sha = hex::encode(Sha256::digest(&bytes));

    let store = Store::open().expect("store");
    let pkg = LockedPackage {
        name: "evil".into(),
        version: "0.1".into(),
        filename: "evil-0.1.tar.gz".into(),
        url: format!("file://{}", fixture.display()),
        sha256: sha,
        kind: ArtifactKind::Sdist,
    };

    let result = build::build_sdist_wheel(
        &store,
        Platform::host().unwrap(),
        &pkg,
        "3.12.14",
    );
    let err = result.expect_err("build reaching the network must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("sandboxed build") || msg.contains("failed"),
        "unexpected error shape: {msg}"
    );
}

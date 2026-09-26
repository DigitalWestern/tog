//! Acceptance: a build that attempts undeclared network access MUST fail.
//!
//! Heavy (realizes CPython + build toolchain on first run), so #[ignore]d;
//! tests/acceptance.sh runs it with a shared TOG_STORE:
//!     cargo test --test sandbox_deny -- --ignored

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use sha2::{Digest, Sha256};
use tog::kernel::platform::Platform;
use tog::kernel::sandbox::{run_build_spec, BuildSpec};
use tog::kernel::store::Store;
use tog::kernel::types::*;
use tog::tailors::python;
use tog::tailors::python::build;

mod common;

use common::{fixture, TempDir};

/// `TOG_SANDBOX_TESTS=required` (any non-empty value) turns the Linux
/// skip into a panic so CI cannot report a skipped check as passed.
fn required_sandbox_tests() -> bool {
    matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty())
}

fn skip_or_panic(test_name: &str, reason: impl std::fmt::Display) {
    if required_sandbox_tests() {
        panic!("required Linux sandbox test {test_name} unavailable: {reason}");
    }
    eprintln!("skip {test_name}: {reason}");
}

#[test]
#[ignore]
fn network_access_during_build_fails() {
    let fixture = fixture("evil-0.1.tar.gz");
    let bytes = std::fs::read(&fixture).expect("fixture exists");
    let sha = hex::encode(Sha256::digest(&bytes));

    let store = Store::open().expect("store");
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let pkg = LockedPackage {
        name: "evil".into(),
        version: "0.1".into(),
        filename: "evil-0.1.tar.gz".into(),
        url: format!("file://{}", fixture.display()),
        sha256: sha,
        kind: ArtifactKind::Sdist,
        git: None,
    };

    let result = build::build_sdist_wheel(
        &store,
        activity,
        Platform::host().unwrap(),
        &pkg,
        &python::shipped_selection("3.12.14").unwrap(),
    );
    let err = result.expect_err("build reaching the network must fail");
    let msg = err.to_string();
    // A sandbox that failed to set up (Unsupported) is not evidence of
    // denial: the build must have run and exited non-zero inside it.
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "sandbox did not run: {msg}"
    );
    assert!(
        msg.contains("sandboxed build of evil==0.1 failed"),
        "unexpected error shape: {msg}"
    );
    assert!(
        msg.contains("sandboxed command failed (exit status"),
        "build did not execute: {msg}"
    );
}

#[test]
fn bwrap_contract() {
    match Platform::host() {
        Ok(Platform::X86_64UnknownLinuxGnu) => {}
        Ok(platform) => {
            skip_or_panic(
                "bwrap_contract",
                format!("not Linux ({})", platform.triple()),
            );
            return;
        }
        Err(error) => {
            skip_or_panic(
                "bwrap_contract",
                format!("not a supported Linux host ({error})"),
            );
            return;
        }
    }
    // tog's own preflight, so this gate mounts exactly the system layout
    // real builds get and a skip carries the reason doctor would print.
    if let Err(error) = tog::kernel::sandbox::probe(Platform::X86_64UnknownLinuxGnu) {
        skip_or_panic(
            "bwrap_contract",
            format!("bubblewrap preflight failed: {error}"),
        );
        return;
    }

    let temp = TempDir::new("sandbox-contract");
    let root = temp.path();
    let scratch = root.join("scratch");
    let writable = root.join("writable");
    let forbidden = root.join("forbidden");
    std::fs::create_dir(&scratch).unwrap();
    std::fs::create_dir(&writable).unwrap();
    std::fs::create_dir(&forbidden).unwrap();
    let writable_arg = writable.to_str().unwrap().to_string();
    let forbidden_arg = forbidden.to_str().unwrap().to_string();

    assert!(std::path::Path::new("/usr/bin/curl").is_file());
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    use std::io::Write;
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    let host_connection =
        std::net::TcpStream::connect(address).expect("host positive network control");
    let network_url = format!("http://127.0.0.1:{}/", address.port());
    let network = BuildSpec {
        argv: vec![
            "/usr/bin/sh".into(),
            "-c".into(),
            // curl exit 7 = could not connect (namespace isolated). 0 means the
            // network leaked (exit 91); any other code means the probe itself
            // did not run and is surfaced verbatim rather than counted as pass.
            format!(
                "/usr/bin/curl -fsS --connect-timeout 2 --max-time 3 {network_url} >/dev/null 2>&1; rc=$?; if [ \"$rc\" -eq 7 ]; then exit 0; elif [ \"$rc\" -eq 0 ]; then exit 91; else exit \"$rc\"; fi"
            ),
        ],
        cwd: scratch.clone(),
        env: vec![],
        read: vec![],
        write: vec![],
        scratch: scratch.clone(),
        path: "/usr/bin:/bin".into(),
        host_view: tog::kernel::sandbox::HostView::Full,
    };
    run_build_spec(&network).expect("network must be denied inside bwrap");
    drop(host_connection);
    server.join().unwrap();

    let writes = BuildSpec {
        argv: vec![
            "/usr/bin/sh".into(),
            "-c".into(),
            "if /usr/bin/touch \"$1/allowed\" && ! /usr/bin/touch \"$2/forbidden\"; then exit 0; else exit 92; fi".into(),
            "sh".into(),
            writable_arg,
            forbidden_arg,
        ],
        cwd: scratch.clone(),
        env: vec![],
        read: vec![],
        write: vec![writable.clone()],
        scratch,
        path: "/usr/bin:/bin".into(),
        host_view: tog::kernel::sandbox::HostView::Full,
    };
    run_build_spec(&writes).expect("declared write must work and undeclared write must fail");
    assert!(writable.join("allowed").exists());
    assert!(!forbidden.join("forbidden").exists());
}

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

use common::TempDir;
use std::path::Path;

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

/// A setuptools sdist named `name`, version 0.1, whose setup.py runs
/// `prelude` first and ships the one module `modules` names, if any,
/// packed with the host tar into `dir`.
fn sdist(dir: &Path, name: &str, prelude: &str, modules: &str) -> LockedPackage {
    let root = dir.join(format!("{name}-0.1"));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("PKG-INFO"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: 0.1\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("pyproject.toml"),
        "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"setuptools.build_meta\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("setup.py"),
        // The scratch path makes every run's sdist new to the store, so the
        // build runs here rather than coming back from an earlier run's
        // cached wheel.
        format!(
            "# built from {}\n{prelude}\nfrom setuptools import setup\n\
             setup(name=\"{name}\", version=\"0.1\", py_modules=[{modules}])\n",
            dir.display()
        ),
    )
    .unwrap();
    let filename = format!("{name}-0.1.tar.gz");
    let archive = dir.join(&filename);
    let status = std::process::Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(dir)
        .arg(format!("{name}-0.1"))
        .status()
        .unwrap();
    assert!(status.success(), "tar {filename}");
    let bytes = std::fs::read(&archive).unwrap();
    LockedPackage {
        name: name.into(),
        version: "0.1".into(),
        filename,
        url: format!("file://{}", archive.display()),
        sha256: hex::encode(Sha256::digest(&bytes)),
        kind: ArtifactKind::Sdist,
        git: None,
    }
}

/// Connect to an IP literal (no resolver involved) and keep what happened
/// in `outcome`: `connected`, or the repr of the error connect raised.
const CONNECT_PROBE: &str = "import socket\n\
    try:\n    \
        socket.create_connection((\"1.1.1.1\", 443), timeout=10).close()\n    \
        outcome = \"connected\"\n\
    except OSError as error:\n    \
        outcome = repr(error)\n";

/// A build that opens a connection fails, and the reason is the network
/// namespace itself, not an HTTP error, a DNS failure, or a missing
/// setuptools. pip keeps a build backend's output out of both the relayed
/// stderr and the error's log tail, so the evidence travels in a wheel:
/// a recorder sdist runs the same connect, writes what it raised into a
/// module, and builds. That build succeeding is also the control that the
/// build toolchain works offline.
#[test]
#[ignore]
fn network_access_during_build_fails() {
    let temp = TempDir::new("sandbox-deny");
    let store = Store::open().expect("store");
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let python = python::shipped_selection("3.12.14").unwrap();
    let platform = Platform::host().unwrap();

    let recorder = sdist(
        temp.path(),
        "connectrecord",
        &format!(
            "{CONNECT_PROBE}open(\"connectrecord.py\", \"w\").write(\"OUTCOME = %r\\n\" % outcome)\n"
        ),
        "\"connectrecord\"",
    );
    let wheel = build::build_sdist_wheel(&store, activity, platform, &recorder, &python)
        .expect("the recorder sdist must build: the build toolchain works offline");
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&wheel).unwrap()).unwrap();
    let mut recorded = String::new();
    std::io::Read::read_to_string(
        &mut archive.by_name("connectrecord.py").unwrap(),
        &mut recorded,
    )
    .unwrap();
    // A namespace with no route out: the kernel refuses the connect before
    // a packet leaves. A timeout would mean the packet left and was dropped
    // somewhere else, which is not the sandbox's denial.
    assert_eq!(
        recorded, "OUTCOME = \"OSError(101, 'Network is unreachable')\"\n",
        "the build's connect was not refused by the sandbox"
    );

    let probe = sdist(
        temp.path(),
        "phonehome",
        &format!("{CONNECT_PROBE}assert outcome == \"connected\", outcome\n"),
        "",
    );
    let err = build::build_sdist_wheel(&store, activity, platform, &probe, &python)
        .expect_err("build reaching the network must fail");
    let msg = err.to_string();
    // A sandbox that failed to set up (Unsupported) is not evidence of
    // denial: the build must have run and exited non-zero inside it.
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "sandbox did not run: {msg}"
    );
    assert!(
        msg.contains("sandboxed build of phonehome==0.1 failed"),
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

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
    let mut attribution = tog::kernel::policy::Attribution::open("python").unwrap();
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
    let wheel = build::build_sdist_wheel(
        &mut tog::kernel::resolve::ResolutionDoor::open(
            &store,
            activity,
            platform,
            tog::kernel::resolve::DoorKind::Planner,
            &mut attribution,
        )
        .unwrap(),
        &recorder,
        &python,
    )
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
    let err = build::build_sdist_wheel(
        &mut tog::kernel::resolve::ResolutionDoor::open(
            &store,
            activity,
            platform,
            tog::kernel::resolve::DoorKind::Planner,
            &mut attribution,
        )
        .unwrap(),
        &probe,
        &python,
    )
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

/// The resolution door's Linux confinement, end to end: bubblewrap in the
/// `Proxy` network mode, the relay (the real `tog` binary), the seccomp
/// filter, the socket scan, quiescence, and publication. The "tool" is a C
/// probe compiled with the host's cc; the "proxy" is a stub Unix listener
/// that answers every connection with one line.
#[cfg(target_os = "linux")]
mod door {
    use super::*;
    use std::ffi::OsString;
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tog::kernel::activity::ActivityMode;
    use tog::kernel::fsroot::ProjectRoot;
    use tog::kernel::resolve::confine::{
        confined_run, ConfinedOutcome, ConfinedRun, SocketScan, Stdout,
    };
    use tog::kernel::resolve::outputs::Outputs;
    use tog::kernel::resolve::relay::ToolStatus;
    use tog::kernel::resolve::snapshot::{Snapshot, SnapshotSpec};
    use tog::kernel::resolve::transaction::{HoldSpec, Transaction};

    /// One supervised child per process at a time.
    static DOOR: Mutex<()> = Mutex::new(());

    const PROXY_REPLY: &str = "PROXY-OK";

    struct Door {
        temp: TempDir,
        store: Store,
        project: PathBuf,
        tools: PathBuf,
        probe: PathBuf,
        proxy: PathBuf,
        connections: Arc<AtomicUsize>,
    }

    fn door(test: &str) -> Option<Door> {
        if !matches!(Platform::host(), Ok(Platform::X86_64UnknownLinuxGnu)) {
            skip_or_panic(test, "not a supported Linux host");
            return None;
        }
        if let Err(error) = tog::kernel::sandbox::probe(Platform::X86_64UnknownLinuxGnu) {
            skip_or_panic(test, format!("bubblewrap preflight failed: {error}"));
            return None;
        }
        let temp = TempDir::new("door");
        let root = temp.path().join("store");
        for sub in [
            "objects",
            "meta",
            "tmp",
            "roots",
            "root-locks",
            "records",
            "forests",
            "backups",
        ] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        let tools = temp.path().join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let probe = tools.join("door_probe");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/door_probe.c");
        let compiled = std::process::Command::new("/usr/bin/cc")
            .arg("-O1")
            .arg("-o")
            .arg(&probe)
            .arg(&source)
            .output();
        match compiled {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                skip_or_panic(
                    test,
                    format!("cc failed: {}", String::from_utf8_lossy(&output.stderr)),
                );
                return None;
            }
            Err(error) => {
                skip_or_panic(test, format!("no C compiler at /usr/bin/cc: {error}"));
                return None;
            }
        }
        let project = temp.path().join("project");
        std::fs::create_dir_all(project.join(".git/hooks")).unwrap();
        std::fs::write(project.join("package.json"), b"{\"dependencies\":{}}\n").unwrap();
        std::fs::write(project.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        let proxy = temp.path().join("p.sock");
        let listener = UnixListener::bind(&proxy).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(format!("{PROXY_REPLY}\n").as_bytes());
            }
        });
        Some(Door {
            store: Store {
                root: root.canonicalize().unwrap(),
            },
            project: project.canonicalize().unwrap(),
            tools: tools.canonicalize().unwrap(),
            probe,
            proxy,
            connections,
            temp,
        })
    }

    impl Door {
        fn snapshot(&self) -> Snapshot {
            let activity = self.store.activity(ActivityMode::Shared).unwrap();
            Snapshot::build(
                &self.store,
                &activity,
                &SnapshotSpec {
                    lock_root: &self.project,
                    extra_roots: &[],
                    exclude: &[],
                },
            )
            .unwrap()
        }

        fn probe_argv(&self, args: &[&str]) -> Vec<OsString> {
            std::iter::once(self.probe.clone().into_os_string())
                .chain(args.iter().map(OsString::from))
                .collect()
        }

        fn shell_argv(&self, script: &str) -> Vec<OsString> {
            ["/bin/sh", "-c", script, "sh", self.probe.to_str().unwrap()]
                .iter()
                .map(OsString::from)
                .collect()
        }

        fn run(
            &self,
            snapshot: &Snapshot,
            argv: &[OsString],
            scan: SocketScan,
        ) -> std::io::Result<ConfinedOutcome> {
            let _one = DOOR.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let activity = self.store.activity(ActivityMode::Shared).unwrap();
            let env = [(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))];
            confined_run(
                &self.store,
                &activity,
                &ConfinedRun {
                    tool: "the door probe",
                    why: "runs whatever the test tells it to",
                    unconfined_denied: true,
                    snapshot,
                    proxy_socket: &self.proxy,
                    executable: Path::new(env!("CARGO_BIN_EXE_tog")),
                    argv,
                    cwd: &snapshot.lock_root().real,
                    env: &env,
                    read_roots: std::slice::from_ref(&self.tools),
                    stdout: Stdout::Capture,
                    socket_scan: scan,
                },
            )
        }

        fn stdout_of(&self, args: &[&str]) -> String {
            let snapshot = self.snapshot();
            let outcome = self
                .run(&snapshot, &self.probe_argv(args), SocketScan::Full)
                .unwrap();
            assert_eq!(outcome.status, ToolStatus::Code(0), "{args:?}");
            String::from_utf8(outcome.stdout).unwrap()
        }
    }

    #[test]
    fn linux_door_reaches_only_the_proxy() {
        let Some(door) = door("linux_door_reaches_only_the_proxy") else {
            return;
        };
        let snapshot = door.snapshot();
        let outcome = door
            .run(
                &snapshot,
                &door.shell_argv(
                    "\"$1\" tcp 127.0.0.1 8119; \"$1\" tcp 1.1.1.1 443; \"$1\" tcp 10.0.0.1 80",
                ),
                SocketScan::Full,
            )
            .unwrap();
        let stdout = String::from_utf8(outcome.stdout).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines[0], format!("tcp ok {PROXY_REPLY}"), "{stdout}");
        let unreachable = format!("tcp connect errno={}", libc::ENETUNREACH);
        assert_eq!(lines[1], unreachable, "{stdout}");
        assert_eq!(lines[2], unreachable, "{stdout}");
        assert_eq!(door.connections.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn linux_door_has_no_dns() {
        let Some(door) = door("linux_door_has_no_dns") else {
            return;
        };
        let stdout = door.stdout_of(&["dns", "example.com"]);
        assert!(stdout.starts_with("dns fail"), "{stdout}");
        let stdout = door.stdout_of(&["read", "/etc/resolv.conf"]);
        assert_eq!(stdout.trim(), format!("read errno={}", libc::ENOENT));
    }

    #[test]
    fn linux_door_does_not_mount_the_real_project() {
        let Some(door) = door("linux_door_does_not_mount_the_real_project") else {
            return;
        };
        let snapshot = door.snapshot();
        std::fs::write(door.project.join("after.txt"), b"only on the host\n").unwrap();
        let outcome = door
            .run(
                &snapshot,
                &door.shell_argv("echo tool > written.txt; \"$1\" read after.txt"),
                SocketScan::Full,
            )
            .unwrap();
        let stdout = String::from_utf8(outcome.stdout).unwrap();
        assert_eq!(stdout.trim(), format!("read errno={}", libc::ENOENT));
        assert!(!door.project.join("written.txt").exists());
        assert!(snapshot.lock_root().staged.join("written.txt").exists());
    }

    /// The probe double-forks a setsid child that keeps rewriting a file
    /// and exits at once. By the time the door returns, the child is dead:
    /// the relay killed it, and the file stops changing.
    #[test]
    fn linux_door_descendants_die_with_the_relay() {
        let Some(door) = door("linux_door_descendants_die_with_the_relay") else {
            return;
        };
        let snapshot = door.snapshot();
        let target = snapshot.lock_root().real.join("package-lock.json");
        let outcome = door
            .run(
                &snapshot,
                &door.shell_argv(&format!(
                    "\"$1\" daemon {} 30; /usr/bin/sleep 0.3",
                    target.display()
                )),
                SocketScan::Full,
            )
            .unwrap();
        assert_eq!(outcome.status, ToolStatus::Code(0));
        assert!(outcome.killed >= 1, "nothing was left to kill: {outcome:?}");
        let staged = snapshot.lock_root().staged.join("package-lock.json");
        let first = std::fs::read(&staged).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            std::fs::read(&staged).unwrap(),
            first,
            "a descendant kept writing"
        );
    }

    #[test]
    fn linux_tree_is_killed_before_validation() {
        let Some(door) = door("linux_tree_is_killed_before_validation") else {
            return;
        };
        let snapshot = door.snapshot();
        let target = snapshot.lock_root().real.join("package.json");
        door.run(
            &snapshot,
            &door.shell_argv(&format!("\"$1\" daemon {} 30", target.display())),
            SocketScan::Full,
        )
        .unwrap();
        let before = snapshot.diff().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            snapshot.diff().unwrap(),
            before,
            "the stage changed after the door"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn linux_door_cannot_connect_to_a_socket_in_a_read_root() {
        let Some(door) = door("linux_door_cannot_connect_to_a_socket_in_a_read_root") else {
            return;
        };
        let socket = door.tools.join("agent.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let snapshot = door.snapshot();
        let argv = door.probe_argv(&["unix", socket.to_str().unwrap()]);
        let refused = door.run(&snapshot, &argv, SocketScan::Full).unwrap_err();
        assert!(refused.to_string().contains("agent.sock"), "{refused}");
        // Unscanned, the seccomp filter alone keeps it unreachable.
        let outcome = door
            .run(&snapshot, &argv, SocketScan::SkippedForTest)
            .unwrap();
        let stdout = String::from_utf8(outcome.stdout).unwrap();
        assert_eq!(
            stdout.trim(),
            format!("unix socket errno={}", libc::EAFNOSUPPORT)
        );
    }

    #[test]
    fn linux_door_cannot_connect_to_a_socket_created_after_preflight() {
        let Some(door) = door("linux_door_cannot_connect_to_a_socket_created_after_preflight")
        else {
            return;
        };
        let socket = door.tools.join("late.sock");
        let snapshot = door.snapshot();
        // The socket appears only once the tool is running, so the scan
        // before it passed.
        let started = snapshot.lock_root().staged.join("started");
        let host_side = socket.clone();
        let creator = std::thread::spawn(move || {
            while !started.exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            let listener = UnixListener::bind(&host_side).unwrap();
            std::thread::sleep(Duration::from_secs(3));
            drop(listener);
        });
        let outcome = door
            .run(
                &snapshot,
                &door.shell_argv(&format!(
                    ": > started; \"$1\" wait-unix {}",
                    socket.display()
                )),
                SocketScan::Full,
            )
            .unwrap();
        creator.join().unwrap();
        let stdout = String::from_utf8(outcome.stdout).unwrap();
        assert_eq!(
            stdout.trim(),
            format!("unix socket errno={}", libc::EAFNOSUPPORT)
        );
    }

    /// The socket filter is an allow-list: AF_VSOCK, which reaches the
    /// host across a network namespace, and every family but inet, inet6
    /// and route netlink are refused.
    #[test]
    fn linux_door_refuses_vsock_and_every_family_but_inet() {
        let Some(door) = door("linux_door_refuses_vsock_and_every_family_but_inet") else {
            return;
        };
        let refused = format!("errno={}", libc::EAFNOSUPPORT);
        assert_eq!(
            door.stdout_of(&["vsock", "1", "9999"]).trim(),
            format!("vsock socket {refused}")
        );
        for family in ["3", "4", "5", "9", "17", "38", "44", "45"] {
            assert_eq!(
                door.stdout_of(&["family", family]).trim(),
                format!("family {refused}"),
                "family {family}"
            );
        }
        assert_eq!(door.stdout_of(&["family", "2"]).trim(), "family ok");
        assert_eq!(door.stdout_of(&["family", "10"]).trim(), "family ok");
    }

    #[test]
    fn linux_door_tool_cannot_use_keyrings() {
        let Some(door) = door("linux_door_tool_cannot_use_keyrings") else {
            return;
        };
        let eperm = libc::EPERM;
        assert_eq!(
            door.stdout_of(&["keyring"]).trim(),
            format!("keyring session={eperm} user={eperm} add={eperm} request={eperm}")
        );
    }

    /// The sandbox root is read-only once the binds are in place: the tool
    /// cannot move /run/tog aside and plant another socket, or create
    /// /etc/ld.so.preload, and it still reaches the proxy. The snapshot,
    /// scratch and /tmp stay writable.
    #[test]
    fn linux_door_root_is_read_only_and_the_proxy_cannot_be_redirected() {
        let Some(door) = door("linux_door_root_is_read_only_and_the_proxy_cannot_be_redirected")
        else {
            return;
        };
        let snapshot = door.snapshot();
        let script = "mv /run/tog /run/moved 2>/dev/null && echo moved || echo no-move\n\
             ln -s /tmp/other.sock /run/tog/p2 2>/dev/null && echo linked || echo no-link\n\
             echo x > /etc/ld.so.preload 2>/dev/null && echo preload || echo no-preload\n\
             mkdir /planted 2>/dev/null && echo mkdir || echo no-mkdir\n\
             echo x > /tmp/scratch && echo tmp-ok\n\
             echo x > written.txt && echo project-ok\n\
             \"$1\" tcp 127.0.0.1 8119";
        let outcome = door
            .run(&snapshot, &door.shell_argv(script), SocketScan::Full)
            .unwrap();
        let stdout = String::from_utf8(outcome.stdout).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            lines,
            [
                "no-move",
                "no-link",
                "no-preload",
                "no-mkdir",
                "tmp-ok",
                "project-ok",
                &format!("tcp ok {PROXY_REPLY}"),
            ],
            "{stdout}"
        );
    }

    #[test]
    fn linux_door_socketpair_still_works() {
        let Some(door) = door("linux_door_socketpair_still_works") else {
            return;
        };
        assert_eq!(door.stdout_of(&["socketpair"]).trim(), "socketpair ok");
    }

    #[test]
    fn linux_door_exec_log_records_every_exec() {
        let Some(door) = door("linux_door_exec_log_records_every_exec") else {
            return;
        };
        let snapshot = door.snapshot();
        let outcome = door
            .run(
                &snapshot,
                &door.shell_argv("/usr/bin/true && /usr/bin/env true && \"$1\" socketpair"),
                SocketScan::Full,
            )
            .unwrap();
        let paths: Vec<String> = outcome
            .execs
            .iter()
            .filter_map(|exec| exec.path.clone())
            .collect();
        assert_eq!(
            paths.first().map(String::as_str),
            Some("/bin/sh"),
            "{paths:?}"
        );
        for expected in [
            "/usr/bin/true",
            "/usr/bin/env",
            door.probe.to_str().unwrap(),
        ] {
            assert!(
                paths.iter().any(|path| path == expected),
                "{expected}: {paths:?}"
            );
        }
        // env execs `true` through PATH.
        assert!(
            paths.iter().filter(|path| path.ends_with("/true")).count() >= 2,
            "{paths:?}"
        );
    }

    #[test]
    fn linux_door_filter_kills_a_foreign_syscall_arch() {
        let Some(door) = door("linux_door_filter_kills_a_foreign_syscall_arch") else {
            return;
        };
        if !cfg!(target_arch = "x86_64") {
            eprintln!("skip linux_door_filter_kills_a_foreign_syscall_arch: int $0x80 is x86 only");
            return;
        }
        let snapshot = door.snapshot();
        let outcome = door
            .run(&snapshot, &door.probe_argv(&["int80"]), SocketScan::Full)
            .unwrap();
        assert_eq!(
            outcome.status,
            ToolStatus::Signal(libc::SIGSYS),
            "{outcome:?}"
        );
        assert!(!String::from_utf8_lossy(&outcome.stdout).contains("survived"));
    }

    #[test]
    fn linux_door_denies_io_uring_setup() {
        let Some(door) = door("linux_door_denies_io_uring_setup") else {
            return;
        };
        assert_eq!(
            door.stdout_of(&["io_uring"]).trim(),
            format!("io_uring errno={}", libc::EPERM)
        );
    }

    #[test]
    fn linux_door_tool_cannot_ptrace_or_read_the_relay() {
        let Some(door) = door("linux_door_tool_cannot_ptrace_or_read_the_relay") else {
            return;
        };
        let stdout = door.stdout_of(&["ptrace-parent"]);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            lines[0],
            format!("ptrace rc=-1 errno={}", libc::EPERM),
            "{stdout}"
        );
        assert!(lines[1].starts_with("mem fd=-1 "), "{stdout}");
        assert_eq!(
            lines[2],
            format!("vm rc=-1 errno={}", libc::EPERM),
            "{stdout}"
        );
    }

    /// The namespace's pid 1 is the non-dumpable relay: the tool cannot
    /// open its memory for writing (a bwrap init there was unfiltered and
    /// dumpable), and a `SIGSTOP` from inside does not stop it.
    #[test]
    fn linux_door_tool_cannot_write_or_stop_the_namespace_init() {
        let Some(door) = door("linux_door_tool_cannot_write_or_stop_the_namespace_init") else {
            return;
        };
        let stdout = door.stdout_of(&["pid1"]);
        let lines: Vec<&str> = stdout.lines().collect();
        assert!(lines[0].starts_with("pid1 mem fd=-1 "), "{stdout}");
        assert_ne!(lines[1], "pid1 state=T", "{stdout}");
        assert!(lines[1].starts_with("pid1 state="), "{stdout}");
    }

    /// A setsid, double-forked child rewrites a declared output in a loop
    /// after the tool exits. What is published equals the immutable copy,
    /// and it does not change afterwards.
    #[test]
    fn descendant_writes_during_publication_do_not_reach_the_project() {
        let Some(door) = door("descendant_writes_during_publication_do_not_reach_the_project")
        else {
            return;
        };
        let activity = door.store.activity(ActivityMode::Shared).unwrap();
        let declared = vec![
            PathBuf::from("package.json"),
            PathBuf::from("package-lock.json"),
        ];
        let transaction = Transaction::hold(
            &door.store,
            &activity,
            ProjectRoot::open(&door.project).unwrap(),
            &HoldSpec {
                ecosystem: "npm",
                outputs: &declared,
                receipt: true,
            },
        )
        .unwrap();
        let snapshot = door.snapshot();
        let lock = snapshot.lock_root().real.join("package-lock.json");
        let outcome = door
            .run(
                &snapshot,
                &door.shell_argv(&format!(
                    "echo '{{\"lockfileVersion\":3}}' > package-lock.json; \"$1\" daemon {} 10",
                    lock.display()
                )),
                SocketScan::Full,
            )
            .unwrap();
        assert_eq!(outcome.status, ToolStatus::Code(0));
        let changes = snapshot.diff().unwrap();
        let classified = snapshot.classify(&changes, &declared, &[]).unwrap();
        let outputs =
            Outputs::copy(&door.store, &activity, &snapshot, &classified.outputs, &[]).unwrap();
        let copy = outputs
            .contents(outputs.get(Path::new("package-lock.json")).unwrap())
            .unwrap();
        transaction.publish(&outputs, Some(b"receipt\n")).unwrap();
        let published = std::fs::read(door.project.join("package-lock.json")).unwrap();
        assert_eq!(published, copy);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            std::fs::read(door.project.join("package-lock.json")).unwrap(),
            copy
        );
        assert_eq!(
            std::fs::read(door.project.join(".tog/resolution/npm.json")).unwrap(),
            b"receipt\n"
        );
        drop(door.temp);
    }
}

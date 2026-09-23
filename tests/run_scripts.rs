//! End-to-end package.json script runner test. Heavy: realizes the pinned
//! Node toolchain, so it is ignored and uses a throwaway store.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-run-scripts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tog(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(project)
        .env("TOG_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

#[test]
#[ignore]
fn package_json_script_runs_inside_projected_env() {
    let temp = TempDir::new();
    let project = &temp.0;
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"fx","version":"1.0.0","scripts":{"pretest":"echo $npm_lifecycle_event > out.txt","test":"echo $npm_lifecycle_event >> out.txt && echo $INIT_CWD >> out.txt && echo $npm_package_name >> out.txt && node -e \"process.exit(process.argv[1]==='fail'?3:0)\"","posttest":"echo $npm_lifecycle_event >> out.txt"}}"#,
    )
    .unwrap();
    std::fs::write(
        project.join("package-lock.json"),
        r#"{"name":"fx","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fx","version":"1.0.0"}}}"#,
    )
    .unwrap();

    let store = temp.0.join("store");
    let binary = Path::new(env!("CARGO_BIN_EXE_tog"));
    let synced = tog(&binary, project, &store, &["sync"]);
    assert!(
        synced.status.success(),
        "sync failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&synced.stdout),
        String::from_utf8_lossy(&synced.stderr)
    );

    let subdir = project.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    let init_cwd = subdir.canonicalize().unwrap();
    let first = tog(&binary, &subdir, &store, &["run", "test"]);
    assert!(
        first.status.success(),
        "run test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(project.join("out.txt")).unwrap(),
        format!("pretest\ntest\n{}\nfx\nposttest\n", init_cwd.display())
    );

    let second = tog(&binary, &subdir, &store, &["run", "test", "fail"]);
    assert_eq!(second.status.code(), Some(3));
}

//! End-to-end package.json script runner test. Heavy: realizes the pinned
//! Node toolchain, so it is ignored and uses a throwaway store.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

mod common;

use common::{assert_frozen_never_writes_the_lock, assert_ok, tog, TempDir};

#[test]
#[ignore]
fn package_json_script_runs_inside_projected_env() {
    let temp = TempDir::new("run-scripts");
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

    let home = temp.path();
    assert_ok(tog(project, home, &["sync"]), "sync");

    let subdir = project.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    let init_cwd = subdir.canonicalize().unwrap();
    assert_ok(tog(&subdir, home, &["run", "test"]), "run test");
    assert_eq!(
        std::fs::read_to_string(project.join("out.txt")).unwrap(),
        format!("pretest\ntest\n{}\nfx\nposttest\n", init_cwd.display())
    );

    let second = tog(&subdir, home, &["run", "test", "fail"]);
    assert_eq!(second.status.code(), Some(3));

    // Without its lock the project is refused under --frozen and left
    // alone; a plan regenerates the lock with the store npm.
    assert_frozen_never_writes_the_lock(project, home, "package-lock.json");
}

//! Kernel smoke test: bypasses the planner entirely — hand-built Plan with
//! pinned artifacts — and proves store + fetch + cpython + wheel + projection
//! work end to end. Heavy (downloads CPython on cold store), so #[ignore]d;
//! run: cargo test --test kernel_smoke -- --ignored

use blanket::{platform::Platform, project, store::Store, types::*};
use std::process::Command;

#[test]
#[ignore]
fn realize_env_and_run_python() {
    let store = Store::open().expect("store");
    let plan = Plan {
        ecosystem: "python".into(),
        python_version: "3.12.14".into(),
        packages: vec![LockedPackage {
            name: "six".into(),
            version: "1.17.0".into(),
            filename: "six-1.17.0-py2.py3-none-any.whl".into(),
            url: "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl".into(),
            sha256: "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274".into(),
            kind: ArtifactKind::Wheel,
        git: None,
        }],
    };

    let env = project::realize_env(&store, Platform::host().unwrap(), &plan).expect("realize");
    assert!(env.join("bin/python").exists());
    assert!(env.join("pyvenv.cfg").is_file());

    let out = Command::new(env.join("bin/python"))
        .args([
            "-c",
            "import six, sys; print(six.__version__, sys.version.split()[0])",
        ])
        .output()
        .expect("run python");
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "1.17.0 3.12.14");

    // Idempotent: same plan, same object.
    let env2 =
        project::realize_env(&store, Platform::host().unwrap(), &plan).expect("realize again");
    assert_eq!(env, env2);
}

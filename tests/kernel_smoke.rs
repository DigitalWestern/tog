//! Kernel smoke test: bypasses the planner entirely — hand-built Plan with
//! pinned artifacts — and proves store + fetch + cpython + wheel + projection
//! work end to end. Heavy (downloads CPython on cold store), so #[ignore]d;
//! run: cargo test --test kernel_smoke -- --ignored

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

#[cfg(debug_assertions)]
use std::collections::BTreeMap;
#[cfg(debug_assertions)]
use std::fs;
#[cfg(debug_assertions)]
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;
use tog::kernel::platform::Platform;
#[cfg(debug_assertions)]
use tog::kernel::store::ObjectDeps;
use tog::kernel::store::Store;
use tog::kernel::types::*;

mod common;

#[cfg(debug_assertions)]
use common::TempDir;

#[test]
#[ignore]
fn realize_env_and_run_python() {
    let store = Store::open().expect("store");
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
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

    let env =
        tog::tailors::python::env::realize_env(&store, activity, Platform::host().unwrap(), &plan)
            .expect("realize");
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
        tog::tailors::python::env::realize_env(&store, activity, Platform::host().unwrap(), &plan)
            .expect("realize again");
    assert_eq!(env, env2);
}

#[test]
#[cfg(debug_assertions)]
fn tailor_grammar_drift_panics_before_publishing() {
    // This regression commits through the kernel directly, so it keeps an
    // explicit installation even though public tailor realization entry
    // points now self-install their rows.
    tog::tailors::install_kinds();
    let temp = TempDir::new("kernel-smoke");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        fs::create_dir_all(temp.0.join(sub)).unwrap();
    }
    let store = Store {
        root: temp.0.clone(),
    };
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let identity = Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: "3.12.14".into(),
        inputs: BTreeMap::from([("platform".into(), "x86_64-unknown-linux-gnu".into())]),
    };
    let id = identity.object_id();
    let valid_identity = Identity {
        kind: "cpython".into(),
        name: "cpython-control".into(),
        version: "3.12.14".into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".into(), "a".repeat(64)),
            ("platform".into(), "x86_64-unknown-linux-gnu".into()),
        ]),
    };
    let valid_staged = store.stage_with_activity(activity).unwrap();
    fs::write(valid_staged.join("payload"), b"valid").unwrap();
    store
        .commit_with_activity_and_deps(
            activity,
            &valid_identity,
            &valid_staged,
            &[],
            &ObjectDeps::new(),
        )
        .expect("valid tailor identity is the control");
    let staged = store.stage_with_activity(activity).unwrap();
    fs::write(staged.join("payload"), b"malformed").unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        store
            .commit_with_activity_and_deps(activity, &identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
    }));
    let payload = result.expect_err("malformed tailor identity was published");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("object-kind grammar drift"), "{message}");
    assert!(
        !store.object_path(&id).exists(),
        "object directory was published"
    );
    assert!(
        !store.root.join("meta").join(format!("{id}.json")).exists(),
        "meta record was published"
    );
}

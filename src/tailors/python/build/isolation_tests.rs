//! Real PyPI source-package build coverage. These tests use the unit-test
//! relay hook because dependency resolution runs through the confined door.
//! Build the CLI, then run with TMPDIR under HOME and TOG_SANDBOX_TESTS=required:
//! `cargo test --locked --lib build::isolation_tests -- --ignored --test-threads=2`.

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]
    use crate::kernel::platform::Platform;
    use crate::kernel::store::Store;
    use crate::kernel::types::{ArtifactKind, LockedPackage, Plan};
    use crate::tailors::python;
    use crate::tailors::python::build;
    use std::process::Command;

    fn package(
        name: &str,
        version: &str,
        filename: &str,
        url: &str,
        sha256: &str,
    ) -> LockedPackage {
        LockedPackage {
            name: name.into(),
            version: version.into(),
            filename: filename.into(),
            url: url.into(),
            sha256: sha256.into(),
            kind: ArtifactKind::Sdist,
            git: None,
        }
    }

    fn runtime_numpy() -> Plan {
        Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![LockedPackage {
                name: "numpy".into(),
                version: "1.26.4".into(),
                filename: "numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64.whl".into(),
                url: String::new(),
                sha256: "a".repeat(64),
                kind: ArtifactKind::Wheel,
                git: None,
            }],
        }
    }

    /// Keep the actual CLI relay in a test-only thread-local slot. Production
    /// always binds its own running executable and accepts no override.
    struct RelayGuard;

    impl Drop for RelayGuard {
        fn drop(&mut self) {
            crate::kernel::resolve::door::RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn test_store(
        label: &str,
    ) -> Option<(
        crate::kernel::testutil::TempDir,
        Store,
        crate::kernel::activity::StoreActivity,
        RelayGuard,
    )> {
        let relay = crate::kernel::resolve::testing::relay(label)?;
        crate::kernel::resolve::door::RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        let (temp, store, activity) = crate::kernel::resolve::testing::scratch_store(label);
        Some((temp, store, activity, RelayGuard))
    }

    /// The store object a built wheel was published in, by its meta record.
    fn wheel_object_meta(store: &Store, wheel: &std::path::Path) -> serde_json::Value {
        let id = wheel
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();
        serde_json::from_slice(
            &std::fs::read(store.root.join("meta").join(format!("{id}.json"))).unwrap(),
        )
        .unwrap()
    }

    /// The dist-info directory names in the site-packages of the build
    /// environment a wheel's record names: what the build actually saw.
    fn build_env_dists(store: &Store, wheel: &std::path::Path) -> Vec<String> {
        let meta = wheel_object_meta(store, wheel);
        let inputs = &meta["identity"]["inputs"];
        assert_eq!(inputs["schema"], "sdist-build/4", "{inputs}");
        let build_env = inputs["build_env"]
            .as_str()
            .unwrap_or_else(|| panic!("no build_env input: {inputs}"));
        let site = store
            .object_path(build_env)
            .join("lib/python3.12/site-packages");
        let mut dists: Vec<String> = std::fs::read_dir(&site)
            .unwrap_or_else(|error| panic!("{}: {error}", site.display()))
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".dist-info"))
            .collect();
        dists.sort();
        dists
    }

    fn python_import(wheel: &std::path::Path, code: &str) {
        let output = Command::new("python3")
            .args([
                "-c",
                &format!("import sys; sys.path.insert(0, sys.argv[1]); {code}"),
                wheel.to_str().unwrap(),
            ])
            .output()
            .expect("python3");
        assert!(
            output.status.success(),
            "python import failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn pure_python_flit_sdist_uses_isolated_build_env() {
        let _env_guard = crate::kernel::policy::test_env_lock();
        let _attribution_guard = crate::kernel::policy::attribution_test_lock();
        let Some((_temp, store, activity, _relay)) =
            test_store("pure_python_flit_sdist_uses_isolated_build_env")
        else {
            return;
        };
        let activity = &activity;
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let pkg = package(
            "tomli-w",
            "1.2.0",
            "tomli_w-1.2.0.tar.gz",
            "https://files.pythonhosted.org/packages/19/75/241269d1da26b624c0d5e110e8149093c759b7a286138f4efd61a60e75fe/tomli_w-1.2.0.tar.gz",
            "2dd14fac5a47c27be9cd4c976af5a12d87fb1f0b4512f81d69cce3b35ae25021",
        );
        let wheel = build::build_sdist_wheel(
            &mut crate::kernel::resolve::ResolutionDoor::open(
                &store,
                activity,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
                &mut attribution,
            )
            .unwrap(),
            &pkg,
            &python::shipped_selection("3.12.14").unwrap(),
        )
        .expect("tomli-w sdist build");
        assert!(wheel.is_file());
        python_import(
            &wheel,
            "import tomli_w; assert tomli_w.dumps({'ok': True}) == 'ok = true\\n'",
        );
        // The build ran in an isolated environment holding the sdist's own
        // build backend (flit_core), not the fast setuptools path: the wheel's
        // record names that environment, and the environment has flit_core.
        let dists = build_env_dists(&store, &wheel);
        assert!(
            dists.iter().any(|name| name.starts_with("flit_core-")),
            "build environment without flit_core: {dists:?}"
        );
        assert!(
            !dists.iter().any(|name| name.starts_with("setuptools-")),
            "build environment carries setuptools: {dists:?}"
        );
        attribution.discard();
    }

    #[test]
    #[ignore]
    fn insightface_sdist_builds_with_runtime_numpy_constraint() {
        let _env_guard = crate::kernel::policy::test_env_lock();
        let _attribution_guard = crate::kernel::policy::attribution_test_lock();
        let Some((_temp, store, activity, _relay)) =
            test_store("insightface_sdist_builds_with_runtime_numpy_constraint")
        else {
            return;
        };
        let activity = &activity;
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let pkg = package(
            "insightface",
            "0.7.3",
            "insightface-0.7.3.tar.gz",
            "https://files.pythonhosted.org/packages/0b/8d/0f4af90999ca96cf8cb846eb5ae27c5ef5b390f9c090dd19e4fa76364c13/insightface-0.7.3.tar.gz",
            "f191f719612ebb37018f41936814500544cd0f86e6fcd676c023f354c668ddf7",
        );
        let wheel = build::build_sdist_wheel_with_runtime_plan(
            &mut crate::kernel::resolve::ResolutionDoor::open(
                &store,
                activity,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
                &mut attribution,
            )
            .unwrap(),
            &pkg,
            &python::shipped_selection("3.12.14").unwrap(),
            &runtime_numpy(),
        )
        .expect("insightface sdist build");
        assert!(wheel.is_file(), "built insightface wheel disappeared");
        // The runtime plan's numpy pin constrained the build environment: it
        // holds exactly numpy 1.26.4, not the newest numpy the sdist's own
        // `numpy` build requirement would resolve to.
        let dists = build_env_dists(&store, &wheel);
        assert!(
            dists.contains(&"numpy-1.26.4.dist-info".to_string()),
            "build environment did not see the runtime numpy constraint: {dists:?}"
        );
        // insightface/__init__.py imports onnxruntime, which this test does not
        // realize. Import an onnxruntime-free leaf from the built wheel instead;
        // the wheel's package contents are exercised without downloading models.
        python_import(
            &wheel,
            "import sys, types, tempfile, zipfile; d=tempfile.TemporaryDirectory(); zipfile.ZipFile(sys.argv[1]).extractall(d.name); p=types.ModuleType('insightface'); p.__path__=[d.name+'/insightface']; sys.modules['insightface']=p; u=types.ModuleType('insightface.utils'); u.__path__=[d.name+'/insightface/utils']; sys.modules['insightface.utils']=u; import insightface.utils.constant as c; assert c.DEFAULT_MP_NAME == 'buffalo_l'",
        );
        attribution.discard();
    }

    /// A Rust sdist (fastuuid, a pyo3 extension) builds through the vendored
    /// Cargo path: its wheel record names the Rust toolchain and the vendor
    /// object the build ran against. tokenizers 0.13.3 used to be the subject;
    /// the pinned Rust rejects its legacy invalid_reference_casting code, so
    /// the smaller real sdist that exercises the same path is the test.
    #[test]
    #[ignore]
    fn fastuuid_rust_sdist_builds_offline_after_vendoring() {
        let _env_guard = crate::kernel::policy::test_env_lock();
        let _attribution_guard = crate::kernel::policy::attribution_test_lock();
        let Some((_temp, store, activity, _relay)) =
            test_store("fastuuid_rust_sdist_builds_offline_after_vendoring")
        else {
            return;
        };
        let activity = &activity;
        let mut attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let fastuuid = package(
            "fastuuid",
            "0.14.0",
            "fastuuid-0.14.0.tar.gz",
            "https://files.pythonhosted.org/packages/c3/7d/d9daedf0f2ebcacd20d599928f8913e9d2aea1d56d2d355a93bfa2b611d7/fastuuid-0.14.0.tar.gz",
            "178947fc2f995b38497a74172adee64fdeb8b7ec18f2a5934d037641ba265d26",
        );
        let wheel = build::build_sdist_wheel(
            &mut crate::kernel::resolve::ResolutionDoor::open(
                &store,
                activity,
                Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
                &mut attribution,
            )
            .unwrap(),
            &fastuuid,
            &python::shipped_selection("3.12.14").unwrap(),
        )
        .expect("fastuuid Rust sdist build");
        assert!(wheel.is_file());
        // pyo3 0.18 cannot name CPython 3.12 directly; the implementation sets
        // PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 for this Rust build path.
        let name = wheel.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("fastuuid-0.14.0-"), "{name}");
        let inputs = wheel_object_meta(&store, &wheel)["identity"]["inputs"].clone();
        assert_eq!(inputs["schema"], "sdist-build/5", "{inputs}");
        assert_eq!(
            inputs["rust_build_config"], "rust-lint-cap-warn/1",
            "{inputs}"
        );
        for input in ["rust", "vendor", "build_env"] {
            assert!(
                inputs[input].as_str().is_some_and(|id| !id.is_empty()),
                "no {input} input on the Rust wheel's record: {inputs}"
            );
        }
        attribution.discard();
    }
}

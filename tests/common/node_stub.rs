//! Offline stand-ins for the toolchains a Node environment realizes: a Node
//! tree with exactly the layout `realize_runtime` checks, and the CPython
//! node-gyp would use. Neither runs anything (`bin/node` exits 1), so a
//! suite built on them runs install scripts as plain `sh`, never `node -e`.

use std::path::{Path, PathBuf};

use tog::kernel::fetch::Digest;
use tog::kernel::platform::Platform;
use tog::kernel::store::{ObjectDeps, Store};
use tog::kernel::types::Identity;
use tog::tailors::node;

/// The files `realize_runtime` requires of a Node object, and their stub
/// contents.
const NODE_LAYOUT: [(&str, &str); 4] = [
    ("bin/node", "#!/bin/sh\nexit 1\n"),
    ("include/node/node.h", ""),
    ("lib/node_modules/npm/bin/npm-cli.js", ""),
    (
        "lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js",
        "",
    ),
];

fn write_node_layout(root: &Path) {
    for (relative, contents) in NODE_LAYOUT {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}

/// Tar `dir/<top>` into `dir/<top>.tgz`.
pub fn tar(dir: &Path, top: &str) -> PathBuf {
    let tarball = dir.join(format!("{top}.tgz"));
    let status = super::tar_create()
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(dir)
        .arg(top)
        .status()
        .unwrap();
    assert!(status.success());
    tarball
}

/// A Node release stub and a selection whose host row names it by digest.
/// The row keeps its shipped nodejs.org URL, which the source policy admits,
/// and the stub is seeded into the verified cache under that digest, so
/// realizing it is a cache hit and never reaches the network.
pub fn stub_node_selection(
    dir: &Path,
    store: &Store,
    activity: &tog::kernel::activity::StoreActivity,
    platform: Platform,
) -> tog::kernel::toolchain::Selected {
    write_node_layout(&dir.join("node-stub"));
    let tarball = tar(dir, "node-stub");
    let (sha256, _) = tog::kernel::fetch::cache_insert(store, activity, &tarball).unwrap();
    let mut selected = node::shipped_selection().unwrap();
    let row = selected
        .bundle
        .artifacts
        .iter_mut()
        .find(|row| row.platform == platform && row.component == "node")
        .expect("the shipped Node release has a host row");
    row.digest = Digest::sha256(&sha256).unwrap();
    selected
}

/// Publish the Node stub under the id of the shipped Node itself, for a
/// case that drives the binary and so cannot hand it a selection: the
/// binary's `realize_runtime` finds the object already in the store and
/// never downloads the real release.
pub fn seed_shipped_node(store: &Store, platform: Platform) {
    let selected = node::shipped_selection().unwrap();
    let spec = selected.artifact(platform, "node").unwrap();
    let identity = Identity {
        kind: "nodejs".into(),
        name: "nodejs".into(),
        version: spec.version.clone(),
        inputs: std::collections::BTreeMap::from([
            ("artifact_sha256".to_string(), spec.digest.hex().to_string()),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    };
    assert_eq!(
        identity.object_id(),
        node::runtime_object_id(platform, &selected).unwrap(),
        "the stub is published under the id the producer looks up"
    );
    publish(store, &identity, write_node_layout);
}

/// Publish a stub of the CPython node-gyp would use under the exact id
/// `ensure_gyp_python` looks up, so lifecycle setup finds it cached instead
/// of downloading the real interpreter. No script that uses this calls it.
pub fn seed_gyp_python(store: &Store, platform: Platform) {
    tog::tailors::install_kinds();
    let selected = tog::tailors::python::shipped_selection("3.12").unwrap();
    let spec = selected.artifact(platform, "cpython").unwrap();
    let identity = Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: spec.version.clone(),
        inputs: std::collections::BTreeMap::from([
            ("artifact_sha256".to_string(), spec.digest.hex().to_string()),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    };
    assert_eq!(
        identity.object_id(),
        tog::tailors::python::runtime_object_id(platform, &selected).unwrap(),
        "the stub is published under the id the producer looks up"
    );
    publish(store, &identity, |staged| {
        std::fs::create_dir_all(staged.join("bin")).unwrap();
    });
}

fn publish(store: &Store, identity: &Identity, fill: impl FnOnce(&Path)) {
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    tog::tailors::install_kinds();
    let staged = store.stage_with_activity(activity).unwrap();
    fill(&staged);
    store
        .commit_with_activity_and_deps(activity, identity, &staged, &[], &ObjectDeps::new())
        .unwrap();
}

/// Whether the build sandbox can start here. `TOG_SANDBOX_TESTS=required`
/// (any non-empty value) turns a missing sandbox from a skip into a failure,
/// as in tests/sandbox_deny.rs.
pub fn sandbox_or_skip(test_name: &str, platform: Platform) -> bool {
    match tog::kernel::sandbox::probe(platform) {
        Ok(_) => true,
        Err(error) => {
            if matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty()) {
                panic!("required sandbox test {test_name} unavailable: {error}");
            }
            eprintln!("skip {test_name}: sandbox unavailable: {error}");
            false
        }
    }
}

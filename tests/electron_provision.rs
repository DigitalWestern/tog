//! Electron provisioning. Heavy: downloads the real release
//! zip (~100 MB), so it is ignored by default.

use std::path::{Path, PathBuf};
use tog::kernel::platform::Platform;
use tog::kernel::store::Store;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = tog::kernel::store::remove_tree(&self.0);
    }
}

fn store_at(root: &Path) -> Store {
    let store_root = root.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        std::fs::create_dir_all(store_root.join(sub)).unwrap();
    }
    Store {
        root: store_root.canonicalize().unwrap(),
    }
}

#[test]
#[ignore]
fn electron_is_provisioned_where_its_installer_looks() {
    let platform = Platform::host().expect("host platform");
    let root = Temp(std::env::temp_dir().join(format!(
        "tog-electron-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir_all(&root.0).unwrap();
    let store = store_at(&root.0);
    let scratch = root.0.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();

    // A real, published release.
    let version = "39.0.0";
    let provisioning = tog::kernel::provider::artifacts::provision(
        &store, platform, "electron", version, &scratch,
    )
    .expect("provision")
    .expect("electron is provisioned");

    let cache_root = provisioning
        .envs
        .iter()
        .find(|(key, _)| key == "electron_config_cache")
        .map(|(_, value)| PathBuf::from(value))
        .expect("the installer's cache variable is set");
    let release_url = format!("https://github.com/electron/electron/releases/download/v{version}");
    let dir = cache_root.join(tog::kernel::provider::artifacts::electron_cache_directory(
        &release_url,
    ));
    let (os, arch) = match platform {
        Platform::Aarch64AppleDarwin => ("darwin", "arm64"),
        Platform::X86_64UnknownLinuxGnu => ("linux", "x64"),
    };
    let zip = dir.join(format!("electron-v{version}-{os}-{arch}.zip"));
    let sums = dir.join("SHASUMS256.txt");
    assert!(
        zip.is_file(),
        "the zip must be in the cache at {}",
        zip.display()
    );
    assert!(
        sums.is_file(),
        "@electron/get verifies against SHASUMS256.txt from the same cache"
    );
    assert!(
        std::fs::metadata(&zip).unwrap().len() > 10 << 20,
        "the zip should be a real release artifact"
    );
    // The zip tog stored is the one upstream's manifest names.
    let listed = std::fs::read_to_string(&sums).unwrap();
    assert!(
        listed.contains(&format!("electron-v{version}-{os}-{arch}.zip")),
        "the checksum manifest names this artifact"
    );
    assert_eq!(provisioning.records.len(), 1, "the provenance is recorded");
}

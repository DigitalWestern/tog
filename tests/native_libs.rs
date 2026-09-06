//! Linux-first native-library coverage. Heavy and networked; run with:
//! `BLANKET_STORE=$HOME/scratch/tmp/nx12-store TMPDIR=$HOME/scratch/tmp
//! BLANKET_SANDBOX_TESTS=required cargo test --test native_libs -- --ignored

use blanket::{
    nativelibs::{compose_env, ensure_native_libs, size_bytes},
    platform::Platform,
    sandbox::{run_build_spec, BuildSpec},
    store::Store,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "blanket-native-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn required_sandbox_tests() -> bool {
    matches!(std::env::var_os("BLANKET_SANDBOX_TESTS"), Some(value) if !value.is_empty())
}

fn linux_ready() -> bool {
    match Platform::host() {
        Ok(Platform::X86_64UnknownLinuxGnu) => {}
        Ok(platform) => {
            if required_sandbox_tests() {
                panic!("required native library test cannot run on {}", platform.triple());
            }
            eprintln!("skip native library test: host is {}", platform.triple());
            return false;
        }
        Err(error) => {
            if required_sandbox_tests() {
                panic!("required native library test unavailable: {error}");
            }
            eprintln!("skip native library test: {error}");
            return false;
        }
    }
    true
}

fn assert_ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn shell_quote(path: &Path) -> String {
    let path = path.to_string_lossy().replace('\'', "'\\''");
    format!("'{path}'")
}

#[test]
#[ignore]
fn linux_native_libs_pkg_config_sdist_and_runtime() {
    if !linux_ready() {
        return;
    }
    let store_path = match std::env::var_os("BLANKET_STORE") {
        Some(path) => PathBuf::from(path),
        None if required_sandbox_tests() => {
            panic!("required native library test needs BLANKET_STORE");
        }
        None => {
            eprintln!("skip native library test: set BLANKET_STORE to a throwaway store");
            return;
        }
    };
    let store = Store::open().expect("store");
    let native = ensure_native_libs(&store, Platform::host().unwrap()).expect("native libset");
    let bytes = size_bytes(&native.path).expect("native libset size");
    println!(
        "native libset id={} size_mb={:.1}",
        native.id,
        bytes as f64 / (1024.0 * 1024.0)
    );

    let temp = TempDir::new();
    let pkg_scratch = temp.0.join("pkg-config-scratch");
    std::fs::create_dir_all(&pkg_scratch).unwrap();
    let version_file = pkg_scratch.join("pango-version");
    let env = compose_env(
        &native.path,
        &[("PATH".into(), "/usr/bin:/bin".into())],
    );
    let path = env
        .iter()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.clone())
        .unwrap();
    let command = format!(
        "{} --modversion pango > {}",
        shell_quote(&native.path.join("bin/pkg-config")),
        shell_quote(&version_file)
    );
    run_build_spec(&BuildSpec {
        argv: vec!["/bin/sh".into(), "-c".into(), command],
        cwd: pkg_scratch.clone(),
        env,
        read: vec![native.path.clone()],
        write: vec![pkg_scratch.clone()],
        scratch: pkg_scratch,
        path,
    })
    .expect("sandboxed pkg-config");
    let pango_version = std::fs::read_to_string(&version_file).unwrap();
    println!("sandbox pkg-config pango={}", pango_version.trim());
    assert_eq!(pango_version.trim(), "1.50.11");

    let project = temp.0.join("manimpango");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native-libs/requirements.txt"),
        project.join("requirements.txt"),
    )
    .unwrap();
    let blanket_bin = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));
    let sync = Command::new(&blanket_bin)
        .current_dir(&project)
        .env("BLANKET_STORE", &store_path)
        .arg("sync")
        .output()
        .unwrap();
    assert_ok(sync, "manimpango sync");
    let plan: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".blanket/plan.json")).unwrap(),
    )
    .unwrap();
    let manimpango = plan["plan"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == "manimpango")
        .expect("manimpango in plan");
    assert_eq!(manimpango["kind"], "Sdist");
    assert!(project.join(".blanket/closures/python.json").is_file());
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".blanket/closures/python.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(closure["body"]["native_libs"]["id"], native.id);

    let run = Command::new(&blanket_bin)
        .current_dir(&project)
        .env("BLANKET_STORE", &store_path)
        .args(["run", "python", "-c", "import manimpango; print('manimpango ok')"])
        .output()
        .unwrap();
    let output = assert_ok(run, "blanket run python import manimpango");
    assert!(output.contains("manimpango ok"), "unexpected run output: {output}");
    println!("blanket run python import manimpango: ok");
}

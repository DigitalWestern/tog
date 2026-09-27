//! Linux-first native-library coverage. Heavy and networked, and it opens
//! the store in-process, so it needs a throwaway one named up front:
//! `TOG_STORE=<throwaway-store> TMPDIR=$HOME/scratch/tmp
//! TOG_SANDBOX_TESTS=required cargo test --test native_libs -- --ignored`

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;

use tog::kernel::platform::Platform;
use tog::kernel::provider::nativelibs::{compose_env, ensure_native_libs, size_bytes};
use tog::kernel::sandbox::{run_build_spec, BuildSpec};
use tog::kernel::store::Store;

mod common;

use common::{assert_ok, fixture, tog_at, TempDir};

fn required_sandbox_tests() -> bool {
    matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty())
}

fn linux_ready() -> bool {
    match Platform::host() {
        Ok(Platform::X86_64UnknownLinuxGnu) => {}
        Ok(platform) => {
            if required_sandbox_tests() {
                panic!(
                    "required native library test cannot run on {}",
                    platform.triple()
                );
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
    let store_path = match std::env::var_os("TOG_STORE") {
        Some(path) => PathBuf::from(path),
        None if required_sandbox_tests() => {
            panic!("required native library test needs TOG_STORE");
        }
        None => {
            eprintln!("skip native library test: set TOG_STORE to a throwaway store");
            return;
        }
    };
    let store = Store::open().expect("store");
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    tog::tailors::install_kinds();
    let native =
        ensure_native_libs(&store, activity, Platform::host().unwrap()).expect("native libset");
    let bytes = size_bytes(&native.path).expect("native libset size");
    println!(
        "native libset id={} size_mb={:.1}",
        native.id,
        bytes as f64 / (1024.0 * 1024.0)
    );

    let temp = TempDir::new("native-e2e");
    let pkg_scratch = temp.0.join("pkg-config-scratch");
    std::fs::create_dir_all(&pkg_scratch).unwrap();
    let version_file = pkg_scratch.join("pango-version");
    let env = compose_env(&native.path, &[("PATH".into(), "/usr/bin:/bin".into())]);

    // Cargo must receive the native library search path and rpath through its
    // Rust-specific flag channels. This deliberately uses a Rust cdylib
    // rather than a C/Cython build: the latter only exercises LDFLAGS.
    let rust_probe = temp.0.join("rust-pango-probe");
    std::fs::create_dir_all(rust_probe.join("src")).unwrap();
    std::fs::write(
        rust_probe.join("Cargo.toml"),
        "[package]\nname = \"rust-pango-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\ncrate-type = [\"cdylib\"]\n",
    )
    .unwrap();
    std::fs::write(
        rust_probe.join("src/lib.rs"),
        r#"use std::ffi::CStr;

#[link(name = "pango-1.0")]
unsafe extern "C" {
    fn pango_version_string() -> *const std::ffi::c_char;
}

#[no_mangle]
pub unsafe extern "C" fn tog_pango_version() -> *const std::ffi::c_char {
    pango_version_string()
}

#[no_mangle]
pub unsafe extern "C" fn tog_pango_version_is_pinned() -> bool {
    CStr::from_ptr(pango_version_string()).to_bytes() == b"1.50.11"
}
"#,
    )
    .unwrap();
    let host_path = std::env::var_os("PATH").unwrap();
    let find_tool = |name: &str| {
        std::env::split_paths(&host_path)
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from(name))
    };
    let cargo_bin = find_tool("cargo");
    let rustc_bin = find_tool("rustc");
    let mut cargo_probe = Command::new(&cargo_bin);
    cargo_probe
        .current_dir(&rust_probe)
        .args(["build", "--release"])
        .env("RUSTC", &rustc_bin)
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    for (key, value) in &env {
        cargo_probe.env(key, value);
    }
    cargo_probe.env("PATH", host_path);
    let cargo_output = cargo_probe.output().unwrap();
    assert_ok(cargo_output, "Rust Pango probe build");
    let probe = rust_probe.join("target/release/librust_pango_probe.so");
    assert!(
        probe.is_file(),
        "Rust probe did not produce {}",
        probe.display()
    );
    let readelf = assert_ok(
        Command::new("readelf")
            .args(["-dW"])
            .arg(&probe)
            .output()
            .unwrap(),
        "readelf Rust Pango probe",
    );
    let native_lib = native.path.join("lib/libpango-1.0.so.0");
    assert!(
        readelf.lines().any(|line| {
            (line.contains("RUNPATH") || line.contains("RPATH"))
                && line.contains(&native.path.join("lib").display().to_string())
        }),
        "Rust probe has no native library runpath:\n{readelf}"
    );
    let ldd = assert_ok(
        Command::new("ldd").arg(&probe).output().unwrap(),
        "ldd Rust Pango probe",
    );
    assert!(
        ldd.lines()
            .any(|line| line.contains(&native_lib.display().to_string())),
        "Rust probe resolved a host Pango instead of {}:\n{ldd}",
        native_lib.display()
    );
    println!(
        "Rust Pango probe: {} -> {}",
        probe.display(),
        native_lib.display()
    );
    // The probe's own check, called: the Pango it linked reports the
    // pinned version, so the runpath resolved to the libset at run time
    // and not merely on paper.
    let pinned = assert_ok(
        Command::new("python3")
            .args([
                "-c",
                "import ctypes, sys; lib = ctypes.CDLL(sys.argv[1]); \
                 lib.tog_pango_version_is_pinned.restype = ctypes.c_bool; \
                 print('pinned' if lib.tog_pango_version_is_pinned() else 'unpinned')",
            ])
            .arg(&probe)
            .output()
            .unwrap(),
        "call the Rust Pango probe",
    );
    assert_eq!(
        pinned.trim(),
        "pinned",
        "the Rust probe's Pango is not the pinned 1.50.11"
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
        env: env.clone(),
        read: vec![native.path.clone()],
        write: vec![pkg_scratch.clone()],
        scratch: pkg_scratch,
        path: path.clone(),
        host_view: tog::kernel::sandbox::HostView::Full,
    })
    .expect("sandboxed pkg-config");
    let pango_version = std::fs::read_to_string(&version_file).unwrap();
    println!("sandbox pkg-config pango={}", pango_version.trim());
    assert_eq!(pango_version.trim(), "1.50.11");

    let confdir_file = temp.0.join("fontconfig-confdir");
    let command = format!(
        "{} --variable=confdir fontconfig > {}",
        shell_quote(&native.path.join("bin/pkg-config")),
        shell_quote(&confdir_file)
    );
    run_build_spec(&BuildSpec {
        argv: vec!["/bin/sh".into(), "-c".into(), command],
        cwd: temp.0.clone(),
        env,
        read: vec![native.path.clone()],
        write: vec![temp.0.clone()],
        scratch: temp.0.clone(),
        path,
        host_view: tog::kernel::sandbox::HostView::Full,
    })
    .expect("sandboxed fontconfig pkg-config");
    let confdir = std::fs::read_to_string(&confdir_file).unwrap();
    println!("sandbox pkg-config fontconfig confdir={}", confdir.trim());
    assert_eq!(
        confdir.trim(),
        native.path.join("etc/fonts").display().to_string()
    );

    let project = temp.0.join("manimpango");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::copy(
        fixture("native-libs/requirements.txt"),
        project.join("requirements.txt"),
    )
    .unwrap();
    let sync = tog_at(&project, &temp.0, &store_path, &["sync"]);
    assert_ok(sync, "manimpango sync");
    let plan: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join(".tog/plan.json")).unwrap())
            .unwrap();
    let manimpango = plan["plan"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == "manimpango")
        .expect("manimpango in plan");
    assert_eq!(manimpango["kind"], "Sdist");
    assert!(project.join(".tog/closures/python.json").is_file());
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".tog/closures/python.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(closure["body"]["native_libs"]["id"], native.id);

    let run = tog_at(
        &project,
        &temp.0,
        &store_path,
        &[
            "run",
            "python",
            "-c",
            "import manimpango; print('manimpango ok')",
        ],
    );
    let output = assert_ok(run, "tog run python import manimpango");
    assert!(
        output.contains("manimpango ok"),
        "unexpected run output: {output}"
    );
    println!("tog run python import manimpango: ok");
    // The import proves little on a host with its own Pango: the
    // extension's dynamic linkage has to name the libset's Pango. Every
    // compiled module in the package is checked, not just the first.
    let package_dir = assert_ok(
        tog_at(
            &project,
            &temp.0,
            &store_path,
            &[
                "run",
                "python",
                "-c",
                "import manimpango, os; print(os.path.dirname(manimpango.__file__))",
            ],
        ),
        "locate manimpango",
    );
    let package_dir = PathBuf::from(package_dir.trim());
    let extensions: Vec<PathBuf> = std::fs::read_dir(&package_dir)
        .unwrap_or_else(|error| panic!("{}: {error}", package_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "so"))
        .collect();
    assert!(
        !extensions.is_empty(),
        "no compiled extension under {}",
        package_dir.display()
    );
    for extension in &extensions {
        let ldd = assert_ok(
            Command::new("ldd").arg(extension).output().unwrap(),
            "ldd manimpango extension",
        );
        assert!(
            ldd.lines()
                .any(|line| line.contains(&native_lib.display().to_string())),
            "{} resolved a host Pango instead of {}:\n{ldd}",
            extension.display(),
            native_lib.display()
        );
        assert!(
            !ldd.lines().any(|line| {
                line.contains("libpango") && !line.contains(&native.path.display().to_string())
            }),
            "{} resolves a Pango library outside the libset:\n{ldd}",
            extension.display()
        );
    }
    println!(
        "manimpango extensions link the libset Pango: {}",
        extensions.len()
    );
}

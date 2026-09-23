//! The Cargo tailor: project Cargo environments and sandboxed builds over
//! the pinned Rust toolchain and Cargo.lock vendoring that live in
//! `kernel::provider::{rust, crates}`.

pub mod inputs;
pub mod objects;
pub mod rustfmt;
pub mod tailor;

use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::toolchain::{LegacyEvidence, Selected};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use crate::kernel::provider::crates::{
    lock_digest, plan_cargo, vendor_object_id, CargoCrate, CargoGitReference, CargoGitSource,
    CargoPlan,
};
pub(crate) use crate::kernel::provider::crates::{
    plan_git_sources, project_git_sources, tog_config_text_for,
};
pub use crate::kernel::provider::rust::{
    preflight_platform, resolve_toolchain, resolve_toolchain_choice, resolve_toolchain_quiet,
    runtime_object_id, rust_object_id, toolchain_catalog, toolchain_file_components,
    ToolchainChoice,
};

/// Realize the Rust toolchain `selected` names; see
/// `kernel::provider::rust::realize_runtime`.
pub fn realize_runtime(
    store: &Store,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::provider::rust::realize_runtime(store, platform, selected)
}

/// Realize the registry closure as a Cargo directory source; see
/// `kernel::provider::crates::realize_vendor`.
pub fn realize_vendor(store: &Store, plan: &CargoPlan) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::provider::crates::realize_vendor(store, plan)
}

/// A pre-lock cargo closure records the toolchain under `plan.rust_version`;
/// a rustfmt closure records it at the top level. Both name the Rust object
/// under `rust_object`: the three component archives and the recipe its
/// identity names are the proof.
pub fn legacy_toolchain_evidence(
    ecosystem: &str,
    platform: Option<Platform>,
    body: &serde_json::Value,
    store: Option<&crate::kernel::store::Store>,
) -> LegacyEvidence {
    use crate::comforter::toolchain::{self as project_toolchain, LegacyRuntime};
    let pointer = if ecosystem == "rustfmt" {
        "/rust_version"
    } else {
        "/plan/rust_version"
    };
    let mut evidence =
        crate::comforter::legacy_toolchain_evidence(platform, body, &[("rustc", pointer)]);
    project_toolchain::prove_legacy_runtime(
        &mut evidence,
        store,
        body,
        LegacyRuntime {
            pointer: "/rust_object",
            via: &[],
            kind: "rust",
        },
        |identity, evidence| {
            project_toolchain::expect_legacy_version(
                identity,
                evidence,
                "rustc",
                &identity.version,
            )?;
            let recipe = project_toolchain::schema_recipe(identity)?;
            crate::kernel::provider::rust::RUNTIME_COMPONENTS
                .iter()
                .map(|component| {
                    project_toolchain::proved_from_identity(
                        identity,
                        component,
                        &format!("{}_sha256", component.replace('-', "_")),
                        "sha256",
                        recipe,
                    )
                })
                .collect()
        },
    );
    evidence
}

/// The Rust object a pre-lock sync from `selected` left for legacy seeding
/// to read, and the body field that names it (cargo and rustfmt closures
/// both use it).
#[cfg(test)]
pub(crate) fn legacy_runtime_for_test(
    platform: Platform,
    selected: &Selected,
    store: &Store,
) -> (serde_json::Value, Vec<Identity>) {
    let rust = identity_of(platform, &runtime_rows(platform, selected).unwrap());
    let body = serde_json::json!({
        "rust_object": crate::comforter::toolchain::object_ref_for_test(store, &rust.object_id()),
    });
    (body, vec![rust])
}

/// The `store/tmp` scratch name for a `cargo build`. The `stage-` prefix is
/// the one `gc::collect` sweeps, so a build killed before its cleanup leaks
/// nothing permanent; see `unique_dir`.
const BUILD_SCRATCH_PREFIX: &str = "stage-cargo-build";

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
use crate::kernel::provider::crates::vendor_identity;
#[cfg(test)]
use crate::kernel::provider::rust::{
    extract_rust_components, identity_of, runtime_rows, rust_components, rust_identity,
    RustComponent, RUST_VERSION,
};
#[cfg(test)]
use crate::kernel::types::Identity;

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let components = rust_components(platform).expect("pinned Rust components for test platform");
    let rust = rust_identity(platform, &components);
    let rust_object_id = rust.object_id();
    let rustfmt = rustfmt::live_identity_for_test(platform, &rust_object_id)
        .expect("pinned rustfmt component for test platform");
    let vendor_empty = vendor_identity(&CargoPlan {
        rust_version: RUST_VERSION.into(),
        crates: Vec::new(),
        members: Vec::new(),
    })
    .expect("empty Cargo vendor identity")
    .1;
    let vendor_registry = vendor_identity(&CargoPlan {
        rust_version: RUST_VERSION.into(),
        crates: vec![CargoCrate {
            name: "serde".into(),
            version: "1.0.0".into(),
            sha256: "a".repeat(64),
            url: "https://crates.io/api/v1/crates/serde/1.0.0/download".into(),
            git: None,
        }],
        members: Vec::new(),
    })
    .expect("registry Cargo vendor identity")
    .1;
    let vendor_registry_many = vendor_identity(&CargoPlan {
        rust_version: RUST_VERSION.into(),
        crates: vec![
            CargoCrate {
                name: "rand".into(),
                version: "0.9.0".into(),
                sha256: "b".repeat(64),
                url: "https://crates.io/api/v1/crates/rand/0.9.0/download".into(),
                git: None,
            },
            CargoCrate {
                name: "serde".into(),
                version: "1.0.0".into(),
                sha256: "a".repeat(64),
                url: "https://crates.io/api/v1/crates/serde/1.0.0/download".into(),
                git: None,
            },
        ],
        members: Vec::new(),
    })
    .expect("multi-crate Cargo vendor identity")
    .1;
    vec![
        rust,
        rustfmt,
        vendor_empty,
        vendor_registry,
        vendor_registry_many,
    ]
}

/// A later `--config` outranks ours; letting one through would let a hostile
/// invocation swap the vendor source while provenance still claims tog's.
fn reject_user_config(args: &[String]) -> io::Result<()> {
    for arg in args {
        if arg == "--config" || arg.starts_with("--config=") {
            return Err(err(
                "--config is managed by tog (it enforces the verified vendor source); \
                 put project settings in .cargo/config.toml instead",
            ));
        }
    }
    Ok(())
}

/// Fold the two toolchain entries into a closure body being built.
pub(crate) fn merge_record(body: &mut serde_json::Value, record: serde_json::Value) {
    if let (Some(body), Some(record)) = (body.as_object_mut(), record.as_object()) {
        for (key, value) in record {
            body.insert(key.clone(), value.clone());
        }
    }
}

/// Project Cargo with a writable home, forced directory-source replacement,
/// and provenance for the exact toolchain/vendor closure. `toolchain` is the
/// selection the run honored: the closure records it so the release this
/// Rust object came from is readable without re-deriving it from the plan.
pub fn project_cargo_env(
    project_dir: &Path,
    rust_obj: &Path,
    vendor_obj: &Path,
    plan: &CargoPlan,
    lock_digest: &str,
    toolchain: &Selected,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let project_dir = project_dir.canonicalize()?;
    // The workspace root is what gets registered, and projecting a cargo-home
    // into a root no record can name leaves wrappers pointing at objects the
    // next sweep is free to remove.
    Store::check_registrable(&project_dir)?;
    let rust_obj = rust_obj.canonicalize()?;
    let vendor_obj = vendor_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&rust_obj)
        .ok_or_else(|| err("Rust object is not in a Tog store"))?;
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let meta_dir = project_dir.join(".tog");
    fs::create_dir_all(&meta_dir)?;
    let cargo_home = project_child_dir(&project_dir, ".tog/cargo-home")?;
    // bin gets its own containment check: a symlinked bin would carry the
    // wrapper write outside the project.
    let bin_dir = project_child_dir(&project_dir, ".tog/cargo-home/bin")?;
    let config = cargo_home.join("tog-config.toml");
    let wrapper = bin_dir.join("cargo");

    write_atomic(
        &config,
        tog_config_text_for(&vendor_obj, &plan_git_sources(plan))?.as_bytes(),
        None,
    )?;

    let cargo_bin = rust_obj.join("bin/cargo");
    let rustc_bin = rust_obj.join("bin/rustc");
    let wrapper_text = format!(
        "#!/bin/sh\n\
         for a in \"$@\"; do case \"$a\" in --config|--config=*)\n\
           echo 'tog: --config is managed by tog' >&2; exit 2;; esac; done\n\
         export CARGO_HOME=\"{}\"\n\
         export RUSTC=\"{}\"\n\
         export RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=\n\
         unset RUSTUP_HOME RUSTUP_TOOLCHAIN\n\
         exec \"{}\" --frozen --config \"{}\" \"$@\"\n",
        shell_double_quote(&cargo_home),
        shell_double_quote(&rustc_bin),
        shell_double_quote(&cargo_bin),
        shell_double_quote(&config),
    );
    write_atomic(&wrapper, wrapper_text.as_bytes(), Some(0o755))?;

    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({
            "path": path.display().to_string(),
            "id": id,
        }))
    };
    let mut body = serde_json::json!({
        "rust_object": object_ref(&rust_obj)?,
        "vendor_object": object_ref(&vendor_obj)?,
        "cargo_lock_sha256": lock_digest,
        "plan": plan,
    });
    // The Rust object is this ecosystem's runtime: the record names the
    // bundle it came from and refers to it directly, so a later catalog
    // refresh cannot re-pair these dependencies with another compiler.
    merge_record(
        &mut body,
        crate::comforter::toolchain::closure_record(toolchain, &rust_obj),
    );
    let valid_objects = [rust_obj.as_path(), vendor_obj.as_path()]
        .iter()
        .all(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(crate::kernel::store::is_object_id)
        });
    if !valid_objects {
        #[cfg(test)]
        {
            return crate::comforter::write_closure_legacy(
                &project_dir,
                "cargo",
                body,
                attribution,
            );
        }
        #[cfg(not(test))]
        {
            return Err(err(
                "Cargo closure references must name complete store objects",
            ));
        }
    }
    let mut refs = crate::comforter::ClosureRefs::new();
    // The runtime object and `rust_object` are the same object; the direct
    // reference is what keeps it alive across a GC.
    refs.object_path(&store, &activity, &rust_obj)?;
    refs.object_path(&store, &activity, &vendor_obj)?;
    crate::comforter::write_closure(
        &project_dir,
        "cargo",
        body,
        &store,
        &activity,
        refs,
        attribution,
    )
}

/// Build a Cargo project in the network-denied sandbox.
pub fn build_sandboxed(
    platform: Platform,
    project_dir: &Path,
    rust_obj: &Path,
    vendor_obj: &Path,
    args: &[String],
) -> io::Result<()> {
    let store = Store::open()?;
    reject_user_config(args)?;
    let project_dir = project_dir.canonicalize()?;
    let rust_obj = rust_obj.canonicalize()?;
    let vendor_obj = vendor_obj.canonicalize()?;
    let target = project_child_dir(&project_dir, "target")?;
    let cargo_bin = rust_obj.join("bin/cargo");
    if !cargo_bin.is_file() || !vendor_obj.is_dir() {
        return Err(err("cargo environment is incomplete; run `tog` first"));
    }

    let store_tmp = rust_obj
        .parent()
        .and_then(Path::parent)
        .map(|path| path.join("tmp"))
        .ok_or_else(|| err("cannot locate store tmp for Cargo build"))?;
    let scratch = build_scratch(&store_tmp)?;
    // Disposable per-build CARGO_HOME + config inside the scratch dir: the
    // projected cargo-home must never be writable in-sandbox, or a build
    // script could replace the wrapper that later runs UNsandboxed under
    // `tog run`.
    let build_home = scratch.join("cargo-home");
    fs::create_dir_all(&build_home)?;
    let config = build_home.join("tog-config.toml");
    fs::write(
        &config,
        tog_config_text_for(&vendor_obj, &project_git_sources(&project_dir))?,
    )?;
    let mut argv = vec![
        cargo_bin
            .to_str()
            .ok_or_else(|| err("Cargo path is not UTF-8"))?
            .to_string(),
        "--frozen".to_string(),
        "--config".to_string(),
        config
            .to_str()
            .ok_or_else(|| err("Cargo config path is not UTF-8"))?
            .to_string(),
        "build".to_string(),
    ];
    argv.extend(args.iter().cloned());
    let spec = crate::kernel::sandbox::BuildSpec {
        argv,
        cwd: project_dir.clone(),
        env: vec![
            ("CARGO_HOME".to_string(), build_home.display().to_string()),
            ("CARGO_TARGET_DIR".to_string(), target.display().to_string()),
            // Env outranks a project's [build] rustc / rustc-wrapper config:
            // the pinned compiler is not negotiable (empty wrapper = none).
            (
                "RUSTC".to_string(),
                rust_obj.join("bin/rustc").display().to_string(),
            ),
            ("RUSTC_WRAPPER".to_string(), String::new()),
            ("RUSTC_WORKSPACE_WRAPPER".to_string(), String::new()),
        ],
        read: vec![project_dir.clone(), rust_obj.clone(), vendor_obj.clone()],
        write: vec![target],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", rust_obj.join("bin").display()),
    };
    let result = crate::kernel::sandbox::run_build_spec_on_for_store(platform, &spec, &store);
    let _ = fs::remove_dir_all(&scratch);
    result.map_err(|e| {
        io::Error::new(e.kind(), format!(
            "Cargo build failed: {e}; network is denied; external path dependencies outside the project and build scripts needing network are unsupported (declared-artifact support may come later)"
        ))
    })
}

fn project_child_dir(project_dir: &Path, relative: &str) -> io::Result<PathBuf> {
    let path = project_dir.join(relative);
    fs::create_dir_all(&path)?;
    let path = path.canonicalize()?;
    if !path.starts_with(project_dir) {
        return Err(err(format!(
            "Cargo path {} escapes project {}",
            path.display(),
            project_dir.display()
        )));
    }
    Ok(path)
}

/// The scratch directory one `cargo build` runs in. Every caller of the
/// build goes through here, so the prefix cannot drift away from the one the
/// gc stage sweep reclaims without the sweep test noticing.
fn build_scratch(store_tmp: &Path) -> io::Result<PathBuf> {
    unique_dir(store_tmp, BUILD_SCRATCH_PREFIX)
}

/// A scratch directory under `store/tmp`. Every caller passes a `stage-`
/// prefix on purpose: `gc::collect` reclaims exactly `store/tmp/stage-*`, so
/// a run killed by a signal before its cleanup still gets collected.
/// Sweeping only touches stages older than a day, so a live run's scratch
/// (created moments ago, and written to throughout) is never swept out from
/// under it.
fn unique_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(parent)?;
    for attempt in 0..100 {
        let path = parent.join(format!(
            "{prefix}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            attempt
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(err(format!(
        "could not create a {prefix} scratch directory under {}: every candidate name was taken",
        parent.display()
    )))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| err(format!("path has no parent: {}", path.display())))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    let result = (|| {
        fs::write(&tmp, bytes)?;
        if let Some(mode) = mode {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
            }
        }
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn shell_double_quote(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

#[cfg(test)]
mod tests {

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_pinned_rust_components() {
        for platform in Platform::ALL {
            let components = rust_components(*platform).unwrap();
            let mut expected: Vec<String> = components
                .iter()
                .map(|component| format!("sha256:{}", component.sha256))
                .collect();
            expected.sort();
            expected.dedup();
            assert_eq!(
                recovered_cache(rust_identity(*platform, &components)),
                expected
            );
        }
    }

    fn recovered_cache(identity: crate::kernel::types::Identity) -> Vec<String> {
        match crate::kernel::objmeta::adapt_identity_for_test(identity, Vec::new()) {
            crate::kernel::objmeta::Adaptation::Proven(deps) => {
                assert!(
                    deps.objects.is_empty(),
                    "a pinned artifact has no object deps"
                );
                deps.cache
                    .iter()
                    .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                    .collect()
            }
            crate::kernel::objmeta::Adaptation::Unresolved(reason) => panic!("{reason}"),
        }
    }
    use super::*;
    use crate::kernel::toolchain::Component as BundleComponent;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    use std::process::Command;

    /// The shipped Rust selection: what a run with no lock to honor is
    /// handed, and the only thing these tests need a `Selected` for.
    fn selection() -> Selected {
        crate::kernel::toolchain::shipped(&toolchain_catalog().unwrap()).unwrap()
    }

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let components = rust_components(platform).unwrap();
        let identity = rust_identity(platform, &components);
        assert_eq!(
            identity.object_id(),
            "b8418440835c4ec1f591381a17ae60ab12d1c727-rust-1.96.1"
        );
    }

    #[test]
    fn rust_component_sets_are_complete_unique_and_pinned() {
        let expected_names = BTreeSet::from(["cargo", "rust-std", "rustc"]);
        for platform in Platform::ALL {
            let components = rust_components(*platform).unwrap();
            assert_eq!(components.len(), 3);
            assert_eq!(
                components
                    .iter()
                    .map(|component| component.component)
                    .collect::<BTreeSet<_>>(),
                expected_names
            );
            assert!(components
                .iter()
                .all(|component| component.version == RUST_VERSION));
            assert!(components
                .iter()
                .all(|component| component.platform == *platform));
        }
    }

    #[test]
    fn linux_rust_component_urls_and_digests_are_exact() {
        let platform = Platform::X86_64UnknownLinuxGnu;
        let expected = [
            (
                "rustc",
                "https://static.rust-lang.org/dist/rustc-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
                "3545a0efad2355ecb0a3b9ac02efee96e27f1f9d24b7ce2fc3f279b2efb0d923",
            ),
            (
                "rust-std",
                "https://static.rust-lang.org/dist/rust-std-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
                "1bf4fde5048cca33e6ea00c7471281ed96d792f6923141e3db45072743a1afae",
            ),
            (
                "cargo",
                "https://static.rust-lang.org/dist/cargo-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
                "ecc53a3c49fab5ab8c9301b3bbc8fb1dff9be6c65287add3f57a0fe8fddfea9e",
            ),
        ];
        let components = rust_components(platform).unwrap();
        for (name, url, sha256) in expected {
            let component = components
                .iter()
                .find(|component| component.component == name)
                .unwrap();
            assert_eq!(component.url, url);
            assert_eq!(component.sha256, sha256);
            assert!(component.url.contains("x86_64-unknown-linux-gnu"));
        }
        assert!(rust_components(Platform::Aarch64AppleDarwin)
            .unwrap()
            .iter()
            .all(|component| component.url.contains("aarch64-apple-darwin")));
    }

    #[test]
    fn rust_identity_is_platform_specific() {
        let darwin = rust_components(Platform::Aarch64AppleDarwin).unwrap();
        let linux = rust_components(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_ne!(
            rust_identity(Platform::Aarch64AppleDarwin, &darwin).object_id(),
            rust_identity(Platform::X86_64UnknownLinuxGnu, &linux).object_id()
        );
    }
    use std::env;
    use std::ffi::OsString;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!("{prefix}-{}-{suffix}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    use crate::kernel::store::STORE_ENV_LOCK;

    struct StoreEnv(Option<OsString>);

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => env::set_var("TOG_STORE", value),
                None => env::remove_var("TOG_STORE"),
            }
        }
    }

    fn with_temp_store(f: impl FnOnce(&Store, &Path)) {
        let _lock = STORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::new("tog-cargo-store");
        let old = env::var_os("TOG_STORE");
        env::set_var("TOG_STORE", temp.path());
        let _env = StoreEnv(old);
        let store = Store::open().unwrap();
        f(&store, temp.path());
    }

    fn exception_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::kernel::policy::exception_guard()
    }

    fn package_lock(package: &str, version: u64) -> String {
        format!("version = {version}\n\n[[package]]\n{package}")
    }

    #[test]
    fn plans_registry_and_workspace_closure() {
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        let lock = format!(
            r#"version = 4

[[package]]
name = "demo"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{hash_a}"

[[package]]
name = "workspace-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "sparse+https://index.crates.io/"
checksum = "{hash_b}"

[[package]]
name = "serde"
version = "1.0.1"
source = "sparse+https://index.crates.io/"
checksum = "{hash_b}"
"#
        );
        let plan = plan_cargo(&lock, "1.96.1").unwrap();
        assert_eq!(plan.rust_version, "1.96.1");
        assert_eq!(plan.members, vec!["workspace-app"]);
        assert_eq!(plan.crates.len(), 3);
        assert_eq!(
            plan.crates[0].url,
            "https://static.crates.io/crates/demo/demo-1.2.3.crate"
        );
        assert_eq!(plan.crates[1].version, "1.0.0");
        assert_eq!(plan.crates[2].version, "1.0.1");
    }

    #[test]
    fn cargo_plan_rejects_unsupported_or_hostile_lock_entries() {
        let hash = "a".repeat(64);
        let cases = [
            (
                "git source",
                format!(
                    "name = \"a\"\nversion = \"1.0.0\"\nsource = \"git+https://example.com/a\""
                ),
            ),
            (
                "alternative registry",
                format!(
                    "name = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.com/index\"\nchecksum = \"{hash}\""
                ),
            ),
            (
                "missing checksum",
                "name = \"a\"\nversion = \"1.0.0\"\nsource = \"sparse+https://index.crates.io/\"".into(),
            ),
            (
                "bad checksum",
                "name = \"a\"\nversion = \"1.0.0\"\nsource = \"sparse+https://index.crates.io/\"\nchecksum = \"zz\"".into(),
            ),
            (
                "hostile name",
                format!("name = \"../evil\"\nversion = \"1.0.0\"\nchecksum = \"{hash}\""),
            ),
        ];
        for (label, package) in cases {
            assert!(
                plan_cargo(&package_lock(&package, 4), "1.96.1").is_err(),
                "{label} should fail"
            );
        }

        assert!(plan_cargo(
            &package_lock("name = \"a\"\nversion = \"1.0.0\"", 2),
            "1.96.1"
        )
        .is_err());
        let duplicate = format!(
            "name = \"a\"\nversion = \"1.0.0\"\nchecksum = \"{hash}\"\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nchecksum = \"{hash}\""
        );
        assert!(plan_cargo(&package_lock(&duplicate, 4), "1.96.1").is_err());
    }

    /// An unpacked sdist reads only its own toolchain file. The store's
    /// scratch directory sits under `$HOME` or wherever `TOG_STORE` points, so
    /// a file above the sdist is someone else's: a `~/rust-toolchain` naming
    /// nightly must not fail every Rust sdist build, and its components must
    /// not be recorded against one.
    #[test]
    fn an_sdist_ignores_toolchain_files_above_its_root() {
        use crate::kernel::provider::rust::{
            resolve_toolchain_within, toolchain_file_components_within,
        };
        let _exception_guard = exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let platform = Platform::X86_64UnknownLinuxGnu;
        let temp = TempDir::new("tog-sdist-toolchain");
        let sdist = temp.path().join("store/tmp/work/source");
        fs::create_dir_all(&sdist).unwrap();
        fs::write(temp.path().join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        fs::write(
            temp.path().join("store/rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"miri\"]\n",
        )
        .unwrap();

        // The project search climbs to the stray files.
        let climbed =
            crate::kernel::provider::rust::resolve_toolchain_quiet(platform, &sdist).unwrap();
        assert_eq!(climbed.unavailable, vec!["miri".to_string()]);
        assert!(resolve_toolchain(platform, temp.path()).is_err());
        crate::kernel::policy::clear();

        assert_eq!(
            resolve_toolchain_within(platform, &sdist).unwrap(),
            RUST_VERSION
        );
        assert!(toolchain_file_components_within(platform, &sdist)
            .unwrap()
            .is_empty());
        assert!(crate::kernel::policy::pending().is_empty());

        // The sdist's own file is still read.
        fs::write(sdist.join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        assert!(resolve_toolchain_within(platform, &sdist).is_err());
    }

    #[test]
    fn resolves_toolchain_files_and_pins() {
        let _exception_guard = exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-toolchain");
        let project = temp.path().join("project/child");
        fs::create_dir_all(&project).unwrap();
        let root = project.parent().unwrap();

        fs::write(root.join("rust-toolchain"), "1.96\n").unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\nprofile = \"minimal\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::write(root.join("rust-toolchain"), "1.96.1\n").unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"beta\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::write(root.join("rust-toolchain"), "stable\n").unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::write(root.join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        let error = resolve_toolchain(Platform::Aarch64AppleDarwin, &project)
            .unwrap_err()
            .to_string();
        assert!(error.contains("1.96.1"));

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"wasm32-unknown-unknown\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(Platform::Aarch64AppleDarwin, &project).is_err());
        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::remove_file(root.join("rust-toolchain.toml")).unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );
        let _ = crate::kernel::policy::drain();
    }

    /// A selection built from another ecosystem's bundle, or one whose rows
    /// name a layout this binary has never heard of, is refused before
    /// anything is fetched. A lock is an input like any other: it can name a
    /// recipe a newer tog invented, and the honest answer is to say so.
    #[test]
    fn realization_refuses_a_foreign_selection_and_an_unknown_recipe() {
        use crate::kernel::toolchain::fixtures;
        let temp = TempDir::new("tog-rust-refusals");
        let store = Store {
            root: temp.path().join("absent-store"),
        };
        let platform = Platform::host().unwrap();

        let foreign = Selected {
            ecosystem: "python".into(),
            bundle: fixtures::bundle("cpython-3.13.15", "cpython", "3.13.15", Platform::ALL),
            lock_sha256: None,
            source: crate::kernel::toolchain::Source::Lock,
        };
        let error = realize_runtime(&store, platform, &foreign)
            .unwrap_err()
            .to_string();
        assert!(error.contains("python selection"), "{error}");
        assert!(error.contains("Rust tailor"), "{error}");

        // The right ecosystem, laid out by a recipe this binary does not know.
        let mut bundle = fixtures::bundle("rust-9.9.9", "rustc", "9.9.9", Platform::ALL);
        for component in ["rust-std", "cargo"] {
            bundle
                .components
                .push(BundleComponent::new(component, "9.9.9"));
            bundle.artifacts.extend(
                Platform::ALL
                    .iter()
                    .map(|p| fixtures::row(*p, component, 'd')),
            );
        }
        let unknown = Selected {
            ecosystem: "rust".into(),
            bundle,
            lock_sha256: None,
            source: crate::kernel::toolchain::Source::Lock,
        };
        let error = realize_runtime(&store, platform, &unknown)
            .unwrap_err()
            .to_string();
        assert!(error.contains("recipe example/1"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");

        // A row with no artifact for this platform is refused by name too.
        let one_platform = Selected {
            ecosystem: "rust".into(),
            bundle: fixtures::bundle("rust-1.96.1", "rustc", "1.96.1", &[]),
            lock_sha256: None,
            source: crate::kernel::toolchain::Source::Lock,
        };
        let error = realize_runtime(&store, platform, &one_platform)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rustc"), "{error}");
        assert!(error.contains(platform.triple()), "{error}");

        assert!(
            !store.root.exists(),
            "a refused selection touched the store"
        );
    }

    /// Realization from a locked bundle row and realization from the
    /// compiled pin are two spellings of one object. If they ever disagree,
    /// a project that adopts a lock silently rebuilds its toolchain under a
    /// new id and every record naming the old one goes stale.
    #[test]
    fn a_selected_row_and_the_pin_build_the_same_object_id() {
        let selected = selection();
        for platform in Platform::ALL {
            let components = rust_components(*platform).unwrap();
            let rows = runtime_rows(*platform, &selected).unwrap();
            assert_eq!(
                identity_of(*platform, &rows).object_id(),
                rust_identity(*platform, &components).object_id(),
                "{}",
                platform.triple()
            );
            assert_eq!(
                runtime_object_id(*platform, &selected).unwrap(),
                rust_object_id(*platform, RUST_VERSION).unwrap()
            );
            // Same for the formatter, which is paired with that object.
            let rust_object =
                Path::new("/objects").join(rust_object_id(*platform, RUST_VERSION).unwrap());
            assert_eq!(
                rustfmt::identity_for_test(*platform, &selected, &rust_object)
                    .unwrap()
                    .object_id(),
                rustfmt::live_identity_for_test(
                    *platform,
                    &rust_object_id(*platform, RUST_VERSION).unwrap()
                )
                .unwrap()
                .object_id(),
                "{}",
                platform.triple()
            );
        }
    }

    /// The one resolver left that reads a version off a project path serves
    /// callers with no selection to honor (the Python sdist build, `tog
    /// deps`). With no toolchain file to narrow it, it must land on exactly
    /// the shipped selection — the same release a lockless run of the Rust
    /// tailor is handed — or those two paths would realize different Rust
    /// toolchains for one machine.
    #[test]
    fn the_lockless_resolver_agrees_with_the_shipped_selection() {
        let temp = TempDir::new("tog-cargo-lockless");
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let shipped = selection();
        for platform in Platform::ALL {
            assert_eq!(
                resolve_toolchain(*platform, &project).unwrap(),
                shipped.version("rustc").unwrap(),
                "{}",
                platform.triple()
            );
        }
    }

    /// Once a lock decides the version, the toolchain file is read for one
    /// thing only: the components it asks for that tog does not provide. The
    /// channel is selection's business, so a channel this binary could never
    /// resolve on its own is no longer this path's error — the run that got
    /// here was already handed a selection that answered it.
    #[test]
    fn a_toolchain_file_contributes_components_not_a_version() {
        let _exception_guard = exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let platform = Platform::X86_64UnknownLinuxGnu;
        let temp = TempDir::new("tog-cargo-file-components");
        let project = temp.path().join("project/child");
        fs::create_dir_all(&project).unwrap();
        let root = project.parent().unwrap();

        // No file at all, and a bare channel line: nothing to contribute.
        assert!(toolchain_file_components(platform, &project)
            .unwrap()
            .is_empty());
        fs::write(root.join("rust-toolchain"), "1.96.1\n").unwrap();
        assert!(toolchain_file_components(platform, &project)
            .unwrap()
            .is_empty());
        assert!(crate::kernel::policy::pending().is_empty());

        // The components tog provides are not unavailable; the rest are,
        // in file order, and they are the run's exception.
        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"rustc\", \"clippy\", \"cargo\", \"miri\"]\n",
        )
        .unwrap();
        assert_eq!(
            toolchain_file_components(platform, &project).unwrap(),
            ["clippy", "miri"]
        );
        let recorded = crate::kernel::policy::drain();
        let exception = recorded
            .iter()
            .find(|exception| {
                exception.kind == crate::kernel::policy::TOOLCHAIN_COMPONENT_UNAVAILABLE
            })
            .expect("unavailable components are an exception");
        assert!(
            exception.subject.ends_with("rust-toolchain"),
            "{exception:?}"
        );
        assert!(exception.detail.contains("clippy, miri"), "{exception:?}");

        // A channel no pin table could answer still yields its components:
        // the version came from the lock, and this path never re-decides it.
        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"nightly-2026-01-01\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(platform, &project).is_err());
        assert_eq!(
            toolchain_file_components(platform, &project).unwrap(),
            ["clippy"]
        );
        let _ = crate::kernel::policy::drain();

        // A target that is not this host is still refused: tog realizes one
        // platform's toolchain and cannot honor a cross-compilation request.
        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"wasm32-unknown-unknown\"]\n",
        )
        .unwrap();
        let error = toolchain_file_components(platform, &project)
            .unwrap_err()
            .to_string();
        assert!(error.contains("wasm32-unknown-unknown"), "{error}");
        let _ = crate::kernel::policy::drain();
    }

    #[test]
    fn resolves_linux_toolchain_files_targets_and_policy() {
        let _exception_guard = exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-linux-toolchain");
        let project = temp.path().join("project/child");
        fs::create_dir_all(&project).unwrap();
        let root = project.parent().unwrap();

        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        for channel in ["stable", "1.96", "1.96.1"] {
            fs::write(root.join("rust-toolchain"), format!("{channel}\n")).unwrap();
            assert_eq!(
                resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
                "1.96.1"
            );
        }

        fs::write(root.join("rust-toolchain"), "beta\n").unwrap();
        assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());
        fs::write(root.join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"x86_64-unknown-linux-gnu\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        for target in ["aarch64-apple-darwin", "wasm32-unknown-unknown"] {
            fs::write(
                root.join("rust-toolchain"),
                format!("[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"{target}\"]\n"),
            )
            .unwrap();
            assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());
        }

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        assert!(crate::kernel::policy::pending()
            .iter()
            .any(|exception| exception.kind
                == crate::kernel::policy::TOOLCHAIN_COMPONENT_UNAVAILABLE));
        let _ = crate::kernel::policy::drain();

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"aarch64-apple-darwin\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());
    }

    #[test]
    fn rustfmt_toolchain_component_is_recorded_as_unavailable_under_permissive_policy() {
        let _exception_guard = exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-rustfmt-policy");
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"rustfmt\"]\n",
        )
        .unwrap();

        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        assert!(crate::kernel::policy::pending().iter().any(|exception| {
            exception.kind == crate::kernel::policy::TOOLCHAIN_COMPONENT_UNAVAILABLE
                && exception.subject.ends_with("rust-toolchain.toml")
                && exception.detail.contains("rustfmt")
        }));
        let _ = crate::kernel::policy::drain();
    }

    fn make_component_archives(
        dir: &Path,
        components: &[&RustComponent],
        platform: Platform,
        rustlib_target: Option<&str>,
    ) -> Vec<PathBuf> {
        components
            .iter()
            .map(|component| {
                let root_name = format!(
                    "{}-{}-{}",
                    component.component,
                    RUST_VERSION,
                    platform.triple()
                );
                let root = dir.join(&root_name);
                let package = match component.component {
                    "rust-std" => root.join(format!("rust-std-{}", platform.triple())),
                    name => root.join(name),
                };
                fs::create_dir_all(&package).unwrap();
                match component.component {
                    "rustc" | "cargo" => {
                        fs::create_dir_all(package.join("bin")).unwrap();
                        fs::write(
                            package.join("bin").join(component.component),
                            component.component,
                        )
                        .unwrap();
                    }
                    "rust-std" => {
                        if let Some(target) = rustlib_target {
                            let rustlib = package.join("lib/rustlib").join(target);
                            fs::create_dir_all(&rustlib).unwrap();
                            fs::write(rustlib.join("marker"), b"synthetic").unwrap();
                        }
                    }
                    other => panic!("unexpected component {other}"),
                }
                let archive = dir.join(format!("{root_name}.tar.xz"));
                let status = std::process::Command::new("/usr/bin/tar")
                    .args(["-cJf"])
                    .arg(&archive)
                    .args(["-C"])
                    .arg(dir)
                    .arg(&root_name)
                    .status()
                    .unwrap();
                assert!(status.success());
                archive
            })
            .collect()
    }

    fn component_names(components: &[&'static RustComponent]) -> Vec<&'static str> {
        components
            .iter()
            .map(|component| component.component)
            .collect()
    }

    #[test]
    fn component_layout_is_validated_before_publication() {
        let platform = Platform::X86_64UnknownLinuxGnu;
        let components = rust_components(platform).unwrap();

        let correct = TempDir::new("tog-rust-layout-correct");
        let archives = make_component_archives(
            correct.path(),
            &components,
            platform,
            Some(platform.triple()),
        );
        let staged = correct.path().join("staged");
        fs::create_dir(&staged).unwrap();
        extract_rust_components(&staged, platform, &component_names(&components), &archives)
            .unwrap();
        assert!(staged.join("bin/rustc").is_file());
        assert!(staged.join("bin/cargo").is_file());
        assert!(staged
            .join(format!("lib/rustlib/{}", platform.triple()))
            .is_dir());

        let missing = TempDir::new("tog-rust-layout-missing");
        let archives = make_component_archives(missing.path(), &components, platform, None);
        let staged = missing.path().join("staged");
        fs::create_dir(&staged).unwrap();
        assert!(extract_rust_components(
            &staged,
            platform,
            &component_names(&components),
            &archives
        )
        .is_err());

        let wrong = TempDir::new("tog-rust-layout-wrong");
        let archives = make_component_archives(
            wrong.path(),
            &components,
            platform,
            Some(Platform::Aarch64AppleDarwin.triple()),
        );
        let staged = wrong.path().join("staged");
        fs::create_dir(&staged).unwrap();
        assert!(extract_rust_components(
            &staged,
            platform,
            &component_names(&components),
            &archives
        )
        .is_err());
    }

    fn make_crate(dir: &Path, name: &str, version: &str, symlink: bool) -> (PathBuf, String) {
        let root_name = format!("{name}-{version}");
        let root = dir.join(&root_name);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"tiny\"\n").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        if symlink {
            std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        }
        let archive = dir.join(format!("{root_name}.crate"));
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(dir)
            .arg(&root_name)
            .status()
            .unwrap();
        assert!(status.success());
        let hash = hex::encode(Sha256::digest(fs::read(&archive).unwrap()));
        (archive, hash)
    }

    /// A `cargo build` killed before its own cleanup leaves its scratch under
    /// `store/tmp`. `gc::collect` reclaims exactly `store/tmp/stage-*`, so the
    /// build scratch has to be named with that prefix or it leaks forever.
    #[test]
    fn a_leftover_cargo_build_scratch_is_swept_by_gc() {
        with_temp_store(|store, root| {
            // Through the same helper `build_sandboxed` uses, so a prefix
            // that drifts back out of the swept namespace fails here.
            let scratch = build_scratch(&store.root.join("tmp")).unwrap();
            let name = scratch.file_name().unwrap().to_str().unwrap().to_string();
            assert!(name.starts_with("stage-"), "{name}");
            fs::write(scratch.join("cargo-home"), b"leftover").unwrap();
            // Only stages older than a day are stale; a live build's scratch
            // is never swept out from under it.
            let old = SystemTime::now()
                .checked_sub(std::time::Duration::from_secs(2 * 24 * 60 * 60))
                .unwrap();
            fs::File::open(&scratch).unwrap().set_modified(old).unwrap();

            // A registered, resolvable root: the sweep refuses outright when
            // a recorded project cannot be resolved.
            let project = root.join("project");
            fs::create_dir_all(project.join(".tog/closures")).unwrap();
            fs::write(
                project.join(".tog/closures/cargo.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schema": "closure/1",
                    "ecosystem": "cargo",
                    "body": {},
                }))
                .unwrap(),
            )
            .unwrap();
            store.register_root(&project).unwrap();
            let mut out = Vec::new();
            let report =
                crate::kernel::gc::collect(store, crate::kernel::gc::Options::default(), &mut out)
                    .unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(report.stages, 1, "{text}");
            assert!(!scratch.exists(), "{text}");
        });
    }

    #[test]
    fn realizes_vendor_and_writes_complete_checksums() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        with_temp_store(|store, root| {
            let source = root.join("source");
            fs::create_dir_all(&source).unwrap();
            let (archive, hash) = make_crate(&source, "tiny", "1.0.0", false);
            let plan = CargoPlan {
                rust_version: "1.96.1".into(),
                crates: vec![CargoCrate {
                    name: "tiny".into(),
                    version: "1.0.0".into(),
                    sha256: hash.clone(),
                    url: format!("file://{}", archive.display()),
                    git: None,
                }],
                members: vec![],
            };
            let object = realize_vendor(store, &plan).unwrap();
            let crate_dir = object.join("tiny-1.0.0");
            assert_eq!(
                fs::read_to_string(crate_dir.join("src/lib.rs")).unwrap(),
                "pub fn answer() -> u32 { 42 }\n"
            );
            let checksum: serde_json::Value =
                serde_json::from_slice(&fs::read(crate_dir.join(".cargo-checksum.json")).unwrap())
                    .unwrap();
            assert_eq!(checksum["package"], hash);
            assert_eq!(
                checksum["files"]["src/lib.rs"],
                hex::encode(Sha256::digest(b"pub fn answer() -> u32 { 42 }\n"))
            );
            assert!(checksum["files"].get(".cargo-checksum.json").is_none());
        });
    }

    #[test]
    fn rejects_symlinked_crate_entries() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        with_temp_store(|store, root| {
            let source = root.join("source");
            fs::create_dir_all(&source).unwrap();
            let (archive, hash) = make_crate(&source, "tiny", "1.0.0", true);
            let plan = CargoPlan {
                rust_version: "1.96.1".into(),
                crates: vec![CargoCrate {
                    name: "tiny".into(),
                    version: "1.0.0".into(),
                    sha256: hash,
                    url: format!("file://{}", archive.display()),
                    git: None,
                }],
                members: vec![],
            };
            let error = realize_vendor(store, &plan).unwrap_err().to_string();
            assert!(error.contains("tiny@1.0.0"));
            assert!(error.contains("symlink"));
        });
    }

    /// A Cargo workspace member sends its closure and its record to the
    /// workspace root, not to the directory sync ran in, so the root gets the
    /// same check — before a cargo-home is projected into a workspace no root
    /// record can name and no sweep will protect.
    #[test]
    fn cargo_env_is_refused_for_a_root_that_cannot_be_registered() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-unrecordable");
        let root = temp.path().join("ws ");
        fs::create_dir_all(&root).unwrap();
        let plan = CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![],
            members: vec!["member".into()],
        };
        let error = project_cargo_env(
            &root,
            &temp.path().join("absent-rust"),
            &temp.path().join("absent-vendor"),
            &plan,
            &lock_digest("version = 4\n"),
            &selection(),
            &mut attribution,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            !root.join(".tog").exists(),
            "projected into a workspace no record can name"
        );
        attribution.discard();
    }

    #[test]
    fn projects_cargo_config_wrapper_and_closure() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-project");
        let project = temp.path().join("project");
        let rust = temp.path().join("objects/rust-id");
        let vendor = temp.path().join("objects/vendor-id");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(rust.join("bin")).unwrap();
        fs::create_dir_all(&vendor).unwrap();
        fs::write(rust.join("bin/cargo"), "fake cargo").unwrap();
        let plan = CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![],
            members: vec!["app".into()],
        };
        let digest = lock_digest("version = 4\n");
        project_cargo_env(
            &project,
            &rust,
            &vendor,
            &plan,
            &digest,
            &selection(),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let home = project.join(".tog/cargo-home").canonicalize().unwrap();
        let vendor = vendor.canonicalize().unwrap();
        let rust = rust.canonicalize().unwrap();
        let config = fs::read_to_string(home.join("tog-config.toml")).unwrap();
        assert!(config.contains("[source.crates-io]"));
        assert!(config.contains("replace-with = \"tog-vendor\""));
        assert!(config.contains(&format!("directory = \"{}\"", vendor.display())));
        assert!(config.contains("[net]\noffline = true"));

        let wrapper_path = home.join("bin/cargo");
        let wrapper = fs::read_to_string(&wrapper_path).unwrap();
        assert!(wrapper.contains(&format!("export CARGO_HOME=\"{}\"", home.display())));
        assert!(wrapper.contains("unset RUSTUP_HOME RUSTUP_TOOLCHAIN"));
        assert!(wrapper.contains("--frozen --config"));
        assert!(wrapper.contains(&format!("\"{}\"", rust.join("bin/cargo").display())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(wrapper_path).unwrap().permissions().mode() & 0o111,
                0o111
            );
        }

        let closure = crate::comforter::read_closure(&project, "cargo").unwrap();
        assert_eq!(closure["rust_object"]["id"], "rust-id");
        assert_eq!(closure["vendor_object"]["id"], "vendor-id");
        assert_eq!(closure["cargo_lock_sha256"], digest);
        assert_eq!(closure["plan"]["members"][0], "app");
        // The closure states the selection it was realized from and refers
        // to the runtime object directly, so it needs no seeding from its
        // plan the next time this project is resolved, and a GC keeps the
        // toolchain alive by that reference.
        let selected = selection();
        assert_eq!(closure["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(closure["toolchain"]["ecosystem"], "cargo");
        assert_eq!(closure["toolchain"]["release"], selected.bundle.release);
        assert_eq!(closure["toolchain"]["versions"]["rustc"], RUST_VERSION);
        assert_eq!(closure["runtime_object"]["id"], "rust-id");
        assert_eq!(
            closure["runtime_object"]["id"],
            closure["rust_object"]["id"]
        );
        // Wrapper enforces the pinned compiler and refuses --config takeover.
        assert!(wrapper.contains(&format!(
            "export RUSTC=\"{}\"",
            rust.join("bin/rustc").display()
        )));
        assert!(wrapper.contains("--config|--config=*"));
    }

    #[test]
    fn projection_refuses_symlinked_bin_escape() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-symlink-bin");
        let project = temp.path().join("project");
        let outside = temp.path().join("outside");
        let rust = temp.path().join("objects/rust-id");
        let vendor = temp.path().join("objects/vendor-id");
        fs::create_dir_all(project.join(".tog/cargo-home")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(rust.join("bin")).unwrap();
        fs::create_dir_all(&vendor).unwrap();
        std::os::unix::fs::symlink(&outside, project.join(".tog/cargo-home/bin")).unwrap();
        let plan = CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![],
            members: vec![],
        };
        let result = project_cargo_env(
            &project,
            &rust,
            &vendor,
            &plan,
            "digest",
            &selection(),
            &mut attribution,
        );
        assert!(
            result.is_err(),
            "symlinked bin must not carry writes outside the project"
        );
        assert!(!outside.join("cargo").exists());
        attribution.discard();
    }

    /// With complete object ids the strict publication path runs, and the
    /// durable root/2 record `project_cargo_env` publishes names exactly the
    /// Rust object and the vendor object it was handed: nothing inferred
    /// from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _store_env = STORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let temp = TempDir::new("tog-cargo-closure-refs");
        let store_root = temp.path().join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store {
            root: store_root.canonicalize().unwrap(),
        };
        let rust_id = format!("{}-rust-{RUST_VERSION}", "1".repeat(40));
        let vendor_id = format!("{}-vendor-0", "2".repeat(40));
        for id in [&rust_id, &vendor_id] {
            let object = store.object_path(id);
            fs::create_dir_all(&object).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({ "id": id })).unwrap(),
            )
            .unwrap();
        }
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let plan = CargoPlan {
            rust_version: RUST_VERSION.into(),
            crates: vec![],
            members: vec!["app".into()],
        };
        project_cargo_env(
            &project,
            &store.object_path(&rust_id),
            &store.object_path(&vendor_id),
            &plan,
            &lock_digest("version = 4\n"),
            &selection(),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(record.objects, BTreeSet::from([rust_id, vendor_id]));
        assert!(record.projections.is_empty(), "{:?}", record.projections);

        // `gc --register` rebuilds the same record from this closure alone.
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
    }

    #[test]
    fn build_rejects_user_config_flag() {
        for bad in ["--config", "--config=net.offline=false"] {
            let error = build_sandboxed(
                Platform::Aarch64AppleDarwin,
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                &[bad.to_string()],
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("--config is managed by tog"),
                "{bad}: {error}"
            );
        }
    }
}

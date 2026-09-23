use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use tog::kernel::platform::Platform;

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn run(binary: &Path, project: &Path, store: &Path, args: &[&str], tmp: &Path) -> Output {
    run_from(binary, project, store, args, tmp)
}

fn run_from(binary: &Path, current_dir: &Path, store: &Path, args: &[&str], tmp: &Path) -> Output {
    Command::new(binary)
        .current_dir(current_dir)
        .env("TOG_STORE", store)
        .env("TMPDIR", tmp)
        .args(args)
        .output()
        .unwrap()
}

fn assert_ok(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore]
fn pnpm_and_yarn_lockfiles_import_end_to_end() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("scratch/tmp");
    fs::create_dir_all(&scratch).unwrap();
    let store = scratch.join("nx7-store");
    let binary = Path::new(env!("CARGO_BIN_EXE_tog"));

    for fixture in ["proj-pnpm", "proj-pnpm-ws", "proj-yarn1"] {
        let project = scratch.join(format!("nx7-{fixture}"));
        if project.exists() {
            fs::remove_dir_all(&project).unwrap();
        }
        copy_tree(&root.join("tests/fixtures").join(fixture), &project);

        let synced = run(binary, &project, &store, &["sync"], &scratch);
        assert_ok(&synced, &format!("sync {fixture}"));
        let closure = fs::read_to_string(project.join(".tog/closures/node.json")).unwrap();
        let expected_source = if fixture == "proj-yarn1" {
            "yarn.lock"
        } else {
            "pnpm-lock.yaml"
        };
        assert!(closure.contains(&format!("\"lock_source\": \"{expected_source}\"")));

        let check = run(
            binary,
            &project,
            &store,
            &[
                "run",
                "node",
                "-e",
                "if (!require('is-odd')(3)) process.exit(1)",
            ],
            &scratch,
        );
        assert_ok(&check, &format!("is-odd from {fixture}"));

        if fixture == "proj-pnpm-ws" {
            let workspace = run(
                binary,
                &project,
                &store,
                &[
                    "run",
                    "node",
                    "-e",
                    "if (!require('@fixture/lib')(3)) process.exit(1)",
                ],
                &scratch,
            );
            assert_ok(&workspace, "workspace link");

            let workspace_dir = project.join("packages/lib");
            let workspace_dep = run_from(
                binary,
                &workspace_dir,
                &store,
                &[
                    "run",
                    "node",
                    "-e",
                    "if (require('is-number/package.json').version !== '7.0.0') process.exit(1)",
                ],
                &scratch,
            );
            assert_ok(&workspace_dep, "workspace-local is-number");

            let root_dep = run(
                binary,
                &project,
                &store,
                &[
                    "run",
                    "node",
                    "-e",
                    "if (require('is-number/package.json').version !== '6.0.0') process.exit(1)",
                ],
                &scratch,
            );
            assert_ok(&root_dep, "root is-number");
        }
    }
}

/// Local `file:` packages run under the pinned Node and see the versions the
/// lock gives them, resolved from their real paths: one inside the importer
/// that depends on it, one inside a different importer. Both need
/// is-number@6 while the root has 7.
#[test]
#[ignore]
fn pnpm_local_packages_resolve_their_dependencies_from_their_real_paths() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("scratch/tmp");
    fs::create_dir_all(&scratch).unwrap();
    let store = scratch.join("nx7-store");
    let binary = Path::new(env!("CARGO_BIN_EXE_tog"));
    let project = scratch.join("nx7-proj-pnpm-local");
    if project.exists() {
        fs::remove_dir_all(&project).unwrap();
    }
    copy_tree(&root.join("tests/fixtures/proj-pnpm-local"), &project);
    assert_ok(&run(binary, &project, &store, &["sync"], &scratch), "sync");

    let app = project.join("packages/app");
    let check = run_from(
        binary,
        &app,
        &store,
        &[
            "run",
            "node",
            "-e",
            "const same = require('local-same'), cross = require('local-cross'); \
             if (same !== '6.0.0' || cross !== '6.0.0') { console.error(same, cross); process.exit(1) }",
        ],
        &scratch,
    );
    assert_ok(&check, "local packages see is-number@6");
    let root_check = run(
        binary,
        &project,
        &store,
        &[
            "run",
            "node",
            "-e",
            "if (require('is-number/package.json').version !== '7.0.0') process.exit(1)",
        ],
        &scratch,
    );
    assert_ok(&root_check, "the root keeps is-number@7");
    for source in ["packages/app/vendor/same", "packages/lib/vendor/cross"] {
        assert!(
            !project.join(source).join("node_modules").exists(),
            "nothing may be written into {source}"
        );
    }
}

const SRI: &str =
    "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

fn scratch_project(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tog-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn node_version() -> &'static str {
    tog::tailors::node::node_pin(Platform::X86_64UnknownLinuxGnu)
        .unwrap()
        .version
}

/// vitejs/vite's shape (#50): a workspace importer depends on `file:` a
/// directory that is itself an importer, whose own `file:` dependency then
/// was planted at `<link>/node_modules/...`. Projection created that path
/// through the link, i.e. a real `node_modules` directory inside the user's
/// source tree, and then refused to project the importer's own
/// `node_modules` symlink over it. pnpm installs each importer's
/// dependencies into that importer's own `node_modules`; nothing is ever
/// written beneath a link.
#[test]
fn pnpm_links_never_plant_packages_inside_the_linked_source_directory() {
    let dir = scratch_project("pnpm-link-nesting");
    for sub in ["license/dep-mit", "license/dep-nested", "ws/vendor/a"] {
        fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let lock = format!(
        r#"lockfileVersion: '9.0'
importers:
  .: {{}}
  license:
    dependencies:
      '@t/dep-mit':
        specifier: file:./dep-mit
        version: file:license/dep-mit
  license/dep-mit:
    dependencies:
      '@t/dep-nested':
        specifier: file:../dep-nested
        version: file:license/dep-nested
  license/dep-nested: {{}}
  ws:
    dependencies:
      a:
        specifier: file:./vendor/a
        version: file:ws/vendor/a
packages:
  '@t/dep-mit@file:license/dep-mit':
    resolution: {{directory: license/dep-mit, type: directory}}
  '@t/dep-nested@file:license/dep-nested':
    resolution: {{directory: license/dep-nested, type: directory}}
  a@file:ws/vendor/a:
    resolution: {{directory: ws/vendor/a, type: directory}}
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  '@t/dep-mit@file:license/dep-mit':
    dependencies:
      '@t/dep-nested': file:license/dep-nested
  '@t/dep-nested@file:license/dep-nested': {{}}
  a@file:ws/vendor/a:
    dependencies:
      b: 1.0.0
  b@1.0.0: {{}}
"#
    );
    let plan = tog::tailors::node::lock_import::plan_pnpm(
        Platform::X86_64UnknownLinuxGnu,
        &lock,
        &dir,
        node_version(),
    )
    .unwrap();
    let link_paths = plan
        .links
        .iter()
        .map(|link| link.path.as_str())
        .collect::<Vec<_>>();
    for path in plan
        .packages
        .iter()
        .map(|package| package.path.as_str())
        .chain(link_paths.iter().copied())
    {
        for link in &link_paths {
            assert!(
                !path.starts_with(&format!("{link}/")),
                "{path} is inside the linked source directory {link}: {:?}",
                plan.links
            );
        }
    }
    // The importer's own dependency is projected from its own node_modules.
    assert!(
        plan.links.iter().any(
            |link| link.path == "license/dep-mit/node_modules/@t/dep-nested"
                && link.target == "license/dep-nested"
        ),
        "{:?}",
        plan.links
    );
    // A local package that is not an importer still gets its registry
    // dependency, placed where Node finds it from the package's real path.
    assert!(
        plan.packages.iter().any(|package| package.name == "b"),
        "{:?}",
        plan.packages
    );
    let _ = fs::remove_dir_all(dir);
}

fn plan_local(
    name: &str,
    dirs: &[&str],
    lock: &str,
) -> std::io::Result<tog::tailors::node::NpmPlan> {
    let dir = scratch_project(name);
    for sub in dirs {
        fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let plan = tog::tailors::node::lock_import::plan_pnpm(
        Platform::X86_64UnknownLinuxGnu,
        lock,
        &dir,
        node_version(),
    );
    let _ = fs::remove_dir_all(dir);
    plan
}

/// A local package's dependencies go where Node finds them from the
/// package's real path, not from wherever the link to it sits.
#[test]
fn local_package_dependencies_follow_the_real_path_lookup_chain() {
    // The link is hoisted to node_modules/a because a registry package
    // (host) depends on it; a needs b@2 while the root has b@1. Placing b@2
    // under host would leave Node, resolving from vendor/a, on the root b@1.
    let hoisted = format!(
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      b:
        specifier: 1.0.0
        version: 1.0.0
      host:
        specifier: 1.0.0
        version: 1.0.0
packages:
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
  b@2.0.0:
    resolution: {{integrity: {SRI}}}
  host@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  b@1.0.0: {{}}
  b@2.0.0: {{}}
  host@1.0.0:
    dependencies:
      a: file:vendor/a
  a@file:vendor/a:
    dependencies:
      b: 2.0.0
"#
    );
    let error = plan_local("local-hoisted", &["vendor/a"], &hoisted).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("needed by the local package vendor/a"),
        "{error}"
    );

    // Same shape, but the root already links `a` elsewhere, so the second
    // link would nest inside host's directory: a store object.
    let nested = hoisted
        .replace(
            "      host:\n",
            "      a:\n        specifier: link:vendor/other\n        version: link:vendor/other\n      host:\n",
        )
        .replace("      b: 2.0.0\n", "      b: 1.0.0\n");
    let error = plan_local("local-nested", &["vendor/a", "vendor/other"], &nested).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("would be planted inside the package node_modules/host"),
        "{error}"
    );

    // Cross-workspace: app links a package that lives inside the lib
    // importer. Node looks in packages/lib/node_modules, then the root.
    let cross = format!(
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      b:
        specifier: 1.0.0
        version: 1.0.0
  packages/app:
    dependencies:
      cross:
        specifier: file:../lib/vendor/cross
        version: file:packages/lib/vendor/cross
  packages/lib: {{}}
packages:
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
  b@2.0.0:
    resolution: {{integrity: {SRI}}}
  cross@file:packages/lib/vendor/cross:
    resolution: {{directory: packages/lib/vendor/cross, type: directory}}
snapshots:
  b@1.0.0: {{}}
  b@2.0.0: {{}}
  cross@file:packages/lib/vendor/cross:
    dependencies:
      b: 2.0.0
"#
    );
    let plan = plan_local(
        "local-cross",
        &["packages/app", "packages/lib/vendor/cross"],
        &cross,
    )
    .unwrap();
    let placed = |path: &str| {
        plan.packages
            .iter()
            .find(|package| package.path == path)
            .map(|package| package.version.as_str())
    };
    assert_eq!(
        placed("packages/lib/node_modules/b"),
        Some("2.0.0"),
        "{:?}",
        plan.packages
    );
    assert_eq!(
        placed("packages/app/node_modules/b"),
        None,
        "{:?}",
        plan.packages
    );
    assert_eq!(placed("node_modules/b"), Some("1.0.0"));
}

/// The only place a local package inside app can get is-number@6 is app's
/// own node_modules, which would shadow the is-number@7 app itself declares.
/// That layout is not representable, so it is refused, not half-projected.
#[test]
fn a_local_package_may_not_shadow_its_importers_own_dependency() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lock = fs::read_to_string(root.join("tests/fixtures/proj-pnpm-local/pnpm-lock.yaml"))
        .unwrap()
        .replace(
            "  packages/app:\n    dependencies:\n",
            "  packages/app:\n    dependencies:\n      is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n",
        );
    let error = plan_local(
        "local-shadow",
        &["packages/app/vendor/same", "packages/lib/vendor/cross"],
        &lock,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("importer packages/app needs its own is-number"),
        "{error}"
    );
}

fn write_patch(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join("patches").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    hex::encode(Sha256::digest(bytes))
}

/// mermaid-js/mermaid's shape (#52): `patchedDependencies` keyed by a bare
/// package name, which pnpm applies to every locked version, next to a
/// version range and an exact key. pnpm picks exact over range over bare
/// name, and writes the hash it applied into each snapshot key.
fn patched_lock(
    fastdom: &str,
    rough: &str,
    rough_exact: &str,
    fastdom_11_recorded: &str,
) -> String {
    format!(
        r#"lockfileVersion: '9.0'
patchedDependencies:
  fastdom:
    hash: {fastdom}
    path: patches/fastdom.patch
  roughjs@^4.6.0:
    hash: {rough}
    path: patches/roughjs.patch
  roughjs@4.6.6:
    hash: {rough_exact}
    path: patches/roughjs@4.6.6.patch
importers:
  .:
    dependencies:
      fastdom:
        specifier: 1.0.12
        version: 1.0.12(patch_hash={fastdom})
      old-fastdom:
        specifier: npm:fastdom@1.0.11
        version: fastdom@1.0.11(patch_hash={fastdom_11_recorded})
      roughjs:
        specifier: 4.6.5
        version: 4.6.5(patch_hash={rough})
      rough-exact:
        specifier: npm:roughjs@4.6.6
        version: roughjs@4.6.6(patch_hash={rough_exact})
packages:
  fastdom@1.0.11:
    resolution: {{integrity: {SRI}}}
  fastdom@1.0.12:
    resolution: {{integrity: {SRI}}}
  roughjs@4.6.5:
    resolution: {{integrity: {SRI}}}
  roughjs@4.6.6:
    resolution: {{integrity: {SRI}}}
snapshots:
  fastdom@1.0.11(patch_hash={fastdom_11_recorded}): {{}}
  fastdom@1.0.12(patch_hash={fastdom}): {{}}
  roughjs@4.6.5(patch_hash={rough}): {{}}
  roughjs@4.6.6(patch_hash={rough_exact}): {{}}
"#
    )
}

#[test]
fn pnpm_bare_name_and_range_patches_apply_where_pnpm_applied_them() {
    let dir = scratch_project("pnpm-bare-patch");
    let fastdom = write_patch(
        &dir,
        "fastdom.patch",
        b"diff --git a/fastdom.js b/fastdom.js\n",
    );
    let rough = write_patch(&dir, "roughjs.patch", b"diff --git a/rough.js b/rough.js\n");
    let rough_exact = write_patch(&dir, "roughjs@4.6.6.patch", b"diff --git a/exact b/exact\n");
    let plan_for = |lock: &str| {
        tog::tailors::node::lock_import::plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            &dir,
            node_version(),
        )
    };
    let plan = plan_for(&patched_lock(&fastdom, &rough, &rough_exact, &fastdom)).unwrap();
    let patch_of = |name: &str, version: &str| {
        let package = plan
            .packages
            .iter()
            .find(|package| package.name == name && package.version == version)
            .unwrap_or_else(|| panic!("{name}@{version} missing: {:?}", plan.packages));
        package.patch.as_ref().map(|patch| patch.hash.clone())
    };
    // The bare name reaches every locked version.
    assert_eq!(patch_of("fastdom", "1.0.11"), Some(fastdom.clone()));
    assert_eq!(patch_of("fastdom", "1.0.12"), Some(fastdom.clone()));
    // The range applies where the lock says pnpm applied it; the exact key
    // wins over the range for its own version.
    assert_eq!(patch_of("roughjs", "4.6.5"), Some(rough.clone()));
    assert_eq!(patch_of("roughjs", "4.6.6"), Some(rough_exact.clone()));

    // The patch bytes stay bound: an edited patch file is refused.
    fs::write(dir.join("patches/fastdom.patch"), b"changed").unwrap();
    let error = plan_for(&patched_lock(&fastdom, &rough, &rough_exact, &fastdom)).unwrap_err();
    assert!(
        error.to_string().contains("patch fastdom hash mismatch"),
        "{error}"
    );
    write_patch(
        &dir,
        "fastdom.patch",
        b"diff --git a/fastdom.js b/fastdom.js\n",
    );

    // A snapshot that records a different patch than tog would select is a
    // lock tog cannot honor faithfully.
    let other = "0".repeat(64);
    let error = plan_for(&patched_lock(&fastdom, &rough, &rough_exact, &other)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("records fastdom@1.0.11(patch_hash="),
        "{error}"
    );

    // A recorded hash is not a license to skip the range: roughjs@5.0.0
    // carrying the ^4.6.0 patch's hash is outside that range, so no rule
    // selects it and the lock is refused.
    let lock = patched_lock(&fastdom, &rough, &rough_exact, &fastdom).replace("4.6.5", "5.0.0");
    let error = plan_for(&lock).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("records roughjs@5.0.0(patch_hash=")
            && error.to_string().contains("selects no patch"),
        "{error}"
    );
    let _ = fs::remove_dir_all(dir);
}

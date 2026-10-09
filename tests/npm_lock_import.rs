// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use sha2::{Digest, Sha256};
use tog::kernel::platform::Platform;

mod common;

use common::{assert_ok, command, copy_tree, fixture, text, tog, warm_store, TempDir};

/// The binary with its `TMPDIR` inside the scratch home, so whatever a
/// sync stages there is removed with the scratch directory.
fn run(cwd: &Path, home: &Path, store: &Path, args: &[&str]) -> Output {
    command(cwd, home, store)
        .env("TMPDIR", home)
        .args(args)
        .output()
        .unwrap()
}

/// A Node project below a directory tog may search but not list (mode
/// 0111) syncs and runs: every ancestor walk steps through that directory
/// by descriptor instead of listing it (#480, #527).
#[test]
#[ignore]
fn npm_sync_and_run_under_a_search_only_parent() {
    use std::os::unix::fs::PermissionsExt;
    struct Restore<'a>(&'a Path);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp = TempDir::new("npm-search-only");
    let scratch = temp.path();
    let store = warm_store(&temp);
    let parent = scratch.join("search-only");
    let project = parent.join("proj");
    copy_tree(&root.join("tests/fixtures/proj-npm"), &project);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o111)).unwrap();
    // Before the scratch directory goes, so it can be removed.
    let _restore = Restore(&parent);
    assert!(fs::read_dir(&parent).is_err(), "the parent is not listable");

    assert_ok(
        run(&project, scratch, &store, &["sync"]),
        "sync under a search-only parent",
    );
    let check = run(
        &project,
        scratch,
        &store,
        &[
            "run",
            "node",
            "-e",
            "if (!require('is-odd')(3)) process.exit(1)",
        ],
    );
    assert_ok(check, "is-odd under a search-only parent");
}

#[test]
#[ignore]
fn pnpm_and_yarn_lockfiles_import_end_to_end() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp = TempDir::new("npm-lock-import");
    let scratch = temp.path();
    let store = warm_store(&temp);

    for fixture in ["proj-pnpm", "proj-pnpm-ws", "proj-yarn1"] {
        let project = scratch.join(format!("nx7-{fixture}"));
        copy_tree(&root.join("tests/fixtures").join(fixture), &project);

        let synced = run(&project, scratch, &store, &["sync"]);
        assert_ok(synced, &format!("sync {fixture}"));
        let closure = fs::read_to_string(project.join(".tog/closures/node.json")).unwrap();
        let expected_source = if fixture == "proj-yarn1" {
            "yarn.lock"
        } else {
            "pnpm-lock.yaml"
        };
        assert!(closure.contains(&format!("\"lock_source\": \"{expected_source}\"")));

        let check = run(
            &project,
            scratch,
            &store,
            &[
                "run",
                "node",
                "-e",
                "if (!require('is-odd')(3)) process.exit(1)",
            ],
        );
        assert_ok(check, &format!("is-odd from {fixture}"));

        if fixture == "proj-pnpm-ws" {
            let workspace = run(
                &project,
                scratch,
                &store,
                &[
                    "run",
                    "node",
                    "-e",
                    "if (!require('@fixture/lib')(3)) process.exit(1)",
                ],
            );
            assert_ok(workspace, "workspace link");

            let workspace_dir = project.join("packages/lib");
            let workspace_dep = run(
                &workspace_dir,
                scratch,
                &store,
                &[
                    "run",
                    "node",
                    "-e",
                    "if (require('is-number/package.json').version !== '7.0.0') process.exit(1)",
                ],
            );
            assert_ok(workspace_dep, "workspace-local is-number");

            let root_dep = run(
                &project,
                scratch,
                &store,
                &[
                    "run",
                    "node",
                    "-e",
                    "if (require('is-number/package.json').version !== '6.0.0') process.exit(1)",
                ],
            );
            assert_ok(root_dep, "root is-number");
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
    let temp = TempDir::new("npm-lock-import");
    let scratch = temp.path();
    let store = warm_store(&temp);
    let project = scratch.join("nx7-proj-pnpm-local");
    copy_tree(&root.join("tests/fixtures/proj-pnpm-local"), &project);
    assert_ok(run(&project, scratch, &store, &["sync"]), "sync");

    let app = project.join("packages/app");
    let check = run(
        &app,
        scratch,
        &store,
        &[
            "run",
            "node",
            "-e",
            "const same = require('local-same'), cross = require('local-cross'); \
             if (same !== '6.0.0' || cross !== '6.0.0') { console.error(same, cross); process.exit(1) }",
        ],
    );
    assert_ok(check, "local packages see is-number@6");
    let root_check = run(
        &project,
        scratch,
        &store,
        &[
            "run",
            "node",
            "-e",
            "if (require('is-number/package.json').version !== '7.0.0') process.exit(1)",
        ],
    );
    assert_ok(root_check, "the root keeps is-number@7");
    for source in ["packages/app/vendor/same", "packages/lib/vendor/cross"] {
        assert!(
            !project.join(source).join("node_modules").exists(),
            "nothing may be written into {source}"
        );
    }
}

const SRI: &str =
    "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

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
    let temp = TempDir::new("pnpm-link-nesting");
    let dir = temp.path();
    for sub in ["license/dep-mit", "license/dep-nested", "ws/vendor/a"] {
        package_dir(&dir.join(sub));
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
        &tog::kernel::fsroot::ProjectRoot::open(dir).unwrap(),
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
}

/// A local package directory: pnpm reads its package.json, and a `file:`
/// package is packed from it.
fn package_dir(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let name = dir.file_name().unwrap().to_str().unwrap();
    fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    )
    .unwrap();
}

fn plan_local(
    name: &str,
    dirs: &[&str],
    lock: &str,
) -> std::io::Result<tog::tailors::node::NpmPlan> {
    let temp = TempDir::new(name);
    let dir = temp.path();
    for sub in dirs {
        package_dir(&dir.join(sub));
    }

    tog::tailors::node::lock_import::plan_pnpm(
        Platform::X86_64UnknownLinuxGnu,
        lock,
        &tog::kernel::fsroot::ProjectRoot::open(dir).unwrap(),
        node_version(),
    )
}

/// A `file:` directory package is a copy with its own node_modules, as
/// pnpm installs it (#188), so its dependency may differ from the version
/// the root needs. A `link:` package resolves from its source directory
/// instead, so its dependencies go where Node finds them from there.
#[test]
fn local_package_dependencies_follow_the_real_path_lookup_chain() {
    // `a` is hoisted to node_modules/a because a registry package (host)
    // depends on it; a needs b@2 while the root has b@1.
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
    let plan = plan_local("local-hoisted", &["vendor/a"], &hoisted).unwrap();
    let placed = |path: &str| {
        plan.packages
            .iter()
            .find(|package| package.path == path)
            .map(|package| (package.version.as_str(), package.url.as_str()))
    };
    assert_eq!(placed("node_modules/a"), Some(("1.0.0", "file:vendor/a")));
    assert_eq!(
        placed("node_modules/a/node_modules/b").map(|(version, _)| version),
        Some("2.0.0"),
        "{:?}",
        plan.packages
    );
    assert_eq!(
        placed("node_modules/b").map(|(version, _)| version),
        Some("1.0.0")
    );
    assert!(plan.links.is_empty(), "{:?}", plan.links);

    // The same shape through `link:`: the link resolves from vendor/a,
    // where only the root's node_modules is on the chain.
    let linked = hoisted
        .replace("      a: file:vendor/a\n", "      a: link:vendor/a\n")
        .replace("  a@file:vendor/a:\n", "  a@link:vendor/a:\n");
    let error = plan_local("local-linked", &["vendor/a"], &linked)
        .unwrap_err()
        .to_string();
    for part in [
        "the linked package vendor/a needs b@2.0.0",
        "the root importer needs b@1.0.0",
        "reaches node_modules/b first",
        "A linked package resolves its dependencies from its source directory",
    ] {
        assert!(error.contains(part), "{part}: {error}");
    }

    // Same shape, but the root already links `a` elsewhere, so the second
    // link would nest inside host's directory: a store object.
    let nested = linked
        .replace(
            "      host:\n",
            "      a:\n        specifier: link:vendor/other\n        version: link:vendor/other\n      host:\n",
        )
        .replace("      b: 2.0.0\n", "      b: 1.0.0\n");
    let plan = plan_local("local-nested", &["vendor/a", "vendor/other"], &nested).unwrap();
    assert!(
        plan.links.iter().any(
            |link| link.path == "node_modules/host/node_modules/a" && link.target == "vendor/a"
        ),
        "{:?}",
        plan.links
    );
    // host asked for the link, so host is what turns the projection into a
    // copy the link can be planted in.
    let needs_workspace: Vec<&str> = plan
        .packages
        .iter()
        .filter(|package| package.needs_workspace)
        .map(|package| package.path.as_str())
        .collect();
    assert_eq!(needs_workspace, ["node_modules/host"]);

    // Cross-workspace: app depends on a `file:` package that lives inside
    // the lib importer. The copy carries its own b@2.
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
        placed("node_modules/cross/node_modules/b"),
        Some("2.0.0"),
        "{:?}",
        plan.packages
    );
    assert_eq!(placed("packages/lib/node_modules/b"), None);
    assert_eq!(placed("node_modules/b"), Some("1.0.0"));
}

/// app declares is-number@7 and the `file:` package inside app needs
/// is-number@6. As a link, Node resolving from the package's source would
/// reach app's own node_modules first. As the copy pnpm makes, the package
/// carries is-number@6 in its own node_modules (#188).
#[test]
fn a_local_package_gets_its_own_copy_of_a_conflicting_dependency() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lock = fs::read_to_string(root.join("tests/fixtures/proj-pnpm-local/pnpm-lock.yaml"))
        .unwrap()
        .replace(
            "  packages/app:\n    dependencies:\n",
            "  packages/app:\n    dependencies:\n      is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n",
        );
    let plan = plan_local(
        "local-shadow",
        &["packages/app/vendor/same", "packages/lib/vendor/cross"],
        &lock,
    )
    .unwrap();
    let version_at = |path: &str| {
        plan.packages
            .iter()
            .find(|package| package.path == path)
            .map(|package| package.version.as_str())
    };
    assert_eq!(version_at("node_modules/is-number"), Some("7.0.0"));
    let same = plan
        .packages
        .iter()
        .find(|package| package.url == "file:packages/app/vendor/same")
        .expect("the file: package is a package");
    assert_eq!(
        version_at(&format!("{}/node_modules/is-number", same.path)),
        Some("6.0.0"),
        "{:?}",
        plan.packages
    );
}

/// An optional dependency skipped for the host platform is never placed,
/// so it is no requirement: the root's darwin-only b@2 must not conflict
/// with the b@1 a registry package hoists to the root.
#[test]
fn a_platform_skipped_optional_dependency_is_no_requirement() {
    let lock = format!(
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      host:
        specifier: 1.0.0
        version: 1.0.0
    optionalDependencies:
      b:
        specifier: 2.0.0
        version: 2.0.0
packages:
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
  b@2.0.0:
    resolution: {{integrity: {SRI}}}
    os: [darwin]
  host@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  b@1.0.0: {{}}
  b@2.0.0:
    optional: true
  host@1.0.0:
    dependencies:
      b: 1.0.0
"#
    );
    let plan = plan_local("optional-skip", &[], &lock).unwrap();
    assert!(
        plan.packages
            .iter()
            .any(|package| package.path == "node_modules/b" && package.version == "1.0.0"),
        "{:?}",
        plan.packages
    );
}

/// `foo` and `foo@*` both patch every version; pnpm keeps the one its config
/// lists last, an order the lockfile's sorted map loses. The hash pnpm
/// recorded on the snapshot says which one it applied; without it the lock
/// is refused rather than guessed.
#[test]
fn two_every_version_patch_keys_are_settled_by_the_recorded_hash() {
    let temp = TempDir::new("pnpm-every-version-twice");
    let dir = temp.path();
    let bare = write_patch(dir, "foo.patch", b"diff --git a/bare b/bare\n");
    let star = write_patch(dir, "foo-star.patch", b"diff --git a/star b/star\n");
    let lock = |recorded: &str| {
        let suffix = if recorded.is_empty() {
            String::new()
        } else {
            format!("(patch_hash={recorded})")
        };
        format!(
            r#"lockfileVersion: '9.0'
patchedDependencies:
  foo:
    hash: {bare}
    path: patches/foo.patch
  foo@*:
    hash: {star}
    path: patches/foo-star.patch
importers:
  .:
    dependencies:
      foo:
        specifier: 1.0.0
        version: 1.0.0{suffix}
packages:
  foo@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  foo@1.0.0{suffix}: {{}}
"#
        )
    };
    let plan_for = |lock: &str| {
        tog::tailors::node::lock_import::plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            &tog::kernel::fsroot::ProjectRoot::open(dir).unwrap(),
            node_version(),
        )
    };
    for chosen in [&bare, &star] {
        let plan = plan_for(&lock(chosen)).unwrap();
        assert_eq!(
            plan.packages[0].patch.as_ref().map(|patch| &patch.hash),
            Some(chosen)
        );
    }
    let error = plan_for(&lock("")).unwrap_err().to_string();
    assert!(
        error.contains("each patch every version of foo with a different patch"),
        "{error}"
    );
}

/// pnpm's sha256 hash reads patches CRLF-blind, so an LF file and its CRLF
/// twin share one hash while the environment would bind different bytes.
/// Two every-version keys like that are one patch only if the bytes agree.
#[test]
fn every_version_patch_keys_sharing_a_hash_must_share_their_bytes() {
    let temp = TempDir::new("pnpm-every-version-crlf");
    let dir = temp.path();
    let hash = write_patch(dir, "foo.patch", b"diff --git a/x b/x\n");
    write_patch(dir, "foo-star.patch", b"diff --git a/x b/x\r\n");
    write_patch(dir, "foo-same.patch", b"diff --git a/x b/x\n");
    let lock = |star_path: &str, recorded: bool| {
        let suffix = if recorded {
            format!("(patch_hash={hash})")
        } else {
            String::new()
        };
        format!(
            r#"lockfileVersion: '9.0'
patchedDependencies:
  foo:
    hash: {hash}
    path: patches/foo.patch
  foo@*:
    hash: {hash}
    path: patches/{star_path}
importers:
  .:
    dependencies:
      foo:
        specifier: 1.0.0
        version: 1.0.0{suffix}
packages:
  foo@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  foo@1.0.0{suffix}: {{}}
"#
        )
    };
    let plan_for = |lock: &str| {
        tog::tailors::node::lock_import::plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            &tog::kernel::fsroot::ProjectRoot::open(dir).unwrap(),
            node_version(),
        )
    };
    for recorded in [true, false] {
        let error = plan_for(&lock("foo-star.patch", recorded))
            .unwrap_err()
            .to_string();
        assert!(error.contains("foo, foo@*"), "{error}");
        assert!(error.contains("different"), "{error}");
        // Identical bytes under the same hash are one patch.
        let plan = plan_for(&lock("foo-same.patch", recorded)).unwrap();
        assert_eq!(
            plan.packages[0].patch.as_ref().map(|patch| &patch.hash),
            Some(&hash)
        );
    }
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
    let temp = TempDir::new("pnpm-bare-patch");
    let dir = temp.path();
    let fastdom = write_patch(
        dir,
        "fastdom.patch",
        b"diff --git a/fastdom.js b/fastdom.js\n",
    );
    let rough = write_patch(dir, "roughjs.patch", b"diff --git a/rough.js b/rough.js\n");
    let rough_exact = write_patch(dir, "roughjs@4.6.6.patch", b"diff --git a/exact b/exact\n");
    let plan_for = |lock: &str| {
        tog::tailors::node::lock_import::plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            &tog::kernel::fsroot::ProjectRoot::open(dir).unwrap(),
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
        dir,
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
}

/// A copy of `name` in its own project boundary, with `"left-pad": "^1.3.0"`
/// added to the `dependencies` of the package.json at `manifest`.
fn fixture_with_added_dependency(name: &str, manifest: &str) -> TempDir {
    let project = TempDir::boundary(&format!("stale-{name}"));
    copy_tree(&fixture(name), project.path());
    let path = project.path().join(manifest);
    let mut package: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    package["dependencies"]["left-pad"] = serde_json::json!("^1.3.0");
    fs::write(&path, serde_json::to_string_pretty(&package).unwrap()).unwrap();
    project
}

/// A package.json that gained a dependency its lock lacks is refused by
/// `plan` before anything is planned, whichever lock format the project
/// keeps and whichever manifest (root or workspace member) changed. `plan`
/// only parses the lock, so this runs offline.
#[test]
fn plan_refuses_a_lock_that_disagrees_with_package_json() {
    let home = TempDir::new("stale-home");
    for (name, manifest, lock) in [
        ("proj-npm", "package.json", "package-lock.json"),
        ("proj-pnpm", "package.json", "pnpm-lock.yaml"),
        (
            "proj-pnpm-ws",
            "packages/lib/package.json",
            "pnpm-lock.yaml",
        ),
        ("proj-yarn1", "package.json", "yarn.lock"),
    ] {
        let project = fixture_with_added_dependency(name, manifest);
        let out = tog(project.path(), home.path(), &["plan"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(4), "{name}: {stderr}");
        assert!(
            stderr.contains(&format!("{manifest} dependencies disagree with {lock}")),
            "{name}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{name} printed a plan");
    }
}

/// An npm workspace member's package.json is checked against the lock's
/// entry for that member, not only the root's.
#[test]
fn plan_refuses_an_npm_lock_that_disagrees_with_a_workspace_member() {
    let home = TempDir::new("stale-home");
    let project = TempDir::boundary("stale-npm-ws");
    let dir = project.path();
    fs::create_dir_all(dir.join("packages/lib")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["packages/lib"]}"#,
    )
    .unwrap();
    fs::write(
        dir.join("packages/lib/package.json"),
        r#"{"name":"lib","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"requires":true,"packages":{
            "":{"name":"root","workspaces":["packages/lib"]},
            "packages/lib":{"name":"lib","version":"1.0.0"},
            "node_modules/lib":{"resolved":"packages/lib","link":true}}}"#,
    )
    .unwrap();
    let out = tog(dir, home.path(), &["plan"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains("packages/lib/package.json dependencies disagree with package-lock.json"),
        "{stderr}"
    );
}

/// A package.json tog cannot read or parse is an error naming it, never a
/// plan made without it.
#[test]
fn plan_names_a_package_json_it_cannot_read() {
    let home = TempDir::new("stale-home");
    for name in ["proj-npm", "proj-pnpm", "proj-yarn1"] {
        for (contents, expected) in [
            (&b"{ not json"[..], "package.json: "),
            (
                &b"{\"name\":\"\xff\"}"[..],
                "package.json is not valid UTF-8",
            ),
        ] {
            let project = TempDir::boundary(&format!("stale-{name}"));
            copy_tree(&fixture(name), project.path());
            fs::write(project.path().join("package.json"), contents).unwrap();
            let out = tog(project.path(), home.path(), &["plan"]);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "{name}: {stderr}");
            assert!(stderr.contains(expected), "{name}: {stderr}");
            assert!(out.stdout.is_empty(), "{name} printed a plan");
        }
    }
}

/// Plans a yarn classic project whose root depends on the workspace member
/// `lib` (at `version`) with `field: {"lib": spec}`, under an empty lock:
/// only a link to the member can satisfy the dependency.
fn plan_yarn_workspace(
    version: &str,
    field: &str,
    spec: &str,
) -> std::io::Result<tog::tailors::node::NpmPlan> {
    let temp = TempDir::new("yarn-ws-range");
    let dir = temp.path();
    fs::create_dir_all(dir.join("packages/lib")).unwrap();
    let root = serde_json::json!({
        "name": "root",
        "version": "1.0.0",
        "workspaces": ["packages/*"],
        field: {"lib": spec},
    })
    .to_string();
    fs::write(dir.join("package.json"), &root).unwrap();
    fs::write(
        dir.join("packages/lib/package.json"),
        serde_json::json!({"name": "lib", "version": version}).to_string(),
    )
    .unwrap();
    tog::tailors::node::lock_import::plan_yarn(
        Platform::X86_64UnknownLinuxGnu,
        "# yarn lockfile v1\n",
        &root,
        &tog::kernel::fsroot::ProjectRoot::open(dir).unwrap(),
        node_version(),
    )
}

/// Yarn classic links a workspace member whenever its version satisfies the
/// dependency's range under node-semver, so every range form node-semver
/// reads (partials, comparators, x-ranges, alternatives) links the member.
#[test]
fn yarn_workspace_ranges_match_members_as_node_semver_does() {
    for (version, spec) in [
        ("1.5.0", "~1"),
        ("0.0.7", "^0.0"),
        ("0.0.0", "^0.0"),
        ("1.2.3", ">=1.0.0"),
        ("1.9.0", "1.x"),
        ("2.4.0", "^1 || ^2"),
        ("1.0.0", "1.0.0 - 2.0.0"),
        ("1.2.3", "workspace:>=1.0.0 <2"),
        ("1.2.3", "workspace:^"),
        ("1.2.3", "workspace:~"),
        ("1.2.3", "workspace:*"),
        ("1.2.3", "*"),
        ("1.2.3", "latest"),
        ("2.0.0-beta.1", "*"),
        ("2.0.0-beta.1", "latest"),
        ("2.0.0-beta.1", "^2.0.0-beta.0"),
    ] {
        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            let plan = plan_yarn_workspace(version, field, spec)
                .unwrap_or_else(|error| panic!("lib@{version} {field} {spec}: {error}"));
            assert!(
                plan.links
                    .iter()
                    .any(|link| link.path == "node_modules/lib" && link.target == "packages/lib"),
                "lib@{version} {field} {spec}: {:?}",
                plan.links
            );
        }
    }
}

/// A range the member's version does not satisfy is a registry dependency,
/// which an empty lock does not have; under `workspace:` it is refused as a
/// mismatch.
#[test]
fn yarn_workspace_ranges_that_miss_the_member_do_not_link_it() {
    for (version, spec) in [
        ("1.5.0", "~1.4"),
        ("0.1.0", "^0.0"),
        ("0.9.0", ">=1.0.0"),
        ("2.0.0", "1.x"),
        ("3.0.0", "^1 || ^2"),
        ("1.3.0-beta.1", "^1.0.0"),
    ] {
        let error = plan_yarn_workspace(version, "dependencies", spec)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("package.json dependencies disagree with yarn.lock"),
            "lib@{version} {spec}: {error}"
        );
    }
    let error = plan_yarn_workspace("1.2.3", "dependencies", "workspace:^2")
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(
            "Yarn workspace dependency lib@workspace:^2 does not match workspace lib@1.2.3"
        ),
        "{error}"
    );
}
/// A lock `pnpm self-update` wrote holds two documents: a prelude for pnpm
/// itself, then the project's lock. Workspace membership (read by `tog
/// add`), the manifest check and the plan all read the project's.
#[test]
fn every_pnpm_reader_takes_the_project_document_of_a_two_document_lock() {
    let lock = fs::read_to_string(fixture("proj-pnpm-prelude").join("pnpm-lock.yaml")).unwrap();
    assert_eq!(
        tog::tailors::node::lock_import::pnpm_lock_importers(&lock).unwrap(),
        vec![".".to_string()]
    );
    let project = TempDir::boundary("pnpm-prelude");
    copy_tree(&fixture("proj-pnpm-prelude"), project.path());
    let plan = tog::tailors::node::lock_import::plan_pnpm(
        Platform::X86_64UnknownLinuxGnu,
        &lock,
        &tog::kernel::fsroot::ProjectRoot::open(project.path()).unwrap(),
        node_version(),
    )
    .unwrap();
    let mut names = plan
        .packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, ["is-number", "is-odd"]);

    let home = TempDir::new("prelude-home");
    let stale = fixture_with_added_dependency("proj-pnpm-prelude", "package.json");
    let out = tog(stale.path(), home.path(), &["plan"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(
        stderr.contains("package.json dependencies disagree with pnpm-lock.yaml"),
        "{stderr}"
    );
}

/// An underscore in a tarball URL is part of the URL: lockfile v6 and v9
/// write peer context only in parentheses. A peer-suffixed snapshot finds
/// its package by that identity, so cutting at the underscore would give it
/// another tarball's bytes.
#[test]
fn a_pnpm_tarball_url_keeps_the_underscore_in_its_identity() {
    let other = "sha512-ZUNzoqUI/328gbYuFUw9oKe0BVi/reurZZ2ut1+B8ZgEtZ6dtNgKMea7Kp8UvKTnF543WvI/8RwetH1Fzkflzw==";
    let lock = format!(
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      foo:
        specifier: https://example.com/my_b.tgz
        version: https://example.com/my_b.tgz(peer@1.0.0)
      peer:
        specifier: 1.0.0
        version: 1.0.0
packages:
  foo@https://example.com/my_a.tgz:
    resolution: {{integrity: {other}, tarball: https://example.com/my_a.tgz}}
  foo@https://example.com/my_b.tgz:
    resolution: {{integrity: {SRI}, tarball: https://example.com/my_b.tgz}}
  peer@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  foo@https://example.com/my_b.tgz(peer@1.0.0):
    dependencies:
      peer: 1.0.0
  peer@1.0.0: {{}}
"#
    );
    let plan = plan_local("pnpm-underscore", &[], &lock).unwrap();
    let foo = plan
        .packages
        .iter()
        .find(|package| package.name == "foo")
        .unwrap_or_else(|| panic!("{:?}", plan.packages));
    assert_eq!(foo.url, "https://example.com/my_b.tgz", "{foo:?}");
    assert_eq!(foo.integrity, SRI, "{foo:?}");
}

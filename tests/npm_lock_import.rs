use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

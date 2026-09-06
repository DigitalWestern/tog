use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
    Command::new(binary)
        .current_dir(project)
        .env("BLANKET_STORE", store)
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
    let binary = Path::new(env!("CARGO_BIN_EXE_blanket"));

    for fixture in ["proj-pnpm", "proj-pnpm-ws", "proj-yarn1"] {
        let project = scratch.join(format!("nx7-{fixture}"));
        if project.exists() {
            fs::remove_dir_all(&project).unwrap();
        }
        copy_tree(&root.join("tests/fixtures").join(fixture), &project);

        let synced = run(binary, &project, &store, &["sync"], &scratch);
        assert_ok(&synced, &format!("sync {fixture}"));
        let closure = fs::read_to_string(project.join(".blanket/closures/node.json")).unwrap();
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
        }
    }
}

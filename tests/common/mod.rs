//! The one harness for the integration suites: a scratch directory that is
//! removed even when the store inside it is read-only, and a way to run the
//! binary that never sees the developer's home, store, or policy.
//!
//! Each `tests/*.rs` file is its own crate and compiles this module with
//! `mod common;`, so a helper one suite does not use is dead code there.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A scratch directory under the temp root (`TMPDIR` when set), named
/// `tog-<label>-<pid>-<nanos>` so a leftover names the suite that made it.
/// Gone on drop: store objects are read-only by design, so a plain
/// `remove_dir_all` fails on them and the tree stays behind, and enough
/// leftovers fill the per-user /tmp quota until every shell command in the
/// developer's session returns nothing.
pub struct TempDir(pub PathBuf);

impl TempDir {
    /// The clock alone is not unique: macOS's ticks in microseconds, so two
    /// tests with one label could share a directory without the sequence.
    pub fn new(label: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tog-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        // tog records object paths under the store's canonicalized root and
        // compares them exactly; on macOS the temp dir sits under /var, a
        // symlink to /private/var.
        Self(path.canonicalize().unwrap())
    }

    /// A scratch directory that is its own project boundary: it carries an
    /// empty `.tog` directory, so ancestor discovery stops there. For
    /// fixtures that are run in place, which could otherwise sit below a
    /// developer checkout with package manifests of its own.
    pub fn boundary(label: &str) -> Self {
        let temp = Self::new(label);
        std::fs::create_dir_all(temp.0.join(".tog")).unwrap();
        temp
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = tog::kernel::store::remove_tree(&self.0);
    }
}

/// The store a heavy suite should use: the developer's `TOG_STORE` when set,
/// so repeated runs of an ignored suite reuse the toolchains it downloaded,
/// else `store/` under the scratch directory. Only the store is shared; the
/// binary still runs with the scratch home and no policy.
pub fn warm_store(temp: &TempDir) -> PathBuf {
    std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.0.join("store"))
}

/// The binary, configured to run in `cwd` against `store` with `home` as
/// its `HOME`. Every `TOG_*` variable of the developer's session is dropped
/// first, so the machine policy is `home/.tog/policy.toml` (absent unless
/// the test writes it), no signing key or strictness leaks in, and the
/// release check `doctor` makes points at a file that does not exist so the
/// suite stays offline. `TOG_SANDBOX_TESTS` passes through: CI sets it to
/// make a sandbox that cannot start a failure rather than a skip.
pub fn command(cwd: &Path, home: &Path, store: &Path) -> Command {
    command_for(Path::new(env!("CARGO_BIN_EXE_tog")), cwd, home, store)
}

/// [`command`] for a tog binary at `binary` rather than the one cargo
/// built: a test of self-update runs a copy it owns, since the update
/// replaces the file it was started from.
pub fn command_for(binary: &Path, cwd: &Path, home: &Path, store: &Path) -> Command {
    configure(Command::new(binary), cwd, home, store)
}

/// The environment [`command_for`] gives the binary, applied to `command`,
/// which may be a wrapper that execs the binary.
fn configure(mut command: Command, cwd: &Path, home: &Path, store: &Path) -> Command {
    for (name, _) in std::env::vars_os() {
        let leaks = name
            .to_str()
            .is_some_and(|name| name.starts_with("TOG_") && name != "TOG_SANDBOX_TESTS");
        if leaks {
            command.env_remove(&name);
        }
    }
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env("TOG_STORE", store)
        .env(
            "TOG_RELEASE_MANIFEST",
            format!("file://{}", home.join("no-release.json").display()),
        )
        .env("NO_COLOR", "1");
    command
}

/// [`command`] with the network cut: a user and network namespace on Linux
/// (`unshare -rn`), a Seatbelt profile that denies network on macOS, the
/// same wrappers `tests/acceptance.sh` uses. A run that reaches for the
/// network fails instead of quietly downloading.
pub fn offline_command(cwd: &Path, home: &Path, store: &Path) -> Command {
    let binary = env!("CARGO_BIN_EXE_tog");
    let mut wrapper = if cfg!(target_os = "macos") {
        let mut wrapper = Command::new("sandbox-exec");
        wrapper.args(["-p", "(version 1)(allow default)(deny network*)"]);
        wrapper
    } else {
        let mut wrapper = Command::new("unshare");
        wrapper.arg("-rn");
        wrapper
    };
    wrapper.arg(binary);
    configure(wrapper, cwd, home, store)
}

/// [`tog`] with the network cut, see [`offline_command`].
pub fn tog_offline(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    offline_command(cwd, home, &home.join("store"))
        .args(args)
        .output()
        .expect("spawn tog without network")
}

/// Run the binary in `cwd` with `home` as its home and `home/store` as its
/// store: the shape every offline suite uses, where the scratch directory
/// is the home.
pub fn tog(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    tog_at(cwd, home, &home.join("store"), args)
}

/// [`tog`] with extra environment for the child; values are anything that
/// reads as an `OsStr`, so `&[("TOG_STRICT", "1")]` and `&[("TMPDIR", path)]`
/// both work.
pub fn tog_env<V>(cwd: &Path, home: &Path, args: &[&str], env: &[(&str, &V)]) -> Output
where
    V: AsRef<OsStr> + ?Sized,
{
    let mut command = command(cwd, home, &home.join("store"));
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("spawn tog")
}

/// Run the binary against a store that is not under `home`, such as the
/// one [`warm_store`] names.
pub fn tog_at(cwd: &Path, home: &Path, store: &Path, args: &[&str]) -> Output {
    command(cwd, home, store)
        .args(args)
        .output()
        .expect("spawn tog")
}

/// The stdout of a run that must have succeeded; a failure shows both
/// streams under `label`.
pub fn assert_ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `/usr/bin/tar` for creating fixture archives, without host metadata:
/// macOS's bsdtar otherwise adds `._` AppleDouble members and binary
/// provenance xattrs inherited from the process that wrote the files.
pub fn tar_create() -> Command {
    let mut command = Command::new("/usr/bin/tar");
    command.env_remove("TAR_OPTIONS");
    if cfg!(target_os = "macos") {
        command.env("COPYFILE_DISABLE", "1").arg("--no-xattrs");
    }
    command
}

/// Copy a fixture tree into scratch space, files and directories only:
/// fixtures carry no symlinks, and a test that needs one makes it itself.
pub fn copy_tree(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(from, to).unwrap();
        }
    }
}

/// The fixture directory under `tests/fixtures`.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Every regular file under `dir` with its bytes, for a before-and-after
/// comparison that proves a refused run wrote nothing to the project. The
/// one file left out is `.tog/toolchain-input.lock`: tog's own empty
/// advisory lock, created by every sync that reaches the store, which is
/// not a project input.
pub fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    fn walk(dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.symlink_metadata().unwrap().is_dir() {
                walk(&path, files);
            } else if path.is_file() && !path.ends_with(".tog/toolchain-input.lock") {
                files.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    walk(dir, &mut files);
    files
}

/// The lock is gone, so a frozen sync must refuse by name and leave the
/// project byte-identical; a plan then regenerates it through `prepare`
/// with the store toolchain. `home` is the scratch home whose `store/` the
/// project was synced into.
pub fn assert_frozen_never_writes_the_lock(project: &Path, home: &Path, lock: &str) {
    std::fs::remove_file(project.join(lock)).unwrap();
    let before = snapshot(project);
    let frozen = tog(project, home, &["--frozen"]);
    assert!(!frozen.status.success(), "--frozen synced without {lock}");
    let stderr = text(&frozen.stderr);
    assert!(
        stderr.contains(&format!("{lock} is missing and --frozen never creates it")),
        "{stderr}"
    );
    assert_eq!(snapshot(project), before, "--frozen changed the project");
    assert!(!project.join(lock).exists(), "--frozen wrote {lock}");
    assert_ok(tog(project, home, &["plan"]), "plan regenerates the lock");
    assert!(
        project.join(lock).is_file(),
        "plan did not regenerate {lock}"
    );
}

/// The entries directly under the temp root whose names start with
/// `prefix`, for a before-and-after check that a run left nothing there.
pub fn temp_entries(prefix: &str) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(prefix))
        .collect()
}

/// `tog env` over a synced project prints the same bytes twice, and the
/// `HOME` it hands the child is the project's private run home inside
/// `store`: `<store>/run-homes/<project key>/<ecosystem>`, each level a
/// mode-0700 directory, with nothing named `temp_prefix` left under the
/// temp root. A home under the shared temp root would let another user
/// plant startup files the child runs, and a per-process one would change
/// the printed bytes on every call. Returns the printed `HOME`.
pub fn assert_private_run_home(
    project: &Path,
    home: &Path,
    store: &Path,
    ecosystem: &str,
    temp_prefix: &str,
) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let before = temp_entries(temp_prefix);
    let first = assert_ok(
        tog_at(project, home, store, &["env", "--shell", "bash"]),
        "tog env",
    );
    let second = assert_ok(
        tog_at(project, home, store, &["env", "--shell", "bash"]),
        "tog env again",
    );
    assert_eq!(
        first, second,
        "two runs of `tog env` printed different bytes"
    );
    let printed = first
        .lines()
        .find_map(|line| line.strip_prefix("export HOME='"))
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or_else(|| panic!("`tog env` printed no HOME:\n{first}"));
    let printed = PathBuf::from(printed);
    let run_homes = store.canonicalize().unwrap().join("run-homes");
    let relative = printed.strip_prefix(&run_homes).unwrap_or_else(|_| {
        panic!(
            "HOME {} is not under {}",
            printed.display(),
            run_homes.display()
        )
    });
    let mut components = relative.components();
    let key = run_homes.join(components.next().expect("a project key level"));
    let own = key.join(components.next().expect("an ecosystem level"));
    assert_eq!(
        own,
        key.join(ecosystem),
        "HOME {} names another ecosystem",
        printed.display()
    );
    for level in [&key, &own] {
        let stat = std::fs::symlink_metadata(level).unwrap();
        assert!(stat.is_dir(), "{} is not a directory", level.display());
        assert_eq!(
            stat.permissions().mode() & 0o777,
            0o700,
            "{} is not private",
            level.display()
        );
    }
    assert!(
        printed.is_dir(),
        "HOME {} does not exist",
        printed.display()
    );
    let left = temp_entries(temp_prefix);
    let new: Vec<_> = left.difference(&before).collect();
    assert!(new.is_empty(), "runs left {new:?} under the temp root");
    printed
}

/// A local git repository holding one library crate, and the Cargo project
/// at `project` made to depend on it at its commit. A git dependency is a
/// `git-dependency` exception the Cargo sync records, which is what the
/// attribution tests trace.
pub fn add_git_dependency(root: &Path, project: &Path) -> String {
    let repo = root.join("gitdep-repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "t@example.invalid"]);
    git(&["config", "user.name", "t"]);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"gitdep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 7 }\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "one"]);
    let commit = git(&["rev-parse", "HEAD"]);
    let url = format!("file://{}", repo.display());

    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    let manifest = if manifest.contains("[dependencies]\n") {
        manifest.replace(
            "[dependencies]\n",
            &format!("[dependencies]\ngitdep = {{ git = \"{url}\", rev = \"{commit}\" }}\n"),
        )
    } else {
        format!("{manifest}\n[dependencies]\ngitdep = {{ git = \"{url}\", rev = \"{commit}\" }}\n")
    };
    std::fs::write(project.join("Cargo.toml"), manifest).unwrap();
    let lock = std::fs::read_to_string(project.join("Cargo.lock")).unwrap();
    let package = |name: &str| format!("[[package]]\nname = \"{name}\"\n");
    let root_name = manifest_name(project);
    let mut lock = lock;
    let root_entry = package(&root_name);
    let at = lock.find(&root_entry).unwrap() + root_entry.len();
    let rest = &lock[at..];
    let version_end = rest.find('\n').unwrap() + 1;
    let insert = at + version_end;
    if lock[insert..].starts_with("dependencies = [\n") {
        let list = insert + "dependencies = [\n".len();
        lock.insert_str(list, " \"gitdep\",\n");
    } else {
        lock.insert_str(insert, "dependencies = [\n \"gitdep\",\n]\n");
    }
    lock.push_str(&format!(
        "\n[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"git+{url}?rev={commit}#{commit}\"\n"
    ));
    std::fs::write(project.join("Cargo.lock"), lock).unwrap();
    url
}

pub fn manifest_name(project: &Path) -> String {
    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    let line = manifest
        .lines()
        .find(|line| line.starts_with("name = "))
        .unwrap();
    line.trim_start_matches("name = ")
        .trim_matches('"')
        .to_string()
}

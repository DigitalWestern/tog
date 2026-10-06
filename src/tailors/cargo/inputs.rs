//! From a Cargo project to its inputs: toolchain resolution, workspace root
//! discovery through the pinned Cargo, missing-lock generation, and the
//! `CargoPlan`.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::cargo;
use std::io;
use std::path::{Path, PathBuf};

/// Implicit detection for sync/plan: cargo joins the party only when the
/// invocation dir is itself a Cargo package (workspace members included).
/// Without this gate, running tog in any project nested under an
/// unrelated Cargo workspace would silently project into that parent tree.
/// The project is read through the held descriptor.
pub fn is_cargo_here(project: &ProjectRoot) -> bool {
    project.is_input_file(Path::new("Cargo.toml")) || project.is_input_file(Path::new("Cargo.lock"))
}

pub struct CargoInputs {
    pub root: PathBuf,
    /// The same workspace used to read the plan, retained through publication.
    pub workspace: ProjectRoot,
    pub rust_obj: PathBuf,
    pub plan: cargo::CargoPlan,
    pub lock_digest: String,
    /// The workspace's resolution files by the digests the plan read (the
    /// lock by the very bytes it was planned from): the closure's
    /// `resolution_basis`.
    pub resolution_basis: crate::comforter::join::Digests,
}

/// The workspace root cargo uses for `cwd`, found by tog's own walk of the
/// manifests, the way cargo finds it: the nearest `Cargo.toml` at or above
/// `cwd`; the root its `package.workspace` names, if any; else itself when
/// it holds `[workspace]`; else the nearest ancestor whose `Cargo.toml`
/// holds a `[workspace]` that does not exclude it; else its own directory.
/// An ancestor-walk for `Cargo.lock` would pick an unrelated outer lock
/// when independent packages nest.
///
/// No cargo runs on the host to find it. A host cargo reads the project's
/// manifests and configuration (and the files they include, and its own
/// home's) and quotes the line it cannot parse, so a project file that is
/// the signing key under another name (a symlink, a hard link, an include)
/// would print the key. tog's own reads name a parse error's position only,
/// and a manifest that is the signing key is refused by name.
pub fn locate_cargo_root(cwd: &Path) -> io::Result<PathBuf> {
    let held = ProjectRoot::open(cwd)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", cwd.display())))?;
    Ok(locate_held_cargo_root(&held)?.0)
}

/// `locate_cargo_root` for a held project: every manifest above it is read
/// from the directories that contain the held one (`ProjectRoot::ancestors`),
/// not by path, and the root comes back held too. A `package.workspace`
/// root is opened below the nearest of those directories that contains it.
pub(crate) fn locate_held_cargo_root(project: &ProjectRoot) -> io::Result<(PathBuf, ProjectRoot)> {
    let keys = crate::kernel::resolve::confine::signing_key_ids();
    let manifest_name = Path::new("Cargo.toml");
    let mut found = None;
    for dir in project.ancestors() {
        let dir = dir?;
        if dir.is_input_file(manifest_name) {
            found = Some(dir);
            break;
        }
    }
    let dir = found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "could not find Cargo.toml in {} or any parent directory",
                project.path().display()
            ),
        )
    })?;
    let manifest = dir.path().join(manifest_name);
    let table = read_manifest(&dir, &keys)?;
    let named = table
        .get("package")
        .and_then(|package| package.get("workspace"))
        .and_then(|workspace| workspace.as_str());
    if let Some(named) = named {
        let root = normalize(&dir.path().join(named));
        let held = held_below(&dir, &root)?
            .filter(|held| held.is_input_file(manifest_name))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "{} names the workspace {named:?}, which has no Cargo.toml",
                        manifest.display()
                    ),
                )
            })?;
        let held = held.canonicalize_name()?.with_cwd_binding();
        return Ok((held.path().to_path_buf(), held));
    }
    if table.contains_key("workspace") {
        return Ok((dir.path().to_path_buf(), dir.with_cwd_binding()));
    }
    for ancestor in dir.ancestors().skip(1) {
        let ancestor = ancestor?;
        if !ancestor.is_input_file(manifest_name) {
            continue;
        }
        let outer = read_manifest(&ancestor, &keys)?;
        let Some(workspace) = outer.get("workspace").and_then(|w| w.as_table()) else {
            continue;
        };
        if !excludes(ancestor.path(), workspace, &manifest) {
            return Ok((ancestor.path().to_path_buf(), ancestor.with_cwd_binding()));
        }
    }
    Ok((dir.path().to_path_buf(), dir.with_cwd_binding()))
}

/// `path` opened below the nearest directory containing `from` (itself
/// included) whose path is a prefix of it; `None` when it is absent or not
/// a directory.
fn held_below(from: &ProjectRoot, path: &Path) -> io::Result<Option<ProjectRoot>> {
    for dir in from.ancestors() {
        let dir = dir?;
        if let Some(rest) = dir.relative(path) {
            if rest.as_os_str().is_empty() {
                return Ok(Some(dir));
            }
            return dir.input_subdir(rest);
        }
    }
    Ok(None)
}

/// cargo's `is_excluded`: `manifest` is under an `exclude` entry of the
/// workspace at `root` and under none of its `members` entries (each
/// compared as a path prefix, as cargo does).
fn excludes(root: &Path, workspace: &toml::Table, manifest: &Path) -> bool {
    let under = |key: &str| {
        workspace
            .get(key)
            .and_then(|list| list.as_array())
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.as_str())
            .any(|entry| manifest.starts_with(root.join(entry)))
    };
    under("exclude") && !under("members")
}

/// `path` with `.` and `..` resolved by name, as cargo resolves the
/// workspace a package names (symlinks are not followed).
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// A manifest read by tog, never echoed: a file that is the signing key
/// (by device and inode, so a hard link too) is refused by name, anything
/// but a regular file is refused, and a parse error names its position.
fn read_manifest(
    dir: &ProjectRoot,
    keys: &[crate::kernel::resolve::confine::FileId],
) -> io::Result<toml::Table> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let path = &dir.path().join("Cargo.toml");
    let context = |error: io::Error| {
        io::Error::new(error.kind(), format!("read {}: {error}", path.display()))
    };
    let mut file = dir
        .open_input_file(Path::new("Cargo.toml"))
        .map_err(context)?
        .ok_or_else(|| context(io::ErrorKind::NotFound.into()))?;
    let meta = file.metadata().map_err(context)?;
    if keys.contains(&(meta.dev(), meta.ino())) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is the signing key (the same file, by device and inode); move the key out \
                 of the project and point TOG_SIGNING_KEY at it",
                path.display()
            ),
        ));
    }
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(context)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8", path.display()),
        )
    })?;
    crate::kernel::provider::cargo_door::parse_toml(path, &text)
}

/// `toolchain` is the project's selection, and it decides which Rust this
/// call realizes. `lock_root` is the directory the selection was resolved
/// in: the components and cross targets its toolchain file asks for are
/// read there, through the rows the toolchain lock records and the
/// descriptor it is held by, and assembled onto that Rust. One the pinned
/// release does not publish is an error before any project write.
///
/// `project` is where Cargo runs (sync passes the same root for both). It
/// is read through its held descriptor: Cargo runs in `project.path()`, but
/// the lock it names is read back from the directory `project` holds (or,
/// for a workspace rooted above it, from that root).
pub fn load_cargo_inputs(
    platform: Platform,
    lock_root: &ProjectRoot,
    project: &ProjectRoot,
    store: &store::Store,
    activity: &StoreActivity,
    toolchain: &Selected,
) -> io::Result<CargoInputs> {
    let rust_version = toolchain.version("rustc")?;
    let (rust_obj, root, workspace) =
        locate_workspace(platform, lock_root, project, store, activity, toolchain)?;
    read_inputs(root, workspace, rust_obj, rust_version)
}

fn read_inputs(
    root: PathBuf,
    workspace: ProjectRoot,
    rust_obj: PathBuf,
    rust_version: &str,
) -> io::Result<CargoInputs> {
    let lock = read_cargo_lock(&workspace)?
        .ok_or_else(|| crate::tailors::missing_lock(&workspace, "Cargo.lock"))?;
    let plan = cargo::plan_cargo(&lock, rust_version)?;
    let resolution_basis = resolution_basis(&workspace, &lock)?;
    Ok(CargoInputs {
        root,
        workspace,
        rust_obj,
        plan,
        lock_digest: cargo::lock_digest(&lock),
        resolution_basis,
    })
}

/// The closure's `resolution_basis`: every resolution file of the
/// workspace that exists, by digest, with `Cargo.lock` taken from `lock`,
/// the bytes the plan was built from.
fn resolution_basis(
    workspace: &ProjectRoot,
    lock: &str,
) -> io::Result<crate::comforter::join::Digests> {
    use crate::kernel::resolve::record::{file_digests, sha256_hex};
    let mut listed = super::resolve::resolution_outputs(workspace)?;
    listed.extend(super::resolve::resolution_inputs(workspace)?);
    let mut basis = file_digests(workspace, &listed)?;
    basis.insert("Cargo.lock".into(), sha256_hex(lock.as_bytes()));
    Ok(basis)
}

/// The Rust the selection names, realized, and the workspace Cargo
/// uses for `project` ([`locate_cargo_root`]): its root path and that root held as a
/// descriptor. Lock generation and planning share it so both see the same
/// workspace.
fn locate_workspace(
    platform: Platform,
    lock_root: &ProjectRoot,
    project: &ProjectRoot,
    store: &store::Store,
    activity: &StoreActivity,
    toolchain: &Selected,
) -> io::Result<(PathBuf, PathBuf, ProjectRoot)> {
    // Found before anything is realized, by tog's own walk: no cargo runs
    // on the host.
    let (root, workspace) = locate_held_cargo_root(project)?;
    // Cargo is the one tailor whose registered root is not the directory
    // sync was run in: a member of a workspace sends its closure and its
    // record to the workspace root. The preflight checked the invocation
    // directory, so check the root as soon as it is known — before a lock,
    // a vendor object or a cargo-home lands in a workspace that cannot be
    // registered and so cannot be protected.
    store::Store::check_registrable(&root)?;
    let extras = cargo::project_extras_in(lock_root)?;
    let rust_obj = cargo::realize_toolchain(store, activity, platform, toolchain, &extras)?;
    Ok((rust_obj, root, workspace))
}

/// `prepare`: the workspace's Cargo.lock, generated by the Rust the
/// selection names when there is none. The one place the Cargo tailor
/// writes project inputs.
///
/// Cargo runs confined through `door`, a missing-lock door.
pub fn ensure_lock(
    project: &ProjectRoot,
    toolchain: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<()> {
    let (rust_obj, root, workspace) = locate_workspace(
        door.platform(),
        project,
        project,
        door.store(),
        door.lease(),
        toolchain,
    )?;
    if read_cargo_lock(&workspace)?.is_some() {
        return Ok(());
    }
    ensure_cargo_lock(&workspace, &rust_obj, toolchain, door)?;
    if read_cargo_lock(&workspace)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} was not generated", root.join("Cargo.lock").display()),
        ));
    }
    Ok(())
}

/// The workspace's Cargo.lock, read through the held descriptor; `None`
/// when there is none yet.
fn read_cargo_lock(workspace: &ProjectRoot) -> io::Result<Option<String>> {
    workspace.read_input_string(Path::new("Cargo.lock"))
}

/// `cargo generate-lockfile` at the workspace root, confined through
/// `door` (a missing-lock door): the lock and its signed resolution record
/// are published together.
pub fn ensure_cargo_lock(
    workspace: &ProjectRoot,
    rust_obj: &Path,
    toolchain: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<()> {
    ui::note(
        "no Cargo.lock; generating it with the store Rust toolchain \
         (confined, through the resolution proxy)...",
    );
    super::resolve::generate_lock(door, workspace, rust_obj, toolchain).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not generate Cargo.lock: {e}; \
                 run `tog` after fixing the project or network"
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// `dir` mode 0111 (search, no read) until dropped.
    struct SearchOnly(std::path::PathBuf);
    impl SearchOnly {
        fn new(dir: &Path) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o111)).unwrap();
            Self(dir.to_path_buf())
        }
    }
    impl Drop for SearchOnly {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    /// The workspace walk reaches a root whose directory is search-only
    /// (0111): its manifest is read by name through the held ancestor (#480).
    #[test]
    fn a_workspace_root_in_a_search_only_directory_is_found() {
        let temp = TempDir::new();
        let root = temp.0.join("workspace");
        let member = root.join("member");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .unwrap();
        std::fs::write(member.join("Cargo.toml"), "[package]\nname = \"member\"\n").unwrap();
        let _search_only = SearchOnly::new(&root);
        let (found, _held) = locate_held_cargo_root(&ProjectRoot::open(&member).unwrap()).unwrap();
        assert_eq!(found, root.canonicalize().unwrap());
    }

    #[test]
    fn cargo_participation_requires_local_manifest() {
        let temp = TempDir::new();
        let nested = temp.0.join("outer/inner");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(temp.0.join("outer/Cargo.toml"), "[package]\nname=\"o\"\n").unwrap();
        // sync/plan only join in where the invocation dir itself is a package
        let open = |dir: &Path| ProjectRoot::open(dir).unwrap();
        assert!(is_cargo_here(&open(&temp.0.join("outer"))));
        assert!(!is_cargo_here(&open(&nested)));
        std::fs::write(nested.join("Cargo.lock"), "version = 4\n").unwrap();
        assert!(is_cargo_here(&open(&nested)));
    }

    /// tog's walk finds the root cargo would: a package's own directory, a
    /// workspace above it, the root `package.workspace` names, and past a
    /// workspace that excludes it (unless it is also a listed member).
    #[test]
    fn the_workspace_root_is_found_without_cargo() {
        let temp = TempDir::named("cargo-locate");
        let base = temp.0.canonicalize().unwrap();
        let write = |relative: &str, text: &str| {
            let path = base.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        let root = |relative: &str| locate_cargo_root(&base.join(relative)).unwrap();
        write("solo/Cargo.toml", "[package]\nname = \"solo\"\n");
        std::fs::create_dir_all(base.join("solo/src/deep")).unwrap();
        assert_eq!(root("solo/src/deep"), base.join("solo"));
        write(
            "ws/Cargo.toml",
            "[workspace]\nmembers = [\"a\"]\nexclude = [\"out\"]\n",
        );
        write("ws/a/Cargo.toml", "[package]\nname = \"a\"\n");
        assert_eq!(root("ws/a"), base.join("ws"));
        assert_eq!(root("ws"), base.join("ws"));
        // An implicit member, in a hidden directory and deep: still the
        // workspace's.
        write(
            ".h/1/2/3/4/5/6/7/8/9/10/11/12/13/Cargo.toml",
            "[package]\nname = \"deep\"\n",
        );
        write(".h/Cargo.toml", "[workspace]\n");
        assert_eq!(root(".h/1/2/3/4/5/6/7/8/9/10/11/12/13"), base.join(".h"));
        // Excluded: its own root.
        write("ws/out/Cargo.toml", "[package]\nname = \"out\"\n");
        assert_eq!(root("ws/out"), base.join("ws/out"));
        // `package.workspace` wins, resolved by name.
        write(
            "ws/out/inner/Cargo.toml",
            "[package]\nname = \"inner\"\nworkspace = \"../..\"\n",
        );
        assert_eq!(root("ws/out/inner"), base.join("ws"));
        write(
            "ws/out/bad/Cargo.toml",
            "[package]\nworkspace = \"../nowhere\"\n",
        );
        assert!(locate_cargo_root(&base.join("ws/out/bad")).is_err());
        // Nothing at all.
        std::fs::create_dir_all(base.join("empty")).unwrap();
        let error = locate_cargo_root(&base.join("empty"));
        if !Path::new("/Cargo.toml").exists() {
            assert_eq!(error.unwrap_err().kind(), io::ErrorKind::NotFound);
        }
    }

    /// A manifest the walk reads that is the signing key (a hard link, so
    /// no symlink to see) or that does not parse is refused by name and
    /// position, and none of its bytes reach the error.
    #[test]
    fn the_walk_never_echoes_a_manifest() {
        const SEED: &str = "SEEDBYTES0123456789abcdef";
        let temp = TempDir::named("cargo-locate-key");
        let base = temp.0.canonicalize().unwrap();
        let key = base.join("signing.key");
        std::fs::write(&key, format!("ed25519:{SEED}\n")).unwrap();
        let keys = crate::kernel::resolve::confine::key_ids(std::slice::from_ref(&key));
        let project = base.join("p");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::hard_link(&key, project.join("Cargo.toml")).unwrap();
        let error = read_manifest(&ProjectRoot::open(&project).unwrap(), &keys)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is the signing key"), "{error}");
        assert!(!error.contains(SEED), "{error}");
        // Without the key known, the parse error is position only.
        let error = locate_cargo_root(&project).unwrap_err().to_string();
        assert!(!error.contains(SEED), "{error}");
    }

    /// The workspace above a held member is found, and held, from the
    /// member's descriptor: a workspace renamed away after the open is
    /// still the one returned, not a directory put at its path.
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn a_held_member_finds_the_workspace_that_contains_it() {
        let temp = TempDir::new();
        let ws = temp.0.canonicalize().unwrap().join("ws");
        std::fs::create_dir_all(ws.join("member")).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .unwrap();
        std::fs::write(ws.join("member/Cargo.toml"), "[package]\nname = \"m\"\n").unwrap();
        let member = ProjectRoot::open(&ws.join("member")).unwrap();
        std::fs::rename(&ws, temp.0.join("moved")).unwrap();
        std::fs::create_dir_all(ws.join("member")).unwrap();
        std::fs::write(ws.join("member/Cargo.toml"), "[package]\nname = \"m\"\n").unwrap();
        let (root, held) = locate_held_cargo_root(&member).unwrap();
        assert_eq!(root, ws);
        let text = held
            .read_input_string(Path::new("Cargo.toml"))
            .unwrap()
            .unwrap();
        assert!(text.contains("[workspace]"), "{text}");
        let again = held_below(&member, &root).unwrap().unwrap();
        assert!(again.is_input_file(Path::new("Cargo.toml")));
        assert!(again.is_input_dir(Path::new("member")));
        assert!(!ws.join("Cargo.toml").exists());
        let mut child = std::process::Command::new("/bin/cat");
        child.arg("Cargo.toml");
        crate::kernel::fsroot::start_in(&mut child, held.path());
        let output = child.output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("[workspace]"));
    }

    #[test]
    fn loaded_inputs_retain_the_workspace_until_publication() {
        let temp = TempDir::new();
        let base = temp.0.canonicalize().unwrap();
        let member = base.join("member");
        let workspace = base.join("workspace");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"m\"\nworkspace = \"../workspace\"\n",
        )
        .unwrap();
        std::fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"../member\"]\n",
        )
        .unwrap();
        std::fs::write(workspace.join("Cargo.lock"), "# original\nversion = 4\n").unwrap();
        let member = ProjectRoot::open(&member).unwrap();
        let (root, held) = locate_held_cargo_root(&member).unwrap();
        let inputs = read_inputs(root, held, base.join("rust"), "1.96.1").unwrap();
        std::fs::rename(&workspace, base.join("moved")).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(workspace.join("Cargo.lock"), "# replacement\nversion = 4\n").unwrap();
        assert_eq!(
            read_cargo_lock(&inputs.workspace).unwrap().as_deref(),
            Some("# original\nversion = 4\n")
        );
        assert!(inputs.workspace.check_still_named().is_err());
        assert!(!workspace.join(".tog").exists());
        // Reopening would accept the replacement. Publication must use the
        // root retained with the input bytes, as both sync and build do.
        ProjectRoot::open(&workspace)
            .unwrap()
            .check_still_named()
            .unwrap();
    }

    #[test]
    fn a_named_workspace_alias_keeps_a_verified_canonical_publication_name() {
        let temp = TempDir::new();
        let base = temp.0.canonicalize().unwrap();
        let member = base.join("member");
        let workspace = base.join("workspace");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"m\"\nworkspace = \"../alias\"\n",
        )
        .unwrap();
        std::fs::write(
            workspace.join("Cargo.toml"),
            "[workspace]\nmembers = [\"../member\"]\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&workspace, base.join("alias")).unwrap();
        let member = ProjectRoot::open(&member).unwrap();
        let (path, held) = locate_held_cargo_root(&member).unwrap();
        assert_eq!(path, workspace);
        held.check_still_named().unwrap();
        let replacement = base.join("replacement");
        std::fs::create_dir_all(&replacement).unwrap();
        std::fs::remove_file(base.join("alias")).unwrap();
        std::os::unix::fs::symlink(replacement, base.join("alias")).unwrap();
        held.check_still_named().unwrap();
        held.write_file(Path::new("publication"), b"original")
            .unwrap();
        assert_eq!(
            std::fs::read(workspace.join("publication")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn a_held_project_keeps_reading_its_own_lock_after_a_rename() {
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), "# original\nversion = 4\n").unwrap();
        let project = ProjectRoot::open(&dir).unwrap();
        // Another directory takes the path mid-sync, first with no Cargo
        // files at all, then with a lock of its own.
        std::fs::rename(&dir, temp.0.join("moved")).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        assert!(is_cargo_here(&project));
        let workspace = project.try_clone().unwrap();
        assert_eq!(
            read_cargo_lock(&workspace).unwrap().as_deref(),
            Some("# original\nversion = 4\n")
        );
        std::fs::write(dir.join("Cargo.lock"), "# replacement\nversion = 4\n").unwrap();
        assert_eq!(
            read_cargo_lock(&workspace).unwrap().as_deref(),
            Some("# original\nversion = 4\n")
        );
    }
}

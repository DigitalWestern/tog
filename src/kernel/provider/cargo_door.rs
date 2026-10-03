//! Running the store cargo as a resolver: confined through the door, its
//! https traffic intercepted by the proxy session (crates.io through the
//! [`crates_index`](super::crates_index) route, git dependencies through the
//! git row, any other registry as `unattested-index`).
//!
//! Two tailors use it: the Cargo tailor (`tog add`/`remove`/`update`, a
//! missing `Cargo.lock`, `tog attest`) and Python, for the `Cargo.lock` of
//! an sdist's Rust extension. Every cargo resolution goes through here;
//! none falls back to running cargo directly.
//!
//! How cargo is pointed at the session, all with `--config` before the
//! subcommand:
//!
//! - `http.proxy` is the session's forward-proxy URL with the token as its
//!   credentials, and `http.cainfo` the session CA as the sandbox sees it.
//!   cargo's curl adds that CA to its default roots rather than replacing
//!   them, which is harmless here: the sandbox reaches nothing but the
//!   proxy.
//! - The forced settings (`build.rustc` and `build.rustdoc` at the store
//!   Rust, no wrappers, `cargo:token` as the only credential provider for
//!   every registry, `net.git-fetch-with-cli=true`) come from the
//!   forced-settings table, and the door checks they are present.
//! - `CARGO_HOME` is a directory in the run's scratch, so the user's
//!   `~/.cargo` (its config, credentials, and caches) is never read, and
//!   `CARGO_NET_OFFLINE=false` undoes an inherited offline setting.

use super::crates_index;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::confine;
use crate::kernel::resolve::door::{ConfinedSpec, ReceiptProducer, Target, Wire, Wiring};
use crate::kernel::resolve::session::Intercept;
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Why cargo runs isolated, for the missing-capability message.
const WHY: &str = "runs the build.rustc and credential-provider programs a project's \
                   .cargo/config.toml names, and fetches crates from the network";

/// cargo's configuration files in a directory it reads them from.
pub const CONFIG_FILES: [&str; 2] = [".cargo/config.toml", ".cargo/config"];

/// Where a confined cargo run's results go.
pub enum CargoPublish<'a> {
    /// The lock root is a project: `outputs` (the lock and manifests) are
    /// published through the transaction, with the receipt the producer
    /// makes.
    Project {
        outputs: Vec<PathBuf>,
        receipt: Option<ReceiptProducer<'a>>,
    },
    /// The lock root is tog's own (an unpacked sdist): accepted `outputs`
    /// are written back into it, and the caller roots the ledger.
    Detached { outputs: Vec<PathBuf> },
}

/// One confined run of the store cargo.
pub struct CargoRun<'a> {
    /// The store Rust toolchain object (`bin/cargo`, `bin/rustc`).
    pub rust_obj: &'a Path,
    /// Where cargo runs: the workspace root, or the unpacked sdist.
    pub lock_root: &'a Path,
    /// The subcommand and its arguments (`--manifest-path` included).
    pub args: &'a [&'a str],
    pub publish: CargoPublish<'a>,
}

/// The store cargo with output captured, in `lock_root`, offline mode off,
/// rustup's toolchain selection removed, and `PATH` naming the store Rust
/// and the system's own tools (the git `net.git-fetch-with-cli` starts).
pub fn cargo_spec(rust_obj: &Path, lock_root: &Path, args: &[&str]) -> DelegateSpec {
    let mut spec = DelegateSpec::new(rust_obj.join("bin/cargo"));
    spec.args(args)
        .lock_root(lock_root)
        .capture()
        .env("CARGO_NET_OFFLINE", "false")
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", rust_obj.join("bin").display()),
        )
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    spec
}

/// The words a TOML parse error of `name` is reported in: the position
/// only. A parser's own message quotes the source line, and a project file
/// can be a symlink to a secret (the signing key's `ed25519:<seed>` line),
/// so no byte of the file is ever echoed.
pub fn toml_refusal(name: &str, text: &str, error: &toml::de::Error) -> io::Error {
    let at = error
        .span()
        .and_then(|span| text.get(..span.start))
        .map(|before| {
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
            format!(" at line {line}, column {column}")
        })
        .unwrap_or_default();
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{name} is not valid TOML{at}"),
    )
}

/// `text` (read from `path`) as a TOML table, its error from
/// [`toml_refusal`].
pub fn parse_toml(path: &Path, text: &str) -> io::Result<toml::Table> {
    toml::from_str(text).map_err(|error| toml_refusal(&path.display().to_string(), text, &error))
}

/// Where tog's own reads of a project's cargo files may land: under
/// `root`, never the signing key. A project is cloned, so its
/// `.cargo/config.toml` or `Cargo.toml` can be a symlink (or a hard link)
/// to any file the user can read.
pub struct Bound {
    root: PathBuf,
    /// The signing key's files that exist, by device and inode: a hard
    /// link to the key is the key under another name.
    keys: Vec<confine::FileId>,
}

impl Bound {
    /// Bounded by `root`, refusing the key `TOG_SIGNING_KEY` or
    /// `~/.tog/signing.key` names.
    pub fn new(root: &Path) -> io::Result<Bound> {
        Bound::with_keys(root, &confine::signing_key_paths())
    }

    pub(crate) fn with_keys(root: &Path, keys: &[PathBuf]) -> io::Result<Bound> {
        Ok(Bound {
            root: std::fs::canonicalize(root)?,
            keys: confine::key_ids(keys),
        })
    }

    /// The file `path` names, resolved: `None` when there is none (a
    /// dangling symlink included, which cargo reports by its name). The
    /// signing key and anything outside the root are refused by name.
    pub fn resolve(&self, path: &Path) -> io::Result<Option<PathBuf>> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                return Ok(None)
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{}: {error}", path.display()),
                ))
            }
        }
        let Ok(real) = std::fs::canonicalize(path) else {
            return Ok(None);
        };
        self.refuse_key(path, &real)?;
        if !real.starts_with(&self.root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} resolves to {}, outside {}; tog does not read, or let cargo read, a \
                     project file that leads out of the project",
                    path.display(),
                    real.display(),
                    self.root.display()
                ),
            ));
        }
        Ok(Some(real))
    }

    /// Refuse `path` when it is the signing key under any name, wherever
    /// it is (a file of the user's own, above the project).
    pub fn refuse_if_key(&self, path: &Path) -> io::Result<()> {
        match std::fs::canonicalize(path) {
            Ok(real) => self.refuse_key(path, &real),
            Err(_) => Ok(()),
        }
    }

    fn refuse_key(&self, path: &Path, real: &Path) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(real) else {
            return Ok(());
        };
        if self.keys.contains(&(meta.dev(), meta.ino())) {
            let through = if real == path {
                String::new()
            } else {
                format!(", through {}", real.display())
            };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is the signing key (the same file, by device and inode{through}); tog \
                     does not read it as a cargo file or let cargo read it",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    /// The text of the file `path` names, read after [`Self::resolve`]
    /// allowed it, without following a symlink in its last component.
    pub fn read(&self, path: &Path) -> io::Result<Option<String>> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let Some(real) = self.resolve(path)? else {
            return Ok(None);
        };
        let context = |error: io::Error| {
            io::Error::new(error.kind(), format!("read {}: {error}", path.display()))
        };
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&real)
            .map_err(context)?;
        if !file.metadata().map_err(context)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(context)?;
        String::from_utf8(bytes).map(Some).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not valid UTF-8", path.display()),
            )
        })
    }
}

/// One cargo configuration file, read.
pub struct ConfigFile {
    /// Where it is, resolved.
    pub real: PathBuf,
    pub table: toml::Table,
}

/// cargo's configuration in `dir`: `.cargo/config.toml`, `.cargo/config`,
/// and every file they include, transitively. cargo 1.98's `include` is a
/// list of paths or `{ path, optional }` tables, each relative to the
/// directory of the file that names it and ending in `.toml`. Each file is
/// read through `bound`, so an include (or a symlink) that leads out of it
/// is refused by name. An entry cargo itself would reject (not a list, not
/// `.toml`, a missing required file) is left for cargo to report.
pub fn config_files(dir: &Path, bound: &Bound) -> io::Result<Vec<ConfigFile>> {
    let mut queue: Vec<PathBuf> = CONFIG_FILES
        .iter()
        .rev()
        .map(|name| dir.join(name))
        .collect();
    let mut found: Vec<ConfigFile> = Vec::new();
    while let Some(path) = queue.pop() {
        let Some(real) = bound.resolve(&path)? else {
            continue;
        };
        if found.iter().any(|file| file.real == real) {
            continue;
        }
        let Some(text) = bound.read(&path)? else {
            continue;
        };
        let table = parse_toml(&path, &text)?;
        let base = path.parent().unwrap_or(dir).to_path_buf();
        let entries = table
            .get("include")
            .and_then(|include| include.as_array())
            .into_iter()
            .flatten();
        for entry in entries {
            let named = match entry {
                toml::Value::String(path) => Some(path.as_str()),
                toml::Value::Table(table) => table.get("path").and_then(|path| path.as_str()),
                _ => None,
            };
            if let Some(named) = named.filter(|named| named.ends_with(".toml")) {
                queue.push(base.join(named));
            }
        }
        found.push(ConfigFile { real, table });
    }
    Ok(found)
}

/// Every registry name cargo's configuration in `lock_root` defines
/// (`[registries.<name>]`), so each gets the forced credential provider.
/// cargo reads `.cargo/config.toml` (and the older `.cargo/config`) in the
/// directory it runs in and its ancestors; inside the sandbox the lock root
/// is the only one of those that holds the project's files. An unreadable
/// or malformed file is an error: a registry it hides would keep its
/// credential provider. Each is read through a [`Bound`] of the lock root,
/// and the files they include are read too ([`config_files`]): a registry
/// declared in an included file gets the forced provider like any other.
pub fn configured_registries(lock_root: &Path) -> io::Result<Vec<String>> {
    let bound = Bound::new(lock_root)?;
    let mut names = Vec::new();
    for file in config_files(lock_root, &bound)? {
        if let Some(registries) = file.table.get("registries").and_then(|r| r.as_table()) {
            names.extend(registries.keys().cloned());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// The directories outside `lock_root` that cargo reads as `path`
/// dependencies (and `[patch]` or `[replace]` entries), found from every
/// manifest under the lock root and, in turn, from each of theirs: the
/// door snapshots them beside the lock root as read-only inputs, so a
/// workspace that names `../shared` resolves confined. A path that does not
/// exist is left for cargo to report.
///
/// The manifest is the project's, so it does not get to choose any host
/// directory: every root must lie inside the boundary
/// ([`path_dependency_boundary`]) with no hidden directory between the two
/// (`../.cargo` holds `credentials.toml`). A path dependency outside that
/// is an error naming the manifest and the path, before cargo starts.
pub fn path_dependency_roots(lock_root: &Path) -> io::Result<Vec<PathBuf>> {
    let host = Host {
        home: std::env::var_os("HOME").map(PathBuf::from),
        ceiling: None,
    };
    bounded_path_dependency_roots(lock_root, &host)
}

/// What of the host the path-dependency boundary depends on, passed in so
/// a test can fix it: the home directory, and the highest directory the
/// repository search looks at (`None`: up to `/`). A machine with a `.git`
/// above the test's temporary directory otherwise moves the boundary.
struct Host {
    home: Option<PathBuf>,
    ceiling: Option<PathBuf>,
}

fn bounded_path_dependency_roots(lock_root: &Path, host: &Host) -> io::Result<Vec<PathBuf>> {
    let lock_root = std::fs::canonicalize(lock_root)?;
    let keys = Bound::new(&lock_root)?;
    let mut manifests = manifests_under(&lock_root)?;
    let mut outside: Vec<PathBuf> = Vec::new();
    let mut boundary: Option<PathBuf> = None;
    while let Some(manifest) = manifests.pop() {
        let Some(dir) = manifest.parent() else {
            continue;
        };
        for path in path_dependencies(&manifest, &keys)? {
            let Ok(found) = std::fs::canonicalize(dir.join(&path)) else {
                continue;
            };
            if found.starts_with(&lock_root) || outside.iter().any(|seen| found.starts_with(seen)) {
                continue;
            }
            let refuse = |why: String| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} names the path dependency {path:?} ({}), {why}; a confined cargo \
                         reads only path dependencies inside the project's repository (or, \
                         outside one, beside the workspace), so move it there",
                        manifest.display(),
                        found.display()
                    ),
                )
            };
            if boundary.is_none() {
                boundary = Some(path_dependency_boundary(&lock_root, host).map_err(refuse)?);
            }
            let within = boundary.as_deref().expect("set above");
            let Ok(relative) = found.strip_prefix(within) else {
                return Err(refuse(format!("which is outside {}", within.display())));
            };
            let hidden = relative
                .components()
                .any(|component| component.as_os_str().to_string_lossy().starts_with('.'));
            if hidden {
                return Err(refuse("which is in a hidden directory".to_string()));
            }
            if lock_root.starts_with(&found) {
                return Err(refuse(format!(
                    "which contains the workspace root {}",
                    lock_root.display()
                )));
            }
            let nested = found.join("Cargo.toml");
            if nested.is_file() {
                manifests.push(nested);
            }
            outside.retain(|seen| !seen.starts_with(&found));
            outside.push(found);
        }
    }
    outside.sort();
    Ok(outside)
}

/// The directory a workspace's out-of-root path dependencies must lie in:
/// the nearest ancestor of `lock_root` holding `.git` (the repository a
/// monorepo shares), else `lock_root`'s parent (sibling crates). Neither
/// may be `/` or the home directory, which would let a manifest pull in
/// anything the user owns.
fn path_dependency_boundary(lock_root: &Path, host: &Host) -> Result<PathBuf, String> {
    let repository = lock_root
        .ancestors()
        .take_while(|dir| {
            host.ceiling
                .as_ref()
                .is_none_or(|ceiling| dir.starts_with(ceiling))
        })
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf);
    let boundary = match repository {
        Some(repository) => repository,
        None => lock_root
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "and the workspace is at the filesystem root".to_string())?,
    };
    let home = host
        .home
        .as_ref()
        .and_then(|home| std::fs::canonicalize(home).ok());
    if boundary.parent().is_none() || home.as_deref() == Some(boundary.as_path()) {
        return Err(format!(
            "and the directory that would bound it is {}",
            boundary.display()
        ));
    }
    Ok(boundary)
}

/// Every `Cargo.toml` under `root`, skipping hidden directories and
/// cargo's build output, and not following symlinks.
fn manifests_under(root: &Path) -> io::Result<Vec<PathBuf>> {
    const MAX_DEPTH: usize = 12;
    let mut found = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            found.push(manifest);
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let skip = name.to_string_lossy().starts_with('.')
                || name == "target"
                || name == "node_modules";
            if !skip && entry.file_type()?.is_dir() {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(found)
}

/// [`path_dependencies`] of `manifest`, refusing the signing key: the
/// Cargo tailor's receipt walks a workspace's path dependencies with it.
pub fn manifest_path_dependencies(manifest: &Path) -> io::Result<Vec<String>> {
    let dir = manifest.parent().unwrap_or(Path::new("/"));
    path_dependencies(manifest, &Bound::new(dir)?)
}

/// The `path` of every dependency-like entry in `manifest`: the
/// dependency tables (also under `target.<cfg>` and `workspace`),
/// `[patch.<source>]`, and `[replace]`. `[lib]` and `[[bin]]` paths name
/// files of the package itself and are not read. A manifest that does not
/// parse is left for cargo to report.
fn path_dependencies(manifest: &Path, keys: &Bound) -> io::Result<Vec<String>> {
    const TABLES: [&str; 5] = [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "patch",
        "replace",
    ];
    keys.refuse_if_key(manifest)?;
    let text = std::fs::read_to_string(manifest)?;
    let Ok(value) = toml::from_str::<toml::Table>(&text) else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    let mut tables: Vec<&toml::Table> = vec![&value];
    if let Some(workspace) = value.get("workspace").and_then(|w| w.as_table()) {
        tables.push(workspace);
    }
    if let Some(platforms) = value.get("target").and_then(|t| t.as_table()) {
        tables.extend(platforms.values().filter_map(|t| t.as_table()));
    }
    for table in tables {
        for name in TABLES {
            let Some(entries) = table.get(name).and_then(|d| d.as_table()) else {
                continue;
            };
            // `[patch.<source>]` nests one level deeper than the others.
            let mut stack: Vec<&toml::Value> = entries.values().collect();
            while let Some(entry) = stack.pop() {
                let Some(entry) = entry.as_table() else {
                    continue;
                };
                match entry.get("path").and_then(|p| p.as_str()) {
                    Some(path) => paths.push(path.to_string()),
                    None if name == "patch" => stack.extend(entry.values()),
                    None => {}
                }
            }
        }
    }
    Ok(paths)
}

/// A workspace's members inside its root, as cargo 1.98 finds them.
pub(crate) struct Members {
    /// The member directories (relative to the root) that hold a
    /// `Cargo.toml`.
    pub(crate) listed: Vec<PathBuf>,
    /// Members reached through a symlinked directory. cargo follows the
    /// link; the door's stage copies the link, not what it points at, so a
    /// confined cargo would resolve without them, and a record names files
    /// by their place in the workspace. They are not listed, and
    /// [`refuse_unlisted_members`] refuses every confined cargo run on the
    /// workspace (lock generation, edits, attest) rather than publish a
    /// lock or a record that leaves them out.
    pub(crate) through_symlinks: Vec<PathBuf>,
}

/// The member directories (relative to `root`) its `[workspace]` names:
/// each `members` entry, a path or a glob, that holds a `Cargo.toml` and is
/// not under an `exclude` entry, as cargo 1.98.1 lists them. A glob is
/// expanded the way cargo's `glob` crate does ([`expand`]): `*`, `?` and
/// `[...]` within a name, `**` across directories, a wildcard matching a
/// name that starts with `.`, `target` like any other directory. A member
/// outside the root (`../x`) is not listed: the door publishes only inside
/// its lock root.
pub(crate) fn member_dirs(root: &ProjectRoot) -> io::Result<Members> {
    let mut members = Members {
        listed: Vec::new(),
        through_symlinks: Vec::new(),
    };
    let Some(text) = root.read_input_string(Path::new("Cargo.toml"))? else {
        return Ok(members);
    };
    let manifest = parse_toml(&root.path().join("Cargo.toml"), &text)?;
    let workspace = manifest.get("workspace").and_then(|w| w.as_table());
    let list = |key: &str| -> Vec<String> {
        workspace
            .and_then(|w| w.get(key))
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .filter_map(relative_pattern)
                    .collect()
            })
            .unwrap_or_default()
    };
    let exclude: Vec<PathBuf> = list("exclude").iter().map(PathBuf::from).collect();
    for pattern in list("members") {
        let expanded = expand(root.path(), &pattern)?;
        for dir in expanded.dirs {
            let excluded = exclude.iter().any(|ex| dir.starts_with(ex));
            if !excluded
                && root.is_input_file(&dir.join("Cargo.toml"))
                && !members.listed.contains(&dir)
            {
                members.listed.push(dir);
            }
        }
        for dir in expanded.through_symlinks {
            let excluded = exclude.iter().any(|ex| dir.starts_with(ex));
            if !excluded && !members.through_symlinks.contains(&dir) {
                members.through_symlinks.push(dir);
            }
        }
    }
    members.listed.sort();
    members.through_symlinks.sort();
    Ok(members)
}

/// Refuse to attest a workspace with a member reached through a symlinked
/// directory ([`Members::through_symlinks`]) before a confined cargo runs
/// on it: cargo in the stage would not see the member and would resolve
/// without it, and a record could not name it. A sync from a committed
/// lock runs no cargo and is not refused.
pub fn refuse_unlisted_members(root: &ProjectRoot) -> io::Result<()> {
    let members = member_dirs(root)?;
    if members.through_symlinks.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = members
        .through_symlinks
        .iter()
        .map(|dir| dir.display().to_string())
        .collect();
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "the Cargo workspace at {} has members reached through a symlinked directory ({}); \
             the confined cargo sees the workspace's own files only, so it would resolve \
             without them, and a resolution record could not name them. Replace the symlinks \
             with the directories",
            root.path().display(),
            named.join(", ")
        ),
    ))
}

/// A members or exclude entry as a path under the root: `./` and a
/// trailing `/` dropped, `None` for one that leaves the root.
fn relative_pattern(entry: &str) -> Option<String> {
    let trimmed = entry.trim_start_matches("./").trim_end_matches('/');
    let path = Path::new(trimmed);
    let inside = !trimmed.is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    inside.then(|| trimmed.to_string())
}

/// What a members entry names under the root.
#[derive(Default)]
pub(crate) struct Expanded {
    /// Directories it matches, reached without a symlink.
    dirs: Vec<PathBuf>,
    /// Directories it matches, or may match below, through a symlink to a
    /// directory: not followed.
    through_symlinks: Vec<PathBuf>,
}

/// One `/`-separated part of a members glob.
enum Part {
    /// `**`: any number of directories, none included.
    AnyDepth,
    /// A name pattern: `*`, `?` and `[...]` (`[!...]` negated, `a-z`
    /// ranges, a `]` first taken literally), everything else literal.
    Name(Vec<char>),
}

/// The directories under `root` a members entry names, the way cargo's
/// `glob` crate (default options) expands it: `*` and `?` and classes
/// within one name, `**` across directories, a leading `.` matched by a
/// wildcard, no directory skipped. A pattern the `glob` crate would refuse
/// (`**` inside a name, an unclosed `[`) is an error, as it is for cargo.
/// Symlinks are not followed, so the walk ends on any tree; a symlinked
/// directory it would enter is reported instead
/// ([`Expanded::through_symlinks`]).
pub(crate) fn expand(root: &Path, pattern: &str) -> io::Result<Expanded> {
    let invalid = |why: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("workspace members entry {pattern:?} is not a valid glob: {why}"),
        )
    };
    let mut parts = Vec::new();
    for part in pattern.split('/').filter(|part| !part.is_empty()) {
        if part == "**" {
            parts.push(Part::AnyDepth);
            continue;
        }
        if part.contains("**") {
            return Err(invalid("`**` must be a whole path component"));
        }
        let chars: Vec<char> = part.chars().collect();
        check_classes(&chars).map_err(invalid)?;
        parts.push(Part::Name(chars));
    }
    let mut out = Expanded::default();
    let mut seen: std::collections::BTreeSet<(PathBuf, usize)> = Default::default();
    let mut stack = vec![(PathBuf::new(), 0usize)];
    while let Some((relative, index)) = stack.pop() {
        if !seen.insert((relative.clone(), index)) {
            continue;
        }
        let Some(part) = parts.get(index) else {
            if !relative.as_os_str().is_empty() && !out.dirs.contains(&relative) {
                out.dirs.push(relative);
            }
            continue;
        };
        if let Part::AnyDepth = part {
            // None of it: the next part, here.
            stack.push((relative.clone(), index + 1));
        }
        let entries = match std::fs::read_dir(root.join(&relative)) {
            Ok(entries) => entries,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                continue
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("read {}: {error}", root.join(&relative).display()),
                ))
            }
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let child = relative.join(&name);
            let next = match part {
                Part::AnyDepth => index,
                Part::Name(chars) => {
                    let name: Vec<char> = name.to_string_lossy().chars().collect();
                    if !name_matches(chars, &name) {
                        continue;
                    }
                    index + 1
                }
            };
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push((child, next));
            } else if kind.is_symlink()
                && root.join(&child).is_dir()
                && !out.through_symlinks.contains(&child)
            {
                out.through_symlinks.push(child);
            }
        }
    }
    Ok(out)
}

/// Every `[` in a name pattern is closed, as the `glob` crate requires.
fn check_classes(pattern: &[char]) -> Result<(), &'static str> {
    let mut index = 0;
    while index < pattern.len() {
        if pattern[index] == '[' {
            match class_end(pattern, index) {
                Some(end) => index = end + 1,
                None => return Err("a `[` is not closed"),
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

/// The index of the `]` closing the class that opens at `open`: one may
/// follow `[` or `[!` and be taken literally.
fn class_end(pattern: &[char], open: usize) -> Option<usize> {
    let mut index = open + 1;
    if pattern.get(index) == Some(&'!') {
        index += 1;
    }
    if pattern.get(index) == Some(&']') {
        index += 1;
    }
    (index..pattern.len()).find(|&at| pattern[at] == ']')
}

/// Whether `name` matches the name pattern `pattern` (`glob` crate rules,
/// case-sensitive, a leading `.` not special).
fn name_matches(pattern: &[char], name: &[char]) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some('*') => (0..=name.len()).any(|skip| name_matches(&pattern[1..], &name[skip..])),
        Some('?') => !name.is_empty() && name_matches(&pattern[1..], &name[1..]),
        Some('[') => {
            let Some(end) = class_end(pattern, 0) else {
                return false;
            };
            let Some(&first) = name.first() else {
                return false;
            };
            let (negated, body) = match pattern.get(1) {
                Some('!') => (true, &pattern[2..end]),
                _ => (false, &pattern[1..end]),
            };
            let mut hit = false;
            let mut at = 0;
            while at < body.len() {
                if at + 2 < body.len() && body[at + 1] == '-' {
                    hit |= body[at] <= first && first <= body[at + 2];
                    at += 3;
                } else {
                    hit |= body[at] == first;
                    at += 1;
                }
            }
            hit != negated && name_matches(&pattern[end + 1..], &name[1..])
        }
        Some(&literal) => name.first() == Some(&literal) && name_matches(&pattern[1..], &name[1..]),
    }
}

/// The `ConfinedSpec` of `run`, through the process proxy with TLS
/// interception on the crates.io route. Tests replace the route, the
/// proxy, and the permitted set.
pub fn cargo_confined<'a>(
    run: &CargoRun<'a>,
    publish: CargoPublish<'a>,
    registries: &'a [String],
) -> io::Result<ConfinedSpec<'a>> {
    let mut confined = ConfinedSpec::new("cargo", "cargo", WHY);
    confined.forced.rust = Some(run.rust_obj);
    confined.forced.cargo_registries = registries;
    confined.store_reads = vec![run.rust_obj.to_path_buf()];
    confined.extra_roots = path_dependency_roots(run.lock_root)?;
    // cargo's build output is not a resolution input.
    confined.exclude = vec![PathGlob::new("target")?];
    confined.routes = vec![crates_index::route()?];
    confined.intercept = Intercept::Tls;
    confined.wire = Some(Box::new(|wire: &Wire<'_>| wiring(wire)));
    match publish {
        CargoPublish::Project { outputs, receipt } => {
            // A record names files inside the workspace only, so it cannot
            // cover a path dependency outside it: the lock is published
            // without one, and a sync records `unrecorded-resolution`.
            let receipt = match receipt {
                Some(_) if !confined.extra_roots.is_empty() => {
                    let outside: Vec<String> = confined
                        .extra_roots
                        .iter()
                        .map(|root| root.display().to_string())
                        .collect();
                    crate::kernel::ui::note(&format!(
                        "the lock is published without a resolution record: the workspace \
                         reads path dependencies outside it ({}), which a record cannot name",
                        outside.join(", ")
                    ));
                    None
                }
                receipt => receipt,
            };
            confined.outputs = outputs;
            confined.target = Target::Project { receipt };
        }
        CargoPublish::Detached { outputs } => {
            confined.outputs = outputs;
            confined.target = Target::Detached;
        }
    }
    Ok(confined)
}

/// `--config` pairs, forced ones included, before the subcommand; a scratch
/// `CARGO_HOME`.
fn wiring(wire: &Wire<'_>) -> io::Result<Wiring> {
    let ca_file = wire.ca_file.ok_or_else(|| {
        io::Error::other("cargo resolves only through TLS interception, which this run lacks")
    })?;
    let config = |key: &str, value: &str| -> [OsString; 2] {
        // TOML strings: the proxy URL and the CA path hold no quote or
        // backslash (a token is hex, the CA path is fixed).
        ["--config".into(), format!("{key}=\"{value}\"").into()]
    };
    let mut args: Vec<OsString> = Vec::new();
    args.extend(config("http.proxy", &wire.address.proxy_url()));
    args.extend(config("http.cainfo", &ca_file.to_string_lossy()));
    args.extend(wire.forced_args.iter().cloned());
    args.extend(wire.args.iter().cloned());
    Ok(Wiring {
        args,
        env: vec![(
            "CARGO_HOME".into(),
            wire.scratch.join("cargo-home").into_os_string(),
        )],
        ..Wiring::default()
    })
}

/// Run the store cargo confined through `door`. A Detached run's ledger
/// ids come back in the report for the caller to root.
pub fn run_cargo(
    door: &mut ResolutionDoor<'_>,
    mut run: CargoRun<'_>,
) -> io::Result<DelegateReport> {
    let publish = std::mem::replace(
        &mut run.publish,
        CargoPublish::Detached {
            outputs: Vec::new(),
        },
    );
    let registries = configured_registries(run.lock_root)?;
    let confined = cargo_confined(&run, publish, &registries)?;
    let spec = cargo_spec(run.rust_obj, run.lock_root, run.args);
    spec.trace();
    door.run_confined(spec, confined).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("store cargo {}: {error}", run.args.join(" ")),
        )
    })
}

/// `run_cargo` that fails on a nonzero exit, naming cargo's own words.
pub fn run_cargo_checked(
    door: &mut ResolutionDoor<'_>,
    run: CargoRun<'_>,
) -> io::Result<DelegateReport> {
    let args = run.args.join(" ");
    let report = run_cargo(door, run)?;
    if !report.status.success() {
        return Err(io::Error::other(format!(
            "store cargo {args} failed: {}",
            confine::scrub_signing_key(String::from_utf8_lossy(&report.stderr).trim())
        )));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// Path dependencies outside the lock root are read roots, found
    /// through every manifest under it and transitively through theirs;
    /// paths inside the root, package file paths, and missing paths are
    /// not.
    #[test]
    fn out_of_root_path_dependencies_are_read_roots() {
        let temp = TempDir::named("cargo-path-roots");
        let write = |relative: &str, text: &str| {
            let path = temp.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(
            "ws/Cargo.toml",
            "[workspace]\nmembers = [\"app\"]\n[workspace.dependencies]\n\
             shared = { path = \"../shared\" }\n\
             [patch.crates-io]\nitoa = { path = \"../patched\" }\n",
        );
        write(
            "ws/app/Cargo.toml",
            "[package]\nname = \"app\"\n[lib]\npath = \"../../elsewhere/lib.rs\"\n\
             [dependencies]\ninner = { path = \"../inner\" }\n\
             missing = { path = \"../../nope\" }\n\
             [target.'cfg(unix)'.dev-dependencies]\nunixy = { path = \"../../unixy\" }\n",
        );
        write("ws/inner/Cargo.toml", "[package]\nname = \"inner\"\n");
        write(
            "shared/Cargo.toml",
            "[package]\nname = \"shared\"\n[dependencies]\ndeep = { path = \"../deep\" }\n",
        );
        write("deep/Cargo.toml", "[package]\nname = \"deep\"\n");
        write("patched/Cargo.toml", "[package]\nname = \"itoa\"\n");
        write("unixy/Cargo.toml", "[package]\nname = \"unixy\"\n");
        write("elsewhere/lib.rs", "");
        write(
            "ws/target/debug/Cargo.toml",
            "[dependencies]\nx = { path = \"../../../elsewhere\" }\n",
        );
        let root = temp.0.canonicalize().unwrap();
        let host = Host {
            home: None,
            ceiling: Some(root.clone()),
        };
        let names: Vec<String> = bounded_path_dependency_roots(&temp.0.join("ws"), &host)
            .unwrap()
            .iter()
            .map(|path| path.strip_prefix(&root).unwrap().display().to_string())
            .collect();
        assert_eq!(names, vec!["deep", "patched", "shared", "unixy"]);
    }

    /// A manifest does not choose host directories: a path dependency
    /// outside the boundary, in a hidden directory, or containing the
    /// workspace is refused, naming the manifest, and a boundary that
    /// would be the home directory is refused too. Inside a repository the
    /// boundary is the repository, so a monorepo's `../../libs/x` is read.
    #[test]
    fn path_dependencies_outside_the_boundary_are_refused() {
        let temp = TempDir::named("cargo-path-bounds");
        let write = |relative: &str, text: &str| {
            let path = temp.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        let depends_on = |path: &str| {
            format!("[package]\nname = \"ws\"\n[dependencies]\nx = {{ path = {path:?} }}\n")
        };
        write("hidden/.cargo/Cargo.toml", "[package]\nname = \"x\"\n");
        // The repository search stops at the temporary directory, so a
        // `.git` above it (`/tmp/.git` on some machines) changes nothing.
        let ceiling = temp.0.canonicalize().unwrap();
        let host = |home: Option<PathBuf>| Host {
            home,
            ceiling: Some(ceiling.clone()),
        };
        let cases = [
            ("/", "outside"),
            ("../..", "outside"),
            ("../.cargo", "hidden directory"),
            ("..", "contains the workspace root"),
        ];
        for (path, why) in cases {
            write("hidden/ws/Cargo.toml", &depends_on(path));
            let error = bounded_path_dependency_roots(&temp.0.join("hidden/ws"), &host(None))
                .unwrap_err()
                .to_string();
            assert!(error.contains(why), "{path}: {error}");
            assert!(error.contains("hidden/ws/Cargo.toml"), "{path}: {error}");
        }

        // Outside a repository the boundary is the workspace's parent,
        // which may not be the home directory.
        write("home/ws/Cargo.toml", &depends_on("../shared"));
        write("home/shared/Cargo.toml", "[package]\nname = \"x\"\n");
        let home = temp.0.join("home");
        let error = bounded_path_dependency_roots(&home.join("ws"), &host(Some(home.clone())))
            .unwrap_err()
            .to_string();
        assert!(error.contains("would bound it"), "{error}");

        // Inside a repository the repository is the boundary.
        std::fs::create_dir_all(temp.0.join("repo/.git")).unwrap();
        write("repo/apps/ws/Cargo.toml", &depends_on("../../libs/x"));
        write("repo/libs/x/Cargo.toml", "[package]\nname = \"x\"\n");
        let roots =
            bounded_path_dependency_roots(&temp.0.join("repo/apps/ws"), &host(Some(home.clone())))
                .unwrap();
        let expected = temp.0.join("repo/libs/x").canonicalize().unwrap();
        assert_eq!(roots, vec![expected]);
    }

    /// A fake signing key: the line a TOML parser would quote.
    const SEED: &str = "SEEDBYTES0123456789abcdef";

    fn fake_key(dir: &Path) -> PathBuf {
        let key = dir.join("signing.key");
        std::fs::write(&key, format!("ed25519:{SEED}\n")).unwrap();
        key
    }

    /// A cargo file that is the signing key under another name is refused
    /// by name, whether it is a symlink to the key (outside the root or in
    /// it), a hard link to it (the same inode, no symlink at all), or a file
    /// another config includes; no byte of it reaches the error.
    #[test]
    fn cargo_files_that_are_the_signing_key_are_refused_without_its_bytes() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::named("cargo-key-files");
        let key = fake_key(&temp.0);
        let root = temp.0.join("ws");
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        let bound = Bound::with_keys(&root, std::slice::from_ref(&key)).unwrap();
        let refused = |result: io::Result<Vec<ConfigFile>>| {
            let error = result.err().expect("refused").to_string();
            assert!(error.contains("is the signing key"), "{error}");
            assert!(
                !error.contains(SEED),
                "the key's bytes reached the error: {error}"
            );
        };
        let config = root.join(".cargo/config.toml");
        // A symlink to the key.
        symlink(&key, &config).unwrap();
        refused(config_files(&root, &bound));
        std::fs::remove_file(&config).unwrap();
        // A hard link to the key, inside the root.
        std::fs::hard_link(&key, &config).unwrap();
        refused(config_files(&root, &bound));
        std::fs::remove_file(&config).unwrap();
        // An included file hard-linked to the key.
        std::fs::write(&config, "include = [\"key.toml\"]\n").unwrap();
        std::fs::hard_link(&key, root.join(".cargo/key.toml")).unwrap();
        refused(config_files(&root, &bound));
        std::fs::remove_file(root.join(".cargo/key.toml")).unwrap();
        // The key inside the root, by its own name, is the key too.
        let inner = root.join("keys/signing.key");
        std::fs::create_dir_all(inner.parent().unwrap()).unwrap();
        std::fs::rename(&key, &inner).unwrap();
        let bound = Bound::with_keys(&root, std::slice::from_ref(&inner)).unwrap();
        std::fs::write(&config, "include = [\"../keys/signing.toml\"]\n").unwrap();
        symlink(&inner, root.join("keys/signing.toml")).unwrap();
        refused(config_files(&root, &bound));
        // A manifest hard-linked to it is refused before it is read.
        std::fs::remove_file(&config).unwrap();
        std::fs::hard_link(&inner, root.join("Cargo.toml")).unwrap();
        let error = path_dependencies(&root.join("Cargo.toml"), &bound)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is the signing key"), "{error}");
        assert!(!error.contains(SEED), "{error}");
    }

    /// tog's own readers name a parse error's position, never its text,
    /// and refuse a config that leads out of the lock root.
    #[test]
    fn toml_errors_never_echo_the_file() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::named("cargo-toml-echo");
        let key = fake_key(&temp.0);
        let root = temp.0.join("ws");
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        // A malformed file of the project's own.
        std::fs::write(root.join(".cargo/config.toml"), format!("ed25519:{SEED}\n")).unwrap();
        let error = configured_registries(&root).unwrap_err().to_string();
        assert!(error.contains("is not valid TOML at line 1"), "{error}");
        assert!(!error.contains(SEED), "{error}");
        // A config that is a symlink out of the lock root.
        std::fs::remove_file(root.join(".cargo/config.toml")).unwrap();
        symlink(&key, root.join(".cargo/config.toml")).unwrap();
        let error = configured_registries(&root).unwrap_err().to_string();
        assert!(error.contains("outside"), "{error}");
        assert!(!error.contains(SEED), "{error}");
        // The lock the plan reads.
        let error =
            crate::kernel::provider::crates::plan_cargo(&format!("ed25519:{SEED}\n"), "1.98.1")
                .map(drop)
                .unwrap_err()
                .to_string();
        assert!(error.contains("Cargo.lock is not valid TOML"), "{error}");
        assert!(!error.contains(SEED), "{error}");
    }

    /// Registries declared in included files (a path or a `{ path }`
    /// table, nested, relative to the including file) are found, so each
    /// gets the forced provider. An include that leads out of the lock root
    /// is refused by name, as is one through a symlink.
    #[test]
    fn included_config_files_are_read_and_bounded() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::named("cargo-includes");
        let root = temp.0.join("ws");
        std::fs::create_dir_all(root.join(".cargo/sub")).unwrap();
        let write = |relative: &str, text: &str| {
            std::fs::write(root.join(relative), text).unwrap();
        };
        write(
            ".cargo/config.toml",
            "include = [\"sub/a.toml\", { path = \"opt.toml\", optional = true }]\n\
             [registries.top]\nindex = \"sparse+https://top.test/\"\n",
        );
        write(
            ".cargo/sub/a.toml",
            "include = [\"b.toml\"]\n[registries.evil]\nindex = \"sparse+https://evil.test/\"\n",
        );
        write(
            ".cargo/sub/b.toml",
            "[registries.deep]\nindex = \"sparse+https://deep.test/\"\n",
        );
        assert_eq!(
            configured_registries(&root).unwrap(),
            vec!["deep", "evil", "top"]
        );
        let bound = Bound::new(&root).unwrap();
        let real = root.canonicalize().unwrap();
        let files: Vec<PathBuf> = config_files(&root, &bound)
            .unwrap()
            .into_iter()
            .map(|file| file.real.strip_prefix(&real).unwrap().to_path_buf())
            .collect();
        assert_eq!(
            files,
            [
                ".cargo/config.toml",
                ".cargo/sub/a.toml",
                ".cargo/sub/b.toml"
            ]
            .map(PathBuf::from)
            .to_vec()
        );

        // Out of the root, by path and by symlink.
        std::fs::write(temp.0.join("outside.toml"), "[registries.x]\n").unwrap();
        write(
            ".cargo/sub/b.toml",
            "include = [\"../../../outside.toml\"]\n",
        );
        let error = configured_registries(&root).unwrap_err().to_string();
        assert!(error.contains("outside"), "{error}");
        write(".cargo/sub/b.toml", "");
        symlink(temp.0.join("outside.toml"), root.join(".cargo/opt.toml")).unwrap();
        let error = configured_registries(&root).unwrap_err().to_string();
        assert!(error.contains("outside"), "{error}");
    }

    /// A project door keeps its receipt for a self-contained workspace and
    /// drops it when the workspace reads a path dependency outside its
    /// root, which a record cannot name.
    #[test]
    fn a_workspace_with_external_path_dependencies_publishes_no_receipt() {
        let temp = TempDir::named("cargo-receipt");
        let root = temp.0.join("ws");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"ws\"\n").unwrap();
        let confined = |root: &Path| {
            let producer: ReceiptProducer<'static> = Box::new(|_| Ok(None));
            let publish = || CargoPublish::Project {
                outputs: Vec::new(),
                receipt: Some(Box::new(|_| Ok(None))),
            };
            let run = CargoRun {
                rust_obj: Path::new("/nonexistent/rust"),
                lock_root: root,
                args: &["generate-lockfile"],
                publish: publish(),
            };
            let spec = cargo_confined(
                &run,
                CargoPublish::Project {
                    outputs: Vec::new(),
                    receipt: Some(producer),
                },
                &[],
            )
            .unwrap();
            matches!(spec.target, Target::Project { receipt: Some(_) })
        };
        assert!(
            confined(&root),
            "a self-contained workspace keeps its receipt"
        );
        std::fs::create_dir_all(temp.0.join("shared")).unwrap();
        std::fs::write(
            temp.0.join("shared/Cargo.toml"),
            "[package]\nname = \"s\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"ws\"\n[dependencies]\nshared = { path = \"../shared\" }\n",
        )
        .unwrap();
        assert!(!confined(&root), "an external path dependency drops it");
    }

    #[test]
    fn registries_are_read_from_both_config_spellings() {
        let temp = TempDir::named("cargo-registries");
        assert!(configured_registries(&temp.0).unwrap().is_empty());
        std::fs::create_dir_all(temp.0.join(".cargo")).unwrap();
        std::fs::write(
            temp.0.join(".cargo/config.toml"),
            "[registries.internal]\nindex = \"sparse+https://cargo.internal.test/\"\n\
             [registries.other]\nindex = \"sparse+https://other.test/\"\n",
        )
        .unwrap();
        std::fs::write(
            temp.0.join(".cargo/config"),
            "[registries]\nlegacy = { index = \"https://legacy.test/index\" }\n\
             internal = { index = \"sparse+https://cargo.internal.test/\" }\n",
        )
        .unwrap();
        assert_eq!(
            configured_registries(&temp.0).unwrap(),
            vec!["internal", "legacy", "other"]
        );
        std::fs::write(temp.0.join(".cargo/config"), "[registries\n").unwrap();
        assert!(configured_registries(&temp.0).is_err());
    }
}

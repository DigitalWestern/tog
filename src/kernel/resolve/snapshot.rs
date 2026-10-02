//! The staged snapshot a resolution tool runs on, its baseline manifest,
//! and the content-digest diff that decides what the tool changed (kernel
//! layer).
//!
//! The real project is never mounted where a resolution tool can write it.
//! Before the tool starts, every project-side tree it reads (the lock root
//! and each extra read root) is copied into a private store stage: regular
//! files (reflinked with `FICLONE` where the filesystem allows, otherwise
//! copied), directories and symlinks. Sockets, FIFOs and device nodes are
//! left out, so the snapshot holds no socket to connect to. Excluded paths
//! (heavy build outputs a tailor names) are left out too.
//!
//! The stage mirrors absolute paths: a root at `/p/app` is staged at
//! `<stage>/tree/p/app`. On Linux each staged root is bind-mounted back at
//! its real path, so the tool sees real paths everywhere; the mirrored
//! layout also keeps every root at the same position relative to every
//! other, which is what an engine that cannot remap paths needs.
//!
//! While copying, the baseline manifest records each entry's type, mode,
//! and, for a regular file, the SHA-256 of the bytes written into the stage
//! (for a symlink, its target). After the tool has stopped, the stage is
//! walked again and compared by content. Timestamps are never consulted:
//! a same-second rewrite with other bytes is a change, and a byte-identical
//! rewrite is not. Neither walk follows a symlink.
//!
//! Each changed path is then classified. A declared output must still be a
//! regular file reached through real directories. Declared scratch is
//! discarded. Anything else, and always a new `.git`, a change under
//! `.git/hooks`, or a change under `.tog`, fails the door naming the paths.

use crate::kernel::activity::StoreActivity;
use crate::kernel::store::{self, Store};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

/// A path pattern relative to a snapshot root: `/`-separated components,
/// `*` and `?` inside one component, `**` for any number of components. A
/// path matches when the pattern matches it or one of its ancestors, so
/// `obj` and `**/node_modules` cover everything below the directory too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathGlob {
    pattern: String,
    parts: Vec<String>,
}

impl PathGlob {
    pub fn new(pattern: &str) -> io::Result<PathGlob> {
        let invalid = |reason: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path pattern {pattern:?} {reason}"),
            )
        };
        if pattern.is_empty() || pattern.starts_with('/') {
            return Err(invalid("must be a non-empty relative pattern"));
        }
        let parts: Vec<String> = pattern.split('/').map(str::to_string).collect();
        if parts
            .iter()
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid("has an empty, `.` or `..` component"));
        }
        Ok(PathGlob {
            pattern: pattern.to_string(),
            parts,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Does the pattern cover `relative` (itself or an ancestor)?
    pub fn matches(&self, relative: &Path) -> bool {
        let components: Vec<&[u8]> = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.as_bytes()),
                _ => None,
            })
            .collect();
        (1..=components.len()).any(|end| match_parts(&self.parts, &components[..end]))
    }
}

fn match_parts(parts: &[String], components: &[&[u8]]) -> bool {
    match parts.split_first() {
        None => components.is_empty(),
        Some((first, rest)) if first == "**" => {
            (0..=components.len()).any(|skip| match_parts(rest, &components[skip..]))
        }
        Some((first, rest)) => match components.split_first() {
            Some((component, tail)) => {
                match_component(first.as_bytes(), component) && match_parts(rest, tail)
            }
            None => false,
        },
    }
}

fn match_component(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|skip| match_component(rest, &name[skip..])),
        Some((b'?', rest)) => !name.is_empty() && match_component(rest, &name[1..]),
        Some((byte, rest)) => name.first() == Some(byte) && match_component(rest, &name[1..]),
    }
}

/// What one manifest entry was, compared by content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryState {
    File {
        mode: u32,
        sha256: [u8; 32],
    },
    Dir {
        mode: u32,
    },
    Symlink {
        target: OsString,
    },
    /// A FIFO, socket or device that appeared after the baseline. The
    /// baseline never holds one.
    Special {
        kind: &'static str,
    },
}

impl EntryState {
    pub fn kind(&self) -> &'static str {
        match self {
            EntryState::File { .. } => "regular file",
            EntryState::Dir { .. } => "directory",
            EntryState::Symlink { .. } => "symlink",
            EntryState::Special { kind } => kind,
        }
    }
}

/// One path whose entry differs between the baseline and the post-run walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The real path the tool saw.
    pub path: PathBuf,
    /// Index into the snapshot's roots, and the path relative to that root.
    pub root: usize,
    pub relative: PathBuf,
    pub before: Option<EntryState>,
    pub after: Option<EntryState>,
}

/// What the snapshot is built from.
pub struct SnapshotSpec<'a> {
    /// The lock root: the project, or the workspace root.
    pub lock_root: &'a Path,
    /// Project-side read roots outside the lock root (an out-of-root path
    /// dependency). Store objects are not snapshotted; they are bound
    /// read-only as they are.
    pub extra_roots: &'a [PathBuf],
    /// Paths, relative to each root, that are neither copied nor diffed.
    pub exclude: &'a [PathGlob],
}

/// One snapshotted tree.
#[derive(Clone, Debug)]
pub struct Root {
    pub real: PathBuf,
    pub staged: PathBuf,
}

/// The paths a door run classified from the diff.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Classified {
    /// Declared outputs, relative to the lock root, that the tool changed.
    /// Each is a regular file in the stage reached through real directories.
    pub outputs: Vec<PathBuf>,
    /// Changed paths that matched declared scratch; discarded.
    pub scratch: Vec<PathBuf>,
}

/// A staged snapshot: the private stage, its roots, and the baseline. The
/// stage is removed when this is dropped.
#[derive(Debug)]
pub struct Snapshot {
    stage: PathBuf,
    roots: Vec<Root>,
    lock_root: usize,
    scratch: PathBuf,
    exclude: Vec<PathGlob>,
    baseline: BTreeMap<PathBuf, EntryState>,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = remove_private_tree(&self.stage);
    }
}

impl Snapshot {
    /// Copy the lock root and each extra root into a new 0700 stage under
    /// the store's `tmp/`, recording the baseline manifest on the way.
    pub fn build(
        store: &Store,
        activity: &StoreActivity,
        spec: &SnapshotSpec<'_>,
    ) -> io::Result<Snapshot> {
        store.require_activity(activity, "resolution snapshot")?;
        let (reals, lock_root) = normalize_roots(spec.lock_root, spec.extra_roots)?;
        let stage = create_private_dir(&store.root.join("tmp"), "resolve")?;
        let mut snapshot = Snapshot {
            scratch: stage.join("scratch"),
            roots: Vec::new(),
            lock_root,
            stage,
            exclude: spec.exclude.to_vec(),
            baseline: BTreeMap::new(),
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&snapshot.scratch)?;
        for real in reals {
            let staged = snapshot.staged_path(&real);
            let parent = staged.parent().expect("a staged root has a parent");
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
            let mut walk = Walk {
                exclude: &snapshot.exclude,
                entries: &mut snapshot.baseline,
            };
            walk.copy_root(&real, &staged)?;
            snapshot.roots.push(Root { real, staged });
        }
        Ok(snapshot)
    }

    /// The stage directory (tog-owned, 0700).
    pub fn stage(&self) -> &Path {
        &self.stage
    }

    /// A writable directory outside every snapshotted tree, for the tool's
    /// HOME, TMPDIR and caches. Never diffed and never published.
    pub fn scratch(&self) -> &Path {
        &self.scratch
    }

    pub fn roots(&self) -> &[Root] {
        &self.roots
    }

    /// The lock root's real and staged paths.
    pub fn lock_root(&self) -> &Root {
        &self.roots[self.lock_root]
    }

    /// Where `real` (absolute) lives in the stage.
    pub fn staged_path(&self, real: &Path) -> PathBuf {
        let relative = real.strip_prefix("/").unwrap_or(real);
        self.stage.join("tree").join(relative)
    }

    /// The baseline entry of a real path, if it was snapshotted.
    pub fn baseline(&self, real: &Path) -> Option<&EntryState> {
        self.baseline.get(real)
    }

    /// Walk the stage again and compare it with the baseline by content.
    /// Call only after the tool's whole process tree has stopped.
    pub fn diff(&self) -> io::Result<Vec<Change>> {
        let mut after = BTreeMap::new();
        for root in &self.roots {
            let mut walk = Walk {
                exclude: &self.exclude,
                entries: &mut after,
            };
            walk.scan_root(&root.real, &root.staged)?;
        }
        let mut changes = Vec::new();
        let paths: std::collections::BTreeSet<&PathBuf> =
            self.baseline.keys().chain(after.keys()).collect();
        for path in paths {
            let before = self.baseline.get(path);
            let now = after.get(path);
            if before == now {
                continue;
            }
            let (root, relative) = self.locate(path);
            changes.push(Change {
                path: path.clone(),
                root,
                relative,
                before: before.cloned(),
                after: now.cloned(),
            });
        }
        Ok(changes)
    }

    fn locate(&self, path: &Path) -> (usize, PathBuf) {
        for (index, root) in self.roots.iter().enumerate() {
            if let Ok(relative) = path.strip_prefix(&root.real) {
                return (index, relative.to_path_buf());
            }
        }
        (self.lock_root, path.to_path_buf())
    }

    /// Classify `changes`. `outputs` are the declared outputs, relative to
    /// the lock root; `scratch` is the declared scratch, also relative to
    /// the lock root. Every refusal names each offending path.
    pub fn classify(
        &self,
        changes: &[Change],
        outputs: &[PathBuf],
        scratch: &[PathGlob],
    ) -> io::Result<Classified> {
        for output in outputs {
            check_relative(output)?;
        }
        let mut problems = Vec::new();
        let mut classified = Classified::default();
        for output in outputs {
            if let Some(problem) = self.output_parent_problem(output)? {
                problems.push(problem);
            }
        }
        for change in changes {
            let at_lock_root = change.root == self.lock_root;
            if let Some(reason) = protected(&change.relative, change) {
                problems.push(format!("{} ({reason})", change.path.display()));
                continue;
            }
            if at_lock_root && outputs.contains(&change.relative) {
                match (&change.before, &change.after) {
                    (_, Some(EntryState::File { .. })) => {
                        classified.outputs.push(change.relative.clone())
                    }
                    (Some(_), None) => problems.push(format!(
                        "{} (a declared output the tool deleted)",
                        change.path.display()
                    )),
                    (_, Some(other)) => problems.push(format!(
                        "{} (a declared output that is now a {}, not a regular file)",
                        change.path.display(),
                        other.kind()
                    )),
                    (None, None) => {}
                }
                continue;
            }
            if at_lock_root && scratch.iter().any(|glob| glob.matches(&change.relative)) {
                classified.scratch.push(change.relative.clone());
                continue;
            }
            problems.push(format!("{} ({})", change.path.display(), describe(change)));
        }
        if problems.is_empty() {
            return Ok(classified);
        }
        problems.sort();
        problems.dedup();
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the resolution tool changed files it may not change, so nothing was \
                 published: {}",
                listing(&problems)
            ),
        ))
    }

    /// A declared output whose parent inside the stage is no longer a real
    /// directory (a symlink, a file) is refused by name.
    fn output_parent_problem(&self, output: &Path) -> io::Result<Option<String>> {
        let root = self.lock_root();
        let mut dir = open_dir(&root.staged)?;
        let mut shown = root.real.clone();
        let parents: Vec<&OsStr> = output
            .parent()
            .into_iter()
            .flat_map(Path::components)
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        for name in parents {
            shown.push(name);
            let stat = match store::stat_at(dir.as_raw_fd(), name.as_bytes()) {
                Ok(stat) => stat,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Ok(Some(format!(
                    "{} (a directory above the declared output {} is now a {})",
                    shown.display(),
                    output.display(),
                    special_kind(stat.st_mode)
                )));
            }
            dir = open_dir_at(dir.as_raw_fd(), name.as_bytes())?;
        }
        Ok(None)
    }
}

/// Why a change can never be accepted, whatever the spec declares.
fn protected(relative: &Path, change: &Change) -> Option<&'static str> {
    let names: Vec<&[u8]> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.as_bytes()),
            _ => None,
        })
        .collect();
    if names.first() == Some(&&b".tog"[..]) {
        return Some("tog's own state");
    }
    if let Some(at) = names.iter().position(|name| *name == b".git") {
        if names.get(at + 1) == Some(&&b"hooks"[..]) {
            return Some("a git hook");
        }
        if at + 1 == names.len() && change.before.is_none() {
            return Some("a new git repository");
        }
    }
    None
}

fn describe(change: &Change) -> String {
    match (&change.before, &change.after) {
        (None, Some(after)) => format!("new {}", after.kind()),
        (Some(before), None) => format!("removed {}", before.kind()),
        (Some(before), Some(after)) if before.kind() != after.kind() => {
            format!("{} became a {}", before.kind(), after.kind())
        }
        (Some(EntryState::Symlink { .. }), Some(_)) => "symlink target changed".to_string(),
        (Some(EntryState::File { mode: a, .. }), Some(EntryState::File { mode: b, .. }))
            if a != b =>
        {
            "mode changed".to_string()
        }
        (Some(EntryState::Dir { .. }), Some(_)) => "directory mode changed".to_string(),
        _ => "contents changed".to_string(),
    }
}

/// At most this many paths are named in one refusal.
const LISTED_PATHS: usize = 20;

pub(crate) fn listing(items: &[String]) -> String {
    let mut text = items
        .iter()
        .take(LISTED_PATHS)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if items.len() > LISTED_PATHS {
        text.push_str(&format!("; and {} more", items.len() - LISTED_PATHS));
    }
    text
}

/// A declared output path: relative, and made only of normal components.
pub(crate) fn check_relative(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    let normal = !bytes.is_empty()
        && !bytes.starts_with(b"/")
        && !bytes.contains(&0)
        && bytes
            .split(|byte| *byte == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..");
    if normal {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a plain relative path inside the lock root",
                path.display()
            ),
        ))
    }
}

/// Canonicalize the roots and drop any root inside another, so each tree is
/// staged once. Returns the kept roots and the index of the one holding the
/// lock root.
fn normalize_roots(lock_root: &Path, extra: &[PathBuf]) -> io::Result<(Vec<PathBuf>, usize)> {
    let canonical = |path: &Path| {
        fs::canonicalize(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("snapshot root {}: {error}", path.display()),
            )
        })
    };
    let lock = canonical(lock_root)?;
    let mut all = vec![lock.clone()];
    for root in extra {
        all.push(canonical(root)?);
    }
    all.sort();
    all.dedup();
    let mut kept: Vec<PathBuf> = Vec::new();
    for root in all {
        if !kept.iter().any(|outer| root.starts_with(outer)) {
            kept.push(root);
        }
    }
    let index = kept
        .iter()
        .position(|root| lock.starts_with(root))
        .expect("the lock root is under a kept root");
    if kept[index] != lock {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the extra read root {} contains the lock root {}; name the outer tree as \
                 the lock root instead",
                kept[index].display(),
                lock.display()
            ),
        ));
    }
    Ok((kept, index))
}

/// Create `<parent>/<prefix>-<32 hex>` with mode 0700. The random name is
/// unguessable, and `mkdir` fails rather than reuse anything already there.
pub(crate) fn create_private_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    for _ in 0..8 {
        let name = format!(
            "{prefix}-{}",
            hex::encode(crate::kernel::fsroot::urandom_bytes(16)?)
        );
        let path = parent.join(name);
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("create {}: {error}", path.display()),
                ))
            }
        }
    }
    Err(io::Error::other(format!(
        "could not create a private directory under {}",
        parent.display()
    )))
}

/// Remove a stage the tool may have made unreadable: every directory is
/// given back owner rwx before it is entered, and symlinks are never
/// followed.
pub(crate) fn remove_private_tree(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn open_up(path: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() {
            return Ok(());
        }
        let mode = metadata.permissions().mode();
        if mode & 0o700 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        }
        for entry in fs::read_dir(path)? {
            open_up(&entry?.path())?;
        }
        Ok(())
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        _ => {}
    }
    let _ = open_up(path);
    fs::remove_dir_all(path)
}

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

fn open_dir(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io::Error::new(error.kind(), format!("open {}: {error}", path.display())))
}

fn open_dir_at(dirfd: RawFd, name: &[u8]) -> io::Result<fs::File> {
    store::open_file_at(dirfd, name, DIR_FLAGS, 0)
}

fn special_kind(mode: libc::mode_t) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFREG => "regular file",
        libc::S_IFDIR => "directory",
        libc::S_IFLNK => "symlink",
        libc::S_IFIFO => "FIFO",
        libc::S_IFSOCK => "socket",
        libc::S_IFCHR => "character device",
        libc::S_IFBLK => "block device",
        _ => "special file",
    }
}

/// One walk over a tree, filling `entries` keyed by real path.
struct Walk<'a> {
    exclude: &'a [PathGlob],
    entries: &'a mut BTreeMap<PathBuf, EntryState>,
}

impl Walk<'_> {
    fn excluded(&self, relative: &Path) -> bool {
        self.exclude.iter().any(|glob| glob.matches(relative))
    }

    /// Copy `real` into `staged` (which must not exist yet).
    fn copy_root(&mut self, real: &Path, staged: &Path) -> io::Result<()> {
        let source = open_dir(real)?;
        let mode = store::fd_stat(source.as_raw_fd())?.st_mode as u32 & 0o777;
        let parent = open_dir(staged.parent().expect("staged root has a parent"))?;
        let name = staged.file_name().expect("staged root has a name");
        store::mkdir_at(parent.as_raw_fd(), name.as_bytes(), 0o700)?;
        let target = open_dir_at(parent.as_raw_fd(), name.as_bytes())?;
        self.copy_dir(&source, &target, real, Path::new(""))?;
        set_mode(target.as_raw_fd(), mode)?;
        self.entries
            .insert(real.to_path_buf(), EntryState::Dir { mode });
        Ok(())
    }

    fn copy_dir(
        &mut self,
        source: &fs::File,
        target: &fs::File,
        real: &Path,
        relative: &Path,
    ) -> io::Result<()> {
        let mut names = store::read_dir_names_at(source.as_raw_fd())?;
        names.sort();
        for name in names {
            let child_relative = relative.join(&name);
            if self.excluded(&child_relative) {
                continue;
            }
            let child_real = real.join(&name);
            let name = name.as_bytes();
            let stat = match store::stat_at(source.as_raw_fd(), name) {
                Ok(stat) => stat,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let mode = stat.st_mode as u32 & 0o777;
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let from = open_dir_at(source.as_raw_fd(), name).map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("snapshot {}: {error}", child_real.display()),
                        )
                    })?;
                    store::mkdir_at(target.as_raw_fd(), name, 0o700)?;
                    let to = open_dir_at(target.as_raw_fd(), name)?;
                    self.copy_dir(&from, &to, &child_real, &child_relative)?;
                    set_mode(to.as_raw_fd(), mode)?;
                    self.entries.insert(child_real, EntryState::Dir { mode });
                }
                libc::S_IFREG => {
                    if let Some(sha256) = copy_file(source, target, name, mode, &child_real)? {
                        self.entries
                            .insert(child_real, EntryState::File { mode, sha256 });
                    }
                }
                libc::S_IFLNK => {
                    let link = store::read_link_at(source.as_raw_fd(), name)?;
                    symlink_at(link.as_os_str(), target.as_raw_fd(), name)?;
                    self.entries.insert(
                        child_real,
                        EntryState::Symlink {
                            target: link.into_os_string(),
                        },
                    );
                }
                // Sockets, FIFOs and devices are never copied: the
                // snapshot is socket-free by construction.
                _ => {}
            }
        }
        Ok(())
    }

    /// Record `staged` (the stage copy of `real`) without copying.
    fn scan_root(&mut self, real: &Path, staged: &Path) -> io::Result<()> {
        let dir = open_dir(staged)?;
        let mode = store::fd_stat(dir.as_raw_fd())?.st_mode as u32 & 0o777;
        self.entries
            .insert(real.to_path_buf(), EntryState::Dir { mode });
        self.scan_dir(&dir, real, Path::new(""))
    }

    fn scan_dir(&mut self, dir: &fs::File, real: &Path, relative: &Path) -> io::Result<()> {
        for name in store::read_dir_names_at(dir.as_raw_fd())? {
            let child_relative = relative.join(&name);
            if self.excluded(&child_relative) {
                continue;
            }
            let child_real = real.join(&name);
            let name = name.as_bytes();
            let stat = store::stat_at(dir.as_raw_fd(), name)?;
            let mode = stat.st_mode as u32 & 0o777;
            let state = match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    // A directory the tool made unreadable is opened up:
                    // the tree is quiescent and the stage is tog's.
                    if mode & 0o500 != 0o500 {
                        let _ = chmod_at(dir.as_raw_fd(), name, mode | 0o500);
                    }
                    let child = open_dir_at(dir.as_raw_fd(), name)?;
                    self.scan_dir(&child, &child_real, &child_relative)?;
                    EntryState::Dir { mode }
                }
                libc::S_IFREG => {
                    if mode & 0o400 == 0 {
                        let _ = chmod_at(dir.as_raw_fd(), name, mode | 0o400);
                    }
                    EntryState::File {
                        mode,
                        sha256: hash_at(dir.as_raw_fd(), name)?,
                    }
                }
                libc::S_IFLNK => EntryState::Symlink {
                    target: store::read_link_at(dir.as_raw_fd(), name)?.into_os_string(),
                },
                other => EntryState::Special {
                    kind: special_kind(other),
                },
            };
            self.entries.insert(child_real, state);
        }
        Ok(())
    }
}

fn set_mode(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: fchmod on a descriptor this function borrows.
    if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn chmod_at(dirfd: RawFd, name: &[u8], mode: u32) -> io::Result<()> {
    let name = CString::new(name).map_err(|_| io::Error::other("name contains NUL"))?;
    // SAFETY: fchmodat on a borrowed directory and a NUL-terminated name;
    // flags 0 follows nothing here because the caller checked the type.
    if unsafe { libc::fchmodat(dirfd, name.as_ptr(), mode as libc::mode_t, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn symlink_at(target: &OsStr, dirfd: RawFd, name: &[u8]) -> io::Result<()> {
    let target = CString::new(target.as_bytes()).map_err(|_| io::Error::other("NUL in link"))?;
    let name = CString::new(name).map_err(|_| io::Error::other("NUL in name"))?;
    // SAFETY: both strings are NUL-terminated and outlive the call.
    if unsafe { libc::symlinkat(target.as_ptr(), dirfd, name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The SHA-256 of a regular file opened without following a symlink.
pub(crate) fn hash_at(dirfd: RawFd, name: &[u8]) -> io::Result<[u8; 32]> {
    let file = store::open_file_at(
        dirfd,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    hash_reader(&file)
}

pub(crate) fn hash_reader(mut reader: impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

/// Copy one regular file into the stage and return the digest of the bytes
/// the stage now holds. `None` when the entry turned out not to be a
/// regular file by the time it was opened (it is then left out, like any
/// special file).
fn copy_file(
    source: &fs::File,
    target: &fs::File,
    name: &[u8],
    mode: u32,
    shown: &Path,
) -> io::Result<Option<[u8; 32]>> {
    let from = store::open_file_at(
        source.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("snapshot {}: {error}", shown.display()),
        )
    })?;
    if store::fd_stat(from.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(None);
    }
    let mut to = store::open_file_at(
        target.as_raw_fd(),
        name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    let sha256 = if reflink(&from, &to) {
        hash_reader(&to)?
    } else {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut reader = &from;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            to.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
        }
        hasher.finalize().into()
    };
    set_mode(to.as_raw_fd(), mode)?;
    Ok(Some(sha256))
}

/// Share `from`'s extents with `to` (btrfs, XFS). False where the
/// filesystem cannot, and the caller copies instead.
fn reflink(from: &fs::File, to: &fs::File) -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: FICLONE takes the source descriptor as its argument; both
        // descriptors are borrowed for the call.
        unsafe { libc::ioctl(to.as_raw_fd(), libc::FICLONE, from.as_raw_fd()) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (from, to);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::{symlink, PermissionsExt};

    pub(crate) fn temp_store(temp: &TempDir) -> Store {
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp", "roots", "records"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        Store {
            root: root.canonicalize().unwrap(),
        }
    }

    fn project(temp: &TempDir) -> PathBuf {
        let dir = temp.0.join("project");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join(".git/hooks")).unwrap();
        fs::write(dir.join("package.json"), b"{}\n").unwrap();
        fs::write(dir.join("src/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(dir.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(dir.join(".git/hooks/pre-commit"), b"#!/bin/sh\n").unwrap();
        dir.canonicalize().unwrap()
    }

    fn build(store: &Store, lock_root: &Path, exclude: &[PathGlob]) -> Snapshot {
        let activity = store.activity(ActivityMode::Shared).unwrap();
        Snapshot::build(
            store,
            &activity,
            &SnapshotSpec {
                lock_root,
                extra_roots: &[],
                exclude,
            },
        )
        .unwrap()
    }

    fn staged(snapshot: &Snapshot, relative: &str) -> PathBuf {
        snapshot.lock_root().staged.join(relative)
    }

    fn outputs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("package.json"),
            PathBuf::from("package-lock.json"),
        ]
    }

    #[test]
    fn globs_cover_a_path_or_its_ancestors() {
        let glob = |pattern: &str| PathGlob::new(pattern).unwrap();
        assert!(glob("obj").matches(Path::new("obj/Debug/x.json")));
        assert!(!glob("obj").matches(Path::new("src/obj/x")));
        assert!(glob("**/node_modules").matches(Path::new("a/b/node_modules/x")));
        assert!(glob("**/node_modules").matches(Path::new("node_modules")));
        assert!(glob("*.lock").matches(Path::new("uv.lock")));
        assert!(!glob("*.lock").matches(Path::new("a/uv.lock")));
        assert!(glob("a/?/c").matches(Path::new("a/b/c")));
        for bad in ["", "/abs", "a//b", "a/../b", "./a"] {
            assert!(PathGlob::new(bad).is_err(), "{bad:?}");
        }
    }

    /// The snapshot copies files, directories and symlinks with their
    /// modes and leaves sockets, FIFOs and devices out, including git's
    /// fsmonitor socket inside `.git`.
    #[test]
    fn snapshot_omits_sockets_fifos_and_devices() {
        let temp = TempDir::named("snapshot-special");
        let store = temp_store(&temp);
        let dir = project(&temp);
        symlink("src/main.rs", dir.join("link")).unwrap();
        fs::set_permissions(dir.join("src/main.rs"), fs::Permissions::from_mode(0o755)).unwrap();
        let fifo = CString::new(dir.join("pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path in a directory this test owns.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        // A short symlink to `.git` keeps the bind path under SUN_LEN
        // whatever the temp dir, and the socket lands in place.
        let short = PathBuf::from(format!("/tmp/tog-snapsock-{}", std::process::id()));
        let _ = fs::remove_file(&short);
        symlink(dir.join(".git"), &short).unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(short.join("fsmonitor--daemon.ipc")).unwrap();
        fs::remove_file(&short).unwrap();

        let snapshot = build(&store, &dir, &[]);
        assert_eq!(
            fs::read(staged(&snapshot, "package.json")).unwrap(),
            b"{}\n"
        );
        let main = fs::metadata(staged(&snapshot, "src/main.rs")).unwrap();
        assert_eq!(main.permissions().mode() & 0o777, 0o755);
        assert_eq!(
            fs::read_link(staged(&snapshot, "link")).unwrap(),
            PathBuf::from("src/main.rs")
        );
        for gone in ["pipe", ".git/fsmonitor--daemon.ipc"] {
            assert!(
                fs::symlink_metadata(staged(&snapshot, gone)).is_err(),
                "{gone} was copied"
            );
            assert!(snapshot.baseline(&dir.join(gone)).is_none());
        }
        assert!(snapshot.diff().unwrap().is_empty());
        let stage = snapshot.stage().to_path_buf();
        assert_eq!(
            fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(snapshot);
        assert!(!stage.exists(), "the stage outlived the snapshot");
    }

    #[test]
    fn excluded_paths_are_neither_copied_nor_diffed() {
        let temp = TempDir::named("snapshot-exclude");
        let store = temp_store(&temp);
        let dir = project(&temp);
        fs::create_dir_all(dir.join("target/debug")).unwrap();
        fs::write(dir.join("target/debug/big"), b"x").unwrap();
        let snapshot = build(&store, &dir, &[PathGlob::new("target").unwrap()]);
        assert!(!staged(&snapshot, "target").exists());
        fs::create_dir_all(staged(&snapshot, "target")).unwrap();
        fs::write(staged(&snapshot, "target/new"), b"y").unwrap();
        assert!(snapshot.diff().unwrap().is_empty());
    }

    /// A tool that rewrites an undeclared file with different bytes of the
    /// same size and restores its timestamps is still caught.
    #[test]
    fn diff_detects_same_second_rewrite_by_content() {
        let temp = TempDir::named("snapshot-same-second");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        let path = staged(&snapshot, "src/main.rs");
        let before = fs::metadata(&path).unwrap();
        fs::write(&path, b"fn evil() {}\n").unwrap();
        let file = fs::File::options().write(true).open(&path).unwrap();
        file.set_times(
            fs::FileTimes::new()
                .set_modified(before.modified().unwrap())
                .set_accessed(before.accessed().unwrap()),
        )
        .unwrap();
        let changes = snapshot.diff().unwrap();
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].path, dir.join("src/main.rs"));
        let error = snapshot.classify(&changes, &outputs(), &[]).unwrap_err();
        assert!(error.to_string().contains("src/main.rs"), "{error}");
    }

    #[test]
    fn diff_ignores_a_byte_identical_rewrite_of_an_undeclared_file() {
        let temp = TempDir::named("snapshot-identical");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        let path = staged(&snapshot, "src/main.rs");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"fn main() {}\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let changes = snapshot.diff().unwrap();
        assert!(changes.is_empty(), "{changes:?}");
    }

    /// A fixture tool edits a source file and a workflow and exits 0:
    /// nothing is accepted, and both paths are named.
    #[test]
    fn undeclared_change_publishes_nothing() {
        let temp = TempDir::named("snapshot-undeclared");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        fs::write(staged(&snapshot, "package.json"), b"{\"a\":1}\n").unwrap();
        fs::write(staged(&snapshot, "src/main.rs"), b"changed").unwrap();
        fs::create_dir_all(staged(&snapshot, ".github/workflows")).unwrap();
        fs::write(staged(&snapshot, ".github/workflows/x.yml"), b"on: push").unwrap();
        let changes = snapshot.diff().unwrap();
        let error = snapshot.classify(&changes, &outputs(), &[]).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("src/main.rs"), "{message}");
        assert!(message.contains(".github/workflows/x.yml"), "{message}");
        assert!(!message.contains("package.json"), "{message}");
        // The real project was never touched.
        assert_eq!(
            fs::read(dir.join("src/main.rs")).unwrap(),
            b"fn main() {}\n"
        );
    }

    #[test]
    fn new_git_directory_publishes_nothing_and_never_reaches_the_project() {
        let temp = TempDir::named("snapshot-new-git");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        fs::create_dir_all(staged(&snapshot, "vendor/.git")).unwrap();
        fs::write(staged(&snapshot, "vendor/.git/HEAD"), b"x").unwrap();
        let changes = snapshot.diff().unwrap();
        // Even a scratch glob that covers it cannot accept a new repository.
        let scratch = [PathGlob::new("vendor").unwrap()];
        let error = snapshot
            .classify(&changes, &outputs(), &scratch)
            .unwrap_err();
        assert!(
            error.to_string().contains("a new git repository"),
            "{error}"
        );
        assert!(!dir.join("vendor").exists());
    }

    #[test]
    fn git_hook_change_publishes_nothing() {
        let temp = TempDir::named("snapshot-hook");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        fs::write(staged(&snapshot, ".git/hooks/pre-commit"), b"curl evil").unwrap();
        fs::write(staged(&snapshot, ".tog/x"), b"x").unwrap_or_else(|_| {
            fs::create_dir_all(staged(&snapshot, ".tog")).unwrap();
            fs::write(staged(&snapshot, ".tog/x"), b"x").unwrap();
        });
        let changes = snapshot.diff().unwrap();
        let scratch = [PathGlob::new("**").unwrap()];
        let message = snapshot
            .classify(&changes, &outputs(), &scratch)
            .unwrap_err()
            .to_string();
        assert!(message.contains("a git hook"), "{message}");
        assert!(message.contains("tog's own state"), "{message}");
        assert_eq!(
            fs::read(dir.join(".git/hooks/pre-commit")).unwrap(),
            b"#!/bin/sh\n"
        );
    }

    #[test]
    fn declared_scratch_is_discarded() {
        let temp = TempDir::named("snapshot-scratch");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        fs::create_dir_all(staged(&snapshot, "obj/Debug")).unwrap();
        fs::write(staged(&snapshot, "obj/Debug/project.assets.json"), b"{}").unwrap();
        fs::write(staged(&snapshot, "package-lock.json"), b"{\"lock\":1}").unwrap();
        let changes = snapshot.diff().unwrap();
        let classified = snapshot
            .classify(&changes, &outputs(), &[PathGlob::new("obj").unwrap()])
            .unwrap();
        assert_eq!(classified.outputs, vec![PathBuf::from("package-lock.json")]);
        assert!(classified.scratch.contains(&PathBuf::from("obj")));
        assert!(!dir.join("obj").exists());
    }

    #[test]
    fn declared_output_symlink_fails_the_door() {
        let temp = TempDir::named("snapshot-output-link");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        fs::remove_file(staged(&snapshot, "package.json")).unwrap();
        symlink("/etc/passwd", staged(&snapshot, "package.json")).unwrap();
        let changes = snapshot.diff().unwrap();
        let error = snapshot.classify(&changes, &outputs(), &[]).unwrap_err();
        assert!(error.to_string().contains("now a symlink"), "{error}");
        assert!(error.to_string().contains("package.json"), "{error}");
    }

    #[test]
    fn declared_output_parent_dir_symlink_fails_the_door() {
        let temp = TempDir::named("snapshot-output-parent");
        let store = temp_store(&temp);
        let dir = project(&temp);
        fs::create_dir_all(dir.join("member")).unwrap();
        fs::write(dir.join("member/package.json"), b"{}").unwrap();
        let snapshot = build(&store, &dir, &[]);
        let elsewhere = temp.0.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("package.json"), b"{}").unwrap();
        fs::remove_dir_all(staged(&snapshot, "member")).unwrap();
        symlink(&elsewhere, staged(&snapshot, "member")).unwrap();
        let changes = snapshot.diff().unwrap();
        let outputs = [PathBuf::from("member/package.json")];
        let error = snapshot.classify(&changes, &outputs, &[]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a directory above the declared output member/package.json"),
            "{error}"
        );
    }

    #[test]
    fn declared_output_replaced_by_fifo_fails_the_door() {
        let temp = TempDir::named("snapshot-output-fifo");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        let path = staged(&snapshot, "package.json");
        fs::remove_file(&path).unwrap();
        let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path in the test's own stage.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let changes = snapshot.diff().unwrap();
        let error = snapshot.classify(&changes, &outputs(), &[]).unwrap_err();
        assert!(error.to_string().contains("now a FIFO"), "{error}");
    }

    #[test]
    fn a_deleted_declared_output_fails_and_a_never_made_one_is_nothing() {
        let temp = TempDir::named("snapshot-output-deleted");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        let classified = snapshot
            .classify(&snapshot.diff().unwrap(), &outputs(), &[])
            .unwrap();
        assert!(classified.outputs.is_empty());
        fs::remove_file(staged(&snapshot, "package.json")).unwrap();
        let error = snapshot
            .classify(&snapshot.diff().unwrap(), &outputs(), &[])
            .unwrap_err();
        assert!(error.to_string().contains("deleted"), "{error}");
    }

    /// An extra root outside the lock root is staged at its own real path,
    /// keeps its position relative to the lock root, and a change in it is
    /// never an output.
    #[test]
    fn extra_roots_are_staged_beside_the_lock_root() {
        let temp = TempDir::named("snapshot-extra");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let lib = temp.0.join("lib");
        fs::create_dir_all(&lib).unwrap();
        fs::write(lib.join("Cargo.toml"), b"[package]").unwrap();
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let inside = dir.join("src");
        let snapshot = Snapshot::build(
            &store,
            &activity,
            &SnapshotSpec {
                lock_root: &dir,
                extra_roots: &[lib.clone(), inside],
                exclude: &[],
            },
        )
        .unwrap();
        assert_eq!(
            snapshot.roots().len(),
            2,
            "a root inside another is staged once"
        );
        let lib = lib.canonicalize().unwrap();
        let staged_lib = snapshot.staged_path(&lib);
        assert_eq!(
            fs::read(staged_lib.join("Cargo.toml")).unwrap(),
            b"[package]"
        );
        assert_eq!(
            snapshot.lock_root().staged.parent().unwrap().join("lib"),
            staged_lib
        );
        fs::write(staged_lib.join("Cargo.toml"), b"changed").unwrap();
        let changes = snapshot.diff().unwrap();
        let error = snapshot
            .classify(&changes, &[PathBuf::from("Cargo.toml")], &[])
            .unwrap_err();
        assert!(error.to_string().contains("lib/Cargo.toml"), "{error}");
    }

    #[test]
    fn a_stage_the_tool_locked_down_is_still_removed() {
        let temp = TempDir::named("snapshot-locked");
        let store = temp_store(&temp);
        let dir = project(&temp);
        let snapshot = build(&store, &dir, &[]);
        let src = staged(&snapshot, "src");
        fs::set_permissions(&src, fs::Permissions::from_mode(0o000)).unwrap();
        let changes = snapshot.diff().unwrap();
        assert_eq!(changes.len(), 1, "{changes:?}");
        let stage = snapshot.stage().to_path_buf();
        drop(snapshot);
        assert!(!stage.exists());
    }
}

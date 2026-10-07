//! A Rust toolchain that is a directory on this machine (kernel provider
//! layer): what `[toolchain] path = "/custom/rust"` in a rustup toolchain
//! file names.
//!
//! rustup runs such a toolchain as it is. tog does the same, with the two
//! things a lock needs added. First, identity: the tree is probed
//! (`bin/rustc -vV`, `bin/cargo -V`) and content-hashed when the lock is
//! written, and the lock's row for it carries `source = "path"`, the
//! `file://` URL of the tree, both version lines, and that hash. Second,
//! the check: every later realization re-probes and re-hashes the tree, and
//! a tree that is no longer the one the lock names is refused (fail closed)
//! until `tog update --toolchain rust` locks the new one.
//!
//! The tree is imported into the store as an ordinary Rust object (a copy,
//! verified against the same hash), so builds, closures and GC treat it
//! like any other toolchain and a later edit to the directory cannot change
//! what a closure already built with. Every realization records the
//! `external-toolchain` exception: the toolchain came from no pinned
//! release, and a policy can deny that.

use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Digest;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{self, Exception, EXTERNAL_TOOLCHAIN};
use crate::kernel::sandbox::Sandbox;
use crate::kernel::store::{self, ObjectDeps, Store};
use crate::kernel::toolchain::input::{InputRow, RUST_TOOLCHAIN_PATH};
use crate::kernel::toolchain::{
    is_path_url, qualified, ArtifactRow, ArtifactSpec, Bundle, Component, Selected, Version,
    PATH_SOURCE, PATH_URL_SCHEME,
};
use crate::kernel::types::Identity;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component as PathPart, Path, PathBuf};

/// The layout recipe of an imported local tree: copied as it is, checked
/// against the locked content hash.
pub const PATH_RECIPE: &str = "rust-path/1";

/// The release key a path section records. Provenance only.
pub const PATH_RELEASE: &str = "path";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Whether `selected` is a local tree rather than a catalog release.
pub fn is_path(selected: &Selected) -> bool {
    !selected.bundle.artifacts.is_empty()
        && selected
            .bundle
            .artifacts
            .iter()
            .all(|row| is_path_url(&row.url))
}

/// What probing a tree says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Probe {
    /// The numeric rustc release (`1.97.0` for `1.97.0-nightly`), the
    /// version the lock and the object are named by.
    version: String,
    /// cargo's numeric release.
    cargo_version: String,
    /// The first lines of `rustc -vV` and `cargo -V`, joined: the build the
    /// lock records and a re-probe must reproduce.
    build: String,
}

/// A fresh private directory for one version probe, under the temp root:
/// the probe runs before any store is open. The name is random and the
/// directory is created exclusively with mode 0700, so two probes never
/// share one and a directory (or symlink) someone else put at the name is
/// refused, never adopted; a taken name draws another.
fn probe_scratch() -> io::Result<PathBuf> {
    probe_scratch_under(&std::env::temp_dir())
}

/// [`probe_scratch`] under `root`. A temp root that does not exist yet
/// (`TMPDIR` naming a directory nobody has made) is created first, as any
/// shared temp root would be; only the probe's own directory is private.
fn probe_scratch_under(root: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    const ATTEMPTS: usize = 8;
    fs::create_dir_all(root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("create the temp directory {}: {error}", root.display()),
        )
    })?;
    let mut taken = None;
    for _ in 0..ATTEMPTS {
        let random = crate::kernel::fsroot::urandom_bytes(16)?;
        let scratch = root.join(format!("tog-rust-path-probe-{}", hex::encode(random)));
        match fs::DirBuilder::new().mode(0o700).create(&scratch) {
            Ok(()) => return Ok(scratch),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => taken = Some(error),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("create the probe directory {}: {error}", scratch.display()),
                ))
            }
        }
    }
    Err(taken.unwrap_or_else(|| io::Error::other("no probe directory name was tried")))
}

/// Run one of the tree's own binaries for its version output, in the build
/// sandbox: the tree read-only, a scratch directory as the only writable
/// place (its home, temp and working directory), no network and a scrubbed
/// environment. The answer is written to a file in the scratch directory,
/// which is read back once the child exits. This touches no store, so it
/// needs no store lease and runs the same while a lock is being written as
/// during a sync.
fn version_output(platform: Platform, tree: &Path, binary: &str, flag: &str) -> io::Result<String> {
    let scratch = probe_scratch()?;
    let answer = scratch.join("version.txt");
    let program = tree.join("bin").join(binary);
    let (program_arg, answer_arg) = (program.display().to_string(), answer.display().to_string());
    let sandbox = Sandbox {
        read: vec![tree],
        write: Vec::new(),
        host_view: crate::kernel::sandbox::HostView::Full,
    };
    let ran = sandbox.run_in_on(
        platform,
        &[
            "/bin/sh",
            "-c",
            "exec \"$0\" \"$1\" > \"$2\"",
            &program_arg,
            flag,
            &answer_arg,
        ],
        "/usr/bin:/bin",
        &scratch,
        &scratch,
        &[],
        None,
    );
    let read = ran.and_then(|()| fs::read(&answer));
    let _ = fs::remove_dir_all(&scratch);
    let bytes = read.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "the Rust toolchain at {}: bin/{binary} {flag}: {error}",
                tree.display()
            ),
        )
    })?;
    String::from_utf8(bytes).map_err(|_| {
        invalid(format!(
            "the Rust toolchain at {}: bin/{binary} {flag} printed non-UTF-8 output",
            tree.display()
        ))
    })
}

/// The numeric part of a release string (`1.97.0-nightly` -> `1.97.0`),
/// which must be a version tog can compare.
fn numeric_release(tree: &Path, what: &str, release: &str) -> io::Result<String> {
    let numeric = release.split(['-', '+']).next().unwrap_or_default();
    Version::parse(numeric).map_err(|_| {
        invalid(format!(
            "the Rust toolchain at {}: {what} reports release {release:?}, which is not a version",
            tree.display()
        ))
    })?;
    Ok(numeric.to_string())
}

fn probe(tree: &Path, platform: Platform) -> io::Result<Probe> {
    let rustc = version_output(platform, tree, "rustc", "-vV")?;
    let field = |name: &str| {
        rustc
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(str::trim)
    };
    let rustc_line = rustc.lines().next().unwrap_or_default().trim().to_string();
    let (Some(release), Some(host)) = (field("release"), field("host")) else {
        return Err(invalid(format!(
            "the Rust toolchain at {}: bin/rustc -vV names no release and host; is it rustc?",
            tree.display()
        )));
    };
    if host != platform.triple() {
        return Err(invalid(format!(
            "the Rust toolchain at {} is built for {host}, not this host ({})",
            tree.display(),
            platform.triple()
        )));
    }
    let version = numeric_release(tree, "bin/rustc -vV", release)?;
    let cargo = version_output(platform, tree, "cargo", "-V")?;
    let cargo_line = cargo.lines().next().unwrap_or_default().trim().to_string();
    let cargo_release = cargo_line
        .strip_prefix("cargo ")
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| {
            invalid(format!(
                "the Rust toolchain at {}: bin/cargo -V printed {cargo_line:?}; is it cargo?",
                tree.display()
            ))
        })?;
    let cargo_version = numeric_release(tree, "bin/cargo -V", cargo_release)?;
    Ok(Probe {
        version,
        cargo_version,
        build: format!("{rustc_line}; {cargo_line}"),
    })
}

/// The most symlinks one link's resolution may pass through, as the
/// kernel's own limit (`MAXSYMLINKS`) bounds a path lookup. A loop is refused.
const MAX_LINK_HOPS: u32 = 40;

/// Whether the symlink at `link` (relative to `root`) with target text
/// `target` resolves inside the tree. The target is resolved one component
/// at a time against the tree as it is on disk, following every symlink it
/// passes through (each of which must be relative and resolve inside too),
/// and refused the moment a `..` would climb above the root. Text alone is
/// not enough: `d/s -> ..` is inside, but `e -> d/s/../secret` then leaves.
/// A component that does not exist ends the lookups: nothing below it can
/// be a link, and the rest is resolved as written. Anything else would make
/// the imported object depend on a path outside itself.
fn contained_link(root: &Path, link: &Path, target: &Path) -> bool {
    let mut at: Vec<OsString> = link
        .parent()
        .map(|parent| {
            parent
                .components()
                .filter_map(|part| match part {
                    PathPart::Normal(name) => Some(name.to_os_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut hops = 0;
    resolves_within(root, &mut at, target, &mut hops)
}

fn resolves_within(root: &Path, at: &mut Vec<OsString>, target: &Path, hops: &mut u32) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut missing = false;
    for part in target.components() {
        match part {
            PathPart::CurDir => {}
            PathPart::ParentDir => {
                if at.pop().is_none() {
                    return false;
                }
            }
            PathPart::Normal(name) => {
                at.push(name.to_os_string());
                if missing {
                    continue;
                }
                let here = at
                    .iter()
                    .fold(root.to_path_buf(), |path, name| path.join(name));
                match fs::symlink_metadata(&here) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        *hops += 1;
                        if *hops > MAX_LINK_HOPS {
                            return false;
                        }
                        let Ok(next) = fs::read_link(&here) else {
                            return false;
                        };
                        at.pop();
                        if !resolves_within(root, at, &next, hops) {
                            return false;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => missing = true,
                }
            }
            _ => return false,
        }
    }
    true
}

fn file_kind(stat: &libc::stat) -> libc::mode_t {
    stat.st_mode & libc::S_IFMT
}

/// What identifies one version of a file without reading it: device,
/// inode, size, and modification and change times to the nanosecond. A
/// write changes the change time, so a file with the same key holds the
/// same bytes it held when its sha256 was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FileKey([i64; 7]);

impl FileKey {
    // libc's stat field types differ by target (`st_dev` is an i32 on
    // macOS); the casts pin the key's width everywhere.
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &libc::stat) -> FileKey {
        FileKey([
            stat.st_dev as i64,
            stat.st_ino as i64,
            stat.st_size as i64,
            stat.st_mtime as i64,
            stat.st_mtime_nsec as i64,
            stat.st_ctime as i64,
            stat.st_ctime_nsec as i64,
        ])
    }

    fn changed_at(&self) -> i64 {
        self.0[5]
    }
}

/// A regular file the walk met, not yet opened.
struct FileAt<'a> {
    dir: &'a fs::File,
    name: &'a [u8],
    stat: libc::stat,
}

impl FileAt<'_> {
    // `st_mode` is a u16 on macOS and a u32 on Linux.
    #[allow(clippy::useless_conversion)]
    fn executable(&self) -> bool {
        u32::from(self.stat.st_mode) & 0o111 != 0
    }

    /// Open the file the walk saw, relative to its held directory and never
    /// through a symlink, and check the descriptor is still that regular
    /// file. Everything read from it (its bytes, its hash, its copy) is then
    /// that one file, whatever happens to the name meanwhile.
    fn open(&self, root: &Path, path: &Path) -> io::Result<(fs::File, libc::stat)> {
        let file = store::open_file_at(
            self.dir.as_raw_fd(),
            self.name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .map_err(|error| at_entry(root, path, error))?;
        let opened = store::fd_stat(file.as_raw_fd())?;
        if file_kind(&opened) != libc::S_IFREG || !store::same_inode(&opened, &self.stat) {
            return Err(invalid(format!(
                "the Rust toolchain at {}: {} changed while tog read it; run tog again",
                root.display(),
                path.display()
            )));
        }
        Ok((file, opened))
    }
}

/// One entry of a tree walk, in a canonical order.
enum Entry<'a> {
    Dir,
    File(FileAt<'a>),
    Link(PathBuf),
}

fn at_entry(root: &Path, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "the Rust toolchain at {}: {}: {error}",
            root.display(),
            path.display()
        ),
    )
}

/// The tree's root directory, opened without following a symlink at it.
fn open_root(root: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("the Rust toolchain at {}: {error}", root.display()),
            )
        })
}

/// Walk the tree at `root` in byte order of names, calling `visit` with
/// each entry's path relative to `root`. Every directory is read through a
/// descriptor opened with O_NOFOLLOW and checked against the entry the walk
/// saw, so a directory swapped for a symlink mid-walk is refused rather
/// than followed. A special file (socket, device, fifo) or a symlink that
/// resolves outside the tree is refused.
fn walk(root: &Path, visit: &mut dyn FnMut(&Path, Entry<'_>) -> io::Result<()>) -> io::Result<()> {
    walk_dir(root, &open_root(root)?, Path::new(""), visit)
}

fn walk_dir(
    root: &Path,
    dir: &fs::File,
    relative: &Path,
    visit: &mut dyn FnMut(&Path, Entry<'_>) -> io::Result<()>,
) -> io::Result<()> {
    let dirfd = dir.as_raw_fd();
    let mut names =
        store::read_dir_names_at(dirfd).map_err(|error| at_entry(root, relative, error))?;
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for name in names {
        let path = relative.join(&name);
        let bytes = name.as_bytes();
        let stat = store::stat_at(dirfd, bytes).map_err(|error| at_entry(root, &path, error))?;
        let kind = file_kind(&stat);
        if kind == libc::S_IFLNK {
            let target =
                store::read_link_at(dirfd, bytes).map_err(|error| at_entry(root, &path, error))?;
            if !contained_link(root, &path, &target) {
                return Err(invalid(format!(
                    "the Rust toolchain at {}: {} links to {}, which resolves outside the toolchain; tog imports only a self-contained tree",
                    root.display(),
                    path.display(),
                    target.display()
                )));
            }
            visit(&path, Entry::Link(target))?;
        } else if kind == libc::S_IFDIR {
            let child = store::open_file_at(
                dirfd,
                bytes,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
            .map_err(|error| at_entry(root, &path, error))?;
            if !store::same_inode(&store::fd_stat(child.as_raw_fd())?, &stat) {
                return Err(invalid(format!(
                    "the Rust toolchain at {}: {} changed while tog read it; run tog again",
                    root.display(),
                    path.display()
                )));
            }
            visit(&path, Entry::Dir)?;
            walk_dir(root, &child, &path, visit)?;
        } else if kind == libc::S_IFREG {
            visit(
                &path,
                Entry::File(FileAt {
                    dir,
                    name: bytes,
                    stat,
                }),
            )?;
        } else {
            return Err(invalid(format!(
                "the Rust toolchain at {}: {} is not a file, directory or symlink",
                root.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

/// The cheap pass: every link resolved and every entry's kind checked,
/// no file opened. It runs before anything is hashed, so a tree tog will
/// refuse is refused before a whole toolchain is read.
fn check_tree(root: &Path) -> io::Result<()> {
    walk(root, &mut |_, _| Ok(()))
}

/// Read `file` to its end, hashing it and, when `copy` is given, writing
/// the same bytes there.
fn read_sha256(file: &mut fs::File, mut copy: Option<&mut fs::File>) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if let Some(copy) = copy.as_deref_mut() {
            copy.write_all(&buffer[..read])?;
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/// The records a tree hash is taken over: one length-prefixed record per
/// entry, in walk order, naming its relative path and kind, a file's
/// executable bit and content sha256, and a link's target.
struct TreeHasher(Sha256);

impl TreeHasher {
    fn new() -> TreeHasher {
        let mut hasher = TreeHasher(Sha256::new());
        hasher.record(&[b"rust-path-tree", b"1"]);
        hasher
    }

    fn record(&mut self, fields: &[&[u8]]) {
        for field in fields {
            self.0.update(field.len().to_string().as_bytes());
            self.0.update(b":");
            self.0.update(field);
        }
    }

    fn entry(&mut self, path: &Path, entry: &Entry<'_>, sha256: Option<&str>) {
        let name = path.as_os_str().as_bytes();
        match entry {
            Entry::Dir => self.record(&[b"dir", name]),
            Entry::File(file) => {
                let mode: &[u8] = if file.executable() { b"x" } else { b"-" };
                self.record(&[b"file", name, mode, sha256.unwrap_or_default().as_bytes()]);
            }
            Entry::Link(target) => self.record(&[b"link", name, target.as_os_str().as_bytes()]),
        }
    }

    fn finish(self) -> io::Result<Digest> {
        Digest::sha256(&hex::encode(self.0.finalize()))
    }
}

/// The content hash of the tree at `root`. Two trees hash alike exactly
/// when they hold the same names, bytes, links and executable bits.
/// Owners, times and other mode bits are not content.
#[cfg(test)]
pub fn tree_digest(root: &Path) -> io::Result<Digest> {
    tree_digest_cached(root, None)
}

/// [`tree_digest`], reading a file's sha256 from the cache at `cache`
/// instead of the file when the file's [`FileKey`] is the one the cache
/// recorded, and writing back what it learned. The tree walk, the link
/// checks and the hash over the records run in full every time: only
/// unchanged file bytes are not read again.
fn tree_digest_cached(root: &Path, cache: Option<&Path>) -> io::Result<Digest> {
    tree_digest_quiet(root, cache, true, quiet_before())
}

/// [`tree_digest`] reading every file, then replacing the cache at `cache`
/// with what it read. This is the hash a lock is written from, and the one
/// that settles any disagreement with a cached hash: it never takes a sum
/// from the cache, so a stale entry cannot outlive it.
fn tree_digest_refreshed(root: &Path, cache: Option<&Path>) -> io::Result<Digest> {
    tree_digest_quiet(root, cache, false, quiet_before())
}

#[cfg(test)]
thread_local! {
    /// Run between the tree walk and the cache rewrite, for the test that
    /// the store's lease is held across both.
    static AFTER_TREE_WALK: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

/// A file changed in the same clock tick as its hash could keep its key
/// with other bytes, so only files quiet for a while are remembered.
fn quiet_before() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |now| now.as_secs() as i64 - CACHE_QUIET_SECONDS)
}

/// The tree hash, reading a file's sum from the cache at `cache` when
/// `trust` and the file's key matches, and remembering only files whose
/// change time (in seconds) is before `quiet_before`.
fn tree_digest_quiet(
    root: &Path,
    cache: Option<&Path>,
    trust: bool,
    quiet_before: i64,
) -> io::Result<Digest> {
    check_tree(root)?;
    let stored = cache.map(load_cache).unwrap_or_default();
    let known = if trust {
        stored.clone()
    } else {
        BTreeMap::new()
    };
    let mut learned = BTreeMap::new();
    let mut hasher = TreeHasher::new();
    walk(root, &mut |path, entry| {
        let Entry::File(file) = &entry else {
            hasher.entry(path, &entry, None);
            return Ok(());
        };
        let seen = FileKey::of(&file.stat);
        let name = path.to_str().map(str::to_string);
        let (sha256, key) = match name.as_ref().and_then(|name| known.get(name)) {
            Some(cached) if cached.key == seen => (cached.sha256.clone(), seen),
            _ => {
                let (mut opened, stat) = file.open(root, path)?;
                let sha256 = read_sha256(&mut opened, None)?;
                let key = FileKey::of(&stat);
                if FileKey::of(&store::fd_stat(opened.as_raw_fd())?) != key {
                    return Err(invalid(format!(
                        "the Rust toolchain at {}: {} changed while tog read it; run tog again",
                        root.display(),
                        path.display()
                    )));
                }
                (sha256, key)
            }
        };
        if let Some(name) = name {
            if key.changed_at() < quiet_before {
                learned.insert(
                    name,
                    CachedFile {
                        key,
                        sha256: sha256.clone(),
                    },
                );
            }
        }
        hasher.entry(path, &entry, Some(&sha256));
        Ok(())
    })?;
    #[cfg(test)]
    if let Some(hook) = AFTER_TREE_WALK.with(std::cell::Cell::get) {
        hook();
    }
    if let Some(cache) = cache {
        if learned != stored {
            save_cache(cache, &learned);
        }
    }
    hasher.finish()
}

/// Copy the tree at `from` into the existing empty directory `to`: files
/// with their bytes and executable bit, directories, and (contained)
/// symlinks as links. Each file is read once, from the descriptor the walk
/// checked, and hashed as it is copied, so the digest returned is the hash
/// of exactly what was written.
fn copy_tree(from: &Path, to: &Path) -> io::Result<Digest> {
    let mut hasher = TreeHasher::new();
    walk(from, &mut |path, entry| {
        let dest = to.join(path);
        let sha256 = match &entry {
            Entry::Dir => {
                fs::create_dir(&dest)?;
                None
            }
            Entry::Link(target) => {
                std::os::unix::fs::symlink(target, &dest)?;
                None
            }
            Entry::File(file) => {
                let (mut source, _) = file.open(from, path)?;
                let mut copy = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&dest)?;
                let sha256 = read_sha256(&mut source, Some(&mut copy))?;
                let mode = if file.executable() { 0o755 } else { 0o644 };
                copy.set_permissions(fs::Permissions::from_mode(mode))?;
                Some(sha256)
            }
        };
        hasher.entry(path, &entry, sha256.as_deref());
        Ok(())
    })?;
    hasher.finish()
}

/// The store cache namespace of tree hashes, one file per tree path. It is
/// only ever a shortcut: a missing or unreadable entry means files are read.
const TREE_CACHE: &str = "rust-path-tree";

/// The schema of one [`TREE_CACHE`] entry.
const CACHE_SCHEMA: &str = "rust-path-tree-cache/1";

/// How long a file must have been unchanged for its hash to be remembered.
const CACHE_QUIET_SECONDS: i64 = 2;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CachedFile {
    key: FileKey,
    sha256: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheFile {
    schema: String,
    files: BTreeMap<String, CachedFile>,
}

/// Where the hashes of the tree at `tree` are cached in `store`.
fn cache_path(store: &Store, tree: &Path) -> PathBuf {
    store.cache_path(
        TREE_CACHE,
        &hex::encode(Sha256::digest(tree.as_os_str().as_bytes())),
    )
}

/// The cache of the active store, when there is one, with the shared lease
/// that keeps it from being swept while `select` reads and writes it. The
/// store is only located, never created, and a busy one is skipped: the
/// cache is a shortcut, and without it the files are read. So is a store
/// that fails to open or lease, its error dropped. That includes a store
/// this thread already holds exclusively: the shared lease cannot be had
/// alongside it, so `select` waits out the lease's retries (about 45 ms)
/// and then hashes the tree without the cache.
fn store_cache(tree: &Path) -> Option<(PathBuf, StoreActivity)> {
    Store::existing_shared()
        .ok()
        .flatten()
        .map(|(store, activity)| (cache_path(&store, tree), activity))
}

fn load_cache(path: &Path) -> BTreeMap<String, CachedFile> {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CacheFile>(&bytes).ok())
        .filter(|cache| cache.schema == CACHE_SCHEMA)
        .map(|cache| cache.files)
        .unwrap_or_default()
}

/// Replace the cache at `path` with `files`, through a temporary file and
/// a rename so a reader never sees half of one. A cache that cannot be
/// written costs only a re-read next time, so failures are dropped.
fn save_cache(path: &Path, files: &BTreeMap<String, CachedFile>) {
    let Some(parent) = path.parent() else {
        return;
    };
    let body = CacheFile {
        schema: CACHE_SCHEMA.to_string(),
        files: files.clone(),
    };
    let Ok(bytes) = serde_json::to_vec(&body) else {
        return;
    };
    // The sequence keeps two writers in one process apart when the clock
    // does not: macOS's ticks in microseconds.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temporary = parent.join(format!(
        ".tmp-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let written = fs::create_dir_all(parent)
        .and_then(|()| fs::write(&temporary, &bytes))
        .and_then(|()| fs::rename(&temporary, path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
}

/// The directory a `toolchain.path` value names: as written when absolute,
/// against the project directory (where the toolchain file is) when
/// relative, as rustup resolves it. It must exist and be a directory.
fn tree_of(project: &Path, value: &str) -> io::Result<PathBuf> {
    let written = Path::new(value);
    let joined = if written.is_absolute() {
        written.to_path_buf()
    } else {
        project.join(written)
    };
    let tree = joined.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "rust-toolchain.toml: toolchain.path {value} ({}): {error}",
                joined.display()
            ),
        )
    })?;
    if !tree.is_dir() {
        return Err(invalid(format!(
            "rust-toolchain.toml: toolchain.path {value} ({}) is not a directory",
            tree.display()
        )));
    }
    Ok(tree)
}

/// The bundle a lock records for the local tree the discovered `rows`
/// name, or `None` when they name none. The tree is probed and hashed now:
/// this is the moment the lock's identity for it is taken, from every
/// file's bytes. What it read is written to the active store's cache, so
/// the realization that follows does not read the tree's files again.
pub fn select(platform: Platform, project: &Path, rows: &[InputRow]) -> io::Result<Option<Bundle>> {
    select_with(platform, project, rows, store_cache)
}

fn select_with(
    platform: Platform,
    project: &Path,
    rows: &[InputRow],
    cache: fn(&Path) -> Option<(PathBuf, StoreActivity)>,
) -> io::Result<Option<Bundle>> {
    let Some(value) = rows
        .iter()
        .find(|row| row.field == RUST_TOOLCHAIN_PATH.1)
        .and_then(|row| row.value.as_deref())
    else {
        return Ok(None);
    };
    let tree = tree_of(project, value)?;
    check_tree(&tree)?;
    let probe = probe(&tree, platform)?;
    // The lock's digest is read from the files themselves, never from the
    // cache; the cache is refreshed on the way, for the realization next.
    let cache = cache(&tree);
    let digest = tree_digest_refreshed(&tree, cache.as_ref().map(|(path, _)| path.as_path()))?;
    let url = tree
        .to_str()
        .map(|path| format!("{PATH_URL_SCHEME}{path}"))
        .ok_or_else(|| {
            invalid(format!(
                "the Rust toolchain path {} is not UTF-8",
                tree.display()
            ))
        })?;
    Ok(Some(Bundle {
        release: PATH_RELEASE.to_string(),
        revision: None,
        primary: vec!["rustc".into()],
        components: vec![
            Component::new("rustc", &probe.version),
            Component::embedded("cargo", &probe.cargo_version, "rustc"),
        ],
        artifacts: vec![ArtifactRow::new(
            platform,
            "rustc",
            PATH_SOURCE,
            &probe.build,
            PATH_RECIPE,
            &url,
            digest,
        )],
    }))
}

/// The locked row of a path selection, checked before anything is read.
fn locked_row(platform: Platform, selected: &Selected) -> io::Result<(ArtifactSpec, PathBuf)> {
    let row = selected.artifact(platform, "rustc")?;
    row.check_from("cargo", PATH_RECIPE, "sha256", selected.row_source())?;
    let tree = row
        .url
        .strip_prefix(PATH_URL_SCHEME)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            invalid(format!(
                "cargo: the local Rust toolchain row names {}, not an absolute file:// path",
                row.url
            ))
        })?;
    Ok((row, tree))
}

/// The object a path selection is imported as, from the locked row alone:
/// no probe, no hash, so an id can be named without touching the tree.
pub fn identity(platform: Platform, selected: &Selected) -> io::Result<Identity> {
    let (row, _) = locked_row(platform, selected)?;
    Ok(Identity {
        kind: "rust".into(),
        name: "rust".into(),
        version: row.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), PATH_RECIPE.to_string()),
            ("platform".to_string(), platform.triple().to_string()),
            ("tree_sha256".to_string(), row.digest.hex().to_string()),
            ("build".to_string(), row.build.clone()),
        ]),
    })
}

/// Refuse a tree that is no longer the one `row` locked: another build, or
/// other content. This is what makes a path toolchain fail closed. The
/// hash reads unchanged files' sums from `cache`; a mismatch is confirmed
/// by reading every file before it is reported, so a stale cache can never
/// be the reason a tree is refused.
fn verify(
    platform: Platform,
    tree: &Path,
    row: &ArtifactSpec,
    cache: Option<&Path>,
) -> io::Result<()> {
    let changed = |what: String| changed_since_locked(tree, &what);
    check_tree(tree)?;
    let probe = probe(tree, platform)?;
    if probe.build != row.build || probe.version != row.version {
        return Err(changed(format!(
            "locked {}, now {}",
            row.build, probe.build
        )));
    }
    let mut digest = tree_digest_cached(tree, cache)?;
    if let (true, Some(cache)) = (digest != row.digest, cache) {
        // Read every file past the sums that disagreed: the cache is
        // rebuilt from what the tree holds now.
        digest = tree_digest_refreshed(tree, Some(cache))?;
    }
    if digest != row.digest {
        return Err(changed(format!(
            "locked content {}, now {}",
            qualified(&row.digest),
            qualified(&digest)
        )));
    }
    Ok(())
}

fn changed_since_locked(tree: &Path, what: &str) -> io::Error {
    invalid(format!(
        "the Rust toolchain at {} changed since tog-toolchain.toml locked it ({what}); \
         run `tog update --toolchain rust` to lock the tree as it is now",
        tree.display()
    ))
}

/// Why a copy whose bytes do not hash to the lock is refused, decided by
/// reading the whole tree again (never the cache, which is rewritten from
/// the read): a tree that no longer matches the lock is reported as
/// changed, one that does was edited during the copy. Either way no stale
/// cached sum is left to pass the next verification.
fn copy_mismatch(tree: &Path, row: &ArtifactSpec, copied: &Digest, cache: &Path) -> io::Error {
    match tree_digest_refreshed(tree, Some(cache)) {
        Err(error) => error,
        Ok(now) if now != row.digest => changed_since_locked(
            tree,
            &format!(
                "locked content {}, now {}",
                qualified(&row.digest),
                qualified(&now)
            ),
        ),
        Ok(_) => invalid(format!(
            "the Rust toolchain at {} changed while it was imported (locked content {}, copied {}); run tog again",
            tree.display(),
            qualified(&row.digest),
            qualified(copied)
        )),
    }
}

/// The exception every use of a local tree records.
fn exception(tree: &Path, row: &ArtifactSpec) -> Exception {
    Exception {
        kind: EXTERNAL_TOOLCHAIN.to_string(),
        subject: tree.display().to_string(),
        detail: format!(
            "{} from a local directory (content {}), not a pinned release",
            row.build,
            qualified(&row.digest)
        ),
    }
}

/// Realize a path selection: verify the tree is still the locked one,
/// then import it (or find the import already in the store). The
/// `external-toolchain` exception is recorded either way, before anything
/// is copied, so a policy that denies it stops here.
pub fn realize(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "Rust toolchain")?;
    let (row, tree) = locked_row(platform, selected)?;
    let cache = cache_path(store, &tree);
    verify(platform, &tree, &row, Some(&cache))?;
    let identity = identity(platform, selected)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        // The import carries the exception in its metadata: the cached
        // check records it again, or refuses it under a denying policy.
        policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let exception = exception(&tree, &row);
    policy::record(&exception.kind, &exception.subject, &exception.detail)?;
    let staged = store.stage_with_activity(activity)?;
    let imported = copy_tree(&tree, &staged).and_then(|copied| {
        // The copy is what is committed, so it is what must hash to the
        // lock: a tree edited between the check and the copy is refused.
        // The digest is of the bytes as they were written, and the copy's
        // links are checked again against the copy's own layout.
        check_tree(&staged)?;
        if copied != row.digest {
            return Err(copy_mismatch(&tree, &row, &copied, &cache));
        }
        super::rust::validate_rust_layout(&staged, platform)
    });
    if let Err(error) = imported {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }
    let candidate = [exception];
    let (path, applied) = store
        .commit_with_activity_and_deps(activity, &identity, &staged, &candidate, &ObjectDeps::new())
        .map_err(|e| io::Error::new(e.kind(), format!("commit the local Rust toolchain: {e}")))?;
    for other in applied {
        if !candidate.contains(&other) {
            policy::record(&other.kind, &other.subject, &other.detail)?;
        }
    }
    Ok(path)
}

/// A fake local toolchain for tests: a tree whose `bin/rustc` and
/// `bin/cargo` are shell scripts printing what the real ones print, with
/// the layout a Rust object needs.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn fake_toolchain(tree: &Path, platform: Platform, release: &str) {
        fs::create_dir_all(tree.join("bin")).unwrap();
        fs::create_dir_all(tree.join(format!("lib/rustlib/{}/lib", platform.triple()))).unwrap();
        let script = |name: &str, body: String| {
            let path = tree.join("bin").join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        };
        script(
            "rustc",
            format!(
                "printf 'rustc {release} (0123abcde 2026-06-26)\\nbinary: rustc\\n\
                 commit-hash: 0123abcde\\nhost: {}\\nrelease: {release}\\n'\n",
                platform.triple()
            ),
        );
        script(
            "cargo",
            format!("printf 'cargo {release} (4567fedcb 2026-06-26)\\n'\n"),
        );
        fs::write(
            tree.join(format!("lib/rustlib/{}/lib/libstd.rlib", platform.triple())),
            b"std",
        )
        .unwrap();
        std::os::unix::fs::symlink("rustc", tree.join("bin/rustc-alias")).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::fake_toolchain;
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    fn temp(name: &str) -> TempDir {
        TempDir::named(&format!("rust-path-{name}"))
    }

    fn path_row(value: &str) -> InputRow {
        InputRow {
            path: PathBuf::from("rust-toolchain.toml"),
            field: RUST_TOOLCHAIN_PATH.1.to_string(),
            value: Some(value.to_string()),
            absent: false,
            sha256: Some("0".repeat(64)),
        }
    }

    #[test]
    fn the_tree_hash_is_content_and_nothing_else() {
        let dir = temp("hash");
        let (a, b) = (dir.0.join("a"), dir.0.join("b"));
        fake_toolchain(&a, host(), "1.96.1");
        fake_toolchain(&b, host(), "1.96.1");
        assert_eq!(tree_digest(&a).unwrap(), tree_digest(&b).unwrap());
        // Bytes, an executable bit, a name and a link target each change it.
        let base = tree_digest(&a).unwrap();
        let std = format!("lib/rustlib/{}/lib/libstd.rlib", host().triple());
        fs::write(b.join(&std), b"STD").unwrap();
        assert_ne!(tree_digest(&b).unwrap(), base);
        fs::write(b.join(&std), b"std").unwrap();
        assert_eq!(tree_digest(&b).unwrap(), base);
        fs::set_permissions(b.join(&std), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(tree_digest(&b).unwrap(), base);
        fs::set_permissions(b.join(&std), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(b.join("bin/rustc-alias")).unwrap();
        std::os::unix::fs::symlink("cargo", b.join("bin/rustc-alias")).unwrap();
        assert_ne!(tree_digest(&b).unwrap(), base);
        // A link out of the tree is refused, not followed.
        fs::remove_file(b.join("bin/rustc-alias")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/env", b.join("bin/rustc-alias")).unwrap();
        let error = tree_digest(&b).unwrap_err();
        assert!(
            error.to_string().contains("outside the toolchain"),
            "{error}"
        );
        assert!(!contained_link(
            &b,
            Path::new("bin/x"),
            Path::new("../../etc")
        ));
        assert!(contained_link(
            &b,
            Path::new("bin/x"),
            Path::new("../lib/y")
        ));
    }

    fn no_cache(_: &Path) -> Option<(PathBuf, StoreActivity)> {
        None
    }

    thread_local! {
        static LEASED_ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
        static EXCLUSIVE_AFTER_WALK: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    /// `store_cache` for the store at `LEASED_ROOT`.
    fn leased_cache(tree: &Path) -> Option<(PathBuf, StoreActivity)> {
        let store = Store::for_test(LEASED_ROOT.with_borrow(Clone::clone)?);
        let activity = store.try_activity_shared().unwrap()?;
        Some((cache_path(&store, tree), activity))
    }

    /// `select` holds the cache's shared lease from before the tree walk
    /// to past the cache rewrite: an exclusive job cannot start between
    /// them (#434).
    #[test]
    fn the_cache_lease_is_held_while_the_tree_is_hashed() {
        if !crate::kernel::sandbox::linux_ready("the_cache_lease_is_held_while_the_tree_is_hashed")
        {
            return;
        }
        let dir = temp("leased");
        fake_toolchain(&dir.0.join("tree"), host(), "1.96.1");
        let root = dir.0.join("store");
        for sub in ["objects", "meta", "tmp", "cache"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        LEASED_ROOT.set(Some(root.clone()));
        AFTER_TREE_WALK.set(Some(|| {
            let root = LEASED_ROOT.with_borrow(Clone::clone).unwrap();
            let exclusive = Store::for_test(root).try_activity_exclusive().unwrap();
            EXCLUSIVE_AFTER_WALK.set(Some(exclusive.is_some()));
        }));
        let selected = select_with(host(), &dir.0, &[path_row("tree")], leased_cache);
        AFTER_TREE_WALK.set(None);
        LEASED_ROOT.set(None);
        selected.unwrap().unwrap();
        assert_eq!(
            EXCLUSIVE_AFTER_WALK.get(),
            Some(false),
            "an exclusive lease was free between the tree walk and the cache rewrite"
        );
        // Control: once `select` returns, the lease is released.
        assert!(Store::for_test(root)
            .try_activity_exclusive()
            .unwrap()
            .is_some());
    }

    /// Links are resolved against the tree on disk, through the links they
    /// pass: text that stays inside can still lead out.
    #[test]
    fn a_link_that_leaves_through_another_link_is_refused() {
        let dir = temp("chained");
        let tree = dir.0.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        fs::write(dir.0.join("secret"), b"outside").unwrap();
        fs::create_dir(tree.join("d")).unwrap();
        // d/s is the root itself: inside.
        std::os::unix::fs::symlink("..", tree.join("d/s")).unwrap();
        assert!(tree_digest(&tree).is_ok());
        // A link through d/s to the root's own files stays inside.
        std::os::unix::fs::symlink("d/s/bin/rustc", tree.join("inside")).unwrap();
        assert!(tree_digest(&tree).is_ok());
        // `d/s/../secret` never climbs above the root as text, but d/s is
        // the root, so its `..` is the root's parent.
        std::os::unix::fs::symlink("d/s/../secret", tree.join("e")).unwrap();
        assert!(contained_link(&tree, Path::new("d/s"), Path::new("..")));
        assert!(!contained_link(
            &tree,
            Path::new("e"),
            Path::new("d/s/../secret")
        ));
        let error = tree_digest(&tree).unwrap_err();
        assert!(
            error.to_string().contains("e links to d/s/../secret"),
            "{error}"
        );
        assert!(
            error.to_string().contains("outside the toolchain"),
            "{error}"
        );
        fs::create_dir(dir.0.join("copy")).unwrap();
        let error = copy_tree(&tree, &dir.0.join("copy")).unwrap_err();
        assert!(
            error.to_string().contains("outside the toolchain"),
            "{error}"
        );
        fs::remove_file(tree.join("e")).unwrap();
        // A loop resolves nowhere, and an absolute hop inside a chain leaves.
        std::os::unix::fs::symlink("loop-b", tree.join("loop-a")).unwrap();
        std::os::unix::fs::symlink("loop-a", tree.join("loop-b")).unwrap();
        assert!(tree_digest(&tree).is_err());
        fs::remove_file(tree.join("loop-a")).unwrap();
        fs::remove_file(tree.join("loop-b")).unwrap();
        std::os::unix::fs::symlink(&dir.0, tree.join("d/abs")).unwrap();
        assert!(!contained_link(
            &tree,
            Path::new("f"),
            Path::new("d/abs/secret")
        ));
        fs::remove_file(tree.join("d/abs")).unwrap();
        // A dangling link inside the tree stays inside.
        std::os::unix::fs::symlink("not-yet/../bin", tree.join("dangling")).unwrap();
        assert!(tree_digest(&tree).is_ok());
    }

    /// A file is read through the descriptor the walk checked: a name
    /// swapped for a symlink between the walk seeing it and reading it is
    /// refused, not followed.
    #[test]
    fn a_file_swapped_for_a_link_mid_walk_is_refused() {
        let dir = temp("swap");
        let tree = dir.0.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        fs::write(dir.0.join("secret"), b"outside").unwrap();
        let mut refused = Vec::new();
        walk(&tree, &mut |path, entry| {
            if let Entry::File(file) = entry {
                if path == Path::new("bin/cargo") {
                    fs::remove_file(tree.join(path))?;
                    std::os::unix::fs::symlink(dir.0.join("secret"), tree.join(path))?;
                    refused.push(file.open(&tree, path).is_err());
                }
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(refused, [true]);
    }

    /// An unchanged file's sum comes from the cache; a changed one is read,
    /// and verification never refuses a tree on a cached sum alone.
    #[test]
    fn unchanged_files_are_hashed_from_the_cache() {
        if !crate::kernel::sandbox::linux_ready("unchanged_files_are_hashed_from_the_cache") {
            return;
        }
        let dir = temp("cache");
        let tree = dir.0.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        let cache = dir.0.join("cache.json");
        let full = tree_digest(&tree).unwrap();
        // Every file is quiet enough to remember in this test.
        assert_eq!(
            tree_digest_quiet(&tree, Some(&cache), true, i64::MAX).unwrap(),
            full
        );
        let std = format!("lib/rustlib/{}/lib/libstd.rlib", host().triple());
        let mut files = load_cache(&cache);
        assert!(files.contains_key(&std), "{files:?}");
        assert!(files.contains_key("bin/rustc"), "{files:?}");
        // A cached sum is used without reading the file: a wrong one shows.
        files.get_mut(&std).unwrap().sha256 = "0".repeat(64);
        save_cache(&cache, &files);
        assert_ne!(
            tree_digest_quiet(&tree, Some(&cache), true, i64::MAX).unwrap(),
            full
        );
        // The verification of the locked tree reads past the wrong sum.
        let bundle = select_with(host(), &dir.0, &[path_row("tree")], no_cache)
            .unwrap()
            .unwrap();
        let row = Selected {
            ecosystem: "rust".into(),
            bundle,
            lock_sha256: None,
            source: crate::kernel::toolchain::Source::Lock,
            helpers: BTreeMap::new(),
        }
        .artifact(host(), "rustc")
        .unwrap();
        files.get_mut(&std).unwrap().sha256 = "0".repeat(64);
        save_cache(&cache, &files);
        verify(host(), &tree.canonicalize().unwrap(), &row, Some(&cache)).unwrap();
        // ...and drops the wrong sum rather than keep re-reading past it.
        assert!(load_cache(&cache)
            .get(&std)
            .is_none_or(|cached| cached.sha256 != "0".repeat(64)));
        // A changed file has another key, so it is read again.
        fs::write(tree.join(&std), b"STD").unwrap();
        let changed = tree_digest_quiet(&tree, Some(&cache), true, i64::MAX).unwrap();
        assert_eq!(changed, tree_digest(&tree).unwrap());
        assert_ne!(changed, full);
        // A file changed within the quiet window is not remembered.
        let _ = fs::remove_file(&cache);
        tree_digest_cached(&tree, Some(&cache)).unwrap();
        assert!(!load_cache(&cache).contains_key(&std));
    }

    /// A cached sum that lies about a changed file lets verification pass,
    /// but the copy's own hash catches it; the refusal then re-reads the
    /// tree and rewrites the cache, so the next run reports the change
    /// truthfully instead of repeating the same mismatch, and restoring the
    /// file imports the tree.
    #[test]
    fn realize_recovers_from_a_stale_cached_sum() {
        if !crate::kernel::sandbox::linux_ready("realize_recovers_from_a_stale_cached_sum") {
            return;
        }
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let _attribution = crate::kernel::policy::Attribution::open("cargo").unwrap();
        let dir = temp("realize-cache");
        let store_root = dir.0.join("store");
        for sub in [
            "objects",
            "meta",
            "cache/sha256",
            "tmp",
            "roots",
            "forests",
            "backups",
            "root-locks",
        ] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store::for_test(store_root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let tree = dir.0.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        let bundle = select_with(host(), &dir.0, &[path_row("tree")], no_cache)
            .unwrap()
            .unwrap();
        let selected = Selected {
            ecosystem: "rust".into(),
            bundle,
            lock_sha256: None,
            source: crate::kernel::toolchain::Source::Lock,
            helpers: BTreeMap::new(),
        };
        let tree = tree.canonicalize().unwrap();
        let cache = cache_path(&store, &tree);
        let std = format!("lib/rustlib/{}/lib/libstd.rlib", host().triple());
        let locked_sum = hex::encode(Sha256::digest(b"std"));

        // Change the file, then forge its cache entry: the new key, with
        // the sum the lock was taken from.
        fs::write(tree.join(&std), b"STD").unwrap();
        tree_digest_quiet(&tree, Some(&cache), false, i64::MAX).unwrap();
        let mut files = load_cache(&cache);
        files.get_mut(&std).unwrap().sha256 = locked_sum.clone();
        save_cache(&cache, &files);
        assert_eq!(
            tree_digest_quiet(&tree, Some(&cache), true, i64::MAX).unwrap(),
            selected.artifact(host(), "rustc").unwrap().digest,
            "the forged entry does not stand in for the locked bytes"
        );

        let first = realize(&store, &activity, host(), &selected).unwrap_err();
        assert!(
            first
                .to_string()
                .contains("changed since tog-toolchain.toml locked it"),
            "{first}"
        );
        // The forged sum is gone: the cache holds what the file holds.
        assert_ne!(
            load_cache(&cache)
                .get(&std)
                .map(|cached| cached.sha256.clone()),
            Some(locked_sum)
        );
        let again = realize(&store, &activity, host(), &selected).unwrap_err();
        assert!(
            again
                .to_string()
                .contains("changed since tog-toolchain.toml locked it"),
            "{again}"
        );
        // Restoring the bytes the lock names imports the tree.
        fs::write(tree.join(&std), b"std").unwrap();
        let imported = realize(&store, &activity, host(), &selected).unwrap();
        assert_eq!(
            fs::read(imported.join(&std)).unwrap(),
            b"std",
            "the import holds the locked bytes"
        );
        drop(activity);
    }

    /// Each probe gets its own directory, private to this user.
    #[test]
    fn probe_scratch_directories_are_private_and_distinct() {
        let (first, second) = (probe_scratch().unwrap(), probe_scratch().unwrap());
        assert_ne!(first, second);
        for scratch in [&first, &second] {
            let mode = fs::symlink_metadata(scratch).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o700, "{}", scratch.display());
            fs::remove_dir(scratch).unwrap();
        }
    }

    /// A temp root that does not exist yet is created, and the probe
    /// directory inside it is still private.
    #[test]
    fn probe_scratch_creates_a_missing_temp_root() {
        let dir = temp("probe-root");
        let root = dir.0.join("not/made/yet");
        let scratch = probe_scratch_under(&root).unwrap();
        assert_eq!(scratch.parent(), Some(root.as_path()));
        let mode = fs::symlink_metadata(&scratch).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o700, "{}", scratch.display());
    }

    #[test]
    fn a_path_row_selects_the_probed_and_hashed_tree() {
        if !crate::kernel::sandbox::linux_ready("a_path_row_selects_the_probed_and_hashed_tree") {
            return;
        }
        let dir = temp("select");
        let tree = dir.0.join("custom-rust");
        fake_toolchain(&tree, host(), "1.97.0-nightly");
        // No path row: the catalog answers.
        assert_eq!(select_with(host(), &dir.0, &[], no_cache).unwrap(), None);
        // Relative to the project, as rustup reads it.
        let bundle = select_with(host(), &dir.0, &[path_row("custom-rust")], no_cache)
            .unwrap()
            .unwrap();
        assert_eq!(bundle.release, PATH_RELEASE);
        assert_eq!(bundle.component("rustc").unwrap().version, "1.97.0");
        assert_eq!(bundle.component("cargo").unwrap().version, "1.97.0");
        assert!(bundle.complete_for(host()));
        let row = bundle.artifact(host(), "rustc").unwrap();
        assert_eq!(row.recipe, PATH_RECIPE);
        assert_eq!(row.provider, PATH_SOURCE);
        assert_eq!(
            row.url,
            format!("file://{}", tree.canonicalize().unwrap().display())
        );
        assert_eq!(row.digest, tree_digest(&tree).unwrap());
        assert_eq!(
            row.build,
            "rustc 1.97.0-nightly (0123abcde 2026-06-26); cargo 1.97.0-nightly (4567fedcb 2026-06-26)"
        );
        // The same tree named absolutely is the same bundle.
        let absolute = select_with(
            host(),
            &dir.0,
            &[path_row(tree.to_str().unwrap())],
            no_cache,
        )
        .unwrap()
        .unwrap();
        assert_eq!(absolute, bundle);
        // A missing tree, or one built for another host, is refused.
        let error = select_with(host(), &dir.0, &[path_row("nowhere")], no_cache).unwrap_err();
        assert!(
            error.to_string().contains("toolchain.path nowhere"),
            "{error}"
        );
        let foreign = dir.0.join("foreign");
        let other = if host() == Platform::X86_64UnknownLinuxGnu {
            Platform::Aarch64AppleDarwin
        } else {
            Platform::X86_64UnknownLinuxGnu
        };
        fake_toolchain(&foreign, other, "1.96.1");
        let error = select_with(host(), &dir.0, &[path_row("foreign")], no_cache).unwrap_err();
        assert!(error.to_string().contains("not this host"), "{error}");
    }
}

/// Offline tests for `locked_row` (#348): what a path selection's locked
/// row must look like before any tree is read. Reached through
/// `identity`, the public caller that touches nothing else.
#[cfg(test)]
mod locked_row_tests {
    use super::*;
    use crate::kernel::toolchain::Source;

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    fn selected(recipe: &str, url: &str, digest: Digest) -> Selected {
        Selected {
            ecosystem: "rust".into(),
            bundle: Bundle {
                release: PATH_RELEASE.into(),
                revision: None,
                primary: vec!["rustc".into()],
                // As a real path selection declares them: cargo rides in
                // the rustc tree, so it has no artifact row of its own.
                components: vec![
                    Component::new("rustc", "1.97.0"),
                    Component::embedded("cargo", "1.97.0", "rustc"),
                ],
                artifacts: vec![ArtifactRow {
                    platform: host(),
                    component: "rustc".into(),
                    provider: PATH_SOURCE.into(),
                    build: "rustc 1.97.0 (0123abcde 2026-06-26)".into(),
                    recipe: recipe.into(),
                    url: url.into(),
                    digest,
                }],
            },
            lock_sha256: None,
            source: Source::Lock,
            helpers: BTreeMap::new(),
        }
    }

    fn sha256() -> Digest {
        Digest::sha256(&"a".repeat(64)).unwrap()
    }

    fn refusal(selected: &Selected) -> String {
        identity(host(), selected)
            .map(drop)
            .expect_err("the row must be refused")
            .to_string()
    }

    #[test]
    fn a_recipe_this_tog_does_not_know_is_refused() {
        assert_eq!(
            refusal(&selected("rust-path/2", "file:///opt/rust", sha256())),
            "cargo: recipe rust-path/2 in tog-toolchain.toml is not known to this tog; upgrade tog"
        );
    }

    /// A path selection made now, not read from a lock, says so (#558).
    #[test]
    fn a_refused_row_of_a_new_selection_names_the_catalog() {
        let mut new = selected("rust-path/2", "file:///opt/rust", sha256());
        new.source = Source::Created;
        assert_eq!(
            refusal(&new),
            "cargo: recipe rust-path/2 in the toolchain catalog is not known to this tog; upgrade tog"
        );
    }

    #[test]
    fn a_tree_digest_that_is_not_sha256_is_refused() {
        let sha512 = Digest::sha512(&"b".repeat(128)).unwrap();
        assert_eq!(
            refusal(&selected(PATH_RECIPE, "file:///opt/rust", sha512)),
            "cargo: rustc artifact digest must be sha256, got sha512"
        );
    }

    #[test]
    fn a_url_that_is_not_an_absolute_file_path_is_refused() {
        for url in [
            "https://static.rust-lang.org/dist/rust.tar.xz",
            "file://opt/rust",
            "file://./rust",
            "file://",
            "/opt/rust",
        ] {
            assert_eq!(
                refusal(&selected(PATH_RECIPE, url, sha256())),
                format!(
                    "cargo: the local Rust toolchain row names {url}, not an absolute file:// path"
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn the_recipe_is_checked_before_the_digest_and_the_url() {
        // Every field wrong: the recipe refusal wins, so an old tog says
        // "upgrade" rather than complaining about a row it cannot read.
        let sha512 = Digest::sha512(&"b".repeat(128)).unwrap();
        let error = refusal(&selected("rust-path/2", "https://x/rust", sha512.clone()));
        assert!(error.starts_with("cargo: recipe rust-path/2"), "{error}");
        let error = refusal(&selected(PATH_RECIPE, "https://x/rust", sha512));
        assert!(error.contains("must be sha256, got sha512"), "{error}");
    }

    #[test]
    fn control_a_well_formed_row_names_the_tree_object() {
        let identity =
            identity(host(), &selected(PATH_RECIPE, "file:///opt/rust", sha256())).unwrap();
        assert_eq!(identity.kind, "rust");
        assert_eq!(identity.name, "rust");
        assert_eq!(identity.version, "1.97.0");
        assert_eq!(identity.inputs["schema"], PATH_RECIPE);
        assert_eq!(identity.inputs["platform"], host().triple());
        assert_eq!(identity.inputs["tree_sha256"], "a".repeat(64));
        assert_eq!(
            identity.inputs["build"],
            "rustc 1.97.0 (0123abcde 2026-06-26)"
        );
    }
}

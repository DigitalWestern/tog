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

/// Run one of the tree's own binaries for its version output, in the build
/// sandbox: the tree read-only, a scratch directory as the only writable
/// place (its home, temp and working directory), no network and a scrubbed
/// environment. The answer is written to a file in the scratch directory,
/// which is read back once the child exits. This touches no store, so it
/// needs no store lease and runs the same while a lock is being written as
/// during a sync.
fn version_output(platform: Platform, tree: &Path, binary: &str, flag: &str) -> io::Result<String> {
    let scratch = std::env::temp_dir().join(format!(
        "tog-rust-path-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    fs::create_dir_all(&scratch)?;
    let answer = scratch.join("version.txt");
    let program = tree.join("bin").join(binary);
    let (program_arg, answer_arg) = (program.display().to_string(), answer.display().to_string());
    let sandbox = Sandbox {
        read: vec![tree],
        write: Vec::new(),
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
pub fn tree_digest(root: &Path) -> io::Result<Digest> {
    tree_digest_cached(root, None)
}

/// [`tree_digest`], reading a file's sha256 from the cache at `cache`
/// instead of the file when the file's [`FileKey`] is the one the cache
/// recorded, and writing back what it learned. The tree walk, the link
/// checks and the hash over the records run in full every time: only
/// unchanged file bytes are not read again.
fn tree_digest_cached(root: &Path, cache: Option<&Path>) -> io::Result<Digest> {
    // A file changed in the same clock tick as its hash could keep its key
    // with other bytes, so only files quiet for a while are remembered.
    let quiet_before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |now| now.as_secs() as i64 - CACHE_QUIET_SECONDS);
    tree_digest_quiet(root, cache, quiet_before)
}

/// [`tree_digest_cached`], remembering only files whose change time (in
/// seconds) is before `quiet_before`.
fn tree_digest_quiet(root: &Path, cache: Option<&Path>, quiet_before: i64) -> io::Result<Digest> {
    check_tree(root)?;
    let known = cache.map(load_cache).unwrap_or_default();
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
    if let Some(cache) = cache {
        if learned != known {
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

/// The cache of the active store, when there is one: what `select` reads
/// and writes. The store is only located, never created.
fn store_cache(tree: &Path) -> Option<PathBuf> {
    Store::existing()
        .ok()
        .flatten()
        .map(|store| cache_path(&store, tree))
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
    let temporary = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
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
/// this is the moment the lock's identity for it is taken. File hashes are
/// shared with the active store's cache, so the realization that follows
/// does not read the tree's files again.
pub fn select(platform: Platform, project: &Path, rows: &[InputRow]) -> io::Result<Option<Bundle>> {
    select_with(platform, project, rows, store_cache)
}

fn select_with(
    platform: Platform,
    project: &Path,
    rows: &[InputRow],
    cache: fn(&Path) -> Option<PathBuf>,
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
    let digest = tree_digest_cached(&tree, cache(&tree).as_deref())?;
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
    if row.recipe != PATH_RECIPE {
        return Err(invalid(format!(
            "cargo: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
            row.recipe
        )));
    }
    if row.digest.algo() != "sha256" {
        return Err(invalid(format!(
            "cargo: the local Rust toolchain row is a {} digest; this tog hashes trees with sha256",
            row.digest.algo()
        )));
    }
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
    let changed = |what: String| {
        invalid(format!(
            "the Rust toolchain at {} changed since tog-toolchain.toml locked it ({what}); \
             run `tog update --toolchain rust` to lock the tree as it is now",
            tree.display()
        ))
    };
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
        // Drop the sums that disagreed and read every file: the cache is
        // rebuilt from what the tree holds now.
        let _ = fs::remove_file(cache);
        digest = tree_digest_cached(tree, Some(cache))?;
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
    verify(platform, &tree, &row, Some(&cache_path(store, &tree)))?;
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
            return Err(invalid(format!(
                "the Rust toolchain at {} changed while it was imported (locked content {}, copied {}); run tog again",
                tree.display(),
                qualified(&row.digest),
                qualified(&copied)
            )));
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

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tog-rust-path-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
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
        let (a, b) = (dir.join("a"), dir.join("b"));
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
        let _ = fs::remove_dir_all(&dir);
    }

    fn no_cache(_: &Path) -> Option<PathBuf> {
        None
    }

    /// Links are resolved against the tree on disk, through the links they
    /// pass: text that stays inside can still lead out.
    #[test]
    fn a_link_that_leaves_through_another_link_is_refused() {
        let dir = temp("chained");
        let tree = dir.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        fs::write(dir.join("secret"), b"outside").unwrap();
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
        fs::create_dir(dir.join("copy")).unwrap();
        let error = copy_tree(&tree, &dir.join("copy")).unwrap_err();
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
        std::os::unix::fs::symlink(&dir, tree.join("d/abs")).unwrap();
        assert!(!contained_link(
            &tree,
            Path::new("f"),
            Path::new("d/abs/secret")
        ));
        fs::remove_file(tree.join("d/abs")).unwrap();
        // A dangling link inside the tree stays inside.
        std::os::unix::fs::symlink("not-yet/../bin", tree.join("dangling")).unwrap();
        assert!(tree_digest(&tree).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A file is read through the descriptor the walk checked: a name
    /// swapped for a symlink between the walk seeing it and reading it is
    /// refused, not followed.
    #[test]
    fn a_file_swapped_for_a_link_mid_walk_is_refused() {
        let dir = temp("swap");
        let tree = dir.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        fs::write(dir.join("secret"), b"outside").unwrap();
        let mut refused = Vec::new();
        walk(&tree, &mut |path, entry| {
            if let Entry::File(file) = entry {
                if path == Path::new("bin/cargo") {
                    fs::remove_file(tree.join(path))?;
                    std::os::unix::fs::symlink(dir.join("secret"), tree.join(path))?;
                    refused.push(file.open(&tree, path).is_err());
                }
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(refused, [true]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// An unchanged file's sum comes from the cache; a changed one is read,
    /// and verification never refuses a tree on a cached sum alone.
    #[test]
    fn unchanged_files_are_hashed_from_the_cache() {
        let dir = temp("cache");
        let tree = dir.join("tree");
        fake_toolchain(&tree, host(), "1.96.1");
        let cache = dir.join("cache.json");
        let full = tree_digest(&tree).unwrap();
        // Every file is quiet enough to remember in this test.
        assert_eq!(
            tree_digest_quiet(&tree, Some(&cache), i64::MAX).unwrap(),
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
            tree_digest_quiet(&tree, Some(&cache), i64::MAX).unwrap(),
            full
        );
        // The verification of the locked tree reads past the wrong sum.
        let bundle = select_with(host(), &dir, &[path_row("tree")], no_cache)
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
        let changed = tree_digest_quiet(&tree, Some(&cache), i64::MAX).unwrap();
        assert_eq!(changed, tree_digest(&tree).unwrap());
        assert_ne!(changed, full);
        // A file changed within the quiet window is not remembered.
        let _ = fs::remove_file(&cache);
        tree_digest_cached(&tree, Some(&cache)).unwrap();
        assert!(!load_cache(&cache).contains_key(&std));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_row_selects_the_probed_and_hashed_tree() {
        let dir = temp("select");
        let tree = dir.join("custom-rust");
        fake_toolchain(&tree, host(), "1.97.0-nightly");
        // No path row: the catalog answers.
        assert_eq!(select_with(host(), &dir, &[], no_cache).unwrap(), None);
        // Relative to the project, as rustup reads it.
        let bundle = select_with(host(), &dir, &[path_row("custom-rust")], no_cache)
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
        let absolute = select_with(host(), &dir, &[path_row(tree.to_str().unwrap())], no_cache)
            .unwrap()
            .unwrap();
        assert_eq!(absolute, bundle);
        // A missing tree, or one built for another host, is refused.
        let error = select_with(host(), &dir, &[path_row("nowhere")], no_cache).unwrap_err();
        assert!(
            error.to_string().contains("toolchain.path nowhere"),
            "{error}"
        );
        let foreign = dir.join("foreign");
        let other = if host() == Platform::X86_64UnknownLinuxGnu {
            Platform::Aarch64AppleDarwin
        } else {
            Platform::X86_64UnknownLinuxGnu
        };
        fake_toolchain(&foreign, other, "1.96.1");
        let error = select_with(host(), &dir, &[path_row("foreign")], no_cache).unwrap_err();
        assert!(error.to_string().contains("not this host"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }
}

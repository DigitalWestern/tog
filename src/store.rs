use crate::policy::Exception;
use crate::types::Identity;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Content/input-addressed immutable store (the closet).
///
/// Layout:
///   <root>/objects/<object-id>/     immutable realized outputs
///   <root>/meta/<object-id>.json    identity + provenance
///   <root>/cache/sha256/<hash>      verified downloaded artifacts
///   <root>/tmp/                     staging for atomic renames
///
/// ponytail: store root defaults to ~/.blanket/store (BLANKET_STORE overrides).
/// The /opt/blanket/store decision only matters once binary-cache sharing
/// exists; identity format is machine-independent so migration is re-realize.
pub struct Store {
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEntry {
    pub key: String,
    pub path: PathBuf,
    pub registry_path: PathBuf,
}

const ROOTS_INITIALIZED: &str = ".initialized";

/// Serializes every test that sets or clears `BLANKET_STORE`. The variable is
/// process-global, so an unguarded test clearing it mid-run sends a guarded one
/// to the real `~/.blanket/store` — which is populated, and fails any assertion
/// about a fresh store. One lock for the whole crate: separate per-module locks
/// do not exclude each other. Poison is ignored deliberately, so a single
/// failing test does not cascade into every other holder.
#[cfg(test)]
pub(crate) static STORE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Store {
    pub fn open() -> io::Result<Store> {
        let root = std::env::var_os("BLANKET_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".blanket/store"));
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(root.join(sub))?;
        }
        // Canonical path: sandbox subpath rules and store identities must
        // never see /tmp-style symlinked prefixes (macOS: /tmp -> /private/tmp).
        let root = root.canonicalize()?;
        Ok(Store { root })
    }

    pub fn object_path(&self, id: &str) -> PathBuf {
        self.root.join("objects").join(id)
    }

    /// Register a project whose closure was just written. Registry entries
    /// are keyed by the canonical project path, so moving a project creates a
    /// new root instead of accidentally retaining the old location.
    pub fn register_root(&self, project_dir: &Path) -> io::Result<RootEntry> {
        let project_dir = project_dir.canonicalize()?;
        let key = root_key(&project_dir);
        let roots = self.root.join("roots");
        fs::create_dir_all(&roots)?;
        let dest = roots.join(&key);
        let tmp = roots.join(format!(".{key}.tmp.{}", std::process::id()));
        fs::write(&tmp, format!("{}\n", project_dir.display()))?;
        fs::rename(&tmp, &dest)?;
        // Keep an explicit initialization marker so an empty registry can be
        // distinguished from a store upgraded from before roots existed.
        fs::write(roots.join(ROOTS_INITIALIZED), b"1\n")?;
        Ok(RootEntry {
            key,
            path: project_dir,
            registry_path: dest,
        })
    }

    /// Read the roots registry without validating whether projects still
    /// exist. `blanket store roots` is an inspection command; GC performs the
    /// stale-root drop during its sweep.
    pub fn roots(&self) -> io::Result<Vec<RootEntry>> {
        let roots = self.root.join("roots");
        fs::create_dir_all(&roots)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(roots)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let key = entry.file_name().to_string_lossy().into_owned();
            if !is_sha1(&key) {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            let path = PathBuf::from(text.trim());
            if path.as_os_str().is_empty() {
                continue;
            }
            entries.push(RootEntry {
                key,
                path,
                registry_path: entry.path(),
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    /// Whether this store has opted into registry-rooted collection. Stores
    /// created before the registry feature may have objects but no roots
    /// directory, so Store::open creating that directory is not sufficient.
    /// Valid root entries are accepted as initialized for compatibility with
    /// stores written by the first registry implementation, before the marker
    /// was added.
    pub(crate) fn registry_initialized(&self) -> io::Result<bool> {
        let roots = self.root.join("roots");
        if roots.join(ROOTS_INITIALIZED).is_file() {
            return Ok(true);
        }
        for entry in fs::read_dir(roots)? {
            let entry = entry?;
            if entry.file_type()?.is_file() && is_sha1(&entry.file_name().to_string_lossy()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn remove_root_entry(&self, entry: &RootEntry) -> io::Result<()> {
        match fs::remove_file(&entry.registry_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Exclusive cross-process lock guarding publication and sweeping.
    /// Held only for the short rename/chmod/meta window, never during
    /// downloads or builds, so contention is negligible.
    pub(crate) fn publish_lock(&self) -> io::Result<fs::File> {
        let f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(self.root.join("tmp/.publish.lock"))?;
        f.lock()?;
        Ok(f)
    }

    /// Exclusive lock shared by fetches and GC. A cache lease keeps this
    /// lock until its verified artifact has been extracted by the caller.
    pub(crate) fn gc_lock(&self) -> io::Result<fs::File> {
        let f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(self.root.join("gc.lock"))?;
        f.lock()?;
        Ok(f)
    }

    /// Completeness check without sweeping (safe to call while holding the
    /// publish lock).
    fn is_complete(&self, id: &str) -> Option<bool> {
        let md = fs::metadata(self.object_path(id)).ok()?;
        use std::os::unix::fs::PermissionsExt;
        Some(
            md.is_dir()
                && md.permissions().mode() & 0o222 == 0
                && self.root.join("meta").join(format!("{id}.json")).is_file(),
        )
    }

    /// An object is valid only when fully published: directory present,
    /// root read-only, and metadata written (in that commit order). A
    /// crash mid-publication leaves an invalid object, which is swept and
    /// rebuilt instead of trusted.
    pub fn has(&self, id: &str) -> bool {
        let Ok(_lock) = self.publish_lock() else {
            return false;
        };
        match self.is_complete(id) {
            None => false,
            Some(true) => {
                // A cache hit is still active use. GC holds this same lock
                // while sweeping, so the touch and the sweep cannot cross.
                let _ = touch_path(&self.object_path(id));
                true
            }
            Some(false) => {
                // Looks like a crashed publication — but a CONCURRENT commit
                // may be in its rename->chmod->meta window. We already hold
                // the lock, so sweep only what is still incomplete now.
                match self.is_complete(id) {
                    Some(true) => {
                        let _ = touch_path(&self.object_path(id));
                        true
                    }
                    Some(false) => {
                        let _ = remove_tree(&self.object_path(id));
                        false
                    }
                    None => false,
                }
            }
        }
    }

    /// Stage dir for building a new object; caller fills it, then calls commit.
    /// Collision-proof: SystemTime ticks in microseconds on macOS, so two
    /// threads can draw the same timestamp — create_dir (not _all) makes a
    /// collision an AlreadyExists we retry with a sequence number.
    pub fn stage(&self) -> io::Result<PathBuf> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        loop {
            let dir = self.root.join("tmp").join(format!(
                "stage-{}-{}-{}",
                std::process::id(),
                nanos(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Atomically move a staged dir into the store under `identity`, write
    /// metadata, and mark the tree read-only. Returns the object path and the
    /// exceptions stored with the object.
    /// If the object already exists the staged dir is discarded (cache hit).
    pub fn commit(
        &self,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        let id = identity.object_id();
        let dest = self.object_path(&id);
        if self.has(&id) {
            return self.cache_hit(&id, &dest, staged, exceptions);
        }
        // Read-only BEFORE publication (contents; APFS can't rename a
        // read-only dir, so the root is locked right after the rename —
        // the only window is top-level entry creation, never mutation).
        for entry in fs::read_dir(staged)? {
            make_read_only(&entry?.path())?;
        }
        // Publish under the cross-process lock so a concurrent has() never
        // mistakes the rename->chmod->meta window for a crashed object.
        let _lock = self.publish_lock()?;
        if self.is_complete(&id) == Some(true) {
            return self.cache_hit(&id, &dest, staged, exceptions);
        }
        // Under the lock, anything at dest is a crashed leftover (a live
        // publication can't be mid-window, and a complete object returned
        // above): sweep it so the rename lands.
        if dest.is_dir() {
            remove_tree(&dest)?;
        }
        fs::rename(staged, &dest)
            .map_err(|e| io::Error::new(e.kind(), format!("publish {}: {e}", dest.display())))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(perms.mode() & !0o222);
            fs::set_permissions(&dest, perms)?;
        }
        let meta = serde_json::json!({
            "id": id,
            "identity": identity,
            "created": unix_secs(),
            "exceptions": exceptions,
            "refs": object_refs(identity),
        });
        // Meta is the completion marker: write via tmp + atomic rename so a
        // crash mid-write can never leave a partial file that has() would
        // accept as complete.
        let meta_tmp = self.root.join("tmp").join(format!("meta-{id}.json"));
        fs::write(&meta_tmp, serde_json::to_vec_pretty(&meta)?)?;
        fs::rename(&meta_tmp, self.root.join("meta").join(format!("{id}.json")))?;
        // The stage directory may have been built for hours. Refresh the
        // published object's activity marker while publication is still
        // protected by the lock, before GC can inspect it.
        touch_path(&dest)?;
        Ok((dest, exceptions.to_vec()))
    }

    fn cache_hit(
        &self,
        id: &str,
        dest: &Path,
        staged: &Path,
        candidate: &[Exception],
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        let winner = self.exceptions(id)?;
        let result = crate::policy::check_exception_set(id, &winner).and_then(|_| {
            if winner != candidate {
                return Err(io::Error::other(format!(
                    "object {id} was published concurrently with different exceptions; winner: {winner:?}; staged: {candidate:?}; re-run sync"
                )));
            }
            Ok((dest.to_path_buf(), winner))
        });
        if result.is_ok() {
            let _ = touch_path(dest);
        }
        let _ = remove_tree(staged);
        result
    }

    pub fn exceptions(&self, id: &str) -> io::Result<Vec<Exception>> {
        let path = self.root.join("meta").join(format!("{id}.json"));
        let meta: serde_json::Value =
            serde_json::from_reader(fs::File::open(&path)?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse {}: {e}", path.display()),
                )
            })?;
        match meta.get("exceptions") {
            None => Ok(Vec::new()),
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse exceptions in {}: {e}", path.display()),
                )
            }),
        }
    }

    pub fn cache_path(&self, algo: &str, hex: &str) -> PathBuf {
        self.root.join("cache").join(algo).join(hex)
    }
}

fn errno_location() -> *mut libc::c_int {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: libc returns the calling thread's errno slot.
        unsafe { libc::__errno_location() }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: libc returns the calling thread's errno slot.
        unsafe { libc::__error() }
    }
}

fn fd_set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl operates on the caller-owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fd_stat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: stat is initialized by fstat before it is read.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is borrowed for the duration of this call.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn stat_at(dirfd: RawFd, name: &[u8]) -> io::Result<libc::stat> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: stat is initialized by fstatat before it is read, and name is a
    // NUL-terminated path that lives through the call.
    let mut stat = unsafe { std::mem::zeroed() };
    // SAFETY: dirfd is borrowed for the duration of this call.
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn same_inode(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn is_directory(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

fn is_symlink(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

fn entry_names_at(dirfd: RawFd) -> io::Result<Vec<OsString>> {
    // fdopendir takes ownership of its descriptor, so duplicate the borrowed
    // directory fd before handing it to libc.
    // SAFETY: fcntl duplicates the borrowed descriptor.
    let duplicate = unsafe { libc::fcntl(dirfd, libc::F_DUPFD, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = fd_set_cloexec(duplicate) {
        // SAFETY: duplicate is owned here because fdopendir has not taken it.
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    // SAFETY: duplicate is a valid directory descriptor and ownership moves
    // to the DIR until closedir.
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: errno_location points at this thread's errno slot.
        unsafe { *errno_location() = 0 };
        // SAFETY: directory remains valid until closedir below.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            // SAFETY: errno_location points at this thread's errno slot.
            let errno = unsafe { *errno_location() };
            // SAFETY: directory owns the duplicated descriptor.
            unsafe { libc::closedir(directory) };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            return Ok(names);
        }
        // SAFETY: d_name is a NUL-terminated name supplied by readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(OsString::from_vec(name.to_bytes().to_vec()));
        }
    }
}

/// Enumerate a directory through an already-open descriptor. Callers use this
/// for directories whose pathname may be renamed while they work.
pub(crate) fn read_dir_names_at(dirfd: RawFd) -> io::Result<Vec<OsString>> {
    entry_names_at(dirfd)
}

fn unlink_if_same(
    dirfd: RawFd,
    name: &[u8],
    expected: &libc::stat,
    flags: libc::c_int,
) -> io::Result<()> {
    let current = match stat_at(dirfd, name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !same_inode(&current, expected) {
        return Ok(());
    }
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: dirfd is borrowed and name is NUL-terminated for this call.
    if unsafe { libc::unlinkat(dirfd, name.as_ptr(), flags) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn remove_tree_entry_at(parentfd: RawFd, name: &[u8]) -> io::Result<()> {
    let expected = match stat_at(parentfd, name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if is_symlink(&expected) || !is_directory(&expected) {
        return unlink_if_same(parentfd, name, &expected, 0);
    }

    let name_c = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory entry contains NUL"))?;
    // SAFETY: name_c is NUL-terminated and parentfd is borrowed.
    let childfd = unsafe {
        libc::openat(
            parentfd,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if childfd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        if error.raw_os_error() == Some(libc::ELOOP) {
            // The entry became a symlink after fstatat. Re-check it without
            // following it, then unlink only that same symlink.
            if let Ok(current) = stat_at(parentfd, name) {
                if is_symlink(&current) {
                    return unlink_if_same(parentfd, name, &current, 0);
                }
            }
            return Ok(());
        }
        return Err(error);
    };
    let child = unsafe { fs::File::from_raw_fd(childfd) };
    let actual = fd_stat(child.as_raw_fd())?;
    if !same_inode(&actual, &expected) {
        return Ok(());
    }
    let mut mode = actual.st_mode;
    mode |= 0o200;
    // SAFETY: child is owned by this function.
    let _ = unsafe { libc::fchmod(child.as_raw_fd(), mode) };
    remove_tree_at(child.as_raw_fd())?;
    unlink_if_same(parentfd, name, &expected, libc::AT_REMOVEDIR)
}

/// Remove the contents of a possibly read-only directory through a borrowed
/// descriptor. It never resolves a child pathname: symlinks are unlinked and
/// directories are opened with O_NOFOLLOW before recursion. The caller owns
/// the directory itself and may remove it with unlinkat(AT_REMOVEDIR).
pub(crate) fn remove_tree_at(dirfd: RawFd) -> io::Result<()> {
    let stat = fd_stat(dirfd)?;
    if !is_directory(&stat) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not a directory",
        ));
    }
    let mut mode = stat.st_mode;
    mode |= 0o200;
    // SAFETY: dirfd is borrowed by the caller.
    let _ = unsafe { libc::fchmod(dirfd, mode) };
    for name in entry_names_at(dirfd)? {
        remove_tree_entry_at(dirfd, name.as_os_str().as_bytes())?;
    }
    Ok(())
}

/// Remove a possibly read-only staged tree (restore write bits first).
pub fn remove_tree(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn unlock(p: &Path) -> io::Result<()> {
        let md = fs::symlink_metadata(p)?;
        if md.file_type().is_symlink() {
            return Ok(());
        }
        let mut perms = md.permissions();
        perms.set_mode(perms.mode() | 0o200);
        let _ = fs::set_permissions(p, perms);
        if md.is_dir() {
            for entry in fs::read_dir(p)? {
                unlock(&entry?.path())?;
            }
        }
        Ok(())
    }
    let _ = unlock(path);
    fs::remove_dir_all(path)
}

/// Recursively remove write permission (files and dirs). Symlinks untouched.
fn make_read_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            make_read_only(&entry?.path())?;
        }
    }
    let mut perms = md.permissions();
    perms.set_mode(perms.mode() & !0o222);
    fs::set_permissions(path, perms)
        .map_err(|e| io::Error::new(e.kind(), format!("chmod {}: {e}", path.display())))
}

/// The object/cache mtime is the cheap activity marker used by GC. Opening
/// the path and setting its timestamp avoids a platform-specific touch
/// executable and also works for read-only published directories/files.
pub(crate) fn touch_path(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.set_modified(SystemTime::now())
}

pub(crate) fn object_id_token(value: &str) -> Option<String> {
    value
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'))
        .find(|token| is_object_id(token))
        .map(str::to_string)
}

fn is_object_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 41
        && bytes[..40].iter().all(u8::is_ascii_hexdigit)
        && bytes[40] == b'-'
        && bytes[41..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'_' || *b == b'-')
}

fn is_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn root_key(project_dir: &Path) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(project_dir.to_string_lossy().as_bytes()))
}

fn object_refs(identity: &Identity) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for value in identity.inputs.values() {
        if let Some(id) = object_id_token(value) {
            refs.insert(id);
        }
    }
    refs.into_iter().collect()
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME set"))
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::process::Command;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-store-test-{}-{}",
                std::process::id(),
                nanos()
            ));
            for sub in ["objects", "meta", "cache/sha256", "tmp"] {
                fs::create_dir_all(path.join(sub)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = remove_tree(&self.0);
        }
    }

    fn identity() -> Identity {
        Identity {
            kind: "test".into(),
            name: "object".into(),
            version: "1".into(),
            inputs: BTreeMap::new(),
        }
    }

    fn staged(store: &Store) -> PathBuf {
        let path = store.stage().unwrap();
        fs::write(path.join("content"), b"content").unwrap();
        path
    }

    #[test]
    fn roots_registry_adds_atomically_and_drops_entries() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let root = store.register_root(&project).unwrap();
        assert_eq!(store.roots().unwrap(), vec![root.clone()]);
        assert_eq!(
            fs::read_to_string(&root.registry_path).unwrap().trim(),
            project.canonicalize().unwrap().display().to_string()
        );
        store.remove_root_entry(&root).unwrap();
        assert!(store.roots().unwrap().is_empty());
    }

    #[test]
    fn commit_reconciles_cached_exceptions() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let identity = identity();
        let exception = Exception {
            kind: crate::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        let (object, applied) = store
            .commit(&identity, &staged(&store), std::slice::from_ref(&exception))
            .unwrap();
        assert_eq!(object, store.object_path(&identity.object_id()));
        assert_eq!(applied, vec![exception.clone()]);

        let error = store.commit(&identity, &staged(&store), &[]).unwrap_err();
        assert!(error
            .to_string()
            .contains("was published concurrently with different exceptions"));
        assert!(error.to_string().contains("winner:"));
        assert!(error.to_string().contains("staged: []"));

        let (same_object, applied) = store
            .commit(&identity, &staged(&store), std::slice::from_ref(&exception))
            .unwrap();
        assert_eq!(same_object, object);
        assert_eq!(applied, vec![exception]);
    }

    #[test]
    fn strict_policy_rejects_cached_exceptions() {
        if std::env::var_os("BLANKET_STORE_STRICT_CHILD").is_some() {
            let store = Store::open().unwrap();
            crate::policy::init(&store.root, false).unwrap();
            let error = store.commit(&identity(), &staged(&store), &[]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let temp = TempDir::new();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let exception = Exception {
            kind: crate::policy::FILE_COLLISION.into(),
            subject: "content".into(),
            detail: "first and second".into(),
        };
        store
            .commit(
                &identity(),
                &staged(&store),
                std::slice::from_ref(&exception),
            )
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::tests::strict_policy_rejects_cached_exceptions",
                "--nocapture",
            ])
            .env("BLANKET_STORE", &store.root)
            .env("BLANKET_STORE_STRICT_CHILD", "1")
            .env("BLANKET_STRICT", "1")
            .env_remove("BLANKET_POLICY")
            .env("HOME", &temp.0)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "strict child failed: {}",
            String::from_utf8_lossy(&child.stderr)
        );
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

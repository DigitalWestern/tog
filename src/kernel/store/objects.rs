//! Object write, commit, and immutability (kernel store): staging, the
//! publish lock, cache hits, and the dependency evidence a commit records.

use super::*;
use crate::kernel::policy::Exception;

/// Explicit dependency evidence supplied when an object is published.  The
/// sets are ordered so the on-disk metadata is deterministic and easy to
/// compare during a cache hit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectDeps {
    pub objects: BTreeSet<String>,
    pub cache: BTreeSet<crate::kernel::digest::Digest>,
}

impl ObjectDeps {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn object_id(&mut self, id: &str) -> io::Result<&mut Self> {
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed dependency object id {id:?}"),
            ));
        }
        self.objects.insert(id.to_string());
        Ok(self)
    }

    pub fn cache_digest(&mut self, digest: crate::kernel::digest::Digest) -> &mut Self {
        self.cache.insert(digest);
        self
    }
}

impl Store {
    /// Validate a referenced object without refreshing its activity marker.
    /// Root publication uses this read-only form so a closure cannot claim a
    /// half-published or foreign object and so preparation does not mutate
    /// mtimes before the durable root exists.
    pub(crate) fn validate_object_complete(
        &self,
        activity: &StoreActivity,
        id: &str,
    ) -> io::Result<()> {
        self.require_activity(activity, "object reference validation")?;
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed object id {id:?}"),
            ));
        }
        let object = self.object_path(id);
        let object_meta = fs::symlink_metadata(&object).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("object reference {id} is unavailable: {error}"),
            )
        })?;
        if object_meta.file_type().is_symlink() || !object_meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference {id} is not a real directory"),
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        if object_meta.permissions().mode() & 0o222 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference {id} is still writable"),
            ));
        }
        let metadata = self.root.join("meta").join(format!("{id}.json"));
        let metadata_stat = fs::symlink_metadata(&metadata).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("object reference {id} has no metadata: {error}"),
            )
        })?;
        if metadata_stat.file_type().is_symlink() || !metadata_stat.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference {id} metadata is not a regular file"),
            ));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&metadata)?).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse object reference metadata {id}: {e}"),
                )
            })?;
        if value.get("id").and_then(serde_json::Value::as_str) != Some(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object reference metadata {id} has a mismatched id"),
            ));
        }
        Ok(())
    }

    /// Exclusive cross-process lock guarding publication and sweeping.
    /// Held only for the short rename/chmod/meta window, never during
    /// downloads or builds, so contention is negligible.
    pub(crate) fn publish_lock(&self) -> io::Result<fs::File> {
        let f = open_private_lock(&self.root.join("tmp/.publish.lock"), "publish")?;
        f.lock()?;
        Ok(f)
    }

    /// Completeness check without sweeping (safe to call while holding the
    /// publish lock).
    ///
    /// The record must also parse: one a crash left empty or cut short is a
    /// crashed publication too, so the next lookup clears the object and the
    /// next commit writes a whole record over it. A record that cannot be
    /// read for another reason (a permission) is not evidence of a crash.
    pub(super) fn is_complete(&self, id: &str) -> Option<bool> {
        let md = fs::symlink_metadata(self.object_path(id)).ok()?;
        use std::os::unix::fs::PermissionsExt;
        let meta_path = self.root.join("meta").join(format!("{id}.json"));
        let meta = fs::symlink_metadata(&meta_path);
        let record_is_whole = || {
            use std::os::unix::fs::OpenOptionsExt;
            if publication_failpoint("before-completeness-open").is_err() {
                return true;
            }
            let file = match fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&meta_path)
            {
                Ok(file) => file,
                Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return false,
                Err(_) => return true,
            };
            match file.metadata() {
                Ok(meta) if !meta.is_file() => return false,
                Err(_) => return true,
                _ => {}
            }
            match serde_json::from_reader::<_, serde_json::Value>(std::io::BufReader::new(file)) {
                Ok(value) => value.is_object(),
                Err(error) => error.is_io(),
            }
        };
        Some(
            !md.file_type().is_symlink()
                && md.is_dir()
                && md.permissions().mode() & 0o222 == 0
                && meta
                    .as_ref()
                    .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
                && record_is_whole(),
        )
    }

    /// The identity a fully published object records, read without a
    /// lease, a publish lock, an mtime touch, or the crashed-publication
    /// cleanup `has` performs. `Ok(None)` means only that the object is
    /// absent or mid-publication; a permission error, a symlink or a
    /// non-directory object, and metadata that is not a regular file or does
    /// not describe `id` (its identity must hash to it) are errors. For
    /// read-only callers that only need to know what an object is; a
    /// concurrent sweep can make the answer `None`, never a wrong identity.
    pub fn published_identity(&self, id: &str) -> io::Result<Option<Identity>> {
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed object id {id:?}"),
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
        // Only absence is "not held". Anything else the filesystem says
        // (permission, a symlink or file where the object should be) is an
        // error, never a miss.
        let object = match fs::symlink_metadata(self.object_path(id)) {
            Ok(object) => object,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if object.file_type().is_symlink() || !object.is_dir() {
            return Err(invalid(format!(
                "store object {id} is not a real directory"
            )));
        }
        // Commit order is rename, chmod read-only, then metadata: a
        // writable root, or a missing record, is a publication in flight.
        if object.permissions().mode() & 0o222 != 0 {
            return Ok(None);
        }
        published_identity_failpoint("before-metadata-open");
        let path = self.root.join("meta").join(format!("{id}.json"));
        // O_NONBLOCK: a FIFO planted as the record must not hang a
        // read-only caller in open(2); the descriptor's own type is checked
        // before a byte is read. On a regular file the flag changes nothing.
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(invalid(format!("store object {id} metadata is a symlink")))
            }
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(invalid(format!(
                "store object {id} metadata is not a regular file"
            )));
        }
        let value: serde_json::Value = serde_json::from_reader(file)
            .map_err(|error| invalid(format!("parse store object {id} metadata: {error}")))?;
        // The record must describe `id`: its identity hashes to it. A
        // sweep and a republish of the same id in between leave a record
        // that still does, so the answer is that identity or nothing.
        let record = crate::kernel::objmeta::read_record_value(id, value)?;
        published_identity_failpoint("after-metadata-read");
        Ok(Some(record.identity))
    }

    /// An object is valid only when fully published: directory present,
    /// root read-only, and metadata written (in that commit order). A
    /// crash mid-publication leaves an invalid object, which is swept and
    /// rebuilt instead of trusted.
    ///
    /// Test-only: it takes a lease of its own, and production code borrows
    /// its caller's through `has_with_activity`.
    #[cfg(test)]
    pub fn has(&self, id: &str) -> io::Result<bool> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.has_with_activity(&activity, id)
    }

    /// Activity-aware lookup: the caller's lease covers the check. It is
    /// fallible, so a lock failure cannot be mistaken for a cache miss.
    pub fn has_with_activity(&self, activity: &StoreActivity, id: &str) -> io::Result<bool> {
        self.require_activity(activity, "store object lookup")?;
        // The id names one entry under `objects/`. `.` or `..` would name
        // `objects/` itself or the store root, which the crashed-publication
        // cleanup below would then empty. Ids read back from a closure are
        // project-editable, so refuse anything that is not one plain name.
        if !is_single_entry_name(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed object id {id:?}"),
            ));
        }
        let _lock = self.publish_lock()?;
        match self.is_complete(id) {
            None => Ok(false),
            Some(true) => {
                // A cache hit is still active use. GC holds this same lock
                // while sweeping, so the touch and the sweep cannot cross.
                let _ = touch_path(&self.object_path(id));
                Ok(true)
            }
            Some(false) => {
                // Looks like a crashed publication. The parent descriptor and
                // inode check make this cleanup safe if an entry was replaced
                // between the completeness read and removal.
                let objects = open_real_directory(&self.root.join("objects"), "objects")?;
                let name = id.as_bytes();
                let expected = match stat_at(objects.as_raw_fd(), name) {
                    Ok(expected) => expected,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error),
                };
                if !remove_tree_entry_if_same(objects.as_raw_fd(), name, &expected)? {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        format!("incomplete object {id} changed during cleanup; retry later"),
                    ));
                }
                objects.sync_all()?;
                Ok(false)
            }
        }
    }

    /// Stage dir for building a new object; caller fills it, then calls commit.
    /// Collision-proof: SystemTime ticks in microseconds on macOS, so two
    /// threads can draw the same timestamp — create_dir (not _all) makes a
    /// collision an AlreadyExists we retry with a sequence number.
    ///
    /// Test-only, like `has`: production uses `stage_with_activity`.
    #[cfg(test)]
    pub fn stage(&self) -> io::Result<PathBuf> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.stage_with_activity(&activity)
    }

    pub fn stage_with_activity(&self, activity: &StoreActivity) -> io::Result<PathBuf> {
        self.require_activity(activity, "store staging")?;
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
    /// Publish an object with explicit dependency and cache evidence.
    ///
    /// This is the only publication entry point. There is deliberately no
    /// convenience form that infers a dependency set from the identity map:
    /// an inferred set is a guess, and `commit_internal` stamps what it
    /// is given as `evidence: "explicit"`. Certifying a guess as explicit is
    /// exactly the failure this explicit-evidence boundary prevents.
    ///
    /// Test-only, like `has`: production uses
    /// `commit_with_activity_and_deps`.
    #[cfg(test)]
    pub fn commit_with_deps(
        &self,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.commit_with_activity_and_deps(&activity, identity, staged, exceptions, deps)
    }

    pub fn commit_with_activity_and_deps(
        &self,
        activity: &StoreActivity,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        self.commit_internal(activity, identity, staged, exceptions, deps)
    }

    pub(super) fn commit_internal(
        &self,
        activity: &StoreActivity,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        self.require_activity(activity, "store publication")?;
        validate_object_deps(self, activity, deps)?;
        // Grammar drift check. Each `ObjectKind` row describes the inputs
        // its producer writes, and nothing else would notice a producer
        // drifting away from its row. This is the one publication choke
        // point, and the identity is final here, so the row is checked
        // against the real thing.
        //
        // `debug_assertions`, not `test`: public tailor realization entry
        // points self-install the rows, direct kernel callers install them
        // explicitly, and CLI commands get them through `commands::dispatch`.
        // Release builds skip the check, so a store written by a release build
        // is still readable. This catches developer error, it is not a store
        // invariant. Every committed kind must have a registered row; see
        // `check_identity_grammar`.
        #[cfg(debug_assertions)]
        if let Err(reason) = crate::kernel::objmeta::check_identity_grammar(identity) {
            panic!(
                "object-kind grammar drift: kind {}, {}: {reason}\nthe producer and its \
                 ObjectKind row in src/kernel/objmeta.rs (or the tailor's objects.rs) disagree; \
                 restore the producer if the drift is accidental (a dropped input like \
                 artifact_sha256 would let distinct artifacts share an object id); update the row \
                 only for an intentional, compatible addition; introduce a new schema value when \
                 identity semantics change",
                identity.kind,
                match crate::kernel::objmeta::schema_input_of(identity) {
                    Some(schema) => format!("schema {schema}"),
                    None => "no schema input".to_string(),
                },
            );
        }
        let id = identity.object_id();
        let dest = self.object_path(&id);
        if self.has_with_activity(activity, &id)? {
            return self.cache_hit(&id, &dest, staged, exceptions, deps);
        }
        publication_failpoint("after-lookup")?;
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
            return self.cache_hit(&id, &dest, staged, exceptions, deps);
        }
        // An old record must stop certifying this id before a replacement
        // becomes visible. Persist that invalidation even when the object
        // is already gone, as after an interrupted GC.
        let metadata = open_store_directory(&self.root.join("meta"), "meta")?;
        let meta_name = format!("{id}.json");
        match stat_at(metadata.as_raw_fd(), meta_name.as_bytes()) {
            Ok(stat) => {
                if !unlink_if_same(metadata.as_raw_fd(), meta_name.as_bytes(), &stat, 0)? {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "completion record changed during recovery",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fsync_directory(metadata.as_raw_fd())?;
        // Under the lock, anything at dest is a crashed leftover (a live
        // publication can't be mid-window, and a complete object returned
        // above): sweep it so the rename lands.
        let objects = open_real_directory(&self.root.join("objects"), "objects")?;
        if let Ok(expected) = stat_at(objects.as_raw_fd(), id.as_bytes()) {
            if !remove_tree_entry_if_same(objects.as_raw_fd(), id.as_bytes(), &expected)? {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    format!("object {id} changed during publication; retry later"),
                ));
            }
            objects.sync_all()?;
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
            "schema": "object-meta/2",
            "id": id,
            "identity": identity,
            "created": unix_secs(),
            "exceptions": exceptions,
            "dependencies": deps.objects.iter().collect::<Vec<_>>(),
            "cache_digests": deps.cache.iter().map(|digest| {
                serde_json::json!({"algo": digest.algo(), "hex": digest.hex()})
            }).collect::<Vec<_>>(),
            "evidence": "explicit",
        });
        // Meta is the completion marker: write via tmp + atomic rename so a
        // crash mid-write can never leave a partial file that has() would
        // accept as complete.
        // Durable in order: the object's contents and its name under
        // `objects/`, then the record's bytes, then its name under `meta/`.
        // A power loss can then never leave a record whose object or bytes
        // did not survive.
        publication_failpoint("before-sync-tree")?;
        sync_tree(&dest)?;
        fsync_directory(objects.as_raw_fd())?;
        publish_completion(self, &metadata, &meta_name, &meta)?;
        // The stage directory may have been built for hours. Refresh the
        // published object's activity marker while publication is still
        // protected by the lock, before GC can inspect it.
        touch_path(&dest)?;
        Ok((dest, exceptions.to_vec()))
    }

    pub(super) fn cache_hit(
        &self,
        id: &str,
        dest: &Path,
        staged: &Path,
        candidate: &[Exception],
        deps: &ObjectDeps,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        validate_cached_dependency_evidence(&self.root, id, deps)?;
        let winner = self.exceptions(id)?;
        let result = crate::kernel::policy::check_exception_set(id, &winner).and_then(|_| {
            if winner != candidate {
                return Err(io::Error::other(format!(
                    "object {id} was published concurrently with different exceptions; winner: {winner:?}; staged: {candidate:?}; re-run 'tog'"
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
}

fn publish_completion(
    store: &Store,
    metadata: &fs::File,
    name: &str,
    value: &serde_json::Value,
) -> io::Result<()> {
    let tmp = open_store_directory(&store.root.join("tmp"), "tmp")?;
    let bytes = serde_json::to_vec_pretty(value)?;
    for _ in 0..16 {
        let candidate = format!("meta-{}-{}.json", std::process::id(), nanos());
        let mut file = match open_file_at(
            tmp.as_raw_fd(),
            candidate.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let expected = fd_stat(file.as_raw_fd())?;
        let result = (|| {
            io::Write::write_all(&mut file, &bytes)?;
            file.sync_all()?;
            if !same_inode(&stat_at(tmp.as_raw_fd(), candidate.as_bytes())?, &expected) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "completion temporary was replaced",
                ));
            }
            rename_between(
                tmp.as_raw_fd(),
                candidate.as_bytes(),
                metadata.as_raw_fd(),
                name.as_bytes(),
            )?;
            fsync_directory(metadata.as_raw_fd())
        })();
        if result.is_err() {
            let _ = unlink_if_same(tmp.as_raw_fd(), candidate.as_bytes(), &expected, 0);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "completion temporary names are occupied",
    ))
}

#[cfg(test)]
thread_local! {
    pub(super) static PUBLICATION_FAILPOINT: std::cell::RefCell<Option<Box<dyn FnMut(&str) -> io::Result<()>>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn publication_failpoint(at: &str) -> io::Result<()> {
    PUBLICATION_FAILPOINT.with(|slot| match slot.borrow_mut().as_mut() {
        Some(hook) => hook(at),
        None => Ok(()),
    })
}

#[cfg(not(test))]
fn publication_failpoint(_at: &str) -> io::Result<()> {
    Ok(())
}

/// What commit does to a staged tree, for tests outside the store.
#[cfg(test)]
pub(crate) fn make_read_only_for_test(path: &Path) -> io::Result<()> {
    make_read_only(path)
}

/// Recursively remove write permission (files and dirs). Symlinks untouched.
pub(super) fn make_read_only(path: &Path) -> io::Result<()> {
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

#[cfg(test)]
thread_local! {
    /// A test's hook at the named points of `published_identity`, so a
    /// sweep or republish can be interleaved deterministically.
    pub(crate) static PUBLISHED_IDENTITY_FAILPOINT: std::cell::RefCell<Option<Box<dyn FnMut(&str)>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn published_identity_failpoint(at: &str) {
    PUBLISHED_IDENTITY_FAILPOINT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(at);
        }
    });
}

#[cfg(not(test))]
fn published_identity_failpoint(_at: &str) {}

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

/// Extract a complete object id from a store object path without accepting a
/// path-shaped string or a nested child as evidence. The caller still gets
/// the final existence/metadata check from `validate_object_deps` when the
/// id is published as a dependency.
pub(crate) fn object_id_from_path(path: &Path) -> io::Result<String> {
    let objects = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object path has no objects parent: {}", path.display()),
        )
    })?;
    if objects.file_name().and_then(|name| name.to_str()) != Some("objects") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "object path is not directly below an objects directory: {}",
                path.display()
            ),
        ));
    }
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("object path id is not UTF-8: {}", path.display()),
            )
        })?;
    if !is_object_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("object path has an invalid object id {id:?}"),
        ));
    }
    Ok(id.to_string())
}

pub(crate) fn is_object_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 41
        && bytes[..40].iter().all(u8::is_ascii_hexdigit)
        && bytes[40] == b'-'
        && !value.contains("..")
        && bytes[41..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'_' || *b == b'-')
}

/// One plain directory entry name: not empty, not `.` or `..`, no `/` or
/// NUL. Looser than `is_object_id` on purpose: `Identity::object_id` keeps
/// `.` from names and versions, so a committed id may contain `..`.
fn is_single_entry_name(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\0'])
}

pub(super) fn is_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn validate_object_deps(
    store: &Store,
    activity: &StoreActivity,
    deps: &ObjectDeps,
) -> io::Result<()> {
    for id in &deps.objects {
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed dependency object id {id:?}"),
            ));
        }
        store.validate_object_complete(activity, id)?;
    }
    for digest in &deps.cache {
        let path = store.cache_path(digest.algo(), digest.hex());
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cache dependency {}:{} is unavailable: {error}",
                    digest.algo(),
                    digest.hex()
                ),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cache dependency {}:{} is not a regular file",
                    digest.algo(),
                    digest.hex()
                ),
            ));
        }
    }
    Ok(())
}

/// Compare newly supplied evidence with an already-published object's
/// metadata. A record with different evidence is unsafe to reuse because the
/// winner's transitive closure would no longer be the candidate's closure,
/// and so is one whose evidence cannot be read at all.
pub(super) fn validate_cached_dependency_evidence(
    root: &Path,
    id: &str,
    candidate: &ObjectDeps,
) -> io::Result<()> {
    let record =
        crate::kernel::objmeta::read_record_at(&root.join("meta").join(format!("{id}.json")))?;
    if record.dependencies != candidate.objects || record.cache != candidate.cache {
        let names = |cache: &BTreeSet<crate::kernel::digest::Digest>| {
            cache
                .iter()
                .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                .collect::<BTreeSet<_>>()
        };
        return Err(io::Error::other(format!(
            "object {id} was published concurrently with different dependency evidence; winner objects: {:?}, staged objects: {:?}, winner cache: {:?}, staged cache: {:?}; re-run 'tog'",
            record.dependencies,
            candidate.objects,
            names(&record.cache),
            names(&candidate.cache),
        )));
    }
    Ok(())
}

/// `has_with_activity` runs crashed-publication cleanup on whatever the id
/// names under `objects/`, so an id that is not one plain entry name must be
/// refused before anything is looked up or removed.
#[cfg(test)]
mod object_id_guard_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn a_lookup_refuses_ids_that_are_not_one_entry_name() {
        let temp = TempDir::named("object-id-guard");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(temp.0.join(sub)).unwrap();
        }
        fs::write(temp.0.join("objects/victim"), "keep").unwrap();
        fs::write(temp.0.join("keep"), "keep").unwrap();
        let store = Store::for_test(temp.0.clone());
        let activity = store.activity(ActivityMode::Shared).unwrap();
        for id in ["", ".", "..", "a/b", "../keep", "/etc", "a\0b"] {
            let error = store.has_with_activity(&activity, id).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
            assert_eq!(error.to_string(), format!("malformed object id {id:?}"));
            assert!(temp.0.join("objects/victim").is_file(), "id {id:?}");
            assert!(temp.0.join("keep").is_file(), "id {id:?}");
        }
        // A plain name that is not a strict object id is still a lookup:
        // stores written before `sanitize` split dot runs hold ids with `..`.
        for id in ["absent", "0000000000000000000000000000000000000000-a..b-1"] {
            assert!(
                !store.has_with_activity(&activity, id).unwrap(),
                "id {id:?}"
            );
        }
        crate::kernel::objmeta::register_test_kinds();
        let identity = Identity {
            kind: "test".into(),
            name: "a..b".into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let id = identity.object_id();
        assert!(is_object_id(&id) && id.ends_with("-a.-b-1"), "{id}");
        let staged = store.stage_with_activity(&activity).unwrap();
        fs::write(staged.join("payload"), "a..b").unwrap();
        store
            .commit_with_activity_and_deps(&activity, &identity, &staged, &[], &ObjectDeps::new())
            .unwrap();
        assert!(store.has_with_activity(&activity, &id).unwrap());
        assert_eq!(
            fs::read_to_string(store.object_path(&id).join("payload")).unwrap(),
            "a..b"
        );
    }
}

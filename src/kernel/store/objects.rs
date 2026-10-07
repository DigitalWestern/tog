//! Object write, commit, and immutability (kernel store): staging, the
//! publish lock, cache hits, and the dependency evidence a commit records.

use super::*;
use crate::kernel::policy::Exception;

/// The most bytes an object's metadata record may hold. A record is its
/// identity, its exceptions and its dependency ids, so a legitimate one is
/// kilobytes: 16 MiB is room for some 250,000 dependencies. The cap keeps
/// a planted or runaway record from exhausting memory while it is parsed.
/// It is separate from the 1 MiB cap on fact records (`RECORD_CAP`).
pub const META_CAP: u64 = 16 << 20;

/// An object record's JSON, read through at most `META_CAP + 1` bytes.
///
/// The outer error is a failed read, or a record over the cap (kind
/// `FileTooLarge`): neither is evidence that a publication crashed, so a
/// caller deciding completeness keeps the object. The inner error is a
/// record that is not JSON, which a crash can leave.
pub(crate) fn read_meta_json(
    file: &fs::File,
) -> io::Result<Result<serde_json::Value, serde_json::Error>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    file.take(META_CAP + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > META_CAP {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("object metadata is over the {META_CAP}-byte cap; it was left in place"),
        ));
    }
    Ok(serde_json::from_slice(&bytes))
}

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
        // The whole record check, the one a cache hit and the sweep make:
        // a record whose identity, schema or evidence this tog cannot read
        // is not a complete object.
        crate::kernel::objmeta::read_store_record(self, id).map_err(|error| {
            io::Error::new(error.kind(), format!("object reference {id}: {error}"))
        })?;
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

    /// `meta/`, held from the store root without a symlink: a caller that
    /// lists it and opens each record with [`open_object_meta_at`] reads
    /// one directory's names and records even if `meta/` is renamed or
    /// replaced meanwhile. `None` when `meta/` does not exist.
    pub(crate) fn open_object_meta_dir(&self) -> io::Result<Option<fs::File>> {
        let dir = self.open_namespace(&["meta"])?;
        held_meta_failpoint();
        Ok(dir)
    }

    /// Open `meta/<id>.json` from held descriptors: the store root, then
    /// `meta/`, then the record, none of them through a symlink.
    pub(crate) fn open_object_meta(&self, id: &str) -> io::Result<MetaFile> {
        let Some(dir) = self.open_namespace(&["meta"])? else {
            return Ok(MetaFile::Missing);
        };
        open_object_meta_at(&dir, id)
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
        let record_is_whole = || {
            if publication_failpoint("before-completeness-open").is_err() {
                return true;
            }
            match self.open_object_meta(id) {
                // An oversized record is refused by its readers, never
                // taken for a crash and swept.
                Ok(MetaFile::File(file)) => match read_meta_json(&file) {
                    Ok(Ok(value)) => value.is_object(),
                    Ok(Err(_)) => false,
                    Err(_) => true,
                },
                Ok(MetaFile::Missing | MetaFile::NotRegular) => false,
                Err(_) => true,
            }
        };
        Some(
            !md.file_type().is_symlink()
                && md.is_dir()
                && md.permissions().mode() & 0o222 == 0
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
        let file = match self.open_object_meta(id)? {
            MetaFile::File(file) => file,
            MetaFile::Missing => return Ok(None),
            MetaFile::NotRegular => {
                return Err(invalid(format!(
                    "store object {id} metadata is not a regular file"
                )))
            }
        };
        let value = read_meta_json(&file)
            .map_err(|error| io::Error::new(error.kind(), format!("store object {id}: {error}")))?
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

    /// Test-only, like `has`: [`Store::commit_with_activity_and_deps`]
    /// under a shared lease of its own.
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

    /// Atomically move a staged dir into the store under `identity`, write
    /// metadata, and mark the tree read-only. Returns the object path and the
    /// exceptions stored with the object. If the object already exists the
    /// staged dir is discarded (cache hit).
    ///
    /// This is the only publication entry point, and its dependency and
    /// cache evidence is explicit. There is deliberately no convenience form
    /// that infers a dependency set from the identity map: an inferred set
    /// is a guess, and this stamps what it is given as `evidence:
    /// "explicit"`. Certifying a guess as explicit is exactly the failure
    /// this boundary prevents.
    pub fn commit_with_activity_and_deps(
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
        // The record is built, and its size checked, before anything is
        // published: one over the cap is refused while the object is still
        // only staged, never left visible without a record.
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
        let meta = serde_json::to_vec_pretty(&meta)?;
        if meta.len() as u64 > META_CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "object {id} metadata would be {} bytes, over the {META_CAP}-byte cap; \
                     nothing was published",
                    meta.len()
                ),
            ));
        }
        // Every link in a directory a closure can put on PATH (the root's
        // own entries, `bin`, any `bin` or `.bin` below) stays inside the
        // object or a declared object, checked while the object is still
        // only staged. Objects published before the check existed are not
        // swept: the check runs at publication only.
        super::bin_links::check_bin_links(self, &id, staged, &dest, &deps.objects)?;
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
        let metadata = open_real_directory(&self.root.join("meta"), "meta")?;
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
        validate_cached_dependency_evidence(self, id, deps)?;
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

    /// The exceptions `id`'s record carries, from the record objmeta's
    /// checked reader parsed whole.
    pub fn exceptions(&self, id: &str) -> io::Result<Vec<Exception>> {
        Ok(crate::kernel::objmeta::read_store_record(self, id)?.exceptions)
    }
}

fn publish_completion(
    store: &Store,
    metadata: &fs::File,
    name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let tmp = open_real_directory(&store.root.join("tmp"), "tmp")?;
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
            io::Write::write_all(&mut file, bytes)?;
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

/// `<id>.json` under `dir`, a held `meta/` ([`Store::open_object_meta_dir`]),
/// opened without following a symlink.
pub(crate) fn open_object_meta_at(dir: &fs::File, id: &str) -> io::Result<MetaFile> {
    open_meta_file_at(dir.as_raw_fd(), format!("{id}.json").as_bytes())
}

#[cfg(test)]
thread_local! {
    /// A test's hook right after a reader has taken its held `meta/`
    /// descriptor, so `meta/` can be swapped before anything is listed.
    pub(crate) static HELD_META_FAILPOINT: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn held_meta_failpoint() {
    HELD_META_FAILPOINT.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(not(test))]
pub(crate) fn held_meta_failpoint() {}

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
    store: &Store,
    id: &str,
    candidate: &ObjectDeps,
) -> io::Result<()> {
    let record = crate::kernel::objmeta::read_store_record(store, id)?;
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

/// Every reader of `meta/<id>.json` opens it through `open_object_meta`:
/// a FIFO planted as the record is refused without blocking, and a
/// symlinked `meta/` does not redirect the read.
#[cfg(test)]
mod meta_reader_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn published(store: &Store) -> String {
        crate::kernel::objmeta::register_test_kinds();
        let identity = Identity {
            kind: "test".into(),
            name: "meta-reader".into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        store.publish_bare_with(&identity, |_| {})
    }

    /// Each reader's answer, on a thread so a reader that blocks on a FIFO
    /// fails the test instead of hanging it.
    fn readers(store: &Store, id: &str) -> [Result<(), String>; 5] {
        let (store, id) = (store.clone(), id.to_owned());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let activity = store.activity(ActivityMode::Shared).unwrap();
            let text = |result: io::Result<()>| result.map_err(|error| error.to_string());
            let _ = sender.send([
                text(store.published_identity(&id).and_then(|found| {
                    found
                        .map(drop)
                        .ok_or_else(|| io::Error::other("no identity"))
                })),
                text(store.validate_object_complete(&activity, &id)),
                match store.is_complete(&id) {
                    Some(true) => Ok(()),
                    other => Err(format!("is_complete: {other:?}")),
                },
                text(store.exceptions(&id).map(drop)),
                text(validate_cached_dependency_evidence(
                    &store,
                    &id,
                    &ObjectDeps::new(),
                )),
            ]);
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a metadata reader blocked")
    }

    /// `len` bytes of one JSON object: braces around spaces.
    fn padded_record(len: u64) -> Vec<u8> {
        let mut bytes = vec![b' '; len as usize];
        bytes[0] = b'{';
        bytes[len as usize - 1] = b'}';
        bytes
    }

    #[test]
    fn a_record_at_the_cap_is_read_and_one_byte_past_it_is_refused() {
        let temp = TempDir::named("meta-cap-read");
        let path = temp.0.join("record.json");
        fs::write(&path, padded_record(META_CAP)).unwrap();
        let value = read_meta_json(&fs::File::open(&path).unwrap()).unwrap();
        assert!(value.unwrap().is_object());
        fs::write(&path, padded_record(META_CAP + 1)).unwrap();
        let error = read_meta_json(&fs::File::open(&path).unwrap()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
    }

    /// An oversized record is refused by every reader, and the completeness
    /// probe keeps its object: it is not a crashed publication to sweep.
    #[test]
    fn an_oversized_record_is_refused_and_its_object_kept() {
        let temp = TempDir::named("meta-cap-probe");
        Store::open_at(&temp.0).unwrap();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let id = published(&store);
        let record = store.root.join("meta").join(format!("{id}.json"));
        fs::remove_file(&record).unwrap();
        fs::write(&record, padded_record(META_CAP + 1)).unwrap();
        let [identity, complete, is_complete, exceptions, evidence] = readers(&store, &id);
        assert_eq!(is_complete, Ok(()));
        for answer in [identity, complete, exceptions, evidence] {
            assert!(answer.unwrap_err().contains("byte cap"));
        }
        let activity = store.activity(ActivityMode::Shared).unwrap();
        assert!(store.has_with_activity(&activity, &id).unwrap());
        assert!(store.object_path(&id).is_dir());
        assert_eq!(fs::metadata(&record).unwrap().len(), META_CAP + 1);
    }

    /// A record that would be over the cap is refused while its object is
    /// only staged: nothing appears under `objects/` or `meta/`.
    #[test]
    fn an_oversized_record_is_never_published() {
        let temp = TempDir::named("meta-cap-write");
        Store::open_at(&temp.0).unwrap();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        crate::kernel::objmeta::register_test_kinds();
        let identity = Identity {
            kind: "test".into(),
            name: "meta-cap-write".into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let staged = store.stage_with_activity(&activity).unwrap();
        let exception = Exception {
            kind: "test".into(),
            subject: "subject".into(),
            detail: "x".repeat(META_CAP as usize),
        };
        let error = store
            .commit_with_activity_and_deps(
                &activity,
                &identity,
                &staged,
                &[exception],
                &ObjectDeps::new(),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("nothing was published"));
        let id = identity.object_id();
        assert!(!store.object_path(&id).exists());
        assert!(!store.root.join("meta").join(format!("{id}.json")).exists());
    }

    /// A `bin/` link to the host refuses the publication before anything
    /// lands: no object directory, no record.
    #[test]
    fn a_bin_link_out_of_the_object_publishes_nothing() {
        let temp = TempDir::named("bin-link-out");
        Store::open_at(&temp.0).unwrap();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        crate::kernel::objmeta::register_test_kinds();
        let identity = Identity {
            kind: "test".into(),
            name: "bin-link-out".into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let staged = store.stage_with_activity(&activity).unwrap();
        let host = store.root.join("host-tool");
        fs::write(&host, "x").unwrap();
        fs::create_dir(staged.join("bin")).unwrap();
        std::os::unix::fs::symlink(&host, staged.join("bin/x")).unwrap();
        let error = store
            .commit_with_activity_and_deps(&activity, &identity, &staged, &[], &ObjectDeps::new())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        let text = error.to_string();
        assert!(text.contains("bin/x leads to"), "{text}");
        assert!(text.contains("host-tool"), "{text}");
        assert!(text.contains("nothing was published"), "{text}");
        let id = identity.object_id();
        assert!(!store.object_path(&id).exists());
        assert!(!store.root.join("meta").join(format!("{id}.json")).exists());
        assert!(!store.has_with_activity(&activity, &id).unwrap());
    }

    #[test]
    fn every_metadata_reader_refuses_a_fifo_and_a_symlinked_meta() {
        let temp = TempDir::named("meta-readers");
        Store::open_at(&temp.0).unwrap();
        let store = Store {
            root: temp.0.canonicalize().unwrap(),
        };
        let id = published(&store);
        for (index, answer) in readers(&store, &id).iter().enumerate() {
            assert_eq!(answer, &Ok(()), "reader {index}");
        }

        // A FIFO where the record belongs.
        let record = store.root.join("meta").join(format!("{id}.json"));
        let saved = fs::read(&record).unwrap();
        fs::remove_file(&record).unwrap();
        let name = std::ffi::CString::new(record.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path in a directory this test owns.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let [identity, complete, is_complete, exceptions, evidence] = readers(&store, &id);
        for answer in [identity, complete, exceptions, evidence] {
            assert!(answer.unwrap_err().contains("not a regular file"));
        }
        assert_eq!(is_complete.unwrap_err(), "is_complete: Some(false)");
        fs::remove_file(&record).unwrap();

        // `meta/` itself a symlink to a directory holding a good record.
        let elsewhere = store.root.join("meta-elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join(format!("{id}.json")), saved).unwrap();
        fs::remove_dir(store.root.join("meta")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.root.join("meta")).unwrap();
        let [identity, complete, is_complete, exceptions, evidence] = readers(&store, &id);
        for answer in [identity, complete, exceptions, evidence] {
            assert!(answer.unwrap_err().contains("is not a real directory"));
        }
        // A `meta/` that cannot be opened is no evidence of a crashed
        // publication, so the lookup does not clear the object over it.
        assert_eq!(is_complete, Ok(()));
    }
}

/// Every reader that admits an object by its record (a closure or root
/// reference, the exceptions a cache hit compares) runs objmeta's whole
/// record check, not a lighter one of its own.
#[cfg(test)]
mod record_check_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn store_with_object(label: &str) -> (TempDir, Store, String) {
        let temp = TempDir::named(label);
        Store::open_at(&temp.0).unwrap();
        let store = Store::for_test(temp.0.canonicalize().unwrap());
        let id = store.publish_bare_test("record-check", "1");
        (temp, store, id)
    }

    fn rewrite(store: &Store, id: &str, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = store.root.join("meta").join(format!("{id}.json"));
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(&mut record);
        fs::write(&path, record.to_string()).unwrap();
    }

    #[test]
    fn a_reference_to_a_record_the_parser_refuses_is_refused_without_mutation() {
        type Edit = fn(&mut serde_json::Value);
        let cases: [(&str, Edit, &str); 5] = [
            (
                "identity",
                |record| record["identity"]["version"] = "2".into(),
                "identity hashes to a different object id",
            ),
            (
                "schema",
                |record| record["schema"] = "object-meta/3".into(),
                "unknown metadata schema object-meta/3",
            ),
            (
                "evidence",
                |record| {
                    record.as_object_mut().unwrap().remove("evidence");
                },
                "has no evidence marker",
            ),
            (
                "dependencies",
                |record| record["dependencies"] = serde_json::json!(["not an id"]),
                "malformed or duplicate dependency",
            ),
            (
                "exceptions",
                |record| record["exceptions"] = serde_json::json!([{"kind": 1}]),
                "has malformed exceptions",
            ),
        ];
        for (label, edit, expected) in cases {
            let (_temp, store, id) = store_with_object(&format!("record-check-{label}"));
            rewrite(&store, &id, edit);
            let record = store.root.join("meta").join(format!("{id}.json"));
            let bytes = fs::read(&record).unwrap();
            let object_mtime = fs::metadata(store.object_path(&id))
                .unwrap()
                .modified()
                .unwrap();
            let activity = store.activity(ActivityMode::Shared).unwrap();

            let error = store
                .validate_object_complete(&activity, &id)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
            // `Store::exceptions` reads the record through the same parser.
            // (`ClosureRefs::object_id` admits closure and root references
            // through `validate_object_complete` above; it lives in the
            // comforter layer, so this kernel test does not call it.)
            let error = store.exceptions(&id).unwrap_err().to_string();
            assert!(error.contains(expected), "{label}: {error}");

            assert_eq!(fs::read(&record).unwrap(), bytes, "{label}: record changed");
            assert_eq!(
                fs::metadata(store.object_path(&id))
                    .unwrap()
                    .modified()
                    .unwrap(),
                object_mtime,
                "{label}: the read refreshed the object"
            );
            assert!(store.object_path(&id).is_dir(), "{label}: object removed");
        }
    }

    #[test]
    fn exceptions_come_from_the_checked_record() {
        let (_temp, store, id) = store_with_object("record-check-exceptions");
        assert_eq!(store.exceptions(&id).unwrap(), Vec::new());

        // A producer that allowed nothing may write no field at all.
        rewrite(&store, &id, |record| {
            record.as_object_mut().unwrap().remove("exceptions");
        });
        assert_eq!(store.exceptions(&id).unwrap(), Vec::new());

        let exception = Exception {
            kind: "weak-integrity".into(),
            subject: "left-pad".into(),
            detail: "sha1 only".into(),
        };
        rewrite(&store, &id, |record| {
            record["exceptions"] = serde_json::json!([exception]);
        });
        assert_eq!(store.exceptions(&id).unwrap(), vec![exception.clone()]);
        let record = crate::kernel::objmeta::read_store_record(&store, &id).unwrap();
        assert_eq!(record.exceptions, vec![exception]);
    }
}

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
    pub(super) fn is_complete(&self, id: &str) -> Option<bool> {
        let md = fs::symlink_metadata(self.object_path(id)).ok()?;
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(self.root.join("meta").join(format!("{id}.json")));
        Some(
            !md.file_type().is_symlink()
                && md.is_dir()
                && md.permissions().mode() & 0o222 == 0
                && meta
                    .as_ref()
                    .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file()),
        )
    }

    /// The identity a fully published object records, read without a
    /// lease, a publish lock, an mtime touch, or the crashed-publication
    /// cleanup `has` performs: `Ok(None)` when this store holds no complete
    /// object `id`. The metadata must describe `id` (its identity hashes to
    /// it), or this is an error. For read-only callers that only need to
    /// know what an object is; a concurrent sweep can make the answer
    /// `None`, never a wrong identity.
    pub fn published_identity(&self, id: &str) -> io::Result<Option<Identity>> {
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed object id {id:?}"),
            ));
        }
        if self.is_complete(id) != Some(true) {
            return Ok(None);
        }
        let path = self.root.join("meta").join(format!("{id}.json"));
        match crate::kernel::objmeta::read_record_at(&path) {
            Ok(record) => Ok(Some(record.identity)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// An object is valid only when fully published: directory present,
    /// root read-only, and metadata written (in that commit order). A
    /// crash mid-publication leaves an invalid object, which is swept and
    /// rebuilt instead of trusted.
    pub fn has(&self, id: &str) -> io::Result<bool> {
        let activity = self.activity(ActivityMode::Shared)?;
        self.has_with_activity(&activity, id)
    }

    /// Activity-aware form used by long-lived operations. The compatibility
    /// `has` wrapper above is intentionally fallible too, so a lock failure
    /// cannot be mistaken for a cache miss.
    pub fn has_with_activity(&self, activity: &StoreActivity, id: &str) -> io::Result<bool> {
        self.require_activity(activity, "store object lookup")?;
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
                let objects = open_store_directory(&self.root.join("objects"), "objects")?;
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
    /// an inferred set is a guess, and `commit_internal_impl` stamps what it
    /// is given as `evidence: "explicit"`. Certifying a guess as explicit is
    /// exactly the failure this explicit-evidence boundary prevents.
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
        self.commit_internal_impl(activity, identity, staged, exceptions, deps, true)
    }

    pub(super) fn commit_internal_impl(
        &self,
        activity: &StoreActivity,
        identity: &Identity,
        staged: &Path,
        exceptions: &[Exception],
        deps: &ObjectDeps,
        explicit: bool,
    ) -> io::Result<(PathBuf, Vec<Exception>)> {
        self.require_activity(activity, "store publication")?;
        validate_object_deps(self, activity, deps)?;
        // Grammar drift check. Each `KindAdapter` row
        // claims to describe the inputs its producer writes *today*, but the
        // rows were only ever read by the legacy-migration path, so a
        // producer could drift away from its row and nothing would notice
        // until a migration ran on a store nobody could rebuild. This is the
        // one publication choke point, and the identity is final here, so the
        // row is checked against the real thing.
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
                 KindAdapter row in src/kernel/objmeta.rs (or the tailor's objects.rs) disagree; \
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
        // Under the lock, anything at dest is a crashed leftover (a live
        // publication can't be mid-window, and a complete object returned
        // above): sweep it so the rename lands.
        let objects = open_store_directory(&self.root.join("objects"), "objects")?;
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
        let meta = if explicit {
            serde_json::json!({
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
            })
        } else {
            serde_json::json!({
                "id": id,
                "identity": identity,
                "created": unix_secs(),
                "exceptions": exceptions,
                "refs": object_refs(identity),
            })
        };
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

    /// Replace one metadata record atomically. Callers must already own the
    /// exclusive maintenance/activity lease; keeping that requirement at the
    /// call site prevents a migration from upgrading a long-lived shared job.
    pub(crate) fn replace_metadata(&self, id: &str, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = self.root.join("tmp").join(format!(
            "meta-migrate-{id}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        let destination = self.root.join("meta").join(format!("{id}.json"));
        if let Err(error) = fs::rename(&tmp, &destination) {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        fs::File::open(self.root.join("meta"))?.sync_all()
    }
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

pub(super) fn is_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn object_refs(identity: &Identity) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for value in identity.inputs.values() {
        if let Some(id) = object_id_token(value) {
            refs.insert(id);
        }
    }
    refs.into_iter().collect()
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
/// explicit metadata. A legacy record is deliberately left alone: a cache hit
/// cannot upgrade or certify it, and the maintenance adapter owns that
/// transition. An explicit record with different evidence is unsafe to reuse
/// because the winner's transitive closure would no longer be the candidate's
/// closure.
pub(super) fn validate_cached_dependency_evidence(
    root: &Path,
    id: &str,
    candidate: &ObjectDeps,
) -> io::Result<()> {
    let path = root.join("meta").join(format!("{id}.json"));
    let bytes = fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse object metadata {}: {error}", path.display()),
        )
    })?;
    if let Some(schema_value) = value.get("schema") {
        let schema = schema_value.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has an invalid schema"),
            )
        })?;
        if schema != "object-meta/2" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object {id} has unknown metadata schema {schema}"),
            ));
        }
    } else {
        return Ok(());
    }
    let mut objects = BTreeSet::new();
    for value in value
        .get("dependencies")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has no explicit dependencies"),
            )
        })?
    {
        let value = value.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has a non-string dependency"),
            )
        })?;
        if !is_object_id(value) || !objects.insert(value.to_string()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has malformed or duplicate dependency"),
            ));
        }
    }
    let mut cache = BTreeSet::new();
    for value in value
        .get("cache_digests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has no explicit cache digests"),
            )
        })?
    {
        let object = value.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has a malformed cache digest"),
            )
        })?;
        let algo = object
            .get("algo")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object metadata {id} cache digest has no algorithm"),
                )
            })?;
        let hex = object
            .get("hex")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("object metadata {id} cache digest has no hex"),
                )
            })?;
        let digest = match algo {
            "sha1" => crate::kernel::digest::Digest::sha1(hex),
            "sha256" => crate::kernel::digest::Digest::sha256(hex),
            "sha512" => crate::kernel::digest::Digest::sha512(hex),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} uses unsupported cache algorithm {other}"),
            )),
        }?;
        if !cache.insert(format!("{}:{}", digest.algo(), digest.hex())) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object metadata {id} has duplicate cache digest"),
            ));
        }
    }
    let candidate_cache: BTreeSet<_> = candidate
        .cache
        .iter()
        .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
        .collect();
    let winner_cache = cache;
    if objects != candidate.objects || winner_cache != candidate_cache {
        return Err(io::Error::other(format!(
            "object {id} was published concurrently with different dependency evidence; winner objects: {objects:?}, staged objects: {:?}, winner cache: {winner_cache:?}, staged cache: {candidate_cache:?}; re-run 'tog'",
            candidate.objects
        )));
    }
    Ok(())
}

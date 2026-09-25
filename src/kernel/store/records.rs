//! Store-owned records: small JSON facts tog establishes itself and keeps
//! across syncs, under `<root>/records/<kind>/<name>.json`. A tailor uses
//! them to answer a question it would otherwise ask the network again, such
//! as the digest a registry serves for an immutable package coordinate.
//!
//! The store, unlike a project, is written only by tog: a repository cannot
//! ship a record, so what a record says is what an earlier tog run checked.
//! Every access resolves from held descriptors with `O_NOFOLLOW`, and a
//! write is a private file in `tmp/` renamed into place, so a reader sees
//! either the old record or the new one, never a torn write or a planted
//! symlink's target.

use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read as _, Write as _};

const RECORDS: &str = "records";

/// A record kind is one path component tog names itself: lowercase ASCII,
/// digits and `-`.
fn check_kind(kind: &str) -> io::Result<()> {
    let valid = !kind.is_empty()
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("store record kind {kind:?} is not a plain name"),
        ))
    }
}

/// The file a key lives in: the SHA-256 of the key, so any key (a JSON
/// array of coordinates, a project path) maps to one safe file name.
fn file_name(key: &str) -> String {
    format!("{}.json", hex::encode(Sha256::digest(key.as_bytes())))
}

impl Store {
    /// Open `relative` under the store root one component at a time, never
    /// following a symlink. `None` when a component is absent.
    fn open_namespace(&self, relative: &[&str]) -> io::Result<Option<fs::File>> {
        let mut dir = open_store_directory(&self.root, "store root")?;
        for component in relative {
            match open_file_at(
                dir.as_raw_fd(),
                component.as_bytes(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            ) {
                Ok(next) => dir = next,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR)
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "store namespace {} is not a real directory",
                            self.root.join(relative.join("/")).display()
                        ),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Some(dir))
    }

    /// The value recorded under `key` in `kind`, or `None` when there is
    /// none. A record that does not parse, or that names another key, is
    /// `None` too: the caller then does the work the record would have
    /// saved and writes a fresh one. A symlink anywhere on the way is an
    /// error, never followed.
    pub fn read_record(&self, kind: &str, key: &str) -> io::Result<Option<serde_json::Value>> {
        check_kind(kind)?;
        let Some(dir) = self.open_namespace(&[RECORDS, kind])? else {
            return Ok(None);
        };
        let name = file_name(key);
        let file = match open_file_at(
            dir.as_raw_fd(),
            name.as_bytes(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "store record {} is a symlink",
                        self.root.join(RECORDS).join(kind).join(&name).display()
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        (&file).take(1 << 20).read_to_end(&mut bytes)?;
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return Ok(None);
        };
        if record["key"].as_str() != Some(key) {
            return Ok(None);
        }
        Ok(Some(record["value"].clone()))
    }

    /// Record `value` under `key` in `kind`, replacing any earlier record.
    /// The bytes go to a new private file under `tmp/` first and are renamed
    /// into the kind's directory, so a crash leaves the old record or none.
    pub fn write_record(
        &self,
        activity: &StoreActivity,
        kind: &str,
        key: &str,
        value: &serde_json::Value,
    ) -> io::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        self.require_activity(activity, "store record write")?;
        check_kind(kind)?;
        self.ensure_namespace(&Path::new(RECORDS).join(kind))?;
        let dir = self.open_namespace(&[RECORDS, kind])?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "store record namespace vanished")
        })?;
        let tmp = self
            .open_namespace(&["tmp"])?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "store tmp is missing"))?;
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({"key": key, "value": value}))?;
        let tmp_name = loop {
            let candidate = format!(
                "record-{}-{}-{}",
                std::process::id(),
                nanos(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            );
            match open_file_at(
                tmp.as_raw_fd(),
                candidate.as_bytes(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            ) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
                        unlink_at(tmp.as_raw_fd(), candidate.as_bytes());
                        return Err(error);
                    }
                    break candidate;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        let name = file_name(key);
        if let Err(error) = rename_between(
            tmp.as_raw_fd(),
            tmp_name.as_bytes(),
            dir.as_raw_fd(),
            name.as_bytes(),
        ) {
            unlink_at(tmp.as_raw_fd(), tmp_name.as_bytes());
            return Err(error);
        }
        fsync_directory(dir.as_raw_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;

    fn store() -> (Store, crate::kernel::testutil::TempDir) {
        let dir = crate::kernel::testutil::TempDir::named("records");
        let root = dir.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let root = root.canonicalize().unwrap();
        (Store { root }, dir)
    }

    #[test]
    fn a_record_reads_back_by_its_key_and_is_replaced_whole() {
        let (store, _dir) = store();
        let activity = store.activity(ActivityMode::Shared).unwrap();
        assert_eq!(store.read_record("demo", "a").unwrap(), None);
        store
            .write_record(&activity, "demo", "a", &serde_json::json!({"n": 1}))
            .unwrap();
        store
            .write_record(&activity, "demo", "b", &serde_json::json!({"n": 2}))
            .unwrap();
        store
            .write_record(&activity, "demo", "a", &serde_json::json!({"n": 3}))
            .unwrap();
        assert_eq!(
            store.read_record("demo", "a").unwrap(),
            Some(serde_json::json!({"n": 3}))
        );
        assert_eq!(
            store.read_record("demo", "b").unwrap(),
            Some(serde_json::json!({"n": 2}))
        );
        assert_eq!(store.read_record("other", "a").unwrap(), None);
        // Nothing is left behind in tmp.
        assert_eq!(fs::read_dir(store.root.join("tmp")).unwrap().count(), 0);
    }

    #[test]
    fn a_record_moved_onto_another_key_is_no_record() {
        let (store, _dir) = store();
        let activity = store.activity(ActivityMode::Shared).unwrap();
        store
            .write_record(&activity, "demo", "a", &serde_json::json!("x"))
            .unwrap();
        let dir = store.root.join(RECORDS).join("demo");
        fs::rename(dir.join(file_name("a")), dir.join(file_name("b"))).unwrap();
        assert_eq!(store.read_record("demo", "b").unwrap(), None);
        fs::write(dir.join(file_name("c")), b"not json").unwrap();
        assert_eq!(store.read_record("demo", "c").unwrap(), None);
    }

    #[test]
    fn a_symlinked_namespace_or_record_is_refused() {
        let (store, dir) = store();
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let elsewhere = dir.0.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(store.root.join(RECORDS)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store.root.join(RECORDS).join("demo")).unwrap();
        assert!(store.read_record("demo", "a").is_err());
        assert!(store
            .write_record(&activity, "demo", "a", &serde_json::json!(1))
            .is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);

        fs::remove_file(store.root.join(RECORDS).join("demo")).unwrap();
        fs::create_dir_all(store.root.join(RECORDS).join("demo")).unwrap();
        let target = elsewhere.join("target.json");
        fs::write(&target, br#"{"key": "a", "value": 1}"#).unwrap();
        std::os::unix::fs::symlink(
            &target,
            store.root.join(RECORDS).join("demo").join(file_name("a")),
        )
        .unwrap();
        let error = store.read_record("demo", "a").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(check_kind("../x").is_err() && check_kind("").is_err());
    }
}

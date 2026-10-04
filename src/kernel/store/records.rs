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

/// The largest record `read_record` accepts: records are small facts.
const RECORD_CAP: u64 = 1 << 20;

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
        // Read one byte past the cap so a longer file is refused whole, not
        // parsed from a prefix that happens to be complete JSON.
        let mut bytes = Vec::new();
        (&file).take(RECORD_CAP + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > RECORD_CAP {
            return Ok(None);
        }
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

    pub(super) fn store() -> (Store, crate::kernel::testutil::TempDir) {
        let dir = crate::kernel::testutil::TempDir::named("records");
        let root = dir.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let root = root.canonicalize().unwrap();
        (Store::for_test(root), dir)
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
        let error = store.read_record("demo", "a").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error.to_string().contains("is not a real directory"),
            "{error}"
        );
        let error = store
            .write_record(&activity, "demo", "a", &serde_json::json!(1))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error.to_string().contains("is not a real directory"),
            "{error}"
        );
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
        assert!(error.to_string().contains("is a symlink"), "{error}");
        for kind in ["../x", ""] {
            let error = check_kind(kind).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
            assert!(error.to_string().contains("is not a plain name"), "{error}");
        }
    }
}

/// The read side trusts nothing it finds under `records/`: a FIFO, a
/// directory or an oversized file where a record belongs is no record, and
/// the write side takes only this store's own lease.
#[cfg(test)]
mod record_guard_tests {
    use super::tests::store;
    use super::*;
    use crate::kernel::activity::ActivityMode;

    fn record_path(store: &Store, kind: &str, key: &str) -> PathBuf {
        store.root.join(RECORDS).join(kind).join(file_name(key))
    }

    /// Opening a FIFO without `O_NONBLOCK` would wait for a writer forever.
    /// The read runs on its own thread so a regression fails here instead
    /// of hanging the suite.
    #[test]
    fn a_fifo_where_a_record_belongs_is_no_record_and_does_not_block() {
        let (store, _dir) = store();
        let path = record_path(&store, "demo", "a");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (send, receive) = std::sync::mpsc::channel();
        let reader = store.clone();
        std::thread::spawn(move || {
            let _ = send.send(reader.read_record("demo", "a").map_err(|e| e.to_string()));
        });
        let answer = receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("reading a FIFO record blocked");
        assert_eq!(answer, Ok(None));
    }

    #[test]
    fn a_directory_where_a_record_belongs_is_no_record() {
        let (store, _dir) = store();
        fs::create_dir_all(record_path(&store, "demo", "a")).unwrap();
        assert_eq!(store.read_record("demo", "a").unwrap(), None);
    }

    /// A record of exactly 1 MiB reads back; one byte more is no record,
    /// even when its first MiB is complete JSON.
    #[test]
    fn a_record_over_one_mib_is_no_record() {
        let (store, _dir) = store();
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let envelope = |value: &str| {
            serde_json::to_vec_pretty(&serde_json::json!({"key": "a", "value": value})).unwrap()
        };
        let overhead = envelope("").len();
        let path = record_path(&store, "demo", "a");
        store
            .write_record(&activity, "demo", "a", &serde_json::json!("seed"))
            .unwrap();

        let fits = "x".repeat((1 << 20) - overhead);
        fs::write(&path, envelope(&fits)).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 1 << 20);
        assert_eq!(
            store.read_record("demo", "a").unwrap(),
            Some(serde_json::json!(fits))
        );

        let over = "x".repeat((1 << 20) - overhead + 1);
        fs::write(&path, envelope(&over)).unwrap();
        assert_eq!(store.read_record("demo", "a").unwrap(), None);

        // A complete record in the first MiB does not excuse what follows.
        for tail in [&b" "[..], b"\n", b"garbage"] {
            let mut bytes = envelope(&fits);
            bytes.extend_from_slice(tail);
            fs::write(&path, bytes).unwrap();
            assert_eq!(store.read_record("demo", "a").unwrap(), None, "{tail:?}");
        }
    }

    #[test]
    fn a_write_under_another_stores_lease_is_refused() {
        let (store, _dir) = store();
        let (other, _other_dir) = super::tests::store();
        let foreign = other.activity(ActivityMode::Shared).unwrap();
        let error = store
            .write_record(&foreign, "demo", "a", &serde_json::json!(1))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other, "{error}");
        assert_eq!(
            error.to_string(),
            format!(
                "store record write requires an active shared lease for store {}; \
                 the supplied lease belongs to {}",
                store.root.display(),
                other.root.display()
            )
        );
        assert!(!store.root.join(RECORDS).exists());
        drop(foreign);
        let own = store.activity(ActivityMode::Shared).unwrap();
        store
            .write_record(&own, "demo", "a", &serde_json::json!(1))
            .unwrap();
        assert_eq!(
            store.read_record("demo", "a").unwrap(),
            Some(serde_json::json!(1))
        );
    }

    #[test]
    fn a_kind_that_is_not_a_plain_name_is_refused() {
        let (store, _dir) = store();
        let activity = store.activity(ActivityMode::Shared).unwrap();
        for kind in ["", "Demo", "a/b", "..", ".", "a_b", "a.b"] {
            let expected = format!("store record kind {kind:?} is not a plain name");
            let error = store.read_record(kind, "a").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
            assert_eq!(error.to_string(), expected);
            let error = store
                .write_record(&activity, kind, "a", &serde_json::json!(1))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
            assert_eq!(error.to_string(), expected);
        }
        assert!(!store.root.join(RECORDS).exists());
        store
            .write_record(&activity, "demo-2", "a", &serde_json::json!(1))
            .unwrap();
    }
}

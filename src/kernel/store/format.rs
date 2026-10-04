//! The store format marker (kernel store): `<root>/format`, one line naming
//! the layout every record in this store is written in.
//!
//! The marker is what lets a tog tell a store it can read from one it
//! cannot. It is written before the first namespace of a new store is
//! created, so a store that has namespaces and no marker was written by a
//! tog from before the marker existed. This tog has no reader for those
//! records, and neither that store nor one with a marker it does not know
//! is opened: `tog gc --reset` empties it, or the directory is moved aside.

use super::*;
use std::io::{Read as _, Write as _};

/// The marker's name under the store root.
pub const FORMAT_FILE: &str = "format";

/// The format this tog reads and writes.
pub const STORE_FORMAT: u32 = 1;

/// The word before the number on the marker's one line.
const FORMAT_WORD: &str = "tog-store";

/// Every namespace `Store::open` creates under the root. The first
/// component of each is also how a store with no marker is told from a
/// directory nothing has been stored in yet.
pub(super) const NAMESPACES: &[&str] = &[
    "objects",
    "meta",
    "cache/sha1",
    "cache/sha256",
    "cache/sha512",
    "tmp",
    "roots",
    "forests",
    "backups",
    "root-locks",
    "run-homes",
    "records",
];

/// What `tog gc --reset` removes from the root: everything written in the
/// store's record formats, and everything that only means something next to
/// those records. `tmp` is emptied rather than removed (it holds the
/// publication lock), and the marker is rewritten.
///
/// Whatever is not listed stays: `cache/` (verified downloads, each named
/// by its own digest, which is what the store is rebuilt from), `backups/`
/// (directories that were the user's before tog moved them aside),
/// `run-homes/`, the planners' download caches, the first-run notices, the
/// lock files, and anything tog does not recognise.
pub(crate) const RESET_REMOVES: &[&str] = &[
    "objects",
    "meta",
    "roots",
    "records",
    "resolve",
    "forests",
    "root-locks",
    // What a tog from before the marker left when it could not finish its
    // metadata maintenance. Nothing reads it now.
    "maintenance-deferred",
];

/// What the marker says about a store directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFormat {
    /// The marker names the format this tog reads.
    Current,
    /// No marker and no store namespace: nothing has been stored here, and
    /// `Store::open` creates the store with the marker.
    Uninitialized,
    /// Store namespaces with no marker: written before the marker existed.
    PreEpoch,
    /// A well-formed marker naming a later format than this tog knows.
    Newer(u32),
    /// A marker this tog cannot read as any format; the text says what is
    /// there instead.
    Unknown(String),
}

impl StoreFormat {
    /// The marker line for the current format, newline included.
    pub fn current_line() -> String {
        format!("{FORMAT_WORD} {STORE_FORMAT}\n")
    }

    /// Whether this tog may open the store.
    pub fn usable(&self) -> bool {
        matches!(self, StoreFormat::Current | StoreFormat::Uninitialized)
    }

    /// Why the store at `root` is not opened, with the way out, or `None`
    /// for a store this tog may open. A sentence with no leading capital
    /// and no final period, so it reads after `tog: error: ` and inside a
    /// `doctor` row alike.
    pub fn refusal(&self, root: &Path) -> Option<String> {
        let root = root.display();
        let reset = "empty it with `tog gc --reset` (downloads are kept, and the next `tog` in \
                     each project rebuilds what it needs), or move the directory aside";
        match self {
            StoreFormat::Current | StoreFormat::Uninitialized => None,
            StoreFormat::PreEpoch => Some(format!(
                "the store at {root} has no format marker: an older tog wrote it, and this tog \
                 does not read its records; {reset}"
            )),
            StoreFormat::Newer(format) => Some(format!(
                "the store at {root} is format {FORMAT_WORD} {format} and this tog reads \
                 {FORMAT_WORD} {STORE_FORMAT}: a newer tog wrote it. Update tog with `tog update \
                 --self`, or point TOG_STORE at another directory; to give the store to this \
                 older tog instead, {reset}"
            )),
            StoreFormat::Unknown(found) => Some(format!(
                "the store at {root} has a format marker this tog does not know ({found}; \
                 expected \"{FORMAT_WORD} {STORE_FORMAT}\"): the marker is damaged, or the \
                 directory is not a tog store; {reset}"
            )),
        }
    }

    /// The one command a `fix:` line names for a refused store: update for
    /// a store a newer tog wrote, reset for the rest.
    pub fn fix(&self) -> &'static str {
        match self {
            StoreFormat::Newer(_) => "tog update --self",
            _ => "tog gc --reset",
        }
    }

    /// `refusal` as the error a command returns.
    pub(super) fn refuse(&self, root: &Path) -> io::Result<()> {
        match self.refusal(root) {
            Some(message) => Err(io::Error::new(io::ErrorKind::InvalidData, message)),
            None => Ok(()),
        }
    }
}

/// Read what the marker says about `root`, changing nothing. `root` must
/// exist.
pub fn probe(root: &Path) -> io::Result<StoreFormat> {
    let path = root.join(FORMAT_FILE);
    // Open first, then check what was opened, and never follow a symlink:
    // the marker decides whether every record under this root is trusted.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path);
    let file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return if has_namespace(root)? {
                Ok(StoreFormat::PreEpoch)
            } else {
                Ok(StoreFormat::Uninitialized)
            };
        }
        Err(error) => {
            // A symlink (ELOOP) or a socket (ENXIO, EOPNOTSUPP) fails to
            // open. Either is a marker nobody wrote, not an I/O failure.
            return match fs::symlink_metadata(&path) {
                Ok(stat) if !stat.is_file() => Ok(StoreFormat::Unknown(
                    "the marker is not a regular file".into(),
                )),
                _ => Err(error),
            };
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(StoreFormat::Unknown(
            "the marker is not a regular file".into(),
        ));
    }
    // The marker is one short line. Anything longer is not a marker, and is
    // not read to its end to find that out.
    let mut bytes = Vec::new();
    file.take(65).read_to_end(&mut bytes)?;
    Ok(parse(&bytes))
}

/// What a marker holding `bytes` says.
fn parse(bytes: &[u8]) -> StoreFormat {
    let unknown = || {
        let shown: String = String::from_utf8_lossy(bytes)
            .chars()
            .take(40)
            .flat_map(char::escape_default)
            .collect();
        StoreFormat::Unknown(format!("it reads \"{shown}\""))
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return unknown();
    };
    let line = text.strip_suffix('\n').unwrap_or(text);
    let Some(number) = line
        .strip_prefix(FORMAT_WORD)
        .and_then(|rest| rest.strip_prefix(' '))
    else {
        return unknown();
    };
    // Digits only, and no leading zero: one spelling per format.
    if number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
    {
        return unknown();
    }
    match number.parse::<u32>() {
        Ok(STORE_FORMAT) => StoreFormat::Current,
        Ok(format) if format > STORE_FORMAT => StoreFormat::Newer(format),
        _ => unknown(),
    }
}

/// Whether anything is where one of the store's namespaces would be.
fn has_namespace(root: &Path) -> io::Result<bool> {
    for namespace in NAMESPACES {
        let first = namespace.split('/').next().expect("a namespace has a name");
        match fs::symlink_metadata(root.join(first)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// Write the current marker into `root`. The bytes go to a temporary beside
/// the marker and are renamed into place, so a crash leaves either no
/// marker or a whole one, and two togs creating the same store at once both
/// rename the same line.
pub(super) fn write_marker(root: &Path) -> io::Result<()> {
    let root_dir = open_store_directory(root, "store root")?;
    let tmp = format!(".{FORMAT_FILE}.{}.{}.tmp", std::process::id(), nanos());
    let mut file = open_file_at(
        root_dir.as_raw_fd(),
        tmp.as_bytes(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o644,
    )?;
    let result = (|| {
        file.write_all(StoreFormat::current_line().as_bytes())?;
        file.sync_all()?;
        rename_at(root_dir.as_raw_fd(), tmp.as_bytes(), FORMAT_FILE.as_bytes())?;
        fsync_directory(root_dir.as_raw_fd())
    })();
    if result.is_err() {
        unlink_at(root_dir.as_raw_fd(), tmp.as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn marker(temp: &TempDir, bytes: &[u8]) -> StoreFormat {
        fs::write(temp.0.join(FORMAT_FILE), bytes).unwrap();
        probe(&temp.0).unwrap()
    }

    #[test]
    fn the_marker_is_one_line_naming_the_current_format() {
        assert_eq!(StoreFormat::current_line(), "tog-store 1\n");
        let temp = TempDir::new();
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Uninitialized);
        write_marker(&temp.0).unwrap();
        assert_eq!(
            fs::read(temp.0.join(FORMAT_FILE)).unwrap(),
            b"tog-store 1\n"
        );
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Current);
        // Nothing but the marker is left behind.
        let names: Vec<_> = fs::read_dir(&temp.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(FORMAT_FILE)]);
    }

    #[test]
    fn a_namespace_without_a_marker_is_a_pre_epoch_store() {
        for namespace in ["objects", "meta", "cache", "roots", "records"] {
            let temp = TempDir::new();
            fs::create_dir(temp.0.join(namespace)).unwrap();
            assert_eq!(
                probe(&temp.0).unwrap(),
                StoreFormat::PreEpoch,
                "{namespace}"
            );
        }
        // A directory holding only files tog never names is not a store yet.
        let temp = TempDir::new();
        fs::write(temp.0.join("notes.txt"), b"x").unwrap();
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Uninitialized);
    }

    #[test]
    fn a_newer_marker_and_an_unreadable_one_are_told_apart() {
        let temp = TempDir::new();
        assert_eq!(marker(&temp, b"tog-store 1\n"), StoreFormat::Current);
        assert_eq!(marker(&temp, b"tog-store 1"), StoreFormat::Current);
        assert_eq!(marker(&temp, b"tog-store 2\n"), StoreFormat::Newer(2));
        assert_eq!(marker(&temp, b"tog-store 17\n"), StoreFormat::Newer(17));
        for bytes in [
            &b""[..],
            b"\n",
            b"tog-store\n",
            b"tog-store 0\n",
            b"tog-store 01\n",
            b"tog-store +1\n",
            b"tog-store 1 \n",
            b"tog-store 1\n\n",
            b" tog-store 1\n",
            b"tog-store  1\n",
            b"tog-store one\n",
            b"tog-store 99999999999999999999\n",
            b"blanket-store 1\n",
            b"\xff\xfe",
        ] {
            assert!(
                matches!(marker(&temp, bytes), StoreFormat::Unknown(_)),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        // A marker far longer than a marker is not read to its end.
        assert!(matches!(
            marker(&temp, &b"tog-store 1".repeat(1000)),
            StoreFormat::Unknown(_)
        ));
    }

    #[test]
    fn a_marker_that_is_not_a_regular_file_is_unknown_and_never_followed() {
        let temp = TempDir::new();
        let elsewhere = temp.0.join("elsewhere");
        fs::write(&elsewhere, StoreFormat::current_line()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join(FORMAT_FILE)).unwrap();
        assert!(matches!(probe(&temp.0).unwrap(), StoreFormat::Unknown(_)));
        fs::remove_file(temp.0.join(FORMAT_FILE)).unwrap();
        fs::create_dir(temp.0.join(FORMAT_FILE)).unwrap();
        assert!(matches!(probe(&temp.0).unwrap(), StoreFormat::Unknown(_)));
    }

    #[test]
    fn every_refusal_names_the_store_and_both_ways_out() {
        let root = Path::new("/somewhere/store");
        assert_eq!(StoreFormat::Current.refusal(root), None);
        assert_eq!(StoreFormat::Uninitialized.refusal(root), None);
        for format in [
            StoreFormat::PreEpoch,
            StoreFormat::Newer(2),
            StoreFormat::Unknown("it reads \"x\"".into()),
        ] {
            assert!(!format.usable());
            let message = format.refusal(root).unwrap();
            assert!(message.contains("/somewhere/store"), "{message}");
            assert!(message.contains("`tog gc --reset`"), "{message}");
            assert!(message.contains("move the directory aside"), "{message}");
        }
        let newer = StoreFormat::Newer(2).refusal(root).unwrap();
        assert!(newer.contains("a newer tog wrote it"), "{newer}");
        assert!(newer.contains("tog-store 2"), "{newer}");
        assert!(newer.contains("`tog update --self`"), "{newer}");
        let old = StoreFormat::PreEpoch.refusal(root).unwrap();
        assert!(old.contains("an older tog wrote it"), "{old}");
    }
}

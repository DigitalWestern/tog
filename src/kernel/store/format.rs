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
    /// A marker that is there and cannot be opened or read (its mode, an
    /// I/O error); the text is the system's reason. Nothing in the store is
    /// trusted without it, and `tog gc --reset` replaces it without reading
    /// it.
    Unreadable(String),
}

/// The error a refused store is reported with: the reason as its message,
/// and the one command that is the way out as a separate `fix`, so the
/// top level prints it on its own `fix:` line. The command acts on the
/// store that was refused: see `StoreFormat::fix_for`.
#[derive(Debug)]
pub struct Refused {
    pub message: String,
    pub fix: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refused {}

/// The `fix:` command of an error that is a store refusal, if it is one.
pub fn refusal_fix(error: &io::Error) -> Option<&str> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Refused>())
        .map(|refused| refused.fix.as_str())
}

/// `command` with `TOG_STORE` set to exactly `root`, as a POSIX shell
/// reads it. The command empties a store, so the path is never
/// approximated: it is spelled from its bytes, in the plainest of three
/// forms that is exact.
///
/// - Every byte one no shell reads specially: the path as it is.
/// - Text with no control character: single quotes, each single quote
///   inside written as `'\''`.
/// - Anything else (bytes that are not UTF-8, which a `String` cannot
///   carry, or control characters, which a terminal may not show): the
///   bytes as octal escapes in a `printf` format. `$(...)` drops trailing
///   newlines, so a path that ends in one is printed with a `.` after it
///   that the command takes off again.
fn with_store(command: &str, root: &Path) -> String {
    let bytes = root.as_os_str().as_bytes();
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"/._-+:@,".contains(&byte);
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.is_empty() && bytes.iter().all(|&byte| plain(byte) || byte == b'%') => {
            format!("TOG_STORE={text} {command}")
        }
        Ok(text) if !text.chars().any(char::is_control) => {
            format!("TOG_STORE='{}' {command}", text.replace('\'', "'\\''"))
        }
        _ => {
            let mut format = String::new();
            for &byte in bytes {
                match byte {
                    byte if plain(byte) => format.push(char::from(byte)),
                    b'%' => format.push_str("%%"),
                    byte => format.push_str(&format!("\\{byte:03o}")),
                }
            }
            if bytes.last() == Some(&b'\n') {
                format!("(p=\"$(printf '{format}.')\"; TOG_STORE=\"${{p%.}}\" {command})")
            } else {
                format!("TOG_STORE=\"$(printf '{format}')\" {command}")
            }
        }
    }
}

/// `command`, made to act on the store at `root`. A bare `tog` acts on the
/// store `selected`: for any other store the command carries its own
/// `TOG_STORE=`, with `root` absolute, so pasting it never empties the
/// wrong one. `selected` is `None` when what a bare `tog` selects cannot be
/// relied on: see `StoreFormat::fix_for`.
fn command_on(command: &str, root: &Path, selected: Option<&Path>) -> String {
    let root = root
        .canonicalize()
        .or_else(|_| std::path::absolute(root))
        .unwrap_or_else(|_| root.to_path_buf());
    match selected {
        Some(selected) if root == selected => command.to_string(),
        _ => with_store(command, &root),
    }
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

    /// Why the store at `root` is not opened, or `None` for a store this
    /// tog may open. A sentence with no leading capital and no final
    /// period, so it reads after `tog: error: ` and inside a `doctor` row
    /// alike. The command that is the way out is `fix`, printed on its own
    /// line, so the prose names what it does and not how it is spelled.
    pub fn refusal(&self, root: &Path) -> Option<String> {
        let root = root.display();
        let reset = "Emptying it keeps its downloads, and the next `tog` in each project \
                     rebuilds what it needs (or move the directory aside)";
        match self {
            StoreFormat::Current | StoreFormat::Uninitialized => None,
            StoreFormat::PreEpoch => Some(format!(
                "the store at {root} has no format marker: an older tog wrote it, and this tog \
                 does not read its records. {reset}"
            )),
            StoreFormat::Newer(format) => Some(format!(
                "the store at {root} is format {FORMAT_WORD} {format} and this tog reads \
                 {FORMAT_WORD} {STORE_FORMAT}: a newer tog wrote it. Update this tog, or point \
                 TOG_STORE at another directory"
            )),
            StoreFormat::Unknown(found) => Some(format!(
                "the store at {root} has a format marker this tog does not know ({found}; \
                 expected \"{FORMAT_WORD} {STORE_FORMAT}\"): the marker is damaged, or the \
                 directory is not a tog store. {reset}"
            )),
            StoreFormat::Unreadable(why) => Some(format!(
                "the store at {root} has a format marker this tog cannot read ({why}), so \
                 nothing in it is trusted. {reset}"
            )),
        }
    }

    /// The one command that is the way out of a refused store: update for
    /// a store a newer tog wrote, reset for the rest. This is the command
    /// for the store a bare `tog` selects; `fix_for` is the one to print.
    pub fn fix(&self) -> &'static str {
        match self {
            StoreFormat::Newer(_) => "tog update --self",
            _ => "tog gc --reset",
        }
    }

    /// `fix` as a `fix:` line prints it for the store at `root`. A reset
    /// empties whichever store the command selects, and the line is pasted
    /// into a shell, not into this process. So the bare command is printed
    /// only when it selects `root` wherever it is typed: `TOG_STORE` is
    /// unset or absolute, and names `root`. In every other case the
    /// command names `root` itself, absolute:
    /// `TOG_STORE=<root> tog gc --reset`. That covers a store other than
    /// the configured one (an x environment's own store), and a relative
    /// `TOG_STORE`, which `tog -C <dir>` resolves from `<dir>` and the
    /// shell that pastes the fix resolves from somewhere else. Updating tog
    /// is the same command for every store.
    pub fn fix_for(&self, root: &Path) -> String {
        match self {
            StoreFormat::Newer(_) => self.fix().to_string(),
            _ => {
                let configured = Store::configured_root().0;
                let selected = configured
                    .is_absolute()
                    .then(|| configured.canonicalize().ok())
                    .flatten();
                command_on(self.fix(), root, selected.as_deref())
            }
        }
    }

    /// `refusal` as the error a command returns.
    pub(super) fn refuse(&self, root: &Path) -> io::Result<()> {
        match self.refusal(root) {
            Some(message) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                Refused {
                    message,
                    fix: self.fix_for(root),
                },
            )),
            None => Ok(()),
        }
    }
}

/// Hold the store root against a concurrent creation or reset: an
/// exclusive `flock` on the root directory itself, released when the
/// returned handle is dropped. `Store::open` holds it while it reads the
/// marker and creates what is missing, and `gc::reset` holds it from the
/// moment it removes the marker until the new one is published, so an open
/// never initialises namespaces inside a store that is being emptied and
/// never judges one that is half created.
///
/// The wait is never silent: when another tog holds the root, one line
/// says so before this one blocks. A filesystem with no `flock` on a
/// directory cannot hold a store, and the error says that.
pub(crate) fn lock_root(root: &Path) -> io::Result<fs::File> {
    let directory = open_real_directory(root, "store root")?;
    let unsupported = |error: io::Error| {
        io::Error::new(
            error.kind(),
            format!(
                "lock the store directory {}: {error}. tog takes a file lock (flock) on \
                 the store directory before it creates or empties a store, so the store has to \
                 be on a filesystem that supports one; point TOG_STORE at a directory on a \
                 local disk",
                root.display()
            ),
        )
    };
    match directory.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            crate::kernel::ui::note(&format!(
                "waiting for another tog that is creating or emptying the store at {}",
                root.display()
            ));
            directory.lock().map_err(unsupported)?;
        }
        Err(fs::TryLockError::Error(error)) => return Err(unsupported(error)),
    }
    Ok(directory)
}

/// Read what the marker says about `root`, changing nothing. `root` must
/// exist.
pub fn probe(root: &Path) -> io::Result<StoreFormat> {
    if let Some(format) = read_marker(root)? {
        return Ok(format);
    }
    if !has_namespace(root)? {
        return Ok(StoreFormat::Uninitialized);
    }
    // A tog creating this store publishes the marker before its first
    // namespace. So namespaces seen after a missing marker may be a store
    // being created right now, whose marker has landed since: read it again
    // before calling the store unmarked.
    Ok(read_marker(root)?.unwrap_or(StoreFormat::PreEpoch))
}

/// What the marker file says, or `None` when there is no marker file.
fn read_marker(root: &Path) -> io::Result<Option<StoreFormat>> {
    let path = root.join(FORMAT_FILE);
    // Open first, then check what was opened, and never follow a symlink:
    // the marker decides whether every record under this root is trusted.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path);
    let file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            // A symlink (ELOOP) or a socket (ENXIO, EOPNOTSUPP) fails to
            // open: a marker nobody wrote. A regular file that fails to
            // open is a marker that cannot be read, which is an answer
            // about the store and not a reason to say nothing at all.
            return match fs::symlink_metadata(&path) {
                Ok(stat) if !stat.is_file() => Ok(Some(StoreFormat::Unknown(
                    "the marker is not a regular file".into(),
                ))),
                Ok(_) => Ok(Some(StoreFormat::Unreadable(error.to_string()))),
                Err(gone) if gone.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(error),
            };
        }
    };
    if !file.metadata()?.is_file() {
        return Ok(Some(StoreFormat::Unknown(
            "the marker is not a regular file".into(),
        )));
    }
    // The marker is one short line. Anything longer is not a marker, and is
    // not read to its end to find that out.
    let mut bytes = Vec::new();
    match file.take(65).read_to_end(&mut bytes) {
        Ok(_) => Ok(Some(parse(&bytes))),
        Err(error) => Ok(Some(StoreFormat::Unreadable(error.to_string()))),
    }
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
    let root_dir = open_real_directory(root, "store root")?;
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
            StoreFormat::Unknown("it reads \"x\"".into()),
            StoreFormat::Unreadable("Permission denied (os error 13)".into()),
        ] {
            assert!(!format.usable());
            let message = format.refusal(root).unwrap();
            assert!(message.contains("/somewhere/store"), "{message}");
            assert!(message.contains("move the directory aside"), "{message}");
            // The command is the fix line's, never spelled in the prose.
            assert!(!message.contains("--reset"), "{message}");
            assert_eq!(format.fix(), "tog gc --reset");
            let error = format.refuse(root).unwrap_err();
            assert_eq!(error.to_string(), message);
            // `/somewhere/store` is not the store a bare `tog` selects.
            assert_eq!(
                refusal_fix(&error),
                Some("TOG_STORE=/somewhere/store tog gc --reset")
            );
        }
        let newer = StoreFormat::Newer(2);
        assert!(!newer.usable());
        assert_eq!(newer.fix(), "tog update --self");
        // Updating tog is one command whatever store asked for it.
        assert_eq!(newer.fix_for(root), "tog update --self");
        let newer = newer.refusal(root).unwrap();
        assert!(newer.contains("a newer tog wrote it"), "{newer}");
        assert!(newer.contains("tog-store 2"), "{newer}");
        let old = StoreFormat::PreEpoch.refusal(root).unwrap();
        assert!(old.contains("an older tog wrote it"), "{old}");
        let unreadable = StoreFormat::Unreadable("Permission denied".into())
            .refusal(root)
            .unwrap();
        assert!(unreadable.contains("Permission denied"), "{unreadable}");
        assert_eq!(refusal_fix(&io::Error::other("something else")), None);
    }

    /// A fix acts on the store that was refused: bare for the store a bare
    /// `tog` selects, and naming any other store in a form a shell reads
    /// back as exactly that path.
    #[test]
    fn a_fix_names_a_store_the_bare_command_would_not_select() {
        let reset = "tog gc --reset";
        let a = Path::new("/home/me/.tog/store");
        assert_eq!(command_on(reset, a, Some(a)), reset);
        assert_eq!(
            command_on(reset, a, Some(Path::new("/elsewhere"))),
            "TOG_STORE=/home/me/.tog/store tog gc --reset"
        );
        assert_eq!(
            command_on(reset, a, None),
            "TOG_STORE=/home/me/.tog/store tog gc --reset"
        );
        // A selected store named through a symlink is the same store.
        let temp = TempDir::named("store-format-fix");
        let real = temp.0.join("real");
        fs::create_dir(&real).unwrap();
        let real = real.canonicalize().unwrap();
        let link = temp.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(command_on(reset, &link, Some(&real)), reset);
        assert_eq!(command_on(reset, &real, Some(&real)), reset);

        // Every spelling is exact: a shell that runs the command gives the
        // child the path's own bytes, whatever they are.
        let cases: [(&[u8], &str); 12] = [
            (
                b"/plain/path-1.0_x+y:z@h%,",
                "TOG_STORE=/plain/path-1.0_x+y:z@h%, env",
            ),
            (b"/with space/store", "TOG_STORE='/with space/store' env"),
            (b"/it's/store", "TOG_STORE='/it'\\''s/store' env"),
            (
                b"/a$b`c\"d\\e;f&g|h*i?j(k)l<m>n~o#p!q",
                "TOG_STORE='/a$b`c\"d\\e;f&g|h*i?j(k)l<m>n~o#p!q' env",
            ),
            (
                "/caf\u{e9}/\u{fffd}".as_bytes(),
                "TOG_STORE='/caf\u{e9}/\u{fffd}' env",
            ),
            (b"/-dash/~tilde", "TOG_STORE='/-dash/~tilde' env"),
            // Not UTF-8: no `String` holds this path, so its bytes are
            // spelled out.
            (b"/st\xff", "TOG_STORE=\"$(printf '/st\\377')\" env"),
            (
                b"/a b\xfe'%\\c",
                "TOG_STORE=\"$(printf '/a\\040b\\376\\047%%\\134c')\" env",
            ),
            // Control characters, a newline inside among them.
            (
                b"/new\nline\x1b[0m",
                "TOG_STORE=\"$(printf '/new\\012line\\033\\1330m')\" env",
            ),
            // Trailing newlines, which `$(...)` would drop.
            (
                b"/ends\n\n",
                "(p=\"$(printf '/ends\\012\\012.')\"; TOG_STORE=\"${p%.}\" env)",
            ),
            (
                b"/x\xff\n",
                "(p=\"$(printf '/x\\377\\012.')\"; TOG_STORE=\"${p%.}\" env)",
            ),
            (b"/9\x01", "TOG_STORE=\"$(printf '/9\\001')\" env"),
        ];
        for (bytes, expected) in cases {
            use std::os::unix::ffi::OsStrExt as _;
            let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
            assert_eq!(with_store("env", path), expected, "{path:?}");
            // A shell that runs it hands the command a TOG_STORE of
            // exactly these bytes.
            let command = with_store("sh -c 'printf %s \"$TOG_STORE\"'", path);
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&command)
                .env_remove("TOG_STORE")
                .output()
                .unwrap();
            assert!(out.status.success(), "{command}");
            assert_eq!(out.stdout, bytes, "{command}");
        }
    }

    /// The bare command is printed only for a store a bare `tog` selects
    /// from any directory. A relative selection is not that: the fix names
    /// the refused store, absolute.
    #[test]
    fn a_fix_for_a_store_selected_relatively_names_it_absolutely() {
        let temp = TempDir::named("store-format-relative");
        let root = temp.0.join("store");
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        // What `fix_for` passes when TOG_STORE is relative: no selection.
        assert_eq!(
            command_on("tog gc --reset", &root, None),
            format!("TOG_STORE={} tog gc --reset", root.display())
        );
        // A root that reaches here relative is printed absolute.
        let relative = Path::new("no-such-store-here");
        let command = command_on("tog gc --reset", relative, None);
        let absolute = std::path::absolute(relative).unwrap();
        assert_eq!(
            command,
            format!("TOG_STORE={} tog gc --reset", absolute.display())
        );
    }

    /// Many togs creating one store at once: every one of them ends with
    /// the store open, and none takes the other's namespaces for a store
    /// written before the marker existed.
    #[test]
    fn concurrent_creation_never_reads_as_a_store_without_a_marker() {
        for round in 0..20 {
            let temp = TempDir::named(&format!("store-format-race-{round}"));
            let root = temp.0.join("store");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
            let threads: Vec<_> = (0..16)
                .map(|index| {
                    let root = root.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        // Half create the store, half only look at it.
                        if index % 2 == 0 {
                            Store::open_at(&root).map(|_| StoreFormat::Current)
                        } else {
                            Ok(Store::probe_at(&root)?
                                .map_or(StoreFormat::Uninitialized, |(_, format)| format))
                        }
                    })
                })
                .collect();
            for thread in threads {
                let seen = thread.join().unwrap().unwrap();
                assert!(seen.usable(), "round {round}: {seen:?}");
            }
            assert_eq!(probe(&root).unwrap(), StoreFormat::Current);
        }
    }

    /// The window the re-read closes, held open by hand: the marker is
    /// absent on the first read and published, with its namespaces, by the
    /// time the namespaces are looked for.
    #[test]
    fn a_marker_published_between_the_two_reads_is_honoured() {
        let temp = TempDir::named("store-format-reread");
        assert_eq!(read_marker(&temp.0).unwrap(), None);
        write_marker(&temp.0).unwrap();
        fs::create_dir(temp.0.join("objects")).unwrap();
        assert!(has_namespace(&temp.0).unwrap());
        assert_eq!(read_marker(&temp.0).unwrap(), Some(StoreFormat::Current));
        assert_eq!(probe(&temp.0).unwrap(), StoreFormat::Current);
    }
}

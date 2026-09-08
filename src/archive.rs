//! Pre-materialization archive validation and delegated extraction
//! (PLAN.md WP2, ordered PR 2 of the toolchain-lock design).
//!
//! Every pinned toolchain arrives as a tarball that the platform's tar
//! unpacks into a store stage. tar's own defences differ by implementation
//! and version, so this module does not trust them: it lists every entry
//! first and refuses the archive as a whole before a single byte is written
//! when any entry is an absolute name, contains a `..` component, is a hard
//! link or a special file, or is a symlink whose target is not lexically
//! contained in the destination after `--strip-components`. Only a listing
//! that passes completely is extracted, and the delegated tar runs with
//! `TAR_OPTIONS` unset so the user's environment cannot add flags.
//!
//! The listing is `tar -tv`, parsed per platform: GNU tar on Linux prints
//! five columns before the name, libarchive's bsdtar on macOS prints eight.
//! Any line that does not parse is a refusal, never a skip, so a name that
//! manages to break a line (both tars escape control characters, but this
//! module does not rely on it) fails closed. Containment is decided on the
//! escaped text tar prints, which is sound because neither tar ever escapes
//! `/` or `.`, the only characters the rules look for.

use std::io;
use std::path::Path;
use std::process::Command;

use crate::platform::Platform;

/// One archive member as tar lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// The member name exactly as listed (directories keep their trailing
    /// `/`), before any `--strip-components`.
    pub name: String,
    /// Symlink target or hard-link target, when the kind has one.
    pub link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    HardLink,
    /// Block/character device, FIFO, socket, or any type letter this module
    /// does not know; always refused.
    Special(char),
}

/// How the archive is compressed; passed explicitly so the delegated tar is
/// invoked with the same flag the call site used before this module existed
/// (a byte-identical extraction is part of the object-identity contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
}

impl Compression {
    fn flag(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gzip => "z",
            Compression::Xz => "J",
        }
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn tar_command(platform: Platform) -> Command {
    let _ = platform;
    let mut command = Command::new("/usr/bin/tar");
    // The user's environment must not add extraction flags.
    command.env_remove("TAR_OPTIONS");
    command
}

/// List `archive` with the platform's tar and parse every entry.
pub fn list(
    platform: Platform,
    archive: &Path,
    compression: Compression,
) -> io::Result<Vec<Entry>> {
    let output = tar_command(platform)
        .arg(format!("-tv{}f", compression.flag()))
        .arg(archive)
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("list {}: {e}", archive.display())))?;
    if !output.status.success() {
        return Err(err(format!(
            "list {} failed: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let listing = String::from_utf8(output.stdout).map_err(|_| {
        err(format!(
            "list {}: tar printed a name that is not UTF-8",
            archive.display()
        ))
    })?;
    parse_listing(platform, &listing)
}

/// Number of whitespace-separated columns before the name field in `tar -tv`
/// output: GNU tar prints mode, owner/group, size, date, time; bsdtar prints
/// mode, links, owner, group, size, month, day, time-or-year.
fn leading_columns(platform: Platform) -> usize {
    if platform.is_macos() {
        8
    } else {
        5
    }
}

/// Parse `tar -tv` output. Every line must parse; an unparseable line refuses
/// the whole listing.
pub fn parse_listing(platform: Platform, listing: &str) -> io::Result<Vec<Entry>> {
    let leading = leading_columns(platform);
    let mut entries = Vec::new();
    for line in listing.split('\n') {
        if line.is_empty() {
            continue;
        }
        entries.push(parse_line(line, leading)?);
    }
    Ok(entries)
}

fn parse_line(line: &str, leading: usize) -> io::Result<Entry> {
    let mode: Vec<char> = line.chars().take(10).collect();
    if mode.len() != 10
        || !mode[1..]
            .iter()
            .all(|c| matches!(c, 'r' | 'w' | 'x' | 's' | 'S' | 't' | 'T' | 'l' | 'L' | '-'))
    {
        return Err(err(format!(
            "archive listing line does not parse: {line:?}"
        )));
    }
    let kind = match mode[0] {
        '-' => EntryKind::File,
        'd' => EntryKind::Dir,
        'l' => EntryKind::Symlink,
        'h' => EntryKind::HardLink,
        other => EntryKind::Special(other),
    };
    let Some(field) = name_field(line, leading) else {
        return Err(err(format!(
            "archive listing line does not parse: {line:?}"
        )));
    };
    if field.is_empty() || !graphic(field) {
        return Err(err(format!(
            "archive listing line has an empty or unprintable name: {line:?}"
        )));
    }
    let (name, link) = match kind {
        EntryKind::Symlink => split_once_exactly(field, " -> ").ok_or_else(|| {
            err(format!(
                "archive symlink entry is ambiguous (expected exactly one \" -> \"): {field:?}"
            ))
        })?,
        EntryKind::HardLink => split_once_exactly(field, " link to ").ok_or_else(|| {
            err(format!(
                "archive hard-link entry is ambiguous (expected exactly one \" link to \"): {field:?}"
            ))
        })?,
        _ => (field, None),
    };
    if name.is_empty() {
        return Err(err(format!("archive entry has an empty name: {line:?}")));
    }
    Ok(Entry {
        kind,
        name: name.to_string(),
        link: link.map(str::to_string),
    })
}

/// Skip `leading` whitespace-separated columns; the remainder after the one
/// separating space is the name field, verbatim (a name may begin with, end
/// with, or contain spaces).
fn name_field(line: &str, leading: usize) -> Option<&str> {
    let mut rest = line;
    for _ in 0..leading {
        rest = rest.trim_start_matches(' ');
        let end = rest.find(' ')?;
        rest = &rest[end..];
    }
    rest.strip_prefix(' ')
}

/// Split on `separator` only when it occurs exactly once; two occurrences
/// mean either the name or the target contains the separator and the line
/// cannot be attributed, so the caller refuses.
fn split_once_exactly<'a>(field: &'a str, separator: &str) -> Option<(&'a str, Option<&'a str>)> {
    if field.matches(separator).count() != 1 {
        return None;
    }
    let (name, target) = field.split_once(separator)?;
    if target.is_empty() {
        return None;
    }
    Some((name, Some(target)))
}

fn graphic(text: &str) -> bool {
    !text.chars().any(|c| c.is_control())
}

/// Refuse anything that could write or point outside the destination once
/// the first `strip` path components are removed, the way tar's
/// `--strip-components` removes them. Entries with `strip` or fewer
/// components are skipped by tar and therefore ignored here, except that
/// their kind is still checked: a hard link or a device is refused wherever
/// it sits.
pub fn validate(entries: &[Entry], strip: usize) -> io::Result<()> {
    for entry in entries {
        match entry.kind {
            EntryKind::HardLink => {
                return Err(err(format!(
                    "archive entry {:?} is a hard link (to {:?}); hard links are refused",
                    entry.name,
                    entry.link.as_deref().unwrap_or("")
                )))
            }
            EntryKind::Special(kind) => {
                return Err(err(format!(
                    "archive entry {:?} is a special file (type {kind:?}); only files, directories, and contained symlinks are accepted",
                    entry.name
                )))
            }
            EntryKind::File | EntryKind::Dir | EntryKind::Symlink => {}
        }
        let components = contained_components(&entry.name)
            .map_err(|reason| err(format!("archive entry {:?}: {reason}", entry.name)))?;
        if components.len() <= strip {
            continue;
        }
        let stripped = &components[strip..];
        if entry.kind == EntryKind::Symlink {
            let target = entry.link.as_deref().unwrap_or("");
            symlink_contained(stripped, target).map_err(|reason| {
                err(format!(
                    "archive symlink {:?} -> {:?}: {reason}",
                    entry.name, target
                ))
            })?;
        }
    }
    Ok(())
}

/// The name's path components, refusing absolute names, `..`, and empty
/// components other than a directory's trailing slash. `.` is kept: tar
/// counts it for `--strip-components`.
fn contained_components(name: &str) -> Result<Vec<&str>, String> {
    if name.starts_with('/') {
        return Err("absolute member name".into());
    }
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    if trimmed.is_empty() {
        return Err("empty member name".into());
    }
    let mut components = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" => return Err("empty path component".into()),
            ".." => return Err("`..` path component".into()),
            other => components.push(other),
        }
    }
    Ok(components)
}

/// A symlink at `stripped` (its components after `--strip-components`) is
/// contained when its target, resolved lexically from the link's directory,
/// never leaves the destination root. Every symlink is checked on its own,
/// so a chain of contained links stays contained.
fn symlink_contained(stripped: &[&str], target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("empty symlink target".into());
    }
    if target.starts_with('/') {
        return Err("absolute symlink target".into());
    }
    let mut depth = stripped.len().saturating_sub(1);
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if depth == 0 {
                    return Err("symlink target escapes the destination".into());
                }
                depth -= 1;
            }
            _ => depth += 1,
        }
    }
    Ok(())
}

/// List, validate, and extract `archive` into `destination`, returning the
/// validated listing. Nothing is written when validation fails.
pub fn extract(
    platform: Platform,
    archive: &Path,
    destination: &Path,
    strip: usize,
    compression: Compression,
) -> io::Result<Vec<Entry>> {
    let entries = list(platform, archive, compression)?;
    extract_validated(platform, archive, destination, strip, compression, &entries)?;
    Ok(entries)
}

/// Extract an archive whose listing the caller already obtained from `list`
/// (so it could check layout first). The listing is validated again here;
/// the check is cheap and this is the function that writes.
pub fn extract_validated(
    platform: Platform,
    archive: &Path,
    destination: &Path,
    strip: usize,
    compression: Compression,
    entries: &[Entry],
) -> io::Result<()> {
    validate(entries, strip)?;
    let status = tar_command(platform)
        .arg(format!("-x{}f", compression.flag()))
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .arg("--strip-components")
        .arg(strip.to_string())
        .status()
        .map_err(|e| io::Error::new(e.kind(), format!("extract {}: {e}", archive.display())))?;
    if !status.success() {
        return Err(err(format!(
            "extract {} into {} failed ({status})",
            archive.display(),
            destination.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const GNU: Platform = Platform::X86_64UnknownLinuxGnu;
    const BSD: Platform = Platform::Aarch64AppleDarwin;

    fn entry(kind: EntryKind, name: &str, link: Option<&str>) -> Entry {
        Entry {
            kind,
            name: name.to_string(),
            link: link.map(str::to_string),
        }
    }

    // ---- listing parsers ---------------------------------------------------

    /// Real GNU tar 1.35 `-tv` output for a crafted archive (names with
    /// spaces and an arrow, a hard link, a symlink, a device, a FIFO, an
    /// absolute name, a `..` name, and an escaped newline).
    const GNU_LISTING: &str = "\
drwxr-xr-x 0/0               0 1969-12-31 19:00 pkg/
drwxr-xr-x 0/0               0 1969-12-31 19:00 pkg/a b/
-rw-r--r-- 0/0               1 1969-12-31 19:00 pkg/a b/file with -> arrow
hrw-r--r-- 0/0               0 1969-12-31 19:00 pkg/hard link to pkg/a b/file with -> arrow
lrwxrwxrwx root/root         0 2023-12-31 19:00 python/bin/2to3 -> 2to3-3.12
crw-r--r-- 0/0             1,3 1969-12-31 19:00 pkg/dev
prw-r--r-- 0/0               0 1969-12-31 19:00 pkg/fifo
-rw-r--r-- 0/0               1 1969-12-31 19:00 /abs/file
-rw-r--r-- 0/0               1 1969-12-31 19:00 pkg/../escape
-rw-r--r-- 0/0               1 1969-12-31 19:00 pkg/nl\\nname
";

    #[test]
    fn gnu_listing_parses_every_kind_and_keeps_names_verbatim() {
        let entries = parse_listing(GNU, GNU_LISTING).unwrap();
        assert_eq!(
            entries,
            vec![
                entry(EntryKind::Dir, "pkg/", None),
                entry(EntryKind::Dir, "pkg/a b/", None),
                entry(EntryKind::File, "pkg/a b/file with -> arrow", None),
                entry(
                    EntryKind::HardLink,
                    "pkg/hard",
                    Some("pkg/a b/file with -> arrow")
                ),
                entry(EntryKind::Symlink, "python/bin/2to3", Some("2to3-3.12")),
                entry(EntryKind::Special('c'), "pkg/dev", None),
                entry(EntryKind::Special('p'), "pkg/fifo", None),
                entry(EntryKind::File, "/abs/file", None),
                entry(EntryKind::File, "pkg/../escape", None),
                entry(EntryKind::File, "pkg/nl\\nname", None),
            ]
        );
    }

    /// libarchive's bsdtar `-tv` layout (mode, link count, owner, group,
    /// size or `major,minor`, month, day, time-or-year, name).
    const BSD_LISTING: &str = "\
drwxr-xr-x  0 root   wheel       0 Jan  1  2024 node-v24.20.0-darwin-arm64/
-rwxr-xr-x  0 root   wheel  123456 Jan  1  2024 node-v24.20.0-darwin-arm64/bin/node
lrwxr-xr-x  0 root   wheel       0 Jan  1  2024 node-v24.20.0-darwin-arm64/bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js
hrw-r--r--  2 root   wheel       0 Jan  1 12:34 pkg/hard link to pkg/file
crw-r--r--  0 root   wheel     1,3 Jan  1 12:34 pkg/dev
-rw-r--r--  0 root   wheel       1 Jan  1 12:34 pkg/a b/file with -> arrow
";

    #[test]
    fn bsdtar_listing_parses_with_its_eight_leading_columns() {
        let entries = parse_listing(BSD, BSD_LISTING).unwrap();
        assert_eq!(
            entries,
            vec![
                entry(EntryKind::Dir, "node-v24.20.0-darwin-arm64/", None),
                entry(EntryKind::File, "node-v24.20.0-darwin-arm64/bin/node", None),
                entry(
                    EntryKind::Symlink,
                    "node-v24.20.0-darwin-arm64/bin/npm",
                    Some("../lib/node_modules/npm/bin/npm-cli.js")
                ),
                entry(EntryKind::HardLink, "pkg/hard", Some("pkg/file")),
                entry(EntryKind::Special('c'), "pkg/dev", None),
                entry(EntryKind::File, "pkg/a b/file with -> arrow", None),
            ]
        );
        // The GNU parser applied to bsdtar output does not silently produce
        // wrong names: the extra columns end up in the name and the archive
        // is then judged on that text, never skipped. The reverse (bsdtar
        // parser on GNU output) fails to find eight columns and refuses.
        assert!(parse_listing(BSD, GNU_LISTING).is_err());
    }

    #[test]
    fn unparseable_or_ambiguous_lines_refuse_the_listing() {
        // A raw newline in a name would split a line; the fragment has no
        // mode column and refuses everything.
        assert!(parse_listing(GNU, "-rw-r--r-- 0/0 1 1969-12-31 19:00 pkg/nl\nname\n").is_err());
        // Type letters this module does not know are specials, never files.
        let entries = parse_listing(GNU, "Drw-r--r-- 0/0 0 1969-12-31 19:00 dump/\n").unwrap();
        assert_eq!(entries[0].kind, EntryKind::Special('D'));
        // A symlink line with two arrows cannot be attributed and is refused
        // rather than split at either arrow (splitting at the last one would
        // let a target like `../x -> y` pass as `y`).
        assert!(parse_listing(
            GNU,
            "lrwxrwxrwx 0/0 0 1969-12-31 19:00 pkg/x -> ../x -> y\n"
        )
        .is_err());
        // An empty target, an empty name, and control characters refuse.
        assert!(parse_listing(GNU, "lrwxrwxrwx 0/0 0 1969-12-31 19:00 pkg/x -> \n").is_err());
        assert!(parse_listing(GNU, "-rw-r--r-- 0/0 0 1969-12-31 19:00 \n").is_err());
        assert!(parse_listing(GNU, "-rw-r--r-- 0/0 0 1969-12-31 19:00 pkg/\u{7}bell\n").is_err());
        // Fewer columns than the format promises is a parse failure.
        assert!(parse_listing(GNU, "-rw-r--r-- 0/0 0 1969-12-31\n").is_err());
        // A name that begins with a space survives.
        let entries = parse_listing(GNU, "-rw-r--r-- 0/0 0 1969-12-31 19:00  spacey\n").unwrap();
        assert_eq!(entries[0].name, " spacey");
    }

    // ---- containment rules -------------------------------------------------

    fn refused(entries: &[Entry], strip: usize, needle: &str) {
        let error = validate(entries, strip).expect_err(needle);
        assert!(
            error.to_string().contains(needle),
            "{needle:?} not in {error}"
        );
    }

    #[test]
    fn names_that_could_write_outside_are_refused() {
        refused(
            &[entry(EntryKind::File, "/abs/file", None)],
            0,
            "absolute member name",
        );
        refused(
            &[entry(EntryKind::File, "pkg/../escape", None)],
            0,
            "`..` path component",
        );
        refused(
            &[entry(EntryKind::Dir, "../", None)],
            0,
            "`..` path component",
        );
        refused(
            &[entry(EntryKind::File, "pkg//x", None)],
            0,
            "empty path component",
        );
        refused(
            &[entry(EntryKind::File, "/", None)],
            0,
            "absolute member name",
        );
        // `..` is refused even where strip would drop the entry: the rule is
        // about the archive, not about what tar happens to skip.
        refused(
            &[entry(EntryKind::File, "../x", None)],
            3,
            "`..` path component",
        );
        // `.` components are ordinary and count for strip like tar counts them.
        validate(&[entry(EntryKind::File, "./pkg/x", None)], 1).unwrap();
    }

    #[test]
    fn hard_links_and_special_files_are_refused_regardless_of_strip() {
        refused(
            &[entry(EntryKind::HardLink, "pkg/hard", Some("pkg/file"))],
            0,
            "hard link",
        );
        refused(
            &[entry(EntryKind::HardLink, "pkg/hard", Some("pkg/file"))],
            5,
            "hard link",
        );
        for kind in ['b', 'c', 'p', 's', 'D', 'M'] {
            refused(
                &[entry(EntryKind::Special(kind), "pkg/odd", None)],
                0,
                "special file",
            );
        }
    }

    #[test]
    fn symlinks_are_accepted_only_when_lexically_contained_after_strip() {
        let ok = |name: &str, target: &str, strip: usize| {
            validate(&[entry(EntryKind::Symlink, name, Some(target))], strip).unwrap()
        };
        let bad = |name: &str, target: &str, strip: usize| {
            refused(
                &[entry(EntryKind::Symlink, name, Some(target))],
                strip,
                "escapes the destination",
            )
        };
        ok("python/bin/2to3", "2to3-3.12", 0);
        ok("node/bin/npm", "../lib/node_modules/npm/bin/npm-cli.js", 0);
        ok("node/bin/npm", "../lib/node_modules/npm/bin/npm-cli.js", 1);
        ok("pkg/a/b/c", "../../x", 0);
        ok("pkg/a/b/c", "./././x", 0);
        ok("pkg/a/b/c", "../../a/../x", 0);
        // Three `..` from a link three directories deep is the destination
        // root itself: contained. One more escapes.
        ok("pkg/a/b/c", "../../../x", 0);
        bad("pkg/a/b/c", "../../../../x", 0);
        ok("pkg/l", "../x", 0);
        ok("pkg/l", "..", 0);
        bad("pkg/l", "../../x", 0);
        bad("l", "../x", 0);
        bad("l", "..", 0);
        // Contained before strip, escaping after it: tar strips the name but
        // never rewrites the target, so post-strip is what counts.
        ok("pkg/l", "../other", 0);
        bad("pkg/l", "../other", 1);
        // `..` in the middle after climbing back is still contained.
        ok("pkg/a/l", "../a/../b", 1);
        refused(
            &[entry(EntryKind::Symlink, "pkg/l", Some("/etc/passwd"))],
            0,
            "absolute symlink target",
        );
        refused(
            &[entry(EntryKind::Symlink, "pkg/l", Some(""))],
            0,
            "empty symlink target",
        );
        // Entries strip would drop are skipped, except for their kind.
        validate(&[entry(EntryKind::Dir, "pkg/", None)], 1).unwrap();
        validate(&[entry(EntryKind::Symlink, "pkg", Some("/x"))], 1).unwrap();
    }

    // ---- end to end with the real tar ------------------------------------

    fn temp_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "blanket-archive-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A hand-built ustar member: the tar format is simple enough that the
    /// tests need no tar binary to write hostile members (hard links,
    /// devices, absolute names) that `tar -c` would refuse or rewrite.
    fn ustar(name: &str, typeflag: u8, link: &str, data: &[u8]) -> Vec<u8> {
        assert!(name.len() < 100 && link.len() < 100);
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let mode = if typeflag == b'5' {
            "0000755\0"
        } else {
            "0000644\0"
        };
        header[100..108].copy_from_slice(mode.as_bytes());
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size = if typeflag == b'0' { data.len() } else { 0 };
        header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = typeflag;
        header[157..157 + link.len()].copy_from_slice(link.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        if typeflag == b'3' || typeflag == b'4' {
            header[329..337].copy_from_slice(b"0000001\0");
            header[337..345].copy_from_slice(b"0000003\0");
        }
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut out = header;
        if typeflag == b'0' {
            out.extend_from_slice(data);
            let pad = (512 - data.len() % 512) % 512;
            out.extend(std::iter::repeat(0u8).take(pad));
        }
        out
    }

    fn write_tar(path: &Path, members: &[Vec<u8>]) {
        let mut bytes = Vec::new();
        for member in members {
            bytes.extend_from_slice(member);
        }
        bytes.extend(std::iter::repeat(0u8).take(1024));
        fs::write(path, bytes).unwrap();
    }

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    #[test]
    fn hostile_members_are_refused_before_anything_is_written() {
        let temp = temp_dir("hostile");
        let sentinel = temp.join("outside-sentinel");
        fs::write(&sentinel, b"untouched").unwrap();
        let destination = temp.join("dest");
        fs::create_dir_all(&destination).unwrap();
        // Each archive is well-formed except for one hostile member placed
        // AFTER benign members, so a tar that extracted as it read would
        // already have written `pkg/benign` by the time it met the member.
        let benign = [
            ustar("pkg/", b'5', "", b""),
            ustar("pkg/benign", b'0', "", b"hello"),
        ];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "symlink escapes",
                ustar("pkg/escape", b'2', "../../outside-sentinel", b""),
            ),
            (
                "absolute symlink",
                ustar("pkg/abs", b'2', "/etc/passwd", b""),
            ),
            (
                "symlink escapes after strip",
                ustar("pkg/up", b'2', "../outside-sentinel", b""),
            ),
            ("hard link", ustar("pkg/hard", b'1', "pkg/benign", b"")),
            ("character device", ustar("pkg/dev", b'3', "", b"")),
            ("fifo", ustar("pkg/fifo", b'6', "", b"")),
            ("dot-dot name", ustar("pkg/../escaped", b'0', "", b"x")),
            ("absolute name", ustar("/abs/escaped", b'0', "", b"x")),
        ];
        for (label, hostile) in cases {
            let archive = temp.join(format!("{}.tar", label.replace(' ', "-")));
            let mut members = benign.to_vec();
            members.push(hostile);
            write_tar(&archive, &members);
            let error =
                extract(host(), &archive, &destination, 1, Compression::None).expect_err(label);
            assert!(
                !error.to_string().is_empty(),
                "{label}: refusal must explain itself"
            );
            assert_eq!(
                fs::read_dir(&destination).unwrap().count(),
                0,
                "{label}: something was written into the destination"
            );
            assert_eq!(fs::read(&sentinel).unwrap(), b"untouched", "{label}");
        }
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn contained_archives_extract_with_strip_and_keep_their_symlinks() {
        let temp = temp_dir("good");
        let archive = temp.join("good.tar");
        write_tar(
            &archive,
            &[
                ustar("root/", b'5', "", b""),
                ustar("root/bin/", b'5', "", b""),
                ustar("root/bin/tool", b'0', "", b"#!/bin/sh\n"),
                ustar("root/bin/alias", b'2', "tool", b""),
                ustar("root/lib/", b'5', "", b""),
                ustar("root/lib/link", b'2', "../bin/tool", b""),
                ustar("root/a b/", b'5', "", b""),
                ustar("root/a b/file with -> arrow", b'0', "", b"x"),
            ],
        );
        let destination = temp.join("dest");
        fs::create_dir_all(&destination).unwrap();
        let entries = extract(host(), &archive, &destination, 1, Compression::None).unwrap();
        assert_eq!(entries.len(), 8);
        assert!(destination.join("bin/tool").is_file());
        assert_eq!(
            fs::read_link(destination.join("bin/alias")).unwrap(),
            PathBuf::from("tool")
        );
        assert_eq!(
            fs::read_link(destination.join("lib/link")).unwrap(),
            PathBuf::from("../bin/tool")
        );
        assert_eq!(
            fs::read(destination.join("a b/file with -> arrow")).unwrap(),
            b"x"
        );
        assert!(!destination.join("root").exists(), "strip was not applied");

        // The same archive without strip keeps the root, and the delegated
        // tar ignores TAR_OPTIONS from the environment.
        let plain = temp.join("plain");
        fs::create_dir_all(&plain).unwrap();
        std::env::set_var("TAR_OPTIONS", "--strip-components=1");
        let result = extract(host(), &archive, &plain, 0, Compression::None);
        std::env::remove_var("TAR_OPTIONS");
        result.unwrap();
        assert!(plain.join("root/bin/tool").is_file());
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn real_tar_lists_a_gzip_archive_made_by_tar_itself() {
        let temp = temp_dir("gzip");
        let source = temp.join("source");
        fs::create_dir_all(source.join("pkg/bin")).unwrap();
        fs::write(source.join("pkg/bin/tool"), b"tool").unwrap();
        std::os::unix::fs::symlink("tool", source.join("pkg/bin/alias")).unwrap();
        let archive = temp.join("pkg.tar.gz");
        assert!(Command::new("/usr/bin/tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("pkg")
            .status()
            .unwrap()
            .success());
        let entries = list(host(), &archive, Compression::Gzip).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"pkg/bin/tool"), "{names:?}");
        let alias = entries.iter().find(|e| e.name == "pkg/bin/alias").unwrap();
        assert_eq!(alias.kind, EntryKind::Symlink);
        assert_eq!(alias.link.as_deref(), Some("tool"));
        validate(&entries, 1).unwrap();
        let _ = fs::remove_dir_all(&temp);
    }
}

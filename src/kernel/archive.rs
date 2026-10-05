//! Pre-materialization archive validation and delegated extraction.
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
//! The listing comes from the archive's own 512-byte header blocks, read in
//! process: ustar names plus the POSIX `prefix` field, PAX `path`, `linkpath`
//! and `size` records, and GNU `L`/`K` long names. Decompression is in
//! process and streaming; member data is skipped, never buffered. Anything
//! the reader cannot model — a sparse member, a global header that renames,
//! an unknown type letter, a bad checksum, a short block, a name that is not
//! printable UTF-8 — refuses the whole archive rather than skipping a
//! member, because a member this module cannot describe is a member it
//! cannot judge. The names the reader produces are then cross-checked
//! against `tar -t`, which prints one stored name per line: if the reader and
//! the tar that will perform the extraction disagree about what the archive
//! contains, nothing is extracted.
//!
//! PAX record values are bytes until a key the reader acts on (`path`,
//! `linkpath`, `size`) decodes them as UTF-8; the rest are metadata whose
//! bytes are never read, which lets macOS tar's binary extended-attribute
//! records through. Names are held to what a listing can show faithfully:
//! no control, bidirectional-override or zero-width characters. And because
//! one lock must realize the same tree on Linux and on APFS, which folds
//! case and Unicode normalization, two names that APFS would treat as one
//! refuse the archive. The delegated tar is told not to restore extended
//! attributes, ACLs, file flags or AppleDouble metadata: an object's
//! identity covers names, bytes and the executable bit, and nothing else
//! may land in it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

use crate::kernel::activity::StoreActivity;

/// One archive member as the header reader read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// The member name exactly as stored (directories keep their trailing
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
}

/// How the archive is compressed. The caller passes it explicitly, never
/// sniffed, so each call site keeps one fixed tar flag: a different flag
/// could change the extracted bytes, and a byte-identical extraction is part
/// of the object-identity contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
}

impl Compression {
    fn flag(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gzip => "z",
            Compression::Bzip2 => "j",
            Compression::Xz => "J",
        }
    }
}

/// Ceiling on the total member bytes one archive may carry. The header
/// reader adds up every regular file's declared size (plus metadata
/// headers) before the delegated tar writes anything and refuses past
/// this: a compression bomb must not fill the disk first. It matches the
/// per-package 1 GiB cap the registry extractors already enforced after
/// the fact, and every pinned toolchain is orders of magnitude below it.
pub const MAX_ARCHIVE_BYTES: u64 = 1 << 30;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// The tar that lists and extracts every archive: the host's own
/// `/usr/bin/tar`, GNU tar on Linux and bsdtar on macOS. There is no
/// per-platform choice to make here. The binary sits at the same path on
/// both hosts, the flags below are fixed because a different command line
/// would change what lands in an object, and the two tars' differences are
/// handled where they show: the header reader models both, and `cross_check`
/// refuses an archive the reader and the host tar disagree about.
fn tar_command() -> Command {
    let mut command = Command::new("/usr/bin/tar");
    // The user's environment must not add extraction flags.
    command.env_remove("TAR_OPTIONS");
    // A pinned locale keeps tar's diagnostics and its `-t` output in the one
    // encoding this module compares against, and keeps the delegated
    // extraction identical on every host.
    command.env("LC_ALL", "C");
    command.env("LANG", "C");
    command.env_remove("LC_TIME");
    command
}

/// Flags the `tar -t` listing carries. `--numeric-owner` protects no parser
/// here, since the listing is read from the header blocks; it stays because
/// the command line is fixed. Nothing else: a listing writes no files, so
/// the flags that stop tar restoring metadata have nothing to act on there,
/// and bsdtar's man page marks every one of them for other modes. A flag
/// that can only fail must not sit on the command every listing runs.
///
/// The cost is `._name` members: bsdtar's AppleDouble handling folds them
/// into the member that follows, which the header reader does not model,
/// so a Mac-packed tarball's listing disagrees with the reader and the
/// cross-check refuses it on macOS rather than extracting the wrong tree.
/// Whether `--no-mac-metadata` on `-t` would lift that is the open half of
/// the AppleDouble item in FOLLOW-UPS.
const TAR_LIST_FLAGS: [&str; 1] = ["--numeric-owner"];

/// Flags the extraction carries. The delegated extraction writes object
/// bytes and its command line is fixed, because a different command line
/// would change what lands in an object. Beyond `--numeric-owner`, these
/// keep the extracted tree to what an object's identity covers (names,
/// bytes, the executable bit) by telling tar not to restore extended
/// attributes, ACLs, BSD file flags or macOS AppleDouble metadata from the
/// archive. GNU tar restores none of these unless asked; bsdtar restores
/// all of them by default when it runs as root.
#[cfg(target_os = "macos")]
const TAR_EXTRACT_FLAGS: [&str; 5] = [
    "--numeric-owner",
    "--no-xattrs",
    "--no-acls",
    "--no-fflags",
    "--no-mac-metadata",
];
#[cfg(not(target_os = "macos"))]
const TAR_EXTRACT_FLAGS: [&str; 3] = ["--numeric-owner", "--no-xattrs", "--no-acls"];

/// List `archive` by reading its tar headers, cross-checked against the
/// platform tar's own listing.
pub fn list(archive: &Path, compression: Compression) -> io::Result<Vec<Entry>> {
    list_inner(archive, compression, None)
}

/// Store-consuming archive listing. The caller's activity lease is borrowed
/// for the whole read, so GC cannot observe the store as idle while a caller
/// still depends on an extracted/cache input.
pub(crate) fn list_with_activity(
    activity: &StoreActivity,
    archive: &Path,
    compression: Compression,
) -> io::Result<Vec<Entry>> {
    list_inner(archive, compression, Some(activity))
}

fn list_inner(
    archive: &Path,
    compression: Compression,
    activity: Option<&StoreActivity>,
) -> io::Result<Vec<Entry>> {
    // The caller's lease covers both the in-process read and the
    // cross-check child.
    let entries = read_archive(archive, compression)
        .map_err(|e| io::Error::new(e.kind(), format!("list {}: {e}", archive.display())))?;
    // Cross-check every name against the tar that will do the extraction.
    // `-t` prints one stored name per line and nothing else, so it cannot be
    // shifted by a wide field, a locale, or a tar version that reformats.
    // Disagreement means the reader and tar do not see the same archive, and
    // a reader that is wrong about a name is a reader whose containment
    // decision was made on text that is not the name. Refuse rather than
    // extract on a guess.
    let names = list_names(archive, compression, activity)?;
    cross_check(archive, &entries, &names)?;
    Ok(entries)
}

/// The archive listed by the platform tar without `-v`: one stored name per
/// line, no columns.
// Reviewed site (tests/architecture.rs): `None` arm of `Option<&StoreActivity>`: no store is involved.
#[allow(clippy::disallowed_methods)]
fn list_names(
    archive: &Path,
    compression: Compression,
    activity: Option<&StoreActivity>,
) -> io::Result<Vec<String>> {
    let mut command = list_command(archive, compression);
    let output = match activity {
        Some(activity) => crate::kernel::supervise::local_output(&mut command, activity),
        None => command.output(),
    }
    .map_err(|e| io::Error::new(e.kind(), format!("list {}: {e}", archive.display())))?;
    if !output.status.success() {
        return Err(err(format!(
            "list {} failed: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        err(format!(
            "list {}: tar printed a name that is not UTF-8",
            archive.display()
        ))
    })?;
    Ok(text.lines().map(str::to_string).collect())
}

/// `tar -t` over `archive`, with the fixed listing flags.
fn list_command(archive: &Path, compression: Compression) -> Command {
    let mut command = tar_command();
    command
        .args(TAR_LIST_FLAGS)
        .arg(format!("-t{}f", compression.flag()))
        .arg(archive);
    command
}

/// Refuse when the header reader and the platform tar disagree about the
/// sequence of member names.
fn cross_check(archive: &Path, entries: &[Entry], names: &[String]) -> io::Result<()> {
    let disagrees = names.len() != entries.len()
        || names
            .iter()
            .zip(entries.iter())
            .any(|(printed, entry)| !name_agrees(&entry.name, printed));
    if disagrees {
        return Err(err(format!(
            "list {}: the header reader and tar's listing disagree about entry names; refusing to extract (headers: {:?}, tar: {:?})",
            archive.display(),
            entries.iter().map(|e| &e.name).take(8).collect::<Vec<_>>(),
            names.iter().take(8).collect::<Vec<_>>()
        )));
    }
    Ok(())
}

/// Does the line tar printed name the member the reader read?
///
/// Both tars print `-t` names through a C-string quoter, and the pinned `C`
/// locale makes every byte outside printable ASCII unprintable, so a name
/// with any non-ASCII byte — Go's own test tree has one — arrives as
/// three-digit octal escapes rather than as itself. GNU tar additionally
/// doubles a literal backslash; bsdtar leaves it alone. Names are already
/// known to be UTF-8 free of control characters, so those are the only two
/// ways the printed form can differ from the stored one. The comparison
/// therefore renders *the reader's* name the way each tar would and asks
/// whether tar printed one of them: the rendering is derived from the name
/// the containment rules will judge, and it is injective, so an accepted
/// line cannot stand for some other name.
fn name_agrees(name: &str, printed: &str) -> bool {
    printed == name || printed == octal_escaped(name, true) || printed == octal_escaped(name, false)
}

fn octal_escaped(name: &str, double_backslash: bool) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.as_bytes() {
        match byte {
            b'\\' if double_backslash => out.push_str("\\\\"),
            0x20..=0x7e => out.push(*byte as char),
            other => out.push_str(&format!("\\{other:03o}")),
        }
    }
    out
}

// ---- tar header reader ----------------------------------------------------

/// A tar header block, and the unit every member is padded to.
const BLOCK: usize = 512;

/// Ceiling on the data a metadata header (PAX extended or global, GNU long
/// name or long link) may carry. Real archives stay orders of magnitude
/// below it; the cap stops a hostile header asking for an unbounded
/// allocation, and member data is never held at all.
const METADATA_LIMIT: u64 = 1 << 20;

/// Open `archive`, wrap it in the decompressor the caller named, and read the
/// tar stream. Decompression is streaming: no whole-archive buffer exists.
fn read_archive(archive: &Path, compression: Compression) -> io::Result<Vec<Entry>> {
    let file = io::BufReader::new(File::open(archive)?);
    match compression {
        Compression::None => read_entries(file, None),
        // Multi-member, matching what `tar -z` accepts.
        Compression::Gzip => read_entries(
            io::BufReader::new(flate2::read::MultiGzDecoder::new(file)),
            None,
        ),
        Compression::Bzip2 => {
            read_entries(io::BufReader::new(bzip2::read::BzDecoder::new(file)), None)
        }
        Compression::Xz => read_entries(
            io::BufReader::new(liblzma::read::XzDecoder::new(file)),
            None,
        ),
    }
    .map(|(entries, _)| entries)
}

/// Header state that a `L`, `K` or `x` block leaves for the member that
/// follows it. Conflicting GNU and PAX names or link targets are refused:
/// GNU tar and bsdtar apply different precedence to those extensions.
#[derive(Default)]
struct Pending {
    long_name: Option<String>,
    long_link: Option<String>,
    pax_path: Option<String>,
    pax_linkpath: Option<String>,
    pax_size: Option<u64>,
}

impl Pending {
    fn is_set(&self) -> bool {
        self.long_name.is_some()
            || self.long_link.is_some()
            || self.pax_path.is_some()
            || self.pax_linkpath.is_some()
            || self.pax_size.is_some()
    }
}

/// Read an uncompressed tar stream and return one `Entry` per member, or a
/// refusal naming the member that could not be modelled.
///
/// `want` names one regular-file member whose bytes are captured instead of
/// skipped (at most its `u64` cap): the single-member read behind
/// `read_member`. Everything else about the walk is identical, so the bytes
/// come from the same modelled stream the listing describes. Only the first
/// member with that exact stored name is captured.
fn read_entries(
    mut reader: impl Read,
    want: Option<(&str, u64)>,
) -> io::Result<(Vec<Entry>, Option<Vec<u8>>)> {
    let mut entries = Vec::new();
    let mut wanted: Option<Vec<u8>> = None;
    let mut budget = Budget::default();
    let mut pending = Pending::default();
    let mut block = [0u8; BLOCK];
    loop {
        let filled = read_block(&mut reader, &mut block)?;
        if filled == 0 {
            // Both GNU tar and bsdtar treat a stream that stops without an
            // end-of-archive block as truncated.
            return Err(err("truncated archive: no end-of-archive block"));
        }
        if filled != BLOCK {
            return Err(err(format!(
                "truncated archive: a header block is {filled} bytes, not {BLOCK}"
            )));
        }
        if block.iter().all(|byte| *byte == 0) {
            if pending.is_set() {
                return Err(err(
                    "archive ends with an extended header that names no member",
                ));
            }
            // Both tars stop at the first all-zero block; so does this.
            return Ok((entries, wanted));
        }
        if !checksum_matches(&block) {
            return Err(err(format!(
                "archive entry {:?} has a bad header checksum",
                String::from_utf8_lossy(c_string(&block[..100]))
            )));
        }
        let header_name = String::from_utf8_lossy(c_string(&block[..100])).into_owned();
        let typeflag = block[156];
        let raw_size = parse_size(&block[124..136])
            .map_err(|reason| err(format!("archive entry {header_name:?}: {reason}")))?;

        // Metadata blocks describe the member that follows; they are not
        // members themselves and do not clear each other's state.
        match typeflag {
            b'x' => {
                let data = read_metadata(&mut reader, raw_size, &header_name, &mut budget)?;
                let records = pax_records(&data, &header_name)?;
                apply_pax(records, &header_name, &mut pending)?;
                continue;
            }
            b'g' => {
                let data = read_metadata(&mut reader, raw_size, &header_name, &mut budget)?;
                let records = pax_records(&data, &header_name)?;
                check_global(&records, &header_name)?;
                continue;
            }
            b'L' | b'K' => {
                let data = read_metadata(&mut reader, raw_size, &header_name, &mut budget)?;
                let value = utf8(c_string(&data), "GNU long name")?.to_string();
                if typeflag == b'L' {
                    pending.long_name = Some(value);
                } else {
                    pending.long_link = Some(value);
                }
                continue;
            }
            _ => {}
        }

        // A real member. Assemble its name from the fields the format
        // actually defines, refusing any magic this reader does not model.
        let magic = &block[257..263];
        let version = &block[263..265];
        let posix = magic == b"ustar\0" && version == b"00";
        let old_gnu = magic == b"ustar " && version == b" \0";
        let v7 = magic.iter().all(|byte| *byte == 0);
        if !posix && !old_gnu && !v7 {
            return Err(err(format!(
                "archive entry {header_name:?} carries an unknown tar magic ({:?}); the layout is not modelled",
                String::from_utf8_lossy(&block[257..265])
            )));
        }
        let mut name = utf8(c_string(&block[..100]), "member name")?.to_string();
        if posix {
            let prefix = utf8(c_string(&block[345..500]), "member name prefix")?;
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let mut link = utf8(c_string(&block[157..257]), "link target")?.to_string();
        for (gnu, pax, field) in [
            (&pending.long_name, &pending.pax_path, "path"),
            (&pending.long_link, &pending.pax_linkpath, "linkpath"),
        ] {
            if let (Some(gnu), Some(pax)) = (gnu, pax) {
                if gnu != pax {
                    return Err(err(format!(
                        "archive entry {header_name:?} has conflicting GNU and PAX {field} values; refusing to extract"
                    )));
                }
            }
        }
        if let Some(long) = pending.long_name.take() {
            name = long;
        }
        if let Some(long) = pending.long_link.take() {
            link = long;
        }
        if let Some(path) = pending.pax_path.take() {
            name = path;
        }
        if let Some(path) = pending.pax_linkpath.take() {
            link = path;
        }
        let size = pending.pax_size.take().unwrap_or(raw_size);
        pending = Pending::default();

        check_name_text(&name, &link)?;

        let kind = match typeflag {
            b'0' | b'\0' => EntryKind::File,
            b'5' => EntryKind::Dir,
            b'2' => EntryKind::Symlink,
            b'1' => {
                return Err(err(format!(
                    "archive entry {name:?} is a hard link (to {link:?}); hard links are refused"
                )))
            }
            other => {
                // Devices, FIFOs, sockets, contiguous files, GNU sparse and
                // dump extensions, and anything unallocated. Data may or may
                // not follow such a header, so the stream is ambiguous from
                // here: refuse instead of trying to resynchronize.
                return Err(err(format!(
                    "archive entry {name:?} is a special file (type {:?}); only files, directories, and contained symlinks are accepted",
                    other as char
                )));
            }
        };
        if kind == EntryKind::Symlink && link.is_empty() {
            return Err(err(format!("archive entry {name:?}: empty symlink target")));
        }
        if kind != EntryKind::File && size != 0 {
            return Err(err(format!(
                "archive entry {name:?} is not a regular file but declares {size} bytes of data; the layout is not modelled"
            )));
        }
        if kind == EntryKind::File {
            budget.add(size, &format!("entry {name:?}"))?;
        }
        take_or_skip(
            &mut reader,
            &name,
            size,
            kind == EntryKind::File,
            want,
            &mut wanted,
        )?;
        let link = if kind == EntryKind::Symlink {
            Some(link)
        } else {
            None
        };
        entries.push(Entry { kind, name, link });
    }
}

/// Running byte budget: every declared file size and every metadata header
/// counts before its data is even skipped, so a bomb refuses on its headers
/// rather than after filling the disk.
#[derive(Default)]
struct Budget {
    total: u64,
}

impl Budget {
    fn add(&mut self, more: u64, what: &str) -> io::Result<()> {
        self.total = self.total.checked_add(more).ok_or_else(|| {
            err(format!(
                "archive holds more than {MAX_ARCHIVE_BYTES} bytes of member data; refusing to extract"
            ))
        })?;
        if self.total > MAX_ARCHIVE_BYTES {
            return Err(err(format!(
                "archive {what} passes the {MAX_ARCHIVE_BYTES} byte budget; refusing to extract"
            )));
        }
        Ok(())
    }
}

/// Capture one member's bytes when it is the wanted member, else skip its
/// data; refuse a wanted member that is not a regular file. Only the first
/// member with that exact stored name is captured.
fn take_or_skip(
    reader: &mut impl Read,
    name: &str,
    size: u64,
    is_file: bool,
    want: Option<(&str, u64)>,
    wanted: &mut Option<Vec<u8>>,
) -> io::Result<()> {
    if !is_file {
        if wanted.is_none() && want.is_some_and(|(member, _)| member == name) {
            return Err(err(format!(
                "archive member {name:?} is not a regular file"
            )));
        }
        return Ok(());
    }
    if wanted.is_none() && want.is_some_and(|(member, _)| member == name) {
        let cap = want.map(|(_, cap)| cap).unwrap_or(0);
        if size > cap {
            return Err(err(format!(
                "archive member {name:?} holds {size} bytes, more than the {cap} byte read cap"
            )));
        }
        *wanted = Some(read_member_data(reader, size, name)?);
    } else {
        skip(reader, size, name)?;
    }
    skip(reader, padding(size), name)
}

/// Bytes of NUL padding after `size` bytes of member data.
fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// Fill `block`, returning how many bytes arrived. Fewer than `BLOCK` means
/// the stream ended inside a header.
fn read_block(reader: &mut impl Read, block: &mut [u8; BLOCK]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < BLOCK {
        match reader.read(&mut block[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Discard `count` bytes; a short stream is a truncated archive.
fn skip(reader: &mut impl Read, count: u64, name: &str) -> io::Result<()> {
    if count == 0 {
        return Ok(());
    }
    let discarded = io::copy(&mut reader.by_ref().take(count), &mut io::sink())?;
    if discarded != count {
        return Err(err(format!(
            "truncated archive: entry {name:?} declares more data than the stream holds"
        )));
    }
    Ok(())
}

/// Read exactly `size` bytes of one member's data; a short stream is a
/// truncated archive. The caller checked `size` against its cap first, so
/// the allocation is bounded by that cap.
fn read_member_data(reader: &mut impl Read, size: u64, name: &str) -> io::Result<Vec<u8>> {
    let mut data = vec![0u8; size as usize];
    let mut filled = 0;
    while filled < data.len() {
        match reader.read(&mut data[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    if filled != data.len() {
        return Err(err(format!(
            "truncated archive: entry {name:?} declares more data than the stream holds"
        )));
    }
    Ok(data)
}

/// Read the data a metadata header carries, plus its padding, counting it
/// against the byte budget: metadata counts like member data, so a stream
/// of unbounded extended headers refuses the same way a bomb does.
fn read_metadata(
    reader: &mut impl Read,
    size: u64,
    name: &str,
    budget: &mut Budget,
) -> io::Result<Vec<u8>> {
    if size > METADATA_LIMIT {
        return Err(err(format!(
            "archive extended header {name:?} carries {size} bytes, more than this reader accepts"
        )));
    }
    let mut data = vec![0u8; size as usize];
    let mut filled = 0;
    while filled < data.len() {
        match reader.read(&mut data[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    if filled != data.len() {
        return Err(err(format!(
            "truncated archive: extended header {name:?} is cut short"
        )));
    }
    budget.add(data.len() as u64, "extended headers")?;
    skip(reader, padding(size), name)?;
    Ok(data)
}

/// The stored checksum with the field itself counted as spaces. GNU tar
/// accepts either the unsigned or the signed sum; some historical tars wrote
/// the latter by treating the header bytes as signed chars.
fn checksum_matches(block: &[u8; BLOCK]) -> bool {
    let Some(stored) = parse_octal(&block[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (index, byte) in block.iter().enumerate() {
        let byte = if (148..156).contains(&index) {
            b' '
        } else {
            *byte
        };
        unsigned += byte as u64;
        signed += (byte as i8) as i64;
    }
    stored == unsigned || i64::try_from(stored).is_ok_and(|stored| stored == signed)
}

/// Bytes up to the first NUL, or the whole field when it has none.
fn c_string(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    &field[..end]
}

fn utf8<'a>(bytes: &'a [u8], what: &str) -> io::Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        err(format!(
            "archive {what} {:?} is not UTF-8",
            String::from_utf8_lossy(bytes)
        ))
    })
}

/// Octal ASCII, NUL- or space-terminated, leading and trailing spaces
/// allowed; an all-blank field is zero. `None` means the field is not a
/// number this reader can read.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let digits = c_string(field);
    let digits = trim_spaces(digits);
    if digits.is_empty() {
        return Some(0);
    }
    let mut value: u64 = 0;
    for byte in digits {
        if !(b'0'..=b'7').contains(byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add((byte - b'0') as u64)?;
    }
    Some(value)
}

fn trim_spaces(mut bytes: &[u8]) -> &[u8] {
    while bytes.first() == Some(&b' ') {
        bytes = &bytes[1..];
    }
    while bytes.last() == Some(&b' ') {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// The size field: octal, or GNU's base-256 form when the high bit of the
/// first byte is set. Only the non-negative base-256 form that fits in a
/// `u64` is accepted; anything else is a layout this reader cannot model.
fn parse_size(field: &[u8]) -> Result<u64, String> {
    if field[0] & 0x80 == 0 {
        return parse_octal(field).ok_or_else(|| "size field is not octal".to_string());
    }
    if field[0] != 0x80 {
        return Err("base-256 size is negative or wider than 64 bits".into());
    }
    let mut value: u64 = 0;
    for byte in &field[1..] {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(*byte as u64))
            .ok_or_else(|| "base-256 size is wider than 64 bits".to_string())?;
    }
    Ok(value)
}

/// PAX records, `"%d %s=%s\n"` where the length counts its own digits, the
/// space and the newline. Every record must parse and the records must fill
/// the header's data exactly.
fn pax_records(data: &[u8], name: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut records = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let rest = &data[at..];
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits == 0 || digits > 19 {
            return Err(err(format!(
                "archive PAX header {name:?} has a record with no length: {:?}",
                String::from_utf8_lossy(&rest[..rest.len().min(32)])
            )));
        }
        let length: usize = std::str::from_utf8(&rest[..digits])
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| {
                err(format!(
                    "archive PAX header {name:?} has an unreadable record length"
                ))
            })?;
        if length <= digits + 2 || length > rest.len() {
            return Err(err(format!(
                "archive PAX header {name:?} has a record whose length {length} does not match its data"
            )));
        }
        let record = &rest[..length];
        if record[digits] != b' ' || record[length - 1] != b'\n' {
            return Err(err(format!(
                "archive PAX header {name:?} has a record whose length {length} does not match its data"
            )));
        }
        let body = &record[digits + 1..length - 1];
        let equals = body.iter().position(|byte| *byte == b'=').ok_or_else(|| {
            err(format!(
                "archive PAX header {name:?} has a record with no \"=\""
            ))
        })?;
        let key = utf8(&body[..equals], "PAX record key")?.to_string();
        // Values stay bytes: POSIX says UTF-8, but vendors store raw
        // extended attributes here (macOS tar's `SCHILY.xattr.*`), and only
        // the keys `apply_pax` acts on need to be text.
        records.push((key, body[equals + 1..].to_vec()));
        at += length;
    }
    Ok(records)
}

/// Keys that change the member this reader describes, decoded as UTF-8
/// here; keys that are only metadata, whose bytes are never read; and
/// everything else, which is a layout it does not model.
fn apply_pax(records: Vec<(String, Vec<u8>)>, name: &str, pending: &mut Pending) -> io::Result<()> {
    for (key, value) in records {
        match key.as_str() {
            "path" => pending.pax_path = Some(utf8(&value, "PAX path")?.to_string()),
            "linkpath" => pending.pax_linkpath = Some(utf8(&value, "PAX linkpath")?.to_string()),
            "size" => {
                let text = utf8(&value, "PAX size")?;
                // Digits only. Rust's parser also takes a leading `+`,
                // which bsdtar reads as zero and GNU tar refuses: a size the
                // three of us read differently is a stream we walk
                // differently, and a header hidden in the gap would never
                // reach `tar -t`.
                let size = text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
                    .then(|| text.parse::<u64>().ok())
                    .flatten()
                    .ok_or_else(|| {
                        err(format!(
                            "archive PAX header {name:?} has a size record {text:?} that is not a decimal number"
                        ))
                    })?;
                pending.pax_size = Some(size);
            }
            // `charset` describes the member's data, which tar does not
            // convert; `hdrcharset`, which would make names raw bytes, is
            // not here and so is refused below.
            "mtime" | "atime" | "ctime" | "uid" | "gid" | "uname" | "gname" | "comment"
            | "charset" => {}
            // star's sparse-file size: tar extracts the member at this size,
            // which the reader would not see.
            "SCHILY.realsize" => {
                return Err(err(format!(
                    "archive PAX header {name:?} carries \"SCHILY.realsize\", which would resize the member; refusing to extract"
                )))
            }
            other if other.starts_with("SCHILY.") || other.starts_with("LIBARCHIVE.") => {}
            other => {
                return Err(err(format!(
                    "archive PAX header {name:?} carries the unmodelled key {other:?}; refusing to extract"
                )))
            }
        }
    }
    Ok(())
}

/// A global header may set defaults for every following member, so it is
/// accepted only when it cannot rename or resize one.
fn check_global(records: &[(String, Vec<u8>)], name: &str) -> io::Result<()> {
    for (key, _) in records {
        if matches!(
            key.as_str(),
            "path" | "linkpath" | "size" | "hdrcharset" | "SCHILY.realsize"
        ) || key.starts_with("GNU.sparse.")
        {
            return Err(err(format!(
                "archive global PAX header {name:?} carries {key:?}, which would rename or resize members; refusing to extract"
            )));
        }
    }
    Ok(())
}

/// The name and link target as text: not empty, and free of characters a
/// listing cannot show faithfully.
fn check_name_text(name: &str, link: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(err("archive entry has an empty name"));
    }
    if let Some(what) = invisible(name) {
        return Err(err(format!(
            "archive entry {name:?} has {what} in its name"
        )));
    }
    if let Some(what) = invisible(link) {
        return Err(err(format!(
            "archive entry {name:?} has {what} in its link target {link:?}"
        )));
    }
    Ok(())
}

/// The first character in `text` that would not show as itself in a
/// listing, named: a control, a bidirectional control, or one of the
/// invisible and zero-width characters. Names are read by people (tar's
/// listing, an error, a diff of two closures), and a character that
/// reorders or hides the text around it lets one name pass for another.
/// UTF-8 validity does not cover these: every one is a well-formed scalar
/// value.
///
/// Control (`Cc`) and format (`Cf`) come from the Unicode general category
/// via `icu_properties`, so a new format control in a future Unicode
/// version is refused without updating a list. Line and paragraph
/// separators (`Zl`, `Zp`) and the invisible marks that are not `Cf` — the
/// joiners and fillers below plus the variation selectors (`Mn`) — stay an
/// explicit list, because refusing all of `Mn` or `Lo` would refuse
/// legitimate combining marks and letters.
fn general_category(c: char) -> icu_properties::props::GeneralCategory {
    use std::sync::OnceLock;
    static MAP: OnceLock<
        icu_properties::CodePointMapDataBorrowed<'static, icu_properties::props::GeneralCategory>,
    > = OnceLock::new();
    MAP.get_or_init(icu_properties::CodePointMapData::new)
        .get(c)
}

fn invisible(text: &str) -> Option<&'static str> {
    use icu_properties::props::GeneralCategory as Gc;
    text.chars().find_map(|c| match general_category(c) {
        Gc::Control => Some("a control character"),
        Gc::Format => {
            if matches!(
                c,
                '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            ) {
                // Arabic letter mark, left-to-right and right-to-left marks,
                // embeddings, overrides, and isolates.
                Some("a bidirectional control character")
            } else {
                Some("an invisible character")
            }
        }
        Gc::LineSeparator | Gc::ParagraphSeparator => Some("an invisible character"),
        _ => {
            if matches!(
                c,
                '\u{034F}'
                    | '\u{115F}'
                    | '\u{1160}'
                    | '\u{17B4}'
                    | '\u{17B5}'
                    | '\u{180B}'..='\u{180D}'
                    | '\u{180F}'
                    | '\u{3164}'
                    | '\u{FE00}'..='\u{FE0F}'
                    | '\u{FFA0}'
                    | '\u{E0100}'..='\u{E01EF}'
            ) {
                // Combining grapheme joiner, Hangul and Khmer fillers,
                // Mongolian free-variation selectors, halfwidth Hangul
                // filler, and the variation selectors. None of these is
                // `Cf`, so the category check above does not see them.
                Some("an invisible character")
            } else {
                None
            }
        }
    })
}

/// Refuse anything that could write or point outside the destination once
/// the first `strip` path components are removed, the way tar's
/// `--strip-components` removes them. Entries with `strip` or fewer
/// components are skipped by tar, so only their name is still checked: an
/// absolute name or a `..` component is refused wherever it sits.
#[cfg(test)]
pub fn validate(entries: &[Entry], strip: usize) -> io::Result<()> {
    validate_with_options(entries, &ExtractOptions::stripped(strip))
}

/// The containment check under the extraction's full options: `strip`, and whether
/// the archive is a per-platform build that only this host's platform
/// ever extracts (see [`ExtractOptions::platform_specific`]).
pub fn validate_with_options(entries: &[Entry], options: &ExtractOptions) -> io::Result<()> {
    let strip = options.strip;
    let mut kept: Vec<(&Entry, Vec<&str>)> = Vec::new();
    // Hard links and special files never become entries: the listing
    // refuses them where it reads their type.
    for entry in entries {
        let components = contained_components(&entry.name)
            .map_err(|reason| err(format!("archive entry {:?}: {reason}", entry.name)))?;
        if components.len() <= strip {
            continue;
        }
        let stripped: Vec<&str> = components[strip..]
            .iter()
            .copied()
            .filter(|component| *component != ".")
            .collect();
        kept.push((entry, stripped));
    }
    // Two names APFS would treat as one extract as one file there and two
    // on Linux, so one archive would realize two different trees. Every
    // prefix counts, since `Lib/a` and `lib/b` share one directory on APFS
    // and two on Linux. Identical spellings are tar's ordinary
    // last-one-wins on both.
    //
    // A per-platform build is only ever extracted on its own platform, so
    // there is no second tree to diverge from: Linux keeps both names, as
    // the archive says. It is still checked on macOS, where APFS would
    // merge them.
    let check_folding = !options.platform_specific || cfg!(target_os = "macos");
    let mut folded: BTreeMap<String, String> = BTreeMap::new();
    for (_, stripped) in kept.iter().filter(|_| check_folding) {
        for end in 1..=stripped.len() {
            let prefix = stripped[..end].join("/");
            match folded.get(&folded_name(&prefix)) {
                Some(other) if *other != prefix => {
                    return Err(err(format!(
                        "archive entries {other:?} and {prefix:?} are one name on a case-insensitive or normalization-insensitive filesystem; refusing to extract"
                    )));
                }
                Some(_) => {}
                None => {
                    folded.insert(folded_name(&prefix), prefix);
                }
            }
        }
    }
    // Symlink names are held folded, so a target that walks through `S`
    // is caught by a link named `s`: on APFS they are the same link.
    let symlinks: BTreeSet<String> = kept
        .iter()
        .filter(|(entry, _)| entry.kind == EntryKind::Symlink)
        .map(|(_, stripped)| folded_name(&stripped.join("/")))
        .collect();
    for (entry, stripped) in &kept {
        for end in 1..stripped.len() {
            let ancestor = stripped[..end].join("/");
            if symlinks.contains(&folded_name(&ancestor)) {
                return Err(err(format!(
                    "archive entry {:?} is written through symlink {:?}",
                    entry.name, ancestor
                )));
            }
        }
        if entry.kind == EntryKind::Symlink {
            let target = entry.link.as_deref().unwrap_or("");
            symlink_contained(stripped, target, &symlinks).map_err(|reason| {
                err(format!(
                    "archive symlink {:?} -> {:?}: {reason}",
                    entry.name, target
                ))
            })?;
        }
    }
    Ok(())
}

/// An approximation of the form under which APFS compares two names:
/// canonically decomposed (NFD, so `é` and `e` plus a combining acute are
/// one), full Unicode case-folded (so `SS` and `ß` meet, as do Turkish
/// dotted/dotless `I` and the Greek final forms), and decomposed again in
/// case folding composed anything. Go's module zip refuses case collisions
/// the same way; it does not normalize.
fn folded_name(name: &str) -> String {
    use caseless::Caseless;
    use unicode_normalization::UnicodeNormalization;
    let decomposed: String = name.nfd().collect();
    let folded: String = decomposed.chars().default_case_fold().collect();
    folded.nfd().collect()
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

/// A symlink at `stripped` is contained when its target, resolved lexically
/// from the link's own directory, never rises above the destination root.
///
/// Lexical resolution is only trustworthy while it agrees with what the
/// filesystem would do, and the two disagree exactly when the walk passes
/// *through* another symlink: `..` applied to an unresolved name pops the
/// name, while `..` applied to the real path pops wherever that symlink
/// pointed. Traversing an archive-defined symlink is therefore refused
/// outright, which restores the agreement instead of trying to model it.
///
/// A symlink as the target's *final* component is not a traversal — nothing
/// is resolved through it here — and it is contained by its own validation,
/// so composing the two stays inside.
/// `symlinks` holds the archive's symlink names in `folded_name` form.
fn symlink_contained(
    stripped: &[&str],
    target: &str,
    symlinks: &BTreeSet<String>,
) -> Result<(), String> {
    if target.is_empty() {
        return Err("empty symlink target".into());
    }
    if target.starts_with('/') {
        return Err("absolute symlink target".into());
    }
    let mut path: Vec<&str> = stripped[..stripped.len().saturating_sub(1)].to_vec();
    let components: Vec<&str> = target.split('/').collect();
    for (index, component) in components.iter().enumerate() {
        match *component {
            "" | "." => {}
            ".." => {
                if path.is_empty() {
                    return Err("symlink target escapes the destination".into());
                }
                path.pop();
            }
            name => {
                path.push(name);
                if index + 1 < components.len() && symlinks.contains(&folded_name(&path.join("/")))
                {
                    return Err(format!(
                        "symlink target resolves through another symlink in the archive ({:?})",
                        path.join("/")
                    ));
                }
            }
        }
    }
    Ok(())
}

/// List, validate, and extract `archive` into `destination`, returning the
/// validated listing. Nothing is written when validation fails.
#[cfg(test)]
pub fn extract(
    archive: &Path,
    destination: &Path,
    strip: usize,
    compression: Compression,
) -> io::Result<Vec<Entry>> {
    extract_with_options(
        archive,
        destination,
        &ExtractOptions::stripped(strip),
        compression,
    )
}

/// How the delegated `tar -x` writes: how many leading path components it
/// strips, and whether GNU tar applies directory modes after extraction.
///
/// `delay_directory_restore` is npm's `--delay-directory-restore`: registry
/// tarballs packed by arbitrary publishers carry directories with mode
/// 0666, and GNU tar creates such a directory 0666, then cannot open its
/// children. Applying directory modes after extraction keeps the tree
/// identical on both tars (bsdtar descends anyway). It is a GNU-only flag,
/// so on macOS it changes nothing.
///
/// `platform_specific` marks a per-platform build (a toolchain, a conda
/// package, tog's own release binary): an archive pinned for one platform
/// and extracted only there. For those the case and normalization
/// collision check runs only on a case-insensitive host (macOS), because
/// on Linux both names are simply two files and no other platform ever
/// sees the archive. python-build-standalone's Linux CPython ships
/// `share/terminfo/2/2621A` beside `2621a`, and conda-forge's Linux
/// ncurses `share/terminfo/N` beside `n`. Registry packages (npm, sdists,
/// crates, Hex) install on every platform and keep the check everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractOptions {
    pub strip: usize,
    pub delay_directory_restore: bool,
    pub platform_specific: bool,
}

impl ExtractOptions {
    /// A platform-neutral archive: the collision check runs everywhere.
    pub fn stripped(strip: usize) -> Self {
        ExtractOptions {
            strip,
            delay_directory_restore: false,
            platform_specific: false,
        }
    }

    /// A per-platform build, extracted only on the platform it was built for.
    pub fn platform_build(strip: usize) -> Self {
        ExtractOptions {
            platform_specific: true,
            ..ExtractOptions::stripped(strip)
        }
    }
}

/// List, validate, and extract with full options, returning the validated
/// listing. Nothing is written when validation fails.
pub fn extract_with_options(
    archive: &Path,
    destination: &Path,
    options: &ExtractOptions,
    compression: Compression,
) -> io::Result<Vec<Entry>> {
    let entries = list(archive, compression)?;
    extract_validated_with_options(archive, destination, options, compression, &entries)?;
    Ok(entries)
}

/// Store-consuming list, validate, and extract with full options, returning
/// the validated listing. The caller's activity lease covers the listing,
/// the validation, and the extraction child. Nothing is written when
/// validation fails.
pub(crate) fn extract_with_activity_and_options(
    activity: &StoreActivity,
    archive: &Path,
    destination: &Path,
    options: &ExtractOptions,
    compression: Compression,
) -> io::Result<Vec<Entry>> {
    let entries = list_with_activity(activity, archive, compression)?;
    extract_validated_with_activity_and_options(
        activity,
        archive,
        destination,
        options,
        compression,
        &entries,
    )?;
    Ok(entries)
}

/// Extract an archive whose listing the caller already obtained from `list`
/// (so it could check layout first). The listing is validated again here;
/// the check is cheap and this is the function that writes.
pub fn extract_validated(
    archive: &Path,
    destination: &Path,
    strip: usize,
    compression: Compression,
    entries: &[Entry],
) -> io::Result<()> {
    extract_validated_with_options(
        archive,
        destination,
        &ExtractOptions::stripped(strip),
        compression,
        entries,
    )
}

/// Extract a listed archive with full options, validating the listing again.
pub fn extract_validated_with_options(
    archive: &Path,
    destination: &Path,
    options: &ExtractOptions,
    compression: Compression,
    entries: &[Entry],
) -> io::Result<()> {
    extract_validated_inner(archive, destination, options, compression, entries, None)
}

pub(crate) fn extract_validated_with_activity(
    activity: &StoreActivity,
    archive: &Path,
    destination: &Path,
    strip: usize,
    compression: Compression,
    entries: &[Entry],
) -> io::Result<()> {
    extract_validated_inner(
        archive,
        destination,
        &ExtractOptions::stripped(strip),
        compression,
        entries,
        Some(activity),
    )
}

pub(crate) fn extract_validated_with_activity_and_options(
    activity: &StoreActivity,
    archive: &Path,
    destination: &Path,
    options: &ExtractOptions,
    compression: Compression,
    entries: &[Entry],
) -> io::Result<()> {
    extract_validated_inner(
        archive,
        destination,
        options,
        compression,
        entries,
        Some(activity),
    )
}

/// Read one regular-file member's bytes without writing anything to disk:
/// the `tar -xO` use (a manifest read out of an sdist) without a second
/// tar invocation whose flags the environment could shift. The archive is
/// still listed and cross-checked first, so the bytes come from the same
/// modelled stream an extraction would see. `member` is the exact stored
/// name from `list`; `cap` bounds the member's declared size.
pub fn read_member(
    archive: &Path,
    compression: Compression,
    member: &str,
    cap: u64,
) -> io::Result<Vec<u8>> {
    read_member_inner(archive, compression, member, cap, None)
}

/// Store-consuming single-member read. The caller's activity lease is
/// borrowed for the whole read, so GC cannot observe the store as idle.
pub(crate) fn read_member_with_activity(
    activity: &StoreActivity,
    archive: &Path,
    compression: Compression,
    member: &str,
    cap: u64,
) -> io::Result<Vec<u8>> {
    read_member_inner(archive, compression, member, cap, Some(activity))
}

fn read_member_inner(
    archive: &Path,
    compression: Compression,
    member: &str,
    cap: u64,
    activity: Option<&StoreActivity>,
) -> io::Result<Vec<u8>> {
    // The listing cross-checks the header reader against the tar that
    // would perform an extraction; a disagreement refuses before any
    // member bytes are trusted.
    match activity {
        Some(activity) => list_with_activity(activity, archive, compression)?,
        None => list(archive, compression)?,
    };
    let file = io::BufReader::new(File::open(archive)?);
    let (_, wanted) = match compression {
        Compression::None => read_entries(file, Some((member, cap)))?,
        Compression::Gzip => read_entries(
            io::BufReader::new(flate2::read::MultiGzDecoder::new(file)),
            Some((member, cap)),
        )?,
        Compression::Bzip2 => read_entries(
            io::BufReader::new(bzip2::read::BzDecoder::new(file)),
            Some((member, cap)),
        )?,
        Compression::Xz => read_entries(
            io::BufReader::new(liblzma::read::XzDecoder::new(file)),
            Some((member, cap)),
        )?,
    };
    wanted.ok_or_else(|| {
        err(format!(
            "archive {} has no member {member:?}",
            archive.display()
        ))
    })
}

/// Pack `work`'s explicit null-delimited `list` into `uncompressed` with
/// the deterministic ustar layout git sources publish: the one `tar -c`
/// invocation in the tree, kept here so every `/usr/bin/tar` argv lives
/// in this module. `is_macos` picks bsdtar's owner and list flags over
/// GNU's; the packed bytes are identical either way (zeroed owners, ustar
/// headers, sorted null-delimited input).
pub(crate) fn pack_ustar_with_activity(
    activity: &StoreActivity,
    uncompressed: &Path,
    work: &Path,
    list: &Path,
    is_macos: bool,
) -> io::Result<()> {
    let owner_flags: &[&str] = if is_macos {
        // bsdtar
        &["--uid", "0", "--gid", "0", "--numeric-owner"]
    } else {
        // GNU tar
        &["--owner=0", "--group=0", "--numeric-owner"]
    };
    let list_flags: &[&str] = if is_macos {
        // bsdtar treats --null input as verbatim; it has no GNU
        // --verbatim-files-from option.
        &["--null"]
    } else {
        &["--null", "--verbatim-files-from"]
    };
    let mut tar = tar_command();
    tar.args(["-cf"])
        .arg(uncompressed)
        .args(["--format=ustar", "--no-recursion"])
        .args(owner_flags)
        .args(list_flags)
        .arg("-C")
        .arg(work)
        .arg("-T")
        .arg(list);
    let status = crate::kernel::supervise::local_status(&mut tar, activity)?;
    if !status.success() {
        let _ = std::fs::remove_file(uncompressed);
        return Err(err(format!(
            "packing {} failed (tar {status})",
            work.display()
        )));
    }
    Ok(())
}

/// `tar -x` of `archive` into `destination`, with the fixed extraction
/// flags.
fn extract_command(
    archive: &Path,
    destination: &Path,
    options: &ExtractOptions,
    compression: Compression,
) -> Command {
    let mut command = tar_command();
    command
        .args(TAR_EXTRACT_FLAGS)
        .arg(format!("-x{}f", compression.flag()))
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .arg("--strip-components")
        .arg(options.strip.to_string());
    if options.delay_directory_restore && !cfg!(target_os = "macos") {
        command.arg("--delay-directory-restore");
    }
    command
}

fn extract_validated_inner(
    archive: &Path,
    destination: &Path,
    options: &ExtractOptions,
    compression: Compression,
    entries: &[Entry],
    activity: Option<&StoreActivity>,
) -> io::Result<()> {
    validate_with_options(entries, options)?;
    let mut command = extract_command(archive, destination, options, compression);
    let status = status_for(&mut command, activity)
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

// Reviewed site (tests/architecture.rs): `None` arm of `Option<&StoreActivity>`: no store is involved.
#[allow(clippy::disallowed_methods)]
fn status_for(
    command: &mut Command,
    activity: Option<&StoreActivity>,
) -> io::Result<std::process::ExitStatus> {
    match activity {
        Some(activity) => crate::kernel::supervise::local_status(command, activity),
        None => command.status(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::testutil::TempDir;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn entry(kind: EntryKind, name: &str, link: Option<&str>) -> Entry {
        Entry {
            kind,
            name: name.to_string(),
            link: link.map(str::to_string),
        }
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

    // ---- hand-built archives ----------------------------------------------

    fn temp_dir(label: &str) -> TempDir {
        TempDir::named(&format!("archive-{label}"))
    }

    /// Recompute the header checksum over the first block, the way every tar
    /// writer does: the field itself counts as eight spaces.
    fn reseal(mut member: Vec<u8>) -> Vec<u8> {
        member[148..156].copy_from_slice(b"        ");
        let sum: u32 = member[..512].iter().map(|b| *b as u32).sum();
        member[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        member
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
        // Only the types that carry data declare a size; the others are
        // written with an empty payload.
        let size = if matches!(typeflag, b'0' | b'x' | b'g' | b'L' | b'K') {
            data.len()
        } else {
            0
        };
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
        let mut out = reseal(header);
        if !data.is_empty() {
            out.extend_from_slice(data);
            let pad = (512 - data.len() % 512) % 512;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
        out
    }

    /// Set the owner/group *name* fields, which come out of the archive and
    /// are therefore the attacker's to choose.
    fn with_owner_names(mut header: Vec<u8>, uname: &str, gname: &str) -> Vec<u8> {
        assert!(uname.len() < 32 && gname.len() < 32);
        header[265..265 + uname.len()].copy_from_slice(uname.as_bytes());
        header[297..297 + gname.len()].copy_from_slice(gname.as_bytes());
        reseal(header)
    }

    /// Fill the POSIX 155-byte `prefix` field, which tar prepends to the name.
    fn with_prefix(mut member: Vec<u8>, prefix: &str) -> Vec<u8> {
        assert!(prefix.len() < 155);
        member[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        reseal(member)
    }

    /// Rewrite the octal size without touching the data blocks that follow.
    fn with_size_octal(mut member: Vec<u8>, size: u64) -> Vec<u8> {
        member[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        reseal(member)
    }

    /// Rewrite the size in GNU's base-256 form: high bit set on the first
    /// byte, the value big-endian in the remaining eleven.
    fn with_size_base256(mut member: Vec<u8>, size: u64) -> Vec<u8> {
        let mut field = [0u8; 12];
        field[0] = 0x80;
        for (offset, byte) in size.to_be_bytes().iter().enumerate() {
            field[4 + offset] = *byte;
        }
        member[124..136].copy_from_slice(&field);
        reseal(member)
    }

    /// Replace the magic and version bytes (old GNU headers use `ustar  \0`).
    fn with_magic(mut member: Vec<u8>, magic: &[u8; 8]) -> Vec<u8> {
        member[257..265].copy_from_slice(magic);
        reseal(member)
    }

    /// Put arbitrary bytes in the 100-byte name field.
    fn with_raw_name(mut member: Vec<u8>, name: &[u8]) -> Vec<u8> {
        assert!(name.len() < 100);
        member[..100].fill(0);
        member[..name.len()].copy_from_slice(name);
        reseal(member)
    }

    /// One PAX record, `"%d %s=%s\n"`, whose length counts its own digits.
    fn pax_record(key: &str, value: &str) -> String {
        let body = format!(" {key}={value}\n");
        let mut digits = 1;
        loop {
            let total = digits + body.len();
            if total.to_string().len() == digits {
                return format!("{total}{body}");
            }
            digits += 1;
        }
    }

    fn pax(records: &[(&str, &str)]) -> Vec<u8> {
        pax_raw(b'x', pax_body(records).as_bytes())
    }

    fn pax_global(records: &[(&str, &str)]) -> Vec<u8> {
        pax_raw(b'g', pax_body(records).as_bytes())
    }

    fn pax_body(records: &[(&str, &str)]) -> String {
        records
            .iter()
            .map(|(key, value)| pax_record(key, value))
            .collect()
    }

    fn pax_raw(typeflag: u8, data: &[u8]) -> Vec<u8> {
        let name = if typeflag == b'g' {
            "pax_global_header"
        } else {
            "PaxHeaders/member"
        };
        ustar(name, typeflag, "", data)
    }

    /// A GNU `L`/`K` block: the value, NUL-terminated, as the member data.
    fn gnu_long(typeflag: u8, value: &str) -> Vec<u8> {
        let mut data = value.as_bytes().to_vec();
        data.push(0);
        with_magic(ustar("././@LongLink", typeflag, "", &data), b"ustar  \0")
    }

    fn joined(members: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for member in members {
            bytes.extend_from_slice(member);
        }
        bytes.extend(std::iter::repeat_n(0u8, 1024));
        bytes
    }

    fn write_tar(path: &Path, members: &[Vec<u8>]) {
        fs::write(path, joined(members)).unwrap();
    }

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    /// Write `bytes` as a `.tar` and list it through the public entry point,
    /// so the header reader and the `tar -t` cross-check both run.
    fn list_bytes(label: &str, bytes: &[u8]) -> io::Result<Vec<Entry>> {
        let temp = temp_dir(label);
        let archive = temp.0.join("a.tar");
        fs::write(&archive, bytes).unwrap();
        list(&archive, Compression::None)
    }

    fn list_members(label: &str, members: &[Vec<u8>]) -> io::Result<Vec<Entry>> {
        list_bytes(label, &joined(members))
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn refusal(label: &str, members: &[Vec<u8>], needle: &str) {
        let error = list_members(label, members).expect_err(needle);
        assert!(
            error.to_string().contains(needle),
            "{needle:?} not in {error}"
        );
    }

    /// One tar runs everywhere: the host's `/usr/bin/tar`, taking no
    /// platform argument, because the command line is fixed by the
    /// object-identity contract and the binary is at the same path on both
    /// supported hosts. The builder is also the one place the child's
    /// environment is scrubbed, so the user cannot add extraction flags or
    /// reshape tar's output through the locale.
    #[test]
    fn tar_command_is_the_hosts_tar_with_a_scrubbed_environment() {
        // The signature is the guard: a platform argument would not compile.
        let command = tar_command();
        assert_eq!(command.get_program(), "/usr/bin/tar");
        let env: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for removed in ["TAR_OPTIONS", "LC_TIME"] {
            assert!(
                env.contains(&(removed.to_string(), None)),
                "{removed} is not cleared: {env:?}"
            );
        }
        for (key, value) in [("LC_ALL", "C"), ("LANG", "C")] {
            assert!(
                env.contains(&(key.to_string(), Some(value.to_string()))),
                "{key} is not pinned to {value}: {env:?}"
            );
        }
    }

    /// The extraction tells tar to restore nothing an object's identity does
    /// not cover: extended attributes and ACLs on both tars, BSD file flags
    /// and AppleDouble metadata on bsdtar, which restores all four by
    /// default as root. The listing carries none of those flags: it writes
    /// nothing for them to act on, and bsdtar documents each of them for
    /// other modes, so on `-t` they could only fail.
    #[test]
    fn extraction_tells_tar_to_restore_no_metadata_and_the_listing_carries_no_such_flag() {
        let archive = Path::new("/tmp/does-not-matter.tar");
        let args = |command: &Command| -> Vec<String> {
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };
        let list_args = args(&list_command(archive, Compression::Gzip));
        assert_eq!(
            list_args[..2],
            ["--numeric-owner".to_string(), "-tzf".to_string()],
            "{list_args:?}"
        );

        let extract_args = args(&extract_command(
            archive,
            Path::new("/tmp/dest"),
            &ExtractOptions::stripped(1),
            Compression::Gzip,
        ));
        for flag in ["--numeric-owner", "--no-xattrs", "--no-acls"] {
            assert!(
                extract_args.contains(&flag.to_string()),
                "{flag} missing: {extract_args:?}"
            );
        }
        for flag in ["--no-fflags", "--no-mac-metadata"] {
            assert_eq!(
                extract_args.contains(&flag.to_string()),
                cfg!(target_os = "macos"),
                "{flag}: {extract_args:?}"
            );
        }
        // The flags come before the mode, so tar reads them for it.
        assert_eq!(
            extract_args.iter().position(|arg| arg == "-xzf"),
            Some(TAR_EXTRACT_FLAGS.len()),
            "{extract_args:?}"
        );
    }

    /// An archive that carries an extended attribute extracts without it.
    /// GNU tar drops xattrs on extraction unless asked, so on Linux this
    /// cannot notice `--no-xattrs` going missing: the argv test above is
    /// what guards the flag. Here it proves the host tar accepts the flags
    /// in `-x` mode on a real archive, and fails if the command line ever
    /// asks for `--xattrs`. It only runs on Linux, so bsdtar's restore-by-
    /// default behaviour on macOS is covered by the argv test alone.
    #[test]
    #[cfg(target_os = "linux")]
    fn extracted_files_carry_no_extended_attributes() {
        use std::ffi::CString;
        let temp = temp_dir("xattr");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("pkg")).unwrap();
        let file = source.join("pkg/tool");
        fs::write(&file, b"tool").unwrap();
        let path = CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
        let key = CString::new("user.tog").unwrap();
        // SAFETY: both strings are NUL-terminated and outlive the call; the
        // value pointer and length describe a live byte slice.
        let set =
            unsafe { libc::setxattr(path.as_ptr(), key.as_ptr(), b"1".as_ptr().cast(), 1, 0) };
        if set != 0 {
            let error = io::Error::last_os_error();
            // Only a filesystem without user xattrs may skip, and it says so.
            assert_eq!(
                error.raw_os_error(),
                Some(libc::ENOTSUP),
                "setxattr failed: {error}"
            );
            eprintln!("skip extracted_files_carry_no_extended_attributes: {error}");
            return;
        }
        let archive = temp.0.join("pkg.tar");
        assert!(crate::kernel::testutil::tar_create()
            .args(["--format=posix", "--xattrs", "-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("pkg")
            .status()
            .unwrap()
            .success());
        let bytes = fs::read(&archive).unwrap();
        assert!(
            bytes.windows(21).any(|w| w == b"SCHILY.xattr.user.tog"),
            "the fixture archive carries no xattr record"
        );
        let destination = temp.0.join("out");
        fs::create_dir_all(&destination).unwrap();
        let entries = extract(&archive, &destination, 1, Compression::None).unwrap();
        assert_eq!(names(&entries), vec!["pkg/", "pkg/tool"]);
        let out = CString::new(destination.join("tool").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: as above; a null buffer of length zero only queries the size.
        let got = unsafe { libc::getxattr(out.as_ptr(), key.as_ptr(), std::ptr::null_mut(), 0) };
        assert_eq!(got, -1, "the extracted file carries the archive's xattr");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA)
        );
    }

    // ---- the header reader -------------------------------------------------

    /// Owner and group names are archive content, so an attacker chooses
    /// them. The previous listing parser skipped a fixed number of
    /// whitespace columns in `tar -tv` output, and a name containing a space
    /// added one, shifting the date into the name the parser returned. The
    /// reader takes the name from the header field, which no other field can
    /// reach into, so the owner names are simply not part of the answer.
    #[test]
    fn owner_names_containing_spaces_cannot_shift_the_parsed_name() {
        let scratch = TempDir::named("archive-owner");
        let base = scratch.0.clone();
        let archive = base.join("evil.tar");
        write_tar(
            &archive,
            &[with_owner_names(
                ustar("../escape", b'0', "", b"pwn\n"),
                "ro ot",
                "gr oup",
            )],
        );

        // The name must survive parsing intact: `..` still reads as `..`.
        let entries = list(&archive, Compression::None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].name, "../escape",
            "owner names shifted the parsed name"
        );

        // And containment must therefore refuse it.
        let error = validate(&entries, 0).unwrap_err();
        assert!(error.to_string().contains("escape"), "{error}");

        let destination = base.join("dest");
        fs::create_dir_all(&destination).unwrap();
        assert!(extract(&archive, &destination, 0, Compression::None).is_err());
        assert!(
            !base.join("escape").exists(),
            "a member escaped the destination"
        );
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }

    #[test]
    fn a_posix_prefix_field_joins_the_stored_name() {
        let entries = list_members(
            "prefix",
            &[
                with_prefix(ustar("pkg/", b'5', "", b""), "deep/nested/root"),
                with_prefix(ustar("bin/tool", b'0', "", b"x"), "deep/nested/root/pkg"),
            ],
        )
        .unwrap();
        assert_eq!(
            names(&entries),
            vec!["deep/nested/root/pkg/", "deep/nested/root/pkg/bin/tool"]
        );
        // A GNU-magic header has no prefix field at all: the same bytes must
        // then list as the bare name, and tar must agree.
        let entries = list_members(
            "prefix-gnu",
            &[with_magic(
                with_prefix(ustar("pkg/bin/tool", b'0', "", b"x"), "ignored"),
                b"ustar  \0",
            )],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/bin/tool"]);
    }

    #[test]
    fn gnu_long_names_and_long_links_are_read_verbatim() {
        let long_name = format!("pkg/{}/file.txt", "n".repeat(130));
        let long_target = format!("../{}/target", "t".repeat(130));
        let entries = list_members(
            "gnu-long",
            &[
                gnu_long(b'L', &long_name),
                ustar(&long_name[..99], b'0', "", b"x"),
                gnu_long(b'K', &long_target),
                gnu_long(b'L', &format!("{long_name}.link")),
                ustar(&long_name[..99], b'2', &long_target[..99], b""),
            ],
        )
        .unwrap();
        assert_eq!(
            names(&entries),
            vec![long_name.as_str(), &format!("{long_name}.link")]
        );
        assert_eq!(entries[1].kind, EntryKind::Symlink);
        assert_eq!(entries[1].link.as_deref(), Some(long_target.as_str()));
    }

    #[test]
    fn pax_path_linkpath_and_size_override_the_header_fields() {
        // The header claims no data, PAX says five bytes, and five bytes of
        // data (one padded block) follow. Listing the member after it proves
        // the reader skipped the block PAX described, not the one the octal
        // size described.
        let entries = list_members(
            "pax-size",
            &[
                pax(&[("path", "pkg/real-name"), ("size", "5")]),
                with_size_octal(ustar("pkg/wrong", b'0', "", b"hello"), 0),
                ustar("pkg/after", b'0', "", b"after"),
            ],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/real-name", "pkg/after"]);

        // PAX `path` and `linkpath` replace the header's name and link fields.
        let entries = list_members(
            "pax-path",
            &[
                pax(&[
                    ("path", "pkg/from-pax"),
                    ("linkpath", "deep/target"),
                    ("mtime", "1700000000"),
                    ("uname", "root"),
                    ("SCHILY.fflags", "none"),
                ]),
                ustar("pkg/header-name", b'2', "header-target", b""),
            ],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/from-pax"]);
        assert_eq!(entries[0].link.as_deref(), Some("deep/target"));
    }

    /// One PAX record with a raw byte value, for values that are not text.
    fn pax_record_bytes(key: &str, value: &[u8]) -> Vec<u8> {
        let mut body = format!(" {key}=").into_bytes();
        body.extend_from_slice(value);
        body.push(b'\n');
        let mut digits = 1;
        while (digits + body.len()).to_string().len() != digits {
            digits += 1;
        }
        let mut record = (digits + body.len()).to_string().into_bytes();
        record.extend(body);
        record
    }

    /// PAX values are bytes until a key the reader acts on decodes them.
    /// macOS tar stores extended attributes such as `com.apple.provenance`
    /// as `SCHILY.xattr.*` records whose values are raw bytes, and nothing
    /// says another metadata record cannot be; the reader never reads
    /// those bytes, so they need not be text. `path`, `linkpath` and `size`
    /// become the name, the target and the data length, so they must be.
    /// `SCHILY.realsize`, which tar extracts a member at, is refused.
    #[test]
    fn pax_values_are_bytes_and_only_the_keys_the_reader_uses_must_be_text() {
        let binary = b"\x01\x02\0D\x18\xff\xfe";
        for key in [
            "SCHILY.xattr.com.apple.provenance",
            "LIBARCHIVE.xattr.com.apple.quarantine",
            "SCHILY.fflags",
            "uname",
            "comment",
        ] {
            let record = pax_record_bytes(key, binary);
            let entries = list_members(
                &format!("pax-binary-{}", key.to_lowercase().replace('.', "-")),
                &[pax_raw(b'x', &record), ustar("pkg/tog", b'0', "", b"x")],
            )
            .unwrap();
            assert_eq!(names(&entries), vec!["pkg/tog"], "{key}");
        }

        for (key, value) in [
            ("path", &b"pkg/\xff"[..]),
            ("linkpath", b"tar\xffget"),
            ("size", b"1\xff"),
        ] {
            let record = pax_record_bytes(key, value);
            refusal(
                &format!("pax-binary-{key}"),
                &[pax_raw(b'x', &record), ustar("pkg/x", b'2', "t", b"")],
                "not UTF-8",
            );
        }

        refusal(
            "pax-realsize",
            &[
                pax(&[("SCHILY.realsize", "100000")]),
                ustar("pkg/f", b'0', "", b"x"),
            ],
            "would resize the member",
        );
        refusal(
            "pax-global-realsize",
            &[
                pax_global(&[("SCHILY.realsize", "100000")]),
                ustar("pkg/f", b'0', "", b"x"),
            ],
            "SCHILY.realsize",
        );
    }

    #[test]
    fn member_data_past_the_budget_is_refused_before_anything_is_written() {
        // A PAX size overrides the header size, so one member can declare
        // past the budget while carrying a byte of real data: the refusal
        // names the budget, not a short stream, and the destination stays
        // empty.
        let size = (MAX_ARCHIVE_BYTES + 1).to_string();
        let mut member = pax(&[("path", "pkg/big"), ("size", size.as_str())]);
        member.extend(ustar("pkg/big", b'0', "", b"x"));
        let temp = temp_dir("budget");
        let archive = temp.0.join("a.tar");
        write_tar(&archive, &[member]);
        let dest = temp.0.join("dest");
        fs::create_dir(&dest).unwrap();
        for error in [
            list(&archive, Compression::None).expect_err("budget"),
            extract(&archive, &dest, 0, Compression::None).expect_err("budget"),
        ] {
            assert!(error.to_string().contains("byte budget"), "{error}");
        }
        assert!(fs::read_dir(&dest).unwrap().next().is_none());
        // Accumulation across members refuses the same way.
        let mut budget = Budget::default();
        budget.add(MAX_ARCHIVE_BYTES, "test").unwrap();
        let error = budget.add(1, "test").expect_err("budget");
        assert!(error.to_string().contains("byte budget"), "{error}");
    }

    #[test]
    fn read_member_returns_one_members_bytes() {
        let temp = temp_dir("read-member");
        let archive = temp.0.join("a.tar");
        write_tar(
            &archive,
            &[
                ustar("pkg/pyproject.toml", b'0', "", b"[build-system]\n"),
                ustar("pkg/other.txt", b'0', "", b"other"),
                ustar("pkg/dir", b'5', "", b""),
            ],
        );
        let bytes =
            read_member(&archive, Compression::None, "pkg/pyproject.toml", 16 << 20).unwrap();
        assert_eq!(bytes, b"[build-system]\n");
        let error =
            read_member(&archive, Compression::None, "pkg/missing", 16 << 20).expect_err("missing");
        assert!(error.to_string().contains("has no member"), "{error}");
        let error = read_member(&archive, Compression::None, "pkg/dir", 16 << 20).expect_err("dir");
        assert!(error.to_string().contains("not a regular file"), "{error}");
        let error = read_member(&archive, Compression::None, "pkg/other.txt", 2).expect_err("cap");
        assert!(error.to_string().contains("read cap"), "{error}");
    }

    #[test]
    fn delay_directory_restore_is_a_gnu_only_extraction_flag() {
        let archive = Path::new("/tmp/does-not-matter.tar");
        let args = |command: &Command| -> Vec<String> {
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };
        let delayed = ExtractOptions {
            strip: 1,
            delay_directory_restore: true,
            ..ExtractOptions::stripped(1)
        };
        let delayed_args = args(&extract_command(
            archive,
            Path::new("/tmp/dest"),
            &delayed,
            Compression::Gzip,
        ));
        assert_eq!(
            delayed_args.contains(&"--delay-directory-restore".to_string()),
            !cfg!(target_os = "macos"),
        );
        let plain_args = args(&extract_command(
            archive,
            Path::new("/tmp/dest"),
            &ExtractOptions::stripped(1),
            Compression::Gzip,
        ));
        assert!(
            !plain_args.contains(&"--delay-directory-restore".to_string()),
            "{plain_args:?}"
        );
    }

    #[test]
    fn matching_gnu_and_pax_extensions_are_accepted_in_either_order() {
        for reverse in [false, true] {
            let mut members = vec![
                gnu_long(b'L', "pkg/link"),
                gnu_long(b'K', "target"),
                pax(&[("path", "pkg/link"), ("linkpath", "target")]),
            ];
            if reverse {
                members.reverse();
            }
            members.push(ustar("pkg/header-name", b'2', "header-target", b""));
            let entries = list_members("matching-extensions", &members).unwrap();
            assert_eq!(names(&entries), vec!["pkg/link"]);
            assert_eq!(entries[0].link.as_deref(), Some("target"));
        }
    }

    #[test]
    fn conflicting_gnu_and_pax_extensions_are_refused_before_writes() {
        let temp = temp_dir("conflicting-extensions");
        let sentinel = temp.0.join("outside-sentinel");
        fs::write(&sentinel, b"untouched").unwrap();
        let destination = temp.0.join("dest");
        fs::create_dir_all(&destination).unwrap();
        for (kind, key, value) in [(b'L', "path", "pkg/link"), (b'K', "linkpath", "benign")] {
            for reverse in [false, true] {
                let mut extensions = vec![
                    gnu_long(kind, "../../outside-sentinel"),
                    pax(&[(key, value)]),
                ];
                if reverse {
                    extensions.reverse();
                }
                let mut members = vec![
                    ustar("pkg/", b'5', "", b""),
                    ustar("pkg/benign", b'0', "", b"hello"),
                ];
                members.extend(extensions);
                members.push(ustar("pkg/link", b'2', "benign", b""));
                let archive = temp.0.join("conflict.tar");
                write_tar(&archive, &members);
                let error = extract(&archive, &destination, 1, Compression::None)
                    .expect_err("conflicting extensions must be refused before extraction");
                assert!(
                    error
                        .to_string()
                        .contains(&format!("conflicting GNU and PAX {key}")),
                    "{key}, reverse={reverse}: {error}"
                );
                assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
                assert_eq!(fs::read(&sentinel).unwrap(), b"untouched");
            }
        }
    }

    #[test]
    fn malformed_and_unmodelled_pax_records_are_refused() {
        // The length must count the whole record; 5 does not.
        refusal(
            "pax-badlen",
            &[
                pax_raw(b'x', b"5 path=pkg/x\n"),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "does not match its data",
        );
        // A sparse map describes a layout this reader does not model.
        refusal(
            "pax-sparse",
            &[
                pax(&[("GNU.sparse.map", "0,5")]),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "GNU.sparse.map",
        );
        // So does a header charset, which would make names raw bytes.
        refusal(
            "pax-hdrcharset",
            &[
                pax(&[("hdrcharset", "BINARY")]),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "hdrcharset",
        );
        // A key neither tar acts on is still a layout the reader does not
        // model: refused rather than ignored, a second guard behind the
        // extraction flags.
        refusal(
            "pax-unknown",
            &[
                pax(&[("SUN.holesdata", "0:5")]),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "unmodelled key \"SUN.holesdata\"",
        );
        // `charset` describes the data, which tar does not convert.
        let entries = list_members(
            "pax-charset",
            &[
                pax(&[("charset", "ISO-IR 10646 2000 UTF-8")]),
                ustar("pkg/x", b'0', "", b"x"),
            ],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/x"]);
        // A global header may carry the same metadata, bytes and all.
        let mut global = pax_record_bytes("SCHILY.xattr.user.tog", b"\xff\x00");
        global.extend(pax_record("charset", "BINARY").into_bytes());
        let entries = list_members(
            "pax-global-bytes",
            &[pax_raw(b'g', &global), ustar("pkg/x", b'0', "", b"x")],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/x"]);
        // A size with a sign parses in Rust, reads as zero in bsdtar and is
        // an error in GNU tar: three readers, three streams. Digits only.
        for size in ["+5", "-5", " 5", "5 ", ""] {
            refusal(
                &format!(
                    "pax-size-{}",
                    size.trim().replace('+', "plus").replace('-', "minus")
                ),
                &[pax(&[("size", size)]), ustar("pkg/x", b'0', "", b"x")],
                "not a decimal number",
            );
        }
        // A record with no `=` is not a record.
        refusal(
            "pax-noeq",
            &[
                pax_raw(b'x', b"9 nokey\n\n"),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "no \"=\"",
        );
        // An extended header that names no member is a truncated archive.
        refusal(
            "pax-dangling",
            &[pax(&[("path", "pkg/ghost")])],
            "names no member",
        );
    }

    #[test]
    fn a_global_header_is_accepted_only_when_it_cannot_rename() {
        let entries = list_members(
            "global-ok",
            &[
                pax_global(&[("comment", "built by hand"), ("mtime", "1700000000")]),
                ustar("pkg/x", b'0', "", b"x"),
            ],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/x"]);
        refusal(
            "global-path",
            &[
                pax_global(&[("path", "pkg/renamed")]),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "would rename or resize members",
        );
    }

    #[test]
    fn a_base_256_size_is_read_and_one_past_the_stream_is_truncation() {
        let entries = list_members(
            "base256",
            &[
                with_size_base256(ustar("pkg/big", b'0', "", b"hello"), 5),
                ustar("pkg/after", b'0', "", b"after"),
            ],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/big", "pkg/after"]);
        refusal(
            "base256-huge",
            &[with_size_base256(
                ustar("pkg/big", b'0', "", b"hello"),
                1 << 40,
            )],
            "byte budget",
        );
        // A negative base-256 size is not a size.
        let mut member = ustar("pkg/big", b'0', "", b"hello");
        member[124..136].copy_from_slice(&[0xffu8; 12]);
        refusal("base256-negative", &[reseal(member)], "base-256 size");
    }

    #[test]
    fn a_truncated_archive_is_refused_and_a_lone_zero_block_ends_the_listing() {
        let member = ustar("pkg/x", b'0', "", b"hello");
        // No end-of-archive block at all.
        let error = list_bytes("trunc-end", &member).expect_err("truncated");
        assert!(
            error.to_string().contains("no end-of-archive block"),
            "{error}"
        );
        // A header cut in half.
        let mut cut = member.clone();
        cut.extend_from_slice(&ustar("pkg/y", b'0', "", b"y")[..300]);
        let error = list_bytes("trunc-header", &cut).expect_err("truncated");
        assert!(error.to_string().contains("truncated archive"), "{error}");
        // Data that stops before the size the header declared.
        let short = &joined(&[ustar("pkg/x", b'0', "", b"hello")])[..512];
        let error = list_bytes("trunc-data", short).expect_err("truncated");
        assert!(error.to_string().contains("truncated archive"), "{error}");
        // A single zero block is where both tars stop, so the reader stops
        // there too and lists everything before it.
        let mut lone = member.clone();
        lone.extend(std::iter::repeat_n(0u8, 512));
        let entries = list_bytes("lone-zero", &lone).unwrap();
        assert_eq!(names(&entries), vec!["pkg/x"]);
    }

    #[test]
    fn a_bad_header_checksum_refuses_the_archive() {
        let mut member = ustar("pkg/x", b'0', "", b"hello");
        // Flip a byte in the name *after* sealing, so the stored sum is stale.
        member[0] = b'P';
        refusal("checksum", &[member], "bad header checksum");
    }

    #[test]
    fn control_characters_and_non_utf8_in_names_are_refused() {
        refusal(
            "control-name",
            &[ustar("pkg/a\nb", b'0', "", b"x")],
            "control character",
        );
        refusal(
            "control-link",
            &[ustar("pkg/l", b'2', "tar\u{7}get", b"")],
            "control character",
        );
        refusal(
            "non-utf8",
            &[with_raw_name(ustar("pkg/x", b'0', "", b"x"), b"pkg/\xff")],
            "not UTF-8",
        );
        refusal(
            "empty-target",
            &[ustar("pkg/l", b'2', "", b"")],
            "empty symlink target",
        );
    }

    /// Valid UTF-8 can still lie about itself: a right-to-left override
    /// renders `pkg/\u{202E}txt.exe` as `pkg/exe.txt`, and a zero-width
    /// space makes two names look like one. Both are refused in names and
    /// in link targets.
    #[test]
    fn bidi_controls_and_zero_width_characters_in_names_are_refused() {
        for (label, name, needle) in [
            (
                "rtl-override",
                "pkg/\u{202E}txt.exe",
                "bidirectional control",
            ),
            ("ltr-isolate", "pkg/\u{2066}x", "bidirectional control"),
            ("zero-width-space", "pkg/a\u{200B}b", "invisible"),
            ("zero-width-joiner", "pkg/a\u{200D}b", "invisible"),
            ("bom", "pkg/\u{FEFF}x", "invisible"),
            ("variation-selector", "pkg/a\u{FE0F}", "invisible"),
            ("tag", "pkg/a\u{E0041}", "invisible"),
            ("line-separator", "pkg/a\u{2028}b", "invisible"),
            // `Cf` by category, not by list: neither Arabic number sign
            // nor the Syriac abbreviation mark was in the old explicit
            // set, and both must still refuse.
            ("arabic-number-sign", "pkg/a\u{0600}b", "invisible"),
            ("syriac-abbrev", "pkg/a\u{070F}b", "invisible"),
            ("soft-hyphen", "pkg/a\u{00AD}b", "invisible"),
            ("interlinear-anchor", "pkg/a\u{FFF9}b", "invisible"),
            ("language-tag", "pkg/a\u{E0001}b", "invisible"),
        ] {
            refusal(label, &[ustar(name, b'0', "", b"x")], needle);
            refusal(
                &format!("{label}-pax"),
                &[pax(&[("path", name)]), ustar("pkg/x", b'0', "", b"x")],
                needle,
            );
        }
        refusal(
            "rtl-link",
            &[ustar("pkg/l", b'2', "tar\u{202E}get", b"")],
            "bidirectional control character in its link target",
        );
        // GNU long names and long links are names too.
        refusal(
            "rtl-gnu-long",
            &[
                gnu_long(b'L', "pkg/\u{202E}txt.exe"),
                ustar("pkg/x", b'0', "", b"x"),
            ],
            "bidirectional control",
        );
        refusal(
            "zero-width-gnu-link",
            &[
                gnu_long(b'K', "tar\u{200B}get"),
                ustar("pkg/l", b'2', "t", b""),
            ],
            "invisible character in its link target",
        );
        // Plain non-ASCII text is still a name.
        let entries = list_members("accented", &[ustar("pkg/caf\u{E9}", b'0', "", b"x")]).unwrap();
        assert_eq!(names(&entries), vec!["pkg/caf\u{E9}"]);
    }

    /// APFS compares names case-insensitively and after Unicode
    /// normalization, so two archive names that differ only there extract
    /// as one file on a Mac and two on Linux. The same archive would
    /// realize two trees; refuse it. Identical names, and names that
    /// `--strip-components` drops, are not collisions.
    #[test]
    fn names_that_fold_together_on_apfs_are_refused() {
        let file = |name: &str| entry(EntryKind::File, name, None);
        let collide = |a: &str, b: &str, strip: usize| {
            let error = validate(&[file(a), file(b)], strip).expect_err("collision");
            assert!(
                error.to_string().contains("one name on a case-insensitive"),
                "{a} vs {b}: {error}"
            );
        };
        collide("pkg/README", "pkg/readme", 0);
        collide("pkg/Caf\u{E9}", "pkg/Cafe\u{301}", 0);
        collide("pkg/Lib/", "pkg/lib", 0);
        // Full case folding, not lowercasing: `SS` and `ß` meet, as do a
        // long `s` and `S` and final and medial sigma. `to_lowercase`
        // leaves every one of these pairs apart.
        collide("pkg/STRASSE", "pkg/stra\u{DF}e", 0);
        collide("pkg/\u{DF}", "pkg/SS", 0);
        collide("pkg/S", "pkg/\u{17F}", 0);
        collide("pkg/\u{3C3}", "pkg/\u{3C2}", 0);
        // Two files in what APFS makes one directory and Linux makes two,
        // with no directory entries to compare.
        collide("pkg/Lib/a", "pkg/lib/b", 0);
        // After stripping one component the two land in the same place.
        collide("a/README", "b/readme", 1);
        // Exact duplicates are tar's last-one-wins on both platforms.
        validate(&[file("pkg/x"), file("pkg/x")], 0).unwrap();
        // Different directories do not fold together.
        validate(&[file("pkg/a/README"), file("pkg/b/readme")], 0).unwrap();
        // Stripped-away entries are never written, so they cannot collide.
        validate(&[file("README"), file("readme")], 1).unwrap();

        // A target that walks through `S` walks through the archive's own
        // symlink `s` on APFS, and `s` points two levels up: refused as a
        // traversal, as it would be with the exact spelling.
        let link = |name: &str, target: &str| entry(EntryKind::Symlink, name, Some(target));
        let error = validate(&[link("p/q/s", "../.."), link("p/q/a", "S/../../..")], 0)
            .expect_err("traversal through a case-folded symlink");
        assert!(
            error
                .to_string()
                .contains("resolves through another symlink"),
            "{error}"
        );
        // A file under a case-folded symlink name is a name collision first:
        // the prefix `p/S` folds onto the link `p/s`.
        let error = validate(&[link("p/s", "."), file("p/S/x")], 0)
            .expect_err("write through a case-folded symlink");
        assert!(
            error.to_string().contains("one name on a case-insensitive"),
            "{error}"
        );
    }

    /// A per-platform build is extracted only on its own platform, so two
    /// names that fold together are two files on Linux and a refusal only
    /// on a case-insensitive host. Linux CPython's terminfo carries
    /// `2621A` beside `2621a`. Containment is unchanged: a write through a
    /// case-folded symlink name is still refused everywhere.
    #[test]
    fn a_platform_build_checks_folding_only_on_a_case_insensitive_host() {
        let file = |name: &str| entry(EntryKind::File, name, None);
        let entries = [
            file("python/share/terminfo/2/2621A"),
            file("python/share/terminfo/2/2621a"),
        ];
        let platform = validate_with_options(&entries, &ExtractOptions::platform_build(1));
        if cfg!(target_os = "macos") {
            let error = platform.expect_err("APFS merges the two names");
            assert!(
                error.to_string().contains("one name on a case-insensitive"),
                "{error}"
            );
        } else {
            platform.unwrap();
        }
        // A platform-neutral archive refuses on every host.
        let error = validate_with_options(&entries, &ExtractOptions::stripped(1))
            .expect_err("portable archives keep the check");
        assert!(
            error.to_string().contains("one name on a case-insensitive"),
            "{error}"
        );
        let link = |name: &str, target: &str| entry(EntryKind::Symlink, name, Some(target));
        validate_with_options(
            &[link("p/s", "."), file("p/S/x")],
            &ExtractOptions::platform_build(0),
        )
        .expect_err("write through a case-folded symlink");
    }

    #[test]
    fn a_directory_or_symlink_carrying_data_is_refused() {
        refusal(
            "dir-size",
            &[with_size_octal(ustar("pkg/", b'5', "", b""), 7)],
            "not a regular file but declares 7 bytes",
        );
        refusal(
            "symlink-size",
            &[with_size_octal(ustar("pkg/l", b'2', "target", b""), 7)],
            "not a regular file but declares 7 bytes",
        );
    }

    #[test]
    fn an_unknown_tar_magic_is_refused() {
        refusal(
            "magic",
            &[with_magic(ustar("pkg/x", b'0', "", b"x"), b"gnutar\0\0")],
            "unknown tar magic",
        );
    }

    #[test]
    fn the_cross_check_refuses_when_the_reader_and_tar_disagree() {
        let archive = Path::new("/tmp/does-not-matter.tar");
        let entries = vec![
            entry(EntryKind::Dir, "pkg/", None),
            entry(EntryKind::File, "pkg/x", None),
        ];
        cross_check(archive, &entries, &["pkg/".into(), "pkg/x".into()]).unwrap();
        // A different name, and a different count, both refuse.
        let error = cross_check(archive, &entries, &["pkg/".into(), "pkg/y".into()])
            .expect_err("disagreement");
        assert!(error.to_string().contains("disagree about entry names"));
        assert!(cross_check(archive, &entries, &["pkg/".into()]).is_err());

        // Under `LC_ALL=C` both tars print a non-ASCII byte as a three-digit
        // octal escape, and GNU tar doubles a literal backslash. Either
        // rendering of the reader's own name agrees; a different name does
        // not, however it is spelled.
        let odd = vec![
            entry(EntryKind::File, "pkg/\u{de}foo.go", None),
            entry(EntryKind::File, "pkg/back\\slash", None),
        ];
        cross_check(
            archive,
            &odd,
            &["pkg/\\303\\236foo.go".into(), "pkg/back\\\\slash".into()],
        )
        .unwrap();
        cross_check(
            archive,
            &odd,
            &["pkg/\u{de}foo.go".into(), "pkg/back\\slash".into()],
        )
        .unwrap();
        assert!(cross_check(
            archive,
            &odd,
            &["pkg/\\303\\237foo.go".into(), "pkg/back\\\\slash".into()]
        )
        .is_err());
    }

    /// A real archive whose member name is not ASCII: the Go toolchain
    /// tarball has one, and the platform tar prints it escaped.
    #[test]
    fn a_non_ascii_member_name_survives_the_cross_check() {
        let entries = list_members(
            "non-ascii",
            &[
                ustar("pkg/", b'5', "", b""),
                ustar("pkg/\u{de}foo.go", b'0', "", b"package main\n"),
            ],
        )
        .unwrap();
        assert_eq!(names(&entries), vec!["pkg/", "pkg/\u{de}foo.go"]);
    }

    // ---- compression -------------------------------------------------------

    fn sample_members() -> Vec<Vec<u8>> {
        vec![
            ustar("pkg/", b'5', "", b""),
            ustar("pkg/bin/", b'5', "", b""),
            ustar("pkg/bin/tool", b'0', "", b"#!/bin/sh\n"),
            ustar("pkg/bin/alias", b'2', "tool", b""),
        ]
    }

    #[test]
    fn gzip_streams_list_identically_to_the_plain_tar() {
        let temp = temp_dir("gzip-inproc");
        let bytes = joined(&sample_members());
        let plain = temp.0.join("pkg.tar");
        fs::write(&plain, &bytes).unwrap();
        let expected = list(&plain, Compression::None).unwrap();

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&bytes).unwrap();
        let single = temp.0.join("pkg.tar.gz");
        fs::write(&single, encoder.finish().unwrap()).unwrap();
        assert_eq!(list(&single, Compression::Gzip).unwrap(), expected);

        // Two concatenated gzip members, which is what `tar -z` accepts and
        // what a plain single-stream decoder would silently truncate.
        let split = 512 * 2;
        let mut concatenated = Vec::new();
        for half in [&bytes[..split], &bytes[split..]] {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(half).unwrap();
            concatenated.extend(encoder.finish().unwrap());
        }
        let multi = temp.0.join("multi.tar.gz");
        fs::write(&multi, &concatenated).unwrap();
        assert_eq!(list(&multi, Compression::Gzip).unwrap(), expected);
    }

    #[test]
    fn an_xz_stream_lists_identically_to_the_plain_tar() {
        let temp = temp_dir("xz-inproc");
        let bytes = joined(&sample_members());
        let plain = temp.0.join("pkg.tar");
        fs::write(&plain, &bytes).unwrap();
        let expected = list(&plain, Compression::None).unwrap();

        let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&bytes).unwrap();
        let compressed = temp.0.join("pkg.tar.xz");
        fs::write(&compressed, encoder.finish().unwrap()).unwrap();
        assert_eq!(list(&compressed, Compression::Xz).unwrap(), expected);
    }

    // ---- end to end with the real tar ------------------------------------

    #[test]
    fn dot_components_do_not_inflate_the_symlink_depth_budget() {
        let scratch = TempDir::named("archive-dot");
        let base = scratch.0.clone();
        let archive = base.join("dot.tar");
        write_tar(&archive, &[ustar("./l", b'2', "../ESCAPED", b"")]);
        let entries = list(&archive, Compression::None).unwrap();
        refused(&entries, 0, "symlink target escapes the destination");

        let padded = base.join("padded.tar");
        write_tar(
            &padded,
            &[ustar("pkg/././././l", b'2', "../../../../ESCAPED", b"")],
        );
        let entries = list(&padded, Compression::None).unwrap();
        refused(&entries, 1, "symlink target escapes the destination");
    }

    #[test]
    fn a_target_resolving_through_another_archive_symlink_is_refused() {
        let up = entry(EntryKind::Symlink, "pkg/x/up", Some(".."));
        let out = entry(EntryKind::Symlink, "pkg/x/out", Some("up/../../ESCAPED"));
        validate(std::slice::from_ref(&up), 0).unwrap();
        refused(
            &[up.clone(), out.clone()],
            0,
            "resolves through another symlink",
        );
        refused(&[out, up], 0, "resolves through another symlink");
    }

    #[test]
    fn a_member_written_through_an_archive_symlink_is_refused() {
        let link = entry(EntryKind::Symlink, "pkg/lib", Some("real"));
        let through = entry(EntryKind::File, "pkg/lib/payload", None);
        refused(&[link, through], 0, "written through symlink");
    }

    #[test]
    fn hostile_members_are_refused_before_anything_is_written() {
        let temp = temp_dir("hostile");
        let sentinel = temp.0.join("outside-sentinel");
        fs::write(&sentinel, b"untouched").unwrap();
        let destination = temp.0.join("dest");
        fs::create_dir_all(&destination).unwrap();
        // Each archive is well-formed except for one hostile member placed
        // AFTER benign members, so a tar that extracted as it read would
        // already have written `pkg/benign` by the time it met the member.
        let benign = [
            ustar("pkg/", b'5', "", b""),
            ustar("pkg/benign", b'0', "", b"hello"),
        ];
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "symlink escapes",
                ustar("pkg/escape", b'2', "../../outside-sentinel", b""),
                "symlink target escapes the destination",
            ),
            (
                "absolute symlink",
                ustar("pkg/abs", b'2', "/etc/passwd", b""),
                "absolute symlink target",
            ),
            (
                "symlink escapes after strip",
                ustar("pkg/up", b'2', "../outside-sentinel", b""),
                "symlink target escapes the destination",
            ),
            (
                "hard link",
                ustar("pkg/hard", b'1', "pkg/benign", b""),
                "hard links are refused",
            ),
            (
                "character device",
                ustar("pkg/dev", b'3', "", b""),
                "is a special file (type '3')",
            ),
            (
                "fifo",
                ustar("pkg/fifo", b'6', "", b""),
                "is a special file (type '6')",
            ),
            (
                "dot-dot name",
                ustar("pkg/../escaped", b'0', "", b"x"),
                "`..` path component",
            ),
            (
                "absolute name",
                ustar("/abs/escaped", b'0', "", b"x"),
                "absolute member name",
            ),
        ];
        for (label, hostile, needle) in cases {
            let archive = temp.0.join(format!("{}.tar", label.replace(' ', "-")));
            let mut members = benign.to_vec();
            members.push(hostile);
            write_tar(&archive, &members);
            let error = extract(&archive, &destination, 1, Compression::None).expect_err(label);
            assert!(
                error.to_string().contains(needle),
                "{label}: {needle:?} not in {error}"
            );
            assert_eq!(
                fs::read_dir(&destination).unwrap().count(),
                0,
                "{label}: something was written into the destination"
            );
            assert_eq!(fs::read(&sentinel).unwrap(), b"untouched", "{label}");
        }
    }

    #[test]
    fn contained_archives_extract_with_strip_and_keep_their_symlinks() {
        let temp = temp_dir("good");
        let archive = temp.0.join("good.tar");
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
        let destination = temp.0.join("dest");
        fs::create_dir_all(&destination).unwrap();
        let entries = extract(&archive, &destination, 1, Compression::None).unwrap();
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
        // tar ignores TAR_OPTIONS from the environment. The planted option
        // is one the fixed command line has no flag to override (an
        // explicit `--strip-components 0` would beat a planted strip), so
        // tar reading it would drop the file.
        let plain = temp.0.join("plain");
        fs::create_dir_all(&plain).unwrap();
        let result = {
            let _env = crate::kernel::policy::test_env_lock();
            std::env::set_var("TAR_OPTIONS", "--exclude=tool");
            let result = extract(&archive, &plain, 0, Compression::None);
            std::env::remove_var("TAR_OPTIONS");
            result
        };
        result.unwrap();
        assert!(plain.join("root/bin/tool").is_file());
    }

    #[test]
    fn real_tar_lists_a_gzip_archive_made_by_tar_itself() {
        let temp = temp_dir("gzip");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("pkg/bin")).unwrap();
        fs::write(source.join("pkg/bin/tool"), b"tool").unwrap();
        std::os::unix::fs::symlink("tool", source.join("pkg/bin/alias")).unwrap();
        let archive = temp.0.join("pkg.tar.gz");
        assert!(crate::kernel::testutil::tar_create()
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("pkg")
            .status()
            .unwrap()
            .success());
        let entries = list(&archive, Compression::Gzip).unwrap();
        let listed: Vec<&str> = names(&entries);
        assert!(listed.contains(&"pkg/bin/tool"), "{listed:?}");
        let alias = entries.iter().find(|e| e.name == "pkg/bin/alias").unwrap();
        assert_eq!(alias.kind, EntryKind::Symlink);
        assert_eq!(alias.link.as_deref(), Some("tool"));
        validate(&entries, 1).unwrap();
    }

    /// The same tree written by tar in each of the formats a real toolchain
    /// tarball arrives in: the reader must list them identically.
    #[test]
    fn real_tar_formats_all_list_the_same_tree() {
        let temp = temp_dir("formats");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("pkg/bin")).unwrap();
        fs::write(source.join("pkg/bin/tool"), b"tool").unwrap();
        std::os::unix::fs::symlink("tool", source.join("pkg/bin/alias")).unwrap();
        let mut listings = Vec::new();
        let formats: &[&str] = match host() {
            Platform::Aarch64AppleDarwin => &["gnutar", "ustar", "pax"],
            Platform::X86_64UnknownLinuxGnu => &["gnu", "ustar", "posix", "oldgnu"],
        };
        for &format in formats {
            let archive = temp.0.join(format!("{format}.tar"));
            assert!(crate::kernel::testutil::tar_create()
                .arg(format!("--format={format}"))
                .arg("-cf")
                .arg(&archive)
                .arg("-C")
                .arg(&source)
                .arg("pkg")
                .status()
                .unwrap()
                .success());
            listings.push((format, list(&archive, Compression::None).unwrap()));
        }
        let (_, first) = &listings[0];
        for (format, listing) in &listings[1..] {
            assert_eq!(listing, first, "--format={format} listed differently");
        }
    }
}

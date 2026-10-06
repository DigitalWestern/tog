//! The dynamic loader's cache (`/etc/ld.so.cache`) a `RuntimeOnly`
//! sandbox gets (#332). The view moves the host's regular ELF `lib*.so`
//! files out of the linker's reach (`hostview::RUNTIME_SUBDIR`), and host
//! programs must still load them. `LD_LIBRARY_PATH` would find them, but
//! glibc searches it before a program's own `DT_RUNPATH`, so a program a
//! build bundles and runs would load a host library in place of its own
//! copy of the same soname. The cache is searched after `DT_RUNPATH`.
//!
//! So the view's cache is the host's, rewritten: every entry that names a
//! moved library names its new path, and a moved library no entry names
//! gets one under its file name, which is how `LD_LIBRARY_PATH` found it.
//!
//! The format is glibc's `glibc-ld.so.cache1.1` (`elf/dl-cache.h`): a
//! header, entries sorted for the loader's binary search, then strings
//! and an optional extension directory. A host cache in the older
//! combined format carries the new one inside it, and that is what is
//! read. The written cache keeps the `glibc-hwcaps` extension, the only
//! one whose contents the loader uses, and drops the rest.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAGIC_NEW: &[u8] = b"glibc-ld.so.cache1.1";
const MAGIC_OLD: &[u8] = b"ld.so-1.7.0";
const HEADER_LEN: usize = 48;
const ENTRY_LEN: usize = 24;
const OLD_HEADER_LEN: usize = 16;
const OLD_ENTRY_LEN: usize = 12;
const EXTENSION_MAGIC: u32 = 0xeaa4_2174;
const EXTENSION_TAG_HWCAPS: u32 = 1;
/// The loader's flags for a library of this machine's own ABI
/// (`_DL_CACHE_DEFAULT_ID`), for a host whose cache names none.
const NATIVE_FLAGS: Option<i32> = if cfg!(target_arch = "x86_64") {
    Some(0x0303)
} else if cfg!(target_arch = "aarch64") {
    Some(0x0a03)
} else {
    None
};

/// One library the view moved: where the host has it, with its directory
/// canonical, and where the sandbox has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MovedLibrary {
    pub(crate) host: PathBuf,
    pub(crate) inside: PathBuf,
}

/// One cache entry, its strings resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    flags: i32,
    key: Vec<u8>,
    value: Vec<u8>,
    osversion: u32,
    hwcap: u64,
}

/// A parsed cache: its entries in file order, its `glibc-hwcaps`
/// subdirectory names, and its endianness flag byte.
#[derive(Debug, Default)]
struct Cache {
    entries: Vec<Entry>,
    hwcaps: Vec<Vec<u8>>,
    flags: u8,
}

/// The host cache at `host_cache`, rewritten for `moved` (see the module
/// documentation). A host without a cache gets one of the moved libraries
/// alone.
pub(crate) fn for_view(host_cache: &Path, moved: &[MovedLibrary]) -> io::Result<Vec<u8>> {
    let cache = match fs::read(host_cache) {
        Ok(bytes) => parse(&bytes).map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the host's dynamic loader cache {} cannot be read: {reason}",
                    host_cache.display()
                ),
            )
        })?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Cache {
            flags: native_endian_flag(),
            ..Cache::default()
        },
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("read {}: {error}", host_cache.display()),
            ))
        }
    };
    Ok(serialize(&relocate(cache, moved)))
}

/// Point every entry naming a moved library at its new path, and add an
/// entry for each moved library none names.
fn relocate(mut cache: Cache, moved: &[MovedLibrary]) -> Cache {
    let by_host: BTreeMap<&Path, &Path> = moved
        .iter()
        .map(|library| (library.host.as_path(), library.inside.as_path()))
        .collect();
    let mut canonical_dirs = CanonicalDirs::default();
    let mut named = std::collections::BTreeSet::new();
    let mut dir_flags: BTreeMap<PathBuf, i32> = BTreeMap::new();
    for entry in &mut cache.entries {
        let Some(host) = canonical_dirs.file(bytes_path(&entry.value)) else {
            continue;
        };
        if let Some(parent) = host.parent() {
            dir_flags.entry(parent.to_path_buf()).or_insert(entry.flags);
        }
        if let Some(inside) = by_host.get(host.as_path()) {
            entry.value = path_bytes(inside);
            named.insert(host);
        }
    }
    let libc_flags = cache
        .entries
        .iter()
        .find(|entry| entry.key == b"libc.so.6")
        .map(|entry| entry.flags)
        .or(NATIVE_FLAGS);
    for library in moved {
        if named.contains(&library.host) {
            continue;
        }
        let Some(name) = library.inside.file_name() else {
            continue;
        };
        // A library in a directory the cache names takes that directory's
        // flags. One elsewhere takes the native flags if it is of this
        // machine's own ABI, and is left out otherwise: the loader would
        // skip an entry whose flags it does not accept anyway.
        let flags = match library.host.parent().and_then(|dir| dir_flags.get(dir)) {
            Some(flags) => *flags,
            None => match libc_flags {
                Some(flags) if native_abi(&library.host) => flags,
                _ => continue,
            },
        };
        insert(
            &mut cache.entries,
            Entry {
                flags,
                key: path_bytes(Path::new(name)),
                value: path_bytes(&library.inside),
                osversion: 0,
                hwcap: 0,
            },
        );
    }
    cache
}

/// Insert `entry` where the loader's binary search finds it: the entries
/// are in descending `libcmp` order, and among equal keys the first that
/// fits wins, so a new entry goes after the host's own.
fn insert(entries: &mut Vec<Entry>, entry: Entry) {
    let at = entries.partition_point(|other| libcmp(&other.key, &entry.key).is_ge());
    entries.insert(at, entry);
}

/// glibc's `_dl_cache_libcmp`: bytes compare as bytes, except that runs
/// of digits compare as numbers, and a digit sorts after a non-digit.
fn libcmp(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut i, mut j) = (0, 0);
    while i < left.len() {
        let (a, b) = (left[i], right.get(j).copied().unwrap_or(0));
        if a.is_ascii_digit() {
            if !b.is_ascii_digit() {
                return Ordering::Greater;
            }
            let number = |bytes: &[u8], at: &mut usize| {
                let mut value: i32 = 0;
                while *at < bytes.len() && bytes[*at].is_ascii_digit() {
                    value = value
                        .wrapping_mul(10)
                        .wrapping_add(i32::from(bytes[*at] - b'0'));
                    *at += 1;
                }
                value
            };
            let (x, y) = (number(left, &mut i), number(right, &mut j));
            if x != y {
                return x.cmp(&y);
            }
        } else if b.is_ascii_digit() {
            return Ordering::Less;
        } else if a != b {
            // glibc compares `char`, signed on the hosts tog runs on.
            return (a as i8).cmp(&(b as i8));
        } else {
            i += 1;
            j += 1;
        }
    }
    0i8.cmp(&(right.get(j).copied().unwrap_or(0) as i8))
}

/// Whether the ELF file at `path` has the class, byte order and machine of
/// the running tog, which is of the host's own ABI.
fn native_abi(path: &Path) -> bool {
    let ident = |path: &Path| -> Option<[u8; 20]> {
        let mut header = [0u8; 20];
        fs::File::open(path).ok()?.read_exact(&mut header).ok()?;
        header.starts_with(b"\x7fELF").then_some(header)
    };
    let (Some(library), Some(own)) = (ident(path), ident(Path::new("/proc/self/exe"))) else {
        return false;
    };
    library[4..6] == own[4..6] && library[18..20] == own[18..20]
}

/// Each cache path with its directory resolved as the host resolves it
/// (`/lib64/libnss3.so` is `/usr/lib64/libnss3.so` on a merged-/usr host),
/// one `canonicalize` per directory.
#[derive(Default)]
struct CanonicalDirs(BTreeMap<PathBuf, Option<PathBuf>>);

impl CanonicalDirs {
    fn file(&mut self, path: &Path) -> Option<PathBuf> {
        let (parent, name) = (path.parent()?, path.file_name()?);
        let dir = self
            .0
            .entry(parent.to_path_buf())
            .or_insert_with(|| parent.canonicalize().ok());
        Some(dir.as_ref()?.join(name))
    }
}

fn bytes_path(bytes: &[u8]) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(bytes))
}

fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

fn native_endian_flag() -> u8 {
    if cfg!(target_endian = "little") {
        2
    } else {
        3
    }
}

/// Parse a cache in the new format, or the new format carried inside the
/// older combined one.
fn parse(bytes: &[u8]) -> Result<Cache, String> {
    let new = if bytes.starts_with(MAGIC_NEW) {
        bytes
    } else if bytes.starts_with(MAGIC_OLD) {
        let count = u32_at(bytes, 12)? as usize;
        let end = count
            .checked_mul(OLD_ENTRY_LEN)
            .and_then(|len| len.checked_add(OLD_HEADER_LEN))
            .ok_or("its entry count overflows")?;
        let start = end.next_multiple_of(8);
        match bytes.get(start..) {
            Some(new) if new.starts_with(MAGIC_NEW) => new,
            _ => return Err("it is in the old format alone".to_string()),
        }
    } else {
        return Err("it does not start with a known magic".to_string());
    };
    let count = u32_at(new, 20)? as usize;
    let flags = *new.get(28).ok_or("it is truncated")?;
    let extension = u32_at(new, 32)? as usize;
    let string = |offset: u32| -> Result<Vec<u8>, String> {
        let tail = new
            .get(offset as usize..)
            .ok_or(format!("a string offset {offset} is past its end"))?;
        let len = tail
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(format!("the string at {offset} is not terminated"))?;
        Ok(tail[..len].to_vec())
    };
    let mut entries = Vec::with_capacity(count.min(new.len() / ENTRY_LEN));
    for index in 0..count {
        let at = HEADER_LEN + index * ENTRY_LEN;
        entries.push(Entry {
            flags: u32_at(new, at)? as i32,
            key: string(u32_at(new, at + 4)?)?,
            value: string(u32_at(new, at + 8)?)?,
            osversion: u32_at(new, at + 12)?,
            hwcap: u64_at(new, at + 16)?,
        });
    }
    let mut hwcaps = Vec::new();
    if extension != 0 {
        if u32_at(new, extension)? != EXTENSION_MAGIC {
            return Err("its extension directory has the wrong magic".to_string());
        }
        for section in 0..u32_at(new, extension + 4)? as usize {
            let at = extension + 8 + section * 16;
            if u32_at(new, at)? != EXTENSION_TAG_HWCAPS {
                continue;
            }
            let (offset, size) = (
                u32_at(new, at + 8)? as usize,
                u32_at(new, at + 12)? as usize,
            );
            for item in 0..size / 4 {
                hwcaps.push(string(u32_at(new, offset + item * 4)?)?);
            }
        }
    }
    Ok(Cache {
        entries,
        hwcaps,
        flags,
    })
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .map(|slice| u32::from_ne_bytes(slice.try_into().expect("four bytes")))
        .ok_or_else(|| "it is truncated".to_string())
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, String> {
    bytes
        .get(at..at + 8)
        .map(|slice| u64::from_ne_bytes(slice.try_into().expect("eight bytes")))
        .ok_or_else(|| "it is truncated".to_string())
}

/// Write `cache` in the new format: header, entries, strings, then the
/// extension directory when there are `glibc-hwcaps` names.
fn serialize(cache: &Cache) -> Vec<u8> {
    let mut strings: Vec<u8> = Vec::new();
    let mut offsets: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    let base = HEADER_LEN + cache.entries.len() * ENTRY_LEN;
    let mut intern = |text: &[u8]| -> u32 {
        // Offsets are from the start of the cache; the strings follow the
        // entries.
        *offsets.entry(text.to_vec()).or_insert_with(|| {
            let offset = (base + strings.len()) as u32;
            strings.extend_from_slice(text);
            strings.push(0);
            offset
        })
    };
    let entries: Vec<(&Entry, u32, u32)> = cache
        .entries
        .iter()
        .map(|entry| (entry, intern(&entry.key), intern(&entry.value)))
        .collect();
    let hwcaps: Vec<u32> = cache.hwcaps.iter().map(|name| intern(name)).collect();
    let mut out = Vec::with_capacity(base + strings.len() + 64);
    out.extend_from_slice(MAGIC_NEW);
    out.extend_from_slice(&(entries.len() as u32).to_ne_bytes());
    out.extend_from_slice(&(strings.len() as u32).to_ne_bytes());
    out.extend_from_slice(&[cache.flags, 0, 0, 0]);
    let extension_at = if hwcaps.is_empty() {
        0
    } else {
        (base + strings.len()).next_multiple_of(8)
    };
    out.extend_from_slice(&(extension_at as u32).to_ne_bytes());
    out.extend_from_slice(&[0; 12]);
    for (entry, key, value) in entries {
        out.extend_from_slice(&entry.flags.to_ne_bytes());
        out.extend_from_slice(&key.to_ne_bytes());
        out.extend_from_slice(&value.to_ne_bytes());
        out.extend_from_slice(&entry.osversion.to_ne_bytes());
        out.extend_from_slice(&entry.hwcap.to_ne_bytes());
    }
    out.extend_from_slice(&strings);
    if extension_at != 0 {
        out.resize(extension_at, 0);
        out.extend_from_slice(&EXTENSION_MAGIC.to_ne_bytes());
        out.extend_from_slice(&1u32.to_ne_bytes());
        let section_data = (extension_at + 8 + 16) as u32;
        for word in [
            EXTENSION_TAG_HWCAPS,
            0,
            section_data,
            (hwcaps.len() * 4) as u32,
        ] {
            out.extend_from_slice(&word.to_ne_bytes());
        }
        for offset in hwcaps {
            out.extend_from_slice(&offset.to_ne_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn entry(key: &str, value: &str) -> Entry {
        Entry {
            flags: 0x0303,
            key: key.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
            osversion: 0,
            hwcap: 0,
        }
    }

    fn keys(cache: &Cache) -> Vec<String> {
        cache
            .entries
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.key).into_owned())
            .collect()
    }

    #[test]
    fn libcmp_orders_digit_runs_as_numbers() {
        use std::cmp::Ordering::*;
        assert_eq!(libcmp(b"libfoo.so.10", b"libfoo.so.9"), Greater);
        assert_eq!(libcmp(b"libfoo.so.1", b"libfoo.so.1"), Equal);
        assert_eq!(libcmp(b"libfoo.so", b"libfoo.so.1"), Less);
        assert_eq!(libcmp(b"liba1", b"libab"), Greater);
        assert_eq!(libcmp(b"libb", b"liba"), Greater);
    }

    #[test]
    fn a_cache_round_trips_through_its_bytes() {
        let cache = Cache {
            entries: vec![
                entry("libz.so.1", "/usr/lib64/libz.so.1"),
                Entry {
                    hwcap: 1 << 62,
                    ..entry("libc.so.6", "/usr/lib64/glibc-hwcaps/x86-64-v3/libc.so.6")
                },
                entry("libc.so.6", "/usr/lib64/libc.so.6"),
            ],
            hwcaps: vec![b"x86-64-v3".to_vec()],
            flags: 2,
        };
        let bytes = serialize(&cache);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.entries, cache.entries);
        assert_eq!(parsed.hwcaps, cache.hwcaps);
        assert_eq!(parsed.flags, 2);
        // The combined format carries the new one after its own entries.
        let mut combined = MAGIC_OLD.to_vec();
        combined.resize(OLD_HEADER_LEN + 2 * OLD_ENTRY_LEN, 0);
        combined[12..16].copy_from_slice(&2u32.to_ne_bytes());
        combined.resize(combined.len().next_multiple_of(8), 0);
        combined.extend_from_slice(&bytes);
        assert_eq!(parse(&combined).unwrap().entries, cache.entries);
        assert!(parse(b"garbage").is_err());
        assert!(parse(&bytes[..60]).is_err());
    }

    /// A moved library an entry names is renamed in place; one no entry
    /// names is added where the loader's search finds it, after a host
    /// entry with the same key, with its directory's flags.
    #[test]
    fn moved_libraries_are_renamed_or_added() {
        let host = TempDir::new();
        let lib = host.0.join("lib64");
        fs::create_dir(&lib).unwrap();
        let lib = lib.canonicalize().unwrap();
        let alias = host.0.join("lib");
        std::os::unix::fs::symlink(&lib, &alias).unwrap();
        let path = |dir: &Path, name: &str| dir.join(name).to_string_lossy().into_owned();
        let cache = Cache {
            entries: vec![
                Entry {
                    flags: 0x0a03,
                    ..entry("libz.so.1", &path(&lib, "libz.so.1"))
                },
                entry("libnss3.so", &path(&alias, "libnss3.so")),
                entry("libbfd.so", "/elsewhere/libbfd.so"),
            ],
            hwcaps: Vec::new(),
            flags: 2,
        };
        let moved = |name: &str| MovedLibrary {
            host: lib.join(name),
            inside: Path::new("/usr/lib64/.tog-host-runtime").join(name),
        };
        let relocated = relocate(cache, &[moved("libnss3.so"), moved("libbfd.so")]);
        assert_eq!(
            keys(&relocated),
            ["libz.so.1", "libnss3.so", "libbfd.so", "libbfd.so"]
        );
        assert_eq!(
            relocated.entries[1].value,
            b"/usr/lib64/.tog-host-runtime/libnss3.so"
        );
        assert_eq!(relocated.entries[2].value, b"/elsewhere/libbfd.so");
        assert_eq!(
            relocated.entries[3].value,
            b"/usr/lib64/.tog-host-runtime/libbfd.so"
        );
        assert_eq!(relocated.entries[3].flags, 0x0a03);
    }

    #[test]
    fn a_host_without_a_cache_gets_one_of_its_moved_native_libraries() {
        let host = TempDir::new();
        let own = host.0.join("libown.so");
        fs::copy("/proc/self/exe", &own).unwrap();
        let foreign = host.0.join("libforeign.so");
        fs::write(&foreign, b"\x7fELF not this machine's").unwrap();
        let moved: Vec<MovedLibrary> = [&own, &foreign]
            .iter()
            .map(|host| MovedLibrary {
                host: host.to_path_buf(),
                inside: Path::new("/r").join(host.file_name().unwrap()),
            })
            .collect();
        let bytes = for_view(&host.0.join("absent"), &moved).unwrap();
        let cache = parse(&bytes).unwrap();
        if NATIVE_FLAGS.is_some() {
            assert_eq!(keys(&cache), ["libown.so"]);
        }
        assert_eq!(cache.flags, native_endian_flag());
        let unreadable = host.0.join("cache");
        fs::write(&unreadable, b"not a cache").unwrap();
        let error = for_view(&unreadable, &moved).unwrap_err();
        assert!(error.to_string().contains("cannot be read"), "{error}");
    }

    /// This host's own cache parses, and survives a round trip unchanged in
    /// every entry and `glibc-hwcaps` name.
    #[test]
    fn this_hosts_cache_round_trips() {
        let Ok(bytes) = fs::read("/etc/ld.so.cache") else {
            eprintln!("skip: this host has no /etc/ld.so.cache");
            return;
        };
        let cache = parse(&bytes).unwrap();
        assert!(!cache.entries.is_empty());
        let again = parse(&serialize(&cache)).unwrap();
        assert_eq!(again.entries, cache.entries);
        assert_eq!(again.hwcaps, cache.hwcaps);
        for pair in cache.entries.windows(2) {
            assert!(libcmp(&pair[0].key, &pair[1].key).is_ge(), "{pair:?}");
        }
    }
}

//! Node's archive reads, extraction and packing: every call this tailor
//! makes into `kernel::archive`, and the tarball a `file:` directory
//! package is packed into (`local_package`), the one archive this tailor
//! writes itself. heavy.yml's `gate` watches `src/tailors/*/unpack.rs`, so
//! a change here runs the heavy suite against real archives (#325).
//! `tests/architecture.rs` keeps the calls here.

use super::*;
use std::io::{Read, Write};

pub(super) fn tarball_has_binding_gyp(activity: &StoreActivity, path: &Path) -> io::Result<bool> {
    let entries = crate::kernel::archive::list_with_activity(
        activity,
        path,
        crate::kernel::archive::Compression::Gzip,
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("list npm tarball {}: {e}", path.display()),
        )
    })?;
    Ok(entries.iter().any(|entry| {
        let trimmed = entry.name.trim_end_matches('/');
        trimmed == "binding.gyp" || trimmed.ends_with("/binding.gyp")
    }))
}

/// Unpack a Node distribution tarball into `staged`, past its one
/// top-level `node-v<version>-<platform>/` directory.
pub(super) fn extract_node_dist(
    activity: &StoreActivity,
    tarball: &Path,
    staged: &Path,
) -> io::Result<()> {
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        tarball,
        staged,
        &crate::kernel::archive::ExtractOptions::platform_build(1),
        crate::kernel::archive::Compression::Gzip,
    )
    .map(|_| ())
    .map_err(|e| io::Error::new(e.kind(), format!("extract node tarball: {e}")))
}

/// Unpack one registry tarball into `dest`, past its `package/` root.
pub(super) fn extract_npm_package(
    activity: &StoreActivity,
    platform: Platform,
    tarball: &Path,
    dest: &Path,
) -> io::Result<()> {
    // Registry tarballs are packed by arbitrary publishers; some
    // (pngjs, eta 1.x) carry directories with mode 0666. bsdtar
    // (macOS) descends into them anyway; GNU tar creates the
    // directory 0666 and then cannot open its children unless
    // directory modes are applied after extraction. The caller's
    // normalize_modes rewrites every mode afterwards, so the store
    // content is identical either way.
    let options = crate::kernel::archive::ExtractOptions {
        delay_directory_restore: !platform.is_macos(),
        ..crate::kernel::archive::ExtractOptions::stripped(1)
    };
    crate::kernel::archive::extract_with_activity_and_options(
        activity,
        tarball,
        dest,
        &options,
        crate::kernel::archive::Compression::Gzip,
    )
    .map(|_| ())
}

/// The largest size the 12-byte octal ustar field holds; a larger member
/// carries its size in a PAX record.
const USTAR_MAX_SIZE: u64 = 0o77777777777;

/// The gzip level a `file:` package is packed at. Pinned, not flate2's
/// default: the level picks the deflate stream and the header's XFL byte,
/// and the tarball's digest is the package's integrity, so a level that
/// moved with a dependency would change every `file:` package's identity
/// (#613). flate2's pure-Rust backend (the default feature set) produces
/// the same stream on every host.
const GZIP_LEVEL: flate2::Compression = flate2::Compression::new(6);

/// The gzipped tarball of a `file:` directory package, built the same way
/// every time: a `package/` root, ustar headers with zeroed owners and
/// times, a zero gzip mtime, an unknown OS byte (255) and a pinned level,
/// so the same members in the same order are the same bytes, on every host.
pub(super) struct PackageTarball<W: Write> {
    gzip: flate2::write::GzEncoder<W>,
}

impl<W: Write> PackageTarball<W> {
    /// Start the tarball on `out`, with its `package/` root.
    pub(super) fn new(out: W) -> io::Result<Self> {
        let mut gzip = flate2::GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(out, GZIP_LEVEL);
        write_member(&mut gzip, "package/", b'5', 0o755, 0, &mut io::empty())?;
        Ok(Self { gzip })
    }

    /// A directory member; `name` ends in `/`.
    pub(super) fn dir(&mut self, name: &str) -> io::Result<()> {
        write_member(&mut self.gzip, name, b'5', 0o755, 0, &mut io::empty())
    }

    /// A regular file member of `size` bytes read from `data`.
    pub(super) fn file(
        &mut self,
        name: &str,
        mode: u32,
        size: u64,
        data: &mut impl Read,
    ) -> io::Result<()> {
        write_member(&mut self.gzip, name, b'0', mode, size, data)
    }

    /// End the archive with its two zero blocks and the gzip trailer.
    pub(super) fn finish(mut self) -> io::Result<()> {
        self.gzip.write_all(&[0u8; 1024])?;
        self.gzip.finish()?.flush()
    }
}

/// One ustar member. A name past the 100 bytes ustar holds, or a size
/// past the 8 GiB its octal field holds, goes in a PAX record before it.
fn write_member(
    out: &mut impl Write,
    name: &str,
    typeflag: u8,
    mode: u32,
    size: u64,
    data: &mut impl Read,
) -> io::Result<()> {
    out.write_all(&member_header(name, typeflag, mode, size))?;
    let copied = io::copy(&mut data.take(size), out)?;
    if copied != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} changed size while packing"),
        ));
    }
    pad(out, size)
}

/// The header blocks of one member: a PAX header when the name or size
/// does not fit ustar, then the ustar header.
fn member_header(name: &str, typeflag: u8, mode: u32, size: u64) -> Vec<u8> {
    let mut blocks = Vec::new();
    let mut records = String::new();
    if name.len() > 100 {
        records.push_str(&pax_record("path", name));
    }
    if size > USTAR_MAX_SIZE {
        records.push_str(&pax_record("size", &size.to_string()));
    }
    if !records.is_empty() {
        blocks.extend_from_slice(&header("././@PaxHeader", b'x', 0o644, records.len() as u64));
        blocks.extend_from_slice(records.as_bytes());
        pad(&mut blocks, records.len() as u64).expect("a Vec write cannot fail");
    }
    // The ustar field keeps what fits; the PAX record above names it whole.
    let mut cut = name.len().min(100);
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    blocks.extend_from_slice(&header(&name[..cut], typeflag, mode, size));
    blocks
}

/// `<length> <key>=<value>\n`, where the length counts itself.
fn pax_record(key: &str, value: &str) -> String {
    let body = format!(" {key}={value}\n");
    let mut length = body.len() + 1;
    while format!("{length}{body}").len() != length {
        length += 1;
    }
    format!("{length}{body}")
}

fn pad(out: &mut impl Write, size: u64) -> io::Result<()> {
    let rest = (512 - size % 512) % 512;
    out.write_all(&vec![0u8; rest as usize])
}

/// A ustar header. A size past the octal field is written as zero; the
/// PAX `size` record `member_header` put before it carries the value.
fn header(name: &str, typeflag: u8, mode: u32, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    let name = &name.as_bytes()[..name.len().min(100)];
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size = if size > USTAR_MAX_SIZE { 0 } else { size };
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let sum: u32 = header.iter().map(|byte| *byte as u32).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A member of 8 GiB or more does not fit the ustar size field: it
    /// gets a PAX `size` record, which the archive reader prefers, and
    /// the ustar field reads zero instead of overflowing.
    #[test]
    fn a_member_too_large_for_ustar_carries_its_size_in_a_pax_record() {
        let size = 1u64 << 33;
        let blocks = member_header("package/big.bin", b'0', 0o644, size);
        assert_eq!(
            blocks.len(),
            512 * 3,
            "a PAX header, its record, the ustar header"
        );
        assert_eq!(blocks[156], b'x');
        let record = std::str::from_utf8(&blocks[512..1024]).unwrap();
        assert!(record.contains(" size=8589934592\n"), "{record:?}");
        let ustar = &blocks[1024..];
        assert_eq!(&ustar[124..136], b"00000000000\0");
        let sum: u32 = ustar
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *byte as u32
                }
            })
            .sum();
        assert_eq!(&ustar[148..155], format!("{sum:06o}\0").as_bytes());
        // A size that fits needs no PAX header.
        assert_eq!(
            member_header("package/small", b'0', 0o644, USTAR_MAX_SIZE).len(),
            512
        );
    }

    /// The gzip header carries nothing from the host or the clock: a zero
    /// mtime, no flags (no name, comment or extra field), the unknown OS
    /// byte, and the XFL byte the pinned level sets. Packed twice, the
    /// tarball is the same bytes (#613).
    #[test]
    fn the_gzip_header_is_fixed_and_the_tarball_packs_identically() {
        let pack = || {
            let mut out = Vec::new();
            let mut tarball = PackageTarball::new(&mut out).unwrap();
            tarball.dir("package/lib/").unwrap();
            tarball
                .file("package/lib/index.js", 0o644, 5, &mut &b"hello"[..])
                .unwrap();
            tarball.finish().unwrap();
            out
        };
        let bytes = pack();
        assert_eq!(bytes, pack());
        // RFC 1952: ID1, ID2, CM (deflate), FLG, MTIME (4 bytes), XFL, OS.
        assert_eq!(&bytes[..4], &[0x1f, 0x8b, 8, 0], "id, method, flags");
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0], "mtime");
        assert_eq!(bytes[8], 0, "XFL for level {}", GZIP_LEVEL.level());
        assert_eq!(bytes[9], 255, "OS byte: unknown");
        // The members read back through the archive reader, and the gzip
        // trailer's length is the tar stream's: a directory block, a file
        // block and its data block, the two end blocks.
        let decompressed = {
            let mut tar = Vec::new();
            flate2::read::GzDecoder::new(&bytes[..])
                .read_to_end(&mut tar)
                .unwrap();
            tar
        };
        assert_eq!(decompressed.len(), 512 * 6);
        assert_eq!(&decompressed[512 * 3..512 * 3 + 5], b"hello");
    }

    /// A registry tarball whose `package/sub/b` is a hard link to
    /// `package/a` unpacks with both names on the same bytes, past the
    /// `package/` root (#556; crates got the same check in #542).
    #[test]
    fn an_npm_tarball_with_a_contained_hard_link_unpacks_both_names() {
        use std::os::unix::fs::MetadataExt;
        let temp = crate::kernel::testutil::TempDir::named("npm-hard-link");
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("package/sub")).unwrap();
        fs::write(source.join("package/a"), "shared bytes").unwrap();
        fs::hard_link(source.join("package/a"), source.join("package/sub/b")).unwrap();
        let tarball = temp.0.join("pkg.tgz");
        let status = crate::kernel::testutil::tar_create()
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&source)
            .arg("package")
            .status()
            .unwrap();
        assert!(status.success());
        let (_store_dir, _store, activity) =
            crate::kernel::resolve::testing::scratch_store("npm-hard-link-store");
        let dest = temp.0.join("dest");
        fs::create_dir_all(&dest).unwrap();
        extract_npm_package(&activity, Platform::host().unwrap(), &tarball, &dest).unwrap();
        assert_eq!(fs::read(dest.join("sub/b")).unwrap(), b"shared bytes");
        let (a, b) = (
            fs::metadata(dest.join("a")).unwrap(),
            fs::metadata(dest.join("sub/b")).unwrap(),
        );
        assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    }
}

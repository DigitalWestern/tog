//! `file:` directory packages (pnpm): the package is a copy of a directory
//! in the project, as pnpm installs it, never a link to the source. A copy
//! has a `node_modules` of its own, so its dependencies may differ from
//! the versions the workspace member that names it needs (#188); a link
//! resolves from the source's real path, where only one version of each
//! name can sit.
//!
//! The copy is packed the way a registry package arrives: a gzipped tar
//! with a `package/` root, built the same way every time (sorted names,
//! zeroed owners and times), so its sha256 is a stable content address.
//! That digest is the package's integrity. Sync puts the tarball in the
//! store's cache under it, and the environment extracts it like any
//! registry tarball. `tog status` packs the directory again and compares:
//! an edit to the source is a change, as an edit to package.json is.
//!
//! The directory is read through the held project descriptor. A symlink
//! inside it is followed when its target lies inside the project, and
//! refused when it leads outside (an absolute target, or one that climbs
//! past the project root): the copy holds the project's own files, never
//! what a link happens to point at. A directory reached twice on one path
//! (a link to an ancestor) is refused rather than walked again, and a
//! directory past `MAX_ENTRIES` names or `MAX_BYTES` of content is refused
//! rather than packed. A FIFO, socket or device is skipped, as `npm pack`
//! skips everything that is not a file or a directory. `node_modules` and
//! `.git` directories are left out, at any depth, as `npm pack` leaves
//! them out. Other `npm pack` rules (the `files` list, `.npmignore`) are
//! not applied: the copy holds everything else in the directory.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::store::Store;
use crate::tailors::node::NpmPackage;
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The `url` a `file:` directory package carries: `file:` and its
/// project-relative directory. Nothing fetches it; the tarball is packed
/// from the project and placed in the cache under its integrity.
pub(crate) const URL_PREFIX: &str = "file:";

/// Directory nesting past this is refused. A link to an ancestor is
/// caught by the directory identities on the path; this is the backstop.
const MAX_DEPTH: usize = 64;

/// What a `file:` directory may hold before packing it is refused: more
/// than this is not a package but a tree someone pointed a `file:` at by
/// mistake, and packing it would fill the store.
#[derive(Clone, Copy)]
struct Limits {
    /// Names walked, files, directories and skipped entries alike.
    entries: usize,
    /// Bytes of file content.
    bytes: u64,
}

const LIMITS: Limits = Limits {
    entries: 200_000,
    bytes: 4 << 30,
};

/// The largest size the 12-byte octal ustar field holds; a larger member
/// carries its size in a PAX record.
const USTAR_MAX_SIZE: u64 = 0o77777777777;

/// The project-relative directory of a `file:` directory package.
pub(crate) fn source_dir(package: &NpmPackage) -> Option<&str> {
    package.url.strip_prefix(URL_PREFIX)
}

/// The `url` for the package packed from `dir`.
pub(crate) fn url_for(dir: &str) -> String {
    format!("{URL_PREFIX}{dir}")
}

fn err(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The sha256 SRI of the tarball packed from `dir`.
pub(crate) fn integrity(project: &ProjectRoot, dir: &str) -> io::Result<String> {
    let mut hasher = HashWriter(Sha256::new());
    pack(project, dir, &mut hasher)?;
    Ok(format!(
        "sha256-{}",
        crate::kernel::base64::encode(&hasher.0.finalize())
    ))
}

/// The `version` the package.json in `dir` names: what the closure, the
/// SBOM and the package's install scripts see. `0.0.0` when it names none,
/// or when the directory has no package.json (Node still loads its
/// `index.js`).
pub(crate) fn version(project: &ProjectRoot, dir: &str) -> io::Result<String> {
    let Some(manifest) = project.read_input_string(&Path::new(dir).join("package.json"))? else {
        return Ok("0.0.0".into());
    };
    let value: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| err(format!("{dir}/package.json: {e}")))?;
    Ok(value["version"].as_str().unwrap_or("0.0.0").to_string())
}

/// Pack every `file:` directory package in `packages` into the store's
/// cache, refusing one whose directory no longer packs to the integrity
/// the plan recorded: it changed after the plan was made, and the next
/// sync plans it again.
pub(crate) fn stage(
    store: &Store,
    activity: &StoreActivity,
    project: &ProjectRoot,
    packages: &[NpmPackage],
) -> io::Result<()> {
    for package in packages {
        let Some(dir) = source_dir(package) else {
            continue;
        };
        let tmp = store.root.join("tmp").join(format!(
            "local-{}.tgz",
            crate::kernel::fsroot::random_suffix()?
        ));
        let staged = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            pack(project, dir, &mut file)?;
            file.sync_all()?;
            drop(file);
            crate::kernel::fetch::cache_insert(store, activity, &tmp)
        })();
        let _ = std::fs::remove_file(&tmp);
        let (hex, _) =
            staged.map_err(|e| io::Error::new(e.kind(), format!("pack {}: {e}", package.path)))?;
        let packed = crate::kernel::digest::Digest::sha256(&hex)?;
        if !crate::kernel::digest::sri_candidates(&package.integrity)?.contains(&packed) {
            return Err(err(format!(
                "{dir} changed while tog synced it; run 'tog' again to plan the new contents"
            )));
        }
    }
    Ok(())
}

/// The `file:` directory packages of a closure's `packages` rows (each
/// names its directory as `local`) whose directory no
/// longer packs to the recorded integrity, by directory. A directory that
/// cannot be packed any more (removed, or now holding a symlink out of
/// the project) is changed too.
pub(crate) fn changed(project: &ProjectRoot, packages: &[serde_json::Value]) -> Vec<String> {
    let mut changed = Vec::new();
    for package in packages {
        let Some(dir) = package["local"].as_str() else {
            continue;
        };
        let recorded = package["integrity"].as_str().unwrap_or_default();
        match integrity(project, dir) {
            Ok(current) if current == recorded => {}
            Ok(_) => changed.push(dir.to_string()),
            Err(_) => changed.push(format!("{dir} (unreadable)")),
        }
    }
    changed.sort();
    changed.dedup();
    changed
}

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One member of the tarball, in packing order.
enum Member {
    Dir(String),
    File { name: String, path: PathBuf },
}

/// Write the gzipped tarball of `dir` to `out`.
pub(crate) fn pack(project: &ProjectRoot, dir: &str, out: &mut impl Write) -> io::Result<()> {
    pack_within(project, dir, out, LIMITS)
}

fn pack_within(
    project: &ProjectRoot,
    dir: &str,
    out: &mut impl Write,
    limits: Limits,
) -> io::Result<()> {
    // The directory itself may be reached through a symlink: resolve it
    // once, and walk the directory it names, inside the project.
    let base = resolve_inside(project, Path::new(dir))?
        .ok_or_else(|| err(format!("the file: package {dir} does not exist")))?;
    if project.input_entry(&base)? != Entry::Directory {
        return Err(err(format!("the file: package {dir} is not a directory")));
    }
    let mut walk = Walk {
        project,
        limits,
        on_path: Vec::new(),
        entries: 0,
        members: Vec::new(),
    };
    walk.collect(&base, "", 0)?;
    let mut gzip = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(out, flate2::Compression::default());
    write_member(&mut gzip, "package/", b'5', 0o755, 0, &mut io::empty())?;
    let mut bytes = 0u64;
    for member in walk.members {
        match member {
            Member::Dir(name) => {
                write_member(&mut gzip, &name, b'5', 0o755, 0, &mut io::empty())?;
            }
            Member::File { name, path } => {
                let mut file = project
                    .open_input_file(&path)?
                    .ok_or_else(|| err(format!("{} vanished while packing", path.display())))?;
                let meta = file.metadata()?;
                if !meta.is_file() {
                    return Err(err(format!(
                        "{} is not a regular file; a file: package holds files and directories only",
                        path.display()
                    )));
                }
                bytes = bytes.saturating_add(meta.len());
                if bytes > limits.bytes {
                    return Err(err(format!(
                        "the file: package {dir} holds more than {} bytes of files (at {}); a file: package is a copy of a package, not of a data set",
                        limits.bytes,
                        path.display()
                    )));
                }
                use std::os::unix::fs::PermissionsExt;
                let mode = if meta.permissions().mode() & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                };
                write_member(&mut gzip, &name, b'0', mode, meta.len(), &mut file)?;
            }
        }
    }
    // Two zero blocks end the archive.
    gzip.write_all(&[0u8; 1024])?;
    gzip.finish()?.flush()
}

/// Where the project-relative `path` leads once every symlink in it is
/// followed, as a project-relative path again: `None` when it leads to
/// nothing, an error when it leads outside the project or to the project
/// root itself. The check is against the held root's path, which `open`
/// made canonical and nothing here resolves again.
fn resolve_inside(project: &ProjectRoot, path: &Path) -> io::Result<Option<PathBuf>> {
    let target = match std::fs::canonicalize(project.path().join(path)) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("{}: cannot follow the symlink: {error}", path.display()),
            ))
        }
    };
    match project.relative(&target) {
        Some(relative) if relative.as_os_str().is_empty() => Err(err(format!(
            "{} is a symlink to the project root; a file: package cannot hold the project",
            path.display()
        ))),
        Some(relative) => Ok(Some(relative.to_path_buf())),
        None => Err(err(format!(
            "{} is a symlink to {}, outside the project; a file: package holds the project's own files",
            path.display(),
            target.display()
        ))),
    }
}

/// The depth-first walk of a `file:` directory.
struct Walk<'a> {
    project: &'a ProjectRoot,
    limits: Limits,
    /// The identity (device, inode) of every directory on the current
    /// path, root first: a directory already here is a loop.
    on_path: Vec<(u64, u64)>,
    entries: usize,
    members: Vec<Member>,
}

impl Walk<'_> {
    /// Every member below `dir` (a resolved project-relative path, no
    /// symlink in it), depth first in name order.
    fn collect(&mut self, dir: &Path, prefix: &str, depth: usize) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(err(format!(
                "{} nests deeper than {MAX_DEPTH} directories",
                dir.display()
            )));
        }
        let held = self
            .project
            .input_subdir(dir)?
            .ok_or_else(|| err(format!("{} vanished while packing", dir.display())))?;
        use std::os::fd::AsRawFd;
        let identity =
            crate::kernel::store::stat_identity(&crate::kernel::store::fd_stat(held.as_raw_fd())?);
        if self.on_path.contains(&identity) {
            return Err(err(format!(
                "{} is reached again through a symlink to one of its own ancestors; a file: package cannot contain itself",
                dir.display()
            )));
        }
        self.on_path.push(identity);
        let names = held
            .read_input_dir(Path::new("."))?
            .ok_or_else(|| err(format!("{} vanished while packing", dir.display())))?;
        for name in names {
            let text = name
                .to_str()
                .ok_or_else(|| err(format!("{}: a name that is not UTF-8", dir.display())))?;
            if text == "node_modules" || text == ".git" {
                continue;
            }
            self.entries += 1;
            if self.entries > self.limits.entries {
                return Err(err(format!(
                    "{} holds more than {} entries (at {text}); a file: package is a copy of a package, not of a tree",
                    dir.display(),
                    self.limits.entries
                )));
            }
            let path = dir.join(&name);
            let member = format!("package/{prefix}{text}");
            // Seen without following, from the directory just listed.
            let (kind, path) = match held.entry(Path::new(&name))? {
                Entry::Symlink => match resolve_inside(self.project, &path)? {
                    // A symlink to nothing names nothing to copy.
                    None => continue,
                    Some(target) => (self.project.entry(&target)?, target),
                },
                kind => (kind, path),
            };
            match kind {
                Entry::Regular => self.members.push(Member::File { name: member, path }),
                Entry::Directory => {
                    self.members.push(Member::Dir(format!("{member}/")));
                    self.collect(&path, &format!("{prefix}{text}/"), depth + 1)?;
                }
                // A FIFO, socket or device is not part of a package, as
                // `npm pack` leaves it out; a resolved target cannot be a
                // symlink, and one that vanished names nothing to copy.
                Entry::Other | Entry::Symlink | Entry::Absent => {}
            }
        }
        self.on_path.pop();
        Ok(())
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
        return Err(err(format!("{name} changed size while packing")));
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
    use std::fs;

    fn package_dir(root: &Path) {
        let dir = root.join("vendor/local");
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::create_dir_all(dir.join("node_modules/skipped")).unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"name":"local","version":"2.1.0","bin":{"local":"bin.js"}}"#,
        )
        .unwrap();
        fs::write(dir.join("lib/index.js"), "module.exports = 1;\n").unwrap();
        fs::write(dir.join("bin.js"), "#!/usr/bin/env node\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("bin.js"), fs::Permissions::from_mode(0o755)).unwrap();
        let long = "a".repeat(120);
        fs::write(dir.join("lib").join(&long), "long\n").unwrap();
    }

    /// tog's own archive reader lists what was packed: the `package/`
    /// root, the long name through its PAX record, and no node_modules.
    #[test]
    fn a_packed_directory_reads_back_through_the_archive_reader() {
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        let project = ProjectRoot::open(&temp.0).unwrap();
        let tarball = temp.0.join("local.tgz");
        let mut file = fs::File::create(&tarball).unwrap();
        pack(&project, "vendor/local", &mut file).unwrap();
        drop(file);
        let (_lease_dir, activity) = crate::kernel::testutil::detached_lease();
        let names: Vec<String> = crate::kernel::archive::list_with_activity(
            &activity,
            &tarball,
            crate::kernel::archive::Compression::Gzip,
        )
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
        let long = format!("package/lib/{}", "a".repeat(120));
        for want in [
            "package/package.json",
            "package/bin.js",
            "package/lib/index.js",
            long.as_str(),
        ] {
            assert!(
                names.iter().any(|name| name.trim_end_matches('/') == want),
                "{want} in {names:?}"
            );
        }
        assert!(
            !names.iter().any(|name| name.contains("node_modules")),
            "{names:?}"
        );
    }

    #[test]
    fn the_integrity_is_stable_and_follows_the_contents() {
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        let project = ProjectRoot::open(&temp.0).unwrap();
        let first = integrity(&project, "vendor/local").unwrap();
        assert_eq!(first, integrity(&project, "vendor/local").unwrap());
        assert!(first.starts_with("sha256-"), "{first}");
        // node_modules is not part of the package.
        fs::write(temp.0.join("vendor/local/node_modules/skipped/x"), "x").unwrap();
        assert_eq!(first, integrity(&project, "vendor/local").unwrap());
        fs::write(
            temp.0.join("vendor/local/lib/index.js"),
            "module.exports = 2;\n",
        )
        .unwrap();
        assert_ne!(first, integrity(&project, "vendor/local").unwrap());
        assert_eq!(version(&project, "vendor/local").unwrap(), "2.1.0");
    }

    /// The member names of the tarball `pack` writes for `dir`.
    fn packed_names(project: &ProjectRoot, dir: &str) -> Vec<String> {
        let tarball = project.path().join("packed.tgz");
        let mut file = fs::File::create(&tarball).unwrap();
        pack(project, dir, &mut file).unwrap();
        drop(file);
        let (_lease_dir, activity) = crate::kernel::testutil::detached_lease();
        let names = crate::kernel::archive::list_with_activity(
            &activity,
            &tarball,
            crate::kernel::archive::Compression::Gzip,
        )
        .unwrap()
        .into_iter()
        .map(|entry| entry.name.trim_end_matches('/').to_string())
        .collect();
        fs::remove_file(&tarball).unwrap();
        names
    }

    /// A FIFO or a socket in the directory is left out, as `npm pack`
    /// leaves out everything that is not a file or a directory.
    #[test]
    fn a_fifo_in_the_directory_is_skipped() {
        use std::os::unix::ffi::OsStrExt;
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        let fifo = temp.0.join("vendor/local/pipe");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated name remains valid for the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let project = ProjectRoot::open(&temp.0).unwrap();
        let names = packed_names(&project, "vendor/local");
        assert!(!names.iter().any(|name| name.contains("pipe")), "{names:?}");
        assert!(names.contains(&"package/bin.js".to_string()), "{names:?}");
    }

    /// A project with the package at `project/vendor/local` and a file
    /// beside the project, where no symlink may lead.
    fn project_beside_outside() -> (crate::kernel::testutil::TempDir, ProjectRoot) {
        let temp = crate::kernel::testutil::TempDir::new();
        fs::create_dir_all(temp.0.join("project")).unwrap();
        package_dir(&temp.0.join("project"));
        fs::write(temp.0.join("outside.txt"), "secret\n").unwrap();
        let project = ProjectRoot::open(&temp.0.join("project")).unwrap();
        (temp, project)
    }

    #[test]
    fn a_symlink_out_of_the_project_is_refused_and_named() {
        let (temp, project) = project_beside_outside();
        let outside = temp.0.join("outside.txt").canonicalize().unwrap();
        // Absolute.
        let link = temp.0.join("project/vendor/local/lib/abs");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let error = integrity(&project, "vendor/local").unwrap_err().to_string();
        assert!(error.contains("lib/abs"), "{error}");
        assert!(error.contains("outside the project"), "{error}");
        assert!(error.contains(&outside.display().to_string()), "{error}");
        fs::remove_file(&link).unwrap();
        // Climbing with `..` past the project root.
        std::os::unix::fs::symlink(
            "../../../../outside.txt",
            temp.0.join("project/vendor/local/lib/climb"),
        )
        .unwrap();
        let error = integrity(&project, "vendor/local").unwrap_err().to_string();
        assert!(error.contains("lib/climb"), "{error}");
        assert!(error.contains("outside the project"), "{error}");
        // The package directory itself, reached through a link out.
        std::os::unix::fs::symlink(&temp.0, temp.0.join("project/vendor/away")).unwrap();
        let error = integrity(&project, "vendor/away").unwrap_err().to_string();
        assert!(error.contains("vendor/away"), "{error}");
        assert!(error.contains("outside the project"), "{error}");
    }

    /// A symlink that stays inside the project is followed: the copy
    /// holds the target's contents under the link's name.
    #[test]
    fn a_symlink_inside_the_project_is_followed() {
        let (temp, project) = project_beside_outside();
        let root = temp.0.join("project");
        fs::create_dir_all(root.join("shared")).unwrap();
        fs::write(root.join("shared/util.js"), "shared\n").unwrap();
        // A file, climbing out of the package but not out of the project,
        // and a directory, by an absolute path inside the project.
        std::os::unix::fs::symlink(
            "../../../shared/util.js",
            root.join("vendor/local/lib/util.js"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            root.canonicalize().unwrap().join("shared"),
            root.join("vendor/local/shared"),
        )
        .unwrap();
        let names = packed_names(&project, "vendor/local");
        for want in [
            "package/lib/util.js",
            "package/shared",
            "package/shared/util.js",
        ] {
            assert!(names.contains(&want.to_string()), "{want} in {names:?}");
        }
        // A dangling link names nothing to copy.
        std::os::unix::fs::symlink("nowhere", root.join("vendor/local/lib/gone")).unwrap();
        assert_eq!(packed_names(&project, "vendor/local"), names);
    }

    #[test]
    fn a_symlink_loop_is_refused_not_followed_forever() {
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        // Two links to the parent: the first one walked is the loop.
        std::os::unix::fs::symlink("..", temp.0.join("vendor/local/lib/up")).unwrap();
        std::os::unix::fs::symlink("..", temp.0.join("vendor/local/lib/up2")).unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let error = integrity(&project, "vendor/local").unwrap_err().to_string();
        assert!(error.contains("reached again through a symlink"), "{error}");
        assert!(error.contains("vendor/local"), "{error}");
        // A link to the project root is refused before any walk.
        fs::remove_file(temp.0.join("vendor/local/lib/up")).unwrap();
        fs::remove_file(temp.0.join("vendor/local/lib/up2")).unwrap();
        std::os::unix::fs::symlink("../../..", temp.0.join("vendor/local/lib/root")).unwrap();
        let error = integrity(&project, "vendor/local").unwrap_err().to_string();
        assert!(error.contains("symlink to the project root"), "{error}");
    }

    #[test]
    fn a_directory_past_the_entry_or_byte_limit_is_refused() {
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        let project = ProjectRoot::open(&temp.0).unwrap();
        let mut sink = io::sink();
        let within = Limits {
            entries: 100,
            bytes: 1 << 20,
        };
        pack_within(&project, "vendor/local", &mut sink, within).unwrap();
        let error = pack_within(
            &project,
            "vendor/local",
            &mut sink,
            Limits {
                entries: 3,
                ..within
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("more than 3 entries"), "{error}");
        assert!(error.contains("vendor/local"), "{error}");
        let error = pack_within(
            &project,
            "vendor/local",
            &mut sink,
            Limits {
                bytes: 10,
                ..within
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("more than 10 bytes"), "{error}");
        assert!(error.contains("vendor/local"), "{error}");
    }

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

    #[test]
    fn staging_puts_the_tarball_in_the_cache_and_refuses_a_changed_source() {
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        let project = ProjectRoot::open(&temp.0).unwrap();
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let package = NpmPackage {
            path: "node_modules/local".into(),
            name: "local".into(),
            version: "2.1.0".into(),
            url: url_for("vendor/local"),
            integrity: integrity(&project, "vendor/local").unwrap(),
            bin: Vec::new(),
            patch: None,
            git: None,
            foreign_platform: false,
            needs_workspace: false,
        };
        stage(&store, &activity, &project, std::slice::from_ref(&package)).unwrap();
        let digest = crate::kernel::digest::Digest::from_sri(&package.integrity).unwrap();
        assert!(store.cache_path(digest.algo(), digest.hex()).is_file());
        fs::write(temp.0.join("vendor/local/lib/index.js"), "changed\n").unwrap();
        let error = stage(&store, &activity, &project, std::slice::from_ref(&package))
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed while tog synced"), "{error}");
        let body = serde_json::json!({"local": "vendor/local", "integrity": package.integrity});
        assert_eq!(changed(&project, &[body]), vec!["vendor/local".to_string()]);
    }
}

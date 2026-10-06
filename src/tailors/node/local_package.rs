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
//! inside it is followed, as a pathname read inside the project would
//! follow it; a FIFO, socket or device is refused. `node_modules` and
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

/// Directory nesting past this is refused: a symlink to an ancestor would
/// otherwise be followed forever.
const MAX_DEPTH: usize = 64;

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
/// cannot be packed any more (removed, or holding a FIFO) is changed too.
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
    if project.input_entry(Path::new(dir))? != Entry::Directory {
        return Err(err(format!("the file: package {dir} is not a directory")));
    }
    let mut members = Vec::new();
    collect(project, Path::new(dir), "", 0, &mut members)?;
    let mut gzip = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(out, flate2::Compression::default());
    write_member(&mut gzip, "package/", b'5', 0o755, 0, &mut io::empty())?;
    for member in members {
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

/// Every member below `dir`, depth first in name order.
fn collect(
    project: &ProjectRoot,
    dir: &Path,
    prefix: &str,
    depth: usize,
    members: &mut Vec<Member>,
) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(err(format!(
            "{} nests deeper than {MAX_DEPTH} directories; a symlink loop?",
            dir.display()
        )));
    }
    let names = project
        .read_input_dir(dir)?
        .ok_or_else(|| err(format!("{} vanished while packing", dir.display())))?;
    for name in names {
        let text = name
            .to_str()
            .ok_or_else(|| err(format!("{}: a name that is not UTF-8", dir.display())))?;
        if text == "node_modules" || text == ".git" {
            continue;
        }
        let path = dir.join(&name);
        let member = format!("package/{prefix}{text}");
        match project.input_entry(&path)? {
            Entry::Regular => members.push(Member::File { name: member, path }),
            Entry::Directory => {
                members.push(Member::Dir(format!("{member}/")));
                collect(project, &path, &format!("{prefix}{text}/"), depth + 1, members)?;
            }
            // A symlink whose target is gone names nothing to copy.
            Entry::Absent => {}
            Entry::Other | Entry::Symlink => {
                return Err(err(format!(
                    "{} is not a regular file or directory; a file: package holds files and directories only",
                    path.display()
                )))
            }
        }
    }
    Ok(())
}

/// One ustar member. A name past the 100 bytes ustar holds goes in a PAX
/// `path` record before it.
fn write_member(
    out: &mut impl Write,
    name: &str,
    typeflag: u8,
    mode: u32,
    size: u64,
    data: &mut impl Read,
) -> io::Result<()> {
    if name.len() > 100 {
        let record = pax_record("path", name);
        out.write_all(&header("././@PaxHeader", b'x', 0o644, record.len() as u64))?;
        out.write_all(record.as_bytes())?;
        pad(out, record.len() as u64)?;
    }
    // The ustar field keeps what fits; the PAX record above names it whole.
    let mut cut = name.len().min(100);
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    let short = &name[..cut];
    out.write_all(&header(short, typeflag, mode, size))?;
    let copied = io::copy(&mut data.take(size), out)?;
    if copied != size {
        return Err(err(format!("{name} changed size while packing")));
    }
    pad(out, size)
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

fn header(name: &str, typeflag: u8, mode: u32, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    let name = &name.as_bytes()[..name.len().min(100)];
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
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

    #[test]
    fn a_fifo_in_the_directory_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        let fifo = temp.0.join("vendor/local/pipe");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated name remains valid for the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let project = ProjectRoot::open(&temp.0).unwrap();
        let error = integrity(&project, "vendor/local").unwrap_err().to_string();
        assert!(error.contains("pipe"), "{error}");
    }

    #[test]
    fn a_symlink_loop_is_refused_not_followed_forever() {
        let temp = crate::kernel::testutil::TempDir::new();
        package_dir(&temp.0);
        std::os::unix::fs::symlink("..", temp.0.join("vendor/local/lib/up")).unwrap();
        let project = ProjectRoot::open(&temp.0).unwrap();
        let error = integrity(&project, "vendor/local").unwrap_err().to_string();
        assert!(error.contains("nests deeper"), "{error}");
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

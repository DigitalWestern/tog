//! One Hex package tarball, unpacked and verified: the inner checksum
//! over the outer members, the tarball's own CHECKSUM member, the
//! contents tree, and the metadata against the lock. The download (and
//! its outer sha256) happens in `realize_deps`; everything here runs on
//! bytes already on disk, so tests reach every refusal offline.

use super::{err, HexDep};
use crate::kernel::activity::StoreActivity;
use crate::kernel::archive::{extract_with_activity_and_options, Compression, ExtractOptions};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Unpack the verified outer tarball `tar` of `d` through `scratch` into
/// `staged/<app>`, returning that directory with `hex_metadata.config`
/// in place. Any disagreement with the lock refuses the package.
pub(super) fn unpack_verified(
    activity: &StoreActivity,
    tar: &Path,
    scratch: &Path,
    staged: &Path,
    d: &HexDep,
) -> io::Result<PathBuf> {
    // Unpack the OUTER tar (VERSION, metadata.config, contents.tar.gz, CHECKSUM).
    let outer_dir = scratch.join(format!("outer-{}", d.app));
    let app: &str = &d.app;
    let extract = |archive: &Path, dest: &Path, compression: Compression, what: &str| {
        extract_with_activity_and_options(
            activity,
            archive,
            dest,
            &ExtractOptions::stripped(0),
            compression,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("{app}: {what} extraction failed: {e}")))
    };
    fs::create_dir_all(&outer_dir)?;
    extract(tar, &outer_dir, Compression::None, "outer tar")?;
    // Inner checksum per hex spec — over REGULAR outer members only.
    let mut hasher = Sha256::new();
    for part in ["VERSION", "metadata.config", "contents.tar.gz", "CHECKSUM"] {
        let p = outer_dir.join(part);
        let md = fs::symlink_metadata(&p).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{}: missing {part} in tarball: {e}", d.app),
            )
        })?;
        if !md.file_type().is_file() {
            return Err(err(format!("{}: {part} is not a regular file", d.app)));
        }
        if part != "CHECKSUM" {
            hasher.update(&fs::read(&p)?);
        }
    }
    let got_inner = hex::encode(hasher.finalize());
    if got_inner != d.inner_sha256 {
        return Err(err(format!(
            "{}: inner checksum mismatch\n  expected {}\n  got      {got_inner}",
            d.app, d.inner_sha256
        )));
    }
    // The tarball's own CHECKSUM member is the (deprecated) inner hash;
    // agreement is cheap belt-and-braces.
    let shipped = fs::read_to_string(outer_dir.join("CHECKSUM"))?;
    if !shipped.trim().eq_ignore_ascii_case(&d.inner_sha256) {
        return Err(err(format!(
            "{}: tarball CHECKSUM member disagrees with the lock",
            d.app
        )));
    }
    // Layout keyed by the lock APP name (may differ from package).
    let dep_dir = staged.join(&d.app);
    fs::create_dir_all(&dep_dir)?;
    extract(
        &outer_dir.join("contents.tar.gz"),
        &dep_dir,
        Compression::Gzip,
        "contents",
    )?;
    check_dep_tree(&dep_dir, &d.app)?;
    // Reserved destinations must not pre-exist in package contents —
    // a shipped symlink named .hex/hex_metadata.config would carry our
    // writes through the link.
    for reserved in [".hex", "hex_metadata.config"] {
        if fs::symlink_metadata(dep_dir.join(reserved)).is_ok() {
            return Err(err(format!(
                "{}: package ships a reserved {reserved} entry; refusing",
                d.app
            )));
        }
    }
    // Metadata cross-check: the app/version inside metadata.config must
    // agree with the lock coordinates.
    let meta = fs::read_to_string(outer_dir.join("metadata.config"))?;
    let has_kv = |k: &str, v: &str| meta.contains(&format!("{{<<\"{k}\">>,<<\"{v}\">>}}"));
    if !has_kv("app", &d.app) || !has_kv("version", &d.version) {
        return Err(err(format!(
            "{}: hex metadata disagrees with the lock (app/version)",
            d.app
        )));
    }
    fs::copy(
        outer_dir.join("metadata.config"),
        dep_dir.join("hex_metadata.config"),
    )?;
    Ok(dep_dir)
}

/// Extraction containment: regular files and dirs, plus symlinks whose
/// target resolves INSIDE the dep dir (hex packages legitimately contain
/// safe symlinks — stricter-than-cargo here would be a regression).
fn check_dep_tree(dep_dir: &Path, app: &str) -> io::Result<()> {
    fn walk(root: &Path, dir: &Path, app: &str) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let md = fs::symlink_metadata(&path)?;
            let ft = md.file_type();
            if ft.is_symlink() {
                let target = fs::read_link(&path)?;
                let resolved = path
                    .parent()
                    .map(|p| p.join(&target))
                    .and_then(|t| t.canonicalize().ok());
                let root_canon = root.canonicalize()?;
                let ok = resolved
                    .map(|c| c.starts_with(&root_canon))
                    .unwrap_or(false);
                if !ok {
                    return Err(err(format!("{app}: symlink escapes the package")));
                }
            } else if ft.is_dir() {
                walk(root, &path, app)?;
            } else if !ft.is_file() {
                return Err(err(format!("{app}: hostile special entry")));
            }
        }
        Ok(())
    }
    walk(dep_dir, dep_dir, app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::{detached_lease, tar_create, TempDir};

    const METADATA: &str = "{<<\"app\">>,<<\"demo\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n";

    /// A Hex package in the real layout: an uncompressed outer tar of
    /// VERSION, metadata.config, contents.tar.gz and CHECKSUM, where the
    /// inner checksum covers the first three.
    struct Package {
        temp: TempDir,
        /// The unpacked outer members, editable before `pack`.
        outer: PathBuf,
        /// The lock row the package answers to.
        dep: HexDep,
    }

    impl Package {
        /// The package, with `contents` (relative path, body) as its tree
        /// and `metadata` as its metadata.config.
        fn new(contents: &[(&str, &str)], metadata: &str) -> Self {
            Self::build(
                |tree| {
                    for (rel, body) in contents {
                        let path = tree.join(rel);
                        fs::create_dir_all(path.parent().unwrap()).unwrap();
                        fs::write(path, body).unwrap();
                    }
                },
                metadata,
            )
        }

        /// The package whose contents tree `fill` writes.
        fn build(fill: impl FnOnce(&Path), metadata: &str) -> Self {
            let temp = TempDir::named("hextar");
            let tree = temp.0.join("tree");
            fs::create_dir_all(&tree).unwrap();
            fill(&tree);
            let outer = temp.0.join("outer");
            fs::create_dir_all(&outer).unwrap();
            let mut pack = tar_create();
            pack.arg("-C").arg(&tree).arg("-czf");
            pack.arg(outer.join("contents.tar.gz"));
            pack.args(fs::read_dir(&tree).unwrap().map(|e| e.unwrap().file_name()));
            assert!(pack.status().unwrap().success());
            fs::write(outer.join("VERSION"), "3").unwrap();
            fs::write(outer.join("metadata.config"), metadata).unwrap();
            let dep = HexDep {
                app: "demo".into(),
                package: "demo".into(),
                version: "1.0.0".into(),
                inner_sha256: String::new(),
                outer_sha256: "0".repeat(64),
                managers: vec!["mix".into()],
            };
            let mut package = Package { temp, outer, dep };
            package.reseal();
            package
        }

        fn good() -> Self {
            Self::new(&[("lib/demo.ex", "defmodule Demo do\nend\n")], METADATA)
        }

        /// Recompute the inner checksum over the outer members as they
        /// stand, into both CHECKSUM and the lock row, so a later check is
        /// reached with the checksum gates passed.
        fn reseal(&mut self) {
            let mut inner = Sha256::new();
            for part in ["VERSION", "metadata.config", "contents.tar.gz"] {
                inner.update(fs::read(self.outer.join(part)).unwrap());
            }
            let inner = hex::encode(inner.finalize());
            fs::write(self.outer.join("CHECKSUM"), inner.to_uppercase()).unwrap();
            self.dep.inner_sha256 = inner;
        }

        fn unpack(&self) -> io::Result<PathBuf> {
            let tar = self.temp.0.join("demo-1.0.0.tar");
            let mut pack = tar_create();
            pack.arg("-C").arg(&self.outer).arg("-cf").arg(&tar);
            for part in ["VERSION", "metadata.config", "contents.tar.gz", "CHECKSUM"] {
                if fs::symlink_metadata(self.outer.join(part)).is_ok() {
                    pack.arg(part);
                }
            }
            assert!(pack.status().unwrap().success());
            self.unpack_tar(&tar)
        }

        fn unpack_tar(&self, tar: &Path) -> io::Result<PathBuf> {
            let (lease, activity) = detached_lease();
            let scratch = self.temp.0.join("scratch");
            let staged = self.temp.0.join("staged");
            fs::create_dir_all(&scratch).unwrap();
            fs::create_dir_all(&staged).unwrap();
            let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let unpacked = unpack_verified(&activity, tar, &scratch, &staged, &self.dep);
            drop(lease);
            unpacked
        }

        fn refusal(&self) -> String {
            match self.unpack() {
                Ok(dir) => panic!("the package was accepted into {}", dir.display()),
                Err(e) => e.to_string(),
            }
        }
    }

    #[test]
    fn a_package_that_matches_its_lock_row_is_unpacked() {
        let package = Package::good();
        let dir = package.unpack().unwrap();
        assert_eq!(dir, package.temp.0.join("staged/demo"));
        assert_eq!(
            fs::read_to_string(dir.join("lib/demo.ex")).unwrap(),
            "defmodule Demo do\nend\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("hex_metadata.config")).unwrap(),
            METADATA
        );
    }

    #[test]
    fn outer_members_that_do_not_hash_to_the_locked_inner_checksum_are_refused() {
        let package = Package::good();
        fs::write(package.outer.join("VERSION"), "4").unwrap();
        let e = package.refusal();
        assert!(e.starts_with("demo: inner checksum mismatch"), "{e}");
        assert!(
            e.contains(&format!("expected {}", package.dep.inner_sha256)),
            "{e}"
        );
    }

    #[test]
    fn a_checksum_member_that_disagrees_with_the_lock_is_refused() {
        let package = Package::good();
        fs::write(package.outer.join("CHECKSUM"), "0".repeat(64)).unwrap();
        assert_eq!(
            package.refusal(),
            "demo: tarball CHECKSUM member disagrees with the lock"
        );
        // Case is not part of the checksum: Hex writes it uppercase.
        let package = Package::good();
        fs::write(package.outer.join("CHECKSUM"), &package.dep.inner_sha256).unwrap();
        package.unpack().unwrap();
    }

    #[test]
    fn a_missing_or_irregular_outer_member_is_refused() {
        for part in ["VERSION", "metadata.config", "contents.tar.gz", "CHECKSUM"] {
            let package = Package::good();
            fs::remove_file(package.outer.join(part)).unwrap();
            let e = package.refusal();
            assert!(
                e.starts_with(&format!("demo: missing {part} in tarball: ")),
                "{e}"
            );
        }
        let package = Package::good();
        fs::remove_file(package.outer.join("VERSION")).unwrap();
        fs::create_dir(package.outer.join("VERSION")).unwrap();
        assert_eq!(package.refusal(), "demo: VERSION is not a regular file");
        // A link is refused as a link, not followed to a regular file.
        let package = Package::good();
        fs::remove_file(package.outer.join("CHECKSUM")).unwrap();
        std::os::unix::fs::symlink("VERSION", package.outer.join("CHECKSUM")).unwrap();
        assert_eq!(package.refusal(), "demo: CHECKSUM is not a regular file");
    }

    #[test]
    fn a_package_that_ships_a_reserved_entry_is_refused() {
        for reserved in [".hex", "hex_metadata.config"] {
            let package = Package::new(&[("lib/demo.ex", ""), (reserved, "planted\n")], METADATA);
            assert_eq!(
                package.refusal(),
                format!("demo: package ships a reserved {reserved} entry; refusing")
            );
        }
    }

    #[test]
    fn metadata_that_names_another_app_or_version_is_refused() {
        for metadata in [
            METADATA.replace("<<\"demo\">>", "<<\"other\">>"),
            METADATA.replace("<<\"1.0.0\">>", "<<\"1.0.1\">>"),
        ] {
            let package = Package::new(&[("lib/demo.ex", "")], &metadata);
            assert_eq!(
                package.refusal(),
                "demo: hex metadata disagrees with the lock (app/version)",
                "{metadata}"
            );
        }
    }

    /// The archive layer refuses an escaping link on extraction, so the
    /// tree walk is driven directly: it is the check that holds for the
    /// links extraction lets through.
    #[test]
    fn dep_tree_refuses_escaping_links_and_special_files() {
        let temp = TempDir::named("hextar-tree");
        let dep = temp.0.join("dep");
        fs::create_dir_all(dep.join("lib")).unwrap();
        fs::write(dep.join("lib/demo.ex"), "").unwrap();
        std::os::unix::fs::symlink("lib/demo.ex", dep.join("inside")).unwrap();
        check_dep_tree(&dep, "demo").unwrap();

        // The target exists, so only the containment comparison refuses it.
        fs::write(temp.0.join("outside"), "").unwrap();
        std::os::unix::fs::symlink("../../outside", dep.join("lib/escape")).unwrap();
        let e = check_dep_tree(&dep, "demo").unwrap_err().to_string();
        assert_eq!(e, "demo: symlink escapes the package");
        fs::remove_file(dep.join("lib/escape")).unwrap();

        std::os::unix::fs::symlink("missing.ex", dep.join("lib/dangling")).unwrap();
        let e = check_dep_tree(&dep, "demo").unwrap_err().to_string();
        assert_eq!(e, "demo: symlink escapes the package");
        fs::remove_file(dep.join("lib/dangling")).unwrap();

        let fifo = std::ffi::CString::new(dep.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let e = check_dep_tree(&dep, "demo").unwrap_err().to_string();
        assert_eq!(e, "demo: hostile special entry");
    }

    /// The tree walk runs on what `unpack_verified` extracts: a link the
    /// archive layer lets through (relative, inside) but that resolves to
    /// nothing is refused; one that resolves inside is kept.
    #[test]
    fn unpacking_runs_the_tree_check_on_the_contents() {
        let with_link = |target: &'static str| {
            Package::build(
                move |tree| {
                    fs::create_dir_all(tree.join("lib")).unwrap();
                    fs::write(tree.join("lib/demo.ex"), "").unwrap();
                    std::os::unix::fs::symlink(target, tree.join("lib/alias.ex")).unwrap();
                },
                METADATA,
            )
        };
        let package = with_link("demo.ex");
        let dir = package.unpack().unwrap();
        assert_eq!(
            fs::read_link(dir.join("lib/alias.ex")).unwrap(),
            Path::new("demo.ex")
        );

        assert_eq!(
            with_link("missing.ex").refusal(),
            "demo: symlink escapes the package"
        );
    }

    #[test]
    fn archives_that_do_not_extract_are_refused_with_their_stage() {
        let package = Package::good();
        let tar = package.temp.0.join("junk.tar");
        fs::write(&tar, "not a tar archive").unwrap();
        let e = package.unpack_tar(&tar).unwrap_err().to_string();
        assert!(e.starts_with("demo: outer tar extraction failed: "), "{e}");

        // Checksums resealed over the junk, so only extraction refuses it.
        let mut package = Package::good();
        fs::write(package.outer.join("contents.tar.gz"), "not gzip").unwrap();
        package.reseal();
        let e = package.refusal();
        assert!(e.starts_with("demo: contents extraction failed: "), "{e}");
    }
}

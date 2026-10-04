//! `node_modules/.bin` (node tailor): the launchers a sync links for the
//! packages a project can run by name.

use super::*;
use std::collections::btree_map::Entry;

/// .bin launchers for physically top-level (hoisted) packages, which is what
/// node_modules/.bin holds in npm's own layout.
pub(super) fn link_package_bins(
    staged: &Path,
    packages: &[(NpmPackage, PathBuf)],
) -> io::Result<()> {
    // Per `.bin` directory: each bin name in folded form, with the name and
    // the package that claimed it first.
    let mut claimed = BTreeMap::<(PathBuf, String), (String, String)>::new();
    for (p, _) in packages {
        if !is_importer_top_level(&p.path) || p.bin.is_empty() {
            continue;
        }
        let bin_dir = env_node_modules_path(staged, &p.path).join(".bin");
        fs::create_dir_all(&bin_dir)?;
        for (bin_name, rel) in &p.bin {
            // bin metadata comes from the lockfile (attacker-editable), so
            // it is validated hard: single normal name component, relative
            // target with only normal components, canonical target inside
            // the package directory, not a symlink.
            let name_ok = !bin_name.is_empty()
                && !bin_name.starts_with('.')
                && !bin_name.contains('/')
                && !bin_name.contains('\\');
            let rel_path = normalized_bin_path(rel);
            if !name_ok || rel_path.is_err() {
                return Err(err(format!(
                    "{}: unsafe bin entry {bin_name:?} -> {rel:?}",
                    p.path
                )));
            }
            let rel_path = rel_path.unwrap();
            let pkg_dir = env_package_path(staged, &p.path);
            let target_file = pkg_dir.join(&rel_path);
            let md = match fs::symlink_metadata(&target_file) {
                Ok(md) => md,
                Err(_) => continue, // bin target genuinely absent: npm tolerates this
            };
            if !md.is_file() {
                return Err(err(format!(
                    "{}: bin target {rel} is not a regular file",
                    p.path
                )));
            }
            let canon = target_file.canonicalize()?;
            if !canon.starts_with(pkg_dir.canonicalize()?) {
                return Err(err(format!(
                    "{}: bin target {rel} escapes the package directory",
                    p.path
                )));
            }
            // Relative link: [<importer>/]node_modules/.bin/x -> ../<name>/<rel>.
            let link_target = bin_link_target(&p.path, &rel_path.to_string_lossy());
            let link = bin_dir.join(bin_name);
            // A case-insensitive filesystem (APFS) keeps one of `Tool` and
            // `tool`, and the other command would run the wrong package.
            match claimed.entry((bin_dir.clone(), folded(bin_name))) {
                Entry::Occupied(first) if first.get().0 != *bin_name => {
                    let (first_name, first_path) = first.get();
                    return Err(err(format!(
                        "bin {bin_name:?} from {} and bin {first_name:?} from {first_path} \
                         differ only by case or Unicode normalization, so a case-insensitive \
                         filesystem would keep one of them",
                        p.path
                    )));
                }
                Entry::Occupied(_) => {}
                Entry::Vacant(slot) => {
                    slot.insert((bin_name.clone(), p.path.clone()));
                }
            }
            if link.symlink_metadata().is_ok() {
                // Real graphs collide (playwright + @playwright/test both
                // declare `playwright`). npm keeps the first hoisted claim;
                // plan order is sorted, so first-wins is deterministic.
                crate::kernel::ui::note(&format!(
                    "bin {bin_name:?} already claimed; skipping the one from {}",
                    p.path
                ));
                continue;
            }
            std::os::unix::fs::symlink(&link_target, &link)?;
            use std::os::unix::fs::PermissionsExt;
            let mut perms = md.permissions();
            perms.set_mode(perms.mode() | 0o755);
            fs::set_permissions(&target_file, perms)?;
        }
    }
    Ok(())
}

/// A bin name as a case-insensitive filesystem compares it: Unicode NFC,
/// then lower case. Two names with the same folded form are one entry there.
fn folded(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization as _;
    name.nfc().collect::<String>().to_lowercase()
}

/// Bins land in one `.bin` directory per importer. Two names that a
/// case-insensitive filesystem would merge are refused; the same name twice
/// keeps npm's first claim.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn package(path: &str, bin: &str) -> (NpmPackage, PathBuf) {
        let package = NpmPackage {
            path: path.into(),
            name: path.rsplit('/').next().unwrap().into(),
            version: "1.0.0".into(),
            url: String::new(),
            integrity: String::new(),
            bin: vec![(bin.into(), "cli.js".into())],
            patch: None,
            git: None,
            foreign_platform: false,
            needs_workspace: false,
        };
        (package, PathBuf::new())
    }

    fn staged(paths: &[&str]) -> TempDir {
        let staged = TempDir::named("node-bins");
        for path in paths {
            let dir = env_package_path(&staged.0, path);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("cli.js"), "#!/usr/bin/env node\n").unwrap();
        }
        staged
    }

    #[test]
    fn bin_names_a_case_insensitive_filesystem_would_merge_are_refused() {
        for (first, second) in [
            ("Tool", "tool"),
            ("\u{e9}", "\u{c9}"),
            ("e\u{301}", "\u{e9}"),
        ] {
            let staged = staged(&["node_modules/a", "node_modules/b"]);
            let packages = [
                package("node_modules/a", first),
                package("node_modules/b", second),
            ];
            let error = link_package_bins(&staged.0, &packages).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "bin {second:?} from node_modules/b and bin {first:?} from node_modules/a \
                     differ only by case or Unicode normalization, so a case-insensitive \
                     filesystem would keep one of them"
                )
            );
        }
    }

    #[test]
    fn the_same_bin_name_keeps_the_first_claim_and_other_importers_are_separate() {
        let staged = staged(&[
            "node_modules/a",
            "node_modules/b",
            "packages/web/node_modules/c",
        ]);
        let packages = [
            package("node_modules/a", "tool"),
            package("node_modules/b", "tool"),
            package("packages/web/node_modules/c", "Tool"),
        ];
        link_package_bins(&staged.0, &packages).unwrap();
        let link = staged.0.join("node_modules/.bin/tool");
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("../a/cli.js"));
        let web = env_node_modules_path(&staged.0, "packages/web/node_modules/c");
        assert_eq!(
            fs::read_link(web.join(".bin/Tool")).unwrap(),
            Path::new("../c/cli.js")
        );
    }
}

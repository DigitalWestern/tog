//! What a failed gem build left in the staged GEM_HOME, so the retry
//! against the whole host starts from the state a clean install would.
//!
//! Every gem of a plan installs into one staged GEM_HOME. A hermetic
//! attempt that fails may still have written there, and the retry runs in
//! the same tree. RubyGems' own leftovers from a failed extension build are
//! known (checked with RubyGems 3.6 and a gem whose `extconf.rb` aborts):
//! the gem's directory under `gems/`, its extension directory under
//! `extensions/<platform>/<abi>/` with `gem_make.out` and `mkmf.log`, the
//! platform and ABI directories above that when this was the first
//! extension, and, in an empty GEM_HOME, the standard subdirectories
//! RubyGems creates before it installs anything. Those are removed. Any
//! other change is the build's own doing, and the retry is refused rather
//! than run on top of it.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The subdirectories RubyGems creates in an empty GEM_HOME before its
/// first install (`Gem.ensure_gem_subdirectories`).
const STANDARD_SUBDIRECTORIES: &[&str] = &[
    "build_info",
    "cache",
    "doc",
    "extensions",
    "gems",
    "plugins",
    "specifications",
];

/// One path's state. A directory is compared by kind, mode and inode only:
/// its size and modification time change whenever an entry under it is
/// added or removed, and every such entry has its own line in the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    kind: char,
    mode: u32,
    inode: u64,
    size: u64,
    modified_ns: i128,
    target: Option<PathBuf>,
}

/// Every path under a GEM_HOME, relative to it, with its state. Symlinks
/// are recorded, never followed.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Manifest(BTreeMap<PathBuf, Entry>);

pub(super) fn manifest(root: &Path) -> io::Result<Manifest> {
    let mut entries = BTreeMap::new();
    walk(root, Path::new(""), &mut entries)?;
    Ok(Manifest(entries))
}

fn walk(root: &Path, relative: &Path, entries: &mut BTreeMap<PathBuf, Entry>) -> io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let path = relative.join(entry.file_name());
        let metadata = fs::symlink_metadata(root.join(&path))?;
        let file_type = metadata.file_type();
        let (kind, target) = if file_type.is_symlink() {
            ('l', Some(fs::read_link(root.join(&path))?))
        } else if file_type.is_dir() {
            ('d', None)
        } else if file_type.is_file() {
            ('f', None)
        } else {
            ('o', None)
        };
        let directory = kind == 'd';
        entries.insert(
            path.clone(),
            Entry {
                kind,
                mode: metadata.mode(),
                inode: metadata.ino(),
                size: if directory { 0 } else { metadata.size() },
                modified_ns: if directory {
                    0
                } else {
                    i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())
                },
                target,
            },
        );
        if directory {
            walk(root, &path, entries)?;
        }
    }
    Ok(())
}

/// The first path, in path order, that differs between two manifests:
/// added, removed, or changed.
fn first_change(before: &Manifest, after: &Manifest) -> Option<PathBuf> {
    before
        .0
        .keys()
        .chain(after.0.keys())
        .filter(|path| before.0.get(*path) != after.0.get(*path))
        .min()
        .cloned()
}

/// Remove what a failed install of `full_name` leaves in `gem_home` (see
/// the module comment), then refuse if anything else differs from
/// `before`, the manifest taken before the attempt.
pub(super) fn discard_failed_attempt(
    gem_home: &Path,
    full_name: &str,
    before: &Manifest,
) -> io::Result<()> {
    let known = |relative: &Path| before.0.contains_key(relative);
    remove_if_new(gem_home, &Path::new("gems").join(full_name), &known)?;
    let extensions = Path::new("extensions");
    let mut new_parents = Vec::new();
    if gem_home.join(extensions).is_dir() {
        for platform in fs::read_dir(gem_home.join(extensions))? {
            let platform = extensions.join(platform?.file_name());
            if !gem_home.join(&platform).is_dir() {
                continue;
            }
            for abi in fs::read_dir(gem_home.join(&platform))? {
                let abi = platform.join(abi?.file_name());
                remove_if_new(gem_home, &abi.join(full_name), &known)?;
                new_parents.push(abi);
            }
            new_parents.push(platform);
        }
    }
    new_parents.extend(STANDARD_SUBDIRECTORIES.iter().map(PathBuf::from));
    for directory in new_parents {
        if known(&directory) {
            continue;
        }
        // Only an empty directory the attempt created: `remove_dir` fails
        // on anything else, which the comparison below then reports.
        let _ = fs::remove_dir(gem_home.join(directory));
    }
    let after = manifest(gem_home)?;
    match first_change(before, &after) {
        None => Ok(()),
        Some(path) => Err(io::Error::other(format!(
            "the failed build changed {} in the gem home, outside the gem's own \
             directories; it was not retried against the whole host",
            gem_home.join(path).display()
        ))),
    }
}

/// Remove `relative` under `gem_home` if the attempt created it. A path
/// that was there before is the comparison's to report, not ours to
/// delete.
fn remove_if_new(
    gem_home: &Path,
    relative: &Path,
    known: &dyn Fn(&Path) -> bool,
) -> io::Result<()> {
    let path = gem_home.join(relative);
    if known(relative) || fs::symlink_metadata(&path).is_err() {
        return Ok(());
    }
    crate::kernel::store::remove_tree(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// A GEM_HOME with one gem installed and the directories RubyGems
    /// made for it.
    fn gem_home(label: &str) -> TempDir {
        let temp = TempDir::named(&format!("ruby-gem-home-{label}"));
        for directory in STANDARD_SUBDIRECTORIES {
            fs::create_dir_all(temp.0.join(directory)).unwrap();
        }
        fs::create_dir_all(temp.0.join("bin")).unwrap();
        fs::create_dir_all(temp.0.join("gems/pure-1.0/lib")).unwrap();
        fs::write(
            temp.0.join("gems/pure-1.0/lib/pure.rb"),
            "module Pure; end\n",
        )
        .unwrap();
        fs::write(temp.0.join("specifications/pure-1.0.gemspec"), "spec\n").unwrap();
        temp
    }

    /// What RubyGems leaves when `failext-1.0`'s extension build aborts.
    fn fail_like_rubygems(root: &Path) {
        let extension = root.join("extensions/x86_64-linux/3.4.0-static/failext-1.0");
        fs::create_dir_all(&extension).unwrap();
        fs::write(extension.join("gem_make.out"), "abort\n").unwrap();
        fs::write(extension.join("mkmf.log"), "have_header: no\n").unwrap();
        fs::create_dir_all(root.join("gems/failext-1.0/ext/failext")).unwrap();
        fs::write(
            root.join("gems/failext-1.0/ext/failext/extconf.rb"),
            "abort\n",
        )
        .unwrap();
    }

    #[test]
    fn manifests_see_additions_removals_and_rewrites() {
        let home = gem_home("diff");
        let before = manifest(&home.0).unwrap();
        assert_eq!(first_change(&before, &manifest(&home.0).unwrap()), None);

        fs::write(home.0.join("bin/marker"), "x").unwrap();
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("bin/marker"))
        );
        fs::remove_file(home.0.join("bin/marker")).unwrap();

        // Same size, new bytes through a new inode: still a change.
        let file = home.0.join("gems/pure-1.0/lib/pure.rb");
        fs::remove_file(&file).unwrap();
        fs::write(&file, "module Evil; end\n").unwrap();
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("gems/pure-1.0/lib/pure.rb"))
        );

        let home = gem_home("diff-link");
        let before = manifest(&home.0).unwrap();
        std::os::unix::fs::symlink("/etc", home.0.join("bin/etc")).unwrap();
        assert_eq!(
            first_change(&before, &manifest(&home.0).unwrap()),
            Some(PathBuf::from("bin/etc"))
        );
    }

    /// A failed extension build's own leftovers are removed and the retry
    /// may run; the tree is then what it was before the attempt.
    #[test]
    fn rubygems_own_leftovers_are_discarded() {
        let home = gem_home("leftovers");
        let before = manifest(&home.0).unwrap();
        fail_like_rubygems(&home.0);
        discard_failed_attempt(&home.0, "failext-1.0", &before).unwrap();
        assert_eq!(manifest(&home.0).unwrap(), before);

        // In an empty GEM_HOME the first install also creates RubyGems'
        // standard subdirectories.
        let empty = TempDir::named("ruby-gem-home-empty");
        fs::create_dir_all(empty.0.join("bin")).unwrap();
        let before = manifest(&empty.0).unwrap();
        for directory in STANDARD_SUBDIRECTORIES {
            fs::create_dir_all(empty.0.join(directory)).unwrap();
        }
        fail_like_rubygems(&empty.0);
        discard_failed_attempt(&empty.0, "failext-1.0", &before).unwrap();
        assert_eq!(manifest(&empty.0).unwrap(), before);
    }

    /// A build that wrote anywhere else, another gem included, is not
    /// retried, and the refusal names the first changed path.
    #[test]
    fn a_failed_build_that_wrote_elsewhere_refuses_the_retry() {
        let home = gem_home("elsewhere");
        let before = manifest(&home.0).unwrap();
        fail_like_rubygems(&home.0);
        fs::write(
            home.0.join("gems/pure-1.0/lib/pure.rb"),
            "module Evil; end\n",
        )
        .unwrap();
        fs::write(home.0.join("bin/marker"), "x").unwrap();
        let error = discard_failed_attempt(&home.0, "failext-1.0", &before).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("bin/marker"), "{message}");
        assert!(message.contains("not retried"), "{message}");
        // RubyGems' own leftovers went regardless.
        assert!(!home.0.join("gems/failext-1.0").exists());
    }
}

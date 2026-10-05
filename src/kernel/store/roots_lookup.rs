//! Resolve a root key against the directory holding the record.

use super::*;

/// The directory-entry name `key` stands for among `names`: itself when an
/// entry has exactly that name, otherwise the one entry that equals it
/// ignoring ASCII case (what a case-insensitive filesystem opened). `None`
/// when neither exists. The caller must verify the recovered entry's identity.
fn on_disk_spelling(
    names: impl IntoIterator<Item = std::ffi::OsString>,
    key: &str,
) -> Option<String> {
    let mut folded = None;
    for name in names {
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == key {
            return Some(name.to_string());
        }
        if folded.is_none() && name.eq_ignore_ascii_case(key) {
            folded = Some(name.to_string());
        }
    }
    folded
}

pub(super) fn verified_root_spelling(
    dir: RawFd,
    key: &str,
    expected: &libc::stat,
) -> io::Result<String> {
    let changed = || {
        io::Error::new(
            io::ErrorKind::Interrupted,
            format!("root registry entry {key} changed during lookup; retry later"),
        )
    };
    let spelling = on_disk_spelling(read_dir_names_at(dir)?, key).ok_or_else(changed)?;
    let actual = stat_at(dir, spelling.as_bytes()).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            changed()
        } else {
            error
        }
    })?;
    if !same_inode(expected, &actual) {
        return Err(changed());
    }
    Ok(spelling)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::ffi::OsString;

    fn names(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    /// A key typed in another case maps to the record's on-disk name, an
    /// exact name wins over a folded one, and an absent key maps to
    /// nothing (#163: the dry-run exclusion compares on-disk names).
    #[test]
    fn a_key_maps_to_its_on_disk_spelling() {
        let lower = "abcdef0123456789abcdef0123456789abcdef01";
        let upper = lower.to_ascii_uppercase();
        assert_eq!(
            on_disk_spelling(names(&[lower]), &upper).as_deref(),
            Some(lower)
        );
        assert_eq!(
            on_disk_spelling(names(&[&upper, lower]), lower).as_deref(),
            Some(lower)
        );
        assert_eq!(on_disk_spelling(names(&["other"]), lower), None);
    }

    #[test]
    fn a_folded_neighbor_cannot_replace_a_disappearing_record() {
        let temp = TempDir::new();
        let lower = "abcdef0123456789abcdef0123456789abcdef01";
        let upper = lower.to_ascii_uppercase();
        fs::write(temp.0.join(lower), "original").unwrap();
        fs::write(temp.0.join(&upper), "neighbor").unwrap();
        let dir = open_real_directory(&temp.0, "roots").unwrap();
        let expected = stat_at(dir.as_raw_fd(), lower.as_bytes()).unwrap();
        let neighbor = stat_at(dir.as_raw_fd(), upper.as_bytes()).unwrap();
        if same_inode(&expected, &neighbor) {
            return;
        }
        fs::remove_file(temp.0.join(lower)).unwrap();
        assert_eq!(
            verified_root_spelling(dir.as_raw_fd(), lower, &expected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(fs::read_to_string(temp.0.join(&upper)).unwrap(), "neighbor");
    }

    #[test]
    fn spelling_uses_the_held_directory_after_path_replacement() {
        let temp = TempDir::new();
        let roots = temp.0.join("roots");
        fs::create_dir(&roots).unwrap();
        let key = "abcdef0123456789abcdef0123456789abcdef01";
        fs::write(roots.join(key), "original").unwrap();
        let dir = open_real_directory(&roots, "roots").unwrap();
        let expected = stat_at(dir.as_raw_fd(), key.as_bytes()).unwrap();
        fs::rename(&roots, temp.0.join("held")).unwrap();
        fs::create_dir(&roots).unwrap();
        fs::write(roots.join(key.to_ascii_uppercase()), "replacement").unwrap();
        assert_eq!(
            verified_root_spelling(dir.as_raw_fd(), key, &expected).unwrap(),
            key
        );
    }
}

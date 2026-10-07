//! The containment rules every listing passes before tar extracts it:
//! names, symlinks and hard links that stay inside the destination after
//! `--strip-components`, and no two names APFS would fold into one.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use super::{err, Entry, EntryKind, ExtractOptions};

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
    let kept = kept_entries(entries, strip)?;
    // Two names APFS would treat as one extract as one file there and two
    // on Linux, so one archive would realize two different trees. Every
    // prefix counts, since `Lib/a` and `lib/b` share one directory on APFS
    // and two on Linux. Identical spellings are `written_once`'s rule.
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
    hard_links_contained(&kept, strip)?;
    written_once(&kept)
}

/// The entries tar writes after `--strip-components strip`, each with its
/// name as extraction compares names: the components past the first
/// `strip`, `.` dropped, so `pkg/./a` and `pkg/a/` are both `pkg/a`. An
/// absolute name or a `..` component is refused wherever it sits. Special
/// files never become entries: the listing refuses them where it reads
/// their type.
fn kept_entries(entries: &[Entry], strip: usize) -> io::Result<Vec<(&Entry, Vec<&str>)>> {
    let mut kept: Vec<(&Entry, Vec<&str>)> = Vec::new();
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
    Ok(kept)
}

/// No name is written more than once: tar extracts the last write, so
/// neither entry's bytes are what the whole archive says, and whether a
/// later write replaces a hard-linked file or writes through it differs by
/// tar, so two platforms could realize different trees. The rule is the
/// one `read_member` applies (#556, #613): a member read in process and
/// the tree extracted on disk refuse the same archives, so a manifest read
/// out of an sdist can never see bytes its build does not.
///
/// A directory entry may repeat (`pkg/` then `pkg/./`): a directory
/// carries no bytes, tar creates it once and the second entry only reapplies
/// metadata the store normalizes away, so every tar realizes one directory.
/// A directory sharing its name with a file, link or symlink is refused
/// with the rest: one tar fails on the existing entry where another
/// replaces it.
fn written_once(kept: &[(&Entry, Vec<&str>)]) -> io::Result<()> {
    let mut seen: BTreeMap<String, &Entry> = BTreeMap::new();
    for (entry, stripped) in kept {
        match seen.insert(stripped.join("/"), entry) {
            Some(earlier) if earlier.kind == EntryKind::Dir && entry.kind == EntryKind::Dir => {}
            Some(earlier) => {
                return Err(err(format!(
                    "archive entry {:?} is written more than once (also as {:?}); refusing",
                    earlier.name, entry.name
                )));
            }
            None => {}
        }
    }
    Ok(())
}

/// A hard link is tar's second name for a member it already extracted, so
/// it is accepted when that member is an earlier regular file kept after
/// `--strip-components`. Both tars strip a hard link's target the way they
/// strip its name, so the target is compared in stripped form. A link or
/// target written twice is refused by `written_once`, with every other
/// repeated name.
fn hard_links_contained(kept: &[(&Entry, Vec<&str>)], strip: usize) -> io::Result<()> {
    let mut earlier_files: BTreeSet<String> = BTreeSet::new();
    for (entry, stripped) in kept {
        let name = stripped.join("/");
        match entry.kind {
            EntryKind::File => {
                earlier_files.insert(name);
            }
            EntryKind::HardLink => {
                let target = entry.link.as_deref().unwrap_or("");
                let refuse = |reason: &str| {
                    err(format!(
                        "archive hard link {:?} -> {:?}: {reason}",
                        entry.name, target
                    ))
                };
                let components = contained_components(target).map_err(|reason| refuse(&reason))?;
                if components.len() <= strip {
                    return Err(refuse("the target does not survive --strip-components"));
                }
                let target_name = components[strip..]
                    .iter()
                    .copied()
                    .filter(|component| *component != ".")
                    .collect::<Vec<_>>()
                    .join("/");
                if target_name == name {
                    return Err(refuse("the link names itself"));
                }
                if !earlier_files.contains(&target_name) {
                    return Err(refuse(
                        "the target is not an earlier regular file in the archive",
                    ));
                }
            }
            EntryKind::Dir | EntryKind::Symlink => {}
        }
    }
    Ok(())
}

/// The stored name of the regular file the hard link `link` names, under
/// extraction's hard-link rules with nothing stripped: every name in
/// `entries` must be contained, and every hard link passes the checks
/// [`validate_with_options`] applies to hard links, so the target is an
/// earlier regular file, not the link itself, and neither is written
/// twice. Symlinks and folded names are not checked: nothing is written to
/// disk, so neither can change which bytes are read. A target spelled
/// `pkg/./a` or `pkg/a/` finds the member stored as `pkg/a`, as tar would.
pub(super) fn hard_link_target<'a>(entries: &'a [Entry], link: &Entry) -> io::Result<&'a str> {
    let kept = kept_entries(entries, 0)?;
    hard_links_contained(&kept, 0)?;
    written_once(&kept)?;
    let target = link.link.as_deref().unwrap_or("");
    let wanted: Vec<&str> = contained_components(target)
        .map_err(|reason| err(format!("archive hard link {:?}: {reason}", link.name)))?
        .into_iter()
        .filter(|component| *component != ".")
        .collect();
    kept.iter()
        .find(|(entry, name)| entry.kind == EntryKind::File && *name == wanted)
        .map(|(entry, _)| entry.name.as_str())
        .ok_or_else(|| err(format!("archive hard link {:?}: no target", link.name)))
}

/// [`written_once`] over the whole listing with nothing stripped, for a
/// read that extracts nothing (`read_member`): the archive is refused on
/// the same repeated names extraction refuses it on.
pub(super) fn members_written_once(entries: &[Entry]) -> io::Result<()> {
    written_once(&kept_entries(entries, 0)?)
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

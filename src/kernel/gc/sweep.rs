//! Sweep phase 4 (kernel gc): `execute` is the only phase that removes
//! anything, relative to the descriptors `read` held, after confirming the
//! snapshot is unchanged.

use super::*;

/// Phase 4. The only phase that deletes.
///
/// Each candidate is re-`fstatat`ed relative to the descriptor held since
/// the read phase and compared with the `(dev, ino)` and file type recorded
/// in the plan. A replacement stops that deletion with an error; it is never
/// skipped silently. An error after deletion has begun reports what was
/// already removed — there is no filesystem rollback, and the zero-deletions
/// promise covers validation failures, not post-validation I/O errors.
pub(super) fn execute<W: Write>(
    plan: &SweepPlan,
    snapshot: &Snapshot,
    store: &Store,
    activity: &StoreActivity,
    out: &mut W,
) -> io::Result<Report> {
    store.require_exclusive_activity(activity, "garbage collection")?;
    // Crash residue from the read phase is removed here and only here: after
    // the deletion plan has been validated, under the continuously held
    // exclusive lease. A dry run never reaches this, so it deletes nothing —
    // including crash residue.
    store.clear_crash_temps(&snapshot.crash_temps)?;
    let mut report = Report::default();
    for removal in &plan.removals {
        let parent = snapshot.dirs.get(removal.parent);
        let result = (|| -> io::Result<()> {
            confirm_unchanged(
                parent,
                removal.name.as_bytes(),
                &removal.stat,
                &removal.label,
            )?;
            if let Some((meta_name, meta_stat)) = &removal.companion {
                confirm_unchanged(
                    &snapshot.dirs.meta,
                    meta_name.as_bytes(),
                    meta_stat,
                    &format!("metadata for {}", removal.label),
                )?;
            }
            if (removal.stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                remove_snapshot_entry(
                    &parent.file,
                    removal.name.as_bytes(),
                    &removal.stat,
                    &removal.label,
                )?;
            } else {
                unlink_snapshot_entry(
                    &parent.file,
                    removal.name.as_bytes(),
                    &removal.stat,
                    &removal.label,
                )?;
            }
            // The candidate is gone. Account for it *before* touching its
            // companion record, so a companion unlink failure can never drop
            // a completed deletion from the report.
            report.freed_bytes += removal.bytes;
            match removal.counter {
                Counter::Objects => report.objects += 1,
                Counter::CachedArtifacts => report.cached_artifacts += 1,
                Counter::Stages => report.stages += 1,
                Counter::Forests => report.forests += 1,
                Counter::Backups => report.backups += 1,
            }
            if let Some((meta_name, meta_stat)) = &removal.companion {
                unlink_snapshot_entry(
                    &snapshot.dirs.meta.file,
                    meta_name.as_bytes(),
                    meta_stat,
                    &format!("metadata for {}", removal.label),
                )
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "{error}; the record meta/{meta_name} is orphaned and blocks the \
                             next sweep — restore the removed object or delete the stray record \
                             with `tog gc --migrate-metadata`"
                        ),
                    )
                })?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if report != Report::default() {
                writeln!(
                    out,
                    "stopped after an error; deletions already completed: {} objects, {} cached \
                     artifacts, {} stages, {} forests, {} backups, {} freed",
                    report.objects,
                    report.cached_artifacts,
                    report.stages,
                    report.forests,
                    report.backups,
                    size(report.freed_bytes)
                )?;
            }
            return Err(io::Error::new(
                error.kind(),
                format!("{}: {error}", removal.label),
            ));
        }
    }
    for note in &plan.notes {
        writeln!(out, "skipped {note}")?;
    }
    Ok(report)
}

/// Compare a candidate with what the plan recorded, immediately before its
/// removal. A replaced name, or a name that changed file type, is an error.
pub(super) fn confirm_unchanged(
    parent: &HeldDir,
    name: &[u8],
    expected: &libc::stat,
    label: &str,
) -> io::Result<()> {
    let actual = store::stat_at(parent.file.as_raw_fd(), name).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{label} disappeared from {} before removal", parent.label),
        )
    })?;
    if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!(
                "{label} was replaced after the deletion plan was made; nothing was removed for it"
            ),
        ));
    }
    if (actual.st_mode & libc::S_IFMT) != (expected.st_mode & libc::S_IFMT) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} changed file type after the deletion plan was made"),
        ));
    }
    Ok(())
}

pub(super) fn remove_snapshot_entry(
    parent: &fs::File,
    name: &[u8],
    expected: &libc::stat,
    label: &str,
) -> io::Result<()> {
    if store::remove_tree_entry_if_same(parent.as_raw_fd(), name, expected)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("{label} changed during cleanup; retry later"),
        ))
    }
}

pub(super) fn unlink_snapshot_entry(
    parent: &fs::File,
    name: &[u8],
    expected: &libc::stat,
    label: &str,
) -> io::Result<()> {
    if store::unlink_if_same(parent.as_raw_fd(), name, expected, 0)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("{label} changed during cleanup; retry later"),
        ))
    }
}

//! Recovery of interrupted resolution publications: which journals are
//! trusted, and how each state is finished or undone (kernel layer).

use super::*;

/// Is there a publication journal in the project at `dir`? Only `dir`
/// itself is looked at, never an ancestor: a journal belongs to the
/// project a command operates on. Store-free and cheap: a command calls
/// this first and opens the store only when recovery has work to do.
pub fn has_pending_journal(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir.join(JOURNAL_DIR)) else {
        return false;
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .any(|name| is_journal_name(&name))
}

pub(super) fn is_journal_name(name: &str) -> bool {
    name.strip_suffix(".json")
        .is_some_and(|eco| check_ecosystem(eco).is_ok())
}

/// Recover the interrupted resolution publications of the project at
/// `dir` (the project the command operates on; a workspace root's journal
/// is recovered by the next transaction there). Every tog command that
/// writes a project runs this before anything else. Takes the store's
/// project lock and the project directory's own lock itself.
pub fn recover_project(
    store: &Store,
    activity: &StoreActivity,
    dir: &Path,
) -> io::Result<Vec<Restored>> {
    if !has_pending_journal(dir) {
        return Ok(Vec::new());
    }
    let root = ProjectRoot::open(dir)?;
    let lock = store.project_lock_in(&root)?;
    let _dir_lock = lock_project_dir(&root)?;
    let notes = recover_locked(store, activity, &root, &lock)?;
    narrate(root.path(), &notes, "recovered");
    Ok(notes)
}

/// The `flock` every holder of a project's journal takes on the project
/// directory itself. The store's project lock is per store; this one is
/// per project, whatever store a process uses.
pub(super) fn lock_project_dir(root: &ProjectRoot) -> io::Result<fs::File> {
    let file = store::open_file_at(
        root.as_raw_fd(),
        b".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    file.lock()?;
    Ok(file)
}

pub(super) fn recover_locked(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
) -> io::Result<Vec<Restored>> {
    let Some(journals) = root.subdir(Path::new(JOURNAL_DIR))? else {
        return Ok(Vec::new());
    };
    let mut notes = Vec::new();
    let mut names = store::read_dir_names_at(journals.as_raw_fd())?;
    names.sort();
    for name in names {
        let Some(name) = name.to_str() else { continue };
        if is_journal_temp(name) {
            unlink_at(journals.as_raw_fd(), OsStr::new(name))?;
            continue;
        }
        if !is_journal_name(name) {
            continue;
        }
        let shown = journals.path().join(name);
        let journal = read_journal(&journals, name)?;
        check_journal(store, activity, root, lock, &journal)
            .map_err(|detail| untrusted_journal(&shown, &detail))?;
        match journal.state {
            JournalState::Held | JournalState::Finished => {
                finish(store, activity, root, lock, &journal)?;
            }
            JournalState::Committed => {
                finish_committed(store, activity, root, lock, &journal)?;
            }
            JournalState::Publishing => {
                notes.extend(undo(store, root, &journal)?);
                finish(store, activity, root, lock, &journal)?;
            }
        }
    }
    Ok(notes)
}

/// Whether `journal` describes a publication tog made in this project
/// with this store. Returns what does not hold, in words.
fn check_journal(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
    journal: &Journal,
) -> Result<(), String> {
    if !store::is_object_id(&journal.originals) {
        return Err("its originals id is malformed".into());
    }
    for dir in &journal.created_dirs {
        let dir = Path::new(dir);
        check_target(dir).map_err(|error| error.to_string())?;
        let ours = [".tog", JOURNAL_DIR, RESOLUTION_DIR]
            .iter()
            .any(|tog| dir == Path::new(tog));
        let a_parent = journal
            .targets
            .iter()
            .any(|target| Path::new(&target.target).starts_with(dir));
        if !ours && !a_parent {
            return Err(format!(
                "it names {} as a directory it created",
                dir.display()
            ));
        }
    }
    for target in &journal.targets {
        check_journal_target(journal, target)?;
    }
    let identity = store
        .published_identity(&journal.originals)
        .map_err(|error| error.to_string())?;
    let Some(identity) = identity else {
        return match journal.state {
            // Held: killed before the originals were committed, so nothing
            // was rooted and nothing in the project was touched. Finished:
            // killed after the originals were released, and `tog gc` has
            // collected them since. Either way only the journal is left.
            JournalState::Held | JournalState::Finished => Ok(()),
            _ => Err(format!(
                "its originals object {} is not in this store ({})",
                journal.originals,
                store.root.display()
            )),
        };
    };
    if identity.kind != ORIGINALS_KIND || identity.name != journal.ecosystem {
        return Err(format!(
            "{} is not a {} originals object",
            journal.originals, journal.ecosystem
        ));
    }
    // Neither state touches a target again, and a finished journal's
    // originals may already be unrooted.
    if matches!(journal.state, JournalState::Held | JournalState::Finished) {
        return Ok(());
    }
    let rooted = store
        .rooted_objects_locked(activity, root, lock)
        .map_err(|error| error.to_string())?;
    if !rooted.contains(&journal.originals) {
        return Err(format!(
            "its originals object {} is not rooted to this project",
            journal.originals
        ));
    }
    for target in &journal.targets {
        let listed = (0..).map_while(|index| {
            identity
                .inputs
                .get(&format!("target:{index}"))
                .map(|name| (index, name, identity.inputs.get(&format!("digest:{index}"))))
        });
        let matched = listed
            .into_iter()
            .find(|(_, name, _)| **name == target.target)
            .is_some_and(|(index, _, digest)| {
                digest == Some(&target.original)
                    && match &target.copy {
                        Some(copy) => *copy == index.to_string(),
                        None => target.original == ABSENT,
                    }
            });
        if !matched {
            return Err(format!(
                "its originals object does not hold {} at the digest it names",
                target.target
            ));
        }
    }
    Ok(())
}

/// One target: a project path of the kind a transaction holds (no `.tog`
/// state but the receipt), its temporary named exactly as `temp_beside`
/// names it and beside it, and well-formed digests.
fn check_journal_target(journal: &Journal, target: &JournalTarget) -> Result<(), String> {
    let relative = Path::new(&target.target);
    check_target(relative).map_err(|error| error.to_string())?;
    if relative.starts_with(".tog") && relative != receipt_path(&journal.ecosystem) {
        return Err(format!("it names {} as a target", target.target));
    }
    if !is_temp_for(relative, Path::new(&target.temp)) {
        return Err(format!(
            "{} is not a temporary tog makes for {}",
            target.temp, target.target
        ));
    }
    if parse_digest(&target.new).is_none()
        || (target.original != ABSENT && parse_digest(&target.original).is_none())
    {
        return Err(format!("a digest for {} is malformed", target.target));
    }
    Ok(())
}

/// `temp` is `<dir>/.<name>.tog-<16 hex>.tmp` for `target` `<dir>/<name>`.
fn is_temp_for(target: &Path, temp: &Path) -> bool {
    if check_target(temp).is_err() || temp.parent() != target.parent() {
        return false;
    }
    let (Some(name), Some(temp)) = (
        target.file_name().and_then(OsStr::to_str),
        temp.file_name().and_then(OsStr::to_str),
    ) else {
        return false;
    };
    temp.strip_prefix('.')
        .and_then(|rest| rest.strip_prefix(name))
        .and_then(|rest| rest.strip_prefix(".tog-"))
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(|hex| {
            hex.len() == 16
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn untrusted_journal(shown: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the resolution journal {} does not describe a publication tog made in this \
             project with this store ({detail}), so nothing was changed. If a tog command \
             using another TOG_STORE was interrupted here, run it again with that store; \
             otherwise inspect {} and delete it",
            shown.display(),
            shown.display()
        ),
    )
}

pub(super) fn narrate(project: &Path, notes: &[Restored], verb: &str) {
    let mut restored = Vec::new();
    let mut edited = Vec::new();
    for note in notes {
        match note {
            Restored::Restored(path) | Restored::Removed(path) => {
                restored.push(path.display().to_string())
            }
            Restored::LeftEdited(path) => edited.push(path.display().to_string()),
            Restored::Unchanged(_) => {}
        }
    }
    if !restored.is_empty() {
        ui::note(&format!(
            "{verb} an unfinished resolution publication in {}: put back {}",
            project.display(),
            snapshot::listing(&restored)
        ));
    }
    if !edited.is_empty() {
        ui::warning(
            &format!(
                "an unfinished resolution publication in {} found files edited since it \
                 started, and left them as they are: {}",
                project.display(),
                snapshot::listing(&edited)
            ),
            "check those files, then run the command again",
        );
    }
}

/// A committed journal: the targets are published. Delete each displaced
/// temporary that still holds exactly its target's pre-run bytes (anything
/// else there is left alone and reported), then `finish`.
pub(super) fn finish_committed(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
    journal: &Journal,
) -> io::Result<()> {
    let mut kept = Vec::new();
    for target in &journal.targets {
        let temp = PathBuf::from(&target.temp);
        let Ok((dir, name)) = parent_of(root, &temp) else {
            continue;
        };
        match current_at(dir.as_raw_fd(), &name)? {
            Current::Absent => {}
            Current::File(digest) if hex::encode(digest) == target.original => {
                unlink_at(dir.as_raw_fd(), &name)?;
            }
            _ => kept.push(root.path().join(&temp).display().to_string()),
        }
    }
    if !kept.is_empty() {
        ui::warning(
            &format!(
                "a finished resolution publication in {} left files it did not write where \
                 its temporaries were, and kept them: {}",
                root.path().display(),
                snapshot::listing(&kept)
            ),
            "inspect those files and delete them if they are not yours",
        );
    }
    fault(FaultPoint::TempsRemoved)?;
    finish(store, activity, root, lock, journal)
}

/// The last steps of every transaction and every recovery, once the
/// project's files are final (untouched, published, or undone): release
/// the originals, then delete the journal, then the directories the
/// transaction created (`.tog/journal` cannot go while the journal is in
/// it).
///
/// The journal goes last so that a failed release is retried: the next
/// recovery finds the journal and releases again. A `publishing` or
/// `committed` journal is trusted only while its originals are rooted, so
/// it is first rewritten as `finished`, which is trusted without them; a
/// crash between the release and the journal's removal then leaves a
/// journal the next recovery finishes instead of refusing. If that
/// rewrite fails, the old journal stays and recovery repeats the step it
/// names, which finds nothing left to do in the project.
pub(super) fn finish(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
    journal: &Journal,
) -> io::Result<()> {
    let journals = root.subdir(Path::new(JOURNAL_DIR))?;
    if let (JournalState::Publishing | JournalState::Committed, Some(journals)) =
        (journal.state, &journals)
    {
        let mut finished = journal.clone();
        finished.state = JournalState::Finished;
        write_journal(journals, &finished)?;
    }
    fault(FaultPoint::Releasing)?;
    release(store, activity, root, lock, journal)?;
    fault(FaultPoint::Released)?;
    if let Some(journals) = &journals {
        remove_journal(journals, &journal.ecosystem)?;
    }
    remove_created_dirs(root, journal)
}

pub(super) fn release(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
    journal: &Journal,
) -> io::Result<()> {
    store.unroot_objects_locked(
        activity,
        root,
        &BTreeSet::from([journal.originals.clone()]),
        lock,
    )
}

/// Undo every target of an unfinished journal, last first, then remove the
/// directories it created if they are empty. Decides by content alone.
pub(super) fn undo(
    store: &Store,
    root: &ProjectRoot,
    journal: &Journal,
) -> io::Result<Vec<Restored>> {
    let mut notes = Vec::new();
    for target in journal.targets.iter().rev() {
        notes.push(undo_target(store, root, journal, target)?);
    }
    Ok(notes)
}

fn undo_target(
    store: &Store,
    root: &ProjectRoot,
    journal: &Journal,
    target: &JournalTarget,
) -> io::Result<Restored> {
    check_journal_target(journal, target).map_err(|detail| journal_error(journal, &detail))?;
    let relative = PathBuf::from(&target.target);
    let shown = root.path().join(&relative);
    let Ok((dir, name)) = parent_of(root, &relative) else {
        // Its directory is gone: nothing of ours can be in it.
        return Ok(Restored::Unchanged(shown));
    };
    let temp_path = PathBuf::from(&target.temp);
    let temp = file_name(&temp_path);
    let malformed = || journal_error(journal, "a digest is malformed");
    let new = Current::File(parse_digest(&target.new).ok_or_else(malformed)?);
    let original = match target.original.as_str() {
        ABSENT => Current::Absent,
        digest => Current::File(parse_digest(digest).ok_or_else(malformed)?),
    };
    let now = current_at(dir.as_raw_fd(), &name)?;
    let note = if now == new {
        match original {
            Current::Absent => {
                unlink_at(dir.as_raw_fd(), &name)?;
                Restored::Removed(shown)
            }
            _ if exchange_back(target, current_at(dir.as_raw_fd(), temp)?, original) => {
                exchange(dir.as_raw_fd(), temp, &name)?;
                Restored::Restored(shown)
            }
            _ => {
                // No displaced file to put back, or something else (a file
                // or symlink planted after a crash): restore from the
                // stored copy. A directory there fails the unlink, and the
                // journal is kept.
                let bytes = original_bytes(store, journal, target)?;
                let mode = target_mode(dir.as_raw_fd(), &name)?;
                unlink_at(dir.as_raw_fd(), temp)?;
                write_temp(dir.as_raw_fd(), temp, &bytes, mode)?;
                rename_replace(dir.as_raw_fd(), temp, &name)?;
                Restored::Restored(shown)
            }
        }
    } else if now == original {
        Restored::Unchanged(shown)
    } else {
        Restored::LeftEdited(shown)
    };
    // Whatever is left at the temporary is never the only copy of anything
    // the user wrote: after the branch above it holds the new bytes or an
    // unswapped temporary.
    unlink_at(dir.as_raw_fd(), temp)?;
    store::fsync_directory(dir.as_raw_fd())?;
    Ok(note)
}

/// Whether the file at a target's temporary is what the swap displaced,
/// to be exchanged back. A target marked `swapped` passed the compare, so
/// its temporary held exactly the pre-run bytes: anything else there now
/// was planted, and the stored copy is used instead. A `pending` target
/// whose swap happened was interrupted before the compare, so the
/// temporary may hold a user's edit the swap displaced, and exchanging it
/// back is what keeps that edit.
fn exchange_back(target: &JournalTarget, temp: Current, original: Current) -> bool {
    match target.state {
        TargetState::Swapped => temp == original,
        TargetState::Pending => matches!(temp, Current::File(_)),
    }
}

fn original_bytes(store: &Store, journal: &Journal, target: &JournalTarget) -> io::Result<Vec<u8>> {
    let Some(copy) = &target.copy else {
        return Err(journal_error(
            journal,
            "a present original has no stored copy",
        ));
    };
    if copy.is_empty() || !copy.bytes().all(|b| b.is_ascii_digit()) {
        return Err(journal_error(
            journal,
            "the originals reference is malformed",
        ));
    }
    let path = store.object_path(&journal.originals).join(copy);
    let bytes = fs::read(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "the pre-run copy of {} at {} cannot be read ({error}); the journal was kept",
                target.target,
                path.display()
            ),
        )
    })?;
    if hex::encode(Sha256::digest(&bytes)) != target.original {
        return Err(journal_error(
            journal,
            "a stored original does not match its digest",
        ));
    }
    Ok(bytes)
}

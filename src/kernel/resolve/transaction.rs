//! The resolution transaction: how a door's outputs replace project files
//! all-or-nothing, and how an interrupted publication is undone (kernel
//! layer).
//!
//! The model, in order:
//!
//! 1. **Hold.** Before the tool runs, every target (each declared output,
//!    then the receipt) is opened without following a symlink through the
//!    held project directory. Its bytes are copied into an immutable store
//!    object (the *originals*), rooted in the project's root record so
//!    `tog gc` cannot collect it while a publication may still need it, and
//!    its sha256 becomes the pre-run digest. A target that does not exist
//!    is recorded as `absent`.
//! 2. **Journal.** Before the first project write, a journal at
//!    `.tog/resolution/.journal-<ecosystem>.json` lists every target: its
//!    temporary name, pre-run digest, new digest and state. The file and its
//!    directory are fsynced. The journal's presence means "publication may
//!    be incomplete".
//! 3. **Swap, then compare.** Each target's new bytes go to a temporary
//!    beside it, which is atomically exchanged with the target
//!    (`renameat2(RENAME_EXCHANGE)`). The temporary now holds exactly what
//!    the target held an instant before; if its digest is not the pre-run
//!    digest, somebody edited the file during the run, so the two are
//!    exchanged back (their edit is restored exactly) and the transaction
//!    fails. An absent target is created with `RENAME_NOREPLACE`, which
//!    fails if anything appeared meanwhile.
//! 4. **Commit.** Once the receipt is in place, the journal is marked
//!    committed, the displaced temporaries and the journal are deleted, and
//!    the originals are released.
//!
//! Any failure during step 3 undoes every target in reverse, and recovery
//! after a crash does the same from the journal alone. Both decide by
//! content: a target at its new digest is restored (by exchanging the
//! displaced original back, or from the originals object), a target at its
//! pre-run digest is left alone, and a target at any third digest was
//! edited since and is left alone and reported.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::outputs::{Outputs, MAX_OUTPUT_BYTES};
use crate::kernel::resolve::snapshot;
use crate::kernel::store::{self, ObjectDeps, Store};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The project directory holding receipts and journals.
pub const RESOLUTION_DIR: &str = ".tog/resolution";
const JOURNAL_SCHEMA: &str = "resolution-journal/1";
const ORIGINALS_KIND: &str = "resolution-originals";
const ORIGINALS_SCHEMA: &str = "resolution-originals/1";
const ABSENT: &str = "absent";
const RECEIPT_MODE: u32 = 0o644;

/// The receipt a door publishes for `ecosystem`, relative to the lock root.
pub fn receipt_path(ecosystem: &str) -> PathBuf {
    Path::new(RESOLUTION_DIR).join(format!("{ecosystem}.json"))
}

fn journal_name(ecosystem: &str) -> String {
    format!(".journal-{ecosystem}.json")
}

/// What `Transaction::hold` holds.
#[derive(Clone, Debug)]
pub struct HoldSpec<'a> {
    /// `[a-z0-9-]+`: names the receipt and the journal.
    pub ecosystem: &'a str,
    /// Declared outputs, relative to the lock root, in publication order.
    pub outputs: &'a [PathBuf],
    /// Hold (and later replace) the receipt as the last target.
    pub receipt: bool,
}

#[derive(Clone, Debug)]
struct Original {
    sha256: [u8; 32],
    mode: u32,
    /// The file name inside the originals object.
    copy: String,
}

#[derive(Clone, Debug)]
struct Held {
    relative: PathBuf,
    original: Option<Original>,
    receipt: bool,
}

/// A held target set, from `hold` to `publish` or `abandon`. Dropping it
/// unpublished is `abandon`.
pub struct Transaction<'a> {
    store: &'a Store,
    activity: &'a StoreActivity,
    root: ProjectRoot,
    lock: fs::File,
    ecosystem: String,
    targets: Vec<Held>,
    originals: Option<String>,
    finished: bool,
}

impl std::fmt::Debug for Transaction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("root", &self.root.path())
            .field("ecosystem", &self.ecosystem)
            .field("targets", &self.targets)
            .field("originals", &self.originals)
            .finish()
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.release();
        }
    }
}

impl<'a> Transaction<'a> {
    /// Take the project lock, recover any interrupted publication in
    /// `root`, then hold `spec`'s targets. The lock is kept until the
    /// transaction ends, which serializes every writer of this project's
    /// resolution state; the caller must not already hold it.
    pub fn hold(
        store: &'a Store,
        activity: &'a StoreActivity,
        root: ProjectRoot,
        spec: &HoldSpec<'_>,
    ) -> io::Result<Transaction<'a>> {
        let lock = store.project_lock_in(&root)?;
        Self::hold_locked(store, activity, root, lock, spec)
    }

    /// `hold` for a caller that already took `store.project_lock_in(&root)`;
    /// the transaction takes that lock over.
    pub fn hold_locked(
        store: &'a Store,
        activity: &'a StoreActivity,
        root: ProjectRoot,
        project_lock: fs::File,
        spec: &HoldSpec<'_>,
    ) -> io::Result<Transaction<'a>> {
        store.require_activity(activity, "resolution transaction")?;
        check_ecosystem(spec.ecosystem)?;
        let mut relatives: Vec<(PathBuf, bool)> = Vec::new();
        for output in spec.outputs {
            check_target(output)?;
            if output.starts_with(".tog") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{} is tog's own state, never a declared output",
                        output.display()
                    ),
                ));
            }
            if relatives.iter().any(|(held, _)| held == output) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is declared twice", output.display()),
                ));
            }
            relatives.push((output.clone(), false));
        }
        if spec.receipt {
            relatives.push((receipt_path(spec.ecosystem), true));
        }
        recover_locked(store, activity, &root, &project_lock)?;
        let mut transaction = Transaction {
            store,
            activity,
            root,
            lock: project_lock,
            ecosystem: spec.ecosystem.to_string(),
            targets: Vec::new(),
            originals: None,
            finished: false,
        };
        let copies = transaction.read_originals(relatives)?;
        transaction.commit_originals(copies)?;
        Ok(transaction)
    }

    /// The lock root this transaction holds.
    pub fn root(&self) -> &ProjectRoot {
        &self.root
    }

    /// The project lock, held from `hold` until `publish` or `abandon`.
    /// Anything between them that needs it (registering the ledger in the
    /// root record) must borrow this one: a second `project_lock_in` from
    /// this process would wait on this lock forever.
    pub fn project_lock(&self) -> &fs::File {
        &self.lock
    }

    /// The pre-run sha256 of a held target, `None` when it was absent.
    pub fn original_digest(&self, relative: &Path) -> Option<[u8; 32]> {
        self.targets
            .iter()
            .find(|held| held.relative == relative)
            .and_then(|held| held.original.as_ref().map(|original| original.sha256))
    }

    fn read_originals(&mut self, relatives: Vec<(PathBuf, bool)>) -> io::Result<Vec<Vec<u8>>> {
        let mut copies = Vec::new();
        for (index, (relative, receipt)) in relatives.into_iter().enumerate() {
            let original = match read_regular(&self.root, &relative)? {
                Some((bytes, mode)) => {
                    let original = Original {
                        sha256: Sha256::digest(&bytes).into(),
                        mode,
                        copy: index.to_string(),
                    };
                    copies.push(bytes);
                    Some(original)
                }
                None => None,
            };
            self.targets.push(Held {
                relative,
                original,
                receipt,
            });
        }
        Ok(copies)
    }

    /// Commit the originals as one store object and root it for this
    /// project. Nothing to commit when every target is absent.
    fn commit_originals(&mut self, copies: Vec<Vec<u8>>) -> io::Result<()> {
        if copies.is_empty() {
            return Ok(());
        }
        let stage = self.store.stage_with_activity(self.activity)?;
        let identity = match self.write_originals(&stage, copies) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = store::remove_tree(&stage);
                return Err(error);
            }
        };
        self.store.commit_with_activity_and_deps(
            self.activity,
            &identity,
            &stage,
            &[],
            &ObjectDeps::new(),
        )?;
        let id = identity.object_id();
        self.store.register_root_parts_with_project_lock(
            self.activity,
            &self.root,
            BTreeSet::from([id.clone()]),
            BTreeSet::new(),
            &self.lock,
        )?;
        self.originals = Some(id);
        Ok(())
    }

    fn write_originals(&self, stage: &Path, copies: Vec<Vec<u8>>) -> io::Result<Identity> {
        let mut copies = copies.into_iter();
        let mut targets = Vec::new();
        for held in &self.targets {
            if let Some(original) = &held.original {
                let bytes = copies.next().expect("one copy per present target");
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(stage.join(&original.copy))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            targets.push((
                path_text(&held.relative)?.to_string(),
                held.original.as_ref().map(|original| original.sha256),
            ));
        }
        let run = hex::encode(crate::kernel::fsroot::urandom_bytes(16)?);
        Ok(originals_identity(&self.ecosystem, &run, &targets))
    }

    /// Publish: replace each held target that has a new version (the
    /// outputs the tool changed, then `receipt`), all or nothing. A held
    /// output the tool left alone must still hold its pre-run bytes.
    pub fn publish(mut self, outputs: &Outputs, receipt: Option<&[u8]>) -> io::Result<()> {
        let plan = self.plan(outputs, receipt)?;
        let created_dirs = self.prepare_dirs(&plan)?;
        let mut journal = Journal {
            schema: JOURNAL_SCHEMA.to_string(),
            ecosystem: self.ecosystem.clone(),
            state: JournalState::Publishing,
            originals: self.originals.clone(),
            created_dirs: created_dirs
                .iter()
                .map(|dir| path_text(dir).map(str::to_string))
                .collect::<io::Result<_>>()?,
            targets: plan.iter().map(|entry| entry.journal.clone()).collect(),
        };
        let resolution = self.resolution_dir()?;
        let outcome = (|| {
            write_journal(&resolution, &journal)?;
            fault(FaultPoint::Journaled)?;
            for (index, entry) in plan.iter().enumerate() {
                self.swap(entry, index)?;
                journal.targets[index].state = TargetState::Swapped;
                write_journal(&resolution, &journal)?;
                fault(FaultPoint::Marked(index))?;
            }
            self.verify_unpublished(&plan)?;
            fault(FaultPoint::Verified)?;
            journal.state = JournalState::Committed;
            write_journal(&resolution, &journal)?;
            fault(FaultPoint::Committed)
        })();
        match outcome {
            Ok(()) => {
                self.finished = true;
                finish_committed(self.store, self.activity, &self.root, &self.lock, &journal)
            }
            Err(error) if is_crash(&error) => {
                // A simulated process death: nothing more runs.
                self.finished = true;
                Err(error)
            }
            Err(error) => {
                let undone = undo(self.store, &self.root, &journal);
                match undone {
                    Ok(notes) => {
                        remove_journal(&resolution, &self.ecosystem)?;
                        remove_created_tog_dirs(&self.root, &journal)?;
                        self.finished = true;
                        self.release()?;
                        narrate(self.root.path(), &notes, "undone");
                        Err(error)
                    }
                    Err(undo_error) => {
                        // The journal stays, and so does the originals'
                        // root: the next writing command recovers.
                        self.finished = true;
                        Err(io::Error::new(
                            error.kind(),
                            format!(
                                "{error}; undoing the partial publication also failed \
                                 ({undo_error}), so the journal in {} was kept and the next \
                                 tog command in this project will finish undoing it",
                                self.root.path().join(RESOLUTION_DIR).display()
                            ),
                        ))
                    }
                }
            }
        }
    }

    /// Give up before publishing: nothing in the project was touched, so
    /// only the originals are released.
    pub fn abandon(mut self) -> io::Result<()> {
        self.finished = true;
        self.release()
    }

    fn release(&self) -> io::Result<()> {
        let Some(id) = &self.originals else {
            return Ok(());
        };
        self.store.unroot_objects_locked(
            self.activity,
            &self.root,
            &BTreeSet::from([id.clone()]),
            &self.lock,
        )
    }

    fn plan(&self, outputs: &Outputs, receipt: Option<&[u8]>) -> io::Result<Vec<Planned>> {
        for file in outputs.files() {
            if !self
                .targets
                .iter()
                .any(|held| !held.receipt && held.relative == file.relative)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a held target", file.relative.display()),
                ));
            }
        }
        let mut plan = Vec::new();
        for (index, held) in self.targets.iter().enumerate() {
            let (bytes, mode) = if held.receipt {
                match receipt {
                    Some(bytes) => (bytes.to_vec(), RECEIPT_MODE),
                    None => continue,
                }
            } else {
                match outputs.get(&held.relative) {
                    Some(file) => (outputs.contents(file)?, file.mode),
                    None => continue,
                }
            };
            let mode = held
                .original
                .as_ref()
                .map_or(mode, |original| original.mode);
            let temp = temp_beside(&held.relative)?;
            plan.push(Planned {
                target: index,
                bytes,
                mode,
                journal: JournalTarget {
                    target: path_text(&held.relative)?.to_string(),
                    temp: path_text(&temp)?.to_string(),
                    original: held
                        .original
                        .as_ref()
                        .map_or(ABSENT.to_string(), |original| hex::encode(original.sha256)),
                    copy: held.original.as_ref().map(|original| original.copy.clone()),
                    new: String::new(),
                    state: TargetState::Pending,
                },
            });
            let last = plan.last_mut().expect("just pushed");
            last.journal.new = hex::encode(Sha256::digest(&last.bytes));
        }
        if receipt.is_some() && !self.targets.iter().any(|held| held.receipt) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a receipt was given to a transaction that does not hold one",
            ));
        }
        Ok(plan)
    }

    /// Create `.tog/resolution` and every missing parent of a planned
    /// target, returning the directories created (outermost first).
    fn prepare_dirs(&self, plan: &[Planned]) -> io::Result<Vec<PathBuf>> {
        let mut wanted: Vec<PathBuf> = vec![PathBuf::from(RESOLUTION_DIR)];
        for entry in plan {
            if let Some(parent) = self.targets[entry.target].relative.parent() {
                if !parent.as_os_str().is_empty() {
                    wanted.push(parent.to_path_buf());
                }
            }
        }
        let mut created = Vec::new();
        for dir in wanted {
            let mut prefix = PathBuf::new();
            for component in dir.components() {
                prefix.push(component);
                if self.root.subdir(&prefix)?.is_none() {
                    self.root.create_dir_all(&prefix)?;
                    created.push(prefix.clone());
                }
            }
        }
        Ok(created)
    }

    fn resolution_dir(&self) -> io::Result<ProjectRoot> {
        self.root.subdir(Path::new(RESOLUTION_DIR))?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{} vanished",
                    self.root.path().join(RESOLUTION_DIR).display()
                ),
            )
        })
    }

    /// Step 3 for one target: temporary, exchange (or no-replace create),
    /// compare the displaced bytes.
    fn swap(&self, entry: &Planned, index: usize) -> io::Result<()> {
        let held = &self.targets[entry.target];
        let (dir, name) = parent_of(&self.root, &held.relative)?;
        let temp = file_name(Path::new(&entry.journal.temp));
        write_temp(dir.as_raw_fd(), temp, &entry.bytes, entry.mode)?;
        fault(FaultPoint::TempWritten(index))?;
        let shown = self.root.path().join(&held.relative);
        match &held.original {
            None => create_noreplace(dir.as_raw_fd(), temp, &name).map_err(|error| {
                let _ = unlink_at(dir.as_raw_fd(), temp);
                if error.kind() == io::ErrorKind::AlreadyExists {
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "{} appeared while the resolution ran; nothing was published",
                            shown.display()
                        ),
                    )
                } else {
                    error
                }
            })?,
            Some(original) => {
                exchange(dir.as_raw_fd(), temp, &name)?;
                fault(FaultPoint::Swapped(index))?;
                if current_at(dir.as_raw_fd(), temp)? != Current::File(original.sha256) {
                    exchange(dir.as_raw_fd(), temp, &name)?;
                    return Err(io::Error::other(format!(
                        "{} changed while the resolution ran, so it was left as you had it \
                         and nothing was published; run the command again",
                        shown.display()
                    )));
                }
            }
        }
        store::fsync_directory(dir.as_raw_fd())
    }

    /// Every held target not being replaced must still hold its pre-run
    /// bytes; a receipt or output edited meanwhile fails the transaction.
    fn verify_unpublished(&self, plan: &[Planned]) -> io::Result<()> {
        for (index, held) in self.targets.iter().enumerate() {
            if plan.iter().any(|entry| entry.target == index) {
                continue;
            }
            let expected = held
                .original
                .as_ref()
                .map_or(Current::Absent, |original| Current::File(original.sha256));
            if current(&self.root, &held.relative)? != expected {
                return Err(io::Error::other(format!(
                    "{} changed while the resolution ran; nothing was published; run the \
                     command again",
                    self.root.path().join(&held.relative).display()
                )));
            }
        }
        Ok(())
    }
}

/// The identity of one transaction's originals object: `run` makes it
/// that transaction's own, and each target is named with its pre-run
/// digest or `absent`.
fn originals_identity(
    ecosystem: &str,
    run: &str,
    targets: &[(String, Option<[u8; 32]>)],
) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), ORIGINALS_SCHEMA.to_string()),
        ("run".to_string(), run.to_string()),
    ]);
    for (index, (target, digest)) in targets.iter().enumerate() {
        inputs.insert(format!("target:{index}"), target.clone());
        inputs.insert(
            format!("digest:{index}"),
            digest.map_or(ABSENT.to_string(), hex::encode),
        );
    }
    Identity {
        kind: ORIGINALS_KIND.to_string(),
        name: ecosystem.to_string(),
        version: "1".to_string(),
        inputs,
    }
}

/// A live `resolution-originals` identity, for the object-kind grammar
/// tests.
#[cfg(test)]
pub(crate) fn live_identity_for_test() -> Identity {
    originals_identity(
        "npm",
        &"0".repeat(32),
        &[
            ("package.json".to_string(), Some([7; 32])),
            ("package-lock.json".to_string(), None),
        ],
    )
}

struct Planned {
    target: usize,
    bytes: Vec<u8>,
    mode: u32,
    journal: JournalTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum JournalState {
    Publishing,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TargetState {
    Pending,
    Swapped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalTarget {
    target: String,
    temp: String,
    /// Hex sha256 of the pre-run bytes, or `absent`.
    original: String,
    /// The file holding the pre-run bytes inside the originals object.
    copy: Option<String>,
    new: String,
    state: TargetState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    ecosystem: String,
    state: JournalState,
    originals: Option<String>,
    created_dirs: Vec<String>,
    targets: Vec<JournalTarget>,
}

/// What recovery or an undo did to one target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Restored {
    /// Put back to its pre-run bytes.
    Restored(PathBuf),
    /// A file the publication created, removed again.
    Removed(PathBuf),
    /// Already at its pre-run bytes.
    Unchanged(PathBuf),
    /// At neither the pre-run nor the new bytes: edited since, left alone.
    LeftEdited(PathBuf),
}

/// Is there an interrupted publication journal in `dir` or any ancestor?
/// Store-free and cheap: a command calls this first and opens the store
/// only when recovery has work to do.
pub fn has_pending_journal(dir: &Path) -> bool {
    dir.ancestors()
        .any(|ancestor| !journals_in(ancestor).is_empty())
}

fn journals_in(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir.join(RESOLUTION_DIR)) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| is_journal_name(name))
        .collect()
}

fn is_journal_name(name: &str) -> bool {
    name.strip_prefix(".journal-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .is_some_and(|eco| check_ecosystem(eco).is_ok())
}

/// Recover every interrupted resolution publication for the project at
/// `dir` or the workspace above it. Every tog command that writes a project
/// runs this before anything else. Takes the project lock itself.
pub fn recover_project(
    store: &Store,
    activity: &StoreActivity,
    dir: &Path,
) -> io::Result<Vec<Restored>> {
    let mut all = Vec::new();
    for ancestor in dir.ancestors() {
        if journals_in(ancestor).is_empty() {
            continue;
        }
        let root = ProjectRoot::open(ancestor)?;
        let lock = store.project_lock_in(&root)?;
        let notes = recover_locked(store, activity, &root, &lock)?;
        narrate(root.path(), &notes, "recovered");
        all.extend(notes);
    }
    Ok(all)
}

fn recover_locked(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
) -> io::Result<Vec<Restored>> {
    let Some(resolution) = root.subdir(Path::new(RESOLUTION_DIR))? else {
        return Ok(Vec::new());
    };
    let mut notes = Vec::new();
    let mut names = store::read_dir_names_at(resolution.as_raw_fd())?;
    names.sort();
    for name in names {
        let Some(name) = name.to_str() else { continue };
        if is_journal_temp(name) {
            unlink_at(resolution.as_raw_fd(), OsStr::new(name))?;
            continue;
        }
        if !is_journal_name(name) {
            continue;
        }
        let journal = read_journal(&resolution, name)?;
        match journal.state {
            JournalState::Committed => {
                finish_committed(store, activity, root, lock, &journal)?;
            }
            JournalState::Publishing => {
                notes.extend(undo(store, root, &journal)?);
                remove_journal(&resolution, &journal.ecosystem)?;
                remove_created_tog_dirs(root, &journal)?;
                release(store, activity, root, lock, &journal)?;
            }
        }
    }
    Ok(notes)
}

fn narrate(project: &Path, notes: &[Restored], verb: &str) {
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

/// A committed journal: the targets are published; delete the displaced
/// temporaries and the journal, then release the originals.
fn finish_committed(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
    journal: &Journal,
) -> io::Result<()> {
    for target in &journal.targets {
        let temp = PathBuf::from(&target.temp);
        check_target(&temp)?;
        if let Ok((dir, name)) = parent_of(root, &temp) {
            unlink_at(dir.as_raw_fd(), &name)?;
        }
    }
    fault(FaultPoint::TempsRemoved)?;
    let resolution = root
        .subdir(Path::new(RESOLUTION_DIR))?
        .ok_or_else(|| io::Error::other("the resolution directory vanished"))?;
    remove_journal(&resolution, &journal.ecosystem)?;
    release(store, activity, root, lock, journal)
}

fn release(
    store: &Store,
    activity: &StoreActivity,
    root: &ProjectRoot,
    lock: &fs::File,
    journal: &Journal,
) -> io::Result<()> {
    match &journal.originals {
        Some(id) => {
            store.unroot_objects_locked(activity, root, &BTreeSet::from([id.clone()]), lock)
        }
        None => Ok(()),
    }
}

/// Undo every target of an unfinished journal, last first, then remove the
/// directories it created if they are empty. Decides by content alone.
fn undo(store: &Store, root: &ProjectRoot, journal: &Journal) -> io::Result<Vec<Restored>> {
    let mut notes = Vec::new();
    for target in journal.targets.iter().rev() {
        notes.push(undo_target(store, root, journal, target)?);
    }
    for dir in journal.created_dirs.iter().rev() {
        let dir = PathBuf::from(dir);
        check_target(&dir)?;
        if dir == Path::new(RESOLUTION_DIR) || dir == Path::new(".tog") {
            // They hold the journal; `remove_created_tog_dirs` takes them
            // once it is gone.
            continue;
        }
        if let Ok((parent, name)) = parent_of(root, &dir) {
            remove_empty_dir(parent.as_raw_fd(), &name)?;
        }
    }
    Ok(notes)
}

fn undo_target(
    store: &Store,
    root: &ProjectRoot,
    journal: &Journal,
    target: &JournalTarget,
) -> io::Result<Restored> {
    let relative = PathBuf::from(&target.target);
    let temp_path = PathBuf::from(&target.temp);
    check_target(&relative)?;
    check_target(&temp_path)?;
    if temp_path.parent() != relative.parent() {
        return Err(journal_error(
            journal,
            "a temporary is not beside its target",
        ));
    }
    let shown = root.path().join(&relative);
    let Ok((dir, name)) = parent_of(root, &relative) else {
        // Its directory is gone: nothing of ours can be in it.
        return Ok(Restored::Unchanged(shown));
    };
    let temp = file_name(&temp_path);
    let new = Current::File(parse_digest(journal, &target.new)?);
    let original = match target.original.as_str() {
        ABSENT => Current::Absent,
        digest => Current::File(parse_digest(journal, digest)?),
    };
    let now = current_at(dir.as_raw_fd(), &name)?;
    let note = if now == new {
        match original {
            Current::Absent => {
                unlink_at(dir.as_raw_fd(), &name)?;
                Restored::Removed(shown)
            }
            _ if matches!(current_at(dir.as_raw_fd(), temp)?, Current::File(_)) => {
                // The temporary holds exactly what the swap displaced.
                exchange(dir.as_raw_fd(), temp, &name)?;
                Restored::Restored(shown)
            }
            _ => {
                // No displaced file to put back, or something that is not
                // one (a symlink planted after a crash): restore from the
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

fn original_bytes(store: &Store, journal: &Journal, target: &JournalTarget) -> io::Result<Vec<u8>> {
    let (Some(id), Some(copy)) = (&journal.originals, &target.copy) else {
        return Err(journal_error(
            journal,
            "a present original has no stored copy",
        ));
    };
    if !store::is_object_id(id) || copy.is_empty() || !copy.bytes().all(|b| b.is_ascii_digit()) {
        return Err(journal_error(
            journal,
            "the originals reference is malformed",
        ));
    }
    let path = store.object_path(id).join(copy);
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

/// After the journal of an undone publication is deleted: remove
/// `.tog/resolution` and `.tog` if that publication created them and they
/// are now empty.
fn remove_created_tog_dirs(root: &ProjectRoot, journal: &Journal) -> io::Result<()> {
    for dir in [RESOLUTION_DIR, ".tog"] {
        if !journal.created_dirs.iter().any(|created| created == dir) {
            continue;
        }
        if let Ok((parent, name)) = parent_of(root, Path::new(dir)) {
            remove_empty_dir(parent.as_raw_fd(), &name)?;
        }
    }
    Ok(())
}

fn journal_error(journal: &Journal, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the {} resolution journal cannot be recovered: {detail}; inspect the files it \
             names, then delete it",
            journal.ecosystem
        ),
    )
}

fn parse_digest(journal: &Journal, text: &str) -> io::Result<[u8; 32]> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| journal_error(journal, "a digest is malformed"))
}

fn read_journal(resolution: &ProjectRoot, name: &str) -> io::Result<Journal> {
    let shown = resolution.path().join(name);
    let bytes = resolution.read_file(Path::new(name))?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} vanished", shown.display()),
        )
    })?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the resolution journal {} is unreadable ({error}); inspect the files it \
                 names, then delete it",
                shown.display()
            ),
        )
    })?;
    if journal.schema != JOURNAL_SCHEMA || journal_name(&journal.ecosystem) != name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the resolution journal {} is not a {JOURNAL_SCHEMA} journal for its name; \
                 inspect it, then delete it",
                shown.display()
            ),
        ));
    }
    Ok(journal)
}

fn is_journal_temp(name: &str) -> bool {
    name.starts_with(".journal-") && name.ends_with(".tmp")
}

/// Replace the journal atomically: temporary, fsync, rename, fsync the
/// directory.
fn write_journal(resolution: &ProjectRoot, journal: &Journal) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(io::Error::other)?;
    let name = journal_name(&journal.ecosystem);
    let temp = format!(
        "{name}.{}.tmp",
        hex::encode(crate::kernel::fsroot::urandom_bytes(8)?)
    );
    write_temp(resolution.as_raw_fd(), OsStr::new(&temp), &bytes, 0o644)?;
    rename_replace(resolution.as_raw_fd(), OsStr::new(&temp), OsStr::new(&name))?;
    store::fsync_directory(resolution.as_raw_fd())
}

fn remove_journal(resolution: &ProjectRoot, ecosystem: &str) -> io::Result<()> {
    unlink_at(resolution.as_raw_fd(), OsStr::new(&journal_name(ecosystem)))?;
    store::fsync_directory(resolution.as_raw_fd())
}

fn check_ecosystem(ecosystem: &str) -> io::Result<()> {
    if !ecosystem.is_empty()
        && ecosystem
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ecosystem:?} is not an ecosystem name"),
        ))
    }
}

fn check_target(path: &Path) -> io::Result<()> {
    snapshot::check_relative(path)?;
    path_text(path).map(|_| ())
}

fn path_text(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not UTF-8; tog cannot journal it", path.display()),
        )
    })
}

fn file_name(path: &Path) -> &OsStr {
    path.file_name()
        .expect("a checked relative path has a name")
}

fn temp_beside(relative: &Path) -> io::Result<PathBuf> {
    let name = file_name(relative).to_string_lossy();
    let temp = format!(
        ".{name}.tog-{}.tmp",
        hex::encode(crate::kernel::fsroot::urandom_bytes(8)?)
    );
    Ok(relative.with_file_name(temp))
}

/// The held directory containing `relative`, reached without following a
/// symlink, and the leaf name.
fn parent_of(root: &ProjectRoot, relative: &Path) -> io::Result<(ProjectRoot, OsString)> {
    let name = file_name(relative).to_os_string();
    let parent = match relative.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            root.subdir(parent)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} is missing", root.path().join(parent).display()),
                )
            })?
        }
        _ => root.try_clone()?,
    };
    Ok((parent, name))
}

/// The regular file at `relative`, and its permission bits; `None` when
/// it or a parent is absent. A symlink or any other kind of entry is
/// refused.
fn read_regular(root: &ProjectRoot, relative: &Path) -> io::Result<Option<(Vec<u8>, u32)>> {
    let (dir, name) = match parent_of(root, relative) {
        Ok(found) => found,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let shown = root.path().join(relative);
    let file = match open_regular(dir.as_raw_fd(), &name) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("{}: {error}", shown.display()),
            ))
        }
    };
    let mode = store::fd_stat(file.as_raw_fd())?.st_mode as u32 & 0o777;
    let mut bytes = Vec::new();
    (&file).take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is larger than a resolution target may be",
                shown.display()
            ),
        ));
    }
    Ok(Some((bytes, mode)))
}

fn open_regular(dirfd: RawFd, name: &OsStr) -> io::Result<Option<fs::File>> {
    match store::open_file_at(
        dirfd,
        name.as_bytes(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => {
            if store::fd_stat(file.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not a regular file; refusing to replace it",
                ));
            }
            Ok(Some(file))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a symlink; refusing to replace it",
        )),
        Err(error) => {
            if let Ok(stat) = store::stat_at(dirfd, name.as_bytes()) {
                if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "not a regular file; refusing to replace it",
                    ));
                }
            }
            Err(error)
        }
    }
}

/// What an entry holds now, by content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Current {
    Absent,
    File([u8; 32]),
    Other,
}

fn current(root: &ProjectRoot, relative: &Path) -> io::Result<Current> {
    match parent_of(root, relative) {
        Ok((dir, name)) => current_at(dir.as_raw_fd(), &name),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Current::Absent),
        Err(error) => Err(error),
    }
}

fn current_at(dirfd: RawFd, name: &OsStr) -> io::Result<Current> {
    match open_regular(dirfd, name) {
        Ok(Some(file)) => Ok(Current::File(snapshot::hash_reader(&file)?)),
        Ok(None) => Ok(Current::Absent),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(Current::Other),
        Err(error) => Err(error),
    }
}

fn target_mode(dirfd: RawFd, name: &OsStr) -> io::Result<u32> {
    Ok(store::stat_at(dirfd, name.as_bytes())?.st_mode as u32 & 0o777)
}

fn cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))
}

fn write_temp(dirfd: RawFd, name: &OsStr, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = store::open_file_at(
        dirfd,
        name.as_bytes(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    file.write_all(bytes)?;
    // SAFETY: fchmod on the descriptor just created.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    file.sync_all()
}

/// How `rename_at` treats an existing destination.
#[derive(Clone, Copy)]
enum Rename {
    Replace,
    Exchange,
    NoReplace,
}

#[cfg(target_os = "linux")]
fn rename_at(dirfd: RawFd, old: &OsStr, new: &OsStr, mode: Rename) -> io::Result<()> {
    let flags = match mode {
        Rename::Replace => 0,
        Rename::Exchange => libc::RENAME_EXCHANGE,
        Rename::NoReplace => libc::RENAME_NOREPLACE,
    };
    let (old, new) = (cstring(old)?, cstring(new)?);
    // SAFETY: a held directory and two NUL-terminated relative names.
    if unsafe { libc::renameat2(dirfd, old.as_ptr(), dirfd, new.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Elsewhere only the plain rename is wired up; exchange and no-replace
/// report ENOSYS, which `exchange` refuses and `create_noreplace` answers
/// with its link fallback.
#[cfg(not(target_os = "linux"))]
fn rename_at(dirfd: RawFd, old: &OsStr, new: &OsStr, mode: Rename) -> io::Result<()> {
    if !matches!(mode, Rename::Replace) {
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    let (old, new) = (cstring(old)?, cstring(new)?);
    // SAFETY: a held directory and two NUL-terminated relative names.
    if unsafe { libc::renameat(dirfd, old.as_ptr(), dirfd, new.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Atomically exchange two names. There is no fallback: a filesystem
/// without `RENAME_EXCHANGE` cannot give swap-then-compare, so the door
/// fails there rather than publish without it.
fn exchange(dirfd: RawFd, a: &OsStr, b: &OsStr) -> io::Result<()> {
    rename_at(dirfd, a, b, Rename::Exchange).map_err(|error| {
        if matches!(
            error.raw_os_error(),
            Some(libc::EINVAL) | Some(libc::ENOSYS)
        ) {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "this filesystem cannot exchange two files atomically ({error}), which \
                     a resolution needs to publish safely"
                ),
            )
        } else {
            error
        }
    })
}

/// Rename `temp` to `target` only if `target` does not exist. Where the
/// filesystem lacks `RENAME_NOREPLACE`, a hard link (which also refuses an
/// existing name) and an unlink do the same.
fn create_noreplace(dirfd: RawFd, temp: &OsStr, target: &OsStr) -> io::Result<()> {
    match rename_at(dirfd, temp, target, Rename::NoReplace) {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EINVAL) | Some(libc::ENOSYS)
            ) =>
        {
            let (old, new) = (cstring(temp)?, cstring(target)?);
            // SAFETY: as in rename_at; flags 0 never follows a symlink.
            if unsafe { libc::linkat(dirfd, old.as_ptr(), dirfd, new.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            unlink_at(dirfd, temp)
        }
        other => other,
    }
}

fn rename_replace(dirfd: RawFd, old: &OsStr, new: &OsStr) -> io::Result<()> {
    rename_at(dirfd, old, new, Rename::Replace)
}

fn unlink_at(dirfd: RawFd, name: &OsStr) -> io::Result<()> {
    let name = cstring(name)?;
    // SAFETY: a held directory and a NUL-terminated relative name.
    if unsafe { libc::unlinkat(dirfd, name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    Ok(())
}

fn remove_empty_dir(dirfd: RawFd, name: &OsStr) -> io::Result<()> {
    let name = cstring(name)?;
    // SAFETY: as in unlink_at; AT_REMOVEDIR removes only an empty directory.
    if unsafe { libc::unlinkat(dirfd, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOENT) | Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
        ) {
            return Err(error);
        }
    }
    Ok(())
}

/// Named points inside `publish` and recovery where a test can inject a
/// failure, a simulated crash, or a concurrent edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    Journaled,
    TempWritten(usize),
    Swapped(usize),
    Marked(usize),
    Verified,
    Committed,
    TempsRemoved,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Continue,
    Fail,
    Crash,
}

#[cfg(test)]
thread_local! {
    pub(crate) static FAULTS: std::cell::RefCell<Option<Box<dyn FnMut(FaultPoint) -> Fault>>> =
        std::cell::RefCell::new(None);
}

const CRASH: &str = "simulated crash";

#[cfg(test)]
fn fault(point: FaultPoint) -> io::Result<()> {
    let fault = FAULTS.with(|hook| {
        hook.borrow_mut()
            .as_mut()
            .map_or(Fault::Continue, |hook| hook(point))
    });
    match fault {
        Fault::Continue => Ok(()),
        Fault::Fail => Err(io::Error::other(format!("injected failure at {point:?}"))),
        Fault::Crash => Err(io::Error::new(io::ErrorKind::Interrupted, CRASH)),
    }
}

#[cfg(not(test))]
fn fault(_point: FaultPoint) -> io::Result<()> {
    Ok(())
}

fn is_crash(error: &io::Error) -> bool {
    cfg!(test) && error.kind() == io::ErrorKind::Interrupted && error.to_string() == CRASH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::resolve::snapshot::{Snapshot, SnapshotSpec};
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::symlink;

    const OLD_MANIFEST: &[u8] = b"{\"dependencies\":{}}\n";
    const NEW_MANIFEST: &[u8] = b"{\"dependencies\":{\"a\":\"1\"}}\n";
    const NEW_LOCK: &[u8] = b"{\"lockfileVersion\":3}\n";
    const OLD_RECEIPT: &[u8] = b"old receipt\n";
    const NEW_RECEIPT: &[u8] = b"new receipt\n";
    const USER_EDIT: &[u8] = b"the user's own edit\n";

    struct Fixture {
        _temp: TempDir,
        store: Store,
        project: PathBuf,
    }

    fn fixture(label: &str, receipt: bool) -> Fixture {
        let temp = TempDir::named(&format!("txn-{label}"));
        let root = temp.0.join("store");
        for sub in [
            "objects",
            "meta",
            "tmp",
            "roots",
            "root-locks",
            "forests",
            "backups",
        ] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("package.json"), OLD_MANIFEST).unwrap();
        if receipt {
            fs::create_dir_all(project.join(RESOLUTION_DIR)).unwrap();
            fs::write(project.join(receipt_path("npm")), OLD_RECEIPT).unwrap();
        }
        Fixture {
            store: Store {
                root: root.canonicalize().unwrap(),
            },
            project: project.canonicalize().unwrap(),
            _temp: temp,
        }
    }

    fn declared() -> Vec<PathBuf> {
        vec![
            PathBuf::from("package.json"),
            PathBuf::from("package-lock.json"),
        ]
    }

    fn set_hook(hook: impl FnMut(FaultPoint) -> Fault + 'static) {
        FAULTS.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    fn clear_hook() {
        FAULTS.with(|slot| *slot.borrow_mut() = None);
    }

    /// Hold, run a fake tool on a snapshot that rewrites package.json and
    /// creates package-lock.json, then publish with `hook` installed.
    fn run_door(
        fx: &Fixture,
        between: impl FnOnce(&Path),
        hook: impl FnMut(FaultPoint) -> Fault + 'static,
    ) -> io::Result<()> {
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let root = ProjectRoot::open(&fx.project).unwrap();
        let outputs_declared = declared();
        let transaction = Transaction::hold(
            &fx.store,
            &activity,
            root,
            &HoldSpec {
                ecosystem: "npm",
                outputs: &outputs_declared,
                receipt: true,
            },
        )?;
        let snapshot = Snapshot::build(
            &fx.store,
            &activity,
            &SnapshotSpec {
                lock_root: &fx.project,
                extra_roots: &[],
                exclude: &[],
            },
        )?;
        let staged = snapshot.lock_root().staged.clone();
        fs::write(staged.join("package.json"), NEW_MANIFEST)?;
        fs::write(staged.join("package-lock.json"), NEW_LOCK)?;
        let changes = snapshot.diff()?;
        let classified = snapshot.classify(&changes, &outputs_declared, &[])?;
        let outputs = Outputs::copy(&fx.store, &activity, &snapshot, &classified.outputs, &[])?;
        between(&fx.project);
        set_hook(hook);
        let result = transaction.publish(&outputs, Some(NEW_RECEIPT));
        clear_hook();
        result
    }

    fn read(fx: &Fixture, relative: &str) -> Option<Vec<u8>> {
        fs::read(fx.project.join(relative)).ok()
    }

    fn assert_original(fx: &Fixture, receipt: Option<&[u8]>) {
        assert_eq!(read(fx, "package.json").as_deref(), Some(OLD_MANIFEST));
        assert_eq!(read(fx, "package-lock.json"), None);
        assert_eq!(read(fx, ".tog/resolution/npm.json").as_deref(), receipt);
        assert_clean(fx);
    }

    fn assert_published(fx: &Fixture) {
        assert_eq!(read(fx, "package.json").as_deref(), Some(NEW_MANIFEST));
        assert_eq!(read(fx, "package-lock.json").as_deref(), Some(NEW_LOCK));
        assert_eq!(
            read(fx, ".tog/resolution/npm.json").as_deref(),
            Some(NEW_RECEIPT)
        );
        assert_clean(fx);
    }

    /// No journal, no temporaries, and no originals still rooted.
    fn assert_clean(fx: &Fixture) {
        assert!(!has_pending_journal(&fx.project));
        for dir in [fx.project.clone(), fx.project.join(RESOLUTION_DIR)] {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let name = entry.unwrap().file_name().into_string().unwrap();
                assert!(!name.ends_with(".tmp"), "a temporary was left: {name}");
            }
        }
        assert!(rooted_originals(fx).is_empty(), "originals still rooted");
    }

    fn rooted_originals(fx: &Fixture) -> Vec<String> {
        let key = Store::root_key(&fx.project).unwrap();
        let Ok(entry) = fx.store.lookup_root(&key) else {
            return Vec::new();
        };
        let objects = entry
            .record
            .map(|record| record.objects)
            .unwrap_or_default();
        objects
            .into_iter()
            .filter(|id| {
                fs::read_to_string(fx.store.root.join("meta").join(format!("{id}.json")))
                    .is_ok_and(|meta| meta.contains(ORIGINALS_KIND))
            })
            .collect()
    }

    fn recover(fx: &Fixture) -> Vec<Restored> {
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        recover_project(&fx.store, &activity, &fx.project).unwrap()
    }

    #[test]
    fn publish_replaces_changed_outputs_then_the_receipt() {
        let fx = fixture("publish", true);
        run_door(&fx, |_| {}, |_| Fault::Continue).unwrap();
        assert_published(&fx);
    }

    #[test]
    fn a_first_publication_creates_the_receipt_directory() {
        let fx = fixture("first", false);
        run_door(&fx, |_| {}, |_| Fault::Continue).unwrap();
        assert_published(&fx);
    }

    /// The user edits package.json after the originals were held; the
    /// swap displaces their edit, the compare catches it, and it is
    /// exchanged back exactly.
    #[test]
    fn user_edit_after_hold_is_kept_and_nothing_is_published() {
        let fx = fixture("edit-after-hold", true);
        let error = run_door(
            &fx,
            |project| fs::write(project.join("package.json"), USER_EDIT).unwrap(),
            |_| Fault::Continue,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while the resolution ran"),
            "{error}"
        );
        assert_eq!(read(&fx, "package.json").as_deref(), Some(USER_EDIT));
        assert_eq!(read(&fx, "package-lock.json"), None);
        assert_eq!(
            read(&fx, ".tog/resolution/npm.json").as_deref(),
            Some(OLD_RECEIPT)
        );
        assert_clean(&fx);
    }

    /// The edit lands after the temporary is written, an instant before
    /// the exchange.
    #[test]
    fn user_edit_just_before_the_swap_is_kept() {
        let fx = fixture("edit-before-swap", true);
        let project = fx.project.clone();
        let error = run_door(
            &fx,
            |_| {},
            move |point| {
                if point == FaultPoint::TempWritten(0) {
                    fs::write(project.join("package.json"), USER_EDIT).unwrap();
                }
                Fault::Continue
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("package.json"), "{error}");
        assert_eq!(read(&fx, "package.json").as_deref(), Some(USER_EDIT));
        assert_eq!(read(&fx, "package-lock.json"), None);
        assert_clean(&fx);
    }

    /// Another `tog attest` rewrites the receipt while the door runs: the
    /// receipt swap catches it, and every output is undone.
    #[test]
    fn concurrent_receipt_edit_fails_and_undoes_every_output() {
        let fx = fixture("receipt-edit", true);
        let project = fx.project.clone();
        let error = run_door(
            &fx,
            |_| {},
            move |point| {
                if point == FaultPoint::TempWritten(2) {
                    fs::write(project.join(receipt_path("npm")), USER_EDIT).unwrap();
                }
                Fault::Continue
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("npm.json"), "{error}");
        assert_eq!(read(&fx, "package.json").as_deref(), Some(OLD_MANIFEST));
        assert_eq!(read(&fx, "package-lock.json"), None);
        assert_eq!(
            read(&fx, ".tog/resolution/npm.json").as_deref(),
            Some(USER_EDIT)
        );
        assert_clean(&fx);
    }

    /// No receipt at hold; one appears before publication: the no-replace
    /// create refuses, and the one that appeared is kept.
    #[test]
    fn a_receipt_that_appears_during_the_run_is_not_replaced() {
        let fx = fixture("receipt-appears", false);
        let error = run_door(
            &fx,
            |project| {
                fs::create_dir_all(project.join(RESOLUTION_DIR)).unwrap();
                fs::write(project.join(receipt_path("npm")), USER_EDIT).unwrap();
            },
            |_| Fault::Continue,
        )
        .unwrap_err();
        assert!(error.to_string().contains("appeared"), "{error}");
        assert_eq!(
            read(&fx, ".tog/resolution/npm.json").as_deref(),
            Some(USER_EDIT)
        );
        assert_eq!(read(&fx, "package.json").as_deref(), Some(OLD_MANIFEST));
        assert_eq!(read(&fx, "package-lock.json"), None);
        assert_clean(&fx);
    }

    #[test]
    fn a_created_target_that_appears_during_the_run_is_not_replaced() {
        let fx = fixture("created-appears", true);
        let project = fx.project.clone();
        let error = run_door(
            &fx,
            |_| {},
            move |point| {
                if point == FaultPoint::TempWritten(1) {
                    fs::write(project.join("package-lock.json"), USER_EDIT).unwrap();
                }
                Fault::Continue
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("appeared"), "{error}");
        assert_eq!(read(&fx, "package-lock.json").as_deref(), Some(USER_EDIT));
        assert_eq!(read(&fx, "package.json").as_deref(), Some(OLD_MANIFEST));
        assert_clean(&fx);
    }

    /// A failure before publication (the ledger commit, in the door) is
    /// `abandon`: the project is untouched and the originals released.
    #[test]
    fn abandon_touches_nothing_and_releases_the_originals() {
        let fx = fixture("abandon", true);
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let root = ProjectRoot::open(&fx.project).unwrap();
        let lock = fx.store.project_lock_in(&root).unwrap();
        let declared = declared();
        let transaction = Transaction::hold_locked(
            &fx.store,
            &activity,
            root,
            lock,
            &HoldSpec {
                ecosystem: "npm",
                outputs: &declared,
                receipt: true,
            },
        )
        .unwrap();
        assert_eq!(
            transaction.original_digest(Path::new("package.json")),
            Some(Sha256::digest(OLD_MANIFEST).into())
        );
        assert_eq!(
            transaction.original_digest(Path::new("package-lock.json")),
            None
        );
        assert_eq!(
            rooted_originals(&fx).len(),
            1,
            "originals are rooted while held"
        );
        transaction.abandon().unwrap();
        assert_original(&fx, Some(OLD_RECEIPT));
    }

    #[test]
    fn swap_failure_mid_publication_restores_every_target() {
        for point in [
            FaultPoint::Journaled,
            FaultPoint::TempWritten(0),
            FaultPoint::Swapped(0),
            FaultPoint::Marked(0),
            FaultPoint::TempWritten(1),
            FaultPoint::Marked(1),
            FaultPoint::TempWritten(2),
            FaultPoint::Swapped(2),
            FaultPoint::Marked(2),
            FaultPoint::Verified,
        ] {
            let fx = fixture("fail", true);
            let error = run_door(
                &fx,
                |_| {},
                move |at| {
                    if at == point {
                        Fault::Fail
                    } else {
                        Fault::Continue
                    }
                },
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("injected failure"),
                "{point:?}: {error}"
            );
            assert_original(&fx, Some(OLD_RECEIPT));
        }
    }

    /// A failed first publication takes back the `.tog/resolution` it
    /// created, after a crash as well as on the spot.
    #[test]
    fn a_failed_first_publication_leaves_no_tog_directory() {
        for fault in [Fault::Fail, Fault::Crash] {
            let fx = fixture("first-fail", false);
            let _ = run_door(
                &fx,
                |_| {},
                move |point| {
                    if point == FaultPoint::Marked(1) {
                        fault
                    } else {
                        Fault::Continue
                    }
                },
            );
            if fault == Fault::Crash {
                recover(&fx);
            }
            assert!(!fx.project.join(".tog").exists(), "{fault:?}");
            assert_eq!(read(&fx, "package.json").as_deref(), Some(OLD_MANIFEST));
            assert_clean(&fx);
        }
    }

    /// After a crash, a symlink planted at a swapped target's temporary is
    /// never exchanged into the target: the original comes back from the
    /// stored copy.
    #[test]
    fn recovery_never_exchanges_a_planted_symlink_into_a_target() {
        let fx = fixture("planted", true);
        let _ = run_door(
            &fx,
            |_| {},
            |point| {
                if point == FaultPoint::Marked(0) {
                    Fault::Crash
                } else {
                    Fault::Continue
                }
            },
        );
        let temp = fs::read_dir(&fx.project)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.to_string_lossy().ends_with(".tmp"))
            .unwrap();
        fs::remove_file(&temp).unwrap();
        symlink("/etc/passwd", &temp).unwrap();
        recover(&fx);
        let meta = fs::symlink_metadata(fx.project.join("package.json")).unwrap();
        assert!(meta.file_type().is_file());
        assert_original(&fx, Some(OLD_RECEIPT));
    }

    /// A crash at every point of publication: afterwards the journal is
    /// there (once it was written), the originals are still rooted, and
    /// recovery leaves the project either exactly as it was or, once the
    /// journal says committed, exactly as published.
    #[test]
    fn crash_at_every_journal_state_recovers() {
        let points = [
            (FaultPoint::Journaled, false),
            (FaultPoint::TempWritten(0), false),
            (FaultPoint::Swapped(0), false),
            (FaultPoint::Marked(0), false),
            (FaultPoint::TempWritten(1), false),
            (FaultPoint::Marked(1), false),
            (FaultPoint::TempWritten(2), false),
            (FaultPoint::Swapped(2), false),
            (FaultPoint::Marked(2), false),
            (FaultPoint::Verified, false),
            (FaultPoint::Committed, true),
            (FaultPoint::TempsRemoved, true),
        ];
        for (point, committed) in points {
            let fx = fixture("crash", true);
            let error = run_door(
                &fx,
                |_| {},
                move |at| {
                    if at == point {
                        Fault::Crash
                    } else {
                        Fault::Continue
                    }
                },
            )
            .unwrap_err();
            assert!(is_crash(&error), "{point:?}: {error}");
            assert!(has_pending_journal(&fx.project), "{point:?}: no journal");
            assert_eq!(
                rooted_originals(&fx).len(),
                1,
                "{point:?}: originals unrooted"
            );
            let notes = recover(&fx);
            if committed {
                assert_published(&fx);
            } else {
                assert_original(&fx, Some(OLD_RECEIPT));
                assert!(
                    !notes
                        .iter()
                        .any(|note| matches!(note, Restored::LeftEdited(_))),
                    "{point:?}: {notes:?}"
                );
            }
        }
    }

    /// A crash between the exchange and the compare, with the user's edit
    /// displaced into the temporary: recovery exchanges it back.
    #[test]
    fn crash_after_displacing_a_user_edit_restores_the_edit() {
        let fx = fixture("crash-displaced", true);
        let project = fx.project.clone();
        let _ = run_door(
            &fx,
            |_| {},
            move |point| match point {
                FaultPoint::TempWritten(0) => {
                    fs::write(project.join("package.json"), USER_EDIT).unwrap();
                    Fault::Continue
                }
                FaultPoint::Swapped(0) => Fault::Crash,
                _ => Fault::Continue,
            },
        );
        recover(&fx);
        assert_eq!(read(&fx, "package.json").as_deref(), Some(USER_EDIT));
        assert_clean(&fx);
    }

    /// After a crash the user edits a swapped target: recovery leaves it,
    /// reports it, and still undoes the rest.
    #[test]
    fn recovery_leaves_an_edited_target_and_reports_it() {
        let fx = fixture("recover-edited", true);
        let _ = run_door(
            &fx,
            |_| {},
            |point| {
                if point == FaultPoint::Marked(1) {
                    Fault::Crash
                } else {
                    Fault::Continue
                }
            },
        );
        fs::write(fx.project.join("package.json"), USER_EDIT).unwrap();
        let notes = recover(&fx);
        assert!(
            notes.contains(&Restored::LeftEdited(fx.project.join("package.json"))),
            "{notes:?}"
        );
        assert!(notes.contains(&Restored::Removed(fx.project.join("package-lock.json"))));
        assert_eq!(read(&fx, "package.json").as_deref(), Some(USER_EDIT));
        assert_eq!(read(&fx, "package-lock.json"), None);
        assert_eq!(
            read(&fx, ".tog/resolution/npm.json").as_deref(),
            Some(OLD_RECEIPT)
        );
        assert_clean(&fx);
    }

    /// The next hold runs recovery first, so a door started after a crash
    /// begins from the originals.
    #[test]
    fn hold_recovers_a_leftover_journal_first() {
        let fx = fixture("hold-recovers", true);
        let _ = run_door(
            &fx,
            |_| {},
            |point| {
                if point == FaultPoint::Marked(0) {
                    Fault::Crash
                } else {
                    Fault::Continue
                }
            },
        );
        assert_eq!(read(&fx, "package.json").as_deref(), Some(NEW_MANIFEST));
        run_door(&fx, |_| {}, |_| Fault::Continue).unwrap();
        assert_published(&fx);
    }

    /// A recovery that cannot restore (its originals are gone) keeps the
    /// journal and fails, so every later command keeps refusing.
    #[test]
    fn recovery_without_its_originals_fails_closed() {
        let fx = fixture("recover-missing", true);
        let _ = run_door(
            &fx,
            |_| {},
            |point| {
                if point == FaultPoint::Marked(0) {
                    Fault::Crash
                } else {
                    Fault::Continue
                }
            },
        );
        // Remove the temporary (the displaced original) and the stored copy.
        for entry in fs::read_dir(&fx.project).unwrap() {
            let path = entry.unwrap().path();
            if path.to_string_lossy().ends_with(".tmp") {
                fs::remove_file(path).unwrap();
            }
        }
        let id = rooted_originals(&fx).pop().unwrap();
        let object = fx.store.object_path(&id);
        store::restore_write_bits(&object).unwrap();
        fs::remove_file(object.join("0")).unwrap();
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let error = recover_project(&fx.store, &activity, &fx.project).unwrap_err();
        assert!(error.to_string().contains("journal was kept"), "{error}");
        assert!(has_pending_journal(&fx.project));
    }

    #[test]
    fn a_symlinked_or_special_target_is_refused_at_hold() {
        let fx = fixture("hold-symlink", true);
        fs::remove_file(fx.project.join("package.json")).unwrap();
        symlink("/etc/passwd", fx.project.join("package.json")).unwrap();
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let root = ProjectRoot::open(&fx.project).unwrap();
        let lock = fx.store.project_lock_in(&root).unwrap();
        let declared = declared();
        let error = Transaction::hold_locked(
            &fx.store,
            &activity,
            root,
            lock,
            &HoldSpec {
                ecosystem: "npm",
                outputs: &declared,
                receipt: true,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error}");
    }

    #[test]
    fn a_journal_found_in_a_parent_is_recovered_from_a_member() {
        let fx = fixture("member", true);
        fs::create_dir_all(fx.project.join("member")).unwrap();
        let _ = run_door(
            &fx,
            |_| {},
            |point| {
                if point == FaultPoint::Marked(1) {
                    Fault::Crash
                } else {
                    Fault::Continue
                }
            },
        );
        assert!(has_pending_journal(&fx.project.join("member")));
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        recover_project(&fx.store, &activity, &fx.project.join("member")).unwrap();
        assert_original(&fx, Some(OLD_RECEIPT));
    }
}
